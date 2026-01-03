//! Resolute - A DNS proxy with DOH/DOT support, EDNS Client Subnet, and GeoIP-based routing.

// Use jemalloc as the global allocator (Linux/macOS only, better performance)
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

mod cache;
mod config;
mod domain_list;
mod edns;
mod geoip;
mod router;
mod server;
mod upstream;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::geoip::GeoIpLookup;
use crate::router::Router;
use crate::server::DnsServer;

/// Resolute - A DNS proxy with DOH/DOT support, EDNS Client Subnet, and GeoIP-based routing.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Path to the configuration file
    #[arg(short = 'c', long = "config", default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();
    let config_path = args.config;

    // Load configuration
    let config = Config::load(&config_path)
        .with_context(|| format!("Failed to load config from {:?}", config_path))?;

    // Initialize logging
    init_logging(&config.server.log_level)?;

    info!("Starting Resolute DNS proxy");
    info!("Config loaded from: {:?}", config_path);
    for addr in &config.server.listen {
        info!("Listening on: {}", addr);
    }

    // Initialize GeoIP database (may download from URL)
    let geoip_proxy = config.geoip.proxy.as_ref()
        .and_then(|name| config.proxies.get(name));
    let geoip = GeoIpLookup::from_config(&config.geoip, geoip_proxy)
        .await
        .context("Failed to initialize GeoIP database")?;

    // Initialize router (loads domain lists)
    let listen_addrs = config.server.listen.clone();
    let router = Router::new(config, geoip)
        .await
        .context("Failed to initialize router")?;
    let router = Arc::new(router);

    // Start DNS server
    let server = Arc::new(DnsServer::new(listen_addrs, router));
    info!("DNS server starting...");

    server.run().await?;

    Ok(())
}

/// Initialize logging with the specified level
fn init_logging(level: &str) -> Result<()> {
    let level = level.parse::<Level>().unwrap_or(Level::INFO);

    let filter = EnvFilter::builder()
        .with_default_directive(level.into())
        .from_env_lossy();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_ansi(!cfg!(windows))
        .init();

    Ok(())
}
