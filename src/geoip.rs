//! GeoIP lookup using MaxMind mmdb database.
//!
//! Supports loading from local file or downloading from URL.

use anyhow::{Context, Result};
use maxminddb::{geoip2, Reader};
use reqwest::Proxy;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::{debug, info, trace};

use crate::config::{GeoIpConfig, ProxyConfig};

/// GeoIP lookup service
pub struct GeoIpLookup {
    reader: Arc<Reader<Vec<u8>>>,
}

impl GeoIpLookup {
    /// Create a new GeoIP lookup from mmdb file
    pub fn from_file<P: AsRef<Path>>(mmdb_path: P) -> Result<Self> {
        let reader = Reader::open_readfile(mmdb_path.as_ref())
            .with_context(|| format!("Failed to open mmdb file: {:?}", mmdb_path.as_ref()))?;

        debug!("Loaded GeoIP database: {:?}", mmdb_path.as_ref());

        Ok(Self {
            reader: Arc::new(reader),
        })
    }

    /// Create GeoIP lookup from configuration
    /// If URL is specified, downloads the database (with caching)
    pub async fn from_config(config: &GeoIpConfig, proxy_config: Option<&ProxyConfig>) -> Result<Self> {
        // If local path is specified, use it directly
        if let Some(ref path) = config.path {
            info!("Loading GeoIP database from local file: {}", path);
            return Self::from_file(path);
        }

        // Otherwise, download from URL
        if let Some(ref url) = config.url {
            let cache_path = get_cache_path(config, url);

            // Check if we need to download/update
            let should_download = should_download_db(&cache_path, config.update_interval_hours);

            if should_download {
                if let Some(proxy_cfg) = proxy_config {
                    info!("Downloading GeoIP database from: {} via proxy: {}", url, proxy_cfg.url);
                } else {
                    info!("Downloading GeoIP database from: {}", url);
                }
                download_mmdb(url, &cache_path, proxy_config).await?;
            } else {
                info!("Using cached GeoIP database: {:?}", cache_path);
            }

            return Self::from_file(&cache_path);
        }

        anyhow::bail!("No GeoIP source configured (neither path nor url)")
    }

    /// Look up the country code for an IP address
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        // maxminddb 0.27+ uses lookup().decode() pattern
        let lookup_result = match self.reader.lookup(ip) {
            Ok(result) => result,
            Err(e) => {
                if !is_private_ip(ip) {
                    trace!("GeoIP lookup failed for {}: {}", ip, e);
                }
                return None;
            }
        };

        match lookup_result.decode::<geoip2::Country>() {
            Ok(Some(result)) => {
                // In maxminddb 0.27+, country.iso_code is directly accessible
                let country_code = result
                    .country
                    .iso_code
                    .map(|s| s.to_string());
                trace!("GeoIP lookup {}: {:?}", ip, country_code);
                country_code
            }
            Ok(None) => {
                trace!("GeoIP lookup {}: no data", ip);
                None
            }
            Err(e) => {
                if !is_private_ip(ip) {
                    trace!("GeoIP decode failed for {}: {}", ip, e);
                }
                None
            }
        }
    }

    /// Check if an IP address is located in a specific country
    #[allow(dead_code)]
    pub fn is_country(&self, ip: IpAddr, country_code: &str) -> bool {
        self.lookup_country(ip)
            .map(|code| code.eq_ignore_ascii_case(country_code))
            .unwrap_or(false)
    }
}

/// Get the cache file path for a given URL
fn get_cache_path(config: &GeoIpConfig, url: &str) -> PathBuf {
    let cache_dir = config.get_cache_dir();

    // Generate filename from URL (use last path segment or hash)
    let filename = url
        .rsplit('/')
        .next()
        .filter(|s| s.ends_with(".mmdb") || s.ends_with(".mmdb.gz"))
        .map(|s| s.to_string())
        .unwrap_or_else(|| "geoip.mmdb".to_string());

    // Remove .gz extension if present (we'll decompress)
    let filename = filename.trim_end_matches(".gz");

    cache_dir.join(filename)
}

/// Check if we should download/update the database
fn should_download_db(cache_path: &Path, update_interval_hours: u64) -> bool {
    // If file doesn't exist, definitely download
    if !cache_path.exists() {
        return true;
    }

    // If update interval is 0, never auto-update
    if update_interval_hours == 0 {
        return false;
    }

    // Check file modification time
    let metadata = match fs::metadata(cache_path) {
        Ok(m) => m,
        Err(_) => return true,
    };

    let modified = match metadata.modified() {
        Ok(t) => t,
        Err(_) => return true,
    };

    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::MAX);

    let max_age = Duration::from_secs(update_interval_hours * 3600);

    if age > max_age {
        debug!(
            "GeoIP database is {:?} old (max: {:?}), will update",
            age, max_age
        );
        true
    } else {
        false
    }
}

/// Download mmdb file from URL
async fn download_mmdb(url: &str, cache_path: &Path, proxy_config: Option<&ProxyConfig>) -> Result<()> {
    // Create cache directory if it doesn't exist
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create cache directory: {:?}", parent))?;
    }

    // Build HTTP client with optional proxy
    let mut client_builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(300)) // 5 minutes timeout for large files
        .connect_timeout(Duration::from_secs(30))
        .use_rustls_tls();

    if let Some(proxy_cfg) = proxy_config {
        let proxy_url = &proxy_cfg.url;
        let reqwest_proxy = if proxy_url.starts_with("socks5://") {
            // reqwest requires socks5h:// for DNS resolution through proxy
            let socks_url = proxy_url.replace("socks5://", "socks5h://");
            Proxy::all(&socks_url)
                .with_context(|| format!("Invalid SOCKS5 proxy URL: {}", proxy_url))?
        } else {
            Proxy::all(proxy_url)
                .with_context(|| format!("Invalid HTTP proxy URL: {}", proxy_url))?
        };
        client_builder = client_builder.proxy(reqwest_proxy);
    }

    let client = client_builder.build()?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to download from {}", url))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "Failed to download GeoIP database: HTTP {}",
            response.status()
        );
    }

    let bytes = response
        .bytes()
        .await
        .context("Failed to read response body")?;

    info!("Downloaded {} bytes from {}", bytes.len(), url);

    // Check if it's gzipped and decompress if needed
    let data = if url.ends_with(".gz") || is_gzip(&bytes) {
        debug!("Decompressing gzipped database...");
        decompress_gzip(&bytes)?
    } else {
        bytes.to_vec()
    };

    // Write to temporary file first, then rename (atomic operation)
    let temp_path = cache_path.with_extension("mmdb.tmp");

    let mut file = fs::File::create(&temp_path)
        .with_context(|| format!("Failed to create temp file: {:?}", temp_path))?;

    file.write_all(&data)
        .context("Failed to write database file")?;

    file.sync_all()?;
    drop(file);

    // Rename to final path
    fs::rename(&temp_path, cache_path)
        .with_context(|| format!("Failed to rename {:?} to {:?}", temp_path, cache_path))?;

    info!("GeoIP database saved to: {:?}", cache_path);

    Ok(())
}

/// Check if data is gzip compressed
fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

/// Decompress gzip data
fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;

    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .context("Failed to decompress gzip data")?;

    Ok(decompressed)
}

/// Check if an IP is a private/reserved address
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                // 100.64.0.0/10 (Carrier-grade NAT)
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
            // Note: is_unique_local() and is_unicast_link_local() are unstable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ip_detection() {
        // Private IPv4
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));

        // Loopback
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
        assert!(is_private_ip("::1".parse().unwrap()));

        // Link-local
        assert!(is_private_ip("169.254.1.1".parse().unwrap()));

        // CGNAT
        assert!(is_private_ip("100.64.0.1".parse().unwrap()));
        assert!(is_private_ip("100.127.255.255".parse().unwrap()));

        // Public IP should not be private
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_cache_path_generation() {
        let config = GeoIpConfig {
            path: None,
            url: Some("https://example.com/GeoLite2-Country.mmdb".to_string()),
            proxy: None,
            cache_dir: Some("/tmp/test".to_string()),
            update_interval_hours: 24,
        };

        let path = get_cache_path(&config, config.url.as_ref().unwrap());
        assert_eq!(path, PathBuf::from("/tmp/test/GeoLite2-Country.mmdb"));
    }

    #[test]
    fn test_cache_path_with_gz() {
        let config = GeoIpConfig {
            path: None,
            url: Some("https://example.com/GeoLite2-Country.mmdb.gz".to_string()),
            proxy: None,
            cache_dir: Some("/tmp/test".to_string()),
            update_interval_hours: 24,
        };

        let path = get_cache_path(&config, config.url.as_ref().unwrap());
        assert_eq!(path, PathBuf::from("/tmp/test/GeoLite2-Country.mmdb"));
    }

    #[test]
    #[ignore] // Requires mmdb file
    fn test_geoip_lookup() {
        let geoip = GeoIpLookup::from_file("/path/to/GeoLite2-Country.mmdb").unwrap();

        // Cloudflare DNS is in the US
        let country = geoip.lookup_country("1.1.1.1".parse().unwrap());
        println!("1.1.1.1 country: {:?}", country);

        // Test CN detection
        // You would need a known CN IP to test this
    }
}
