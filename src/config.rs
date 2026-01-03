//! Configuration file structures and parsing for Resolute DNS proxy.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

/// Root configuration structure
#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub geoip: GeoIpConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub domain_list: DomainListConfig,
    #[serde(default)]
    pub proxies: HashMap<String, ProxyConfig>,
    #[serde(default)]
    pub upstreams: HashMap<String, UpstreamConfig>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    pub default: DefaultConfig,
}

/// Server listening configuration
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Addresses to listen on (e.g., ["127.0.0.1:53", "[::1]:53"])
    /// Can be a single address string or an array of addresses
    #[serde(default = "default_listen", deserialize_with = "deserialize_listen_addrs")]
    pub listen: Vec<SocketAddr>,
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_listen() -> Vec<SocketAddr> {
    vec!["127.0.0.1:53".parse().unwrap()]
}

/// Deserialize listen addresses from either a single string or an array
fn deserialize_listen_addrs<'de, D>(deserializer: D) -> std::result::Result<Vec<SocketAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, SeqAccess, Visitor};
    use std::fmt;

    struct ListenAddrsVisitor;

    impl<'de> Visitor<'de> for ListenAddrsVisitor {
        type Value = Vec<SocketAddr>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string or array of socket addresses")
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: de::Error,
        {
            let addr: SocketAddr = value.parse().map_err(de::Error::custom)?;
            Ok(vec![addr])
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut addrs = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                let addr: SocketAddr = s.parse().map_err(de::Error::custom)?;
                addrs.push(addr);
            }
            if addrs.is_empty() {
                return Err(de::Error::custom("listen address list cannot be empty"));
            }
            Ok(addrs)
        }
    }

    deserializer.deserialize_any(ListenAddrsVisitor)
}

fn default_log_level() -> String {
    "info".to_string()
}

/// GeoIP database configuration
#[derive(Debug, Deserialize)]
pub struct GeoIpConfig {
    /// Path to MaxMind mmdb file (local path)
    pub path: Option<String>,
    /// URL to download mmdb file from (will be cached locally)
    pub url: Option<String>,
    /// Proxy to use for downloading (references [proxies.xxx])
    pub proxy: Option<String>,
    /// Directory to cache downloaded mmdb file (default: ~/.cache/resolute)
    pub cache_dir: Option<String>,
    /// Auto-update interval in hours (0 = disabled, default: 24)
    #[serde(default = "default_update_interval")]
    pub update_interval_hours: u64,
}

fn default_update_interval() -> u64 {
    24
}

impl GeoIpConfig {
    /// Validate that either path or url is specified
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.path.is_none() && self.url.is_none() {
            anyhow::bail!("GeoIP config must specify either 'path' or 'url'");
        }
        Ok(())
    }

    /// Get the cache directory path
    pub fn get_cache_dir(&self) -> std::path::PathBuf {
        if let Some(ref dir) = self.cache_dir {
            std::path::PathBuf::from(dir)
        } else {
            dirs::cache_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("resolute")
        }
    }
}

/// DNS cache configuration
#[derive(Debug, Clone, Deserialize)]
pub struct CacheConfig {
    /// Enable DNS caching (default: true)
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,
    /// Maximum number of cached entries (default: 10000)
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: u64,
    /// Minimum TTL in seconds (default: 60)
    #[serde(default = "default_cache_min_ttl")]
    pub min_ttl: u32,
    /// Maximum TTL in seconds (default: 86400 = 24 hours)
    #[serde(default = "default_cache_max_ttl")]
    pub max_ttl: u32,
    /// TTL for negative responses (NXDOMAIN, etc.) in seconds (default: 300)
    #[serde(default = "default_cache_negative_ttl")]
    pub negative_ttl: u32,
}

fn default_cache_enabled() -> bool {
    true
}

fn default_cache_max_entries() -> u64 {
    10000
}

fn default_cache_min_ttl() -> u32 {
    60
}

fn default_cache_max_ttl() -> u32 {
    86400
}

fn default_cache_negative_ttl() -> u32 {
    300
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            max_entries: default_cache_max_entries(),
            min_ttl: default_cache_min_ttl(),
            max_ttl: default_cache_max_ttl(),
            negative_ttl: default_cache_negative_ttl(),
        }
    }
}

/// Domain list configuration for v2fly/domain-list-community
#[derive(Debug, Deserialize)]
pub struct DomainListConfig {
    /// URL for geosite dat file
    /// Default: https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat.xz
    #[serde(default = "default_domain_list_url")]
    pub url: String,
    /// Proxy to use for downloading (references [proxies.xxx])
    pub proxy: Option<String>,
    /// Cache directory for downloaded domain lists
    pub cache_dir: Option<String>,
    /// Update interval in hours (0 = no caching)
    #[serde(default = "default_domain_list_update_interval")]
    pub update_interval_hours: u64,
}

fn default_domain_list_url() -> String {
    "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat.xz".to_string()
}

fn default_domain_list_update_interval() -> u64 {
    24
}

impl Default for DomainListConfig {
    fn default() -> Self {
        Self {
            url: default_domain_list_url(),
            proxy: None,
            cache_dir: None,
            update_interval_hours: default_domain_list_update_interval(),
        }
    }
}

impl DomainListConfig {
    /// Get the cache directory path
    pub fn get_cache_dir(&self) -> std::path::PathBuf {
        if let Some(ref dir) = self.cache_dir {
            std::path::PathBuf::from(dir)
        } else {
            dirs::cache_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("resolute")
                .join("domain-lists")
        }
    }
}

/// Proxy server configuration
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// Proxy server URL (e.g., "http://127.0.0.1:8080" or "socks5://127.0.0.1:1080")
    pub url: String,
    /// Outbound IP address of this proxy (for EDNS Client Subnet)
    pub outbound_ip: IpAddr,
    /// Optional description
    #[serde(default)]
    #[allow(dead_code)]
    pub description: Option<String>,
}

impl ProxyConfig {
    /// Parse proxy URL and return type and address
    pub fn parse_url(&self) -> Result<ProxyType> {
        if self.url.starts_with("http://") {
            let addr = self.url.strip_prefix("http://").unwrap();
            Ok(ProxyType::Http(addr.to_string()))
        } else if self.url.starts_with("https://") {
            let addr = self.url.strip_prefix("https://").unwrap();
            Ok(ProxyType::Https(addr.to_string()))
        } else if self.url.starts_with("socks5://") {
            let addr = self.url.strip_prefix("socks5://").unwrap();
            Ok(ProxyType::Socks5(addr.to_string()))
        } else {
            anyhow::bail!(
                "Invalid proxy URL '{}'. Must start with http://, https://, or socks5://",
                self.url
            )
        }
    }
}

/// Parsed proxy type
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ProxyType {
    Http(String),
    Https(String),
    Socks5(String),
}

/// Upstream DNS server configuration
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum UpstreamConfig {
    /// DNS over HTTPS
    Doh {
        /// Full URL (e.g., "https://1.1.1.1/dns-query")
        url: String,
        /// Proxy to use for this upstream (reference to [proxies.xxx])
        proxy: Option<String>,
        /// EDNS client IP mode
        #[serde(default)]
        edns_client_ip: EdnsClientIp,
    },
    /// DNS over TLS
    Dot {
        /// Server address with port (e.g., "9.9.9.9:853")
        server: String,
        /// TLS hostname for certificate verification
        hostname: String,
        /// Proxy to use for this upstream (only socks5 supported for DOT)
        proxy: Option<String>,
        /// EDNS client IP mode
        #[serde(default)]
        edns_client_ip: EdnsClientIp,
    },
}

impl UpstreamConfig {
    pub fn edns_client_ip(&self) -> &EdnsClientIp {
        match self {
            UpstreamConfig::Doh { edns_client_ip, .. } => edns_client_ip,
            UpstreamConfig::Dot { edns_client_ip, .. } => edns_client_ip,
        }
    }

    pub fn proxy(&self) -> Option<&String> {
        match self {
            UpstreamConfig::Doh { proxy, .. } => proxy.as_ref(),
            UpstreamConfig::Dot { proxy, .. } => proxy.as_ref(),
        }
    }
}

/// EDNS Client Subnet IP source
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EdnsClientIp {
    /// Use local machine's IP
    Local,
    /// Don't send EDNS Client Subnet
    #[default]
    None,
    /// Use the proxy's outbound IP (auto, uses the proxy configured for upstream)
    Proxy,
    /// Use a specific IP address with optional prefix (e.g., "1.2.3.4" or "120.76.0.0/14")
    #[serde(untagged)]
    Custom(EdnsSubnet),
}

/// EDNS Client Subnet with IP and optional prefix length
#[derive(Debug, Clone, PartialEq)]
pub struct EdnsSubnet {
    pub ip: IpAddr,
    pub prefix_len: Option<u8>,
}

impl<'de> Deserialize<'de> for EdnsSubnet {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        // Try to parse as CIDR (e.g., "120.76.0.0/14")
        if let Some((ip_str, prefix_str)) = s.split_once('/') {
            let ip: IpAddr = ip_str.parse()
                .map_err(|e| serde::de::Error::custom(format!("Invalid IP address '{}': {}", ip_str, e)))?;
            let prefix_len: u8 = prefix_str.parse()
                .map_err(|e| serde::de::Error::custom(format!("Invalid prefix length '{}': {}", prefix_str, e)))?;

            // Validate prefix length
            let max_prefix = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix_len > max_prefix {
                return Err(serde::de::Error::custom(format!(
                    "Prefix length {} exceeds maximum {} for {:?}",
                    prefix_len, max_prefix, ip
                )));
            }

            Ok(EdnsSubnet { ip, prefix_len: Some(prefix_len) })
        } else {
            // Parse as plain IP address
            let ip: IpAddr = s.parse()
                .map_err(|e| serde::de::Error::custom(format!("Invalid IP address '{}': {}", s, e)))?;
            Ok(EdnsSubnet { ip, prefix_len: None })
        }
    }
}

/// Routing rule for domain matching
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    /// Domain suffixes to match (e.g., [".cn", ".baidu.com"])
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    /// Domain keywords to match
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    /// Exact domains to match
    #[serde(default)]
    pub domain: Vec<String>,
    /// Domain list names to load from v2fly/domain-list-community
    /// (e.g., ["cn", "google", "geolocation-!cn"])
    #[serde(default)]
    pub domain_list: Vec<String>,
    /// Local file paths containing domain lists
    #[serde(default)]
    pub domain_list_file: Vec<String>,
    /// Upstream name to use when matched
    pub upstream: String,
    /// Override proxy for this rule (reference to [proxies.xxx])
    pub proxy: Option<String>,
    /// Override EDNS client IP for this rule
    pub edns_client_ip: Option<EdnsClientIp>,
}

/// Default/fallback routing configuration
#[derive(Debug, Deserialize)]
pub struct DefaultConfig {
    /// Default upstream (used when no rule matches)
    pub upstream: String,
    /// Default proxy (optional)
    pub proxy: Option<String>,
    /// Default EDNS client IP mode
    #[serde(default)]
    pub edns_client_ip: EdnsClientIp,
    /// Local IP to use for EDNS (auto-detected if not specified)
    pub local_ip: Option<IpAddr>,
}

impl Config {
    /// Load configuration from a TOML file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
        Self::parse(&content)
    }

    /// Parse configuration from TOML string
    pub fn parse(content: &str) -> Result<Self> {
        let config: Config = toml::from_str(content).context("Failed to parse TOML config")?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration
    fn validate(&self) -> Result<()> {
        // Validate GeoIP config
        self.geoip.validate()?;

        // Validate proxy URLs
        for (name, proxy) in &self.proxies {
            proxy.parse_url()
                .with_context(|| format!("Invalid proxy '{}'", name))?;
        }

        // Check that all referenced upstreams exist
        for rule in &self.rules {
            if !self.upstreams.contains_key(&rule.upstream) {
                anyhow::bail!(
                    "Rule references unknown upstream '{}'. Available: {:?}",
                    rule.upstream,
                    self.upstreams.keys().collect::<Vec<_>>()
                );
            }
            // Check proxy references in rules
            if let Some(ref proxy_name) = rule.proxy {
                if !self.proxies.contains_key(proxy_name) {
                    anyhow::bail!(
                        "Rule references unknown proxy '{}'. Available: {:?}",
                        proxy_name,
                        self.proxies.keys().collect::<Vec<_>>()
                    );
                }
            }
        }

        // Check default upstream
        if !self.upstreams.contains_key(&self.default.upstream) {
            anyhow::bail!(
                "Default upstream '{}' not found in upstreams",
                self.default.upstream
            );
        }

        // Check proxy reference in default config
        if let Some(ref proxy_name) = self.default.proxy {
            if !self.proxies.contains_key(proxy_name) {
                anyhow::bail!(
                    "Default proxy '{}' not found in proxies",
                    proxy_name
                );
            }
        }

        // Check proxy reference in domain_list config
        if let Some(ref proxy_name) = self.domain_list.proxy {
            if !self.proxies.contains_key(proxy_name) {
                anyhow::bail!(
                    "domain_list.proxy '{}' not found in proxies. Available: {:?}",
                    proxy_name,
                    self.proxies.keys().collect::<Vec<_>>()
                );
            }
        }

        // Check proxy reference in geoip config
        if let Some(ref proxy_name) = self.geoip.proxy {
            if !self.proxies.contains_key(proxy_name) {
                anyhow::bail!(
                    "geoip.proxy '{}' not found in proxies. Available: {:?}",
                    proxy_name,
                    self.proxies.keys().collect::<Vec<_>>()
                );
            }
        }

        // Check proxy references in upstreams
        for (name, upstream) in &self.upstreams {
            if let Some(proxy_name) = upstream.proxy() {
                if !self.proxies.contains_key(proxy_name) {
                    anyhow::bail!(
                        "Upstream '{}' references unknown proxy '{}'. Available: {:?}",
                        name,
                        proxy_name,
                        self.proxies.keys().collect::<Vec<_>>()
                    );
                }
            }
        }

        Ok(())
    }

    /// Get the EDNS Client Subnet based on the mode
    pub fn resolve_edns_subnet(&self, mode: &EdnsClientIp, proxy_name: Option<&str>) -> Option<EdnsSubnet> {
        match mode {
            EdnsClientIp::None => None,
            EdnsClientIp::Local => self.default.local_ip.map(|ip| EdnsSubnet { ip, prefix_len: None }),
            EdnsClientIp::Proxy => {
                // Use the proxy's outbound IP
                proxy_name
                    .and_then(|name| self.proxies.get(name))
                    .map(|p| EdnsSubnet { ip: p.outbound_ip, prefix_len: None })
            }
            EdnsClientIp::Custom(subnet) => Some(subnet.clone()),
        }
    }

    /// Get proxy config by name
    #[allow(dead_code)]
    pub fn get_proxy(&self, name: &str) -> Option<&ProxyConfig> {
        self.proxies.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let toml = r#"
[server]
listen = "127.0.0.1:5353"
log_level = "debug"

[geoip]
path = "/path/to/GeoLite2-Country.mmdb"

[proxies.hk]
url = "http://127.0.0.1:8080"
outbound_ip = "1.2.3.4"
description = "Hong Kong proxy"

[proxies.us]
url = "socks5://127.0.0.1:1080"
outbound_ip = "5.6.7.8"

[upstreams.cloudflare]
type = "doh"
url = "https://1.1.1.1/dns-query"
proxy = "us"
edns_client_ip = "proxy"

[upstreams.alidns]
type = "doh"
url = "https://dns.alidns.com/dns-query"
edns_client_ip = "local"

[upstreams.quad9]
type = "dot"
server = "9.9.9.9:853"
hostname = "dns.quad9.net"
proxy = "us"

[[rules]]
domain_suffix = [".cn", ".baidu.com"]
upstream = "alidns"

[[rules]]
domain = ["google.com"]
domain_keyword = ["github"]
upstream = "cloudflare"
proxy = "hk"
edns_client_ip = "proxy"

[default]
upstream = "cloudflare"
proxy = "us"
edns_client_ip = "proxy"
"#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.server.listen[0].port(), 5353);
        assert_eq!(config.upstreams.len(), 3);
        assert_eq!(config.proxies.len(), 2);
        assert_eq!(config.rules.len(), 2);

        // Test default config
        assert_eq!(config.default.upstream, "cloudflare");
        assert_eq!(config.default.proxy, Some("us".to_string()));

        // Test proxy resolution
        let us_subnet = config.resolve_edns_subnet(&EdnsClientIp::Proxy, Some("us"));
        assert_eq!(us_subnet.map(|s| s.ip), Some("5.6.7.8".parse().unwrap()));
    }

    #[test]
    fn test_proxy_url_parsing() {
        let http_proxy = ProxyConfig {
            url: "http://127.0.0.1:8080".to_string(),
            outbound_ip: "1.2.3.4".parse().unwrap(),
            description: None,
        };
        assert!(matches!(http_proxy.parse_url().unwrap(), ProxyType::Http(_)));

        let socks5_proxy = ProxyConfig {
            url: "socks5://127.0.0.1:1080".to_string(),
            outbound_ip: "1.2.3.4".parse().unwrap(),
            description: None,
        };
        assert!(matches!(socks5_proxy.parse_url().unwrap(), ProxyType::Socks5(_)));
    }

    #[test]
    fn test_invalid_proxy_reference() {
        let toml = r#"
[server]
listen = "127.0.0.1:53"

[geoip]
path = "/path/to/db.mmdb"

[upstreams.alidns]
type = "doh"
url = "https://dns.alidns.com/dns-query"
proxy = "nonexistent"

[default]
upstream = "alidns"
"#;

        let result = Config::parse(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn test_invalid_upstream_reference() {
        let toml = r#"
[server]
listen = "127.0.0.1:53"

[geoip]
path = "/path/to/db.mmdb"

[upstreams.alidns]
type = "doh"
url = "https://dns.alidns.com/dns-query"

[[rules]]
domain_suffix = [".cn"]
upstream = "nonexistent"

[default]
upstream = "alidns"
"#;

        let result = Config::parse(toml);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn test_simple_config() {
        // Test minimal config with just default upstream
        let toml = r#"
[server]
listen = "127.0.0.1:53"

[geoip]
path = "/path/to/db.mmdb"

[upstreams.cloudflare]
type = "doh"
url = "https://1.1.1.1/dns-query"

[default]
upstream = "cloudflare"
"#;

        let config = Config::parse(toml).unwrap();
        assert_eq!(config.default.upstream, "cloudflare");
        assert_eq!(config.default.proxy, None);
    }
}
