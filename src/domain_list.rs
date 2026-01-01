//! Domain list loader for v2fly/domain-list-community format.
//!
//! Supports loading domain lists from:
//! - dlc.dat (protobuf format, recommended)
//! - Local text files
//!
//! Format: https://github.com/v2fly/domain-list-community

use anyhow::{Context, Result};
use prost::Message;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::{debug, info, warn};
use xz2::read::XzDecoder;

// ============================================================================
// Protobuf definitions for v2fly geosite.dat format
// See: https://github.com/v2fly/v2ray-core/blob/master/app/router/routercommon/common.proto
// ============================================================================

/// Domain type in geosite
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum DomainType {
    Plain = 0,   // keyword match
    Regex = 1,   // regex match
    Domain = 2,  // domain suffix match
    Full = 3,    // exact match
}

/// Domain entry in geosite
#[derive(Clone, PartialEq, prost::Message)]
pub struct ProtoDomain {
    #[prost(enumeration = "DomainType", tag = "1")]
    pub domain_type: i32,
    #[prost(string, tag = "2")]
    pub value: String,
    #[prost(message, repeated, tag = "3")]
    pub attribute: Vec<ProtoAttribute>,
}

/// Domain attribute
#[derive(Clone, PartialEq, prost::Message)]
pub struct ProtoAttribute {
    #[prost(string, tag = "1")]
    pub key: String,
    #[prost(oneof = "AttributeValue", tags = "2, 3")]
    pub typed_value: Option<AttributeValue>,
}

#[derive(Clone, PartialEq, prost::Oneof)]
pub enum AttributeValue {
    #[prost(bool, tag = "2")]
    BoolValue(bool),
    #[prost(int64, tag = "3")]
    IntValue(i64),
}

/// GeoSite entry (one country/category)
#[derive(Clone, PartialEq, prost::Message)]
pub struct ProtoGeoSite {
    #[prost(string, tag = "1")]
    pub country_code: String,
    #[prost(message, repeated, tag = "2")]
    pub domain: Vec<ProtoDomain>,
}

/// GeoSite list (the entire dat file)
#[derive(Clone, PartialEq, prost::Message)]
pub struct ProtoGeoSiteList {
    #[prost(message, repeated, tag = "1")]
    pub entry: Vec<ProtoGeoSite>,
}

// ============================================================================
// Domain list structures
// ============================================================================

/// Parsed domain list
#[derive(Debug, Default, Clone)]
pub struct DomainList {
    /// Exact domain matches (full:)
    pub domains: Vec<String>,
    /// Domain suffix matches (domain:)
    pub domain_suffixes: Vec<String>,
    /// Keyword matches (keyword:)
    pub keywords: Vec<String>,
    /// Regex patterns (regexp:) - stored as strings
    pub regexps: Vec<String>,
}

impl DomainList {
    /// Create a new empty domain list
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if the list is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
            && self.domain_suffixes.is_empty()
            && self.keywords.is_empty()
            && self.regexps.is_empty()
    }

    /// Get total count of rules
    pub fn len(&self) -> usize {
        self.domains.len() + self.domain_suffixes.len() + self.keywords.len() + self.regexps.len()
    }

    /// Merge another domain list into this one
    pub fn merge(&mut self, other: DomainList) {
        self.domains.extend(other.domains);
        self.domain_suffixes.extend(other.domain_suffixes);
        self.keywords.extend(other.keywords);
        self.regexps.extend(other.regexps);
    }

    /// Deduplicate entries
    pub fn deduplicate(&mut self) {
        dedup_vec(&mut self.domains);
        dedup_vec(&mut self.domain_suffixes);
        dedup_vec(&mut self.keywords);
        dedup_vec(&mut self.regexps);
    }
}

fn dedup_vec(v: &mut Vec<String>) {
    let set: HashSet<_> = v.drain(..).collect();
    v.extend(set);
}

// ============================================================================
// Domain list loader
// ============================================================================

/// Domain list loader with caching support
pub struct DomainListLoader {
    dat_url: String,
    proxy_url: Option<String>,
    cache_dir: PathBuf,
    update_interval: Duration,
    /// Loaded geosite data (lazy loaded)
    geosite_cache: Option<HashMap<String, DomainList>>,
}

impl DomainListLoader {
    /// Create a new loader with dat URL and cache directory
    pub fn new(
        dat_url: String,
        proxy_url: Option<String>,
        cache_dir: PathBuf,
        update_interval_hours: u64,
    ) -> Self {
        Self {
            dat_url,
            proxy_url,
            cache_dir,
            update_interval: Duration::from_secs(update_interval_hours * 3600),
            geosite_cache: None,
        }
    }

    /// Load a domain list by name (e.g., "cn", "google", "geolocation-!cn")
    pub async fn load(&mut self, name: &str) -> Result<DomainList> {
        // Ensure geosite data is loaded
        if self.geosite_cache.is_none() {
            self.load_geosite_dat().await?;
        }

        // Look up in cache
        let name_lower = name.to_lowercase();
        if let Some(cache) = &self.geosite_cache {
            if let Some(list) = cache.get(&name_lower) {
                debug!(
                    "Found domain list '{}': {} domains, {} suffixes, {} keywords",
                    name,
                    list.domains.len(),
                    list.domain_suffixes.len(),
                    list.keywords.len()
                );
                return Ok(list.clone());
            }
        }

        // List available names for debugging
        if let Some(cache) = &self.geosite_cache {
            let available: Vec<_> = cache.keys().take(10).collect();
            warn!(
                "Domain list '{}' not found. Available lists (first 10): {:?}",
                name, available
            );
        }

        anyhow::bail!("Domain list '{}' not found in geosite.dat", name)
    }

    /// Load geosite.dat file
    async fn load_geosite_dat(&mut self) -> Result<()> {
        let cache_file = self.cache_dir.join("dlc.dat");

        // Check if cache is fresh
        let need_download = if self.update_interval.as_secs() > 0 && cache_file.exists() {
            if let Ok(metadata) = fs::metadata(&cache_file) {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(elapsed) = modified.elapsed() {
                        elapsed >= self.update_interval
                    } else {
                        true
                    }
                } else {
                    true
                }
            } else {
                true
            }
        } else {
            !cache_file.exists()
        };

        if need_download {
            self.download_geosite_dat(&cache_file).await?;
        } else {
            info!("Using cached geosite.dat: {}", cache_file.display());
        }

        // Parse the dat file
        self.parse_geosite_dat(&cache_file)?;
        Ok(())
    }

    /// Download geosite.dat from URL
    async fn download_geosite_dat(&self, cache_file: &Path) -> Result<()> {
        let proxy_info = self.proxy_url.as_deref().unwrap_or("direct");
        info!(
            "Downloading domain list from: {} via {}",
            self.dat_url, proxy_info
        );

        fs::create_dir_all(&self.cache_dir)
            .context("Failed to create cache directory")?;

        // Build HTTP client with optional proxy
        let client = if let Some(ref proxy_url) = self.proxy_url {
            let proxy = if proxy_url.starts_with("socks5://") {
                // reqwest uses socks5h for DNS resolution through proxy
                let socks_url = proxy_url.replace("socks5://", "socks5h://");
                reqwest::Proxy::all(&socks_url)
                    .with_context(|| format!("Invalid SOCKS5 proxy URL: {}", proxy_url))?
            } else {
                reqwest::Proxy::all(proxy_url)
                    .with_context(|| format!("Invalid proxy URL: {}", proxy_url))?
            };
            reqwest::Client::builder()
                .proxy(proxy)
                .build()
                .context("Failed to create HTTP client with proxy")?
        } else {
            reqwest::Client::new()
        };

        let response = client
            .get(&self.dat_url)
            .send()
            .await
            .with_context(|| format!("Failed to download {}", self.dat_url))?
            .error_for_status()
            .with_context(|| format!("HTTP error downloading {}", self.dat_url))?;

        let content = response.bytes().await?;
        let download_size = content.len();
        info!("Downloaded {} bytes via {}", download_size, proxy_info);

        // Decompress if xz
        let decompressed = if self.dat_url.ends_with(".xz") {
            info!("Decompressing xz archive...");
            let mut decoder = XzDecoder::new(&content[..]);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)
                .context("Failed to decompress xz archive")?;
            info!(
                "Decompressed: {} KB -> {} KB",
                download_size / 1024,
                decompressed.len() / 1024
            );
            decompressed
        } else {
            content.to_vec()
        };

        // Write to cache (atomic write via temp file)
        let temp_file = cache_file.with_extension("tmp");
        fs::write(&temp_file, &decompressed)
            .context("Failed to write temp cache file")?;
        fs::rename(&temp_file, cache_file)
            .context("Failed to rename cache file")?;

        info!("Domain list cached to: {}", cache_file.display());
        Ok(())
    }

    /// Parse geosite.dat protobuf file
    fn parse_geosite_dat(&mut self, path: &Path) -> Result<()> {
        let data = fs::read(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        let geosite_list = ProtoGeoSiteList::decode(&data[..])
            .context("Failed to parse geosite.dat protobuf")?;

        let mut cache = HashMap::new();
        for entry in geosite_list.entry {
            let name = entry.country_code.to_lowercase();
            let mut list = DomainList::new();

            for domain in entry.domain {
                let value = domain.value.to_lowercase();
                match DomainType::try_from(domain.domain_type) {
                    Ok(DomainType::Full) => list.domains.push(value),
                    Ok(DomainType::Domain) => list.domain_suffixes.push(value),
                    Ok(DomainType::Plain) => list.keywords.push(value),
                    Ok(DomainType::Regex) => list.regexps.push(domain.value),
                    Err(_) => {} // Unknown type, skip
                }
            }

            cache.insert(name, list);
        }

        info!("Loaded {} domain lists from geosite.dat", cache.len());
        self.geosite_cache = Some(cache);
        Ok(())
    }

    /// Load from a local text file (v2fly format)
    pub fn load_file<P: AsRef<Path>>(&self, path: P) -> Result<DomainList> {
        self.parse_text_file(path.as_ref())
    }

    /// Parse a text format domain list file
    fn parse_text_file(&self, path: &Path) -> Result<DomainList> {
        let file = fs::File::open(path)
            .with_context(|| format!("Failed to open {}", path.display()))?;
        let reader = BufReader::new(file);
        self.parse_text_reader(reader, path)
    }

    /// Parse from a reader (text format)
    fn parse_text_reader<R: Read>(&self, reader: BufReader<R>, source: &Path) -> Result<DomainList> {
        let mut list = DomainList::new();
        let base_dir = source.parent().unwrap_or(Path::new("."));

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Remove inline comments and attributes
            let line = line.split('#').next().unwrap_or(line).trim();
            let line = line.split('@').next().unwrap_or(line).trim();

            if line.is_empty() {
                continue;
            }

            // Parse line
            if let Some(included) = line.strip_prefix("include:") {
                // Include another file
                let include_path = base_dir.join(included.trim());
                if include_path.exists() {
                    match self.parse_text_file(&include_path) {
                        Ok(included_list) => list.merge(included_list),
                        Err(e) => warn!("Failed to include {}: {}", included, e),
                    }
                } else {
                    debug!("Include file not found locally, skipping: {}", included);
                }
            } else if let Some(domain) = line.strip_prefix("full:") {
                list.domains.push(domain.trim().to_lowercase());
            } else if let Some(domain) = line.strip_prefix("domain:") {
                list.domain_suffixes.push(domain.trim().to_lowercase());
            } else if let Some(keyword) = line.strip_prefix("keyword:") {
                list.keywords.push(keyword.trim().to_lowercase());
            } else if let Some(regexp) = line.strip_prefix("regexp:") {
                list.regexps.push(regexp.trim().to_string());
            } else {
                // Default is domain suffix (as per v2fly format)
                list.domain_suffixes.push(line.to_lowercase());
            }
        }

        list.deduplicate();
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_text_domain_list_format() {
        let content = r#"
# This is a comment
include:another-file
domain:google.com
full:www.example.com
keyword:facebook
regexp:^ads\..*\.com$
baidu.com
taobao.com @cn
"#;

        let loader = DomainListLoader::new(
            "https://example.com/dlc.dat".to_string(),
            None, // No proxy
            PathBuf::from("/tmp"),
            0,
        );

        let reader = BufReader::new(content.as_bytes());
        let list = loader.parse_text_reader(reader, Path::new("/tmp/test.txt")).unwrap();

        assert!(list.domain_suffixes.contains(&"google.com".to_string()));
        assert!(list.domain_suffixes.contains(&"baidu.com".to_string()));
        assert!(list.domain_suffixes.contains(&"taobao.com".to_string()));
        assert!(list.domains.contains(&"www.example.com".to_string()));
        assert!(list.keywords.contains(&"facebook".to_string()));
        assert!(list.regexps.contains(&"^ads\\..*\\.com$".to_string()));
    }
}
