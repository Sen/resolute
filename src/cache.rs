//! DNS response caching using moka.
//!
//! Caches DNS responses with TTL-based expiration.

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{Record, RecordType};
use moka::future::Cache;
use moka::Expiry;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, trace};

use crate::config::CacheConfig;

/// Cache key: (domain_name, query_type)
type CacheKey = (String, RecordType);

/// Cached DNS response data with expiration info
#[derive(Clone, Debug)]
struct CachedResponse {
    /// Answer records
    answers: Vec<Record>,
    /// Response code
    response_code: ResponseCode,
    /// TTL for this entry (seconds)
    ttl_secs: u32,
}

/// Custom expiry policy that uses per-entry TTL
struct DnsExpiry;

impl Expiry<CacheKey, CachedResponse> for DnsExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CachedResponse,
        _current_time: Instant,
    ) -> Option<Duration> {
        Some(Duration::from_secs(value.ttl_secs as u64))
    }
}

/// DNS response cache
pub struct DnsCache {
    cache: Cache<CacheKey, CachedResponse>,
    config: CacheConfig,
    /// Cache statistics
    hits: AtomicU64,
    misses: AtomicU64,
}

impl DnsCache {
    /// Create a new DNS cache from configuration
    pub fn new(config: CacheConfig) -> Self {
        let cache = Cache::builder()
            .max_capacity(config.max_entries)
            // Use custom expiry policy for per-entry TTL
            .expire_after(DnsExpiry)
            .build();

        debug!(
            "DNS cache initialized: max_entries={}, min_ttl={}s, max_ttl={}s, negative_ttl={}s",
            config.max_entries, config.min_ttl, config.max_ttl, config.negative_ttl
        );

        Self {
            cache,
            config,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Create a disabled cache (always misses)
    pub fn disabled() -> Self {
        Self {
            cache: Cache::builder().max_capacity(0).expire_after(DnsExpiry).build(),
            config: CacheConfig::default(),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Check if caching is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && self.config.max_entries > 0
    }

    /// Look up a cached response
    pub async fn get(&self, query_name: &str, query_type: RecordType) -> Option<Message> {
        if !self.is_enabled() {
            return None;
        }

        let key = Self::make_key(query_name, query_type);

        if let Some(cached) = self.cache.get(&key).await {
            self.hits.fetch_add(1, Ordering::Relaxed);
            trace!("Cache HIT: {} {:?}", query_name, query_type);

            // Reconstruct response message
            let mut response = Message::new();
            response.set_response_code(cached.response_code);
            response.set_message_type(hickory_proto::op::MessageType::Response);

            for record in &cached.answers {
                response.add_answer(record.clone());
            }

            return Some(response);
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        trace!("Cache MISS: {} {:?}", query_name, query_type);
        None
    }

    /// Store a response in the cache
    pub async fn put(&self, query_name: &str, query_type: RecordType, response: &Message) {
        if !self.is_enabled() {
            return;
        }

        let key = Self::make_key(query_name, query_type);

        // Calculate TTL from response records
        let ttl = self.calculate_ttl(response);

        if ttl == 0 {
            trace!("Not caching {} {:?}: TTL is 0", query_name, query_type);
            return;
        }

        let cached = CachedResponse {
            answers: response.answers().to_vec(),
            response_code: response.response_code(),
            ttl_secs: ttl,
        };

        // Insert (TTL is handled by custom expiry policy)
        self.cache.insert(key, cached).await;

        trace!(
            "Cached {} {:?} for {}s ({} records)",
            query_name,
            query_type,
            ttl,
            response.answers().len()
        );
    }

    /// Calculate TTL for caching based on response
    fn calculate_ttl(&self, response: &Message) -> u32 {
        // For NXDOMAIN or other errors, use negative TTL
        if response.response_code() != ResponseCode::NoError {
            return self.config.negative_ttl;
        }

        // If no answers, use negative TTL
        if response.answers().is_empty() {
            return self.config.negative_ttl;
        }

        // Find minimum TTL from all answer records
        let min_ttl = response
            .answers()
            .iter()
            .map(|r| r.ttl())
            .min()
            .unwrap_or(0);

        // Clamp to configured range
        min_ttl.clamp(self.config.min_ttl, self.config.max_ttl)
    }

    /// Create cache key from query name and type
    fn make_key(query_name: &str, query_type: RecordType) -> CacheKey {
        // Normalize: lowercase, remove trailing dot
        let normalized = query_name.to_lowercase();
        let normalized = normalized.trim_end_matches('.');
        (normalized.to_string(), query_type)
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entries: self.cache.entry_count(),
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
}

impl CacheStats {
    /// Calculate hit rate percentage
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn create_test_response(domain: &str, ip: Ipv4Addr, ttl: u32) -> Message {
        let mut response = Message::new();
        response.set_response_code(ResponseCode::NoError);
        response.set_message_type(hickory_proto::op::MessageType::Response);

        let name = Name::from_str(domain).unwrap();
        let record = Record::from_rdata(name, ttl, RData::A(ip.into()));
        response.add_answer(record);

        response
    }

    #[tokio::test]
    async fn test_cache_hit_miss() {
        let config = CacheConfig {
            enabled: true,
            max_entries: 100,
            min_ttl: 10,
            max_ttl: 3600,
            negative_ttl: 60,
        };
        let cache = DnsCache::new(config);

        // Initial lookup should miss
        let result = cache.get("example.com", RecordType::A).await;
        assert!(result.is_none());

        // Store a response
        let response = create_test_response("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        cache.put("example.com", RecordType::A, &response).await;

        // Should now hit
        let result = cache.get("example.com", RecordType::A).await;
        assert!(result.is_some());

        // Different query type should miss
        let result = cache.get("example.com", RecordType::AAAA).await;
        assert!(result.is_none());

        // Check stats
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 2);
    }

    #[tokio::test]
    async fn test_cache_disabled() {
        let config = CacheConfig {
            enabled: false,
            ..Default::default()
        };
        let cache = DnsCache::new(config);

        let response = create_test_response("example.com", Ipv4Addr::new(1, 2, 3, 4), 300);
        cache.put("example.com", RecordType::A, &response).await;

        // Should always miss when disabled
        let result = cache.get("example.com", RecordType::A).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_ttl_clamping() {
        let config = CacheConfig {
            enabled: true,
            max_entries: 100,
            min_ttl: 60,
            max_ttl: 300,
            negative_ttl: 30,
        };
        let cache = DnsCache::new(config);

        // Response with TTL below min
        let response = create_test_response("low-ttl.com", Ipv4Addr::new(1, 2, 3, 4), 10);
        let ttl = cache.calculate_ttl(&response);
        assert_eq!(ttl, 60); // Clamped to min

        // Response with TTL above max
        let response = create_test_response("high-ttl.com", Ipv4Addr::new(1, 2, 3, 4), 86400);
        let ttl = cache.calculate_ttl(&response);
        assert_eq!(ttl, 300); // Clamped to max
    }
}

