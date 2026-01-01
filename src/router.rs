//! DNS routing engine with rule-based upstream selection.

use anyhow::{Context, Result};
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, trace, warn};

use crate::cache::DnsCache;
use crate::config::{Config, EdnsClientIp, EdnsSubnet, Rule, UpstreamConfig};
use crate::domain_list::{DomainList, DomainListLoader};
use crate::edns::extract_response_ips;
use crate::geoip::GeoIpLookup;
use crate::upstream::{DohClient, DotClient, UpstreamClient};

/// Routing decision containing upstream, proxy, and EDNS configuration
#[derive(Debug, Clone)]
pub struct RoutingDecision {
    pub upstream_name: String,
    pub proxy_name: Option<String>,
    pub edns_subnet: Option<EdnsSubnet>,
    /// How the rule was matched
    pub match_info: Option<MatchInfo>,
}

/// Information about how a rule was matched
#[derive(Debug, Clone)]
pub struct MatchInfo {
    /// Match type (domain, domain_suffix, domain_keyword, domain_list)
    pub match_type: String,
    /// The value that matched
    pub matched_value: String,
    /// Rule index (1-based for display)
    pub rule_index: usize,
}

/// Compiled rule with loaded domain lists
struct CompiledRule {
    /// Original rule reference
    rule: Rule,
    /// Loaded domain list (merged from domain_list and domain_list_file)
    loaded_domains: DomainList,
    /// Rule index (for logging)
    rule_index: usize,
}

/// DNS Router that handles rule matching and upstream selection
pub struct Router {
    config: Arc<Config>,
    /// Map of (upstream_name, proxy_name) -> client
    /// proxy_name is "" for direct connections
    upstreams: HashMap<(String, String), Arc<dyn UpstreamClient>>,
    geoip: Arc<GeoIpLookup>,
    /// Compiled rules with loaded domain lists
    compiled_rules: Vec<CompiledRule>,
    /// DNS response cache
    cache: DnsCache,
}

impl Router {
    /// Create a new router from configuration (loads domain lists from URLs)
    pub async fn new(config: Config, geoip: GeoIpLookup) -> Result<Self> {
        let config = Arc::new(config);
        let mut upstreams: HashMap<(String, String), Arc<dyn UpstreamClient>> = HashMap::new();

        // Collect all proxy combinations we need to create
        let mut needed_combinations: Vec<(String, Option<String>)> = Vec::new();

        // From upstreams config
        for (name, upstream_config) in &config.upstreams {
            needed_combinations.push((name.clone(), upstream_config.proxy().cloned()));
        }

        // From rules (proxy overrides)
        for rule in &config.rules {
            if rule.proxy.is_some() {
                needed_combinations.push((rule.upstream.clone(), rule.proxy.clone()));
            }
        }

        // From default config
        needed_combinations.push((
            config.default.upstream.clone(),
            config.default.proxy.clone(),
        ));

        // Create upstream clients for each combination
        for (upstream_name, proxy_name) in needed_combinations {
            let key = (upstream_name.clone(), proxy_name.clone().unwrap_or_default());
            if upstreams.contains_key(&key) {
                continue;
            }

            let upstream_config = config.upstreams.get(&upstream_name)
                .with_context(|| format!("Upstream '{}' not found", upstream_name))?;

            let proxy_config = proxy_name.as_ref()
                .and_then(|name| config.proxies.get(name));

            let client: Arc<dyn UpstreamClient> = match upstream_config {
                UpstreamConfig::Doh { url, .. } => {
                    Arc::new(DohClient::with_proxy(
                        format!("{}@{}", upstream_name, proxy_name.as_deref().unwrap_or("direct")),
                        url.clone(),
                        proxy_config,
                    )?)
                }
                UpstreamConfig::Dot { server, hostname, .. } => {
                    Arc::new(DotClient::with_proxy(
                        format!("{}@{}", upstream_name, proxy_name.as_deref().unwrap_or("direct")),
                        server.clone(),
                        hostname.clone(),
                        proxy_config,
                    )?)
                }
            };

            info!(
                "Initialized upstream: {} via {}",
                upstream_name,
                proxy_name.as_deref().unwrap_or("direct")
            );
            upstreams.insert(key, client);
        }

        // Load domain lists for each rule
        // Get proxy URL if configured
        let domain_list_proxy_url = config.domain_list.proxy.as_ref()
            .and_then(|name| config.proxies.get(name))
            .map(|p| p.url.clone());

        let mut loader = DomainListLoader::new(
            config.domain_list.url.clone(),
            domain_list_proxy_url,
            config.domain_list.get_cache_dir(),
            config.domain_list.update_interval_hours,
        );

        let mut compiled_rules = Vec::new();
        for (idx, rule) in config.rules.iter().enumerate() {
            let mut loaded_domains = DomainList::new();

            // Load from domain_list (geosite names like "cn", "google")
            for name in &rule.domain_list {
                match loader.load(name).await {
                    Ok(list) => {
                        info!("Rule #{}: Loaded domain list '{}': {} rules", idx + 1, name, list.len());
                        loaded_domains.merge(list);
                    }
                    Err(e) => {
                        warn!("Rule #{}: Failed to load domain list '{}': {}", idx + 1, name, e);
                    }
                }
            }

            // Load from local files
            for path in &rule.domain_list_file {
                match loader.load_file(path) {
                    Ok(list) => {
                        info!("Rule #{}: Loaded domain list file '{}': {} rules", idx + 1, path, list.len());
                        loaded_domains.merge(list);
                    }
                    Err(e) => {
                        warn!("Rule #{}: Failed to load domain list file '{}': {}", idx + 1, path, e);
                    }
                }
            }

            loaded_domains.deduplicate();
            compiled_rules.push(CompiledRule {
                rule: rule.clone(),
                loaded_domains,
                rule_index: idx + 1, // 1-based for display
            });
        }

        // Initialize DNS cache
        let cache = DnsCache::new(config.cache.clone());
        if config.cache.enabled {
            info!(
                "DNS cache enabled: max_entries={}, min_ttl={}s, max_ttl={}s",
                config.cache.max_entries, config.cache.min_ttl, config.cache.max_ttl
            );
        } else {
            info!("DNS cache disabled");
        }

        Ok(Self {
            config,
            upstreams,
            geoip: Arc::new(geoip),
            compiled_rules,
            cache,
        })
    }

    /// Resolve a DNS query
    pub async fn resolve(&self, request: Message) -> Result<Message> {
        // Extract query name
        let query = request
            .queries()
            .first()
            .context("No query in DNS message")?;
        let query_name = query.name().to_string();
        let query_type = query.query_type();

        trace!("Resolving {} {:?}", query_name, query_type);

        // Check cache first
        if let Some(mut cached_response) = self.cache.get(&query_name, query_type).await {
            cached_response.set_id(request.id());
            self.log_cache_hit(&query_name, query_type, &cached_response);
            return Ok(cached_response);
        }

        // Try domain-based rule matching first
        let decision = self.match_domain_rules(&query_name)
            .unwrap_or_else(|| self.create_default_decision());

        let response = self.query_upstream(&request, &decision).await?;

        // Cache the response
        self.cache.put(&query_name, query_type, &response).await;

        Ok(response)
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> crate::cache::CacheStats {
        self.cache.stats()
    }

    /// Match query name against domain rules
    fn match_domain_rules(&self, query_name: &str) -> Option<RoutingDecision> {
        let query_lower = query_name.to_lowercase();
        // Remove trailing dot if present
        let query_normalized = query_lower.trim_end_matches('.');

        for compiled in &self.compiled_rules {
            let rule = &compiled.rule;
            let rule_idx = compiled.rule_index;

            // Check exact domain match (from config)
            for domain in &rule.domain {
                if query_normalized == domain.to_lowercase() {
                    return Some(self.create_decision_with_match(
                        rule,
                        "domain",
                        domain,
                        rule_idx,
                    ));
                }
            }

            // Check exact domain match (from loaded domain lists)
            for domain in &compiled.loaded_domains.domains {
                if query_normalized == domain.as_str() {
                    return Some(self.create_decision_with_match(
                        rule,
                        "domain_list(full)",
                        domain,
                        rule_idx,
                    ));
                }
            }

            // Check domain suffix match (from config)
            for suffix in &rule.domain_suffix {
                let suffix_lower = suffix.to_lowercase();
                let suffix_normalized = suffix_lower.trim_start_matches('.');

                if query_normalized == suffix_normalized
                    || query_normalized.ends_with(&format!(".{}", suffix_normalized))
                {
                    return Some(self.create_decision_with_match(
                        rule,
                        "domain_suffix",
                        suffix,
                        rule_idx,
                    ));
                }
            }

            // Check domain suffix match (from loaded domain lists)
            for suffix in &compiled.loaded_domains.domain_suffixes {
                if query_normalized == suffix.as_str()
                    || query_normalized.ends_with(&format!(".{}", suffix))
                {
                    return Some(self.create_decision_with_match(
                        rule,
                        "domain_list",
                        suffix,
                        rule_idx,
                    ));
                }
            }

            // Check domain keyword match (from config)
            for keyword in &rule.domain_keyword {
                if query_normalized.contains(&keyword.to_lowercase()) {
                    return Some(self.create_decision_with_match(
                        rule,
                        "domain_keyword",
                        keyword,
                        rule_idx,
                    ));
                }
            }

            // Check domain keyword match (from loaded domain lists)
            for keyword in &compiled.loaded_domains.keywords {
                if query_normalized.contains(keyword.as_str()) {
                    return Some(self.create_decision_with_match(
                        rule,
                        "domain_list(keyword)",
                        keyword,
                        rule_idx,
                    ));
                }
            }

            // Note: regexp matching from domain lists is not implemented
            // as it requires regex compilation and would impact performance
        }

        None
    }

    /// Create routing decision from a matched rule with match info
    fn create_decision_with_match(
        &self,
        rule: &Rule,
        match_type: &str,
        matched_value: &str,
        rule_index: usize,
    ) -> RoutingDecision {
        // Determine proxy: rule override > upstream default
        let proxy_name = rule.proxy.clone()
            .or_else(|| {
                self.config.upstreams.get(&rule.upstream)
                    .and_then(|u| u.proxy().cloned())
            });

        // Determine EDNS mode: rule override > upstream default
        let edns_mode = rule.edns_client_ip.clone()
            .or_else(|| {
                self.config.upstreams.get(&rule.upstream)
                    .map(|u| u.edns_client_ip().clone())
            })
            .unwrap_or_default();

        RoutingDecision {
            upstream_name: rule.upstream.clone(),
            proxy_name: proxy_name.clone(),
            edns_subnet: self.resolve_edns_subnet(&edns_mode, proxy_name.as_deref()),
            match_info: Some(MatchInfo {
                match_type: match_type.to_string(),
                matched_value: matched_value.to_string(),
                rule_index,
            }),
        }
    }

    /// Create routing decision for default (no match)
    fn create_default_decision(&self) -> RoutingDecision {
        let default_upstream = &self.config.default.upstream;
        let default_proxy = self.config.default.proxy.clone()
            .or_else(|| {
                self.config.upstreams.get(default_upstream)
                    .and_then(|u| u.proxy().cloned())
            });

        RoutingDecision {
            upstream_name: default_upstream.clone(),
            proxy_name: default_proxy.clone(),
            edns_subnet: self.resolve_edns_subnet(&self.config.default.edns_client_ip, default_proxy.as_deref()),
            match_info: None, // No match, using default
        }
    }

    /// Resolve EDNS client IP mode to subnet
    fn resolve_edns_subnet(&self, mode: &EdnsClientIp, proxy_name: Option<&str>) -> Option<EdnsSubnet> {
        self.config.resolve_edns_subnet(mode, proxy_name)
    }

    /// Query an upstream DNS server
    async fn query_upstream(
        &self,
        request: &Message,
        decision: &RoutingDecision,
    ) -> Result<Message> {
        let key = (
            decision.upstream_name.clone(),
            decision.proxy_name.clone().unwrap_or_default(),
        );

        let upstream = self
            .upstreams
            .get(&key)
            .with_context(|| {
                format!(
                    "Upstream '{}' via '{}' not found",
                    decision.upstream_name,
                    decision.proxy_name.as_deref().unwrap_or("direct")
                )
            })?;

        // Extract query info for logging
        let query_name = request
            .queries()
            .first()
            .map(|q| q.name().to_string())
            .unwrap_or_else(|| "?".to_string());
        let query_type = request
            .queries()
            .first()
            .map(|q| q.query_type())
            .unwrap_or(RecordType::A);

        let mut response = upstream
            .query(request.clone(), decision.edns_subnet.clone())
            .await?;

        // Ensure response has correct ID
        response.set_id(request.id());

        // Log the query result
        self.log_query_result(
            &query_name,
            query_type,
            decision,
            &response,
        );

        Ok(response)
    }

    /// Log query result with IPs and country codes
    fn log_query_result(
        &self,
        query_name: &str,
        query_type: RecordType,
        decision: &RoutingDecision,
        response: &Message,
    ) {
        let ips = extract_response_ips(response);

        // Format IPs with country codes
        let ips_with_geo: Vec<String> = ips
            .iter()
            .map(|ip| {
                let country = self.geoip.lookup_country(*ip)
                    .unwrap_or_else(|| "??".to_string());
                format!("{}({})", ip, country)
            })
            .collect();

        let result_str = if ips_with_geo.is_empty() {
            // No A/AAAA records, show response code
            format!("{:?}", response.response_code())
        } else {
            ips_with_geo.join(", ")
        };

        let proxy_str = decision.proxy_name.as_deref().unwrap_or("direct");
        let edns_str = decision.edns_subnet.as_ref()
            .map(|s| {
                if let Some(prefix) = s.prefix_len {
                    format!("{}/{}", s.ip, prefix)
                } else {
                    s.ip.to_string()
                }
            })
            .unwrap_or_else(|| "none".to_string());

        // Format match info
        let match_str = decision.match_info.as_ref()
            .map(|m| format!("rule#{} {}:{}", m.rule_index, m.match_type, m.matched_value))
            .unwrap_or_else(|| "default".to_string());

        info!(
            "{} {:?} [{}] -> {} via {} [ECS:{}] => {}",
            query_name.trim_end_matches('.'),
            query_type,
            match_str,
            decision.upstream_name,
            proxy_str,
            edns_str,
            result_str
        );
    }

    /// Log cache hit with IPs and country codes
    fn log_cache_hit(
        &self,
        query_name: &str,
        query_type: RecordType,
        response: &Message,
    ) {
        let ips = extract_response_ips(response);

        // Format IPs with country codes
        let ips_with_geo: Vec<String> = ips
            .iter()
            .map(|ip| {
                let country = self.geoip.lookup_country(*ip)
                    .unwrap_or_else(|| "??".to_string());
                format!("{}({})", ip, country)
            })
            .collect();

        let result_str = if ips_with_geo.is_empty() {
            format!("{:?}", response.response_code())
        } else {
            ips_with_geo.join(", ")
        };

        info!(
            "{} {:?} [CACHE] => {}",
            query_name.trim_end_matches('.'),
            query_type,
            result_str
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_domain_suffix_matching() {
        // Test suffix matching logic
        let query = "www.baidu.com";
        let suffix = ".baidu.com";

        let query_normalized = query.trim_end_matches('.');
        let suffix_normalized = suffix.trim_start_matches('.');

        assert!(
            query_normalized == suffix_normalized
                || query_normalized.ends_with(&format!(".{}", suffix_normalized))
        );
    }

    #[test]
    fn test_exact_domain_matching() {
        let query = "baidu.com";
        let domain = "baidu.com";

        assert_eq!(query.to_lowercase(), domain.to_lowercase());
    }

    #[test]
    fn test_keyword_matching() {
        let query = "api.github.com";
        let keyword = "github";

        assert!(query.to_lowercase().contains(&keyword.to_lowercase()));
    }
}
