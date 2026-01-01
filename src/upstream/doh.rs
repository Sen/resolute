//! DNS over HTTPS (DOH) client implementation.

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use reqwest::{Client, Proxy};
use std::time::Duration;
use tracing::{debug, trace};

use super::UpstreamClient;
use crate::config::{EdnsSubnet, ProxyConfig};
use crate::edns::add_edns_client_subnet;

/// DNS over HTTPS client
pub struct DohClient {
    name: String,
    url: String,
    client: Client,
}

impl DohClient {
    /// Create a new DOH client without proxy
    #[allow(dead_code)]
    pub fn new(name: String, url: String) -> Result<Self> {
        Self::with_proxy(name, url, None)
    }

    /// Create a new DOH client with optional proxy
    pub fn with_proxy(name: String, url: String, proxy: Option<&ProxyConfig>) -> Result<Self> {
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(2)
            .use_rustls_tls();

        // Configure proxy if specified
        if let Some(proxy_config) = proxy {
            let proxy_url = &proxy_config.url;
            let reqwest_proxy = if proxy_url.starts_with("socks5://") {
                // reqwest uses socks5h for DNS resolution through proxy
                let socks_url = proxy_url.replace("socks5://", "socks5h://");
                Proxy::all(&socks_url)
                    .with_context(|| format!("Invalid SOCKS5 proxy URL: {}", proxy_url))?
            } else {
                // HTTP/HTTPS proxy
                Proxy::all(proxy_url)
                    .with_context(|| format!("Invalid HTTP proxy URL: {}", proxy_url))?
            };
            builder = builder.proxy(reqwest_proxy);
            debug!("DOH client '{}' using proxy: {}", name, proxy_url);
        }

        let client = builder.build().context("Failed to create HTTP client")?;

        Ok(Self { name, url, client })
    }

    /// Send query using GET method (RFC 8484)
    async fn query_get(&self, message: &Message) -> Result<Message> {
        let wire_format = message.to_vec()?;
        let encoded = URL_SAFE_NO_PAD.encode(&wire_format);

        let url = format!("{}?dns={}", self.url, encoded);
        trace!("DOH GET request to {}", url);

        let response = self
            .client
            .get(&url)
            .header("Accept", "application/dns-message")
            .send()
            .await
            .context("DOH GET request failed")?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("DOH server returned error status: {}", status);
        }

        let body = response.bytes().await.context("Failed to read DOH response body")?;
        let dns_response = Message::from_bytes(&body).context("Failed to parse DOH response")?;

        Ok(dns_response)
    }

    /// Send query using POST method (RFC 8484)
    async fn query_post(&self, message: &Message) -> Result<Message> {
        let wire_format = message.to_vec()?;

        trace!("DOH POST request to {} ({} bytes)", self.url, wire_format.len());

        let response = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(wire_format)
            .send()
            .await
            .context("DOH POST request failed")?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("DOH server returned error status: {}", status);
        }

        let body = response.bytes().await.context("Failed to read DOH response body")?;
        let dns_response = Message::from_bytes(&body).context("Failed to parse DOH response")?;

        Ok(dns_response)
    }
}

#[async_trait]
impl UpstreamClient for DohClient {
    async fn query(&self, mut message: Message, edns_subnet: Option<EdnsSubnet>) -> Result<Message> {
        // Add EDNS Client Subnet if specified
        if let Some(ref subnet) = edns_subnet {
            add_edns_client_subnet(&mut message, subnet);
        }

        debug!(
            "[{}] DOH query for {:?} (ECS: {:?})",
            self.name,
            message.queries().first().map(|q| q.name().to_string()),
            edns_subnet
        );

        // Try POST first (more reliable for larger queries), fall back to GET
        match self.query_post(&message).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                debug!("DOH POST failed, trying GET: {}", e);
                self.query_get(&message).await
            }
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn create_test_query(domain: &str) -> Message {
        let mut message = Message::new();
        message.set_id(1234);
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        let name = Name::from_ascii(domain).unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        message
    }

    #[tokio::test]
    #[ignore] // Requires network access
    async fn test_doh_cloudflare() {
        let client = DohClient::new(
            "cloudflare".to_string(),
            "https://1.1.1.1/dns-query".to_string(),
        )
        .unwrap();

        let query = create_test_query("example.com");
        let response = client.query(query, None).await.unwrap();

        assert!(!response.answers().is_empty());
    }
}
