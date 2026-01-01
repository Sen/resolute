//! DNS over TLS (DOT) client implementation.

use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_socks::tcp::Socks5Stream;
use tracing::{debug, trace, warn};

use super::UpstreamClient;
use crate::config::{EdnsSubnet, ProxyConfig};
use crate::edns::add_edns_client_subnet;

/// DNS over TLS client
pub struct DotClient {
    name: String,
    server: String,
    hostname: String,
    tls_connector: TlsConnector,
    socks5_proxy: Option<String>,
}

impl DotClient {
    /// Create a new DOT client without proxy
    #[allow(dead_code)]
    pub fn new(name: String, server: String, hostname: String) -> Result<Self> {
        Self::with_proxy(name, server, hostname, None)
    }

    /// Create a new DOT client with optional proxy
    pub fn with_proxy(
        name: String,
        server: String,
        hostname: String,
        proxy: Option<&ProxyConfig>,
    ) -> Result<Self> {
        // Build TLS config with default root certificates
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let tls_connector = TlsConnector::from(Arc::new(tls_config));

        // Only SOCKS5 proxy is supported for DOT (TCP connections)
        let socks5_proxy = if let Some(proxy_config) = proxy {
            if proxy_config.url.starts_with("socks5://") {
                let addr = proxy_config.url.strip_prefix("socks5://").unwrap().to_string();
                debug!("DOT client '{}' using SOCKS5 proxy: {}", name, addr);
                Some(addr)
            } else {
                warn!(
                    "DOT client '{}': HTTP proxy not supported for DOT, ignoring proxy config",
                    name
                );
                None
            }
        } else {
            None
        };

        Ok(Self {
            name,
            server,
            hostname,
            tls_connector,
            socks5_proxy,
        })
    }

    /// Connect to the DOT server (directly or through SOCKS5 proxy)
    async fn connect(&self) -> Result<Box<dyn AsyncReadWrite + Unpin + Send>> {
        if let Some(ref proxy_addr) = self.socks5_proxy {
            // Connect through SOCKS5 proxy
            trace!("Connecting to DOT server {} via SOCKS5 proxy {}", self.server, proxy_addr);
            let stream = Socks5Stream::connect(proxy_addr.as_str(), self.server.as_str())
                .await
                .with_context(|| {
                    format!(
                        "Failed to connect to DOT server {} via SOCKS5 proxy {}",
                        self.server, proxy_addr
                    )
                })?;
            Ok(Box::new(stream))
        } else {
            // Direct connection
            trace!("Connecting to DOT server {}", self.server);
            let stream = TcpStream::connect(&self.server)
                .await
                .with_context(|| format!("Failed to connect to DOT server {}", self.server))?;
            Ok(Box::new(stream))
        }
    }

    /// Send a DNS query over TLS
    async fn send_query(&self, message: &Message) -> Result<Message> {
        // Connect to server (directly or via proxy)
        let tcp_stream = self.connect().await?;

        // Perform TLS handshake
        let server_name = ServerName::try_from(self.hostname.clone())
            .map_err(|_| anyhow::anyhow!("Invalid server name: {}", self.hostname))?;

        let mut tls_stream = self
            .tls_connector
            .connect(server_name, tcp_stream)
            .await
            .context("TLS handshake failed")?;

        // Serialize DNS message
        let wire_format = message.to_vec()?;
        let len = wire_format.len() as u16;

        // Send length-prefixed message
        tls_stream.write_all(&len.to_be_bytes()).await?;
        tls_stream.write_all(&wire_format).await?;
        tls_stream.flush().await?;

        trace!("Sent DOT query ({} bytes)", wire_format.len());

        // Read response length
        let mut len_buf = [0u8; 2];
        tls_stream.read_exact(&mut len_buf).await?;
        let response_len = u16::from_be_bytes(len_buf) as usize;

        // Read response
        let mut response_buf = vec![0u8; response_len];
        tls_stream.read_exact(&mut response_buf).await?;

        trace!("Received DOT response ({} bytes)", response_len);

        // Parse response
        let response = Message::from_bytes(&response_buf).context("Failed to parse DOT response")?;

        Ok(response)
    }
}

/// Trait alias for async read + write
trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

#[async_trait]
impl UpstreamClient for DotClient {
    async fn query(&self, mut message: Message, edns_subnet: Option<EdnsSubnet>) -> Result<Message> {
        // Add EDNS Client Subnet if specified
        if let Some(ref subnet) = edns_subnet {
            add_edns_client_subnet(&mut message, subnet);
        }

        debug!(
            "[{}] DOT query for {:?} (ECS: {:?})",
            self.name,
            message.queries().first().map(|q| q.name().to_string()),
            edns_subnet
        );

        self.send_query(&message).await
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
    async fn test_dot_quad9() {
        let client = DotClient::new(
            "quad9".to_string(),
            "9.9.9.9:853".to_string(),
            "dns.quad9.net".to_string(),
        )
        .unwrap();

        let query = create_test_query("example.com");
        let response = client.query(query, None).await.unwrap();

        assert!(!response.answers().is_empty());
    }
}
