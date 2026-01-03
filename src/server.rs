//! UDP/TCP DNS server implementation.

use anyhow::Result;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::serialize::binary::BinDecodable;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use crate::router::Router;

/// DNS Server that listens on UDP and TCP
pub struct DnsServer {
    listen_addrs: Vec<SocketAddr>,
    router: Arc<Router>,
}

impl DnsServer {
    pub fn new(listen_addrs: Vec<SocketAddr>, router: Arc<Router>) -> Self {
        Self {
            listen_addrs,
            router,
        }
    }

    /// Start the DNS server (both UDP and TCP on all addresses)
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let mut handles = Vec::new();

        // Start UDP and TCP listeners for each address
        for addr in &self.listen_addrs {
            let server = self.clone();
            let addr = *addr;
            handles.push(tokio::spawn(async move {
                server.run_udp(addr).await
            }));

            let server = self.clone();
            handles.push(tokio::spawn(async move {
                server.run_tcp(addr).await
            }));
        }

        // Wait for any listener to finish (which would be an error)
        for handle in handles {
            handle.await??;
        }

        Ok(())
    }

    /// Run UDP DNS server on a specific address
    async fn run_udp(self: Arc<Self>, addr: SocketAddr) -> Result<()> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        info!("UDP DNS server listening on {}", addr);

        let mut buf = vec![0u8; 4096];
        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    let data = buf[..len].to_vec();
                    let socket = socket.clone();
                    let router = self.router.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_udp_query(&socket, src, &data, &router).await {
                            warn!("Failed to handle UDP query from {}: {}", src, e);
                        }
                    });
                }
                Err(e) => {
                    error!("UDP recv error on {}: {}", addr, e);
                }
            }
        }
    }

    /// Run TCP DNS server on a specific address
    async fn run_tcp(self: Arc<Self>, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!("TCP DNS server listening on {}", addr);

        loop {
            match listener.accept().await {
                Ok((stream, src)) => {
                    let router = self.router.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_connection(stream, src, &router).await {
                            warn!("Failed to handle TCP connection from {}: {}", src, e);
                        }
                    });
                }
                Err(e) => {
                    error!("TCP accept error on {}: {}", addr, e);
                }
            }
        }
    }
}

/// Handle a single UDP DNS query
async fn handle_udp_query(
    socket: &UdpSocket,
    src: SocketAddr,
    data: &[u8],
    router: &Router,
) -> Result<()> {
    debug!("Received UDP query from {} ({} bytes)", src, data.len());

    // Parse the DNS message
    let request = match Message::from_bytes(data) {
        Ok(msg) => msg,
        Err(e) => {
            warn!("Failed to parse DNS message from {}: {}", src, e);
            return Ok(());
        }
    };

    // Process the query through the router
    let response = match router.resolve(request).await {
        Ok(resp) => resp,
        Err(e) => {
            warn!("Failed to resolve query: {}", e);
            return Ok(());
        }
    };

    // Serialize and send response
    let response_bytes = response.to_vec()?;
    socket.send_to(&response_bytes, src).await?;

    debug!("Sent UDP response to {} ({} bytes)", src, response_bytes.len());
    Ok(())
}

/// Handle a TCP DNS connection (may contain multiple queries)
async fn handle_tcp_connection(
    mut stream: TcpStream,
    src: SocketAddr,
    router: &Router,
) -> Result<()> {
    debug!("TCP connection from {}", src);

    loop {
        // Read the 2-byte length prefix
        let mut len_buf = [0u8; 2];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client closed connection
                break;
            }
            Err(e) => return Err(e.into()),
        }

        let len = u16::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 65535 {
            warn!("Invalid DNS message length from {}: {}", src, len);
            break;
        }

        // Read the DNS message
        let mut data = vec![0u8; len];
        stream.read_exact(&mut data).await?;

        // Parse the DNS message
        let request = match Message::from_bytes(&data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("Failed to parse DNS message from {}: {}", src, e);
                continue;
            }
        };

        // Process the query
        let response = match router.resolve(request).await {
            Ok(resp) => resp,
            Err(e) => {
                warn!("Failed to resolve query: {}", e);
                continue;
            }
        };

        // Serialize response with length prefix
        let response_bytes = response.to_vec()?;
        let len_bytes = (response_bytes.len() as u16).to_be_bytes();

        stream.write_all(&len_bytes).await?;
        stream.write_all(&response_bytes).await?;

        debug!("Sent TCP response to {} ({} bytes)", src, response_bytes.len());
    }

    Ok(())
}

/// Create a DNS error response
#[allow(dead_code)]
pub fn create_error_response(request: &Message, rcode: ResponseCode) -> Message {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.set_response_code(rcode);

    // Copy the question section
    for query in request.queries() {
        response.add_query(query.clone());
    }

    response
}
