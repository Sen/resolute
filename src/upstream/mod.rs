//! Upstream DNS client implementations (DOH, DOT).

mod doh;
mod dot;

pub use doh::DohClient;
pub use dot::DotClient;

use crate::config::EdnsSubnet;
use anyhow::Result;
use async_trait::async_trait;
use hickory_proto::op::Message;

/// Trait for upstream DNS clients
#[async_trait]
pub trait UpstreamClient: Send + Sync {
    /// Send a DNS query and receive a response
    async fn query(&self, message: Message, edns_subnet: Option<EdnsSubnet>) -> Result<Message>;

    /// Get the name/identifier of this upstream
    #[allow(dead_code)]
    fn name(&self) -> &str;
}

