//! EDNS Client Subnet (ECS) support.
//!
//! Implements RFC 7871 - Client Subnet in DNS Queries.

use crate::config::EdnsSubnet;
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
use hickory_proto::rr::RData;
use std::net::IpAddr;
use tracing::trace;

/// Add EDNS Client Subnet option to a DNS message.
///
/// This modifies the message in place, adding or updating the OPT record
/// with the Client Subnet option containing the specified subnet.
pub fn add_edns_client_subnet(message: &mut Message, subnet: &EdnsSubnet) {
    // Determine prefix length: use custom if provided, otherwise default
    // Default: /24 for IPv4, /56 for IPv6 (common recommendations)
    let source_prefix_len = subnet.prefix_len.unwrap_or_else(|| {
        match subnet.ip {
            IpAddr::V4(_) => 24,
            IpAddr::V6(_) => 56,
        }
    });
    let scope_prefix_len = 0;

    let client_subnet = ClientSubnet::new(subnet.ip, source_prefix_len, scope_prefix_len);
    let ecs_option = EdnsOption::Subnet(client_subnet);

    trace!(
        "Adding EDNS Client Subnet: {}/{} (scope: {})",
        subnet.ip,
        source_prefix_len,
        scope_prefix_len
    );

    // Check if OPT record already exists
    let edns = message.extensions_mut();

    if let Some(opt) = edns {
        // OPT record exists, add/update ECS option
        opt.options_mut().insert(ecs_option);
    } else {
        // Create new EDNS with ECS
        let mut new_edns = hickory_proto::op::Edns::new();
        new_edns.set_max_payload(4096);
        new_edns.set_version(0);
        new_edns.options_mut().insert(ecs_option);
        message.set_edns(new_edns);
    }
}

/// Extract the Client Subnet option from a DNS response if present.
///
/// Returns the scope prefix length, which indicates how much of the
/// client subnet was used by the authoritative server.
#[allow(dead_code)]
pub fn extract_edns_client_subnet(message: &Message) -> Option<ClientSubnet> {
    let edns = message.extensions().as_ref()?;

    for (_code, option) in edns.options().as_ref().iter() {
        if let EdnsOption::Subnet(subnet) = option {
            return Some(subnet.clone());
        }
    }

    None
}

/// Extract A/AAAA record IPs from a DNS response.
pub fn extract_response_ips(message: &Message) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    for answer in message.answers() {
        match answer.data() {
            RData::A(a) => ips.push(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => ips.push(IpAddr::V6(aaaa.0)),
            _ => {}
        }
    }

    ips
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn create_test_query() -> Message {
        let mut message = Message::new();
        message.set_id(1234);
        message.set_message_type(MessageType::Query);
        message.set_op_code(OpCode::Query);
        message.set_recursion_desired(true);

        let name = Name::from_ascii("example.com").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        message
    }

    #[test]
    fn test_add_edns_client_subnet_v4() {
        let mut message = create_test_query();
        let subnet = EdnsSubnet {
            ip: "192.168.1.100".parse().unwrap(),
            prefix_len: None, // Use default /24
        };

        add_edns_client_subnet(&mut message, &subnet);

        let edns = message.extensions().as_ref().expect("EDNS should be present");
        let mut found = false;
        for (_code, option) in edns.options().as_ref().iter() {
            if let EdnsOption::Subnet(subnet) = option {
                assert_eq!(subnet.source_prefix(), 24);
                found = true;
            }
        }
        assert!(found, "ECS option should be present");
    }

    #[test]
    fn test_add_edns_client_subnet_v6() {
        let mut message = create_test_query();
        let subnet = EdnsSubnet {
            ip: "2001:db8::1".parse().unwrap(),
            prefix_len: None, // Use default /56
        };

        add_edns_client_subnet(&mut message, &subnet);

        let edns = message.extensions().as_ref().expect("EDNS should be present");
        let mut found = false;
        for (_code, option) in edns.options().as_ref().iter() {
            if let EdnsOption::Subnet(s) = option {
                assert_eq!(s.source_prefix(), 56);
                found = true;
            }
        }
        assert!(found, "ECS option should be present");
    }

    #[test]
    fn test_add_edns_client_subnet_custom_prefix() {
        let mut message = create_test_query();
        let subnet = EdnsSubnet {
            ip: "120.76.0.0".parse().unwrap(),
            prefix_len: Some(14), // Custom /14
        };

        add_edns_client_subnet(&mut message, &subnet);

        let edns = message.extensions().as_ref().expect("EDNS should be present");
        let mut found = false;
        for (_code, option) in edns.options().as_ref().iter() {
            if let EdnsOption::Subnet(s) = option {
                assert_eq!(s.source_prefix(), 14);
                found = true;
            }
        }
        assert!(found, "ECS option should be present");
    }
}
