use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddrV4};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub bind_address: Option<SocketAddrV4>,
    pub default_dns_address: Option<SocketAddrV4>,
    pub default_network_interface: String,
    pub alternate_networks: HashMap<String, AltNet>,
}

#[derive(Debug, Deserialize)]
pub struct AltNet {
    // Domain suffixes
    // TODO: maybe use a BTree if this list exceeds a given size
    pub domains: Vec<String>,
    // Address of DNS server to use for the specified domains
    pub dns_address: SocketAddrV4,
    // Interface through which traffic should be routed
    pub network_interface: String,
    // Optional host through which traffic should be routed (disables routing table lookup)
    pub router: Option<IpAddr>,
}
