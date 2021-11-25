use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddrV4};
use std::sync::{Arc, RwLock};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub bind_address: Option<SocketAddrV4>,
    pub default_dns_address: Option<SocketAddrV4>,
    pub default_network_interface: String,
    pub alternate_networks: HashMap<String, Arc<RwLock<AltNet>>>,
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

    pub dyn_vpn: Option<DynVpn>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "driver")]
pub enum DynVpn {
    #[serde(rename = "openconnect")]
    OpenConnect(OpenConnect),
}

#[derive(Debug, Deserialize, Clone)]
pub struct OpenConnect {
    pub protocol: String,
    pub server: String,
    pub user: Option<String>,
    pub password: Option<String>,
    pub server_cert: Option<String>,
    #[serde(default = "bool::default")]
    pub disable_ipv6: bool,
}
