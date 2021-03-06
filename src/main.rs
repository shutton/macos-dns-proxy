use anyhow::{anyhow, Result};
use cidr::{AnyIpCidr, Ipv4Cidr, Ipv6Cidr};
use log::*;
use macos_routing_table::RoutingTable;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use structopt::StructOpt;
use tokio::sync::mpsc;
use tokio::time::timeout;

mod dns_server;
use dns_server::dns_server;

mod udp_socket_pool;
use udp_socket_pool::UdpSocketPool;

mod rt_server;
use rt_server::{get_default_gw_addr, get_gw_netif, rt_server, update_route, RTRequest};

mod config;
use config::{AltNet, Config};

use crate::rt_server::update_routing_table;

mod openconnect;

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:53";
const DEFAULT_DNS_ADDRESS: &str = "8.8.8.8:53";

#[derive(StructOpt, Debug)]
struct Opt {
    #[structopt(long, default_value = "dns-proxy.toml")]
    config: String,
}

struct ProxyRequest {
    dns_addr: SocketAddrV4,
    altnet_name: String,
    request: Vec<u8>,
    req_domain: Option<String>,
    rt_tx: mpsc::Sender<RTRequest>,
    route_through_if: String,
    route_through_host: Option<IpAddr>,
    dns_reply_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    addr: SocketAddr,
    sockpool: deadpool::managed::Pool<UdpSocketPool>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    env_logger::init();

    let config: Config = toml::from_str(
        std::fs::read_to_string(&opt.config)
            .map_err(|e| anyhow!("Unable to read configuration from {:?}: {}", &opt.config, e))?
            .as_str(),
    )
    .map_err(|e| {
        anyhow!(
            "Unable to parse configuration from {:?}: {}",
            &opt.config,
            e
        )
    })?;

    //
    // Determine default DNS address and its interface
    //
    let bind_addr = config
        .bind_address
        .unwrap_or_else(|| DEFAULT_BIND_ADDRESS.parse().unwrap());
    let default_dns_address = config
        .default_dns_address
        .unwrap_or_else(|| DEFAULT_DNS_ADDRESS.parse().unwrap());
    let default_net_if = config.default_network_interface;
    info!("Default DNS address: {:?}", &default_dns_address);

    // Pull the current routing table
    let rt = RoutingTable::load_from_netstat().await?;
    let (rt_tx, rt_rx) = mpsc::channel(32);
    tokio::spawn(rt_server(rt_rx, rt));

    for (net_name, altnet) in &config.alternate_networks {
        let altnet_guard = altnet.read().unwrap();
        // Is this network managed by a VPN?
        if let Some(dyn_vpn) = &altnet_guard.dyn_vpn {
            match dyn_vpn {
                config::DynVpn::OpenConnect(_) => {
                    openconnect::spawn(net_name.clone(), altnet.clone(), rt_tx.clone()).await?
                }
            }
        }

        //
        // Ensure there's a route to DNS servers for alternative networks
        //
        let dns_addr = IpAddr::from(*altnet_guard.dns_address.ip());
        // Find the interface that handles this DNS address
        if let Some(cur_if) = get_gw_netif(rt_tx.clone(), dns_addr).await? {
            if cur_if == altnet_guard.network_interface {
                info!(
                    "DNS requests for {} ({}) are already routed through {}",
                    net_name,
                    altnet_guard.dns_address.ip(),
                    altnet_guard.network_interface
                );
            } else {
                warn!(
                    "DNS requests for {} ({}) are NOT routed through {}",
                    net_name,
                    altnet_guard.dns_address.ip(),
                    altnet_guard.network_interface
                );
                if let Some(gw_addr) =
                    get_default_gw_addr(rt_tx.clone(), &altnet_guard.network_interface, dns_addr)
                        .await?
                {
                    update_route(
                        "add",
                        AnyIpCidr::V4(Ipv4Cidr::new_host(*altnet_guard.dns_address.ip())),
                        gw_addr,
                    )
                    .await?;
                }
            }
        }
    }

    let (dns_tx, mut dns_rx) = mpsc::channel(32);
    let (dns_reply_tx, dns_reply_rx) = mpsc::channel(32);
    tokio::spawn(dns_server(bind_addr, dns_tx, dns_reply_rx));

    let sockpool = deadpool::managed::Pool::builder(UdpSocketPool)
        .max_size(16)
        .build()
        .unwrap();

    loop {
        while let Some((request, addr)) = dns_rx.recv().await {
            debug!("Received {} bytes from {:?}", request.len(), addr);
            let result = inspect(
                default_dns_address,
                &default_net_if,
                &config.alternate_networks,
                &request,
            )?;
            let rt_tx = rt_tx.clone();
            let altnet_name = result.net_name.to_string();
            let sockpool = sockpool.clone();
            tokio::spawn(handle_request(ProxyRequest {
                dns_addr: result.dns_address,
                altnet_name,
                request,
                req_domain: result.domain_name,
                rt_tx,
                route_through_if: result.net_if.to_owned(),
                route_through_host: result.gw_addr.to_owned(),
                dns_reply_tx: dns_reply_tx.clone(),
                addr,
                sockpool,
            }));
        }
    }
}

async fn handle_request(req: ProxyRequest) -> Result<()> {
    // Establish a local response port
    let local_server = req.sockpool.get().await.unwrap();
    debug!(
        "Querying {} from {:?}",
        &req.dns_addr,
        local_server.local_addr()
    );
    local_server.send_to(&req.request, req.dns_addr).await?;
    let mut reply = [0u8; 512];
    let len =
        if let Ok(reply) = timeout(Duration::from_secs(5), local_server.recv(&mut reply)).await {
            match reply {
                Ok(reply) => reply,
                Err(e) => {
                    warn!("Failed getting reply from {}: {}", &req.dns_addr, e);
                    return Err(anyhow!("io error: {}", e));
                }
            }
        } else {
            warn!("Timed out waiting for reply from {}", &req.dns_addr);
            return Err(anyhow!("timeout"));
        };

    if let Some(req_domain) = &req.req_domain {
        // Now check the reply and make sure it will use the expected interface
        let msg = bytes::Bytes::copy_from_slice(&reply[..len]);
        let reply_dns = dns_message_parser::Dns::decode(msg);
        if let Ok(reply) = reply_dns {
            for rr in reply.answers {
                // Just handle A records for now.  Ignore AAAA and others.
                let (addr, qtype) = match &rr {
                    dns_message_parser::rr::RR::A(addr) => {
                        (Some(IpAddr::from(addr.ipv4_addr)), "A")
                    }
                    dns_message_parser::rr::RR::AAAA(addr) => {
                        (Some(IpAddr::from(addr.ipv6_addr)), "AAAA")
                    }
                    _ => (None, "N/A"),
                };
                debug!("DNS({}):{:?} {:?}", req.altnet_name, req.dns_addr, rr);
                if let Some(ipaddr) = addr {
                    // Check the routing table to find out what interface this host *currently* routes through
                    if let Ok(Some(net_if)) = get_gw_netif(req.rt_tx.clone(), ipaddr).await {
                        if req.route_through_if != net_if {
                            // The address for this host does not currently route through the desired interface. Find a host to do that
                            let gw_addr = if let Some(gw_addr) = req.route_through_host {
                                // Specified directly
                                Some(gw_addr)
                            } else {
                                // Query the routing table for a host or default route
                                get_default_gw_addr(
                                    req.rt_tx.clone(),
                                    &req.route_through_if,
                                    ipaddr,
                                )
                                .await?
                            };

                            if let Some(gw_addr) = gw_addr {
                                let ipaddr = match ipaddr {
                                    IpAddr::V4(addr) => AnyIpCidr::from(Ipv4Cidr::new_host(addr)),
                                    IpAddr::V6(addr) => AnyIpCidr::from(Ipv6Cidr::new_host(addr)),
                                };
                                debug!(
                                    "adding a route for {} ({}) via {:?}!",
                                    req_domain, ipaddr, gw_addr,
                                );
                                if let Err(e) = update_route("add", ipaddr, gw_addr).await {
                                    warn!("failed to add route: {}", e);
                                } else {
                                    info!(
                                        "routing {}:{} -> {} via {}({}) (NEW)",
                                        qtype,
                                        req_domain,
                                        ipaddr,
                                        req.route_through_if,
                                        req.altnet_name
                                    );
                                    update_routing_table(req.rt_tx.clone()).await?;
                                }
                            } else {
                                debug!("no route for {} {} -> {}!", qtype, req_domain, ipaddr)
                            }
                        } else {
                            info!(
                                "routing {}:{} -> {} via {}({})",
                                qtype, req_domain, ipaddr, req.route_through_if, req.altnet_name,
                            );
                        }
                    }
                }
            }
        }
    }
    req.dns_reply_tx
        .send((reply[..len].to_owned(), req.addr))
        .await?;

    Ok(())
}

struct InspectResult {
    dns_address: SocketAddrV4,
    net_name: String,
    net_if: String,
    gw_addr: Option<IpAddr>,
    domain_name: Option<String>,
}

fn inspect<'a>(
    default_dns_address: SocketAddrV4,
    default_net_if: &'a str,
    altnets: &'a HashMap<String, Arc<RwLock<AltNet>>>,
    buf: &[u8],
) -> Result<InspectResult> {
    debug!("Inspecting {:?}", buf);
    let msg = bytes::Bytes::copy_from_slice(buf);
    let query = dns_message_parser::Dns::decode(msg)?;
    let mut domain_name: Option<String> = None;
    debug!("query = {:?}", query);
    for question in query.questions {
        debug!("domain_name = {:?}", question.domain_name);
        let this_domain_name: String = question.domain_name.into();
        for (net_name, altnet) in altnets {
            let altnet = altnet.read().unwrap();
            if altnet
                .domains
                .iter()
                .any(|domain_name| this_domain_name.ends_with(domain_name))
            {
                return Ok(InspectResult {
                    dns_address: altnet.dns_address,
                    net_name: net_name.into(),
                    net_if: altnet.network_interface.clone(),
                    gw_addr: altnet.router,
                    domain_name: Some(this_domain_name),
                });
            }
        }
        domain_name = Some(this_domain_name);
    }

    Ok(InspectResult {
        dns_address: default_dns_address,
        net_name: "default".into(),
        net_if: default_net_if.into(),
        gw_addr: None,
        domain_name,
    })
}
