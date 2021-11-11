use anyhow::{anyhow, Result};
use futures::future::FutureExt;
use futures::select;
use log::*;
use macos_routing_table::RoutingTable;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::process::Stdio;
use std::time::Duration;
use structopt::StructOpt;
use tokio::time::timeout;
use tokio::{
    net::UdpSocket,
    process::Command,
    sync::{mpsc, oneshot},
};

const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:53";
const DEFAULT_DNS_ADDRESS: &str = "8.8.8.8:53";

#[derive(StructOpt, Debug)]
struct Opt {
    #[structopt(long, default_value = "dns-proxy.toml")]
    config: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    bind_address: Option<SocketAddrV4>,
    default_dns_address: Option<SocketAddrV4>,
    default_network_interface: String,
    alternate_networks: HashMap<String, AltNet>,
}

#[derive(Debug, Deserialize)]
struct AltNet {
    // Domain suffixes
    // TODO: maybe use a BTree if this list exceeds a given size
    domains: Vec<String>,
    // Address of DNS server to use for the specified domains
    dns_address: SocketAddrV4,
    // Interface through which traffic should be routed
    network_interface: String,
}

/// A routing table request
#[derive(Debug)]
enum RTRequest {
    /// Replace the routing table with the one provided
    Replace(RoutingTable),
    /// Query the routing table for the given IP address to find the interface
    /// currently handling that IP.  The response is sent back via the provided
    /// oneshot channel.
    Query {
        ipaddr: IpAddr,
        reply_tx: oneshot::Sender<Option<String>>,
    },
    // Query the gateway address for routing an address across a given interface
    QueryGw {
        net_if: String,
        ipaddr: IpAddr,
        reply_tx: oneshot::Sender<Option<IpAddr>>,
    },
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

    //
    // Ensure there's a route to DNS servers for alternative networks
    //
    for (net_name, altnet) in &config.alternate_networks {
        let dns_addr = IpAddr::from(*altnet.dns_address.ip());
        if let Some(cur_if) = rt.find_gateway_netif(dns_addr) {
            if cur_if == altnet.network_interface {
                info!(
                    "DNS requests for {} ({}) are already routed through {}",
                    net_name,
                    altnet.dns_address.ip(),
                    altnet.network_interface
                );
            } else {
                warn!(
                    "DNS requests for {} ({}) are NOT routed through {}",
                    net_name,
                    altnet.dns_address.ip(),
                    altnet.network_interface
                );
                if let Some(gw_addr) = query_gateway(&rt, &altnet.network_interface, &dns_addr) {
                    update_route("add", IpAddr::from(*altnet.dns_address.ip()), gw_addr).await?;
                }
            }
        }
    }

    let (rt_tx, rt_rx) = mpsc::channel(32);
    tokio::spawn(rt_server(rt_rx, rt));

    let (dns_tx, mut dns_rx) = mpsc::channel(32);
    let (dns_reply_tx, dns_reply_rx) = mpsc::channel(32);
    tokio::spawn(dns_server(bind_addr, dns_tx, dns_reply_rx));

    loop {
        while let Some((request, addr)) = dns_rx.recv().await {
            debug!("Received {} bytes from {:?}", request.len(), addr);
            let (dns_addr, altnet_name, route_through_if, req_domain) = inspect(
                default_dns_address,
                &default_net_if,
                &config.alternate_networks,
                &request,
            )?;
            let rt_tx = rt_tx.clone();
            let altnet_name = altnet_name.to_string();
            tokio::spawn(handle_request(
                dns_addr,
                altnet_name,
                request,
                req_domain,
                rt_tx,
                route_through_if.to_owned(),
                dns_reply_tx.clone(),
                addr,
            ));
        }
    }
}

/// The base DNS server.  As queries are received, they're sent back via the `tx`
/// MPSC channel along with the client socket address.  Also monitors the `rx`
/// channel for responses and relays those to the specified socket address.
async fn dns_server<T: tokio::net::ToSocketAddrs + std::fmt::Debug>(
    bind_addr: T,
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    mut rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
) -> Result<()> {
    debug!("Binding to {:?}", &bind_addr);
    let server_socket = UdpSocket::bind(bind_addr).await?;
    info!("Bound to {:?}", server_socket.local_addr()?);
    let mut buf = vec![0u8; 512];

    loop {
        select! {
            result = server_socket.recv_from(&mut buf).fuse() => {
                match result {
                    Ok((len, addr)) => tx.send((buf[..len].to_owned(), addr)).await?,
                    Err(e) => warn!("recv_from() failed: {}", e),
                }
            }
            result = rx.recv().fuse() => {
                if let Some((reply, addr)) = result {
                    server_socket.send_to(&reply, addr).await?;
                }
            }
        }
    }
}

/// The routing table server.  Holds a routing table, and performs queries
/// against it, as well as allowing its replacement.
async fn rt_server(mut rx: mpsc::Receiver<RTRequest>, mut rt: RoutingTable) -> Result<()> {
    let mut cache = lru::LruCache::new(1024);
    while let Some(query) = rx.recv().await {
        match query {
            RTRequest::Replace(new_rt) => {
                rt = new_rt;
                cache.clear();
            }
            RTRequest::Query { ipaddr, reply_tx } => {
                let entry = cache.get(&ipaddr).or_else(|| rt.find_route_entry(ipaddr));
                if let Some(entry) = entry {
                    reply_tx.send(Some(entry.net_if.to_owned())).unwrap();
                    let entry = entry.clone();
                    cache.put(ipaddr, entry);
                } else {
                    reply_tx.send(None).unwrap();
                }
            }
            RTRequest::QueryGw {
                net_if,
                ipaddr,
                reply_tx,
            } => {
                reply_tx.send(query_gateway(&rt, &net_if, &ipaddr)).unwrap();
            }
        }
    }
    Ok(())
}

// TODO: this needs to be multiplexed to reduce the number of bind()'s.
async fn handle_request(
    dns_addr: SocketAddrV4,
    altnet_name: String,
    request: Vec<u8>,
    req_domain: Option<String>,
    rt_tx: mpsc::Sender<RTRequest>,
    route_through_if: String,
    dns_reply_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    addr: SocketAddr,
) -> Result<()> {
    // Establish a local respose port
    let local_server = UdpSocket::bind("0.0.0.0:0").await?;
    debug!("Querying {}", &dns_addr);
    local_server.send_to(&request, dns_addr).await?;
    let mut reply = [0u8; 512];
    let len =
        if let Ok(reply) = timeout(Duration::from_secs(5), local_server.recv(&mut reply)).await {
            match reply {
                Ok(reply) => reply,
                Err(e) => {
                    warn!("Failed getting reply from {}: {}", &dns_addr, e);
                    return Err(anyhow!("io error: {}", e));
                }
            }
        } else {
            warn!("Timed out waiting for reply from {}", &dns_addr);
            return Err(anyhow!("timeout"));
        };
    // Free up the socket as quickly as possible
    drop(local_server);

    if let Some(req_domain) = req_domain {
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
                debug!("DNS({}):{:?} {:?}", altnet_name, dns_addr, rr);
                if let Some(ipaddr) = addr {
                    let (reply_tx, reply_rx) = oneshot::channel();
                    rt_tx.send(RTRequest::Query { ipaddr, reply_tx }).await?;
                    if let Ok(Some(net_if)) = reply_rx.await {
                        if route_through_if != net_if {
                            let (reply_tx, reply_rx) = oneshot::channel();
                            rt_tx
                                .send(RTRequest::QueryGw {
                                    net_if: route_through_if.clone(),
                                    ipaddr,
                                    reply_tx,
                                })
                                .await?;
                            if let Ok(Some(gw_addr)) = reply_rx.await {
                                debug!(
                                    "adding a route for {} ({}) via {:?}!",
                                    req_domain, ipaddr, gw_addr,
                                );
                                // Compute a time slot to expire this entry.
                                // Every ten minutes, we drop all the routes that were created at least an hour ago.
                                //
                                // NOTE: Routes don't expire. We have no idea how long a connection may require them, how long the
                                //       DNS entry will be cached (before we see it again), etc.
                                if let Err(e) = update_route("add", ipaddr, gw_addr).await {
                                    warn!("failed to add route: {}", e);
                                } else {
                                    info!(
                                        "routing {}:{} -> {} via {}({}) (NEW)",
                                        qtype, req_domain, ipaddr, route_through_if, altnet_name
                                    );
                                    let new_rt = RoutingTable::load_from_netstat().await?;
                                    rt_tx.send(RTRequest::Replace(new_rt)).await?;
                                }
                            } else {
                                debug!("no route for {} {} -> {}!", qtype, req_domain, ipaddr)
                            }
                        } else {
                            info!(
                                "routing {}:{} -> {} via {}({})",
                                qtype, req_domain, ipaddr, route_through_if, altnet_name,
                            );
                        }
                    }
                }
            }
        }
    }
    dns_reply_tx.send((reply[..len].to_owned(), addr)).await?;

    Ok(())
}

fn inspect<'a>(
    default_dns_address: SocketAddrV4,
    default_net_if: &'a str,
    altnets: &'a HashMap<String, AltNet>,
    buf: &[u8],
) -> Result<(SocketAddrV4, &'a str, &'a str, Option<String>)> {
    debug!("Inspecting {:?}", buf);
    let msg = bytes::Bytes::copy_from_slice(buf);
    let query = dns_message_parser::Dns::decode(msg)?;
    let mut domain_name: Option<String> = None;
    debug!("query = {:?}", query);
    for question in query.questions {
        debug!("domain_name = {:?}", question.domain_name);
        let this_domain_name: String = question.domain_name.into();
        for (altnet_name, altnet) in altnets {
            if altnet
                .domains
                .iter()
                .any(|domain_name| this_domain_name.ends_with(domain_name))
            {
                return Ok((
                    altnet.dns_address,
                    altnet_name,
                    &altnet.network_interface,
                    Some(this_domain_name),
                ));
            }
        }
        domain_name = Some(this_domain_name);
    }

    Ok((default_dns_address, "default", default_net_if, domain_name))
}

fn ipaddr_same_proto(left: &IpAddr, right: &IpAddr) -> bool {
    std::mem::discriminant(left) == std::mem::discriminant(right)
}

async fn update_route(operation: &str, dest: IpAddr, gw_addr: IpAddr) -> Result<()> {
    let output = Command::new("/sbin/route")
        .arg(operation)
        .arg(format!("{}", dest))
        .arg(gw_addr.to_string())
        .stdout(Stdio::null())
        .output()
        .await?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr =
            String::from_utf8(output.stderr).unwrap_or_else(|_| "non-UTF-8 stderr".to_owned());
        Err(anyhow!(
            "route {} {:?} {:?} exited with {}, err: {}",
            operation,
            dest,
            gw_addr,
            output.status,
            stderr
        ))
    }
}

// Return a gateway address for the specified network interface that matches the
// protocol of the provided IP address
fn query_gateway(rt: &RoutingTable, net_if: &str, addr: &IpAddr) -> Option<IpAddr> {
    rt.default_gateways_for_netif(net_if)
        .map(|gw_addrs| {
            gw_addrs
                .iter()
                .find(|gw_addr| ipaddr_same_proto(gw_addr, addr))
                .cloned()
        })
        .flatten()
}
