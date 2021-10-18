use anyhow::{anyhow, Result};
use futures::future::FutureExt;
use futures::select;
use log::*;
use macos_routing_table::RoutingTable;
use serde::Deserialize;
use std::net::IpAddr;
use std::net::{SocketAddr, SocketAddrV4};
use structopt::StructOpt;
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
    alternate_networks: Vec<AltNet>,
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
        addr: IpAddr,
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
    for altnet in &config.alternate_networks {
        let dns_addr = IpAddr::from(*altnet.dns_address.ip());
        if let Some(cur_if) = rt.find_gateway_netif(dns_addr) {
            if cur_if == altnet.network_interface {
                info!(
                    "DNS requests for {} are already routed through {}",
                    altnet.dns_address.ip(),
                    altnet.network_interface
                );
            } else {
                warn!(
                    "DNS requests for {} are NOT routed through {}",
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
    tokio::spawn(rt_server(rt_rx));
    // Load the initial routing table
    rt_tx.send(RTRequest::Replace(rt)).await?;

    let (dns_tx, mut dns_rx) = mpsc::channel(32);
    let (dns_reply_tx, dns_reply_rx) = mpsc::channel(32);
    tokio::spawn(dns_server(bind_addr, dns_tx, dns_reply_rx));

    loop {
        while let Some((request, addr)) = dns_rx.recv().await {
            debug!("Received {} bytes from {:?}", request.len(), addr);
            let (dns_addr, route_through_if, req_domain) = inspect(
                default_dns_address,
                &default_net_if,
                &config.alternate_networks,
                &request,
            )?;
            let rt_tx = rt_tx.clone();
            tokio::spawn(handle_request(
                dns_addr,
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
async fn rt_server(mut rx: mpsc::Receiver<RTRequest>) -> Result<()> {
    let mut rt = None;
    let mut cache = lru::LruCache::new(1024);
    while let Some(query) = rx.recv().await {
        match query {
            RTRequest::Replace(new_rt) => rt = Some(new_rt),
            RTRequest::Query { ipaddr, reply_tx } => {
                if let Some(rt) = &rt {
                    let entry = cache.get(&ipaddr).or_else(|| rt.find_route_entry(ipaddr));
                    if let Some(entry) = entry {
                        reply_tx.send(Some(entry.net_if.to_owned())).unwrap();
                        let entry = entry.clone();
                        cache.put(ipaddr, entry);
                    } else {
                        reply_tx.send(None).unwrap();
                    }
                }
            }
            RTRequest::QueryGw {
                net_if,
                addr,
                reply_tx,
            } => {
                reply_tx
                    .send(
                        rt.as_ref()
                            .map(|rt| query_gateway(rt, &net_if, &addr))
                            .flatten(),
                    )
                    .unwrap();
            }
        }
    }
    Ok(())
}

// TODO: this needs to be multiplexed to reduce the number of bind()'s.
async fn handle_request(
    dns_addr: SocketAddrV4,
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
    let len = local_server.recv(&mut reply).await?;

    if let Some(req_domain) = req_domain {
        // Now check the reply and make sure it will use the expected interface
        let msg = bytes::Bytes::copy_from_slice(&reply[..len]);
        let reply_dns = dns_message_parser::Dns::decode(msg);
        if let Ok(reply) = reply_dns {
            for rr in reply.answers {
                // Just handle A records for now.  Ignore AAAA and others.
                if let dns_message_parser::rr::RR::A(a) = rr {
                    let (reply_tx, reply_rx) = oneshot::channel();
                    rt_tx
                        .send(RTRequest::Query {
                            ipaddr: IpAddr::V4(a.ipv4_addr),
                            reply_tx,
                        })
                        .await?;
                    if let Ok(Some(net_if)) = reply_rx.await {
                        if route_through_if != net_if {
                            let (reply_tx, reply_rx) = oneshot::channel();
                            rt_tx
                                .send(RTRequest::QueryGw {
                                    net_if: route_through_if.clone(),
                                    addr: IpAddr::V4(a.ipv4_addr),
                                    reply_tx,
                                })
                                .await?;
                            if let Ok(Some(gw_addr)) = reply_rx.await {
                                warn!(
                                    "Need to add a route for {} ({}) via {:?}! for {:?}",
                                    req_domain,
                                    a.ipv4_addr,
                                    gw_addr,
                                    std::time::Duration::from_secs(a.ttl as u64)
                                );
                                // Compute a time slot to expire this entry.
                                // Every ten minutes, we drop all the routes that were created at least an hour ago.
                                if let Err(e) =
                                    update_route("add", a.ipv4_addr.into(), gw_addr).await
                                {
                                    warn!("failed to add route: {}", e);
                                } else {
                                    let new_rt = RoutingTable::load_from_netstat().await?;
                                    rt_tx.send(RTRequest::Replace(new_rt)).await?;
                                    let req_domain = req_domain.clone();
                                    let rt_tx = rt_tx.clone();
                                    // Remove it after a minute
                                    // FIXME: make it the TTL of the record or longer
                                    tokio::spawn(async move {
                                        tokio::time::sleep(std::time::Duration::from_secs(
                                            a.ttl as u64,
                                        ))
                                        .await;
                                        if let Err(e) =
                                            update_route("delete", a.ipv4_addr.into(), gw_addr)
                                                .await
                                        {
                                            warn!("failed to remove route: {}", e);
                                        } else {
                                            info!(
                                                "removed route for {} ({}) via {:?}",
                                                req_domain, a.ipv4_addr, gw_addr
                                            );
                                            let new_rt =
                                                RoutingTable::load_from_netstat().await.unwrap();
                                            rt_tx.send(RTRequest::Replace(new_rt)).await.unwrap();
                                        };
                                    });
                                }
                            } else {
                                warn!("Couldn't get a route for {} ({})!", req_domain, a.ipv4_addr)
                            }
                        } else {
                            info!(
                                "Route {} ({}) via {}",
                                req_domain, a.ipv4_addr, route_through_if
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
    altnets: &'a [AltNet],
    buf: &[u8],
) -> Result<(SocketAddrV4, &'a str, Option<String>)> {
    debug!("Inspecting {:?}", buf);
    let msg = bytes::Bytes::copy_from_slice(buf);
    let query = dns_message_parser::Dns::decode(msg)?;
    let mut domain_name: Option<String> = None;
    debug!("query = {:?}", query);
    for question in query.questions {
        debug!("domain_name = {:?}", question.domain_name);
        let this_domain_name: String = question.domain_name.into();
        for altnet in altnets {
            if altnet
                .domains
                .iter()
                .any(|domain_name| this_domain_name.ends_with(domain_name))
            {
                return Ok((
                    altnet.dns_address,
                    &altnet.network_interface,
                    Some(this_domain_name),
                ));
            }
        }
        domain_name = Some(this_domain_name);
    }

    Ok((default_dns_address, default_net_if, domain_name))
}

fn ipaddr_same_proto(left: &IpAddr, right: &IpAddr) -> bool {
    std::mem::discriminant(left) == std::mem::discriminant(right)
}

async fn update_route(operation: &str, dest: IpAddr, gw_addr: IpAddr) -> Result<()> {
    let mut child = Command::new("/sbin/route")
        .arg(operation)
        .arg(format!("{}", dest))
        .arg(gw_addr.to_string())
        .spawn()?;
    let status = child.wait().await?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "route {} {:?} {:?} exited with {}",
            operation,
            dest,
            gw_addr,
            status
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
