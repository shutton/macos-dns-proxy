use anyhow::{anyhow, Result};
use cidr::{AnyIpCidr, Cidr};
use log::debug;
use macos_routing_table::RoutingTable;
use std::net::IpAddr;
use std::process::Stdio;
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};

/// A routing table request
#[derive(Debug)]
pub enum RTRequest {
    /// Replace the routing table with the one provided
    Replace(RoutingTable),
    /// Query the routing table for the given IP address to find the interface
    /// currently handling that IP.  The response is sent back via the provided
    /// oneshot channel.
    Query {
        ipaddr: IpAddr,
        reply_tx: oneshot::Sender<Option<String>>,
    },
    QueryGw {
        ipaddr: IpAddr,
        reply_tx: oneshot::Sender<Option<IpAddr>>,
    },
    // Query the gateway address for routing an address across a given interface
    QueryDefaultGw {
        net_if: String,
        ipaddr: IpAddr,
        reply_tx: oneshot::Sender<Option<IpAddr>>,
    },
}

/// The routing table server.  Holds a routing table, and performs queries
/// against it, as well as allowing its replacement.
pub async fn rt_server(mut rx: mpsc::Receiver<RTRequest>, mut rt: RoutingTable) -> Result<()> {
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
            RTRequest::QueryDefaultGw {
                net_if,
                ipaddr,
                reply_tx,
            } => {
                reply_tx
                    .send(query_default_gw(&rt, &net_if, &ipaddr))
                    .unwrap();
            }
            RTRequest::QueryGw { ipaddr, reply_tx } => {
                if let Some((entity, _)) = rt.find_gateway(ipaddr) {
                    match entity {
                        macos_routing_table::Entity::Cidr(cidr) => {
                            if cidr.is_host_address() {
                                reply_tx.send(Some(cidr.first_address().unwrap())).unwrap();
                            } else {
                                reply_tx.send(None).unwrap();
                            }
                        }
                        _ => reply_tx.send(None).unwrap(),
                    }
                }
            }
        }
    }
    Ok(())
}

// Return a gateway address for the specified network interface that matches the
// protocol of the provided IP address
fn query_default_gw(rt: &RoutingTable, net_if: &str, addr: &IpAddr) -> Option<IpAddr> {
    rt.default_gateways_for_netif(net_if)
        .map(|gw_addrs| {
            gw_addrs
                .iter()
                .find(|gw_addr| ipaddr_same_proto(gw_addr, addr))
                .cloned()
        })
        .flatten()
}

fn ipaddr_same_proto(left: &IpAddr, right: &IpAddr) -> bool {
    std::mem::discriminant(left) == std::mem::discriminant(right)
}

pub async fn get_gw_addr(rt_tx: mpsc::Sender<RTRequest>, ipaddr: IpAddr) -> Result<Option<IpAddr>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rt_tx.send(RTRequest::QueryGw { reply_tx, ipaddr }).await?;
    Ok(reply_rx.await?)
}

pub async fn get_default_gw_addr(
    rt_tx: mpsc::Sender<RTRequest>,
    route_through_if: &str,
    ipaddr: IpAddr,
) -> Result<Option<IpAddr>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rt_tx
        .send(RTRequest::QueryDefaultGw {
            net_if: route_through_if.to_owned(),
            ipaddr,
            reply_tx,
        })
        .await?;
    Ok(reply_rx.await?)
}

pub async fn get_gw_netif(
    rt_tx: mpsc::Sender<RTRequest>,
    ipaddr: IpAddr,
) -> Result<Option<String>> {
    let (reply_tx, reply_rx) = oneshot::channel();
    rt_tx.send(RTRequest::Query { ipaddr, reply_tx }).await?;
    Ok(reply_rx.await?)
}

pub async fn update_route(operation: &str, dest: AnyIpCidr, gw_addr: IpAddr) -> Result<()> {
    let mut cmd = Command::new("/sbin/route");
    cmd.arg(operation);
    match dest {
        AnyIpCidr::Any => todo!(),
        AnyIpCidr::V4(dest) => {
            if dest.is_host_address() {
                cmd.arg("-host");
                cmd.arg(format!("{}", dest.first_address()));
            } else {
                cmd.arg("-net");
                cmd.arg(format!("{}", dest.first_address()));
                cmd.arg("-netmask");
                cmd.arg(format!("{}", dest.mask()));
            }
        }
        AnyIpCidr::V6(_) => todo!(),
    }
    cmd.arg(gw_addr.to_string());
    debug!("Executing {:?}", &cmd);
    let output = cmd.stdout(Stdio::null()).output().await?;
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

pub async fn update_routing_table(rt_tx: mpsc::Sender<RTRequest>) -> Result<()> {
    let new_rt = RoutingTable::load_from_netstat()
        .await
        .map_err(|e| anyhow!("Unable to load new routing table: {}", e))?;
    rt_tx
        .send(RTRequest::Replace(new_rt))
        .await
        .map_err(|e| anyhow!("Unable to send new routing table: {}", e))?;
    Ok(())
}
