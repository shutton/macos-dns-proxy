use anyhow::Result;
use macos_routing_table::RoutingTable;
use std::net::IpAddr;
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
                reply_tx.send(query_gateway(&rt, &net_if, &ipaddr)).unwrap();
            }
        }
    }
    Ok(())
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

fn ipaddr_same_proto(left: &IpAddr, right: &IpAddr) -> bool {
    std::mem::discriminant(left) == std::mem::discriminant(right)
}

pub async fn get_gw_addr(
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
