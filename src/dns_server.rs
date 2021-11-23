use anyhow::Result;
use futures::future::FutureExt;
use futures::select;
use log::{debug, info, warn};
use nix::sys::socket::{self, sockopt::ReusePort};
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use tokio::{net::UdpSocket, sync::mpsc};

/// The base DNS server.  As queries are received, they're sent back via the `tx`
/// MPSC channel along with the client socket address.  Also monitors the `rx`
/// channel for responses and relays those to the specified socket address.
pub async fn dns_server<T: tokio::net::ToSocketAddrs + std::fmt::Debug>(
    bind_addr: T,
    tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    mut rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
) -> Result<()> {
    debug!("Binding to {:?}", &bind_addr);
    let server_socket = UdpSocket::bind(bind_addr).await?;
    socket::setsockopt(server_socket.as_raw_fd(), ReusePort, &true)?;
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
