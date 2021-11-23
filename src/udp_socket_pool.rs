pub struct UdpSocketPool;
use std::os::unix::prelude::AsRawFd;

use anyhow::Result;
use async_trait::async_trait;
use log::debug;
use nix::sys::socket::{self, sockopt::ReusePort};
use tokio::net::UdpSocket;

#[async_trait]
impl deadpool::managed::Manager for UdpSocketPool {
    type Type = UdpSocket;
    type Error = anyhow::Error;

    async fn create(&self) -> Result<UdpSocket> {
        debug!("Creating socket");
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        socket::setsockopt(sock.as_raw_fd(), ReusePort, &true)?;
        debug!("Sock: {:?}", sock);
        Ok(sock)
    }

    async fn recycle(
        &self,
        _sock: &mut UdpSocket,
    ) -> deadpool::managed::RecycleResult<anyhow::Error> {
        debug!("Recycling socket");
        Ok(())
    }
}
