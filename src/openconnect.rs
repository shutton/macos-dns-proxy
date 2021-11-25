use crate::config::{AltNet, DynVpn};
use crate::rt_server::{get_gw_addr, update_route, update_routing_table, RTRequest};
use anyhow::{anyhow, Result};
use cidr::AnyIpCidr;
use log::{debug, info, warn};
use nix::unistd::mkfifo;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddrV4};
use std::os::unix::prelude::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

const OPENCONNECT_PATH: &str = "/usr/local/bin/openconnect";
const DEFAULT_IP4_MTU: &str = "1412";

// pub async fn spawn(vpncfg: DynVpn) -> Result<()> {
pub async fn spawn(
    net_name: String,
    altnet: Arc<RwLock<AltNet>>,
    rt_tx: mpsc::Sender<RTRequest>,
) -> Result<()> {
    let mut cmd = Command::new(OPENCONNECT_PATH);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    let mut password = None;
    let mut server = String::new();

    match altnet.read() {
        Ok(altnet_guard) => {
            if let Some(DynVpn::OpenConnect(occfg)) = &(*altnet_guard).dyn_vpn {
                cmd.arg(format!("--protocol={}", occfg.protocol));

                // Set user/password
                match (&occfg.user, &occfg.password) {
                    (Some(user), Some(passwd)) => {
                        cmd.arg(format!("--user={}", user));
                        cmd.arg("--passwd-on-stdin");
                        password = Some(passwd.clone());
                    }
                    (None, Some(_)) => return Err(anyhow!("password specified without user")),
                    // Grab this from the macOS keychain
                    (Some(_), None) => todo!(),
                    (None, None) => (),
                };

                if let Some(cert) = &occfg.server_cert {
                    cmd.arg(format!("--servercert={}", cert));
                }

                server = occfg.server.clone();
            }
        }
        Err(e) => return Err(anyhow!("Unable to lock altnet for reading: {}", e)),
    }

    // Hack up a VPN script that just sends back the environment
    let dir = tempdir()?;
    let script_path = dir.path().join("vpnc-script");
    let pipe_path = dir.path().join("vpnc-pipe");
    let content = format!("#!/bin/sh\nprintenv > {}", pipe_path.to_str().unwrap());
    tokio::fs::write(&script_path, content).await?;
    let mut perms = std::fs::metadata(&script_path)?.permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(&script_path, perms)?;
    mkfifo(&pipe_path, nix::sys::stat::Mode::S_IRWXU)?;
    info!("vpnc-script = {:?}", &script_path);
    info!("vpnc-pipe   = {:?}", &pipe_path);
    cmd.arg(format!("--script={}", script_path.to_str().unwrap()));

    cmd.arg(server);

    {
        let altnet = altnet.clone();
        tokio::spawn(async move {
            if let Err(e) =
                spawn_openconnect(net_name, altnet, cmd, password, dir, pipe_path, rt_tx).await
            {
                warn!("Failed to spawn openconnect: {}", e);
            }
        });
    }

    Ok(())
}

async fn spawn_openconnect(
    net_name: String,
    altnet: Arc<RwLock<AltNet>>,
    mut cmd: Command,
    password: Option<String>,
    _tempdir: TempDir,
    pipe_path: PathBuf,
    rt_tx: mpsc::Sender<RTRequest>,
) -> Result<()> {
    info!("spawning openconnect for {}", &net_name);
    let mut child = cmd.spawn()?;

    // Feed in the password (or nothing)
    let mut stdin = child.stdin.take().unwrap();
    if let Some(password) = password {
        debug!("sending password for {}", &net_name);
        stdin.write_all(password.as_bytes()).await?;
        stdin.flush().await?;
    }
    drop(stdin);

    {
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let net_name = net_name.clone();
        tokio::spawn(async move {
            let mut lines = stdout.lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                info!("stdout({}) = {:?}", &net_name, line);
            }
        });
    }

    {
        let stderr = BufReader::new(child.stderr.take().unwrap());
        let net_name = net_name.clone();
        tokio::spawn(async move {
            let mut lines = stderr.lines();
            while let Some(line) = lines.next_line().await.unwrap() {
                info!("stderr({}) = {:?}", &net_name, line);
            }
        });
    }

    // Snag the output from the named pipe
    loop {
        debug!("waiting for openconnect for {}", &net_name);
        let oc_env = String::from_utf8(tokio::fs::read(&pipe_path).await?)?;

        debug!("received environment for {}", &net_name);

        let mut reason = None;
        let mut env = HashMap::new();

        for line in oc_env.lines() {
            let mut parts = line.splitn(2, '=');
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                if key == "reason" {
                    reason = Some(value);
                } else if key.starts_with("INTERNAL_IP4_") || key == "VPNGATEWAY" || key == "TUNDEV"
                {
                    env.insert(key, value);
                }
            }
        }

        if let Some(reason) = reason {
            info!("openconnect called vpnc-script, reason = {}", reason);
            match reason {
                "connect" => {
                    match vpn_up(env, rt_tx.clone()).await {
                        Ok(vp) => {
                            info!("{} VPN is up", &net_name);
                            // Update the route and device in the altnet profile
                            if let Ok(mut altnet_guard) = altnet.write() {
                                altnet_guard.router = Some(vp.internal_ip4_addr);
                                altnet_guard.network_interface = vp.tundev.clone();
                                // FIXME: add more than one if available
                                if let Some(std::net::IpAddr::V4(addr)) = vp.internal_ip4_dns.get(0)
                                {
                                    altnet_guard.dns_address = SocketAddrV4::new(*addr, 53);
                                }
                            }
                        }
                        Err(e) => warn!("{} VPN failed setup: {}", &net_name, e),
                    }
                }
                "disconnect" => {
                    // This is generally not desirable
                    warn!("{} VPN disconnected", &net_name);
                    match vpn_down(env).await {
                        Ok(vp) => {
                            // Update the route and device in the altnet profile
                            if let Ok(mut altnet_guard) = altnet.write() {
                                altnet_guard.router = Some(vp.internal_ip4_addr);
                                altnet_guard.network_interface = vp.tundev.clone();
                                // FIXME: add more than one if available
                                if let Some(std::net::IpAddr::V4(addr)) = vp.internal_ip4_dns.get(0)
                                {
                                    altnet_guard.dns_address = SocketAddrV4::new(*addr, 53);
                                }
                            }
                        }
                        Err(e) => warn!("{} VPN failed teardown: {}", &net_name, e),
                    }
                    if let Ok(mut altnet_guard) = altnet.write() {
                        altnet_guard.router = None;
                    }
                }
                reason => {
                    info!("{} VPN event {:?}", &net_name, reason);
                    // Nothing else to do
                    continue;
                }
            }
            if let Err(e) = update_routing_table(rt_tx.clone()).await {
                warn!("Unable to update routing table: {}", e);
            }
        }
    }
}

struct VpnParams {
    tundev: String,
    vpn_gateway: IpAddr,
    internal_ip4_addr: IpAddr,
    internal_ip4_net: AnyIpCidr,
    internal_ip4_mtu: usize,
    internal_ip4_dns: Vec<IpAddr>,
}

impl TryFrom<&HashMap<&str, &str>> for VpnParams {
    type Error = anyhow::Error;

    fn try_from(env: &HashMap<&str, &str>) -> Result<Self> {
        let tundev = env
            .get("TUNDEV")
            .ok_or_else(|| anyhow!("TUNDEV not specified"))?
            .to_string();

        let vpn_gateway = env
            .get("VPNGATEWAY")
            .ok_or_else(|| anyhow!("VPNGATEWAY not specified"))?
            .parse()?;

        let internal_ip4_addr = env
            .get("INTERNAL_IP4_ADDRESS")
            .ok_or_else(|| {
                anyhow!("neither INTERNAL_IP4_ADDRESS nor INTERNAL_IP6_ADDRESS specified")
            })?
            .parse()?;

        let internal_ip4_netaddr = env
            .get("INTERNAL_IP4_NETADDR")
            .ok_or_else(|| {
                anyhow!("neither INTERNAL_IP4_NETADDR nor INTERNAL_IP6_NETADDR specified")
            })?
            .parse()?;

        // FIXME: IPv6 not handled
        let internal_netmask_len = convert_netmask(
            env.get("INTERNAL_IP4_NETMASK")
                .ok_or_else(|| anyhow!("INTERNAL_IP4_NETMASK not specified"))?,
        )?;

        let internal_ip4_net = AnyIpCidr::new(internal_ip4_netaddr, internal_netmask_len)?;

        let internal_ip4_mtu = if let Some(mtu) = env.get("INTERNAL_IP4_MTU") {
            mtu.parse()?
        } else {
            DEFAULT_IP4_MTU.parse()?
        };

        let mut internal_ip4_dns = vec![];
        if let Some(addrs) = env.get("INTERNAL_IP4_DNS") {
            for addr in addrs.split(' ') {
                internal_ip4_dns.push(addr.parse()?);
            }
        }

        Ok(VpnParams {
            tundev,
            vpn_gateway,
            internal_ip4_addr,
            internal_ip4_net,
            internal_ip4_mtu,
            internal_ip4_dns,
        })
    }
}

fn convert_netmask(mask: &str) -> Result<u8> {
    let netmask = std::net::Ipv4Addr::from_str(mask)?;
    let addr_u32 = u32::from_be_bytes(netmask.octets());
    let mut mask_len = 0;
    for i in (0..32).rev() {
        if addr_u32 & (1 << i) != 0 {
            mask_len += 1;
        } else {
            break;
        }
    }
    Ok(mask_len)
}

async fn ifconfig_tun_dev(vp: &VpnParams) -> Result<()> {
    let mut cmd = Command::new("/sbin/ifconfig");
    cmd.arg(&vp.tundev);
    cmd.arg(format!("{}", vp.internal_ip4_addr));
    cmd.arg(format!("{}", vp.internal_ip4_addr));
    cmd.arg("netmask");
    cmd.arg("255.255.255.255");
    cmd.arg("mtu");
    cmd.arg(format!("{}", vp.internal_ip4_mtu));
    info!("Executing: {:?}", &cmd);

    match cmd.output().await {
        Ok(output) => {
            info!(
                "ifconfig status {}, output = {:?}, err = {:?}",
                output.status, output.stdout, output.stderr
            );
            Ok(())
        }
        Err(e) => Err(anyhow!("failed to execute ifconfig: {}", e)),
    }
}

async fn vpn_down(env: HashMap<&str, &str>) -> Result<VpnParams> {
    let vp =
        VpnParams::try_from(&env).map_err(|e| anyhow!("Unable to obtain VPN parameters: {}", e))?;

    // Remove the route to the internal network via the VPN gateway
    update_route("delete", vp.internal_ip4_net, vp.internal_ip4_addr)
        .await
        .map_err(|e| {
            anyhow!(
                "Failed to remove network route for {:?} -> {:?}: {}",
                vp.internal_ip4_net,
                vp.internal_ip4_addr,
                e
            )
        })?;
    Ok(vp)
}

async fn vpn_up(env: HashMap<&str, &str>, rt_tx: mpsc::Sender<RTRequest>) -> Result<VpnParams> {
    let vp =
        VpnParams::try_from(&env).map_err(|e| anyhow!("Unable to obtain VPN parameters: {}", e))?;

    ifconfig_tun_dev(&vp)
        .await
        .map_err(|e| anyhow!("Unable to configure tunnel interface: {}", e))?;

    if false {
        // Set a persistent route to the VPN gateway via the default gateway
        // Note: probably not necessary when not overriding the default route!
        let default_gw_addr = get_gw_addr(rt_tx.clone(), vp.vpn_gateway)
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "Failed to determine gateway address for VPN gateway ({})",
                    vp.vpn_gateway
                )
            })?;

        update_route("add", AnyIpCidr::new_host(vp.vpn_gateway), default_gw_addr)
            .await
            .map_err(|e| {
                anyhow!(
                    "Failed to set host route for {:?} -> {:?}: {}",
                    vp.vpn_gateway,
                    default_gw_addr,
                    e
                )
            })?;
        info!(
            "Routed VPN gateway ({}) through {}",
            vp.vpn_gateway, default_gw_addr
        );
    }

    // Set a route to the internal network via the VPN gateway
    update_route("add", vp.internal_ip4_net, vp.internal_ip4_addr)
        .await
        .map_err(|e| {
            anyhow!(
                "Failed to set network route for {:?} -> {:?}: {}",
                vp.internal_ip4_net,
                vp.internal_ip4_addr,
                e
            )
        })?;

    // Make sure the DNS addresses for this altnet are routed correctly
    // FIXME: These routes might still exist from a prior invocation.  For now, ignore any errors.
    for dns_addr in &vp.internal_ip4_dns {
        if let Err(e) =
            update_route("add", AnyIpCidr::new_host(*dns_addr), vp.internal_ip4_addr).await
        {
            warn!(
                "Couldn't add route for DNS address {} via {}: {}",
                dns_addr, vp.internal_ip4_addr, e
            );
        }
    }

    Ok(vp)
}
