use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use rtnetlink::new_connection;
use rustix::system::sethostname;

use super::mount::place_etc;

pub struct NetworkConfig {
    pub address: Option<String>,
    pub mask: Option<String>,
    pub router: Option<String>,
    pub dns1: Option<String>,
    pub dns2: Option<String>,
    pub dns3: Option<String>,
    pub search: Option<String>,
}

pub async fn configure_network(netconf: NetworkConfig) -> Result<()> {
    // Allow unprivileged users to use ping, as most distros do by default.
    {
        let mut file = fs::File::options()
            .write(true)
            .open("/proc/sys/net/ipv4/ping_group_range")
            .context("Failed to open ipv4/ping_group_range for writing")?;

        file.write_all(format!("{} {}", 0, 2147483647).as_bytes())
            .context("Failed to extend ping group range")?;
    }

    {
        let hostname =
            fs::read_to_string("/etc/hostname").unwrap_or("placeholder-hostname".to_string());
        let hostname = if let Some((hostname, _)) = hostname.split_once('\n') {
            hostname.to_owned()
        } else {
            hostname
        };
        sethostname(hostname.as_bytes()).context("Failed to set hostname")?;
    }

    let address = Ipv4Addr::from_str(&netconf.address.context("Missing MUVM_NETWORK_ADDRESS")?)?;
    let mask = u32::from(Ipv4Addr::from_str(
        &netconf.mask.context("Missing MUVM_NETWORK_MASK")?,
    )?);
    let prefix = (!mask).leading_zeros() as u8;
    let router = netconf.router.context("Missing MUVM_NETWORK_ROUTER")?;
    let router = Ipv4Addr::from_str(&router)?;

    let (connection, handle, _) = new_connection().unwrap();
    tokio::spawn(connection);
    let mut links = handle.link().get().match_name("eth0".to_string()).execute();
    if let Some(link) = links.try_next().await? {
        handle
            .address()
            .add(link.header.index, IpAddr::V4(address), prefix)
            .execute()
            .await?;
        handle.link().set(link.header.index).up().execute().await?
    }
    handle.route().add().v4().gateway(router).execute().await?;

    // Only override resolv.conf is we have some values to put on it.
    if netconf.dns1.is_some() || netconf.dns2.is_some() || netconf.dns3.is_some() {
        place_etc("resolv.conf", None)?;
        let mut resolv = fs::File::options()
            .write(true)
            .open("/etc/resolv.conf")
            .context("Failed to open resolv.conf")?;

        for ns in [netconf.dns1, netconf.dns2, netconf.dns3]
            .into_iter()
            .flatten()
        {
            resolv
                .write_all(format!("nameserver {}\n", ns).as_bytes())
                .context("Failed to write resolv.conf")?;
        }

        if let Some(search) = netconf.search {
            resolv
                .write_all(format!("search {}\n", search).as_bytes())
                .context("Failed to write resolv.conf")?;
        }
    }

    Ok(())
}
