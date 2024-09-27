use std::fs;
use std::io::Write;
use std::os::unix::process::ExitStatusExt as _;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use log::debug;
use rustix::system::sethostname;

use crate::utils::env::find_in_path;
use crate::utils::fs::find_executable;

pub fn configure_network() -> Result<()> {
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
            fs::read_to_string("/etc/hostname").context("Failed to read `/etc/hostname`")?;
        let hostname = if let Some((hostname, _)) = hostname.split_once('\n') {
            hostname.to_owned()
        } else {
            hostname
        };
        sethostname(hostname.as_bytes()).context("Failed to set hostname")?;
    }

    let dhcpcd_path = find_in_path("dhcpcd").context("Failed to check existence of `dhcpcd`")?;
    let dhcpcd_path = if let Some(dhcpcd_path) = dhcpcd_path {
        Some(dhcpcd_path)
    } else {
        find_executable("/sbin/dhcpcd").context("Failed to check existence of `/sbin/dhcpcd`")?
    };
    if let Some(dhcpcd_path) = dhcpcd_path {
        let output = Command::new(dhcpcd_path)
            .args(["-M", "--nodev", "eth0"])
            .output()
            .context("Failed to execute `dhcpcd` as child process")?;
        debug!(output:?; "dhcpcd output");
        if !output.status.success() {
            let err = if let Some(code) = output.status.code() {
                anyhow!("`dhcpcd` process exited with status code: {code}")
            } else {
                anyhow!(
                    "`dhcpcd` process terminated by signal: {}",
                    output
                        .status
                        .signal()
                        .expect("either one of status code or signal should be set")
                )
            };
            Err(err)?;
        }

        return Ok(());
    }

    let dhclient_path =
        find_in_path("dhclient").context("Failed to check existence of `dhclient`")?;
    let dhclient_path = if let Some(dhclient_path) = dhclient_path {
        Some(dhclient_path)
    } else {
        find_executable("/sbin/dhclient")
            .context("Failed to check existence of `/sbin/dhclient`")?
    };
    let dhclient_path =
        dhclient_path.ok_or_else(|| anyhow!("could not find required `dhcpcd` or `dhclient`"))?;
    let output = Command::new(dhclient_path)
        .output()
        .context("Failed to execute `dhclient` as child process")?;
    debug!(output:?; "dhclient output");
    if !output.status.success() {
        let err = if let Some(code) = output.status.code() {
            anyhow!("`dhclient` process exited with status code: {code}")
        } else {
            anyhow!(
                "`dhclient` process terminated by signal: {}",
                output
                    .status
                    .signal()
                    .expect("either one of status code or signal should be set")
            )
        };
        Err(err)?;
    }

    Ok(())
}
