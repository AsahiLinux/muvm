use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use log::debug;
use rustix::io::dup;

struct PublishSpec<'a> {
    udp: bool,
    guest_range: (u32, u32),
    host_range: (u32, u32),
    ip: &'a str,
}

fn parse_range(r: &str) -> Result<(u32, u32)> {
    Ok(if let Some(pos) = r.find('-') {
        (r[..pos].parse()?, r[pos + 1..].parse()?)
    } else {
        let val = r.parse()?;
        (val, val)
    })
}

impl PublishSpec<'_> {
    fn parse(mut arg: &str) -> Result<PublishSpec> {
        let mut udp = false;
        if arg.ends_with("/udp") {
            udp = true;
        }
        if let Some(pos) = arg.rfind('/') {
            arg = &arg[..pos];
        }
        let guest_range_start = arg.rfind(':');
        let guest_range = parse_range(&arg[guest_range_start.map(|x| x + 1).unwrap_or(0)..])?;
        let mut ip = "";
        let host_range = match guest_range_start {
            None => guest_range,
            Some(guest_range_start) => {
                arg = &arg[..guest_range_start];
                let ip_start = arg.rfind(':');
                if let Some(ip_start) = ip_start {
                    ip = &arg[..ip_start];
                    arg = &arg[ip_start + 1..];
                }
                if arg.is_empty() {
                    guest_range
                } else {
                    parse_range(arg)?
                }
            },
        };
        Ok(PublishSpec {
            ip,
            host_range,
            guest_range,
            udp,
        })
    }
    fn to_args(&self) -> [String; 2] {
        let optslash = if self.ip.is_empty() { "" } else { "/" };
        [
            if self.udp { "-u" } else { "-t" }.to_owned(),
            format!(
                "{}{}{}-{}:{}-{}",
                self.ip,
                optslash,
                self.host_range.0,
                self.host_range.1,
                self.guest_range.0,
                self.guest_range.1
            ),
        ]
    }
}

pub fn connect_to_passt<P>(passt_socket_path: P) -> Result<UnixStream>
where
    P: AsRef<Path>,
{
    Ok(UnixStream::connect(passt_socket_path)?)
}

pub fn start_passt(publish_ports: &[String]) -> Result<UnixStream> {
    // SAFETY: The child process should not inherit the file descriptor of
    // `parent_socket`. There is no documented guarantee of this, but the
    // implementation as of writing atomically sets `SOCK_CLOEXEC`.
    // See https://github.com/rust-lang/rust/blob/1.77.0/library/std/src/sys/pal/unix/net.rs#L124-L125
    // See https://github.com/rust-lang/rust/issues/47946#issuecomment-364776373
    let (parent_socket, child_socket) =
        UnixStream::pair().context("Failed to create socket pair for `passt` child process")?;

    // SAFETY: The parent process should not keep the file descriptor of
    // `child_socket` open. It is a `UnixStream` so the file descriptor will be
    // closed on drop.
    // See https://doc.rust-lang.org/std/io/index.html#io-safety
    //
    // The `dup` call clears the `FD_CLOEXEC` flag on the new `child_fd`, which
    // should be inherited by the child process.
    let child_fd = dup(child_socket)
        .context("Failed to duplicate file descriptor for `passt` child process")?;

    debug!(fd = child_fd.as_raw_fd(); "passing fd to passt");

    let mut cmd = Command::new("passt");
    // SAFETY: `child_fd` is an `OwnedFd` and consumed to prevent closing on drop,
    // as it will now be owned by the child process.
    // See https://doc.rust-lang.org/std/io/index.html#io-safety
    cmd.args(["-q", "-f", "--fd"])
        .arg(format!("{}", child_fd.into_raw_fd()));
    for spec in publish_ports {
        cmd.args(PublishSpec::parse(spec)?.to_args());
    }
    let child = cmd.spawn();
    if let Err(err) = child {
        return Err(err).context("Failed to execute `passt` as child process");
    }

    Ok(parent_socket)
}
