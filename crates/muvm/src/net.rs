use std::collections::HashMap;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use log::debug;
use regex::Regex;
use rustix::io::dup;

pub fn connect_to_passt<P>(passt_socket_path: P) -> Result<UnixStream>
where
    P: AsRef<Path>,
{
    Ok(UnixStream::connect(passt_socket_path)?)
}

pub fn start_passt(server_port: u32, env: &mut HashMap<String, String>) -> Result<UnixStream> {
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

    // SAFETY: `child_fd` is an `OwnedFd` and consumed to prevent closing on drop,
    // as it will now be owned by the child process.
    // See https://doc.rust-lang.org/std/io/index.html#io-safety
    let output = Command::new("passt")
        .args(["-t"])
        .arg(format!("{server_port}:{server_port}"))
        .arg("--fd")
        .arg(format!("{}", child_fd.into_raw_fd()))
        .output()
        .context("Failed to execute `passt` as child process")?;

    let content = String::from_utf8(output.stderr).context("Failed to parse `passt` output")?;

    let re =
        Regex::new(r".*assign: (?<address>.+)\n.*mask: (?<mask>.+)\n.*router: (?<router>.+).*\n")
            .unwrap();
    if let Some(caps) = re.captures(&content) {
        if let Some(address) = caps.name("address") {
            env.insert(
                "MUVM_NETWORK_ADDRESS".to_owned(),
                address.as_str().to_string(),
            );
        } else {
            println!("Can't read network address from passt output. Expect degraded networking");
        }
        if let Some(mask) = caps.name("mask") {
            env.insert("MUVM_NETWORK_MASK".to_owned(), mask.as_str().to_string());
        } else {
            println!("Can't read network mask from passt output. Expect degraded networking");
        }
        if let Some(router) = caps.name("router") {
            env.insert(
                "MUVM_NETWORK_ROUTER".to_owned(),
                router.as_str().to_string(),
            );
        } else {
            println!("Can't read network router from passt output. Expect degraded networking");
        }
    }

    if let Some(dns_index) = content.find("DNS:") {
        let dns_data = &content[dns_index + 5..];
        let mut i = 1;
        for line in dns_data.split("\n") {
            if line.starts_with("    ") {
                env.insert(
                    format!("MUVM_NETWORK_DNS{}", i).to_owned(),
                    line.trim().to_string(),
                );
                if i == 3 {
                    // MAXNS == 3, ignore the rest.
                    break;
                }
                i += 1;
            } else {
                break;
            }
        }
    }

    if let Some(search_index) = content.find("DNS search list:") {
        let search_data = &content[search_index + 17..];
        for line in search_data.split("\n") {
            if line.starts_with("    ") {
                env.insert("MUVM_NETWORK_SEARCH".to_owned(), line.trim().to_string());
            }
        }
    }

    Ok(parent_socket)
}
