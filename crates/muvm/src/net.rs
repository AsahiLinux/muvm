use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use log::debug;
use rustix::io::dup;

pub fn connect_to_passt<P>(passt_socket_path: P) -> Result<UnixStream>
where
    P: AsRef<Path>,
{
    Ok(UnixStream::connect(passt_socket_path)?)
}

pub fn start_passt(server_port: u32, root_server_port: u32) -> Result<UnixStream> {
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
    let child = Command::new("passt")
        .args(["-q", "-f", "-t"])
        .arg(format!(
            "{server_port}:{server_port},{root_server_port}:{root_server_port}"
        ))
        .arg("--fd")
        .arg(format!("{}", child_fd.into_raw_fd()))
        .spawn();
    if let Err(err) = child {
        return Err(err).context("Failed to execute `passt` as child process");
    }

    Ok(parent_socket)
}
