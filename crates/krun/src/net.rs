use std::{
    fmt,
    os::{
        fd::{AsRawFd, IntoRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    path::Path,
    process::Command,
};

use anyhow::{Context, Result};
use log::debug;
use rustix::{
    io::dup,
    net::{socketpair, AddressFamily, SocketFlags, SocketType},
};

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum NetMode {
    PASST = 0,
    TSI,
}

pub fn connect_to_passt<P>(passt_socket_path: P) -> Result<UnixStream>
where
    P: AsRef<Path> + fmt::Debug,
{
    Ok(UnixStream::connect(passt_socket_path)?)
}

pub fn start_passt() -> Result<OwnedFd> {
    let (parent_fd, child_fd) = socketpair(
        AddressFamily::UNIX,
        SocketType::STREAM,
        // SAFETY: The child process should not inherit `parent_fd`.
        SocketFlags::CLOEXEC,
        None,
    )?;

    // SAFETY: The parent process should not keep `child_fd` open. It is an `OwnedFd` so it will be
    // closed on drop.
    // See https://doc.rust-lang.org/std/io/index.html#io-safety
    //
    // The `dup` call clears the `FD_CLOEXEC` flag on the new `child_fd`, which should be inherited
    // by the child process.
    let child_fd =
        dup(child_fd).context("Failed to duplicate file descriptor for `passt` child process")?;

    debug!(fd = child_fd.as_raw_fd(); "passing fd to passt");

    // SAFETY: `child_fd` is an `OwnedFd` and consumed to prevent closing on drop, as it will now be
    // owned by the child process.
    // See https://doc.rust-lang.org/std/io/index.html#io-safety
    let child = Command::new("passt")
        .args(["-q", "-f", "--fd"])
        .arg(format!("{}", child_fd.into_raw_fd()))
        .spawn();
    if let Err(err) = child {
        return Err(err).context("Failed to execute `passt` as child process");
    }

    Ok(parent_fd)
}
