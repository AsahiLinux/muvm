use std::collections::HashMap;
use std::env;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::symlink;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use log::debug;
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, UnixAddr};

pub struct HostBus {
    path: PathBuf,
    alias: bool,
}

impl HostBus {
    fn new(path: PathBuf, runtime_dir: &Path) -> Result<Self> {
        if path.to_str().is_some() {
            return Ok(Self { path, alias: false });
        }

        // libkrun requires UTF-8 even though Unix sockets accept arbitrary bytes.
        // Its normal shutdown uses _exit, so reuse one runtime-directory alias
        // under the launcher's VM lock instead of leaking a temporary directory.
        let dir = runtime_dir.join("krun");
        let alias_path = dir.join("atspi");
        if alias_path.to_str().is_none() {
            bail!("AT-SPI host alias path is not UTF-8");
        }
        fs::create_dir_all(dir)?;
        match fs::symlink_metadata(&alias_path) {
            Ok(meta) if meta.file_type().is_symlink() => fs::remove_file(&alias_path)?,
            Ok(_) => bail!("AT-SPI host alias {alias_path:?} already exists and is not a symlink"),
            Err(err) if err.kind() == ErrorKind::NotFound => {},
            Err(err) => return Err(err.into()),
        }
        symlink(std::path::absolute(&path)?, &alias_path)?;
        Ok(Self {
            path: alias_path,
            alias: true,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for HostBus {
    fn drop(&mut self) {
        if self.alias {
            // Clean up on startup errors; normal shutdown leaves the reusable
            // symlink for the next launch or XDG_RUNTIME_DIR session cleanup.
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn parse_unix_path_address(address: &str) -> Option<PathBuf> {
    if address.contains(';') {
        return None;
    }
    let pairs = address.strip_prefix("unix:")?;
    let mut path = None;
    for pair in pairs.split(',') {
        let (key, value) = pair.split_once('=')?;
        if key == "path" {
            path = Some(percent_decode(value)?);
        }
    }
    path.filter(|p| !p.is_empty()).map(PathBuf::from)
}

fn percent_decode(value: &str) -> Option<OsString> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(OsString::from_vec(out))
}

pub fn percent_encode(path: &Path) -> String {
    let mut out = String::new();
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_/.\\*".contains(&b) {
            out.push(b as char);
        } else {
            write!(out, "%{b:02X}").unwrap();
        }
    }
    out
}

pub fn guest_socket_path(host_path: &Path, uid: u32) -> PathBuf {
    // Preserve the path advertised by the host's AT_SPI_BUS X11 property.
    // Non-UTF-8 paths need an alias because the guest configuration uses JSON.
    let runtime_dir = PathBuf::from(format!("/run/user/{uid}"));
    if host_path.starts_with(&runtime_dir)
        && host_path.to_str().is_some()
        && !host_path
            .components()
            .any(|part| part == Component::ParentDir)
    {
        host_path.to_path_buf()
    } else {
        runtime_dir.join("at-spi").join("bus_0")
    }
}

pub fn configure_guest_env(env: &mut HashMap<String, String>, guest_path: &Path) {
    env.entry("AT_SPI_BUS_ADDRESS".to_owned())
        .or_insert_with(|| format!("unix:path={}", percent_encode(guest_path)));
    // The host cannot reach guest application sockets.
    env.entry("ATSPI_DISABLE_P2P".to_owned())
        .or_insert_with(|| "1".to_owned());
    // Firefox otherwise waits for org.a11y.Status on the unbridged session bus.
    env.entry("GNOME_ACCESSIBILITY".to_owned())
        .or_insert_with(|| "1".to_owned());
}

fn can_connect(path: &Path) -> bool {
    // A full listen queue must not block startup.
    let result = UnixAddr::new(path).and_then(|address| {
        let fd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )?;
        connect(fd.as_raw_fd(), &address)
    });
    if let Err(err) = result {
        debug!(path:?, err:?; "AT-SPI bus socket is unavailable");
    }
    result.is_ok()
}

fn query_host_bus_address() -> Result<String> {
    let output = Command::new("busctl")
        .args([
            "--user",
            "--timeout=5",
            "--json=short",
            "call",
            "org.a11y.Bus",
            "/org/a11y/bus",
            "org.a11y.Bus",
            "GetAddress",
        ])
        .output()
        .context("failed to run busctl")?;
    if !output.status.success() {
        bail!(
            "GetAddress failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    reply["data"][0]
        .as_str()
        .map(str::to_owned)
        .context("GetAddress did not return an address")
}

fn path_from_address(source: &str, address: &str) -> Option<PathBuf> {
    let path = parse_unix_path_address(address);
    if path.is_none() {
        eprintln!("AT-SPI bus address {address:?} from {source} is not a single unix:path address");
    }
    path
}

pub fn discover_host_bus(runtime_dir: &Path) -> Option<HostBus> {
    let (source, address) = match env::var("AT_SPI_BUS_ADDRESS")
        .ok()
        .filter(|a| !a.is_empty())
    {
        Some(address) => ("AT_SPI_BUS_ADDRESS", address),
        None => match query_host_bus_address() {
            Ok(address) => ("org.a11y.Bus.GetAddress", address),
            Err(err) => {
                debug!(err:?; "could not discover AT-SPI bus, accessibility bridge disabled");
                return None;
            },
        },
    };
    let path = path_from_address(source, &address).filter(|path| can_connect(path))?;
    HostBus::new(path, runtime_dir)
        .inspect_err(|err| {
            eprintln!(
                "Failed to prepare host AT-SPI socket, accessibility bridge disabled: {err:#}"
            );
        })
        .ok()
}
