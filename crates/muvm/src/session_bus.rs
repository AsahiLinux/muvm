use std::env;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::atspi::{can_connect, parse_unix_path_address, percent_encode, HostBus};

pub fn discover_host_bus(runtime_dir: &Path) -> Result<HostBus> {
    let address = env::var("DBUS_SESSION_BUS_ADDRESS")
        .ok()
        .filter(|address| !address.is_empty())
        .unwrap_or_else(|| format!("unix:path={}", percent_encode(&runtime_dir.join("bus"))));
    let path = parse_unix_path_address(&address)
        .context("--session-bus requires a single unix:path D-Bus address")?;
    if !path.is_absolute() {
        bail!("--session-bus requires an absolute session bus socket path");
    }
    if !can_connect(&path) {
        bail!("Cannot connect to host session bus at {path:?}");
    }
    HostBus::new(path, runtime_dir, "session-bus")
}

pub fn guest_socket_path(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}/bus"))
}

pub fn guest_address(uid: u32) -> String {
    format!("unix:path={}", percent_encode(&guest_socket_path(uid)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_bus_lives_in_guest_runtime_directory() {
        assert_eq!(guest_address(1000), "unix:path=/run/user/1000/bus");
        assert_eq!(guest_address(42), "unix:path=/run/user/42/bus");
    }

    #[test]
    fn host_address_decodes_escaped_paths() {
        assert_eq!(
            parse_unix_path_address("unix:path=/tmp/a%20b/bus,guid=abc"),
            Some(PathBuf::from("/tmp/a b/bus"))
        );
    }

    #[test]
    fn unsupported_addresses_are_not_treated_as_paths() {
        for address in [
            "unix:abstract=/tmp/bus",
            "tcp:host=localhost,port=1234",
            "unix:path=/tmp/bus;unix:path=/tmp/other",
            "unix:path=/tmp/%XX",
        ] {
            assert_eq!(parse_unix_path_address(address), None, "{address}");
        }
    }
}
