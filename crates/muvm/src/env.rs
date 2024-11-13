use std::collections::HashMap;
use std::env::{self, VarError};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use super::utils::env::find_in_path;
use anyhow::{Context, Result};
use log::debug;

/// Automatically pass these environment variables to the microVM, if they are
/// set.
const WELL_KNOWN_ENV_VARS: [&str; 20] = [
    "LANG",
    "LC_ADDRESS",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_IDENTIFICATION",
    "LC_MEASUREMENT",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NAME",
    "LC_NUMERIC",
    "LC_PAPER",
    "LC_TELEPHONE",
    "LC_TIME",
    "LD_LIBRARY_PATH",
    "LIBGL_DRIVERS_PATH",
    "MESA_LOADER_DRIVER_OVERRIDE", // needed for asahi
    "PATH",                        // needed by `muvm-guest` program
    "RUST_LOG",
    "XMODIFIERS",
];

/// See https://github.com/AsahiLinux/docs/wiki/Devices
const ASAHI_SOC_COMPAT_IDS: [&str; 1] = ["apple,arm-platform"];

pub fn prepare_env_vars(env: Vec<(String, Option<String>)>) -> Result<HashMap<String, String>> {
    let mut env_map = HashMap::new();

    for key in WELL_KNOWN_ENV_VARS {
        let value = match env::var(key) {
            Ok(value) => value,
            Err(VarError::NotPresent) => {
                if key == "MESA_LOADER_DRIVER_OVERRIDE" {
                    match fs::read_to_string("/proc/device-tree/compatible") {
                        Ok(compatible) => {
                            for compat_id in compatible.split('\0') {
                                if ASAHI_SOC_COMPAT_IDS.iter().any(|&s| s == compat_id) {
                                    env_map.insert(
                                        "MESA_LOADER_DRIVER_OVERRIDE".to_owned(),
                                        "asahi".to_owned(),
                                    );
                                    break;
                                }
                            }
                        },
                        Err(err) if err.kind() == ErrorKind::NotFound => {
                            continue;
                        },
                        Err(err) => {
                            Err(err).context("Failed to read `/proc/device-tree/compatible`")?
                        },
                    }
                }
                continue;
            },
            Err(err) => Err(err).with_context(|| format!("Failed to get `{key}` env var"))?,
        };
        env_map.insert(key.to_owned(), value);
    }

    if !(env_map.contains_key("LANG")
        || env_map.contains_key("LC_CTYPE")
        || env_map.contains_key("LC_ALL"))
    {
        // Set a default UTF-8 locale if none
        env_map.insert("LANG".to_owned(), "C.UTF-8".to_owned());
    }

    // Force XIM usage for GTK2/3 and QT4/QT5 (QT6 and GTK4 drop this).
    // This actually works with muvm-x11bridge for input methods in Steam,
    // since it ships the xim plugin for its bundled gtk3.
    // Once we have wayland, the Wayland transport should work for newer stuff.
    // This way we don't need to support passing through the dbus/socket based
    // direct plugin support.
    env_map.insert("GTK_IM_MODULE".to_owned(), "xim".to_owned());
    env_map.insert("QT_IM_MODULE".to_owned(), "xim".to_owned());

    for (key, value) in env {
        let value = value.map_or_else(
            || env::var(&key).with_context(|| format!("Failed to get `{key}` env var")),
            Ok,
        )?;
        env_map.insert(key, value);
    }

    debug!(env:? = env_map; "env vars");

    Ok(env_map)
}

pub fn find_muvm_exec<P>(program: P) -> Result<String>
where
    P: AsRef<Path>,
{
    let program = program.as_ref();
    let path = find_in_path(program)
        .with_context(|| format!("Failed to check existence of {program:?}"))?;
    let path = if let Some(path) = path {
        path
    } else {
        let path = env::current_exe().and_then(|p| p.canonicalize());
        let path = path.context("Failed to get path of current running executable")?;
        path.with_file_name(program)
    };
    let path = path.to_str().with_context(|| {
        format!("Failed to process {program:?} path as it contains invalid UTF-8")
    })?;

    Ok(path.to_string())
}
