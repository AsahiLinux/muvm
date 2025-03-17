use std::collections::HashMap;
use std::env::{self, VarError};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use log::debug;

#[cfg(not(debug_assertions))]
use crate::utils::env::find_in_path;

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

/// Variables to drop if we're inheriting the environment from the host.
const DROP_ENV_VARS: [&str; 17] = [
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "ICEAUTHORITY",
    "KONSOLE_DBUS_SERVICE",
    "KONSOLE_DBUS_SESSION",
    "KONSOLE_DBUS_WINDOW",
    "MANAGERPID",
    "PAM_KWALLET5_LOGIN",
    "SESSION_MANAGER",
    "SYSTEMD_EXEC_PID",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
    "XDG_SEAT",
    "XDG_SEAT_PATH",
    "XDG_SESSION_PATH",
    "XDG_VTNR",
];

/// See https://github.com/AsahiLinux/docs/wiki/Devices
const ASAHI_SOC_COMPAT_IDS: [&str; 1] = ["apple,arm-platform"];

pub fn prepare_env_vars(
    env: Vec<(String, Option<String>)>,
    inherit_env: bool,
) -> Result<HashMap<String, String>> {
    let mut env_map = HashMap::new();

    if inherit_env {
        for (key, value) in env::vars() {
            env_map.insert(key, value);
        }

        for key in DROP_ENV_VARS {
            env_map.remove(key);
        }
    } else {
        for key in WELL_KNOWN_ENV_VARS {
            let value = match env::var(key) {
                Ok(value) => value,
                Err(VarError::NotPresent) => continue,
                Err(err) => Err(err).with_context(|| format!("Failed to get `{key}` env var"))?,
            };
            env_map.insert(key.to_owned(), value);
        }
    }

    if !env_map.contains_key("MESA_LOADER_DRIVER_OVERRIDE") {
        match fs::read_to_string("/proc/device-tree/compatible") {
            Ok(compatible) => {
                for compat_id in compatible.split('\0') {
                    if ASAHI_SOC_COMPAT_IDS.iter().any(|&s| s == compat_id) {
                        env_map
                            .insert("MESA_LOADER_DRIVER_OVERRIDE".to_owned(), "asahi".to_owned());
                        break;
                    }
                }
            },
            Err(err) if err.kind() == ErrorKind::NotFound => (),
            Err(err) => return Err(err).context("Failed to read `/proc/device-tree/compatible`"),
        }
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

    // Force a separate Firefox profile, since Firefox in muvm cannot see
    // the lock from outside the VM and will concurrently launch on the same
    // profile, corrupting it. This makes Firefox safely work in the VM
    // (for browser launches).
    if let Ok(home) = env::var("HOME") {
        let mut path = PathBuf::new();
        path.push(home);
        path.push(".mozilla");
        path.push("firefox");
        if path.exists() {
            path.push("muvm-profile");
            if !path.exists() {
                std::fs::create_dir(&path)?;
            }
            env_map.insert(
                "XRE_PROFILE_PATH".to_owned(),
                path.to_str().unwrap().to_owned(),
            );
        }
    }

    // Specifically allow users to force-overwrite vars inside the VM to the "outside"
    // ones, even when inheriting the environment, e.g. if someone wanted to
    // pass in a variable that's meant to be dropped,
    // or overwrite one of the variables we set like GTK_IM_MODULE.
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

#[cfg(not(debug_assertions))]
pub fn find_muvm_exec<P>(program: P) -> Result<PathBuf>
where
    P: AsRef<Path>,
{
    let program = program.as_ref();

    let path = find_in_path(program)
        .with_context(|| format!("Failed to check existence of {program:?}"))?;
    let path = path.with_context(|| format!("Could not find {program:?}"))?;

    Ok(path)
}

#[cfg(debug_assertions)]
pub fn find_muvm_exec<P>(program: P) -> Result<PathBuf>
where
    P: AsRef<Path>,
{
    let program = program.as_ref();

    let path = env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("Failed to get path of current running executable")?;
    let path = path.with_file_name(program);

    Ok(path)
}
