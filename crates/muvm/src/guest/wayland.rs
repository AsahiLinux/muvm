use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use log::{debug, warn};

use crate::utils::env::find_in_path;
use crate::utils::stdio::make_stdout_stderr;

const WAYLAND_PROXY: &str = "wl-cross-domain-proxy";
const SOCKET_WAIT: Duration = Duration::from_secs(5);

/// The host's `WAYLAND_DISPLAY` if it is a plain socket name. libkrun joins the name onto the host's
/// `XDG_RUNTIME_DIR` for the cross-domain Wayland channel, without special handling of an absolute
/// path, so only a plain name can be served.
pub fn plain_wayland_display(value: Option<String>) -> Option<String> {
    value.filter(|name| !name.is_empty() && !name.contains('/') && name != "." && name != "..")
}

/// Serve the host compositor inside the guest under the host's own
/// `WAYLAND_DISPLAY` name. libkrun connects the virtio-gpu cross-domain
/// Wayland channel to the host socket; the proxy carries client traffic and
/// shm buffers across it. Using the host's name keeps a forwarded
/// `-e WAYLAND_DISPLAY` pointing at the guest socket.
pub fn setup_wayland_forwarding<P>(run_path: P, display: &str) -> Result<()>
where
    P: AsRef<Path>,
{
    let proxy_path = find_in_path(WAYLAND_PROXY)
        .with_context(|| format!("Failed to look for `{WAYLAND_PROXY}`"))?;
    let Some(proxy_path) = proxy_path else {
        debug!("`{WAYLAND_PROXY}` not found in PATH, Wayland passthrough will not work");
        return Ok(());
    };
    let socket_path = run_path.as_ref().join(display);

    let envs: HashMap<String, String> = env::vars().collect();
    let (stdout, stderr) = make_stdout_stderr(&proxy_path, &envs)?;

    Command::new(proxy_path)
        .arg("--socket-path")
        .arg(&socket_path)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .with_context(|| format!("Failed to execute `{WAYLAND_PROXY}` as child process"))?;

    // The proxy opens the GPU device before it binds, and a client started at once would not find the
    // socket. Without it, leave WAYLAND_DISPLAY unset so clients use the X11 bridge.
    let deadline = Instant::now() + SOCKET_WAIT;
    while !socket_path.exists() {
        if Instant::now() >= deadline {
            warn!("`{WAYLAND_PROXY}` did not create {socket_path:?}, Wayland passthrough is off");
            return Ok(());
        }
        sleep(Duration::from_millis(20));
    }

    // SAFETY: Safe if and only if `muvm-guest` program is not multithreaded. It is not at this point:
    // the x11bridge thread is started by `setup_x11_forwarding`, which `muvm-guest` calls after this.
    // See https://doc.rust-lang.org/std/env/fn.set_var.html#safety
    env::set_var("WAYLAND_DISPLAY", display);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::plain_wayland_display;

    #[test]
    fn plain_names_are_served() {
        assert_eq!(
            plain_wayland_display(Some("wayland-1".into())),
            Some("wayland-1".into())
        );
        assert_eq!(
            plain_wayland_display(Some("wayland-0".into())),
            Some("wayland-0".into())
        );
    }

    #[test]
    fn paths_and_empty_names_are_not() {
        assert_eq!(plain_wayland_display(None), None);
        assert_eq!(plain_wayland_display(Some(String::new())), None);
        assert_eq!(
            plain_wayland_display(Some("/run/user/1000/wayland-1".into())),
            None
        );
        assert_eq!(plain_wayland_display(Some("a/b".into())), None);
        assert_eq!(plain_wayland_display(Some(".".into())), None);
        assert_eq!(plain_wayland_display(Some("..".into())), None);
    }
}
