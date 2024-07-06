use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use utils::env::find_in_path;
use utils::stdio::make_stdout_stderr;

pub fn setup_socket_proxy<P>(socket_path: P, port: u16) -> Result<()>
where
    P: AsRef<Path>,
{
    let socat_path = find_in_path("socat").context("Failed to check existence of `socat`")?;
    let Some(socat_path) = socat_path else {
        return Ok(());
    };

    let envs: HashMap<String, String> = env::vars().collect();
    let (stdout, stderr) = make_stdout_stderr(&socat_path, &envs)?;

    Command::new(socat_path)
        .arg(format!(
            "UNIX-LISTEN:{},fork",
            socket_path
                .as_ref()
                .to_str()
                .expect("pulse_path should not contain invalid UTF-8")
        ))
        .arg(format!("VSOCK-CONNECT:2:{}", port))
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .context("Failed to execute `socat` as child process")?;

    Ok(())
}
