use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::{env, fs};

use anyhow::{Context, Result};
use utils::env::find_in_path;
use utils::stdio::make_stdout_stderr;

pub fn setup_pulse_proxy<P>(run_path: P) -> Result<()>
where
    P: AsRef<Path>,
{
    let socat_path = find_in_path("socat").context("Failed to check existence of `socat`")?;
    let Some(socat_path) = socat_path else {
        return Ok(());
    };

    let envs: HashMap<String, String> = env::vars().collect();
    let (stdout, stderr) = make_stdout_stderr(&socat_path, &envs)?;

    let run_path = run_path.as_ref();
    let pulse_path = run_path.join("pulse");
    fs::create_dir(&pulse_path)
        .context("Failed to create `pulse` directory in `XDG_RUNTIME_DIR`")?;
    let pulse_path = pulse_path.join("native");
    Command::new(socat_path)
        .arg(format!(
            "UNIX-LISTEN:{},fork",
            pulse_path
                .to_str()
                .expect("pulse_path should not contain invalid UTF-8")
        ))
        .arg("VSOCK-CONNECT:2:3333")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .context("Failed to execute `socat` as child process")?;

    Ok(())
}
