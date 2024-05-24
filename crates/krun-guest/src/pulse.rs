use std::{fs, path::PathBuf, process::Command};

use anyhow::{Context, Result};
use utils::env::find_in_path;

pub fn setup_pulse_proxy(run_path: PathBuf) -> Result<()> {
    if let Some(socat_path) = find_in_path("socat")? {
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
            .spawn()
            .context("Failed to execute `socat` as child process")?;
    }
    Ok(())
}
