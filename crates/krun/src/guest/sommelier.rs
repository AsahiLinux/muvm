use std::env;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use log::debug;

use crate::utils::env::find_in_path;

pub fn exec_sommelier<P>(command: P, command_args: &[String]) -> Result<()>
where
    P: AsRef<Path>,
{
    let sommelier_path =
        find_in_path("sommelier").context("Failed to check existence of `sommelier`")?;
    let Some(sommelier_path) = sommelier_path else {
        return Ok(());
    };

    let gl_env = env::var("LIBGL_DRIVERS_PATH").ok();

    let mut cmd = Command::new(sommelier_path);
    cmd.args(["--virtgpu-channel", "-X", "--glamor"]);

    if let Some(gl_env) = gl_env {
        cmd.arg(format!("--xwayland-gl-driver-path={gl_env}"));
    }

    let command = command.as_ref();
    cmd.arg(command).args(command_args);

    debug!(command:?, command_args:?; "exec");
    let err = cmd.exec();
    Err(err).context("Failed to exec `sommelier`")?
}
