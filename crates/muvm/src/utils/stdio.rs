use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result};
use uuid::Uuid;

pub fn make_stdout_stderr<P>(command: P, envs: &HashMap<String, String>) -> Result<(Stdio, Stdio)>
where
    P: AsRef<Path>,
{
    let command = command.as_ref();
    let filename = command
        .file_name()
        .context("Failed to obtain basename from command path")?;
    let filename = filename
        .to_str()
        .context("Failed to process command as it contains invalid UTF-8")?;
    let base = if envs.contains_key("XDG_RUNTIME_DIR") {
        Path::new(&envs["XDG_RUNTIME_DIR"])
    } else {
        Path::new("/tmp")
    };
    let uuid = Uuid::now_v7();
    let path_stdout = base.join(format!("muvm-{filename}-{uuid}.stdout"));
    let path_stderr = base.join(format!("muvm-{filename}-{uuid}.stderr"));
    Ok((
        File::create_new(path_stdout)?.into(),
        File::create_new(path_stderr)?.into(),
    ))
}
