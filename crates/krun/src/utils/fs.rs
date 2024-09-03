use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub fn find_executable<P>(path: P) -> Result<Option<PathBuf>>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();

    if !path.is_file() {
        return Ok(None);
    }

    let Ok(metadata) = fs::metadata(path) else {
        return Ok(None);
    };

    if metadata.permissions().mode() & 0o111 != 0 {
        let path = path.canonicalize().context("Failed to canonicalize path")?;
        return Ok(Some(path));
    }

    Ok(None)
}
