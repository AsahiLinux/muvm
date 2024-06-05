use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

use anyhow::{anyhow, Context, Result};

pub fn find_in_path<P>(program: P) -> Result<Option<PathBuf>>
where
    P: AsRef<Path>,
{
    let program = program.as_ref();

    // Only accept program name, i.e. a relative path with one component.
    if program.parent() != Some(Path::new("")) {
        return Err(anyhow!("invalid program name {program:?}"));
    };

    // Impossible to perform search if `PATH` env var is not set or invalid.
    let Ok(path_env) = env::var("PATH") else {
        return Err(anyhow!("`PATH` env var is not set or invalid"));
    };

    for search_path in env::split_paths(&path_env) {
        let pb = search_path.join(program);
        if !pb.is_file() {
            continue;
        }
        let Ok(metadata) = fs::metadata(&pb) else {
            continue;
        };
        if metadata.permissions().mode() & 0o111 != 0 {
            let pb = pb.canonicalize().context("Failed to canonicalize path")?;
            return Ok(Some(pb));
        }
    }

    Ok(None)
}
