use std::env;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use super::fs::find_executable;

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
        let path = search_path.join(program);
        if let Some(path) = find_executable(&path)
            .with_context(|| format!("Failed to check existence of {path:?}"))?
        {
            return Ok(Some(path));
        }
    }

    Ok(None)
}
