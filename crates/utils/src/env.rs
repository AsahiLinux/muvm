use std::{
    env,
    ffi::CString,
    fs, io,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

pub fn find_in_path<P>(program: P) -> io::Result<Option<PathBuf>>
where
    P: AsRef<Path>,
{
    let program = program.as_ref();

    // Only accept program name, i.e. a relative path with one component.
    if program.parent() != Some(Path::new("")) {
        return Err(io::Error::other(format!(
            "invalid program name {program:?}"
        )));
    };

    // Impossible to perform search if `PATH` env var is not set or invalid.
    let Ok(path_env) = env::var("PATH") else {
        return Err(io::Error::other("`PATH` env var is not set or invalid"));
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
            return pb.canonicalize().map(Some);
        }
    }

    Ok(None)
}

pub fn find_krun_exec(name: &str) -> Result<CString> {
    let krun_path = find_in_path(name).context("Failed to check existence of {name}")?;
    let krun_path = if let Some(krun_path) = krun_path {
        krun_path
    } else {
        let krun_path = env::current_exe().and_then(|p| p.canonicalize());
        let krun_path = krun_path.context("Failed to get path of current running executable")?;
        krun_path.with_file_name(format!(
            "{}-guest",
            krun_path
                .file_name()
                .expect("krun_path should end with a file name")
                .to_str()
                .context("Failed to process `krun` file name as it contains invalid UTF-8")?
        ))
    };
    let krun_path = CString::new(
        krun_path
            .to_str()
            .context("Failed to process {name} path as it contains invalid UTF-8")?,
    )
    .context("Failed to process {name} path as it contains NUL character")?;

    Ok(krun_path)
}
