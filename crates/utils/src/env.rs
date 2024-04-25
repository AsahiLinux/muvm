use std::{
    env, fs, io,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

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
