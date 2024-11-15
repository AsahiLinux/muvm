use std::env;
use std::fs::{self, Permissions};
use std::os::unix::fs::{chown, PermissionsExt as _};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use nix::unistd::{setgid, setuid, Gid, Uid, User};

pub fn setup_user(username: String, uid: Uid, gid: Gid) -> Result<PathBuf> {
    setup_directories(uid, gid)?;

    setgid(gid).context("Failed to setgid")?;
    setuid(uid).context("Failed to setuid")?;

    let path = tempfile::Builder::new()
        .prefix(&format!("muvm-run-{uid}-"))
        .permissions(Permissions::from_mode(0o755))
        .tempdir()
        .context("Failed to create temp dir for `XDG_RUNTIME_DIR`")?
        .into_path();
    // SAFETY: Safe if and only if `muvm-guest` program is not multithreaded.
    // See https://doc.rust-lang.org/std/env/fn.set_var.html#safety
    env::set_var("XDG_RUNTIME_DIR", &path);

    let user = User::from_name(&username)
        .map_err(Into::into)
        .and_then(|user| user.ok_or_else(|| anyhow!("requested entry not found")))
        .with_context(|| format!("Failed to get user `{username}` from user database"))?;

    {
        // SAFETY: Safe if and only if `muvm-guest` program is not multithreaded.
        // See https://doc.rust-lang.org/std/env/fn.set_var.html#safety
        env::set_var("HOME", user.dir);
    }

    Ok(path)
}

fn setup_directories(uid: Uid, gid: Gid) -> Result<()> {
    for dir in ["/dev/dri", "/dev/snd"] {
        if !Path::new(dir).exists() {
            continue;
        }

        let dir_iter =
            fs::read_dir(dir).with_context(|| format!("Failed to read directory `{dir}`"))?;

        for entry in dir_iter {
            let path = entry
                .with_context(|| format!("Failed to read directory entry in `{dir}`"))?
                .path();
            chown(&path, Some(uid.into()), Some(gid.into()))
                .with_context(|| format!("Failed to chown {path:?}"))?;
        }
    }

    if Path::new("/dev/vsock").exists() {
        chown("/dev/vsock", Some(uid.into()), Some(gid.into()))
            .context("Failed to chown `/dev/vsock`")?;
    }

    Ok(())
}
