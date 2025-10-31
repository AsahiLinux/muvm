use std::env;
use std::fs;
use std::os::unix::fs::chown;
use std::path::{Path, PathBuf};

use crate::guest::hidpipe::UINPUT_PATH;
use crate::utils::fs::mkdir_mode;
use anyhow::{anyhow, Context, Result};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, setresgid, setresuid, ForkResult, Gid, Uid, User};

pub fn setup_user(uid: Uid, gid: Gid) -> Result<PathBuf> {
    setup_directories(uid, gid)?;

    let path = PathBuf::from(format!("/run/user/{uid}"));

    mkdir_mode(path.parent().unwrap(), 0o755)?;
    mkdir_mode(&path, 0o700)?;

    chown(&path, Some(uid.into()), Some(gid.into()))
        .with_context(|| format!("Failed to chown {path:?}"))?;

    setresgid(gid, gid, Gid::from(0)).context("Failed to setgid")?;
    setresuid(uid, uid, Uid::from(0)).context("Failed to setuid")?;

    // SAFETY: Safe if and only if `muvm-guest` program is not multithreaded.
    // See https://doc.rust-lang.org/std/env/fn.set_var.html#safety
    env::set_var("XDG_RUNTIME_DIR", &path);

    let user = User::from_uid(uid)
        .map_err(Into::into)
        .and_then(|user| user.ok_or_else(|| anyhow!("requested entry not found")))
        .with_context(|| format!("Failed to get user `{uid}` from user database"))?;

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

    chown(UINPUT_PATH, Some(uid.into()), Some(gid.into()))?;

    Ok(())
}

/// # Safety
/// f will be run in post-fork environment, and so must be async signal safe
pub unsafe fn run_as_root(f: impl FnOnce() -> i32) -> Result<i32> {
    // SAFETY: child only calls _exit, setuid, and f, all are async signal safe
    match unsafe { fork()? } {
        ForkResult::Child => {
            // SAFETY: _exit and setuid are safe as no pointers are involved
            unsafe {
                nix::libc::setuid(0);
                nix::libc::_exit(f());
            }
        },
        ForkResult::Parent { child } => match waitpid(child, None)? {
            WaitStatus::Exited(_, code) => Ok(code),
            e => Err(anyhow!("Unexpected status: {:?}", e)),
        },
    }
}
