use std::fs::{File, create_dir_all};
use std::env::var_os;
use std::os::fd::AsFd;

use anyhow::{Context, Result};
use rustix::fs::CWD;
use rustix::mount::{mount2, move_mount, mount_recursive_bind, open_tree, MountFlags, MoveMountFlags, OpenTreeFlags};

pub fn mount_filesystems() -> Result<()> {
    mount2(
        Some("tmpfs"),
        "/var/run",
        Some("tmpfs"),
        MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::RELATIME,
        None,
    )
    .context("Failed to mount `/var/run`")?;

    let _ = File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open("/tmp/resolv.conf")
        .context("Failed to create `/tmp/resolv.conf`")?;

    {
        let fd = open_tree(
            CWD,
            "/tmp/resolv.conf",
            OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
        )
        .context("Failed to open_tree `/tmp/resolv.conf`")?;

        move_mount(
            fd.as_fd(),
            "",
            CWD,
            "/etc/resolv.conf",
            MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
        )
        .context("Failed to move_mount `/etc/resolv.conf`")?;
    }

    let opengl_driver = var_os("OPENGL_DRIVER");
    if let Some(dir) = opengl_driver {
        create_dir_all("/run/opengl-driver")?;
        mount_recursive_bind(
            dir,
            "/run/opengl-driver",
        )
        .context("Failed to mount `/run/opengl-driver`")?;
    }

    let nixos_curr_sys = var_os("NIXOS_CURRENT_SYSTEM");
    if let Some(dir) = nixos_curr_sys {
        create_dir_all("/run/current-system")?;
        mount_recursive_bind(
            dir,
            "/run/current-system",
        )
        .context("Failed to mount `/run/current-system`")?;
    }

    mount2(
        Some("binfmt_misc"),
        "/proc/sys/fs/binfmt_misc",
        Some("binfmt_misc"),
        MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::RELATIME,
        None,
    )
    .context("Failed to mount `binfmt_misc`")?;

    Ok(())
}
