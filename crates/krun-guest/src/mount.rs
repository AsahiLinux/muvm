use std::ffi::CString;
use std::fs::File;
use std::os::fd::AsFd;
use std::path::Path;

use anyhow::{Context, Result};
use rustix::fs::{mkdir, Mode, CWD};
use rustix::mount::{
    mount2, mount_bind, move_mount, open_tree, MountFlags, MoveMountFlags, OpenTreeFlags,
};

fn mount_fex_rootfs() -> Result<()> {
    let dir = "/run/fex-emu/";
    let dir_base = dir.to_string() + "base";
    let dir_mesa = dir.to_string() + "mesa";
    let dir_rootfs = dir.to_string() + "rootfs";

    // Create the directories for our mountpoints.
    // This must succeed since /run/ was just mounted and is now an empty tmpfs.
    for dir in [dir, &dir_base, &dir_mesa, &dir_rootfs] {
        mkdir(
            dir,
            Mode::RUSR | Mode::XUSR | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
        )
        .context("Failed to create FEX rootfs directory")?;
    }

    // Mount the squashfs images.
    let fex_map = [(&dir_base, "/dev/vda"), (&dir_mesa, "/dev/vdb")];
    let flags = MountFlags::RDONLY;

    for (dir, disk) in fex_map {
        mount2(Some(disk), dir, Some("squashfs"), flags, None)
            .context("Failed to mount squashfs")?;
    }

    // Overlay the mounts together.
    let opts = format!("lowerdir={}:{}", dir_mesa, dir_base);
    let opts = CString::new(opts).unwrap();
    let overlay = "overlay".to_string();
    let overlay_ = Some(&overlay);
    mount2(overlay_, &dir_rootfs, overlay_, flags, Some(&opts)).context("Failed to overlay")?;

    Ok(())
}

pub fn mount_filesystems() -> Result<()> {
    mount2(
        Some("tmpfs"),
        "/var/run",
        Some("tmpfs"),
        MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::RELATIME,
        None,
    )
    .context("Failed to mount `/var/run`")?;

    if let Err(_) = mount_fex_rootfs() {
        println!("Failed to mount FEX rootfs, carrying on without.")
    }

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

    mount2(
        Some("binfmt_misc"),
        "/proc/sys/fs/binfmt_misc",
        Some("binfmt_misc"),
        MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::RELATIME,
        None,
    )
    .context("Failed to mount `binfmt_misc`")?;

    // Expose the host filesystem (without any overlaid mounts) as /run/krun-host
    let host_path = Path::new("/run/krun-host");
    std::fs::create_dir_all(host_path)?;
    mount_bind("/", host_path).context("Failed to bind-mount / on /run/krun-host")?;

    if Path::new("/tmp/.X11-unix").exists() {
        // Mount a tmpfs for X11 sockets, so the guest doesn't clobber host X server
        // sockets
        mount2(
            Some("tmpfs"),
            "/tmp/.X11-unix",
            Some("tmpfs"),
            MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::RELATIME,
            None,
        )
        .context("Failed to mount `/tmp/.X11-unix`")?;
    }

    Ok(())
}
