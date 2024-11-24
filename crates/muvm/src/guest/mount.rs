use std::ffi::CString;
use std::fs::{read_dir, File};
use std::io::Write;
use std::os::fd::AsFd;
use std::path::Path;

use anyhow::{Context, Result};
use rustix::fs::{mkdir, symlink, Mode, CWD};
use rustix::mount::{
    mount2, mount_bind, move_mount, open_tree, unmount, MountFlags, MoveMountFlags, OpenTreeFlags,
    UnmountFlags,
};

fn make_tmpfs(dir: &str) -> Result<()> {
    mount2(
        Some("tmpfs"),
        dir,
        Some("tmpfs"),
        MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::RELATIME,
        None,
    )
    .context("Failed to mount tmpfs")
}

fn mkdir_fex(dir: &str) {
    // Must succeed since /run/ was just mounted and is now an empty tmpfs.
    mkdir(
        dir,
        Mode::RUSR | Mode::XUSR | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
    )
    .unwrap();
}

fn mount_fex_rootfs() -> Result<()> {
    let dir = "/run/fex-emu/";
    let dir_rootfs = dir.to_string() + "rootfs";

    // Make base directories
    mkdir_fex(dir);

    let flags = MountFlags::RDONLY;
    let mut images = Vec::new();

    // Find /dev/vd*
    for x in read_dir("/dev").unwrap() {
        let file = x.unwrap();
        let name = file.file_name().into_string().unwrap();
        if !name.starts_with("vd") {
            continue;
        }

        let path = file.path().into_os_string().into_string().unwrap();
        let dir = dir.to_string() + &name;

        // Mount the erofs images.
        mkdir_fex(&dir);
        mount2(Some(path), dir.clone(), Some("erofs"), flags, None)
            .context("Failed to mount erofs")
            .unwrap();
        images.push(dir);
    }

    if images.len() >= 2 {
        // Overlay the mounts together.
        let opts = format!(
            "lowerdir={}",
            images.into_iter().rev().collect::<Vec<String>>().join(":")
        );
        let opts = CString::new(opts).unwrap();
        let overlay = "overlay".to_string();
        let overlay_ = Some(&overlay);

        mkdir_fex(&dir_rootfs);
        mount2(overlay_, &dir_rootfs, overlay_, flags, Some(&opts)).context("Failed to overlay")?;
    } else if images.len() == 1 {
        // Just expose the one mount
        symlink(&images[0], &dir_rootfs)?;
    } else if images.is_empty() {
        // If no images were passed, FEX is either managed by the host os
        // or is not installed at all. Avoid clobbering the config in that case.
        return Ok(());
    }

    // Now we need to tell FEX about this. One of the FEX share directories has an unmounted rootfs
    // and a Config.json telling FEX to use FUSE. Neither should be visible to the guest. Instead,
    // we want to replace the folders and tell FEX to use our mounted rootfs
    for base in ["/usr/share/fex-emu", "/usr/local/share/fex-emu"] {
        if Path::new(base).exists() {
            let json = format!("{{\"Config\":{{\"RootFS\":\"{dir_rootfs}\"}}}}\n");
            let path = base.to_string() + "/Config.json";

            make_tmpfs(base)?;
            File::create(Path::new(&path))?.write_all(json.as_bytes())?;
        }
    }

    Ok(())
}

pub fn place_etc(file: &str, contents: Option<&str>) -> Result<()> {
    let tmp = "/tmp/".to_string() + file;
    let etc = "/etc/".to_string() + file;

    {
        let mut file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .context("Failed to create temp backing of an etc file")?;

        if let Some(content) = contents {
            file.write_all(content.as_bytes())
                .context("Failed to write tmp backing of etc")?;
        }
    }

    let fd = open_tree(
        CWD,
        &tmp,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )
    .context("Failed to open_tree tmp")?;

    move_mount(
        fd.as_fd(),
        "",
        CWD,
        etc,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .context("Failed to move_mount tmp to etc")
}

pub fn mount_filesystems() -> Result<()> {
    make_tmpfs("/var/run")?;

    if mount_fex_rootfs().is_err() {
        println!("Failed to mount FEX rootfs, carrying on without.")
    }

    place_etc("resolv.conf", Some("nameserver 1.1.1.1\n"))?;

    mount2(
        Some("binfmt_misc"),
        "/proc/sys/fs/binfmt_misc",
        Some("binfmt_misc"),
        MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::RELATIME,
        None,
    )
    .context("Failed to mount `binfmt_misc`")?;

    // Expose the host filesystem (without any overlaid mounts) as /run/muvm-host
    let host_path = Path::new("/run/muvm-host");
    std::fs::create_dir_all(host_path)?;
    mount_bind("/", host_path).context("Failed to bind-mount / on /run/muvm-host")?;

    if Path::new("/tmp/.X11-unix").exists() {
        // Mount a tmpfs for X11 sockets, so the guest doesn't clobber host X server
        // sockets
        make_tmpfs("/tmp/.X11-unix")?;
    }

    // Mount /dev/shm separately with DAX enabled, to allow cross-domain shared memory
    // /dev/shm is mounted by libkrunfw, so unmount it first
    unmount("/dev/shm", UnmountFlags::empty()).context("Failed to unmount /dev/shm")?;
    mount2(
        Some("devshm"),
        "/dev/shm",
        Some("virtiofs"),
        MountFlags::NOEXEC | MountFlags::NOSUID,
        Some(c"dax"),
    )
    .context("Failed to mount `/dev/shm`")?;

    Ok(())
}
