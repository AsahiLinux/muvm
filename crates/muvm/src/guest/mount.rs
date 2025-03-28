use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{read_dir, read_link, DirEntry, File};
use std::io::Write;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rustix::fs::{mkdir, symlink, Mode, CWD};
use rustix::mount::{
    mount2, mount_bind, mount_recursive_bind, move_mount, open_tree, unmount, MountFlags,
    MoveMountFlags, OpenTreeFlags, UnmountFlags,
};
use rustix::path::Arg;
use serde_json::json;

fn make_tmpfs<P>(dir: P) -> Result<()>
where
    P: rustix::path::Arg,
{
    mount2(
        Some("tmpfs"),
        dir,
        Some("tmpfs"),
        MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::RELATIME,
        None,
    )
    .context("Failed to mount tmpfs")
}

fn mkdir_fex<P>(dir: P)
where
    P: rustix::path::Arg,
{
    // Must succeed since /run/ was just mounted and is now an empty tmpfs.
    mkdir(
        dir,
        Mode::RUSR | Mode::XUSR | Mode::RGRP | Mode::XGRP | Mode::ROTH | Mode::XOTH,
    )
    .unwrap();
}

fn do_mount_recursive_bind(source: &str, target: PathBuf) -> Result<()> {
    // Special case, do not recursively mount the FEX stuff itself, but do
    // the /run/muvm-host thing.
    if source == "/run" {
        mount_bind(source, &target)
            .with_context(|| format!("Failed to mount {source:?} on {target:?}"))?;
        let host = target.join("muvm-host");
        mount_bind("/", &host).with_context(|| format!("Failed to mount / on {host:?}"))?;
    } else {
        mount_recursive_bind(source, &target)
            .with_context(|| format!("Failed to mount {source:?} on {target:?}"))?;
    }
    Ok(())
}

fn mount_fex_rootfs(merged_rootfs: bool) -> Result<()> {
    let dir = Path::new("/run/fex-emu/");
    let dir_rootfs = dir.join("rootfs");

    // Make base directories
    mkdir_fex(dir);

    let flags = MountFlags::RDONLY;
    let mut images = Vec::new();

    // In merged RootFS mode, make /run/fex-emu a tmpfs.
    // This ensures that once /run is bind-mounted into the
    // rootfs, /run/fex-emu/* isn't itself visible within the
    // rootfs, so recursive RootFS lookups don't succeed and
    // break things.
    if merged_rootfs {
        make_tmpfs(dir)?;
    }

    // Find /dev/vd*
    let mut dev_vd_entries: Vec<DirEntry> = read_dir("/dev")
        .context("Failed to read directory `/dev`")?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to read directory entry in `/dev`")?
        .into_iter()
        .filter(|entry| {
            entry
                .file_name()
                .into_string()
                .expect("file_name should not contain invalid UTF-8")
                .starts_with("vd")
        })
        .collect();
    // [readdir(3)](https://man7.org/linux/man-pages/man3/readdir.3.html#NOTES)
    //
    // > The order in which filenames are read by successive calls to readdir() depends on the
    // > filesystem implementation; it is unlikely that the names will be sorted in any fashion.
    dev_vd_entries.sort_unstable_by_key(|entry| entry.file_name());
    for entry in dev_vd_entries {
        let target_dir = dir.join(entry.file_name());
        // Mount the erofs images.
        mkdir_fex(&target_dir);
        mount2(Some(entry.path()), &target_dir, Some("erofs"), flags, None)
            .context("Failed to mount erofs")?;
        images.push(target_dir);
    }

    if images.is_empty() {
        // If no images were passed, FEX is either managed by the host os
        // or is not installed at all. Avoid clobbering the config in that case.
        // merged_rootfs is ignored in this case.
        return Ok(());
    }

    #[allow(clippy::collapsible_else_if)]
    if merged_rootfs {
        // For merged rootfs mode, we need to overlay subtrees separately
        // onto the real rootfs. First, insert the real rootfs as the
        // bottom-most "image".
        images.insert(0, PathBuf::from("/"));

        let mut merge_dirs = HashSet::new();
        let mut non_dirs = HashSet::new();

        mkdir_fex(&dir_rootfs);

        // List all the merged root entries in each layer
        // Go backwards, since the file type of the topmost layer "wins"
        for image in images.iter().rev() {
            for entry in read_dir(image).unwrap() {
                let Ok(entry) = entry else { continue };
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                let source = entry.path();
                let file_name = entry.file_name();
                let target = dir_rootfs.join(&file_name);

                if file_type.is_file() {
                    // File in the root fs, bind mount it from the uppermost layer
                    if non_dirs.insert(file_name) {
                        File::create(&target)?;
                        mount_bind(source, target)?;
                    }
                } else if file_type.is_symlink() {
                    // Symlink in the root fs, create it from the uppermost layer
                    if non_dirs.insert(file_name) {
                        let symlink_target = read_link(source)?;
                        symlink(symlink_target, target)?;
                    }
                } else {
                    // Directory, so we potentially have to overlayfs it
                    if merge_dirs.insert(file_name) {
                        mkdir_fex(target);
                    }
                }
            }
        }

        // Now, go through each potential merged dir and figure out which
        // layers have it, then mount an overlayfs (or bind if one layer).
        for dir in merge_dirs {
            let target = dir_rootfs.join(&dir);
            let mut layers = Vec::new();

            for image in images.iter() {
                let source = image.join(&dir);
                if source.is_dir() {
                    layers.push(source.as_str().unwrap().to_owned());
                }
            }
            assert!(!layers.is_empty());
            if layers.len() == 1 {
                do_mount_recursive_bind(&layers[0], target)?;
            } else {
                if layers[0] == "/etc" {
                    // Special case: /etc has an overlaid mount for /etc/resolv.conf,
                    // which will confuse overlayfs. So grab the raw mount.
                    layers[0] = "/run/muvm-host/etc".to_owned();
                }
                let opts = format!(
                    "lowerdir={lowerdir},metacopy=off,redirect_dir=nofollow,userxattr",
                    lowerdir = layers.into_iter().rev().collect::<Vec<String>>().join(":")
                );
                let opts = CString::new(opts).unwrap();
                let overlay = "overlay".to_string();
                let overlay_ = Some(&overlay);

                mount2(overlay_, &target, overlay_, flags, Some(&opts))
                    .context("Failed to overlay")?;
            }
        }

        // Special case: Put back the /etc/resolv.conf overlay on top
        overlay_file(
            "/etc/resolv.conf",
            dir_rootfs.join("etc/resolv.conf").as_str().unwrap(),
        )?;
    } else {
        if images.len() >= 2 {
            // Overlay the mounts together.
            let opts = format!(
                "lowerdir={lowerdir}",
                lowerdir = images
                    .into_iter()
                    .rev()
                    .map(|path| path.as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
                    .join(":")
            );
            let opts = CString::new(opts).unwrap();
            let overlay = "overlay".to_string();
            let overlay_ = Some(&overlay);

            mkdir_fex(&dir_rootfs);
            mount2(overlay_, &dir_rootfs, overlay_, flags, Some(&opts))
                .context("Failed to overlay")?;
        } else {
            assert!(images.len() == 1);
            // Just expose the one mount
            symlink(&images[0], &dir_rootfs)?;
        }
    }

    // Now we need to tell FEX about this. One of the FEX share directories has an unmounted rootfs
    // and a Config.json telling FEX to use FUSE. Neither should be visible to the guest. Instead,
    // we want to replace the folders and tell FEX to use our mounted rootfs
    for base in ["/usr/share/fex-emu", "/usr/local/share/fex-emu"] {
        if Path::new(base).exists() {
            let json = if merged_rootfs {
                json!({
                    "Config": {
                        "RootFS": dir_rootfs,
                        "MergedRootFS": "1",
                    },
                })
            } else {
                json!({
                    "Config": {
                        "RootFS": dir_rootfs,
                    },
                })
            }
            .to_string();
            let path = base.to_string() + "/Config.json";
            let host_dir = "/run/muvm-host".to_string() + base;

            make_tmpfs(base)?;
            for entry in read_dir(host_dir).unwrap() {
                let entry = entry.unwrap();
                let file_name = entry.file_name();
                if file_name == "Config.json" {
                    continue;
                }
                let dest = Path::new(base).join(file_name);
                symlink(entry.path(), dest)?;
            }

            File::create(Path::new(&path))?.write_all(json.as_bytes())?;
        }
    }

    Ok(())
}

pub fn overlay_file(src: &str, dest: &str) -> Result<()> {
    let fd = open_tree(
        CWD,
        src,
        OpenTreeFlags::OPEN_TREE_CLONE | OpenTreeFlags::OPEN_TREE_CLOEXEC,
    )
    .with_context(|| format!("Failed to open_tree {src:?}"))?;

    move_mount(
        fd.as_fd(),
        "",
        CWD,
        dest,
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )
    .with_context(|| format!("Failed to move_mount {src:?} to {dest:?}"))
}

pub fn place_file(backing: &str, dest: &str, contents: Option<&str>) -> Result<()> {
    {
        let mut file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(backing)
            .context("Failed to create temp backing of an etc file")?;

        if let Some(content) = contents {
            file.write_all(content.as_bytes())
                .context("Failed to write tmp backing of etc")?;
        }
    }

    overlay_file(backing, dest)
}

pub fn mount_filesystems(merged_rootfs: bool) -> Result<()> {
    make_tmpfs("/var/run")?;

    place_file("/run/resolv.conf", "/etc/resolv.conf", None)?;

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

    // Do this last so it can pick up all the submounts made above.
    if let Err(e) = mount_fex_rootfs(merged_rootfs) {
        println!("Failed to mount FEX rootfs, carrying on without. Error: {e}");
    }

    Ok(())
}
