use std::{
    env::{self, VarError},
    ffi::{c_char, CString},
    fs,
    io::ErrorKind,
    os::fd::{IntoRawFd, OwnedFd},
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use krun::{
    cli_options::options,
    net::{connect_to_passt, start_passt, NetMode},
};
use krun_sys::{
    krun_add_vsock_port, krun_create_ctx, krun_set_exec, krun_set_gpu_options, krun_set_log_level,
    krun_set_passt_fd, krun_set_root, krun_set_vm_config, krun_set_workdir, krun_start_enter,
    VIRGLRENDERER_DRM, VIRGLRENDERER_THREAD_SYNC, VIRGLRENDERER_USE_ASYNC_FENCE_CB,
    VIRGLRENDERER_USE_EGL,
};
use log::debug;
use nix::unistd::User;
use rustix::{
    io::Errno,
    process::{geteuid, getgid, getrlimit, getuid, setrlimit, Resource},
};
use utils::env::find_in_path;

fn main() -> Result<()> {
    env_logger::init();

    if getuid().as_raw() == 0 || geteuid().as_raw() == 0 {
        println!("Running as root is not supported as it may break your system");
        return Err(anyhow!("real user ID or effective user ID is 0"));
    }

    let options = options().fallback_to_usage().run();

    {
        // Set the log level to "off".
        //
        // SAFETY: Safe as no pointers involved.
        let err = unsafe { krun_set_log_level(0) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to configure log level");
        }
    }

    let ctx_id = {
        // Create the configuration context.
        //
        // SAFETY: Safe as no pointers involved.
        let ctx_id = unsafe { krun_create_ctx() };
        if ctx_id < 0 {
            let err = Errno::from_raw_os_error(-ctx_id);
            return Err(err).context("Failed to create configuration context");
        }
        ctx_id as u32
    };

    {
        // Configure the number of vCPUs (4) and the amount of RAM (4096 MiB).
        //
        // SAFETY: Safe as no pointers involved.
        let err = unsafe { krun_set_vm_config(ctx_id, 4, 4096) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err)
                .context("Failed to configure the number of vCPUs and/or the amount of RAM");
        }
    }

    {
        // Raise RLIMIT_NOFILE to the maximum allowed to create some room for virtio-fs
        let mut rlim = getrlimit(Resource::Nofile);
        rlim.current = rlim.maximum;
        setrlimit(Resource::Nofile, rlim).context("Failed to raise `RLIMIT_NOFILE`")?;
    }

    {
        // SAFETY: `root_path` is a pointer to a C-string literal.
        let err = unsafe { krun_set_root(ctx_id, c"/".as_ptr()) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to configure root path");
        }
    }

    {
        let virgl_flags = VIRGLRENDERER_USE_EGL
            | VIRGLRENDERER_DRM
            | VIRGLRENDERER_THREAD_SYNC
            | VIRGLRENDERER_USE_ASYNC_FENCE_CB;
        // SAFETY: Safe as no pointers involved.
        let err = unsafe { krun_set_gpu_options(ctx_id, virgl_flags) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to configure gpu");
        }
    }

    if options.net == NetMode::PASST {
        let passt_fd: OwnedFd = if let Some(passt_socket) = options.passt_socket {
            connect_to_passt(passt_socket)
                .context("Failed to connect to `passt`")?
                .into()
        } else {
            start_passt().context("Failed to start `passt`")?.into()
        };
        // SAFETY: `passt_fd` is an `OwnedFd` and consumed to prevent closing on drop.
        // See https://doc.rust-lang.org/std/io/index.html#io-safety
        let err = unsafe { krun_set_passt_fd(ctx_id, passt_fd.into_raw_fd()) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to configure net mode");
        }
    }

    if let Ok(run_path) = env::var("XDG_RUNTIME_DIR") {
        let pulse_path = Path::new(&run_path).join("pulse/native");
        if pulse_path.exists() {
            let pulse_path = CString::new(
                pulse_path
                    .to_str()
                    .expect("pulse_path should not contain invalid UTF-8"),
            )
            .context("Failed to process `pulse/native` path as it contains NUL character")?;
            // SAFETY: `pulse_path` is a pointer to a `CString` with long enough lifetime.
            let err = unsafe { krun_add_vsock_port(ctx_id, 3333, pulse_path.as_ptr()) };
            if err < 0 {
                let err = Errno::from_raw_os_error(-err);
                return Err(err).context("Failed to configure vsock for pulse socket");
            }
        }
    }

    let username = env::var("USER").context("Failed to get username from environment")?;
    let user = User::from_name(&username)
        .map_err(Into::into)
        .and_then(|user| user.ok_or_else(|| anyhow!("requested entry not found")))
        .with_context(|| format!("Failed to get user `{username}` from user database"))?;
    let workdir_path = CString::new(
        user.dir
            .to_str()
            .expect("workdir_path should not contain invalid UTF-8"),
    )
    .expect("workdir_path should not contain NUL character");

    {
        // Set the working directory to the user's home directory, just for the sake of
        // completeness.
        //
        // SAFETY: `workdir_path` is a pointer to a `CString` with long enough lifetime.
        let err = unsafe { krun_set_workdir(ctx_id, workdir_path.as_ptr()) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).with_context(|| {
                format!(
                    "Failed to configure `{}` as working directory",
                    workdir_path
                        .into_string()
                        .expect("workdir_path should not contain invalid UTF-8")
                )
            });
        }
    }

    let krun_guest_path =
        find_in_path("krun-guest").context("Failed to check existence of `krun-guest`")?;
    let krun_guest_path = if let Some(krun_guest_path) = krun_guest_path {
        krun_guest_path
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
    let krun_guest_path = CString::new(
        krun_guest_path
            .to_str()
            .context("Failed to process `krun-guest` path as it contains invalid UTF-8")?,
    )
    .context("Failed to process `krun-guest` path as it contains NUL character")?;

    let mut krun_guest_args: Vec<CString> = vec![
        CString::new(username).expect("username should not contain NUL character"),
        CString::new(format!("{}", getuid().as_raw()))
            .expect("uid should not contain NUL character"),
        CString::new(format!("{}", getgid().as_raw()))
            .expect("gid should not contain NUL character"),
    ];
    krun_guest_args.push(
        CString::new(options.command)
            .context("Failed to process command as it contains NUL character")?,
    );
    let command_argc = options.command_args.len();
    for arg in options.command_args {
        let s = CString::new(arg)
            .context("Failed to process command arg as it contains NUL character")?;
        krun_guest_args.push(s);
    }
    let krun_guest_args: Vec<*const c_char> = {
        const KRUN_GUEST_ARGS_FIXED: usize = 4;
        // SAFETY: All pointers must be stored in the same allocation.
        // See https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html#safety
        let mut vec = Vec::with_capacity(KRUN_GUEST_ARGS_FIXED + command_argc + 1);
        for s in &krun_guest_args {
            vec.push(s.as_ptr());
        }
        vec.push(std::ptr::null());
        vec
    };

    let mut env: Vec<CString> = vec![];

    // Automatically pass these environment variables to the microVM, if they are set.
    const WELL_KNOWN_ENV_VARS: [&str; 5] = [
        "LD_LIBRARY_PATH",
        "LIBGL_DRIVERS_PATH",
        "MESA_LOADER_DRIVER_OVERRIDE", // needed for asahi
        "PATH",                        // needed by `krun-guest` program
        "RUST_LOG",
    ];

    // https://github.com/AsahiLinux/docs/wiki/Devices
    const ASAHI_SOC_COMPAT_IDS: [&str; 12] = [
        "apple,t8103",
        "apple,t6000",
        "apple,t6001",
        "apple,t6002",
        "apple,t8112",
        "apple,t6020",
        "apple,t6021",
        "apple,t6022",
        "apple,t8122",
        "apple,t6030",
        "apple,t6031",
        "apple,t6034",
    ];
    for key in WELL_KNOWN_ENV_VARS {
        let value = match env::var(key) {
            Ok(value) => value,
            Err(VarError::NotPresent) => {
                if key == "MESA_LOADER_DRIVER_OVERRIDE" {
                    match fs::read_to_string("/proc/device-tree/compatible") {
                        Ok(compatibles) => {
                            for compatible in compatibles.split('\0') {
                                if ASAHI_SOC_COMPAT_IDS.iter().any(|&s| s == compatible) {
                                    env.push(c"MESA_LOADER_DRIVER_OVERRIDE=asahi".to_owned());
                                    break;
                                }
                            }
                        },
                        Err(err) if err.kind() == ErrorKind::NotFound => {
                            continue;
                        },
                        Err(err) => {
                            Err(err).context("Failed to read `/proc/device-tree/compatible`")?
                        },
                    }
                }
                continue;
            },
            Err(err) => Err(err).with_context(|| format!("Failed to get `{key}` env var"))?,
        };
        let s = CString::new(format!("{key}={value}")).with_context(|| {
            format!("Failed to process `{key}` env var as it contains NUL character")
        })?;
        env.push(s);
    }

    for (key, value) in options.env {
        let value = value.map_or_else(
            || env::var(&key).with_context(|| format!("Failed to get `{key}` env var")),
            Ok,
        )?;
        let s = CString::new(format!("{key}={value}")).with_context(|| {
            format!("Failed to process `{key}` env var as it contains NUL character")
        })?;
        env.push(s);
    }

    debug!(env:?; "env vars");

    let env: Vec<*const c_char> = {
        // SAFETY: All pointers must be stored in the same allocation.
        // See https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html#safety
        let mut vec = Vec::with_capacity(env.len() + 1);
        for s in &env {
            vec.push(s.as_ptr());
        }
        vec.push(std::ptr::null());
        vec
    };

    {
        // Specify the path of the binary to be executed in the isolated context, relative to
        // the root path.
        //
        // SAFETY:
        // * `krun_guest_path` is a pointer to a `CString` with long enough lifetime.
        // * `krun_guest_args` is a pointer to a `Vec` of pointers to `CString`s all with long
        //   enough lifetime.
        // * `env` is a pointer to a `Vec` of pointers to `CString`s all with long enough lifetime.
        let err = unsafe {
            krun_set_exec(
                ctx_id,
                krun_guest_path.as_ptr(),
                krun_guest_args.as_ptr(),
                env.as_ptr(),
            )
        };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err)
                .context("Failed to configure the parameters for the executable to be run");
        }
    }

    {
        // Start and enter the microVM. Unless there is some error while creating the microVM
        // this function never returns.
        //
        // SAFETY: Safe as no pointers involved.
        let err = unsafe { krun_start_enter(ctx_id) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to create the microVM");
        }
    }

    unreachable!("`krun_start_enter` should never return");
}
