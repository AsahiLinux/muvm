use std::ffi::{c_char, CString};
use std::os::fd::{IntoRawFd, OwnedFd};
use std::path::Path;
use std::{cmp, env};

use anyhow::{anyhow, Context, Result};
use krun::cli_options::options;
use krun::cpu::{get_fallback_cores, get_performance_cores};
use krun::env::{find_krun_exec, prepare_env_vars};
use krun::launch::{launch_or_lock, LaunchResult};
use krun::net::{connect_to_passt, start_passt};
use krun::types::MiB;
use krun_sys::{
    krun_add_vsock_port, krun_create_ctx, krun_set_exec, krun_set_gpu_options, krun_set_log_level,
    krun_set_passt_fd, krun_set_root, krun_set_vm_config, krun_set_workdir, krun_start_enter,
    VIRGLRENDERER_DRM, VIRGLRENDERER_THREAD_SYNC, VIRGLRENDERER_USE_ASYNC_FENCE_CB,
    VIRGLRENDERER_USE_EGL,
};
use log::debug;
use nix::sys::sysinfo::sysinfo;
use nix::unistd::User;
use rustix::io::Errno;
use rustix::process::{
    geteuid, getgid, getrlimit, getuid, sched_setaffinity, setrlimit, CpuSet, Resource,
};

fn main() -> Result<()> {
    env_logger::init();

    if getuid().as_raw() == 0 || geteuid().as_raw() == 0 {
        println!("Running as root is not supported as it may break your system");
        return Err(anyhow!("real user ID or effective user ID is 0"));
    }

    let options = options().fallback_to_usage().run();

    let (_lock_file, command, command_args, env) = match launch_or_lock(
        options.server_port,
        options.command,
        options.command_args,
        options.env,
    )? {
        LaunchResult::LaunchRequested => {
            // There was a krun instance already running and we've requested it
            // to launch the command successfully, so all the work is done.
            return Ok(());
        },
        LaunchResult::LockAcquired {
            lock_file,
            command,
            command_args,
            env,
        } => (lock_file, command, command_args, env),
    };

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
        let cpu_list = if !options.cpu_list.is_empty() {
            options.cpu_list
        } else {
            get_performance_cores()
                .inspect_err(|err| {
                    debug!(err:?; "get_performance_cores error");
                })
                .or_else(|_err| get_fallback_cores())?
        };
        let num_vcpus = cpu_list.iter().fold(0, |acc, cpus| acc + cpus.len()) as u8;
        let ram_mib = if let Some(ram_mib) = options.mem {
            ram_mib
        } else {
            let sysinfo = sysinfo().context("Failed to get system information")?;
            let ram_total = sysinfo.ram_total() / 1024 / 1024;
            cmp::min(MiB::from((ram_total as f64 * 0.8) as u32), MiB::from(16384))
        };
        // Bind the microVM to the specified CPU cores.
        let mut cpuset = CpuSet::new();
        for cpus in cpu_list {
            for cpu in cpus {
                cpuset.set(cpu as usize);
            }
        }
        debug!(cpuset:?; "sched_setaffinity");
        sched_setaffinity(None, &cpuset).context("Failed to set CPU affinity")?;
        // Configure the number of vCPUs and the amount of RAM (max 16384 MiB).
        //
        // SAFETY: Safe as no pointers involved.
        debug!(num_vcpus, ram_mib = u32::from(ram_mib); "krun_set_vm_config");
        let err = unsafe { krun_set_vm_config(ctx_id, num_vcpus, ram_mib.into()) };
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

    {
        let passt_fd: OwnedFd = if let Some(passt_socket) = options.passt_socket {
            connect_to_passt(passt_socket)
                .context("Failed to connect to `passt`")?
                .into()
        } else {
            start_passt(options.server_port)
                .context("Failed to start `passt`")?
                .into()
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

        let socket_dir = Path::new(&run_path).join("krun/socket");
        std::fs::create_dir_all(&socket_dir)?;
        // Dynamic ports: Applications may listen on these sockets as neeeded.
        for port in 50000..50200 {
            let socket_path = socket_dir.join(format!("port-{}", port));
            let socket_path = CString::new(
                socket_path
                    .to_str()
                    .expect("socket_path should not contain invalid UTF-8"),
            )
            .context("Failed to process dynamic socket path as it contains NUL character")?;
            // SAFETY: `socket_path` is a pointer to a `CString` with long enough lifetime.
            let err = unsafe { krun_add_vsock_port(ctx_id, port, socket_path.as_ptr()) };
            if err < 0 {
                let err = Errno::from_raw_os_error(-err);
                return Err(err).context("Failed to configure vsock for dynamic socket");
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

    let krun_guest_path = find_krun_exec("krun-guest")?;
    let krun_server_path = find_krun_exec("krun-server")?;

    let mut krun_guest_args: Vec<CString> = vec![
        CString::new(username).expect("username should not contain NUL character"),
        CString::new(format!("{}", getuid().as_raw()))
            .expect("uid should not contain NUL character"),
        CString::new(format!("{}", getgid().as_raw()))
            .expect("gid should not contain NUL character"),
    ];

    krun_guest_args.push(krun_server_path);
    krun_guest_args.push(
        CString::new(
            command
                .to_str()
                .context("Failed to process command as it contains invalid UTF-8")?,
        )
        .context("Failed to process command as it contains NUL character")?,
    );
    let command_argc = command_args.len();
    for arg in command_args {
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

    let mut env = prepare_env_vars(env).context("Failed to prepare environment variables")?;
    env.insert(
        "KRUN_SERVER_PORT".to_owned(),
        options.server_port.to_string(),
    );
    let env: Vec<CString> = {
        let mut vec = Vec::with_capacity(env.len());
        for (key, value) in env {
            let s = CString::new(format!("{key}={value}")).with_context(|| {
                format!("Failed to process `{key}` env var as it contains NUL character")
            })?;
            vec.push(s);
        }
        vec
    };
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
        // Specify the path of the binary to be executed in the isolated context,
        // relative to the root path.
        //
        // SAFETY:
        // * `krun_guest_path` is a pointer to a `CString` with long enough lifetime.
        // * `krun_guest_args` is a pointer to a `Vec` of pointers to `CString`s all
        //   with long enough lifetime.
        // * `env` is a pointer to a `Vec` of pointers to `CString`s all with long
        //   enough lifetime.
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
        // Start and enter the microVM. Unless there is some error while creating the
        // microVM this function never returns.
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
