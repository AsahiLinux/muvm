use std::convert::Infallible;
use std::env;
use std::ffi::{c_char, CString};
use std::fs::{self, File};
use std::io::Write;
use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{anyhow, Context, Result};
use krun_sys::{
    krun_add_disk, krun_add_virtiofs2, krun_add_vsock_port, krun_add_vsock_port2, krun_create_ctx,
    krun_set_console_output, krun_set_env, krun_set_gpu_options2, krun_set_log_level,
    krun_set_passt_fd, krun_set_root, krun_set_vm_config, krun_set_workdir, krun_start_enter,
    VIRGLRENDERER_DRM, VIRGLRENDERER_THREAD_SYNC, VIRGLRENDERER_USE_ASYNC_FENCE_CB,
    VIRGLRENDERER_USE_EGL,
};
use log::debug;
use muvm::cli_options::{options, Options};
use muvm::cpu::{get_fallback_cores, get_performance_cores};
use muvm::env::{find_muvm_exec, prepare_env_vars};
use muvm::hidpipe_server::spawn_hidpipe_server;
use muvm::launch::{launch_or_lock, LaunchResult, DYNAMIC_PORT_RANGE};
use muvm::monitor::spawn_monitor;
use muvm::net::{connect_to_passt, start_passt};
use muvm::types::MiB;
use muvm::utils::launch::{GuestConfiguration, HIDPIPE_SOCKET, MUVM_GUEST_SOCKET, PULSE_SOCKET};
use nix::fcntl::{fcntl, FcntlArg};
use nix::sys::sysinfo::sysinfo;
use nix::unistd::User;
use rustix::io::{dup, Errno};
use rustix::process::{
    geteuid, getgid, getrlimit, getuid, sched_setaffinity, setrlimit, CpuSet, Resource,
};
use serde::Serialize;
use tempfile::NamedTempFile;
use uuid::Uuid;

const LOCK_FD_ENV_VAR: &str = "__MUVM_DO_LAUNCH_VM_LOCK__";

#[derive(Serialize)]
pub struct KrunConfig {
    #[serde(rename = "Cmd")]
    args: Vec<String>,
    #[serde(rename = "Env")]
    envs: Vec<String>,
}
#[derive(Serialize)]
pub struct KrunBaseConfig {
    #[serde(rename = "Config")]
    config: KrunConfig,
}

fn add_ro_disk(ctx_id: u32, label: &str, path: &str) -> Result<()> {
    let path_cstr = CString::new(path).unwrap();
    let path_ptr = path_cstr.as_ptr();

    let label_cstr = CString::new(label).unwrap();
    let label_ptr = label_cstr.as_ptr();

    // SAFETY: `path_ptr` and `label_ptr` are live pointers to C-strings
    let err = unsafe { krun_add_disk(ctx_id, label_ptr, path_ptr, true) };

    if err < 0 {
        Err(Errno::from_raw_os_error(-err).into())
    } else {
        Ok(())
    }
}

fn main() -> Result<ExitCode> {
    env_logger::init();

    if getuid().as_raw() == 0 || geteuid().as_raw() == 0 {
        println!("Running as root is not supported as it may break your system");
        return Err(anyhow!("real user ID or effective user ID is 0"));
    }

    let options = options().fallback_to_usage().run();
    if let Ok(lock_fd) = env::var(LOCK_FD_ENV_VAR) {
        let lock_fd = lock_fd.parse()?;
        fcntl(lock_fd, FcntlArg::F_GETFD).context("Lockfile fd is not open")?;
        // SAFETY: We verify that the file descriptor is valid.
        // The file will not be read from/written to,
        // so worse case if it's not a file nothing bad will happen,
        // as we only care about calling `close` on Drop.
        let _lock_file = unsafe { File::from_raw_fd(lock_fd) };
        launch_vm(options)?;
        unreachable!("`launch_vm` never returns");
    }

    let (lock_file, command, command_args, env) = match launch_or_lock(
        options.command,
        options.command_args,
        options.env,
        options.tty,
        options.privileged,
    )? {
        LaunchResult::LaunchRequested(code) => {
            // There was a muvm instance already running and we've requested it
            // to launch the command successfully, so all the work is done.
            return Ok(code);
        },
        LaunchResult::LockAcquired {
            lock_file,
            command,
            command_args,
            env,
        } => (lock_file, command, command_args, env),
    };

    // Make it lose CLOEXEC
    let lock_fd = dup(lock_file)?;
    Command::new(env::current_exe()?)
        .args(env::args())
        .env(LOCK_FD_ENV_VAR, lock_fd.into_raw_fd().to_string())
        .spawn()?;
    match launch_or_lock(command, command_args, env, options.tty, options.privileged)? {
        LaunchResult::LockAcquired { .. } => Err(anyhow!("VM did not start")),
        LaunchResult::LaunchRequested(code) => Ok(code),
    }
}

fn launch_vm(options: Options) -> Result<Infallible> {
    let mut env =
        prepare_env_vars(Vec::new()).context("Failed to prepare environment variables")?;
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

        let sysinfo = sysinfo().context("Failed to get system information")?;
        let ram_total_mib = (sysinfo.ram_total() / (1024 * 1024)) as u32;

        // By default, set the microVM RAM to be 80% of the system's RAM.
        let ram_mib = options
            .mem
            .unwrap_or(MiB::from((ram_total_mib as f64 * 0.8) as u32));

        // By default, HK sets the heap size to be half the size of the *guest* memory.
        // Since commit 167744dc it's also possible to override the heap size by setting
        // the HK_SYSMEM environment variable.
        //
        // Let's set the SHM window for virtio-gpu to be as large as the host's RAM, not
        // because we expect VRAM to be as large as RAM, but to account for the more than
        // likely region fragmentation.
        //
        // Then, let's set HK_SYSMEM to be either half the size of the *host* memory, or
        // the value passed by the user with the "vram" argument.
        let vram_shm_mib = MiB::from(ram_total_mib as u32);
        let vram_mib = options.vram.unwrap_or(MiB::from(ram_total_mib as u32 / 2));
        env.insert(
            "HK_SYSMEM".to_owned(),
            (u32::from(vram_mib) as u64 * 1024 * 1024).to_string(),
        );

        // Bind the microVM to the specified CPU cores.
        let mut cpuset = CpuSet::new();
        for cpus in cpu_list {
            for cpu in cpus {
                cpuset.set(cpu as usize);
            }
        }
        debug!(cpuset:?; "sched_setaffinity");
        sched_setaffinity(None, &cpuset).context("Failed to set CPU affinity")?;
        // Configure the number of vCPUs and the amount of RAM.
        //
        // SAFETY: Safe as no pointers involved.
        debug!(num_vcpus, ram_mib = u32::from(ram_mib); "krun_set_vm_config");
        let err = unsafe { krun_set_vm_config(ctx_id, num_vcpus, ram_mib.into()) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err)
                .context("Failed to configure the number of vCPUs and/or the amount of RAM");
        }

        let virgl_flags = VIRGLRENDERER_USE_EGL
            | VIRGLRENDERER_DRM
            | VIRGLRENDERER_THREAD_SYNC
            | VIRGLRENDERER_USE_ASYNC_FENCE_CB;
        // SAFETY: Safe as no pointers involved.
        let err = unsafe {
            krun_set_gpu_options2(
                ctx_id,
                virgl_flags,
                (u32::from(vram_shm_mib) as u64) * 1024 * 1024,
            )
        };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to configure gpu");
        }
    }

    {
        // Raise RLIMIT_NOFILE to the maximum allowed to create some room for virtio-fs
        let mut rlim = getrlimit(Resource::Nofile);
        rlim.current = rlim.maximum;
        setrlimit(Resource::Nofile, rlim).context("Failed to raise `RLIMIT_NOFILE`")?;
    }

    // If the user specified a disk image, we want to load and fail if it's missing. If the user
    // did not specify a disk image, we want to load the system images if installed but fail
    // gracefully if missing. This follows the principle of least surprise.
    //
    // What we don't want is a clever autodiscovery mechanism that searches $HOME for images.
    // That's liable to blow up in exciting ways. Instead we require images to be selected
    // explicitly, either on the CLI or hardcoded here.
    let disks: Vec<String> = if !options.fex_images.is_empty() {
        options.fex_images
    } else {
        let default_disks = [
            "/usr/share/fex-emu/RootFS/default.erofs",
            "/usr/share/fex-emu/overlays/mesa-i386.erofs",
            "/usr/share/fex-emu/overlays/mesa-x86_64.erofs",
        ];

        default_disks
            .iter()
            .map(|x| x.to_string())
            .filter(|x| Path::new(x).exists())
            .collect()
    };

    if options.merged_rootfs && disks.is_empty() {
        return Err(anyhow!(
            "Merged RootFS mode requires one or more RootFS images"
        ));
    }

    for path in disks {
        add_ro_disk(ctx_id, &path, &path).context("Failed to configure disk")?;
    }

    {
        // SAFETY: `root_path` is a pointer to a C-string literal.
        let err = unsafe { krun_set_root(ctx_id, c"/".as_ptr()) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to configure root path");
        }

        // SAFETY: `c_path` and `c_path` are pointers to C-string literals.
        let err = unsafe {
            krun_add_virtiofs2(
                ctx_id,
                c"devshm".as_ptr(),
                c"/dev/shm/".as_ptr(),
                1u64 << 29, // 512MiB should be enough for /dev/shm
            )
        };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to configure /dev/shm filesystem");
        }
    }

    {
        let passt_fd: OwnedFd = if let Some(passt_socket) = options.passt_socket {
            connect_to_passt(passt_socket)
                .context("Failed to connect to `passt`")?
                .into()
        } else {
            start_passt(&options.publish_ports)
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

    let console_base;
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
            let err = unsafe { krun_add_vsock_port(ctx_id, PULSE_SOCKET, pulse_path.as_ptr()) };
            if err < 0 {
                let err = Errno::from_raw_os_error(-err);
                return Err(err).context("Failed to configure vsock for pulse socket");
            }
        }

        let hidpipe_path = Path::new(&run_path).join("hidpipe");
        spawn_hidpipe_server(hidpipe_path.clone()).context("Failed to spawn hidpipe thread")?;
        let hidpipe_path = CString::new(
            hidpipe_path
                .to_str()
                .expect("hidpipe_path should not contain invalid UTF-8"),
        )
        .context("Failed to process `hidpipe` path as it contains NUL character")?;

        // SAFETY: `hidpipe_path` is a pointer to a `CString` with long enough lifetime.
        let err = unsafe { krun_add_vsock_port(ctx_id, HIDPIPE_SOCKET, hidpipe_path.as_ptr()) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to configure vsock for hidpipe socket");
        }

        let socket_dir = Path::new(&run_path).join("krun/socket");
        std::fs::create_dir_all(&socket_dir)?;
        // Dynamic ports: Applications may listen on these sockets as neeeded.
        for port in DYNAMIC_PORT_RANGE {
            let socket_path = socket_dir.join(format!("port-{port}"));
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

        let server_path = Path::new(&run_path).join("krun/server");
        _ = fs::remove_file(&server_path);
        let server_path = CString::new(
            server_path
                .to_str()
                .expect("server_path should not contain invalid UTF-8"),
        )
        .context("Failed to process `muvm-guest` path as it contains NUL characters")?;
        // SAFETY: `server_path` is a pointer to a `CString` with long enough lifetime.
        let err =
            unsafe { krun_add_vsock_port2(ctx_id, MUVM_GUEST_SOCKET, server_path.as_ptr(), true) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to configure vsock for guest server socket");
        }
        console_base = run_path;
    } else {
        console_base = "/tmp".to_string();
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

    let muvm_guest_path = find_muvm_exec("muvm-guest")?;

    let display = env::var("DISPLAY").ok();
    let guest_config = GuestConfiguration {
        username,
        uid: getuid().as_raw(),
        gid: getgid().as_raw(),
        host_display: display,
        merged_rootfs: options.merged_rootfs,
        emulator: options.emulator,
    };
    let mut muvm_config_file = NamedTempFile::new()
        .context("Failed to create a temporary file to store the muvm guest config")?;
    write!(
        muvm_config_file,
        "{}",
        serde_json::to_string(&guest_config)
            .context("Failed to transform GuestConfiguration into a JSON string")?
    )
    .context("Failed to write to temporary config file")?;

    let muvm_config_path = muvm_config_file
        .path()
        .to_str()
        .context("Temporary directory path contains invalid UTF-8")?
        .to_owned();
    let muvm_guest_args = vec![
        muvm_guest_path
            .to_str()
            .context("Failed to process `muvm-guest` path as it contains invalid UTF-8")?
            .to_owned(),
        muvm_config_path,
    ];

    // And forward XAUTHORITY. This will be modified to fix the
    // display name in muvm-guest.
    if let Ok(xauthority) = env::var("XAUTHORITY") {
        env.insert("XAUTHORITY".to_owned(), xauthority);
    }

    let krun_config = KrunBaseConfig {
        config: KrunConfig {
            args: muvm_guest_args,
            envs: env
                .into_iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect(),
        },
    };

    // SAFETY: `config_file` lifetime needs to exceed krun_start_enter's
    let mut config_file = NamedTempFile::new()
        .context("Failed to create a temporary file to store the krun config")?;
    write!(
        config_file,
        "{}",
        serde_json::to_string(&krun_config)
            .context("Failed to transform KrunConfig into a JSON string")?
    )
    .context("Failed to write to temporary config file")?;

    let krun_config_env = CString::new(format!("KRUN_CONFIG={}", config_file.path().display()))
        .context("Failed to process config_file var as it contains NUL character")?;
    let env: Vec<*const c_char> = vec![krun_config_env.as_ptr(), std::ptr::null()];

    {
        // Sets environment variables to be configured in the context of the executable.
        //
        // SAFETY:
        // * `env` is a pointer to a `Vec` of pointers to `CString`s all with long
        //   enough lifetime.
        let err = unsafe { krun_set_env(ctx_id, env.as_ptr()) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to set the environment variables in the guest");
        }
    }

    {
        let uuid = Uuid::now_v7();
        let path = Path::new(&console_base).join(format!("muvm-{uuid}.console"));
        let console_path = CString::new(
            path.to_str()
                .expect("console_path should not contain invalid UTF-8"),
        )
        .expect("console_path should not contain NUL character");
        // SAFETY: `console_path` is a CString that outlives this call
        let err = unsafe { krun_set_console_output(ctx_id, console_path.as_ptr()) };
        if err < 0 {
            let err = Errno::from_raw_os_error(-err);
            return Err(err).context("Failed to configure console");
        }
    }

    spawn_monitor();

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
