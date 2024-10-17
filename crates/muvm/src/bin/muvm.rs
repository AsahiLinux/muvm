use std::env;
use std::ffi::{c_char, CString};
use std::io::Write;
use std::os::fd::{IntoRawFd, OwnedFd};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use krun_sys::{
    krun_add_disk, krun_add_vsock_port, krun_create_ctx, krun_set_env, krun_set_gpu_options2,
    krun_set_log_level, krun_set_passt_fd, krun_set_root, krun_set_vm_config, krun_set_workdir,
    krun_start_enter, VIRGLRENDERER_DRM, VIRGLRENDERER_THREAD_SYNC,
    VIRGLRENDERER_USE_ASYNC_FENCE_CB, VIRGLRENDERER_USE_EGL,
};
use log::debug;
use muvm::cli_options::options;
use muvm::cpu::{get_fallback_cores, get_performance_cores};
use muvm::env::{find_muvm_exec, prepare_env_vars};
use muvm::launch::{launch_or_lock, LaunchResult};
use muvm::monitor::spawn_monitor;
use muvm::net::{connect_to_passt, start_passt};
use muvm::types::MiB;
use nix::sys::sysinfo::sysinfo;
use nix::unistd::User;
use rustix::io::Errno;
use rustix::process::{
    geteuid, getgid, getrlimit, getuid, sched_setaffinity, setrlimit, CpuSet, Resource,
};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

#[derive(Serialize, Deserialize)]
pub struct KrunConfig {
    #[serde(rename = "Cmd")]
    args: Vec<String>,
    #[serde(rename = "Env")]
    envs: Vec<String>,
}
#[derive(Serialize, Deserialize)]
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

fn main() -> Result<()> {
    env_logger::init();

    if getuid().as_raw() == 0 || geteuid().as_raw() == 0 {
        println!("Running as root is not supported as it may break your system");
        return Err(anyhow!("real user ID or effective user ID is 0"));
    }

    let options = options().fallback_to_usage().run();

    let (cookie, _lock_file, command, command_args, env) = match launch_or_lock(
        options.server_port,
        options.command,
        options.command_args,
        options.env,
    )? {
        LaunchResult::LaunchRequested => {
            // There was a muvm instance already running and we've requested it
            // to launch the command successfully, so all the work is done.
            return Ok(());
        },
        LaunchResult::LockAcquired {
            cookie,
            lock_file,
            command,
            command_args,
            env,
        } => (cookie, lock_file, command, command_args, env),
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

        let sysinfo = sysinfo().context("Failed to get system information")?;
        let ram_total_mib = (sysinfo.ram_total() / (1024 * 1024)) as u32;

        let ram_mib = if let Some(ram_mib) = options.mem {
            ram_mib
        } else {
            // By default, set the microVM RAM to be 80% of the system's RAM.
            let guest_ram = (ram_total_mib as f64 * 0.8) as u32;
            // Ensure we leave 3072 MiB free for the host + VRAM to avoid
            // compromising the host's stability. This mainly applies to systems
            // with 8GB of RAM.
            let guest_ram = if ram_total_mib
                .checked_sub(guest_ram)
                .context("Failed to calculate the amount of free RAM")?
                < 3072
            {
                ram_total_mib
                    .checked_sub(3072)
                    .context("Systems with less than 3072 MiB of RAM are not supported")?
            } else {
                guest_ram
            };
            MiB::from(guest_ram)
        };
        // VRAM is actually the SHM window for virtio-gpu. The userspace drivers in the
        // guest are expected to be conservative and tell applications that the amount
        // of VRAM is just a percentage of the guest's RAM, so we can afford being more
        // aggressive here and set the window to be as large as the system's RAM, leaving
        // some room for dealing with potential fragmentation.
        let vram_mib = options.vram.unwrap_or(MiB::from(ram_total_mib as u32));

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
                (u32::from(vram_mib) as u64) * 1024 * 1024,
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
    }

    {
        let passt_fd: OwnedFd = if let Some(passt_socket) = options.passt_socket {
            connect_to_passt(passt_socket)
                .context("Failed to connect to `passt`")?
                .into()
        } else {
            start_passt(options.server_port, options.root_server_port)
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
        let hidpipe_path = Path::new(&run_path).join("hidpipe");
        if hidpipe_path.exists() {
            let hidpipe_path = CString::new(
                hidpipe_path
                    .to_str()
                    .expect("hidpipe_path should not contain invalid UTF-8"),
            )
            .context("Failed to process `hidpipe` path as it contains NUL character")?;
            // SAFETY: `hidpipe_path` is a pointer to a `CString` with long enough lifetime.
            let err = unsafe { krun_add_vsock_port(ctx_id, 3334, hidpipe_path.as_ptr()) };
            if err < 0 {
                let err = Errno::from_raw_os_error(-err);
                return Err(err).context("Failed to configure vsock for hidpipe socket");
            }
        }
    }

    // Forward the native X11 display into the guest as a socket
    if let Ok(x11_display) = env::var("DISPLAY") {
        if let Some(x11_display) = x11_display.strip_prefix(":") {
            let socket_path = Path::new("/tmp/.X11-unix/").join(format!("X{}", x11_display));
            if socket_path.exists() {
                let socket_path = CString::new(
                    socket_path
                        .to_str()
                        .expect("socket_path should not contain invalid UTF-8"),
                )
                .context("Failed to process dynamic socket path as it contains NUL character")?;
                // SAFETY: `socket_path` is a pointer to a `CString` with long enough lifetime.
                let err = unsafe { krun_add_vsock_port(ctx_id, 6000, socket_path.as_ptr()) };
                if err < 0 {
                    let err = Errno::from_raw_os_error(-err);
                    return Err(err).context("Failed to configure vsock for host X11 socket");
                }
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

    let muvm_guest_path = find_muvm_exec("muvm-guest")?;
    let muvm_server_path = find_muvm_exec("muvm-server")?;

    let mut muvm_guest_args: Vec<String> = vec![
        muvm_guest_path,
        username,
        format!("{uid}", uid = getuid().as_raw()),
        format!("{gid}", gid = getgid().as_raw()),
        muvm_server_path,
        command
            .to_str()
            .context("Failed to process command as it contains invalid UTF-8")?
            .to_string(),
    ];
    for arg in command_args {
        muvm_guest_args.push(arg);
    }

    let mut env = prepare_env_vars(env).context("Failed to prepare environment variables")?;
    env.insert(
        "MUVM_SERVER_PORT".to_owned(),
        options.server_port.to_string(),
    );
    env.insert(
        "MUVM_ROOT_SERVER_PORT".to_owned(),
        options.root_server_port.to_string(),
    );
    env.insert("MUVM_SERVER_COOKIE".to_owned(), cookie.to_string());

    let mut krun_config = KrunConfig {
        args: Vec::new(),
        envs: Vec::new(),
    };
    for arg in muvm_guest_args {
        krun_config.args.push(arg);
    }
    for (key, value) in env {
        krun_config.envs.push(format!("{}={}", key, value));
    }
    let krun_config = KrunBaseConfig {
        config: krun_config,
    };

    // SAFETY: `config_file` lifetime needs to exceed krun_start_enter's
    let mut config_file = NamedTempFile::new()
        .context("Failed to create a temporary file to store the guest config")?;
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

    spawn_monitor(options.root_server_port, cookie);

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
