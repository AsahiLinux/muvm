use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd;
use std::panic::catch_unwind;
use std::process::Command;
use std::{cmp, env, fs, thread};

use anyhow::{Context, Result};
use muvm::guest::box64::setup_box;
use muvm::guest::bridge::x11::start_x11bridge;
use muvm::guest::fex::setup_fex;
use muvm::guest::hidpipe::start_hidpipe;
use muvm::guest::mount::mount_filesystems;
use muvm::guest::net::configure_network;
use muvm::guest::server::server_main;
use muvm::guest::socket::setup_socket_proxy;
use muvm::guest::user::setup_user;
use muvm::guest::x11::setup_x11_forwarding;
use muvm::utils::launch::{Emulator, GuestConfiguration, PULSE_SOCKET};
use nix::unistd::{Gid, Uid};
use rustix::process::{getrlimit, setrlimit, Resource};

const KRUN_CONFIG: &str = "KRUN_CONFIG";

fn main() -> Result<()> {
    env_logger::init();

    if let Ok(val) = env::var("__X11BRIDGE_DEBUG") {
        start_x11bridge(val.parse()?);
        return Ok(());
    }

    let config_path = env::args()
        .nth(1)
        .context("expected configuration file path")?;
    let mut config_file = File::open(&config_path)?;
    let mut config_buf = Vec::new();
    config_file.read_to_end(&mut config_buf)?;
    fs::remove_file(config_path).context("Unable to delete temporary muvm configuration file")?;
    if let Ok(krun_config_path) = env::var(KRUN_CONFIG) {
        fs::remove_file(krun_config_path)
            .context("Unable to delete temporary krun configuration file")?;
        // SAFETY: We are single-threaded at this point
        env::remove_var(KRUN_CONFIG);
    }
    // SAFETY: We are single-threaded at this point
    env::remove_var("KRUN_WORKDIR");
    let options = serde_json::from_slice::<GuestConfiguration>(&config_buf)?;

    {
        const ESYNC_RLIMIT_NOFILE: u64 = 524288;
        // Raise RLIMIT_NOFILE. This is required for wine's esync to work.
        // See https://github.com/lutris/docs/blob/master/HowToEsync.md
        // See https://github.com/zfigura/wine/blob/esync/README.esync
        let mut rlim = getrlimit(Resource::Nofile);
        rlim.maximum = if let Some(maximum) = rlim.maximum {
            Some(cmp::max(maximum, ESYNC_RLIMIT_NOFILE))
        } else {
            Some(ESYNC_RLIMIT_NOFILE)
        };
        rlim.current = rlim.maximum;
        setrlimit(Resource::Nofile, rlim).context("Failed to raise `RLIMIT_NOFILE`")?;
    }

    if let Err(err) = mount_filesystems(options.merged_rootfs) {
        return Err(err).context("Failed to mount filesystems, bailing out");
    }

    // Use the correct TTY, which fixes pty issues etc. (/dev/console cannot be a controlling tty)
    let console = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open("/dev/hvc0")?;
    rustix::stdio::dup2_stdin(console.as_fd())?;
    rustix::stdio::dup2_stdout(console.as_fd())?;
    rustix::stdio::dup2_stderr(console.as_fd())?;

    Command::new("/usr/lib/systemd/systemd-udevd").spawn()?;

    if let Some(emulator) = options.emulator {
        match emulator {
            Emulator::Box => setup_box()?,
            Emulator::Fex => setup_fex()?,
        };
    } else if let Err(err) = setup_fex() {
        eprintln!("Error setting up FEX in binfmt_misc: {err}");
        eprintln!("Failed to find or configure FEX, falling back to Box");

        if let Err(err) = setup_box() {
            eprintln!("Error setting up Box in binfmt_misc: {err}");
            eprintln!("No emulators were configured, x86 emulation may not work");
        }
    }

    configure_network()?;

    let run_path = match setup_user(
        options.username,
        Uid::from(options.uid),
        Gid::from(options.gid),
    ) {
        Ok(p) => p,
        Err(err) => return Err(err).context("Failed to set up user, bailing out"),
    };

    let pulse_path = run_path.join("pulse");
    std::fs::create_dir(&pulse_path)
        .context("Failed to create `pulse` directory in `XDG_RUNTIME_DIR`")?;
    let pulse_path = pulse_path.join("native");
    setup_socket_proxy(pulse_path, PULSE_SOCKET)?;

    if let Some(host_display) = options.host_display {
        setup_x11_forwarding(run_path, &host_display)?;
    }

    let uid = options.uid;
    thread::spawn(move || {
        if catch_unwind(|| start_hidpipe(uid)).is_err() {
            eprintln!("hidpipe thread crashed, input device passthrough will no longer function");
        }
    });

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async { server_main(options.command.command, options.command.command_args).await })
}
