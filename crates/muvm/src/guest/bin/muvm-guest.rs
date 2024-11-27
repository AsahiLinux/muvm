use std::cmp;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use anyhow::{Context, Result};
use log::debug;
use muvm::env::find_muvm_exec;
use muvm::guest::cli_options::options;
use muvm::guest::fex::setup_fex;
use muvm::guest::mount::mount_filesystems;
use muvm::guest::net::configure_network;
use muvm::guest::socket::setup_socket_proxy;
use muvm::guest::sommelier::exec_sommelier;
use muvm::guest::user::setup_user;
#[cfg(feature = "x11bridge")]
use muvm::guest::x11::setup_x11_forwarding;
use muvm::utils::env::find_in_path;
use rustix::process::{getrlimit, setrlimit, Resource};

fn main() -> Result<()> {
    env_logger::init();

    let options = options().run();

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

    if let Err(err) = mount_filesystems() {
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

    setup_fex()?;

    configure_network()?;

    if let Some(hidpipe_client_path) = find_in_path("hidpipe-client")? {
        Command::new(hidpipe_client_path)
            .arg(format!("{}", options.uid))
            .spawn()?;
    }

    // Before switching to the user, start another instance of muvm-server to serve
    // launch requests as root.
    let muvm_server_path = find_muvm_exec("muvm-server")?;
    Command::new(muvm_server_path)
        .spawn()
        .context("Failed to execute `muvm-server` as child process")?;

    let run_path = match setup_user(options.username, options.uid, options.gid) {
        Ok(p) => p,
        Err(err) => return Err(err).context("Failed to set up user, bailing out"),
    };

    let pulse_path = run_path.join("pulse");
    std::fs::create_dir(&pulse_path)
        .context("Failed to create `pulse` directory in `XDG_RUNTIME_DIR`")?;
    let pulse_path = pulse_path.join("native");
    setup_socket_proxy(pulse_path, 3333)?;

    #[cfg(feature = "x11bridge")]
    let direct_x11 = setup_x11_forwarding(run_path)?;
    #[cfg(not(feature = "x11bridge"))]
    let direct_x11 = false;

    if !direct_x11 {
        // Will not return if successful.
        exec_sommelier(&options.command, &options.command_args)
            .context("Failed to execute sommelier")?;
    }

    // Fallback option if sommelier is not present or for direct X11 mode.
    debug!(command:? = options.command, command_args:? = options.command_args; "exec");
    let err = Command::new(&options.command)
        .args(options.command_args)
        .exec();
    Err(err).with_context(|| format!("Failed to exec {:?}", options.command))?
}
