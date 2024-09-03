use std::cmp;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use anyhow::{Context, Result};
use krun::guest::cli_options::options;
use krun::guest::fex::setup_fex;
use krun::guest::mount::mount_filesystems;
use krun::guest::net::configure_network;
use krun::guest::socket::setup_socket_proxy;
use krun::guest::sommelier::exec_sommelier;
use krun::guest::user::setup_user;
use krun::guest::x11::setup_x11_forwarding;
use krun::utils::env::find_in_path;
use log::debug;
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
    Command::new("/usr/lib/systemd/systemd-udevd").spawn()?;

    setup_fex()?;

    configure_network()?;

    if let Some(hidpipe_client_path) = find_in_path("hidpipe-client")? {
        Command::new(hidpipe_client_path)
            .arg(format!("{}", options.uid))
            .spawn()?;
    }

    let run_path = match setup_user(options.username, options.uid, options.gid) {
        Ok(p) => p,
        Err(err) => return Err(err).context("Failed to set up user, bailing out"),
    };

    let pulse_path = run_path.join("pulse");
    std::fs::create_dir(&pulse_path)
        .context("Failed to create `pulse` directory in `XDG_RUNTIME_DIR`")?;
    let pulse_path = pulse_path.join("native");
    setup_socket_proxy(pulse_path, 3333)?;

    setup_x11_forwarding(run_path)?;

    // Will not return if successful.
    exec_sommelier(&options.command, &options.command_args)
        .context("Failed to execute sommelier")?;

    // Fallback option if sommelier is not present.
    debug!(command:? = options.command, command_args:? = options.command_args; "exec");
    let err = Command::new(&options.command)
        .args(options.command_args)
        .exec();
    Err(err).with_context(|| format!("Failed to exec {:?}", options.command))?
}
