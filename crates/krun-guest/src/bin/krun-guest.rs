use std::{os::unix::process::CommandExt as _, process::Command};

use anyhow::{Context, Result};
use krun_guest::{
    cli_options::options, fex::setup_fex, mount::mount_filesystems, net::configure_network,
    sommelier::exec_sommelier, user::setup_user,
};
use log::debug;
use rustix::process::{getrlimit, setrlimit, Resource};

fn main() -> Result<()> {
    env_logger::init();

    let options = options().run();

    {
        // Raise RLIMIT_NOFILE to the maximum allowed. This is required for wine's esync to work.
        // See https://github.com/lutris/docs/blob/master/HowToEsync.md
        // See https://github.com/zfigura/wine/blob/esync/README.esync
        let mut rlim = getrlimit(Resource::Nofile);
        rlim.current = rlim.maximum;
        setrlimit(Resource::Nofile, rlim).context("Failed to raise `RLIMIT_NOFILE`")?;
    }

    if let Err(err) = mount_filesystems() {
        return Err(err).context("Couldn't mount filesystems, bailing out");
    }

    setup_fex()?;

    configure_network()?;

    if let Err(err) = setup_user(options.username, options.uid, options.gid) {
        return Err(err).context("Couldn't set up user, bailing out");
    }

    // Will not return if successful.
    exec_sommelier(&options.command, &options.command_args)
        .context("Failed to execute sommelier")?;

    // Fallback option if sommelier is not present.
    debug!(command:% = options.command, command_args:? = options.command_args; "exec");
    let err = Command::new(&options.command)
        .args(options.command_args)
        .exec();
    Err(err).with_context(|| format!("Failed to exec `{}`", options.command))?
}
