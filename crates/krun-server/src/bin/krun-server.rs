use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::panic;
use std::process::Command;

use anyhow::{Context, Result};
use krun_server::cli_options::options;
use krun_server::server::start_server;
use nix::sys::socket::{shutdown, Shutdown};

fn main() -> Result<()> {
    env_logger::init();

    let options = options().run();

    let listener = TcpListener::bind(format!("0.0.0.0:{}", options.server_port))?;
    let listener_fd = listener.as_raw_fd();

    let server_thread = start_server(listener);

    Command::new(&options.command)
        .args(options.command_args)
        .status()
        .with_context(|| format!("Failed to execute command {:?}", options.command))?;

    shutdown(listener_fd, Shutdown::Both)?;
    if let Err(err) = server_thread.join() {
        panic::resume_unwind(err);
    }

    Ok(())
}
