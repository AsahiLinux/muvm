use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::process::Command;

use anyhow::Result;
use krun_server::cli_options::options;
use krun_server::server::start_server;
use nix::sys::socket::{shutdown, Shutdown};

fn main() -> Result<()> {
    env_logger::init();

    let options = options().run();

    let listener = TcpListener::bind(format!("0.0.0.0:{}", &options.server_port))?;
    let listener_fd = listener.as_raw_fd();

    let server_thread = start_server(listener);

    let status = Command::new(&options.command)
        .args(options.command_args)
        .status();
    if let Err(err) = status {
        println!("Error executing command {}: {}", options.command, err);
    }

    shutdown(listener_fd, Shutdown::Both)?;
    if let Err(err) = server_thread.join() {
        println!("Error waiting for server thread termination: {err:?}");
    }

    Ok(())
}
