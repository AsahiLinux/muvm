use std::env;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;

use anyhow::{Context, Result};
use log::error;
use muvm::server::cli_options::options;
use muvm::server::worker::{State, Worker};
use nix::unistd::geteuid;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::StreamExt as _;
use uuid::Uuid;

fn main() -> Result<()> {
    let cookie = env::var("MUVM_SERVER_COOKIE")
        .with_context(|| "Could find server cookie as an environment variable")?;

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async { tokio_main(cookie).await })
}

async fn tokio_main(cookie: String) -> Result<()> {
    env_logger::init();

    let cookie = Uuid::try_parse(&cookie).context("Couldn't parse cookie as UUID v7")?;
    let uid: u32 = geteuid().into();

    let (server_port, command, command_args) = if uid == 0 {
        let server_port = if let Ok(server_port) = env::var("MUVM_ROOT_SERVER_PORT") {
            server_port.parse()?
        } else {
            3335
        };
        (
            server_port,
            PathBuf::from("/bin/sleep"),
            vec!["inf".to_string()],
        )
    } else {
        let options = options().run();
        (options.server_port, options.command, options.command_args)
    };

    let listener = TcpListener::bind(format!("0.0.0.0:{}", server_port)).await?;
    let (state_tx, state_rx) = watch::channel(State::new());

    let mut worker_handle = tokio::spawn(async move {
        let mut worker = Worker::new(cookie, listener, state_tx);
        worker.run().await;
    });
    let command_status = Command::new(&command).args(command_args).status();
    tokio::pin!(command_status);
    let mut state_rx = WatchStream::new(state_rx);

    let mut server_died = false;
    let mut command_exited = false;

    loop {
        tokio::select! {
            res = &mut worker_handle, if !server_died => {
                // If an error is received here, accepting connections from the
                // TCP listener failed due to non-transient errors and the
                // server is giving up and shutting down.
                //
                // Errors encountered when handling individual connections do
                // not bubble up to this point.
                if let Err(err) = res {
                    error!(err:% = err; "server task failed");
                    server_died = true;
                }
            },
            res = &mut command_status, if !command_exited => {
                match res {
                    Ok(status) => {
                        if !status.success() {
                            if let Some(code) = status.code() {
                                eprintln!(
                                    "{:?} process exited with status code: {code}",
                                    command
                                );
                            } else {
                                eprintln!(
                                    "{:?} process terminated by signal: {}",
                                    command,
                                    status
                                        .signal()
                                        .expect("either one of status code or signal should be set")
                                );
                            }
                        }
                    },
                    Err(err) => {
                        eprintln!(
                            "Failed to execute {:?} as child process: {err}",
                            command
                        );
                    },
                }
                command_exited = true;
            },
            Some(state) = state_rx.next(), if command_exited => {
                if state.connection_idle() && state.child_processes() == 0 {
                    // Server is idle (not currently handling an accepted
                    // incoming connection) and no more child processes.
                    // We're done.
                    return Ok(());
                }
                println!(
                    "Waiting for {} other commands launched through this muvm server to exit...",
                    state.child_processes()
                );
                println!("Press Ctrl+C to force quit");
            },
        }
    }
}
