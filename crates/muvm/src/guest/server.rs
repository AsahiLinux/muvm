use crate::guest::server_worker::{State, Worker};
use crate::utils::launch::MUVM_GUEST_SOCKET;
use anyhow::Result;
use log::error;
use nix::libc::VMADDR_CID_ANY;
use nix::sys::socket::{
    bind, listen, socket, AddressFamily, Backlog, SockFlag, SockType, VsockAddr,
};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::ExitCode;
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::sync::watch;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::StreamExt as _;

pub async fn server_main(command: PathBuf, command_args: Vec<String>) -> Result<ExitCode> {
    let sock_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .unwrap();
    bind(
        sock_fd.as_raw_fd(),
        &VsockAddr::new(VMADDR_CID_ANY, MUVM_GUEST_SOCKET),
    )?;
    listen(&sock_fd, Backlog::MAXCONN)?;
    let std_listener = StdUnixListener::from(sock_fd);
    std_listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(std_listener)?;
    let (state_tx, state_rx) = watch::channel(State::new());

    let mut worker_handle = tokio::spawn(async move {
        let mut worker = Worker::new(listener, state_tx);
        worker.run().await;
    });
    let command_status = Command::new(&command).args(command_args).status();
    tokio::pin!(command_status);
    let mut state_rx = WatchStream::new(state_rx);

    let mut server_died = false;
    let mut command_exit_code = None;

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
            res = &mut command_status, if command_exit_code.is_none() => {
                command_exit_code = Some(match res {
                    Ok(status) if status.success() => ExitCode::SUCCESS,
                    Ok(status) => {
                        if let Some(code) = status.code() {
                            eprintln!(
                                "{command:?} process exited with status code: {code}"
                            );
                            ExitCode::from(code as u8)
                        } else {
                            eprintln!(
                                "{:?} process terminated by signal: {}",
                                command,
                                status
                                    .signal()
                                    .expect("either one of status code or signal should be set")
                            );
                            ExitCode::FAILURE
                        }
                    },
                    Err(err) => {
                        eprintln!(
                            "Failed to execute {command:?} as child process: {err}"
                        );
                        ExitCode::FAILURE
                    },
                })
            },
            Some(state) = state_rx.next(), if command_exit_code.is_some() => {
                if state.connection_idle() && state.child_processes() == 0 {
                    // Server is idle (not currently handling an accepted
                    // incoming connection) and no more child processes.
                    // We're done.
                    return Ok(command_exit_code.unwrap());
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
