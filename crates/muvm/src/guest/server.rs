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
use tokio::net::UnixListener;
use tokio::sync::watch;
use tokio::time::{self, Duration, Instant};
use tokio_stream::wrappers::WatchStream;
use tokio_stream::StreamExt as _;

pub async fn server_main() -> Result<()> {
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
    let mut state_rx = WatchStream::new(state_rx);
    let far_future = Duration::from_secs(3600 * 24 * 365);
    let linger_timer = time::sleep(far_future);
    tokio::pin!(linger_timer);

    let mut all_exited = false;

    loop {
        tokio::select! {
            res = &mut worker_handle => {
                // If an error is received here, accepting connections from the
                // TCP listener failed due to non-transient errors and the
                // server is giving up and shutting down.
                //
                // Errors encountered when handling individual connections do
                // not bubble up to this point.
                if let Err(err) = res {
                    error!(err:% = err; "server task failed");
                    return Ok(());
                }
            },
            Some(state) = state_rx.next() => {
                if state.connection_idle() && state.child_processes() == 0 {
                    linger_timer.as_mut().reset(Instant::now() + Duration::from_secs(10));
                    all_exited = true;
                } else {
                    linger_timer.as_mut().reset(Instant::now() + far_future);
                    println!(
                        "Waiting for {} other commands launched through this muvm server to exit...",
                        state.child_processes()
                    );
                    all_exited = false;
                }
            },
            _tick = &mut linger_timer, if all_exited => {
                // Server is idle (not currently handling an accepted
                // incoming connection) and no more child processes.
                // We're done.
                return Ok(());
            }
        }
    }
}
