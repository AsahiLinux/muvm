use anyhow::Result;
use krun_server::cli_options::options;
use krun_server::server::{Server, State};
use log::error;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time;
use tokio::time::Instant;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::StreamExt as _;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let options = options().run();

    let listener = TcpListener::bind(format!("0.0.0.0:{}", options.server_port)).await?;
    let (state_tx, state_rx) = watch::channel(State::new());

    let mut server_handle = tokio::spawn(async move {
        let mut server = Server::new(listener, state_tx);
        server.run().await;
    });
    let mut state_rx = WatchStream::from_changes(state_rx);
    let far_future = Duration::from_secs(3600 * 24 * 365);
    let linger_timer = time::sleep(far_future);
    tokio::pin!(linger_timer);

    loop {
        tokio::select! {
            res = &mut server_handle => {
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
                } else {
                    linger_timer.as_mut().reset(Instant::now() + far_future);
                    println!(
                        "Waiting for {} other commands launched through this krun server to exit...",
                        state.child_processes()
                    );
                }
            },
            _tick = &mut linger_timer => {
                // Server is idle (not currently handling an accepted
                // incoming connection) and no more child processes.
                // We're done.
                return Ok(());
            }
        }
    }
}
