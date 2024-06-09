use std::collections::HashMap;
use std::env;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{anyhow, Context, Result};
use log::{debug, error};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt as _;
use utils::launch::Launch;
use utils::stdio::make_stdout_stderr;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct State {
    pub connection_idle: bool,
    pub child_processes: usize,
}

pub async fn start_server(listener: TcpListener, state_tx: watch::Sender<State>) {
    let mut listener_stream = TcpListenerStream::new(listener);
    let mut child_set = JoinSet::new();

    loop {
        tokio::select! {
            Some(stream) = listener_stream.next() => {
                state_tx.send_if_modified(|state| {
                    let connection_idle = false;
                    if state.connection_idle == connection_idle {
                        return false;
                    }
                    state.connection_idle = connection_idle;
                    true
                });
                let stream = match stream {
                    Ok(stream) => stream,
                    Err(err) => {
                        eprintln!("Failed to accept incoming connection: {err}");
                        state_tx.send_if_modified(|state| {
                            let connection_idle = true;
                            if state.connection_idle == connection_idle {
                                return false;
                            }
                            state.connection_idle = connection_idle;
                            true
                        });
                        continue;
                    },
                };
                let stream = BufStream::new(stream);

                match handle_connection(stream).await {
                    Ok((command, mut child)) => {
                        child_set.spawn(async move { (command, child.wait().await) });
                        state_tx.send_if_modified(|state| {
                            let child_processes = child_set.len();
                            if state.child_processes == child_processes {
                                return false;
                            }
                            state.child_processes = child_processes;
                            true
                        });
                    },
                    Err(err) => {
                        eprintln!("Failed to process client request: {err:?}");
                    },
                }
                state_tx.send_if_modified(|state| {
                    let connection_idle = true;
                    if state.connection_idle == connection_idle {
                        return false;
                    }
                    state.connection_idle = connection_idle;
                    true
                });
            },
            Some(res) = child_set.join_next() => {
                match res {
                    Ok((command, res)) => match res {
                        Ok(status) => {
                            debug!(command:?; "child process exited");
                            if !status.success() {
                                if let Some(code) = status.code() {
                                    eprintln!(
                                        "{command:?} process exited with status code: {code}"
                                    );
                                } else {
                                    eprintln!(
                                        "{command:?} process terminated by signal: {}",
                                        status
                                            .signal()
                                            .expect(
                                                "either one of status code or signal should be set"
                                            )
                                    );
                                }
                            }
                        },
                        Err(err) => {
                            eprintln!("Failed to wait for {command:?} process to exit: {err}");
                        },
                    },
                    Err(err) => {
                        error!(err:% = err; "child task failed");
                    },
                }
                state_tx.send_if_modified(|state| {
                    let child_processes = child_set.len();
                    if state.child_processes == child_processes {
                        return false;
                    }
                    state.child_processes = child_processes;
                    true
                });
            },
        }
    }
}

async fn read_request(stream: &mut BufStream<TcpStream>) -> Result<Launch> {
    let mut buf = String::new();
    loop {
        if stream.read_line(&mut buf).await? == 0 {
            return Err(anyhow!("unexpected EOF"));
        }
        if buf.contains("EOM") {
            let launch: Launch = serde_json::from_str(&buf[..buf.len() - 5])?;
            return Ok(launch);
        }
    }
}

async fn handle_connection(mut stream: BufStream<TcpStream>) -> Result<(PathBuf, Child)> {
    let mut envs: HashMap<String, String> = env::vars().collect();

    let Launch {
        command,
        command_args,
        env,
    } = read_request(&mut stream).await?;
    debug!(command:?, command_args:?, env:?; "received launch request");
    envs.extend(env);

    let (stdout, stderr) = make_stdout_stderr(&command, &envs)?;

    let res = Command::new(&command)
        .args(command_args)
        .envs(envs)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .with_context(|| format!("Failed to execute {command:?} as child process"));
    if let Err(err) = &res {
        let msg = format!("{err:?}");
        stream.write_all(msg.as_bytes()).await.ok();
    } else {
        stream.write_all(b"OK").await.ok();
    }
    stream.flush().await.ok();

    res.map(|child| (command, child))
}
