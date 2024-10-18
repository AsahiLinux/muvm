use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::os::unix::process::ExitStatusExt as _;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::{env, io};

use anyhow::{anyhow, Context, Result};
use log::{debug, error};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::{JoinError, JoinSet};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt as _;
use uuid::Uuid;

use crate::utils::launch::Launch;
use crate::utils::stdio::make_stdout_stderr;

pub enum ConnRequest {
    DropCaches,
    ExecuteCommand { command: PathBuf, child: Child },
}

#[derive(Debug)]
pub struct Worker {
    cookie: Uuid,
    listener_stream: TcpListenerStream,
    state_tx: watch::Sender<State>,
    child_set: JoinSet<(PathBuf, ChildResult)>,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct State {
    connection_idle: bool,
    child_processes: usize,
}

type ChildResult = Result<ExitStatus, io::Error>;

impl Worker {
    pub fn new(cookie: Uuid, listener: TcpListener, state_tx: watch::Sender<State>) -> Self {
        Worker {
            cookie,
            listener_stream: TcpListenerStream::new(listener),
            state_tx,
            child_set: JoinSet::new(),
        }
    }

    pub async fn run(&mut self) {
        loop {
            tokio::select! {
                Some(stream) = self.listener_stream.next() => {
                    self.set_connection_idle(false);
                    let stream = match stream {
                        Ok(stream) => stream,
                        Err(err) => {
                            eprintln!("Failed to accept incoming connection: {err}");
                            self.set_connection_idle(true);
                            continue;
                        },
                    };
                    let stream = BufStream::new(stream);

                    match handle_connection(self.cookie, stream).await {
                        Ok(request) => match request {
                            ConnRequest::DropCaches => {},
                            ConnRequest::ExecuteCommand {command, mut child } => {
                                self.child_set.spawn(async move { (command, child.wait().await) });
                                self.set_child_processes(self.child_set.len());
                            }
                        },
                        Err(err) => {
                            eprintln!("Failed to process client request: {err:?}");
                        },
                    }
                    self.set_connection_idle(true);
                },
                Some(res) = self.child_set.join_next() => self.handle_child_join(res),
            }
        }
    }

    fn handle_child_join(&self, res: Result<(PathBuf, ChildResult), JoinError>) {
        match res {
            Ok((command, res)) => match res {
                Ok(status) => {
                    debug!(command:?; "child process exited");
                    if !status.success() {
                        if let Some(code) = status.code() {
                            eprintln!("{command:?} process exited with status code: {code}");
                        } else {
                            eprintln!(
                                "{command:?} process terminated by signal: {}",
                                status
                                    .signal()
                                    .expect("either one of status code or signal should be set")
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
        self.set_child_processes(self.child_set.len());
    }

    fn set_connection_idle(&self, connection_idle: bool) {
        self.state_tx.send_if_modified(|state| {
            if state.connection_idle == connection_idle {
                return false;
            }
            state.connection_idle = connection_idle;
            true
        });
    }

    fn set_child_processes(&self, child_processes: usize) {
        self.state_tx.send_if_modified(|state| {
            if state.child_processes == child_processes {
                return false;
            }
            state.child_processes = child_processes;
            true
        });
    }
}

impl State {
    pub fn new() -> Self {
        Self {
            connection_idle: true,
            child_processes: 0,
        }
    }

    pub fn connection_idle(&self) -> bool {
        self.connection_idle
    }

    pub fn child_processes(&self) -> usize {
        self.child_processes
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
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

async fn handle_connection(
    server_cookie: Uuid,
    mut stream: BufStream<TcpStream>,
) -> Result<ConnRequest> {
    let mut envs: HashMap<String, String> = env::vars().collect();

    let Launch {
        cookie,
        command,
        command_args,
        env,
    } = read_request(&mut stream).await?;
    debug!(command:?, command_args:?, env:?; "received launch request");
    if cookie != server_cookie {
        debug!("invalid cookie in launch request");
        let msg = "Invalid cookie";
        stream.write_all(msg.as_bytes()).await.ok();
        stream.flush().await.ok();
        return Err(anyhow!(msg));
    }

    if command.to_string_lossy().contains("/muvmdropcaches") {
        let mut file = File::options()
            .write(true)
            .open("/proc/sys/vm/drop_caches")
            .context("Failed to open /proc/sys/vm/drop_caches for writing")?;

        {
            file.write_all(b"1")
                .context("Failed to write to /proc/sys/vm/drop_caches")?;
        }
        stream.write_all(b"OK").await.ok();
        stream.flush().await.ok();
        return Ok(ConnRequest::DropCaches);
    }

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

    res.map(|child| ConnRequest::ExecuteCommand { command, child })
}
