use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::{env, io, thread};

use anyhow::{anyhow, Context, Result};
use log::{debug, error};
use nix::errno::Errno;
use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags, EpollTimeout};
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, VsockAddr};
use nix::unistd::{pipe, setresgid, setresuid, setsid, Gid, Uid};
use rustix::process::ioctl_tiocsctty;
use rustix::pty::{ptsname, unlockpt};
use rustix::termios::{tcsetwinsize, Winsize};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufStream};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::task::{JoinError, JoinSet};
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::StreamExt as _;

use crate::guest::user;
use crate::utils::launch::Launch;
use crate::utils::stdio::make_stdout_stderr;
use crate::utils::tty::*;

pub enum ConnRequest {
    HandledByBuiltin,
    ExecuteCommand {
        command: PathBuf,
        child: Child,
        stop_pipe: Option<OwnedFd>,
    },
}

#[derive(Debug)]
pub struct Worker {
    listener_stream: UnixListenerStream,
    state_tx: watch::Sender<State>,
    child_set: JoinSet<(PathBuf, ChildResult, Option<OwnedFd>)>,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct State {
    connection_idle: bool,
    child_processes: usize,
}

type ChildResult = Result<ExitStatus, io::Error>;

impl Worker {
    pub fn new(listener: UnixListener, state_tx: watch::Sender<State>) -> Self {
        Worker {
            listener_stream: UnixListenerStream::new(listener),
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

                    match handle_connection(stream).await {
                        Ok(request) => match request {
                            ConnRequest::HandledByBuiltin => {},
                            ConnRequest::ExecuteCommand {command, mut child, stop_pipe } => {
                                self.child_set.spawn(async move { (command, child.wait().await, stop_pipe) });
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

    fn handle_child_join(&self, res: Result<(PathBuf, ChildResult, Option<OwnedFd>), JoinError>) {
        match res {
            Ok((command, res, stop_pipe)) => match res {
                Ok(status) => {
                    debug!(command:?; "child process exited");
                    if let Some(sp) = stop_pipe {
                        let code = status.code().unwrap_or_default() as u8;
                        _ = File::from(sp).write_all(&[code]);
                    }
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

async fn read_request(stream: &mut BufStream<UnixStream>) -> Result<Launch> {
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

async fn write_to(
    mut stream: BufStream<UnixStream>,
    path: &'static std::ffi::CStr,
    data: &[u8],
) -> Result<ConnRequest> {
    // SAFETY: `open` and `write` are async signal safe
    let code = unsafe {
        user::run_as_root(|| {
            let fd = nix::libc::open(path.as_ptr(), nix::libc::O_WRONLY);
            if fd < 0 {
                return 1;
            }
            let written = nix::libc::write(fd, data.as_ptr() as *const _, data.len()) as usize;
            if written == data.len() {
                0
            } else {
                2
            }
        })
        .with_context(|| format!("Failed to write to {path:?}"))?
    };
    match code {
        0 => {
            stream.write_all(b"OK").await.ok();
            stream.flush().await.ok();
            Ok(ConnRequest::HandledByBuiltin)
        },
        1 => Err(anyhow!("Failed to open {path:?} for writing")),
        2 => Err(anyhow!("Failed to write to {path:?}")),
        err => Err(anyhow!(
            "Unexpected return status when attempting to write to {path:?}: {err}"
        )),
    }
}

async fn handle_connection(mut stream: BufStream<UnixStream>) -> Result<ConnRequest> {
    let mut envs: HashMap<String, String> = env::vars().collect();

    let Launch {
        command,
        command_args,
        env,
        vsock_port,
        tty,
        privileged,
    } = read_request(&mut stream).await?;
    debug!(command:?, command_args:?, env:?; "received launch request");

    if command == Path::new("/muvmdropcaches") {
        return write_to(stream, c"/proc/sys/vm/drop_caches", b"1").await;
    } else if command == Path::new("/muvmwatermarkscalefactor") {
        let Some(data) = command_args.first() else {
            return Err(anyhow!("muvmwatermarkscalefactor: missing arg"));
        };
        return write_to(
            stream,
            c"/proc/sys/vm/watermark_scale_factor",
            data.as_bytes(),
        )
        .await;
    }

    envs.extend(env);

    let stdin;
    let stdout;
    let stderr;
    let mut tty_fd = None;
    if vsock_port == 0 {
        (stdout, stderr) = make_stdout_stderr(&command, &envs)?;
        stdin = Stdio::null();
    } else if !tty {
        stdin = Stdio::piped();
        stdout = Stdio::piped();
        stderr = Stdio::piped();
    } else {
        let tty_m = File::options()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NOCTTY)
            .open("/dev/ptmx")?;
        let tty_s_path = ptsname(&tty_m, Vec::new())?;
        unlockpt(&tty_m)?;
        let tty_s = File::options()
            .read(true)
            .write(true)
            .open(OsString::from_vec(tty_s_path.into_bytes()))?;
        stdin = Stdio::from(tty_s.try_clone()?);
        stdout = Stdio::from(tty_s.try_clone()?);
        stderr = Stdio::from(tty_s);
        tty_fd = Some(tty_m);
    }

    let mut cmd = Command::new(&command);
    cmd.args(command_args)
        .envs(envs)
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr);
    if tty {
        unsafe {
            cmd.pre_exec(|| {
                setsid()?;
                ioctl_tiocsctty(io::stdin())?;
                Ok(())
            });
        }
    }
    if privileged {
        unsafe {
            cmd.pre_exec(|| {
                setresuid(Uid::from(0), Uid::from(0), Uid::from(0))?;
                setresgid(Gid::from(0), Gid::from(0), Gid::from(0))?;
                Ok(())
            });
        }
    }
    let res = cmd
        .spawn()
        .with_context(|| format!("Failed to execute {command:?} as child process"));
    if let Err(err) = &res {
        let msg = format!("{err:?}");
        stream.write_all(msg.as_bytes()).await.ok();
    } else {
        stream.write_all(b"OK").await.ok();
    }
    stream.flush().await.ok();

    res.map(|mut child| {
        let stop_pipe;
        if vsock_port != 0 {
            let (stop_r, stop_w) = pipe().unwrap();
            stop_pipe = Some(stop_w);
            let stdin: OwnedFd;
            let stdout;
            let stderr;
            if tty {
                stdin = tty_fd.unwrap().into();
                stdout = stdin.try_clone().unwrap();
                stderr = None;
            } else {
                stdin = child.stdin.take().unwrap().into_owned_fd().unwrap();
                stdout = child.stdout.take().unwrap().into_owned_fd().unwrap();
                stderr = Some(child.stderr.take().unwrap().into_owned_fd().unwrap());
            }
            thread::spawn(move || {
                _ = run_io_guest(stdin, stdout, stderr, stop_r, vsock_port);
            });
        } else {
            stop_pipe = None;
        }
        ConnRequest::ExecuteCommand {
            command,
            child,
            stop_pipe,
        }
    })
}

fn run_io_guest(
    stdin: OwnedFd,
    stdout: OwnedFd,
    stderr: Option<OwnedFd>,
    stop_pipe: OwnedFd,
    vsock_port: u32,
) -> Result<()> {
    let mut stdin = Some(File::from(stdin));
    let mut stdout = File::from(stdout);
    let mut stderr = stderr.map(File::from);
    let mut stop_pipe = File::from(stop_pipe);
    let vsock_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;
    connect(
        vsock_fd.as_raw_fd(),
        &VsockAddr::new(nix::libc::VMADDR_CID_HOST, vsock_port),
    )?;
    let mut vsock = StdUnixStream::from(vsock_fd);
    let epoll = Epoll::new(EpollCreateFlags::empty())?;
    epoll.add(&stdout, EpollEvent::new(EpollFlags::EPOLLIN, 1))?;
    if let Some(ref stderr) = stderr {
        epoll.add(stderr, EpollEvent::new(EpollFlags::EPOLLIN, 2))?;
    }
    epoll.add(&vsock, EpollEvent::new(EpollFlags::EPOLLIN, 3))?;
    epoll.add(&stop_pipe, EpollEvent::new(EpollFlags::EPOLLIN, 4))?;
    loop {
        let mut evts = [EpollEvent::empty()];
        match epoll.wait(&mut evts, EpollTimeout::NONE) {
            Err(Errno::EINTR) | Ok(0) => {
                continue;
            },
            Ok(_) => {},
            e => {
                e?;
            },
        }
        if evts[0].events().contains(EpollFlags::EPOLLIN) {
            match evts[0].data() {
                1 | 2 => {
                    let mut buf = [0; 4096];
                    let len;
                    let opc;
                    if evts[0].data() == 1 {
                        len = stdout.read(&mut buf)?;
                        opc = CMD_WRITE_STDOUT;
                    } else {
                        len = stderr.as_mut().unwrap().read(&mut buf)?;
                        opc = CMD_WRITE_STDERR;
                    }
                    let cmd = ((len << CMD_SHIFT) as u16 | opc).to_le_bytes();
                    vsock.write_all(&cmd)?;
                    vsock.write_all(&buf[..len])?;
                },
                3 => {
                    let mut cmd = [0; 2];
                    vsock.read_exact(&mut cmd)?;
                    let cmd = u16::from_le_bytes(cmd);
                    let opc = cmd & CMD_MASK;
                    if opc == CMD_WRITE_STDIN {
                        let len = cmd as usize >> CMD_SHIFT;
                        if len == 0 {
                            stdin = None;
                        } else {
                            let mut buf = vec![0; len];
                            vsock.read_exact(&mut buf)?;
                            stdin.as_mut().unwrap().write_all(&buf)?;
                        }
                    } else if opc == CMD_UPDATE_SIZE {
                        let mut data = [0; 4];
                        vsock.read_exact(&mut data)?;
                        if let Some(stdin) = stdin.as_ref() {
                            tcsetwinsize(
                                stdin,
                                Winsize {
                                    ws_col: u16::from_le_bytes(data[..2].try_into().unwrap()),
                                    ws_row: u16::from_le_bytes(data[2..].try_into().unwrap()),
                                    ws_xpixel: 0,
                                    ws_ypixel: 0,
                                },
                            )?;
                        }
                    } else {
                        unreachable!();
                    }
                },
                4 => {
                    let mut code = [0];
                    stop_pipe.read_exact(&mut code)?;
                    let cmd = ((code[0] as u16) << CMD_SHIFT) | CMD_EXIT;
                    vsock.write_all(&cmd.to_le_bytes())?;
                    break Ok(());
                },
                _ => unreachable!(),
            }
        }
        if evts[0]
            .events()
            .intersects(EpollFlags::EPOLLERR | EpollFlags::EPOLLHUP)
        {
            match evts[0].data() {
                1 => epoll.delete(&stdout)?,
                2 => epoll.delete(stderr.as_ref().unwrap())?,
                3 | 4 => break Ok(()),
                _ => unreachable!(),
            }
        }
    }
}
