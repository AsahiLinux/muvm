use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rustix::fs::{flock, FlockOperation};

use crate::env::prepare_env_vars;
use crate::tty::{run_io_host, RawTerminal};
use crate::utils::launch::Launch;
use nix::unistd::unlink;
use std::ops::Range;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;

pub const DYNAMIC_PORT_RANGE: Range<u32> = 50000..50200;

pub enum LaunchResult {
    LaunchRequested(ExitCode),
    LockAcquired {
        lock_file: File,
        command: PathBuf,
        command_args: Vec<String>,
        env: Vec<(String, Option<String>)>,
    },
}

#[derive(Debug)]
enum LaunchError {
    Connection(std::io::Error),
    Json(serde_json::Error),
    Server(String),
}

impl Error for LaunchError {}

impl Display for LaunchError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match *self {
            Self::Connection(ref err) => {
                write!(f, "could not connect to muvm server: {err}")
            },
            Self::Json(ref err) => {
                write!(f, "could not serialize into JSON: {err}")
            },
            Self::Server(ref err) => {
                write!(f, "muvm server returned an error: {err}")
            },
        }
    }
}

fn acquire_socket_lock() -> Result<(File, u32)> {
    let run_path = env::var("XDG_RUNTIME_DIR")
        .map_err(|e| anyhow!("unable to get XDG_RUNTIME_DIR: {:?}", e))?;
    let socket_dir = Path::new(&run_path).join("krun/socket");
    for port in DYNAMIC_PORT_RANGE {
        let path = socket_dir.join(format!("port-{port}.lock"));
        return Ok((
            if !path.exists() {
                let lock_file = File::create(path).context("Failed to create socket lock")?;
                flock(&lock_file, FlockOperation::NonBlockingLockExclusive)
                    .context("Failed to acquire socket lock")?;
                lock_file
            } else {
                let lock_file = File::options()
                    .write(true)
                    .read(true)
                    .open(path)
                    .context("Failed to open lock file")?;
                if flock(&lock_file, FlockOperation::NonBlockingLockExclusive).is_err() {
                    continue;
                }
                lock_file
            },
            port,
        ));
    }
    Err(anyhow!("Ran out of ports."))
}

fn wrapped_launch(
    command: PathBuf,
    command_args: Vec<String>,
    env: HashMap<String, String>,
    tty: bool,
    privileged: bool,
) -> Result<ExitCode> {
    let run_path = env::var("XDG_RUNTIME_DIR")
        .map_err(|e| anyhow!("unable to get XDG_RUNTIME_DIR: {:?}", e))?;
    let socket_dir = Path::new(&run_path).join("krun/socket");
    let (_lock, vsock_port) = acquire_socket_lock()?;
    let path = socket_dir.join(format!("port-{vsock_port}"));
    _ = unlink(&path);
    let listener = UnixListener::bind(path).context("Failed to listen on vm socket")?;
    let raw_tty = if tty {
        Some(
            RawTerminal::set()
                .context("Asked to allocate a tty for the command, but stdin is not a tty")?,
        )
    } else {
        None
    };
    request_launch(command, command_args, env, vsock_port, tty, privileged)?;
    let code = run_io_host(listener, tty)?;
    drop(raw_tty);
    Ok(ExitCode::from(code))
}

pub fn launch_or_lock(
    command: PathBuf,
    command_args: Vec<String>,
    env: Vec<(String, Option<String>)>,
    tty: bool,
    privileged: bool,
) -> Result<LaunchResult> {
    let lock_file = lock_file()?;
    match lock_file {
        Some(lock_file) => Ok(LaunchResult::LockAcquired {
            lock_file,
            command,
            command_args,
            env,
        }),
        None => {
            let env = prepare_env_vars(env)?;
            let mut tries = 0;
            loop {
                match wrapped_launch(
                    command.clone(),
                    command_args.clone(),
                    env.clone(),
                    tty,
                    privileged,
                ) {
                    Err(err) => match err.downcast_ref::<LaunchError>() {
                        Some(&LaunchError::Connection(_)) => {
                            if tries == 3 {
                                return Err(anyhow!("could not request launch to server: {err}"));
                            } else {
                                tries += 1;
                            }
                        },
                        _ => {
                            return Err(anyhow!("could not request launch to server: {err}"));
                        },
                    },
                    Ok(code) => return Ok(LaunchResult::LaunchRequested(code)),
                }
            }
        },
    }
}

fn lock_file() -> Result<Option<File>> {
    let run_path = env::var("XDG_RUNTIME_DIR")
        .context("Failed to read XDG_RUNTIME_DIR environment variable")?;
    let lock_path = Path::new(&run_path).join("muvm.lock");

    let lock_file = if !lock_path.exists() {
        let lock_file = File::create(lock_path).context("Failed to create lock file")?;
        flock(&lock_file, FlockOperation::NonBlockingLockExclusive)
            .context("Failed to acquire exclusive lock on new lock file")?;
        lock_file
    } else {
        let lock_file = File::options()
            .write(true)
            .read(true)
            .open(lock_path)
            .context("Failed to create lock file")?;
        let ret = flock(&lock_file, FlockOperation::NonBlockingLockExclusive);
        if ret.is_err() {
            return Ok(None);
        }
        lock_file
    };
    Ok(Some(lock_file))
}

pub fn request_launch(
    command: PathBuf,
    command_args: Vec<String>,
    env: HashMap<String, String>,
    vsock_port: u32,
    tty: bool,
    privileged: bool,
) -> Result<()> {
    let run_path = env::var("XDG_RUNTIME_DIR")
        .map_err(|e| anyhow!("unable to get XDG_RUNTIME_DIR: {:?}", e))?;
    let socket_path = Path::new(&run_path).join("krun/server");
    let mut stream = UnixStream::connect(socket_path).map_err(LaunchError::Connection)?;

    let launch = Launch {
        command,
        command_args,
        env,
        vsock_port,
        tty,
        privileged,
    };

    stream
        .write_all(
            serde_json::to_string(&launch)
                .map_err(LaunchError::Json)?
                .as_bytes(),
        )
        .map_err(LaunchError::Connection)?;
    stream
        .write_all(b"\nEOM\n")
        .map_err(LaunchError::Connection)?;
    stream.flush().map_err(LaunchError::Connection)?;

    let mut buf_reader = BufReader::new(&mut stream);
    let mut resp = String::new();
    buf_reader
        .read_line(&mut resp)
        .map_err(LaunchError::Connection)?;

    if resp == "OK" {
        Ok(())
    } else {
        Err(LaunchError::Server(resp).into())
    }
}
