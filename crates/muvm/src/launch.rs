use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rustix::fs::{flock, FlockOperation};
use uuid::Uuid;

use crate::env::prepare_env_vars;
use crate::utils::launch::Launch;

pub enum LaunchResult {
    LaunchRequested,
    LockAcquired {
        cookie: Uuid,
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

pub fn launch_or_lock(
    server_port: u32,
    command: PathBuf,
    command_args: Vec<String>,
    env: Vec<(String, Option<String>)>,
) -> Result<LaunchResult> {
    let running_server_port = env::var("MUVM_SERVER_PORT").ok();
    if let Some(port) = running_server_port {
        let port: u32 = port.parse()?;
        let env = prepare_env_vars(env)?;
        let cookie = read_cookie()?;
        if let Err(err) = request_launch(port, cookie, command, command_args, env) {
            return Err(anyhow!("could not request launch to server: {err}"));
        }
        return Ok(LaunchResult::LaunchRequested);
    }

    let (lock_file, cookie) = lock_file()?;
    match lock_file {
        Some(lock_file) => Ok(LaunchResult::LockAcquired {
            cookie,
            lock_file,
            command,
            command_args,
            env,
        }),
        None => {
            let env = prepare_env_vars(env)?;
            let mut tries = 0;
            loop {
                match request_launch(
                    server_port,
                    cookie,
                    command.clone(),
                    command_args.clone(),
                    env.clone(),
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
                    Ok(_) => return Ok(LaunchResult::LaunchRequested),
                }
            }
        },
    }
}

fn read_cookie() -> Result<Uuid> {
    let run_path = env::var("XDG_RUNTIME_DIR")
        .context("Failed to read XDG_RUNTIME_DIR environment variable")?;
    let lock_path = Path::new(&run_path).join("muvm.lock");
    let mut lock_file = File::options()
        .write(false)
        .read(true)
        .open(lock_path)
        .context("Failed to open lock file")?;

    let mut data: Vec<u8> = Vec::with_capacity(16);
    lock_file.read_to_end(&mut data)?;

    Uuid::from_slice(&data).context("Failed to read cookie from lock file")
}

fn lock_file() -> Result<(Option<File>, Uuid)> {
    let run_path = env::var("XDG_RUNTIME_DIR")
        .context("Failed to read XDG_RUNTIME_DIR environment variable")?;
    let lock_path = Path::new(&run_path).join("muvm.lock");

    let mut lock_file = if !lock_path.exists() {
        let lock_file = File::create(lock_path).context("Failed to create lock file")?;
        flock(&lock_file, FlockOperation::NonBlockingLockExclusive)
            .context("Failed to acquire exclusive lock on new lock file")?;
        lock_file
    } else {
        let mut lock_file = File::options()
            .write(true)
            .read(true)
            .open(lock_path)
            .context("Failed to create lock file")?;
        let ret = flock(&lock_file, FlockOperation::NonBlockingLockExclusive);
        if ret.is_err() {
            let mut data: Vec<u8> = Vec::with_capacity(16);
            lock_file.read_to_end(&mut data)?;
            let cookie = Uuid::from_slice(&data).context("Failed to read cookie from lock file")?;
            return Ok((None, cookie));
        }
        lock_file
    };

    let cookie = Uuid::now_v7();
    lock_file.set_len(0)?;
    lock_file.write_all(cookie.as_bytes())?;
    Ok((Some(lock_file), cookie))
}

pub fn request_launch(
    server_port: u32,
    cookie: Uuid,
    command: PathBuf,
    command_args: Vec<String>,
    env: HashMap<String, String>,
) -> Result<()> {
    let mut stream =
        TcpStream::connect(format!("127.0.0.1:{server_port}")).map_err(LaunchError::Connection)?;

    let launch = Launch {
        cookie,
        command,
        command_args,
        env,
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
