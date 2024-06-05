use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use rustix::fs::{flock, FlockOperation};
use rustix::path::Arg;
use utils::launch::Launch;

use crate::env::prepare_env_vars;

pub enum LaunchResult {
    LaunchRequested,
    LockAcquired {
        lock_file: File,
        command: PathBuf,
        command_args: Vec<String>,
        env: Vec<(String, Option<String>)>,
    },
}

pub fn launch_or_lock(
    server_port: u32,
    command: PathBuf,
    command_args: Vec<String>,
    env: Vec<(String, Option<String>)>,
) -> Result<LaunchResult> {
    let running_server_port = env::var("KRUN_SERVER_PORT").ok();
    if let Some(port) = running_server_port {
        let port: u32 = port.parse()?;
        let env = prepare_env_vars(env)?;
        request_launch(port, command, command_args, env)?;
        return Ok(LaunchResult::LaunchRequested);
    }

    let (lock_file, running_server_port) = lock_file(server_port)?;
    match lock_file {
        Some(lock_file) => Ok(LaunchResult::LockAcquired {
            lock_file,
            command,
            command_args,
            env,
        }),
        None => {
            if let Some(port) = running_server_port {
                let env = prepare_env_vars(env)?;
                let mut tries = 0;
                while let Err(err) =
                    request_launch(port, command.clone(), command_args.clone(), env.clone())
                {
                    if tries == 3 {
                        return Err(err);
                    } else {
                        tries += 1;
                    }
                }
                Ok(LaunchResult::LaunchRequested)
            } else {
                Err(anyhow!(
                    "krun is already running but couldn't find its server port, bailing out"
                ))
            }
        },
    }
}

fn lock_file(server_port: u32) -> Result<(Option<File>, Option<u32>)> {
    let run_path = env::var("XDG_RUNTIME_DIR")
        .context("Failed to read XDG_RUNTIME_DIR environment variable")?;
    let lock_path = Path::new(&run_path).join("krun.lock");

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
            let mut data: Vec<u8> = Vec::with_capacity(5);
            lock_file.read_to_end(&mut data)?;
            let port = match data.to_string_lossy().parse::<u32>() {
                Ok(port) => {
                    if port > 1024 {
                        Some(port)
                    } else {
                        None
                    }
                },
                Err(_) => None,
            };
            return Ok((None, port));
        }
        lock_file
    };

    lock_file.set_len(0)?;
    lock_file.write_all(format!("{server_port}").as_bytes())?;
    Ok((Some(lock_file), None))
}

fn request_launch(
    server_port: u32,
    command: PathBuf,
    command_args: Vec<String>,
    env: HashMap<String, String>,
) -> Result<()> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{server_port}"))?;

    let launch = Launch {
        command,
        command_args,
        env,
    };

    stream.write_all(serde_json::to_string(&launch)?.as_bytes())?;
    stream.write_all(b"\nEOM\n")?;
    stream.flush()?;

    let mut buf_reader = BufReader::new(&mut stream);
    let mut resp = String::new();
    buf_reader.read_line(&mut resp)?;

    if resp == "OK" {
        Ok(())
    } else {
        Err(anyhow!("could not request launch to server: {resp}"))
    }
}
