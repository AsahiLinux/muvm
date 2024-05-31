use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::Path,
};

use anyhow::{anyhow, Context, Result};
use rustix::{
    fs::{flock, FlockOperation},
    path::Arg,
};
use serde_json;
use utils::launch::Launch;

use crate::cli_options::Options;

pub enum LockResult {
    LaunchRequested,
    LockAcquired(File),
}

pub fn lock_or_connect(options: &Options) -> Result<LockResult> {
    let running_server_port = env::var("KRUN_SERVER_PORT").ok();
    if let Some(port) = running_server_port {
        let port: u32 = port.parse()?;
        request_launch(port, &options.command, &options.command_args, &options.env)?;
        return Ok(LockResult::LaunchRequested);
    }

    let (lock_file, running_server_port) = lock_file(options.server_port)?;
    match lock_file {
        Some(lock_file) => Ok(LockResult::LockAcquired(lock_file)),
        None => {
            if let Some(port) = running_server_port {
                let mut tries = 0;
                while let Err(e) =
                    request_launch(port, &options.command, &options.command_args, &options.env)
                {
                    if tries == 3 {
                        return Err(e);
                    } else {
                        tries += 1;
                    }
                }
                Ok(LockResult::LaunchRequested)
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
        let lock_file = File::create(lock_path).context("Can't create lock file")?;
        flock(&lock_file, FlockOperation::NonBlockingLockExclusive)
            .context("Can't acquire an exclusive lock on new lock file")?;
        lock_file
    } else {
        let mut lock_file = File::options()
            .write(true)
            .read(true)
            .open(lock_path)
            .context("Can't create lock file")?;
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
    lock_file.write_all(format!("{}", server_port).as_bytes())?;
    Ok((Some(lock_file), None))
}

fn request_launch(
    port: u32,
    command: &String,
    args: &[String],
    envs: &Vec<(String, Option<String>)>,
) -> Result<()> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))?;

    let mut envs_map: HashMap<String, String> = HashMap::new();
    for (k, v) in envs {
        if let Some(v) = v {
            envs_map.insert(k.to_string(), v.to_string());
        }
    }

    let launch = Launch {
        command: command.to_string(),
        args: args.to_vec(),
        envs: envs_map,
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
        Err(anyhow!("Error requesting launch to server: {resp}"))
    }
}
