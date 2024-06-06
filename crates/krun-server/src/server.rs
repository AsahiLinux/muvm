use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use log::debug;
use utils::launch::Launch;

pub fn start_server(listener: TcpListener) -> JoinHandle<()> {
    thread::spawn(move || {
        if let Err(err) = work(listener) {
            debug!(err:?; "server thread is terminating")
        }
    })
}

fn work(listener: TcpListener) -> Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;

        if let Err(err) = handle_connection(stream) {
            println!("Error processing client request: {err:?}");
        }
    }

    Ok(())
}

fn read_request(mut stream: &TcpStream) -> Result<Launch> {
    let mut buf_reader = BufReader::new(&mut stream);
    let mut buf = String::new();
    loop {
        if buf_reader.read_line(&mut buf)? == 0 {
            return Err(anyhow!("unexpected EOF"));
        }
        if buf.contains("EOM") {
            let launch: Launch = serde_json::from_str(&buf[..buf.len() - 5])?;
            return Ok(launch);
        }
    }
}

fn make_stdout_stderr<P>(command: P, envs: &HashMap<String, String>) -> Result<(Stdio, Stdio)>
where
    P: AsRef<Path>,
{
    let command = command.as_ref();
    let filename = command
        .file_name()
        .context("Failed to obtain basename from command path")?;
    let filename = filename
        .to_str()
        .context("Failed to process command as it contains invalid UTF-8")?;
    let base = if envs.contains_key("XDG_RUNTIME_DIR") {
        Path::new(&envs["XDG_RUNTIME_DIR"])
    } else {
        Path::new("/tmp")
    };
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let path_stdout = base.join(format!("krun-{filename}-{ts}.stdout"));
    let path_stderr = base.join(format!("krun-{filename}-{ts}.stderr"));
    Ok((
        File::create_new(path_stdout)?.into(),
        File::create_new(path_stderr)?.into(),
    ))
}

fn handle_connection(mut stream: TcpStream) -> Result<()> {
    let mut envs: HashMap<String, String> = env::vars().collect();

    let Launch {
        command,
        command_args,
        env,
    } = read_request(&stream)?;
    envs.extend(env);

    let (stdout, stderr) = make_stdout_stderr(&command, &envs)?;

    let err = Command::new(&command)
        .args(command_args)
        .envs(envs)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn();
    if let Err(err) = err {
        let msg = format!("Failed to execute command {command:?}: {err}");
        stream.write_all(msg.as_bytes()).ok();
    } else {
        stream.write_all(b"OK").ok();
    }
    stream.flush().ok();

    Ok(())
}
