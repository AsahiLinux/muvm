use std::{
    collections::HashMap,
    env,
    fs::File,
    io::{BufRead, BufReader, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::Command,
    thread::{self, JoinHandle},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Result};
use log::debug;
use utils::launch::Launch;

pub fn start_server(listener: TcpListener) -> JoinHandle<()> {
    thread::spawn(move || {
        if let Err(err) = work(listener) {
            debug!("krun server thread is terminating: {err:?}")
        }
    })
}

fn work(listener: TcpListener) -> Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;

        if let Err(e) = handle_connection(stream) {
            println!("Error processing client request: {e}");
        }
    }

    Ok(())
}

fn read_request(mut stream: &TcpStream) -> Result<Launch> {
    let mut buf_reader = BufReader::new(&mut stream);
    let mut buf = String::new();
    loop {
        if buf_reader.read_line(&mut buf)? == 0 {
            return Err(anyhow!("Unexpected EOF"));
        }
        if buf.contains("EOM") {
            let launch: Launch = serde_json::from_str(&buf[..buf.len() - 5])?;
            return Ok(launch);
        }
    }
}

fn handle_connection(mut stream: TcpStream) -> Result<()> {
    let mut envs: HashMap<String, String> = env::vars().collect();

    let launch = read_request(&stream)?;
    envs.extend(launch.envs);

    let (stdout, stderr) = {
        let base = if envs.contains_key("XDG_RUNTIME_DIR") {
            Path::new(&envs["XDG_RUNTIME_DIR"])
        } else {
            Path::new("/tmp")
        };
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
        let path_stdout = base.join(format!("krun-{}-{}.stdout", launch.command, ts));
        let path_stderr = base.join(format!("krun-{}-{}.stderr", launch.command, ts));
        (
            File::create_new(path_stdout)?,
            File::create_new(path_stderr)?,
        )
    };

    let err = Command::new(&launch.command)
        .args(launch.args)
        .envs(envs)
        .stdout(stdout)
        .stderr(stderr)
        .spawn();
    if let Err(err) = err {
        let error = format!("Error executing command {}: {}", launch.command, err);
        let _ = stream.write_all(error.as_bytes());
    } else {
        let _ = stream.write_all(b"OK");
    }
    let _ = stream.flush();

    Ok(())
}
