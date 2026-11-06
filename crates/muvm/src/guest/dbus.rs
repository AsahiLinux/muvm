use std::collections::VecDeque;
use std::fmt::Write as _;
use std::fs;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::net::{UnixListener as StdUnixListener, UnixStream as StdUnixStream};
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use log::debug;
use nix::libc::VMADDR_CID_HOST;
use nix::sys::socket::{connect, socket, AddressFamily, SockFlag, SockType, VsockAddr};
use nix::unistd::getuid;
use tokio::io::{copy_bidirectional, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};

#[derive(Default)]
struct SaslOutput {
    to_server: Vec<u8>,
    to_client: Vec<u8>,
}

#[derive(PartialEq, Eq)]
enum ClientState {
    Nul,
    Lines,
    Done,
}

#[derive(PartialEq, Eq)]
enum Reply {
    FromServer,
    LocalError,
}

// vsock cannot pass file descriptors. Reject NEGOTIATE_UNIX_FD locally,
// keeping replies ordered for clients that pipeline SASL commands.
// Each command gets one reply, except BEGIN.
struct SaslFilter {
    external_identity: Vec<u8>,
    authenticating_external: bool,
    client_state: ClientState,
    client_pending: Vec<u8>,
    server_pending: Vec<u8>,
    replies: VecDeque<Reply>,
}

impl SaslFilter {
    const MAX_LINE: usize = 16 * 1024;

    fn new(uid: u32) -> Self {
        let mut external_identity = String::new();
        for b in uid.to_string().bytes() {
            write!(external_identity, "{b:02X}").unwrap();
        }
        SaslFilter {
            external_identity: external_identity.into_bytes(),
            authenticating_external: false,
            client_state: ClientState::Nul,
            client_pending: Vec::new(),
            server_pending: Vec::new(),
            replies: VecDeque::new(),
        }
    }

    fn done(&self) -> bool {
        self.client_state == ClientState::Done && self.replies.is_empty()
    }

    fn drain_local_replies(&mut self, to_client: &mut Vec<u8>) {
        while self.replies.front() == Some(&Reply::LocalError) {
            self.replies.pop_front();
            to_client.extend_from_slice(b"ERROR\r\n");
        }
        if self.done() {
            // The last read may also contain D-Bus messages.
            to_client.append(&mut self.server_pending);
        }
    }

    fn feed_client(&mut self, mut input: &[u8]) -> Result<SaslOutput> {
        let mut out = SaslOutput::default();
        if self.client_state == ClientState::Nul {
            let Some((&first, rest)) = input.split_first() else {
                return Ok(out);
            };
            if first != 0 {
                return Err(anyhow!("D-Bus client did not start with a NUL byte"));
            }
            out.to_server.push(0);
            self.client_state = ClientState::Lines;
            input = rest;
        }
        if self.client_state == ClientState::Done {
            out.to_server.extend_from_slice(input);
            return Ok(out);
        }
        self.client_pending.extend_from_slice(input);
        while let Some(end) = find_crlf(&self.client_pending) {
            if end > Self::MAX_LINE {
                return Err(anyhow!("D-Bus SASL line too long"));
            }
            let rest = self.client_pending.split_off(end + 2);
            let line = std::mem::replace(&mut self.client_pending, rest);
            if !line[..end]
                .iter()
                .all(|&b| b.is_ascii_graphic() || b == b' ' || b == b'\t')
            {
                return Err(anyhow!("Invalid byte in D-Bus SASL line"));
            }
            match sasl_command(&line[..end]) {
                b"AUTH" => {
                    let response = external_auth_response(&line[..end]);
                    self.authenticating_external = response.is_some();
                    if response.is_some_and(|r| !r.is_empty()) {
                        // The host sees the VM owner's credentials, including
                        // for privileged guest apps.
                        out.to_server.extend_from_slice(b"AUTH EXTERNAL ");
                        out.to_server.extend_from_slice(&self.external_identity);
                        out.to_server.extend_from_slice(b"\r\n");
                    } else if response.is_some() {
                        // GDBus clients without an initial response expect a
                        // DATA challenge; preserve that exchange.
                        out.to_server.extend_from_slice(b"AUTH EXTERNAL\r\n");
                    } else {
                        out.to_server.extend_from_slice(&line);
                    }
                    self.replies.push_back(Reply::FromServer);
                },
                b"DATA"
                    if self.authenticating_external && sasl_response(&line[4..end]).is_some() =>
                {
                    out.to_server.extend_from_slice(b"DATA ");
                    out.to_server.extend_from_slice(&self.external_identity);
                    out.to_server.extend_from_slice(b"\r\n");
                    self.replies.push_back(Reply::FromServer);
                },
                b"NEGOTIATE_UNIX_FD" => self.replies.push_back(Reply::LocalError),
                b"BEGIN" => {
                    // Invalid BEGIN leaves the server in SASL mode.
                    if !line[b"BEGIN".len()..end]
                        .iter()
                        .all(|&b| b == b' ' || b == b'\t')
                    {
                        return Err(anyhow!("D-Bus SASL BEGIN has arguments"));
                    }
                    // dbus-broker does not accept tab separators.
                    out.to_server.extend_from_slice(b"BEGIN\r\n");
                    self.client_state = ClientState::Done;
                    out.to_server.append(&mut self.client_pending);
                    break;
                },
                _ => {
                    if sasl_command(&line[..end]) == b"CANCEL" {
                        self.authenticating_external = false;
                    }
                    out.to_server.extend_from_slice(&line);
                    self.replies.push_back(Reply::FromServer);
                },
            }
        }
        if self.client_pending.len() > Self::MAX_LINE {
            return Err(anyhow!("D-Bus SASL line too long"));
        }
        self.drain_local_replies(&mut out.to_client);
        Ok(out)
    }

    fn feed_server(&mut self, input: &[u8]) -> Result<Vec<u8>> {
        let mut to_client = Vec::new();
        if self.done() {
            to_client.extend_from_slice(input);
            return Ok(to_client);
        }
        self.server_pending.extend_from_slice(input);
        while !self.done() {
            let Some(end) = find_crlf(&self.server_pending) else {
                break;
            };
            if end > Self::MAX_LINE {
                return Err(anyhow!("D-Bus SASL line too long"));
            }
            let rest = self.server_pending.split_off(end + 2);
            let line = std::mem::replace(&mut self.server_pending, rest);
            if sasl_command(&line[..end]) == b"AGREE_UNIX_FD" {
                return Err(anyhow!("D-Bus server agreed to unix fd passing"));
            }
            to_client.extend_from_slice(&line);
            match self.replies.pop_front() {
                Some(Reply::FromServer) => {},
                Some(Reply::LocalError) => {
                    return Err(anyhow!("D-Bus SASL reply queue out of order"))
                },
                None => return Err(anyhow!("D-Bus server sent an unexpected SASL line")),
            }
            self.drain_local_replies(&mut to_client);
        }
        if self.server_pending.len() > Self::MAX_LINE {
            return Err(anyhow!("D-Bus SASL line too long"));
        }
        Ok(to_client)
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn sasl_command(line: &[u8]) -> &[u8] {
    // dbus-daemon also accepts tab separators.
    line.split(|&b| b == b' ' || b == b'\t')
        .next()
        .unwrap_or(line)
}

fn external_auth_response(line: &[u8]) -> Option<&[u8]> {
    let mut args = line
        .split(|&b| b == b' ' || b == b'\t')
        .filter(|arg| !arg.is_empty());
    if args.next() != Some(b"AUTH") || args.next() != Some(b"EXTERNAL") {
        return None;
    }
    let response = args.next().unwrap_or_default();
    if args.next().is_some() {
        return None;
    }
    sasl_response(response)
}

fn sasl_response(response: &[u8]) -> Option<&[u8]> {
    let response = response.trim_ascii();
    (response.len() % 2 == 0 && response.iter().all(u8::is_ascii_hexdigit)).then_some(response)
}

pub fn bind_dbus_socket(path: &Path) -> Result<StdUnixListener> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("D-Bus socket path {path:?} has no parent directory"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("Failed to create {dir:?}"))?;
    // /run is a guest tmpfs, so this cannot unlink the host socket.
    match fs::remove_file(path) {
        Ok(()) => {},
        Err(err) if err.kind() == ErrorKind::NotFound => {},
        Err(err) => return Err(err).with_context(|| format!("Failed to remove stale {path:?}")),
    }
    let listener =
        StdUnixListener::bind(path).with_context(|| format!("Failed to bind {path:?}"))?;
    listener
        .set_nonblocking(true)
        .context("Failed to set D-Bus listener nonblocking")?;
    Ok(listener)
}

fn connect_host(port: u32) -> Result<StdUnixStream> {
    let fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .context("Failed to create vsock socket")?;
    connect(fd.as_raw_fd(), &VsockAddr::new(VMADDR_CID_HOST, port))
        .context("Failed to connect to host D-Bus bus over vsock")?;
    let stream = StdUnixStream::from(fd);
    stream
        .set_nonblocking(true)
        .context("Failed to set vsock stream nonblocking")?;
    Ok(stream)
}

async fn proxy_connection(mut client: UnixStream, port: u32) -> Result<()> {
    let server = tokio::task::spawn_blocking(move || connect_host(port))
        .await
        .context("vsock connect task failed")??;
    let mut server = UnixStream::from_std(server)?;

    let mut filter = SaslFilter::new(getuid().as_raw());
    let mut client_buf = [0u8; 4096];
    let mut server_buf = [0u8; 4096];
    while !filter.done() {
        tokio::select! {
            n = client.read(&mut client_buf) => {
                let n = n?;
                if n == 0 {
                    return Ok(());
                }
                let out = filter.feed_client(&client_buf[..n])?;
                server.write_all(&out.to_server).await?;
                client.write_all(&out.to_client).await?;
            },
            n = server.read(&mut server_buf) => {
                let n = n?;
                if n == 0 {
                    return Ok(());
                }
                let to_client = filter.feed_server(&server_buf[..n])?;
                client.write_all(&to_client).await?;
            },
        }
    }
    copy_bidirectional(&mut client, &mut server).await?;
    Ok(())
}

pub async fn run_dbus_bridge(listener: StdUnixListener, port: u32) {
    let listener = match UnixListener::from_std(listener) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("D-Bus bridge: failed to register listener: {err}");
            return;
        },
    };
    loop {
        match listener.accept().await {
            Ok((client, _)) => {
                tokio::spawn(async move {
                    if let Err(err) = proxy_connection(client, port).await {
                        debug!(err:? = err; "D-Bus bridge connection closed");
                    }
                });
            },
            Err(err) => {
                eprintln!("D-Bus bridge: failed to accept incoming connection: {err}");
                // Back off on temporary errors such as EMFILE.
                tokio::time::sleep(Duration::from_secs(1)).await;
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipelined_fd_negotiation_is_rejected_in_reply_order() {
        let mut filter = SaslFilter::new(1000);
        let out = filter
            .feed_client(b"\0AUTH EXTERNAL 30\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\nmessage")
            .unwrap();
        assert_eq!(
            out.to_server,
            b"\0AUTH EXTERNAL 31303030\r\nBEGIN\r\nmessage"
        );
        assert!(out.to_client.is_empty());
        assert!(!filter.done());
        assert_eq!(
            filter.feed_server(b"OK guid\r\nreply").unwrap(),
            b"OK guid\r\nERROR\r\nreply"
        );
        assert!(filter.done());
    }

    #[test]
    fn external_auth_without_initial_response_preserves_challenge() {
        let mut filter = SaslFilter::new(1000);
        assert_eq!(
            filter
                .feed_client(b"\0AUTH EXTERNAL\r\n")
                .unwrap()
                .to_server,
            b"\0AUTH EXTERNAL\r\n"
        );
        assert_eq!(filter.feed_server(b"DATA\r\n").unwrap(), b"DATA\r\n");
        assert_eq!(
            filter.feed_client(b"DATA 30\r\n").unwrap().to_server,
            b"DATA 31303030\r\n"
        );
        assert_eq!(filter.feed_server(b"OK guid\r\n").unwrap(), b"OK guid\r\n");
        assert_eq!(
            filter
                .feed_client(b"NEGOTIATE_UNIX_FD\r\n")
                .unwrap()
                .to_client,
            b"ERROR\r\n"
        );
        assert_eq!(
            filter.feed_client(b"BEGIN\r\n").unwrap().to_server,
            b"BEGIN\r\n"
        );
        assert!(filter.done());
    }

    #[test]
    fn fragmented_authentication_and_binary_messages_are_preserved() {
        let mut filter = SaslFilter::new(1000);
        assert_eq!(filter.feed_client(b"\0AU").unwrap().to_server, b"\0");
        assert_eq!(
            filter
                .feed_client(b"TH EXTERNAL 31303030\r\n")
                .unwrap()
                .to_server,
            b"AUTH EXTERNAL 31303030\r\n"
        );
        assert!(filter.feed_server(b"OK guid\r").unwrap().is_empty());
        assert_eq!(filter.feed_server(b"\n").unwrap(), b"OK guid\r\n");
        assert_eq!(
            filter.feed_client(b"BEGIN\r\n\0\xff").unwrap().to_server,
            b"BEGIN\r\n\0\xff"
        );
        assert_eq!(filter.feed_server(b"\0\xff").unwrap(), b"\0\xff");
    }

    #[test]
    fn malformed_and_unbounded_authentication_is_rejected() {
        assert!(SaslFilter::new(1000)
            .feed_client(b"AUTH EXTERNAL\r\n")
            .is_err());
        let mut filter = SaslFilter::new(1000);
        filter.feed_client(b"\0").unwrap();
        assert!(filter
            .feed_client(&vec![b'A'; SaslFilter::MAX_LINE + 1])
            .is_err());
    }
}
