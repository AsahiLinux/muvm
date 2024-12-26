use std::path::PathBuf;

use anyhow::Context;
use bpaf::{any, construct, env, positional, OptionParser, Parser};
use nix::libc::{gid_t, uid_t};
use nix::unistd::{Gid, Uid};

#[derive(Clone, Debug)]
pub struct Options {
    pub username: String,
    pub uid: Uid,
    pub gid: Gid,
    pub server_port: u32,
    pub command: PathBuf,
    pub command_args: Vec<String>,
}

pub fn options() -> OptionParser<Options> {
    let server_port = env("MUVM_SERVER_PORT")
        .short('p')
        .help("TCP port to listen for command launch requests")
        .argument("SERVER_PORT")
        .fallback(3334)
        .display_fallback();
    let username = positional("USER");
    let uid = positional::<String>("UID").parse(|s| {
        s.parse::<uid_t>()
            .context("Failed to parse UID")
            .map(|uid| uid.into())
    });
    let gid = positional::<String>("GID").parse(|s| {
        s.parse::<gid_t>()
            .context("Failed to parse GID")
            .map(|gid| gid.into())
    });
    let command = positional("COMMAND");
    let command_args = any::<String, _, _>("COMMAND_ARGS", |arg| {
        (!["--help", "-h"].contains(&&*arg)).then_some(arg)
    })
    .many();

    construct!(Options {
        server_port,
        // positionals
        username,
        uid,
        gid,
        command,
        command_args,
    })
    .to_options()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_options() {
        options().check_invariants(false)
    }
}
