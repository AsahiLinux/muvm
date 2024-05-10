use std::path::PathBuf;

use anyhow::anyhow;
use bpaf::{any, construct, long, positional, OptionParser, Parser};

use crate::net::NetMode;

#[derive(Clone, Debug)]
pub struct Options {
    pub env: Vec<(String, Option<String>)>,
    pub net: NetMode,
    pub passt_socket: Option<PathBuf>,
    pub command: String,
    pub command_args: Vec<String>,
}

pub fn options() -> OptionParser<Options> {
    let env = long("env")
        .short('e')
        .help(
            "Set environment variable to be passed to the microVM
            ENV should be in KEY=VALUE format, or KEY on its own to inherit the
            current value from the local environment",
        )
        .argument::<String>("ENV")
        .parse(|s| match s.split_once('=') {
            Some(("", _)) => Err(anyhow!("invalid ENV format")),
            Some((k, v)) => Ok((k.to_owned(), Some(v.to_owned()))),
            None => Ok((s, None)),
        })
        .many();
    let net = long("net")
        .help(
            "Set network mode
            NET_MODE can be either PASST (default) or TSI",
        )
        .argument::<String>("NET_MODE")
        .fallback("PASST".to_owned())
        .display_fallback()
        .parse(|s| match &*s.to_ascii_uppercase() {
            "PASST" => Ok(NetMode::PASST),
            "TSI" => Ok(NetMode::TSI),
            _ => Err(anyhow!("invalid NET_MODE value")),
        });
    let passt_socket = long("passt-socket")
        .help("Instead of starting passt, connect to passt socket at PATH")
        .argument("PATH")
        .optional();
    let command = positional("COMMAND").help("the command you want to execute in the vm");
    let command_args = any::<String, _, _>("COMMAND_ARGS", |arg| {
        (!["--help", "-h"].contains(&&*arg)).then_some(arg)
    })
    .help("arguments of COMMAND")
    .many();

    construct!(Options {
        env,
        net,
        passt_socket,
        // positionals
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
