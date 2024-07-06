use std::ops::Range;
use std::path::PathBuf;

use anyhow::{anyhow, Context};
use bpaf::{any, construct, long, positional, OptionParser, Parser};

use crate::types::MiB;

#[derive(Clone, Debug)]
pub struct Options {
    pub cpu_list: Vec<Range<u16>>,
    pub env: Vec<(String, Option<String>)>,
    pub mem: Option<MiB>,
    pub passt_socket: Option<PathBuf>,
    pub server_port: u32,
    pub interactive: bool,
    pub command: PathBuf,
    pub command_args: Vec<String>,
}

pub fn options() -> OptionParser<Options> {
    let cpu_list = long("cpu-list")
        .short('c')
        .help(
            "The numerical list of processors that this microVM will be bound to.
            Numbers are separated by commas and may include ranges. For
            example: 0,5,8-11.
    [default: all logical CPUs on the host, limited to performance cores
        (if applicable)]",
        )
        .argument::<String>("CPU_LIST")
        .parse(|s| {
            s.split(',')
                .map(|s| s.split_once('-').unwrap_or((s, s)))
                .map(|(start, end)| {
                    let start = start.parse::<u16>().context("Failed to parse start")?;
                    let end = end.parse::<u16>().context("Failed to parse end")?;
                    Ok::<_, anyhow::Error>(start..(end + 1))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .many()
        .map(|nested| nested.into_iter().flatten().collect());
    let env = long("env")
        .short('e')
        .help(
            "Set environment variable to be passed to the microVM
            ENV should be in KEY=VALUE format, or KEY on its own to inherit
            the current value from the local environment",
        )
        .argument::<String>("ENV")
        .parse(|s| match s.split_once('=') {
            Some(("", _)) => Err(anyhow!("invalid ENV format")),
            Some((k, v)) => Ok((k.to_owned(), Some(v.to_owned()))),
            None => Ok((s, None)),
        })
        .many();
    let mem = long("mem")
        .help(
            "The amount of RAM, in MiB, that will be available to this microVM.
            The memory configured for the microVM will not be reserved
            immediately. Instead, it will be provided as the guest demands
            it, and both the guest and libkrun (acting as the Virtual
            Machine Monitor) will attempt to return as many pages as
            possible to the host.
    [default: 80% of total RAM]",
        )
        .argument("MEM")
        .guard(
            |&mem| mem <= MiB::from(16384),
            "the maximum amount of RAM supported is 16384 MiB",
        )
        .optional();
    let passt_socket = long("passt-socket")
        .help("Instead of starting passt, connect to passt socket at PATH")
        .argument("PATH")
        .optional();
    let server_port = long("server-port")
        .short('p')
        .help("Set the port to be used in server mode")
        .argument("SERVER_PORT")
        .fallback(3334)
        .display_fallback();
    let interactive = long("interactive")
        .short('i')
        .help("Allocate a tty guest-side and connect it to the current stdin/out")
        .switch();
    let command = positional("COMMAND").help("the command you want to execute in the vm");
    let command_args = any::<String, _, _>("COMMAND_ARGS", |arg| {
        (!["--help", "-h"].contains(&&*arg)).then_some(arg)
    })
    .help("arguments of COMMAND")
    .many();

    construct!(Options {
        cpu_list,
        env,
        mem,
        passt_socket,
        server_port,
        interactive,
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
