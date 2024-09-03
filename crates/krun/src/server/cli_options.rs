use std::path::PathBuf;

use bpaf::{any, construct, env, positional, OptionParser, Parser};

#[derive(Clone, Debug)]
pub struct Options {
    pub server_port: u32,
    pub command: PathBuf,
    pub command_args: Vec<String>,
}

pub fn options() -> OptionParser<Options> {
    let server_port = env("KRUN_SERVER_PORT")
        .short('p')
        .help("TCP port to listen for command launch requests")
        .argument("SERVER_PORT")
        .fallback(3334)
        .display_fallback();
    let command = positional("COMMAND");
    let command_args = any::<String, _, _>("COMMAND_ARGS", |arg| {
        (!["--help", "-h"].contains(&&*arg)).then_some(arg)
    })
    .many();

    construct!(Options {
        server_port,
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
