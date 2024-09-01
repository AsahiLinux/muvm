use bpaf::{construct, env, OptionParser, Parser};

#[derive(Clone, Debug)]
pub struct Options {
    pub server_port: u32,
}

pub fn options() -> OptionParser<Options> {
    let server_port = env("KRUN_SERVER_PORT")
        .short('p')
        .help("TCP port to listen for command launch requests")
        .argument("SERVER_PORT")
        .fallback(3334)
        .display_fallback();

    construct!(Options { server_port }).to_options()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_options() {
        options().check_invariants(false)
    }
}
