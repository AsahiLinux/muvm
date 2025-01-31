use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Launch {
    pub command: PathBuf,
    pub command_args: Vec<String>,
    pub env: HashMap<String, String>,
    pub vsock_port: u32,
    pub tty: bool,
    pub privileged: bool,
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum Emulator {
    Box,
    Fex,
}

impl FromStr for Emulator {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = s.to_lowercase();
        if v.starts_with("box") {
            Ok(Emulator::Box)
        } else if v.starts_with("fex") {
            Ok(Emulator::Fex)
        } else {
            Err(anyhow!("Invalid or unsupported emulator"))
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct GuestConfiguration {
    pub command: Launch,
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub host_display: Option<String>,
    pub merged_rootfs: bool,
    pub emulator: Option<Emulator>,
}

pub const PULSE_SOCKET: u32 = 3333;
pub const HIDPIPE_SOCKET: u32 = PULSE_SOCKET + 1;
pub const MUVM_GUEST_SOCKET: u32 = HIDPIPE_SOCKET + 1;
