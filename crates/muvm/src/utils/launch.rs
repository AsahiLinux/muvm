use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

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
pub struct GuestConfiguration {
    pub command: Launch,
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub host_display: Option<String>,
    pub merged_rootfs: bool,
}

pub const PULSE_SOCKET: u32 = 3333;
pub const HIDPIPE_SOCKET: u32 = PULSE_SOCKET + 1;
pub const MUVM_GUEST_SOCKET: u32 = HIDPIPE_SOCKET + 1;
