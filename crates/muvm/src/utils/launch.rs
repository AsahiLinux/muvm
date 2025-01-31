use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Launch {
    pub cookie: Uuid,
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
    pub server_port: u32,
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub host_display: Option<String>,
    pub server_cookie: Uuid,
    pub merged_rootfs: bool,
}
