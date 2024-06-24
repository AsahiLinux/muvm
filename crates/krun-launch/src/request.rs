use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Request {
    pub command: PathBuf,
    pub command_args: Vec<String>,
    pub env: HashMap<String, String>,
}
