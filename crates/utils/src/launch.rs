use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Launch {
    pub command: PathBuf,
    pub command_args: Vec<String>,
    pub env: HashMap<String, String>,
    pub cwd: PathBuf,
}
