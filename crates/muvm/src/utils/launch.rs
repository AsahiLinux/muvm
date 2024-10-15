use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Launch {
    pub cookie: Uuid,
    pub command: PathBuf,
    pub command_args: Vec<String>,
    pub env: HashMap<String, String>,
}
