use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct Launch {
    pub command: String,
    pub args: Vec<String>,
    pub envs: HashMap<String, String>,
}
