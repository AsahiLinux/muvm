use std::{
    env, io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::utils::env::get_var_if_exists;

#[derive(Deserialize, Serialize, Default)]
pub struct Configuration {
    pub execute_pre: Option<PathBuf>,
}

fn get_user_config_path() -> Result<PathBuf> {
    let mut path = get_var_if_exists("XDG_CONFIG_DIR").map_or_else(
        || {
            let base = env::var("HOME").context("Failed to get HOME")?;
            let mut base = PathBuf::from(base);
            base.push(".config");
            Ok(base)
        },
        |p| p.map(PathBuf::from),
    )?;
    path.push("muvm");
    path.push("config.json");
    Ok(path)
}

fn get_global_config_path() -> Result<PathBuf> {
    Ok(PathBuf::from("/etc/muvm/config.json"))
}

fn get_system_config_path() -> Result<PathBuf> {
    Ok(PathBuf::from("/usr/lib/muvm/config.json"))
}

const CONFIG_PATHS: &[fn() -> Result<PathBuf>] = &[
    get_user_config_path,
    get_global_config_path,
    get_system_config_path,
];

fn read_to_string_if_exists(p: &Path) -> Option<Result<String>> {
    match std::fs::read_to_string(p) {
        Ok(content) => Some(Ok(content)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => None,
        Err(e) => Some(Err(e.into())),
    }
}

impl Configuration {
    pub fn parse_config_file() -> Result<Self> {
        let Some(content) = CONFIG_PATHS.iter().find_map(|get_config_path| {
            let config_path = match get_config_path() {
                Ok(path) => path,
                Err(e) => return Some(Err(e)),
            };
            read_to_string_if_exists(&config_path)
        }) else {
            return Ok(Default::default());
        };
        Ok(serde_json::from_str(&content?)?)
    }
}
