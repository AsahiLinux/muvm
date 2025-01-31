use std::fs::File;
use std::io::Write;

use anyhow::{anyhow, Context, Result};

use crate::utils::env::find_in_path;

const BOX32_BINFMT_MISC_RULE: &str = ":BOX32:M:0:\\x7fELF\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\\
                                        x00\\x00\\x00\\x00\\x00\\x02\\x00\\x03\\x00:\\xff\\xff\\\
                                        xff\\xff\\xff\\xfe\\xfe\\x00\\x00\\x00\\x00\\xff\\xff\\\
                                        xff\\xff\\xff\\xfe\\xff\\xff\\xff:${BOX64}:POCF";
const BOX64_BINFMT_MISC_RULE: &str =
    ":BOX64:M:0:\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\\
     x00\\x3e\\x00:\\xff\\xff\\xff\\xff\\xff\\xfe\\xfe\\x00\\x00\\x00\\x00\\xff\\xff\\xff\\xff\\\
     xff\\xfe\\xff\\xff\\xff:${BOX64}:POCF";

pub fn setup_box() -> Result<()> {
    let box64_path = find_in_path("box64").context("Failed to check existence of `box64`")?;
    let Some(box64_path) = box64_path else {
        return Err(anyhow!("Failed to find `box64` in PATH"));
    };
    let box64_path = box64_path
        .to_str()
        .context("Failed to process `box64` path as it contains invalid UTF-8")?;

    let mut file = File::options()
        .write(true)
        .open("/proc/sys/fs/binfmt_misc/register")
        .context("Failed to open binfmt_misc/register for writing")?;

    {
        let rule = BOX32_BINFMT_MISC_RULE.replace("${BOX64}", box64_path);
        file.write_all(rule.as_bytes())
            .context("Failed to register `Box32` binfmt_misc rule")?;
    }
    {
        let rule = BOX64_BINFMT_MISC_RULE.replace("${BOX64}", box64_path);
        file.write_all(rule.as_bytes())
            .context("Failed to register `Box64` binfmt_misc rule")?;
    }

    Ok(())
}
