use std::fs::File;
use std::io::Write;

use anyhow::{Context, Result};

use crate::utils::env::find_in_path;

const FEX_X86_BINFMT_MISC_RULE: &str = ":FEX-x86:M:0:\\x7fELF\\x01\\x01\\x01\\x00\\x00\\x00\\x00\\\
                                        x00\\x00\\x00\\x00\\x00\\x02\\x00\\x03\\x00:\\xff\\xff\\\
                                        xff\\xff\\xff\\xfe\\xfe\\x00\\x00\\x00\\x00\\xff\\xff\\\
                                        xff\\xff\\xff\\xfe\\xff\\xff\\xff:${FEX_INTERPRETER}:POCF";
const FEX_X86_64_BINFMT_MISC_RULE: &str =
    ":FEX-x86_64:M:0:\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\\
     x00\\x3e\\x00:\\xff\\xff\\xff\\xff\\xff\\xfe\\xfe\\x00\\x00\\x00\\x00\\xff\\xff\\xff\\xff\\\
     xff\\xfe\\xff\\xff\\xff:${FEX_INTERPRETER}:POCF";

pub fn setup_fex() -> Result<()> {
    let fex_interpreter_path =
        find_in_path("FEXInterpreter").context("Failed to check existence of `FEXInterpreter`")?;
    let Some(fex_interpreter_path) = fex_interpreter_path else {
        return Ok(());
    };
    let fex_interpreter_path = fex_interpreter_path
        .to_str()
        .context("Failed to process `FEXInterpreter` path as it contains invalid UTF-8")?;

    let mut file = File::options()
        .write(true)
        .open("/proc/sys/fs/binfmt_misc/register")
        .context("Failed to open binfmt_misc/register for writing")?;

    {
        let rule = FEX_X86_BINFMT_MISC_RULE.replace("${FEX_INTERPRETER}", fex_interpreter_path);
        file.write_all(rule.as_bytes())
            .context("Failed to register `FEX-x86` binfmt_misc rule")?;
    }
    {
        let rule = FEX_X86_64_BINFMT_MISC_RULE.replace("${FEX_INTERPRETER}", fex_interpreter_path);
        file.write_all(rule.as_bytes())
            .context("Failed to register `FEX-x86_64` binfmt_misc rule")?;
    }

    Ok(())
}
