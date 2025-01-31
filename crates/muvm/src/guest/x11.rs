use std::fs::File;
use std::io::{Read, Write};
use std::panic::catch_unwind;
use std::path::Path;
use std::{env, thread};

use anyhow::{anyhow, Context, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::guest::x11bridge::start_x11bridge;

pub fn setup_x11_forwarding<P>(run_path: P, host_display: &str) -> Result<()>
where
    P: AsRef<Path>,
{
    if !host_display.starts_with(':') {
        return Err(anyhow!("Invalid host DISPLAY"));
    }
    let host_display = &host_display[1..];

    // SAFETY: Safe if and only if `muvm-guest` program is not multithreaded.
    // See https://doc.rust-lang.org/std/env/fn.set_var.html#safety
    env::set_var("DISPLAY", ":1");
    env::set_var("XSHMFENCE_NO_MEMFD", "1");

    if let Ok(xauthority) = std::env::var("XAUTHORITY") {
        let src_path = format!("/run/muvm-host/{xauthority}");
        let mut rdr = File::open(src_path)?;

        let dst_path = run_path.as_ref().join("xauth");
        let mut wtr = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&dst_path)
            .context("Failed to create `xauth`")?;

        while let Ok(family) = rdr.read_u16::<BigEndian>() {
            let mut addr = vec![0u8; rdr.read_u16::<BigEndian>()? as usize];
            rdr.read_exact(&mut addr)?;

            let mut display = vec![0u8; rdr.read_u16::<BigEndian>()? as usize];
            rdr.read_exact(&mut display)?;

            let mut name = vec![0u8; rdr.read_u16::<BigEndian>()? as usize];
            rdr.read_exact(&mut name)?;

            let mut data = vec![0u8; rdr.read_u16::<BigEndian>()? as usize];
            rdr.read_exact(&mut data)?;

            // Only copy the wildcard entry
            if family != 0xffff {
                continue;
            }

            // Check for the correct host display
            if !display.is_empty() && display != host_display.as_bytes() {
                continue;
            }

            // Always use display number 1
            let display = b"1";

            wtr.write_u16::<BigEndian>(family)?;
            wtr.write_u16::<BigEndian>(addr.len().try_into()?)?;
            wtr.write_all(&addr)?;
            wtr.write_u16::<BigEndian>(display.len().try_into()?)?;
            wtr.write_all(display)?;
            wtr.write_u16::<BigEndian>(name.len().try_into()?)?;
            wtr.write_all(&name)?;
            wtr.write_u16::<BigEndian>(data.len().try_into()?)?;
            wtr.write_all(&data)?;

            break;
        }

        // SAFETY: Safe if and only if `muvm-guest` program is not multithreaded.
        // See https://doc.rust-lang.org/std/env/fn.set_var.html#safety
        env::set_var("XAUTHORITY", dst_path);
    }
    thread::spawn(|| {
        if catch_unwind(|| start_x11bridge(1)).is_err() {
            eprintln!("x11bridge thread crashed, x11 passthrough will no longer function");
        }
    });

    Ok(())
}
