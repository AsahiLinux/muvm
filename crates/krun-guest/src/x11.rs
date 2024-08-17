use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use crate::socket::setup_socket_proxy;

pub fn setup_x11_forwarding<P>(run_path: P) -> Result<()>
where
    P: AsRef<Path>,
{
    // Set by krun if DISPLAY was provided from the host.
    let host_display = match env::var("HOST_DISPLAY") {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };

    if !host_display.starts_with(":") {
        return Err(anyhow!("Invalid host DISPLAY"));
    }
    let host_display = &host_display[1..];

    setup_socket_proxy(Path::new("/tmp/.X11-unix/X1"), 6000)?;

    // Set HOST_DISPLAY to :1, which is the display number within the guest
    // at which the actual host display is accessible.
    // SAFETY: Safe if and only if `krun-guest` program is not multithreaded.
    // See https://doc.rust-lang.org/std/env/fn.set_var.html#safety
    env::set_var("HOST_DISPLAY", ":1");

    if let Ok(xauthority) = std::env::var("XAUTHORITY") {
        let src_path = format!("/run/krun-host/{}", xauthority);
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
            if display != host_display.as_bytes() {
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

        // SAFETY: Safe if and only if `krun-guest` program is not multithreaded.
        // See https://doc.rust-lang.org/std/env/fn.set_var.html#safety
        env::set_var("XAUTHORITY", dst_path);
    }

    Ok(())
}
