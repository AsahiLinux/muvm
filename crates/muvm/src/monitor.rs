use std::collections::HashMap;
use std::path::PathBuf;
use std::thread;
use std::time;

use anyhow::Result;
use log::debug;
use procfs::{Current, Meminfo};
use uuid::Uuid;

use crate::launch::request_launch;

#[derive(Clone, Debug, PartialEq)]
pub enum GuestPressure {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl From<GuestPressure> for u32 {
    fn from(pressure: GuestPressure) -> u32 {
        match pressure {
            GuestPressure::None => 10,
            GuestPressure::Low => 1000,
            GuestPressure::Medium => 2000,
            GuestPressure::High => 3000,
            // Same waterlevel as High, but also explicitly requesting
            // the guest to drop its page cache.
            GuestPressure::Critical => 3000,
        }
    }
}

pub fn spawn_monitor(server_port: u32, cookie: Uuid) {
    thread::spawn(move || run(server_port, cookie));
}

fn set_guest_pressure(server_port: u32, cookie: Uuid, pressure: GuestPressure) -> Result<()> {
    if pressure == GuestPressure::Critical {
        debug!("requesting the guest to drop its caches");
        // This is a fake command that tells muvm-server to write to "/proc/sys/vm/drop_caches"
        let command = PathBuf::from("/muvmdropcaches");
        let command_args = vec![];
        let env = HashMap::new();
        request_launch(server_port, cookie, command, command_args, env)?;
    }

    let wsf: u32 = pressure.into();
    debug!("setting watermark_scale_factor to {wsf}");

    let command = PathBuf::from("/sbin/sysctl");
    let command_args = vec![format!("vm.watermark_scale_factor={}", wsf)];
    let env = HashMap::new();
    request_launch(server_port, cookie, command, command_args, env)
}

fn run(server_port: u32, cookie: Uuid) {
    let mut guest_pressure = GuestPressure::None;
    loop {
        let meminfo = Meminfo::current().ok();
        if let Some(meminfo) = meminfo {
            if let Some(available) = meminfo.mem_available {
                let avail_ratio = (available * 100) / meminfo.mem_total;
                debug!(
                    "avail_ratio={avail_ratio}, avail={available}, total={}",
                    meminfo.mem_total
                );
                let new_pressure = if avail_ratio <= 10 {
                    GuestPressure::Critical
                } else if avail_ratio <= 15 {
                    GuestPressure::High
                } else if avail_ratio <= 20 {
                    GuestPressure::Medium
                } else if avail_ratio <= 25 {
                    GuestPressure::Low
                } else {
                    GuestPressure::None
                };

                debug!("Pressure at {:?}", new_pressure);

                if new_pressure != guest_pressure {
                    if let Err(err) = set_guest_pressure(server_port, cookie, new_pressure.clone())
                    {
                        println!("Failed to set the new pressure in the guest: {err}");
                    } else {
                        guest_pressure = new_pressure;
                    }
                }
            }
        }
        thread::sleep(time::Duration::from_millis(500));
    }
}
