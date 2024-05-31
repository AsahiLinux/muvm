use std::{cmp::Ordering, fs, ops::Range};

use anyhow::{Context, Result};
use rustix::process::{sched_getaffinity, CpuSet};

pub fn get_performance_cores() -> Result<Vec<Range<u16>>> {
    let mut perf_max_freq = None;
    let mut perf_core_nums = vec![];
    let dir_iter = fs::read_dir("/sys/devices/system/cpu")
        .context("Failed to read directory `/sys/devices/system/cpu`")?;

    for entry in dir_iter {
        let entry = entry.context("Failed to read directory entry in `/sys/devices/system/cpu`")?;
        let file_name = entry
            .file_name()
            .into_string()
            .expect("file_name should not contain invalid UTF-8");
        let Some(core_num) = file_name
            .strip_prefix("cpu")
            .and_then(|suffix| suffix.parse::<u16>().ok())
        else {
            // e.g. `cpufreq`, `cpuidle`
            continue;
        };
        let path = entry.path().join("cpufreq/cpuinfo_max_freq");
        let max_freq = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {path:?}"))?
            .trim_end()
            .parse::<u32>()
            .expect("cpuinfo_max_freq should be u32");
        match max_freq.cmp(&perf_max_freq.unwrap_or(0)) {
            Ordering::Greater => {
                perf_core_nums.clear();
                perf_core_nums.push(core_num..(core_num + 1));
                perf_max_freq = Some(max_freq);
            },
            Ordering::Equal => {
                perf_core_nums.push(core_num..(core_num + 1));
            },
            Ordering::Less => {},
        }
    }

    Ok(perf_core_nums)
}

pub fn get_fallback_cores() -> Result<Vec<Range<u16>>> {
    let cpuset = sched_getaffinity(None).context("Failed to get CPU affinity")?;
    let cpu_count = cpuset.count();
    let mut cpu_list = vec![];
    let num_cpus = 0;

    for i in 0..(CpuSet::MAX_CPU as u16) {
        if num_cpus >= cpu_count {
            break;
        }
        if cpuset.is_set(i as usize) {
            cpu_list.push(i..(i + 1));
        }
    }

    Ok(cpu_list)
}
