//! NUMA-aware CPU pinning for tokio worker threads.
//! Reads Linux sysfs topology to discover physical cores (skipping SMT siblings),
//! then pins each worker thread to a distinct core with sched_setaffinity(2).

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Detect physical (non-SMT) CPU IDs from sysfs topology.
/// Returns empty vec on non-Linux or any read error (caller should skip pinning).
pub fn physical_core_ids() -> Vec<usize> {
    let mut seen: HashSet<(usize, usize)> = HashSet::new();
    let mut result = Vec::new();
    for cpu in 0..512usize {
        let core_id_path = format!("/sys/devices/system/cpu/cpu{}/topology/core_id", cpu);
        let pkg_path = format!("/sys/devices/system/cpu/cpu{}/topology/physical_package_id", cpu);
        let Ok(cid_str) = std::fs::read_to_string(&core_id_path) else { break; };
        let core_id: usize = cid_str.trim().parse().unwrap_or(cpu);
        let pkg_id: usize = std::fs::read_to_string(&pkg_path)
            .ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        if seen.insert((pkg_id, core_id)) {
            result.push(cpu);
        }
    }
    result
}

/// Pin the current thread to `cpu_id` using sched_setaffinity(2).
/// No-op on non-Linux or if cpu_id >= 1024.
#[cfg(target_os = "linux")]
pub fn pin_current_thread(cpu_id: usize) {
    if cpu_id >= 1024 { return; }
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu_id, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn pin_current_thread(_cpu_id: usize) {}

/// Thread-safe round-robin CPU selector for `on_thread_start` callbacks.
pub struct CpuRoundRobin {
    cores: Vec<usize>,
    counter: AtomicUsize,
}

impl CpuRoundRobin {
    pub fn new(cores: Vec<usize>) -> Self {
        Self { cores, counter: AtomicUsize::new(0) }
    }

    /// Called from each new tokio worker thread — pins it to the next physical core.
    pub fn pin_next(&self) {
        if self.cores.is_empty() { return; }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % self.cores.len();
        pin_current_thread(self.cores[idx]);
    }
}
