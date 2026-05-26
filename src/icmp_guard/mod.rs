// ICMP flood protection with inter-process coordination.
//
// Guards against ICMP floods via iptables/nftables rate-limiting.
// Uses a lock file (/var/run/icmp_guard.lock) so that only ONE process
// (RunNginx, RunAlexDB, or Runbound) sets up rules at a time.
// When the owner exits, rules are removed and the lock is released.
// A second instance that finds the lock alive will skip setup silently.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

const LOCK_FILE: &str = "/var/run/icmp_guard.pid";
const ICMP_RATE: &str = "5/second";
const ICMP_BURST: u32 = 10;
const ICMP_COMMENT: &str = "icmp_guard";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Iptables,
    Nftables,
    None,
}

pub struct IcmpGuard {
    is_owner: bool,
    backend: Backend,
    enabled: bool,
}

impl IcmpGuard {
    /// Set up ICMP protection. If `enabled` is false or another process already
    /// holds the lock, this is a no-op and `is_owner` will be false.
    pub fn setup(enabled: bool) -> Self {
        if !enabled {
            return Self { is_owner: false, backend: Backend::None, enabled: false };
        }
        if Self::lock_is_held() {
            info!("icmp_guard: protection already active — skipping setup");
            return Self { is_owner: false, backend: Backend::None, enabled: true };
        }
        let backend = Self::detect_backend();
        if backend == Backend::None {
            warn!("icmp_guard: no supported firewall backend found — ICMP protection disabled");
            return Self { is_owner: false, backend: Backend::None, enabled: true };
        }
        match Self::apply_rules(backend) {
            Ok(()) => {
                Self::write_lock();
                info!("icmp_guard: ICMP rate-limiting active via {:?} ({}r/s burst {})",
                      backend, ICMP_RATE, ICMP_BURST);
                Self { is_owner: true, backend, enabled: true }
            }
            Err(e) => {
                warn!("icmp_guard: failed to apply rules: {e}");
                Self { is_owner: false, backend: Backend::None, enabled: true }
            }
        }
    }

    pub fn teardown(&self) {
        if !self.is_owner { return; }
        if let Err(e) = Self::remove_rules(self.backend) {
            warn!("icmp_guard: cleanup error: {e}");
        }
        let _ = fs::remove_file(LOCK_FILE);
        info!("icmp_guard: rules removed, lock released");
    }

    // ── Lock file ─────────────────────────────────────────────────────────────

    fn lock_is_held() -> bool {
        let Ok(content) = fs::read_to_string(LOCK_FILE) else { return false };
        let pid_str = content.split(':').nth(1).unwrap_or("").trim();
        let Ok(pid) = pid_str.parse::<u32>() else { return false };
        // kill(pid, 0) — signal 0 only checks existence
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    fn write_lock() {
        let content = format!("runnginx:{}\n", std::process::id());
        if let Ok(mut f) = fs::OpenOptions::new()
            .write(true).create(true).truncate(true).open(LOCK_FILE)
        {
            let _ = f.write_all(content.as_bytes());
        }
    }

    // ── Backend detection ────────────────────────────────────────────────────

    fn detect_backend() -> Backend {
        if cmd_ok("which", &["nft"]) {
            return Backend::Nftables;
        }
        if cmd_ok("which", &["iptables"]) {
            return Backend::Iptables;
        }
        Backend::None
    }

    // ── Rule management ──────────────────────────────────────────────────────

    fn apply_rules(backend: Backend) -> Result<(), String> {
        match backend {
            Backend::Iptables => {
                // Accept rate-limited ICMP echo-request
                run_cmd("iptables", &[
                    "-I", "INPUT", "-p", "icmp", "--icmp-type", "echo-request",
                    "-m", "limit", "--limit", ICMP_RATE,
                    "--limit-burst", &ICMP_BURST.to_string(),
                    "-m", "comment", "--comment", ICMP_COMMENT,
                    "-j", "ACCEPT",
                ])?;
                // Drop excess ICMP echo-request
                run_cmd("iptables", &[
                    "-I", "INPUT", "-p", "icmp", "--icmp-type", "echo-request",
                    "-m", "comment", "--comment", ICMP_COMMENT,
                    "-j", "DROP",
                ])?;
                // Same for IPv6
                let _ = run_cmd("ip6tables", &[
                    "-I", "INPUT", "-p", "icmpv6", "--icmpv6-type", "echo-request",
                    "-m", "limit", "--limit", ICMP_RATE,
                    "--limit-burst", &ICMP_BURST.to_string(),
                    "-m", "comment", "--comment", ICMP_COMMENT,
                    "-j", "ACCEPT",
                ]);
                let _ = run_cmd("ip6tables", &[
                    "-I", "INPUT", "-p", "icmpv6", "--icmpv6-type", "echo-request",
                    "-m", "comment", "--comment", ICMP_COMMENT,
                    "-j", "DROP",
                ]);
                Ok(())
            }
            Backend::Nftables => {
                // Ensure the filter table and input chain exist, then add rule
                // Using a named set approach — add rate-limit accept then drop
                let add_accept = format!(
                    "add rule inet filter input ip protocol icmp icmp type echo-request \
                     limit rate {ICMP_RATE} burst {ICMP_BURST} packets accept comment \"{ICMP_COMMENT}\""
                );
                let add_drop = format!(
                    "add rule inet filter input ip protocol icmp icmp type echo-request \
                     drop comment \"{ICMP_COMMENT}\""
                );
                run_cmd("nft", &[&add_accept])?;
                run_cmd("nft", &[&add_drop])?;
                Ok(())
            }
            Backend::None => Ok(()),
        }
    }

    fn remove_rules(backend: Backend) -> Result<(), String> {
        match backend {
            Backend::Iptables => {
                // Delete by matching the comment tag
                let _ = run_cmd("iptables", &[
                    "-D", "INPUT", "-p", "icmp", "--icmp-type", "echo-request",
                    "-m", "limit", "--limit", ICMP_RATE,
                    "--limit-burst", &ICMP_BURST.to_string(),
                    "-m", "comment", "--comment", ICMP_COMMENT,
                    "-j", "ACCEPT",
                ]);
                let _ = run_cmd("iptables", &[
                    "-D", "INPUT", "-p", "icmp", "--icmp-type", "echo-request",
                    "-m", "comment", "--comment", ICMP_COMMENT,
                    "-j", "DROP",
                ]);
                let _ = run_cmd("ip6tables", &[
                    "-D", "INPUT", "-p", "icmpv6", "--icmpv6-type", "echo-request",
                    "-m", "limit", "--limit", ICMP_RATE,
                    "--limit-burst", &ICMP_BURST.to_string(),
                    "-m", "comment", "--comment", ICMP_COMMENT,
                    "-j", "ACCEPT",
                ]);
                let _ = run_cmd("ip6tables", &[
                    "-D", "INPUT", "-p", "icmpv6", "--icmpv6-type", "echo-request",
                    "-m", "comment", "--comment", ICMP_COMMENT,
                    "-j", "DROP",
                ]);
                Ok(())
            }
            Backend::Nftables => {
                // Delete rules by comment — list handles, then delete
                let out = Command::new("nft")
                    .args(["-a", "list", "chain", "inet", "filter", "input"])
                    .output()
                    .map_err(|e| e.to_string())?;
                let text = String::from_utf8_lossy(&out.stdout);
                for line in text.lines() {
                    if line.contains(ICMP_COMMENT) {
                        if let Some(h) = line.split("# handle ").nth(1) {
                            let handle = h.trim();
                            let _ = Command::new("nft")
                                .args(["delete", "rule", "inet", "filter", "input", "handle", handle])
                                .status();
                        }
                    }
                }
                Ok(())
            }
            Backend::None => Ok(()),
        }
    }
}

impl Drop for IcmpGuard {
    fn drop(&mut self) { self.teardown(); }
}

fn cmd_ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args).output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(cmd).args(args).status()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if status.success() { Ok(()) } else { Err(format!("{cmd} exited with {status}")) }
}
