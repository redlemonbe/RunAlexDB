//! XDP availability detection — runtime check with automatic fallback.
//!
//! Checks whether XDP/eBPF is available on this system without loading any
//! program. Runs once at startup; log informs operator of the result.

/// Returns true if XDP is likely available on this Linux host.
///
/// Checks: running on Linux, kernel >= 4.8, BPF filesystem mounted.
/// On any other OS or older kernel, returns false immediately (no panic).
pub fn check_available() -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        return false;
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(ver_str) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let ver_str = ver_str.trim();
            // Parse "major.minor.patch-..." — only major.minor matters
            let mut parts = ver_str.split('.').take(2).filter_map(|s| {
                s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse::<u32>().ok()
            });
            if let (Some(major), Some(minor)) = (parts.next(), parts.next()) {
                if major < 4 || (major == 4 && minor < 8) {
                    return false;
                }
            }
        }

        std::path::Path::new("/sys/fs/bpf").exists()
    }
}
