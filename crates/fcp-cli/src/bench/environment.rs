//! Environment metadata collection for benchmark reproducibility.
//!
//! Collects OS, CPU, memory, git, and version information to enable
//! meaningful regression tracking across different machines and commits.

use std::process::Command;

use chrono::Utc;

use super::types::EnvironmentInfo;

/// Collect environment information for the benchmark report.
///
/// This function gathers:
/// - OS name and version
/// - CPU architecture and count
/// - Memory (if available via `/proc/meminfo` on Linux)
/// - Git commit, branch, and dirty status
/// - FCP CLI and rustc versions
pub fn collect() -> EnvironmentInfo {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let cpu_count = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);

    let os_version = get_os_version();
    let memory_bytes = get_memory_bytes();
    let (git_commit, git_branch, git_dirty) = get_git_info();
    let rustc_version = get_rustc_version();

    EnvironmentInfo {
        os,
        os_version,
        arch,
        cpu_count,
        memory_bytes,
        git_commit,
        git_branch,
        git_dirty,
        fcp_version: env!("CARGO_PKG_VERSION").to_string(),
        rustc_version,
        timestamp: Utc::now(),
    }
}

fn get_os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        // Try to read /etc/os-release for distribution info.
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if let Some(version) = line.strip_prefix("PRETTY_NAME=") {
                    return version.trim_matches('"').to_string();
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = Command::new("cmd").args(["/C", "ver"]).output() {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim().to_string();
            }
        }
    }

    "unknown".to_string()
}

#[allow(clippy::missing_const_for_fn)]
fn get_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if let Some(value) = line.strip_prefix("MemTotal:") {
                    let parts: Vec<&str> = value.split_whitespace().collect();
                    if let Some(kb_str) = parts.first() {
                        if let Ok(kb) = kb_str.parse::<u64>() {
                            return Some(kb * 1024); // Convert KB to bytes.
                        }
                    }
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn get_git_info() -> (Option<String>, Option<String>, Option<bool>) {
    let commit = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let branch = Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty());

    (commit, branch, dirty)
}

fn get_rustc_version() -> Option<String> {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_returns_valid_os() {
        let info = collect();
        assert!(!info.os.is_empty(), "os should not be empty");
        let valid_os = ["linux", "macos", "windows"];
        assert!(
            valid_os.contains(&info.os.as_str()),
            "unexpected os: {}",
            info.os
        );
    }

    #[test]
    fn collect_returns_valid_arch() {
        let info = collect();
        assert!(!info.arch.is_empty());
        let valid_arch = ["x86_64", "aarch64", "x86", "arm"];
        assert!(
            valid_arch.contains(&info.arch.as_str()),
            "unexpected arch: {}",
            info.arch
        );
    }

    #[test]
    fn collect_returns_positive_cpu_count() {
        let info = collect();
        assert!(info.cpu_count >= 1);
    }

    #[test]
    fn collect_returns_nonempty_fcp_version() {
        let info = collect();
        assert!(!info.fcp_version.is_empty());
    }

    #[test]
    fn collect_returns_timestamp_not_epoch() {
        let info = collect();
        assert!(info.timestamp.timestamp() > 0);
    }

    #[test]
    fn collect_os_version_not_empty() {
        let info = collect();
        assert!(!info.os_version.is_empty());
    }

    #[test]
    fn get_os_version_returns_string() {
        let version = get_os_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn get_git_info_returns_some_in_repo() {
        let (commit, branch, dirty) = get_git_info();
        // We're in a git repo, so these should be Some
        assert!(commit.is_some(), "expected git commit");
        assert!(branch.is_some(), "expected git branch");
        assert!(dirty.is_some(), "expected git dirty status");
    }

    #[test]
    fn get_git_commit_is_short_hash() {
        let (commit, _, _) = get_git_info();
        if let Some(c) = commit {
            assert!(
                c.len() >= 7 && c.len() <= 12,
                "short hash length: {}",
                c.len()
            );
            assert!(c.chars().all(|ch| ch.is_ascii_hexdigit()), "not hex: {c}");
        }
    }

    #[test]
    fn get_git_branch_is_nonempty() {
        let (_, branch, _) = get_git_info();
        if let Some(b) = branch {
            assert!(!b.is_empty());
        }
    }

    #[test]
    fn get_rustc_version_returns_some() {
        let version = get_rustc_version();
        assert!(version.is_some());
        let v = version.unwrap();
        assert!(v.starts_with("rustc "), "expected 'rustc ...' got '{v}'");
    }

    #[test]
    fn collect_deterministic_static_fields() {
        let info1 = collect();
        let info2 = collect();
        assert_eq!(info1.os, info2.os);
        assert_eq!(info1.arch, info2.arch);
        assert_eq!(info1.cpu_count, info2.cpu_count);
        assert_eq!(info1.fcp_version, info2.fcp_version);
    }

    #[test]
    fn collect_git_branch_is_main() {
        let info = collect();
        // Per AGENTS.md, we always use main
        if let Some(ref branch) = info.git_branch {
            assert_eq!(branch, "main", "expected main branch");
        }
    }
}
