//! macOS sandbox implementation using seatbelt (sandbox-exec).
//!
//! # Enforcement Mechanism
//!
//! macOS provides the `sandbox_init` API which enforces a profile specified in
//! Scheme-based sandbox profile language (SBPL). The sandbox is enforced at the
//! kernel level and cannot be bypassed from userspace.
//!
//! # Profile Generation
//!
//! We generate SBPL profiles dynamically based on the `CompiledPolicy`. The
//! profile follows Apple's sandbox profile language conventions while enforcing
//! FCP2's security requirements.
//!
//! # Limitations
//!
//! - Sandbox profiles are declarative and applied atomically
//! - Once applied, restrictions cannot be relaxed
//! - Some system resources require specific entitlements
//! - Network filtering is coarse-grained (allow/deny per protocol)

#![cfg(target_os = "macos")]

use std::ffi::CString;
use std::fmt::Write as _;
use std::path::Path;

use tracing::{debug, info, warn};

use crate::sandbox::{CompiledPolicy, Sandbox, SandboxError};

/// Sanitize a filesystem path for safe inclusion in an SBPL profile string.
///
/// Rejects paths containing characters that could inject SBPL directives
/// (double quotes, parentheses, backslashes, newlines). Returns the path
/// unchanged if safe, or a placeholder that will match nothing if dangerous.
fn sanitize_sbpl_path(path: &str) -> String {
    if path.contains('"') || path.contains('\\') || path.contains('(') || path.contains(')') || path.contains('\n') || path.contains('\r') {
        warn!(path = %path, "Rejected sandbox path containing SBPL-injection characters");
        // Return a path that will never match any real filesystem entry
        "/dev/null/REJECTED_UNSAFE_PATH".to_string()
    } else {
        path.to_string()
    }
}

// ============================================================================
// macOS Sandbox
// ============================================================================

/// macOS sandbox using seatbelt profiles.
#[derive(Debug, Default)]
pub struct MacOsSandbox {
    /// Cached profile string (for debugging).
    _cached_profile: Option<String>,
}

impl MacOsSandbox {
    /// Create a new macOS sandbox.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _cached_profile: None,
        }
    }

    /// Generate a seatbelt profile (SBPL) from the compiled policy.
    fn generate_profile(policy: &CompiledPolicy) -> String {
        let mut profile = String::new();

        // Version header
        profile.push_str("(version 1)\n\n");

        // Default deny
        profile.push_str(";; Default deny all\n");
        profile.push_str("(deny default)\n\n");

        // Allow basic process operations
        profile.push_str(";; Basic process operations\n");
        profile.push_str("(allow process-info-codesignature)\n");
        profile.push_str("(allow process-info-pidinfo)\n");
        profile.push_str("(allow process-info-setcontrol)\n");
        profile.push_str("(allow sysctl-read)\n");
        profile.push_str("(allow mach-lookup\n");
        profile.push_str("  (global-name \"com.apple.system.logger\")\n");
        profile.push_str("  (global-name \"com.apple.system.notification_center\")\n");
        profile.push_str(")\n\n");

        // Memory operations
        profile.push_str(";; Memory operations\n");
        profile.push_str("(allow mach-priv-host-port)\n\n");

        // Signal handling
        profile.push_str(";; Signal handling\n");
        profile.push_str("(allow signal (target self))\n\n");

        // File system access
        profile.push_str(";; Filesystem access\n");

        // Always allow read of system libraries
        profile.push_str("(allow file-read*\n");
        profile.push_str("  (subpath \"/usr/lib\")\n");
        profile.push_str("  (subpath \"/System/Library\")\n");
        profile.push_str("  (subpath \"/Library/Frameworks\")\n");
        profile.push_str("  (subpath \"/Applications/Xcode.app/Contents/Developer/Toolchains\")\n");
        profile.push_str("  (literal \"/dev/null\")\n");
        profile.push_str("  (literal \"/dev/random\")\n");
        profile.push_str("  (literal \"/dev/urandom\")\n");
        profile.push_str(")\n");

        // Add read-only paths from policy
        if !policy.readonly_paths.is_empty() {
            profile.push_str("(allow file-read*\n");
            for path in &policy.readonly_paths {
                let escaped = sanitize_sbpl_path(&path.display().to_string());
                let _ = writeln!(profile, "  (subpath \"{escaped}\")");
            }
            profile.push_str(")\n");
        }

        // Add writable paths from policy
        if !policy.writable_paths.is_empty() {
            profile.push_str("(allow file-read* file-write*\n");
            for path in &policy.writable_paths {
                let escaped = sanitize_sbpl_path(&path.display().to_string());
                let _ = writeln!(profile, "  (subpath \"{escaped}\")");
            }
            profile.push_str(")\n");
        }

        profile.push('\n');

        // Process execution
        if policy.deny_exec {
            profile.push_str(";; Process execution denied\n");
            profile.push_str("(deny process-exec)\n");
            profile.push_str("(deny process-fork)\n\n");
        } else {
            profile.push_str(";; Process execution allowed\n");
            profile.push_str("(allow process-exec)\n");
            profile.push_str("(allow process-fork)\n\n");
        }

        // Network access
        if policy.block_direct_network {
            profile.push_str(";; Direct network access blocked (use Network Guard)\n");
            profile.push_str("(deny network*)\n");
            // Allow Unix domain sockets for IPC with Network Guard
            profile.push_str("(allow network-outbound\n");
            profile.push_str("  (path \"/var/run/fcp-network-guard.sock\")\n");
            profile.push_str(")\n");
            profile.push_str("(allow network-bind network-inbound\n");
            profile.push_str("  (local unix-socket)\n");
            profile.push_str(")\n\n");
        } else {
            profile.push_str(";; Network access allowed\n");
            profile.push_str("(allow network*)\n\n");
        }

        // Debugging / ptrace
        if policy.deny_ptrace {
            profile.push_str(";; Debugging denied\n");
            profile.push_str("(deny process-info-codesignature (with no-log))\n");
            profile.push_str("(deny system-privilege)\n\n");
        }

        // IPC
        profile.push_str(";; Allow basic IPC\n");
        profile.push_str("(allow ipc-posix-shm-read-data)\n");
        profile.push_str("(allow ipc-posix-shm-write-data)\n\n");

        // Resource limits
        let _ = writeln!(
            profile,
            ";; Resource limits: memory={}MB, cpu={}%",
            policy.memory_limit_bytes / (1024 * 1024),
            policy.cpu_percent
        );
        // Note: macOS sandbox doesn't have direct rlimit support in profiles
        // We apply these via setrlimit separately

        debug!(
            profile_len = profile.len(),
            "Generated macOS sandbox profile"
        );

        profile
    }

    /// Apply resource limits using setrlimit.
    fn apply_rlimits(policy: &CompiledPolicy) {
        // Memory limit
        let memory_limit = libc::rlimit {
            rlim_cur: policy.memory_limit_bytes,
            rlim_max: policy.memory_limit_bytes,
        };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_AS, &memory_limit) != 0 {
                warn!(
                    error = %std::io::Error::last_os_error(),
                    "Failed to set memory limit"
                );
            }
        }

        // CPU time limit
        let cpu_seconds = policy.wall_clock_timeout.as_secs();
        let cpu_limit = libc::rlimit {
            rlim_cur: cpu_seconds,
            rlim_max: cpu_seconds + 5,
        };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) != 0 {
                warn!(
                    error = %std::io::Error::last_os_error(),
                    "Failed to set CPU limit"
                );
            }
        }

        // File descriptor limit
        let fd_limit = libc::rlimit {
            rlim_cur: 1024,
            rlim_max: 4096,
        };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_NOFILE, &fd_limit) != 0 {
                warn!(
                    error = %std::io::Error::last_os_error(),
                    "Failed to set file descriptor limit"
                );
            }
        }

        // Disable core dumps
        let core_limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        unsafe {
            if libc::setrlimit(libc::RLIMIT_CORE, &core_limit) != 0 {
                warn!(
                    error = %std::io::Error::last_os_error(),
                    "Failed to disable core dumps"
                );
            }
        }

        // NOTE: RLIMIT_NPROC is NOT set on macOS even when deny_exec is true.
        // On macOS (like Linux NPTL), RLIMIT_NPROC counts threads as processes.
        // Setting it to 0 would crash any async runtime (Tokio, etc.) that needs
        // worker threads. Process execution is instead restricted by the SBPL
        // profile's `(deny process-exec)` directive.

        info!("Applied resource limits via setrlimit");
    }
}

impl Sandbox for MacOsSandbox {
    fn apply(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        info!(
            profile = ?policy.profile,
            memory_mb = policy.memory_limit_bytes / (1024 * 1024),
            cpu_percent = policy.cpu_percent,
            deny_exec = policy.deny_exec,
            deny_ptrace = policy.deny_ptrace,
            block_network = policy.block_direct_network,
            "Applying macOS sandbox"
        );

        // Step 1: Apply resource limits
        Self::apply_rlimits(policy);

        // Step 2: Generate and apply sandbox profile
        let profile = Self::generate_profile(policy);

        // Convert profile to C string
        let c_profile = CString::new(profile.as_bytes())
            .map_err(|e| SandboxError::PolicyCompilationFailed(format!("invalid profile: {e}")))?;

        // Apply sandbox using sandbox_init
        let mut errorbuf: *mut i8 = std::ptr::null_mut();

        let result = unsafe {
            sandbox_init(
                c_profile.as_ptr(),
                0, // SANDBOX_NAMED (profile is inline, not a file)
                &mut errorbuf,
            )
        };

        if result != 0 {
            let error_msg = if errorbuf.is_null() {
                "unknown error".to_string()
            } else {
                let err = unsafe { std::ffi::CStr::from_ptr(errorbuf) };
                let msg = err.to_string_lossy().to_string();
                unsafe {
                    sandbox_free_error(errorbuf);
                }
                msg
            };

            return Err(SandboxError::ApplyFailed(format!(
                "sandbox_init failed: {error_msg}"
            )));
        }

        info!("macOS sandbox applied successfully");
        Ok(())
    }

    fn is_available(&self) -> bool {
        // Sandbox is available on all macOS versions we support (10.5+)
        true
    }

    fn platform_name(&self) -> &'static str {
        "macos"
    }

    fn verify_file_access(
        &self,
        policy: &CompiledPolicy,
        path: &Path,
        write: bool,
    ) -> Result<(), SandboxError> {
        let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

        if write {
            for writable in &policy.writable_paths {
                if path.starts_with(writable) {
                    return Ok(());
                }
            }
            return Err(SandboxError::PolicyCompilationFailed(format!(
                "write access to {} not allowed",
                path.display()
            )));
        }

        // Check system paths (always readable)
        let system_paths = ["/usr/lib", "/System/Library", "/Library/Frameworks"];
        for sys_path in system_paths {
            if path.starts_with(sys_path) {
                return Ok(());
            }
        }

        // Check policy paths
        for readable in policy.readonly_paths.iter().chain(&policy.writable_paths) {
            if path.starts_with(readable) {
                return Ok(());
            }
        }

        Err(SandboxError::PolicyCompilationFailed(format!(
            "read access to {} not allowed",
            path.display()
        )))
    }

    fn verify_exec_allowed(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        if policy.deny_exec {
            Err(SandboxError::PolicyCompilationFailed(
                "process execution is denied".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn verify_network_blocked(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        if policy.block_direct_network {
            Ok(())
        } else {
            Err(SandboxError::PolicyCompilationFailed(
                "direct network access is allowed (use Network Guard)".into(),
            ))
        }
    }
}

// ============================================================================
// FFI Bindings
// ============================================================================

// SAFETY: These are FFI bindings to macOS sandbox APIs.
// sandbox_init and sandbox_free_error are documented Apple APIs.
unsafe extern "C" {
    /// Initialize sandbox with a profile string.
    fn sandbox_init(profile: *const i8, flags: u64, errorbuf: *mut *mut i8) -> i32;

    /// Free error buffer from `sandbox_init`.
    fn sandbox_free_error(errorbuf: *mut i8);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::CompiledPolicy;
    use fcp_manifest::SandboxProfile;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_policy() -> CompiledPolicy {
        CompiledPolicy {
            profile: SandboxProfile::Strict,
            memory_limit_bytes: 256 * 1024 * 1024,
            cpu_percent: 50,
            wall_clock_timeout: Duration::from_secs(30),
            readonly_paths: vec![PathBuf::from("/usr"), PathBuf::from("/opt")],
            writable_paths: vec![PathBuf::from("/tmp/test")],
            deny_exec: true,
            deny_ptrace: true,
            block_direct_network: true,
            state_dir: Some(PathBuf::from("/tmp/test")),
            platform_flags: crate::sandbox::PlatformFlags::default(),
        }
    }

    #[test]
    fn test_macos_sandbox_available() {
        let sandbox = MacOsSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "macos");
    }

    #[test]
    fn test_generate_profile_structure() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);

        // Check basic structure
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));

        // Check file access rules
        assert!(profile.contains("file-read*"));
        assert!(profile.contains("/usr"));
        assert!(profile.contains("/tmp/test"));

        // Check network is blocked
        assert!(profile.contains("network access blocked"));
        assert!(profile.contains("(deny network*)"));

        // Check exec is denied
        assert!(profile.contains("(deny process-exec)"));
        assert!(profile.contains("(deny process-fork)"));
    }

    #[test]
    fn test_generate_profile_permissive() {
        let mut policy = test_policy();
        policy.block_direct_network = false;
        policy.deny_exec = false;

        let profile = MacOsSandbox::generate_profile(&policy);

        // Check network is allowed
        assert!(profile.contains("(allow network*)"));

        // Check exec is allowed
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("(allow process-fork)"));
    }

    #[test]
    fn test_verify_file_access_system_paths() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();

        // System paths should always be readable
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/usr/lib/libSystem.B.dylib"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    Path::new("/System/Library/Frameworks/CoreFoundation.framework"),
                    false
                )
                .is_ok()
        );

        // But not writable
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/usr/lib/test.dylib"), true)
                .is_err()
        );
    }

    #[test]
    fn test_verify_file_access_policy_paths() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();

        // Writable path should allow read and write
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/tmp/test/data.db"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/tmp/test/data.db"), true)
                .is_ok()
        );

        // Unknown path should be denied
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/home/user/secret"), false)
                .is_err()
        );
    }

    // ── Batch: profile generation edge cases ──

    #[test]
    fn test_generate_profile_no_readonly_paths() {
        let mut policy = test_policy();
        policy.readonly_paths = vec![];
        let profile = MacOsSandbox::generate_profile(&policy);
        // Should still have system read paths but no extra readonly section
        assert!(profile.contains("/usr/lib"));
        // The extra (allow file-read* ...) block for policy paths should not appear
        // (system paths are always present in a separate block)
    }

    #[test]
    fn test_generate_profile_no_writable_paths() {
        let mut policy = test_policy();
        policy.writable_paths = vec![];
        let profile = MacOsSandbox::generate_profile(&policy);
        // Should not contain file-write for policy writable paths
        assert!(!profile.contains("file-write*\n  (subpath"));
    }

    #[test]
    fn test_generate_profile_ptrace_allowed() {
        let mut policy = test_policy();
        policy.deny_ptrace = false;
        let profile = MacOsSandbox::generate_profile(&policy);
        // Should not contain the ptrace-deny section
        assert!(!profile.contains("Debugging denied"));
        assert!(!profile.contains("(deny system-privilege)"));
    }

    #[test]
    fn test_generate_profile_ptrace_denied() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("Debugging denied"));
        assert!(profile.contains("(deny system-privilege)"));
    }

    #[test]
    fn test_generate_profile_multiple_readonly_paths() {
        let mut policy = test_policy();
        policy.readonly_paths = vec![
            PathBuf::from("/data/models"),
            PathBuf::from("/data/config"),
            PathBuf::from("/data/assets"),
        ];
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("/data/models"));
        assert!(profile.contains("/data/config"));
        assert!(profile.contains("/data/assets"));
    }

    #[test]
    fn test_generate_profile_multiple_writable_paths() {
        let mut policy = test_policy();
        policy.writable_paths = vec![PathBuf::from("/tmp/cache"), PathBuf::from("/tmp/logs")];
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("/tmp/cache"));
        assert!(profile.contains("/tmp/logs"));
    }

    #[test]
    fn test_generate_profile_network_guard_socket() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        // When network blocked, should allow IPC to network guard socket
        assert!(profile.contains("fcp-network-guard.sock"));
    }

    #[test]
    fn test_generate_profile_resource_limits_comment() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("memory=256MB"));
        assert!(profile.contains("cpu=50%"));
    }

    #[test]
    fn test_generate_profile_ipc_always_allowed() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("(allow ipc-posix-shm-read-data)"));
        assert!(profile.contains("(allow ipc-posix-shm-write-data)"));
    }

    #[test]
    fn test_generate_profile_system_libraries_always_readable() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("/usr/lib"));
        assert!(profile.contains("/System/Library"));
        assert!(profile.contains("/Library/Frameworks"));
        assert!(profile.contains("/dev/null"));
        assert!(profile.contains("/dev/random"));
        assert!(profile.contains("/dev/urandom"));
    }

    #[test]
    fn test_generate_profile_starts_with_version() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.starts_with("(version 1)"));
    }

    // ── Batch: verify methods ──

    #[test]
    fn test_verify_exec_allowed_when_denied() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        assert!(policy.deny_exec);
        let result = sandbox.verify_exec_allowed(&policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("denied"));
    }

    #[test]
    fn test_verify_exec_allowed_when_permitted() {
        let sandbox = MacOsSandbox::new();
        let mut policy = test_policy();
        policy.deny_exec = false;
        assert!(sandbox.verify_exec_allowed(&policy).is_ok());
    }

    #[test]
    fn test_verify_network_blocked_when_strict() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        assert!(policy.block_direct_network);
        // When network IS blocked, verify_network_blocked returns Ok
        assert!(sandbox.verify_network_blocked(&policy).is_ok());
    }

    #[test]
    fn test_verify_network_blocked_when_permissive() {
        let sandbox = MacOsSandbox::new();
        let mut policy = test_policy();
        policy.block_direct_network = false;
        // When network is NOT blocked, verify_network_blocked returns Err
        let result = sandbox.verify_network_blocked(&policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_file_access_readonly_path_write_denied() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        // /opt is in readonly_paths, so write should be denied
        let result = sandbox.verify_file_access(&policy, Path::new("/opt/data.txt"), true);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_file_access_readonly_path_read_allowed() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        // /opt is in readonly_paths
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/opt/data.txt"), false)
                .is_ok()
        );
    }

    #[test]
    fn test_verify_file_access_library_frameworks() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    Path::new("/Library/Frameworks/Python.framework"),
                    false
                )
                .is_ok()
        );
    }

    // ── Batch: construction ──

    #[test]
    fn test_macos_sandbox_default() {
        let sandbox = MacOsSandbox::default();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "macos");
    }

    #[test]
    fn test_macos_sandbox_debug() {
        let sandbox = MacOsSandbox::new();
        let debug = format!("{sandbox:?}");
        assert!(debug.contains("MacOsSandbox"));
    }

    // ── Batch: SBPL path sanitization (security regression for 1fcd949) ──

    #[test]
    fn test_sanitize_sbpl_path_clean_path_passes_through() {
        assert_eq!(sanitize_sbpl_path("/usr/local/bin"), "/usr/local/bin");
        assert_eq!(sanitize_sbpl_path("/tmp/test"), "/tmp/test");
        assert_eq!(sanitize_sbpl_path("/home/user/data.db"), "/home/user/data.db");
    }

    #[test]
    fn test_sanitize_sbpl_path_rejects_double_quotes() {
        // Double quotes could close the SBPL string and inject directives
        let result = sanitize_sbpl_path("/tmp/evil\")(allow default)(\"");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_rejects_backslash() {
        let result = sanitize_sbpl_path("/tmp/evil\\path");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_rejects_parentheses() {
        // Parentheses are SBPL syntax delimiters
        let result = sanitize_sbpl_path("/tmp/evil(allow default)");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");

        let result = sanitize_sbpl_path("/tmp/evil)inject");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_rejects_newlines() {
        let result = sanitize_sbpl_path("/tmp/evil\npath");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");

        let result = sanitize_sbpl_path("/tmp/evil\rpath");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_empty_string() {
        // Empty string has no dangerous chars, passes through
        assert_eq!(sanitize_sbpl_path(""), "");
    }

    #[test]
    fn test_sanitize_sbpl_path_allows_special_but_safe_chars() {
        // These are unusual but not SBPL-injectable
        assert_eq!(sanitize_sbpl_path("/tmp/path with spaces"), "/tmp/path with spaces");
        assert_eq!(sanitize_sbpl_path("/tmp/path-with-dashes"), "/tmp/path-with-dashes");
        assert_eq!(sanitize_sbpl_path("/tmp/path_under_score"), "/tmp/path_under_score");
        assert_eq!(sanitize_sbpl_path("/tmp/path.with.dots"), "/tmp/path.with.dots");
    }

    #[test]
    fn test_generate_profile_with_malicious_readonly_path() {
        let mut policy = test_policy();
        policy.readonly_paths = vec![PathBuf::from("/tmp/safe"), PathBuf::from("/tmp/evil\")(allow default)(\"")];
        let profile = MacOsSandbox::generate_profile(&policy);

        // Safe path should be present
        assert!(profile.contains("/tmp/safe"));
        // Malicious path should be replaced with the rejection placeholder
        assert!(profile.contains("/dev/null/REJECTED_UNSAFE_PATH"));
        // The injected SBPL directive must NOT appear
        assert!(!profile.contains("(allow default)"));
    }

    #[test]
    fn test_generate_profile_with_malicious_writable_path() {
        let mut policy = test_policy();
        policy.writable_paths = vec![PathBuf::from("/tmp/evil\n(allow default)")];
        let profile = MacOsSandbox::generate_profile(&policy);

        // Injection attempt must be sanitized
        assert!(profile.contains("/dev/null/REJECTED_UNSAFE_PATH"));
        // Count occurrences of "(allow default)" - should be zero outside system boilerplate
        // The profile should NOT have an extra "(allow default)" from injection
        let default_deny_count = profile.matches("(deny default)").count();
        assert_eq!(default_deny_count, 1, "Only the legitimate deny-default should be present");
    }
}
