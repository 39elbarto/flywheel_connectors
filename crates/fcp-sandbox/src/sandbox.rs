//! OS-level sandbox enforcement.
//!
//! This module provides platform-specific process isolation for FCP2 connectors.
//! The sandbox enforces:
//!
//! - Resource limits (memory, CPU, wall-clock time)
//! - Filesystem access controls (read-only paths, writable paths)
//! - Process restrictions (deny exec, deny ptrace)
//! - Network model enforcement (all network via Network Guard in strict/moderate)
//!
//! # Platform Support
//!
//! - **Linux (Tier 1)**: seccomp-bpf + namespaces, optionally Landlock
//! - **macOS (Tier 1)**: seatbelt profiles (sandbox-exec)
//! - **Windows (Tier 2)**: `AppContainer` + job objects

use std::path::PathBuf;
use std::time::Duration;

use fcp_manifest::{SandboxProfile, SandboxSection};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Errors
// ============================================================================

/// Errors from sandbox operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Platform not supported.
    #[error("sandbox not supported on this platform: {0}")]
    UnsupportedPlatform(String),

    /// Failed to compile policy.
    #[error("failed to compile sandbox policy: {0}")]
    PolicyCompilationFailed(String),

    /// Failed to apply sandbox.
    #[error("failed to apply sandbox: {0}")]
    ApplyFailed(String),

    /// Resource limit exceeded.
    #[error("resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// Invalid configuration.
    #[error("invalid sandbox configuration: {0}")]
    InvalidConfig(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Syscall failed.
    #[error("syscall failed: {0}")]
    SyscallFailed(String),

    /// Timeout.
    #[error("wall-clock timeout exceeded")]
    Timeout,
}

// ============================================================================
// Compiled Policy
// ============================================================================

/// A compiled sandbox policy ready for application.
///
/// This is the platform-agnostic representation of sandbox rules after
/// compilation from `SandboxSection`. Platform-specific implementations
/// translate this into native enforcement primitives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicy {
    /// Original sandbox profile level.
    pub profile: SandboxProfile,

    /// Memory limit in bytes.
    pub memory_limit_bytes: u64,

    /// CPU limit as a percentage (1-100).
    pub cpu_percent: u8,

    /// Wall-clock timeout.
    pub wall_clock_timeout: Duration,

    /// Paths allowed for read-only access.
    pub readonly_paths: Vec<PathBuf>,

    /// Paths allowed for read-write access.
    pub writable_paths: Vec<PathBuf>,

    /// Deny spawning child processes.
    pub deny_exec: bool,

    /// Deny ptrace/debugging.
    pub deny_ptrace: bool,

    /// Block direct network access (all network via Network Guard IPC).
    ///
    /// True for `strict` and `moderate` profiles.
    pub block_direct_network: bool,

    /// State directory for connector persistent data.
    ///
    /// This is typically `$CONNECTOR_STATE` expanded to an absolute path.
    pub state_dir: Option<PathBuf>,

    /// Additional platform-specific flags.
    pub platform_flags: PlatformFlags,
}

/// Platform-specific configuration flags.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformFlags {
    /// Linux: Use Landlock if available (kernel 5.13+).
    #[serde(default)]
    pub linux_use_landlock: bool,

    /// Linux: Use user namespaces for isolation.
    #[serde(default)]
    pub linux_use_userns: bool,

    /// macOS: Entitlements to request.
    #[serde(default)]
    pub macos_entitlements: Vec<String>,

    /// Windows: Use low-integrity `AppContainer`.
    #[serde(default)]
    pub windows_low_integrity: bool,
}

impl PlatformFlags {
    /// Check if all platform flags are at their default values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.linux_use_landlock
            && !self.linux_use_userns
            && self.macos_entitlements.is_empty()
            && !self.windows_low_integrity
    }
}

impl CompiledPolicy {
    /// Create a compiled policy from a manifest sandbox section.
    ///
    /// # Arguments
    ///
    /// * `section` - The sandbox section from the connector manifest.
    /// * `state_dir` - Optional absolute path to the connector's state directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy cannot be compiled.
    pub fn from_manifest(
        section: &SandboxSection,
        state_dir: Option<PathBuf>,
    ) -> Result<Self, SandboxError> {
        // Expand special paths
        let readonly_paths = section
            .fs_readonly_paths
            .iter()
            .filter_map(|p| expand_path(p, state_dir.as_ref()))
            .collect();

        let mut writable_paths: Vec<PathBuf> = section
            .fs_writable_paths
            .iter()
            .filter_map(|p| expand_path(p, state_dir.as_ref()))
            .collect();

        // Always add state_dir to writable paths if provided
        if let Some(ref dir) = state_dir {
            if !writable_paths.contains(dir) {
                writable_paths.push(dir.clone());
            }
        }

        // Determine if direct network should be blocked
        let block_direct_network = matches!(
            section.profile,
            SandboxProfile::Strict | SandboxProfile::StrictPlus | SandboxProfile::Moderate
        );

        Ok(Self {
            profile: section.profile,
            memory_limit_bytes: u64::from(section.memory_mb) * 1024 * 1024,
            cpu_percent: section.cpu_percent,
            wall_clock_timeout: Duration::from_millis(section.wall_clock_timeout_ms),
            readonly_paths,
            writable_paths,
            deny_exec: section.deny_exec,
            deny_ptrace: section.deny_ptrace,
            block_direct_network,
            state_dir,
            platform_flags: PlatformFlags::default(),
        })
    }

    /// Set platform-specific flags.
    #[must_use]
    pub fn with_platform_flags(mut self, flags: PlatformFlags) -> Self {
        self.platform_flags = flags;
        self
    }
}

/// Expand special path variables.
fn expand_path(path: &str, state_dir: Option<&PathBuf>) -> Option<PathBuf> {
    if path.starts_with("$CONNECTOR_STATE") {
        state_dir.map(|sd| {
            if path == "$CONNECTOR_STATE" {
                sd.clone()
            } else {
                let suffix = path.strip_prefix("$CONNECTOR_STATE/").unwrap_or("");
                sd.join(suffix)
            }
        })
    } else {
        Some(PathBuf::from(path))
    }
}

// ============================================================================
// Sandbox Trait
// ============================================================================

/// Platform-specific sandbox implementation.
///
/// Each platform provides its own implementation that translates the
/// `CompiledPolicy` into native enforcement mechanisms.
pub trait Sandbox: Send + Sync {
    /// Apply the sandbox to the current process.
    ///
    /// This should be called early in the connector's startup, before any
    /// untrusted code runs. Once applied, the sandbox restrictions cannot
    /// be relaxed.
    ///
    /// # Safety
    ///
    /// This function modifies process-wide security state. It should only
    /// be called once per process, typically from the main thread during
    /// initialization.
    ///
    /// # Errors
    ///
    /// Returns an error if the sandbox cannot be applied.
    fn apply(&self, policy: &CompiledPolicy) -> Result<(), SandboxError>;

    /// Check if the sandbox can be applied on this platform.
    ///
    /// Returns `true` if all required kernel/OS features are available.
    fn is_available(&self) -> bool;

    /// Get the platform name (e.g., "linux", "macos", "windows").
    fn platform_name(&self) -> &'static str;

    /// Verify that a file operation would be allowed under the sandbox.
    ///
    /// This is useful for pre-flight checks before applying the sandbox.
    fn verify_file_access(
        &self,
        policy: &CompiledPolicy,
        path: &std::path::Path,
        write: bool,
    ) -> Result<(), SandboxError>;

    /// Verify that process spawning would be allowed.
    fn verify_exec_allowed(&self, policy: &CompiledPolicy) -> Result<(), SandboxError>;

    /// Verify that direct network access would be blocked.
    fn verify_network_blocked(&self, policy: &CompiledPolicy) -> Result<(), SandboxError>;
}

// ============================================================================
// Factory
// ============================================================================

/// Create the appropriate sandbox for the current platform.
///
/// # Errors
///
/// Returns an error if no sandbox implementation is available for this platform.
#[allow(unreachable_code)]
pub fn create_sandbox() -> Result<Box<dyn Sandbox>, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        return Ok(Box::new(super::linux::LinuxSandbox::new()));
    }

    #[cfg(target_os = "macos")]
    {
        return Ok(Box::new(super::macos::MacOsSandbox::new()));
    }

    #[cfg(target_os = "windows")]
    {
        return Ok(Box::new(super::windows::WindowsSandbox::new()));
    }

    Err(SandboxError::UnsupportedPlatform(
        std::env::consts::OS.to_string(),
    ))
}

// ============================================================================
// Test Utilities
// ============================================================================

/// A no-op sandbox for testing.
#[derive(Debug, Default)]
pub struct NoOpSandbox;

impl Sandbox for NoOpSandbox {
    fn apply(&self, _policy: &CompiledPolicy) -> Result<(), SandboxError> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }

    fn platform_name(&self) -> &'static str {
        "noop"
    }

    fn verify_file_access(
        &self,
        _policy: &CompiledPolicy,
        _path: &std::path::Path,
        _write: bool,
    ) -> Result<(), SandboxError> {
        Ok(())
    }

    fn verify_exec_allowed(&self, _policy: &CompiledPolicy) -> Result<(), SandboxError> {
        Ok(())
    }

    fn verify_network_blocked(&self, _policy: &CompiledPolicy) -> Result<(), SandboxError> {
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sandbox_section() -> SandboxSection {
        SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 256,
            cpu_percent: 50,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: vec!["/usr".into(), "/lib".into()],
            fs_writable_paths: vec!["$CONNECTOR_STATE".into()],
            deny_exec: true,
            deny_ptrace: true,
        }
    }

    #[test]
    fn test_compile_policy() {
        let section = test_sandbox_section();
        let state_dir = Some(PathBuf::from("/var/lib/fcp/connectors/test"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();

        assert_eq!(policy.profile, SandboxProfile::Strict);
        assert_eq!(policy.memory_limit_bytes, 256 * 1024 * 1024);
        assert_eq!(policy.cpu_percent, 50);
        assert_eq!(policy.wall_clock_timeout, Duration::from_secs(30));
        assert!(policy.readonly_paths.contains(&PathBuf::from("/usr")));
        assert!(policy.readonly_paths.contains(&PathBuf::from("/lib")));
        assert!(
            policy
                .writable_paths
                .contains(&PathBuf::from("/var/lib/fcp/connectors/test"))
        );
        assert!(policy.deny_exec);
        assert!(policy.deny_ptrace);
        assert!(policy.block_direct_network);
    }

    #[test]
    fn test_expand_path_state_dir() {
        let state_dir = PathBuf::from("/var/lib/fcp/state");

        assert_eq!(
            expand_path("$CONNECTOR_STATE", Some(&state_dir)),
            Some(PathBuf::from("/var/lib/fcp/state"))
        );

        assert_eq!(
            expand_path("$CONNECTOR_STATE/data", Some(&state_dir)),
            Some(PathBuf::from("/var/lib/fcp/state/data"))
        );

        assert_eq!(
            expand_path("/usr/lib", Some(&state_dir)),
            Some(PathBuf::from("/usr/lib"))
        );

        assert_eq!(expand_path("$CONNECTOR_STATE", None), None);
    }

    #[test]
    fn test_block_network_by_profile() {
        let mut section = test_sandbox_section();

        section.profile = SandboxProfile::Strict;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.block_direct_network);

        section.profile = SandboxProfile::StrictPlus;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.block_direct_network);

        section.profile = SandboxProfile::Moderate;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.block_direct_network);

        section.profile = SandboxProfile::Permissive;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(!policy.block_direct_network);
    }

    #[test]
    fn test_noop_sandbox() {
        let sandbox = NoOpSandbox;
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "noop");

        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(sandbox.apply(&policy).is_ok());
    }

    // ── New tests ──

    #[test]
    fn test_sandbox_error_display() {
        let e = SandboxError::UnsupportedPlatform("wasm".into());
        assert!(e.to_string().contains("wasm"));

        let e = SandboxError::PolicyCompilationFailed("bad rule".into());
        assert!(e.to_string().contains("bad rule"));

        let e = SandboxError::ApplyFailed("seccomp denied".into());
        assert!(e.to_string().contains("seccomp denied"));

        let e = SandboxError::ResourceLimitExceeded("memory".into());
        assert!(e.to_string().contains("memory"));

        let e = SandboxError::InvalidConfig("missing field".into());
        assert!(e.to_string().contains("missing field"));

        let e = SandboxError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert!(e.to_string().contains("gone"));

        let e = SandboxError::SyscallFailed("prctl".into());
        assert!(e.to_string().contains("prctl"));

        let e = SandboxError::Timeout;
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn test_platform_flags_default_is_empty() {
        let flags = PlatformFlags::default();
        assert!(flags.is_empty());
        assert!(!flags.linux_use_landlock);
        assert!(!flags.linux_use_userns);
        assert!(flags.macos_entitlements.is_empty());
        assert!(!flags.windows_low_integrity);
    }

    #[test]
    fn test_platform_flags_not_empty() {
        let flags = PlatformFlags {
            linux_use_landlock: true,
            ..Default::default()
        };
        assert!(!flags.is_empty());

        let flags = PlatformFlags {
            linux_use_userns: true,
            ..Default::default()
        };
        assert!(!flags.is_empty());

        let flags = PlatformFlags {
            macos_entitlements: vec!["com.apple.security.network.client".into()],
            ..Default::default()
        };
        assert!(!flags.is_empty());

        let flags = PlatformFlags {
            windows_low_integrity: true,
            ..Default::default()
        };
        assert!(!flags.is_empty());
    }

    #[test]
    fn test_compiled_policy_with_platform_flags() {
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.platform_flags.is_empty());

        let flags = PlatformFlags {
            linux_use_landlock: true,
            ..Default::default()
        };
        let policy = policy.with_platform_flags(flags);
        assert!(policy.platform_flags.linux_use_landlock);
    }

    #[test]
    fn test_expand_path_connector_state_subpath() {
        let state_dir = PathBuf::from("/data/state");
        assert_eq!(
            expand_path("$CONNECTOR_STATE/db/main.sqlite", Some(&state_dir)),
            Some(PathBuf::from("/data/state/db/main.sqlite"))
        );
    }

    #[test]
    fn test_expand_path_absolute_ignores_state_dir() {
        let state_dir = PathBuf::from("/data/state");
        assert_eq!(
            expand_path("/etc/hosts", Some(&state_dir)),
            Some(PathBuf::from("/etc/hosts"))
        );
    }

    #[test]
    fn test_compiled_policy_state_dir_added_to_writable() {
        let mut section = test_sandbox_section();
        section.fs_writable_paths = vec![]; // No writable paths
        let state_dir = Some(PathBuf::from("/data/state"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
        assert!(
            policy
                .writable_paths
                .contains(&PathBuf::from("/data/state"))
        );
    }

    #[test]
    fn test_compiled_policy_state_dir_not_duplicated() {
        let mut section = test_sandbox_section();
        section.fs_writable_paths = vec!["$CONNECTOR_STATE".into()];
        let state_dir = Some(PathBuf::from("/data/state"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
        // $CONNECTOR_STATE expands to /data/state, and state_dir is also /data/state
        // Should not be duplicated
        let count = policy
            .writable_paths
            .iter()
            .filter(|p| *p == &PathBuf::from("/data/state"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_create_sandbox_returns_linux() {
        let sandbox = create_sandbox().unwrap();
        assert_eq!(sandbox.platform_name(), "linux");
        assert!(sandbox.is_available());
    }

    #[test]
    fn test_noop_sandbox_verify_file_access() {
        let sandbox = NoOpSandbox;
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        // NoOp always allows
        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/anything"), true)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/anything"), false)
                .is_ok()
        );
    }

    #[test]
    fn test_noop_sandbox_verify_exec_and_network() {
        let sandbox = NoOpSandbox;
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(sandbox.verify_exec_allowed(&policy).is_ok());
        assert!(sandbox.verify_network_blocked(&policy).is_ok());
    }

    #[test]
    fn test_compiled_policy_serde_roundtrip() {
        let section = test_sandbox_section();
        let state_dir = Some(PathBuf::from("/tmp/state"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();

        let json = serde_json::to_string(&policy).unwrap();
        let roundtrip: CompiledPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtrip.profile, policy.profile);
        assert_eq!(roundtrip.memory_limit_bytes, policy.memory_limit_bytes);
        assert_eq!(roundtrip.cpu_percent, policy.cpu_percent);
        assert_eq!(roundtrip.deny_exec, policy.deny_exec);
        assert_eq!(roundtrip.deny_ptrace, policy.deny_ptrace);
        assert_eq!(roundtrip.block_direct_network, policy.block_direct_network);
    }

    #[test]
    fn test_platform_flags_serde_roundtrip() {
        let flags = PlatformFlags {
            linux_use_landlock: true,
            linux_use_userns: true,
            macos_entitlements: vec!["com.apple.security.network.client".into()],
            windows_low_integrity: true,
        };

        let json = serde_json::to_string(&flags).unwrap();
        let roundtrip: PlatformFlags = serde_json::from_str(&json).unwrap();

        assert!(roundtrip.linux_use_landlock);
        assert!(roundtrip.linux_use_userns);
        assert_eq!(roundtrip.macos_entitlements.len(), 1);
        assert!(roundtrip.windows_low_integrity);
    }
}
