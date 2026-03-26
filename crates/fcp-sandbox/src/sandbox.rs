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

use std::path::{Path, PathBuf};
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
        // Validate resource limits — zero values make execution impossible
        if section.memory_mb == 0 {
            return Err(SandboxError::InvalidConfig(
                "memory_mb must be > 0: zero memory limit makes execution impossible".into(),
            ));
        }
        if section.wall_clock_timeout_ms == 0 {
            return Err(SandboxError::InvalidConfig(
                "wall_clock_timeout_ms must be > 0: zero timeout makes execution impossible".into(),
            ));
        }
        if section.cpu_percent == 0 {
            return Err(SandboxError::InvalidConfig(
                "cpu_percent must be > 0: zero CPU makes execution impossible".into(),
            ));
        }
        if section.cpu_percent > 100 {
            return Err(SandboxError::InvalidConfig(format!(
                "cpu_percent must be <= 100, got {}: invalid percentage",
                section.cpu_percent
            )));
        }

        // Expand special paths
        let readonly_paths = compile_paths(
            &section.fs_readonly_paths,
            state_dir.as_ref(),
            "sandbox.fs_readonly_paths",
        )?;

        let mut writable_paths = compile_paths(
            &section.fs_writable_paths,
            state_dir.as_ref(),
            "sandbox.fs_writable_paths",
        )?;

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
fn compile_paths(
    paths: &[String],
    state_dir: Option<&PathBuf>,
    field_name: &str,
) -> Result<Vec<PathBuf>, SandboxError> {
    let mut compiled = Vec::with_capacity(paths.len());

    for path in paths {
        match expand_path(path, state_dir) {
            Ok(Some(expanded)) => compiled.push(expanded),
            Ok(None) => {}
            Err(message) => {
                return Err(SandboxError::PolicyCompilationFailed(format!(
                    "invalid {field_name} entry `{path}`: {message}"
                )));
            }
        }
    }

    Ok(compiled)
}

fn expand_path(path: &str, state_dir: Option<&PathBuf>) -> Result<Option<PathBuf>, &'static str> {
    validate_manifest_path(path)?;

    Ok(path.strip_prefix("$CONNECTOR_STATE/").map_or_else(
        || {
            if path == "$CONNECTOR_STATE" {
                state_dir.cloned()
            } else {
                Some(PathBuf::from(path))
            }
        },
        |suffix| state_dir.map(|sd| sd.join(suffix)),
    ))
}

fn validate_manifest_path(path: &str) -> Result<(), &'static str> {
    if path == "$CONNECTOR_STATE" {
        return Ok(());
    }

    if let Some(suffix) = path.strip_prefix("$CONNECTOR_STATE/") {
        return validate_connector_state_subpath(suffix);
    }

    if is_manifest_absolute_path(path) {
        return Ok(());
    }

    Err("paths must be absolute or use `$CONNECTOR_STATE[/subpath]`")
}

fn validate_connector_state_subpath(suffix: &str) -> Result<(), &'static str> {
    for component in Path::new(suffix).components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err("`$CONNECTOR_STATE` subpaths must contain only normal path components");
        }
    }

    Ok(())
}

fn is_manifest_absolute_path(path: &str) -> bool {
    Path::new(path).is_absolute()
        || path.starts_with('/')
        || path.starts_with(r"\\")
        || path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && matches!(path.as_bytes().get(1), Some(b':'))
            && matches!(path.as_bytes().get(2), Some(b'\\' | b'/'))
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

    /// Apply the sandbox to a child process being spawned via `std::process::Command`.
    ///
    /// This should hook into the command setup (e.g., using `pre_exec` on Unix) to
    /// ensure the child process is fully sandboxed before executing the payload.
    /// Default implementation relies on the connector binary to invoke `apply()` itself,
    /// but platform-specific implementations (e.g., Linux namespaces, macOS seatbelt)
    /// may override this to enforce sandboxing immediately from the host.
    fn apply_to_command(
        &self,
        cmd: &mut std::process::Command,
        policy: &CompiledPolicy,
    ) -> Result<(), SandboxError> {
        let _ = (cmd, policy);
        Ok(())
    }

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

/// Normalize a path lexically without resolving symlinks or checking existence.
/// Resolves `.` and `..` components.
#[must_use]
pub fn normalize_path(path: &std::path::Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                let last = out.components().next_back();
                match last {
                    Some(std::path::Component::Normal(_)) => {
                        out.pop();
                    }
                    Some(std::path::Component::RootDir) => {
                        // At root, .. does nothing
                    }
                    _ => {
                        // Either empty, prefix, or another ..
                        out.push(std::path::Component::ParentDir);
                    }
                }
            }
            std::path::Component::CurDir => {}
            _ => out.push(comp),
        }
    }
    out
}

/// Resolve a path for policy checks, even when the leaf path does not exist yet.
///
/// This canonicalizes the full path when possible. If the leaf is missing, it
/// canonicalizes the nearest existing ancestor and then appends the unresolved
/// suffix. That keeps policy checks aligned with where the kernel will actually
/// traverse, including symlink-plus-`..` semantics in existing ancestors.
#[must_use]
pub fn resolve_policy_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }

        if let Ok(canonical_ancestor) = ancestor.canonicalize() {
            let unresolved_suffix = path
                .strip_prefix(ancestor)
                .unwrap_or_else(|_| Path::new(""));
            return normalize_path(&canonical_ancestor.join(unresolved_suffix));
        }
    }

    if path.is_relative() {
        if let Ok(cwd) = std::env::current_dir() {
            return normalize_path(&cwd.join(path));
        }
    }

    normalize_path(path)
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

    fn apply_to_command(
        &self,
        cmd: &mut std::process::Command,
        policy: &CompiledPolicy,
    ) -> Result<(), SandboxError> {
        let _ = (cmd, policy);
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
        // NoOp intentionally skips all policy enforcement. Callers that need
        // path validation must use a real platform backend.
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
                .iter()
                .any(|p| p.as_path() == Path::new("/var/lib/fcp/connectors/test"))
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
            Ok(Some(PathBuf::from("/var/lib/fcp/state")))
        );

        assert_eq!(
            expand_path("$CONNECTOR_STATE/data", Some(&state_dir)),
            Ok(Some(PathBuf::from("/var/lib/fcp/state/data")))
        );

        assert_eq!(
            expand_path("/usr/lib", Some(&state_dir)),
            Ok(Some(PathBuf::from("/usr/lib")))
        );

        assert_eq!(expand_path("$CONNECTOR_STATE", None), Ok(None));
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
            Ok(Some(PathBuf::from("/data/state/db/main.sqlite")))
        );
    }

    #[test]
    fn test_expand_path_absolute_ignores_state_dir() {
        let state_dir = PathBuf::from("/data/state");
        assert_eq!(
            expand_path("/etc/hosts", Some(&state_dir)),
            Ok(Some(PathBuf::from("/etc/hosts")))
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
                .iter()
                .any(|p| p.as_path() == Path::new("/data/state"))
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
            .filter(|p| p.as_path() == Path::new("/data/state"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_create_sandbox_returns_platform_backend() {
        let sandbox = create_sandbox().unwrap();
        let expected = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            panic!("test_create_sandbox_returns_platform_backend is unsupported on this platform");
        };

        assert_eq!(sandbox.platform_name(), expected);
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

    #[cfg(unix)]
    #[test]
    fn test_resolve_policy_path_rejects_symlink_escape_for_missing_leaf() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Canonicalize temp_dir to resolve macOS symlinks (/var → /private/var)
        // so that policy path comparisons use consistent prefixes.
        let base = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!(
                "fcp-sandbox-path-resolution-{}-{unique}",
                std::process::id()
            ));
        let allowed = base.join("allowed");
        let escaped = base.join("escaped");
        let link = allowed.join("link");
        let pending_write = link.join("future.txt");

        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&escaped).unwrap();
        symlink(&escaped, &link).unwrap();

        assert_eq!(
            resolve_policy_path(&pending_write),
            escaped.join("future.txt")
        );

        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 256,
            cpu_percent: 50,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: Vec::new(),
            fs_writable_paths: vec![allowed.display().to_string()],
            deny_exec: true,
            deny_ptrace: true,
        };
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        let sandbox = create_sandbox().unwrap();

        let result = sandbox.verify_file_access(&policy, &pending_write, true);
        assert!(
            result.is_err(),
            "symlinked existing ancestors must not bypass writable path checks",
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_resolve_policy_path_preserves_symlink_parent_semantics() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "fcp-sandbox-symlink-parent-{}-{unique}",
            std::process::id()
        ));
        let allowed = base.join("allowed");
        let escaped = base.join("escaped");
        let link = allowed.join("link");
        let sneaky_write = link.join("..").join("future.txt");

        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&escaped).unwrap();
        symlink(&escaped, &link).unwrap();

        let expected = sneaky_write
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            .expect("parent with symlink and .. should canonicalize")
            .join("future.txt");

        assert_eq!(resolve_policy_path(&sneaky_write), expected);
        assert_ne!(
            expected,
            allowed.join("future.txt"),
            "symlink parent traversal must not collapse lexically inside the allowed tree",
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

    // ── New tests: CompiledPolicy clone + debug ──

    #[test]
    fn test_compiled_policy_clone() {
        let section = test_sandbox_section();
        let state_dir = Some(PathBuf::from("/tmp/clone-test"));
        let original = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
        let cloned = original.clone();
        assert_eq!(original.profile, cloned.profile);
        assert_eq!(original.memory_limit_bytes, cloned.memory_limit_bytes);
        assert_eq!(original.cpu_percent, cloned.cpu_percent);
        assert_eq!(original.wall_clock_timeout, cloned.wall_clock_timeout);
        assert_eq!(original.readonly_paths, cloned.readonly_paths);
        assert_eq!(original.writable_paths, cloned.writable_paths);
        assert_eq!(original.deny_exec, cloned.deny_exec);
        assert_eq!(original.deny_ptrace, cloned.deny_ptrace);
        assert_eq!(original.block_direct_network, cloned.block_direct_network);
        assert_eq!(original.state_dir, cloned.state_dir);
    }

    #[test]
    fn test_compiled_policy_debug() {
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        let debug = format!("{policy:?}");
        assert!(debug.contains("CompiledPolicy"));
        assert!(debug.contains("Strict"));
    }

    #[test]
    fn test_platform_flags_clone() {
        let original = PlatformFlags {
            linux_use_landlock: true,
            linux_use_userns: true,
            macos_entitlements: vec!["ent1".into(), "ent2".into()],
            windows_low_integrity: true,
        };
        let cloned = original.clone();
        assert_eq!(original.linux_use_landlock, cloned.linux_use_landlock);
        assert_eq!(original.linux_use_userns, cloned.linux_use_userns);
        assert_eq!(original.macos_entitlements, cloned.macos_entitlements);
        assert_eq!(original.windows_low_integrity, cloned.windows_low_integrity);
    }

    #[test]
    fn test_platform_flags_debug() {
        let flags = PlatformFlags::default();
        let debug = format!("{flags:?}");
        assert!(debug.contains("PlatformFlags"));
    }

    #[test]
    fn test_compiled_policy_no_state_dir() {
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.state_dir.is_none());
        // $CONNECTOR_STATE paths should be skipped when state_dir is None
        assert!(
            !policy
                .writable_paths
                .iter()
                .any(|p| p.display().to_string().contains("CONNECTOR_STATE"))
        );
    }

    #[test]
    fn test_compiled_policy_memory_conversion() {
        let mut section = test_sandbox_section();
        section.memory_mb = 1024;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.memory_limit_bytes, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_compiled_policy_wall_clock_conversion() {
        let mut section = test_sandbox_section();
        section.wall_clock_timeout_ms = 60_000;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.wall_clock_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_compiled_policy_zero_memory() {
        let mut section = test_sandbox_section();
        section.memory_mb = 0;
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig(_)));
        assert!(err.to_string().contains("memory_mb"));
    }

    #[test]
    fn test_compiled_policy_max_cpu() {
        let mut section = test_sandbox_section();
        section.cpu_percent = 100;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.cpu_percent, 100);
    }

    #[test]
    fn test_compiled_policy_min_cpu() {
        let mut section = test_sandbox_section();
        section.cpu_percent = 1;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.cpu_percent, 1);
    }

    #[test]
    fn test_compiled_policy_zero_cpu() {
        let mut section = test_sandbox_section();
        section.cpu_percent = 0;
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig(_)));
        assert!(err.to_string().contains("cpu_percent"));
    }

    #[test]
    fn test_compiled_policy_cpu_over_100() {
        let mut section = test_sandbox_section();
        section.cpu_percent = 101;
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig(_)));
        assert!(err.to_string().contains("cpu_percent"));
        assert!(err.to_string().contains("101"));
    }

    #[test]
    fn test_compiled_policy_cpu_max_u8() {
        let mut section = test_sandbox_section();
        section.cpu_percent = 255;
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig(_)));
        assert!(err.to_string().contains("255"));
    }

    #[test]
    fn test_expand_path_no_state_dir_prefix() {
        // A path that starts with $CONNECTOR_STATE/ but state_dir is None
        assert_eq!(expand_path("$CONNECTOR_STATE/data", None), Ok(None));
    }

    #[test]
    fn test_expand_path_regular_path_no_state_dir() {
        // Regular paths don't need state_dir
        assert_eq!(
            expand_path("/etc/config", None),
            Ok(Some(PathBuf::from("/etc/config")))
        );
    }

    #[test]
    fn test_expand_path_nested_subpath() {
        let state_dir = PathBuf::from("/data");
        assert_eq!(
            expand_path("$CONNECTOR_STATE/a/b/c/d", Some(&state_dir)),
            Ok(Some(PathBuf::from("/data/a/b/c/d")))
        );
    }

    #[test]
    fn test_noop_sandbox_debug() {
        let sandbox = NoOpSandbox;
        let debug = format!("{sandbox:?}");
        assert!(debug.contains("NoOpSandbox"));
    }

    #[test]
    fn test_noop_sandbox_apply_to_command() {
        let sandbox = NoOpSandbox;
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        let mut cmd = std::process::Command::new("echo");
        assert!(sandbox.apply_to_command(&mut cmd, &policy).is_ok());
    }

    #[test]
    fn test_compiled_policy_serde_with_platform_flags() {
        let section = test_sandbox_section();
        let flags = PlatformFlags {
            linux_use_landlock: true,
            linux_use_userns: false,
            macos_entitlements: vec!["com.apple.security.app-sandbox".into()],
            windows_low_integrity: true,
        };
        let policy = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags);
        let json = serde_json::to_string(&policy).unwrap();
        let roundtrip: CompiledPolicy = serde_json::from_str(&json).unwrap();
        assert!(roundtrip.platform_flags.linux_use_landlock);
        assert!(!roundtrip.platform_flags.linux_use_userns);
        assert_eq!(roundtrip.platform_flags.macos_entitlements.len(), 1);
        assert!(roundtrip.platform_flags.windows_low_integrity);
    }

    #[test]
    fn test_platform_flags_serde_defaults_omitted() {
        // Default flags deserialized from empty JSON object
        let json = "{}";
        let flags: PlatformFlags = serde_json::from_str(json).unwrap();
        assert!(flags.is_empty());
    }

    #[test]
    fn test_compiled_policy_multiple_readonly_paths() {
        let mut section = test_sandbox_section();
        section.fs_readonly_paths =
            vec!["/usr".into(), "/lib".into(), "/opt".into(), "/etc".into()];
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.readonly_paths.len(), 4);
    }

    #[test]
    fn test_compiled_policy_multiple_writable_paths_with_state() {
        let mut section = test_sandbox_section();
        section.fs_writable_paths = vec![
            "$CONNECTOR_STATE".into(),
            "$CONNECTOR_STATE/cache".into(),
            "/tmp/scratch".into(),
        ];
        let state_dir = Some(PathBuf::from("/var/state"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
        assert!(policy.writable_paths.contains(&PathBuf::from("/var/state")));
        assert!(
            policy
                .writable_paths
                .contains(&PathBuf::from("/var/state/cache"))
        );
        assert!(
            policy
                .writable_paths
                .contains(&PathBuf::from("/tmp/scratch"))
        );
    }

    #[test]
    fn test_sandbox_error_debug() {
        let e = SandboxError::Timeout;
        let debug = format!("{e:?}");
        assert!(debug.contains("Timeout"));
    }

    #[test]
    fn test_sandbox_error_io_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no access");
        let e: SandboxError = io_err.into();
        assert!(e.to_string().contains("no access"));
    }

    #[test]
    fn test_compiled_policy_strict_plus_blocks_network() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::StrictPlus;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.block_direct_network);
    }

    #[test]
    fn test_compiled_policy_moderate_blocks_network() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Moderate;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.block_direct_network);
    }

    // ── New batch: SandboxError display and debug additional variants ──

    #[test]
    fn test_sandbox_error_unsupported_platform_display() {
        let e = SandboxError::UnsupportedPlatform("haiku".into());
        let msg = e.to_string();
        assert!(msg.contains("haiku"));
        assert!(msg.contains("not supported"));
    }

    #[test]
    fn test_sandbox_error_policy_compilation_display() {
        let e = SandboxError::PolicyCompilationFailed("invalid path".into());
        let msg = e.to_string();
        assert!(msg.contains("invalid path"));
        assert!(msg.contains("compile"));
    }

    #[test]
    fn test_sandbox_error_apply_failed_display() {
        let e = SandboxError::ApplyFailed("seccomp rejected".into());
        let msg = e.to_string();
        assert!(msg.contains("seccomp rejected"));
        assert!(msg.contains("apply"));
    }

    #[test]
    fn test_sandbox_error_resource_limit_display() {
        let e = SandboxError::ResourceLimitExceeded("cpu time".into());
        let msg = e.to_string();
        assert!(msg.contains("cpu time"));
    }

    #[test]
    fn test_sandbox_error_invalid_config_display() {
        let e = SandboxError::InvalidConfig("cpu_percent > 100".into());
        let msg = e.to_string();
        assert!(msg.contains("cpu_percent > 100"));
    }

    #[test]
    fn test_sandbox_error_syscall_display() {
        let e = SandboxError::SyscallFailed("prctl(PR_SET_NO_NEW_PRIVS)".into());
        let msg = e.to_string();
        assert!(msg.contains("prctl"));
    }

    #[test]
    fn test_sandbox_error_timeout_display() {
        let e = SandboxError::Timeout;
        let msg = e.to_string();
        assert!(msg.contains("timeout"));
    }

    #[test]
    fn test_sandbox_error_io_permission_denied() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let e: SandboxError = io_err.into();
        let msg = e.to_string();
        assert!(msg.contains("access denied"));
    }

    #[test]
    fn test_sandbox_error_io_not_found() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e: SandboxError = io_err.into();
        let msg = e.to_string();
        assert!(msg.contains("file missing"));
    }

    #[test]
    fn test_sandbox_error_debug_all_variants() {
        let errors: Vec<SandboxError> = vec![
            SandboxError::UnsupportedPlatform("os".into()),
            SandboxError::PolicyCompilationFailed("x".into()),
            SandboxError::ApplyFailed("y".into()),
            SandboxError::ResourceLimitExceeded("z".into()),
            SandboxError::InvalidConfig("a".into()),
            SandboxError::SyscallFailed("b".into()),
            SandboxError::Timeout,
        ];
        for err in &errors {
            let dbg = format!("{err:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── New batch: PlatformFlags edge cases ──

    #[test]
    fn test_platform_flags_with_multiple_entitlements() {
        let flags = PlatformFlags {
            linux_use_landlock: false,
            linux_use_userns: false,
            macos_entitlements: vec![
                "com.apple.security.app-sandbox".into(),
                "com.apple.security.network.client".into(),
                "com.apple.security.files.user-selected.read-only".into(),
            ],
            windows_low_integrity: false,
        };
        assert!(!flags.is_empty());
        assert_eq!(flags.macos_entitlements.len(), 3);
    }

    #[test]
    fn test_platform_flags_all_fields_set() {
        let flags = PlatformFlags {
            linux_use_landlock: true,
            linux_use_userns: true,
            macos_entitlements: vec!["ent".into()],
            windows_low_integrity: true,
        };
        assert!(!flags.is_empty());
        let json = serde_json::to_string(&flags).unwrap();
        let rt: PlatformFlags = serde_json::from_str(&json).unwrap();
        assert!(rt.linux_use_landlock);
        assert!(rt.linux_use_userns);
        assert_eq!(rt.macos_entitlements.len(), 1);
        assert!(rt.windows_low_integrity);
    }

    #[test]
    fn test_platform_flags_serde_partial_fields() {
        // Only some fields present in JSON; rest should default
        let json = r#"{"linux_use_landlock": true}"#;
        let flags: PlatformFlags = serde_json::from_str(json).unwrap();
        assert!(flags.linux_use_landlock);
        assert!(!flags.linux_use_userns);
        assert!(flags.macos_entitlements.is_empty());
        assert!(!flags.windows_low_integrity);
    }

    // ── New batch: CompiledPolicy edge cases ──

    #[test]
    fn test_compiled_policy_empty_readonly_and_writable() {
        let mut section = test_sandbox_section();
        section.fs_readonly_paths = vec![];
        section.fs_writable_paths = vec![];
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.readonly_paths.is_empty());
        assert!(policy.writable_paths.is_empty());
    }

    #[test]
    fn test_compiled_policy_zero_timeout() {
        let mut section = test_sandbox_section();
        section.wall_clock_timeout_ms = 0;
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig(_)));
        assert!(err.to_string().contains("wall_clock_timeout_ms"));
    }

    #[test]
    fn test_compiled_policy_large_memory() {
        let mut section = test_sandbox_section();
        section.memory_mb = 32_768; // 32 GB
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.memory_limit_bytes, 32_768 * 1024 * 1024);
    }

    #[test]
    fn test_compiled_policy_serde_json_roundtrip_all_fields() {
        let section = test_sandbox_section();
        let state_dir = Some(PathBuf::from("/var/data"));
        let flags = PlatformFlags {
            linux_use_landlock: true,
            linux_use_userns: false,
            macos_entitlements: vec!["ent".into()],
            windows_low_integrity: true,
        };
        let policy = CompiledPolicy::from_manifest(&section, state_dir)
            .unwrap()
            .with_platform_flags(flags);
        let json = serde_json::to_string_pretty(&policy).unwrap();
        let rt: CompiledPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.profile, policy.profile);
        assert_eq!(rt.memory_limit_bytes, policy.memory_limit_bytes);
        assert_eq!(rt.cpu_percent, policy.cpu_percent);
        assert_eq!(rt.deny_exec, policy.deny_exec);
        assert_eq!(rt.deny_ptrace, policy.deny_ptrace);
        assert_eq!(rt.block_direct_network, policy.block_direct_network);
        assert_eq!(rt.state_dir, policy.state_dir);
        assert!(rt.platform_flags.linux_use_landlock);
        assert!(rt.platform_flags.windows_low_integrity);
    }

    // ── New batch: expand_path edge cases ──

    #[test]
    fn test_expand_path_state_dir_with_deep_nesting() {
        let sd = PathBuf::from("/mnt/data");
        assert_eq!(
            expand_path("$CONNECTOR_STATE/a/b/c/d/e/f", Some(&sd)),
            Ok(Some(PathBuf::from("/mnt/data/a/b/c/d/e/f")))
        );
    }

    #[test]
    fn test_expand_path_rejects_unknown_dollar_prefix() {
        let err = expand_path("$HOME/data", None).unwrap_err();
        assert!(err.contains("absolute"));
    }

    #[test]
    fn test_expand_path_rejects_relative_path() {
        let err = expand_path("relative/path", None).unwrap_err();
        assert!(err.contains("absolute"));
    }

    #[test]
    fn test_expand_path_rejects_connector_state_parent_escape() {
        let err =
            expand_path("$CONNECTOR_STATE/../cache", Some(&PathBuf::from("/state"))).unwrap_err();
        assert!(err.contains("normal path components"));
    }

    #[test]
    fn test_compiled_policy_rejects_relative_paths() {
        let mut section = test_sandbox_section();
        section.fs_readonly_paths = vec!["relative/path".into()];
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::PolicyCompilationFailed(_)));
        assert!(err.to_string().contains("fs_readonly_paths"));
    }

    #[test]
    fn test_compiled_policy_rejects_connector_state_escape() {
        let mut section = test_sandbox_section();
        section.fs_writable_paths = vec!["$CONNECTOR_STATE/../cache".into()];
        let err =
            CompiledPolicy::from_manifest(&section, Some(PathBuf::from("/state"))).unwrap_err();
        assert!(matches!(err, SandboxError::PolicyCompilationFailed(_)));
        assert!(err.to_string().contains("normal path components"));
    }

    // ── New batch: NoOpSandbox default trait ──

    #[test]
    fn test_noop_sandbox_default_trait() {
        let sandbox = NoOpSandbox;
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "noop");
    }

    #[test]
    fn test_noop_sandbox_verify_all_operations() {
        let sandbox = NoOpSandbox;
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();

        // All verifications should pass for NoOp
        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/etc/secret"), true)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/nonexistent"), false)
                .is_ok()
        );
        assert!(sandbox.verify_exec_allowed(&policy).is_ok());
        assert!(sandbox.verify_network_blocked(&policy).is_ok());
        assert!(sandbox.apply(&policy).is_ok());
    }
}
