//! OS-level sandbox enforcement.
//!
//! This module provides platform-specific process isolation for FCP connectors.
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

use std::collections::BTreeSet;
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

/// Windows `AppContainer` capability that allows outbound client sockets.
pub const WINDOWS_APPCONTAINER_INTERNET_CLIENT: &str = "internetClient";

/// Windows `AppContainer` capability that allows inbound and outbound internet sockets.
pub const WINDOWS_APPCONTAINER_INTERNET_CLIENT_SERVER: &str = "internetClientServer";

/// Windows `AppContainer` capability that allows private-network client/server sockets.
pub const WINDOWS_APPCONTAINER_PRIVATE_NETWORK_CLIENT_SERVER: &str = "privateNetworkClientServer";

const WINDOWS_APPCONTAINER_PROFILE_PREFIX: &str = "fcp";
const WINDOWS_APPCONTAINER_PROFILE_NAME_MAX_LEN: usize = 64;
const WINDOWS_APPCONTAINER_PROFILE_HASH_LEN: usize = 16;
const WINDOWS_NETWORK_APPCONTAINER_CAPABILITIES: [&str; 3] = [
    WINDOWS_APPCONTAINER_INTERNET_CLIENT,
    WINDOWS_APPCONTAINER_INTERNET_CLIENT_SERVER,
    WINDOWS_APPCONTAINER_PRIVATE_NETWORK_CLIENT_SERVER,
];

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

    /// Windows: `AppContainer` capability names to grant when launching under `AppContainer`.
    ///
    /// Network capabilities are rejected for strict/moderate profiles because those profiles
    /// require all egress to pass through Network Guard. Permissive profiles get
    /// [`WINDOWS_APPCONTAINER_INTERNET_CLIENT`] by default when this list omits an explicit
    /// network capability.
    #[serde(default)]
    pub windows_appcontainer_capabilities: Vec<String>,
}

impl PlatformFlags {
    /// Check if all platform flags are at their default values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.linux_use_landlock
            && !self.linux_use_userns
            && self.macos_entitlements.is_empty()
            && !self.windows_low_integrity
            && self.windows_appcontainer_capabilities.is_empty()
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

    /// Return the normalized Windows `AppContainer` capabilities implied by this policy.
    pub fn windows_appcontainer_capabilities(&self) -> Result<Vec<String>, SandboxError> {
        let mut requested = self
            .platform_flags
            .windows_appcontainer_capabilities
            .clone();
        if !self.block_direct_network
            && !requested
                .iter()
                .any(|capability| is_windows_network_appcontainer_capability(capability.trim()))
        {
            requested.push(WINDOWS_APPCONTAINER_INTERNET_CLIENT.to_owned());
        }

        let capabilities = normalize_windows_appcontainer_capabilities(&requested)?;
        if self.block_direct_network {
            for capability in &capabilities {
                if is_windows_network_appcontainer_capability(capability) {
                    return Err(SandboxError::InvalidConfig(format!(
                        "windows AppContainer capability `{capability}` conflicts with sandbox profile {:?}: direct network must remain blocked",
                        self.profile
                    )));
                }
            }
        }

        Ok(capabilities)
    }

    /// Build the deterministic Windows `AppContainer` profile metadata for a connector.
    pub fn windows_appcontainer_profile(
        &self,
        connector_id: &str,
    ) -> Result<WindowsAppContainerProfile, SandboxError> {
        WindowsAppContainerProfile::from_policy(connector_id, self)
    }
}

/// Deterministic Windows `AppContainer` profile metadata derived from an FCP sandbox policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsAppContainerProfile {
    /// `AppContainer` profile name. Windows requires at most 64 characters matching
    /// `[-_. A-Za-z0-9]+`.
    pub name: String,

    /// Capability names that will be resolved to `AppContainer` capability SIDs.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Result from attempting to create a Windows `AppContainer` profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppContainerCreateOutcome {
    /// A new per-user profile was created.
    Created,
    /// The profile already existed and should be resolved by name.
    AlreadyExists,
}

/// High-level lifecycle action taken for a Windows `AppContainer` profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppContainerLifecycleAction {
    /// The operator has not enabled the Windows `AppContainer` launch path.
    SkippedInactive,
    /// A new profile was created.
    Created,
    /// An existing profile SID was resolved and reused.
    ReusedExisting,
    /// The profile metadata was valid, but the requested launch mechanism is unsupported.
    LaunchPathUnsupported,
}

/// Cleanup decision for a Windows `AppContainer` lifecycle attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppContainerCleanupDecision {
    /// No profile was created or opened.
    None,
    /// The profile is retained for deterministic connector-instance reuse.
    RetainProfile,
    /// The profile was removed by an explicit smoke-test cleanup pass.
    DeleteProfile,
}

/// Fakeable profile API used by the Windows backend lifecycle controller.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
pub(super) trait WindowsAppContainerProfileApi {
    /// Create the profile, or report that it already exists.
    fn create_profile(
        &mut self,
        profile: &WindowsAppContainerProfile,
    ) -> Result<WindowsAppContainerCreateOutcome, SandboxError>;

    /// Resolve the SID for an existing profile.
    fn derive_profile_sid(&mut self, profile_name: &str) -> Result<(), SandboxError>;

    /// Delete the profile for smoke/e2e cleanup.
    fn delete_profile(&mut self, profile_name: &str) -> Result<(), SandboxError>;
}

/// Structured report for Windows `AppContainer` profile preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsAppContainerLifecycleReport {
    /// Profile metadata used by the lifecycle operation.
    pub profile: WindowsAppContainerProfile,
    /// Lifecycle action taken.
    pub action: WindowsAppContainerLifecycleAction,
    /// Whether an `AppContainer` SID was obtained or resolved.
    pub sid_present: bool,
    /// Cleanup choice made by the lifecycle controller.
    pub cleanup: WindowsAppContainerCleanupDecision,
    /// Structured skip reason when no OS call was attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

#[cfg(any(test, target_os = "windows"))]
impl WindowsAppContainerLifecycleReport {
    fn inactive(profile: WindowsAppContainerProfile) -> Self {
        Self {
            profile,
            action: WindowsAppContainerLifecycleAction::SkippedInactive,
            sid_present: false,
            cleanup: WindowsAppContainerCleanupDecision::None,
            skip_reason: Some(
                "windows_appcontainer_not_active_createprocessasuser_path_unwired".to_owned(),
            ),
        }
    }

    const fn active(
        profile: WindowsAppContainerProfile,
        action: WindowsAppContainerLifecycleAction,
    ) -> Self {
        Self {
            profile,
            action,
            sid_present: true,
            cleanup: WindowsAppContainerCleanupDecision::RetainProfile,
            skip_reason: None,
        }
    }
}

/// Run Windows `AppContainer` profile create/reuse logic through a fakeable API.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
pub(super) fn prepare_windows_appcontainer_lifecycle<A>(
    profile: WindowsAppContainerProfile,
    appcontainer_active: bool,
    api: &mut A,
) -> Result<WindowsAppContainerLifecycleReport, SandboxError>
where
    A: WindowsAppContainerProfileApi,
{
    if !appcontainer_active {
        return Ok(WindowsAppContainerLifecycleReport::inactive(profile));
    }

    match api.create_profile(&profile)? {
        WindowsAppContainerCreateOutcome::Created => {
            Ok(WindowsAppContainerLifecycleReport::active(
                profile,
                WindowsAppContainerLifecycleAction::Created,
            ))
        }
        WindowsAppContainerCreateOutcome::AlreadyExists => {
            api.derive_profile_sid(&profile.name)?;
            Ok(WindowsAppContainerLifecycleReport::active(
                profile,
                WindowsAppContainerLifecycleAction::ReusedExisting,
            ))
        }
    }
}

/// Delete a Windows `AppContainer` profile through the fakeable profile API.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
#[allow(dead_code)]
pub(super) fn cleanup_windows_appcontainer_profile<A>(
    profile_name: &str,
    api: &mut A,
) -> Result<WindowsAppContainerCleanupDecision, SandboxError>
where
    A: WindowsAppContainerProfileApi,
{
    validate_windows_appcontainer_profile_name(profile_name)?;
    api.delete_profile(profile_name)?;
    Ok(WindowsAppContainerCleanupDecision::DeleteProfile)
}

/// Redaction-safe JSONL evidence for Windows `AppContainer` smoke/skips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsAppContainerEvidence {
    /// Schema marker for downstream evidence validators.
    pub schema: &'static str,
    /// Operating-system family for this evidence record.
    pub os: &'static str,
    /// Hashed connector id or connector seed.
    pub connector_id_hash: String,
    /// Hashed `AppContainer` profile name.
    pub profile_name_hash: String,
    /// Capability names after normalization and deny-policy checks.
    pub capabilities: Vec<String>,
    /// Capability mapping decision.
    pub capability_decision: &'static str,
    /// Lifecycle action result.
    pub lifecycle_action: WindowsAppContainerLifecycleAction,
    /// Whether an `AppContainer` SID was present.
    pub sid_present: bool,
    /// Whether the job object was attached after lifecycle preparation.
    pub job_object_attached: bool,
    /// Stable step ordering for appcontainer -> job-object enforcement.
    pub step_order: Vec<&'static str>,
    /// Final result string for the scripted/e2e action.
    pub action_result: &'static str,
    /// Cleanup decision.
    pub cleanup: WindowsAppContainerCleanupDecision,
    /// Structured skip reason when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

impl WindowsAppContainerEvidence {
    /// Build redaction-safe evidence from a lifecycle report.
    #[must_use]
    pub fn from_lifecycle(
        connector_id: &str,
        report: &WindowsAppContainerLifecycleReport,
        job_object_attached: bool,
        action_result: &'static str,
    ) -> Self {
        let mut step_order = vec!["appcontainer_lifecycle"];
        if job_object_attached {
            step_order.push("job_object_attach");
        }

        Self {
            schema: "fcp.windows_appcontainer_smoke.v1",
            os: "windows",
            connector_id_hash: stable_fnv1a64_hex(connector_id),
            profile_name_hash: stable_fnv1a64_hex(&report.profile.name),
            capabilities: report.profile.capabilities.clone(),
            capability_decision: if report.profile.capabilities.is_empty() {
                "none_required"
            } else {
                "mapped"
            },
            lifecycle_action: report.action,
            sid_present: report.sid_present,
            job_object_attached,
            step_order,
            action_result,
            cleanup: report.cleanup,
            skip_reason: report.skip_reason.clone(),
        }
    }

    /// Render this record as a single JSONL line.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Process-launch mechanism selected for Windows `AppContainer` enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppContainerProcessLaunchMechanism {
    /// No process launch was attempted because `AppContainer` launch is inactive.
    SkippedInactive,
    /// `STARTUPINFOEX` security-capability attributes are used for launch.
    StartupInfoExSecurityCapabilities,
    /// `std::process::Command` mutation cannot carry `AppContainer` attributes.
    UnsupportedStdCommandMutation,
}

/// Intended job-object attachment for a Windows `AppContainer` launched process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsJobObjectAttachmentIntent {
    /// No child process is expected, so no job object attachment is planned.
    None,
    /// Attach the launched child process to a configured job object immediately after launch.
    AttachAfterLaunch,
}

/// Redaction-safe JSONL evidence for Windows `AppContainer` process-launch readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsAppContainerProcessLaunchEvidence {
    /// Schema marker for downstream evidence validators.
    pub schema: &'static str,
    /// Operating-system family for this evidence record.
    pub os: &'static str,
    /// Hashed connector id or connector seed.
    pub connector_id_hash: String,
    /// Hashed `AppContainer` profile name.
    pub profile_name_hash: String,
    /// Capability names after normalization and deny-policy checks.
    pub capabilities: Vec<String>,
    /// Capability mapping decision.
    pub capability_decision: &'static str,
    /// Profile lifecycle action observed before launch.
    pub lifecycle_action: WindowsAppContainerLifecycleAction,
    /// Whether an `AppContainer` SID was present for launch.
    pub sid_present: bool,
    /// Launch mechanism selected by the Windows sandbox.
    pub launch_mechanism: WindowsAppContainerProcessLaunchMechanism,
    /// Whether a process was actually attached to a job object.
    pub job_object_attached: bool,
    /// Expected job-object attachment behavior.
    pub job_object_attachment_intent: WindowsJobObjectAttachmentIntent,
    /// Hashed launched process id when a child process was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id_hash: Option<String>,
    /// Final readiness layer this evidence is allowed to claim today.
    pub final_filter_strength: FilterStrength,
    /// Stable step ordering for lifecycle, launch, and job attachment.
    pub step_order: Vec<&'static str>,
    /// Final result string for the scripted/e2e action.
    pub action_result: &'static str,
    /// Cleanup decision.
    pub cleanup: WindowsAppContainerCleanupDecision,
    /// Structured skip reason when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

impl WindowsAppContainerProcessLaunchEvidence {
    /// Build redaction-safe process-launch evidence from a lifecycle report.
    #[must_use]
    pub fn from_lifecycle(
        connector_id: &str,
        report: &WindowsAppContainerLifecycleReport,
        launch_mechanism: WindowsAppContainerProcessLaunchMechanism,
        job_object_attached: bool,
        action_result: &'static str,
        process_id: Option<u32>,
    ) -> Self {
        let mut step_order = vec!["appcontainer_lifecycle"];
        if launch_mechanism
            == WindowsAppContainerProcessLaunchMechanism::StartupInfoExSecurityCapabilities
        {
            step_order.push("startupinfoex_security_capabilities");
        }
        if job_object_attached {
            step_order.push("job_object_attach");
        }

        Self {
            schema: "fcp.windows_appcontainer_process_launch.v1",
            os: "windows",
            connector_id_hash: stable_fnv1a64_hex(connector_id),
            profile_name_hash: stable_fnv1a64_hex(&report.profile.name),
            capabilities: report.profile.capabilities.clone(),
            capability_decision: if report.profile.capabilities.is_empty() {
                "none_required"
            } else {
                "mapped"
            },
            lifecycle_action: report.action,
            sid_present: report.sid_present,
            launch_mechanism,
            job_object_attached,
            job_object_attachment_intent: if report.sid_present {
                WindowsJobObjectAttachmentIntent::AttachAfterLaunch
            } else {
                WindowsJobObjectAttachmentIntent::None
            },
            process_id_hash: process_id.map(|pid| stable_fnv1a64_hex(&pid.to_string())),
            final_filter_strength: FilterStrength::ProcessLimit,
            step_order,
            action_result,
            cleanup: report.cleanup,
            skip_reason: report.skip_reason.clone(),
        }
    }

    /// Render this record as a single JSONL line.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl WindowsAppContainerProfile {
    /// Derive a stable `AppContainer` profile from a connector id and compiled policy.
    pub fn from_policy(connector_id: &str, policy: &CompiledPolicy) -> Result<Self, SandboxError> {
        Ok(Self {
            name: windows_appcontainer_profile_name(connector_id)?,
            capabilities: policy.windows_appcontainer_capabilities()?,
        })
    }
}

fn windows_appcontainer_profile_name(connector_id: &str) -> Result<String, SandboxError> {
    let mut fragment = sanitize_windows_appcontainer_name_fragment(connector_id);
    let hash = stable_fnv1a64_hex(connector_id);
    let separators_len = 2;
    let max_fragment_len = WINDOWS_APPCONTAINER_PROFILE_NAME_MAX_LEN
        - WINDOWS_APPCONTAINER_PROFILE_PREFIX.len()
        - WINDOWS_APPCONTAINER_PROFILE_HASH_LEN
        - separators_len;
    fragment.truncate(max_fragment_len);

    let name = format!("{WINDOWS_APPCONTAINER_PROFILE_PREFIX}-{fragment}-{hash}");
    validate_windows_appcontainer_profile_name(&name)?;
    Ok(name)
}

fn sanitize_windows_appcontainer_name_fragment(value: &str) -> String {
    let mut fragment = String::with_capacity(value.len().min(43));
    let mut last_was_dash = false;

    for byte in value.bytes() {
        let next = if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_') {
            last_was_dash = false;
            char::from(byte.to_ascii_lowercase())
        } else if last_was_dash {
            continue;
        } else {
            last_was_dash = true;
            '-'
        };
        fragment.push(next);
    }

    let fragment = fragment.trim_matches('-');
    if fragment.is_empty() {
        "connector".to_owned()
    } else {
        fragment.to_owned()
    }
}

fn stable_fnv1a64_hex(value: &str) -> String {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

fn validate_windows_appcontainer_profile_name(name: &str) -> Result<(), SandboxError> {
    if name.is_empty() || name.len() > WINDOWS_APPCONTAINER_PROFILE_NAME_MAX_LEN {
        return Err(SandboxError::InvalidConfig(format!(
            "windows AppContainer profile name must be 1..={WINDOWS_APPCONTAINER_PROFILE_NAME_MAX_LEN} bytes, got {}",
            name.len()
        )));
    }

    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b' '))
    {
        return Err(SandboxError::InvalidConfig(format!(
            "windows AppContainer profile name `{name}` contains characters outside [-_. A-Za-z0-9]"
        )));
    }

    Ok(())
}

fn normalize_windows_appcontainer_capabilities(
    requested: &[String],
) -> Result<Vec<String>, SandboxError> {
    let mut capabilities = BTreeSet::new();
    for capability in requested {
        let capability = capability.trim();
        validate_windows_appcontainer_capability_name(capability)?;
        capabilities.insert(capability.to_owned());
    }

    Ok(capabilities.into_iter().collect())
}

fn validate_windows_appcontainer_capability_name(name: &str) -> Result<(), SandboxError> {
    if name.is_empty() {
        return Err(SandboxError::InvalidConfig(
            "windows AppContainer capability names must not be empty".into(),
        ));
    }

    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SandboxError::InvalidConfig(format!(
            "windows AppContainer capability `{name}` contains unsupported characters"
        )));
    }

    Ok(())
}

fn is_windows_network_appcontainer_capability(capability: &str) -> bool {
    WINDOWS_NETWORK_APPCONTAINER_CAPABILITIES.contains(&capability)
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
// Filter Strength (cross-platform parity metric)
// ============================================================================

/// Precision of the sandbox's enforcement boundary (NORMATIVE — cross-platform parity).
///
/// This is a coarse-grained classifier of "how narrow an attack surface does
/// this platform's sandbox actually filter?". Higher discriminant values
/// indicate stronger filtering. Use via `>=` comparison.
///
/// The three levels correspond to concrete mechanisms in the tree:
///
/// | Level            | Platform | Mechanism                                        |
/// |------------------|----------|--------------------------------------------------|
/// | `SyscallLevel`   | Linux    | seccomp-bpf with `SECCOMP_RET_KILL_PROCESS`      |
/// | `ProfileLevel`   | macOS    | `sandbox_init` / SBPL `(deny ...)` rules          |
/// | `ProcessLimit`   | Windows  | Job Object `ActiveProcessLimit` + memory limits  |
///
/// # Why this distinction matters
///
/// - **`SyscallLevel`** filters every syscall individually at the kernel
///   trap boundary. A hostile connector that discovers an unknown native
///   code path is still stopped at `int 0x80` / `syscall` because the
///   seccomp allowlist enumerates the kernel ABI, not a set of named
///   operations. `SECCOMP_RET_KILL_PROCESS` terminates the process
///   synchronously on any disallowed syscall.
///
/// - **`ProfileLevel`** filters *named* operations at the Mach/BSD API
///   layer (`process-exec`, `file-read*`, `network*`, etc.). Apple's
///   sandbox is enforced in-kernel, but the granularity is the operation
///   name the profile declares — not the underlying syscall. A previously
///   unknown native-API path or a syscall the profile does not explicitly
///   name may still reach the kernel. macOS is therefore strictly coarser
///   than Linux seccomp even though both are kernel-enforced.
///
/// - **`ProcessLimit`** does no per-operation filtering at all. Windows
///   job objects constrain *resource consumption* (process count, memory,
///   CPU time) but never inspect syscalls or API names. A connector that
///   stays inside its budget can invoke any Win32/NT API the process
///   integrity level allows. Any API-level denial that Linux seccomp or
///   macOS SBPL catches today is, on Windows, relying entirely on the
///   connector honoring the `deny_exec`/`deny_ptrace` contract in its
///   own code plus `ActiveProcessLimit = 1` catching `CreateProcess`.
///
/// # Parity gap (bead 459lp)
///
/// FCP's strict profile specifies kernel-enforced syscall-level filtering.
/// Today only Linux reaches `SyscallLevel`; macOS lands at `ProfileLevel`
/// and Windows at `ProcessLimit`. Strict-profile connectors that require
/// the full guarantee MUST run under [`WasiRuntime`](crate::WasiRuntime),
/// which never leaves the host process and so is unaffected by this gap.
///
/// [`WasiRuntime`]: crate::WasiRuntime
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum FilterStrength {
    /// Coarsest: only process and resource limits are enforced.
    ///
    /// Windows job objects live here. The sandbox can stop `deny_exec`
    /// via `ActiveProcessLimit = 1` and enforce memory/CPU ceilings, but
    /// it does not filter syscalls or named operations. Any native API
    /// the process integrity level permits is reachable.
    ProcessLimit = 0,

    /// Intermediate: named operations are denied at the OS API layer,
    /// but individual syscalls are not filtered.
    ///
    /// macOS `sandbox_init` with SBPL `(deny process-exec)` /
    /// `(deny file-read*)` / `(deny network*)` lives here. Enforcement is
    /// kernel-backed but operates on a named-operation vocabulary, so a
    /// syscall path not covered by a `(deny ...)` rule can still reach
    /// the kernel. Thread-as-process accounting also forces us to skip
    /// `RLIMIT_NPROC = 0` here (it would starve any async runtime),
    /// leaving the SBPL profile as the sole `deny_exec` enforcement.
    ProfileLevel = 1,

    /// Strongest: every syscall is individually filtered at the kernel
    /// trap boundary; denied syscalls terminate the process.
    ///
    /// Linux seccomp-bpf with `SECCOMP_RET_KILL_PROCESS` and an
    /// architecture-validated allowlist lives here. This is the only
    /// level that meets the strict-profile "no unknown syscall reaches
    /// the kernel" guarantee.
    SyscallLevel = 2,
}

impl FilterStrength {
    /// Stable string identifier (for audit logs and decision receipts).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessLimit => "process_limit",
            Self::ProfileLevel => "profile_level",
            Self::SyscallLevel => "syscall_level",
        }
    }

    /// The expected filter strength for a given target OS identifier
    /// (matches `std::env::consts::OS` values).
    ///
    /// Tests use this to assert that the current platform's `Sandbox`
    /// impl returns exactly the parity level documented here — guarding
    /// against silent regressions (e.g., Windows gaining a weaker
    /// mechanism that still claims a higher level, or macOS's profile
    /// being downgraded during a refactor).
    #[must_use]
    pub fn expected_for_target_os(os: &str) -> Option<Self> {
        // Intentionally exhaustive match on the documented targets. New
        // host targets added without a parity review will return None,
        // forcing the test to fail loudly rather than default-allow.
        match os {
            "linux" => Some(Self::SyscallLevel),
            "macos" => Some(Self::ProfileLevel),
            "windows" => Some(Self::ProcessLimit),
            _ => None,
        }
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
    /// Report the precision of this sandbox's enforcement mechanism.
    ///
    /// See [`FilterStrength`] for the levels and their meaning. The default
    /// implementation returns the weakest level ([`FilterStrength::ProcessLimit`])
    /// so that any new [`Sandbox`] impl that forgets to override this method
    /// is classified as coarse-grained by default — a conservative choice
    /// that prevents the parity assertion from silently treating a weaker
    /// sandbox as stronger than it is.
    fn filter_strength(&self) -> FilterStrength {
        FilterStrength::ProcessLimit
    }

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

fn verify_file_access_policy(
    policy: &CompiledPolicy,
    path: &Path,
    write: bool,
) -> Result<(), SandboxError> {
    let path = resolve_policy_path(path);

    if write {
        for writable in &policy.writable_paths {
            let writable = resolve_policy_path(writable);
            if path.starts_with(&writable) {
                return Ok(());
            }
        }
        return Err(SandboxError::ApplyFailed(format!(
            "write access denied to path: {}",
            path.display()
        )));
    }

    for readable in policy.readonly_paths.iter().chain(&policy.writable_paths) {
        let readable = resolve_policy_path(readable);
        if path.starts_with(&readable) {
            return Ok(());
        }
    }

    Err(SandboxError::ApplyFailed(format!(
        "read access denied to path: {}",
        path.display()
    )))
}

fn verify_exec_policy(policy: &CompiledPolicy) -> Result<(), SandboxError> {
    if policy.deny_exec {
        Err(SandboxError::ApplyFailed(
            "process spawning is denied by sandbox policy".into(),
        ))
    } else {
        Ok(())
    }
}

fn verify_network_policy(policy: &CompiledPolicy) -> Result<(), SandboxError> {
    if policy.block_direct_network {
        Ok(())
    } else {
        Err(SandboxError::ApplyFailed(
            "direct network access is permitted by sandbox policy".into(),
        ))
    }
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
        policy: &CompiledPolicy,
        path: &std::path::Path,
        write: bool,
    ) -> Result<(), SandboxError> {
        verify_file_access_policy(policy, path, write)
    }

    fn verify_exec_allowed(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        verify_exec_policy(policy)
    }

    fn verify_network_blocked(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        verify_network_policy(policy)
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
        assert!(flags.windows_appcontainer_capabilities.is_empty());
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

        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT.into()],
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
    fn test_windows_appcontainer_profile_name_is_stable_and_bounded() {
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        let profile = policy
            .windows_appcontainer_profile("fcp.test.github:request-response:1.0.0")
            .unwrap();

        assert!(
            profile
                .name
                .starts_with("fcp-fcp.test.github-request-response-1.0.0-")
        );
        assert!(profile.name.len() <= 64);
        assert_eq!(
            profile,
            policy
                .windows_appcontainer_profile("fcp.test.github:request-response:1.0.0")
                .unwrap()
        );
    }

    #[test]
    fn test_windows_appcontainer_capabilities_follow_network_policy() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Strict;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(
            policy
                .windows_appcontainer_capabilities()
                .unwrap()
                .is_empty()
        );

        section.profile = SandboxProfile::Permissive;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(
            policy.windows_appcontainer_capabilities().unwrap(),
            vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT]
        );
    }

    #[test]
    fn test_windows_appcontainer_capabilities_are_normalized() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Permissive;
        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec![
                " custom.capability ".into(),
                WINDOWS_APPCONTAINER_PRIVATE_NETWORK_CLIENT_SERVER.into(),
                "custom.capability".into(),
            ],
            ..Default::default()
        };
        let policy = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags);

        assert_eq!(
            policy.windows_appcontainer_capabilities().unwrap(),
            vec![
                "custom.capability",
                WINDOWS_APPCONTAINER_PRIVATE_NETWORK_CLIENT_SERVER
            ]
        );
    }

    #[test]
    fn test_windows_appcontainer_rejects_network_capabilities_when_network_blocked() {
        let section = test_sandbox_section();
        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec![
                WINDOWS_APPCONTAINER_INTERNET_CLIENT_SERVER.into(),
            ],
            ..Default::default()
        };
        let err = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags)
            .windows_appcontainer_capabilities()
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("direct network must remain blocked")
        );
    }

    #[test]
    fn test_windows_appcontainer_rejects_invalid_capability_name() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Permissive;
        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec!["camera/read".into()],
            ..Default::default()
        };
        let err = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags)
            .windows_appcontainer_capabilities()
            .unwrap_err();

        assert!(err.to_string().contains("unsupported characters"));
    }

    #[derive(Debug, Clone, Copy)]
    enum FakeCreateProfileResult {
        Created,
        AlreadyExists,
        Fail,
    }

    struct FakeWindowsAppContainerApi {
        create_result: FakeCreateProfileResult,
        derive_fails: bool,
        delete_fails: bool,
        calls: Vec<String>,
    }

    impl FakeWindowsAppContainerApi {
        fn new(create_result: FakeCreateProfileResult) -> Self {
            Self {
                create_result,
                derive_fails: false,
                delete_fails: false,
                calls: Vec::new(),
            }
        }

        fn with_derive_failure(mut self) -> Self {
            self.derive_fails = true;
            self
        }

        fn with_delete_failure(mut self) -> Self {
            self.delete_fails = true;
            self
        }
    }

    impl WindowsAppContainerProfileApi for FakeWindowsAppContainerApi {
        fn create_profile(
            &mut self,
            profile: &WindowsAppContainerProfile,
        ) -> Result<WindowsAppContainerCreateOutcome, SandboxError> {
            self.calls.push(format!("create:{}", profile.name));
            match self.create_result {
                FakeCreateProfileResult::Created => Ok(WindowsAppContainerCreateOutcome::Created),
                FakeCreateProfileResult::AlreadyExists => {
                    Ok(WindowsAppContainerCreateOutcome::AlreadyExists)
                }
                FakeCreateProfileResult::Fail => Err(SandboxError::SyscallFailed(
                    "CreateAppContainerProfile failed: access denied".into(),
                )),
            }
        }

        fn derive_profile_sid(&mut self, profile_name: &str) -> Result<(), SandboxError> {
            self.calls.push(format!("derive:{profile_name}"));
            if self.derive_fails {
                Err(SandboxError::SyscallFailed(
                    "DeriveAppContainerSidFromAppContainerName failed: invalid argument".into(),
                ))
            } else {
                Ok(())
            }
        }

        fn delete_profile(&mut self, profile_name: &str) -> Result<(), SandboxError> {
            self.calls.push(format!("delete:{profile_name}"));
            if self.delete_fails {
                Err(SandboxError::SyscallFailed(
                    "DeleteAppContainerProfile failed: access denied".into(),
                ))
            } else {
                Ok(())
            }
        }
    }

    fn fake_windows_appcontainer_profile() -> WindowsAppContainerProfile {
        WindowsAppContainerProfile {
            name: "fcp-test-connector-0123456789abcdef".into(),
            capabilities: vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT.into()],
        }
    }

    #[test]
    fn test_windows_appcontainer_lifecycle_skips_without_active_backend() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::Fail);

        let report =
            prepare_windows_appcontainer_lifecycle(profile.clone(), false, &mut api).unwrap();

        assert_eq!(report.profile, profile);
        assert_eq!(
            report.action,
            WindowsAppContainerLifecycleAction::SkippedInactive
        );
        assert!(!report.sid_present);
        assert_eq!(report.cleanup, WindowsAppContainerCleanupDecision::None);
        assert!(report.skip_reason.is_some());
        assert!(api.calls.is_empty());
    }

    #[test]
    fn test_windows_appcontainer_lifecycle_records_profile_create() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::Created);

        let report =
            prepare_windows_appcontainer_lifecycle(profile.clone(), true, &mut api).unwrap();

        assert_eq!(report.profile, profile);
        assert_eq!(report.action, WindowsAppContainerLifecycleAction::Created);
        assert!(report.sid_present);
        assert_eq!(
            report.cleanup,
            WindowsAppContainerCleanupDecision::RetainProfile
        );
        assert_eq!(
            api.calls,
            vec!["create:fcp-test-connector-0123456789abcdef"]
        );
    }

    #[test]
    fn test_windows_appcontainer_lifecycle_reuses_existing_profile_sid() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::AlreadyExists);

        let report =
            prepare_windows_appcontainer_lifecycle(profile.clone(), true, &mut api).unwrap();

        assert_eq!(report.profile, profile);
        assert_eq!(
            report.action,
            WindowsAppContainerLifecycleAction::ReusedExisting
        );
        assert!(report.sid_present);
        assert_eq!(
            api.calls,
            vec![
                "create:fcp-test-connector-0123456789abcdef",
                "derive:fcp-test-connector-0123456789abcdef"
            ]
        );
    }

    #[test]
    fn test_windows_appcontainer_lifecycle_maps_create_failure() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::Fail);

        let err = prepare_windows_appcontainer_lifecycle(profile, true, &mut api).unwrap_err();

        assert!(err.to_string().contains("CreateAppContainerProfile"));
        assert_eq!(
            api.calls,
            vec!["create:fcp-test-connector-0123456789abcdef"]
        );
    }

    #[test]
    fn test_windows_appcontainer_lifecycle_maps_sid_derivation_failure() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::AlreadyExists)
            .with_derive_failure();

        let err = prepare_windows_appcontainer_lifecycle(profile, true, &mut api).unwrap_err();

        assert!(
            err.to_string()
                .contains("DeriveAppContainerSidFromAppContainerName")
        );
        assert_eq!(
            api.calls,
            vec![
                "create:fcp-test-connector-0123456789abcdef",
                "derive:fcp-test-connector-0123456789abcdef"
            ]
        );
    }

    #[test]
    fn test_windows_appcontainer_cleanup_deletes_profile() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::Created);

        let cleanup = cleanup_windows_appcontainer_profile(&profile.name, &mut api).unwrap();

        assert_eq!(cleanup, WindowsAppContainerCleanupDecision::DeleteProfile);
        assert_eq!(
            api.calls,
            vec!["delete:fcp-test-connector-0123456789abcdef"]
        );
    }

    #[test]
    fn test_windows_appcontainer_cleanup_maps_delete_failure() {
        let profile = fake_windows_appcontainer_profile();
        let mut api =
            FakeWindowsAppContainerApi::new(FakeCreateProfileResult::Created).with_delete_failure();

        let err = cleanup_windows_appcontainer_profile(&profile.name, &mut api).unwrap_err();

        assert!(err.to_string().contains("DeleteAppContainerProfile"));
        assert_eq!(
            api.calls,
            vec!["delete:fcp-test-connector-0123456789abcdef"]
        );
    }

    #[test]
    fn test_windows_appcontainer_evidence_records_cleanup_delete() {
        let report = WindowsAppContainerLifecycleReport {
            profile: fake_windows_appcontainer_profile(),
            action: WindowsAppContainerLifecycleAction::Created,
            sid_present: true,
            cleanup: WindowsAppContainerCleanupDecision::DeleteProfile,
            skip_reason: None,
        };
        let evidence =
            WindowsAppContainerEvidence::from_lifecycle("connector", &report, true, "real_smoke");
        let line = evidence.to_jsonl_line().unwrap();

        assert_eq!(
            evidence.cleanup,
            WindowsAppContainerCleanupDecision::DeleteProfile
        );
        assert!(line.contains("\"cleanup\":\"delete_profile\""));
        assert_eq!(evidence.action_result, "real_smoke");
    }

    #[test]
    fn test_windows_appcontainer_evidence_redacts_connector_and_profile_names() {
        let profile = WindowsAppContainerProfile {
            name: "fcp-secret-customer-0123456789abcdef".into(),
            capabilities: vec!["custom.capability".into()],
        };
        let report = WindowsAppContainerLifecycleReport::inactive(profile);
        let evidence = WindowsAppContainerEvidence::from_lifecycle(
            "secret-customer@example.com",
            &report,
            false,
            "skip",
        );
        let line = evidence.to_jsonl_line().unwrap();

        assert!(line.contains("fcp.windows_appcontainer_smoke.v1"));
        assert!(line.contains("windows_appcontainer_not_active"));
        assert!(!line.contains("secret-customer@example.com"));
        assert!(!line.contains("fcp-secret-customer"));
        assert!(evidence.step_order.contains(&"appcontainer_lifecycle"));
        assert!(!evidence.step_order.contains(&"job_object_attach"));
    }

    #[test]
    fn test_windows_appcontainer_evidence_records_job_object_attachment_order() {
        let profile = fake_windows_appcontainer_profile();
        let report = WindowsAppContainerLifecycleReport::active(
            profile,
            WindowsAppContainerLifecycleAction::Created,
        );
        let evidence =
            WindowsAppContainerEvidence::from_lifecycle("connector", &report, true, "apply");

        assert!(evidence.job_object_attached);
        assert_eq!(
            evidence.step_order,
            vec!["appcontainer_lifecycle", "job_object_attach"]
        );
        assert_eq!(evidence.action_result, "apply");
        assert!(evidence.sid_present);
        assert_eq!(
            evidence.cleanup,
            WindowsAppContainerCleanupDecision::RetainProfile
        );
    }

    #[test]
    fn test_windows_appcontainer_process_launch_evidence_records_startupinfoex_path() {
        let profile = fake_windows_appcontainer_profile();
        let report = WindowsAppContainerLifecycleReport::active(
            profile,
            WindowsAppContainerLifecycleAction::Created,
        );
        let evidence = WindowsAppContainerProcessLaunchEvidence::from_lifecycle(
            "connector",
            &report,
            WindowsAppContainerProcessLaunchMechanism::StartupInfoExSecurityCapabilities,
            true,
            "launched",
            Some(4242),
        );
        let line = evidence.to_jsonl_line().unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(
            value["schema"],
            "fcp.windows_appcontainer_process_launch.v1"
        );
        assert_eq!(
            value["launch_mechanism"],
            "startup_info_ex_security_capabilities"
        );
        assert_eq!(value["job_object_attachment_intent"], "attach_after_launch");
        assert_eq!(value["job_object_attached"].as_bool(), Some(true));
        assert_eq!(value["final_filter_strength"], "process_limit");
        assert!(value["process_id_hash"].as_str().is_some());
        assert_eq!(
            evidence.step_order,
            vec![
                "appcontainer_lifecycle",
                "startupinfoex_security_capabilities",
                "job_object_attach"
            ]
        );
        assert!(!line.contains("4242"));
    }

    #[test]
    fn test_windows_appcontainer_process_launch_evidence_redacts_skip_names() {
        let profile = WindowsAppContainerProfile {
            name: "fcp-secret-customer-0123456789abcdef".into(),
            capabilities: vec!["custom.capability".into()],
        };
        let report = WindowsAppContainerLifecycleReport::inactive(profile);
        let evidence = WindowsAppContainerProcessLaunchEvidence::from_lifecycle(
            "secret-customer@example.com",
            &report,
            WindowsAppContainerProcessLaunchMechanism::SkippedInactive,
            false,
            "skip",
            None,
        );
        let line = evidence.to_jsonl_line().unwrap();

        assert!(line.contains("fcp.windows_appcontainer_process_launch.v1"));
        assert!(line.contains("windows_appcontainer_not_active"));
        assert!(!line.contains("secret-customer@example.com"));
        assert!(!line.contains("fcp-secret-customer"));
        assert_eq!(
            evidence.job_object_attachment_intent,
            WindowsJobObjectAttachmentIntent::None
        );
        assert!(evidence.process_id_hash.is_none());
        assert_eq!(evidence.final_filter_strength, FilterStrength::ProcessLimit);
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
    fn test_create_sandbox_returns_platform_backend() -> Result<(), SandboxError> {
        let expected = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            return Ok(());
        };

        let sandbox = match create_sandbox() {
            Ok(sandbox) => sandbox,
            Err(SandboxError::UnsupportedPlatform(_)) => return Ok(()),
            Err(other) => return Err(other),
        };

        assert_eq!(sandbox.platform_name(), expected);
        assert!(sandbox.is_available());
        Ok(())
    }

    #[test]
    fn test_noop_sandbox_verify_file_access() {
        let sandbox = NoOpSandbox;
        let section = test_sandbox_section();
        // `$CONNECTOR_STATE` in fs_writable_paths only expands when a
        // state_dir is supplied; without it, the writable set is empty
        // and the cache.db assertion below fails spuriously. Mirror
        // test_compile_policy's `state_dir` so the NoOp verifier has a
        // populated writable set to match against.
        let state_dir = Some(PathBuf::from("/var/lib/fcp/connectors/test"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/usr/lib/libc.so"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    std::path::Path::new("/var/lib/fcp/connectors/test/cache.db"),
                    true,
                )
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/anything"), false)
                .is_err()
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
        let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
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
        assert!(sandbox.verify_exec_allowed(&policy).is_err());
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
            windows_appcontainer_capabilities: vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT.into()],
        };

        let json = serde_json::to_string(&flags).unwrap();
        let roundtrip: PlatformFlags = serde_json::from_str(&json).unwrap();

        assert!(roundtrip.linux_use_landlock);
        assert!(roundtrip.linux_use_userns);
        assert_eq!(roundtrip.macos_entitlements.len(), 1);
        assert!(roundtrip.windows_low_integrity);
        assert_eq!(
            roundtrip.windows_appcontainer_capabilities,
            vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT]
        );
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
            windows_appcontainer_capabilities: vec!["custom.capability".into()],
        };
        let cloned = original.clone();
        assert_eq!(original.linux_use_landlock, cloned.linux_use_landlock);
        assert_eq!(original.linux_use_userns, cloned.linux_use_userns);
        assert_eq!(original.macos_entitlements, cloned.macos_entitlements);
        assert_eq!(original.windows_low_integrity, cloned.windows_low_integrity);
        assert_eq!(
            original.windows_appcontainer_capabilities,
            cloned.windows_appcontainer_capabilities
        );
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
            windows_appcontainer_capabilities: vec!["custom.capability".into()],
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
        assert_eq!(
            roundtrip.platform_flags.windows_appcontainer_capabilities,
            vec!["custom.capability"]
        );
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
            windows_appcontainer_capabilities: Vec::new(),
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
            windows_appcontainer_capabilities: vec!["custom.capability".into()],
        };
        assert!(!flags.is_empty());
        let json = serde_json::to_string(&flags).unwrap();
        let rt: PlatformFlags = serde_json::from_str(&json).unwrap();
        assert!(rt.linux_use_landlock);
        assert!(rt.linux_use_userns);
        assert_eq!(rt.macos_entitlements.len(), 1);
        assert!(rt.windows_low_integrity);
        assert_eq!(
            rt.windows_appcontainer_capabilities,
            vec!["custom.capability"]
        );
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
        assert!(flags.windows_appcontainer_capabilities.is_empty());
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
            windows_appcontainer_capabilities: vec!["custom.capability".into()],
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
        assert_eq!(
            rt.platform_flags.windows_appcontainer_capabilities,
            vec!["custom.capability"]
        );
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
        // Provide state_dir so `$CONNECTOR_STATE` in fs_writable_paths
        // expands; without it the writable set is empty and the
        // cache.db write assertion below fails spuriously.
        let state_dir = Some(PathBuf::from("/var/lib/fcp/connectors/test"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();

        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/usr/bin/test"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    std::path::Path::new("/var/lib/fcp/connectors/test/cache.db"),
                    true,
                )
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/etc/secret"), true)
                .is_err()
        );
        assert!(sandbox.verify_exec_allowed(&policy).is_err());
        assert!(sandbox.verify_network_blocked(&policy).is_ok());
        assert!(sandbox.apply(&policy).is_ok());
    }

    // ── FilterStrength parity matrix (bead 459lp) ─────────────────────────
    //
    // These tests lock in the cross-platform filter-coarseness contract
    // documented on [`FilterStrength`]. The matrix is intentionally
    // explicit: if a platform's backing mechanism changes (AppContainer
    // lands on Windows, macOS tightens its SBPL, Linux drops seccomp,
    // etc.) we want the failure to show up as a test regression rather
    // than a silent guarantee change. Update the matrix *and* the
    // [`FilterStrength::expected_for_target_os`] table together.

    #[test]
    fn filter_strength_ordering_strongest_last() {
        // SyscallLevel > ProfileLevel > ProcessLimit. Comparisons use
        // PartialOrd, so trait consumers can assert
        // `sandbox.filter_strength() >= required_level`.
        assert!(FilterStrength::SyscallLevel > FilterStrength::ProfileLevel);
        assert!(FilterStrength::ProfileLevel > FilterStrength::ProcessLimit);
        assert!(FilterStrength::SyscallLevel > FilterStrength::ProcessLimit);
    }

    #[test]
    fn filter_strength_expected_matrix() {
        // Documented parity table. These asserts are the source of truth
        // paired with the table in the FilterStrength rustdoc.
        assert_eq!(
            FilterStrength::expected_for_target_os("linux"),
            Some(FilterStrength::SyscallLevel),
        );
        assert_eq!(
            FilterStrength::expected_for_target_os("macos"),
            Some(FilterStrength::ProfileLevel),
        );
        assert_eq!(
            FilterStrength::expected_for_target_os("windows"),
            Some(FilterStrength::ProcessLimit),
        );
        // Unknown targets MUST NOT default-allow to any strength;
        // returning None forces a deliberate parity review.
        assert_eq!(
            FilterStrength::expected_for_target_os("freebsd"),
            None,
            "new host targets must be reviewed before claiming a strength tier",
        );
    }

    #[test]
    fn filter_strength_default_is_conservative() {
        // Any Sandbox impl that forgets to override filter_strength gets
        // ProcessLimit (the weakest level). The NoOpSandbox doesn't
        // override it, so this test also doubles as a guard on the
        // trait default.
        struct MinimalSandbox;
        impl Sandbox for MinimalSandbox {
            fn apply(&self, _p: &CompiledPolicy) -> Result<(), SandboxError> {
                Ok(())
            }
            fn is_available(&self) -> bool {
                true
            }
            fn platform_name(&self) -> &'static str {
                "minimal"
            }
            fn verify_file_access(
                &self,
                _p: &CompiledPolicy,
                _path: &std::path::Path,
                _w: bool,
            ) -> Result<(), SandboxError> {
                Ok(())
            }
            fn verify_exec_allowed(&self, _p: &CompiledPolicy) -> Result<(), SandboxError> {
                Ok(())
            }
            fn verify_network_blocked(&self, _p: &CompiledPolicy) -> Result<(), SandboxError> {
                Ok(())
            }
        }
        assert_eq!(
            MinimalSandbox.filter_strength(),
            FilterStrength::ProcessLimit,
        );
        assert_eq!(NoOpSandbox.filter_strength(), FilterStrength::ProcessLimit);
    }

    #[test]
    fn filter_strength_as_str_stable_snake_case() {
        // These identifiers are emitted into audit trails — freezing
        // them here stops drive-by rename refactors from breaking
        // downstream log consumers.
        assert_eq!(FilterStrength::ProcessLimit.as_str(), "process_limit");
        assert_eq!(FilterStrength::ProfileLevel.as_str(), "profile_level");
        assert_eq!(FilterStrength::SyscallLevel.as_str(), "syscall_level");
    }

    /// Assert that the active host sandbox reports exactly the
    /// documented filter strength for this target OS.
    ///
    /// Compiled once per host target, so the workspace test matrix
    /// naturally ends up with one assertion per (OS, arch) pair — the
    /// "platform-matrix" coverage the parity bead asks for.
    #[test]
    fn host_sandbox_matches_documented_filter_strength() -> Result<(), SandboxError> {
        let Some(expected) = FilterStrength::expected_for_target_os(std::env::consts::OS) else {
            // Running on a host we haven't reviewed for sandbox parity
            // (e.g., freebsd, solaris). create_sandbox() will fail; we
            // just record that no strength contract applies.
            return Ok(());
        };

        let sandbox = match create_sandbox() {
            Ok(s) => s,
            Err(SandboxError::UnsupportedPlatform(_)) => {
                // Same guard as above, but via the runtime path.
                return Ok(());
            }
            Err(other) => return Err(other),
        };

        assert_eq!(
            sandbox.filter_strength(),
            expected,
            "host sandbox on {} must report FilterStrength::{:?} per the parity matrix; \
             got {:?}. If you intentionally changed the backing mechanism, update \
             both FilterStrength::expected_for_target_os and the rustdoc table.",
            std::env::consts::OS,
            expected,
            sandbox.filter_strength(),
        );
        Ok(())
    }

    // Per-platform compile-gated assertions. These give each CI leg
    // (linux, macos, windows) a concrete failure site when only that
    // platform's parity contract regresses.

    #[cfg(target_os = "linux")]
    #[test]
    fn platform_matrix_linux_is_syscall_level() {
        let sandbox = crate::linux::LinuxSandbox::new();
        assert_eq!(sandbox.filter_strength(), FilterStrength::SyscallLevel);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn platform_matrix_macos_is_profile_level() {
        let sandbox = crate::macos::MacOsSandbox::new();
        assert_eq!(sandbox.filter_strength(), FilterStrength::ProfileLevel);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn platform_matrix_windows_is_process_limit() {
        let sandbox = crate::windows::WindowsSandbox::new();
        assert_eq!(sandbox.filter_strength(), FilterStrength::ProcessLimit);
    }
}
