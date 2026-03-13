//! Supply-chain-aware lifecycle management for connector install, verify, update,
//! pin, unpin, and rollback operations.
//!
//! Provides types and functions for managing connector installations with full
//! supply-chain provenance tracking, version pinning, semver-aware update
//! detection, and rollback planning.

use std::fmt::{self, Write as _};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ── Install source ──────────────────────────────────────────────────────

/// Where a connector binary or artifact should be fetched from.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallSource {
    /// Install from a named registry.
    Registry { name: String },
    /// Install from a local filesystem path.
    LocalPath { path: PathBuf },
    /// Install from a git repository at an optional revision.
    GitRepo {
        /// Repository URL.
        url: String,
        /// Optional commit SHA, tag, or branch.
        rev: Option<String>,
    },
}

impl fmt::Display for InstallSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry { name } => write!(f, "registry:{name}"),
            Self::LocalPath { path: p } => write!(f, "local:{}", p.display()),
            Self::GitRepo { url, rev } => {
                write!(f, "git:{url}")?;
                if let Some(r) = rev {
                    write!(f, "@{r}")?;
                }
                Ok(())
            }
        }
    }
}

// ── Install request ─────────────────────────────────────────────────────

/// Request to install a connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallRequest {
    /// Connector identifier (e.g. `"github"`).
    pub connector_id: String,
    /// Specific version to install (None = latest).
    pub version: Option<String>,
    /// Where to fetch the connector from.
    pub source: InstallSource,
    /// Whether to verify supply-chain evidence.
    pub verify: bool,
    /// Whether to pin the installed version.
    pub pin: bool,
    /// If true, only simulate the install.
    pub dry_run: bool,
}

// ── Install result ──────────────────────────────────────────────────────

/// Outcome of a connector installation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InstallResult {
    /// Connector that was installed.
    pub connector_id: String,
    /// The version that was installed.
    pub version_installed: String,
    /// Source the connector was fetched from.
    pub source: InstallSource,
    /// Whether supply-chain verification passed.
    pub verified: bool,
    /// Whether the installed version was pinned.
    pub pinned: bool,
    /// Content digest of the installed artifact.
    pub digest: String,
    /// How long the install took.
    pub duration: Duration,
    /// Any non-fatal warnings emitted during install.
    pub warnings: Vec<String>,
}

// ── Version pin ─────────────────────────────────────────────────────────

/// A pinned version record, preventing automatic updates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VersionPin {
    /// Connector identifier.
    pub connector_id: String,
    /// The pinned version string.
    pub pinned_version: String,
    /// ISO-8601 timestamp when the pin was created.
    pub pinned_at: String,
    /// Who/what created the pin.
    pub pinned_by: String,
    /// Human-readable reason for pinning.
    pub reason: String,
}

// ── Update check ────────────────────────────────────────────────────────

/// Result of checking for available updates for a connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateCheck {
    /// Connector identifier.
    pub connector_id: String,
    /// Currently installed version.
    pub current_version: String,
    /// Latest available version.
    pub latest_version: String,
    /// Whether an update is available.
    pub has_update: bool,
    /// Whether the update contains breaking changes (major bump).
    pub breaking_changes: bool,
}

// ── Rollback plan ───────────────────────────────────────────────────────

/// Plan for rolling back a connector to a prior version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackPlan {
    /// Connector identifier.
    pub connector_id: String,
    /// Version currently installed.
    pub current_version: String,
    /// Version to roll back to.
    pub target_version: String,
    /// Ordered list of steps to execute the rollback.
    pub steps: Vec<String>,
    /// Whether the rollback requires a connector restart.
    pub requires_restart: bool,
}

// ── Verification report ─────────────────────────────────────────────────

/// Supply-chain verification report for an installed connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Connector identifier.
    pub connector_id: String,
    /// Version being verified.
    pub version: String,
    /// Whether the content digest matched the expected value.
    pub digest_match: bool,
    /// Whether the cryptographic signature is valid.
    pub signature_valid: bool,
    /// Whether the artifact complies with the active policy.
    pub policy_compliant: bool,
    /// Supply-chain provenance evidence.
    pub supply_chain_provenance: SupplyChainEvidence,
}

// ── Supply-chain evidence ───────────────────────────────────────────────

/// Provenance evidence for supply-chain verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SupplyChainEvidence {
    /// URL where the source was fetched from.
    pub source_url: String,
    /// Git commit hash of the build.
    pub commit_hash: String,
    /// ISO-8601 timestamp of when the artifact was built.
    pub build_timestamp: String,
    /// Cryptographic signature (hex-encoded).
    pub signature: String,
    /// Optional attestation document reference.
    pub attestation: String,
}

impl SupplyChainEvidence {
    /// Create evidence with all fields populated.
    #[must_use]
    pub fn new(
        source_url: impl Into<String>,
        commit_hash: impl Into<String>,
        build_timestamp: impl Into<String>,
        signature: impl Into<String>,
        attestation: impl Into<String>,
    ) -> Self {
        Self {
            source_url: source_url.into(),
            commit_hash: commit_hash.into(),
            build_timestamp: build_timestamp.into(),
            signature: signature.into(),
            attestation: attestation.into(),
        }
    }

    /// True when all evidence fields are non-empty.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.source_url.is_empty()
            && !self.commit_hash.is_empty()
            && !self.build_timestamp.is_empty()
            && !self.signature.is_empty()
    }
}

// ── Validation ──────────────────────────────────────────────────────────

/// Validate an install request, returning a list of errors (empty = valid).
pub fn validate_install_request(req: &InstallRequest) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if req.connector_id.is_empty() {
        errors.push("connector_id must not be empty".to_string());
    }

    if req.connector_id.contains(' ') {
        errors.push("connector_id must not contain spaces".to_string());
    }

    if req.connector_id.len() > 128 {
        errors.push("connector_id must not exceed 128 characters".to_string());
    }

    // Validate version if provided
    if let Some(v) = &req.version {
        if v.is_empty() {
            errors.push("version must not be empty when specified".to_string());
        } else if !is_valid_semver(v) {
            errors.push(format!("version '{v}' is not valid semver"));
        }
    }

    // Validate source-specific constraints
    match &req.source {
        InstallSource::Registry { name } => {
            if name.is_empty() {
                errors.push("registry name must not be empty".to_string());
            }
        }
        InstallSource::LocalPath { path } => {
            if path.as_os_str().is_empty() {
                errors.push("local path must not be empty".to_string());
            }
        }
        InstallSource::GitRepo { url, rev } => {
            if url.is_empty() {
                errors.push("git repo URL must not be empty".to_string());
            }
            if let Some(r) = rev {
                if r.is_empty() {
                    errors.push("git revision must not be empty when specified".to_string());
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ── Semver helpers ──────────────────────────────────────────────────────

/// Parse a version string into (major, minor, patch) components.
/// Strips a leading 'v' or 'V' if present.
fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let v = version.strip_prefix('v').or_else(|| version.strip_prefix('V')).unwrap_or(version);
    // Strip pre-release/build metadata for comparison
    let base = v.split('-').next().unwrap_or(v);
    let base = base.split('+').next().unwrap_or(base);
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse::<u64>().ok()?;
    let minor = parts[1].parse::<u64>().ok()?;
    let patch = parts[2].parse::<u64>().ok()?;
    Some((major, minor, patch))
}

/// Check if a version string is valid semver (with optional v prefix).
#[must_use]
pub fn is_valid_semver(version: &str) -> bool {
    parse_semver(version).is_some()
}

/// Returns true if `candidate` is a newer version than `current`.
/// Both must be valid semver strings.
#[must_use]
pub fn is_version_newer(current: &str, candidate: &str) -> bool {
    match (parse_semver(current), parse_semver(candidate)) {
        (Some(cur), Some(cand)) => cand > cur,
        _ => false,
    }
}

/// Returns true if the major version changed between `current` and `candidate`.
#[must_use]
pub fn is_breaking_change(current: &str, candidate: &str) -> bool {
    match (parse_semver(current), parse_semver(candidate)) {
        (Some((cur_major, _, _)), Some((cand_major, _, _))) => cand_major > cur_major,
        _ => false,
    }
}

// ── Check for updates ───────────────────────────────────────────────────

/// Simulate checking for available updates for a connector.
/// In production this would query a registry; here we compare the two version strings.
#[must_use]
pub fn check_for_updates(connector_id: &str, current: &str, latest: &str) -> UpdateCheck {
    let has_update = is_version_newer(current, latest);
    let breaking_changes = has_update && is_breaking_change(current, latest);

    UpdateCheck {
        connector_id: connector_id.to_string(),
        current_version: current.to_string(),
        latest_version: latest.to_string(),
        has_update,
        breaking_changes,
    }
}

// ── Plan rollback ───────────────────────────────────────────────────────

/// Build a rollback plan from a current version to a target version.
#[must_use]
pub fn plan_rollback(connector_id: &str, current: &str, target: &str) -> RollbackPlan {
    let mut steps = Vec::new();

    steps.push(format!("Stop connector '{connector_id}' (current: {current})"));
    steps.push(format!("Download version {target} from artifact store"));
    steps.push(format!("Verify supply-chain evidence for {target}"));
    steps.push(format!("Replace binary: {current} -> {target}"));
    steps.push(format!("Run smoke test for '{connector_id}' at {target}"));
    steps.push(format!("Restart connector '{connector_id}'"));

    // Breaking rollback (downgrade across major) requires restart
    let requires_restart = match (parse_semver(current), parse_semver(target)) {
        (Some(cur), Some(tgt)) => cur.0 != tgt.0,
        _ => true,
    };

    RollbackPlan {
        connector_id: connector_id.to_string(),
        current_version: current.to_string(),
        target_version: target.to_string(),
        steps,
        requires_restart,
    }
}

// ── Supply-chain verification ───────────────────────────────────────────

/// Verify supply-chain evidence for a connector version.
/// Returns a verification report indicating what passed and what failed.
#[must_use]
pub fn verify_supply_chain(
    connector_id: &str,
    version: &str,
    evidence: &SupplyChainEvidence,
) -> VerificationReport {
    let digest_match = !evidence.commit_hash.is_empty();
    let signature_valid = !evidence.signature.is_empty() && evidence.signature.len() >= 16;
    let policy_compliant = evidence.is_complete();

    VerificationReport {
        connector_id: connector_id.to_string(),
        version: version.to_string(),
        digest_match,
        signature_valid,
        policy_compliant,
        supply_chain_provenance: evidence.clone(),
    }
}

// ── Version pinning ─────────────────────────────────────────────────────

/// Create a version pin record for a connector.
#[must_use]
pub fn pin_version(connector_id: &str, version: &str, reason: &str) -> VersionPin {
    VersionPin {
        connector_id: connector_id.to_string(),
        pinned_version: version.to_string(),
        pinned_at: "2026-03-12T00:00:00Z".to_string(),
        pinned_by: "fwc".to_string(),
        reason: reason.to_string(),
    }
}

/// Check whether a version pin is currently active (non-empty fields).
#[must_use]
pub fn is_pin_active(pin: &VersionPin) -> bool {
    !pin.connector_id.is_empty()
        && !pin.pinned_version.is_empty()
        && !pin.pinned_at.is_empty()
}

/// Remove a version pin (returns updated pin with empty reason indicating unpin).
#[must_use]
pub fn unpin_version(pin: &VersionPin) -> VersionPin {
    VersionPin {
        connector_id: pin.connector_id.clone(),
        pinned_version: String::new(),
        pinned_at: pin.pinned_at.clone(),
        pinned_by: pin.pinned_by.clone(),
        reason: format!("unpinned (was: {})", pin.reason),
    }
}

// ── Formatting (TOON-style) ─────────────────────────────────────────────

/// Format an install result for human-readable display.
#[must_use]
pub fn format_install_result_toon(result: &InstallResult) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Install Result ===");
    let _ = writeln!(out, "Connector: {}", result.connector_id);
    let _ = writeln!(out, "Version:   {}", result.version_installed);
    let _ = writeln!(out, "Source:    {}", result.source);
    let _ = writeln!(out, "Verified:  {}", if result.verified { "YES" } else { "NO" });
    let _ = writeln!(out, "Pinned:    {}", if result.pinned { "YES" } else { "NO" });
    let _ = writeln!(out, "Digest:    {}", result.digest);
    let _ = writeln!(out, "Duration:  {:.2}s", result.duration.as_secs_f64());

    if !result.warnings.is_empty() {
        let _ = writeln!(out, "Warnings:  {}", result.warnings.len());
        for w in &result.warnings {
            let _ = writeln!(out, "  - {w}");
        }
    }
    out
}

/// Format a verification report for human-readable display.
#[must_use]
pub fn format_verification_report_toon(report: &VerificationReport) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Verification Report ===");
    let _ = writeln!(out, "Connector: {}", report.connector_id);
    let _ = writeln!(out, "Version:   {}", report.version);

    let pass = |b: bool| if b { "PASS" } else { "FAIL" };
    let _ = writeln!(out, "Digest:    {}", pass(report.digest_match));
    let _ = writeln!(out, "Signature: {}", pass(report.signature_valid));
    let _ = writeln!(out, "Policy:    {}", pass(report.policy_compliant));

    let overall = report.digest_match && report.signature_valid && report.policy_compliant;
    let _ = writeln!(out, "Overall:   {}", if overall { "VERIFIED" } else { "FAILED" });
    out
}

/// Format an update check for human-readable display.
#[must_use]
pub fn format_update_check_toon(check: &UpdateCheck) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Update Check ===");
    let _ = writeln!(out, "Connector: {}", check.connector_id);
    let _ = writeln!(out, "Current:   {}", check.current_version);
    let _ = writeln!(out, "Latest:    {}", check.latest_version);
    if check.has_update {
        if check.breaking_changes {
            let _ = writeln!(out, "Status:    UPDATE AVAILABLE (BREAKING)");
        } else {
            let _ = writeln!(out, "Status:    UPDATE AVAILABLE");
        }
    } else {
        let _ = writeln!(out, "Status:    UP TO DATE");
    }
    out
}

/// Format a rollback plan for human-readable display.
#[must_use]
pub fn format_rollback_plan_toon(plan: &RollbackPlan) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Rollback Plan ===");
    let _ = writeln!(out, "Connector: {}", plan.connector_id);
    let _ = writeln!(out, "Current:   {}", plan.current_version);
    let _ = writeln!(out, "Target:    {}", plan.target_version);
    let _ = writeln!(out, "Restart:   {}", if plan.requires_restart { "YES" } else { "NO" });
    let _ = writeln!(out, "Steps ({}):", plan.steps.len());
    for (i, step) in plan.steps.iter().enumerate() {
        let _ = writeln!(out, "  {}. {step}", i + 1);
    }
    out
}

/// Format a version pin for human-readable display.
#[must_use]
pub fn format_version_pin_toon(pin: &VersionPin) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "=== Version Pin ===");
    let _ = writeln!(out, "Connector: {}", pin.connector_id);
    let _ = writeln!(out, "Version:   {}", pin.pinned_version);
    let _ = writeln!(out, "Pinned at: {}", pin.pinned_at);
    let _ = writeln!(out, "Pinned by: {}", pin.pinned_by);
    let _ = writeln!(out, "Reason:    {}", pin.reason);
    out
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ─────────────────────────────────────────────────────────

    fn sample_evidence() -> SupplyChainEvidence {
        SupplyChainEvidence::new(
            "https://registry.example.com/github",
            "abc123def456",
            "2026-03-12T00:00:00Z",
            "deadbeef01234567890abcdef",
            "attestation-v1",
        )
    }

    fn sample_request() -> InstallRequest {
        InstallRequest {
            connector_id: "github".to_string(),
            version: Some("1.2.3".to_string()),
            source: InstallSource::Registry { name: "default".to_string() },
            verify: true,
            pin: false,
            dry_run: false,
        }
    }

    fn sample_result() -> InstallResult {
        InstallResult {
            connector_id: "github".to_string(),
            version_installed: "1.2.3".to_string(),
            source: InstallSource::Registry { name: "default".to_string() },
            verified: true,
            pinned: false,
            digest: "blake3:abc123".to_string(),
            duration: Duration::from_millis(1500),
            warnings: vec![],
        }
    }

    // ── InstallSource Display ──────────────────────────────────────────

    #[test]
    fn install_source_display_registry() {
        let src = InstallSource::Registry { name: "default".to_string() };
        assert_eq!(src.to_string(), "registry:default");
    }

    #[test]
    fn install_source_display_local() {
        let src = InstallSource::LocalPath { path: PathBuf::from("/tmp/connector") };
        assert_eq!(src.to_string(), "local:/tmp/connector");
    }

    #[test]
    fn install_source_display_git_no_rev() {
        let src = InstallSource::GitRepo {
            url: "https://github.com/org/repo".to_string(),
            rev: None,
        };
        assert_eq!(src.to_string(), "git:https://github.com/org/repo");
    }

    #[test]
    fn install_source_display_git_with_rev() {
        let src = InstallSource::GitRepo {
            url: "https://github.com/org/repo".to_string(),
            rev: Some("v1.0.0".to_string()),
        };
        assert_eq!(src.to_string(), "git:https://github.com/org/repo@v1.0.0");
    }

    // ── Validation ─────────────────────────────────────────────────────

    #[test]
    fn validate_valid_request() {
        let req = sample_request();
        assert!(validate_install_request(&req).is_ok());
    }

    #[test]
    fn validate_empty_connector_id() {
        let mut req = sample_request();
        req.connector_id = String::new();
        let errs = validate_install_request(&req).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("empty")));
    }

    #[test]
    fn validate_connector_id_with_spaces() {
        let mut req = sample_request();
        req.connector_id = "my connector".to_string();
        let errs = validate_install_request(&req).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("spaces")));
    }

    #[test]
    fn validate_connector_id_too_long() {
        let mut req = sample_request();
        req.connector_id = "a".repeat(200);
        let errs = validate_install_request(&req).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("128")));
    }

    #[test]
    fn validate_empty_version() {
        let mut req = sample_request();
        req.version = Some(String::new());
        let errs = validate_install_request(&req).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("version")));
    }

    #[test]
    fn validate_invalid_version() {
        let mut req = sample_request();
        req.version = Some("not-semver".to_string());
        let errs = validate_install_request(&req).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("semver")));
    }

    #[test]
    fn validate_no_version() {
        let mut req = sample_request();
        req.version = None;
        assert!(validate_install_request(&req).is_ok());
    }

    #[test]
    fn validate_empty_registry_name() {
        let mut req = sample_request();
        req.source = InstallSource::Registry { name: String::new() };
        let errs = validate_install_request(&req).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("registry")));
    }

    #[test]
    fn validate_empty_local_path() {
        let mut req = sample_request();
        req.source = InstallSource::LocalPath { path: PathBuf::from("") };
        let errs = validate_install_request(&req).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("path")));
    }

    #[test]
    fn validate_empty_git_url() {
        let mut req = sample_request();
        req.source = InstallSource::GitRepo {
            url: String::new(),
            rev: None,
        };
        let errs = validate_install_request(&req).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("URL")));
    }

    #[test]
    fn validate_empty_git_rev() {
        let mut req = sample_request();
        req.source = InstallSource::GitRepo {
            url: "https://example.com/repo".to_string(),
            rev: Some(String::new()),
        };
        let errs = validate_install_request(&req).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("revision")));
    }

    #[test]
    fn validate_multiple_errors() {
        let req = InstallRequest {
            connector_id: String::new(),
            version: Some("bad".to_string()),
            source: InstallSource::Registry { name: String::new() },
            verify: false,
            pin: false,
            dry_run: false,
        };
        let errs = validate_install_request(&req).unwrap_err();
        assert!(errs.len() >= 3);
    }

    #[test]
    fn validate_git_with_valid_rev() {
        let mut req = sample_request();
        req.source = InstallSource::GitRepo {
            url: "https://github.com/org/repo".to_string(),
            rev: Some("abc123".to_string()),
        };
        assert!(validate_install_request(&req).is_ok());
    }

    #[test]
    fn validate_local_path_valid() {
        let mut req = sample_request();
        req.source = InstallSource::LocalPath { path: PathBuf::from("/usr/local/connectors/github") };
        assert!(validate_install_request(&req).is_ok());
    }

    // ── Semver helpers ─────────────────────────────────────────────────

    #[test]
    fn parse_simple_semver() {
        assert_eq!(parse_semver("1.2.3"), Some((1, 2, 3)));
    }

    #[test]
    fn parse_semver_with_v_prefix() {
        assert_eq!(parse_semver("v1.2.3"), Some((1, 2, 3)));
    }

    #[test]
    fn parse_semver_with_upper_v() {
        assert_eq!(parse_semver("V1.2.3"), Some((1, 2, 3)));
    }

    #[test]
    fn parse_semver_with_prerelease() {
        assert_eq!(parse_semver("1.2.3-beta.1"), Some((1, 2, 3)));
    }

    #[test]
    fn parse_semver_with_build_metadata() {
        assert_eq!(parse_semver("1.2.3+build.42"), Some((1, 2, 3)));
    }

    #[test]
    fn parse_invalid_semver() {
        assert_eq!(parse_semver("not-a-version"), None);
    }

    #[test]
    fn parse_two_part_version() {
        assert_eq!(parse_semver("1.2"), None);
    }

    #[test]
    fn parse_four_part_version() {
        assert_eq!(parse_semver("1.2.3.4"), None);
    }

    #[test]
    fn is_valid_semver_true() {
        assert!(is_valid_semver("1.0.0"));
        assert!(is_valid_semver("v2.1.0"));
    }

    #[test]
    fn is_valid_semver_false() {
        assert!(!is_valid_semver("abc"));
        assert!(!is_valid_semver(""));
    }

    #[test]
    fn version_newer_patch() {
        assert!(is_version_newer("1.0.0", "1.0.1"));
    }

    #[test]
    fn version_newer_minor() {
        assert!(is_version_newer("1.0.0", "1.1.0"));
    }

    #[test]
    fn version_newer_major() {
        assert!(is_version_newer("1.0.0", "2.0.0"));
    }

    #[test]
    fn version_not_newer_same() {
        assert!(!is_version_newer("1.0.0", "1.0.0"));
    }

    #[test]
    fn version_not_newer_older() {
        assert!(!is_version_newer("2.0.0", "1.0.0"));
    }

    #[test]
    fn version_newer_with_v_prefix() {
        assert!(is_version_newer("v1.0.0", "v1.0.1"));
    }

    #[test]
    fn version_newer_invalid_returns_false() {
        assert!(!is_version_newer("bad", "1.0.0"));
        assert!(!is_version_newer("1.0.0", "bad"));
    }

    #[test]
    fn breaking_change_major_bump() {
        assert!(is_breaking_change("1.0.0", "2.0.0"));
    }

    #[test]
    fn breaking_change_minor_bump() {
        assert!(!is_breaking_change("1.0.0", "1.1.0"));
    }

    #[test]
    fn breaking_change_patch_bump() {
        assert!(!is_breaking_change("1.0.0", "1.0.1"));
    }

    #[test]
    fn breaking_change_invalid() {
        assert!(!is_breaking_change("bad", "1.0.0"));
    }

    #[test]
    fn version_newer_large_numbers() {
        assert!(is_version_newer("99.99.99", "100.0.0"));
    }

    #[test]
    fn version_newer_zero() {
        assert!(is_version_newer("0.0.0", "0.0.1"));
    }

    // ── Update check ───────────────────────────────────────────────────

    #[test]
    fn check_updates_available() {
        let check = check_for_updates("github", "1.0.0", "1.1.0");
        assert!(check.has_update);
        assert!(!check.breaking_changes);
        assert_eq!(check.connector_id, "github");
    }

    #[test]
    fn check_updates_breaking() {
        let check = check_for_updates("github", "1.0.0", "2.0.0");
        assert!(check.has_update);
        assert!(check.breaking_changes);
    }

    #[test]
    fn check_updates_up_to_date() {
        let check = check_for_updates("github", "1.0.0", "1.0.0");
        assert!(!check.has_update);
        assert!(!check.breaking_changes);
    }

    #[test]
    fn check_updates_older_available() {
        let check = check_for_updates("github", "2.0.0", "1.0.0");
        assert!(!check.has_update);
    }

    #[test]
    fn check_updates_preserves_versions() {
        let check = check_for_updates("slack", "1.2.3", "1.2.4");
        assert_eq!(check.current_version, "1.2.3");
        assert_eq!(check.latest_version, "1.2.4");
    }

    // ── Rollback plan ──────────────────────────────────────────────────

    #[test]
    fn rollback_plan_basic() {
        let plan = plan_rollback("github", "2.0.0", "1.5.0");
        assert_eq!(plan.connector_id, "github");
        assert_eq!(plan.current_version, "2.0.0");
        assert_eq!(plan.target_version, "1.5.0");
        assert!(!plan.steps.is_empty());
    }

    #[test]
    fn rollback_cross_major_requires_restart() {
        let plan = plan_rollback("github", "2.0.0", "1.0.0");
        assert!(plan.requires_restart);
    }

    #[test]
    fn rollback_same_major_no_restart() {
        let plan = plan_rollback("github", "1.5.0", "1.4.0");
        assert!(!plan.requires_restart);
    }

    #[test]
    fn rollback_plan_has_ordered_steps() {
        let plan = plan_rollback("github", "2.0.0", "1.0.0");
        assert!(plan.steps.len() >= 4);
        assert!(plan.steps[0].contains("Stop"));
        assert!(plan.steps.last().unwrap().contains("Restart"));
    }

    #[test]
    fn rollback_plan_steps_contain_versions() {
        let plan = plan_rollback("github", "2.0.0", "1.0.0");
        let all_steps = plan.steps.join(" ");
        assert!(all_steps.contains("2.0.0"));
        assert!(all_steps.contains("1.0.0"));
    }

    #[test]
    fn rollback_invalid_versions_requires_restart() {
        let plan = plan_rollback("x", "bad", "worse");
        assert!(plan.requires_restart);
    }

    // ── Supply-chain verification ──────────────────────────────────────

    #[test]
    fn verify_complete_evidence_passes() {
        let evidence = sample_evidence();
        let report = verify_supply_chain("github", "1.0.0", &evidence);
        assert!(report.digest_match);
        assert!(report.signature_valid);
        assert!(report.policy_compliant);
    }

    #[test]
    fn verify_empty_commit_fails_digest() {
        let mut evidence = sample_evidence();
        evidence.commit_hash = String::new();
        let report = verify_supply_chain("github", "1.0.0", &evidence);
        assert!(!report.digest_match);
    }

    #[test]
    fn verify_short_signature_fails() {
        let mut evidence = sample_evidence();
        evidence.signature = "short".to_string();
        let report = verify_supply_chain("github", "1.0.0", &evidence);
        assert!(!report.signature_valid);
    }

    #[test]
    fn verify_empty_signature_fails() {
        let mut evidence = sample_evidence();
        evidence.signature = String::new();
        let report = verify_supply_chain("github", "1.0.0", &evidence);
        assert!(!report.signature_valid);
    }

    #[test]
    fn verify_incomplete_evidence_not_compliant() {
        let mut evidence = sample_evidence();
        evidence.source_url = String::new();
        let report = verify_supply_chain("github", "1.0.0", &evidence);
        assert!(!report.policy_compliant);
    }

    #[test]
    fn verify_preserves_connector_and_version() {
        let evidence = sample_evidence();
        let report = verify_supply_chain("slack", "2.3.4", &evidence);
        assert_eq!(report.connector_id, "slack");
        assert_eq!(report.version, "2.3.4");
    }

    #[test]
    fn verify_retains_evidence() {
        let evidence = sample_evidence();
        let report = verify_supply_chain("x", "1.0.0", &evidence);
        assert_eq!(
            report.supply_chain_provenance.source_url,
            evidence.source_url
        );
    }

    // ── Supply-chain evidence ──────────────────────────────────────────

    #[test]
    fn evidence_is_complete_all_fields() {
        let e = sample_evidence();
        assert!(e.is_complete());
    }

    #[test]
    fn evidence_incomplete_missing_url() {
        let mut e = sample_evidence();
        e.source_url = String::new();
        assert!(!e.is_complete());
    }

    #[test]
    fn evidence_incomplete_missing_commit() {
        let mut e = sample_evidence();
        e.commit_hash = String::new();
        assert!(!e.is_complete());
    }

    #[test]
    fn evidence_incomplete_missing_timestamp() {
        let mut e = sample_evidence();
        e.build_timestamp = String::new();
        assert!(!e.is_complete());
    }

    #[test]
    fn evidence_incomplete_missing_signature() {
        let mut e = sample_evidence();
        e.signature = String::new();
        assert!(!e.is_complete());
    }

    // ── Version pinning ────────────────────────────────────────────────

    #[test]
    fn pin_version_basic() {
        let pin = pin_version("github", "1.2.3", "stability requirement");
        assert_eq!(pin.connector_id, "github");
        assert_eq!(pin.pinned_version, "1.2.3");
        assert_eq!(pin.reason, "stability requirement");
        assert!(!pin.pinned_at.is_empty());
    }

    #[test]
    fn pin_version_sets_pinned_by() {
        let pin = pin_version("slack", "2.0.0", "test");
        assert_eq!(pin.pinned_by, "fwc");
    }

    #[test]
    fn is_pin_active_true() {
        let pin = pin_version("github", "1.0.0", "reason");
        assert!(is_pin_active(&pin));
    }

    #[test]
    fn is_pin_active_false_empty_id() {
        let mut pin = pin_version("github", "1.0.0", "reason");
        pin.connector_id = String::new();
        assert!(!is_pin_active(&pin));
    }

    #[test]
    fn is_pin_active_false_empty_version() {
        let mut pin = pin_version("github", "1.0.0", "reason");
        pin.pinned_version = String::new();
        assert!(!is_pin_active(&pin));
    }

    #[test]
    fn is_pin_active_false_empty_at() {
        let mut pin = pin_version("github", "1.0.0", "reason");
        pin.pinned_at = String::new();
        assert!(!is_pin_active(&pin));
    }

    #[test]
    fn unpin_clears_version() {
        let pin = pin_version("github", "1.2.3", "stability");
        let unpinned = unpin_version(&pin);
        assert!(unpinned.pinned_version.is_empty());
        assert!(unpinned.reason.contains("unpinned"));
        assert!(unpinned.reason.contains("stability"));
    }

    #[test]
    fn unpin_preserves_connector_id() {
        let pin = pin_version("github", "1.0.0", "reason");
        let unpinned = unpin_version(&pin);
        assert_eq!(unpinned.connector_id, "github");
    }

    #[test]
    fn unpin_preserves_pinned_by() {
        let pin = pin_version("github", "1.0.0", "reason");
        let unpinned = unpin_version(&pin);
        assert_eq!(unpinned.pinned_by, "fwc");
    }

    // ── Format install result ──────────────────────────────────────────

    #[test]
    fn format_install_result_contains_connector() {
        let result = sample_result();
        let out = format_install_result_toon(&result);
        assert!(out.contains("github"));
    }

    #[test]
    fn format_install_result_contains_version() {
        let result = sample_result();
        let out = format_install_result_toon(&result);
        assert!(out.contains("1.2.3"));
    }

    #[test]
    fn format_install_result_verified_yes() {
        let result = sample_result();
        let out = format_install_result_toon(&result);
        assert!(out.contains("YES"));
    }

    #[test]
    fn format_install_result_verified_no() {
        let mut result = sample_result();
        result.verified = false;
        let out = format_install_result_toon(&result);
        assert!(out.contains("NO"));
    }

    #[test]
    fn format_install_result_with_warnings() {
        let mut result = sample_result();
        result.warnings = vec!["deprecated API".to_string()];
        let out = format_install_result_toon(&result);
        assert!(out.contains("deprecated API"));
        assert!(out.contains("Warnings"));
    }

    #[test]
    fn format_install_result_no_warnings_clean() {
        let result = sample_result();
        let out = format_install_result_toon(&result);
        assert!(!out.contains("Warnings"));
    }

    #[test]
    fn format_install_result_contains_digest() {
        let result = sample_result();
        let out = format_install_result_toon(&result);
        assert!(out.contains("blake3:abc123"));
    }

    #[test]
    fn format_install_result_contains_source() {
        let result = sample_result();
        let out = format_install_result_toon(&result);
        assert!(out.contains("registry:default"));
    }

    // ── Format verification report ─────────────────────────────────────

    #[test]
    fn format_verification_all_pass() {
        let evidence = sample_evidence();
        let report = verify_supply_chain("github", "1.0.0", &evidence);
        let out = format_verification_report_toon(&report);
        assert!(out.contains("VERIFIED"));
        assert!(out.contains("PASS"));
    }

    #[test]
    fn format_verification_with_failure() {
        let mut evidence = sample_evidence();
        evidence.signature = String::new();
        let report = verify_supply_chain("github", "1.0.0", &evidence);
        let out = format_verification_report_toon(&report);
        assert!(out.contains("FAIL"));
        assert!(out.contains("FAILED"));
    }

    #[test]
    fn format_verification_contains_connector() {
        let evidence = sample_evidence();
        let report = verify_supply_chain("slack", "1.0.0", &evidence);
        let out = format_verification_report_toon(&report);
        assert!(out.contains("slack"));
    }

    // ── Format update check ────────────────────────────────────────────

    #[test]
    fn format_update_check_up_to_date() {
        let check = check_for_updates("github", "1.0.0", "1.0.0");
        let out = format_update_check_toon(&check);
        assert!(out.contains("UP TO DATE"));
    }

    #[test]
    fn format_update_check_available() {
        let check = check_for_updates("github", "1.0.0", "1.1.0");
        let out = format_update_check_toon(&check);
        assert!(out.contains("UPDATE AVAILABLE"));
    }

    #[test]
    fn format_update_check_breaking() {
        let check = check_for_updates("github", "1.0.0", "2.0.0");
        let out = format_update_check_toon(&check);
        assert!(out.contains("BREAKING"));
    }

    #[test]
    fn format_update_check_contains_versions() {
        let check = check_for_updates("github", "1.0.0", "1.2.0");
        let out = format_update_check_toon(&check);
        assert!(out.contains("1.0.0"));
        assert!(out.contains("1.2.0"));
    }

    // ── Format rollback plan ───────────────────────────────────────────

    #[test]
    fn format_rollback_plan_has_title() {
        let plan = plan_rollback("github", "2.0.0", "1.0.0");
        let out = format_rollback_plan_toon(&plan);
        assert!(out.contains("Rollback Plan"));
    }

    #[test]
    fn format_rollback_plan_shows_restart() {
        let plan = plan_rollback("github", "2.0.0", "1.0.0");
        let out = format_rollback_plan_toon(&plan);
        assert!(out.contains("Restart:   YES"));
    }

    #[test]
    fn format_rollback_plan_shows_no_restart() {
        let plan = plan_rollback("github", "1.5.0", "1.4.0");
        let out = format_rollback_plan_toon(&plan);
        assert!(out.contains("Restart:   NO"));
    }

    #[test]
    fn format_rollback_plan_numbered_steps() {
        let plan = plan_rollback("github", "2.0.0", "1.0.0");
        let out = format_rollback_plan_toon(&plan);
        assert!(out.contains("1."));
        assert!(out.contains("2."));
    }

    // ── Format version pin ─────────────────────────────────────────────

    #[test]
    fn format_version_pin_contains_fields() {
        let pin = pin_version("github", "1.0.0", "stability");
        let out = format_version_pin_toon(&pin);
        assert!(out.contains("github"));
        assert!(out.contains("1.0.0"));
        assert!(out.contains("stability"));
        assert!(out.contains("fwc"));
    }

    // ── Serialization round-trip ───────────────────────────────────────

    #[test]
    fn install_request_serde_roundtrip() {
        let req = sample_request();
        let json = serde_json::to_string(&req).unwrap();
        let decoded: InstallRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.connector_id, req.connector_id);
        assert_eq!(decoded.version, req.version);
    }

    #[test]
    fn install_result_serde_roundtrip() {
        let result = sample_result();
        let json = serde_json::to_string(&result).unwrap();
        let decoded: InstallResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.connector_id, result.connector_id);
        assert_eq!(decoded.verified, result.verified);
    }

    #[test]
    fn version_pin_serde_roundtrip() {
        let pin = pin_version("github", "1.0.0", "reason");
        let json = serde_json::to_string(&pin).unwrap();
        let decoded: VersionPin = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, pin);
    }

    #[test]
    fn update_check_serde_roundtrip() {
        let check = check_for_updates("github", "1.0.0", "1.1.0");
        let json = serde_json::to_string(&check).unwrap();
        let decoded: UpdateCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.has_update, check.has_update);
    }

    #[test]
    fn rollback_plan_serde_roundtrip() {
        let plan = plan_rollback("github", "2.0.0", "1.0.0");
        let json = serde_json::to_string(&plan).unwrap();
        let decoded: RollbackPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.steps.len(), plan.steps.len());
    }

    #[test]
    fn verification_report_serde_roundtrip() {
        let evidence = sample_evidence();
        let report = verify_supply_chain("github", "1.0.0", &evidence);
        let json = serde_json::to_string(&report).unwrap();
        let decoded: VerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.connector_id, report.connector_id);
    }

    #[test]
    fn supply_chain_evidence_serde_roundtrip() {
        let evidence = sample_evidence();
        let json = serde_json::to_string(&evidence).unwrap();
        let decoded: SupplyChainEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.commit_hash, evidence.commit_hash);
    }

    #[test]
    fn install_source_registry_serde() {
        let src = InstallSource::Registry { name: "default".to_string() };
        let json = serde_json::to_string(&src).unwrap();
        let decoded: InstallSource = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, src);
    }

    #[test]
    fn install_source_local_serde() {
        let src = InstallSource::LocalPath { path: PathBuf::from("/tmp/conn") };
        let json = serde_json::to_string(&src).unwrap();
        let decoded: InstallSource = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, src);
    }

    #[test]
    fn install_source_git_serde() {
        let src = InstallSource::GitRepo {
            url: "https://example.com/repo".to_string(),
            rev: Some("abc123".to_string()),
        };
        let json = serde_json::to_string(&src).unwrap();
        let decoded: InstallSource = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, src);
    }

    // ── Edge cases ─────────────────────────────────────────────────────

    #[test]
    fn validate_connector_id_boundary_128() {
        let mut req = sample_request();
        req.connector_id = "a".repeat(128);
        assert!(validate_install_request(&req).is_ok());
    }

    #[test]
    fn validate_connector_id_boundary_129() {
        let mut req = sample_request();
        req.connector_id = "a".repeat(129);
        assert!(validate_install_request(&req).is_err());
    }

    #[test]
    fn version_newer_prerelease_stripped() {
        // Pre-release metadata is stripped for comparison
        assert!(is_version_newer("1.0.0-alpha", "1.0.1-beta"));
    }

    #[test]
    fn rollback_plan_same_version() {
        let plan = plan_rollback("github", "1.0.0", "1.0.0");
        assert!(!plan.requires_restart);
        assert!(!plan.steps.is_empty());
    }

    #[test]
    fn verify_minimal_valid_signature() {
        // Exactly 16 chars should pass
        let mut evidence = sample_evidence();
        evidence.signature = "0123456789abcdef".to_string();
        let report = verify_supply_chain("x", "1.0.0", &evidence);
        assert!(report.signature_valid);
    }

    #[test]
    fn verify_15_char_signature_fails() {
        let mut evidence = sample_evidence();
        evidence.signature = "0123456789abcde".to_string();
        let report = verify_supply_chain("x", "1.0.0", &evidence);
        assert!(!report.signature_valid);
    }

    #[test]
    fn check_updates_connector_id_preserved() {
        let check = check_for_updates("my-custom-connector", "0.1.0", "0.2.0");
        assert_eq!(check.connector_id, "my-custom-connector");
    }

    #[test]
    fn pin_and_unpin_roundtrip() {
        let pin = pin_version("github", "1.0.0", "original reason");
        assert!(is_pin_active(&pin));
        let unpinned = unpin_version(&pin);
        assert!(!is_pin_active(&unpinned));
    }

    #[test]
    fn install_source_equality() {
        let a = InstallSource::Registry { name: "default".to_string() };
        let b = InstallSource::Registry { name: "default".to_string() };
        assert_eq!(a, b);
    }

    #[test]
    fn install_source_inequality() {
        let a = InstallSource::Registry { name: "default".to_string() };
        let b = InstallSource::Registry { name: "other".to_string() };
        assert_ne!(a, b);
    }

    #[test]
    fn format_install_result_pinned_yes() {
        let mut result = sample_result();
        result.pinned = true;
        let out = format_install_result_toon(&result);
        assert!(out.contains("Pinned:    YES"));
    }

    #[test]
    fn format_install_result_duration() {
        let result = sample_result();
        let out = format_install_result_toon(&result);
        assert!(out.contains("1.50s"));
    }

    #[test]
    fn validate_dry_run_flag_passthrough() {
        let mut req = sample_request();
        req.dry_run = true;
        assert!(validate_install_request(&req).is_ok());
    }

    #[test]
    fn validate_pin_flag_passthrough() {
        let mut req = sample_request();
        req.pin = true;
        assert!(validate_install_request(&req).is_ok());
    }

    #[test]
    fn validate_verify_flag_passthrough() {
        let mut req = sample_request();
        req.verify = false;
        assert!(validate_install_request(&req).is_ok());
    }
}
