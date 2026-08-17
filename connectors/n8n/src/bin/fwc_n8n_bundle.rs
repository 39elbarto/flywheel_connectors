//! Immutable, host-derived release-bundle verification for `fwc-n8n status`.
//!
//! The verifier deliberately has no configurable path or release lookup.  It
//! starts at the canonical current executable, derives its fixed `bin/` and
//! release-root parents, and validates one exact receipt plus twelve exact
//! sibling artifacts.  Root ownership and non-writable group/other modes are
//! the current local trust root; this module does not claim signature
//! verification.

use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use fcp_manifest::LocalMcpPolicy;
use serde::Deserialize;
use serde_json::Value;

const RECEIPT_SCHEMA: &str = "fwc.n8n.bundle.v1";
const RECEIPT_FILE: &str = "receipt.json";
const MAX_RECEIPT_BYTES: usize = 128 * 1024;
const MAX_INVENTORY_BYTES: usize = 2 * 1024 * 1024;
const MAX_LOCAL_MCP_POLICY_BYTES: usize = 256 * 1024;
const EXPECTED_ARTIFACTS: [&str; 12] = [
    "bin/fwc-n8n",
    "bin/fcp-host",
    "bin/fcp-n8n",
    "bin/fcp-mcp-bridge",
    "manifests/fcp-n8n.toml",
    "manifests/fcp-mcp-bridge.toml",
    "inventory/eec.json",
    "inventory/hetzner.json",
    "inventory/eec-official-mcp.json",
    "inventory/hetzner-official-mcp.json",
    "policy/zone-policies.json",
    "policy/local-mcp.json",
];
const EXECUTABLE_ARTIFACTS: [&str; 4] = [
    "bin/fwc-n8n",
    "bin/fcp-host",
    "bin/fcp-n8n",
    "bin/fcp-mcp-bridge",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum BundleErrorCode {
    #[cfg(not(unix))]
    UnsupportedPlatform,
    NotBundleExecutable,
    Layout,
    Metadata,
    Permissions,
    Receipt,
    ReleaseId,
    ArtifactSet,
    ArtifactPath,
    Digest,
    RuntimeFormat,
    InventoryBinding,
    LocalMcpPolicy,
}

impl BundleErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            #[cfg(not(unix))]
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::NotBundleExecutable => "not_bundle_executable",
            Self::Layout => "invalid_layout",
            Self::Metadata => "invalid_metadata",
            Self::Permissions => "invalid_permissions",
            Self::Receipt => "invalid_receipt",
            Self::ReleaseId => "invalid_release_id",
            Self::ArtifactSet => "invalid_artifact_set",
            Self::ArtifactPath => "invalid_artifact_path",
            Self::Digest => "digest_mismatch",
            Self::RuntimeFormat => "invalid_runtime_format",
            Self::InventoryBinding => "invalid_inventory_binding",
            Self::LocalMcpPolicy => "invalid_local_mcp_policy",
        }
    }
}

impl fmt::Debug for BundleErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BundleError {
    code: BundleErrorCode,
}

impl BundleError {
    const fn new(code: BundleErrorCode) -> Self {
        Self { code }
    }

    #[cfg(test)]
    const fn code(self) -> BundleErrorCode {
        self.code
    }
}

impl fmt::Debug for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "fwc-n8n bundle unavailable: {}",
            self.code.as_str()
        )
    }
}

impl std::error::Error for BundleError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleReceipt {
    schema: String,
    release_id: String,
    artifacts: Vec<BundleArtifact>,
}

impl fmt::Debug for BundleReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleReceipt")
            .field("schema", &"<redacted>")
            .field("release_id", &"<redacted>")
            .field("artifact_count", &self.artifacts.len())
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleArtifact {
    path: String,
    digest: String,
}

impl fmt::Debug for BundleArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleArtifact")
            .field("path", &"<redacted>")
            .field("digest", &"<redacted>")
            .finish()
    }
}

/// The only bundle facts that the internal host runner may consume.
///
/// Every path is derived from the canonical current executable and every
/// digest was checked against the immutable receipt before this value was
/// constructed.  This type intentionally exposes no release-root or caller
/// supplied path and never reveals its contents through `Debug`.
pub struct VerifiedBundle {
    fcp_host_path: PathBuf,
    fcp_host_digest: String,
    inventory_eec_path: PathBuf,
    inventory_eec_digest: String,
    inventory_hetzner_path: PathBuf,
    inventory_hetzner_digest: String,
    inventory_eec_official_mcp_path: PathBuf,
    inventory_eec_official_mcp_digest: String,
    inventory_hetzner_official_mcp_path: PathBuf,
    inventory_hetzner_official_mcp_digest: String,
    zone_policy_path: PathBuf,
    zone_policy_digest: String,
    local_mcp_policy: LocalMcpPolicy,
}

impl fmt::Debug for VerifiedBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBundle")
            .field("artifact_count", &12)
            .field("digests", &"<redacted>")
            .finish()
    }
}

impl VerifiedBundle {
    pub fn fcp_host(&self) -> (&Path, &str) {
        (&self.fcp_host_path, &self.fcp_host_digest)
    }

    pub fn inventory_eec(&self) -> (&Path, &str) {
        (&self.inventory_eec_path, &self.inventory_eec_digest)
    }

    pub fn inventory_hetzner(&self) -> (&Path, &str) {
        (&self.inventory_hetzner_path, &self.inventory_hetzner_digest)
    }

    pub fn inventory_eec_official_mcp(&self) -> (&Path, &str) {
        (
            &self.inventory_eec_official_mcp_path,
            &self.inventory_eec_official_mcp_digest,
        )
    }

    pub fn inventory_hetzner_official_mcp(&self) -> (&Path, &str) {
        (
            &self.inventory_hetzner_official_mcp_path,
            &self.inventory_hetzner_official_mcp_digest,
        )
    }

    pub fn zone_policy(&self) -> (&Path, &str) {
        (&self.zone_policy_path, &self.zone_policy_digest)
    }

    pub const fn local_mcp_policy(&self) -> &LocalMcpPolicy {
        &self.local_mcp_policy
    }

    #[cfg(test)]
    pub fn test_fixture() -> Self {
        Self {
            fcp_host_path: PathBuf::from("/release/bin/fcp-host"),
            fcp_host_digest: "a".repeat(64),
            inventory_eec_path: PathBuf::from("/release/inventory/eec.json"),
            inventory_eec_digest: "b".repeat(64),
            inventory_hetzner_path: PathBuf::from("/release/inventory/hetzner.json"),
            inventory_hetzner_digest: "c".repeat(64),
            inventory_eec_official_mcp_path: PathBuf::from(
                "/release/inventory/eec-official-mcp.json",
            ),
            inventory_eec_official_mcp_digest: "e".repeat(64),
            inventory_hetzner_official_mcp_path: PathBuf::from(
                "/release/inventory/hetzner-official-mcp.json",
            ),
            inventory_hetzner_official_mcp_digest: "f".repeat(64),
            zone_policy_path: PathBuf::from("/release/policy/zone-policies.json"),
            zone_policy_digest: "d".repeat(64),
            local_mcp_policy: test_local_mcp_policy(),
        }
    }
}

#[cfg(test)]
fn test_local_mcp_policy() -> LocalMcpPolicy {
    serde_json::from_value(serde_json::json!({
        "package_id": "n8n-mcp",
        "package_version": "2.69.0",
        "launcher_path": "/usr/bin/node",
        "launcher_digest": "0".repeat(64),
        "runtime_executable": "/usr/bin/node",
        "runtime_executable_digest": "0".repeat(64),
        "package_metadata_path": "/usr/local/lib/node_modules/n8n-mcp/package.json",
        "package_metadata_digest": "0".repeat(64),
        "protocol_version": "2024-11-05",
        "fixed_args": ["/usr/local/lib/node_modules/n8n-mcp/dist/mcp/stdio-wrapper.js"],
        "fixed_env": {"N8N_MCP_TELEMETRY_DISABLED": "true"},
        "allowed_methods": ["initialize", "notifications/initialized", "tools/list", "tools/call"],
        "expected_catalog": {
            "tools_documentation": "0".repeat(64),
            "search_nodes": "0".repeat(64),
            "get_node": "0".repeat(64),
            "validate_node": "0".repeat(64),
            "get_template": "0".repeat(64),
            "search_templates": "0".repeat(64),
            "validate_workflow": "0".repeat(64),
        },
        "callable_tools": [
            "tools_documentation", "search_nodes", "get_node", "validate_node",
            "get_template", "search_templates", "validate_workflow"
        ],
        "max_frame_bytes": 262144,
        "max_request_bytes": 65536,
        "max_result_bytes": 262144,
        "max_sequential_calls": 7,
        "startup_timeout_ms": 30000,
        "request_timeout_ms": 30000,
        "shutdown_timeout_ms": 2000,
        "idle_window_ms": 0,
        "network_disabled": true
    }))
    .expect("test local MCP policy")
}

/// Verify the fixed release bundle selected by the canonical current binary.
pub fn verify_current_release_bundle() -> Result<(), BundleError> {
    verify_current_release_bundle_for_bridge().map(|_| ())
}

/// Verify and return the fixed facts needed by the internal host runner.
pub fn verify_current_release_bundle_for_bridge() -> Result<VerifiedBundle, BundleError> {
    #[cfg(not(unix))]
    {
        Err(BundleError::new(BundleErrorCode::UnsupportedPlatform))
    }

    #[cfg(unix)]
    {
        let executable =
            std::env::current_exe().map_err(|_| BundleError::new(BundleErrorCode::Metadata))?;
        verify_release_bundle(&executable, 0)
    }
}

#[cfg(unix)]
fn verify_release_bundle(
    executable: &Path,
    expected_owner: u32,
) -> Result<VerifiedBundle, BundleError> {
    let executable = verify_file(executable, expected_owner, true)?;
    if executable.file_name().and_then(|name| name.to_str()) != Some("fwc-n8n") {
        return Err(BundleError::new(BundleErrorCode::NotBundleExecutable));
    }

    let bin = executable
        .parent()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) == Some("bin"))
        .ok_or_else(|| BundleError::new(BundleErrorCode::Layout))?;
    let root = bin
        .parent()
        .ok_or_else(|| BundleError::new(BundleErrorCode::Layout))?;
    verify_directory(root, expected_owner)?;
    verify_directory(bin, expected_owner)?;
    for directory in ["manifests", "inventory", "policy"] {
        verify_directory(&root.join(directory), expected_owner)?;
    }

    let receipt_path = root.join(RECEIPT_FILE);
    verify_file(&receipt_path, expected_owner, false)?;
    let receipt = read_receipt(&receipt_path)?;
    validate_receipt_shape(&receipt, root)?;

    let verified_artifacts = verify_release_artifacts(root, expected_owner, &receipt)?;

    let artifact = |relative_path: &str| {
        verified_artifacts
            .iter()
            .find(|(path, _, _)| *path == relative_path)
            .map(|(_, path, digest)| (path.clone(), digest.clone()))
            .ok_or_else(|| BundleError::new(BundleErrorCode::ArtifactSet))
    };
    let (fcp_host_path, fcp_host_digest) = artifact("bin/fcp-host")?;
    let (fcp_n8n_path, fcp_n8n_digest) = artifact("bin/fcp-n8n")?;
    let (fcp_mcp_bridge_path, fcp_mcp_bridge_digest) = artifact("bin/fcp-mcp-bridge")?;
    let (manifest_path, _) = artifact("manifests/fcp-n8n.toml")?;
    let (mcp_manifest_path, _) = artifact("manifests/fcp-mcp-bridge.toml")?;
    let (inventory_eec_path, inventory_eec_digest) = artifact("inventory/eec.json")?;
    let (inventory_hetzner_path, inventory_hetzner_digest) = artifact("inventory/hetzner.json")?;
    let (inventory_eec_official_mcp_path, inventory_eec_official_mcp_digest) =
        artifact("inventory/eec-official-mcp.json")?;
    let (inventory_hetzner_official_mcp_path, inventory_hetzner_official_mcp_digest) =
        artifact("inventory/hetzner-official-mcp.json")?;
    let (zone_policy_path, zone_policy_digest) = artifact("policy/zone-policies.json")?;
    let (local_mcp_policy_path, _) = artifact("policy/local-mcp.json")?;
    let local_mcp_policy = read_local_mcp_policy(&local_mcp_policy_path)?;
    #[cfg(target_os = "linux")]
    fcp_sandbox::verify_fixed_static_executable(&fcp_n8n_path)
        .map_err(|_| BundleError::new(BundleErrorCode::RuntimeFormat))?;
    #[cfg(target_os = "linux")]
    fcp_sandbox::verify_fixed_static_executable(&fcp_mcp_bridge_path)
        .map_err(|_| BundleError::new(BundleErrorCode::RuntimeFormat))?;
    #[cfg(not(target_os = "linux"))]
    return Err(BundleError::new(BundleErrorCode::RuntimeFormat));
    verify_inventory_binding(
        &inventory_eec_path,
        "eec",
        "fcp.n8n",
        &fcp_n8n_path,
        &fcp_n8n_digest,
        &manifest_path,
    )?;
    verify_inventory_binding(
        &inventory_hetzner_path,
        "hetzner",
        "fcp.n8n",
        &fcp_n8n_path,
        &fcp_n8n_digest,
        &manifest_path,
    )?;
    verify_inventory_binding(
        &inventory_eec_official_mcp_path,
        "eec",
        "fcp.mcp-bridge",
        &fcp_mcp_bridge_path,
        &fcp_mcp_bridge_digest,
        &mcp_manifest_path,
    )?;
    verify_inventory_binding(
        &inventory_hetzner_official_mcp_path,
        "hetzner",
        "fcp.mcp-bridge",
        &fcp_mcp_bridge_path,
        &fcp_mcp_bridge_digest,
        &mcp_manifest_path,
    )?;
    Ok(VerifiedBundle {
        fcp_host_path,
        fcp_host_digest,
        inventory_eec_path,
        inventory_eec_digest,
        inventory_hetzner_path,
        inventory_hetzner_digest,
        inventory_eec_official_mcp_path,
        inventory_eec_official_mcp_digest,
        inventory_hetzner_official_mcp_path,
        inventory_hetzner_official_mcp_digest,
        zone_policy_path,
        zone_policy_digest,
        local_mcp_policy,
    })
}

#[cfg(unix)]
fn verify_release_artifacts(
    root: &Path,
    expected_owner: u32,
    receipt: &BundleReceipt,
) -> Result<Vec<(&'static str, PathBuf, String)>, BundleError> {
    let mut verified = Vec::with_capacity(EXPECTED_ARTIFACTS.len());
    for relative_path in EXPECTED_ARTIFACTS {
        let artifact = verify_file(
            &root.join(relative_path),
            expected_owner,
            EXECUTABLE_ARTIFACTS.contains(&relative_path),
        )?;
        if !artifact.starts_with(root) {
            return Err(BundleError::new(BundleErrorCode::ArtifactPath));
        }
        let expected_digest = receipt
            .artifacts
            .iter()
            .find(|entry| entry.path == relative_path)
            .map(|entry| entry.digest.as_str())
            .ok_or_else(|| BundleError::new(BundleErrorCode::ArtifactSet))?;
        let actual_digest = hash_file(&artifact)?;
        if actual_digest != expected_digest {
            return Err(BundleError::new(BundleErrorCode::Digest));
        }
        verified.push((relative_path, artifact, actual_digest));
    }
    Ok(verified)
}

fn read_local_mcp_policy(path: &Path) -> Result<LocalMcpPolicy, BundleError> {
    let value = read_bounded_json(path, MAX_LOCAL_MCP_POLICY_BYTES)
        .map_err(|_| BundleError::new(BundleErrorCode::LocalMcpPolicy))?;
    let policy: LocalMcpPolicy = serde_json::from_value(value)
        .map_err(|_| BundleError::new(BundleErrorCode::LocalMcpPolicy))?;
    policy
        .validate()
        .map_err(|_| BundleError::new(BundleErrorCode::LocalMcpPolicy))?;
    Ok(policy)
}

fn verify_inventory_binding(
    path: &Path,
    expected_server_id: &str,
    expected_connector_id: &str,
    executable: &Path,
    executable_digest: &str,
    manifest: &Path,
) -> Result<(), BundleError> {
    let value = read_bounded_json(path, MAX_INVENTORY_BYTES)
        .map_err(|_| BundleError::new(BundleErrorCode::InventoryBinding))?;
    let entries = value
        .as_array()
        .filter(|entries| entries.len() == 1)
        .ok_or_else(|| BundleError::new(BundleErrorCode::InventoryBinding))?;
    let entry = &entries[0];
    let executable = executable
        .to_str()
        .ok_or_else(|| BundleError::new(BundleErrorCode::InventoryBinding))?;
    let manifest = manifest
        .to_str()
        .ok_or_else(|| BundleError::new(BundleErrorCode::InventoryBinding))?;
    let exact = |pointer: &str, expected: &str| {
        entry.pointer(pointer).and_then(Value::as_str) == Some(expected)
    };
    if !exact("/id", expected_connector_id)
        || !exact("/binary", executable)
        || !exact("/manifest_path", manifest)
        || !exact("/config/server_id", expected_server_id)
        || !exact("/lifecycle_mode", "per_invocation")
        || !exact("/runtime_network_enforcement", "host_egress_proxy")
        || !exact("/launch_binding/launcher_path", executable)
        || !exact("/launch_binding/launcher_digest", executable_digest)
        || !exact("/launch_binding/runtime_executable", executable)
        || !exact(
            "/launch_binding/runtime_executable_digest",
            executable_digest,
        )
    {
        return Err(BundleError::new(BundleErrorCode::InventoryBinding));
    }
    if expected_connector_id == "fcp.mcp-bridge" {
        let (expected_url, expected_host, expected_port) = match expected_server_id {
            "eec" => (
                "https://n8n.europeaneyecenter.com/mcp-server/http",
                "n8n.europeaneyecenter.com",
                443,
            ),
            "hetzner" => (
                "https://n8nhet.levilaser.com:8443/mcp-server/http",
                "n8nhet.levilaser.com",
                8443,
            ),
            _ => return Err(BundleError::new(BundleErrorCode::InventoryBinding)),
        };
        let exact_host = entry
            .pointer("/operation_network_constraints/mcp.tools.list/host_allow")
            .and_then(Value::as_array)
            .is_some_and(|hosts| hosts.len() == 1 && hosts[0].as_str() == Some(expected_host));
        let exact_port = entry
            .pointer("/operation_network_constraints/mcp.tools.list/port_allow")
            .and_then(Value::as_array)
            .is_some_and(|ports| ports.len() == 1 && ports[0].as_u64() == Some(expected_port));
        if !exact("/config/mcp_url", expected_url)
            || !exact("/config/security/description_scan", "block")
            || !exact_host
            || !exact_port
            || entry
                .pointer("/allowed_operations")
                .and_then(Value::as_array)
                .is_none_or(|operations| {
                    operations.len() != 1 || operations[0].as_str() != Some("mcp.tools.list")
                })
        {
            return Err(BundleError::new(BundleErrorCode::InventoryBinding));
        }
    }
    Ok(())
}

fn read_bounded_json(path: &Path, max_bytes: usize) -> Result<Value, BundleError> {
    let metadata = fs::metadata(path).map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    if metadata.len() > max_bytes as u64 {
        return Err(BundleError::new(BundleErrorCode::Receipt));
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    let mut bytes = Vec::with_capacity(capacity);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    serde_json::from_slice(&bytes).map_err(|_| BundleError::new(BundleErrorCode::Receipt))
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn verify_release_bundle(
    _executable: &Path,
    _expected_owner: u32,
) -> Result<VerifiedBundle, BundleError> {
    Err(BundleError::new(BundleErrorCode::UnsupportedPlatform))
}

#[cfg(test)]
#[allow(dead_code)]
fn verify_release_bundle_for_owner(
    executable: &Path,
    expected_owner: u32,
) -> Result<VerifiedBundle, BundleError> {
    verify_release_bundle(executable, expected_owner)
}

#[cfg(unix)]
fn verify_directory(path: &Path, expected_owner: u32) -> Result<(), BundleError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| BundleError::new(BundleErrorCode::Layout))?;
    if !metadata.file_type().is_dir() {
        return Err(BundleError::new(BundleErrorCode::Layout));
    }
    verify_metadata(&metadata, expected_owner, false)?;
    let canonical =
        fs::canonicalize(path).map_err(|_| BundleError::new(BundleErrorCode::Layout))?;
    if canonical != path {
        return Err(BundleError::new(BundleErrorCode::Layout));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_file(
    path: &Path,
    expected_owner: u32,
    require_owner_executable: bool,
) -> Result<PathBuf, BundleError> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        fs::symlink_metadata(path).map_err(|_| BundleError::new(BundleErrorCode::Layout))?;
    if !metadata.file_type().is_file() {
        return Err(BundleError::new(BundleErrorCode::Layout));
    }
    verify_metadata(&metadata, expected_owner, true)?;
    if require_owner_executable && metadata.mode() & 0o100 == 0 {
        return Err(BundleError::new(BundleErrorCode::Permissions));
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| BundleError::new(BundleErrorCode::Layout))?;
    if canonical != path {
        return Err(BundleError::new(BundleErrorCode::Layout));
    }
    Ok(canonical)
}

#[cfg(unix)]
fn verify_metadata(
    metadata: &Metadata,
    expected_owner: u32,
    require_single_link: bool,
) -> Result<(), BundleError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.uid() != expected_owner {
        return Err(BundleError::new(BundleErrorCode::Permissions));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(BundleError::new(BundleErrorCode::Permissions));
    }
    if metadata.mode() & 0o7000 != 0 {
        return Err(BundleError::new(BundleErrorCode::Permissions));
    }
    if require_single_link && metadata.nlink() != 1 {
        return Err(BundleError::new(BundleErrorCode::Metadata));
    }
    Ok(())
}

fn read_receipt(path: &Path) -> Result<BundleReceipt, BundleError> {
    let metadata = fs::metadata(path).map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    if metadata.len() > MAX_RECEIPT_BYTES as u64 {
        return Err(BundleError::new(BundleErrorCode::Receipt));
    }
    let mut file = File::open(path).map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    let mut bytes = Vec::with_capacity(capacity);
    file.read_to_end(&mut bytes)
        .map_err(|_| BundleError::new(BundleErrorCode::Receipt))?;
    serde_json::from_slice(&bytes).map_err(|_| BundleError::new(BundleErrorCode::Receipt))
}

fn validate_receipt_shape(receipt: &BundleReceipt, root: &Path) -> Result<(), BundleError> {
    if receipt.schema != RECEIPT_SCHEMA
        || !is_safe_release_id(&receipt.release_id)
        || root.file_name().and_then(|name| name.to_str()) != Some(receipt.release_id.as_str())
    {
        return Err(BundleError::new(BundleErrorCode::ReleaseId));
    }
    if receipt.artifacts.len() != EXPECTED_ARTIFACTS.len() {
        return Err(BundleError::new(BundleErrorCode::ArtifactSet));
    }

    for artifact in &receipt.artifacts {
        if !EXPECTED_ARTIFACTS.contains(&artifact.path.as_str())
            || !is_exact_relative_path(&artifact.path)
            || receipt
                .artifacts
                .iter()
                .filter(|entry| entry.path == artifact.path)
                .count()
                != 1
            || !is_blake3_digest(&artifact.digest)
        {
            return Err(BundleError::new(BundleErrorCode::ArtifactPath));
        }
    }
    Ok(())
}

fn is_safe_release_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn is_exact_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !value.contains('\\')
        && !value.contains("://")
}

fn is_blake3_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(unix)]
fn hash_file(path: &Path) -> Result<String, BundleError> {
    let mut file = File::open(path).map_err(|_| BundleError::new(BundleErrorCode::Digest))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let bytes = file
            .read(&mut buffer)
            .map_err(|_| BundleError::new(BundleErrorCode::Digest))?;
        if bytes == 0 {
            break;
        }
        hasher.update(&buffer[..bytes]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    #[cfg(unix)]
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[cfg(unix)]
    struct ReleaseFixture {
        root: PathBuf,
        executable: PathBuf,
        owner: u32,
    }

    #[cfg(unix)]
    impl ReleaseFixture {
        fn new() -> Self {
            let parent = fs::canonicalize(std::env::temp_dir()).expect("canonical temp dir");
            let root = loop {
                let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
                let release_id = format!("fwc-n8n-test-{}-{sequence}", std::process::id());
                let root = parent.join(&release_id);
                match fs::create_dir(&root) {
                    Ok(()) => break root,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create release fixture root: {error}"),
                }
            };
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .expect("restrict release fixture root");
            for directory in ["bin", "manifests", "inventory", "policy"] {
                let path = root.join(directory);
                fs::create_dir(&path).expect("create release fixture directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("restrict release fixture directory");
            }
            for relative_path in EXPECTED_ARTIFACTS {
                let path = root.join(relative_path);
                let bytes = match relative_path {
                    "bin/fcp-n8n" | "bin/fcp-mcp-bridge" => static_elf_fixture(),
                    "policy/local-mcp.json" => serde_json::to_vec(&test_local_mcp_policy())
                        .expect("encode local MCP policy fixture"),
                    _ => relative_path.as_bytes().to_vec(),
                };
                fs::write(&path, bytes).expect("write release fixture artifact");
                let mode = if EXECUTABLE_ARTIFACTS.contains(&relative_path) {
                    0o700
                } else {
                    0o600
                };
                fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                    .expect("restrict release fixture artifact");
            }
            let owner = fs::symlink_metadata(&root)
                .expect("release fixture metadata")
                .uid();
            let executable = root.join("bin/fwc-n8n");
            let fixture = Self {
                root,
                executable,
                owner,
            };
            fixture.write_inventory("eec");
            fixture.write_inventory("hetzner");
            fixture.write_official_mcp_inventory("eec");
            fixture.write_official_mcp_inventory("hetzner");
            fixture.write_receipt(None);
            fixture
        }

        fn artifact(&self, relative_path: &str) -> PathBuf {
            self.root.join(relative_path)
        }

        fn write_receipt(&self, digest_override: Option<(&str, &str)>) {
            let artifacts: Vec<Value> = EXPECTED_ARTIFACTS
                .iter()
                .map(|relative_path| {
                    let digest = digest_override
                        .filter(|(path, _)| path == relative_path)
                        .map_or_else(
                            || hash_file(&self.artifact(relative_path)).expect("artifact digest"),
                            |(_, digest)| digest.to_owned(),
                        );
                    serde_json::json!({"path": relative_path, "digest": digest})
                })
                .collect();
            let release_id = self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .expect("release fixture id");
            fs::write(
                self.root.join(RECEIPT_FILE),
                serde_json::to_vec(&serde_json::json!({
                    "schema": RECEIPT_SCHEMA,
                    "release_id": release_id,
                    "artifacts": artifacts,
                }))
                .expect("encode release fixture receipt"),
            )
            .expect("write release fixture receipt");
            fs::set_permissions(
                self.root.join(RECEIPT_FILE),
                fs::Permissions::from_mode(0o600),
            )
            .expect("restrict release fixture receipt");
        }

        fn write_inventory(&self, server_id: &str) {
            let executable = self.artifact("bin/fcp-n8n");
            let executable_digest = hash_file(&executable).expect("provider digest");
            let manifest = self.artifact("manifests/fcp-n8n.toml");
            let value = serde_json::json!([{
                "id": "fcp.n8n",
                "binary": executable,
                "manifest_path": manifest,
                "config": {"server_id": server_id},
                "runtime_network_enforcement": "host_egress_proxy",
                "lifecycle_mode": "per_invocation",
                "launch_binding": {
                    "launcher_path": executable,
                    "launcher_digest": executable_digest,
                    "runtime_executable": executable,
                    "runtime_executable_digest": executable_digest,
                }
            }]);
            fs::write(
                self.artifact(&format!("inventory/{server_id}.json")),
                serde_json::to_vec(&value).expect("encode inventory fixture"),
            )
            .expect("write inventory fixture");
        }

        fn write_official_mcp_inventory(&self, server_id: &str) {
            let executable = self.artifact("bin/fcp-mcp-bridge");
            let executable_digest = hash_file(&executable).expect("provider digest");
            let manifest = self.artifact("manifests/fcp-mcp-bridge.toml");
            let mcp_url = match server_id {
                "eec" => "https://n8n.europeaneyecenter.com/mcp-server/http",
                "hetzner" => "https://n8nhet.levilaser.com:8443/mcp-server/http",
                _ => panic!("unsupported fixture server"),
            };
            let (mcp_host, mcp_port) = match server_id {
                "eec" => ("n8n.europeaneyecenter.com", 443),
                "hetzner" => ("n8nhet.levilaser.com", 8443),
                _ => panic!("unsupported fixture server"),
            };
            let value = serde_json::json!([{
                "id": "fcp.mcp-bridge",
                "binary": executable,
                "manifest_path": manifest,
                "config": {
                    "server_id": server_id,
                    "credential_id": "550e8400-e29b-41d4-a716-446655440000",
                    "mcp_url": mcp_url,
                    "security": {"description_scan": "block"},
                },
                "allowed_zones": ["z:work"],
                "allowed_operations": ["mcp.tools.list"],
                "operation_network_constraints": {
                    "mcp.tools.list": {
                        "host_allow": [mcp_host],
                        "port_allow": [mcp_port]
                    }
                },
                "runtime_network_enforcement": "host_egress_proxy",
                "lifecycle_mode": "per_invocation",
                "launch_binding": {
                    "launcher_path": executable,
                    "launcher_digest": executable_digest,
                    "runtime_executable": executable,
                    "runtime_executable_digest": executable_digest,
                }
            }]);
            fs::write(
                self.artifact(&format!("inventory/{server_id}-official-mcp.json")),
                serde_json::to_vec(&value).expect("encode official MCP inventory fixture"),
            )
            .expect("write official MCP inventory fixture");
        }
    }

    #[cfg(unix)]
    fn static_elf_fixture() -> Vec<u8> {
        const HEADER_BYTES: usize = 64;
        const PROGRAM_HEADER_BYTES: usize = 56;
        let mut bytes = vec![0_u8; HEADER_BYTES + PROGRAM_HEADER_BYTES];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&(HEADER_BYTES as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
        bytes[54..56].copy_from_slice(&(PROGRAM_HEADER_BYTES as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&1_u32.to_le_bytes());
        bytes
    }

    #[cfg(unix)]
    impl Drop for ReleaseFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn receipt(root: &str) -> BundleReceipt {
        BundleReceipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            release_id: root.to_owned(),
            artifacts: EXPECTED_ARTIFACTS
                .iter()
                .map(|path| BundleArtifact {
                    path: (*path).to_owned(),
                    digest: "a".repeat(64),
                })
                .collect(),
        }
    }

    #[test]
    fn receipt_shape_accepts_only_exact_release_artifacts() {
        let root = Path::new("release-20260814");
        validate_receipt_shape(&receipt("release-20260814"), root).expect("exact receipt");
    }

    #[test]
    fn receipt_shape_rejects_release_and_artifact_tampering() {
        let root = Path::new("release-20260814");
        for release_id in ["", "../release-20260814", "release/other", "release:latest"] {
            let mut value = receipt("release-20260814");
            value.release_id = release_id.to_owned();
            assert_eq!(
                validate_receipt_shape(&value, root)
                    .expect_err("release id must fail")
                    .code(),
                BundleErrorCode::ReleaseId
            );
        }

        for path in [
            "/tmp/fwc-n8n",
            "../bin/fwc-n8n",
            "bin/./fwc-n8n",
            "https://example.invalid/fwc-n8n",
        ] {
            let mut value = receipt("release-20260814");
            value.artifacts[0].path = path.to_owned();
            assert!(validate_receipt_shape(&value, root).is_err());
        }

        let mut duplicate = receipt("release-20260814");
        duplicate.artifacts[1].path = duplicate.artifacts[0].path.clone();
        assert_eq!(
            validate_receipt_shape(&duplicate, root)
                .expect_err("duplicate artifact must fail")
                .code(),
            BundleErrorCode::ArtifactPath
        );

        let mut digest = receipt("release-20260814");
        digest.artifacts[0].digest = "A".repeat(64);
        assert!(validate_receipt_shape(&digest, root).is_err());
    }

    #[test]
    fn receipt_and_artifact_debug_are_redacted() {
        let value = receipt("release-20260814");
        let receipt_debug = format!("{value:?}");
        let artifact_debug = format!("{:?}", value.artifacts[0]);
        assert!(!receipt_debug.contains("release-20260814"));
        assert!(!receipt_debug.contains("bin/fwc-n8n"));
        assert!(!artifact_debug.contains("bin/fwc-n8n"));
        assert!(!artifact_debug.contains(&"a".repeat(64)));
    }

    #[cfg(unix)]
    #[test]
    fn dev_test_executable_is_not_a_production_bundle() {
        let executable = std::env::current_exe().expect("test executable");
        let owner = fs::symlink_metadata(&executable)
            .expect("test executable metadata")
            .uid();
        let error = verify_release_bundle_for_owner(&executable, owner)
            .expect_err("test executable is not named fwc-n8n");
        assert!(matches!(
            error.code(),
            BundleErrorCode::NotBundleExecutable | BundleErrorCode::Permissions
        ));
        assert!(!format!("{error:?}").contains(executable.to_string_lossy().as_ref()));
    }

    #[cfg(unix)]
    #[test]
    fn complete_release_fixture_verifies_and_tampering_fails_closed() {
        let valid = ReleaseFixture::new();
        verify_release_bundle_for_owner(&valid.executable, valid.owner)
            .expect("complete immutable release fixture");

        let wrong_digest = ReleaseFixture::new();
        wrong_digest.write_receipt(Some(("bin/fcp-host", &"0".repeat(64))));
        assert_eq!(
            verify_release_bundle_for_owner(&wrong_digest.executable, wrong_digest.owner)
                .expect_err("wrong digest")
                .code(),
            BundleErrorCode::Digest
        );

        let stale_inventory = ReleaseFixture::new();
        let inventory_path = stale_inventory.artifact("inventory/eec.json");
        let mut inventory: Value =
            serde_json::from_slice(&fs::read(&inventory_path).expect("read inventory fixture"))
                .expect("decode inventory fixture");
        inventory[0]["binary"] = Value::String("/old/release/bin/fcp-n8n".to_string());
        fs::write(
            &inventory_path,
            serde_json::to_vec(&inventory).expect("encode stale inventory"),
        )
        .expect("write stale inventory");
        stale_inventory.write_receipt(None);
        assert_eq!(
            verify_release_bundle_for_owner(&stale_inventory.executable, stale_inventory.owner)
                .expect_err("stale inventory binding")
                .code(),
            BundleErrorCode::InventoryBinding
        );

        let wrong_official_port = ReleaseFixture::new();
        let inventory_path = wrong_official_port.artifact("inventory/hetzner-official-mcp.json");
        let mut inventory: Value =
            serde_json::from_slice(&fs::read(&inventory_path).expect("read inventory fixture"))
                .expect("decode inventory fixture");
        inventory[0]["operation_network_constraints"]["mcp.tools.list"]["port_allow"] =
            serde_json::json!([443]);
        fs::write(
            &inventory_path,
            serde_json::to_vec(&inventory).expect("encode inventory with wrong official port"),
        )
        .expect("write inventory with wrong official port");
        wrong_official_port.write_receipt(None);
        assert_eq!(
            verify_release_bundle_for_owner(
                &wrong_official_port.executable,
                wrong_official_port.owner,
            )
            .expect_err("wrong official port binding")
            .code(),
            BundleErrorCode::InventoryBinding
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_local_mcp_policy_fails_closed_even_with_matching_receipt() {
        let fixture = ReleaseFixture::new();
        fs::write(
            fixture.artifact("policy/local-mcp.json"),
            serde_json::to_vec(&serde_json::json!({"package_id": "unreviewed"}))
                .expect("encode invalid policy"),
        )
        .expect("replace local MCP policy fixture");
        fixture.write_receipt(None);
        assert_eq!(
            verify_release_bundle_for_owner(&fixture.executable, fixture.owner)
                .expect_err("invalid local MCP policy")
                .code(),
            BundleErrorCode::LocalMcpPolicy
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dynamic_provider_fails_closed_even_with_matching_receipt() {
        let dynamic = ReleaseFixture::new();
        fs::copy("/bin/true", dynamic.artifact("bin/fcp-n8n"))
            .expect("install dynamic provider fixture");
        dynamic.write_inventory("eec");
        dynamic.write_inventory("hetzner");
        dynamic.write_receipt(None);
        assert_eq!(
            verify_release_bundle_for_owner(&dynamic.executable, dynamic.owner)
                .expect_err("dynamic provider must fail")
                .code(),
            BundleErrorCode::RuntimeFormat
        );
    }

    #[cfg(unix)]
    #[test]
    fn release_metadata_tampering_fails_closed() {
        let writable = ReleaseFixture::new();
        fs::set_permissions(
            writable.artifact("bin/fcp-host"),
            fs::Permissions::from_mode(0o666),
        )
        .expect("make artifact writable");
        assert_eq!(
            verify_release_bundle_for_owner(&writable.executable, writable.owner)
                .expect_err("writable artifact")
                .code(),
            BundleErrorCode::Permissions
        );

        let non_executable = ReleaseFixture::new();
        fs::set_permissions(
            non_executable.artifact("bin/fcp-host"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("remove executable bit");
        assert_eq!(
            verify_release_bundle_for_owner(&non_executable.executable, non_executable.owner)
                .expect_err("non-executable host binary")
                .code(),
            BundleErrorCode::Permissions
        );

        let special_mode = ReleaseFixture::new();
        fs::set_permissions(
            special_mode.artifact("bin/fcp-host"),
            fs::Permissions::from_mode(0o4700),
        )
        .expect("set privileged mode bit");
        assert_eq!(
            verify_release_bundle_for_owner(&special_mode.executable, special_mode.owner)
                .expect_err("special executable mode")
                .code(),
            BundleErrorCode::Permissions
        );

        let writable_receipt = ReleaseFixture::new();
        fs::set_permissions(
            writable_receipt.root.join(RECEIPT_FILE),
            fs::Permissions::from_mode(0o620),
        )
        .expect("make receipt group-writable");
        assert_eq!(
            verify_release_bundle_for_owner(&writable_receipt.executable, writable_receipt.owner,)
                .expect_err("writable receipt")
                .code(),
            BundleErrorCode::Permissions
        );

        let linked = ReleaseFixture::new();
        fs::remove_file(linked.artifact("bin/fcp-host")).expect("remove link target");
        symlink("fcp-n8n", linked.artifact("bin/fcp-host")).expect("create artifact symlink");
        assert_eq!(
            verify_release_bundle_for_owner(&linked.executable, linked.owner)
                .expect_err("symlinked artifact")
                .code(),
            BundleErrorCode::Layout
        );

        let hard_linked = ReleaseFixture::new();
        fs::remove_file(hard_linked.artifact("bin/fcp-host")).expect("remove hard-link target");
        fs::hard_link(
            hard_linked.artifact("bin/fcp-n8n"),
            hard_linked.artifact("bin/fcp-host"),
        )
        .expect("create artifact hard link");
        assert_eq!(
            verify_release_bundle_for_owner(&hard_linked.executable, hard_linked.owner)
                .expect_err("hard-linked artifact")
                .code(),
            BundleErrorCode::Metadata
        );

        let missing = ReleaseFixture::new();
        fs::remove_file(missing.artifact("inventory/eec.json")).expect("remove artifact");
        assert_eq!(
            verify_release_bundle_for_owner(&missing.executable, missing.owner)
                .expect_err("missing artifact")
                .code(),
            BundleErrorCode::Layout
        );

        let wrong_owner = ReleaseFixture::new();
        let unexpected_owner = if wrong_owner.owner == u32::MAX {
            0
        } else {
            wrong_owner.owner + 1
        };
        assert_eq!(
            verify_release_bundle_for_owner(&wrong_owner.executable, unexpected_owner,)
                .expect_err("unexpected owner")
                .code(),
            BundleErrorCode::Permissions
        );
    }
}
