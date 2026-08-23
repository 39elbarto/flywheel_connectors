//! Typed, unprivileged validation for an owner-provisioned immutable n8n release.
//!
//! This module deliberately stops at an install plan.  It never invokes a
//! shell, `sudo`, `systemd`, or filesystem mutation.  A separate owner/root
//! installer must consume the returned plan and perform the final
//! stage-rename and temporary-symlink promotion.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use fcp_crypto::ed25519::{Ed25519Signature, Ed25519VerifyingKey, PUBLIC_KEY_SIZE, SIGNATURE_SIZE};
use fcp_manifest::LocalMcpPolicy;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const RECEIPT_SCHEMA: &str = "fwc.n8n.bundle.v1";
const PROVENANCE_SCHEMA: &str = "fwc.n8n.provenance.v1";
const PROVISION_RECEIPT_SCHEMA: &str = "fwc.n8n.provision.v1";
const RECEIPT_FILE: &str = "receipt.json";
const PROVENANCE_FILE: &str = "provenance.json";
const PROVISION_RECEIPT_FILE: &str = "provision-receipt.json";
const MAX_RECEIPT_BYTES: usize = 128 * 1024;
const MAX_PROVENANCE_BYTES: usize = 16 * 1024;
const MAX_PROVISION_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INVENTORY_BYTES: usize = 2 * 1024 * 1024;
const MAX_POLICY_BYTES: usize = 256 * 1024;
const DEFAULT_STAGING_ROOT: &str = "/var/lib/fwc-n8n/staging";
const DEFAULT_INSTALL_ROOT: &str = "/usr/local/lib/fwc-n8n";

const ARTIFACTS: [&str; 12] = [
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
const EXECUTABLES: [&str; 4] = [
    "bin/fwc-n8n",
    "bin/fcp-host",
    "bin/fcp-n8n",
    "bin/fcp-mcp-bridge",
];
const APPROVED_TOOLS: [&str; 3] = ["archive_workflow", "publish_workflow", "unpublish_workflow"];
const PUBLISH_INPUT: &str =
    "sha256:b5fd649c299287d5bbf4091589d2e0c2cf54d3d8a87e5b4e97f5022d0bd74fcf";
const PUBLISH_OUTPUT: &str =
    "sha256:ec97a0fe010542c1aa3fcf484cc4531f27dfb72ce6d4a161d7dcd31d7f0b8ddf";
const UNPUBLISH_INPUT: &str =
    "sha256:4d365469269cb9f2e3d2629cd2d86bdb23b1687cbff015895b59c78228d96115";
const UNPUBLISH_OUTPUT: &str =
    "sha256:31e476b490845afb45d0354ecdfb3fe26015d14d3967747119c5eecef0d2d00c";
const EEC_MCP_URL: &str = "https://n8n.europeaneyecenter.com/mcp-server/http";
const EEC_MCP_HOST: &str = "n8n.europeaneyecenter.com";
const EEC_N8N_VERSION: &str = "2.34.4";
const HETZNER_MCP_URL: &str = "https://n8nhet.levilaser.com:8443/mcp-server/http";
const HETZNER_MCP_HOST: &str = "n8nhet.levilaser.com";
const HETZNER_N8N_VERSION: &str = "2.34.6";
const RELEASE_SIGNATURE_CONTEXT: &[u8] = b"fwc-n8n immutable release v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommonInventoryEntry {
    id: String,
    binary: String,
    manifest_path: String,
    config: CommonInventoryConfig,
    runtime_network_enforcement: String,
    lifecycle_mode: String,
    launch_binding: LaunchBinding,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommonInventoryConfig {
    server_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchBinding {
    launcher_path: String,
    launcher_digest: String,
    runtime_executable: String,
    runtime_executable_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerId {
    Eec,
    Hetzner,
}

impl ServerId {
    fn as_str(self) -> &'static str {
        match self {
            Self::Eec => "eec",
            Self::Hetzner => "hetzner",
        }
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfficialMcpBinding {
    pub server: ServerId,
    pub archive_input_schema_digest: String,
    pub archive_output_schema_digest: String,
}

impl fmt::Debug for OfficialMcpBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfficialMcpBinding")
            .field("server", &self.server)
            .field("schema_digests", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseSignature {
    algorithm: String,
    key_id: String,
    signature: String,
}

impl fmt::Debug for ReleaseSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReleaseSignature")
            .field("algorithm", &self.algorithm)
            .field("key_id", &"<redacted>")
            .field("signature", &"<redacted>")
            .finish()
    }
}

/// Explicit owner-provisioned public verification configuration.
///
/// This type intentionally accepts only public material.  The private signing
/// key is never loaded or generated by the provisioner.
#[derive(Clone)]
pub struct OwnerVerificationConfig {
    key_id: String,
    public_key_hex: String,
}

impl fmt::Debug for OwnerVerificationConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnerVerificationConfig")
            .field("key_id", &"<redacted>")
            .field("public_key", &"<redacted>")
            .finish()
    }
}

impl OwnerVerificationConfig {
    pub fn new(key_id: String, public_key_hex: String) -> Self {
        Self {
            key_id,
            public_key_hex,
        }
    }
}

/// Owner input for preflight validation.  The public constructor only accepts
/// the fixed staging/install roots; tests use the crate-private test builder.
pub struct ProvisionRequest {
    stage_root: PathBuf,
    release_id: String,
    git_revision: String,
    bindings: Vec<OfficialMcpBinding>,
    owner_verification: OwnerVerificationConfig,
    expected_owner: u32,
    current_path: PathBuf,
    releases_root: PathBuf,
}

impl fmt::Debug for ProvisionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionRequest")
            .field("stage_root", &"<redacted>")
            .field("release_id", &"<redacted>")
            .field("git_revision", &"<redacted>")
            .field("binding_count", &self.bindings.len())
            .finish()
    }
}

impl ProvisionRequest {
    pub fn new(
        stage_root: PathBuf,
        release_id: String,
        git_revision: String,
        bindings: Vec<OfficialMcpBinding>,
        owner_verification: OwnerVerificationConfig,
    ) -> Result<Self, ProvisionError> {
        let staging_root = Path::new(DEFAULT_STAGING_ROOT);
        let install_root = Path::new(DEFAULT_INSTALL_ROOT);
        if !is_absolute_child(&stage_root, staging_root) {
            return Err(ProvisionError::new(ProvisionErrorCode::Path));
        }
        Ok(Self {
            stage_root,
            release_id,
            git_revision,
            bindings,
            owner_verification,
            expected_owner: 0,
            current_path: install_root.join("current"),
            releases_root: install_root.join("releases"),
        })
    }

    #[cfg(test)]
    fn for_test(
        stage_root: PathBuf,
        release_id: String,
        git_revision: String,
        bindings: Vec<OfficialMcpBinding>,
        owner_verification: OwnerVerificationConfig,
        expected_owner: u32,
        current_path: PathBuf,
        releases_root: PathBuf,
    ) -> Self {
        Self {
            stage_root,
            release_id,
            git_revision,
            bindings,
            owner_verification,
            expected_owner,
            current_path,
            releases_root,
        }
    }

    pub fn validate(self) -> Result<InstallPlan, ProvisionError> {
        validate_request(&self)?;
        let previous_release = validate_current_pointer(
            &self.current_path,
            &self.releases_root,
            self.expected_owner,
            &self.owner_verification,
        )?;
        let release_path = self.releases_root.join(&self.release_id);
        reject_existing_path(&release_path)?;
        validate_stage_tree(&self, &self.owner_verification)?;
        Ok(InstallPlan {
            release_id: self.release_id.clone(),
            stage_root: self.stage_root.clone(),
            release_path,
            current_path: self.current_path.clone(),
            releases_root: self.releases_root.clone(),
            previous_release,
            git_revision: self.git_revision.clone(),
            bindings: self.bindings.clone(),
            owner_verification: self.owner_verification.clone(),
            expected_owner: self.expected_owner,
            promotion: Promotion::TemporarySymlinkRename,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Promotion {
    TemporarySymlinkRename,
}

/// A validated, but not yet owner-promoted, plan.  There is intentionally no
/// `apply` method in this packet: root-owned installation is a separate seam.
pub struct InstallPlan {
    release_id: String,
    stage_root: PathBuf,
    release_path: PathBuf,
    current_path: PathBuf,
    releases_root: PathBuf,
    previous_release: PathBuf,
    git_revision: String,
    bindings: Vec<OfficialMcpBinding>,
    owner_verification: OwnerVerificationConfig,
    expected_owner: u32,
    promotion: Promotion,
}

impl fmt::Debug for InstallPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallPlan")
            .field("release_id", &"<redacted>")
            .field("promotion", &self.promotion)
            .field("previous_release_present", &self.previous_release.exists())
            .finish()
    }
}

impl InstallPlan {
    pub fn promotion(&self) -> Promotion {
        self.promotion
    }

    /// Return the owner/root rollback intent without changing `current`.
    pub fn rollback_plan(&self) -> RollbackPlan {
        RollbackPlan {
            current_path: self.current_path.clone(),
            target_release: self.previous_release.clone(),
            promotion: self.promotion,
        }
    }

    /// Consume this plan only after repeating every precondition immediately
    /// before an owner-side promotion.
    ///
    /// The returned proof is the only value accepted by [`OwnerAtomicInstaller`].
    /// This method performs no mutation.  The owner implementation must consume
    /// the proof and call [`RevalidatedInstallPlan::revalidate`] once more while
    /// holding its own root-side concurrency guard immediately before rename;
    /// the typestate cannot prove that filesystem operations are atomic with
    /// respect to an unrelated root writer.
    pub fn revalidate(self) -> Result<RevalidatedInstallPlan, ProvisionError> {
        self.validate_now()?;
        Ok(RevalidatedInstallPlan { plan: self })
    }

    fn validate_now(&self) -> Result<(), ProvisionError> {
        #[cfg(not(unix))]
        {
            return Err(ProvisionError::new(ProvisionErrorCode::UnsupportedPlatform));
        }
        #[cfg(unix)]
        {
            let current = validate_current_pointer(
                &self.current_path,
                &self.releases_root,
                self.expected_owner,
                &self.owner_verification,
            )?;
            if current != self.previous_release {
                return Err(ProvisionError::new(ProvisionErrorCode::CurrentPointer));
            }
            reject_existing_path(&self.release_path)?;
            validate_release_tree(
                &self.stage_root,
                &self.release_id,
                &self.git_revision,
                &self.bindings,
                self.expected_owner,
                &self.release_path,
                &self.owner_verification,
            )
        }
    }

    #[cfg(test)]
    fn paths(&self) -> (&Path, &Path, &Path, &Path) {
        (
            &self.stage_root,
            &self.release_path,
            &self.current_path,
            &self.previous_release,
        )
    }
}

/// Opaque proof produced only by a successful [`InstallPlan::revalidate`].
/// It intentionally has no public constructor or mutable path state.
pub struct RevalidatedInstallPlan {
    plan: InstallPlan,
}

impl RevalidatedInstallPlan {
    /// Repeat all checks while the owner-side concurrency guard is held.
    /// Consuming the old proof prevents a caller from reusing it after this
    /// final check.
    pub fn revalidate(self) -> Result<Self, ProvisionError> {
        self.plan.validate_now()?;
        Ok(self)
    }

    pub fn promotion(&self) -> Promotion {
        self.plan.promotion
    }

    /// Validated stage directory to rename into the fixed release root.
    pub fn stage_root(&self) -> &Path {
        &self.plan.stage_root
    }

    /// Validated immutable release destination.
    pub fn release_path(&self) -> &Path {
        &self.plan.release_path
    }

    /// Validated `current` symlink to replace atomically.
    pub fn current_path(&self) -> &Path {
        &self.plan.current_path
    }

    /// Validated previous release retained for rollback.
    pub fn rollback_target(&self) -> &Path {
        &self.plan.previous_release
    }
}

impl fmt::Debug for RevalidatedInstallPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RevalidatedInstallPlan")
            .field("promotion", &self.plan.promotion)
            .field(
                "previous_release_present",
                &self.plan.previous_release.exists(),
            )
            .finish()
    }
}

/// Owner/root installer boundary.  Implementations live outside this
/// connector and receive only a proof-carrying plan.  They must consume it,
/// call [`RevalidatedInstallPlan::revalidate`] under their root-side guard,
/// then perform the fixed atomic operations using the read-only accessors.
pub trait OwnerAtomicInstaller {
    fn promote(&self, plan: RevalidatedInstallPlan) -> Result<(), ProvisionError>;
}

pub struct RollbackPlan {
    current_path: PathBuf,
    target_release: PathBuf,
    promotion: Promotion,
}

impl fmt::Debug for RollbackPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RollbackPlan")
            .field("promotion", &self.promotion)
            .field("target_release_present", &self.target_release.exists())
            .finish()
    }
}

impl RollbackPlan {
    pub fn promotion(&self) -> Promotion {
        self.promotion
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ProvisionErrorCode {
    UnsupportedPlatform,
    InvalidRequest,
    Path,
    Layout,
    Metadata,
    Permissions,
    Receipt,
    Provenance,
    ArtifactSet,
    Digest,
    Policy,
    SecretMaterial,
    CurrentPointer,
    Signature,
}

impl ProvisionErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::InvalidRequest => "invalid_request",
            Self::Path => "invalid_path",
            Self::Layout => "invalid_layout",
            Self::Metadata => "invalid_metadata",
            Self::Permissions => "invalid_permissions",
            Self::Receipt => "invalid_receipt",
            Self::Provenance => "invalid_provenance",
            Self::ArtifactSet => "invalid_artifact_set",
            Self::Digest => "digest_mismatch",
            Self::Policy => "invalid_policy_binding",
            Self::SecretMaterial => "secret_material_present",
            Self::CurrentPointer => "invalid_current_pointer",
            Self::Signature => "invalid_release_signature",
        }
    }
}

impl fmt::Debug for ProvisionErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ProvisionError {
    code: ProvisionErrorCode,
}

impl ProvisionError {
    const fn new(code: ProvisionErrorCode) -> Self {
        Self { code }
    }

    #[cfg(test)]
    const fn code(self) -> ProvisionErrorCode {
        self.code
    }
}

impl fmt::Debug for ProvisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionError")
            .field("code", &self.code)
            .finish()
    }
}

impl fmt::Display for ProvisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "immutable n8n provision denied: {}",
            self.code.as_str()
        )
    }
}

impl std::error::Error for ProvisionError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    release_id: String,
    artifacts: Vec<Artifact>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    schema: String,
    release_id: String,
    git_revision: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProvisionReceipt {
    schema: String,
    release_id: String,
    git_revision: String,
    bindings: Vec<OfficialMcpBinding>,
    artifacts: Vec<Artifact>,
    signature: ReleaseSignature,
}

fn validate_request(request: &ProvisionRequest) -> Result<(), ProvisionError> {
    if !is_safe_release_id(&request.release_id) || !is_git_revision(&request.git_revision) {
        return Err(ProvisionError::new(ProvisionErrorCode::InvalidRequest));
    }
    validate_binding_shape(&request.bindings)?;
    if !is_safe_absolute_path(&request.stage_root)
        || !is_safe_absolute_path(&request.current_path)
        || !is_safe_absolute_path(&request.releases_root)
        || request.stage_root == request.releases_root
        || request.stage_root.starts_with(&request.releases_root)
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Path));
    }
    #[cfg(unix)]
    {
        reject_symlink_ancestors(&request.stage_root, true)?;
        reject_symlink_ancestors(&request.releases_root, true)?;
        reject_symlink_ancestors(&request.current_path, false)?;
    }
    Ok(())
}

fn validate_binding_shape(bindings: &[OfficialMcpBinding]) -> Result<(), ProvisionError> {
    if bindings.len() != 2 {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let mut seen = BTreeSet::new();
    for binding in bindings {
        if !seen.insert(binding.server) {
            return Err(ProvisionError::new(ProvisionErrorCode::Policy));
        }
        if !is_sha256_digest(&binding.archive_input_schema_digest)
            || !is_sha256_digest(&binding.archive_output_schema_digest)
        {
            return Err(ProvisionError::new(ProvisionErrorCode::Policy));
        }
    }
    if seen != BTreeSet::from([ServerId::Eec, ServerId::Hetzner]) {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    Ok(())
}

fn validate_stage_tree(
    request: &ProvisionRequest,
    owner_verification: &OwnerVerificationConfig,
) -> Result<(), ProvisionError> {
    #[cfg(not(unix))]
    {
        let _ = (request, owner_verification);
        return Err(ProvisionError::new(ProvisionErrorCode::UnsupportedPlatform));
    }
    #[cfg(unix)]
    {
        validate_release_tree(
            &request.stage_root,
            &request.release_id,
            &request.git_revision,
            &request.bindings,
            request.expected_owner,
            &request.releases_root.join(&request.release_id),
            owner_verification,
        )
    }
}

#[cfg(unix)]
fn validate_release_tree(
    root: &Path,
    release_id: &str,
    git_revision: &str,
    bindings: &[OfficialMcpBinding],
    expected_owner: u32,
    inventory_release_root: &Path,
    owner_verification: &OwnerVerificationConfig,
) -> Result<(), ProvisionError> {
    validate_directory(root, expected_owner)?;
    let provision_receipt: ProvisionReceipt = read_json(
        &root.join(PROVISION_RECEIPT_FILE),
        expected_owner,
        MAX_PROVISION_RECEIPT_BYTES,
        ProvisionErrorCode::Receipt,
    )?;
    validate_provision_receipt(&provision_receipt, release_id, git_revision, bindings)?;
    for artifact in &provision_receipt.artifacts {
        let path = root.join(&artifact.path);
        validate_file(
            &path,
            expected_owner,
            false,
            MAX_ARTIFACT_BYTES.max(MAX_PROVISION_RECEIPT_BYTES as u64),
        )?;
        if hash_file(&path)? != artifact.digest {
            return Err(ProvisionError::new(ProvisionErrorCode::Digest));
        }
    }
    let provenance: Provenance = read_json(
        &root.join(PROVENANCE_FILE),
        expected_owner,
        MAX_PROVENANCE_BYTES,
        ProvisionErrorCode::Provenance,
    )?;
    if provenance.schema != PROVENANCE_SCHEMA
        || provenance.release_id != release_id
        || provenance.git_revision != git_revision
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Provenance));
    }
    let receipt: Receipt = read_json(
        &root.join(RECEIPT_FILE),
        expected_owner,
        MAX_RECEIPT_BYTES,
        ProvisionErrorCode::Receipt,
    )?;
    validate_receipt(&receipt, release_id)?;
    let receipt_digest = hash_file(&root.join(RECEIPT_FILE))?;
    verify_release_signature(&provision_receipt, &receipt_digest, owner_verification)?;
    for relative_path in ARTIFACTS {
        let path = root.join(relative_path);
        validate_file(
            &path,
            expected_owner,
            EXECUTABLES.contains(&relative_path),
            MAX_ARTIFACT_BYTES,
        )?;
        let digest = hash_file(&path)?;
        let expected = receipt
            .artifacts
            .iter()
            .find(|artifact| artifact.path == relative_path)
            .map(|artifact| artifact.digest.as_str())
            .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::ArtifactSet))?;
        if digest != expected {
            return Err(ProvisionError::new(ProvisionErrorCode::Digest));
        }
        if relative_path == "inventory/eec.json" || relative_path == "inventory/hetzner.json" {
            let server = if relative_path == "inventory/eec.json" {
                ServerId::Eec
            } else {
                ServerId::Hetzner
            };
            let inventory = read_value(&path, MAX_INVENTORY_BYTES)?;
            validate_common_inventory(&inventory, server, inventory_release_root, root)?;
        } else if relative_path.ends_with("official-mcp.json") {
            let server = if relative_path.starts_with("inventory/eec") {
                ServerId::Eec
            } else {
                ServerId::Hetzner
            };
            let binding = bindings
                .iter()
                .find(|binding| binding.server == server)
                .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
            let inventory = read_value(&path, MAX_INVENTORY_BYTES)?;
            validate_inventory(&inventory, server, inventory_release_root, binding)?;
        } else if relative_path == "policy/zone-policies.json" {
            let value = read_value(&path, MAX_POLICY_BYTES)?;
            validate_zone_policies(&value)?;
        } else if relative_path == "policy/local-mcp.json" {
            let value = read_value(&path, MAX_POLICY_BYTES)?;
            validate_local_mcp_policy(&value)?;
        } else if relative_path.starts_with("policy/") {
            let value = read_value(&path, MAX_POLICY_BYTES)?;
            reject_secret_keys(&value)?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct UnsignedProvisionReceipt {
    schema: String,
    release_id: String,
    git_revision: String,
    bindings: Vec<OfficialMcpBinding>,
    artifacts: Vec<Artifact>,
}

fn unsigned_provision_receipt_bytes(receipt: &ProvisionReceipt) -> Result<Vec<u8>, ProvisionError> {
    let mut bindings = receipt.bindings.clone();
    bindings.sort_by_key(|binding| binding.server);
    let mut artifacts = receipt.artifacts.clone();
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    serde_json::to_vec(&UnsignedProvisionReceipt {
        schema: receipt.schema.clone(),
        release_id: receipt.release_id.clone(),
        git_revision: receipt.git_revision.clone(),
        bindings,
        artifacts,
    })
    .map_err(|_| ProvisionError::new(ProvisionErrorCode::Receipt))
}

fn append_signing_field(payload: &mut Vec<u8>, field: &[u8]) {
    payload.extend_from_slice(&(field.len() as u64).to_le_bytes());
    payload.extend_from_slice(field);
}

fn release_signing_payload(
    receipt: &ProvisionReceipt,
    receipt_digest: &str,
    provision_digest: &str,
) -> Result<Vec<u8>, ProvisionError> {
    validate_binding_shape(&receipt.bindings)?;
    let mut bindings = receipt.bindings.clone();
    bindings.sort_by_key(|binding| binding.server);
    let mut payload = Vec::from(b"FCP-N8N-RELEASE-SIGNING-V1\0".as_slice());
    for field in [
        receipt.release_id.as_bytes(),
        receipt.git_revision.as_bytes(),
        receipt_digest.as_bytes(),
        provision_digest.as_bytes(),
    ] {
        append_signing_field(&mut payload, field);
    }
    for binding in bindings {
        for field in [
            binding.server.as_str().as_bytes(),
            binding.archive_input_schema_digest.as_bytes(),
            binding.archive_output_schema_digest.as_bytes(),
        ] {
            append_signing_field(&mut payload, field);
        }
    }
    Ok(payload)
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], ProvisionError> {
    if value.len() != N * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Signature));
    }
    let bytes =
        hex::decode(value).map_err(|_| ProvisionError::new(ProvisionErrorCode::Signature))?;
    let mut decoded = [0_u8; N];
    decoded.copy_from_slice(&bytes);
    Ok(decoded)
}

fn verify_release_signature(
    receipt: &ProvisionReceipt,
    receipt_digest: &str,
    owner_verification: &OwnerVerificationConfig,
) -> Result<(), ProvisionError> {
    if receipt.signature.algorithm != "ed25519"
        || receipt.signature.key_id != owner_verification.key_id
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Signature));
    }
    let public_key_bytes = decode_hex::<PUBLIC_KEY_SIZE>(&owner_verification.public_key_hex)?;
    let verifying_key = Ed25519VerifyingKey::from_bytes(&public_key_bytes)
        .map_err(|_| ProvisionError::new(ProvisionErrorCode::Signature))?;
    if verifying_key.key_id().to_string() != owner_verification.key_id {
        return Err(ProvisionError::new(ProvisionErrorCode::Signature));
    }
    let signature_bytes = decode_hex::<SIGNATURE_SIZE>(&receipt.signature.signature)?;
    let unsigned = unsigned_provision_receipt_bytes(receipt)?;
    let provision_digest = blake3::hash(&unsigned).to_hex().to_string();
    let payload = release_signing_payload(receipt, receipt_digest, &provision_digest)?;
    let signature = Ed25519Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_with_context(RELEASE_SIGNATURE_CONTEXT, &payload, &signature)
        .map_err(|_| ProvisionError::new(ProvisionErrorCode::Signature))
}

#[cfg(unix)]
fn validate_receipt(receipt: &Receipt, release_id: &str) -> Result<(), ProvisionError> {
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.release_id != release_id
        || receipt.artifacts.len() != ARTIFACTS.len()
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Receipt));
    }
    let mut seen = BTreeSet::new();
    for artifact in &receipt.artifacts {
        if !ARTIFACTS.contains(&artifact.path.as_str())
            || !is_exact_relative_path(&artifact.path)
            || !seen.insert(artifact.path.as_str())
            || !is_blake3_digest(&artifact.digest)
        {
            return Err(ProvisionError::new(ProvisionErrorCode::ArtifactSet));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_provision_receipt(
    receipt: &ProvisionReceipt,
    release_id: &str,
    git_revision: &str,
    bindings: &[OfficialMcpBinding],
) -> Result<(), ProvisionError> {
    if receipt.schema != PROVISION_RECEIPT_SCHEMA
        || receipt.release_id != release_id
        || receipt.git_revision != git_revision
        || receipt.artifacts.len() != ARTIFACTS.len() + 2
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Receipt));
    }
    if !same_bindings(&receipt.bindings, bindings)? {
        return Err(ProvisionError::new(ProvisionErrorCode::Receipt));
    }
    let mut expected = ARTIFACTS
        .into_iter()
        .chain([RECEIPT_FILE, PROVENANCE_FILE])
        .collect::<BTreeSet<_>>();
    for artifact in &receipt.artifacts {
        if !is_exact_relative_path(&artifact.path)
            || !expected.remove(artifact.path.as_str())
            || !is_blake3_digest(&artifact.digest)
        {
            return Err(ProvisionError::new(ProvisionErrorCode::ArtifactSet));
        }
    }
    if !expected.is_empty() {
        return Err(ProvisionError::new(ProvisionErrorCode::ArtifactSet));
    }
    Ok(())
}

fn same_bindings(
    left: &[OfficialMcpBinding],
    right: &[OfficialMcpBinding],
) -> Result<bool, ProvisionError> {
    validate_binding_shape(left)?;
    validate_binding_shape(right)?;
    let canonical = |bindings: &[OfficialMcpBinding]| {
        bindings
            .iter()
            .map(|binding| {
                (
                    binding.server,
                    (
                        binding.archive_input_schema_digest.clone(),
                        binding.archive_output_schema_digest.clone(),
                    ),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    Ok(canonical(left) == canonical(right))
}

#[cfg(unix)]
fn validate_common_inventory(
    value: &Value,
    server: ServerId,
    release_root: &Path,
    artifact_root: &Path,
) -> Result<(), ProvisionError> {
    reject_secret_keys(value)?;
    let entries: Vec<CommonInventoryEntry> = serde_json::from_value(value.clone())
        .map_err(|_| ProvisionError::new(ProvisionErrorCode::Policy))?;
    if entries.len() != 1 {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let entry = &entries[0];
    let expected_binary = release_root.join("bin/fcp-n8n");
    let expected_manifest = release_root.join("manifests/fcp-n8n.toml");
    let expected_digest = hash_file(&artifact_root.join("bin/fcp-n8n"))?;
    if entry.id != "fcp.n8n"
        || entry.binary != expected_binary.to_string_lossy()
        || entry.manifest_path != expected_manifest.to_string_lossy()
        || entry.config.server_id != server.as_str()
        || entry.runtime_network_enforcement != "host_egress_proxy"
        || entry.lifecycle_mode != "per_invocation"
        || entry.launch_binding.launcher_path != expected_binary.to_string_lossy()
        || entry.launch_binding.runtime_executable != expected_binary.to_string_lossy()
        || entry.launch_binding.launcher_digest != expected_digest
        || entry.launch_binding.runtime_executable_digest != expected_digest
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_local_mcp_policy(value: &Value) -> Result<(), ProvisionError> {
    reject_secret_keys(value)?;
    let policy: LocalMcpPolicy = serde_json::from_value(value.clone())
        .map_err(|_| ProvisionError::new(ProvisionErrorCode::Policy))?;
    policy
        .validate()
        .map_err(|_| ProvisionError::new(ProvisionErrorCode::Policy))
}

#[cfg(unix)]
fn validate_zone_policies(value: &Value) -> Result<(), ProvisionError> {
    reject_secret_keys(value)?;
    let policies = value
        .as_object()
        .filter(|policies| policies.len() == 1 && policies.contains_key("z:work"))
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    let typed: BTreeMap<String, fcp_core::ZonePolicyObject> = serde_json::from_value(value.clone())
        .map_err(|_| ProvisionError::new(ProvisionErrorCode::Policy))?;
    if typed
        .get("z:work")
        .is_none_or(|policy| policy.zone_id.as_str() != "z:work")
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let policy = policies
        .get("z:work")
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    let policy = policy
        .as_object()
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    require_exact_keys(
        policy,
        &[
            "header",
            "zone_id",
            "principal_allow",
            "principal_deny",
            "connector_allow",
            "connector_deny",
            "capability_allow",
            "capability_deny",
            "capability_ceiling",
            "transport_policy",
            "decision_receipts",
        ],
    )?;
    if policy.get("zone_id").and_then(Value::as_str) != Some("z:work")
        || !is_empty_array(policy.get("principal_allow"))
        || !is_empty_array(policy.get("principal_deny"))
        || !is_empty_array(policy.get("connector_allow"))
        || !is_empty_array(policy.get("connector_deny"))
        || !is_empty_array(policy.get("capability_allow"))
        || !is_empty_array(policy.get("capability_deny"))
        || !is_empty_array(policy.get("capability_ceiling"))
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let transport = policy
        .get("transport_policy")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    require_exact_keys(transport, &["allow_lan", "allow_derp", "allow_funnel"])?;
    if !transport.values().all(|value| value == &Value::Bool(true)) {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let receipts = policy
        .get("decision_receipts")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    require_exact_keys(receipts, &["emit_on_allow", "emit_on_deny"])?;
    if receipts.get("emit_on_allow") != Some(&Value::Bool(false))
        || receipts.get("emit_on_deny") != Some(&Value::Bool(true))
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let header = policy
        .get("header")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    require_exact_keys(
        header,
        &[
            "schema",
            "zone_id",
            "created_at",
            "provenance",
            "refs",
            "foreign_refs",
        ],
    )?;
    if header.get("zone_id").and_then(Value::as_str) != Some("z:work")
        || header.get("created_at").and_then(Value::as_u64).is_none()
        || !is_empty_array(header.get("refs"))
        || !is_empty_array(header.get("foreign_refs"))
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let schema = header
        .get("schema")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    require_exact_keys(schema, &["namespace", "name", "version"])?;
    if schema.get("namespace").and_then(Value::as_str) != Some("fcp.core")
        || schema.get("name").and_then(Value::as_str) != Some("ZonePolicyObject")
        || schema.get("version").and_then(Value::as_str) != Some("1.0.0")
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let provenance = header
        .get("provenance")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    require_exact_keys(provenance, &["origin_zone", "chain", "taint", "elevated"])?;
    if provenance.get("origin_zone").and_then(Value::as_str) != Some("z:work")
        || !is_empty_array(provenance.get("chain"))
        || provenance.get("taint").and_then(Value::as_str) != Some("Untainted")
        || provenance.get("elevated") != Some(&Value::Bool(false))
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    Ok(())
}

#[cfg(unix)]
fn require_exact_keys(
    object: &serde_json::Map<String, Value>,
    expected: &[&str],
) -> Result<(), ProvisionError> {
    if object.len() != expected.len() || !object.keys().all(|key| expected.contains(&key.as_str()))
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    Ok(())
}

#[cfg(unix)]
fn is_empty_array(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.as_array().is_some_and(Vec::is_empty))
}

#[cfg(unix)]
fn validate_inventory(
    value: &Value,
    server: ServerId,
    release_root: &Path,
    binding: &OfficialMcpBinding,
) -> Result<(), ProvisionError> {
    reject_secret_keys(value)?;
    let entries = value
        .as_array()
        .filter(|entries| entries.len() == 1)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    let entry = entries[0]
        .as_object()
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    let expected_top_level = BTreeSet::from([
        "id",
        "binary",
        "manifest_path",
        "config",
        "allowed_zones",
        "allowed_operations",
        "operation_network_constraints",
        "runtime_network_enforcement",
        "lifecycle_mode",
        "launch_binding",
    ]);
    if entry.len() != expected_top_level.len()
        || !entry
            .keys()
            .all(|key| expected_top_level.contains(key.as_str()))
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let expected_binary = release_root.join("bin/fcp-mcp-bridge");
    let expected_manifest = release_root.join("manifests/fcp-mcp-bridge.toml");
    if entry.get("id").and_then(Value::as_str) != Some("fcp.mcp-bridge")
        || entry.get("binary").and_then(Value::as_str) != expected_binary.to_str()
        || entry.get("manifest_path").and_then(Value::as_str) != expected_manifest.to_str()
        || entry
            .get("runtime_network_enforcement")
            .and_then(Value::as_str)
            != Some("host_egress_proxy")
        || entry.get("lifecycle_mode").and_then(Value::as_str) != Some("per_invocation")
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let (expected_url, expected_host, expected_port, expected_version) = match server {
        ServerId::Eec => (EEC_MCP_URL, EEC_MCP_HOST, 443_u64, EEC_N8N_VERSION),
        ServerId::Hetzner => (
            HETZNER_MCP_URL,
            HETZNER_MCP_HOST,
            8443_u64,
            HETZNER_N8N_VERSION,
        ),
    };
    let config = entry
        .get("config")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    let expected_config = BTreeSet::from([
        "server_id",
        "credential_id",
        "mcp_url",
        "security",
        "capability_policy",
    ]);
    if config.len() != expected_config.len()
        || !config
            .keys()
            .all(|key| expected_config.contains(key.as_str()))
        || config.get("server_id").and_then(Value::as_str) != Some(server.as_str())
        || config.get("mcp_url").and_then(Value::as_str) != Some(expected_url)
        || !config
            .get("credential_id")
            .and_then(Value::as_str)
            .is_some_and(is_uuid_ref)
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let security = config
        .get("security")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    if security.len() != 1
        || security.get("description_scan").and_then(Value::as_str) != Some("block")
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let policy = config
        .get("capability_policy")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    let expected_policy = BTreeSet::from([
        "n8n_version",
        "auth_mode",
        "api_scope_digest",
        "approved_tools",
        "archive_workflow_schema",
    ]);
    if policy.len() != expected_policy.len()
        || !policy
            .keys()
            .all(|key| expected_policy.contains(key.as_str()))
        || policy.get("n8n_version").and_then(Value::as_str) != Some(expected_version)
        || policy.get("auth_mode").and_then(Value::as_str) != Some("access_token")
        || !policy
            .get("api_scope_digest")
            .and_then(Value::as_str)
            .is_some_and(is_sha256_digest)
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let tools = policy
        .get("approved_tools")
        .and_then(Value::as_array)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    if tools.len() != APPROVED_TOOLS.len() {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let mut seen = BTreeMap::new();
    for tool in tools {
        let tool = tool
            .as_object()
            .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
        let expected_tool_fields = BTreeSet::from([
            "name",
            "class",
            "input_schema_digest",
            "output_schema_digest",
        ]);
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
        if tool.len() != expected_tool_fields.len()
            || !tool
                .keys()
                .all(|key| expected_tool_fields.contains(key.as_str()))
            || !APPROVED_TOOLS.contains(&name)
            || tool.get("class").and_then(Value::as_str) != Some("write")
        {
            return Err(ProvisionError::new(ProvisionErrorCode::Policy));
        }
        let input = tool
            .get("input_schema_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
        let output = tool
            .get("output_schema_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
        if !is_sha256_digest(input) || !is_sha256_digest(output) {
            return Err(ProvisionError::new(ProvisionErrorCode::Policy));
        }
        let expected = match name {
            "publish_workflow" => (PUBLISH_INPUT, PUBLISH_OUTPUT),
            "unpublish_workflow" => (UNPUBLISH_INPUT, UNPUBLISH_OUTPUT),
            "archive_workflow" => (
                binding.archive_input_schema_digest.as_str(),
                binding.archive_output_schema_digest.as_str(),
            ),
            _ => return Err(ProvisionError::new(ProvisionErrorCode::Policy)),
        };
        if (input, output) != expected || seen.insert(name, (input, output)).is_some() {
            return Err(ProvisionError::new(ProvisionErrorCode::Policy));
        }
    }
    if seen.len() != APPROVED_TOOLS.len() {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let archive_schema = policy
        .get("archive_workflow_schema")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    if archive_schema.len() != 2
        || !archive_schema
            .keys()
            .all(|key| matches!(key.as_str(), "input_schema_digest" | "output_schema_digest"))
        || archive_schema
            .get("input_schema_digest")
            .and_then(Value::as_str)
            != Some(binding.archive_input_schema_digest.as_str())
        || archive_schema
            .get("output_schema_digest")
            .and_then(Value::as_str)
            != Some(binding.archive_output_schema_digest.as_str())
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let zones = entry
        .get("allowed_zones")
        .and_then(Value::as_array)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    if zones != &[Value::String("z:work".to_owned())] {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let operations = entry
        .get("allowed_operations")
        .and_then(Value::as_array)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    let operation_set = operations
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if operations.len() != 2
        || operation_set != BTreeSet::from(["mcp.tools.list", "mcp.tools.call"])
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    let network = entry
        .get("operation_network_constraints")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    if network.len() != 2
        || !network
            .keys()
            .all(|key| matches!(key.as_str(), "mcp.tools.list" | "mcp.tools.call"))
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    for operation in ["mcp.tools.list", "mcp.tools.call"] {
        let constraint = network
            .get(operation)
            .and_then(Value::as_object)
            .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
        if constraint.len() != 2
            || !constraint
                .keys()
                .all(|key| matches!(key.as_str(), "host_allow" | "port_allow"))
            || constraint.get("host_allow")
                != Some(&Value::Array(vec![Value::String(expected_host.to_owned())]))
            || constraint.get("port_allow")
                != Some(&Value::Array(vec![Value::Number(expected_port.into())]))
        {
            return Err(ProvisionError::new(ProvisionErrorCode::Policy));
        }
    }
    let launch = entry
        .get("launch_binding")
        .and_then(Value::as_object)
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Policy))?;
    let expected_launch = BTreeSet::from([
        "launcher_path",
        "launcher_digest",
        "runtime_executable",
        "runtime_executable_digest",
    ]);
    if launch.len() != expected_launch.len()
        || !launch
            .keys()
            .all(|key| expected_launch.contains(key.as_str()))
        || launch.get("launcher_path").and_then(Value::as_str) != expected_binary.to_str()
        || launch.get("runtime_executable").and_then(Value::as_str) != expected_binary.to_str()
        || launch.get("launcher_digest").and_then(Value::as_str)
            != launch
                .get("runtime_executable_digest")
                .and_then(Value::as_str)
        || !launch
            .get("launcher_digest")
            .and_then(Value::as_str)
            .is_some_and(is_blake3_digest)
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Policy));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_current_pointer(
    current_path: &Path,
    releases_root: &Path,
    expected_owner: u32,
    owner_verification: &OwnerVerificationConfig,
) -> Result<PathBuf, ProvisionError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(current_path)
        .map_err(|_| ProvisionError::new(ProvisionErrorCode::CurrentPointer))?;
    if !metadata.file_type().is_symlink()
        || metadata.uid() != expected_owner
        || metadata.nlink() != 1
    {
        return Err(ProvisionError::new(ProvisionErrorCode::CurrentPointer));
    }
    let current = fs::canonicalize(current_path)
        .map_err(|_| ProvisionError::new(ProvisionErrorCode::CurrentPointer))?;
    let releases_root = fs::canonicalize(releases_root)
        .map_err(|_| ProvisionError::new(ProvisionErrorCode::CurrentPointer))?;
    if !current.starts_with(&releases_root) || current == releases_root {
        return Err(ProvisionError::new(ProvisionErrorCode::CurrentPointer));
    }
    if !current
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_safe_release_id)
    {
        return Err(ProvisionError::new(ProvisionErrorCode::CurrentPointer));
    }
    let release_id = current
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::CurrentPointer))?;
    let provenance: Provenance = read_json(
        &current.join(PROVENANCE_FILE),
        expected_owner,
        MAX_PROVENANCE_BYTES,
        ProvisionErrorCode::Provenance,
    )?;
    if provenance.schema != PROVENANCE_SCHEMA
        || provenance.release_id != release_id
        || !is_git_revision(&provenance.git_revision)
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Provenance));
    }
    let provision_receipt: ProvisionReceipt = read_json(
        &current.join(PROVISION_RECEIPT_FILE),
        expected_owner,
        MAX_PROVISION_RECEIPT_BYTES,
        ProvisionErrorCode::Receipt,
    )?;
    validate_binding_shape(&provision_receipt.bindings)?;
    validate_release_tree(
        &current,
        release_id,
        &provenance.git_revision,
        &provision_receipt.bindings,
        expected_owner,
        &current,
        owner_verification,
    )?;
    Ok(current)
}

#[cfg(unix)]
fn reject_existing_path(path: &Path) -> Result<(), ProvisionError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ProvisionError::new(ProvisionErrorCode::CurrentPointer)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ProvisionError::new(ProvisionErrorCode::Layout)),
    }
}

#[cfg(unix)]
fn validate_directory(path: &Path, expected_owner: u32) -> Result<Metadata, ProvisionError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProvisionError::new(ProvisionErrorCode::Layout))?;
    if !metadata.file_type().is_dir() {
        return Err(ProvisionError::new(ProvisionErrorCode::Layout));
    }
    verify_metadata(&metadata, expected_owner, false)?;
    Ok(metadata)
}

#[cfg(unix)]
fn validate_file(
    path: &Path,
    expected_owner: u32,
    executable: bool,
    max_bytes: u64,
) -> Result<Metadata, ProvisionError> {
    use std::os::unix::fs::MetadataExt;

    let metadata =
        fs::symlink_metadata(path).map_err(|_| ProvisionError::new(ProvisionErrorCode::Layout))?;
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Err(ProvisionError::new(ProvisionErrorCode::Layout));
    }
    verify_metadata(&metadata, expected_owner, true)?;
    if executable && metadata.mode() & 0o100 == 0 {
        return Err(ProvisionError::new(ProvisionErrorCode::Permissions));
    }
    if fs::canonicalize(path).map_err(|_| ProvisionError::new(ProvisionErrorCode::Layout))? != path
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Layout));
    }
    Ok(metadata)
}

#[cfg(unix)]
fn verify_metadata(
    metadata: &Metadata,
    expected_owner: u32,
    single_link: bool,
) -> Result<(), ProvisionError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o7000 != 0
    {
        return Err(ProvisionError::new(ProvisionErrorCode::Permissions));
    }
    if single_link && metadata.nlink() != 1 {
        return Err(ProvisionError::new(ProvisionErrorCode::Metadata));
    }
    Ok(())
}

#[cfg(unix)]
fn read_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    owner: u32,
    max_bytes: usize,
    code: ProvisionErrorCode,
) -> Result<T, ProvisionError> {
    validate_file(path, owner, false, max_bytes as u64).map_err(|_| ProvisionError::new(code))?;
    let value = read_bounded(path, max_bytes).map_err(|_| ProvisionError::new(code))?;
    serde_json::from_slice(&value).map_err(|_| ProvisionError::new(code))
}

#[cfg(unix)]
fn read_value(path: &Path, max_bytes: usize) -> Result<Value, ProvisionError> {
    let bytes = read_bounded(path, max_bytes)
        .map_err(|_| ProvisionError::new(ProvisionErrorCode::Policy))?;
    serde_json::from_slice(&bytes).map_err(|_| ProvisionError::new(ProvisionErrorCode::Policy))
}

#[cfg(unix)]
fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, std::io::Error> {
    let metadata = fs::metadata(path)?;
    let length = usize::try_from(metadata.len()).map_err(|_| std::io::ErrorKind::InvalidData)?;
    if length > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bounded read",
        ));
    }
    let mut file = File::open(path)?;
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bounded read",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn hash_file(path: &Path) -> Result<String, ProvisionError> {
    let mut file = File::open(path).map_err(|_| ProvisionError::new(ProvisionErrorCode::Digest))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| ProvisionError::new(ProvisionErrorCode::Digest))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn is_absolute_child(path: &Path, root: &Path) -> bool {
    is_safe_absolute_path(path) && path.starts_with(root) && path != root
}

fn is_safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::ParentDir | Component::CurDir))
}

#[cfg(unix)]
fn reject_symlink_ancestors(path: &Path, include_final: bool) -> Result<(), ProvisionError> {
    let mut cursor = if include_final {
        path.to_path_buf()
    } else {
        path.parent()
            .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Path))?
            .to_path_buf()
    };
    loop {
        let metadata = fs::symlink_metadata(&cursor)
            .map_err(|_| ProvisionError::new(ProvisionErrorCode::Path))?;
        if metadata.file_type().is_symlink() {
            return Err(ProvisionError::new(ProvisionErrorCode::Path));
        }
        if cursor == Path::new("/") {
            break;
        }
        cursor = cursor
            .parent()
            .ok_or_else(|| ProvisionError::new(ProvisionErrorCode::Path))?
            .to_path_buf();
    }
    Ok(())
}

fn is_safe_release_id(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn is_git_revision(value: &str) -> bool {
    (7..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_uuid_ref(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn reject_secret_keys(value: &Value) -> Result<(), ProvisionError> {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let lower = key.to_ascii_lowercase();
                let forbidden = [
                    "secret",
                    "token",
                    "password",
                    "authorization",
                    "private_key",
                    "api_key",
                    "access_key",
                    "cookie",
                ]
                .iter()
                .any(|part| lower.contains(part));
                if forbidden && lower != "credential_id" {
                    return Err(ProvisionError::new(ProvisionErrorCode::SecretMaterial));
                }
                reject_secret_keys(child)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                reject_secret_keys(item)?;
            }
        }
        Value::String(string) if looks_secret_like(string) => {
            return Err(ProvisionError::new(ProvisionErrorCode::SecretMaterial));
        }
        _ => {}
    }
    Ok(())
}

fn looks_secret_like(value: &str) -> bool {
    value.starts_with("Bearer ")
        || value.starts_with("sk-")
        || value.starts_with("ghp_")
        || value.starts_with("xoxb-")
        || value.starts_with("AKIA")
        || (value.len() >= 40
            && !value.starts_with("sha256:")
            && !value.starts_with("https://")
            && !value.starts_with('/')
            && !is_uuid_ref(value)
            && !is_blake3_digest(value)
            && value.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn test_signing_key() -> fcp_crypto::ed25519::Ed25519SigningKey {
        fcp_crypto::ed25519::Ed25519SigningKey::from_bytes(&[7_u8; 32]).expect("test signing key")
    }

    fn test_owner_verification() -> OwnerVerificationConfig {
        let key = test_signing_key();
        OwnerVerificationConfig::new(
            key.key_id().to_string(),
            hex::encode(key.verifying_key().to_bytes()),
        )
    }

    struct Fixture {
        root: PathBuf,
        stage: PathBuf,
        releases: PathBuf,
        current: PathBuf,
        owner: u32,
        release_id: String,
    }

    impl Fixture {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("temp root");
            let id = format!(
                "fwc-provision-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            );
            let root = base.join(id);
            fs::create_dir(&root).expect("fixture root");
            let stage = root.join("staging/release-test");
            let releases = root.join("releases");
            fs::create_dir_all(&stage).expect("stage");
            fs::create_dir(&releases).expect("releases");
            let previous = releases.join("previous");
            fs::create_dir(&previous).expect("previous");
            fs::create_dir(previous.join("bin")).expect("previous bin");
            fs::write(previous.join("bin/fwc-n8n"), b"previous binary").expect("previous binary");
            fs::set_permissions(
                previous.join("bin/fwc-n8n"),
                fs::Permissions::from_mode(0o755),
            )
            .expect("previous binary mode");
            fs::write(previous.join(RECEIPT_FILE), b"previous").expect("previous receipt");
            fs::set_permissions(
                previous.join(RECEIPT_FILE),
                fs::Permissions::from_mode(0o644),
            )
            .expect("receipt mode");
            let current = root.join("current");
            symlink(&previous, &current).expect("current symlink");
            let owner = fs::symlink_metadata(&root).expect("owner metadata").uid();
            let release_id = "release-test".to_owned();
            let fixture = Self {
                root,
                stage,
                releases,
                current,
                owner,
                release_id,
            };
            fixture.populate();
            fixture.populate_previous();
            fixture
        }

        fn populate(&self) {
            for directory in ["bin", "manifests", "inventory", "policy"] {
                let path = self.stage.join(directory);
                fs::create_dir(&path).expect("artifact directory");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("dir mode");
            }
            for path in ARTIFACTS {
                let file = self.stage.join(path);
                let bytes = match path {
                    "inventory/eec.json" => self.common_inventory("eec"),
                    "inventory/hetzner.json" => self.common_inventory("hetzner"),
                    "policy/zone-policies.json" => self.zone_policies(),
                    "policy/local-mcp.json" => self.local_mcp_policy(),
                    _ => path.as_bytes().to_vec(),
                };
                fs::write(&file, bytes).expect("artifact");
                fs::set_permissions(
                    &file,
                    fs::Permissions::from_mode(if EXECUTABLES.contains(&path) {
                        0o755
                    } else {
                        0o644
                    }),
                )
                .expect("file mode");
            }
            let release_root = self.releases.join(&self.release_id);
            let bridge_digest =
                hash_file(&self.stage.join("bin/fcp-mcp-bridge")).expect("bridge digest");
            let make_path =
                |relative: &str| release_root.join(relative).to_string_lossy().to_string();
            for server in ["eec", "hetzner"] {
                let (mcp_url, mcp_host, mcp_port, n8n_version) = if server == "eec" {
                    (EEC_MCP_URL, EEC_MCP_HOST, 443_u64, EEC_N8N_VERSION)
                } else {
                    (
                        HETZNER_MCP_URL,
                        HETZNER_MCP_HOST,
                        8443_u64,
                        HETZNER_N8N_VERSION,
                    )
                };
                let inventory = serde_json::json!([{
                    "id": "fcp.mcp-bridge",
                    "binary": make_path("bin/fcp-mcp-bridge"),
                    "manifest_path": make_path("manifests/fcp-mcp-bridge.toml"),
                    "config": {"server_id": server, "credential_id": "550e8400-e29b-41d4-a716-446655440000", "mcp_url": mcp_url, "security": {"description_scan":"block"}, "capability_policy": {
                        "n8n_version": n8n_version,
                        "auth_mode": "access_token",
                        "api_scope_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                        "approved_tools": [
                            {"name":"archive_workflow","class":"write","input_schema_digest": if server=="eec" {"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} else {"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"output_schema_digest": if server=="eec" {"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"} else {"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}},
                            {"name":"publish_workflow","class":"write","input_schema_digest":PUBLISH_INPUT,"output_schema_digest":PUBLISH_OUTPUT},
                            {"name":"unpublish_workflow","class":"write","input_schema_digest":UNPUBLISH_INPUT,"output_schema_digest":UNPUBLISH_OUTPUT}
                        ],
                        "archive_workflow_schema": {"input_schema_digest": if server=="eec" {"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} else {"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"output_schema_digest": if server=="eec" {"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"} else {"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}}
                    }},
                    "allowed_zones": ["z:work"],
                    "allowed_operations": ["mcp.tools.list", "mcp.tools.call"],
                    "operation_network_constraints": {
                        "mcp.tools.list": {"host_allow": [mcp_host], "port_allow": [mcp_port]},
                        "mcp.tools.call": {"host_allow": [mcp_host], "port_allow": [mcp_port]}
                    },
                    "runtime_network_enforcement": "host_egress_proxy",
                    "lifecycle_mode": "per_invocation",
                    "launch_binding": {
                        "launcher_path": make_path("bin/fcp-mcp-bridge"),
                        "launcher_digest": bridge_digest,
                        "runtime_executable": make_path("bin/fcp-mcp-bridge"),
                        "runtime_executable_digest": bridge_digest
                    }
                }]);
                fs::write(
                    self.stage
                        .join(format!("inventory/{server}-official-mcp.json")),
                    serde_json::to_vec(&inventory).expect("inventory json"),
                )
                .expect("inventory write");
            }
            fs::write(self.stage.join(PROVENANCE_FILE), serde_json::json!({"schema":PROVENANCE_SCHEMA,"release_id":self.release_id,"git_revision":"0123456789abcdef0123456789abcdef01234567"}).to_string()).expect("provenance");
            fs::write(self.stage.join(RECEIPT_FILE), self.receipt()).expect("receipt");
            fs::write(
                self.stage.join(PROVISION_RECEIPT_FILE),
                self.provision_receipt(),
            )
            .expect("provision receipt");
            for name in [RECEIPT_FILE, PROVENANCE_FILE] {
                fs::set_permissions(self.stage.join(name), fs::Permissions::from_mode(0o644))
                    .expect("metadata mode");
            }
        }

        fn common_inventory(&self, server: &str) -> Vec<u8> {
            let executable = self.releases.join(&self.release_id).join("bin/fcp-n8n");
            let manifest = self
                .releases
                .join(&self.release_id)
                .join("manifests/fcp-n8n.toml");
            let digest = hash_file(&self.stage.join("bin/fcp-n8n")).expect("n8n digest");
            serde_json::to_vec(&serde_json::json!([{
                "id": "fcp.n8n",
                "binary": executable,
                "manifest_path": manifest,
                "config": {"server_id": server},
                "runtime_network_enforcement": "host_egress_proxy",
                "lifecycle_mode": "per_invocation",
                "launch_binding": {
                    "launcher_path": executable,
                    "launcher_digest": digest,
                    "runtime_executable": executable,
                    "runtime_executable_digest": digest,
                }
            }]))
            .expect("common inventory json")
        }

        fn local_mcp_policy(&self) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
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
                "callable_tools": ["tools_documentation", "search_nodes", "get_node", "validate_node", "get_template", "search_templates", "validate_workflow"],
                "max_frame_bytes": 262144,
                "max_request_bytes": 65536,
                "max_result_bytes": 262144,
                "max_sequential_calls": 7,
                "startup_timeout_ms": 30000,
                "request_timeout_ms": 30000,
                "shutdown_timeout_ms": 2000,
                "idle_window_ms": 0,
                "network_disabled": true,
            }))
            .expect("local MCP policy json")
        }

        fn zone_policies(&self) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "z:work": {
                    "header": {
                        "schema": {"namespace": "fcp.core", "name": "ZonePolicyObject", "version": "1.0.0"},
                        "zone_id": "z:work",
                        "created_at": 0,
                        "provenance": {"origin_zone": "z:work", "chain": [], "taint": "Untainted", "elevated": false},
                        "refs": [],
                        "foreign_refs": [],
                    },
                    "zone_id": "z:work",
                    "principal_allow": [],
                    "principal_deny": [],
                    "connector_allow": [],
                    "connector_deny": [],
                    "capability_allow": [],
                    "capability_deny": [],
                    "capability_ceiling": [],
                    "transport_policy": {"allow_lan": true, "allow_derp": true, "allow_funnel": true},
                    "decision_receipts": {"emit_on_allow": false, "emit_on_deny": true},
                }
            }))
            .expect("zone policies json")
        }

        fn receipt(&self) -> Vec<u8> {
            self.receipt_for(&self.stage, &self.release_id)
        }

        fn provision_receipt(&self) -> Vec<u8> {
            self.provision_receipt_for(&self.stage, &self.release_id)
        }

        fn receipt_for(&self, root: &Path, release_id: &str) -> Vec<u8> {
            let artifacts = ARTIFACTS
                .iter()
                .map(|path| {
                    serde_json::json!({
                        "path": path,
                        "digest": hash_file(&root.join(path)).expect("digest")
                    })
                })
                .collect::<Vec<_>>();
            serde_json::to_vec(&serde_json::json!({
                "schema": RECEIPT_SCHEMA,
                "release_id": release_id,
                "artifacts": artifacts
            }))
            .expect("receipt json")
        }

        fn provision_receipt_for(&self, root: &Path, release_id: &str) -> Vec<u8> {
            let mut paths = ARTIFACTS.to_vec();
            paths.extend([RECEIPT_FILE, PROVENANCE_FILE]);
            let artifacts = paths
                .iter()
                .map(|path| {
                    serde_json::json!({
                        "path": path,
                        "digest": hash_file(&root.join(path)).expect("provision digest")
                    })
                })
                .collect::<Vec<_>>();
            let git_revision: String = serde_json::from_slice::<Value>(
                &fs::read(root.join(PROVENANCE_FILE)).expect("provenance bytes"),
            )
            .expect("provenance json")["git_revision"]
                .as_str()
                .expect("provenance revision")
                .to_owned();
            let bindings = vec![
                OfficialMcpBinding {
                    server: ServerId::Eec,
                    archive_input_schema_digest:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned(),
                    archive_output_schema_digest:
                        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                            .to_owned(),
                },
                OfficialMcpBinding {
                    server: ServerId::Hetzner,
                    archive_input_schema_digest:
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_owned(),
                    archive_output_schema_digest:
                        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                            .to_owned(),
                },
            ];
            let artifacts = artifacts
                .into_iter()
                .map(|artifact| serde_json::from_value::<Artifact>(artifact).expect("artifact"))
                .collect::<Vec<_>>();
            let signing_receipt = ProvisionReceipt {
                schema: PROVISION_RECEIPT_SCHEMA.to_owned(),
                release_id: release_id.to_owned(),
                git_revision,
                bindings,
                artifacts,
                signature: ReleaseSignature {
                    algorithm: "ed25519".to_owned(),
                    key_id: test_signing_key().key_id().to_string(),
                    signature: "00".repeat(SIGNATURE_SIZE),
                },
            };
            let receipt_digest = hash_file(&root.join(RECEIPT_FILE)).expect("receipt digest");
            let unsigned = unsigned_provision_receipt_bytes(&signing_receipt).expect("unsigned");
            let provision_digest = blake3::hash(&unsigned).to_hex().to_string();
            let payload =
                release_signing_payload(&signing_receipt, &receipt_digest, &provision_digest)
                    .expect("signing payload");
            let signature = test_signing_key()
                .sign_with_context(RELEASE_SIGNATURE_CONTEXT, &payload)
                .to_hex();
            serde_json::to_vec(&serde_json::json!({
                "schema": signing_receipt.schema,
                "release_id": signing_receipt.release_id,
                "git_revision": signing_receipt.git_revision,
                "bindings": signing_receipt.bindings,
                "artifacts": signing_receipt.artifacts,
                "signature": {"algorithm": "ed25519", "key_id": test_signing_key().key_id().to_string(), "signature": signature}
            }))
            .expect("provision receipt json")
        }

        fn populate_previous(&self) {
            let previous = self.releases.join("previous");
            for directory in ["manifests", "inventory", "policy"] {
                fs::create_dir(previous.join(directory)).expect("previous directory");
                fs::set_permissions(previous.join(directory), fs::Permissions::from_mode(0o755))
                    .expect("previous directory mode");
            }
            for path in ARTIFACTS {
                let source = self.stage.join(path);
                let destination = previous.join(path);
                let bytes = if path.starts_with("inventory/") {
                    let (binary, manifest) = if path.ends_with("official-mcp.json") {
                        ("bin/fcp-mcp-bridge", "manifests/fcp-mcp-bridge.toml")
                    } else {
                        ("bin/fcp-n8n", "manifests/fcp-n8n.toml")
                    };
                    let mut value: Value =
                        serde_json::from_slice(&fs::read(&source).expect("source inventory"))
                            .expect("source inventory json");
                    value[0]["binary"] =
                        Value::String(previous.join(binary).to_string_lossy().into_owned());
                    value[0]["manifest_path"] =
                        Value::String(previous.join(manifest).to_string_lossy().into_owned());
                    value[0]["launch_binding"]["launcher_path"] =
                        Value::String(previous.join(binary).to_string_lossy().into_owned());
                    value[0]["launch_binding"]["runtime_executable"] =
                        Value::String(previous.join(binary).to_string_lossy().into_owned());
                    serde_json::to_vec(&value).expect("previous inventory json")
                } else {
                    fs::read(&source).expect("source artifact")
                };
                fs::write(&destination, bytes).expect("previous artifact");
                fs::set_permissions(
                    &destination,
                    fs::Permissions::from_mode(if EXECUTABLES.contains(&path) {
                        0o755
                    } else {
                        0o644
                    }),
                )
                .expect("previous artifact mode");
            }
            fs::write(
                previous.join(PROVENANCE_FILE),
                serde_json::json!({
                    "schema": PROVENANCE_SCHEMA,
                    "release_id": "previous",
                    "git_revision": "0123456789abcdef0123456789abcdef01234567"
                })
                .to_string(),
            )
            .expect("previous provenance");
            fs::write(
                previous.join(RECEIPT_FILE),
                self.receipt_for(&previous, "previous"),
            )
            .expect("previous receipt");
            fs::write(
                previous.join(PROVISION_RECEIPT_FILE),
                self.provision_receipt_for(&previous, "previous"),
            )
            .expect("previous provision receipt");
            for name in [RECEIPT_FILE, PROVENANCE_FILE, PROVISION_RECEIPT_FILE] {
                fs::set_permissions(previous.join(name), fs::Permissions::from_mode(0o644))
                    .expect("previous metadata mode");
            }
        }

        fn set_previous_git_revision(&self) {
            let previous = self.releases.join("previous");
            let revision = "abcdefabcdefabcdefabcdefabcdefabcdefabcd";
            fs::write(
                previous.join(PROVENANCE_FILE),
                serde_json::json!({
                    "schema": PROVENANCE_SCHEMA,
                    "release_id": "previous",
                    "git_revision": revision
                })
                .to_string(),
            )
            .expect("previous provenance revision");
            fs::write(
                previous.join(PROVISION_RECEIPT_FILE),
                self.provision_receipt_for(&previous, "previous"),
            )
            .expect("previous provision revision");
        }

        fn request(&self) -> ProvisionRequest {
            ProvisionRequest::for_test(self.stage.clone(), self.release_id.clone(), "0123456789abcdef0123456789abcdef01234567".to_owned(), vec![
                OfficialMcpBinding { server:ServerId::Eec, archive_input_schema_digest:"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(), archive_output_schema_digest:"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned() },
                OfficialMcpBinding { server:ServerId::Hetzner, archive_input_schema_digest:"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(), archive_output_schema_digest:"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned() },
            ], test_owner_verification(), self.owner, self.current.clone(), self.releases.clone())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn valid_package_yields_non_mutating_atomic_plan() {
        let fixture = Fixture::new();
        fixture.set_previous_git_revision();
        let plan = fixture.request().validate().expect("valid package");
        assert_eq!(plan.promotion(), Promotion::TemporarySymlinkRename);
        assert_eq!(plan.paths().0, fixture.stage);
        assert_eq!(plan.paths().3, fixture.releases.join("previous"));
        assert_eq!(
            plan.rollback_plan().promotion(),
            Promotion::TemporarySymlinkRename
        );
        assert!(!fixture.releases.join(&fixture.release_id).exists());
    }

    #[test]
    fn wrong_git_revision_and_schema_binding_fail_closed() {
        let fixture = Fixture::new();
        let mut request = fixture.request();
        request.git_revision = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_owned();
        let provision_path = fixture.stage.join(PROVISION_RECEIPT_FILE);
        let mut provision: Value =
            serde_json::from_slice(&fs::read(&provision_path).expect("provision receipt"))
                .expect("provision receipt json");
        provision["git_revision"] = Value::String(request.git_revision.clone());
        fs::write(
            provision_path,
            serde_json::to_vec(&provision).expect("provision receipt update"),
        )
        .expect("write provision receipt");
        assert_eq!(
            request.validate().expect_err("wrong revision").code(),
            ProvisionErrorCode::Provenance
        );
        let fixture = Fixture::new();
        let mut request = fixture.request();
        request.bindings[1].archive_output_schema_digest =
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned();
        let provision_path = fixture.stage.join(PROVISION_RECEIPT_FILE);
        let mut provision: Value =
            serde_json::from_slice(&fs::read(&provision_path).expect("provision receipt"))
                .expect("provision receipt json");
        provision["bindings"][1]["archive_output_schema_digest"] =
            Value::String(request.bindings[1].archive_output_schema_digest.clone());
        fs::write(
            provision_path,
            serde_json::to_vec(&provision).expect("provision receipt update"),
        )
        .expect("write provision receipt");
        assert!(matches!(
            request.validate().expect_err("wrong schema").code(),
            ProvisionErrorCode::Policy | ProvisionErrorCode::Signature
        ));
    }

    #[test]
    fn signature_key_algorithm_and_presence_fail_closed_without_mutation() {
        let fixture = Fixture::new();
        let before = fs::canonicalize(&fixture.current).expect("current target");
        let path = fixture.stage.join(PROVISION_RECEIPT_FILE);
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(&path).expect("provision receipt"))
                .expect("provision receipt json");
        receipt["signature"]["algorithm"] = Value::String("rsa".to_owned());
        fs::write(
            &path,
            serde_json::to_vec(&receipt).expect("signature bytes"),
        )
        .expect("write signature");
        assert_eq!(
            fixture.request().validate().expect_err("algorithm").code(),
            ProvisionErrorCode::Signature
        );
        assert_eq!(
            fs::canonicalize(&fixture.current).expect("current target"),
            before
        );
        assert!(fixture.stage.exists());

        let fixture = Fixture::new();
        let mut request = fixture.request();
        request.owner_verification = OwnerVerificationConfig::new(
            "0000000000000000".to_owned(),
            hex::encode([9_u8; PUBLIC_KEY_SIZE]),
        );
        let before = fs::canonicalize(&fixture.current).expect("current target");
        assert_eq!(
            request.validate().expect_err("wrong key").code(),
            ProvisionErrorCode::Signature
        );
        assert_eq!(
            fs::canonicalize(&fixture.current).expect("current target"),
            before
        );
        assert!(fixture.stage.exists());

        let fixture = Fixture::new();
        let path = fixture.stage.join(PROVISION_RECEIPT_FILE);
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(&path).expect("provision receipt"))
                .expect("provision receipt json");
        receipt
            .as_object_mut()
            .expect("receipt object")
            .remove("signature");
        fs::write(&path, serde_json::to_vec(&receipt).expect("receipt bytes"))
            .expect("write missing signature");
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("missing signature")
                .code(),
            ProvisionErrorCode::Receipt
        );
        assert!(fixture.stage.exists());
    }

    struct TestAtomicInstaller;

    impl OwnerAtomicInstaller for TestAtomicInstaller {
        fn promote(&self, proof: RevalidatedInstallPlan) -> Result<(), ProvisionError> {
            let proof = proof.revalidate()?;
            fs::rename(proof.stage_root(), proof.release_path())
                .map_err(|_| ProvisionError::new(ProvisionErrorCode::Layout))?;
            let next = proof.current_path().with_extension("next");
            symlink(proof.release_path(), &next)
                .map_err(|_| ProvisionError::new(ProvisionErrorCode::Layout))?;
            fs::rename(&next, proof.current_path())
                .map_err(|_| ProvisionError::new(ProvisionErrorCode::Layout))?;
            Ok(())
        }
    }

    #[test]
    fn revalidated_proof_exposes_only_fixed_paths_without_mutation() {
        let fixture = Fixture::new();
        let plan = fixture.request().validate().expect("valid plan");
        let before = fs::canonicalize(&fixture.current).expect("current target");
        let proof = plan.revalidate().expect("revalidated proof");
        assert_eq!(proof.stage_root(), fixture.stage.as_path());
        assert_eq!(
            proof.release_path(),
            fixture.releases.join(&fixture.release_id)
        );
        assert_eq!(proof.current_path(), fixture.current.as_path());
        assert_eq!(proof.rollback_target(), fixture.releases.join("previous"));
        assert_eq!(proof.promotion(), Promotion::TemporarySymlinkRename);
        assert_eq!(
            fs::canonicalize(&fixture.current).expect("current target"),
            before
        );
        assert!(fixture.stage.exists());
    }

    #[test]
    fn stale_current_or_stage_cannot_create_revalidated_proof() {
        let fixture = Fixture::new();
        let plan = fixture.request().validate().expect("valid plan");
        let before = fs::canonicalize(&fixture.current).expect("current target");
        fs::remove_file(&fixture.current).expect("remove current");
        symlink(&fixture.stage, &fixture.current).expect("stale current");
        assert_eq!(
            plan.revalidate().expect_err("stale current").code(),
            ProvisionErrorCode::CurrentPointer
        );
        assert_ne!(
            fs::canonicalize(&fixture.current).expect("current target"),
            before
        );

        let fixture = Fixture::new();
        let plan = fixture.request().validate().expect("valid plan");
        fs::write(fixture.stage.join("bin/fcp-host"), b"tampered").expect("tamper stage");
        assert_eq!(
            plan.revalidate().expect_err("stale stage").code(),
            ProvisionErrorCode::Digest
        );
        assert!(fixture.stage.exists());
    }

    #[test]
    fn owner_atomic_seam_consumes_proof_and_preserves_current_on_failure() {
        let fixture = Fixture::new();
        let plan = fixture.request().validate().expect("valid plan");
        let before = fs::canonicalize(&fixture.current).expect("current target");
        let proof = plan.revalidate().expect("revalidated proof");
        fs::create_dir(proof.release_path()).expect("occupy release path");
        assert!(TestAtomicInstaller.promote(proof).is_err());
        assert_eq!(
            fs::canonicalize(&fixture.current).expect("current target"),
            before
        );
        assert!(fixture.stage.exists());

        let fixture = Fixture::new();
        fixture.set_previous_git_revision();
        let plan = fixture.request().validate().expect("valid plan");
        let rollback = plan.rollback_plan();
        let proof = plan.revalidate().expect("revalidated proof");
        TestAtomicInstaller
            .promote(proof)
            .expect("atomic promotion");
        assert_eq!(
            fs::canonicalize(&fixture.current).expect("current target"),
            fixture.releases.join(&fixture.release_id)
        );
        assert!(!fixture.stage.exists());
        assert_eq!(rollback.promotion(), Promotion::TemporarySymlinkRename);
    }

    #[test]
    fn receipt_artifact_owner_mode_and_path_fail_closed() {
        let fixture = Fixture::new();
        fs::write(fixture.stage.join("bin/fcp-host"), b"tampered").expect("tamper");
        assert_eq!(
            fixture.request().validate().expect_err("digest").code(),
            ProvisionErrorCode::Digest
        );
        let fixture = Fixture::new();
        fs::set_permissions(
            fixture.stage.join("policy/local-mcp.json"),
            fs::Permissions::from_mode(0o666),
        )
        .expect("writable");
        assert!(matches!(
            fixture.request().validate().expect_err("mode").code(),
            ProvisionErrorCode::Permissions | ProvisionErrorCode::Layout
        ));
        let fixture = Fixture::new();
        fs::remove_file(fixture.stage.join("bin/fcp-host")).expect("remove");
        symlink("fcp-n8n", fixture.stage.join("bin/fcp-host")).expect("symlink");
        assert_eq!(
            fixture.request().validate().expect_err("symlink").code(),
            ProvisionErrorCode::Layout
        );
    }

    #[test]
    fn current_pointer_and_rollback_target_fail_closed() {
        let fixture = Fixture::new();
        fs::remove_file(&fixture.current).expect("remove current");
        fs::write(&fixture.current, b"not a link").expect("regular current");
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("regular current")
                .code(),
            ProvisionErrorCode::CurrentPointer
        );
        let fixture = Fixture::new();
        fs::remove_file(&fixture.current).expect("remove current");
        symlink(fixture.root.join("outside"), &fixture.current).expect("outside link");
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("outside current")
                .code(),
            ProvisionErrorCode::CurrentPointer
        );
    }

    #[test]
    fn rollback_release_tampering_is_detected_before_stage_validation() {
        let fixture = Fixture::new();
        fs::write(
            fixture.releases.join("previous/bin/fcp-n8n"),
            b"tampered rollback binary",
        )
        .expect("tamper rollback artifact");
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("rollback artifact")
                .code(),
            ProvisionErrorCode::Digest
        );

        let fixture = Fixture::new();
        fs::write(fixture.releases.join("previous/receipt.json"), b"{}").expect("tamper receipt");
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("rollback receipt")
                .code(),
            ProvisionErrorCode::Digest
        );

        let fixture = Fixture::new();
        fs::write(
            fixture.releases.join("previous/provenance.json"),
            serde_json::json!({
                "schema": PROVENANCE_SCHEMA,
                "release_id": "previous",
                "git_revision": "abcdefabcdefabcdefabcdefabcdefabcdefabcd"
            })
            .to_string(),
        )
        .expect("tamper provenance");
        assert!(fixture.request().validate().is_err());

        let fixture = Fixture::new();
        let policy_path = fixture
            .releases
            .join("previous/inventory/eec-official-mcp.json");
        let mut policy: Value =
            serde_json::from_slice(&fs::read(&policy_path).expect("rollback policy"))
                .expect("rollback policy json");
        policy[0]["config"]["capability_policy"]["auth_mode"] = Value::String("wrong".to_owned());
        fs::write(
            &policy_path,
            serde_json::to_vec(&policy).expect("policy bytes"),
        )
        .expect("tamper policy");
        assert!(fixture.request().validate().is_err());
    }

    #[test]
    fn exact_policy_rejects_unknown_fields_and_hidden_secret_values() {
        let fixture = Fixture::new();
        let path = fixture.stage.join("inventory/eec-official-mcp.json");
        let mut inventory: Value =
            serde_json::from_slice(&fs::read(&path).expect("inventory")).expect("inventory json");
        inventory[0]["config"]["capability_policy"]["unexpected_policy_field"] = Value::Bool(true);
        fs::write(
            &path,
            serde_json::to_vec(&inventory).expect("inventory bytes"),
        )
        .expect("unknown field");
        fixture.write_receipt_after_inventory_change(&path);
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("unknown field")
                .code(),
            ProvisionErrorCode::Policy
        );

        let fixture = Fixture::new();
        let path = fixture.stage.join("inventory/eec-official-mcp.json");
        let mut inventory: Value =
            serde_json::from_slice(&fs::read(&path).expect("inventory")).expect("inventory json");
        inventory[0]["operation_network_constraints"]["mcp.tools.list"]["extra"] =
            Value::Bool(true);
        fs::write(
            &path,
            serde_json::to_vec(&inventory).expect("inventory bytes"),
        )
        .expect("network field");
        fixture.write_receipt_after_inventory_change(&path);
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("network field")
                .code(),
            ProvisionErrorCode::Policy
        );

        let fixture = Fixture::new();
        let path = fixture.stage.join("inventory/eec-official-mcp.json");
        let mut inventory: Value =
            serde_json::from_slice(&fs::read(&path).expect("inventory")).expect("inventory json");
        inventory[0]["config"]["capability_policy"]["auth_mode"] =
            Value::String("wrong".to_owned());
        fs::write(
            &path,
            serde_json::to_vec(&inventory).expect("inventory bytes"),
        )
        .expect("auth field");
        fixture.write_receipt_after_inventory_change(&path);
        assert_eq!(
            fixture.request().validate().expect_err("auth field").code(),
            ProvisionErrorCode::Policy
        );

        let fixture = Fixture::new();
        let path = fixture.stage.join("inventory/eec-official-mcp.json");
        let mut inventory: Value =
            serde_json::from_slice(&fs::read(&path).expect("inventory")).expect("inventory json");
        inventory[0]["description"] = Value::String("Bearer hidden-value".to_owned());
        fs::write(
            &path,
            serde_json::to_vec(&inventory).expect("inventory bytes"),
        )
        .expect("secret value");
        fixture.write_receipt_after_inventory_change(&path);
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("secret value")
                .code(),
            ProvisionErrorCode::SecretMaterial
        );
    }

    #[test]
    fn common_inventory_and_policy_shapes_reject_unknown_fields_and_hidden_secrets() {
        let fixture = Fixture::new();
        let path = fixture.stage.join("inventory/eec.json");
        let mut inventory: Value =
            serde_json::from_slice(&fs::read(&path).expect("inventory")).expect("inventory json");
        inventory[0]["unexpected_inventory_field"] = Value::Bool(true);
        fs::write(
            &path,
            serde_json::to_vec(&inventory).expect("inventory bytes"),
        )
        .expect("write inventory");
        fixture.write_receipt_after_inventory_change(&path);
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("common inventory unknown field")
                .code(),
            ProvisionErrorCode::Policy
        );

        let fixture = Fixture::new();
        let path = fixture.stage.join("policy/zone-policies.json");
        let mut policy: Value =
            serde_json::from_slice(&fs::read(&path).expect("zone policy")).expect("policy json");
        policy["z:work"]["unexpected_policy_field"] = Value::Bool(true);
        fs::write(&path, serde_json::to_vec(&policy).expect("policy bytes")).expect("write policy");
        fixture.write_receipt_after_inventory_change(&path);
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("zone policy unknown field")
                .code(),
            ProvisionErrorCode::Policy
        );

        let fixture = Fixture::new();
        let path = fixture.stage.join("policy/local-mcp.json");
        let mut policy: Value =
            serde_json::from_slice(&fs::read(&path).expect("local policy")).expect("policy json");
        policy["fixed_env"]["telemetry"] = Value::String("Bearer hidden-value".to_owned());
        fs::write(&path, serde_json::to_vec(&policy).expect("policy bytes"))
            .expect("write local policy");
        fixture.write_receipt_after_inventory_change(&path);
        assert_eq!(
            fixture
                .request()
                .validate()
                .expect_err("local policy secret")
                .code(),
            ProvisionErrorCode::SecretMaterial
        );
    }

    #[test]
    fn duplicate_server_binding_is_rejected_before_stage_reads() {
        let fixture = Fixture::new();
        let mut request = fixture.request();
        request.bindings = vec![request.bindings[0].clone(), request.bindings[0].clone()];
        assert_eq!(
            request
                .validate()
                .expect_err("duplicate server binding")
                .code(),
            ProvisionErrorCode::Policy
        );
    }

    #[test]
    fn duplicate_server_binding_in_provision_receipt_is_rejected() {
        let fixture = Fixture::new();
        let path = fixture.stage.join(PROVISION_RECEIPT_FILE);
        let mut receipt: Value =
            serde_json::from_slice(&fs::read(&path).expect("provision receipt"))
                .expect("provision receipt json");
        let first = receipt["bindings"][0].clone();
        receipt["bindings"] = Value::Array(vec![first.clone(), first]);
        fs::write(&path, serde_json::to_vec(&receipt).expect("receipt bytes"))
            .expect("write duplicate receipt");
        assert!(matches!(
            fixture
                .request()
                .validate()
                .expect_err("duplicate receipt binding")
                .code(),
            ProvisionErrorCode::Receipt | ProvisionErrorCode::Policy
        ));
    }

    #[test]
    fn unsafe_ancestry_is_rejected_and_plan_debug_is_redacted() {
        let fixture = Fixture::new();
        let alias = fixture.root.join("staging-alias");
        symlink(fixture.root.join("staging"), &alias).expect("staging alias");
        let mut request = fixture.request();
        request.stage_root = alias.join("release-test");
        assert_eq!(
            request.validate().expect_err("symlink ancestry").code(),
            ProvisionErrorCode::Path
        );

        let fixture = Fixture::new();
        let request = fixture.request();
        let plan = request.validate().expect("valid plan");
        let request_debug = format!("{:?}", fixture.request());
        let plan_debug = format!("{plan:?}");
        let rollback_debug = format!("{:?}", plan.rollback_plan());
        for debug in [request_debug, plan_debug, rollback_debug] {
            assert!(!debug.contains("release-test"));
            assert!(!debug.contains("0123456789abcdef"));
            assert!(!debug.contains("sha256:"));
            assert!(!debug.contains("/tmp/"));
        }
    }

    #[test]
    fn caller_path_traversal_is_rejected_before_stage_reads() {
        let fixture = Fixture::new();
        let request = ProvisionRequest::new(
            PathBuf::from("/var/lib/fwc-n8n/staging/../outside"),
            fixture.release_id.clone(),
            "0123456789abcdef0123456789abcdef01234567".to_owned(),
            fixture.request().bindings,
            test_owner_verification(),
        );
        assert_eq!(
            request.expect_err("parent traversal").code(),
            ProvisionErrorCode::Path
        );
    }

    #[test]
    fn secret_material_and_redacted_debug_fail_closed() {
        let fixture = Fixture::new();
        let path = fixture.stage.join("inventory/eec-official-mcp.json");
        let mut value: Value =
            serde_json::from_slice(&fs::read(&path).expect("inventory")).expect("json");
        value[0]["config"]["api_token"] = Value::String("secret-value".to_owned());
        fs::write(&path, serde_json::to_vec(&value).expect("json write")).expect("write");
        fixture.write_receipt_after_inventory_change(&path);
        assert_eq!(
            fixture.request().validate().expect_err("secret").code(),
            ProvisionErrorCode::SecretMaterial
        );
        let debug = format!("{:?}", fixture.request());
        assert!(!debug.contains("0123456789abcdef"));
        assert!(!debug.contains("staging"));
    }

    impl Fixture {
        fn write_receipt_after_inventory_change(&self, changed: &Path) {
            let _ = changed;
            fs::write(self.stage.join(RECEIPT_FILE), self.receipt()).expect("receipt refresh");
            fs::write(
                self.stage.join(PROVISION_RECEIPT_FILE),
                self.provision_receipt(),
            )
            .expect("provision receipt refresh");
        }
    }
}
