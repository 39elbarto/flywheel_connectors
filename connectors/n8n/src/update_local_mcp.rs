//! Closed update adapter contract for the local `n8n-mcp` npm package.
//!
//! This module constructs only fixed `npm` command specifications and converts
//! allowlisted registry metadata into the generic review snapshot. It never
//! executes a shell, accepts a caller-supplied path, or activates a package.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(test)]
use std::fs;
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::update::{
    ApplyReceipt, AuthorizedUpdate, ComponentSnapshot, ProvenanceSnapshot, ToolSnapshot,
    UpdateBackend, UpdateComponent, UpdateError, VerifiedCandidate, apply_authorized,
};

const NPM_PROGRAM: &str = "/usr/bin/npm";
const PACKAGE_NAME: &str = "n8n-mcp";
const STAGING_ROOT: &str = "/var/lib/fwc-n8n/update-staging/local-n8n-mcp";
const NPM_HOME: &str = "/var/lib/fwc-n8n/npm-home";
const NPM_CACHE: &str = "/var/cache/fwc-n8n/npm";
const MAX_VERSION_BYTES: usize = 96;
const COMMAND_TIMEOUT_MS: u64 = 180_000;
const MAX_STAGE_ENTRIES: usize = 100_000;
const MAX_STAGE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_STAGE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_STAGE_JSON_BYTES: u64 = 4 * 1024 * 1024;
const STAGE_TARBALL_RECEIPT: &str = ".registry-artifact.tgz";
const TAR_PROGRAM: &str = "/usr/bin/tar";
const MAX_ARCHIVE_LIST_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FixedCommandSpec {
    program: String,
    args: Vec<String>,
    environment: BTreeMap<String, String>,
    working_directory: String,
    timeout_ms: u64,
    env_clear: bool,
}

impl FixedCommandSpec {
    pub fn program(&self) -> &str {
        &self.program
    }

    pub fn args(&self) -> &[String] {
        &self.args
    }

    pub const fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    pub fn working_directory(&self) -> &str {
        &self.working_directory
    }

    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    /// A future executor must clear the ambient environment before applying
    /// the allowlisted values above.
    pub const fn env_clear(&self) -> bool {
        self.env_clear
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMcpStagePlan {
    component: UpdateComponent,
    exact_version: String,
    stage_id: String,
    stage_root: String,
    package_json_path: String,
    package_lock_path: String,
    install: FixedCommandSpec,
}

impl LocalMcpStagePlan {
    pub const fn component(&self) -> UpdateComponent {
        self.component
    }

    pub fn exact_version(&self) -> &str {
        &self.exact_version
    }

    pub fn stage_id(&self) -> &str {
        &self.stage_id
    }

    pub fn stage_root(&self) -> &str {
        &self.stage_root
    }

    pub fn package_json_path(&self) -> &str {
        &self.package_json_path
    }

    pub fn package_lock_path(&self) -> &str {
        &self.package_lock_path
    }

    pub const fn install(&self) -> &FixedCommandSpec {
        &self.install
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMcpRegistryMetadata {
    pub version: String,
    pub integrity: String,
    pub registry_tarball_url: String,
    pub engine_requirement: String,
    pub dependencies: BTreeMap<String, String>,
    pub lifecycle_scripts_digest: String,
    pub metadata_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedLocalMcpStage {
    candidate: VerifiedCandidate,
    stage_id: String,
    stage_tree_digest: String,
    package_manifest_digest: String,
    package_lock_digest: String,
    entry_count: usize,
    total_bytes: u64,
}

impl std::fmt::Debug for VerifiedLocalMcpStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedLocalMcpStage")
            .field("stage_id", &"<redacted>")
            .field("stage_tree_digest", &"<redacted>")
            .field("package_manifest_digest", &"<redacted>")
            .field("package_lock_digest", &"<redacted>")
            .field("entry_count", &self.entry_count)
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

impl VerifiedLocalMcpStage {
    pub const fn snapshot(&self) -> &ComponentSnapshot {
        self.candidate.snapshot()
    }

    pub fn into_candidate(self) -> VerifiedCandidate {
        self.candidate
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalMcpAdapterError {
    InvalidVersion,
    InvalidMetadata(&'static str),
    Encoding,
    StageLayout,
    StagePermissions,
    StageBounds,
    StageMismatch(&'static str),
    StageIo,
    Snapshot(UpdateError),
}

impl std::fmt::Display for LocalMcpAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::InvalidVersion => "invalid_version",
            Self::InvalidMetadata(code) => code,
            Self::Encoding => "encoding_failed",
            Self::StageLayout => "stage_layout_invalid",
            Self::StagePermissions => "stage_permissions_invalid",
            Self::StageBounds => "stage_bounds_exceeded",
            Self::StageMismatch(code) => code,
            Self::StageIo => "stage_io_failed",
            Self::Snapshot(_) => "snapshot_invalid",
        };
        write!(formatter, "local n8n-mcp update adapter failed: {code}")
    }
}

impl std::error::Error for LocalMcpAdapterError {}

pub fn npm_latest_metadata_plan() -> FixedCommandSpec {
    npm_view_plan("latest")
}

pub fn npm_exact_metadata_plan(version: &str) -> Result<FixedCommandSpec, LocalMcpAdapterError> {
    validate_exact_npm_version(version)?;
    Ok(npm_view_plan(version))
}

pub fn local_mcp_stage_plan(version: &str) -> Result<LocalMcpStagePlan, LocalMcpAdapterError> {
    let stage_id = Uuid::new_v4().to_string();
    build_local_mcp_stage_plan(version, &stage_id, Path::new(STAGING_ROOT))
}

fn build_local_mcp_stage_plan(
    version: &str,
    stage_id: &str,
    staging_root: &Path,
) -> Result<LocalMcpStagePlan, LocalMcpAdapterError> {
    validate_exact_npm_version(version)?;
    validate_stage_id(stage_id)?;
    if !staging_root.is_absolute() {
        return Err(LocalMcpAdapterError::StageLayout);
    }
    let staging_root = staging_root
        .to_str()
        .ok_or(LocalMcpAdapterError::StageLayout)?;
    let stage_root = format!("{staging_root}/{version}/{stage_id}");
    let package_spec = format!("{PACKAGE_NAME}@{version}");
    Ok(LocalMcpStagePlan {
        component: UpdateComponent::LocalN8nMcp,
        exact_version: version.to_string(),
        stage_id: stage_id.to_string(),
        package_json_path: format!("{stage_root}/node_modules/{PACKAGE_NAME}/package.json"),
        package_lock_path: format!("{stage_root}/package-lock.json"),
        install: FixedCommandSpec {
            program: NPM_PROGRAM.to_string(),
            args: vec![
                "install".to_string(),
                "--prefix".to_string(),
                stage_root.clone(),
                "--ignore-scripts".to_string(),
                "--no-audit".to_string(),
                "--no-fund".to_string(),
                "--package-lock=true".to_string(),
                "--save-exact".to_string(),
                package_spec,
            ],
            environment: fixed_npm_environment(),
            working_directory: staging_root.to_string(),
            timeout_ms: COMMAND_TIMEOUT_MS,
            env_clear: true,
        },
        stage_root,
    })
}

pub fn parse_registry_metadata(
    value: &Value,
) -> Result<LocalMcpRegistryMetadata, LocalMcpAdapterError> {
    let object = value
        .as_object()
        .ok_or(LocalMcpAdapterError::InvalidMetadata("metadata_not_object"))?;
    let version = required_string(object.get("version"), "version_missing")?;
    validate_exact_npm_version(version)?;
    let integrity = object
        .get("dist.integrity")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/dist/integrity").and_then(Value::as_str))
        .ok_or(LocalMcpAdapterError::InvalidMetadata("integrity_missing"))?;
    if !valid_integrity(integrity) {
        return Err(LocalMcpAdapterError::InvalidMetadata("integrity_invalid"));
    }
    let registry_tarball_url = value
        .pointer("/dist/tarball")
        .and_then(Value::as_str)
        .ok_or(LocalMcpAdapterError::InvalidMetadata("tarball_missing"))?;
    validate_registry_tarball_url(registry_tarball_url, version)?;
    let engine_requirement = object
        .get("engines")
        .and_then(Value::as_object)
        .and_then(|engines| engines.get("node"))
        .and_then(Value::as_str)
        .ok_or(LocalMcpAdapterError::InvalidMetadata("engine_missing"))?;
    validate_bounded_text(engine_requirement, "engine_invalid")?;
    let dependencies = parse_dependencies(object.get("dependencies"))?;
    let lifecycle_scripts = object.get("scripts").cloned().unwrap_or_else(|| json!({}));
    if !lifecycle_scripts.is_object() {
        return Err(LocalMcpAdapterError::InvalidMetadata("scripts_invalid"));
    }
    let lifecycle_scripts_digest = canonical_digest(&lifecycle_scripts)?;
    let safe_metadata = json!({
        "version": version,
        "integrity": integrity,
        "registryTarballUrl": registry_tarball_url,
        "engineRequirement": engine_requirement,
        "dependencies": dependencies,
        "lifecycleScriptsDigest": lifecycle_scripts_digest,
    });
    let metadata_digest = canonical_digest(&safe_metadata)?;
    Ok(LocalMcpRegistryMetadata {
        version: version.to_string(),
        integrity: integrity.to_string(),
        registry_tarball_url: registry_tarball_url.to_string(),
        engine_requirement: engine_requirement.to_string(),
        dependencies,
        lifecycle_scripts_digest,
        metadata_digest,
    })
}

pub fn snapshot_from_registry_metadata(
    metadata: LocalMcpRegistryMetadata,
    tools: Vec<ToolSnapshot>,
) -> Result<ComponentSnapshot, LocalMcpAdapterError> {
    let snapshot = ComponentSnapshot {
        component: UpdateComponent::LocalN8nMcp,
        version: metadata.version,
        provenance: ProvenanceSnapshot {
            source_kind: "npm_registry".to_string(),
            artifact_digest: metadata.integrity,
            metadata_digest: metadata.metadata_digest,
            engine_requirement: Some(metadata.engine_requirement),
            protocol_versions: BTreeSet::new(),
        },
        dependencies: metadata.dependencies,
        tools,
    };
    // Reuse the public detector for complete validation without exposing an
    // alternate normalization path. A clone is intentional: no-change is the
    // expected validation result.
    crate::update::detect_update(snapshot.clone(), snapshot.clone())
        .map_err(LocalMcpAdapterError::Snapshot)?;
    Ok(snapshot)
}

/// Verify one root-owned, uniquely identified staged npm installation.
///
/// The function reads only paths derived by `local_mcp_stage_plan`, rejects
/// links and writable-by-group/other content, binds registry integrity to the
/// installed package manifest and lockfile, and hashes the complete stage.
#[cfg(target_os = "linux")]
pub fn verify_root_owned_local_mcp_stage(
    plan: &LocalMcpStagePlan,
    metadata: &LocalMcpRegistryMetadata,
    tools: Vec<ToolSnapshot>,
) -> Result<VerifiedLocalMcpStage, LocalMcpAdapterError> {
    let expected = build_local_mcp_stage_plan(
        plan.exact_version(),
        plan.stage_id(),
        Path::new(STAGING_ROOT),
    )?;
    if plan != &expected {
        return Err(LocalMcpAdapterError::StageLayout);
    }
    verify_local_mcp_stage_for_owner(plan, metadata, tools, 0)
}

#[cfg(not(target_os = "linux"))]
pub fn verify_root_owned_local_mcp_stage(
    _plan: &LocalMcpStagePlan,
    _metadata: &LocalMcpRegistryMetadata,
    _tools: Vec<ToolSnapshot>,
) -> Result<VerifiedLocalMcpStage, LocalMcpAdapterError> {
    Err(LocalMcpAdapterError::StageLayout)
}

#[cfg(target_os = "linux")]
fn verify_local_mcp_stage_for_owner(
    plan: &LocalMcpStagePlan,
    metadata: &LocalMcpRegistryMetadata,
    tools: Vec<ToolSnapshot>,
    expected_owner: u32,
) -> Result<VerifiedLocalMcpStage, LocalMcpAdapterError> {
    validate_registry_metadata(metadata)?;
    if metadata.version != plan.exact_version {
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_version_mismatch",
        ));
    }

    let stage_root = Path::new(&plan.stage_root);
    let stage_fd = open_stage_root(stage_root, expected_owner)?;
    let tree = hash_stage_tree(stage_root, &stage_fd, expected_owner)?;

    let package_json_path = Path::new(&plan.package_json_path);
    let package_lock_path = Path::new(&plan.package_lock_path);
    let package_json = read_bounded_stage_json(
        &stage_fd,
        package_json_path,
        stage_root,
        expected_owner,
        MAX_STAGE_JSON_BYTES,
        tree.file_evidence(package_json_path, stage_root)?,
    )?;
    let package_lock = read_bounded_stage_json(
        &stage_fd,
        package_lock_path,
        stage_root,
        expected_owner,
        MAX_STAGE_JSON_BYTES,
        tree.file_evidence(package_lock_path, stage_root)?,
    )?;
    validate_installed_package_manifest(&package_json, metadata, plan.exact_version())?;
    validate_installed_package_lock(&package_lock, metadata, plan.exact_version())?;

    let package_manifest_digest = canonical_digest(&package_json)?;
    let package_lock_digest = canonical_digest(&package_lock)?;
    let package_root = package_json_path
        .parent()
        .ok_or(LocalMcpAdapterError::StageLayout)?;
    let bin_path = package_root.join(package_bin_relative_path(&package_json)?);
    if !bin_path.starts_with(package_root) {
        return Err(LocalMcpAdapterError::StageLayout);
    }
    verify_stage_file_matches_tree(
        &stage_fd,
        &bin_path,
        stage_root,
        expected_owner,
        "package_bin_missing",
        tree.file_evidence(&bin_path, stage_root)?,
    )?;
    let receipt_integrity = verify_registry_tarball_receipt(
        &stage_fd,
        stage_root,
        metadata,
        expected_owner,
        tree.file_evidence(&stage_root.join(STAGE_TARBALL_RECEIPT), stage_root)?,
    )?;
    let artifact_binding_digest = canonical_digest(&(
        "fwc.n8n.local-mcp-artifact-binding.v1",
        &receipt_integrity,
        &tree.digest,
    ))?;
    let safe_metadata_digest = canonical_digest(&(
        "fwc.n8n.local-mcp-stage.v1",
        &metadata.metadata_digest,
        &metadata.integrity,
        &metadata.registry_tarball_url,
        &package_manifest_digest,
        &package_lock_digest,
        &tree.digest,
        &receipt_integrity,
        &artifact_binding_digest,
    ))?;
    let release_artifact_binding = registry_release_binding(metadata, &receipt_integrity)?;
    let snapshot = ComponentSnapshot {
        component: UpdateComponent::LocalN8nMcp,
        version: metadata.version.clone(),
        provenance: ProvenanceSnapshot {
            source_kind: "npm_staged_artifact".to_string(),
            artifact_digest: artifact_binding_digest,
            metadata_digest: safe_metadata_digest.clone(),
            engine_requirement: Some(metadata.engine_requirement.clone()),
            protocol_versions: BTreeSet::new(),
        },
        dependencies: metadata.dependencies.clone(),
        tools,
    };
    crate::update::detect_update(snapshot.clone(), snapshot.clone())
        .map_err(LocalMcpAdapterError::Snapshot)?;
    let candidate = VerifiedCandidate::from_verified_stage_with_release_binding(
        snapshot,
        plan.stage_id.clone(),
        safe_metadata_digest,
        release_artifact_binding,
    )
    .map_err(LocalMcpAdapterError::Snapshot)?;
    Ok(VerifiedLocalMcpStage {
        candidate,
        stage_id: plan.stage_id.clone(),
        stage_tree_digest: tree.digest,
        package_manifest_digest,
        package_lock_digest,
        entry_count: tree.entry_count,
        total_bytes: tree.total_bytes,
    })
}

fn validate_registry_metadata(
    metadata: &LocalMcpRegistryMetadata,
) -> Result<(), LocalMcpAdapterError> {
    validate_exact_npm_version(&metadata.version)?;
    if !valid_integrity(&metadata.integrity) {
        return Err(LocalMcpAdapterError::InvalidMetadata("integrity_invalid"));
    }
    validate_registry_tarball_url(&metadata.registry_tarball_url, &metadata.version)?;
    validate_bounded_text(&metadata.engine_requirement, "engine_invalid")?;
    let dependencies = parse_dependencies(Some(&json!(metadata.dependencies)))?;
    if dependencies != metadata.dependencies
        || !valid_blake3_digest(&metadata.lifecycle_scripts_digest)
        || !valid_blake3_digest(&metadata.metadata_digest)
    {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "metadata_digest_invalid",
        ));
    }
    let expected = canonical_digest(&json!({
        "version": metadata.version,
        "integrity": metadata.integrity,
        "registryTarballUrl": metadata.registry_tarball_url,
        "engineRequirement": metadata.engine_requirement,
        "dependencies": metadata.dependencies,
        "lifecycleScriptsDigest": metadata.lifecycle_scripts_digest,
    }))?;
    if expected != metadata.metadata_digest {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "metadata_digest_mismatch",
        ));
    }
    Ok(())
}

fn validate_installed_package_manifest(
    value: &Value,
    metadata: &LocalMcpRegistryMetadata,
    exact_version: &str,
) -> Result<(), LocalMcpAdapterError> {
    let object = value
        .as_object()
        .ok_or(LocalMcpAdapterError::StageMismatch(
            "package_manifest_invalid",
        ))?;
    if object.get("name").and_then(Value::as_str) != Some(PACKAGE_NAME)
        || object.get("version").and_then(Value::as_str) != Some(exact_version)
        || object
            .get("engines")
            .and_then(Value::as_object)
            .and_then(|engines| engines.get("node"))
            .and_then(Value::as_str)
            != Some(metadata.engine_requirement.as_str())
    {
        return Err(LocalMcpAdapterError::StageMismatch(
            "package_manifest_mismatch",
        ));
    }
    let dependencies = parse_dependencies(object.get("dependencies"))?;
    if dependencies != metadata.dependencies {
        return Err(LocalMcpAdapterError::StageMismatch(
            "package_dependencies_mismatch",
        ));
    }
    let scripts = object.get("scripts").cloned().unwrap_or_else(|| json!({}));
    if !scripts.is_object() || canonical_digest(&scripts)? != metadata.lifecycle_scripts_digest {
        return Err(LocalMcpAdapterError::StageMismatch(
            "package_scripts_mismatch",
        ));
    }
    package_bin_relative_path(value)?;
    Ok(())
}

fn package_bin_relative_path(value: &Value) -> Result<PathBuf, LocalMcpAdapterError> {
    let bin_path = value
        .get("bin")
        .and_then(Value::as_object)
        .and_then(|bin| bin.get(PACKAGE_NAME))
        .and_then(Value::as_str)
        .ok_or(LocalMcpAdapterError::StageMismatch("package_bin_missing"))?;
    validate_safe_relative_path(bin_path)?;
    Ok(PathBuf::from(
        bin_path.strip_prefix("./").unwrap_or(bin_path),
    ))
}

fn validate_installed_package_lock(
    value: &Value,
    metadata: &LocalMcpRegistryMetadata,
    exact_version: &str,
) -> Result<(), LocalMcpAdapterError> {
    let object = value
        .as_object()
        .ok_or(LocalMcpAdapterError::StageMismatch("package_lock_invalid"))?;
    let lockfile_version = object
        .get("lockfileVersion")
        .and_then(Value::as_u64)
        .ok_or(LocalMcpAdapterError::StageMismatch("lock_version_missing"))?;
    if !(2..=3).contains(&lockfile_version) {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_version_unsupported",
        ));
    }
    let package = object
        .get("packages")
        .and_then(Value::as_object)
        .and_then(|packages| packages.get("node_modules/n8n-mcp"))
        .and_then(Value::as_object)
        .ok_or(LocalMcpAdapterError::StageMismatch("lock_package_missing"))?;
    let root = object
        .get("packages")
        .and_then(Value::as_object)
        .and_then(|packages| packages.get(""))
        .and_then(Value::as_object)
        .ok_or(LocalMcpAdapterError::StageMismatch("lock_root_missing"))?;
    let root_dependencies = parse_dependencies(root.get("dependencies"))?;
    if root_dependencies != BTreeMap::from([(PACKAGE_NAME.to_string(), exact_version.to_string())])
    {
        return Err(LocalMcpAdapterError::StageMismatch("lock_root_mismatch"));
    }
    if package.get("version").and_then(Value::as_str) != Some(exact_version)
        || package.get("integrity").and_then(Value::as_str) != Some(metadata.integrity.as_str())
        || package.get("resolved").and_then(Value::as_str)
            != Some(metadata.registry_tarball_url.as_str())
        || parse_dependencies(package.get("dependencies"))? != metadata.dependencies
    {
        return Err(LocalMcpAdapterError::StageMismatch("lock_package_mismatch"));
    }
    Ok(())
}

fn validate_safe_relative_path(value: &str) -> Result<(), LocalMcpAdapterError> {
    if value.is_empty() || value.len() > 512 || !value.is_ascii() || value.contains('\\') {
        return Err(LocalMcpAdapterError::StageMismatch("package_bin_invalid"));
    }
    let trimmed = value.strip_prefix("./").unwrap_or(value);
    let path = Path::new(trimmed);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LocalMcpAdapterError::StageMismatch("package_bin_invalid"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_stage_root(stage_root: &Path, expected_owner: u32) -> Result<File, LocalMcpAdapterError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};

    let relative = stage_root
        .strip_prefix("/")
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
    let filesystem_root = open("/", OFlags::DIRECTORY | OFlags::CLOEXEC, Mode::empty())
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    let fd = openat2(
        &filesystem_root,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| LocalMcpAdapterError::StageLayout)?;
    let file = File::from(fd);
    verify_stage_directory_metadata(
        &file.metadata().map_err(|_| LocalMcpAdapterError::StageIo)?,
        expected_owner,
    )?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn open_stage_file(
    stage_fd: &File,
    path: &Path,
    stage_root: &Path,
    expected_owner: u32,
    missing_code: &'static str,
) -> Result<File, LocalMcpAdapterError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

    let relative = path
        .strip_prefix(stage_root)
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LocalMcpAdapterError::StageLayout);
    }
    let fd = openat2(
        stage_fd,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| LocalMcpAdapterError::StageMismatch(missing_code))?;
    let file = File::from(fd);
    verify_stage_file_metadata(
        &file.metadata().map_err(|_| LocalMcpAdapterError::StageIo)?,
        expected_owner,
    )?;
    Ok(file)
}

#[cfg(target_os = "linux")]
fn read_bounded_stage_json(
    stage_fd: &File,
    path: &Path,
    stage_root: &Path,
    expected_owner: u32,
    max_bytes: u64,
    expected: &StageFileEvidence,
) -> Result<Value, LocalMcpAdapterError> {
    let mut file = open_stage_file(stage_fd, path, stage_root, expected_owner, "json_missing")?;
    let before = file.metadata().map_err(|_| LocalMcpAdapterError::StageIo)?;
    if file_metadata_changed(&expected.metadata, &before) {
        return Err(LocalMcpAdapterError::StageMismatch("stage_changed"));
    }
    if before.len() > max_bytes {
        return Err(LocalMcpAdapterError::StageBounds);
    }
    let capacity = usize::try_from(before.len()).map_err(|_| LocalMcpAdapterError::StageBounds)?;
    let mut bytes = Vec::with_capacity(capacity);
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    if bytes.len() as u64 > max_bytes {
        return Err(LocalMcpAdapterError::StageBounds);
    }
    let after = file.metadata().map_err(|_| LocalMcpAdapterError::StageIo)?;
    verify_stage_file_metadata(&after, expected_owner)?;
    if after.len() != before.len() || after.len() != bytes.len() as u64 {
        return Err(LocalMcpAdapterError::StageMismatch("stage_changed"));
    }
    if file_metadata_changed(&before, &after)
        || format!("blake3-256:{}", blake3::hash(&bytes).to_hex()) != expected.digest
    {
        return Err(LocalMcpAdapterError::StageMismatch("stage_changed"));
    }
    serde_json::from_slice(&bytes).map_err(|_| LocalMcpAdapterError::StageMismatch("json_invalid"))
}

struct StageFileEvidence {
    digest: String,
    metadata: Metadata,
}

struct StageTreeDigest {
    digest: String,
    entry_count: usize,
    total_bytes: u64,
    files: BTreeMap<String, StageFileEvidence>,
}

impl StageTreeDigest {
    fn file_evidence(
        &self,
        path: &Path,
        stage_root: &Path,
    ) -> Result<&StageFileEvidence, LocalMcpAdapterError> {
        let relative = stage_relative_path(path, stage_root)?;
        self.files
            .get(relative)
            .ok_or(LocalMcpAdapterError::StageMismatch("stage_file_missing"))
    }
}

#[cfg(target_os = "linux")]
fn hash_stage_tree(
    stage_root: &Path,
    stage_fd: &File,
    expected_owner: u32,
) -> Result<StageTreeDigest, LocalMcpAdapterError> {
    use rustix::fs::{Mode, OFlags, RawDir, ResolveFlags, openat2};
    use std::ffi::OsStr;
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;
    let root_fd = stage_fd
        .try_clone()
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    let mut pending = vec![(stage_root.to_path_buf(), root_fd)];
    let mut entries: Vec<(PathBuf, Metadata, Option<File>)> = Vec::new();
    let mut watched_directories: Vec<(File, Metadata)> = Vec::new();
    while let Some((directory_path, directory_fd)) = pending.pop() {
        let before = directory_fd
            .metadata()
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        let mut buffer = [MaybeUninit::uninit(); 4096];
        let mut directory = RawDir::new(&directory_fd, &mut buffer);
        while let Some(entry) = directory.next() {
            let entry = entry.map_err(|_| LocalMcpAdapterError::StageIo)?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." || name.is_empty() {
                continue;
            }
            let name = OsStr::from_bytes(name);
            let path = directory_path.join(name);
            let fd = openat2(
                &directory_fd,
                name,
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|_| LocalMcpAdapterError::StageLayout)?;
            let child = File::from(fd);
            let metadata = child
                .metadata()
                .map_err(|_| LocalMcpAdapterError::StageIo)?;
            if metadata.file_type().is_dir() {
                verify_stage_directory_metadata(&metadata, expected_owner)?;
                pending.push((path.clone(), child));
                entries.push((path, metadata, None));
            } else if metadata.file_type().is_file() {
                verify_stage_file_metadata(&metadata, expected_owner)?;
                entries.push((path, metadata, Some(child)));
            } else {
                return Err(LocalMcpAdapterError::StageLayout);
            }
            if entries.len() > MAX_STAGE_ENTRIES {
                return Err(LocalMcpAdapterError::StageBounds);
            }
        }
        let after = directory_fd
            .metadata()
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        if directory_metadata_changed(&before, &after) {
            return Err(LocalMcpAdapterError::StageMismatch("stage_changed"));
        }
        watched_directories.push((directory_fd, after));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"fwc.n8n.local-mcp-stage-tree.v1\0");
    let mut total_bytes = 0u64;
    let mut files = BTreeMap::new();
    for (path, metadata, file) in &mut entries {
        let relative = stage_relative_path(path, stage_root)?;
        let relative_bytes = relative.as_bytes();
        hasher.update(&(relative_bytes.len() as u64).to_le_bytes());
        hasher.update(relative_bytes);
        if metadata.file_type().is_dir() {
            hasher.update(b"d");
            continue;
        }
        if metadata.len() > MAX_STAGE_FILE_BYTES {
            return Err(LocalMcpAdapterError::StageBounds);
        }
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or(LocalMcpAdapterError::StageBounds)?;
        if total_bytes > MAX_STAGE_BYTES {
            return Err(LocalMcpAdapterError::StageBounds);
        }
        hasher.update(b"f");
        hasher.update(&metadata.len().to_le_bytes());
        let file = file.as_mut().ok_or(LocalMcpAdapterError::StageIo)?;
        let mut file_hasher = blake3::Hasher::new();
        let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
        let mut read_total = 0u64;
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|_| LocalMcpAdapterError::StageIo)?;
            if read == 0 {
                break;
            }
            read_total = read_total
                .checked_add(read as u64)
                .ok_or(LocalMcpAdapterError::StageBounds)?;
            if read_total > MAX_STAGE_FILE_BYTES {
                return Err(LocalMcpAdapterError::StageBounds);
            }
            hasher.update(&buffer[..read]);
            file_hasher.update(&buffer[..read]);
        }
        let after = file.metadata().map_err(|_| LocalMcpAdapterError::StageIo)?;
        verify_stage_file_metadata(&after, expected_owner)?;
        if read_total != metadata.len() || file_metadata_changed(metadata, &after) {
            return Err(LocalMcpAdapterError::StageMismatch("stage_changed"));
        }
        files.insert(
            relative.to_string(),
            StageFileEvidence {
                digest: format!("blake3-256:{}", file_hasher.finalize().to_hex()),
                metadata: after,
            },
        );
    }
    for (directory, expected) in watched_directories {
        let after = directory
            .metadata()
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        verify_stage_directory_metadata(&after, expected_owner)?;
        if directory_metadata_changed(&expected, &after) {
            return Err(LocalMcpAdapterError::StageMismatch("stage_changed"));
        }
    }
    Ok(StageTreeDigest {
        digest: format!("blake3-256:{}", hasher.finalize().to_hex()),
        entry_count: entries.len(),
        total_bytes,
        files,
    })
}

#[cfg(target_os = "linux")]
fn verify_stage_file_matches_tree(
    stage_fd: &File,
    path: &Path,
    stage_root: &Path,
    expected_owner: u32,
    missing_code: &'static str,
    expected: &StageFileEvidence,
) -> Result<(), LocalMcpAdapterError> {
    let mut file = open_stage_file(stage_fd, path, stage_root, expected_owner, missing_code)?;
    let before = file.metadata().map_err(|_| LocalMcpAdapterError::StageIo)?;
    if file_metadata_changed(&expected.metadata, &before) {
        return Err(LocalMcpAdapterError::StageMismatch("stage_changed"));
    }
    let mut hasher = blake3::Hasher::new();
    let mut bytes_read = 0u64;
    let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or(LocalMcpAdapterError::StageBounds)?;
        if bytes_read > MAX_STAGE_FILE_BYTES {
            return Err(LocalMcpAdapterError::StageBounds);
        }
        hasher.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|_| LocalMcpAdapterError::StageIo)?;
    verify_stage_file_metadata(&after, expected_owner)?;
    let digest = format!("blake3-256:{}", hasher.finalize().to_hex());
    if bytes_read != before.len()
        || file_metadata_changed(&before, &after)
        || digest != expected.digest
    {
        return Err(LocalMcpAdapterError::StageMismatch("stage_changed"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_registry_tarball_receipt(
    stage_fd: &File,
    stage_root: &Path,
    metadata: &LocalMcpRegistryMetadata,
    expected_owner: u32,
    expected: &StageFileEvidence,
) -> Result<String, LocalMcpAdapterError> {
    use base64::Engine;
    use sha2::{Digest, Sha512};

    let receipt_path = stage_root.join(STAGE_TARBALL_RECEIPT);
    let mut file = open_stage_file(
        stage_fd,
        &receipt_path,
        stage_root,
        expected_owner,
        "registry_receipt_missing",
    )?;
    let before = file.metadata().map_err(|_| LocalMcpAdapterError::StageIo)?;
    if file_metadata_changed(&expected.metadata, &before) {
        return Err(LocalMcpAdapterError::StageMismatch("stage_changed"));
    }
    if before.len() > MAX_STAGE_FILE_BYTES {
        return Err(LocalMcpAdapterError::StageBounds);
    }
    let mut hasher = Sha512::new();
    let mut tree_hasher = blake3::Hasher::new();
    let mut bytes_read = 0u64;
    let mut buffer = vec![0u8; 64 * 1024].into_boxed_slice();
    {
        let mut bounded = (&mut file).take(MAX_STAGE_FILE_BYTES.saturating_add(1));
        loop {
            let read = bounded
                .read(&mut buffer)
                .map_err(|_| LocalMcpAdapterError::StageIo)?;
            if read == 0 {
                break;
            }
            bytes_read = bytes_read
                .checked_add(read as u64)
                .ok_or(LocalMcpAdapterError::StageBounds)?;
            if bytes_read > MAX_STAGE_FILE_BYTES {
                return Err(LocalMcpAdapterError::StageBounds);
            }
            hasher.update(&buffer[..read]);
            tree_hasher.update(&buffer[..read]);
        }
    }
    let after = file.metadata().map_err(|_| LocalMcpAdapterError::StageIo)?;
    verify_stage_file_metadata(&after, expected_owner)?;
    if after.len() != before.len()
        || after.len() != bytes_read
        || file_metadata_changed(&before, &after)
        || format!("blake3-256:{}", tree_hasher.finalize().to_hex()) != expected.digest
    {
        return Err(LocalMcpAdapterError::StageMismatch("stage_changed"));
    }
    let actual = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    );
    if actual != metadata.integrity {
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_integrity_mismatch",
        ));
    }
    Ok(actual)
}

#[cfg(target_os = "linux")]
fn stage_relative_path<'a>(
    path: &'a Path,
    stage_root: &Path,
) -> Result<&'a str, LocalMcpAdapterError> {
    let relative = path
        .strip_prefix(stage_root)
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
    let relative = relative.to_str().ok_or(LocalMcpAdapterError::StageLayout)?;
    if relative.is_empty()
        || Path::new(relative)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LocalMcpAdapterError::StageLayout);
    }
    Ok(relative)
}

#[cfg(target_os = "linux")]
fn directory_metadata_changed(before: &Metadata, after: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.uid() != after.uid()
        || before.gid() != after.gid()
        || before.mode() != after.mode()
        || before.nlink() != after.nlink()
        || before.size() != after.size()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
}

#[cfg(target_os = "linux")]
fn file_metadata_changed(before: &Metadata, after: &Metadata) -> bool {
    directory_metadata_changed(before, after)
}

#[cfg(unix)]
fn verify_stage_directory_metadata(
    metadata: &Metadata,
    expected_owner: u32,
) -> Result<(), LocalMcpAdapterError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o7000 != 0
    {
        return Err(LocalMcpAdapterError::StagePermissions);
    }
    Ok(())
}

#[cfg(unix)]
fn verify_stage_file_metadata(
    metadata: &Metadata,
    expected_owner: u32,
) -> Result<(), LocalMcpAdapterError> {
    use std::os::unix::fs::MetadataExt;

    if !metadata.file_type().is_file()
        || metadata.uid() != expected_owner
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o7000 != 0
        || metadata.nlink() != 1
    {
        return Err(LocalMcpAdapterError::StagePermissions);
    }
    Ok(())
}

fn valid_blake3_digest(value: &str) -> bool {
    value
        .strip_prefix("blake3-256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn npm_view_plan(version: &str) -> FixedCommandSpec {
    FixedCommandSpec {
        program: NPM_PROGRAM.to_string(),
        args: vec![
            "view".to_string(),
            format!("{PACKAGE_NAME}@{version}"),
            "version".to_string(),
            "dist.integrity".to_string(),
            "dist.tarball".to_string(),
            "engines".to_string(),
            "dependencies".to_string(),
            "scripts".to_string(),
            "--json".to_string(),
        ],
        environment: fixed_npm_environment(),
        working_directory: STAGING_ROOT.to_string(),
        timeout_ms: COMMAND_TIMEOUT_MS,
        env_clear: true,
    }
}

fn fixed_npm_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("HOME".to_string(), NPM_HOME.to_string()),
        ("NO_UPDATE_NOTIFIER".to_string(), "1".to_string()),
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("npm_config_cache".to_string(), NPM_CACHE.to_string()),
    ])
}

fn validate_exact_npm_version(version: &str) -> Result<(), LocalMcpAdapterError> {
    if version.is_empty()
        || version.len() > MAX_VERSION_BYTES
        || !version.is_ascii()
        || version
            .as_bytes()
            .first()
            .is_none_or(|byte| !byte.is_ascii_digit())
        || version
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+')))
        || version.contains("..")
    {
        return Err(LocalMcpAdapterError::InvalidVersion);
    }
    let core = version.split(['-', '+']).next().unwrap_or_default();
    let mut parts = core.split('.');
    let valid_core = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && parts.next().is_none();
    if !valid_core {
        return Err(LocalMcpAdapterError::InvalidVersion);
    }
    Ok(())
}

fn validate_stage_id(stage_id: &str) -> Result<(), LocalMcpAdapterError> {
    let parsed = Uuid::parse_str(stage_id)
        .map_err(|_| LocalMcpAdapterError::InvalidMetadata("stage_id_invalid"))?;
    if parsed.to_string() != stage_id
        || parsed.as_bytes()[6] >> 4 != 4
        || parsed.as_bytes()[8] & 0xc0 != 0x80
    {
        return Err(LocalMcpAdapterError::InvalidMetadata("stage_id_invalid"));
    }
    Ok(())
}

fn required_string<'a>(
    value: Option<&'a Value>,
    code: &'static str,
) -> Result<&'a str, LocalMcpAdapterError> {
    value
        .and_then(Value::as_str)
        .ok_or(LocalMcpAdapterError::InvalidMetadata(code))
}

fn parse_dependencies(
    value: Option<&Value>,
) -> Result<BTreeMap<String, String>, LocalMcpAdapterError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or(LocalMcpAdapterError::InvalidMetadata(
            "dependencies_invalid",
        ))?;
    if object.len() > 512 {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "dependencies_oversized",
        ));
    }
    object
        .iter()
        .map(|(name, version)| {
            validate_package_name(name)?;
            let version = version
                .as_str()
                .ok_or(LocalMcpAdapterError::InvalidMetadata(
                    "dependency_version_invalid",
                ))?;
            validate_bounded_text(version, "dependency_version_invalid")?;
            Ok((name.clone(), version.to_string()))
        })
        .collect()
}

fn validate_package_name(name: &str) -> Result<(), LocalMcpAdapterError> {
    if name.is_empty()
        || name.len() > 214
        || !name.is_ascii()
        || name.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'/' | b'-' | b'_' | b'.'))
        })
    {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "dependency_name_invalid",
        ));
    }
    Ok(())
}

fn validate_bounded_text(value: &str, code: &'static str) -> Result<(), LocalMcpAdapterError> {
    if value.is_empty()
        || value.len() > 256
        || !value.is_ascii()
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(LocalMcpAdapterError::InvalidMetadata(code));
    }
    Ok(())
}

fn valid_integrity(value: &str) -> bool {
    value.strip_prefix("sha512-").is_some_and(|encoded| {
        (80..=128).contains(&encoded.len())
            && encoded
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    })
}

fn validate_registry_tarball_url(value: &str, version: &str) -> Result<(), LocalMcpAdapterError> {
    let suffix = format!("/{PACKAGE_NAME}/-/{PACKAGE_NAME}-{version}.tgz");
    if value.len() > 512
        || !value.is_ascii()
        || !value.starts_with("https://registry.npmjs.org")
        || !value.ends_with(&suffix)
        || value.contains(['?', '#', '\\'])
        || value.chars().any(char::is_control)
    {
        return Err(LocalMcpAdapterError::InvalidMetadata("tarball_invalid"));
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, LocalMcpAdapterError> {
    let bytes = serde_json::to_vec(value).map_err(|_| LocalMcpAdapterError::Encoding)?;
    Ok(format!("blake3-256:{}", blake3::hash(&bytes).to_hex()))
}

fn registry_release_binding(
    metadata: &LocalMcpRegistryMetadata,
    artifact_integrity: &str,
) -> Result<String, LocalMcpAdapterError> {
    if artifact_integrity != metadata.integrity {
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_integrity_mismatch",
        ));
    }
    canonical_digest(&(
        "fwc.n8n.registry-release-artifact.v1",
        &metadata.version,
        &metadata.metadata_digest,
        &metadata.integrity,
        &metadata.registry_tarball_url,
        artifact_integrity,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedLocalMcpArtifact {
    version: String,
    bytes: Vec<u8>,
}

impl TrustedLocalMcpArtifact {
    pub fn from_registry_bytes(
        version: &str,
        bytes: Vec<u8>,
    ) -> Result<Self, LocalMcpAdapterError> {
        validate_exact_npm_version(version)?;
        if bytes.len() as u64 > MAX_STAGE_FILE_BYTES {
            return Err(LocalMcpAdapterError::StageBounds);
        }
        Ok(Self {
            version: version.to_string(),
            bytes,
        })
    }
}

pub trait LocalMcpStageIo {
    fn create_empty_stage(&mut self, plan: &LocalMcpStagePlan) -> Result<(), LocalMcpAdapterError>;

    fn discard_stage(&mut self, plan: &LocalMcpStagePlan) -> Result<(), LocalMcpAdapterError>;

    fn materialize_exact_artifact(
        &mut self,
        plan: &LocalMcpStagePlan,
        artifact: &TrustedLocalMcpArtifact,
    ) -> Result<(), LocalMcpAdapterError>;

    fn extract_exact_artifact(
        &mut self,
        plan: &LocalMcpStagePlan,
    ) -> Result<(), LocalMcpAdapterError>;

    fn reverify(
        &mut self,
        plan: &LocalMcpStagePlan,
        metadata: &LocalMcpRegistryMetadata,
        tools: Vec<ToolSnapshot>,
    ) -> Result<VerifiedLocalMcpStage, LocalMcpAdapterError> {
        verify_root_owned_local_mcp_stage(plan, metadata, tools)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LocalMcpExecutorError {
    Adapter(LocalMcpAdapterError),
    Update(UpdateError),
    PlanMismatch,
    CandidateMismatch,
    CleanupFailed {
        original: Box<Self>,
        cleanup: LocalMcpAdapterError,
    },
}

impl std::fmt::Display for LocalMcpExecutorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Adapter(error) => error.fmt(formatter),
            Self::Update(error) => error.fmt(formatter),
            Self::PlanMismatch => formatter.write_str("local n8n-mcp stage plan mismatch"),
            Self::CandidateMismatch => formatter.write_str("local n8n-mcp candidate mismatch"),
            Self::CleanupFailed { .. } => formatter.write_str("local n8n-mcp stage cleanup failed"),
        }
    }
}

impl std::error::Error for LocalMcpExecutorError {}

fn validate_fixed_stage_plan(plan: &LocalMcpStagePlan) -> Result<(), LocalMcpExecutorError> {
    let expected = build_local_mcp_stage_plan(
        plan.exact_version(),
        plan.stage_id(),
        Path::new(STAGING_ROOT),
    )
    .map_err(LocalMcpExecutorError::Adapter)?;
    (plan == &expected)
        .then_some(())
        .ok_or(LocalMcpExecutorError::PlanMismatch)
}

fn verify_artifact_bytes(
    artifact: &TrustedLocalMcpArtifact,
    metadata: &LocalMcpRegistryMetadata,
) -> Result<String, LocalMcpExecutorError> {
    use base64::Engine;
    use sha2::{Digest, Sha512};

    if artifact.version != metadata.version {
        return Err(LocalMcpExecutorError::Adapter(
            LocalMcpAdapterError::StageMismatch("artifact_version_mismatch"),
        ));
    }
    let digest = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&artifact.bytes))
    );
    if digest != metadata.integrity {
        return Err(LocalMcpExecutorError::Adapter(
            LocalMcpAdapterError::StageMismatch("registry_integrity_mismatch"),
        ));
    }
    Ok(digest)
}

fn cleanup_pre_activation_error<I: LocalMcpStageIo>(
    stage_io: &mut I,
    plan: &LocalMcpStagePlan,
    original: LocalMcpExecutorError,
) -> LocalMcpExecutorError {
    match stage_io.discard_stage(plan) {
        Ok(()) => original,
        Err(cleanup) => LocalMcpExecutorError::CleanupFailed {
            original: Box::new(original),
            cleanup,
        },
    }
}

fn validate_authorized_candidate_before_stage(
    authorized: &AuthorizedUpdate,
    plan: &LocalMcpStagePlan,
    metadata: &LocalMcpRegistryMetadata,
) -> Result<(), LocalMcpExecutorError> {
    let candidate = authorized.candidate_handle();
    let snapshot = candidate.snapshot();
    if candidate.stage_id() != plan.stage_id()
        || !valid_blake3_digest(candidate.verification_digest())
        || snapshot.component != UpdateComponent::LocalN8nMcp
        || snapshot.version != plan.exact_version()
        || snapshot.version != metadata.version
        || snapshot.provenance.source_kind != "npm_staged_artifact"
        || !valid_blake3_digest(&snapshot.provenance.artifact_digest)
        || !valid_blake3_digest(&snapshot.provenance.metadata_digest)
    {
        return Err(LocalMcpExecutorError::CandidateMismatch);
    }
    Ok(())
}

/// Prepare and apply one internally generated local n8n-mcp stage.
///
/// Authorization is an opaque, already-consumed owner decision. The plan is
/// checked against the fixed production root, the artifact is checked against
/// registry SRI before materialization, and the extracted stage is independently
/// re-verified before the generic lock/CAS, activation, bounded smoke, and
/// conditional rollback state machine is entered.
pub fn execute_trusted_local_mcp<B, I>(
    backend: &mut B,
    stage_io: &mut I,
    authorized: AuthorizedUpdate,
    plan: &LocalMcpStagePlan,
    metadata: &LocalMcpRegistryMetadata,
    artifact: &TrustedLocalMcpArtifact,
    now_unix_ms: u64,
) -> Result<ApplyReceipt, LocalMcpExecutorError>
where
    B: UpdateBackend,
    I: LocalMcpStageIo,
{
    validate_fixed_stage_plan(plan)?;
    if authorized.component() != UpdateComponent::LocalN8nMcp {
        return Err(LocalMcpExecutorError::CandidateMismatch);
    }
    validate_authorized_candidate_before_stage(&authorized, plan, metadata)?;
    validate_registry_metadata(metadata).map_err(LocalMcpExecutorError::Adapter)?;
    let artifact_integrity = verify_artifact_bytes(artifact, metadata)?;
    let expected_release_binding = registry_release_binding(metadata, &artifact_integrity)
        .map_err(LocalMcpExecutorError::Adapter)?;
    if authorized.candidate_handle().release_artifact_binding()
        != Some(expected_release_binding.as_str())
    {
        return Err(LocalMcpExecutorError::CandidateMismatch);
    }

    stage_io
        .create_empty_stage(plan)
        .map_err(LocalMcpExecutorError::Adapter)?;
    if let Err(error) = stage_io.materialize_exact_artifact(plan, artifact) {
        return Err(cleanup_pre_activation_error(
            stage_io,
            plan,
            LocalMcpExecutorError::Adapter(error),
        ));
    }
    if let Err(error) = stage_io.extract_exact_artifact(plan) {
        return Err(cleanup_pre_activation_error(
            stage_io,
            plan,
            LocalMcpExecutorError::Adapter(error),
        ));
    }

    let verified = match stage_io.reverify(plan, metadata, authorized.candidate().tools.clone()) {
        Ok(verified) => verified,
        Err(error) => {
            return Err(cleanup_pre_activation_error(
                stage_io,
                plan,
                LocalMcpExecutorError::Adapter(error),
            ));
        }
    };
    if verified.candidate.stage_id() != authorized.candidate_handle().stage_id()
        || verified.candidate.verification_digest()
            != authorized.candidate_handle().verification_digest()
        || verified.snapshot() != authorized.candidate()
    {
        return Err(cleanup_pre_activation_error(
            stage_io,
            plan,
            LocalMcpExecutorError::CandidateMismatch,
        ));
    }

    apply_authorized(backend, authorized, now_unix_ms).map_err(LocalMcpExecutorError::Update)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct FixedFilesystemLocalMcpStageIo;

#[cfg(target_os = "linux")]
fn fixed_tar_environment() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([("PATH", "/usr/bin:/bin"), ("LC_ALL", "C")])
}

#[cfg(target_os = "linux")]
fn fixed_tar_command() -> Command {
    let mut command = Command::new(TAR_PROGRAM);
    command.env_clear().envs(fixed_tar_environment());
    command
}

#[cfg(target_os = "linux")]
fn open_tar_handoff_fds(plan: &LocalMcpStagePlan) -> Result<(File, File), LocalMcpAdapterError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};

    // These two descriptors intentionally omit CLOEXEC: tar receives only
    // stable `/proc/self/fd/N` aliases, never a replaceable pathname.
    let filesystem_root =
        open("/", OFlags::DIRECTORY, Mode::empty()).map_err(|_| LocalMcpAdapterError::StageIo)?;
    let relative = Path::new(plan.stage_root())
        .strip_prefix("/")
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
    let stage_fd = File::from(
        openat2(
            &filesystem_root,
            relative,
            OFlags::RDONLY | OFlags::DIRECTORY,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?,
    );
    verify_stage_directory_metadata(
        &stage_fd
            .metadata()
            .map_err(|_| LocalMcpAdapterError::StageIo)?,
        0,
    )?;
    let receipt_fd = File::from(
        openat2(
            &stage_fd,
            STAGE_TARBALL_RECEIPT,
            OFlags::RDONLY | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?,
    );
    verify_stage_file_metadata(
        &receipt_fd
            .metadata()
            .map_err(|_| LocalMcpAdapterError::StageIo)?,
        0,
    )?;
    Ok((stage_fd, receipt_fd))
}

#[cfg(target_os = "linux")]
fn proc_fd_path(file: &File) -> String {
    use std::os::fd::AsRawFd;

    format!("/proc/self/fd/{}", file.as_raw_fd())
}

#[cfg(target_os = "linux")]
fn validate_archive_listing(listing: &[u8]) -> Result<(), LocalMcpAdapterError> {
    if listing.len() > MAX_ARCHIVE_LIST_BYTES {
        return Err(LocalMcpAdapterError::StageBounds);
    }
    let mut entries = BTreeMap::<String, char>::new();
    let mut total_bytes = 0u64;
    for raw_line in listing.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if raw_line.is_empty() {
            continue;
        }
        let line = std::str::from_utf8(raw_line)
            .map_err(|_| LocalMcpAdapterError::StageMismatch("archive_listing_invalid"))?;
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() != 6 {
            return Err(LocalMcpAdapterError::StageMismatch(
                "archive_listing_invalid",
            ));
        }
        let kind = fields[0]
            .as_bytes()
            .first()
            .copied()
            .map(char::from)
            .ok_or(LocalMcpAdapterError::StageMismatch(
                "archive_listing_invalid",
            ))?;
        if !matches!(kind, '-' | 'd') {
            return Err(LocalMcpAdapterError::StageMismatch(
                "archive_entry_type_invalid",
            ));
        }
        let size = fields[2]
            .parse::<u64>()
            .map_err(|_| LocalMcpAdapterError::StageMismatch("archive_size_invalid"))?;
        if kind == '-' {
            total_bytes = total_bytes
                .checked_add(size)
                .ok_or(LocalMcpAdapterError::StageBounds)?;
            if total_bytes > MAX_STAGE_BYTES || size > MAX_STAGE_FILE_BYTES {
                return Err(LocalMcpAdapterError::StageBounds);
            }
        }
        let name = fields[5];
        if name.is_empty()
            || name.len() > 512
            || name.starts_with('/')
            || name.contains('\\')
            || name.chars().any(char::is_control)
        {
            return Err(LocalMcpAdapterError::StageMismatch("archive_path_invalid"));
        }
        let path = Path::new(name);
        if path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        }) {
            return Err(LocalMcpAdapterError::StageMismatch("archive_path_invalid"));
        }
        if entries
            .insert(name.trim_end_matches('/').to_string(), kind)
            .is_some()
        {
            return Err(LocalMcpAdapterError::StageMismatch(
                "archive_duplicate_entry",
            ));
        }
    }
    for (name, kind) in &entries {
        if *kind == 'd' {
            continue;
        }
        let mut parent = Path::new(name).parent();
        while let Some(path) = parent {
            if let Some(parent_kind) = entries.get(path.to_string_lossy().as_ref()) {
                if *parent_kind != 'd' {
                    return Err(LocalMcpAdapterError::StageMismatch(
                        "archive_parent_type_invalid",
                    ));
                }
            }
            parent = path.parent();
        }
    }
    if entries.len() > MAX_STAGE_ENTRIES {
        return Err(LocalMcpAdapterError::StageBounds);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TarListingReadError {
    TooLarge,
    Io,
}

#[cfg(target_os = "linux")]
fn read_bounded_tar_listing<R: Read>(reader: &mut R) -> Result<Vec<u8>, TarListingReadError> {
    let mut listing = Vec::new();
    let mut buffer = vec![0_u8; 16 * 1024].into_boxed_slice();
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| TarListingReadError::Io)?;
        if read == 0 {
            return Ok(listing);
        }
        if listing
            .len()
            .checked_add(read)
            .is_none_or(|length| length > MAX_ARCHIVE_LIST_BYTES)
        {
            return Err(TarListingReadError::TooLarge);
        }
        listing.extend_from_slice(&buffer[..read]);
    }
}

#[cfg(target_os = "linux")]
fn terminate_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(target_os = "linux")]
fn wait_child_until(
    child: &mut Child,
    deadline: Instant,
    timeout_code: &'static str,
) -> Result<std::process::ExitStatus, LocalMcpAdapterError> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| LocalMcpAdapterError::StageIo)?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            terminate_child(child);
            return Err(LocalMcpAdapterError::StageMismatch(timeout_code));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(target_os = "linux")]
fn run_bounded_tar_listing(receipt_path: &str) -> Result<Vec<u8>, LocalMcpAdapterError> {
    let deadline = Instant::now() + Duration::from_millis(COMMAND_TIMEOUT_MS);
    let mut child = fixed_tar_command()
        .args([
            "--list",
            "--verbose",
            "--numeric-owner",
            "--full-time",
            "--quoting-style=escape",
            "--file",
            receipt_path,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    let Some(mut stdout) = child.stdout.take() else {
        terminate_child(&mut child);
        return Err(LocalMcpAdapterError::StageIo);
    };
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let result = read_bounded_tar_listing(&mut stdout);
        let _ = sender.send(result);
    });
    let read_result = loop {
        match receiver.try_recv() {
            Ok(result) => break result,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                terminate_child(&mut child);
                let _ = reader.join();
                return Err(LocalMcpAdapterError::StageIo);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if Instant::now() >= deadline {
            terminate_child(&mut child);
            let _ = reader.join();
            return Err(LocalMcpAdapterError::StageMismatch(
                "archive_listing_timeout",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let listing = match read_result {
        Ok(listing) => listing,
        Err(TarListingReadError::TooLarge) => {
            terminate_child(&mut child);
            let _ = reader.join();
            return Err(LocalMcpAdapterError::StageBounds);
        }
        Err(TarListingReadError::Io) => {
            terminate_child(&mut child);
            let _ = reader.join();
            return Err(LocalMcpAdapterError::StageIo);
        }
    };
    let status = match wait_child_until(&mut child, deadline, "archive_listing_timeout") {
        Ok(status) => status,
        Err(error) => {
            terminate_child(&mut child);
            let _ = reader.join();
            return Err(error);
        }
    };
    if reader.join().is_err() {
        return Err(LocalMcpAdapterError::StageIo);
    }
    if !status.success() {
        return Err(LocalMcpAdapterError::StageMismatch(
            "archive_listing_failed",
        ));
    }
    Ok(listing)
}

#[cfg(target_os = "linux")]
fn digest_open_receipt(file: &mut File) -> Result<String, LocalMcpAdapterError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    let mut hasher = blake3::Hasher::new();
    let mut bytes_read = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or(LocalMcpAdapterError::StageBounds)?;
        if bytes_read > MAX_STAGE_FILE_BYTES {
            return Err(LocalMcpAdapterError::StageBounds);
        }
        hasher.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    Ok(format!("blake3-256:{}", hasher.finalize().to_hex()))
}

#[cfg(target_os = "linux")]
fn verify_open_receipt_digest(file: &mut File, expected: &str) -> Result<(), LocalMcpAdapterError> {
    if digest_open_receipt(file)? != expected {
        return Err(LocalMcpAdapterError::StageMismatch(
            "archive_receipt_changed",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn preflight_archive(plan: &LocalMcpStagePlan) -> Result<String, LocalMcpAdapterError> {
    let (_stage_fd, mut receipt_fd) = open_tar_handoff_fds(plan)?;
    let before_digest = digest_open_receipt(&mut receipt_fd)?;
    let receipt_path = proc_fd_path(&receipt_fd);
    let listing = run_bounded_tar_listing(&receipt_path)?;
    validate_archive_listing(&listing)?;
    let after_digest = digest_open_receipt(&mut receipt_fd)?;
    if before_digest != after_digest {
        return Err(LocalMcpAdapterError::StageMismatch(
            "archive_receipt_changed",
        ));
    }
    Ok(after_digest)
}

#[cfg(target_os = "linux")]
fn discard_stage_contents(
    stage_fd: &File,
    entries: &mut usize,
    total_bytes: &mut u64,
) -> Result<(), LocalMcpAdapterError> {
    use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags, openat2, unlinkat};

    let directory_path = proc_fd_path(stage_fd);
    for entry in std::fs::read_dir(directory_path).map_err(|_| LocalMcpAdapterError::StageIo)? {
        let entry = entry.map_err(|_| LocalMcpAdapterError::StageIo)?;
        let name = entry.file_name();
        let name_path = Path::new(&name);
        if name.as_os_str().is_empty()
            || name_path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(LocalMcpAdapterError::StageLayout);
        }
        *entries = (*entries)
            .checked_add(1)
            .ok_or(LocalMcpAdapterError::StageBounds)?;
        if *entries > MAX_STAGE_ENTRIES {
            return Err(LocalMcpAdapterError::StageBounds);
        }

        let child_dir = openat2(
            stage_fd,
            name_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        );
        if let Ok(child_dir) = child_dir {
            let child_dir = File::from(child_dir);
            verify_stage_directory_metadata(
                &child_dir
                    .metadata()
                    .map_err(|_| LocalMcpAdapterError::StageIo)?,
                0,
            )?;
            discard_stage_contents(&child_dir, entries, total_bytes)?;
            unlinkat(stage_fd, name_path, AtFlags::REMOVEDIR)
                .map_err(|_| LocalMcpAdapterError::StageIo)?;
            continue;
        }

        let child_file = openat2(
            stage_fd,
            name_path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let child_file = File::from(child_file);
        let metadata = child_file
            .metadata()
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        verify_stage_file_metadata(&metadata, 0)?;
        *total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or(LocalMcpAdapterError::StageBounds)?;
        if *total_bytes > MAX_STAGE_BYTES || metadata.len() > MAX_STAGE_FILE_BYTES {
            return Err(LocalMcpAdapterError::StageBounds);
        }
        unlinkat(stage_fd, name_path, AtFlags::empty())
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn discard_fixed_stage(plan: &LocalMcpStagePlan) -> Result<(), LocalMcpAdapterError> {
    use rustix::fs::{AtFlags, Mode, OFlags, ResolveFlags, openat2, unlinkat};

    validate_fixed_stage_plan(plan).map_err(|_| LocalMcpAdapterError::StageLayout)?;
    let staging_fd = open_stage_root(Path::new(STAGING_ROOT), 0)?;
    let version_fd = File::from(
        openat2(
            &staging_fd,
            plan.exact_version(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?,
    );
    verify_stage_directory_metadata(
        &version_fd
            .metadata()
            .map_err(|_| LocalMcpAdapterError::StageIo)?,
        0,
    )?;
    let stage_fd = File::from(
        openat2(
            &version_fd,
            plan.stage_id(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?,
    );
    verify_stage_directory_metadata(
        &stage_fd
            .metadata()
            .map_err(|_| LocalMcpAdapterError::StageIo)?,
        0,
    )?;
    let mut entries = 0;
    let mut total_bytes = 0;
    discard_stage_contents(&stage_fd, &mut entries, &mut total_bytes)?;
    unlinkat(&version_fd, plan.stage_id(), AtFlags::REMOVEDIR)
        .map_err(|_| LocalMcpAdapterError::StageIo)
}

#[cfg(target_os = "linux")]
impl LocalMcpStageIo for FixedFilesystemLocalMcpStageIo {
    fn create_empty_stage(&mut self, plan: &LocalMcpStagePlan) -> Result<(), LocalMcpAdapterError> {
        use rustix::fs::{Mode, OFlags, ResolveFlags, mkdirat, openat2};

        validate_fixed_stage_plan(plan).map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let staging_fd = open_stage_root(Path::new(STAGING_ROOT), 0)?;
        let version_fd = if let Ok(fd) = openat2(
            &staging_fd,
            plan.exact_version(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        ) {
            File::from(fd)
        } else {
            mkdirat(
                &staging_fd,
                plan.exact_version(),
                Mode::from_raw_mode(0o700),
            )
            .map_err(|_| LocalMcpAdapterError::StageLayout)?;
            File::from(
                openat2(
                    &staging_fd,
                    plan.exact_version(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty(),
                    ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
                )
                .map_err(|_| LocalMcpAdapterError::StageLayout)?,
            )
        };
        verify_stage_directory_metadata(
            &version_fd
                .metadata()
                .map_err(|_| LocalMcpAdapterError::StageIo)?,
            0,
        )?;
        mkdirat(&version_fd, plan.stage_id(), Mode::from_raw_mode(0o700))
            .map_err(|_| LocalMcpAdapterError::StageLayout)
    }

    fn discard_stage(&mut self, plan: &LocalMcpStagePlan) -> Result<(), LocalMcpAdapterError> {
        discard_fixed_stage(plan)
    }

    fn materialize_exact_artifact(
        &mut self,
        plan: &LocalMcpStagePlan,
        artifact: &TrustedLocalMcpArtifact,
    ) -> Result<(), LocalMcpAdapterError> {
        use rustix::fs::{Mode, OFlags, openat};

        let stage_fd = open_stage_root(Path::new(plan.stage_root()), 0)?;
        let fd = openat(
            &stage_fd,
            STAGE_TARBALL_RECEIPT,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let mut file = File::from(fd);
        file.write_all(&artifact.bytes)
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        file.sync_all().map_err(|_| LocalMcpAdapterError::StageIo)
    }

    fn extract_exact_artifact(
        &mut self,
        plan: &LocalMcpStagePlan,
    ) -> Result<(), LocalMcpAdapterError> {
        let preflight_digest = preflight_archive(plan)?;
        let (stage_fd, mut receipt_fd) = open_tar_handoff_fds(plan)?;
        verify_open_receipt_digest(&mut receipt_fd, &preflight_digest)?;
        let receipt_path = proc_fd_path(&receipt_fd);
        let stage_path = proc_fd_path(&stage_fd);
        let mut child = fixed_tar_command()
            .args([
                "--extract",
                "--file",
                receipt_path.as_str(),
                "--directory",
                stage_path.as_str(),
                "--no-same-owner",
                "--no-same-permissions",
                "--keep-directory-symlink",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        let deadline = Instant::now() + Duration::from_millis(COMMAND_TIMEOUT_MS);
        loop {
            if child
                .try_wait()
                .map_err(|_| LocalMcpAdapterError::StageIo)?
                .is_some()
            {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(LocalMcpAdapterError::StageMismatch(
                    "artifact_extract_timeout",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let status = child.wait().map_err(|_| LocalMcpAdapterError::StageIo)?;
        if !status.success() {
            return Err(LocalMcpAdapterError::StageMismatch(
                "artifact_extract_failed",
            ));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Default)]
pub struct FixedFilesystemLocalMcpStageIo;

#[cfg(not(target_os = "linux"))]
impl LocalMcpStageIo for FixedFilesystemLocalMcpStageIo {
    fn create_empty_stage(
        &mut self,
        _plan: &LocalMcpStagePlan,
    ) -> Result<(), LocalMcpAdapterError> {
        Err(LocalMcpAdapterError::StageLayout)
    }

    fn discard_stage(&mut self, _plan: &LocalMcpStagePlan) -> Result<(), LocalMcpAdapterError> {
        Err(LocalMcpAdapterError::StageLayout)
    }

    fn materialize_exact_artifact(
        &mut self,
        _plan: &LocalMcpStagePlan,
        _artifact: &TrustedLocalMcpArtifact,
    ) -> Result<(), LocalMcpAdapterError> {
        Err(LocalMcpAdapterError::StageLayout)
    }

    fn extract_exact_artifact(
        &mut self,
        _plan: &LocalMcpStagePlan,
    ) -> Result<(), LocalMcpAdapterError> {
        Err(LocalMcpAdapterError::StageLayout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::ToolImpact;
    use crate::update::{
        BackendError, DecisionLedger, DetectionOutcome, OwnerPrincipal, ReviewDecision,
        SmokeReport, authorize_update, detect_update,
    };

    const STAGE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    const INTEGRITY: &str = "sha512-iGO2wrmm+VGfN+bdmmI5JS/wErX9vVhM+aIto4CiWo3OTz1e5oDebFauc1xMhfNwF40h7rG6CiPTWrvUE1bEGA==";

    fn metadata_value(version: &str) -> Value {
        json!({
            "version": version,
            "dist.integrity": INTEGRITY,
            "dist": {"tarball": format!("https://registry.npmjs.org/{PACKAGE_NAME}/-/{PACKAGE_NAME}-{version}.tgz")},
            "engines": {"node": ">=18.0.0"},
            "dependencies": {"zod": "^3.25.0"},
            "scripts": {"postinstall": "UNTRUSTED-COMMAND-CANARY"},
            "releaseNotes": "UNTRUSTED-INSTRUCTION-CANARY"
        })
    }

    #[cfg(target_os = "linux")]
    fn staged_fixture() -> (
        tempfile::TempDir,
        LocalMcpStagePlan,
        LocalMcpRegistryMetadata,
        u32,
    ) {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().expect("temporary staging root");
        let plan = build_local_mcp_stage_plan("2.69.2", STAGE_ID, root.path())
            .expect("fixed staging plan");
        let package_root = Path::new(plan.package_json_path())
            .parent()
            .expect("package root");
        fs::create_dir_all(package_root.join("dist/mcp")).expect("package directories");
        for directory in [
            Path::new(plan.stage_root())
                .parent()
                .expect("version staging root"),
            Path::new(plan.stage_root()),
            &Path::new(plan.stage_root()).join("node_modules"),
            package_root,
            &package_root.join("dist"),
            &package_root.join("dist/mcp"),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private stage directory");
        }
        let package_json = json!({
            "name": PACKAGE_NAME,
            "version": "2.69.2",
            "engines": {"node": ">=18.0.0"},
            "dependencies": {"zod": "^3.25.0"},
            "scripts": {"postinstall": "UNTRUSTED-COMMAND-CANARY"},
            "bin": {"n8n-mcp": "./dist/mcp/stdio-wrapper.js"}
        });
        fs::write(
            plan.package_json_path(),
            serde_json::to_vec(&package_json).expect("package json"),
        )
        .expect("write package json");
        fs::set_permissions(plan.package_json_path(), fs::Permissions::from_mode(0o600))
            .expect("private package json");
        fs::write(
            package_root.join("dist/mcp/stdio-wrapper.js"),
            b"#!/usr/bin/env node\n",
        )
        .expect("write staged entrypoint");
        fs::set_permissions(
            package_root.join("dist/mcp/stdio-wrapper.js"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("private staged entrypoint");
        let package_lock = json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"n8n-mcp": "2.69.2"}},
                "node_modules/n8n-mcp": {
                    "version": "2.69.2",
                    "resolved": "https://registry.npmjs.org/n8n-mcp/-/n8n-mcp-2.69.2.tgz",
                    "integrity": INTEGRITY,
                    "dependencies": {"zod": "^3.25.0"}
                }
            }
        });
        fs::write(
            plan.package_lock_path(),
            serde_json::to_vec(&package_lock).expect("package lock"),
        )
        .expect("write package lock");
        fs::set_permissions(plan.package_lock_path(), fs::Permissions::from_mode(0o600))
            .expect("private package lock");
        fs::write(
            Path::new(plan.stage_root()).join(STAGE_TARBALL_RECEIPT),
            b"registry tarball receipt\n",
        )
        .expect("write registry receipt");
        fs::set_permissions(
            Path::new(plan.stage_root()).join(STAGE_TARBALL_RECEIPT),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private registry receipt");
        let metadata =
            parse_registry_metadata(&metadata_value("2.69.2")).expect("registry metadata");
        let owner = fs::metadata(root.path()).expect("root metadata").uid();
        (root, plan, metadata, owner)
    }

    #[test]
    fn stage_plan_has_only_fixed_program_paths_environment_and_flags() {
        let plan = local_mcp_stage_plan("2.69.2").unwrap();
        validate_stage_id(plan.stage_id()).expect("internally generated canonical v4 stage id");
        assert_eq!(
            plan.stage_root,
            format!("{STAGING_ROOT}/2.69.2/{}", plan.stage_id())
        );
        assert_eq!(plan.install.program, NPM_PROGRAM);
        assert_eq!(plan.install.working_directory, STAGING_ROOT);
        assert_eq!(plan.install.environment, fixed_npm_environment());
        assert!(plan.install.env_clear);
        assert_eq!(plan.install.args[0], "install");
        assert_eq!(plan.install.args[1], "--prefix");
        assert_eq!(plan.install.args[2], plan.stage_root);
        assert_eq!(
            &plan.install.args[3..],
            [
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--package-lock=true",
                "--save-exact",
                "n8n-mcp@2.69.2",
            ]
        );
    }

    #[test]
    fn version_validation_rejects_command_and_path_injection() {
        for version in [
            "",
            "latest",
            "2.69",
            "2.69.2;id",
            "2.69.2/../../tmp",
            "2.69.2 @evil",
            "@scope/pkg",
            "2..69.2",
        ] {
            assert_eq!(
                local_mcp_stage_plan(version),
                Err(LocalMcpAdapterError::InvalidVersion),
                "{version}"
            );
        }
        assert!(local_mcp_stage_plan("2.70.0-beta.1").is_ok());
    }

    #[test]
    fn public_stage_plans_generate_fresh_canonical_v4_ids() {
        let first = local_mcp_stage_plan("2.69.2").expect("first stage plan");
        let second = local_mcp_stage_plan("2.69.2").expect("second stage plan");
        assert_ne!(first.stage_id(), second.stage_id());
        for stage_id in [first.stage_id(), second.stage_id()] {
            validate_stage_id(stage_id).expect("canonical v4 stage id");
        }
    }

    #[test]
    fn latest_and_exact_detection_use_closed_npm_view_shape() {
        let latest = npm_latest_metadata_plan();
        let exact = npm_exact_metadata_plan("2.69.2").unwrap();
        assert_eq!(latest.args[1], "n8n-mcp@latest");
        assert_eq!(exact.args[1], "n8n-mcp@2.69.2");
        assert_eq!(latest.program, NPM_PROGRAM);
        assert!(latest.args.contains(&"dist.integrity".to_string()));
        assert!(latest.args.contains(&"scripts".to_string()));
    }

    #[test]
    fn metadata_projection_hashes_scripts_and_discards_release_notes() {
        let raw = metadata_value("2.69.2");
        let parsed = parse_registry_metadata(&raw).unwrap();
        let encoded = serde_json::to_string(&parsed).unwrap();
        assert!(!encoded.contains("UNTRUSTED-COMMAND-CANARY"));
        assert!(!encoded.contains("UNTRUSTED-INSTRUCTION-CANARY"));
        assert!(parsed.lifecycle_scripts_digest.starts_with("blake3-256:"));
        assert_eq!(parsed.integrity, INTEGRITY);
    }

    #[test]
    fn candidate_snapshot_contains_only_safe_catalog_metadata() {
        let parsed = parse_registry_metadata(&metadata_value("2.69.2")).unwrap();
        let snapshot = snapshot_from_registry_metadata(
            parsed,
            vec![ToolSnapshot {
                name: "search_nodes".to_string(),
                schema_digest: "sha256:schema".to_string(),
                description_digest: "sha256:description".to_string(),
                impact: ToolImpact::Read,
                permissions: BTreeSet::new(),
            }],
        )
        .unwrap();
        assert_eq!(snapshot.component, UpdateComponent::LocalN8nMcp);
        assert_eq!(snapshot.version, "2.69.2");
        assert_eq!(snapshot.tools.len(), 1);
        assert_eq!(
            snapshot.dependencies.get("zod"),
            Some(&"^3.25.0".to_string())
        );
    }

    #[test]
    fn malformed_registry_metadata_fails_closed() {
        for value in [
            json!([]),
            json!({"version": "2.69.2"}),
            json!({
                "version": "2.69.2",
                "dist.integrity": "sha1-weak",
                "engines": {"node": ">=18"}
            }),
            json!({
                "version": "2.69.2",
                "dist.integrity": INTEGRITY,
                "engines": {"node": ">=18"},
                "dependencies": {"bad name": "1.0.0"}
            }),
        ] {
            assert!(parse_registry_metadata(&value).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verified_stage_binds_registry_lock_manifest_and_complete_tree() {
        let (_root, plan, metadata, owner) = staged_fixture();
        let verified = verify_local_mcp_stage_for_owner(&plan, &metadata, Vec::new(), owner)
            .expect("verified stage");
        assert_eq!(verified.snapshot().version, "2.69.2");
        assert_eq!(
            verified.snapshot().provenance.source_kind,
            "npm_staged_artifact"
        );
        assert!(valid_blake3_digest(
            &verified.snapshot().provenance.artifact_digest
        ));
        assert_ne!(
            verified.snapshot().provenance.artifact_digest,
            metadata.integrity
        );
        assert_ne!(
            verified.snapshot().provenance.artifact_digest,
            verified.stage_tree_digest
        );
        assert!(verified.entry_count >= 5);
        assert!(verified.total_bytes > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_size_manifest_change_after_tree_pass_fails_closed() {
        let (_root, plan, _metadata, owner) = staged_fixture();
        let stage_root = Path::new(plan.stage_root());
        let stage_fd = open_stage_root(stage_root, owner).expect("open stage root");
        let tree = hash_stage_tree(stage_root, &stage_fd, owner).expect("hash stable tree");
        let package_json_path = Path::new(plan.package_json_path());
        let original = fs::read_to_string(package_json_path).expect("read package manifest");
        let changed = original.replace("\"version\":\"2.69.2\"", "\"version\":\"2.69.3\"");
        assert_eq!(changed.len(), original.len());
        assert_ne!(changed, original);
        fs::write(package_json_path, changed).expect("same-size in-place replacement");

        assert!(matches!(
            read_bounded_stage_json(
                &stage_fd,
                package_json_path,
                stage_root,
                owner,
                MAX_STAGE_JSON_BYTES,
                tree.file_evidence(package_json_path, stage_root)
                    .expect("manifest tree evidence"),
            ),
            Err(LocalMcpAdapterError::StageMismatch("stage_changed"))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn same_size_receipt_change_after_tree_pass_fails_closed() {
        let (_root, plan, metadata, owner) = staged_fixture();
        let stage_root = Path::new(plan.stage_root());
        let stage_fd = open_stage_root(stage_root, owner).expect("open stage root");
        let tree = hash_stage_tree(stage_root, &stage_fd, owner).expect("hash stable tree");
        let receipt_path = stage_root.join(STAGE_TARBALL_RECEIPT);
        let mut changed = fs::read(&receipt_path).expect("read registry receipt");
        changed[0] ^= 1;
        fs::write(&receipt_path, changed).expect("same-size in-place replacement");

        assert!(matches!(
            verify_registry_tarball_receipt(
                &stage_fd,
                stage_root,
                &metadata,
                owner,
                tree.file_evidence(&receipt_path, stage_root)
                    .expect("receipt tree evidence"),
            ),
            Err(LocalMcpAdapterError::StageMismatch("stage_changed"))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staged_lock_integrity_mismatch_fails_closed() {
        let (_root, plan, metadata, owner) = staged_fixture();
        let mismatched_lock = json!({
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"n8n-mcp": "2.69.2"}},
                "node_modules/n8n-mcp": {
                    "version": "2.69.2",
                    "resolved": "https://registry.npmjs.org/n8n-mcp/-/n8n-mcp-2.69.2.tgz",
                    "integrity": "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==",
                    "dependencies": {"zod": "^3.25.0"}
                }
            }
        });
        fs::write(
            plan.package_lock_path(),
            serde_json::to_vec(&mismatched_lock).expect("mismatched lock"),
        )
        .expect("replace package lock fixture");
        assert!(matches!(
            verify_local_mcp_stage_for_owner(&plan, &metadata, Vec::new(), owner),
            Err(LocalMcpAdapterError::StageMismatch("lock_package_mismatch"))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staged_registry_receipt_mismatch_never_creates_candidate() {
        let (_root, plan, metadata, owner) = staged_fixture();
        fs::write(
            Path::new(plan.stage_root()).join(STAGE_TARBALL_RECEIPT),
            b"tampered receipt\n",
        )
        .expect("replace registry receipt fixture");
        assert!(matches!(
            verify_local_mcp_stage_for_owner(&plan, &metadata, Vec::new(), owner),
            Err(LocalMcpAdapterError::StageMismatch(
                "registry_integrity_mismatch",
            ))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn oversized_json_is_rejected_by_actual_read_bound() {
        let (_root, plan, metadata, owner) = staged_fixture();
        let oversized = vec![b'{'; (MAX_STAGE_JSON_BYTES as usize) + 1];
        fs::write(plan.package_json_path(), oversized).expect("write oversized json");
        assert!(matches!(
            verify_local_mcp_stage_for_owner(&plan, &metadata, Vec::new(), owner),
            Err(LocalMcpAdapterError::StageBounds)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staged_symlink_is_rejected_before_candidate_creation() {
        let (_root, plan, metadata, owner) = staged_fixture();
        let package_root = Path::new(plan.package_json_path())
            .parent()
            .expect("package root");
        std::os::unix::fs::symlink(
            package_root.join("package.json"),
            package_root.join("unexpected-link"),
        )
        .expect("fixture symlink");
        assert!(matches!(
            verify_local_mcp_stage_for_owner(&plan, &metadata, Vec::new(), owner),
            Err(LocalMcpAdapterError::StageLayout)
        ));
    }

    #[derive(Default)]
    struct MockStageIo {
        calls: Vec<&'static str>,
        verified: Option<VerifiedLocalMcpStage>,
        create_error: Option<LocalMcpAdapterError>,
        materialize_error: Option<LocalMcpAdapterError>,
        extract_error: Option<LocalMcpAdapterError>,
        reverify_error: Option<LocalMcpAdapterError>,
        discard_error: Option<LocalMcpAdapterError>,
    }

    impl LocalMcpStageIo for MockStageIo {
        fn create_empty_stage(
            &mut self,
            _plan: &LocalMcpStagePlan,
        ) -> Result<(), LocalMcpAdapterError> {
            self.calls.push("create");
            self.create_error.take().map_or(Ok(()), Err)
        }

        fn discard_stage(&mut self, _plan: &LocalMcpStagePlan) -> Result<(), LocalMcpAdapterError> {
            self.calls.push("discard");
            self.discard_error.take().map_or(Ok(()), Err)
        }

        fn materialize_exact_artifact(
            &mut self,
            _plan: &LocalMcpStagePlan,
            _artifact: &TrustedLocalMcpArtifact,
        ) -> Result<(), LocalMcpAdapterError> {
            self.calls.push("materialize");
            self.materialize_error.take().map_or(Ok(()), Err)
        }

        fn extract_exact_artifact(
            &mut self,
            _plan: &LocalMcpStagePlan,
        ) -> Result<(), LocalMcpAdapterError> {
            self.calls.push("extract");
            self.extract_error.take().map_or(Ok(()), Err)
        }

        fn reverify(
            &mut self,
            _plan: &LocalMcpStagePlan,
            _metadata: &LocalMcpRegistryMetadata,
            _tools: Vec<ToolSnapshot>,
        ) -> Result<VerifiedLocalMcpStage, LocalMcpAdapterError> {
            self.calls.push("reverify");
            if let Some(error) = self.reverify_error.take() {
                return Err(error);
            }
            self.verified
                .take()
                .ok_or(LocalMcpAdapterError::StageMismatch(
                    "missing_mock_verification",
                ))
        }
    }

    struct MockBackend {
        active: ComponentSnapshot,
        lock_conflict: bool,
        smoke_passes: bool,
        locked: bool,
        rollbacks: usize,
    }

    impl UpdateBackend for MockBackend {
        fn begin_exact(
            &mut self,
            current: &ComponentSnapshot,
            _candidate: &VerifiedCandidate,
        ) -> Result<(), BackendError> {
            if self.lock_conflict || self.locked || &self.active != current {
                return Err(BackendError::ActivationFailed);
            }
            self.locked = true;
            Ok(())
        }

        fn active_snapshot(
            &mut self,
            _component: UpdateComponent,
        ) -> Result<ComponentSnapshot, BackendError> {
            self.locked
                .then(|| self.active.clone())
                .ok_or(BackendError::ActiveReadFailed)
        }

        fn activate_exact(&mut self, candidate: &VerifiedCandidate) -> Result<(), BackendError> {
            if !self.locked {
                return Err(BackendError::ActivationFailed);
            }
            self.active = candidate.snapshot().clone();
            Ok(())
        }

        fn smoke_exact(
            &mut self,
            expected: &ComponentSnapshot,
        ) -> Result<SmokeReport, BackendError> {
            let passed = expected.version != "2.70.0" || self.smoke_passes;
            Ok(SmokeReport {
                passed,
                check_ids: vec!["tools_list".to_string(), "zero_idle".to_string()],
                zero_idle_confirmed: passed,
                redaction_confirmed: passed,
            })
        }

        fn rollback_exact(
            &mut self,
            failed_candidate: &VerifiedCandidate,
            previous: &ComponentSnapshot,
        ) -> Result<(), BackendError> {
            if !self.locked || self.active != *failed_candidate.snapshot() {
                return Err(BackendError::RollbackFailed);
            }
            self.rollbacks += 1;
            self.active = previous.clone();
            Ok(())
        }

        fn finish(&mut self) {
            self.locked = false;
        }
    }

    fn executor_snapshot(version: &str, write: bool) -> ComponentSnapshot {
        executor_snapshot_with_source(
            version,
            write,
            if write {
                "npm_staged_artifact"
            } else {
                "npm_registry"
            },
        )
    }

    fn executor_snapshot_with_source(
        version: &str,
        write: bool,
        source_kind: &str,
    ) -> ComponentSnapshot {
        ComponentSnapshot {
            component: UpdateComponent::LocalN8nMcp,
            version: version.to_string(),
            provenance: ProvenanceSnapshot {
                source_kind: source_kind.to_string(),
                artifact_digest: format!("blake3-256:{}", "a".repeat(64)),
                metadata_digest: format!("blake3-256:{}", "b".repeat(64)),
                engine_requirement: Some(">=18.0.0".to_string()),
                protocol_versions: BTreeSet::new(),
            },
            dependencies: BTreeMap::from([("zod".to_string(), "^3.25.0".to_string())]),
            tools: vec![ToolSnapshot {
                name: if write {
                    "update_workflow"
                } else {
                    "search_nodes"
                }
                .to_string(),
                schema_digest: "blake3-256-schema".to_string(),
                description_digest: "blake3-256-description".to_string(),
                impact: if write {
                    ToolImpact::Write
                } else {
                    ToolImpact::Read
                },
                permissions: BTreeSet::new(),
            }],
        }
    }

    fn executor_fixture() -> (
        LocalMcpStagePlan,
        LocalMcpRegistryMetadata,
        AuthorizedUpdate,
        MockStageIo,
        ComponentSnapshot,
        TrustedLocalMcpArtifact,
    ) {
        executor_fixture_with_source("npm_staged_artifact")
    }

    fn executor_fixture_with_source(
        candidate_source_kind: &str,
    ) -> (
        LocalMcpStagePlan,
        LocalMcpRegistryMetadata,
        AuthorizedUpdate,
        MockStageIo,
        ComponentSnapshot,
        TrustedLocalMcpArtifact,
    ) {
        executor_fixture_with_binding(candidate_source_kind, None)
    }

    fn executor_fixture_with_binding(
        candidate_source_kind: &str,
        binding_override: Option<String>,
    ) -> (
        LocalMcpStagePlan,
        LocalMcpRegistryMetadata,
        AuthorizedUpdate,
        MockStageIo,
        ComponentSnapshot,
        TrustedLocalMcpArtifact,
    ) {
        let plan = local_mcp_stage_plan("2.70.0").expect("stage plan");
        let metadata = parse_registry_metadata(&metadata_value("2.70.0")).expect("metadata");
        let current = executor_snapshot("2.69.0", false);
        let candidate = executor_snapshot_with_source("2.70.0", true, candidate_source_kind);
        let artifact = TrustedLocalMcpArtifact::from_registry_bytes(
            "2.70.0",
            b"registry tarball receipt\n".to_vec(),
        )
        .expect("artifact");
        let release_binding = binding_override.unwrap_or_else(|| {
            registry_release_binding(&metadata, &metadata.integrity).expect("release binding")
        });
        let DetectionOutcome::ReviewRequired { review } =
            detect_update(current.clone(), candidate.clone()).expect("review")
        else {
            panic!("expected review");
        };
        let verified_candidate = VerifiedCandidate::from_verified_stage_with_release_binding(
            candidate,
            plan.stage_id(),
            format!("blake3-256:{}", "c".repeat(64)),
            release_binding,
        )
        .expect("verified candidate");
        let decision = crate::update::VerifiedOwnerDecision::from_trusted_source(
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            OwnerPrincipal::Owner,
            ReviewDecision::Approved,
            &review,
            "offline-test-approval",
            900,
            2_000,
        );
        let mut ledger = TestLedger;
        let authorized = authorize_update(
            current.clone(),
            verified_candidate.clone(),
            &review,
            &decision,
            &mut ledger,
            1_000,
        )
        .expect("authorized update");
        let verified = VerifiedLocalMcpStage {
            candidate: verified_candidate,
            stage_id: plan.stage_id().to_string(),
            stage_tree_digest: format!("blake3-256:{}", "d".repeat(64)),
            package_manifest_digest: format!("blake3-256:{}", "e".repeat(64)),
            package_lock_digest: format!("blake3-256:{}", "f".repeat(64)),
            entry_count: 1,
            total_bytes: 1,
        };
        let io = MockStageIo {
            calls: Vec::new(),
            verified: Some(verified),
            ..MockStageIo::default()
        };
        (plan, metadata, authorized, io, current, artifact)
    }

    #[derive(Default)]
    struct TestLedger;

    impl DecisionLedger for TestLedger {
        fn consume_once(
            &mut self,
            _decision_id: &str,
            _review_digest: &str,
        ) -> Result<bool, UpdateError> {
            Ok(true)
        }
    }

    #[test]
    fn trusted_executor_success_runs_fixed_stage_sequence_and_applies() {
        let (plan, metadata, authorized, mut io, current, artifact) = executor_fixture();
        let mut backend = MockBackend {
            active: current,
            lock_conflict: false,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        let receipt = execute_trusted_local_mcp(
            &mut backend,
            &mut io,
            authorized,
            &plan,
            &metadata,
            &artifact,
            1_500,
        )
        .expect("apply");
        assert_eq!(receipt.status, crate::update::ApplyStatus::Applied);
        assert_eq!(io.calls, ["create", "materialize", "extract", "reverify"]);
        assert!(!io.calls.contains(&"discard"));
        assert_eq!(backend.active.version, "2.70.0");
    }

    #[test]
    fn trusted_executor_discards_after_materialize_failure() {
        let (plan, metadata, authorized, mut io, current, artifact) = executor_fixture();
        io.materialize_error = Some(LocalMcpAdapterError::StageIo);
        let mut backend = MockBackend {
            active: current,
            lock_conflict: false,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        assert_eq!(
            execute_trusted_local_mcp(
                &mut backend,
                &mut io,
                authorized,
                &plan,
                &metadata,
                &artifact,
                1_500,
            ),
            Err(LocalMcpExecutorError::Adapter(
                LocalMcpAdapterError::StageIo,
            ))
        );
        assert_eq!(io.calls, ["create", "materialize", "discard"]);
    }

    #[test]
    fn trusted_executor_discards_after_extract_failure() {
        let (plan, metadata, authorized, mut io, current, artifact) = executor_fixture();
        io.extract_error = Some(LocalMcpAdapterError::StageMismatch("extract_failed"));
        let mut backend = MockBackend {
            active: current,
            lock_conflict: false,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        assert_eq!(
            execute_trusted_local_mcp(
                &mut backend,
                &mut io,
                authorized,
                &plan,
                &metadata,
                &artifact,
                1_500,
            ),
            Err(LocalMcpExecutorError::Adapter(
                LocalMcpAdapterError::StageMismatch("extract_failed"),
            ))
        );
        assert_eq!(io.calls, ["create", "materialize", "extract", "discard"]);
    }

    #[test]
    fn trusted_executor_discards_after_reverify_failure() {
        let (plan, metadata, authorized, mut io, current, artifact) = executor_fixture();
        io.reverify_error = Some(LocalMcpAdapterError::StageMismatch("reverify_failed"));
        let mut backend = MockBackend {
            active: current,
            lock_conflict: false,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        assert_eq!(
            execute_trusted_local_mcp(
                &mut backend,
                &mut io,
                authorized,
                &plan,
                &metadata,
                &artifact,
                1_500,
            ),
            Err(LocalMcpExecutorError::Adapter(
                LocalMcpAdapterError::StageMismatch("reverify_failed"),
            ))
        );
        assert_eq!(
            io.calls,
            ["create", "materialize", "extract", "reverify", "discard"]
        );
    }

    #[test]
    fn trusted_executor_discards_after_post_reverify_candidate_mismatch() {
        let (plan, metadata, authorized, mut io, current, artifact) = executor_fixture();
        let verified = io.verified.as_mut().expect("verified fixture");
        let candidate = verified.candidate.clone();
        verified.candidate = VerifiedCandidate::from_verified_stage_with_release_binding(
            candidate.snapshot().clone(),
            "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            candidate.verification_digest().to_string(),
            candidate
                .release_artifact_binding()
                .expect("release binding")
                .to_string(),
        )
        .expect("mismatched verified candidate");
        let mut backend = MockBackend {
            active: current,
            lock_conflict: false,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        assert_eq!(
            execute_trusted_local_mcp(
                &mut backend,
                &mut io,
                authorized,
                &plan,
                &metadata,
                &artifact,
                1_500,
            ),
            Err(LocalMcpExecutorError::CandidateMismatch)
        );
        assert_eq!(
            io.calls,
            ["create", "materialize", "extract", "reverify", "discard"]
        );
    }

    #[test]
    fn trusted_executor_reports_cleanup_failure_as_terminal() {
        let (plan, metadata, authorized, mut io, current, artifact) = executor_fixture();
        io.materialize_error = Some(LocalMcpAdapterError::StageIo);
        io.discard_error = Some(LocalMcpAdapterError::StageMismatch("cleanup_failed"));
        let mut backend = MockBackend {
            active: current,
            lock_conflict: false,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        let result = execute_trusted_local_mcp(
            &mut backend,
            &mut io,
            authorized,
            &plan,
            &metadata,
            &artifact,
            1_500,
        );
        assert!(matches!(
            result,
            Err(LocalMcpExecutorError::CleanupFailed {
                cleanup: LocalMcpAdapterError::StageMismatch("cleanup_failed"),
                ..
            })
        ));
        assert_eq!(io.calls, ["create", "materialize", "discard"]);
    }

    #[test]
    fn trusted_executor_does_not_discard_when_create_fails() {
        let (plan, metadata, authorized, mut io, current, artifact) = executor_fixture();
        io.create_error = Some(LocalMcpAdapterError::StageIo);
        let mut backend = MockBackend {
            active: current,
            lock_conflict: false,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        assert_eq!(
            execute_trusted_local_mcp(
                &mut backend,
                &mut io,
                authorized,
                &plan,
                &metadata,
                &artifact,
                1_500,
            ),
            Err(LocalMcpExecutorError::Adapter(
                LocalMcpAdapterError::StageIo,
            ))
        );
        assert_eq!(io.calls, ["create"]);
    }

    #[test]
    fn trusted_executor_rejects_candidate_mismatch_before_stage_creation() {
        let (_plan, metadata, authorized, mut io, _current, artifact) = executor_fixture();
        let mismatched_plan = local_mcp_stage_plan("2.71.0").expect("mismatched plan");
        let mut backend = MockBackend {
            active: executor_snapshot("2.69.0", false),
            lock_conflict: false,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        assert_eq!(
            execute_trusted_local_mcp(
                &mut backend,
                &mut io,
                authorized,
                &mismatched_plan,
                &metadata,
                &artifact,
                1_500,
            ),
            Err(LocalMcpExecutorError::CandidateMismatch)
        );
        assert!(io.calls.is_empty());
    }

    #[test]
    fn trusted_executor_rejects_candidate_provenance_before_stage_creation() {
        let (plan, metadata, authorized, mut io, current, artifact) =
            executor_fixture_with_source("npm_registry");
        let mut backend = MockBackend {
            active: current,
            lock_conflict: false,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        assert_eq!(
            execute_trusted_local_mcp(
                &mut backend,
                &mut io,
                authorized,
                &plan,
                &metadata,
                &artifact,
                1_500,
            ),
            Err(LocalMcpExecutorError::CandidateMismatch)
        );
        assert!(io.calls.is_empty());
    }

    #[test]
    fn trusted_executor_rejects_registry_binding_before_stage_creation() {
        let (plan, metadata, authorized, mut io, current, artifact) = executor_fixture_with_binding(
            "npm_staged_artifact",
            Some(format!("blake3-256:{}", "0".repeat(64))),
        );
        let mut backend = MockBackend {
            active: current,
            lock_conflict: false,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        assert_eq!(
            execute_trusted_local_mcp(
                &mut backend,
                &mut io,
                authorized,
                &plan,
                &metadata,
                &artifact,
                1_500,
            ),
            Err(LocalMcpExecutorError::CandidateMismatch)
        );
        assert!(io.calls.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hostile_archive_listing_is_rejected_before_extraction() {
        let listings = [
            b"-rw-r--r-- 0/0 1 2026-08-19 00:00 /absolute".as_slice(),
            b"-rw-r--r-- 0/0 1 2026-08-19 00:00 ../escape".as_slice(),
            b"lrwxrwxrwx 0/0 0 2026-08-19 00:00 link -> target".as_slice(),
            b"hrw-r--r-- 0/0 1 2026-08-19 00:00 hardlink".as_slice(),
            b"crw-r--r-- 0/0 1 2026-08-19 00:00 device".as_slice(),
            b"-rw-r--r-- 0/0 1 2026-08-19 00:00 package\n-rw-r--r-- 0/0 1 2026-08-19 00:00 package/file".as_slice(),
        ];
        for listing in listings {
            assert!(
                validate_archive_listing(listing).is_err(),
                "hostile listing accepted: {:?}",
                String::from_utf8_lossy(listing)
            );
        }
        let oversized = format!(
            "-rw-r--r-- 0/0 {} 2026-08-19 00:00 package/file",
            MAX_STAGE_FILE_BYTES + 1
        );
        assert!(validate_archive_listing(oversized.as_bytes()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn archive_listing_accepts_only_bounded_regular_files_and_directories() {
        let valid = b"drwxr-xr-x 0/0 0 2026-08-19 00:00 package\n-rw-r--r-- 0/0 1 2026-08-19 00:00 package/file";
        assert!(validate_archive_listing(valid).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tar_environment_is_explicit_and_excludes_tar_options() {
        let environment = fixed_tar_environment();
        assert_eq!(environment.get("PATH"), Some(&"/usr/bin:/bin"));
        assert_eq!(environment.get("LC_ALL"), Some(&"C"));
        assert!(!environment.contains_key("TAR_OPTIONS"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_tar_listing_reader_rejects_output_over_limit() {
        let mut reader = std::io::Cursor::new(vec![b'x'; MAX_ARCHIVE_LIST_BYTES + 1]);
        assert_eq!(
            read_bounded_tar_listing(&mut reader),
            Err(TarListingReadError::TooLarge)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tar_listing_deadline_kills_and_waits_for_child() {
        let mut child = Command::new("/bin/sleep")
            .arg("5")
            .spawn()
            .expect("spawn local timeout fixture");
        assert_eq!(
            wait_child_until(
                &mut child,
                Instant::now() + Duration::from_millis(1),
                "archive_listing_timeout",
            ),
            Err(LocalMcpAdapterError::StageMismatch(
                "archive_listing_timeout"
            ))
        );
        assert!(
            child
                .try_wait()
                .expect("child status after timeout")
                .is_some()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn receipt_digest_recheck_rejects_replacement() {
        let root = tempfile::tempdir().expect("receipt tempdir");
        let path = root.path().join(STAGE_TARBALL_RECEIPT);
        fs::write(&path, b"archive-a").expect("write initial receipt");
        let mut preflight = File::open(&path).expect("open initial receipt");
        let digest = digest_open_receipt(&mut preflight).expect("initial receipt digest");
        fs::write(&path, b"archive-b").expect("replace receipt");
        let mut extraction = File::open(&path).expect("open replacement receipt");
        assert_eq!(
            verify_open_receipt_digest(&mut extraction, &digest),
            Err(LocalMcpAdapterError::StageMismatch(
                "archive_receipt_changed"
            ))
        );
    }

    #[test]
    fn trusted_executor_propagates_component_lock_conflict() {
        let (plan, metadata, authorized, mut io, current, artifact) = executor_fixture();
        let mut backend = MockBackend {
            active: current,
            lock_conflict: true,
            smoke_passes: true,
            locked: false,
            rollbacks: 0,
        };
        assert_eq!(
            execute_trusted_local_mcp(
                &mut backend,
                &mut io,
                authorized,
                &plan,
                &metadata,
                &artifact,
                1_500,
            ),
            Err(LocalMcpExecutorError::Update(
                UpdateError::ActivePreconditionMismatch
            ))
        );
    }

    #[test]
    fn trusted_executor_rolls_back_after_smoke_failure() {
        let (plan, metadata, authorized, mut io, current, artifact) = executor_fixture();
        let mut backend = MockBackend {
            active: current.clone(),
            lock_conflict: false,
            smoke_passes: false,
            locked: false,
            rollbacks: 0,
        };
        let receipt = execute_trusted_local_mcp(
            &mut backend,
            &mut io,
            authorized,
            &plan,
            &metadata,
            &artifact,
            1_500,
        )
        .expect("conditional rollback");
        assert_eq!(receipt.status, crate::update::ApplyStatus::RolledBack);
        assert_eq!(backend.rollbacks, 1);
        assert_eq!(backend.active, current);
    }
}
