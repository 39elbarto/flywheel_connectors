//! Closed update adapter contract for the local `n8n-mcp` npm package.
//!
//! This module constructs only fixed `npm` command specifications and converts
//! allowlisted registry metadata into the generic review snapshot. It never
//! executes a shell, accepts a caller-supplied path, or activates a package.

use std::collections::{BTreeMap, BTreeSet};
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
const NPM_GLOBAL_CONFIG: &str = "/var/lib/fwc-n8n/npm-home/global.npmrc";
const MAX_VERSION_BYTES: usize = 96;
const COMMAND_TIMEOUT_MS: u64 = 180_000;
const MAX_STAGE_ENTRIES: usize = 100_000;
const MAX_STAGE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_STAGE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_STAGE_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REGISTRY_CLOSURE_PACKAGES: usize = 10_000;
const MAX_REGISTRY_CLOSURE_EDGES: usize = 50_000;
const STAGE_TARBALL_RECEIPT: &str = ".registry-artifact.tgz";
const STAGE_REGISTRY_CACHE: &str = ".registry-cache";
const STAGE_PROJECT_PACKAGE_JSON: &str = "package.json";
const VERIFICATION_RECEIPT: &str = ".verification-receipt.json";
const LOCK_PROJECT_NAME: &str = "fwc-n8n-local-mcp-stage";
const LOCK_PROJECT_VERSION: &str = "0.0.0";
const TAR_PROGRAM: &str = "/usr/bin/tar";
const MAX_ARCHIVE_LIST_BYTES: usize = 32 * 1024 * 1024;
const MAX_NPM_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

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
    registry_cache_path: String,
    pack: FixedCommandSpec,
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

    pub fn registry_cache_path(&self) -> &str {
        &self.registry_cache_path
    }

    pub const fn install(&self) -> &FixedCommandSpec {
        &self.install
    }

    pub const fn pack(&self) -> &FixedCommandSpec {
        &self.pack
    }

    pub fn verification_receipt_path(&self) -> String {
        let version_root = Path::new(&self.stage_root)
            .parent()
            .and_then(Path::to_str)
            .unwrap_or(self.stage_root.as_str());
        format!("{version_root}/{}{VERIFICATION_RECEIPT}", self.stage_id)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryClosurePackage {
    package_name: String,
    version: String,
    integrity: String,
    registry_tarball_url: String,
    dependencies: BTreeMap<String, String>,
    optional_dependencies: BTreeMap<String, String>,
    peer_dependencies: BTreeMap<String, String>,
    peer_dependencies_meta: BTreeMap<String, bool>,
    os: Vec<String>,
    cpu: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryClosureEdge {
    source_package_name: String,
    source_version: String,
    dependency_name: String,
    dependency_spec: String,
    dependency_kind: String,
    optional: bool,
    target_version: String,
    target_integrity: String,
    target_registry_tarball_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryPackageMetadata {
    package_name: String,
    version: String,
    integrity: String,
    registry_tarball_url: String,
    engine_requirement: Option<String>,
    lifecycle_scripts_digest: String,
    dependencies: BTreeMap<String, String>,
    optional_dependencies: BTreeMap<String, String>,
    peer_dependencies: BTreeMap<String, String>,
    peer_dependencies_meta: BTreeMap<String, bool>,
    os: Vec<String>,
    cpu: Vec<String>,
}

impl RegistryPackageMetadata {
    fn closure_package(&self) -> RegistryClosurePackage {
        RegistryClosurePackage {
            package_name: self.package_name.clone(),
            version: self.version.clone(),
            integrity: self.integrity.clone(),
            registry_tarball_url: self.registry_tarball_url.clone(),
            dependencies: self.dependencies.clone(),
            optional_dependencies: self.optional_dependencies.clone(),
            peer_dependencies: self.peer_dependencies.clone(),
            peer_dependencies_meta: self.peer_dependencies_meta.clone(),
            os: self.os.clone(),
            cpu: self.cpu.clone(),
        }
    }

    fn dependency_edges(&self) -> Vec<RegistryDependencyEdgeSpec> {
        let mut edges = Vec::new();
        for (name, spec) in &self.dependencies {
            if !self.optional_dependencies.contains_key(name) {
                edges.push(RegistryDependencyEdgeSpec {
                    name: name.clone(),
                    spec: spec.clone(),
                    kind: RegistryDependencyKind::Required,
                    optional: false,
                });
            }
        }
        edges.extend(self.optional_dependencies.iter().map(|(name, spec)| {
            RegistryDependencyEdgeSpec {
                name: name.clone(),
                spec: spec.clone(),
                kind: RegistryDependencyKind::Optional,
                optional: true,
            }
        }));
        edges.extend(self.peer_dependencies.iter().map(|(name, spec)| {
            RegistryDependencyEdgeSpec {
                name: name.clone(),
                spec: spec.clone(),
                kind: RegistryDependencyKind::Peer,
                optional: self
                    .peer_dependencies_meta
                    .get(name)
                    .copied()
                    .unwrap_or(false),
            }
        }));
        edges
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryDependencyKind {
    Required,
    Optional,
    Peer,
}

impl RegistryDependencyKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "dependencies",
            Self::Optional => "optionalDependencies",
            Self::Peer => "peerDependencies",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryDependencyEdgeSpec {
    name: String,
    spec: String,
    kind: RegistryDependencyKind,
    optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryClosure {
    packages: Vec<RegistryPackageMetadata>,
    edges: Vec<RegistryClosureEdge>,
    digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifiedLocalMcpStage {
    candidate: VerifiedCandidate,
    stage_id: String,
    stage_tree_digest: String,
    package_manifest_digest: String,
    package_lock_digest: String,
    entrypoint: String,
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
            .field("entrypoint", &self.entrypoint)
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

    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    pub fn stage_tree_digest(&self) -> &str {
        &self.stage_tree_digest
    }

    pub fn package_manifest_digest(&self) -> &str {
        &self.package_manifest_digest
    }

    pub fn package_lock_digest(&self) -> &str {
        &self.package_lock_digest
    }

    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMcpVerificationReceipt {
    pub schema: String,
    pub status: String,
    pub component: UpdateComponent,
    pub version: String,
    pub stage_id: String,
    pub stage_root: String,
    pub receipt_path: String,
    pub metadata_digest: String,
    pub registry_integrity: String,
    pub registry_tarball_url: String,
    pub registry_closure_digest: String,
    pub registry_closure_packages: Vec<RegistryClosurePackage>,
    pub registry_closure_edges: Vec<RegistryClosureEdge>,
    pub artifact_binding_digest: String,
    pub stage_tree_digest: String,
    pub package_manifest_digest: String,
    pub package_lock_digest: String,
    pub entrypoint: String,
    pub entry_count: usize,
    pub total_bytes: u64,
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

impl LocalMcpAdapterError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidVersion => "invalid_version",
            Self::InvalidMetadata(code) | Self::StageMismatch(code) => code,
            Self::Encoding => "encoding_failed",
            Self::StageLayout => "stage_layout_invalid",
            Self::StagePermissions => "stage_permissions_invalid",
            Self::StageBounds => "stage_bounds_exceeded",
            Self::StageIo => "stage_io_failed",
            Self::Snapshot(_) => "snapshot_invalid",
        }
    }
}

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
    let registry_cache_path = format!("{stage_root}/{STAGE_REGISTRY_CACHE}");
    let package_tarball_url =
        format!("https://registry.npmjs.org/{PACKAGE_NAME}/-/{PACKAGE_NAME}-{version}.tgz");
    Ok(LocalMcpStagePlan {
        component: UpdateComponent::LocalN8nMcp,
        exact_version: version.to_string(),
        stage_id: stage_id.to_string(),
        package_json_path: format!("{stage_root}/node_modules/{PACKAGE_NAME}/package.json"),
        package_lock_path: format!("{stage_root}/package-lock.json"),
        registry_cache_path: registry_cache_path.clone(),
        pack: FixedCommandSpec {
            program: NPM_PROGRAM.to_string(),
            args: vec![
                "pack".to_string(),
                package_tarball_url,
                "--ignore-scripts".to_string(),
                "--no-audit".to_string(),
                "--no-fund".to_string(),
                "--bin-links=false".to_string(),
                "--userconfig=/dev/null".to_string(),
                "--globalconfig=/var/lib/fwc-n8n/npm-home/global.npmrc".to_string(),
                "--cache".to_string(),
                registry_cache_path.clone(),
                "--registry=https://registry.npmjs.org".to_string(),
                "--pack-destination".to_string(),
                Path::new(&registry_cache_path)
                    .join(registry_package_key(PACKAGE_NAME)?)
                    .to_str()
                    .ok_or(LocalMcpAdapterError::StageLayout)?
                    .to_string(),
            ],
            environment: fixed_npm_environment_for(&registry_cache_path),
            working_directory: staging_root.to_string(),
            timeout_ms: COMMAND_TIMEOUT_MS,
            env_clear: true,
        },
        install: FixedCommandSpec {
            program: NPM_PROGRAM.to_string(),
            args: vec![
                "ci".to_string(),
                "--prefix".to_string(),
                stage_root.clone(),
                "--ignore-scripts".to_string(),
                "--no-audit".to_string(),
                "--no-fund".to_string(),
                "--cache".to_string(),
                registry_cache_path.clone(),
                "--offline".to_string(),
                "--registry=https://registry.npmjs.org".to_string(),
                "--bin-links=false".to_string(),
                "--userconfig=/dev/null".to_string(),
                "--globalconfig=/var/lib/fwc-n8n/npm-home/global.npmrc".to_string(),
                "--package-lock=true".to_string(),
            ],
            environment: fixed_npm_environment_for(&registry_cache_path),
            working_directory: staging_root.to_string(),
            timeout_ms: COMMAND_TIMEOUT_MS,
            env_clear: true,
        },
        stage_root,
    })
}

fn packed_artifact_path(plan: &LocalMcpStagePlan) -> PathBuf {
    Path::new(plan.registry_cache_path())
        .join(registry_package_key(PACKAGE_NAME).expect("fixed package name"))
        .join(format!("{PACKAGE_NAME}-{}.tgz", plan.exact_version()))
}

fn packed_registry_artifact_path(
    plan: &LocalMcpStagePlan,
    package_name: &str,
    version: &str,
) -> Result<PathBuf, LocalMcpAdapterError> {
    if package_name == PACKAGE_NAME && version == plan.exact_version() {
        return Ok(packed_artifact_path(plan));
    }
    Ok(Path::new(plan.registry_cache_path())
        .join(registry_package_key(package_name)?)
        .join(registry_artifact_filename(package_name, version)?))
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
        .get("dist.tarball")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/dist/tarball").and_then(Value::as_str))
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
    let lifecycle_scripts = object
        .get("scripts")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| json!({}));
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

fn registry_metadata_string<'a>(value: &'a Value, dotted_key: &str) -> Option<&'a str> {
    let pointer = match dotted_key {
        "dist.integrity" => "/dist/integrity",
        "dist.tarball" => "/dist/tarball",
        _ => return None,
    };
    value
        .get(dotted_key)
        .and_then(Value::as_str)
        .or_else(|| value.pointer(pointer).and_then(Value::as_str))
}

fn parse_peer_dependencies_meta(
    value: Option<&Value>,
    peers: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, bool>, LocalMcpAdapterError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or(LocalMcpAdapterError::InvalidMetadata(
            "peer_dependencies_meta_invalid",
        ))?;
    if object.len() > 512 {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "peer_dependencies_meta_oversized",
        ));
    }
    object
        .iter()
        .map(|(name, entry)| {
            validate_package_name(name)?;
            if !peers.contains_key(name) {
                return Err(LocalMcpAdapterError::InvalidMetadata(
                    "peer_dependencies_meta_unknown",
                ));
            }
            let entry = entry
                .as_object()
                .ok_or(LocalMcpAdapterError::InvalidMetadata(
                    "peer_dependencies_meta_invalid",
                ))?;
            if entry.keys().any(|key| key != "optional") {
                return Err(LocalMcpAdapterError::InvalidMetadata(
                    "peer_dependencies_meta_invalid",
                ));
            }
            let optional = entry.get("optional").map_or(Ok(false), |value| {
                value.as_bool().ok_or(LocalMcpAdapterError::InvalidMetadata(
                    "peer_dependencies_meta_invalid",
                ))
            })?;
            Ok((name.clone(), optional))
        })
        .collect()
}

fn parse_platform_constraints(value: Option<&Value>) -> Result<Vec<String>, LocalMcpAdapterError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(Vec::new());
    };
    let values = match value {
        Value::Array(values) => values.clone(),
        Value::String(value) => vec![Value::String(value.clone())],
        _ => {
            return Err(LocalMcpAdapterError::InvalidMetadata(
                "platform_constraints_invalid",
            ));
        }
    };
    if values.len() > 64 {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "platform_constraints_oversized",
        ));
    }
    values
        .iter()
        .map(|value| {
            let value = value.as_str().ok_or(LocalMcpAdapterError::InvalidMetadata(
                "platform_constraints_invalid",
            ))?;
            if value.is_empty()
                || value.len() > 32
                || !value.is_ascii()
                || value.chars().any(char::is_control)
            {
                return Err(LocalMcpAdapterError::InvalidMetadata(
                    "platform_constraints_invalid",
                ));
            }
            Ok(value.to_ascii_lowercase())
        })
        .collect()
}

fn registry_package_metadata(
    package_name: &str,
    value: &Value,
) -> Result<RegistryPackageMetadata, LocalMcpAdapterError> {
    let object = value
        .as_object()
        .ok_or(LocalMcpAdapterError::InvalidMetadata(
            "registry_dependency_closure_invalid",
        ))?;
    let version = object.get("version").and_then(Value::as_str).ok_or(
        LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid"),
    )?;
    validate_exact_npm_version(version).map_err(|_| {
        LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid")
    })?;
    let integrity = registry_metadata_string(value, "dist.integrity").ok_or(
        LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid"),
    )?;
    if !valid_integrity(integrity) {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "registry_dependency_closure_invalid",
        ));
    }
    let tarball = registry_metadata_string(value, "dist.tarball").ok_or(
        LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid"),
    )?;
    validate_registry_package_tarball_url(tarball, package_name, version).map_err(|_| {
        LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid")
    })?;
    let dependencies = parse_dependencies(object.get("dependencies")).map_err(|_| {
        LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid")
    })?;
    let optional_dependencies =
        parse_dependencies(object.get("optionalDependencies")).map_err(|_| {
            LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid")
        })?;
    let peer_dependencies = parse_dependencies(object.get("peerDependencies")).map_err(|_| {
        LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid")
    })?;
    let peer_dependencies_meta =
        parse_peer_dependencies_meta(object.get("peerDependenciesMeta"), &peer_dependencies)
            .map_err(|_| {
                LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid")
            })?;
    let os = parse_platform_constraints(object.get("os")).map_err(|_| {
        LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid")
    })?;
    let cpu = parse_platform_constraints(object.get("cpu")).map_err(|_| {
        LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid")
    })?;
    let engine_requirement = match object.get("engines").filter(|value| !value.is_null()) {
        None => None,
        Some(engines) => {
            let engines = engines
                .as_object()
                .ok_or(LocalMcpAdapterError::InvalidMetadata(
                    "registry_dependency_closure_invalid",
                ))?;
            engines
                .get("node")
                .map(|value| {
                    let value = value.as_str().ok_or(LocalMcpAdapterError::InvalidMetadata(
                        "registry_dependency_closure_invalid",
                    ))?;
                    validate_bounded_text(value, "registry_dependency_closure_invalid")?;
                    Ok::<_, LocalMcpAdapterError>(value.to_string())
                })
                .transpose()?
        }
    };
    let lifecycle_scripts = object
        .get("scripts")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !lifecycle_scripts.is_object() {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "registry_dependency_closure_invalid",
        ));
    }
    let lifecycle_scripts_digest = canonical_digest(&lifecycle_scripts)?;
    // These fields can alter the package source or the selected tree and are
    // intentionally unsupported. Reject them before any tarball is fetched.
    for field in ["bundleDependencies", "bundledDependencies", "overrides"] {
        if object.get(field).is_some_and(|entry| !entry.is_null()) {
            return Err(LocalMcpAdapterError::InvalidMetadata(
                "registry_dependency_closure_invalid",
            ));
        }
    }
    Ok(RegistryPackageMetadata {
        package_name: package_name.to_string(),
        version: version.to_string(),
        integrity: integrity.to_string(),
        registry_tarball_url: tarball.to_string(),
        engine_requirement,
        lifecycle_scripts_digest,
        dependencies,
        optional_dependencies,
        peer_dependencies,
        peer_dependencies_meta,
        os,
        cpu,
    })
}

fn registry_view_candidates(
    package_name: &str,
    value: &Value,
) -> Result<Vec<Value>, LocalMcpAdapterError> {
    if let Some(array) = value.as_array() {
        if array.is_empty() || array.len() > MAX_REGISTRY_CLOSURE_PACKAGES {
            return Err(LocalMcpAdapterError::StageBounds);
        }
        return Ok(array.clone());
    }
    let object = value
        .as_object()
        .ok_or(LocalMcpAdapterError::InvalidMetadata(
            "registry_dependency_closure_invalid",
        ))?;
    if object.get("version").is_some() {
        return Ok(vec![value.clone()]);
    }
    // Some npm versions return a compact object keyed by concrete versions
    // when the query spans more than one result. Normalize that shape without
    // trusting the key as metadata: the selected object's version remains the
    // authority, and a missing version is rejected below.
    let mut candidates = Vec::new();
    for (version, candidate) in object {
        if npm_version_parts(version).is_some() && candidate.is_object() {
            let mut candidate = candidate.clone();
            if candidate.get("version").is_none() {
                candidate["version"] = Value::String(version.clone());
            }
            candidates.push(candidate);
        }
    }
    if candidates.is_empty() {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "registry_dependency_closure_invalid",
        ));
    }
    let _ = package_name;
    Ok(candidates)
}

fn resolve_registry_view_metadata(
    package_name: &str,
    spec: &str,
    value: &Value,
) -> Result<RegistryPackageMetadata, LocalMcpAdapterError> {
    let selected = select_registry_view_value(package_name, spec, value)?;
    registry_package_metadata(package_name, &selected)
}

fn select_registry_view_value(
    package_name: &str,
    spec: &str,
    value: &Value,
) -> Result<Value, LocalMcpAdapterError> {
    let mut candidates = Vec::new();
    for candidate in registry_view_candidates(package_name, value)? {
        let metadata = registry_package_metadata(package_name, &candidate)?;
        if dependency_spec_allows_version(spec, &metadata.version) {
            candidates.push((metadata, candidate));
        }
    }
    candidates.sort_by(|(left, _), (right, _)| {
        npm_version_parts(&right.version)
            .cmp(&npm_version_parts(&left.version))
            .then_with(|| left.integrity.cmp(&right.integrity))
            .then_with(|| left.registry_tarball_url.cmp(&right.registry_tarball_url))
    });
    candidates
        .into_iter()
        .next()
        .map(|(_, candidate)| candidate)
        .ok_or(LocalMcpAdapterError::InvalidMetadata(
            "registry_dependency_closure_invalid",
        ))
}

fn registry_closure_digest(
    packages: &[RegistryPackageMetadata],
    edges: &[RegistryClosureEdge],
) -> Result<String, LocalMcpAdapterError> {
    let safe = packages
        .iter()
        .map(RegistryPackageMetadata::closure_package)
        .collect::<Vec<_>>();
    canonical_digest(&("fwc.n8n.registry-closure.v2", safe, edges))
}

fn registry_closure_receipt_digest(
    packages: &[RegistryClosurePackage],
    edges: &[RegistryClosureEdge],
) -> Result<String, LocalMcpAdapterError> {
    canonical_digest(&("fwc.n8n.registry-closure.v2", packages, edges))
}

fn closure_edge_sort_key(edge: &RegistryClosureEdge) -> (&str, &str, &str, &str, &str, &str) {
    (
        &edge.source_package_name,
        &edge.source_version,
        &edge.dependency_kind,
        &edge.dependency_name,
        &edge.dependency_spec,
        &edge.target_version,
    )
}

fn resolve_registry_dependency_closure<R: LocalMcpCommandRunner>(
    command_runner: &mut R,
    root_metadata: &Value,
    root: &LocalMcpRegistryMetadata,
) -> Result<RegistryClosure, LocalMcpAdapterError> {
    let root_package = registry_package_metadata(PACKAGE_NAME, root_metadata)?;
    if root_package.version != root.version
        || root_package.integrity != root.integrity
        || root_package.registry_tarball_url != root.registry_tarball_url
    {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "registry_dependency_closure_invalid",
        ));
    }
    let mut packages = BTreeMap::<(String, String), RegistryPackageMetadata>::new();
    let mut edges = Vec::new();
    packages.insert(
        (
            root_package.package_name.clone(),
            root_package.version.clone(),
        ),
        root_package,
    );
    let root_key = (PACKAGE_NAME.to_string(), root.version.clone());
    let mut pending = packages
        .get(&root_key)
        .expect("root package inserted")
        .dependency_edges()
        .into_iter()
        .map(|edge| (root_key.clone(), edge))
        .collect::<Vec<_>>();
    let mut edge_count = 0usize;
    while let Some(((source_package_name, source_version), edge)) = pending.pop() {
        edge_count = edge_count
            .checked_add(1)
            .ok_or(LocalMcpAdapterError::StageBounds)?;
        if edge_count > MAX_REGISTRY_CLOSURE_EDGES {
            return Err(LocalMcpAdapterError::StageBounds);
        }
        let plan = npm_dependency_metadata_plan(&edge.name, &edge.spec)?;
        let output = command_runner.run(&plan)?;
        let value: Value = serde_json::from_slice(&output).map_err(|_| {
            LocalMcpAdapterError::InvalidMetadata("registry_dependency_closure_invalid")
        })?;
        let selected = resolve_registry_view_metadata(&edge.name, &edge.spec, &value)?;
        let key = (selected.package_name.clone(), selected.version.clone());
        if let Some(previous) = packages.get(&key) {
            if previous != &selected {
                return Err(LocalMcpAdapterError::InvalidMetadata(
                    "registry_dependency_closure_invalid",
                ));
            }
        } else {
            packages.insert(key.clone(), selected.clone());
            if packages.len() > MAX_REGISTRY_CLOSURE_PACKAGES {
                return Err(LocalMcpAdapterError::StageBounds);
            }
            pending.extend(
                selected
                    .dependency_edges()
                    .into_iter()
                    .map(|child| (key.clone(), child)),
            );
        }
        edges.push(RegistryClosureEdge {
            source_package_name,
            source_version,
            dependency_name: edge.name,
            dependency_spec: edge.spec,
            dependency_kind: edge.kind.as_str().to_string(),
            optional: edge.optional,
            target_version: selected.version.clone(),
            target_integrity: selected.integrity.clone(),
            target_registry_tarball_url: selected.registry_tarball_url.clone(),
        });
    }
    let packages = packages.into_values().collect::<Vec<_>>();
    edges.sort_by(|left, right| closure_edge_sort_key(left).cmp(&closure_edge_sort_key(right)));
    let digest = registry_closure_digest(&packages, &edges)?;
    Ok(RegistryClosure {
        packages,
        edges,
        digest,
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

pub trait LocalMcpCommandRunner {
    fn run(&mut self, command: &FixedCommandSpec) -> Result<Vec<u8>, LocalMcpAdapterError>;
}

#[derive(Debug, Default)]
pub struct FixedNpmCommandRunner;

impl LocalMcpCommandRunner for FixedNpmCommandRunner {
    fn run(&mut self, command: &FixedCommandSpec) -> Result<Vec<u8>, LocalMcpAdapterError> {
        run_fixed_npm_command(command)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NpmOutputError {
    TooLarge,
    Io,
}

fn read_bounded_npm_output<R: Read>(reader: &mut R) -> Result<Vec<u8>, NpmOutputError> {
    let mut output = Vec::new();
    let mut buffer = vec![0_u8; 16 * 1024].into_boxed_slice();
    loop {
        let read = reader.read(&mut buffer).map_err(|_| NpmOutputError::Io)?;
        if read == 0 {
            return Ok(output);
        }
        if output
            .len()
            .checked_add(read)
            .is_none_or(|length| length > MAX_NPM_OUTPUT_BYTES)
        {
            return Err(NpmOutputError::TooLarge);
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn run_fixed_npm_command(command: &FixedCommandSpec) -> Result<Vec<u8>, LocalMcpAdapterError> {
    run_fixed_npm_command_with_spawn(
        command,
        Path::new(NPM_GLOBAL_CONFIG),
        STAGING_ROOT,
        spawn_fixed_npm_command,
    )
}

fn run_fixed_npm_command_with_spawn<F>(
    command: &FixedCommandSpec,
    global_config: &Path,
    expected_working_directory: &str,
    spawn: F,
) -> Result<Vec<u8>, LocalMcpAdapterError>
where
    F: FnOnce(&FixedCommandSpec) -> Result<Vec<u8>, LocalMcpAdapterError>,
{
    if command.program() != NPM_PROGRAM
        || !command.env_clear()
        || command.working_directory() != expected_working_directory
        || command.timeout_ms() == 0
    {
        return Err(LocalMcpAdapterError::StageLayout);
    }
    preflight_npm_command_with_global_config(command, global_config)?;
    spawn(command)
}

fn spawn_fixed_npm_command(command: &FixedCommandSpec) -> Result<Vec<u8>, LocalMcpAdapterError> {
    let mut process = Command::new(command.program());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut process, 0);
    let mut child = process
        .args(command.args())
        .env_clear()
        .envs(command.environment())
        .current_dir(command.working_directory())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    let mut stdout = child.stdout.take().ok_or(LocalMcpAdapterError::StageIo)?;
    let mut stderr = child.stderr.take().ok_or(LocalMcpAdapterError::StageIo)?;
    let (stdout_sender, stdout_receiver) = std::sync::mpsc::sync_channel(1);
    let (stderr_sender, stderr_receiver) = std::sync::mpsc::sync_channel(1);
    let stdout_reader = std::thread::spawn(move || {
        let _ = stdout_sender.send(read_bounded_npm_output(&mut stdout));
    });
    let stderr_reader = std::thread::spawn(move || {
        let _ = stderr_sender.send(read_bounded_npm_output(&mut stderr));
    });

    let deadline = Instant::now() + Duration::from_millis(command.timeout_ms());
    let mut stdout_result = None;
    let mut stderr_result = None;
    let mut status = None;
    loop {
        if stdout_result.is_none() {
            if let Ok(result) = stdout_receiver.try_recv() {
                stdout_result = Some(result);
            }
        }
        if stderr_result.is_none() {
            if let Ok(result) = stderr_receiver.try_recv() {
                stderr_result = Some(result);
            }
        }
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|_| LocalMcpAdapterError::StageIo)?;
        }
        if status.is_some() && stdout_result.is_some() && stderr_result.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            terminate_child(&mut child);
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(LocalMcpAdapterError::StageMismatch("npm_command_timeout"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if stdout_reader.join().is_err() || stderr_reader.join().is_err() {
        return Err(LocalMcpAdapterError::StageIo);
    }
    let stdout = match stdout_result.expect("stdout reader completed") {
        Ok(bytes) => bytes,
        Err(NpmOutputError::TooLarge) => return Err(LocalMcpAdapterError::StageBounds),
        Err(NpmOutputError::Io) => return Err(LocalMcpAdapterError::StageIo),
    };
    match stderr_result.expect("stderr reader completed") {
        Ok(_) => {}
        Err(NpmOutputError::TooLarge) => return Err(LocalMcpAdapterError::StageBounds),
        Err(NpmOutputError::Io) => return Err(LocalMcpAdapterError::StageIo),
    }
    if !status.expect("npm process completed").success() {
        return Err(LocalMcpAdapterError::StageMismatch("npm_command_failed"));
    }
    Ok(stdout)
}

fn preflight_npm_command_with_global_config(
    command: &FixedCommandSpec,
    global_config: &Path,
) -> Result<(), LocalMcpAdapterError> {
    let expected_global_config = format!("--globalconfig={NPM_GLOBAL_CONFIG}");
    if !command
        .args()
        .iter()
        .any(|argument| argument == &expected_global_config)
    {
        return Err(LocalMcpAdapterError::StageLayout);
    }
    reject_unsafe_npm_global_config(global_config)?;
    reject_ambient_npm_markers(command.working_directory())?;
    if let Some(prefix) = npm_prefix(command) {
        reject_ambient_npm_markers_at_prefix(prefix)?;
    }
    Ok(())
}

fn reject_unsafe_npm_global_config(path: &Path) -> Result<(), LocalMcpAdapterError> {
    validate_npm_existing_parent_ancestry(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.len() == 0
                && npm_path_metadata_is_trusted(&metadata) =>
        {
            Ok(())
        }
        Ok(_) => Err(LocalMcpAdapterError::StageLayout),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LocalMcpAdapterError::StageIo),
    }
}

fn reject_ambient_npm_markers(path: &str) -> Result<(), LocalMcpAdapterError> {
    reject_ambient_npm_markers_from(Path::new(path), false)
}

fn reject_ambient_npm_markers_at_prefix(path: &str) -> Result<(), LocalMcpAdapterError> {
    reject_ambient_npm_markers_from(Path::new(path), true)
}

fn reject_ambient_npm_markers_from(
    path: &Path,
    allow_generated_prefix_markers: bool,
) -> Result<(), LocalMcpAdapterError> {
    validate_npm_directory_ancestry(path)?;
    let prefix = path;
    let mut ancestor = Some(path);
    while let Some(path) = ancestor {
        for marker in [
            ".npmrc",
            "package.json",
            "package-lock.json",
            "node_modules",
        ] {
            let is_generated_prefix_marker =
                allow_generated_prefix_markers && path == prefix && marker != ".npmrc";
            if is_generated_prefix_marker {
                let expected_file = marker != "node_modules";
                match std::fs::symlink_metadata(path.join(marker)) {
                    Ok(metadata)
                        if (expected_file && metadata.file_type().is_file())
                            || (!expected_file && metadata.file_type().is_dir()) => {}
                    Ok(_) => return Err(LocalMcpAdapterError::StageLayout),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(LocalMcpAdapterError::StageIo),
                }
                continue;
            }
            match std::fs::symlink_metadata(path.join(marker)) {
                Ok(_) => return Err(LocalMcpAdapterError::StageLayout),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(LocalMcpAdapterError::StageIo),
            }
        }
        ancestor = path.parent();
    }
    Ok(())
}

fn validate_npm_existing_parent_ancestry(path: &Path) -> Result<(), LocalMcpAdapterError> {
    if !is_absolute_normalized_npm_path(path) {
        return Err(LocalMcpAdapterError::StageLayout);
    }
    let mut current = path.parent();
    while let Some(candidate) = current {
        match std::fs::symlink_metadata(candidate) {
            Ok(_) => return validate_npm_directory_ancestry(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                current = candidate.parent();
            }
            Err(_) => return Err(LocalMcpAdapterError::StageIo),
        }
    }
    Err(LocalMcpAdapterError::StageLayout)
}

fn validate_npm_directory_ancestry(path: &Path) -> Result<(), LocalMcpAdapterError> {
    if !is_absolute_normalized_npm_path(path) {
        return Err(LocalMcpAdapterError::StageLayout);
    }
    let mut current = Some(path);
    while let Some(candidate) = current {
        let metadata = match std::fs::symlink_metadata(candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(LocalMcpAdapterError::StageLayout);
            }
            Err(_) => return Err(LocalMcpAdapterError::StageIo),
        };
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_dir()
            || !npm_path_metadata_is_trusted(&metadata)
        {
            return Err(LocalMcpAdapterError::StageLayout);
        }
        if candidate == Path::new("/") {
            return Ok(());
        }
        current = candidate.parent();
    }
    Err(LocalMcpAdapterError::StageLayout)
}

fn is_absolute_normalized_npm_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

#[cfg(unix)]
fn npm_path_metadata_is_trusted(metadata: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    let effective_uid = rustix::process::geteuid().as_raw();
    (metadata.uid() == 0 || metadata.uid() == effective_uid)
        && metadata.mode() & 0o022 == 0
        && metadata.mode() & 0o7000 == 0
}

#[cfg(not(unix))]
const fn npm_path_metadata_is_trusted(_metadata: &Metadata) -> bool {
    false
}

fn npm_prefix(command: &FixedCommandSpec) -> Option<&str> {
    command
        .args()
        .windows(2)
        .find(|window| window[0] == "--prefix")
        .map(|window| window[1].as_str())
}

pub fn stage_exact_local_mcp(
    version: &str,
) -> Result<LocalMcpVerificationReceipt, LocalMcpAdapterError> {
    #[cfg(unix)]
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(LocalMcpAdapterError::StageMismatch("owner_required"));
    }
    #[cfg(not(unix))]
    return Err(LocalMcpAdapterError::StageLayout);

    let mut command_runner = FixedNpmCommandRunner;
    let mut stage_io = FixedFilesystemLocalMcpStageIo;
    stage_exact_local_mcp_with(version, &mut command_runner, &mut stage_io)
}

pub fn stage_exact_local_mcp_with<R, I>(
    version: &str,
    command_runner: &mut R,
    stage_io: &mut I,
) -> Result<LocalMcpVerificationReceipt, LocalMcpAdapterError>
where
    R: LocalMcpCommandRunner,
    I: LocalMcpStageIo,
{
    let plan = local_mcp_stage_plan(version)?;
    let metadata_output = command_runner.run(&npm_exact_metadata_plan(version)?)?;
    let value: Value = serde_json::from_slice(&metadata_output)
        .map_err(|_| LocalMcpAdapterError::InvalidMetadata("metadata_json_invalid"))?;
    let root_value = select_registry_view_value(PACKAGE_NAME, version, &value)?;
    let metadata = parse_registry_metadata(&root_value)?;
    validate_registry_metadata(&metadata)?;
    // Resolve every dependency range to one concrete registry metadata record
    // before creating the stage. This is deterministic (highest matching
    // semver, then integrity/tarball tie-breakers), and rejects source or
    // graph features npm could otherwise fetch or reinterpret during install.
    let closure = resolve_registry_dependency_closure(command_runner, &root_value, &metadata)?;
    stage_io.create_empty_stage(&plan)?;
    let cleanup =
        |stage_io: &mut I, error: LocalMcpAdapterError| match stage_io.discard_stage(&plan) {
            Ok(()) => error,
            Err(cleanup_error) => cleanup_error,
        };
    // Pack each selected exact package into the stage-owned cache, verify its
    // bytes against the selected registry SRI, and only then add it to the
    // same isolated npm cache used by the offline install.
    for package in &closure.packages {
        if let Err(error) = stage_io.prepare_registry_artifact_destination(
            &plan,
            &package.package_name,
            &package.version,
        ) {
            return Err(cleanup(stage_io, error));
        }
        let pack = npm_registry_pack_plan(
            &plan,
            &package.package_name,
            &package.version,
            &package.registry_tarball_url,
        )?;
        if let Err(error) = command_runner.run(&pack) {
            return Err(cleanup(stage_io, error));
        }
        let artifact = match stage_io.materialize_packed_artifact_for(
            &plan,
            &package.package_name,
            &package.version,
        ) {
            Ok(artifact) => artifact,
            Err(error) => return Err(cleanup(stage_io, error)),
        };
        let artifact_metadata = LocalMcpRegistryMetadata {
            version: package.version.clone(),
            integrity: package.integrity.clone(),
            registry_tarball_url: package.registry_tarball_url.clone(),
            engine_requirement: package.engine_requirement.clone().unwrap_or_default(),
            dependencies: package.dependencies.clone(),
            lifecycle_scripts_digest: package.lifecycle_scripts_digest.clone(),
            metadata_digest: metadata.metadata_digest.clone(),
        };
        if let Err(error) = verify_artifact_bytes(&artifact, &artifact_metadata) {
            let adapter_error = match error {
                LocalMcpExecutorError::Adapter(error) => error,
                _ => LocalMcpAdapterError::StageMismatch("registry_integrity_mismatch"),
            };
            return Err(cleanup(stage_io, adapter_error));
        }
        let manifest = artifact.manifest.as_ref().ok_or_else(|| {
            cleanup(
                stage_io,
                LocalMcpAdapterError::StageMismatch("registry_manifest_missing"),
            )
        })?;
        if let Err(error) = validate_selected_registry_manifest(manifest, package) {
            return Err(cleanup(stage_io, error));
        }
        let cache_add =
            npm_registry_cache_add_plan(&plan, &package.package_name, &package.version)?;
        if let Err(error) = command_runner.run(&cache_add) {
            return Err(cleanup(stage_io, error));
        }
    }
    let Some(root_package) = closure.packages.iter().find(|package| {
        package.package_name == PACKAGE_NAME && package.version == metadata.version
    }) else {
        return Err(cleanup(
            stage_io,
            LocalMcpAdapterError::StageMismatch("registry_dependency_closure_invalid"),
        ));
    };
    let project_manifest = build_frozen_install_project_manifest(root_package);
    let frozen_lock = match build_frozen_install_lock(root_package, &closure) {
        Ok(lock) => lock,
        Err(error) => return Err(cleanup(stage_io, error)),
    };
    if let Err(error) =
        stage_io.materialize_frozen_install_inputs(&plan, &project_manifest, &frozen_lock)
    {
        return Err(cleanup(stage_io, error));
    }
    if let Err(error) = stage_io.preflight_archive(&plan) {
        return Err(cleanup(stage_io, error));
    }
    if let Err(error) = command_runner.run(plan.install()) {
        return Err(cleanup(stage_io, error));
    }
    let verified = match stage_io.reverify_with_closure(&plan, &metadata, &closure, Vec::new()) {
        Ok(verified) => verified,
        Err(error) => return Err(cleanup(stage_io, error)),
    };
    if verified.stage_id != plan.stage_id
        || verified.snapshot().component != UpdateComponent::LocalN8nMcp
        || verified.snapshot().version != metadata.version
        || verified.snapshot().provenance.source_kind != "npm_staged_artifact"
    {
        return Err(cleanup(
            stage_io,
            LocalMcpAdapterError::StageMismatch("verified_stage_mismatch"),
        ));
    }
    let receipt = LocalMcpVerificationReceipt {
        schema: "fwc.n8n.local-mcp-verification-receipt.v1".to_string(),
        status: "verified".to_string(),
        component: UpdateComponent::LocalN8nMcp,
        version: metadata.version,
        stage_id: verified.stage_id.clone(),
        stage_root: plan.stage_root().to_string(),
        receipt_path: plan.verification_receipt_path(),
        metadata_digest: metadata.metadata_digest,
        registry_integrity: metadata.integrity,
        registry_tarball_url: metadata.registry_tarball_url,
        registry_closure_digest: closure.digest,
        registry_closure_packages: closure
            .packages
            .iter()
            .map(RegistryPackageMetadata::closure_package)
            .collect(),
        registry_closure_edges: closure.edges.clone(),
        artifact_binding_digest: verified.snapshot().provenance.artifact_digest.clone(),
        stage_tree_digest: verified.stage_tree_digest.clone(),
        package_manifest_digest: verified.package_manifest_digest.clone(),
        package_lock_digest: verified.package_lock_digest.clone(),
        entrypoint: verified.entrypoint.clone(),
        entry_count: verified.entry_count,
        total_bytes: verified.total_bytes,
    };
    if let Err(error) = stage_io.persist_verification_receipt(&plan, &receipt) {
        return Err(cleanup(stage_io, error));
    }
    Ok(receipt)
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
    verify_local_mcp_stage_for_owner_with_closure(plan, metadata, None, tools, expected_owner)
}

#[cfg(target_os = "linux")]
fn verify_local_mcp_stage_for_owner_with_closure(
    plan: &LocalMcpStagePlan,
    metadata: &LocalMcpRegistryMetadata,
    expected_closure: Option<&RegistryClosure>,
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

    let project_package_json_path = stage_root.join(STAGE_PROJECT_PACKAGE_JSON);
    let package_json_path = Path::new(&plan.package_json_path);
    let package_lock_path = Path::new(&plan.package_lock_path);
    let project_package_json = read_bounded_stage_json(
        &stage_fd,
        &project_package_json_path,
        stage_root,
        expected_owner,
        MAX_STAGE_JSON_BYTES,
        tree.file_evidence(&project_package_json_path, stage_root)?,
    )?;
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
    validate_stage_project_manifest(&project_package_json, plan.exact_version())?;
    validate_installed_package_manifest(&package_json, metadata, plan.exact_version())?;
    validate_installed_package_lock_with_closure(
        &package_lock,
        metadata,
        plan.exact_version(),
        &tree,
        expected_closure,
    )?;

    let package_manifest_digest = canonical_digest(&package_json)?;
    let package_lock_digest = canonical_digest(&package_lock)?;
    let package_root = package_json_path
        .parent()
        .ok_or(LocalMcpAdapterError::StageLayout)?;
    let entrypoint_relative = package_bin_relative_path(&package_json)?;
    let bin_path = package_root.join(&entrypoint_relative);
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
        entrypoint: entrypoint_relative.to_string_lossy().into_owned(),
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

fn validate_stage_project_manifest(
    value: &Value,
    exact_version: &str,
) -> Result<(), LocalMcpAdapterError> {
    let object = value
        .as_object()
        .ok_or(LocalMcpAdapterError::StageMismatch(
            "project_manifest_invalid",
        ))?;
    let dependencies = parse_dependencies(object.get("dependencies")).map_err(|_| {
        LocalMcpAdapterError::StageMismatch("project_manifest_dependencies_invalid")
    })?;
    let expected = BTreeMap::from([(PACKAGE_NAME.to_string(), exact_version.to_string())]);
    if object.get("name").and_then(Value::as_str) != Some(LOCK_PROJECT_NAME)
        || object.get("version").and_then(Value::as_str) != Some(LOCK_PROJECT_VERSION)
        || object.get("private").and_then(Value::as_bool) != Some(true)
        || dependencies != expected
        || object
            .get("devDependencies")
            .is_some_and(|value| !value.is_null())
        || object
            .get("optionalDependencies")
            .is_some_and(|value| !value.is_null())
        || object
            .get("peerDependencies")
            .is_some_and(|value| !value.is_null())
    {
        return Err(LocalMcpAdapterError::StageMismatch(
            "project_manifest_mismatch",
        ));
    }
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
    tree: &StageTreeDigest,
) -> Result<(), LocalMcpAdapterError> {
    validate_installed_package_lock_with_closure(value, metadata, exact_version, tree, None)
}

fn validate_installed_package_lock_with_closure(
    value: &Value,
    metadata: &LocalMcpRegistryMetadata,
    exact_version: &str,
    tree: &StageTreeDigest,
    expected_closure: Option<&RegistryClosure>,
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
    let packages = object
        .get("packages")
        .and_then(Value::as_object)
        .ok_or(LocalMcpAdapterError::StageMismatch("lock_packages_invalid"))?;
    let package = packages
        .get("node_modules/n8n-mcp")
        .and_then(Value::as_object)
        .ok_or(LocalMcpAdapterError::StageMismatch("lock_package_missing"))?;
    let root = packages
        .get("")
        .and_then(Value::as_object)
        .ok_or(LocalMcpAdapterError::StageMismatch("lock_root_missing"))?;
    let root_dependencies = parse_lock_dependencies(root.get("dependencies"))?;
    if root_dependencies != BTreeMap::from([(PACKAGE_NAME.to_string(), exact_version.to_string())])
        || root.get("name").and_then(Value::as_str) != Some(LOCK_PROJECT_NAME)
        || root.get("version").and_then(Value::as_str) != Some(LOCK_PROJECT_VERSION)
        || root.get("private").and_then(Value::as_bool) != Some(true)
        || root
            .get("devDependencies")
            .is_some_and(|dependencies| !dependencies.is_null())
        || root
            .get("optionalDependencies")
            .is_some_and(|dependencies| !dependencies.is_null())
    {
        return Err(LocalMcpAdapterError::StageMismatch("lock_root_mismatch"));
    }
    if package.get("version").and_then(Value::as_str) != Some(exact_version)
        || package.get("integrity").and_then(Value::as_str) != Some(metadata.integrity.as_str())
        || package.get("resolved").and_then(Value::as_str)
            != Some(metadata.registry_tarball_url.as_str())
        || parse_lock_dependencies(package.get("dependencies"))? != metadata.dependencies
    {
        return Err(LocalMcpAdapterError::StageMismatch("lock_package_mismatch"));
    }

    let mut lock_package_keys = BTreeSet::new();
    for (key, record) in packages {
        if key.is_empty() {
            continue;
        }
        let package_name = validate_lock_package_key(key)?;
        validate_lock_package_record(key, &package_name, record)?;
        if let Some(closure) = expected_closure {
            let record = record
                .as_object()
                .ok_or(LocalMcpAdapterError::StageMismatch("lock_record_malformed"))?;
            let version = record
                .get("version")
                .and_then(Value::as_str)
                .ok_or(LocalMcpAdapterError::StageMismatch("lock_record_malformed"))?;
            let integrity = record.get("integrity").and_then(Value::as_str).ok_or(
                LocalMcpAdapterError::StageMismatch("lock_record_integrity_missing"),
            )?;
            let resolved = record.get("resolved").and_then(Value::as_str).ok_or(
                LocalMcpAdapterError::StageMismatch("lock_record_non_registry"),
            )?;
            let selected =
                closure_package_for_identity(closure, &package_name, version, integrity, resolved)
                    .ok_or(LocalMcpAdapterError::StageMismatch(
                        "lock_registry_closure_mismatch",
                    ))?;
            validate_lock_record_against_selected(record, selected)?;
        }
        lock_package_keys.insert(key.clone());
    }
    let installed_package_keys = installed_lock_package_keys(tree);
    if !installed_package_keys.is_subset(&lock_package_keys) {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_dependency_closure_mismatch",
        ));
    }
    let missing_package_keys = lock_package_keys
        .difference(&installed_package_keys)
        .cloned()
        .collect::<BTreeSet<_>>();
    if expected_closure.is_none() && !missing_package_keys.is_empty() {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_dependency_closure_mismatch",
        ));
    }
    if let Some(closure) = expected_closure {
        for package_key in missing_package_keys {
            let record = packages
                .get(&package_key)
                .and_then(Value::as_object)
                .ok_or(LocalMcpAdapterError::StageMismatch(
                    "lock_dependency_missing",
                ))?;
            let package_name = validate_lock_package_key(&package_key)?;
            let version = record
                .get("version")
                .and_then(Value::as_str)
                .ok_or(LocalMcpAdapterError::StageMismatch("lock_record_malformed"))?;
            let target = closure
                .packages
                .iter()
                .find(|package| package.package_name == package_name && package.version == version)
                .ok_or(LocalMcpAdapterError::StageMismatch(
                    "lock_registry_closure_mismatch",
                ))?;
            let incoming = closure.edges.iter().filter(|edge| {
                edge.dependency_name == target.package_name
                    && edge.target_version == target.version
                    && edge.target_integrity == target.integrity
                    && edge.target_registry_tarball_url == target.registry_tarball_url
            });
            if incoming
                .into_iter()
                .any(|edge| !optional_edge_omission_is_allowed(edge, target))
            {
                return Err(LocalMcpAdapterError::StageMismatch(
                    "lock_dependency_missing",
                ));
            }
        }
    }

    let mut reachable = BTreeSet::new();
    let mut pending = vec!["node_modules/n8n-mcp".to_string()];
    while let Some(package_key) = pending.pop() {
        if !reachable.insert(package_key.clone()) {
            continue;
        }
        let record = packages
            .get(&package_key)
            .and_then(Value::as_object)
            .ok_or(LocalMcpAdapterError::StageMismatch(
                "lock_dependency_missing",
            ))?;
        if let Some(closure) = expected_closure {
            let source_name = validate_lock_package_key(&package_key)?;
            let source_version = record
                .get("version")
                .and_then(Value::as_str)
                .ok_or(LocalMcpAdapterError::StageMismatch("lock_record_malformed"))?;
            let source = closure
                .packages
                .iter()
                .find(|selected| {
                    selected.package_name == source_name && selected.version == source_version
                })
                .ok_or(LocalMcpAdapterError::StageMismatch(
                    "lock_registry_closure_mismatch",
                ))?;
            for edge in closure.edges.iter().filter(|edge| {
                edge.source_package_name == source.package_name
                    && edge.source_version == source.version
            }) {
                let (_, target) = closure_package_for_edge(
                    closure,
                    &edge.source_package_name,
                    &edge.source_version,
                    &edge.dependency_name,
                    &edge.dependency_kind,
                )
                .ok_or(LocalMcpAdapterError::StageMismatch(
                    "registry_dependency_closure_invalid",
                ))?;
                let Some(dependency_key) =
                    resolve_lock_dependency_key(&package_key, &edge.dependency_name, packages)
                else {
                    if optional_edge_omission_is_allowed(edge, target) {
                        continue;
                    }
                    return Err(LocalMcpAdapterError::StageMismatch(
                        "lock_dependency_missing",
                    ));
                };
                let dependency_record = packages
                    .get(&dependency_key)
                    .and_then(Value::as_object)
                    .ok_or(LocalMcpAdapterError::StageMismatch(
                        "lock_dependency_missing",
                    ))?;
                let dependency_version =
                    dependency_record
                        .get("version")
                        .and_then(Value::as_str)
                        .ok_or(LocalMcpAdapterError::StageMismatch("lock_record_malformed"))?;
                let dependency_integrity = dependency_record
                    .get("integrity")
                    .and_then(Value::as_str)
                    .ok_or(LocalMcpAdapterError::StageMismatch(
                        "lock_record_integrity_missing",
                    ))?;
                let dependency_resolved = dependency_record
                    .get("resolved")
                    .and_then(Value::as_str)
                    .ok_or(LocalMcpAdapterError::StageMismatch(
                        "lock_record_non_registry",
                    ))?;
                if dependency_version != target.version
                    || dependency_integrity != target.integrity
                    || dependency_resolved != target.registry_tarball_url
                {
                    return Err(LocalMcpAdapterError::StageMismatch(
                        "lock_dependency_selection_mismatch",
                    ));
                }
                pending.push(dependency_key);
            }
        } else {
            for (dependency_name, dependency_spec) in lock_record_dependencies(record)? {
                let dependency_key =
                    resolve_lock_dependency_key(&package_key, &dependency_name, packages).ok_or(
                        LocalMcpAdapterError::StageMismatch("lock_dependency_missing"),
                    )?;
                let dependency_record = packages
                    .get(&dependency_key)
                    .and_then(Value::as_object)
                    .ok_or(LocalMcpAdapterError::StageMismatch(
                        "lock_dependency_missing",
                    ))?;
                let dependency_version =
                    dependency_record
                        .get("version")
                        .and_then(Value::as_str)
                        .ok_or(LocalMcpAdapterError::StageMismatch("lock_record_malformed"))?;
                if !dependency_spec_allows_version(&dependency_spec, dependency_version) {
                    return Err(LocalMcpAdapterError::StageMismatch(
                        "lock_dependency_version_mismatch",
                    ));
                }
                pending.push(dependency_key);
            }
        }
    }
    if reachable != lock_package_keys {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_dependency_closure_mismatch",
        ));
    }
    Ok(())
}

fn validate_lock_record_against_selected(
    record: &serde_json::Map<String, Value>,
    selected: &RegistryPackageMetadata,
) -> Result<(), LocalMcpAdapterError> {
    if record
        .get("name")
        .is_some_and(|name| name.as_str() != Some(selected.package_name.as_str()))
        || parse_lock_dependencies(record.get("dependencies"))? != selected.dependencies
        || parse_lock_dependencies(record.get("optionalDependencies"))?
            != selected.optional_dependencies
        || parse_lock_dependencies(record.get("peerDependencies"))? != selected.peer_dependencies
    {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_manifest_dependency_mismatch",
        ));
    }
    let peer_meta = parse_lock_peer_dependencies_meta(
        record.get("peerDependenciesMeta"),
        &selected.peer_dependencies,
    )?;
    let os = parse_lock_platform_constraints(record.get("os"))?;
    let cpu = parse_lock_platform_constraints(record.get("cpu"))?;
    if peer_meta != selected.peer_dependencies_meta {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_manifest_dependency_mismatch",
        ));
    }
    if os != selected.os || cpu != selected.cpu {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_manifest_platform_mismatch",
        ));
    }
    Ok(())
}

fn validate_lock_package_key(key: &str) -> Result<String, LocalMcpAdapterError> {
    if key.is_empty() || key.len() > 4096 || !key.is_ascii() || key.contains('\\') {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_package_key_invalid",
        ));
    }
    let parts: Vec<_> = key.split('/').collect();
    if parts
        .iter()
        .any(|part| part.is_empty() || matches!(*part, "." | ".."))
    {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_package_key_invalid",
        ));
    }
    let mut index = 0;
    let mut package_name = None;
    while index < parts.len() {
        if parts[index] != "node_modules" {
            return Err(LocalMcpAdapterError::StageMismatch(
                "lock_package_key_invalid",
            ));
        }
        index += 1;
        let name_start = index;
        if parts.get(index).is_some_and(|part| part.starts_with('@')) {
            index = index.saturating_add(2);
        } else {
            index = index.saturating_add(1);
        }
        if index > parts.len() {
            return Err(LocalMcpAdapterError::StageMismatch(
                "lock_package_key_invalid",
            ));
        }
        let name = parts[name_start..index].join("/");
        validate_package_name(&name)
            .map_err(|_| LocalMcpAdapterError::StageMismatch("lock_package_name_invalid"))?;
        package_name = Some(name);
        if index < parts.len() && parts[index] != "node_modules" {
            return Err(LocalMcpAdapterError::StageMismatch(
                "lock_package_key_invalid",
            ));
        }
    }
    package_name.ok_or(LocalMcpAdapterError::StageMismatch(
        "lock_package_key_invalid",
    ))
}

fn validate_lock_package_record(
    _key: &str,
    package_name: &str,
    value: &Value,
) -> Result<(), LocalMcpAdapterError> {
    let record = value
        .as_object()
        .ok_or(LocalMcpAdapterError::StageMismatch("lock_record_malformed"))?;
    if record.get("link").is_some_and(|link| !link.is_null())
        || record
            .get("bundledDependencies")
            .is_some_and(|dependencies| !dependencies.is_null())
        || record
            .get("bundleDependencies")
            .is_some_and(|dependencies| !dependencies.is_null())
    {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_record_non_registry",
        ));
    }
    if record
        .get("name")
        .is_some_and(|name| name.as_str() != Some(package_name))
        || record
            .get("version")
            .and_then(Value::as_str)
            .is_none_or(|version| validate_exact_npm_version(version).is_err())
    {
        return Err(LocalMcpAdapterError::StageMismatch("lock_record_malformed"));
    }
    let version = record
        .get("version")
        .and_then(Value::as_str)
        .ok_or(LocalMcpAdapterError::StageMismatch("lock_record_malformed"))?;
    let resolved = record.get("resolved").and_then(Value::as_str).ok_or(
        LocalMcpAdapterError::StageMismatch("lock_record_non_registry"),
    )?;
    validate_registry_package_tarball_url(resolved, package_name, version)?;
    let integrity = record.get("integrity").and_then(Value::as_str).ok_or(
        LocalMcpAdapterError::StageMismatch("lock_record_integrity_missing"),
    )?;
    if !valid_integrity(integrity) {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_record_integrity_invalid",
        ));
    }
    for field in [
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "requires",
    ] {
        parse_lock_dependencies(record.get(field))?;
    }
    if record
        .get("peerDependenciesMeta")
        .is_some_and(|meta| !meta.is_object())
    {
        return Err(LocalMcpAdapterError::StageMismatch("lock_record_malformed"));
    }
    for field in ["dev", "devOptional", "optional", "peer", "hasInstallScript"] {
        if record.get(field).is_some_and(|flag| !flag.is_boolean()) {
            return Err(LocalMcpAdapterError::StageMismatch("lock_record_malformed"));
        }
    }
    Ok(())
}

fn installed_lock_package_keys(tree: &StageTreeDigest) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    for directory in &tree.directories {
        let parts: Vec<_> = directory.split('/').collect();
        for (index, part) in parts.iter().enumerate() {
            if *part != "node_modules" || index + 1 >= parts.len() {
                continue;
            }
            let package_end = if parts[index + 1].starts_with('@') {
                index + 3
            } else {
                index + 2
            };
            if package_end <= parts.len() {
                keys.insert(parts[..package_end].join("/"));
            }
        }
    }
    keys
}

fn parse_lock_dependencies(
    value: Option<&Value>,
) -> Result<BTreeMap<String, String>, LocalMcpAdapterError> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or(LocalMcpAdapterError::StageMismatch(
            "lock_dependencies_invalid",
        ))?;
    if object.len() > 512 {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_dependencies_oversized",
        ));
    }
    object
        .iter()
        .map(|(name, value)| {
            validate_package_name(name)
                .map_err(|_| LocalMcpAdapterError::StageMismatch("lock_dependency_name_invalid"))?;
            let spec = value.as_str().ok_or(LocalMcpAdapterError::StageMismatch(
                "lock_dependency_spec_invalid",
            ))?;
            validate_registry_dependency_spec(spec)
                .map_err(|_| LocalMcpAdapterError::StageMismatch("lock_dependency_non_registry"))?;
            Ok((name.clone(), spec.to_string()))
        })
        .collect()
}

fn parse_lock_peer_dependencies_meta(
    value: Option<&Value>,
    peers: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, bool>, LocalMcpAdapterError> {
    parse_peer_dependencies_meta(value, peers).map_err(|error| match error {
        LocalMcpAdapterError::InvalidMetadata(_) => {
            LocalMcpAdapterError::StageMismatch("lock_peer_dependencies_meta_invalid")
        }
        other => other,
    })
}

fn parse_lock_platform_constraints(
    value: Option<&Value>,
) -> Result<Vec<String>, LocalMcpAdapterError> {
    parse_platform_constraints(value).map_err(|error| match error {
        LocalMcpAdapterError::InvalidMetadata(_) => {
            LocalMcpAdapterError::StageMismatch("lock_platform_constraints_invalid")
        }
        other => other,
    })
}

fn lock_record_dependencies(
    record: &serde_json::Map<String, Value>,
) -> Result<BTreeMap<String, String>, LocalMcpAdapterError> {
    let mut dependencies = BTreeMap::new();
    for field in [
        "dependencies",
        "optionalDependencies",
        "peerDependencies",
        "requires",
    ] {
        for (name, spec) in parse_lock_dependencies(record.get(field))? {
            if dependencies.insert(name, spec).is_some() {
                return Err(LocalMcpAdapterError::StageMismatch(
                    "lock_dependency_duplicate",
                ));
            }
        }
    }
    Ok(dependencies)
}

fn resolve_lock_dependency_key(
    package_key: &str,
    dependency_name: &str,
    packages: &serde_json::Map<String, Value>,
) -> Option<String> {
    let mut base = package_key;
    loop {
        let candidate = format!("{base}/node_modules/{dependency_name}");
        if packages.contains_key(&candidate) {
            return Some(candidate);
        }
        base = base
            .rsplit_once("/node_modules/")
            .map_or("", |(parent, _)| parent);
        if base.is_empty() {
            let candidate = format!("node_modules/{dependency_name}");
            return packages.contains_key(&candidate).then_some(candidate);
        }
    }
}

fn closure_package_for_edge<'a>(
    closure: &'a RegistryClosure,
    source_package_name: &str,
    source_version: &str,
    dependency_name: &str,
    dependency_kind: &str,
) -> Option<(&'a RegistryClosureEdge, &'a RegistryPackageMetadata)> {
    let edge = closure.edges.iter().find(|edge| {
        edge.source_package_name == source_package_name
            && edge.source_version == source_version
            && edge.dependency_name == dependency_name
            && edge.dependency_kind == dependency_kind
    })?;
    let package = closure.packages.iter().find(|package| {
        package.package_name == dependency_name
            && package.version == edge.target_version
            && package.integrity == edge.target_integrity
            && package.registry_tarball_url == edge.target_registry_tarball_url
    })?;
    Some((edge, package))
}

fn closure_package_for_identity<'a>(
    closure: &'a RegistryClosure,
    package_name: &str,
    version: &str,
    integrity: &str,
    resolved: &str,
) -> Option<&'a RegistryPackageMetadata> {
    closure.packages.iter().find(|package| {
        package.package_name == package_name
            && package.version == version
            && package.integrity == integrity
            && package.registry_tarball_url == resolved
    })
}

fn package_parent_path(path: &str) -> Option<&str> {
    path.rsplit_once("/node_modules/").map(|(parent, _)| parent)
}

fn registry_lock_peer_meta(package: &RegistryPackageMetadata) -> Value {
    let meta = package
        .peer_dependencies_meta
        .iter()
        .map(|(name, optional)| (name.clone(), json!({"optional": optional})))
        .collect::<serde_json::Map<_, _>>();
    Value::Object(meta)
}

fn registry_lock_package_record(package: &RegistryPackageMetadata) -> Value {
    let mut record = serde_json::Map::from_iter([
        (
            "name".to_string(),
            Value::String(package.package_name.clone()),
        ),
        (
            "version".to_string(),
            Value::String(package.version.clone()),
        ),
        (
            "resolved".to_string(),
            Value::String(package.registry_tarball_url.clone()),
        ),
        (
            "integrity".to_string(),
            Value::String(package.integrity.clone()),
        ),
        (
            "dependencies".to_string(),
            serde_json::to_value(&package.dependencies).unwrap_or_else(|_| json!({})),
        ),
        (
            "optionalDependencies".to_string(),
            serde_json::to_value(&package.optional_dependencies).unwrap_or_else(|_| json!({})),
        ),
        (
            "peerDependencies".to_string(),
            serde_json::to_value(&package.peer_dependencies).unwrap_or_else(|_| json!({})),
        ),
        (
            "peerDependenciesMeta".to_string(),
            registry_lock_peer_meta(package),
        ),
    ]);
    if let Some(engine_requirement) = &package.engine_requirement {
        record.insert("engines".to_string(), json!({"node": engine_requirement}));
    }
    if !package.os.is_empty() {
        record.insert("os".to_string(), json!(package.os));
    }
    if !package.cpu.is_empty() {
        record.insert("cpu".to_string(), json!(package.cpu));
    }
    Value::Object(record)
}

fn frozen_lock_dependency_path(
    records: &serde_json::Map<String, Value>,
    source_path: &str,
    dependency_name: &str,
    target: &RegistryPackageMetadata,
) -> Result<String, LocalMcpAdapterError> {
    let mut base = Some(source_path);
    while let Some(path) = base {
        let candidate = format!("{path}/node_modules/{dependency_name}");
        if let Some(record) = records.get(&candidate) {
            let version = record.get("version").and_then(Value::as_str).ok_or(
                LocalMcpAdapterError::StageMismatch("registry_lock_placement_invalid"),
            )?;
            if version == target.version {
                return Ok(candidate);
            }
            return Err(LocalMcpAdapterError::StageMismatch(
                "registry_lock_placement_conflict",
            ));
        }
        base = package_parent_path(path);
    }
    let candidate = format!("node_modules/{dependency_name}");
    if let Some(record) = records.get(&candidate) {
        let version = record.get("version").and_then(Value::as_str).ok_or(
            LocalMcpAdapterError::StageMismatch("registry_lock_placement_invalid"),
        )?;
        if version == target.version {
            return Ok(candidate);
        }
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_lock_placement_conflict",
        ));
    }
    Ok(candidate)
}

fn build_frozen_install_lock(
    root: &RegistryPackageMetadata,
    closure: &RegistryClosure,
) -> Result<Value, LocalMcpAdapterError> {
    let root_path = format!("node_modules/{PACKAGE_NAME}");
    let mut records =
        serde_json::Map::from_iter([(root_path.clone(), registry_lock_package_record(root))]);
    let mut pending = vec![(root_path, root.clone())];
    let mut expanded = BTreeSet::new();
    while let Some((source_path, source)) = pending.pop() {
        if !expanded.insert(source_path.clone()) {
            continue;
        }
        for edge in closure.edges.iter().filter(|edge| {
            edge.source_package_name == source.package_name && edge.source_version == source.version
        }) {
            let target = closure
                .packages
                .iter()
                .find(|package| {
                    package.package_name == edge.dependency_name
                        && package.version == edge.target_version
                        && package.integrity == edge.target_integrity
                        && package.registry_tarball_url == edge.target_registry_tarball_url
                })
                .ok_or(LocalMcpAdapterError::StageMismatch(
                    "registry_dependency_closure_invalid",
                ))?;
            let target_path =
                frozen_lock_dependency_path(&records, &source_path, &edge.dependency_name, target)?;
            if !records.contains_key(&target_path) {
                records.insert(target_path.clone(), registry_lock_package_record(target));
                pending.push((target_path, target.clone()));
            }
        }
    }
    let root_dependencies = BTreeMap::from([(PACKAGE_NAME.to_string(), root.version.clone())]);
    let root_record = json!({
        "name": LOCK_PROJECT_NAME,
        "version": LOCK_PROJECT_VERSION,
        "private": true,
        "dependencies": root_dependencies,
    });
    let mut package_records = serde_json::Map::from_iter([(String::new(), root_record)]);
    package_records.extend(records);
    Ok(json!({
        "name": LOCK_PROJECT_NAME,
        "version": LOCK_PROJECT_VERSION,
        "lockfileVersion": 3,
        "requires": true,
        "packages": package_records,
    }))
}

fn build_frozen_install_project_manifest(root: &RegistryPackageMetadata) -> Value {
    let dependencies = BTreeMap::from([(PACKAGE_NAME.to_string(), root.version.clone())]);
    json!({
        "name": LOCK_PROJECT_NAME,
        "version": LOCK_PROJECT_VERSION,
        "private": true,
        "dependencies": dependencies,
    })
}

const fn current_npm_os() -> &'static str {
    if cfg!(target_os = "windows") {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else if cfg!(target_os = "netbsd") {
        "netbsd"
    } else if cfg!(target_os = "solaris") {
        "sunos"
    } else {
        "linux"
    }
}

fn current_npm_cpu() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        "arm" => "arm",
        "powerpc64" => "ppc64",
        "s390x" => "s390x",
        other => other,
    }
}

fn platform_constraint_allows(values: &[String], current: &str) -> bool {
    if values.is_empty() {
        return true;
    }
    if values.iter().any(|value| value == &format!("!{current}")) {
        return false;
    }
    let positive = values.iter().filter(|value| !value.starts_with('!'));
    let has_positive = values.iter().any(|value| !value.starts_with('!'));
    !has_positive || positive.into_iter().any(|value| value == current)
}

fn package_platform_allows_current(package: &RegistryPackageMetadata) -> bool {
    platform_constraint_allows(&package.os, current_npm_os())
        && platform_constraint_allows(&package.cpu, current_npm_cpu())
}

fn optional_edge_omission_is_allowed(
    edge: &RegistryClosureEdge,
    target: &RegistryPackageMetadata,
) -> bool {
    edge.optional
        && (edge.dependency_kind == RegistryDependencyKind::Peer.as_str()
            || !package_platform_allows_current(target))
}

fn validate_registry_package_tarball_url(
    value: &str,
    package_name: &str,
    version: &str,
) -> Result<(), LocalMcpAdapterError> {
    let basename = package_name.rsplit('/').next().unwrap_or(package_name);
    let expected = format!("https://registry.npmjs.org/{package_name}/-/{basename}-{version}.tgz");
    if value.len() > 1024
        || !value.is_ascii()
        || value != expected
        || value.contains(['?', '#', '\\'])
        || value.chars().any(char::is_control)
    {
        return Err(LocalMcpAdapterError::StageMismatch(
            "lock_record_non_registry",
        ));
    }
    Ok(())
}

fn validate_registry_dependency_spec(value: &str) -> Result<(), LocalMcpAdapterError> {
    if value.is_empty()
        || value.len() > 256
        || !value.is_ascii()
        || value.trim() != value
        || value.chars().any(char::is_control)
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'.' | b'-'
                        | b'+'
                        | b'^'
                        | b'~'
                        | b'<'
                        | b'>'
                        | b'='
                        | b'*'
                        | b'x'
                        | b'X'
                        | b'|'
                        | b' '
                ))
        })
        || value.contains("..")
        || value.contains("|||")
        || parse_npm_range(value).is_none()
    {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "dependency_version_invalid",
        ));
    }
    if value
        .split("||")
        .any(|alternative| alternative.trim().is_empty())
    {
        return Err(LocalMcpAdapterError::InvalidMetadata(
            "dependency_version_invalid",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NpmPrereleaseIdentifier {
    Numeric(u64),
    Text(String),
}

impl Ord for NpmPrereleaseIdentifier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Self::Numeric(left), Self::Numeric(right)) => left.cmp(right),
            (Self::Numeric(_), Self::Text(_)) => std::cmp::Ordering::Less,
            (Self::Text(_), Self::Numeric(_)) => std::cmp::Ordering::Greater,
            (Self::Text(left), Self::Text(right)) => left.cmp(right),
        }
    }
}

impl PartialOrd for NpmPrereleaseIdentifier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NpmVersionParts {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Vec<NpmPrereleaseIdentifier>,
}

impl Ord for NpmVersionParts {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(
                || match (self.prerelease.is_empty(), other.prerelease.is_empty()) {
                    (true, true) => std::cmp::Ordering::Equal,
                    (true, false) => std::cmp::Ordering::Greater,
                    (false, true) => std::cmp::Ordering::Less,
                    (false, false) => self.prerelease.cmp(&other.prerelease),
                },
            )
    }
}

impl PartialOrd for NpmVersionParts {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NpmPartialVersion {
    major: Option<u64>,
    minor: Option<u64>,
    patch: Option<u64>,
    prerelease: Vec<NpmPrereleaseIdentifier>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NpmComparatorOperator {
    Equal,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NpmComparator {
    operator: NpmComparatorOperator,
    version: NpmVersionParts,
}

fn npm_version_parts(value: &str) -> Option<NpmVersionParts> {
    let parsed = parse_npm_partial_version(value)?;
    Some(NpmVersionParts {
        major: parsed.major?,
        minor: parsed.minor?,
        patch: parsed.patch?,
        prerelease: parsed.prerelease,
    })
}

fn parse_npm_partial_version(value: &str) -> Option<NpmPartialVersion> {
    if value.is_empty() || !value.is_ascii() || value.chars().any(char::is_whitespace) {
        return None;
    }
    let (without_build, build) = match value.split_once('+') {
        Some((core, build)) if !build.is_empty() && !build.contains('+') => (core, Some(build)),
        Some(_) => return None,
        None => (value, None),
    };
    if let Some(build) = build {
        if build.split('.').any(|part| {
            part.is_empty()
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }) {
            return None;
        }
    }
    let (core, prerelease) = match without_build.split_once('-') {
        Some((core, prerelease)) if !prerelease.is_empty() && !prerelease.contains('-') => {
            (core, Some(prerelease))
        }
        Some((core, prerelease)) if !prerelease.is_empty() => (core, Some(prerelease)),
        Some(_) => return None,
        None => (without_build, None),
    };
    let had_prerelease = prerelease.is_some();
    let prerelease = match prerelease {
        Some(value) => value
            .split('.')
            .map(|part| {
                if part.is_empty()
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                {
                    return None;
                }
                if part.bytes().all(|byte| byte.is_ascii_digit()) {
                    if part.len() > 1 && part.starts_with('0') {
                        return None;
                    }
                    Some(NpmPrereleaseIdentifier::Numeric(part.parse().ok()?))
                } else {
                    Some(NpmPrereleaseIdentifier::Text(part.to_string()))
                }
            })
            .collect::<Option<Vec<_>>>()?,
        None => Vec::new(),
    };
    let parts = core.split('.').collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let mut numbers = [None; 3];
    let mut wildcard_seen = false;
    for (index, part) in parts.iter().enumerate() {
        let wildcard = *part == "*" || part.eq_ignore_ascii_case("x");
        if wildcard {
            wildcard_seen = true;
            continue;
        }
        if wildcard_seen || part.is_empty() || part.bytes().any(|byte| !byte.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        numbers[index] = Some(part.parse().ok()?);
    }
    if had_prerelease && numbers.iter().any(Option::is_none) {
        return None;
    }
    Some(NpmPartialVersion {
        major: numbers[0],
        minor: numbers[1],
        patch: numbers[2],
        prerelease,
    })
}

fn npm_prerelease_upper(major: u64, minor: u64, patch: u64) -> NpmVersionParts {
    NpmVersionParts {
        major,
        minor,
        patch,
        prerelease: vec![NpmPrereleaseIdentifier::Numeric(0)],
    }
}

fn npm_partial_lower(partial: &NpmPartialVersion) -> NpmVersionParts {
    NpmVersionParts {
        major: partial.major.unwrap_or(0),
        minor: partial.minor.unwrap_or(0),
        patch: partial.patch.unwrap_or(0),
        prerelease: partial.prerelease.clone(),
    }
}

fn npm_partial_upper(partial: &NpmPartialVersion) -> Option<NpmVersionParts> {
    partial.major?;
    if partial.minor.is_none() {
        return Some(npm_prerelease_upper(partial.major?.saturating_add(1), 0, 0));
    }
    if partial.patch.is_none() {
        return Some(npm_prerelease_upper(
            partial.major?,
            partial.minor?.saturating_add(1),
            0,
        ));
    }
    None
}

fn npm_partial_greater_lower(partial: &NpmPartialVersion) -> Option<NpmVersionParts> {
    let mut lower = npm_partial_upper(partial)?;
    lower.prerelease.clear();
    Some(lower)
}

fn npm_caret_upper(partial: &NpmPartialVersion) -> NpmVersionParts {
    let major = partial.major.unwrap_or(0);
    let minor = partial.minor.unwrap_or(0);
    let patch = partial.patch.unwrap_or(0);
    if major > 0 {
        npm_prerelease_upper(major.saturating_add(1), 0, 0)
    } else if partial.minor.is_none() {
        npm_prerelease_upper(1, 0, 0)
    } else if minor > 0 {
        npm_prerelease_upper(0, minor.saturating_add(1), 0)
    } else if partial.patch.is_none() {
        npm_prerelease_upper(0, 1, 0)
    } else {
        npm_prerelease_upper(0, 0, patch.saturating_add(1))
    }
}

fn npm_add_partial_comparators(
    output: &mut Vec<NpmComparator>,
    operator: &str,
    partial: &NpmPartialVersion,
) -> Option<()> {
    let lower = npm_partial_lower(partial);
    let upper = npm_partial_upper(partial);
    let full = partial.major.is_some() && partial.minor.is_some() && partial.patch.is_some();
    match operator {
        "=" => {
            if full {
                output.push(NpmComparator {
                    operator: NpmComparatorOperator::Equal,
                    version: lower,
                });
            } else {
                output.push(NpmComparator {
                    operator: NpmComparatorOperator::GreaterOrEqual,
                    version: lower,
                });
                if let Some(upper) = upper {
                    output.push(NpmComparator {
                        operator: NpmComparatorOperator::Less,
                        version: upper,
                    });
                }
            }
        }
        ">=" => output.push(NpmComparator {
            operator: NpmComparatorOperator::GreaterOrEqual,
            version: lower,
        }),
        ">" => {
            if full {
                output.push(NpmComparator {
                    operator: NpmComparatorOperator::Greater,
                    version: lower,
                });
            } else {
                output.push(NpmComparator {
                    operator: NpmComparatorOperator::GreaterOrEqual,
                    version: npm_partial_greater_lower(partial)?,
                });
            }
        }
        "<" => output.push(NpmComparator {
            operator: NpmComparatorOperator::Less,
            version: lower,
        }),
        "<=" => {
            if full {
                output.push(NpmComparator {
                    operator: NpmComparatorOperator::LessOrEqual,
                    version: lower,
                });
            } else {
                output.push(NpmComparator {
                    operator: NpmComparatorOperator::Less,
                    version: upper?,
                });
            }
        }
        "~" => {
            output.push(NpmComparator {
                operator: NpmComparatorOperator::GreaterOrEqual,
                version: lower,
            });
            output.push(NpmComparator {
                operator: NpmComparatorOperator::Less,
                version: if partial.minor.is_none() {
                    npm_prerelease_upper(partial.major?.saturating_add(1), 0, 0)
                } else {
                    npm_prerelease_upper(partial.major?, partial.minor?.saturating_add(1), 0)
                },
            });
        }
        "^" => {
            output.push(NpmComparator {
                operator: NpmComparatorOperator::GreaterOrEqual,
                version: lower,
            });
            output.push(NpmComparator {
                operator: NpmComparatorOperator::Less,
                version: npm_caret_upper(partial),
            });
        }
        _ => return None,
    }
    Some(())
}

fn parse_npm_comparator_token(token: &str, output: &mut Vec<NpmComparator>) -> Option<()> {
    let (operator, value) = if let Some(value) = token.strip_prefix(">=") {
        (">=", value)
    } else if let Some(value) = token.strip_prefix("<=") {
        ("<=", value)
    } else if let Some(value) = token.strip_prefix('>') {
        (">", value)
    } else if let Some(value) = token.strip_prefix('<') {
        ("<", value)
    } else if let Some(value) = token.strip_prefix('^') {
        ("^", value)
    } else if let Some(value) = token.strip_prefix('~') {
        ("~", value)
    } else {
        ("=", token.strip_prefix('=').unwrap_or(token))
    };
    let partial = parse_npm_partial_version(value)?;
    npm_add_partial_comparators(output, operator, &partial)
}

fn parse_npm_hyphen_range(lower: &str, upper: &str, output: &mut Vec<NpmComparator>) -> Option<()> {
    let lower = parse_npm_partial_version(lower)?;
    let upper = parse_npm_partial_version(upper)?;
    output.push(NpmComparator {
        operator: NpmComparatorOperator::GreaterOrEqual,
        version: npm_partial_lower(&lower),
    });
    if let Some(upper) = npm_partial_upper(&upper) {
        output.push(NpmComparator {
            operator: NpmComparatorOperator::Less,
            version: upper,
        });
    } else {
        output.push(NpmComparator {
            operator: NpmComparatorOperator::LessOrEqual,
            version: npm_partial_lower(&upper),
        });
    }
    Some(())
}

fn parse_npm_range(value: &str) -> Option<Vec<Vec<NpmComparator>>> {
    value
        .split("||")
        .map(|alternative| {
            let tokens = alternative.split_ascii_whitespace().collect::<Vec<_>>();
            if tokens.is_empty() {
                return None;
            }
            let mut output = Vec::new();
            if tokens.len() == 3 && tokens[1] == "-" {
                parse_npm_hyphen_range(tokens[0], tokens[2], &mut output)?;
            } else {
                if tokens.contains(&"-") {
                    return None;
                }
                for token in tokens {
                    parse_npm_comparator_token(token, &mut output)?;
                }
            }
            Some(output)
        })
        .collect()
}

fn npm_comparator_matches(comparator: &NpmComparator, version: &NpmVersionParts) -> bool {
    match comparator.operator {
        NpmComparatorOperator::Equal => version == &comparator.version,
        NpmComparatorOperator::Greater => version > &comparator.version,
        NpmComparatorOperator::GreaterOrEqual => version >= &comparator.version,
        NpmComparatorOperator::Less => version < &comparator.version,
        NpmComparatorOperator::LessOrEqual => version <= &comparator.version,
    }
}

fn dependency_spec_allows_version(spec: &str, version: &str) -> bool {
    let Some(version) = npm_version_parts(version) else {
        return false;
    };
    let Some(alternatives) = parse_npm_range(spec) else {
        return false;
    };
    alternatives.into_iter().any(|comparators| {
        (version.prerelease.is_empty()
            || comparators.iter().any(|comparator| {
                comparator.version.major == version.major
                    && comparator.version.minor == version.minor
                    && comparator.version.patch == version.patch
                    && !comparator.version.prerelease.is_empty()
            }))
            && comparators
                .iter()
                .all(|comparator| npm_comparator_matches(comparator, &version))
    })
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
    directories: BTreeSet<String>,
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
    let mut directories = BTreeSet::new();
    let mut files = BTreeMap::new();
    for (path, metadata, file) in &mut entries {
        let relative = stage_relative_path(path, stage_root)?;
        let relative_bytes = relative.as_bytes();
        hasher.update(&(relative_bytes.len() as u64).to_le_bytes());
        hasher.update(relative_bytes);
        if metadata.file_type().is_dir() {
            hasher.update(b"d");
            directories.insert(relative.to_string());
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
        directories,
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
            "optionalDependencies".to_string(),
            "peerDependencies".to_string(),
            "peerDependenciesMeta".to_string(),
            "os".to_string(),
            "cpu".to_string(),
            "bundleDependencies".to_string(),
            "bundledDependencies".to_string(),
            "overrides".to_string(),
            "scripts".to_string(),
            "--userconfig=/dev/null".to_string(),
            format!("--globalconfig={NPM_GLOBAL_CONFIG}"),
            "--cache".to_string(),
            NPM_CACHE.to_string(),
            "--registry=https://registry.npmjs.org".to_string(),
            "--json".to_string(),
        ],
        environment: fixed_npm_environment(),
        working_directory: STAGING_ROOT.to_string(),
        timeout_ms: COMMAND_TIMEOUT_MS,
        env_clear: true,
    }
}

fn npm_dependency_metadata_plan(
    package_name: &str,
    spec: &str,
) -> Result<FixedCommandSpec, LocalMcpAdapterError> {
    npm_dependency_metadata_plan_for_cache(package_name, spec, NPM_CACHE)
}

fn npm_dependency_metadata_plan_for_cache(
    package_name: &str,
    spec: &str,
    cache: &str,
) -> Result<FixedCommandSpec, LocalMcpAdapterError> {
    validate_package_name(package_name)
        .map_err(|_| LocalMcpAdapterError::InvalidMetadata("dependency_name_invalid"))?;
    validate_registry_dependency_spec(spec)?;
    Ok(FixedCommandSpec {
        program: NPM_PROGRAM.to_string(),
        args: vec![
            "view".to_string(),
            format!("{package_name}@{spec}"),
            "version".to_string(),
            "dist.integrity".to_string(),
            "dist.tarball".to_string(),
            "engines".to_string(),
            "dependencies".to_string(),
            "optionalDependencies".to_string(),
            "peerDependencies".to_string(),
            "peerDependenciesMeta".to_string(),
            "os".to_string(),
            "cpu".to_string(),
            "bundleDependencies".to_string(),
            "bundledDependencies".to_string(),
            "overrides".to_string(),
            "scripts".to_string(),
            "--userconfig=/dev/null".to_string(),
            format!("--globalconfig={NPM_GLOBAL_CONFIG}"),
            "--cache".to_string(),
            cache.to_string(),
            "--registry=https://registry.npmjs.org".to_string(),
            "--json".to_string(),
        ],
        environment: fixed_npm_environment_for(cache),
        working_directory: STAGING_ROOT.to_string(),
        timeout_ms: COMMAND_TIMEOUT_MS,
        env_clear: true,
    })
}

fn registry_package_key(package_name: &str) -> Result<String, LocalMcpAdapterError> {
    validate_package_name(package_name)
        .map_err(|_| LocalMcpAdapterError::InvalidMetadata("dependency_name_invalid"))?;
    Ok(package_name.replace('/', "__"))
}

fn registry_artifact_filename(
    package_name: &str,
    version: &str,
) -> Result<String, LocalMcpAdapterError> {
    validate_exact_npm_version(version)?;
    let basename = package_name.rsplit('/').next().unwrap_or(package_name);
    Ok(format!("{basename}-{version}.tgz"))
}

fn npm_registry_pack_plan(
    plan: &LocalMcpStagePlan,
    package_name: &str,
    version: &str,
    registry_tarball_url: &str,
) -> Result<FixedCommandSpec, LocalMcpAdapterError> {
    let package_key = registry_package_key(package_name)?;
    let destination = Path::new(plan.registry_cache_path()).join(package_key);
    let destination = destination
        .to_str()
        .ok_or(LocalMcpAdapterError::StageLayout)?;
    validate_exact_npm_version(version)?;
    validate_registry_package_tarball_url(registry_tarball_url, package_name, version)?;
    Ok(FixedCommandSpec {
        program: NPM_PROGRAM.to_string(),
        args: vec![
            "pack".to_string(),
            registry_tarball_url.to_string(),
            "--ignore-scripts".to_string(),
            "--no-audit".to_string(),
            "--no-fund".to_string(),
            "--bin-links=false".to_string(),
            "--userconfig=/dev/null".to_string(),
            format!("--globalconfig={NPM_GLOBAL_CONFIG}"),
            "--cache".to_string(),
            plan.registry_cache_path().to_string(),
            "--registry=https://registry.npmjs.org".to_string(),
            "--pack-destination".to_string(),
            destination.to_string(),
        ],
        environment: fixed_npm_environment_for(plan.registry_cache_path()),
        working_directory: STAGING_ROOT.to_string(),
        timeout_ms: COMMAND_TIMEOUT_MS,
        env_clear: true,
    })
}

fn npm_registry_cache_add_plan(
    plan: &LocalMcpStagePlan,
    package_name: &str,
    version: &str,
) -> Result<FixedCommandSpec, LocalMcpAdapterError> {
    let source = if package_name == PACKAGE_NAME && version == plan.exact_version() {
        Path::new(plan.stage_root()).join(STAGE_TARBALL_RECEIPT)
    } else {
        let package_key = registry_package_key(package_name)?;
        Path::new(plan.registry_cache_path())
            .join(package_key)
            .join(registry_artifact_filename(package_name, version)?)
    };
    let source = source.to_str().ok_or(LocalMcpAdapterError::StageLayout)?;
    Ok(FixedCommandSpec {
        program: NPM_PROGRAM.to_string(),
        args: vec![
            "cache".to_string(),
            "add".to_string(),
            source.to_string(),
            "--cache".to_string(),
            plan.registry_cache_path().to_string(),
            "--offline".to_string(),
            "--ignore-scripts".to_string(),
            "--no-audit".to_string(),
            "--no-fund".to_string(),
            "--registry=https://registry.npmjs.org".to_string(),
            "--bin-links=false".to_string(),
            "--userconfig=/dev/null".to_string(),
            format!("--globalconfig={NPM_GLOBAL_CONFIG}"),
        ],
        environment: fixed_npm_environment_for(plan.registry_cache_path()),
        working_directory: STAGING_ROOT.to_string(),
        timeout_ms: COMMAND_TIMEOUT_MS,
        env_clear: true,
    })
}

fn fixed_npm_environment() -> BTreeMap<String, String> {
    fixed_npm_environment_for(NPM_CACHE)
}

fn fixed_npm_environment_for(cache: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("HOME".to_string(), NPM_HOME.to_string()),
        ("NO_UPDATE_NOTIFIER".to_string(), "1".to_string()),
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("npm_config_cache".to_string(), cache.to_string()),
    ])
}

fn validate_exact_npm_version(version: &str) -> Result<(), LocalMcpAdapterError> {
    if version.len() > MAX_VERSION_BYTES || npm_version_parts(version).is_none() {
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
            validate_registry_dependency_spec(version)?;
            Ok((name.clone(), version.to_string()))
        })
        .collect()
}

fn validate_package_name(name: &str) -> Result<(), LocalMcpAdapterError> {
    let name_parts: Vec<_> = name.split('/').collect();
    let valid_shape = if name.starts_with('@') {
        name_parts.len() == 2 && name_parts.iter().all(|part| !part.is_empty())
    } else {
        name_parts.len() == 1
    };
    if !valid_shape
        || name.is_empty()
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
    use base64::Engine;

    value.strip_prefix("sha512-").is_some_and(|encoded| {
        encoded.len() == 88
            && base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .is_ok_and(|bytes| bytes.len() == 64)
    })
}

fn validate_registry_tarball_url(value: &str, version: &str) -> Result<(), LocalMcpAdapterError> {
    let expected =
        format!("https://registry.npmjs.org/{PACKAGE_NAME}/-/{PACKAGE_NAME}-{version}.tgz");
    if value.len() > 512
        || !value.is_ascii()
        || value != expected
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
    manifest: Option<Value>,
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
            manifest: None,
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

    fn materialize_packed_artifact(
        &mut self,
        plan: &LocalMcpStagePlan,
    ) -> Result<TrustedLocalMcpArtifact, LocalMcpAdapterError>;

    fn prepare_registry_artifact_destination(
        &mut self,
        _plan: &LocalMcpStagePlan,
        _package_name: &str,
        _version: &str,
    ) -> Result<(), LocalMcpAdapterError> {
        Ok(())
    }

    fn materialize_packed_artifact_for(
        &mut self,
        plan: &LocalMcpStagePlan,
        package_name: &str,
        version: &str,
    ) -> Result<TrustedLocalMcpArtifact, LocalMcpAdapterError> {
        if package_name == PACKAGE_NAME && version == plan.exact_version() {
            self.materialize_packed_artifact(plan)
        } else {
            Err(LocalMcpAdapterError::StageMismatch(
                "packed_artifact_missing",
            ))
        }
    }

    fn materialize_frozen_install_inputs(
        &mut self,
        _plan: &LocalMcpStagePlan,
        _project_manifest: &Value,
        _frozen_lock: &Value,
    ) -> Result<(), LocalMcpAdapterError> {
        Ok(())
    }

    fn preflight_archive(&mut self, _plan: &LocalMcpStagePlan) -> Result<(), LocalMcpAdapterError> {
        Ok(())
    }

    fn persist_verification_receipt(
        &mut self,
        _plan: &LocalMcpStagePlan,
        _receipt: &LocalMcpVerificationReceipt,
    ) -> Result<(), LocalMcpAdapterError> {
        Ok(())
    }

    fn reverify(
        &mut self,
        plan: &LocalMcpStagePlan,
        metadata: &LocalMcpRegistryMetadata,
        tools: Vec<ToolSnapshot>,
    ) -> Result<VerifiedLocalMcpStage, LocalMcpAdapterError> {
        verify_root_owned_local_mcp_stage(plan, metadata, tools)
    }

    fn reverify_with_closure(
        &mut self,
        plan: &LocalMcpStagePlan,
        metadata: &LocalMcpRegistryMetadata,
        _closure: &RegistryClosure,
        tools: Vec<ToolSnapshot>,
    ) -> Result<VerifiedLocalMcpStage, LocalMcpAdapterError> {
        self.reverify(plan, metadata, tools)
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

fn validate_selected_registry_manifest(
    manifest: &Value,
    metadata: &RegistryPackageMetadata,
) -> Result<(), LocalMcpAdapterError> {
    let object = manifest
        .as_object()
        .ok_or(LocalMcpAdapterError::StageMismatch(
            "registry_manifest_invalid",
        ))?;
    if object.get("name").and_then(Value::as_str) != Some(metadata.package_name.as_str())
        || object.get("version").and_then(Value::as_str) != Some(metadata.version.as_str())
    {
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_manifest_mismatch",
        ));
    }
    let engine_requirement = object
        .get("engines")
        .and_then(Value::as_object)
        .and_then(|engines| engines.get("node"))
        .map(|value| {
            value.as_str().ok_or(LocalMcpAdapterError::StageMismatch(
                "registry_manifest_invalid",
            ))
        })
        .transpose()?;
    if engine_requirement != metadata.engine_requirement.as_deref() {
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_manifest_mismatch",
        ));
    }
    let dependencies = parse_dependencies(object.get("dependencies")).map_err(|_| {
        LocalMcpAdapterError::StageMismatch("registry_manifest_dependencies_invalid")
    })?;
    let optional_dependencies =
        parse_dependencies(object.get("optionalDependencies")).map_err(|_| {
            LocalMcpAdapterError::StageMismatch("registry_manifest_dependencies_invalid")
        })?;
    let peer_dependencies = parse_dependencies(object.get("peerDependencies")).map_err(|_| {
        LocalMcpAdapterError::StageMismatch("registry_manifest_dependencies_invalid")
    })?;
    if dependencies != metadata.dependencies
        || optional_dependencies != metadata.optional_dependencies
        || peer_dependencies != metadata.peer_dependencies
    {
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_manifest_mismatch",
        ));
    }
    let peer_dependencies_meta = object
        .get("peerDependenciesMeta")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| json!({}));
    let peer_dependencies_meta =
        parse_peer_dependencies_meta(Some(&peer_dependencies_meta), &peer_dependencies).map_err(
            |_| LocalMcpAdapterError::StageMismatch("registry_manifest_dependencies_invalid"),
        )?;
    let os = parse_platform_constraints(object.get("os"))
        .map_err(|_| LocalMcpAdapterError::StageMismatch("registry_manifest_invalid"))?;
    let cpu = parse_platform_constraints(object.get("cpu"))
        .map_err(|_| LocalMcpAdapterError::StageMismatch("registry_manifest_invalid"))?;
    if peer_dependencies_meta != metadata.peer_dependencies_meta
        || os != metadata.os
        || cpu != metadata.cpu
    {
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_manifest_mismatch",
        ));
    }
    let lifecycle_scripts = object
        .get("scripts")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !lifecycle_scripts.is_object()
        || canonical_digest(&lifecycle_scripts)? != metadata.lifecycle_scripts_digest
    {
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_manifest_mismatch",
        ));
    }
    for field in ["bundleDependencies", "bundledDependencies", "overrides"] {
        if object.get(field).is_some_and(|entry| !entry.is_null()) {
            return Err(LocalMcpAdapterError::StageMismatch(
                "registry_manifest_metadata_unsupported",
            ));
        }
    }
    Ok(())
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
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
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

#[cfg(unix)]
fn terminate_child(child: &mut Child) {
    if let Ok(pid_raw) = i32::try_from(child.id()) {
        if let Some(pid) = rustix::process::Pid::from_raw(pid_raw) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(not(unix))]
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
fn open_fixed_version_directory(plan: &LocalMcpStagePlan) -> Result<File, LocalMcpAdapterError> {
    use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};

    validate_fixed_stage_plan(plan).map_err(|_| LocalMcpAdapterError::StageLayout)?;
    let staging_fd = open_stage_root(Path::new(STAGING_ROOT), 0)?;
    let version_fd = openat2(
        &staging_fd,
        plan.exact_version(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|_| LocalMcpAdapterError::StageLayout)?;
    let version_fd = File::from(version_fd);
    verify_stage_directory_metadata(
        &version_fd
            .metadata()
            .map_err(|_| LocalMcpAdapterError::StageIo)?,
        0,
    )?;
    Ok(version_fd)
}

#[cfg(target_os = "linux")]
fn read_packed_registry_artifact(
    plan: &LocalMcpStagePlan,
    package_name: &str,
    version: &str,
) -> Result<TrustedLocalMcpArtifact, LocalMcpAdapterError> {
    validate_fixed_stage_plan(plan).map_err(|_| LocalMcpAdapterError::StageLayout)?;
    let stage_root = Path::new(plan.stage_root());
    let stage_fd = open_stage_root(stage_root, 0)?;
    let packed_path = packed_registry_artifact_path(plan, package_name, version)?;
    let mut packed = open_stage_file(
        &stage_fd,
        &packed_path,
        stage_root,
        0,
        "packed_artifact_missing",
    )?;
    let before = packed
        .metadata()
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    if before.len() > MAX_STAGE_FILE_BYTES {
        return Err(LocalMcpAdapterError::StageBounds);
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(before.len()).map_err(|_| LocalMcpAdapterError::StageBounds)?,
    );
    (&mut packed)
        .take(MAX_STAGE_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    if bytes.len() as u64 > MAX_STAGE_FILE_BYTES {
        return Err(LocalMcpAdapterError::StageBounds);
    }
    let after = packed
        .metadata()
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    verify_stage_file_metadata(&after, 0)?;
    if before.len() != bytes.len() as u64 || file_metadata_changed(&before, &after) {
        return Err(LocalMcpAdapterError::StageMismatch(
            "packed_artifact_changed",
        ));
    }
    let manifest = read_registry_package_manifest(&packed)?;
    Ok(TrustedLocalMcpArtifact {
        version: version.to_string(),
        bytes,
        manifest: Some(manifest),
    })
}

#[cfg(target_os = "linux")]
fn validate_registry_archive_listing(listing: &[u8]) -> Result<(), LocalMcpAdapterError> {
    validate_archive_listing(listing)?;
    for raw_line in listing.split(|byte| *byte == b'\n') {
        let raw_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if raw_line.is_empty() {
            continue;
        }
        let line = std::str::from_utf8(raw_line)
            .map_err(|_| LocalMcpAdapterError::StageMismatch("archive_listing_invalid"))?;
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        let name = fields
            .get(5)
            .ok_or(LocalMcpAdapterError::StageMismatch(
                "archive_listing_invalid",
            ))?
            .trim_end_matches('/');
        if name == "package/.npmrc"
            || (name.starts_with("package/")
                && (name.ends_with("/npm-shrinkwrap.json") || name.ends_with("/package-lock.json")))
        {
            return Err(LocalMcpAdapterError::StageMismatch(
                "registry_archive_metadata_unsupported",
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_registry_package_manifest(packed: &File) -> Result<Value, LocalMcpAdapterError> {
    let receipt_path = proc_fd_path(packed);
    let listing = run_bounded_tar_listing(&receipt_path)?;
    validate_registry_archive_listing(&listing)?;
    let deadline = Instant::now() + Duration::from_millis(COMMAND_TIMEOUT_MS);
    let mut child = fixed_tar_command()
        .args([
            "--extract",
            "--to-stdout",
            "--file",
            receipt_path.as_str(),
            "package/package.json",
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
        let _ = sender.send(read_bounded_npm_output(&mut stdout));
    });
    let mut output = None;
    let mut status = None;
    loop {
        if output.is_none() {
            if let Ok(result) = receiver.try_recv() {
                output = Some(result);
            }
        }
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|_| LocalMcpAdapterError::StageIo)?;
        }
        if output.is_some() && status.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            terminate_child(&mut child);
            let _ = reader.join();
            return Err(LocalMcpAdapterError::StageMismatch(
                "registry_manifest_timeout",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if reader.join().is_err() {
        return Err(LocalMcpAdapterError::StageIo);
    }
    let output = match output.expect("tar manifest reader completed") {
        Ok(bytes) => bytes,
        Err(NpmOutputError::TooLarge) => return Err(LocalMcpAdapterError::StageBounds),
        Err(NpmOutputError::Io) => return Err(LocalMcpAdapterError::StageIo),
    };
    if !status.expect("tar manifest process completed").success() {
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_manifest_missing",
        ));
    }
    let manifest: Value = serde_json::from_slice(&output)
        .map_err(|_| LocalMcpAdapterError::StageMismatch("registry_manifest_invalid"))?;
    if !manifest.is_object() {
        return Err(LocalMcpAdapterError::StageMismatch(
            "registry_manifest_invalid",
        ));
    }
    Ok(manifest)
}

#[cfg(target_os = "linux")]
fn write_stage_json_file(
    stage_fd: &File,
    name: &str,
    value: &Value,
) -> Result<(), LocalMcpAdapterError> {
    use rustix::fs::{Mode, OFlags, openat};

    let encoded = serde_json::to_vec(value).map_err(|_| LocalMcpAdapterError::Encoding)?;
    if encoded.len() > MAX_STAGE_JSON_BYTES as usize {
        return Err(LocalMcpAdapterError::StageBounds);
    }
    let fd = openat(
        stage_fd,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
    )
    .map_err(|_| LocalMcpAdapterError::StageLayout)?;
    let mut file = File::from(fd);
    file.write_all(&encoded)
        .map_err(|_| LocalMcpAdapterError::StageIo)?;
    file.sync_all().map_err(|_| LocalMcpAdapterError::StageIo)
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
            .map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let stage_fd = openat2(
            &version_fd,
            plan.stage_id(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let stage_fd = File::from(stage_fd);
        mkdirat(&stage_fd, STAGE_REGISTRY_CACHE, Mode::from_raw_mode(0o700))
            .map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let cache_fd = openat2(
            &stage_fd,
            STAGE_REGISTRY_CACHE,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let cache_fd = File::from(cache_fd);
        mkdirat(
            &cache_fd,
            registry_package_key(PACKAGE_NAME)?,
            Mode::from_raw_mode(0o700),
        )
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
        let status = wait_child_until(&mut child, deadline, "artifact_extract_timeout")?;
        if !status.success() {
            return Err(LocalMcpAdapterError::StageMismatch(
                "artifact_extract_failed",
            ));
        }
        Ok(())
    }

    fn materialize_packed_artifact(
        &mut self,
        plan: &LocalMcpStagePlan,
    ) -> Result<TrustedLocalMcpArtifact, LocalMcpAdapterError> {
        use rustix::fs::{Mode, OFlags, openat};
        use std::os::unix::fs::MetadataExt;

        let artifact = read_packed_registry_artifact(plan, PACKAGE_NAME, plan.exact_version())?;

        let stage_fd = open_stage_root(Path::new(plan.stage_root()), 0)?;
        let fd = openat(
            &stage_fd,
            STAGE_TARBALL_RECEIPT,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let mut receipt = File::from(fd);
        receipt
            .write_all(&artifact.bytes)
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        receipt
            .sync_all()
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        let receipt_metadata = receipt
            .metadata()
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        if receipt_metadata.uid() != 0 {
            return Err(LocalMcpAdapterError::StagePermissions);
        }
        Ok(artifact)
    }

    fn prepare_registry_artifact_destination(
        &mut self,
        plan: &LocalMcpStagePlan,
        package_name: &str,
        version: &str,
    ) -> Result<(), LocalMcpAdapterError> {
        use rustix::fs::{Mode, OFlags, ResolveFlags, mkdirat, openat2};

        validate_fixed_stage_plan(plan).map_err(|_| LocalMcpAdapterError::StageLayout)?;
        if package_name == PACKAGE_NAME && version == plan.exact_version() {
            return Ok(());
        }
        let stage_fd = open_stage_root(Path::new(plan.stage_root()), 0)?;
        let cache_fd = openat2(
            &stage_fd,
            STAGE_REGISTRY_CACHE,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let cache_fd = File::from(cache_fd);
        let package_key = registry_package_key(package_name)?;
        if mkdirat(&cache_fd, &package_key, Mode::from_raw_mode(0o700)).is_ok() {
            Ok(())
        } else {
            let package_fd = openat2(
                &cache_fd,
                &package_key,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
            )
            .map_err(|_| LocalMcpAdapterError::StageLayout)?;
            let package_fd = File::from(package_fd);
            verify_stage_directory_metadata(
                &package_fd
                    .metadata()
                    .map_err(|_| LocalMcpAdapterError::StageIo)?,
                0,
            )
        }
    }

    fn materialize_packed_artifact_for(
        &mut self,
        plan: &LocalMcpStagePlan,
        package_name: &str,
        version: &str,
    ) -> Result<TrustedLocalMcpArtifact, LocalMcpAdapterError> {
        use rustix::fs::{Mode, OFlags, openat};

        let artifact = read_packed_registry_artifact(plan, package_name, version)?;
        if package_name == PACKAGE_NAME && version == plan.exact_version() {
            let stage_fd = open_stage_root(Path::new(plan.stage_root()), 0)?;
            let fd = openat(
                &stage_fd,
                STAGE_TARBALL_RECEIPT,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o600),
            )
            .map_err(|_| LocalMcpAdapterError::StageLayout)?;
            let mut receipt = File::from(fd);
            receipt
                .write_all(&artifact.bytes)
                .map_err(|_| LocalMcpAdapterError::StageIo)?;
            receipt
                .sync_all()
                .map_err(|_| LocalMcpAdapterError::StageIo)?;
        }
        Ok(artifact)
    }

    fn materialize_frozen_install_inputs(
        &mut self,
        plan: &LocalMcpStagePlan,
        project_manifest: &Value,
        frozen_lock: &Value,
    ) -> Result<(), LocalMcpAdapterError> {
        validate_fixed_stage_plan(plan).map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let stage_fd = open_stage_root(Path::new(plan.stage_root()), 0)?;
        write_stage_json_file(&stage_fd, STAGE_PROJECT_PACKAGE_JSON, project_manifest)?;
        write_stage_json_file(&stage_fd, "package-lock.json", frozen_lock)
    }

    fn reverify_with_closure(
        &mut self,
        plan: &LocalMcpStagePlan,
        metadata: &LocalMcpRegistryMetadata,
        closure: &RegistryClosure,
        tools: Vec<ToolSnapshot>,
    ) -> Result<VerifiedLocalMcpStage, LocalMcpAdapterError> {
        verify_local_mcp_stage_for_owner_with_closure(plan, metadata, Some(closure), tools, 0)
    }

    fn preflight_archive(&mut self, plan: &LocalMcpStagePlan) -> Result<(), LocalMcpAdapterError> {
        preflight_archive(plan).map(|_| ())
    }

    fn persist_verification_receipt(
        &mut self,
        plan: &LocalMcpStagePlan,
        receipt: &LocalMcpVerificationReceipt,
    ) -> Result<(), LocalMcpAdapterError> {
        use rustix::fs::{Mode, OFlags, openat};
        use std::os::unix::fs::MetadataExt;

        validate_fixed_stage_plan(plan).map_err(|_| LocalMcpAdapterError::StageLayout)?;
        if receipt.schema != "fwc.n8n.local-mcp-verification-receipt.v1"
            || receipt.status != "verified"
            || receipt.version != plan.exact_version()
            || receipt.stage_id != plan.stage_id()
            || receipt.stage_root != plan.stage_root()
            || receipt.receipt_path != plan.verification_receipt_path()
            || !valid_blake3_digest(&receipt.registry_closure_digest)
            || receipt.registry_closure_packages.is_empty()
        {
            return Err(LocalMcpAdapterError::StageMismatch("receipt_invalid"));
        }
        if registry_closure_receipt_digest(
            &receipt.registry_closure_packages,
            &receipt.registry_closure_edges,
        )? != receipt.registry_closure_digest
        {
            return Err(LocalMcpAdapterError::StageMismatch(
                "registry_dependency_closure_invalid",
            ));
        }
        let encoded = serde_json::to_vec(receipt).map_err(|_| LocalMcpAdapterError::Encoding)?;
        if encoded.len() > MAX_STAGE_JSON_BYTES as usize {
            return Err(LocalMcpAdapterError::StageBounds);
        }
        let version_fd = open_fixed_version_directory(plan)?;
        let receipt_name = format!("{}{VERIFICATION_RECEIPT}", plan.stage_id());
        let fd = openat(
            &version_fd,
            &receipt_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|_| LocalMcpAdapterError::StageLayout)?;
        let mut file = File::from(fd);
        file.write_all(&encoded)
            .map_err(|_| LocalMcpAdapterError::StageIo)?;
        file.sync_all().map_err(|_| LocalMcpAdapterError::StageIo)?;
        let metadata = file.metadata().map_err(|_| LocalMcpAdapterError::StageIo)?;
        if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err(LocalMcpAdapterError::StagePermissions);
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

    fn materialize_packed_artifact(
        &mut self,
        _plan: &LocalMcpStagePlan,
    ) -> Result<TrustedLocalMcpArtifact, LocalMcpAdapterError> {
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
    use std::fs;

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
        let zod_root = Path::new(plan.stage_root()).join("node_modules/zod");
        fs::create_dir_all(package_root.join("dist/mcp")).expect("package directories");
        fs::create_dir_all(&zod_root).expect("dependency directories");
        for directory in [
            Path::new(plan.stage_root())
                .parent()
                .expect("version staging root"),
            Path::new(plan.stage_root()),
            &Path::new(plan.stage_root()).join("node_modules"),
            package_root,
            &package_root.join("dist"),
            &package_root.join("dist/mcp"),
            &zod_root,
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .expect("private stage directory");
        }
        let project_manifest = json!({
            "name": LOCK_PROJECT_NAME,
            "version": LOCK_PROJECT_VERSION,
            "private": true,
            "dependencies": {"n8n-mcp": "2.69.2"},
        });
        fs::write(
            Path::new(plan.stage_root()).join(STAGE_PROJECT_PACKAGE_JSON),
            serde_json::to_vec(&project_manifest).expect("project package json"),
        )
        .expect("write project package json");
        fs::set_permissions(
            Path::new(plan.stage_root()).join(STAGE_PROJECT_PACKAGE_JSON),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private project package json");
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
                "": {
                    "name": LOCK_PROJECT_NAME,
                    "version": LOCK_PROJECT_VERSION,
                    "private": true,
                    "dependencies": {"n8n-mcp": "2.69.2"}
                },
                "node_modules/n8n-mcp": {
                    "version": "2.69.2",
                    "resolved": "https://registry.npmjs.org/n8n-mcp/-/n8n-mcp-2.69.2.tgz",
                    "integrity": INTEGRITY,
                    "dependencies": {"zod": "^3.25.0"}
                },
                "node_modules/zod": {
                    "version": "3.25.0",
                    "resolved": "https://registry.npmjs.org/zod/-/zod-3.25.0.tgz",
                    "integrity": INTEGRITY
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
            zod_root.join("package.json"),
            br#"{"name":"zod","version":"3.25.0"}"#,
        )
        .expect("write dependency manifest");
        fs::set_permissions(
            zod_root.join("package.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("private dependency manifest");
        fs::write(zod_root.join("index.js"), b"module.exports = {};\n")
            .expect("write dependency entrypoint");
        fs::set_permissions(zod_root.join("index.js"), fs::Permissions::from_mode(0o600))
            .expect("private dependency entrypoint");
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
        assert_eq!(
            plan.install.environment,
            fixed_npm_environment_for(plan.registry_cache_path())
        );
        assert!(plan.install.env_clear);
        assert_eq!(plan.install.args[0], "ci");
        assert_eq!(plan.install.args[1], "--prefix");
        assert_eq!(plan.install.args[2], plan.stage_root);
        assert_eq!(
            &plan.install.args[3..],
            [
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--cache",
                plan.registry_cache_path(),
                "--offline",
                "--registry=https://registry.npmjs.org",
                "--bin-links=false",
                "--userconfig=/dev/null",
                "--globalconfig=/var/lib/fwc-n8n/npm-home/global.npmrc",
                "--package-lock=true",
            ]
        );
        assert_eq!(plan.pack.program, NPM_PROGRAM);
        assert_eq!(plan.pack.working_directory, STAGING_ROOT);
        assert_eq!(
            plan.pack.environment,
            fixed_npm_environment_for(plan.registry_cache_path())
        );
        assert!(plan.pack.env_clear);
        assert_eq!(
            &plan.pack.args[..],
            [
                "pack",
                "https://registry.npmjs.org/n8n-mcp/-/n8n-mcp-2.69.2.tgz",
                "--ignore-scripts",
                "--no-audit",
                "--no-fund",
                "--bin-links=false",
                "--userconfig=/dev/null",
                "--globalconfig=/var/lib/fwc-n8n/npm-home/global.npmrc",
                "--cache",
                plan.registry_cache_path(),
                "--registry=https://registry.npmjs.org",
                "--pack-destination",
                Path::new(plan.registry_cache_path())
                    .join(registry_package_key(PACKAGE_NAME).expect("package key"))
                    .to_str()
                    .expect("cache path"),
            ]
        );
        assert!(plan.verification_receipt_path().starts_with(STAGING_ROOT));
        assert!(
            !plan
                .verification_receipt_path()
                .starts_with(&format!("{}/", plan.stage_root()))
        );
    }

    fn npm_command_builder_suite(root: &Path) -> Vec<FixedCommandSpec> {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        #[cfg(unix)]
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .expect("private synthetic preflight root");
        let plan =
            build_local_mcp_stage_plan("2.69.2", STAGE_ID, root).expect("synthetic staging plan");
        let mut root_view = npm_latest_metadata_plan();
        root_view.working_directory = root.to_string_lossy().into_owned();
        let mut dependency_view = npm_dependency_metadata_plan_for_cache(
            "zod",
            "^3.25.0",
            &root.join("cache").to_string_lossy(),
        )
        .expect("dependency metadata plan");
        dependency_view.working_directory = root.to_string_lossy().into_owned();
        let dependency_pack = npm_registry_pack_plan(
            &plan,
            "zod",
            "3.25.0",
            "https://registry.npmjs.org/zod/-/zod-3.25.0.tgz",
        )
        .expect("dependency pack plan");
        let mut dependency_pack = dependency_pack;
        dependency_pack.working_directory = root.to_string_lossy().into_owned();
        let cache_add =
            npm_registry_cache_add_plan(&plan, "zod", "3.25.0").expect("cache add plan");
        let mut cache_add = cache_add;
        cache_add.working_directory = root.to_string_lossy().into_owned();
        let mut pack = plan.pack().clone();
        pack.working_directory = root.to_string_lossy().into_owned();
        let mut install = plan.install().clone();
        install.working_directory = root.to_string_lossy().into_owned();
        let mut commands = vec![
            root_view,
            dependency_view,
            pack,
            dependency_pack,
            install,
            cache_add,
        ];
        for command in &mut commands {
            if let Some(prefix_argument) = command
                .args
                .windows(2)
                .position(|window| window[0] == "--prefix")
            {
                command.args[prefix_argument + 1] = root.to_string_lossy().into_owned();
            }
        }
        commands
    }

    #[cfg(unix)]
    fn synthetic_preflight_root() -> tempfile::TempDir {
        let effective_uid = rustix::process::geteuid().as_raw();
        let candidates = [
            std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
            Some(PathBuf::from(format!("/run/user/{effective_uid}"))),
            Some(PathBuf::from("/run")),
            std::env::var_os("HOME").map(PathBuf::from),
        ];
        for candidate in candidates.into_iter().flatten() {
            if validate_npm_directory_ancestry(&candidate).is_ok() {
                if let Ok(root) = tempfile::tempdir_in(&candidate) {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
                        .expect("private synthetic preflight root");
                    return root;
                }
            }
        }
        panic!("no trusted directory available for synthetic npm preflight root");
    }

    #[cfg(not(unix))]
    fn synthetic_preflight_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("synthetic preflight root")
    }

    fn run_npm_preflight_with_spawn_for_test(
        command: &FixedCommandSpec,
        global_config: &Path,
        expected_working_directory: &Path,
    ) -> (Result<Vec<u8>, LocalMcpAdapterError>, usize) {
        let mut spawn_calls = 0;
        let result = run_fixed_npm_command_with_spawn(
            command,
            global_config,
            expected_working_directory
                .to_str()
                .expect("synthetic working directory"),
            |_| {
                spawn_calls += 1;
                Ok(Vec::new())
            },
        );
        (result, spawn_calls)
    }

    #[cfg(unix)]
    #[test]
    fn npm_preflight_accepts_clean_synthetic_layouts_and_empty_global_config() {
        for config_state in ["missing", "empty"] {
            let root = synthetic_preflight_root();
            let global_config = root.path().join("global.npmrc");
            if config_state == "empty" {
                fs::write(&global_config, b"").expect("empty global config");
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&global_config, fs::Permissions::from_mode(0o600))
                        .expect("private empty global config");
                }
            }
            for command in npm_command_builder_suite(root.path()) {
                let (result, spawn_calls) =
                    run_npm_preflight_with_spawn_for_test(&command, &global_config, root.path());
                assert_eq!(
                    result,
                    Ok(Vec::new()),
                    "clean preflight rejected {config_state} global config for {:?}",
                    command.args().first(),
                );
                assert_eq!(spawn_calls, 1);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn npm_preflight_rejects_unsafe_global_config_across_all_command_builders() {
        for config_state in ["nonempty", "directory"] {
            let root = synthetic_preflight_root();
            let global_config = root.path().join("global.npmrc");
            if config_state == "nonempty" {
                fs::write(&global_config, b"registry=https://example.invalid\n")
                    .expect("nonempty global config");
            } else {
                fs::create_dir(&global_config).expect("directory global config");
            }
            for command in npm_command_builder_suite(root.path()) {
                let (result, spawn_calls) =
                    run_npm_preflight_with_spawn_for_test(&command, &global_config, root.path());
                assert_eq!(
                    result,
                    Err(LocalMcpAdapterError::StageLayout),
                    "unsafe {config_state} config reached spawn for {:?}",
                    command.args().first(),
                );
                assert_eq!(spawn_calls, 0);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn npm_preflight_rejects_untrusted_cwd_and_prefix_ancestry_before_spawn() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = synthetic_preflight_root();
        let global_config = root.path().join("global.npmrc");

        let writable_parent = root.path().join("writable-parent");
        let writable_cwd = writable_parent.join("cwd");
        fs::create_dir_all(&writable_cwd).expect("writable cwd");
        fs::set_permissions(&writable_cwd, fs::Permissions::from_mode(0o700))
            .expect("private writable cwd");
        fs::set_permissions(&writable_parent, fs::Permissions::from_mode(0o777))
            .expect("writable cwd ancestor");
        for command in npm_command_builder_suite(root.path()) {
            let mut command = command;
            command.working_directory = writable_cwd.to_string_lossy().into_owned();
            let (result, spawn_calls) =
                run_npm_preflight_with_spawn_for_test(&command, &global_config, &writable_cwd);
            assert_eq!(result, Err(LocalMcpAdapterError::StageLayout));
            assert_eq!(spawn_calls, 0, "writable cwd ancestry reached npm spawn");
        }

        let real_cwd = root.path().join("real-cwd");
        fs::create_dir_all(real_cwd.join("child")).expect("real cwd");
        fs::set_permissions(&real_cwd, fs::Permissions::from_mode(0o700))
            .expect("private real cwd");
        fs::set_permissions(real_cwd.join("child"), fs::Permissions::from_mode(0o700))
            .expect("private real cwd child");
        let symlink_cwd_parent = root.path().join("symlink-cwd-parent");
        symlink(&real_cwd, &symlink_cwd_parent).expect("symlink cwd ancestor");
        let symlink_cwd = symlink_cwd_parent.join("child");
        for command in npm_command_builder_suite(root.path()) {
            let mut command = command;
            command.working_directory = symlink_cwd.to_string_lossy().into_owned();
            let (result, spawn_calls) =
                run_npm_preflight_with_spawn_for_test(&command, &global_config, &symlink_cwd);
            assert_eq!(result, Err(LocalMcpAdapterError::StageLayout));
            assert_eq!(spawn_calls, 0, "symlinked cwd ancestry reached npm spawn");
        }

        let writable_prefix_parent = root.path().join("writable-prefix-parent");
        let writable_prefix = writable_prefix_parent.join("prefix");
        fs::create_dir_all(&writable_prefix).expect("writable prefix");
        fs::set_permissions(&writable_prefix, fs::Permissions::from_mode(0o700))
            .expect("private writable prefix");
        fs::set_permissions(&writable_prefix_parent, fs::Permissions::from_mode(0o777))
            .expect("writable prefix ancestor");
        let real_prefix = root.path().join("real-prefix");
        fs::create_dir_all(real_prefix.join("prefix")).expect("real prefix");
        fs::set_permissions(&real_prefix, fs::Permissions::from_mode(0o700))
            .expect("private real prefix");
        fs::set_permissions(
            real_prefix.join("prefix"),
            fs::Permissions::from_mode(0o700),
        )
        .expect("private real prefix child");
        let symlink_prefix_parent = root.path().join("symlink-prefix-parent");
        symlink(&real_prefix, &symlink_prefix_parent).expect("symlink prefix ancestor");
        let symlink_prefix = symlink_prefix_parent.join("prefix");
        for (prefix, label) in [
            (&writable_prefix, "writable prefix ancestry"),
            (&symlink_prefix, "symlinked prefix ancestry"),
        ] {
            let mut install = npm_command_builder_suite(root.path())
                .into_iter()
                .find(|command| command.args().first().is_some_and(|arg| arg == "ci"))
                .expect("ci command");
            let prefix_argument = install
                .args
                .windows(2)
                .position(|window| window[0] == "--prefix")
                .expect("ci prefix argument");
            install.args[prefix_argument + 1] = prefix.to_string_lossy().into_owned();
            let (result, spawn_calls) =
                run_npm_preflight_with_spawn_for_test(&install, &global_config, root.path());
            assert_eq!(result, Err(LocalMcpAdapterError::StageLayout), "{label}");
            assert_eq!(spawn_calls, 0, "{label} reached npm spawn");
        }
    }

    #[cfg(unix)]
    #[test]
    fn npm_preflight_rejects_untrusted_global_config_before_spawn() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = synthetic_preflight_root();
        let commands = npm_command_builder_suite(root.path());
        let writable_file = root.path().join("writable.npmrc");
        fs::write(&writable_file, b"").expect("writable global config");
        fs::set_permissions(&writable_file, fs::Permissions::from_mode(0o666))
            .expect("writable global config mode");

        let writable_parent = root.path().join("writable-parent");
        fs::create_dir(&writable_parent).expect("writable global config parent");
        fs::set_permissions(&writable_parent, fs::Permissions::from_mode(0o777))
            .expect("writable global config parent mode");
        let writable_parent_config = writable_parent.join("global.npmrc");

        let real_parent = root.path().join("real-parent");
        fs::create_dir(&real_parent).expect("real global config parent");
        fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700))
            .expect("private real global config parent");
        let symlink_parent = root.path().join("symlink-parent");
        symlink(&real_parent, &symlink_parent).expect("symlink global config parent");
        let symlink_parent_config = symlink_parent.join("global.npmrc");

        let real_config = root.path().join("real-global.npmrc");
        fs::write(&real_config, b"").expect("real global config");
        let symlink_config = root.path().join("symlink-global.npmrc");
        symlink(&real_config, &symlink_config).expect("symlink global config");

        for (global_config, label) in [
            (&writable_file, "writable global config"),
            (&writable_parent_config, "writable global config ancestry"),
            (&symlink_parent_config, "symlinked global config ancestry"),
            (&symlink_config, "symlinked global config"),
        ] {
            for command in &commands {
                let (result, spawn_calls) =
                    run_npm_preflight_with_spawn_for_test(command, global_config, root.path());
                assert_eq!(result, Err(LocalMcpAdapterError::StageLayout), "{label}");
                assert_eq!(spawn_calls, 0, "{label} reached npm spawn");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn npm_preflight_rejects_each_ambient_marker_across_all_command_builders() {
        for marker in [
            ".npmrc",
            "package.json",
            "package-lock.json",
            "node_modules",
        ] {
            let root = synthetic_preflight_root();
            let marker_path = root.path().join(marker);
            if marker == "node_modules" {
                fs::create_dir(&marker_path).expect("node_modules marker");
            } else {
                fs::write(&marker_path, b"ambient marker").expect("ambient marker");
            }
            let global_config = root.path().join("global.npmrc");
            for command in npm_command_builder_suite(root.path()) {
                let (result, spawn_calls) =
                    run_npm_preflight_with_spawn_for_test(&command, &global_config, root.path());
                assert_eq!(
                    result,
                    Err(LocalMcpAdapterError::StageLayout),
                    "ambient {marker} marker reached spawn for {:?}",
                    command.args().first(),
                );
                assert_eq!(spawn_calls, 0);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn npm_preflight_accepts_ci_generated_prefix_markers_before_spawn() {
        let root = synthetic_preflight_root();
        let prefix = root.path().join("prefix");
        fs::create_dir_all(prefix.join("node_modules")).expect("generated node_modules");
        fs::write(prefix.join("package.json"), b"{}").expect("generated package manifest");
        fs::write(prefix.join("package-lock.json"), b"{}").expect("generated package lock");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&prefix, fs::Permissions::from_mode(0o700))
                .expect("private generated prefix");
        }
        let global_config = root.path().join("global.npmrc");
        let install = npm_command_builder_suite(root.path())
            .into_iter()
            .find(|command| command.args().first().is_some_and(|arg| arg == "ci"))
            .expect("ci command");
        let mut install = install;
        let prefix_argument = install
            .args
            .windows(2)
            .position(|window| window[0] == "--prefix")
            .expect("ci prefix argument");
        install.args[prefix_argument + 1] = prefix.to_string_lossy().into_owned();
        let (result, spawn_calls) =
            run_npm_preflight_with_spawn_for_test(&install, &global_config, root.path());
        assert_eq!(result, Ok(Vec::new()));
        assert_eq!(spawn_calls, 1);
    }

    #[cfg(unix)]
    #[test]
    fn npm_preflight_rejects_stage_npmrc_and_ambient_prefix_ancestry_before_ci_spawn() {
        for rejection in ["stage_npmrc", "ancestor_package_json"] {
            let root = synthetic_preflight_root();
            let prefix_parent = root.path().join("prefix-parent");
            let prefix = prefix_parent.join("prefix");
            fs::create_dir_all(&prefix).expect("prefix");
            fs::create_dir_all(prefix.join("node_modules")).expect("generated node_modules");
            fs::write(prefix.join("package.json"), b"{}").expect("generated package manifest");
            fs::write(prefix.join("package-lock.json"), b"{}").expect("generated package lock");
            if rejection == "stage_npmrc" {
                fs::write(prefix.join(".npmrc"), b"registry=https://example.invalid\n")
                    .expect("stage npmrc");
            } else {
                fs::write(prefix_parent.join("package.json"), b"ambient marker")
                    .expect("ambient ancestor package marker");
            }
            let global_config = root.path().join("global.npmrc");
            let install = npm_command_builder_suite(root.path())
                .into_iter()
                .find(|command| command.args().first().is_some_and(|arg| arg == "ci"))
                .expect("ci command");
            let mut install = install;
            let prefix_argument = install
                .args
                .windows(2)
                .position(|window| window[0] == "--prefix")
                .expect("ci prefix argument");
            install.args[prefix_argument + 1] = prefix.to_string_lossy().into_owned();
            let (result, spawn_calls) =
                run_npm_preflight_with_spawn_for_test(&install, &global_config, root.path());
            assert_eq!(
                result,
                Err(LocalMcpAdapterError::StageLayout),
                "{rejection}"
            );
            assert_eq!(spawn_calls, 0, "{rejection} reached npm spawn");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn actual_empty_cache_offline_ci_uses_only_verified_artifact_and_rejects_negatives() {
        use base64::Engine;
        use sha2::{Digest, Sha512};
        use std::os::unix::fs::PermissionsExt;

        fn create_tarball(root: &Path, label: &str, body: &str) -> (PathBuf, String) {
            let source = root.join(format!("source-{label}/package"));
            fs::create_dir_all(&source).expect("package source");
            fs::write(
                source.join("package.json"),
                br#"{"name":"n8n-mcp","version":"0.0.1","bin":{"n8n-mcp":"index.js"}}"#,
            )
            .expect("package manifest");
            fs::write(source.join("index.js"), body).expect("package entrypoint");
            fs::set_permissions(source.join("index.js"), fs::Permissions::from_mode(0o700))
                .expect("entrypoint permissions");
            let tarball = root.join(format!("n8n-mcp-0.0.1-{label}.tgz"));
            let status = Command::new(TAR_PROGRAM)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .args([
                    "--create",
                    "--gzip",
                    "--file",
                    tarball.to_str().expect("tarball path"),
                    "--directory",
                    source
                        .parent()
                        .expect("package parent")
                        .to_str()
                        .expect("source path"),
                    "package",
                ])
                .status()
                .expect("tar executable");
            assert!(status.success(), "tarball creation failed: {status}");
            let bytes = fs::read(&tarball).expect("tarball bytes");
            let integrity = format!(
                "sha512-{}",
                base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
            );
            (tarball, integrity)
        }

        fn write_project(stage: &Path, integrity: &str) {
            fs::create_dir_all(stage.join("node_modules")).expect("stage node_modules");
            fs::write(
                stage.join("package.json"),
                br#"{"name":"fwc-n8n-local-mcp-stage","version":"0.0.0","private":true,"dependencies":{"n8n-mcp":"0.0.1"}}"#,
            )
            .expect("stage package manifest");
            let lock = json!({
                "name": LOCK_PROJECT_NAME,
                "version": LOCK_PROJECT_VERSION,
                "lockfileVersion": 3,
                "requires": true,
                "packages": {
                    "": {
                        "name": LOCK_PROJECT_NAME,
                        "version": LOCK_PROJECT_VERSION,
                        "private": true,
                        "dependencies": {"n8n-mcp": "0.0.1"}
                    },
                    "node_modules/n8n-mcp": {
                        "name": "n8n-mcp",
                        "version": "0.0.1",
                        "resolved": "https://registry.npmjs.org/n8n-mcp/-/n8n-mcp-0.0.1.tgz",
                        "integrity": integrity
                    }
                }
            });
            fs::write(
                stage.join("package-lock.json"),
                serde_json::to_vec(&lock).expect("stage lock"),
            )
            .expect("stage package lock");
        }

        fn run_npm(stage: &Path, cache: &Path, home: &Path, args: &[String]) -> bool {
            Command::new(NPM_PROGRAM)
                .env_clear()
                .env("HOME", home)
                .env("NO_UPDATE_NOTIFIER", "1")
                .env("PATH", "/usr/bin:/bin")
                .env("npm_config_cache", cache)
                .args(args)
                .current_dir(stage)
                .status()
                .expect("npm executable")
                .success()
        }

        fn common_install_args(stage: &Path, cache: &Path) -> Vec<String> {
            vec![
                "ci".to_string(),
                "--prefix".to_string(),
                stage.to_string_lossy().into_owned(),
                "--ignore-scripts".to_string(),
                "--no-audit".to_string(),
                "--no-fund".to_string(),
                "--cache".to_string(),
                cache.to_string_lossy().into_owned(),
                "--offline".to_string(),
                "--registry=https://registry.npmjs.org".to_string(),
                "--bin-links=false".to_string(),
                "--userconfig=/dev/null".to_string(),
                format!("--globalconfig={NPM_GLOBAL_CONFIG}"),
                "--package-lock=true".to_string(),
            ]
        }

        let root = tempfile::tempdir().expect("offline npm fixture root");
        let (artifact, integrity) =
            create_tarball(root.path(), "verified", "module.exports = 1;\n");
        let (tampered_artifact, _tampered_integrity) =
            create_tarball(root.path(), "tampered", "module.exports = 2;\n");
        let success_stage = root.path().join("success-stage");
        let success_cache = root.path().join("success-cache");
        let success_home = root.path().join("success-home");
        fs::create_dir_all(&success_cache).expect("empty success cache");
        fs::create_dir_all(&success_home).expect("success npm home");
        write_project(&success_stage, &integrity);
        let cache_args = vec![
            "cache".to_string(),
            "add".to_string(),
            artifact.to_string_lossy().into_owned(),
            "--cache".to_string(),
            success_cache.to_string_lossy().into_owned(),
            "--offline".to_string(),
            "--ignore-scripts".to_string(),
            "--no-audit".to_string(),
            "--no-fund".to_string(),
            "--registry=https://registry.npmjs.org".to_string(),
            "--userconfig=/dev/null".to_string(),
            format!("--globalconfig={NPM_GLOBAL_CONFIG}"),
        ];
        assert!(run_npm(
            &success_stage,
            &success_cache,
            &success_home,
            &cache_args
        ));
        assert!(run_npm(
            &success_stage,
            &success_cache,
            &success_home,
            &common_install_args(&success_stage, &success_cache)
        ));
        assert!(
            success_stage
                .join("node_modules/n8n-mcp/package.json")
                .is_file()
        );

        let missing_stage = root.path().join("missing-stage");
        let missing_cache = root.path().join("missing-cache");
        let missing_home = root.path().join("missing-home");
        fs::create_dir_all(&missing_cache).expect("empty missing cache");
        fs::create_dir_all(&missing_home).expect("missing npm home");
        write_project(&missing_stage, &integrity);
        assert!(!run_npm(
            &missing_stage,
            &missing_cache,
            &missing_home,
            &common_install_args(&missing_stage, &missing_cache)
        ));

        let tampered_stage = root.path().join("tampered-stage");
        let tampered_cache = root.path().join("tampered-cache");
        let tampered_home = root.path().join("tampered-home");
        fs::create_dir_all(&tampered_cache).expect("empty tampered cache");
        fs::create_dir_all(&tampered_home).expect("tampered npm home");
        write_project(&tampered_stage, &integrity);
        let mut tampered_cache_args = cache_args;
        tampered_cache_args[2] = tampered_artifact.to_string_lossy().into_owned();
        tampered_cache_args[4] = tampered_cache.to_string_lossy().into_owned();
        assert!(run_npm(
            &tampered_stage,
            &tampered_cache,
            &tampered_home,
            &tampered_cache_args
        ));
        assert!(!run_npm(
            &tampered_stage,
            &tampered_cache,
            &tampered_home,
            &common_install_args(&tampered_stage, &tampered_cache)
        ));

        let config_stage = root.path().join("config-stage");
        fs::create_dir_all(&config_stage).expect("config stage");
        fs::write(
            config_stage.join(".npmrc"),
            b"registry=https://example.invalid\n",
        )
        .expect("project npmrc");
        let command = FixedCommandSpec {
            program: NPM_PROGRAM.to_string(),
            args: vec![
                "ci".to_string(),
                "--prefix".to_string(),
                config_stage.to_string_lossy().into_owned(),
                format!("--globalconfig={NPM_GLOBAL_CONFIG}"),
            ],
            environment: BTreeMap::new(),
            working_directory: root.path().to_string_lossy().into_owned(),
            timeout_ms: COMMAND_TIMEOUT_MS,
            env_clear: true,
        };
        let (result, spawn_calls) = run_npm_preflight_with_spawn_for_test(
            &command,
            &root.path().join("missing-global.npmrc"),
            root.path(),
        );
        assert_eq!(result, Err(LocalMcpAdapterError::StageLayout));
        assert_eq!(spawn_calls, 0);
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
    fn npm_view_literal_tarball_and_null_scripts_are_normalized() {
        let raw = json!({
            "version": "2.69.2",
            "dist.integrity": INTEGRITY,
            "dist.tarball": "https://registry.npmjs.org/n8n-mcp/-/n8n-mcp-2.69.2.tgz",
            "engines": {"node": ">=18.0.0"},
            "dependencies": {"zod": "^3.25.0"},
            "scripts": null
        });
        let parsed = parse_registry_metadata(&raw).expect("npm view output shape");
        assert_eq!(
            parsed.registry_tarball_url,
            raw["dist.tarball"].as_str().expect("tarball string")
        );
        assert!(parsed.lifecycle_scripts_digest.starts_with("blake3-256:"));
    }

    #[test]
    fn registry_range_array_selects_highest_matching_concrete_version() {
        let output = json!([
            {
                "version": "3.25.0",
                "dist.integrity": INTEGRITY,
                "dist.tarball": "https://registry.npmjs.org/zod/-/zod-3.25.0.tgz",
                "dependencies": {}
            },
            {
                "version": "3.27.1",
                "dist.integrity": INTEGRITY,
                "dist.tarball": "https://registry.npmjs.org/zod/-/zod-3.27.1.tgz",
                "dependencies": {}
            },
            {
                "version": "4.0.0",
                "dist.integrity": INTEGRITY,
                "dist.tarball": "https://registry.npmjs.org/zod/-/zod-4.0.0.tgz",
                "dependencies": {}
            }
        ]);
        let selected =
            resolve_registry_view_metadata("zod", "^3.25.0", &output).expect("range metadata");
        assert_eq!(selected.version, "3.27.1");
        assert_eq!(
            selected.registry_tarball_url,
            "https://registry.npmjs.org/zod/-/zod-3.27.1.tgz"
        );
    }

    #[test]
    fn registry_range_object_map_is_normalized_to_concrete_versions() {
        let output = json!({
            "3.25.0": {
                "dist.integrity": INTEGRITY,
                "dist.tarball": "https://registry.npmjs.org/zod/-/zod-3.25.0.tgz",
                "dependencies": {}
            },
            "3.26.0": {
                "dist.integrity": INTEGRITY,
                "dist.tarball": "https://registry.npmjs.org/zod/-/zod-3.26.0.tgz",
                "dependencies": {}
            }
        });
        let selected = resolve_registry_view_metadata("zod", "^3.25.0", &output)
            .expect("object range metadata");
        assert_eq!(selected.version, "3.26.0");
    }

    #[test]
    fn ordinary_npm_semver_ranges_are_accepted_and_matched() {
        for (spec, version, expected) in [
            ("^1.2", "1.9.0", true),
            ("~1.2", "1.2.9", true),
            (">=1.0.0 <2", "1.8.0", true),
            ("1.2.x", "1.2.7", true),
            ("*", "9.0.0", true),
            ("1.2", "1.3.0", false),
            ("1.2.3 - 2.0.0", "2.1.0", false),
        ] {
            assert!(
                validate_registry_dependency_spec(spec).is_ok(),
                "range syntax rejected: {spec}"
            );
            assert_eq!(
                dependency_spec_allows_version(spec, version),
                expected,
                "{spec}"
            );
        }
    }

    #[test]
    fn npm_semver_handles_prerelease_build_partial_and_hyphen_ranges() {
        for (spec, version, expected) in [
            ("^1.2.3-beta.1", "1.2.3-beta.2", true),
            ("^1.2.3-beta.1", "1.2.4-alpha.1", false),
            ("1.2.3+build.7", "1.2.3+build.99", true),
            ("1.2.3 - 2.0", "2.0.9", true),
            ("1.2.3 - 2.0", "2.1.0", false),
            (">=1.2.3-beta.1 <2.0.0", "1.2.3-beta.2", true),
            (">=1.2.3-beta.1 <2.0.0", "1.2.4-alpha.1", false),
            ("^0.0.3", "0.0.3", true),
            ("^0.0.3", "0.0.4", false),
        ] {
            assert!(
                validate_registry_dependency_spec(spec).is_ok(),
                "range syntax rejected: {spec}"
            );
            assert_eq!(
                dependency_spec_allows_version(spec, version),
                expected,
                "unexpected npm range result for {spec} / {version}"
            );
        }
        for version in ["1.2.3-01", "01.2.3", "1.2.3+", "1.2.3-"] {
            assert!(
                validate_exact_npm_version(version).is_err(),
                "accepted {version}"
            );
        }
    }

    #[test]
    fn npm_semver_excludes_prerelease_at_upper_bound_but_keeps_explicit_prereleases() {
        for spec in ["^1.2.3", ">=1.2.3 <2.0.0"] {
            assert!(
                validate_registry_dependency_spec(spec).is_ok(),
                "range syntax rejected: {spec}"
            );
            assert!(
                !dependency_spec_allows_version(spec, "2.0.0-alpha.1"),
                "{spec} must exclude a prerelease at its 2.0.0 upper boundary"
            );
        }

        let caret = parse_npm_range("^1.2.3").expect("caret range");
        assert_eq!(
            caret[0][1].version,
            npm_prerelease_upper(2, 0, 0),
            "npm caret upper bounds use the lowest prerelease"
        );
        assert!(dependency_spec_allows_version(
            "^1.2.3-beta.1",
            "1.2.3-beta.2"
        ));
    }

    #[test]
    fn npm_semver_comparators_preserve_full_version_bounds() {
        for (spec, version, expected) in [
            (">1.2.3", "1.2.3", false),
            (">1.2.3", "1.2.4", true),
            ("<=1.2.3", "1.2.3", true),
            ("<=1.2.3", "1.2.4", false),
            ("<1.2.3", "1.2.2", true),
            ("<1.2.3", "1.2.3", false),
            (">=1.2.3", "1.2.3", true),
            (">=1.2.3", "1.2.2", false),
            ("<=1.2", "1.2.99", true),
            ("<=1.2", "1.3.0", false),
            (">1.2", "1.3.0", true),
            (">1.2", "1.2.99", false),
        ] {
            assert!(
                validate_registry_dependency_spec(spec).is_ok(),
                "range syntax rejected: {spec}"
            );
            assert_eq!(
                dependency_spec_allows_version(spec, version),
                expected,
                "unexpected npm range result for {spec} / {version}"
            );
        }
    }

    #[test]
    fn npm_semver_partial_greater_ranges_exclude_boundary_prereleases() {
        for (spec, version, expected) in [
            (">1", "2.0.0-alpha.1", false),
            (">1", "2.0.0", true),
            (">1.2", "1.3.0-alpha.1", false),
            (">1.2", "1.3.0", true),
        ] {
            assert_eq!(
                dependency_spec_allows_version(spec, version),
                expected,
                "unexpected npm range result for {spec} / {version}"
            );
        }
    }

    #[test]
    fn optional_peer_metadata_is_normalized_and_platform_constraints_are_bound() {
        let mut raw = json!({
            "version": "3.25.0",
            "dist.integrity": INTEGRITY,
            "dist.tarball": "https://registry.npmjs.org/optional-package/-/optional-package-3.25.0.tgz",
            "dependencies": {},
            "optionalDependencies": {"platform-only": "1.0.0"},
            "peerDependencies": {"peer-package": "^2.0.0", "optional-peer": "^3.0.0"},
            "peerDependenciesMeta": {"optional-peer": {"optional": true}},
            "os": ["darwin"],
            "cpu": ["x64"]
        });
        let metadata = registry_package_metadata("optional-package", &raw)
            .expect("optional and peer metadata");
        assert_eq!(
            metadata.peer_dependencies_meta.get("optional-peer"),
            Some(&true)
        );
        assert!(!metadata.peer_dependencies_meta.contains_key("peer-package"));
        assert_eq!(metadata.os, vec!["darwin"]);
        assert_eq!(metadata.cpu, vec!["x64"]);
        assert!(metadata.dependency_edges().iter().any(|edge| {
            edge.name == "optional-peer"
                && edge.kind == RegistryDependencyKind::Peer
                && edge.optional
        }));
        assert!(metadata.dependency_edges().iter().any(|edge| {
            edge.name == "platform-only"
                && edge.kind == RegistryDependencyKind::Optional
                && edge.optional
        }));

        raw["peerDependenciesMeta"]["peer-package"] = json!({"optional": "yes"});
        assert!(registry_package_metadata("optional-package", &raw).is_err());
    }

    #[test]
    fn frozen_lock_platform_constraints_require_strict_two_way_equality() {
        let selected = registry_package_metadata(
            "platform-package",
            &json!({
                "version": "1.0.0",
                "dist.integrity": INTEGRITY,
                "dist.tarball": "https://registry.npmjs.org/platform-package/-/platform-package-1.0.0.tgz",
                "dependencies": {},
                "os": ["linux"],
                "cpu": ["x64"]
            }),
        )
        .expect("selected platform metadata");
        let mut missing_constraints = registry_lock_package_record(&selected)
            .as_object()
            .expect("lock record")
            .clone();
        missing_constraints.remove("os");
        missing_constraints.remove("cpu");
        assert!(matches!(
            validate_lock_record_against_selected(&missing_constraints, &selected),
            Err(LocalMcpAdapterError::StageMismatch(
                "lock_manifest_platform_mismatch"
            ))
        ));

        let unconstrained = registry_package_metadata(
            "platform-package",
            &json!({
                "version": "1.0.0",
                "dist.integrity": INTEGRITY,
                "dist.tarball": "https://registry.npmjs.org/platform-package/-/platform-package-1.0.0.tgz",
                "dependencies": {}
            }),
        )
        .expect("unconstrained metadata");
        let constrained_record = registry_lock_package_record(&selected);
        assert!(matches!(
            validate_lock_record_against_selected(
                constrained_record.as_object().expect("lock record"),
                &unconstrained,
            ),
            Err(LocalMcpAdapterError::StageMismatch(
                "lock_manifest_platform_mismatch"
            ))
        ));
    }

    #[test]
    fn frozen_lock_is_materialized_from_exact_registry_graph_and_placement() {
        let root = registry_package_metadata(PACKAGE_NAME, &metadata_value("2.69.2"))
            .expect("root metadata");
        let zod = registry_package_metadata(
            "zod",
            &json!({
                "version": "3.25.0",
                "dist.integrity": INTEGRITY,
                "dist.tarball": "https://registry.npmjs.org/zod/-/zod-3.25.0.tgz",
                "dependencies": {}
            }),
        )
        .expect("zod metadata");
        let edge = RegistryClosureEdge {
            source_package_name: PACKAGE_NAME.to_string(),
            source_version: root.version.clone(),
            dependency_name: "zod".to_string(),
            dependency_spec: "^3.25.0".to_string(),
            dependency_kind: "dependencies".to_string(),
            optional: false,
            target_version: zod.version.clone(),
            target_integrity: zod.integrity.clone(),
            target_registry_tarball_url: zod.registry_tarball_url.clone(),
        };
        let closure = RegistryClosure {
            packages: vec![root.clone(), zod],
            edges: vec![edge],
            digest: "blake3-256:test".to_string(),
        };
        let lock = build_frozen_install_lock(&root, &closure).expect("frozen lock");
        let packages = lock["packages"].as_object().expect("lock packages");
        assert!(packages.contains_key(""));
        assert!(packages.contains_key("node_modules/n8n-mcp"));
        assert!(packages.contains_key("node_modules/zod"));
        assert_eq!(
            packages["node_modules/zod"]["resolved"],
            "https://registry.npmjs.org/zod/-/zod-3.25.0.tgz"
        );
        assert_eq!(packages["node_modules/zod"]["integrity"], INTEGRITY);
        assert_eq!(packages[""]["dependencies"][PACKAGE_NAME], "2.69.2");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn staged_plan_returns_redacted_receipt_through_command_and_stage_seams() {
        use base64::Engine;
        use sha2::{Digest, Sha512};

        let artifact_bytes = b"bounded test tarball bytes".to_vec();
        let integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&artifact_bytes))
        );
        let mut raw = metadata_value("2.69.2");
        raw["dist.integrity"] = Value::String(integrity.clone());
        let metadata_output = serde_json::to_vec(&raw).expect("metadata output");
        let (_root, fixture_plan, fixture_metadata, owner) = staged_fixture();
        let verified =
            verify_local_mcp_stage_for_owner(&fixture_plan, &fixture_metadata, Vec::new(), owner)
                .expect("verified fixture");
        let mut root_manifest = raw.clone();
        root_manifest["name"] = Value::String(PACKAGE_NAME.to_string());
        root_manifest["bin"] = json!({PACKAGE_NAME: "./dist/mcp/stdio-wrapper.js"});
        let mut stage_io = MockStageIo {
            verified: Some(verified),
            packed_artifact: Some(TrustedLocalMcpArtifact {
                version: "2.69.2".to_string(),
                bytes: artifact_bytes,
                manifest: Some(root_manifest),
            }),
            ..MockStageIo::default()
        };
        let mut command_runner = MockCommandRunner {
            metadata: metadata_output,
            ..MockCommandRunner::default()
        };
        let receipt = stage_exact_local_mcp_with("2.69.2", &mut command_runner, &mut stage_io)
            .expect("successful staged review");
        assert_eq!(receipt.status, "verified");
        assert_eq!(receipt.registry_integrity, integrity);
        assert_eq!(receipt.version, "2.69.2");
        assert_eq!(receipt.registry_closure_packages.len(), 2);
        assert!(receipt.registry_closure_digest.starts_with("blake3-256:"));
        assert!(receipt.receipt_path.starts_with(STAGING_ROOT));
        assert_eq!(command_runner.calls.len(), 7);
        assert_eq!(command_runner.calls[0][0], "view");
        assert_eq!(command_runner.calls[1][0], "view");
        assert_eq!(command_runner.calls[2][0], "pack");
        assert_eq!(command_runner.calls[3][0], "cache");
        assert_eq!(command_runner.calls[4][0], "pack");
        assert_eq!(command_runner.calls[5][0], "cache");
        assert_eq!(command_runner.calls[6][0], "ci");
        assert!(
            command_runner.calls[..6]
                .iter()
                .all(|args| args.first().is_some_and(|arg| arg != "install"))
        );
        assert!(command_runner.calls[6].contains(&"--offline".to_string()));
        assert!(command_runner.calls[6].contains(&"--cache".to_string()));
        let encoded = serde_json::to_string(&receipt).expect("receipt encoding");
        assert!(!encoded.contains("UNTRUSTED-COMMAND-CANARY"));
        assert!(!encoded.contains("stderr"));
        assert_eq!(stage_io.persisted_receipt, Some(receipt));
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

    #[test]
    fn registry_manifest_disagreement_fails_before_install() {
        let metadata_value = metadata_value("2.69.2");
        let metadata = registry_package_metadata(PACKAGE_NAME, &metadata_value)
            .expect("selected registry metadata");
        let mut manifest = metadata_value;
        manifest["name"] = Value::String(PACKAGE_NAME.to_string());
        assert!(validate_selected_registry_manifest(&manifest, &metadata).is_ok());

        let mut changed_dependencies = manifest.clone();
        changed_dependencies["dependencies"]["zod"] = Value::String("^4.0.0".to_string());
        assert!(validate_selected_registry_manifest(&changed_dependencies, &metadata).is_err());

        let mut published_override = manifest;
        published_override["overrides"] = json!({});
        assert!(validate_selected_registry_manifest(&published_override, &metadata).is_err());
    }

    #[test]
    fn non_registry_dependency_specs_are_rejected_before_npm_install() {
        for spec in [
            "file:../outside",
            "link:../outside",
            "git+https://github.com/example/dependency.git",
            "git://github.com/example/dependency.git",
            "ssh://git@github.com/example/dependency.git",
            "git@github.com:example/dependency.git",
            "https://example.invalid/dependency.tgz",
            "http://example.invalid/dependency.tgz",
            "github:example/dependency",
            "npm:other-package@1.0.0",
        ] {
            let mut raw = metadata_value("2.69.2");
            raw["dependencies"]["zod"] = Value::String(spec.to_string());
            assert!(
                parse_registry_metadata(&raw).is_err(),
                "non-registry dependency spec accepted: {spec}"
            );
        }
    }

    #[test]
    fn nested_non_registry_dependency_specs_are_rejected_before_pack_or_install() {
        fn nested_metadata(
            package_name: &str,
            version: &str,
            field: &str,
            dependency_name: &str,
            spec: &str,
        ) -> Vec<u8> {
            let mut value = json!({
                "version": version,
                "dist.integrity": INTEGRITY,
                "dist.tarball": format!(
                    "https://registry.npmjs.org/{package_name}/-/{package_name}-{version}.tgz"
                ),
                "dependencies": {}
            });
            value[field][dependency_name] = Value::String(spec.to_string());
            serde_json::to_vec(&value).expect("nested metadata")
        }

        let cases = [
            (
                "optional-file",
                vec![nested_metadata(
                    "zod",
                    "3.25.0",
                    "optionalDependencies",
                    "evil",
                    "file:../outside",
                )],
            ),
            (
                "peer-url",
                vec![nested_metadata(
                    "zod",
                    "3.25.0",
                    "peerDependencies",
                    "evil",
                    "https://example.invalid/dependency.tgz",
                )],
            ),
            (
                "transitive-git",
                vec![
                    nested_metadata("zod", "3.25.0", "dependencies", "transitive", "1.0.0"),
                    nested_metadata(
                        "transitive",
                        "1.0.0",
                        "dependencies",
                        "evil",
                        "git+https://github.com/example/evil.git",
                    ),
                ],
            ),
            (
                "transitive-ssh",
                vec![
                    nested_metadata("zod", "3.25.0", "dependencies", "transitive", "1.0.0"),
                    nested_metadata(
                        "transitive",
                        "1.0.0",
                        "dependencies",
                        "evil",
                        "ssh://git@example.invalid/evil.git",
                    ),
                ],
            ),
        ];

        for (label, nested) in cases {
            let mut command_runner = ClosureCommandRunner {
                root: serde_json::to_vec(&metadata_value("2.69.2")).expect("root metadata"),
                nested,
                calls: Vec::new(),
            };
            let mut stage_io = MockStageIo::default();
            let result = stage_exact_local_mcp_with("2.69.2", &mut command_runner, &mut stage_io);
            assert!(result.is_err(), "nested source accepted: {label}");
            assert!(stage_io.calls.is_empty(), "stage created for {label}");
            assert!(
                command_runner
                    .calls
                    .iter()
                    .all(|args| args.first().map(String::as_str) == Some("view")),
                "pack/install reached for {label}"
            );
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
                "": {
                    "name": LOCK_PROJECT_NAME,
                    "version": LOCK_PROJECT_VERSION,
                    "private": true,
                    "dependencies": {"n8n-mcp": "2.69.2"}
                },
                "node_modules/n8n-mcp": {
                    "version": "2.69.2",
                    "resolved": "https://registry.npmjs.org/n8n-mcp/-/n8n-mcp-2.69.2.tgz",
                    "integrity": "sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==",
                    "dependencies": {"zod": "^3.25.0"}
                },
                "node_modules/zod": {
                    "version": "3.25.0",
                    "resolved": "https://registry.npmjs.org/zod/-/zod-3.25.0.tgz",
                    "integrity": INTEGRITY
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
    fn lock_validation_rejects_incomplete_extra_malformed_and_non_registry_closure() {
        for mutation in ["missing", "extra", "malformed", "integrity", "non_registry"] {
            let (_root, plan, metadata, owner) = staged_fixture();
            let stage_root = Path::new(plan.stage_root());
            let stage_fd = open_stage_root(stage_root, owner).expect("open stage root");
            let tree = hash_stage_tree(stage_root, &stage_fd, owner).expect("hash stage");
            let mut lock: Value = serde_json::from_slice(
                &fs::read(plan.package_lock_path()).expect("read package lock"),
            )
            .expect("decode package lock");
            let packages = lock["packages"].as_object_mut().expect("packages object");
            match mutation {
                "missing" => {
                    packages.remove("node_modules/zod");
                }
                "extra" => {
                    packages.insert(
                        "node_modules/extra".to_string(),
                        json!({
                            "version": "1.0.0",
                            "resolved": "https://registry.npmjs.org/extra/-/extra-1.0.0.tgz",
                            "integrity": INTEGRITY
                        }),
                    );
                }
                "malformed" => {
                    packages.insert("node_modules/zod".to_string(), json!("not-a-record"));
                }
                "integrity" => {
                    packages.get_mut("node_modules/zod").expect("zod record")["integrity"] =
                        Value::String("sha1-weak".to_string());
                }
                "non_registry" => {
                    packages.get_mut("node_modules/zod").expect("zod record")["resolved"] =
                        Value::String("git+https://github.com/example/zod.git".to_string());
                }
                _ => unreachable!(),
            }
            assert!(
                validate_installed_package_lock(&lock, &metadata, "2.69.2", &tree).is_err(),
                "lock mutation accepted: {mutation}"
            );
        }
    }

    #[test]
    fn frozen_closure_rejects_nested_lock_edge_retargeting() {
        let root_metadata =
            parse_registry_metadata(&metadata_value("2.69.2")).expect("root metadata");
        let root = registry_package_metadata(PACKAGE_NAME, &metadata_value("2.69.2"))
            .expect("root selected metadata");
        let zod_value = json!({
            "version": "3.25.0",
            "dist.integrity": INTEGRITY,
            "dist.tarball": "https://registry.npmjs.org/zod/-/zod-3.25.0.tgz",
            "dependencies": {"evil": "^1.0.0"}
        });
        let evil_value = |version: &str| {
            json!({
                "version": version,
                "dist.integrity": INTEGRITY,
                "dist.tarball": format!(
                    "https://registry.npmjs.org/evil/-/evil-{version}.tgz"
                ),
                "dependencies": {}
            })
        };
        let zod = registry_package_metadata("zod", &zod_value).expect("zod metadata");
        let evil_selected =
            registry_package_metadata("evil", &evil_value("1.0.0")).expect("evil metadata");
        let evil_retarget =
            registry_package_metadata("evil", &evil_value("1.1.0")).expect("retarget metadata");
        let root_zod = RegistryClosureEdge {
            source_package_name: PACKAGE_NAME.to_string(),
            source_version: root.version.clone(),
            dependency_name: "zod".to_string(),
            dependency_spec: "^3.25.0".to_string(),
            dependency_kind: "dependencies".to_string(),
            optional: false,
            target_version: zod.version.clone(),
            target_integrity: zod.integrity.clone(),
            target_registry_tarball_url: zod.registry_tarball_url.clone(),
        };
        let zod_evil = RegistryClosureEdge {
            source_package_name: "zod".to_string(),
            source_version: zod.version.clone(),
            dependency_name: "evil".to_string(),
            dependency_spec: "^1.0.0".to_string(),
            dependency_kind: "dependencies".to_string(),
            optional: false,
            target_version: evil_selected.version.clone(),
            target_integrity: evil_selected.integrity.clone(),
            target_registry_tarball_url: evil_selected.registry_tarball_url.clone(),
        };
        let closure = RegistryClosure {
            packages: vec![root, zod, evil_selected, evil_retarget],
            edges: vec![root_zod, zod_evil],
            digest: "blake3-256:test".to_string(),
        };
        let lock = json!({
            "lockfileVersion": 3,
            "packages": {
                "": {
                    "name": LOCK_PROJECT_NAME,
                    "version": LOCK_PROJECT_VERSION,
                    "private": true,
                    "dependencies": {"n8n-mcp": "2.69.2"}
                },
                "node_modules/n8n-mcp": {
                    "version": "2.69.2",
                    "resolved": "https://registry.npmjs.org/n8n-mcp/-/n8n-mcp-2.69.2.tgz",
                    "integrity": INTEGRITY,
                    "dependencies": {"zod": "^3.25.0"}
                },
                "node_modules/zod": {
                    "version": "3.25.0",
                    "resolved": "https://registry.npmjs.org/zod/-/zod-3.25.0.tgz",
                    "integrity": INTEGRITY,
                    "dependencies": {"evil": "^1.0.0"}
                },
                "node_modules/evil": {
                    "version": "1.1.0",
                    "resolved": "https://registry.npmjs.org/evil/-/evil-1.1.0.tgz",
                    "integrity": INTEGRITY
                }
            }
        });
        let tree = StageTreeDigest {
            digest: "blake3-256:tree".to_string(),
            entry_count: 0,
            total_bytes: 0,
            directories: BTreeSet::from([
                "node_modules".to_string(),
                "node_modules/n8n-mcp".to_string(),
                "node_modules/zod".to_string(),
                "node_modules/evil".to_string(),
            ]),
            files: BTreeMap::new(),
        };
        assert!(matches!(
            validate_installed_package_lock_with_closure(
                &lock,
                &root_metadata,
                "2.69.2",
                &tree,
                Some(&closure),
            ),
            Err(LocalMcpAdapterError::StageMismatch(
                "lock_dependency_selection_mismatch"
            ))
        ));
    }

    #[test]
    fn optional_dependency_omission_requires_platform_or_optional_peer_justification() {
        let target_value = json!({
            "version": "1.0.0",
            "dist.integrity": INTEGRITY,
            "dist.tarball": "https://registry.npmjs.org/platform-only/-/platform-only-1.0.0.tgz",
            "dependencies": {},
            "os": ["darwin"]
        });
        let target = registry_package_metadata("platform-only", &target_value)
            .expect("platform target metadata");
        let optional_edge = RegistryClosureEdge {
            source_package_name: PACKAGE_NAME.to_string(),
            source_version: "2.69.2".to_string(),
            dependency_name: "platform-only".to_string(),
            dependency_spec: "1.0.0".to_string(),
            dependency_kind: "optionalDependencies".to_string(),
            optional: true,
            target_version: "1.0.0".to_string(),
            target_integrity: INTEGRITY.to_string(),
            target_registry_tarball_url:
                "https://registry.npmjs.org/platform-only/-/platform-only-1.0.0.tgz".to_string(),
        };
        assert!(optional_edge_omission_is_allowed(&optional_edge, &target));
        let required_edge = RegistryClosureEdge {
            optional: false,
            dependency_kind: "dependencies".to_string(),
            ..optional_edge.clone()
        };
        assert!(!optional_edge_omission_is_allowed(&required_edge, &target));
        let optional_peer_edge = RegistryClosureEdge {
            dependency_kind: "peerDependencies".to_string(),
            ..optional_edge
        };
        assert!(optional_edge_omission_is_allowed(
            &optional_peer_edge,
            &target
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cold_cache_stage_rejects_missing_or_tampered_frozen_artifact_before_install() {
        let mut command_runner = MockCommandRunner {
            metadata: serde_json::to_vec(&metadata_value("2.69.2")).expect("metadata output"),
            ..MockCommandRunner::default()
        };
        let mut stage_io = MockStageIo::default();
        let result = stage_exact_local_mcp_with("2.69.2", &mut command_runner, &mut stage_io);
        assert!(matches!(
            result,
            Err(LocalMcpAdapterError::StageMismatch("missing_mock_artifact"))
        ));
        assert_eq!(stage_io.calls, ["create", "pack", "discard"]);
        assert!(
            !command_runner
                .calls
                .iter()
                .any(|args| args.first().map(String::as_str) == Some("install"))
        );
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
        packed_artifact: Option<TrustedLocalMcpArtifact>,
        persisted_receipt: Option<LocalMcpVerificationReceipt>,
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

        fn materialize_packed_artifact(
            &mut self,
            _plan: &LocalMcpStagePlan,
        ) -> Result<TrustedLocalMcpArtifact, LocalMcpAdapterError> {
            self.calls.push("pack");
            self.packed_artifact
                .take()
                .ok_or(LocalMcpAdapterError::StageMismatch("missing_mock_artifact"))
        }

        fn materialize_packed_artifact_for(
            &mut self,
            plan: &LocalMcpStagePlan,
            package_name: &str,
            version: &str,
        ) -> Result<TrustedLocalMcpArtifact, LocalMcpAdapterError> {
            self.calls.push("pack");
            if package_name == PACKAGE_NAME && version == plan.exact_version() {
                return self
                    .packed_artifact
                    .take()
                    .ok_or(LocalMcpAdapterError::StageMismatch("missing_mock_artifact"));
            }
            Ok(TrustedLocalMcpArtifact {
                version: version.to_string(),
                bytes: b"bounded test tarball bytes".to_vec(),
                manifest: Some(json!({
                    "name": package_name,
                    "version": version,
                    "dependencies": {},
                    "scripts": {}
                })),
            })
        }

        fn reverify(
            &mut self,
            plan: &LocalMcpStagePlan,
            _metadata: &LocalMcpRegistryMetadata,
            _tools: Vec<ToolSnapshot>,
        ) -> Result<VerifiedLocalMcpStage, LocalMcpAdapterError> {
            self.calls.push("reverify");
            if let Some(error) = self.reverify_error.take() {
                return Err(error);
            }
            let mut verified = self
                .verified
                .take()
                .ok_or(LocalMcpAdapterError::StageMismatch(
                    "missing_mock_verification",
                ))?;
            verified.stage_id = plan.stage_id().to_string();
            Ok(verified)
        }

        fn persist_verification_receipt(
            &mut self,
            _plan: &LocalMcpStagePlan,
            receipt: &LocalMcpVerificationReceipt,
        ) -> Result<(), LocalMcpAdapterError> {
            self.persisted_receipt = Some(receipt.clone());
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockCommandRunner {
        metadata: Vec<u8>,
        calls: Vec<Vec<String>>,
    }

    impl LocalMcpCommandRunner for MockCommandRunner {
        fn run(&mut self, command: &FixedCommandSpec) -> Result<Vec<u8>, LocalMcpAdapterError> {
            self.calls.push(command.args.clone());
            if command.args.first().map(String::as_str) == Some("view") {
                if command
                    .args
                    .get(1)
                    .is_some_and(|spec| spec.starts_with("n8n-mcp@"))
                {
                    Ok(self.metadata.clone())
                } else {
                    let root = serde_json::from_slice::<Value>(&self.metadata)
                        .expect("root metadata fixture");
                    Ok(serde_json::to_vec(&json!({
                        "version": "3.25.0",
                        "dist.integrity": root["dist.integrity"].clone(),
                        "dist.tarball":
                            "https://registry.npmjs.org/zod/-/zod-3.25.0.tgz"
                    }))
                    .expect("nested metadata"))
                }
            } else {
                Ok(Vec::new())
            }
        }
    }

    struct ClosureCommandRunner {
        root: Vec<u8>,
        nested: Vec<Vec<u8>>,
        calls: Vec<Vec<String>>,
    }

    impl LocalMcpCommandRunner for ClosureCommandRunner {
        fn run(&mut self, command: &FixedCommandSpec) -> Result<Vec<u8>, LocalMcpAdapterError> {
            self.calls.push(command.args.clone());
            if command.args.first().map(String::as_str) != Some("view") {
                return Err(LocalMcpAdapterError::StageMismatch("unexpected_npm_fetch"));
            }
            let view_count = self
                .calls
                .iter()
                .filter(|args| args.first().map(String::as_str) == Some("view"))
                .count();
            if view_count == 1 {
                Ok(self.root.clone())
            } else {
                self.nested
                    .get(view_count - 2)
                    .cloned()
                    .ok_or(LocalMcpAdapterError::StageMismatch(
                        "missing_nested_metadata",
                    ))
            }
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
            entrypoint: "node_modules/n8n-mcp/dist/mcp/stdio-wrapper.js".to_string(),
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
        let published_lockfile =
            b"drwxr-xr-x 0/0 0 2026-08-19 00:00 package\n-rw-r--r-- 0/0 1 2026-08-19 00:00 package/npm-shrinkwrap.json";
        assert!(validate_registry_archive_listing(published_lockfile).is_err());
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

    #[cfg(unix)]
    #[test]
    fn artifact_extract_timeout_terminates_descendants_that_hold_output_pipes() {
        use std::os::unix::process::CommandExt;

        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30 & wait"])
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().expect("spawn process-tree fixture");
        let mut stdout = child.stdout.take().expect("child stdout");
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).expect("read child stdout");
        });
        let started = Instant::now();
        assert_eq!(
            wait_child_until(
                &mut child,
                started + Duration::from_millis(20),
                "artifact_extract_timeout",
            ),
            Err(LocalMcpAdapterError::StageMismatch(
                "artifact_extract_timeout",
            ))
        );
        reader.join().expect("descendant output pipe closed");
        assert!(started.elapsed() < Duration::from_secs(2));
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
