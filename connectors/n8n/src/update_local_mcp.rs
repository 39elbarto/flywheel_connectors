//! Closed update adapter contract for the local `n8n-mcp` npm package.
//!
//! This module constructs only fixed `npm` command specifications and converts
//! allowlisted registry metadata into the generic review snapshot. It never
//! executes a shell, accepts a caller-supplied path, or activates a package.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::update::{
    ComponentSnapshot, ProvenanceSnapshot, ToolSnapshot, UpdateComponent, UpdateError,
};

const NPM_PROGRAM: &str = "/usr/bin/npm";
const PACKAGE_NAME: &str = "n8n-mcp";
const STAGING_ROOT: &str = "/var/lib/fwc-n8n/update-staging/local-n8n-mcp";
const NPM_HOME: &str = "/var/lib/fwc-n8n/npm-home";
const NPM_CACHE: &str = "/var/cache/fwc-n8n/npm";
const MAX_VERSION_BYTES: usize = 96;
const COMMAND_TIMEOUT_MS: u64 = 180_000;

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
    pub component: UpdateComponent,
    pub exact_version: String,
    pub stage_root: String,
    pub package_json_path: String,
    pub package_lock_path: String,
    pub install: FixedCommandSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalMcpRegistryMetadata {
    pub version: String,
    pub integrity: String,
    pub engine_requirement: String,
    pub dependencies: BTreeMap<String, String>,
    pub lifecycle_scripts_digest: String,
    pub metadata_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalMcpAdapterError {
    InvalidVersion,
    InvalidMetadata(&'static str),
    Encoding,
    Snapshot(UpdateError),
}

impl std::fmt::Display for LocalMcpAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::InvalidVersion => "invalid_version",
            Self::InvalidMetadata(code) => code,
            Self::Encoding => "encoding_failed",
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
    validate_exact_npm_version(version)?;
    let stage_root = format!("{STAGING_ROOT}/{version}");
    let package_spec = format!("{PACKAGE_NAME}@{version}");
    Ok(LocalMcpStagePlan {
        component: UpdateComponent::LocalN8nMcp,
        exact_version: version.to_string(),
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
            working_directory: STAGING_ROOT.to_string(),
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
        "engineRequirement": engine_requirement,
        "dependencies": dependencies,
        "lifecycleScriptsDigest": lifecycle_scripts_digest,
    });
    let metadata_digest = canonical_digest(&safe_metadata)?;
    Ok(LocalMcpRegistryMetadata {
        version: version.to_string(),
        integrity: integrity.to_string(),
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

fn npm_view_plan(version: &str) -> FixedCommandSpec {
    FixedCommandSpec {
        program: NPM_PROGRAM.to_string(),
        args: vec![
            "view".to_string(),
            format!("{PACKAGE_NAME}@{version}"),
            "version".to_string(),
            "dist.integrity".to_string(),
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

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, LocalMcpAdapterError> {
    let bytes = serde_json::to_vec(value).map_err(|_| LocalMcpAdapterError::Encoding)?;
    Ok(format!("blake3-256:{}", blake3::hash(&bytes).to_hex()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::ToolImpact;

    const INTEGRITY: &str = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    fn metadata_value(version: &str) -> Value {
        json!({
            "version": version,
            "dist.integrity": INTEGRITY,
            "engines": {"node": ">=18.0.0"},
            "dependencies": {"zod": "^3.25.0"},
            "scripts": {"postinstall": "UNTRUSTED-COMMAND-CANARY"},
            "releaseNotes": "UNTRUSTED-INSTRUCTION-CANARY"
        })
    }

    #[test]
    fn stage_plan_has_only_fixed_program_paths_environment_and_flags() {
        let plan = local_mcp_stage_plan("2.69.2").unwrap();
        assert_eq!(plan.stage_root, format!("{STAGING_ROOT}/2.69.2"));
        assert_eq!(plan.install.program, NPM_PROGRAM);
        assert_eq!(plan.install.working_directory, STAGING_ROOT);
        assert_eq!(plan.install.environment, fixed_npm_environment());
        assert!(plan.install.env_clear);
        assert_eq!(
            plan.install.args,
            [
                "install",
                "--prefix",
                "/var/lib/fwc-n8n/update-staging/local-n8n-mcp/2.69.2",
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
}
