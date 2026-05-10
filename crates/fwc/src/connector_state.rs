#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::too_many_lines
)]

//! Connector-state operator output helpers.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::readiness::{CommandAvailability, CommandEnvelope, DiscoveredConnector};

/// Stable schema version for `fwc connector state explain --json`.
pub const CONNECTOR_STATE_EXPLAIN_SCHEMA_VERSION: &str = "1.0.0";
/// Marker file proving a local connector-state directory is cache-only.
pub const CONNECTOR_STATE_CACHE_MARKER: &str = ".fcp-cache-only";

/// Inputs needed to produce connector-state explain JSON.
#[derive(Clone, Copy, Debug)]
pub struct ConnectorStateExplainRequest<'a> {
    /// Selector the operator typed on the command line.
    pub connector_selector: &'a str,
    /// Optional zone requested for zone-scoped cache inspection.
    pub zone: Option<&'a str>,
    /// Optional override for the local connector state root.
    pub state_root: Option<&'a Path>,
    /// Optional host endpoint supplied by the operator.
    pub explicit_host: Option<&'a str>,
}

/// Build the JSON payload emitted by `fwc connector state explain --json`.
#[must_use]
pub fn connector_state_explain_payload(
    connector: &DiscoveredConnector,
    request: &ConnectorStateExplainRequest<'_>,
) -> Value {
    let (state_root, state_root_source) = connector_state_root_for_explain(request.state_root);
    let connector_cache_dir =
        connector_state_cache_dir(&state_root, connector.detail.summary.id.as_str());
    let zone_cache_dir = request.zone.map(|zone| {
        connector_zone_state_cache_dir(&state_root, connector.detail.summary.id.as_str(), zone)
    });
    let mut warnings = Vec::new();
    let connector_marker_present =
        connector_state_cache_marker_present(&connector_cache_dir, &mut warnings);
    let zone_marker_present = zone_cache_dir
        .as_deref()
        .is_some_and(|path| connector_state_cache_marker_present(path, &mut warnings));
    let local_cache_present = connector_cache_dir.is_dir()
        || zone_cache_dir.as_deref().is_some_and(Path::is_dir)
        || connector_marker_present
        || zone_marker_present;
    let canonical_storage = if connector_marker_present || zone_marker_present {
        "mesh"
    } else {
        "local"
    };
    let zone_supported = request.zone.map(|zone| {
        connector
            .supported_zones
            .iter()
            .any(|candidate| candidate == zone)
    });

    if !connector_marker_present && !zone_marker_present {
        warnings.push(
            "No connector state cache marker was found, so this offline explanation treats the local state path as canonical until a host writes cache-only markers."
                .to_owned(),
        );
    }
    if matches!(zone_supported, Some(false)) {
        if let Some(zone) = request.zone {
            warnings.push(format!(
                "Workspace manifests do not declare zone `{zone}` for this connector."
            ));
        }
    }

    warnings.push(
        "Last canonical sequence and mesh replica count are not proven by local cache markers; they remain null until a host or mesh state route exposes them."
            .to_owned(),
    );
    if request
        .explicit_host
        .map(str::trim)
        .is_some_and(|host| !host.is_empty())
    {
        warnings.push(
            "`--host` was supplied, but this command currently reports local cache-marker evidence only because fcp-host does not expose a connector-state explain route yet."
                .to_owned(),
        );
    }

    let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "connector");
    let mut payload = json!({
        "status": "ok",
        "command": "connector",
        "subcommand": "state explain",
        "schema_version": CONNECTOR_STATE_EXPLAIN_SCHEMA_VERSION,
        "source": "local-cache-markers",
        "message": format!(
            "Explained connector state storage for `{}` from local cache markers and workspace manifests.",
            connector.slug
        ),
        "connector": {
            "requested_selector": request.connector_selector,
            "slug": &connector.slug,
            "canonical_id": &connector.detail.summary.id,
            "name": &connector.detail.summary.name,
            "version": &connector.detail.summary.version,
            "manifest_path": &connector.manifest_path,
        },
        "state_root": {
            "path": state_root.display().to_string(),
            "source": state_root_source,
        },
        "canonical_storage": canonical_storage,
        "last_canonical_seq": Value::Null,
        "mesh_replica_count": Value::Null,
        "local_cache_path": connector_cache_dir.display().to_string(),
        "local_cache_present": local_cache_present,
        "local_cache_marker_present": connector_marker_present,
        "cache_marker": {
            "filename": CONNECTOR_STATE_CACHE_MARKER,
            "path": connector_cache_dir
                .join(CONNECTOR_STATE_CACHE_MARKER)
                .display()
                .to_string(),
            "present": connector_marker_present,
        },
        "zone": {
            "requested": request.zone,
            "supported_by_manifest": zone_supported,
            "supported_zones": &connector.supported_zones,
            "local_cache_path": zone_cache_dir
                .as_ref()
                .map(|path| path.display().to_string()),
            "local_cache_marker_present": zone_marker_present,
        },
        "live_host": connector_state_explain_host_status(request.explicit_host),
        "evidence_handles": connector_state_explain_evidence_handles(
            connector,
            &connector_cache_dir,
            zone_cache_dir.as_deref(),
            connector_marker_present,
            zone_marker_present,
        ),
        "warnings": warnings,
        "next_actions": [
            format!("fwc connector state explain --connector {} --zone <zone> --json", connector.slug),
            format!("fwc mesh explain-availability {} --host <endpoint>", connector.slug),
            "Run a host-backed connector-state externalization E2E before treating mesh sequence or replica fields as proven.".to_owned(),
        ],
    });
    envelope.inject_into(&mut payload);
    payload
}

fn connector_state_root_for_explain(override_root: Option<&Path>) -> (PathBuf, &'static str) {
    if let Some(path) = override_root {
        return (path.to_path_buf(), "argument");
    }
    if let Some(path) = non_empty_os_env("FCP_CONNECTOR_STATE") {
        return (PathBuf::from(path), "env:FCP_CONNECTOR_STATE");
    }
    if let Some(path) = non_empty_os_env("FCP_CONFIG_DIR") {
        return (PathBuf::from(path).join("state"), "env:FCP_CONFIG_DIR");
    }
    if let Some(path) = non_empty_os_env("HOME") {
        return (PathBuf::from(path).join(".fcp").join("state"), "env:HOME");
    }
    (PathBuf::from(".fcp").join("state"), "relative-default")
}

fn non_empty_os_env(key: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(key).filter(|value| !value.is_empty())
}

fn connector_state_cache_dir(root: &Path, connector_id: &str) -> PathBuf {
    root.join(sanitize_connector_state_path_segment(connector_id))
        .join("cache")
}

fn connector_zone_state_cache_dir(root: &Path, connector_id: &str, zone: &str) -> PathBuf {
    connector_state_cache_dir(root, connector_id).join(sanitize_connector_state_path_segment(zone))
}

fn sanitize_connector_state_path_segment(value: &str) -> String {
    let segment = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if segment.is_empty() || segment == "." || segment == ".." {
        "_".to_owned()
    } else {
        segment
    }
}

fn connector_state_cache_marker_present(dir: &Path, warnings: &mut Vec<String>) -> bool {
    let marker_path = dir.join(CONNECTOR_STATE_CACHE_MARKER);
    match std::fs::metadata(&marker_path) {
        Ok(metadata) if metadata.is_file() => true,
        Ok(_) => {
            warnings.push(format!(
                "Connector state cache marker `{}` exists but is not a file.",
                marker_path.display()
            ));
            false
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            warnings.push(format!(
                "Failed to inspect connector state cache marker `{}`: {error}",
                marker_path.display()
            ));
            false
        }
    }
}

fn connector_state_explain_host_status(explicit_host: Option<&str>) -> Value {
    explicit_host
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map_or_else(
            || {
                json!({
                    "requested": false,
                    "state": "not-requested",
                    "route_available": false,
                })
            },
            |host| {
                json!({
                    "requested": true,
                    "endpoint_hash": sha256_prefixed(host.as_bytes()),
                    "state": "not-queried",
                    "route_available": false,
                    "reason": "fcp-host does not expose a connector-state explain route yet",
                })
            },
        )
}

fn connector_state_explain_evidence_handles(
    connector: &DiscoveredConnector,
    connector_cache_dir: &Path,
    zone_cache_dir: Option<&Path>,
    connector_marker_present: bool,
    zone_marker_present: bool,
) -> Vec<Value> {
    let mut handles = vec![
        json!({
            "kind": "workspace-manifest",
            "connector_id": &connector.detail.summary.id,
            "manifest_path": &connector.manifest_path,
        }),
        json!({
            "kind": "connector-state-cache-marker",
            "scope": "connector",
            "path": connector_cache_dir.join(CONNECTOR_STATE_CACHE_MARKER).display().to_string(),
            "present": connector_marker_present,
        }),
    ];
    if let Some(path) = zone_cache_dir {
        handles.push(json!({
            "kind": "connector-state-cache-marker",
            "scope": "zone",
            "path": path.join(CONNECTOR_STATE_CACHE_MARKER).display().to_string(),
            "present": zone_marker_present,
        }));
    }
    handles
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}
