use std::collections::BTreeMap;

use fcp_manifest::{
    ConnectorManifest, LOCAL_MCP_CATALOG_TOOLS, LOCAL_MCP_METHODS, LocalMcpPolicy, ManifestError,
    local_mcp_schema_digest,
};
use serde_json::json;

#[test]
fn local_policy_is_strict_and_part_of_interface_hash() {
    let raw = manifest_toml();
    let unchecked = ConnectorManifest::parse_str_unchecked(&raw).expect("parse policy");
    let hash = unchecked.compute_interface_hash().expect("hash policy");
    let parsed = ConnectorManifest::parse_str(&raw.replace(PLACEHOLDER, &hash.to_string()))
        .expect("validated policy");
    let policy = parsed
        .security
        .as_ref()
        .and_then(|security| security.local_mcp.as_ref())
        .expect("local policy");
    assert_eq!(policy.callable_tools.len(), 7);

    let mut changed = parsed.clone();
    changed
        .security
        .as_mut()
        .expect("security")
        .local_mcp
        .as_mut()
        .expect("local policy")
        .max_sequential_calls += 1;
    assert_ne!(
        parsed.compute_interface_hash().expect("base hash"),
        changed.compute_interface_hash().expect("changed hash")
    );
}

#[test]
fn local_policy_rejects_unknown_fields_and_catalog_drift() {
    let unknown = manifest_toml().replace(
        "network_disabled = true",
        "network_disabled = true\nunknown_field = true",
    );
    assert!(matches!(
        ConnectorManifest::parse_str_unchecked(&unknown),
        Err(ManifestError::Toml(_))
    ));

    let mut policy = test_policy();
    policy.callable_tools.pop();
    assert!(matches!(
        policy.validate(),
        Err(ManifestError::Invalid { .. })
    ));
    let mut policy = test_policy();
    policy.idle_window_ms = 1;
    assert!(matches!(
        policy.validate(),
        Err(ManifestError::Invalid { .. })
    ));
}

#[test]
fn local_policy_rejects_secret_like_environment_keys() {
    let mut policy = test_policy();
    policy
        .fixed_env
        .insert("N8N_API_TOKEN".into(), "redacted".into());
    assert!(matches!(
        policy.validate(),
        Err(ManifestError::Invalid { .. })
    ));
}

#[test]
fn schema_digest_is_independent_of_object_key_order() {
    let left = json!({"type": "object", "properties": {"b": 2, "a": 1}});
    let right = json!({"properties": {"a": 1, "b": 2}, "type": "object"});
    assert_eq!(
        local_mcp_schema_digest(&left),
        local_mcp_schema_digest(&right)
    );
}

const PLACEHOLDER: &str =
    "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000";

fn test_policy() -> LocalMcpPolicy {
    LocalMcpPolicy {
        package_id: "czlonkowski/n8n-mcp".into(),
        package_version: semver::Version::new(2, 67, 2),
        launcher_path: "/usr/bin/node".into(),
        launcher_digest: "0".repeat(64),
        runtime_executable: "/usr/bin/node".into(),
        runtime_executable_digest: "0".repeat(64),
        package_metadata_path: "/usr/share/fcp/package.json".into(),
        package_metadata_digest: "0".repeat(64),
        protocol_version: "2024-11-05".into(),
        fixed_args: vec!["--stdio".into()],
        fixed_env: BTreeMap::new(),
        allowed_methods: LOCAL_MCP_METHODS
            .iter()
            .map(|value| (*value).into())
            .collect(),
        expected_catalog: LOCAL_MCP_CATALOG_TOOLS
            .iter()
            .map(|tool| ((*tool).into(), "0".repeat(64)))
            .collect(),
        callable_tools: LOCAL_MCP_CATALOG_TOOLS
            .iter()
            .map(|value| (*value).into())
            .collect(),
        max_frame_bytes: 64 * 1024,
        max_request_bytes: 64 * 1024,
        max_result_bytes: 64 * 1024,
        max_sequential_calls: 7,
        startup_timeout_ms: 5_000,
        request_timeout_ms: 5_000,
        shutdown_timeout_ms: 1_000,
        idle_window_ms: 0,
        network_disabled: true,
    }
}

fn manifest_toml() -> String {
    let policy = test_policy();
    let mut expected = String::new();
    for (tool, digest) in &policy.expected_catalog {
        expected.push_str(&format!("{tool} = \"{digest}\"\n"));
    }
    format!(
        r#"[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
max_datagram_bytes = 1200
interface_hash = "{PLACEHOLDER}"

[connector]
id = "fcp.local.mcp.test"
name = "Local MCP test"
version = "2026.1.0"
description = "Fixed local MCP policy test"
archetypes = ["operational"]
format = "native"

[zones]
home = "z:private"
allowed_sources = ["z:owner"]
allowed_targets = ["z:private"]
forbidden = ["z:public"]

[capabilities]
required = ["ipc.gateway"]
optional = []
forbidden = ["system.exec"]

[provides.operations.local_mcp]
description = "Fixed local MCP provider test"
capability = "ipc.gateway"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "best_effort"
input_schema = {{ type = "object" }}
output_schema = {{ type = "object" }}

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true

[security]
description_scan = "block"

[security.local_mcp]
package_id = "{package_id}"
package_version = "{package_version}"
launcher_path = "{launcher_path}"
launcher_digest = "{launcher_digest}"
runtime_executable = "{runtime_executable}"
runtime_executable_digest = "{runtime_executable_digest}"
package_metadata_path = "{package_metadata_path}"
package_metadata_digest = "{package_metadata_digest}"
protocol_version = "{protocol_version}"
fixed_args = ["--stdio"]
allowed_methods = ["initialize", "notifications/initialized", "tools/list", "tools/call"]
callable_tools = ["tools_documentation", "search_nodes", "get_node", "validate_node", "get_template", "search_templates", "validate_workflow"]
max_frame_bytes = 65536
max_request_bytes = 65536
max_result_bytes = 65536
max_sequential_calls = 7
startup_timeout_ms = 5000
request_timeout_ms = 5000
shutdown_timeout_ms = 1000
idle_window_ms = 0
network_disabled = true

[security.local_mcp.expected_catalog]
{expected}"#,
        package_id = policy.package_id,
        package_version = policy.package_version,
        launcher_path = policy.launcher_path,
        launcher_digest = policy.launcher_digest,
        runtime_executable = policy.runtime_executable,
        runtime_executable_digest = policy.runtime_executable_digest,
        package_metadata_path = policy.package_metadata_path,
        package_metadata_digest = policy.package_metadata_digest,
        protocol_version = policy.protocol_version,
        expected = expected,
    )
}
