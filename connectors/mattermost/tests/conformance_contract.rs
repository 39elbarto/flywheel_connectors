use std::collections::BTreeSet;

use fcp_mattermost::{MattermostConnector, error::MattermostError};
use fcp_prelude::{FcpError, IdempotencyClass, OperationInfo, RiskLevel, SafetyTier};
use serde_json::{Value, json};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

fn manifest() -> Result<toml::Table, String> {
    MANIFEST_TOML
        .parse::<toml::Table>()
        .map_err(|err| format!("mattermost manifest should parse as TOML: {err}"))
}

fn manifest_operations(
    manifest: &toml::Table,
) -> Result<&toml::map::Map<String, toml::Value>, String> {
    manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| "manifest should declare operation tables".to_owned())
}

fn manifest_operation_schema(
    manifest: &toml::Table,
    operation_id: &str,
    field: &str,
) -> Result<Value, String> {
    let schema = manifest_operations(manifest)?
        .get(operation_id)
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get(field))
        .ok_or_else(|| format!("{operation_id} should declare {field}"))?;
    if schema.as_table().is_none_or(toml::map::Map::is_empty) {
        return Err(format!(
            "{operation_id}.{field} should be a non-empty table"
        ));
    }
    serde_json::to_value(schema)
        .map_err(|err| format!("{operation_id}.{field} should convert to JSON: {err}"))
}

fn manifest_operation_ai_hints<'a>(
    manifest: &'a toml::Table,
    operation_id: &str,
) -> Result<&'a toml::map::Map<String, toml::Value>, String> {
    manifest_operations(manifest)?
        .get(operation_id)
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("ai_hints"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("{operation_id} should declare ai_hints"))
}

fn manifest_operation_network_constraints<'a>(
    manifest: &'a toml::Table,
    operation_id: &str,
) -> Result<&'a toml::map::Map<String, toml::Value>, String> {
    manifest_operations(manifest)?
        .get(operation_id)
        .and_then(toml::Value::as_table)
        .and_then(|operation| operation.get("network_constraints"))
        .and_then(toml::Value::as_table)
        .ok_or_else(|| format!("{operation_id} should declare network_constraints"))
}

fn string_array(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Vec<String>, String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{key} should be an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} entries should be strings"))
        })
        .collect()
}

fn integer_array(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Vec<i64>, String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{key} should be an array"))?
        .iter()
        .map(|entry| {
            entry
                .as_integer()
                .ok_or_else(|| format!("{key} entries should be integers"))
        })
        .collect()
}

fn bool_value(table: &toml::map::Map<String, toml::Value>, key: &str) -> Result<bool, String> {
    table
        .get(key)
        .and_then(toml::Value::as_bool)
        .ok_or_else(|| format!("{key} should be a boolean"))
}

fn integer_value(table: &toml::map::Map<String, toml::Value>, key: &str) -> Result<i64, String> {
    table
        .get(key)
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| format!("{key} should be an integer"))
}

fn validator_for(schema: &Value) -> Result<jsonschema::Validator, String> {
    jsonschema::Validator::new(schema)
        .map_err(|err| format!("operation schema should compile as JSON Schema: {err}"))
}

fn operation<'a>(
    operations: &'a [OperationInfo],
    operation_id: &str,
) -> Result<&'a OperationInfo, String> {
    operations
        .iter()
        .find(|operation| operation.id.as_str() == operation_id)
        .ok_or_else(|| format!("Mattermost operation catalog should include {operation_id}"))
}

fn required_fields(schema: &Value) -> Vec<&str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

#[test]
fn mattermost_manifest_and_runtime_catalog_have_contract_coverage() -> Result<(), String> {
    let manifest = manifest()?;
    let manifest_operations = manifest_operations(&manifest)?;
    let introspection = MattermostConnector::new().introspect();

    assert!(
        introspection.operations.len() >= 22,
        "Mattermost should expose the expected user, team, channel, post, file, reaction, and monitor operations"
    );
    assert!(
        introspection.events.len() >= 10,
        "Mattermost should expose monitor event topics"
    );

    let mut runtime_operation_ids = BTreeSet::new();
    for operation in &introspection.operations {
        assert!(
            runtime_operation_ids.insert(operation.id.as_str().to_owned()),
            "duplicate Mattermost operation id: {}",
            operation.id.as_str()
        );
        assert!(
            manifest_operations.contains_key(operation.id.as_str()),
            "manifest should declare runtime operation {}",
            operation.id.as_str()
        );
        assert!(
            !operation.ai_hints.when_to_use.trim().is_empty(),
            "{} should include agent usage hints",
            operation.id.as_str()
        );
        let manifest_hints = manifest_operation_ai_hints(&manifest, operation.id.as_str())?;
        let manifest_when_to_use = manifest_hints
            .get("when_to_use")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("{} should declare ai_hints.when_to_use", operation.id))?;
        assert!(
            !manifest_when_to_use.trim().is_empty(),
            "{} manifest ai_hints.when_to_use should not be empty",
            operation.id.as_str()
        );
        assert!(
            !string_array(manifest_hints, "common_mistakes")?.is_empty(),
            "{} manifest ai_hints.common_mistakes should not be empty",
            operation.id.as_str()
        );
        let examples = string_array(manifest_hints, "examples")?;
        assert!(
            !examples.is_empty(),
            "{} manifest ai_hints.examples should not be empty",
            operation.id.as_str()
        );
        for example in examples {
            let lower = example.to_ascii_lowercase();
            assert!(
                !lower.contains("token")
                    && !lower.contains("password")
                    && !lower.contains("secret"),
                "{} manifest ai_hints example should not include secret-shaped sample values",
                operation.id.as_str()
            );
        }
        let _input_validator = validator_for(&operation.input_schema)?;
        let _output_validator = validator_for(&operation.output_schema)?;
        let _manifest_input = validator_for(&manifest_operation_schema(
            &manifest,
            operation.id.as_str(),
            "input_schema",
        )?)?;
        let _manifest_output = validator_for(&manifest_operation_schema(
            &manifest,
            operation.id.as_str(),
            "output_schema",
        )?)?;
    }

    for manifest_operation_id in manifest_operations.keys() {
        assert!(
            runtime_operation_ids.contains(manifest_operation_id),
            "runtime catalog should expose manifest operation {manifest_operation_id}"
        );
    }

    Ok(())
}

#[test]
fn mattermost_manifest_declares_per_operation_network_constraints() -> Result<(), String> {
    let manifest = manifest()?;
    let operations = manifest_operations(&manifest)?;

    for (operation_id, operation) in operations {
        let constraints = operation
            .as_table()
            .and_then(|operation| operation.get("network_constraints"))
            .and_then(toml::Value::as_table)
            .ok_or_else(|| format!("{operation_id} should declare network_constraints"))?;
        assert!(
            !string_array(constraints, "host_allow")?.is_empty(),
            "{operation_id} host_allow should not be empty"
        );
        assert!(
            !integer_array(constraints, "port_allow")?.is_empty(),
            "{operation_id} port_allow should not be empty"
        );
        let _require_sni = bool_value(constraints, "require_sni")?;
        let _deny_private_ranges = bool_value(constraints, "deny_private_ranges")?;
    }

    let slash =
        manifest_operation_network_constraints(&manifest, "mattermost.authorize_slash_command")?;
    assert_eq!(string_array(slash, "host_allow")?, vec!["none.invalid"]);
    assert_eq!(integer_array(slash, "port_allow")?, vec![0]);
    assert!(!bool_value(slash, "require_sni")?);
    assert!(bool_value(slash, "deny_localhost")?);
    assert!(bool_value(slash, "deny_private_ranges")?);
    assert!(bool_value(slash, "deny_tailnet_ranges")?);
    assert!(bool_value(slash, "deny_ip_literals")?);
    assert!(bool_value(slash, "require_host_canonicalization")?);
    assert_eq!(integer_value(slash, "dns_max_ips")?, 0);
    assert_eq!(integer_value(slash, "max_redirects")?, 0);
    assert_eq!(integer_value(slash, "connect_timeout_ms")?, 1_000);
    assert_eq!(integer_value(slash, "total_timeout_ms")?, 30_000);
    assert_eq!(integer_value(slash, "max_response_bytes")?, 1_048_576);

    Ok(())
}

#[test]
fn mattermost_key_operation_contracts_are_stable() -> Result<(), String> {
    let operations = MattermostConnector::new().introspect().operations;

    let get_me = operation(&operations, "mattermost.get_me")?;
    assert_eq!(get_me.capability.as_str(), "mattermost.read");
    assert!(matches!(get_me.risk_level, RiskLevel::Low));
    assert!(matches!(get_me.safety_tier, SafetyTier::Safe));
    assert!(matches!(get_me.idempotency, IdempotencyClass::Strict));

    let create_post = operation(&operations, "mattermost.create_post")?;
    assert_eq!(create_post.capability.as_str(), "mattermost.write");
    assert!(matches!(create_post.risk_level, RiskLevel::Medium));
    assert!(matches!(create_post.safety_tier, SafetyTier::Risky));
    assert!(matches!(create_post.idempotency, IdempotencyClass::None));
    assert_eq!(
        required_fields(&create_post.input_schema),
        vec!["channel_id", "message"],
        "create_post must continue requiring a stable channel id and message body"
    );

    let authorize_slash = operation(&operations, "mattermost.authorize_slash_command")?;
    assert_eq!(authorize_slash.capability.as_str(), "mattermost.read");
    assert!(matches!(authorize_slash.safety_tier, SafetyTier::Safe));
    assert_eq!(
        required_fields(&authorize_slash.input_schema),
        vec!["channel_id", "user_id", "command"],
        "slash-command authorization must key policy on stable ids"
    );
    assert!(
        authorize_slash
            .ai_hints
            .common_mistakes
            .iter()
            .any(|hint| hint.contains("stable user_id") && hint.contains("channel_id")),
        "slash-command hints should keep agents away from display-name authorization"
    );

    Ok(())
}

#[test]
fn mattermost_error_taxonomy_maps_provider_failures_to_fcp_errors() {
    assert!(matches!(
        MattermostError::from_api_response(401, r#"{"message":"bad token"}"#, None).to_fcp_error(),
        FcpError::Unauthorized { .. }
    ));
    assert!(matches!(
        MattermostError::from_api_response(403, r#"{"message":"denied"}"#, None).to_fcp_error(),
        FcpError::Unauthorized { .. }
    ));
    assert!(matches!(
        MattermostError::from_api_response(404, r#"{"message":"missing"}"#, None).to_fcp_error(),
        FcpError::ResourceNotFound { .. }
    ));
    assert!(matches!(
        MattermostError::from_api_response(
            429,
            r#"{"message":"slow down","retry_after_ms":2500}"#,
            None
        )
        .to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 2500,
            ..
        }
    ));
}

#[test]
fn mattermost_resource_and_event_contracts_cover_monitoring_surface() -> Result<(), String> {
    let introspection = MattermostConnector::new().introspect();
    let resources = introspection
        .resource_types
        .iter()
        .map(|resource| resource.name.as_str())
        .collect::<BTreeSet<_>>();
    assert!(resources.contains("mattermost.user"));
    assert!(resources.contains("mattermost.team"));
    assert!(resources.contains("mattermost.channel"));
    assert!(resources.contains("mattermost.post"));
    assert!(resources.contains("mattermost.file"));

    let events = introspection
        .events
        .iter()
        .map(|event| event.topic.as_str())
        .collect::<BTreeSet<_>>();
    for topic in [
        "mattermost.posted",
        "mattermost.post_edited",
        "mattermost.post_deleted",
        "mattermost.reaction_added",
        "mattermost.reaction_removed",
        "mattermost.thread_updated",
        "mattermost.typing",
    ] {
        assert!(events.contains(topic), "missing event topic {topic}");
    }

    let event_caps = introspection
        .event_caps
        .expect("Mattermost should advertise event caps");
    assert!(event_caps.streaming);
    assert!(!event_caps.replay);
    assert!(!event_caps.requires_ack);

    let auth_caps = introspection
        .auth_caps
        .expect("Mattermost should advertise auth caps");
    assert_eq!(
        auth_caps.methods,
        vec![
            "personal_access_token".to_owned(),
            "bot_access_token".to_owned(),
            "credential_id".to_owned(),
        ]
    );

    let operations = introspection.operations;
    assert!(
        operations.iter().all(|operation| !operation
            .capability
            .as_str()
            .starts_with("mattermost.admin")),
        "Mattermost connector must not expose workspace-admin capabilities in this slice"
    );
    assert!(
        operations
            .iter()
            .all(|operation| operation.requires_approval.is_some()),
        "operation approval mode should remain explicit"
    );

    let slash_output = &operation(&operations, "mattermost.authorize_slash_command")?.output_schema;
    assert_eq!(
        slash_output["properties"]["decision"]["enum"],
        json!(["allow", "deny"])
    );

    Ok(())
}
