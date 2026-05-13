use fcp_deepgram::DeepgramConnector;
use fcp_manifest::ConnectorManifest;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
use serde_json::{Value, json};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_IDS: [&str; 2] = ["deepgram.listen.transcribe", "deepgram.listen.stream"];

fn deepgram_manifest_unchecked() -> ConnectorManifest {
    ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
        .expect("Deepgram manifest should parse before hash validation")
}

fn manifest_input_schema<'a>(manifest: &'a ConnectorManifest, operation_id: &str) -> &'a Value {
    &manifest
        .provides
        .operations
        .get(operation_id)
        .expect("manifest operation should be declared")
        .input_schema
}

fn json_string<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .expect("value should serialize")
        .as_str()
        .expect("serialized value should be a string")
        .to_string()
}

fn validator_for(schema: &Value) -> jsonschema::Validator {
    jsonschema::Validator::new(schema).expect("manifest operation schema should compile")
}

fn assert_schema_accepts(schema: &Value, payload: &Value) {
    let validator = validator_for(schema);
    let errors: Vec<_> = validator
        .iter_errors(payload)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "schema should accept {payload}; errors: {errors:?}"
    );
}

fn assert_schema_rejects(schema: &Value, payload: &Value) {
    let validator = validator_for(schema);
    assert!(
        validator.iter_errors(payload).next().is_some(),
        "schema should reject {payload}"
    );
}

#[fcp_async_core::runtime::test]
async fn deepgram_provider_contract_is_advertised() {
    let redaction_marker = "deepgram-provider-contract-marker";
    let mut connector = DeepgramConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let configure = connector
        .handle_configure(json!({
            "api_key": redaction_marker,
            "base_url": "http://127.0.0.1:1"
        }))
        .await
        .expect("loopback configure should succeed");
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");

    assert_provider_contract(
        &ProviderContract::new("deepgram", "Deepgram")
            .with_docs_path("/connectors/deepgram/manifest.toml")
            .with_config_key("api_key")
            .with_config_key("credential_id")
            .with_config_key("base_url")
            .with_config_key("request_timeout_ms")
            .with_auth_method(
                ProviderAuthMethodContract::new("api_key", "API key").with_config_key("api_key"),
            )
            .with_auth_method(
                ProviderAuthMethodContract::new("credential_id", "Host credential reference")
                    .with_config_key("credential_id"),
            )
            .with_model_picker_method("api_key")
            .with_model_catalog(
                ProviderModelCatalogContract::new("transcription")
                    .with_model(ProviderModelContract::new("nova-3").with_label("Nova 3")),
            )
            .with_operation(
                ProviderOperationContract::new("deepgram.listen.transcribe")
                    .with_catalog_id("transcription")
                    .with_default_model("nova-3")
                    .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::new("deepgram.listen.stream")
                    .with_catalog_id("transcription")
                    .with_default_model("nova-3")
                    .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new(
                "api",
                "https://api.deepgram.com",
            ))
            .with_base_url(
                ProviderBaseUrlContract::new("loopback-test", "http://127.0.0.1:1")
                    .allow_loopback_http(),
            )
            .with_secret_marker(redaction_marker)
            .with_redaction_payload(ProviderRedactionPayload::new("configure", configure))
            .with_redaction_payload(ProviderRedactionPayload::new("doctor", doctor))
            .with_redaction_payload(ProviderRedactionPayload::new(
                "introspection",
                introspection.clone(),
            ))
            .with_import_side_effect(ProviderImportSideEffectContract::new(
                "fcp_deepgram",
                "provider registry",
            )),
    );

    let realtime = operation(&introspection, "deepgram.listen.stream");
    assert_eq!(
        realtime
            .get("input_schema")
            .and_then(|schema| schema.get("properties"))
            .and_then(|properties| properties.get("model"))
            .and_then(|model| model.get("default"))
            .and_then(Value::as_str),
        Some("nova-3")
    );
    assert_eq!(
        realtime
            .get("input_schema")
            .and_then(|schema| schema.get("properties"))
            .and_then(|properties| properties.get("encoding"))
            .and_then(|encoding| encoding.get("default"))
            .and_then(Value::as_str),
        Some("mulaw")
    );
    assert_eq!(
        realtime
            .get("input_schema")
            .and_then(|schema| schema.get("properties"))
            .and_then(|properties| properties.get("sample_rate"))
            .and_then(|sample_rate| sample_rate.get("default"))
            .and_then(Value::as_u64),
        Some(8000)
    );

    let long_running = deferred_operation(&introspection, "deepgram.listen.stream.long_running");
    assert_eq!(
        long_running.get("default_model").and_then(Value::as_str),
        Some("nova-3")
    );
    assert_eq!(
        long_running.get("default_encoding").and_then(Value::as_str),
        Some("mulaw")
    );
    assert_eq!(
        long_running
            .get("default_sample_rate_hz")
            .and_then(Value::as_u64),
        Some(8000)
    );
    assert!(
        long_running
            .get("rationale")
            .and_then(Value::as_str)
            .is_some_and(
                |rationale| rationale.contains("Retired from connector-local invoke")
                    && rationale.contains("deepgram.listen.stream")
            )
    );
    assert_connector_local_retired(
        long_running,
        "deepgram.listen.stream",
        &[
            "stream_subscription_lifecycle",
            "audio_chunk_fan_in",
            "policy_gated_transcript_fan_out",
            "supervised_shutdown_and_restart",
        ],
    );

    let manifest = parsed_manifest();
    let connector = manifest
        .get("connector")
        .and_then(toml::Value::as_table)
        .expect("manifest connector table should parse");
    assert!(
        connector
            .get("description")
            .and_then(toml::Value::as_str)
            .is_some_and(|description| description.contains("bounded realtime transcription"))
    );
    assert!(
        connector
            .get("archetypes")
            .and_then(toml::Value::as_array)
            .expect("manifest archetypes should parse")
            .iter()
            .any(|archetype| archetype.as_str() == Some("streaming"))
    );
    let migration_hint = connector
        .get("state")
        .and_then(toml::Value::as_table)
        .and_then(|state| state.get("migration_hint"))
        .and_then(toml::Value::as_str)
        .expect("manifest migration_hint should parse");
    assert!(migration_hint.contains("retired from connector-local invoke"));
    assert!(migration_hint.contains("host owns stream session lifecycle"));
}

#[fcp_async_core::runtime::test]
async fn deepgram_manifest_operations_match_runtime_introspection() {
    let manifest = deepgram_manifest_unchecked();
    manifest
        .validate()
        .expect("Deepgram manifest should validate with its checked interface hash");

    let connector = DeepgramConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let runtime_operations = introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("introspection operations should be an array");
    let runtime_ids: Vec<_> = runtime_operations
        .iter()
        .map(|operation| {
            operation
                .get("id")
                .and_then(Value::as_str)
                .expect("operation id should be a string")
        })
        .collect();
    assert_eq!(runtime_ids, EXPECTED_OPERATION_IDS);
    assert_eq!(
        manifest.provides.operations.len(),
        EXPECTED_OPERATION_IDS.len()
    );

    for operation_id in EXPECTED_OPERATION_IDS {
        let manifest_operation = manifest
            .provides
            .operations
            .get(operation_id)
            .expect("manifest operation should be declared");
        let runtime_operation = operation(&introspection, operation_id);

        assert_eq!(
            runtime_operation.get("summary").and_then(Value::as_str),
            Some(manifest_operation.description.as_str())
        );
        assert_eq!(
            runtime_operation.get("capability").and_then(Value::as_str),
            Some(manifest_operation.capability.as_str())
        );
        assert_eq!(
            runtime_operation
                .get("risk_level")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Some(json_string(manifest_operation.risk_level))
        );
        assert_eq!(
            runtime_operation
                .get("safety_tier")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Some(json_string(manifest_operation.safety_tier))
        );
        assert_eq!(
            runtime_operation
                .get("idempotency")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Some(json_string(manifest_operation.idempotency))
        );
        assert_eq!(
            runtime_operation
                .get("requires_approval")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            Some(json_string(manifest_operation.requires_approval))
        );
        assert_eq!(
            runtime_operation.get("input_schema"),
            Some(&manifest_operation.input_schema)
        );
        assert_eq!(
            runtime_operation.get("output_schema"),
            Some(&manifest_operation.output_schema)
        );
        assert!(
            manifest_operation.network_constraints.is_some(),
            "{operation_id} should declare network constraints"
        );
        assert!(
            !manifest_operation.ai_hints.when_to_use.trim().is_empty(),
            "{operation_id} should declare AI guidance"
        );
    }
}

#[test]
fn deepgram_manifest_input_schemas_validate_representative_payloads() {
    let manifest = deepgram_manifest_unchecked();

    let transcribe_schema = manifest_input_schema(&manifest, "deepgram.listen.transcribe");
    assert_schema_accepts(
        transcribe_schema,
        &json!({
            "audio_url": "https://example.com/meeting.wav",
            "media_byte_count": 1_048_576,
            "model": "nova-3",
            "smart_format": true
        }),
    );
    assert_schema_rejects(transcribe_schema, &json!({}));
    assert_schema_rejects(transcribe_schema, &json!({"audio_url": ""}));
    assert_schema_rejects(
        transcribe_schema,
        &json!({"audio_url": "https://example.com/meeting.wav", "media_byte_count": 1_073_741_825}),
    );

    let stream_schema = manifest_input_schema(&manifest, "deepgram.listen.stream");
    assert_schema_accepts(
        stream_schema,
        &json!({
            "audio_chunks_base64": ["bXVsYXctYXVkaW8="],
            "encoding": "mulaw",
            "sample_rate": 8000,
            "max_events": 1024,
            "max_reconnect_attempts": 0
        }),
    );
    assert_schema_accepts(
        stream_schema,
        &json!({
            "audio_base64": "bXVsYXctYXVkaW8=",
            "audio_format": {
                "encoding": "linear16",
                "sample_rate": 16000
            }
        }),
    );
    assert_schema_rejects(stream_schema, &json!({}));
    assert_schema_rejects(stream_schema, &json!({"audio_chunks_base64": []}));
    assert_schema_rejects(
        stream_schema,
        &json!({"audio_base64": "bXVsYXctYXVkaW8=", "sample_rate": 7999}),
    );
    assert_schema_rejects(
        stream_schema,
        &json!({"audio_base64": "bXVsYXctYXVkaW8=", "encoding": "unsupported"}),
    );
}

fn assert_connector_local_retired(
    operation: &Value,
    expected_fallback: &str,
    expected_host_capabilities: &[&str],
) {
    assert_eq!(
        operation.get("outcome").and_then(Value::as_str),
        Some("retired_from_connector_local_invoke")
    );
    assert_eq!(
        operation
            .get("host_platform_required")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        operation
            .get("connector_local_invoke")
            .and_then(Value::as_str),
        Some("unsupported")
    );
    assert_eq!(
        operation
            .get("finite_fallback_operation")
            .and_then(Value::as_str),
        Some(expected_fallback)
    );
    let capabilities = operation
        .get("required_host_capabilities")
        .and_then(Value::as_array)
        .expect("required host capabilities should be advertised");
    for expected in expected_host_capabilities {
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.as_str() == Some(*expected)),
            "missing required host capability {expected}"
        );
    }
}

fn parsed_manifest() -> toml::Value {
    toml::from_str(include_str!("../manifest.toml")).expect("manifest TOML should parse")
}

fn operation<'a>(introspection: &'a Value, id: &str) -> &'a Value {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("operations should be advertised")
        .iter()
        .find(|operation| operation.get("id").and_then(Value::as_str) == Some(id))
        .expect("expected operation should be advertised")
}

fn deferred_operation<'a>(introspection: &'a Value, id: &str) -> &'a Value {
    introspection
        .get("deferred_operations")
        .and_then(Value::as_array)
        .expect("deferred operations should be advertised")
        .iter()
        .find(|operation| operation.get("id").and_then(Value::as_str) == Some(id))
        .expect("expected deferred operation should be advertised")
}
