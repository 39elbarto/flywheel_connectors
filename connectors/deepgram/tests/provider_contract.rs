use fcp_deepgram::DeepgramConnector;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
use serde_json::{Value, json};

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
