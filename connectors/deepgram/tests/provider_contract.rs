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
            .is_some_and(|rationale| rationale.contains("host-owned")
                && rationale.contains("deepgram.listen.stream"))
    );
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
