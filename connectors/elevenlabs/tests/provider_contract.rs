use fcp_elevenlabs::ElevenlabsConnector;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
use serde_json::{Value, json};

#[fcp_async_core::runtime::test]
async fn elevenlabs_provider_contract_is_advertised() {
    let redaction_marker = "elevenlabs-provider-contract-marker";
    let mut connector = ElevenlabsConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let configure = connector
        .handle_configure(json!({
            "api_key": redaction_marker,
            "base_url": "http://127.0.0.1:1/v1"
        }))
        .await
        .expect("loopback configure should succeed");
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");

    assert_provider_contract(
        &ProviderContract::new("elevenlabs", "ElevenLabs")
            .with_docs_path("/connectors/elevenlabs/manifest.toml")
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
                ProviderModelCatalogContract::new("tts_models")
                    .with_model(ProviderModelContract::new("eleven_v3").with_label("Eleven v3"))
                    .with_model(
                        ProviderModelContract::new("eleven_multilingual_v2")
                            .with_label("Eleven Multilingual v2"),
                    )
                    .with_model(
                        ProviderModelContract::new("eleven_turbo_v2_5")
                            .with_label("Eleven Turbo v2.5"),
                    )
                    .with_model(
                        ProviderModelContract::new("eleven_monolingual_v1")
                            .with_label("Eleven Monolingual v1"),
                    ),
            )
            .with_operation(
                ProviderOperationContract::new("elevenlabs.tts.generate")
                    .with_catalog_id("tts_models")
                    .with_default_model("eleven_multilingual_v2")
                    .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new(
                "api",
                "https://api.elevenlabs.io/v1",
            ))
            .with_base_url(
                ProviderBaseUrlContract::new("loopback-test", "http://127.0.0.1:1/v1")
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
                "fcp_elevenlabs",
                "provider registry",
            )),
    );

    let realtime = deferred_operation(&introspection, "elevenlabs.scribe.realtime.transcribe");
    assert_eq!(
        realtime.get("default_model_id").and_then(Value::as_str),
        Some("scribe_v2_realtime")
    );
    assert_eq!(
        realtime.get("default_audio_format").and_then(Value::as_str),
        Some("ulaw_8000")
    );
    assert_eq!(
        realtime
            .get("default_commit_strategy")
            .and_then(Value::as_str),
        Some("vad")
    );
    assert!(
        realtime
            .get("rationale")
            .and_then(Value::as_str)
            .is_some_and(
                |rationale| rationale.contains("asupersync") && rationale.contains("WebSocket")
            )
    );

    let streaming_tts = deferred_operation(&introspection, "elevenlabs.tts.stream");
    assert_eq!(
        streaming_tts
            .get("default_model_id")
            .and_then(Value::as_str),
        Some("eleven_multilingual_v2")
    );
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
