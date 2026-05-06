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
            .with_operation(
                ProviderOperationContract::new("elevenlabs.tts.stream")
                    .with_catalog_id("tts_models")
                    .with_default_model("eleven_multilingual_v2")
                    .require_default_model(),
            )
            .with_model_catalog(ProviderModelCatalogContract::new("stt_models").with_model(
                ProviderModelContract::new("scribe_v2_realtime").with_label("Scribe v2 Realtime"),
            ))
            .with_operation(
                ProviderOperationContract::new("elevenlabs.scribe.realtime.transcribe")
                    .with_catalog_id("stt_models")
                    .with_default_model("scribe_v2_realtime")
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

    let realtime = operation(&introspection, "elevenlabs.scribe.realtime.transcribe");
    let streaming_tts = operation(&introspection, "elevenlabs.tts.stream");
    assert_eq!(
        streaming_tts
            .get("input_schema")
            .and_then(|schema| schema.get("properties"))
            .and_then(|properties| properties.get("max_audio_bytes"))
            .and_then(|field| field.get("default"))
            .and_then(Value::as_u64),
        Some(8 * 1024 * 1024)
    );
    assert_eq!(
        streaming_tts
            .get("input_schema")
            .and_then(|schema| schema.get("properties"))
            .and_then(|properties| properties.get("max_chunks"))
            .and_then(|field| field.get("default"))
            .and_then(Value::as_u64),
        Some(1024)
    );
    assert!(
        realtime
            .get("input_schema")
            .and_then(|schema| schema.get("anyOf"))
            .and_then(Value::as_array)
            .is_some_and(|variants| {
                variants.iter().any(|variant| {
                    variant
                        .get("required")
                        .and_then(Value::as_array)
                        .is_some_and(|required| {
                            required
                                .iter()
                                .any(|field| field.as_str() == Some("audio_chunks_base64"))
                        })
                })
            })
    );
    assert_eq!(
        realtime
            .get("input_schema")
            .and_then(|schema| schema.get("properties"))
            .and_then(|properties| properties.get("model_id"))
            .and_then(|model| model.get("default"))
            .and_then(Value::as_str),
        Some("scribe_v2_realtime")
    );
    assert_eq!(
        realtime
            .get("input_schema")
            .and_then(|schema| schema.get("properties"))
            .and_then(|properties| properties.get("audio_format"))
            .and_then(|format| format.get("default"))
            .and_then(Value::as_str),
        Some("ulaw_8000")
    );
    assert_eq!(
        realtime
            .get("input_schema")
            .and_then(|schema| schema.get("properties"))
            .and_then(|properties| properties.get("commit_strategy"))
            .and_then(|strategy| strategy.get("default"))
            .and_then(Value::as_str),
        Some("vad")
    );

    let long_running = deferred_operation(
        &introspection,
        "elevenlabs.scribe.realtime.transcribe.long_running",
    );
    assert!(
        long_running
            .get("rationale")
            .and_then(Value::as_str)
            .is_some_and(|rationale| rationale.contains("host-owned")
                && rationale.contains("elevenlabs.scribe.realtime.transcribe"))
    );

    let streaming_tts = deferred_operation(&introspection, "elevenlabs.tts.input_stream.websocket");
    assert_eq!(
        streaming_tts
            .get("default_model_id")
            .and_then(Value::as_str),
        Some("eleven_multilingual_v2")
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
