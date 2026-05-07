use fcp_elevenlabs::ElevenlabsConnector;
use fcp_manifest::ConnectorManifest;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
use jsonschema::Validator;
use serde_json::{Value, json};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_IDS: [&str; 4] = [
    "elevenlabs.voices.list",
    "elevenlabs.tts.generate",
    "elevenlabs.tts.stream",
    "elevenlabs.scribe.realtime.transcribe",
];

fn elevenlabs_manifest_unchecked() -> ConnectorManifest {
    ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
        .expect("ElevenLabs manifest should parse before hash validation")
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

fn validator_for(schema: &Value) -> Validator {
    Validator::new(schema).expect("manifest operation schema should compile")
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
            .with_operation(ProviderOperationContract::new("elevenlabs.voices.list"))
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
            .is_some_and(
                |rationale| rationale.contains("Retired from connector-local invoke")
                    && rationale.contains("elevenlabs.scribe.realtime.transcribe")
            )
    );
    assert_connector_local_retired(
        long_running,
        "elevenlabs.scribe.realtime.transcribe",
        &[
            "stream_subscription_lifecycle",
            "audio_chunk_fan_in",
            "policy_gated_transcript_fan_out",
            "supervised_shutdown_and_restart",
        ],
    );

    let streaming_tts = deferred_operation(&introspection, "elevenlabs.tts.input_stream.websocket");
    assert_eq!(
        streaming_tts
            .get("default_model_id")
            .and_then(Value::as_str),
        Some("eleven_multilingual_v2")
    );
    assert_connector_local_retired(
        streaming_tts,
        "elevenlabs.tts.stream",
        &[
            "stream_subscription_lifecycle",
            "partial_text_fan_in",
            "policy_gated_audio_and_alignment_fan_out",
            "supervised_shutdown_and_restart",
        ],
    );

    let manifest = parsed_manifest();
    let migration_hint = manifest
        .get("connector")
        .and_then(toml::Value::as_table)
        .and_then(|connector| connector.get("state"))
        .and_then(toml::Value::as_table)
        .and_then(|state| state.get("migration_hint"))
        .and_then(toml::Value::as_str)
        .expect("manifest migration_hint should parse");
    assert!(migration_hint.contains("retired from connector-local invoke"));
    assert!(migration_hint.contains("Long-running Scribe sessions"));
    assert!(migration_hint.contains("WebSocket input-stream TTS"));
}

#[fcp_async_core::runtime::test]
async fn elevenlabs_manifest_operations_match_runtime_introspection() {
    let manifest = elevenlabs_manifest_unchecked();
    manifest
        .validate()
        .expect("ElevenLabs manifest should validate with its checked interface hash");

    let connector = ElevenlabsConnector::new();
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
            runtime_operation.get("description").and_then(Value::as_str),
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
            runtime_operation.get("network_constraints").is_some(),
            "{operation_id} should expose network constraints through introspection"
        );
        assert!(
            !manifest_operation.ai_hints.when_to_use.trim().is_empty(),
            "{operation_id} should declare AI guidance"
        );
        assert!(
            runtime_operation.get("ai_hints").is_some(),
            "{operation_id} should expose AI guidance through introspection"
        );
    }
}

#[test]
fn elevenlabs_manifest_input_schemas_validate_representative_payloads() {
    let manifest = elevenlabs_manifest_unchecked();

    let voices_schema = manifest_input_schema(&manifest, "elevenlabs.voices.list");
    assert_schema_accepts(voices_schema, &json!({}));
    assert_schema_rejects(voices_schema, &json!(null));

    let tts_generate_schema = manifest_input_schema(&manifest, "elevenlabs.tts.generate");
    assert_schema_accepts(
        tts_generate_schema,
        &json!({
            "voice_id": "21m00Tcm4TlvDq8ikWAM",
            "text": "short redaction-safe fixture text",
            "model_id": "eleven_multilingual_v2",
            "voice_settings": {
                "stability": 0.5,
                "similarity_boost": 0.75,
                "style": 0.0,
                "use_speaker_boost": true,
                "speed": 1.0
            },
            "apply_text_normalization": "auto",
            "output_format": "mp3_44100_128",
            "optimize_streaming_latency": 4
        }),
    );
    assert_schema_rejects(tts_generate_schema, &json!({}));
    assert_schema_rejects(
        tts_generate_schema,
        &json!({"voice_id": "", "text": "hello"}),
    );
    assert_schema_rejects(
        tts_generate_schema,
        &json!({"voice_id": "voice", "text": "", "model_id": "eleven_multilingual_v2"}),
    );
    assert_schema_rejects(
        tts_generate_schema,
        &json!({"voice_id": "voice", "text": "hello", "optimize_streaming_latency": 5}),
    );
    assert_schema_rejects(
        tts_generate_schema,
        &json!({"voice_id": "voice", "text": "hello", "voice_settings": {"speed": 2.1}}),
    );

    let tts_stream_schema = manifest_input_schema(&manifest, "elevenlabs.tts.stream");
    assert_schema_accepts(
        tts_stream_schema,
        &json!({
            "voice_id": "21m00Tcm4TlvDq8ikWAM",
            "text": "stream fixture",
            "model_id": "eleven_multilingual_v2",
            "max_audio_bytes": 16_777_216,
            "max_chunks": 4096
        }),
    );
    assert_schema_rejects(
        tts_stream_schema,
        &json!({"voice_id": "voice", "text": "hello", "max_audio_bytes": 0}),
    );
    assert_schema_rejects(
        tts_stream_schema,
        &json!({"voice_id": "voice", "text": "hello", "max_chunks": 4097}),
    );

    let realtime_schema = manifest_input_schema(&manifest, "elevenlabs.scribe.realtime.transcribe");
    assert_schema_accepts(
        realtime_schema,
        &json!({
            "audio_base64": "dWxhdy1hdWRpbw==",
            "audio_format": "ulaw_8000",
            "sample_rate": 8000,
            "commit_strategy": "vad",
            "language_code": "en",
            "include_timestamps": false,
            "include_language_detection": false,
            "vad_silence_threshold_secs": 0.5,
            "vad_threshold": 0.5,
            "min_speech_duration_ms": 1,
            "min_silence_duration_ms": 1,
            "connect_timeout_ms": 100,
            "timeout_ms": 300_000,
            "max_events": 1024,
            "max_reconnect_attempts": 5,
            "reconnect_delay_ms": 30000
        }),
    );
    assert_schema_accepts(
        realtime_schema,
        &json!({"audio_chunks_base64": ["dWxhdy1hdWRpbw=="], "model_id": "scribe_v2_realtime"}),
    );
    assert_schema_rejects(realtime_schema, &json!({}));
    assert_schema_rejects(realtime_schema, &json!({"audio_chunks_base64": []}));
    assert_schema_rejects(
        realtime_schema,
        &json!({"audio_base64": "dWxhdy1hdWRpbw==", "sample_rate": 7999}),
    );
    assert_schema_rejects(
        realtime_schema,
        &json!({"audio_base64": "dWxhdy1hdWRpbw==", "max_events": 1025}),
    );
    assert_schema_rejects(
        realtime_schema,
        &json!({"audio_base64": "dWxhdy1hdWRpbw==", "max_reconnect_attempts": 6}),
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
