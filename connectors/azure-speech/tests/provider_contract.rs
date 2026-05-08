use fcp_azure_speech::AzureSpeechConnector;
use fcp_manifest::ConnectorManifest;
use jsonschema::Validator;
use serde_json::{Value, json};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_IDS: [&str; 3] = [
    "azure.speech.voices.list",
    "azure.speech.tts.synthesize",
    "azure.speech.stt.transcribe_fast",
];

fn azure_speech_manifest_unchecked() -> ConnectorManifest {
    ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
        .expect("Azure Speech manifest should parse before hash validation")
}

fn manifest_input_schema<'a>(manifest: &'a ConnectorManifest, operation_id: &str) -> &'a Value {
    &manifest
        .provides
        .operations
        .get(operation_id)
        .expect("manifest operation should be declared")
        .input_schema
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
async fn azure_speech_manifest_operations_match_runtime_introspection() {
    let manifest = azure_speech_manifest_unchecked();
    let connector = AzureSpeechConnector::new();
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

    let tts = runtime_operations
        .iter()
        .find(|operation| {
            operation.get("id").and_then(Value::as_str) == Some("azure.speech.tts.synthesize")
        })
        .expect("tts operation should be present");
    assert_eq!(tts["risk_level"], "medium");
    assert_eq!(
        tts["input_schema"]["properties"]["output_format"]["default"],
        "riff-24khz-16bit-mono-pcm"
    );

    let stt = runtime_operations
        .iter()
        .find(|operation| {
            operation.get("id").and_then(Value::as_str) == Some("azure.speech.stt.transcribe_fast")
        })
        .expect("stt operation should be present");
    assert_eq!(stt["idempotency"], "strict");
    assert!(
        stt["network_constraints"]["host_allow"]
            .as_array()
            .expect("host allow should be an array")
            .iter()
            .any(|host| host.as_str() == Some("*.api.cognitive.microsoft.com"))
    );

    let streaming_blocker = introspection
        .get("deferred_operations")
        .and_then(Value::as_array)
        .expect("deferred operations should be an array")
        .iter()
        .find(|operation| {
            operation.get("id").and_then(Value::as_str)
                == Some("azure.speech.tts.text_stream.websocket")
        })
        .expect("TTS text-stream WebSocket blocker should be present");
    assert_eq!(
        streaming_blocker["outcome"],
        "blocked_official_sdk_only_protocol"
    );
    assert!(
        streaming_blocker["official_docs"]
            .as_array()
            .expect("official docs should be present")
            .iter()
            .any(|doc| doc
                .as_str()
                .is_some_and(|doc| doc.contains("text-streaming")))
    );
}

#[test]
fn azure_speech_manifest_schemas_cover_core_request_shapes() {
    let manifest = azure_speech_manifest_unchecked();
    let tts_schema = manifest_input_schema(&manifest, "azure.speech.tts.synthesize");
    assert_schema_accepts(
        tts_schema,
        &json!({
            "text": "hello",
            "voice": "en-US-ChristopherNeural",
            "locale": "en-US"
        }),
    );
    assert_schema_accepts(tts_schema, &json!({"ssml": "<speak></speak>"}));
    assert_schema_rejects(tts_schema, &json!({"text": "hello"}));

    let stt_schema = manifest_input_schema(&manifest, "azure.speech.stt.transcribe_fast");
    assert_schema_accepts(
        stt_schema,
        &json!({
            "audio_base64": "AAAA",
            "content_type": "audio/wav",
            "locale": "en-US"
        }),
    );
    assert_schema_rejects(stt_schema, &json!({"content_type": "audio/wav"}));
}
