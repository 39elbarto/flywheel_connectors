use fcp_azure_speech::AzureSpeechConnector;
use fcp_manifest::ConnectorManifest;
use jsonschema::Validator;
use serde_json::{Value, json};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_IDS: [&str; 22] = [
    "azure.speech.voices.list",
    "azure.speech.tts.synthesize",
    "azure.speech.stt.transcribe_fast",
    "azure.speech.stt.batch.submit",
    "azure.speech.stt.batch.get",
    "azure.speech.stt.batch.files",
    "azure.speech.stt.custom.projects.create",
    "azure.speech.stt.custom.projects.list",
    "azure.speech.stt.custom.projects.get",
    "azure.speech.stt.custom.projects.delete",
    "azure.speech.stt.custom.datasets.create",
    "azure.speech.stt.custom.datasets.list",
    "azure.speech.stt.custom.datasets.get",
    "azure.speech.stt.custom.datasets.delete",
    "azure.speech.stt.custom.models.create",
    "azure.speech.stt.custom.models.list",
    "azure.speech.stt.custom.models.get",
    "azure.speech.stt.custom.models.delete",
    "azure.speech.stt.custom.endpoints.create",
    "azure.speech.stt.custom.endpoints.list",
    "azure.speech.stt.custom.endpoints.get",
    "azure.speech.stt.custom.endpoints.delete",
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
    let batch_submit = runtime_operations
        .iter()
        .find(|operation| {
            operation.get("id").and_then(Value::as_str) == Some("azure.speech.stt.batch.submit")
        })
        .expect("batch submit operation should be present");
    assert_eq!(batch_submit["capability"], "azure.speech.stt");
    assert_eq!(
        batch_submit["input_schema"]["properties"]["locale"]["default"],
        "en-US"
    );
    let batch_files = runtime_operations
        .iter()
        .find(|operation| {
            operation.get("id").and_then(Value::as_str) == Some("azure.speech.stt.batch.files")
        })
        .expect("batch files operation should be present");
    assert_eq!(batch_files["idempotency"], "strict");
    let project_create = runtime_operations
        .iter()
        .find(|operation| {
            operation.get("id").and_then(Value::as_str)
                == Some("azure.speech.stt.custom.projects.create")
        })
        .expect("custom project create operation should be present");
    assert_eq!(project_create["capability"], "azure.speech.stt");
    assert_eq!(
        project_create["input_schema"]["required"][0],
        "display_name"
    );
    let endpoint_delete = runtime_operations
        .iter()
        .find(|operation| {
            operation.get("id").and_then(Value::as_str)
                == Some("azure.speech.stt.custom.endpoints.delete")
        })
        .expect("custom endpoint delete operation should be present");
    assert_eq!(endpoint_delete["requires_approval"], "interactive");

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
    assert_eq!(
        introspection["provider_docs_rechecked"]["entra_auth"],
        "https://learn.microsoft.com/en-us/azure/ai-services/speech-service/how-to-configure-azure-ad-auth"
    );
    assert!(
        introspection["provider_docs_rechecked"]["llm_speech_keyless_auth"]
            .as_str()
            .expect("LLM speech auth doc should be present")
            .contains("llm-speech")
    );
    assert!(
        !introspection
            .get("deferred_operations")
            .and_then(Value::as_array)
            .expect("deferred operations should be an array")
            .iter()
            .any(|operation| operation.get("id").and_then(Value::as_str)
                == Some("azure.speech.entra.managed_identity"))
    );
}

#[test]
fn azure_speech_manifest_ai_hints_cover_all_operations() {
    let manifest = azure_speech_manifest_unchecked();
    for operation_id in EXPECTED_OPERATION_IDS {
        let hints = &manifest
            .provides
            .operations
            .get(operation_id)
            .expect("manifest operation should be declared")
            .ai_hints;
        assert!(
            !hints.when_to_use.trim().is_empty(),
            "{operation_id} should declare ai_hints.when_to_use"
        );
        assert!(
            !hints.common_mistakes.is_empty(),
            "{operation_id} should declare ai_hints.common_mistakes"
        );
        assert!(
            !hints.examples.is_empty(),
            "{operation_id} should declare ai_hints.examples"
        );
        for example in &hints.examples {
            let lower = example.to_ascii_lowercase();
            assert!(
                !lower.contains("token")
                    && !lower.contains("password")
                    && !lower.contains("secret"),
                "{operation_id} example should not include secret-shaped sample values"
            );
        }
    }
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

    let batch_submit_schema = manifest_input_schema(&manifest, "azure.speech.stt.batch.submit");
    assert_schema_accepts(
        batch_submit_schema,
        &json!({
            "display_name": "nightly support calls",
            "locale": "en-US",
            "content_urls": ["https://storage.example/audio.wav?sig=redacted"],
            "time_to_live_hours": 48
        }),
    );
    assert_schema_accepts(
        batch_submit_schema,
        &json!({
            "display_name": "nightly support calls",
            "locale": "en-US",
            "content_container_url": "https://storage.example/container?sig=redacted"
        }),
    );
    assert_schema_rejects(
        batch_submit_schema,
        &json!({"display_name": "missing source", "locale": "en-US"}),
    );

    let batch_get_schema = manifest_input_schema(&manifest, "azure.speech.stt.batch.get");
    assert_schema_accepts(
        batch_get_schema,
        &json!({"transcription_id": "ba7ea6f5-3065-40b7-b49a-a90f48584683"}),
    );
    assert_schema_rejects(batch_get_schema, &json!({}));

    let batch_files_schema = manifest_input_schema(&manifest, "azure.speech.stt.batch.files");
    assert_schema_accepts(
        batch_files_schema,
        &json!({
            "transcription_id": "ba7ea6f5-3065-40b7-b49a-a90f48584683",
            "sas_validity_seconds": 300,
            "top": 2
        }),
    );
    assert_schema_rejects(batch_files_schema, &json!({"top": 2}));
}

#[test]
fn azure_speech_manifest_schemas_cover_custom_speech_request_shapes() {
    let manifest = azure_speech_manifest_unchecked();
    let project_create_schema =
        manifest_input_schema(&manifest, "azure.speech.stt.custom.projects.create");
    assert_schema_accepts(
        project_create_schema,
        &json!({
            "display_name": "project",
            "locale": "en-US",
            "foundry_project_name": "FoundrySpeech"
        }),
    );
    assert_schema_rejects(project_create_schema, &json!({"locale": "en-US"}));

    let dataset_create_schema =
        manifest_input_schema(&manifest, "azure.speech.stt.custom.datasets.create");
    assert_schema_accepts(
        dataset_create_schema,
        &json!({
            "display_name": "dataset",
            "locale": "en-US",
            "kind": "AudioFiles",
            "content_url": "https://storage.example/dataset.zip?sig=redacted",
            "project_id": "project-123"
        }),
    );
    assert_schema_rejects(
        dataset_create_schema,
        &json!({"display_name": "dataset", "locale": "en-US"}),
    );

    let model_create_schema =
        manifest_input_schema(&manifest, "azure.speech.stt.custom.models.create");
    assert_schema_accepts(
        model_create_schema,
        &json!({
            "display_name": "model",
            "locale": "en-US",
            "base_model_id": "base-model-1",
            "datasets": [{"id": "dataset-123"}]
        }),
    );
    assert_schema_rejects(model_create_schema, &json!({"locale": "en-US"}));

    let endpoint_create_schema =
        manifest_input_schema(&manifest, "azure.speech.stt.custom.endpoints.create");
    assert_schema_accepts(
        endpoint_create_schema,
        &json!({
            "display_name": "endpoint",
            "locale": "en-US",
            "model_id": "model-123",
            "project_id": "project-123"
        }),
    );
    assert_schema_rejects(
        endpoint_create_schema,
        &json!({"display_name": "endpoint", "locale": "en-US"}),
    );
}
