use fcp_manifest::ConnectorManifest;
use fcp_mistral::MistralConnector;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
use jsonschema::Validator;
use serde_json::{Value, json};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const EXPECTED_OPERATION_IDS: [&str; 5] = [
    "mistral.chat.completions",
    "mistral.embeddings.create",
    "mistral.audio.transcriptions",
    "mistral.audio.realtime.transcribe",
    "mistral.models.list",
];

fn mistral_manifest_unchecked() -> ConnectorManifest {
    ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
        .expect("Mistral manifest should parse before hash validation")
}

fn input_schema<'a>(introspection: &'a Value, operation_id: &str) -> &'a Value {
    operation(introspection, operation_id)
        .get("input_schema")
        .expect("operation input_schema should be present")
}

fn manifest_input_schema<'a>(manifest: &'a ConnectorManifest, operation_id: &str) -> &'a Value {
    &manifest
        .provides
        .operations
        .get(operation_id)
        .expect("manifest operation should be declared")
        .input_schema
}

fn operation<'a>(introspection: &'a Value, operation_id: &str) -> &'a Value {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .and_then(|operations| {
            operations
                .iter()
                .find(|operation| operation.get("id").and_then(Value::as_str) == Some(operation_id))
        })
        .expect("operation should be present")
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
async fn mistral_provider_contract_is_advertised() {
    let redaction_marker = "mistral-provider-contract-marker";
    let mut connector = MistralConnector::new();
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
        &ProviderContract::new("mistral", "Mistral")
            .with_docs_path("/connectors/mistral/manifest.toml")
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
            .with_default_model("mistral-small-latest")
            .with_model_catalog(
                ProviderModelCatalogContract::new("chat")
                    .with_model(ProviderModelContract::new("mistral-small-latest")),
            )
            .with_model_catalog(
                ProviderModelCatalogContract::new("embeddings")
                    .with_model(ProviderModelContract::new("mistral-embed")),
            )
            .with_model_catalog(
                ProviderModelCatalogContract::new("audio")
                    .with_model(ProviderModelContract::new("voxtral-mini-transcribe")),
            )
            .with_model_catalog(
                ProviderModelCatalogContract::new("realtime-audio").with_model(
                    ProviderModelContract::new("voxtral-mini-transcribe-realtime-2602"),
                ),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "mistral.chat.completions",
                    "chat",
                    input_schema(&introspection, "mistral.chat.completions"),
                )
                .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "mistral.embeddings.create",
                    "embeddings",
                    input_schema(&introspection, "mistral.embeddings.create"),
                )
                .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "mistral.audio.transcriptions",
                    "audio",
                    input_schema(&introspection, "mistral.audio.transcriptions"),
                )
                .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "mistral.audio.realtime.transcribe",
                    "realtime-audio",
                    input_schema(&introspection, "mistral.audio.realtime.transcribe"),
                )
                .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new(
                "api",
                "https://api.mistral.ai/v1",
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
                introspection,
            ))
            .with_import_side_effect(ProviderImportSideEffectContract::new(
                "fcp_mistral",
                "provider registry",
            )),
    );
}

#[fcp_async_core::runtime::test]
async fn mistral_manifest_operations_match_runtime_introspection() {
    let manifest = mistral_manifest_unchecked();
    manifest
        .validate()
        .expect("Mistral manifest should validate with its checked interface hash");

    let connector = MistralConnector::new();
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
fn mistral_manifest_input_schemas_validate_representative_payloads() {
    let manifest = mistral_manifest_unchecked();

    let chat_schema = manifest_input_schema(&manifest, "mistral.chat.completions");
    assert_schema_accepts(
        chat_schema,
        &json!({"messages": [{"role": "user", "content": "hello"}], "model": "mistral-small-latest"}),
    );
    assert_schema_rejects(chat_schema, &json!({}));
    assert_schema_rejects(chat_schema, &json!({"messages": []}));

    let embeddings_schema = manifest_input_schema(&manifest, "mistral.embeddings.create");
    assert_schema_accepts(
        embeddings_schema,
        &json!({"input": ["alpha", "beta"], "model": "mistral-embed"}),
    );
    assert_schema_rejects(embeddings_schema, &json!({}));

    let transcription_schema = manifest_input_schema(&manifest, "mistral.audio.transcriptions");
    assert_schema_accepts(
        transcription_schema,
        &json!({"audio_base64": "YWJj", "filename": "sample.wav", "content_type": "audio/wav"}),
    );
    assert_schema_rejects(transcription_schema, &json!({"audio_base64": ""}));
    assert_schema_rejects(transcription_schema, &json!({"filename": "sample.wav"}));

    let realtime_schema = manifest_input_schema(&manifest, "mistral.audio.realtime.transcribe");
    assert_schema_accepts(
        realtime_schema,
        &json!({"audio_chunks_base64": ["YWJj"], "sample_rate": 48000, "max_events": 1024}),
    );
    assert_schema_rejects(realtime_schema, &json!({}));
    assert_schema_rejects(realtime_schema, &json!({"audio_chunks_base64": []}));
    assert_schema_rejects(
        realtime_schema,
        &json!({"audio_base64": "YWJj", "sample_rate": 48001}),
    );
    assert_schema_rejects(
        realtime_schema,
        &json!({"audio_base64": "YWJj", "max_events": 1025}),
    );

    let models_schema = manifest_input_schema(&manifest, "mistral.models.list");
    assert_schema_accepts(models_schema, &json!({}));
    assert_schema_rejects(models_schema, &json!(null));
}
