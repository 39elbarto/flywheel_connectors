use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
use fcp_together::TogetherConnector;
use fcp_together::client::{DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL};
use serde_json::{Value, json};

fn input_schema<'a>(introspection: &'a Value, operation_id: &str) -> &'a Value {
    introspection
        .get("operations")
        .and_then(Value::as_array)
        .and_then(|operations| {
            operations
                .iter()
                .find(|operation| operation.get("id").and_then(Value::as_str) == Some(operation_id))
        })
        .and_then(|operation| operation.get("input_schema"))
        .expect("operation input_schema should be present")
}

#[fcp_async_core::runtime::test]
async fn together_provider_contract_is_advertised() {
    let redaction_marker = "together-provider-contract-marker";
    let mut connector = TogetherConnector::new();
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
        &ProviderContract::new("together", "Together AI")
            .with_docs_path("/connectors/together/manifest.toml")
            .with_config_key("api_key")
            .with_config_key("credential_id")
            .with_config_key("base_url")
            .with_config_key("default_model")
            .with_config_key("default_embedding_model")
            .with_config_key("request_timeout_ms")
            .with_auth_method(
                ProviderAuthMethodContract::new("api_key", "API key").with_config_key("api_key"),
            )
            .with_auth_method(
                ProviderAuthMethodContract::new("credential_id", "Host credential reference")
                    .with_config_key("credential_id"),
            )
            .with_model_picker_method("api_key")
            .with_default_model(DEFAULT_MODEL)
            .with_model_catalog(
                ProviderModelCatalogContract::new("models")
                    .with_model(ProviderModelContract::new(DEFAULT_MODEL))
                    .with_model(ProviderModelContract::new(DEFAULT_EMBEDDING_MODEL)),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "together.chat.completions",
                    "models",
                    input_schema(&introspection, "together.chat.completions"),
                )
                .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "together.embeddings.create",
                    "models",
                    input_schema(&introspection, "together.embeddings.create"),
                )
                .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new(
                "api",
                "https://api.together.ai/v1",
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
                introspection,
            ))
            .with_import_side_effect(ProviderImportSideEffectContract::new(
                "fcp_together",
                "provider registry",
            )),
    );
}
