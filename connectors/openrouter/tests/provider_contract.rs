use fcp_openrouter::OpenRouterConnector;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
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
async fn openrouter_provider_contract_is_advertised() {
    let redaction_marker = "openrouter-provider-contract-marker";
    let mut connector = OpenRouterConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let configure = connector
        .handle_configure(json!({
            "api_key": redaction_marker,
            "base_url": "http://127.0.0.1:1/api/v1",
            "app_name": "FCP provider contract",
            "app_url": "https://example.com/fcp"
        }))
        .await
        .expect("loopback configure should succeed");
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");

    assert_provider_contract(
        &ProviderContract::new("openrouter", "OpenRouter")
            .with_docs_path("/connectors/openrouter/manifest.toml")
            .with_config_key("api_key")
            .with_config_key("credential_id")
            .with_config_key("base_url")
            .with_config_key("request_timeout_ms")
            .with_config_key("app_name")
            .with_config_key("app_url")
            .with_auth_method(
                ProviderAuthMethodContract::new("api_key", "API key").with_config_key("api_key"),
            )
            .with_auth_method(
                ProviderAuthMethodContract::new("credential_id", "Host credential reference")
                    .with_config_key("credential_id"),
            )
            .with_model_picker_method("api_key")
            .with_default_model("openai/gpt-4.1-mini")
            .with_model_catalog(
                ProviderModelCatalogContract::new("models")
                    .with_model(ProviderModelContract::new("openai/gpt-4.1-mini"))
                    .with_model(ProviderModelContract::new("google/veo-3.1-fast")),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "openrouter.chat.completions",
                    "models",
                    input_schema(&introspection, "openrouter.chat.completions"),
                )
                .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::from_input_schema(
                    "openrouter.videos.generate",
                    "models",
                    input_schema(&introspection, "openrouter.videos.generate"),
                )
                .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new(
                "api",
                "https://openrouter.ai/api/v1",
            ))
            .with_base_url(
                ProviderBaseUrlContract::new("loopback-test", "http://127.0.0.1:1/api/v1")
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
                "fcp_openrouter",
                "provider registry",
            )),
    );
}
