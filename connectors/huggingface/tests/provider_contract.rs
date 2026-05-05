use fcp_huggingface::connector::HuggingfaceConnector;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderModelContract,
    ProviderOperationContract, ProviderRedactionPayload, assert_provider_contract,
};
use serde_json::json;

#[fcp_async_core::runtime::test]
async fn huggingface_provider_contract_is_advertised() {
    let redaction_marker = "huggingface-provider-contract-marker";
    let mut connector = HuggingfaceConnector::new();
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let configure = connector
        .handle_configure(json!({
            "api_token": redaction_marker,
            "inference_url": "http://127.0.0.1:1",
            "hub_url": "http://127.0.0.1:2/api"
        }))
        .await
        .expect("loopback configure should succeed");
    let doctor = connector
        .handle_doctor()
        .await
        .expect("doctor should serialize");

    assert_provider_contract(
        &ProviderContract::new("huggingface", "Hugging Face")
            .with_docs_path("/connectors/huggingface/manifest.toml")
            .with_config_key("api_token")
            .with_config_key("inference_url")
            .with_config_key("hub_url")
            .with_config_key("retry")
            .with_config_key("request_timeout_ms")
            .with_auth_method(
                ProviderAuthMethodContract::new("api_token", "API token")
                    .with_config_key("api_token"),
            )
            .with_model_picker_method("api_token")
            .with_default_model("gpt2")
            .with_model_catalog(
                ProviderModelCatalogContract::new("inference")
                    .with_model(ProviderModelContract::new("gpt2"))
                    .with_model(ProviderModelContract::new("facebook/bart-large-cnn")),
            )
            .with_operation(
                ProviderOperationContract::new("huggingface.inference.text_generation")
                    .with_catalog_id("inference")
                    .with_default_model("gpt2")
                    .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::new("huggingface.inference.summarization")
                    .with_catalog_id("inference")
                    .with_default_model("facebook/bart-large-cnn")
                    .require_default_model(),
            )
            .with_operation(
                ProviderOperationContract::new("huggingface.models.info")
                    .with_catalog_id("inference")
                    .with_default_model_deferral(
                        "model_id is caller-selected; this incubating connector does not publish a default for model metadata lookup",
                    )
                    .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new(
                "inference",
                "https://api-inference.huggingface.co",
            ))
            .with_base_url(ProviderBaseUrlContract::new("hub", "https://huggingface.co/api"))
            .with_base_url(
                ProviderBaseUrlContract::new("loopback-inference", "http://127.0.0.1:1")
                    .allow_loopback_http(),
            )
            .with_secret_marker(redaction_marker)
            .with_redaction_payload(ProviderRedactionPayload::new("configure", configure))
            .with_redaction_payload(ProviderRedactionPayload::new("doctor", doctor))
            .with_redaction_payload(ProviderRedactionPayload::new("introspection", introspection))
            .with_import_side_effect(ProviderImportSideEffectContract::new(
                "fcp_huggingface",
                "provider registry",
            )),
    );
}
