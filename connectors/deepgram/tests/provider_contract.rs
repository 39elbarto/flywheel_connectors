use fcp_deepgram::DeepgramConnector;
use fcp_testkit::provider_contract::{
    ProviderAuthMethodContract, ProviderBaseUrlContract, ProviderContract,
    ProviderImportSideEffectContract, ProviderModelCatalogContract, ProviderOperationContract,
    ProviderRedactionPayload, assert_provider_contract,
};
use serde_json::json;

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
                ProviderModelCatalogContract::new("transcription").allow_dynamic_empty_catalog(),
            )
            .with_operation(
                ProviderOperationContract::new("deepgram.listen.transcribe")
                    .with_catalog_id("transcription")
                    .with_default_model_deferral(
                        "Deepgram applies provider-side transcription defaults when model is omitted in this first connector slice",
                    )
                    .require_default_model(),
            )
            .with_base_url(ProviderBaseUrlContract::new("api", "https://api.deepgram.com"))
            .with_base_url(
                ProviderBaseUrlContract::new("loopback-test", "http://127.0.0.1:1")
                    .allow_loopback_http(),
            )
            .with_secret_marker(redaction_marker)
            .with_redaction_payload(ProviderRedactionPayload::new("configure", configure))
            .with_redaction_payload(ProviderRedactionPayload::new("doctor", doctor))
            .with_redaction_payload(ProviderRedactionPayload::new("introspection", introspection))
            .with_import_side_effect(ProviderImportSideEffectContract::new(
                "fcp_deepgram",
                "provider registry",
            )),
    );
}
