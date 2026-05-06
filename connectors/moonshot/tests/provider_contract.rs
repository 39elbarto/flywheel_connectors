use fcp_moonshot::MoonshotConnector;
use fcp_prelude::FcpConnector;
use serde_json::Value;

#[test]
fn moonshot_provider_contract_is_advertised() {
    let introspection =
        serde_json::to_value(MoonshotConnector::new().introspect()).expect("introspection json");
    let operations = introspection
        .get("operations")
        .and_then(Value::as_array)
        .expect("operations array");
    let chat = operations
        .iter()
        .find(|operation| operation["id"] == "moonshot.chat.completions")
        .expect("chat operation");
    let hints = chat
        .get("ai_hints")
        .or_else(|| chat.get("aiHints"))
        .expect("ai hints");
    assert!(hints.to_string().contains("estimated_input_tokens"));
    assert!(hints.to_string().contains("Do not log"));

    let embeddings = operations
        .iter()
        .find(|operation| operation["id"] == "moonshot.embeddings.create")
        .expect("embeddings operation");
    assert!(embeddings.to_string().contains("unsupported"));
}
