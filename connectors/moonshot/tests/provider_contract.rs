use fcp_moonshot::MoonshotConnector;
use fcp_prelude::FcpConnector;
use serde_json::Value;

#[test]
fn moonshot_provider_contract_is_advertised() -> Result<(), String> {
    let introspection = serde_json::to_value(MoonshotConnector::new().introspect())
        .map_err(|error| error.to_string())?;
    let operations = introspection
        .get("operations")
        .and_then(Value::as_array)
        .ok_or_else(|| "operations array missing".to_string())?;
    let chat = operations
        .iter()
        .find(|operation| {
            operation.get("id").and_then(Value::as_str) == Some("moonshot.chat.completions")
        })
        .ok_or_else(|| "chat operation missing".to_string())?;
    let hints = chat
        .get("ai_hints")
        .or_else(|| chat.get("aiHints"))
        .ok_or_else(|| "ai hints missing".to_string())?;
    assert!(hints.to_string().contains("estimated_input_tokens"));
    assert!(hints.to_string().contains("Do not log"));

    let embeddings = operations
        .iter()
        .find(|operation| {
            operation.get("id").and_then(Value::as_str) == Some("moonshot.embeddings.create")
        })
        .ok_or_else(|| "embeddings operation missing".to_string())?;
    assert!(embeddings.to_string().contains("unavailable"));
    Ok(())
}
