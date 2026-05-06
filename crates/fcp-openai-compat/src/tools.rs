//! Tool-call normalization helpers.

use serde::Deserialize;
use serde_json::Value;

use crate::{FunctionCall, OpenAiError, ToolCall};

/// Tool-call normalization entry point.
pub struct Tools;

#[derive(Debug, Deserialize)]
struct LegacyFunctionCall {
    name: String,
    arguments: String,
}

impl Tools {
    /// Normalize modern `tool_calls` or legacy `function_call` payloads into
    /// the modern tool-call list.
    pub fn normalize(value: &Value) -> Result<Vec<ToolCall>, OpenAiError> {
        let mut calls = Vec::new();
        if let Some(tool_calls) = value.get("tool_calls") {
            let parsed: Vec<ToolCall> =
                serde_json::from_value(tool_calls.clone()).map_err(|err| {
                    OpenAiError::InvalidRequest {
                        message: format!("malformed tool_calls payload: {err}"),
                        param: Some("tool_calls".to_string()),
                        code: Some("malformed_tool_calls".to_string()),
                    }
                })?;
            calls.extend(parsed);
        }

        if let Some(function_call) = value.get("function_call") {
            let legacy: LegacyFunctionCall = serde_json::from_value(function_call.clone())
                .map_err(|err| OpenAiError::InvalidRequest {
                    message: format!("malformed function_call payload: {err}"),
                    param: Some("function_call".to_string()),
                    code: Some("malformed_function_call".to_string()),
                })?;
            calls.push(ToolCall {
                id: "legacy_function_call".to_string(),
                tool_type: "function".to_string(),
                function: FunctionCall {
                    name: legacy.name,
                    arguments: legacy.arguments,
                },
            });
        }

        Ok(calls)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn normalizes_modern_tool_calls() {
        let calls = Tools::normalize(&json!({
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {"name": "lookup", "arguments": "{\"q\":\"x\"}"}
            }]
        }))
        .expect("modern tool calls normalize");

        assert_eq!(calls[0].id, "call_1");
    }

    #[test]
    fn normalizes_legacy_function_call() {
        let calls = Tools::normalize(&json!({
            "function_call": {"name": "lookup", "arguments": "{\"q\":\"x\"}"}
        }))
        .expect("legacy function call normalizes");

        assert_eq!(calls[0].id, "legacy_function_call");
        assert_eq!(calls[0].function.name, "lookup");
    }

    #[test]
    fn malformed_tool_calls_are_rejected() {
        let err = Tools::normalize(&json!({"tool_calls": {"bad": true}}))
            .expect_err("object is not a valid tool_calls array");
        assert!(matches!(err, OpenAiError::InvalidRequest { .. }));
    }
}
