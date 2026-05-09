use std::collections::BTreeMap;

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, EmbeddingInput, EmbeddingsRequest, ProviderExtensions,
    ResponseFormat, ToolChoice, ToolDefinition,
};
use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::client::DEFAULT_MODEL;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatInvokeInput {
    pub model: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub max_completion_tokens: Option<u32>,
    pub top_p: Option<f32>,
    pub stop: Option<Vec<String>>,
    pub tools: Option<Vec<ToolDefinition>>,
    pub tool_choice: Option<ToolChoice>,
    pub response_format: Option<ResponseFormat>,
    pub seed: Option<i64>,
    pub user: Option<String>,
    pub n: Option<u32>,
    pub presence_penalty: Option<f32>,
    pub frequency_penalty: Option<f32>,
    pub logit_bias: Option<BTreeMap<String, f32>>,
    pub logprobs: Option<bool>,
    pub top_logprobs: Option<u32>,
    pub reasoning_effort: Option<String>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl ChatInvokeInput {
    pub fn into_request(mut self, default_model: &str) -> FcpResult<ChatCompletionsRequest> {
        validate_chat_input(&self)?;
        insert_optional_u32(
            &mut self.provider_extensions,
            "max_completion_tokens",
            self.max_completion_tokens,
        );
        insert_optional_string(
            &mut self.provider_extensions,
            "reasoning_effort",
            self.reasoning_effort,
        );
        Ok(ChatCompletionsRequest {
            model: model_or_default(self.model, default_model),
            messages: self.messages,
            temperature: self.temperature,
            max_tokens: self.max_tokens,
            top_p: self.top_p,
            stop: self.stop,
            stream: false,
            tools: self.tools,
            tool_choice: self.tool_choice,
            response_format: self.response_format,
            seed: self.seed,
            user: self.user,
            n: self.n,
            presence_penalty: self.presence_penalty,
            frequency_penalty: self.frequency_penalty,
            logit_bias: self.logit_bias,
            logprobs: self.logprobs,
            top_logprobs: self.top_logprobs,
            provider_extensions: self.provider_extensions,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingsInvokeInput {
    pub model: Option<String>,
    pub input: EmbeddingInput,
    pub encoding_format: Option<String>,
    pub dimensions: Option<u32>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl EmbeddingsInvokeInput {
    pub fn into_request(self, default_model: &str) -> FcpResult<EmbeddingsRequest> {
        validate_embedding_input(&self)?;
        Ok(EmbeddingsRequest {
            model: model_or_default(self.model, default_model),
            input: self.input,
            encoding_format: self.encoding_format,
            dimensions: self.dimensions,
            provider_extensions: self.provider_extensions,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponsesCreateInput {
    pub model: Option<String>,
    pub input: Value,
    pub instructions: Option<String>,
    pub include: Option<Vec<String>>,
    pub tools: Option<Vec<Value>>,
    pub tool_choice: Option<Value>,
    pub max_output_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub store: Option<bool>,
    pub background: Option<bool>,
    pub previous_response_id: Option<String>,
    pub metadata: Option<Value>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ResponsesCreateRequest {
    pub model: String,
    pub input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_extensions: ProviderExtensions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResponsesSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub output_text: String,
    pub output_text_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<Value>,
}

impl ResponsesCreateInput {
    fn into_request(self, default_model: &str) -> FcpResult<ResponsesCreateRequest> {
        validate_responses_input(&self)?;
        Ok(ResponsesCreateRequest {
            model: model_or_default(self.model, default_model),
            input: self.input,
            instructions: self.instructions,
            include: self.include,
            tools: self.tools,
            tool_choice: self.tool_choice,
            max_output_tokens: self.max_output_tokens,
            temperature: self.temperature,
            top_p: self.top_p,
            store: self.store,
            background: self.background,
            previous_response_id: self.previous_response_id,
            metadata: self.metadata,
            provider_extensions: self.provider_extensions,
        })
    }
}

pub fn chat_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<ChatCompletionsRequest> {
    let input: ChatInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Microsoft Foundry chat input: {err}"),
        })?;
    input.into_request(default_model_or_global(default_model))
}

pub fn embeddings_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<EmbeddingsRequest> {
    let input: EmbeddingsInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Microsoft Foundry embeddings input: {err}"),
        })?;
    input.into_request(default_model_or_global(default_model))
}

pub fn responses_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<ResponsesCreateRequest> {
    let input: ResponsesCreateInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Microsoft Foundry responses input: {err}"),
        })?;
    input.into_request(default_model_or_global(default_model))
}

pub fn summarize_responses_value(raw: &Value) -> ResponsesSummary {
    let mut output_text_parts = Vec::new();
    collect_output_text(raw, &mut output_text_parts);
    let output_text = output_text_parts.join("\n");
    ResponsesSummary {
        id: raw
            .get("id")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        model: raw
            .get("model")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        status: raw
            .get("status")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        output_text_bytes: output_text.len(),
        output_text,
        usage: raw.get("usage").cloned(),
    }
}

fn validate_chat_input(input: &ChatInvokeInput) -> FcpResult<()> {
    if input.messages.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "messages must be a non-empty array".into(),
        });
    }
    if input.n.is_some_and(|n| n == 0) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "n must be greater than 0 when supplied".into(),
        });
    }
    if input.max_tokens.is_some() && input.max_completion_tokens.is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Provide max_tokens or max_completion_tokens, not both".into(),
        });
    }
    validate_model(input.model.as_deref())?;
    Ok(())
}

fn validate_embedding_input(input: &EmbeddingsInvokeInput) -> FcpResult<()> {
    validate_model(input.model.as_deref())?;
    if matches!(&input.input, EmbeddingInput::Batch(values) if values.is_empty()) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "embedding input batch must not be empty".into(),
        });
    }
    Ok(())
}

fn validate_responses_input(input: &ResponsesCreateInput) -> FcpResult<()> {
    if input.input.is_null() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "input is required for microsoft_foundry.responses.create".into(),
        });
    }
    validate_model(input.model.as_deref())?;
    if let Some(include) = &input.include {
        for value in include {
            validate_header_safe_string("include", value)?;
        }
    }
    Ok(())
}

fn validate_model(model: Option<&str>) -> FcpResult<()> {
    if let Some(model) = model {
        validate_header_safe_string("model", model)?;
        if model.contains('/') {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "model is a Foundry deployment name and must not contain path separators"
                    .into(),
            });
        }
    }
    Ok(())
}

fn validate_header_safe_string(field: &str, value: &str) -> FcpResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} entries must not be empty"),
        });
    }
    if trimmed
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!("{field} entries contain invalid control characters"),
        });
    }
    Ok(())
}

fn insert_optional_string(
    extensions: &mut ProviderExtensions,
    key: &'static str,
    value: Option<String>,
) {
    if let Some(value) = value {
        extensions.insert(key.to_string(), json!(value));
    }
}

fn insert_optional_u32(extensions: &mut ProviderExtensions, key: &'static str, value: Option<u32>) {
    if let Some(value) = value {
        extensions.insert(key.to_string(), json!(value));
    }
}

fn model_or_default(model: Option<String>, default_model: &str) -> String {
    model.unwrap_or_else(|| default_model_or_global(default_model).to_string())
}

fn default_model_or_global(default_model: &str) -> &str {
    if default_model.trim().is_empty() {
        DEFAULT_MODEL
    } else {
        default_model
    }
}

fn collect_output_text(value: &Value, output_text_parts: &mut Vec<String>) {
    if value
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "output_text")
    {
        if let Some(text) = value.get("text").and_then(Value::as_str) {
            output_text_parts.push(text.to_string());
        }
    }
    if output_text_parts.is_empty() {
        if let Some(text) = value
            .get("output_text")
            .or_else(|| value.pointer("/text/value"))
            .and_then(Value::as_str)
        {
            output_text_parts.push(text.to_string());
        }
    }

    match value {
        Value::Array(values) => {
            for child in values {
                collect_output_text(child, output_text_parts);
            }
        }
        Value::Object(map) => {
            for child in map.values() {
                collect_output_text(child, output_text_parts);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chat_request_maps_max_completion_tokens_to_provider_extension() {
        let request = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "max_completion_tokens": 32,
                "reasoning_effort": "low"
            }),
            DEFAULT_MODEL,
        )
        .expect("chat request should build");
        let value = serde_json::to_value(request).expect("request serializes");
        assert_eq!(value["max_completion_tokens"], 32);
        assert_eq!(value["reasoning_effort"], "low");
        assert!(value.get("max_tokens").is_none());
    }

    #[test]
    fn chat_request_rejects_ambiguous_token_limits() {
        let error = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 32,
                "max_completion_tokens": 32
            }),
            DEFAULT_MODEL,
        )
        .expect_err("ambiguous token limits should fail");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn responses_request_serializes_background_and_store_without_prompt_logging_fields() {
        let request = responses_request_from_value(
            json!({
                "model": "prod-gpt4o",
                "input": [{"role": "user", "content": "private"}],
                "background": true,
                "store": false
            }),
            DEFAULT_MODEL,
        )
        .expect("responses request should build");
        let value = serde_json::to_value(request).expect("request serializes");
        assert_eq!(value["model"], "prod-gpt4o");
        assert_eq!(value["background"], true);
        assert_eq!(value["store"], false);
    }

    #[test]
    fn embedding_batch_must_not_be_empty() {
        let error = embeddings_request_from_value(json!({"input": []}), "embed-deploy")
            .expect_err("empty embedding batch should fail");
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn response_summary_extracts_nested_output_text() {
        let raw = json!({
            "id": "resp_1",
            "model": "gpt-4o",
            "status": "completed",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": "hello"}]
            }],
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let summary = summarize_responses_value(&raw);
        assert_eq!(summary.id.as_deref(), Some("resp_1"));
        assert_eq!(summary.output_text, "hello");
        assert_eq!(summary.output_text_bytes, 5);
    }
}
