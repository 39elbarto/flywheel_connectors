use std::collections::BTreeMap;

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, CompletionsRequest, EmbeddingInput, EmbeddingsRequest,
    PromptInput, ProviderExtensions, ResponseFormat, ToolChoice, ToolDefinition,
};
use fcp_prelude::{FcpError, FcpResult};
use serde::Deserialize;
use serde_json::Value;

use crate::client::{DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChatInvokeInput {
    pub model: Option<String>,
    pub messages: Vec<ChatMessage>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
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
    pub safety_model: Option<String>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl ChatInvokeInput {
    pub fn into_request(self, default_model: &str) -> FcpResult<ChatCompletionsRequest> {
        validate_together_chat_input(&self)?;
        let mut provider_extensions = self.provider_extensions;
        insert_optional_string(
            &mut provider_extensions,
            "reasoning_effort",
            self.reasoning_effort,
        );
        insert_optional_string(&mut provider_extensions, "safety_model", self.safety_model);
        Ok(ChatCompletionsRequest {
            model: validate_or_default_model(self.model, default_model)?,
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
            provider_extensions,
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
        validate_embedding_input_value(&self.input)?;
        if self.dimensions.is_some_and(|dimensions| dimensions == 0) {
            return invalid("dimensions must be greater than 0 when supplied");
        }
        Ok(EmbeddingsRequest {
            model: validate_or_default_model(self.model, default_model)?,
            input: self.input,
            encoding_format: self.encoding_format,
            dimensions: self.dimensions,
            provider_extensions: self.provider_extensions,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyCompletionsInput {
    pub model: Option<String>,
    pub prompt: PromptInput,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f32>,
    pub safety_model: Option<String>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl LegacyCompletionsInput {
    pub fn into_request(self, default_model: &str) -> FcpResult<CompletionsRequest> {
        validate_prompt_input_value(&self.prompt)?;
        let mut provider_extensions = self.provider_extensions;
        insert_optional_string(&mut provider_extensions, "safety_model", self.safety_model);
        Ok(CompletionsRequest {
            model: validate_or_default_model(self.model, default_model)?,
            prompt: self.prompt,
            max_tokens: self.max_tokens,
            temperature: self.temperature,
            provider_extensions,
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
            message: format!("Invalid Together chat input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_MODEL
    } else {
        default_model
    })
}

pub fn embeddings_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<EmbeddingsRequest> {
    let input: EmbeddingsInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Together embeddings input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_EMBEDDING_MODEL
    } else {
        default_model
    })
}

pub fn legacy_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<CompletionsRequest> {
    let input: LegacyCompletionsInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Together legacy completions input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_MODEL
    } else {
        default_model
    })
}

pub fn validate_together_model_id(field: &str, model: &str) -> FcpResult<String> {
    let trimmed = model.trim();
    if trimmed.is_empty() {
        return invalid(&format!("{field} must not be empty"));
    }
    if trimmed
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return invalid(&format!(
            "{field} contains characters that are invalid in requests"
        ));
    }
    let Some((namespace, name)) = trimmed.split_once('/') else {
        return invalid(&format!(
            "{field} must include a namespace/model separator, for example openai/gpt-oss-20b"
        ));
    };
    if namespace.trim().is_empty() || name.trim().is_empty() {
        return invalid(&format!(
            "{field} must include non-empty namespace and model"
        ));
    }
    if trimmed.chars().any(char::is_whitespace) {
        return invalid(&format!("{field} must not contain whitespace"));
    }
    Ok(trimmed.to_string())
}

fn validate_together_chat_input(input: &ChatInvokeInput) -> FcpResult<()> {
    if input.messages.is_empty() {
        return invalid("messages must be a non-empty array");
    }
    if input.n.is_some_and(|n| n == 0 || n > 128) {
        return invalid("n must be between 1 and 128 when supplied");
    }
    validate_optional_reasoning_effort(input.reasoning_effort.as_deref())?;
    validate_optional_model("model", input.model.as_deref())?;
    validate_optional_model("safety_model", input.safety_model.as_deref())?;
    Ok(())
}

fn validate_optional_reasoning_effort(reasoning_effort: Option<&str>) -> FcpResult<()> {
    if reasoning_effort.is_some_and(|value| !matches!(value, "low" | "medium" | "high")) {
        return invalid("reasoning_effort must be low, medium, or high when supplied");
    }
    Ok(())
}

fn validate_optional_model(field: &str, model: Option<&str>) -> FcpResult<()> {
    if let Some(model) = model {
        validate_together_model_id(field, model)?;
    }
    Ok(())
}

fn validate_or_default_model(model: Option<String>, default_model: &str) -> FcpResult<String> {
    model.map_or_else(
        || validate_together_model_id("default_model", default_model),
        |model| validate_together_model_id("model", &model),
    )
}

fn validate_embedding_input_value(input: &EmbeddingInput) -> FcpResult<()> {
    match input {
        EmbeddingInput::Single(value) if value.trim().is_empty() => {
            invalid("embedding input must not be empty")
        }
        EmbeddingInput::Batch(values) if values.is_empty() => {
            invalid("embedding input batch must not be empty")
        }
        EmbeddingInput::Batch(values) if values.len() > 1_000 => {
            invalid("embedding input batch must contain at most 1,000 entries")
        }
        EmbeddingInput::Batch(values) if values.iter().any(|value| value.trim().is_empty()) => {
            invalid("embedding input batch entries must not be empty")
        }
        _ => Ok(()),
    }
}

fn validate_prompt_input_value(input: &PromptInput) -> FcpResult<()> {
    match input {
        PromptInput::Single(value) if value.trim().is_empty() => {
            invalid("prompt must not be empty")
        }
        PromptInput::Batch(values) if values.is_empty() => {
            invalid("prompt batch must not be empty")
        }
        PromptInput::Batch(values) if values.iter().any(|value| value.trim().is_empty()) => {
            invalid("prompt batch entries must not be empty")
        }
        _ => Ok(()),
    }
}

fn insert_optional_string(
    provider_extensions: &mut ProviderExtensions,
    key: &'static str,
    value: Option<String>,
) {
    if let Some(value) = value {
        provider_extensions.insert(key.into(), Value::String(value));
    }
}

fn invalid<T>(message: &str) -> FcpResult<T> {
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    })
}
