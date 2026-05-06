use std::collections::BTreeMap;

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, ProviderExtensions, ResponseFormat, ToolChoice,
    ToolDefinition,
};
use fcp_prelude::{FcpError, FcpResult};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::client::DEFAULT_MODEL;

pub const DEFAULT_CONTEXT_WINDOW_TOKENS: u32 = 256_000;

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
    pub estimated_input_tokens: Option<u32>,
    pub context_window_tokens: Option<u32>,
    pub thinking: Option<Value>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl ChatInvokeInput {
    pub fn into_request(
        mut self,
        default_model: &str,
        default_context_window_tokens: u32,
    ) -> FcpResult<ChatCompletionsRequest> {
        validate_moonshot_chat_input(&self, default_model, default_context_window_tokens)?;
        if let Some(tokens) = self.max_completion_tokens {
            self.provider_extensions
                .insert("max_completion_tokens".into(), json!(tokens));
        }
        if let Some(thinking) = self.thinking.take() {
            self.provider_extensions.insert("thinking".into(), thinking);
        }
        Ok(ChatCompletionsRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            messages: self.messages,
            temperature: self.temperature,
            max_tokens: if self.max_completion_tokens.is_some() {
                None
            } else {
                self.max_tokens
            },
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

pub fn chat_request_from_value(
    value: Value,
    default_model: &str,
    default_context_window_tokens: u32,
) -> FcpResult<ChatCompletionsRequest> {
    let input: ChatInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Moonshot chat input: {err}"),
        })?;
    input.into_request(
        if default_model.trim().is_empty() {
            DEFAULT_MODEL
        } else {
            default_model
        },
        default_context_window_tokens,
    )
}

#[must_use]
pub fn context_window_for_model(model: &str) -> Option<u32> {
    match model.trim() {
        "kimi-k2.6"
        | "kimi-k2.5"
        | "kimi-k2"
        | "kimi-k2-0905-preview"
        | "kimi-k2-turbo-preview"
        | "kimi-k2-thinking"
        | "kimi-k2-thinking-turbo" => Some(256_000),
        "kimi-k2-0711-preview" | "moonshot-v1-128k" | "moonshot-v1-128k-vision-preview" => {
            Some(128_000)
        }
        "moonshot-v1-32k" | "moonshot-v1-32k-vision-preview" => Some(32_000),
        "moonshot-v1-8k" | "moonshot-v1-8k-vision-preview" => Some(8_000),
        _ => None,
    }
}

#[must_use]
pub const fn context_window_class(tokens: u32) -> &'static str {
    match tokens {
        0..=8_000 => "8k",
        8_001..=32_000 => "32k",
        32_001..=128_000 => "128k",
        128_001..=256_000 => "256k",
        _ => "custom",
    }
}

fn validate_moonshot_chat_input(
    input: &ChatInvokeInput,
    default_model: &str,
    default_context_window_tokens: u32,
) -> FcpResult<()> {
    if input.messages.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "messages must be a non-empty array".into(),
        });
    }
    if input.max_tokens.is_some() && input.max_completion_tokens.is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Provide only one of max_tokens or max_completion_tokens".into(),
        });
    }
    if input.n.is_some_and(|n| n != 1) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Moonshot only supports n=1 when n is supplied".into(),
        });
    }
    let model = input.model.as_deref().unwrap_or(default_model);
    if model.trim().is_empty() || model.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "model must be a non-empty printable Moonshot model id".into(),
        });
    }
    let context_window = input
        .context_window_tokens
        .or_else(|| context_window_for_model(model))
        .unwrap_or(default_context_window_tokens);
    if let Some(estimated_input_tokens) = input.estimated_input_tokens {
        let requested_output = input
            .max_completion_tokens
            .or(input.max_tokens)
            .unwrap_or(1024);
        if estimated_input_tokens.saturating_add(requested_output) > context_window {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: format!(
                    "Moonshot context limit exceeded for model {model}: estimated input tokens ({estimated_input_tokens}) plus requested output tokens ({requested_output}) exceeds context window ({context_window}); refusing to silently truncate"
                ),
            });
        }
    }
    Ok(())
}
