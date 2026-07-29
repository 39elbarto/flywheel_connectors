use std::collections::BTreeMap;

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, CompletionsRequest, PromptInput, ProviderExtensions,
    ResponseFormat, ToolChoice, ToolDefinition,
};
use fcp_prelude::{FcpError, FcpResult};
use serde::Deserialize;
use serde_json::Value;

use crate::client::DEFAULT_MODEL;

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
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl ChatInvokeInput {
    pub fn into_request(self, default_model: &str) -> FcpResult<ChatCompletionsRequest> {
        validate_groq_chat_input(&self)?;
        Ok(ChatCompletionsRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
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
            logit_bias: None,
            logprobs: None,
            top_logprobs: None,
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
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl LegacyCompletionsInput {
    pub fn into_request(self, default_model: &str) -> CompletionsRequest {
        CompletionsRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            prompt: self.prompt,
            max_tokens: self.max_tokens,
            temperature: self.temperature,
            provider_extensions: self.provider_extensions,
        }
    }
}

pub fn chat_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<ChatCompletionsRequest> {
    let input: ChatInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Groq chat input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_MODEL
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
            message: format!("Invalid Groq legacy completions input: {err}"),
        })?;
    Ok(input.into_request(default_model))
}

fn validate_groq_chat_input(input: &ChatInvokeInput) -> FcpResult<()> {
    if input.messages.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "messages must be a non-empty array".into(),
        });
    }
    if input.logprobs.is_some() || input.logit_bias.is_some() || input.top_logprobs.is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Groq does not support logprobs, logit_bias, or top_logprobs".into(),
        });
    }
    if input.n.is_some_and(|n| n != 1) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Groq only supports n=1 when n is supplied".into(),
        });
    }
    if input.messages.iter().any(message_has_name) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "Groq does not support messages[].name".into(),
        });
    }
    Ok(())
}

fn message_has_name(message: &ChatMessage) -> bool {
    match message {
        ChatMessage::System { name, .. }
        | ChatMessage::User { name, .. }
        | ChatMessage::Assistant { name, .. }
        | ChatMessage::Tool { name, .. } => name.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn groq_chat_request_uses_default_model_and_preserves_user() {
        let request = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "user": "operator-1",
                "n": 1
            }),
            DEFAULT_MODEL,
        )
        .expect("request should decode");

        assert_eq!(request.model, DEFAULT_MODEL);
        assert_eq!(request.user.as_deref(), Some("operator-1"));
        assert_eq!(request.n, Some(1));
    }

    #[test]
    fn logprobs_are_rejected_for_groq_chat() {
        let error = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "logprobs": true
            }),
            DEFAULT_MODEL,
        )
        .expect_err("logprobs should fail");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn multiple_candidates_are_rejected_for_groq_chat() {
        let error = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "n": 2
            }),
            DEFAULT_MODEL,
        )
        .expect_err("n greater than one should fail");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn message_names_are_rejected_for_groq_chat() {
        let error = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello", "name": "operator"}]
            }),
            DEFAULT_MODEL,
        )
        .expect_err("named messages should fail");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn legacy_completion_request_uses_supplied_default_model() {
        let request = legacy_request_from_value(
            json!({
                "prompt": "Summarize the build status",
                "max_tokens": 24,
                "temperature": 0.2
            }),
            "llama-3.1-8b-instant",
        )
        .expect("legacy request should decode");

        assert_eq!(request.model, "llama-3.1-8b-instant");
        assert_eq!(request.max_tokens, Some(24));
        assert_eq!(request.temperature, Some(0.2));
    }
}
