use std::collections::BTreeMap;

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, ProviderExtensions, ResponseFormat, ToolChoice,
    ToolDefinition,
};
use fcp_prelude::{FcpError, FcpResult};
use serde::Deserialize;
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
    pub reasoning_format: Option<String>,
    pub clear_thinking: Option<bool>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl ChatInvokeInput {
    pub fn into_request(mut self, default_model: &str) -> FcpResult<ChatCompletionsRequest> {
        validate_cerebras_chat_input(&self)?;
        if let Some(max_completion_tokens) = self.max_completion_tokens {
            self.provider_extensions.insert(
                "max_completion_tokens".to_string(),
                json!(max_completion_tokens),
            );
        }
        if let Some(reasoning_effort) = self.reasoning_effort {
            self.provider_extensions
                .insert("reasoning_effort".to_string(), json!(reasoning_effort));
        }
        if let Some(reasoning_format) = self.reasoning_format {
            self.provider_extensions
                .insert("reasoning_format".to_string(), json!(reasoning_format));
        }
        if let Some(clear_thinking) = self.clear_thinking {
            self.provider_extensions
                .insert("clear_thinking".to_string(), json!(clear_thinking));
        }

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
) -> FcpResult<ChatCompletionsRequest> {
    let input: ChatInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Cerebras chat input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_MODEL
    } else {
        default_model
    })
}

fn validate_cerebras_chat_input(input: &ChatInvokeInput) -> FcpResult<()> {
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
    if input.n.is_some_and(|n| n == 0) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "n must be greater than 0 when supplied".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cerebras_provider_extensions_are_flattened_into_request_body() {
        let request = chat_request_from_value(
            json!({
                "model": "llama3.1-8b",
                "messages": [{"role": "user", "content": "hello"}],
                "max_completion_tokens": 256,
                "reasoning_effort": "high",
                "reasoning_format": "hidden",
                "clear_thinking": true
            }),
            DEFAULT_MODEL,
        )
        .expect("request should decode");

        let value = serde_json::to_value(request).expect("request serializes");
        assert_eq!(value["max_completion_tokens"], 256);
        assert_eq!(value["reasoning_effort"], "high");
        assert_eq!(value["reasoning_format"], "hidden");
        assert_eq!(value["clear_thinking"], true);
        assert!(value.get("provider_extensions").is_none());
    }

    #[test]
    fn blank_default_model_falls_back_to_connector_default() {
        let request = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}]
            }),
            "   ",
        )
        .expect("request should use connector default");

        assert_eq!(request.model, DEFAULT_MODEL);
    }

    #[test]
    fn empty_messages_are_rejected() {
        let error = chat_request_from_value(
            json!({
                "messages": []
            }),
            DEFAULT_MODEL,
        )
        .expect_err("empty messages should fail");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn max_token_fields_are_mutually_exclusive() {
        let error = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 32,
                "max_completion_tokens": 64
            }),
            DEFAULT_MODEL,
        )
        .expect_err("duplicated token limit should fail");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn zero_candidate_count_is_rejected() {
        let error = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "n": 0
            }),
            DEFAULT_MODEL,
        )
        .expect_err("zero candidate count should fail");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
}
