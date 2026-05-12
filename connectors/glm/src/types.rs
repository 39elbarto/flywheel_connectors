use std::collections::BTreeMap;

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, EmbeddingInput, EmbeddingsRequest, ProviderExtensions,
    ResponseFormat, ToolChoice, ToolDefinition,
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
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl ChatInvokeInput {
    pub fn into_request(self, default_model: &str) -> FcpResult<ChatCompletionsRequest> {
        validate_chat_input(&self)?;
        Ok(ChatCompletionsRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            messages: self.messages,
            temperature: self.temperature,
            max_tokens: self.max_tokens.or(self.max_completion_tokens),
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
        validate_embeddings_input(&self)?;
        Ok(EmbeddingsRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            input: self.input,
            encoding_format: self.encoding_format,
            dimensions: self.dimensions,
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
            message: format!("Invalid GLM chat input: {err}"),
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
            message: format!("Invalid GLM embeddings input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_EMBEDDING_MODEL
    } else {
        default_model
    })
}

fn validate_chat_input(input: &ChatInvokeInput) -> FcpResult<()> {
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

fn validate_embeddings_input(input: &EmbeddingsInvokeInput) -> FcpResult<()> {
    if input.dimensions.is_some_and(|dimensions| dimensions == 0) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "dimensions must be greater than 0 when supplied".into(),
        });
    }
    match &input.input {
        EmbeddingInput::Single(value) if value.trim().is_empty() => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "embedding input must not be empty".into(),
        }),
        EmbeddingInput::Batch(values) if values.is_empty() => Err(FcpError::InvalidRequest {
            code: 1003,
            message: "embedding input batch must not be empty".into(),
        }),
        EmbeddingInput::Batch(values) if values.iter().any(|value| value.trim().is_empty()) => {
            Err(FcpError::InvalidRequest {
                code: 1003,
                message: "embedding input batch entries must not be empty".into(),
            })
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chat_request_uses_connector_default_when_default_model_is_blank() {
        let request = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}]
            }),
            "   ",
        )
        .expect("chat request should decode");

        assert_eq!(request.model, DEFAULT_MODEL);
    }

    #[test]
    fn max_completion_tokens_maps_to_openai_max_tokens() {
        let request = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "max_completion_tokens": 128
            }),
            DEFAULT_MODEL,
        )
        .expect("chat request should decode");

        assert_eq!(request.max_tokens, Some(128));
    }

    #[test]
    fn conflicting_token_limits_are_rejected() {
        let error = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "hello"}],
                "max_tokens": 64,
                "max_completion_tokens": 128
            }),
            DEFAULT_MODEL,
        )
        .expect_err("conflicting token limits should fail");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn empty_chat_messages_are_rejected() {
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
    fn blank_embedding_input_is_rejected() {
        let error = embeddings_request_from_value(
            json!({
                "input": "   "
            }),
            DEFAULT_EMBEDDING_MODEL,
        )
        .expect_err("blank embedding input should fail");

        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
}
