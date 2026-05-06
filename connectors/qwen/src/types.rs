use std::collections::BTreeMap;

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, ContentPart, ContentParts, EmbeddingInput,
    EmbeddingsRequest, ProviderExtensions, ResponseFormat, ToolChoice, ToolDefinition,
};
use fcp_prelude::{FcpError, FcpResult};
use serde::Deserialize;
use serde_json::Value;

use crate::client::{DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL, DEFAULT_VISION_MODEL};

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
    pub fn into_request(
        self,
        default_model: &str,
        default_vision_model: &str,
    ) -> FcpResult<ChatCompletionsRequest> {
        validate_qwen_chat_input(&self)?;
        let has_image_input = messages_contain_image_url(&self.messages);
        let model = match self.model {
            Some(model) => validate_qwen_model_id("model", &model)?,
            None if has_image_input => {
                validate_qwen_model_id("default_vision_model", default_vision_model)?
            }
            None => validate_qwen_model_id("default_model", default_model)?,
        };
        if has_image_input && !is_qwen_vision_model(&model) {
            return invalid("image_url content requires a Qwen-VL/QVQ model");
        }
        Ok(ChatCompletionsRequest {
            model,
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
        validate_qwen_embeddings_input(&self)?;
        Ok(EmbeddingsRequest {
            model: self.model.map_or_else(
                || validate_qwen_model_id("default_embedding_model", default_model),
                |model| validate_qwen_model_id("model", &model),
            )?,
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
    default_vision_model: &str,
) -> FcpResult<ChatCompletionsRequest> {
    let input: ChatInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Qwen chat input: {err}"),
        })?;
    input.into_request(
        non_empty_or_default(default_model, DEFAULT_MODEL),
        non_empty_or_default(default_vision_model, DEFAULT_VISION_MODEL),
    )
}

pub fn embeddings_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<EmbeddingsRequest> {
    let input: EmbeddingsInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Qwen embeddings input: {err}"),
        })?;
    input.into_request(non_empty_or_default(default_model, DEFAULT_EMBEDDING_MODEL))
}

pub fn validate_qwen_model_id(field: &str, model: &str) -> FcpResult<String> {
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
    if trimmed.chars().any(char::is_whitespace) {
        return invalid(&format!("{field} must not contain whitespace"));
    }
    Ok(trimmed.to_string())
}

pub fn messages_contain_image_url(messages: &[ChatMessage]) -> bool {
    messages.iter().any(message_contains_image_url)
}

pub fn count_image_url_blocks(messages: &[ChatMessage]) -> usize {
    messages.iter().map(count_message_image_url_blocks).sum()
}

fn validate_qwen_chat_input(input: &ChatInvokeInput) -> FcpResult<()> {
    if input.messages.is_empty() {
        return invalid("messages must be a non-empty array");
    }
    if input.max_tokens.is_some() && input.max_completion_tokens.is_some() {
        return invalid("Provide only one of max_tokens or max_completion_tokens");
    }
    if input.n.is_some_and(|n| n == 0 || n > 128) {
        return invalid("n must be between 1 and 128 when supplied");
    }
    validate_messages(&input.messages)
}

fn validate_qwen_embeddings_input(input: &EmbeddingsInvokeInput) -> FcpResult<()> {
    if input.dimensions.is_some_and(|dimensions| dimensions == 0) {
        return invalid("dimensions must be greater than 0 when supplied");
    }
    match &input.input {
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

fn validate_messages(messages: &[ChatMessage]) -> FcpResult<()> {
    for message in messages {
        if let ChatMessage::User { content, .. } = message {
            validate_content_parts(content)?;
        }
    }
    Ok(())
}

fn validate_content_parts(content: &ContentParts) -> FcpResult<()> {
    match content {
        ContentParts::Text(text) if text.trim().is_empty() => {
            invalid("user text content must not be empty")
        }
        ContentParts::Text(_) => Ok(()),
        ContentParts::Multimodal(parts) if parts.is_empty() => {
            invalid("multimodal user content must not be empty")
        }
        ContentParts::Multimodal(parts) => {
            for part in parts {
                validate_content_part(part)?;
            }
            Ok(())
        }
    }
}

fn validate_content_part(part: &ContentPart) -> FcpResult<()> {
    match part {
        ContentPart::Text { text } if text.trim().is_empty() => {
            invalid("multimodal text blocks must not be empty")
        }
        ContentPart::Text { .. } => Ok(()),
        ContentPart::ImageUrl { image_url } => validate_image_url(&image_url.url),
        ContentPart::InputAudio { .. } => invalid(
            "Qwen OpenAI-compatible chat does not accept input_audio blocks in this connector",
        ),
    }
}

fn validate_image_url(value: &str) -> FcpResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return invalid("image_url.url must not be empty");
    }
    if trimmed
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return invalid("image_url.url contains invalid characters");
    }
    if !matches_url_or_image_data(trimmed) {
        return invalid("image_url.url must be https or a data:image URI");
    }
    Ok(())
}

fn matches_url_or_image_data(value: &str) -> bool {
    value.starts_with("https://") || value.starts_with("data:image/")
}

fn message_contains_image_url(message: &ChatMessage) -> bool {
    count_message_image_url_blocks(message) > 0
}

fn count_message_image_url_blocks(message: &ChatMessage) -> usize {
    match message {
        ChatMessage::User {
            content: ContentParts::Multimodal(parts),
            ..
        } => parts
            .iter()
            .filter(|part| matches!(part, ContentPart::ImageUrl { .. }))
            .count(),
        _ => 0,
    }
}

fn is_qwen_vision_model(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    lower.contains("-vl")
        || lower.starts_with("qwen-vl")
        || lower.starts_with("qwen3-vl")
        || lower.starts_with("qvq")
}

fn non_empty_or_default<'a>(value: &'a str, default: &'static str) -> &'a str {
    if value.trim().is_empty() {
        default
    } else {
        value
    }
}

fn invalid<T>(message: &str) -> FcpResult<T> {
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    })
}
