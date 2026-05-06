use std::collections::BTreeMap;

use fcp_openai_compat::{
    ChatCompletionsRequest, ChatMessage, EmbeddingInput, EmbeddingsRequest, ProviderExtensions,
    ResponseFormat, ToolChoice, ToolDefinition,
};
use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{DEFAULT_EMBEDDING_MODEL, DEFAULT_MODEL, DEFAULT_RERANK_MODEL};

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
    pub nvext: Option<Value>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl ChatInvokeInput {
    pub fn into_request(self, default_model: &str) -> FcpResult<ChatCompletionsRequest> {
        validate_chat_input(&self)?;
        let mut provider_extensions = self.provider_extensions;
        insert_optional_value(&mut provider_extensions, "nvext", self.nvext);
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
pub struct RerankInvokeInput {
    pub model: Option<String>,
    pub query: RerankTextInput,
    pub passages: Vec<RerankPassageInput>,
    pub truncate: Option<RerankTruncate>,
}

impl RerankInvokeInput {
    pub fn into_request(self, default_model: &str) -> FcpResult<RerankRequest> {
        if self.passages.is_empty() {
            return invalid("passages must contain at least one entry");
        }
        if self.passages.len() > 512 {
            return invalid("passages must contain at most 512 entries");
        }
        let query = self.query.into_data("query")?;
        let passages = self
            .passages
            .into_iter()
            .map(|passage| passage.into_data("passage"))
            .collect::<FcpResult<Vec<_>>>()?;
        Ok(RerankRequest {
            model: validate_or_default_model(self.model, default_model)?,
            query,
            passages,
            truncate: self.truncate,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RerankRequest {
    pub model: String,
    pub query: RerankData,
    pub passages: Vec<RerankData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncate: Option<RerankTruncate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RerankData {
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RerankTruncate {
    Start,
    End,
    None,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RerankResponse {
    pub rankings: Vec<RerankRanking>,
    #[serde(default)]
    pub usage: Option<RerankUsage>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RerankRanking {
    pub index: usize,
    #[serde(default)]
    pub logit: Option<f64>,
    #[serde(default)]
    pub score: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RerankUsage {
    #[serde(default)]
    pub prompt_tokens: Option<u64>,
    #[serde(default)]
    pub total_tokens: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RerankTextInput {
    Text(String),
    Object { text: String, image: Option<String> },
}

impl RerankTextInput {
    fn into_data(self, field: &str) -> FcpResult<RerankData> {
        match self {
            Self::Text(text) => {
                validate_rerank_text(field, &text).map(|text| RerankData { text, image: None })
            }
            Self::Object { text, image } => {
                let text = validate_rerank_text(field, &text)?;
                if let Some(image) = image.as_deref() {
                    validate_data_url(field, image)?;
                }
                Ok(RerankData { text, image })
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RerankPassageInput {
    Text(String),
    Object { text: String, image: Option<String> },
}

impl RerankPassageInput {
    fn into_data(self, field: &str) -> FcpResult<RerankData> {
        match self {
            Self::Text(text) => {
                validate_rerank_text(field, &text).map(|text| RerankData { text, image: None })
            }
            Self::Object { text, image } => {
                let text = validate_rerank_text(field, &text)?;
                if let Some(image) = image.as_deref() {
                    validate_data_url(field, image)?;
                }
                Ok(RerankData { text, image })
            }
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
            message: format!("Invalid NVIDIA NIM chat input: {err}"),
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
            message: format!("Invalid NVIDIA NIM embeddings input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_EMBEDDING_MODEL
    } else {
        default_model
    })
}

pub fn rerank_request_from_value(value: Value, default_model: &str) -> FcpResult<RerankRequest> {
    let input: RerankInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid NVIDIA NIM rerank input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_RERANK_MODEL
    } else {
        default_model
    })
}

pub fn validate_nim_model_id(field: &str, model: &str) -> FcpResult<String> {
    let trimmed = model.trim();
    if trimmed.is_empty() {
        return invalid(&format!("{field} must not be empty"));
    }
    if trimmed.len() > 512 {
        return invalid(&format!("{field} must be at most 512 bytes"));
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

fn validate_chat_input(input: &ChatInvokeInput) -> FcpResult<()> {
    if input.messages.is_empty() {
        return invalid("messages must be a non-empty array");
    }
    if input.n.is_some_and(|n| n == 0 || n > 128) {
        return invalid("n must be between 1 and 128 when supplied");
    }
    validate_optional_model("model", input.model.as_deref())?;
    Ok(())
}

fn validate_optional_model(field: &str, model: Option<&str>) -> FcpResult<()> {
    if let Some(model) = model {
        validate_nim_model_id(field, model)?;
    }
    Ok(())
}

fn validate_or_default_model(model: Option<String>, default_model: &str) -> FcpResult<String> {
    model.map_or_else(
        || validate_nim_model_id("default_model", default_model),
        |model| validate_nim_model_id("model", &model),
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

fn validate_rerank_text(field: &str, value: &str) -> FcpResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return invalid(&format!("{field} text must not be empty"));
    }
    if trimmed.len() > 9_728 {
        return invalid(&format!("{field} text must be at most 9,728 bytes"));
    }
    Ok(trimmed.to_string())
}

fn validate_data_url(field: &str, value: &str) -> FcpResult<()> {
    let value = value.trim();
    if !value.starts_with("data:image/") {
        return invalid(&format!(
            "{field} image must be a data:image/... URL when supplied"
        ));
    }
    if value.len() > 2_000_000 {
        return invalid(&format!("{field} image data URL is too large"));
    }
    Ok(())
}

fn insert_optional_value(
    provider_extensions: &mut ProviderExtensions,
    key: &'static str,
    value: Option<Value>,
) {
    if let Some(value) = value {
        provider_extensions.insert(key.into(), value);
    }
}

fn invalid<T>(message: &str) -> FcpResult<T> {
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    })
}

#[cfg(test)]
mod tests {
    use fcp_openai_compat::{ChatMessage, EmbeddingInput};
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn chat_builder_defaults_model_and_preserves_nvext_extensions() {
        let request = chat_request_from_value(
            json!({
                "messages": [{"role": "user", "content": "do not log this prompt"}],
                "provider_extensions": {"trace": {"enabled": false}},
                "nvext": {"hot_words": ["FCP"], "beam_width": 4},
                "n": 2
            }),
            "",
        )
        .expect("valid NVIDIA NIM chat request should parse");

        assert_eq!(request.model, DEFAULT_MODEL);
        assert_eq!(request.messages.len(), 1);
        assert_eq!(request.provider_extensions["trace"]["enabled"], false);
        assert_eq!(request.provider_extensions["nvext"]["beam_width"], 4);
        assert_eq!(request.n, Some(2));
    }

    #[test]
    fn chat_builder_rejects_empty_messages_bad_counts_and_unknown_fields() {
        assert!(chat_request_from_value(json!({"messages": []}), DEFAULT_MODEL).is_err());
        assert!(
            chat_request_from_value(
                json!({"messages": [{"role": "user", "content": "x"}], "n": 0}),
                DEFAULT_MODEL,
            )
            .is_err()
        );
        assert!(
            chat_request_from_value(
                json!({"messages": [{"role": "user", "content": "x"}], "n": 129}),
                DEFAULT_MODEL,
            )
            .is_err()
        );
        assert!(
            chat_request_from_value(
                json!({"messages": [{"role": "user", "content": "x"}], "surprise": true}),
                DEFAULT_MODEL,
            )
            .is_err()
        );
    }

    #[test]
    fn embeddings_builder_validates_boundaries_without_exposing_inputs() {
        let single = embeddings_request_from_value(
            json!({"input": "private embedding text", "dimensions": 1024}),
            "",
        )
        .expect("single embedding input should parse");
        assert_eq!(single.model, DEFAULT_EMBEDDING_MODEL);
        assert_eq!(single.dimensions, Some(1024));
        assert_eq!(
            single.input,
            EmbeddingInput::Single("private embedding text".into())
        );

        let batch_values = (0..1_000)
            .map(|idx| format!("doc-{idx}"))
            .collect::<Vec<_>>();
        let batch = embeddings_request_from_value(
            json!({"input": batch_values, "model": DEFAULT_EMBEDDING_MODEL}),
            DEFAULT_EMBEDDING_MODEL,
        )
        .expect("maximum supported embedding batch should parse");
        assert!(matches!(batch.input, EmbeddingInput::Batch(values) if values.len() == 1_000));

        assert!(
            embeddings_request_from_value(json!({"input": ""}), DEFAULT_EMBEDDING_MODEL).is_err()
        );
        assert!(
            embeddings_request_from_value(
                json!({"input": [], "dimensions": 1}),
                DEFAULT_EMBEDDING_MODEL
            )
            .is_err()
        );
        assert!(
            embeddings_request_from_value(json!({"input": ["ok", "   "]}), DEFAULT_EMBEDDING_MODEL)
                .is_err()
        );
        assert!(
            embeddings_request_from_value(
                json!({"input": "ok", "dimensions": 0}),
                DEFAULT_EMBEDDING_MODEL
            )
            .is_err()
        );
    }

    #[test]
    fn rerank_builder_supports_text_and_image_inputs_with_hard_limits() {
        let request = rerank_request_from_value(
            json!({
                "query": {"text": "  which passage wins?  ", "image": "data:image/png;base64,abc"},
                "passages": [
                    "  first passage  ",
                    {"text": "second passage", "image": "data:image/jpeg;base64,def"}
                ],
                "truncate": "START"
            }),
            "",
        )
        .expect("valid rerank request should parse");

        assert_eq!(request.model, DEFAULT_RERANK_MODEL);
        assert_eq!(request.query.text, "which passage wins?");
        assert_eq!(request.passages[0].text, "first passage");
        assert_eq!(request.truncate, Some(RerankTruncate::Start));

        let too_many_passages = vec!["x"; 513];
        assert!(
            rerank_request_from_value(
                json!({"query": "q", "passages": too_many_passages}),
                DEFAULT_RERANK_MODEL,
            )
            .is_err()
        );
        assert!(
            rerank_request_from_value(
                json!({"query": {"text": "q", "image": "https://example.invalid/image.png"}, "passages": ["p"]}),
                DEFAULT_RERANK_MODEL,
            )
            .is_err()
        );
    }

    #[test]
    fn model_ids_are_trimmed_and_header_unsafe_values_are_rejected() {
        let max_model = "m".repeat(512);
        assert_eq!(
            validate_nim_model_id("model", &format!("  {max_model}  "))
                .expect("512-byte model id should pass"),
            max_model
        );
        assert!(validate_nim_model_id("model", &"m".repeat(513)).is_err());
        assert!(validate_nim_model_id("model", "bad model").is_err());
        assert!(validate_nim_model_id("model", "bad\nmodel").is_err());
    }

    #[test]
    fn chat_message_shape_remains_openai_compatible() {
        let request = ChatCompletionsRequest {
            model: DEFAULT_MODEL.into(),
            messages: vec![ChatMessage::user_text("hello")],
            temperature: None,
            max_tokens: Some(64),
            top_p: None,
            stop: None,
            stream: false,
            tools: None,
            tool_choice: None,
            response_format: None,
            seed: None,
            user: None,
            n: None,
            presence_penalty: None,
            frequency_penalty: None,
            logit_bias: None,
            logprobs: None,
            top_logprobs: None,
            provider_extensions: ProviderExtensions::default(),
        };
        let serialized = serde_json::to_value(request).expect("request should serialize");
        assert_eq!(serialized["model"], DEFAULT_MODEL);
        assert_eq!(serialized["messages"][0]["role"], "user");
        assert_eq!(serialized["max_tokens"], 64);
    }
}
