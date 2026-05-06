use fcp_openai_compat::{EmbeddingInput, EmbeddingsRequest, ProviderExtensions};
use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::{DEFAULT_EMBEDDING_MODEL, DEFAULT_MULTIMODAL_MODEL, DEFAULT_RERANK_MODEL};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingsInvokeInput {
    pub model: Option<String>,
    pub input: EmbeddingInput,
    pub input_type: Option<String>,
    pub truncation: Option<bool>,
    pub output_dimension: Option<u32>,
    pub output_dtype: Option<String>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl EmbeddingsInvokeInput {
    pub fn into_request(self, default_model: &str) -> FcpResult<EmbeddingsRequest> {
        validate_embeddings_input(&self)?;
        let mut provider_extensions = self.provider_extensions;
        insert_optional_string(&mut provider_extensions, "input_type", self.input_type);
        insert_optional_bool(&mut provider_extensions, "truncation", self.truncation);
        insert_optional_u32(
            &mut provider_extensions,
            "output_dimension",
            self.output_dimension,
        );
        insert_optional_string(&mut provider_extensions, "output_dtype", self.output_dtype);
        Ok(EmbeddingsRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            input: self.input,
            encoding_format: None,
            dimensions: None,
            provider_extensions,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MultimodalEmbeddingsRequest {
    pub model: String,
    pub inputs: Vec<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncation: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_dimension: Option<u32>,
    #[serde(default, flatten, skip_serializing_if = "ProviderExtensions::is_empty")]
    pub provider_extensions: ProviderExtensions,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultimodalEmbeddingsInvokeInput {
    pub model: Option<String>,
    pub inputs: Vec<Value>,
    pub input_type: Option<String>,
    pub truncation: Option<bool>,
    pub output_encoding: Option<String>,
    pub output_dimension: Option<u32>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl MultimodalEmbeddingsInvokeInput {
    pub fn into_request(self, default_model: &str) -> FcpResult<MultimodalEmbeddingsRequest> {
        validate_multimodal_input(&self)?;
        Ok(MultimodalEmbeddingsRequest {
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            inputs: self.inputs,
            input_type: self.input_type,
            truncation: self.truncation,
            output_encoding: self.output_encoding,
            output_dimension: self.output_dimension,
            provider_extensions: self.provider_extensions,
        })
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RerankRequest {
    pub query: String,
    pub documents: Vec<String>,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_documents: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncation: Option<bool>,
    #[serde(default, flatten, skip_serializing_if = "ProviderExtensions::is_empty")]
    pub provider_extensions: ProviderExtensions,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RerankInvokeInput {
    pub query: String,
    pub documents: Vec<String>,
    pub model: Option<String>,
    pub top_k: Option<u32>,
    pub return_documents: Option<bool>,
    pub truncation: Option<bool>,
    #[serde(default)]
    pub provider_extensions: ProviderExtensions,
}

impl RerankInvokeInput {
    pub fn into_request(self, default_model: &str) -> FcpResult<RerankRequest> {
        validate_rerank_input(&self)?;
        Ok(RerankRequest {
            query: self.query,
            documents: self.documents,
            model: self.model.unwrap_or_else(|| default_model.to_string()),
            top_k: self.top_k,
            return_documents: self.return_documents,
            truncation: self.truncation,
            provider_extensions: self.provider_extensions,
        })
    }
}

pub fn embeddings_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<EmbeddingsRequest> {
    let input: EmbeddingsInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Voyage embeddings input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_EMBEDDING_MODEL
    } else {
        default_model
    })
}

pub fn multimodal_request_from_value(
    value: Value,
    default_model: &str,
) -> FcpResult<MultimodalEmbeddingsRequest> {
    let input: MultimodalEmbeddingsInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Voyage multimodal embeddings input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_MULTIMODAL_MODEL
    } else {
        default_model
    })
}

pub fn rerank_request_from_value(value: Value, default_model: &str) -> FcpResult<RerankRequest> {
    let input: RerankInvokeInput =
        serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
            code: 1003,
            message: format!("Invalid Voyage rerank input: {err}"),
        })?;
    input.into_request(if default_model.trim().is_empty() {
        DEFAULT_RERANK_MODEL
    } else {
        default_model
    })
}

pub fn documented_model_catalog_value() -> &'static [&'static str] {
    &[
        "voyage-4-large",
        "voyage-4",
        "voyage-4-lite",
        "voyage-3-large",
        "voyage-3.5",
        "voyage-3.5-lite",
        "voyage-code-3",
        "voyage-finance-2",
        "voyage-law-2",
        "voyage-multimodal-3.5",
        "voyage-multimodal-3",
        "rerank-2.5",
        "rerank-2.5-lite",
        "rerank-2",
    ]
}

fn validate_embeddings_input(input: &EmbeddingsInvokeInput) -> FcpResult<()> {
    validate_embedding_input_value(&input.input)?;
    validate_input_type(input.input_type.as_deref())?;
    validate_output_dimension(input.output_dimension)?;
    validate_output_dtype(input.output_dtype.as_deref())?;
    validate_model(input.model.as_deref())?;
    Ok(())
}

fn validate_multimodal_input(input: &MultimodalEmbeddingsInvokeInput) -> FcpResult<()> {
    if input.inputs.is_empty() {
        return invalid("inputs must be a non-empty array");
    }
    if input.inputs.len() > 1_000 {
        return invalid("inputs must contain at most 1,000 entries");
    }
    validate_input_type(input.input_type.as_deref())?;
    validate_output_dimension(input.output_dimension)?;
    validate_output_encoding(input.output_encoding.as_deref())?;
    validate_model(input.model.as_deref())?;
    Ok(())
}

fn validate_rerank_input(input: &RerankInvokeInput) -> FcpResult<()> {
    if input.query.trim().is_empty() {
        return invalid("query must not be empty");
    }
    if input.documents.is_empty() {
        return invalid("documents must be a non-empty array");
    }
    if input.documents.len() > 1_000 {
        return invalid("documents must contain at most 1,000 entries");
    }
    if input
        .documents
        .iter()
        .any(|document| document.trim().is_empty())
    {
        return invalid("documents must not contain empty entries");
    }
    if input.top_k.is_some_and(|top_k| {
        top_k == 0 || usize::try_from(top_k).map_or(true, |top_k| top_k > input.documents.len())
    }) {
        return invalid("top_k must be between 1 and documents.len()");
    }
    validate_model(input.model.as_deref())?;
    Ok(())
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

fn validate_input_type(input_type: Option<&str>) -> FcpResult<()> {
    if input_type.is_some_and(|value| !matches!(value, "query" | "document")) {
        return invalid("input_type must be query or document when supplied");
    }
    Ok(())
}

fn validate_output_dimension(output_dimension: Option<u32>) -> FcpResult<()> {
    if output_dimension.is_some_and(|value| !matches!(value, 256 | 512 | 1024 | 2048)) {
        return invalid("output_dimension must be one of 256, 512, 1024, or 2048");
    }
    Ok(())
}

fn validate_output_dtype(output_dtype: Option<&str>) -> FcpResult<()> {
    if output_dtype
        .is_some_and(|value| !matches!(value, "float" | "int8" | "uint8" | "binary" | "ubinary"))
    {
        return invalid("output_dtype must be float, int8, uint8, binary, or ubinary");
    }
    Ok(())
}

fn validate_output_encoding(output_encoding: Option<&str>) -> FcpResult<()> {
    if output_encoding.is_some_and(|value| value != "base64") {
        return invalid("output_encoding must be base64 when supplied");
    }
    Ok(())
}

fn validate_model(model: Option<&str>) -> FcpResult<()> {
    if model.is_some_and(|value| value.trim().is_empty()) {
        return invalid("model must not be empty");
    }
    Ok(())
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

fn insert_optional_bool(
    provider_extensions: &mut ProviderExtensions,
    key: &'static str,
    value: Option<bool>,
) {
    if let Some(value) = value {
        provider_extensions.insert(key.into(), Value::Bool(value));
    }
}

fn insert_optional_u32(
    provider_extensions: &mut ProviderExtensions,
    key: &'static str,
    value: Option<u32>,
) {
    if let Some(value) = value {
        provider_extensions.insert(key.into(), Value::from(value));
    }
}

fn invalid<T>(message: impl Into<String>) -> FcpResult<T> {
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    })
}
