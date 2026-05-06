use std::time::Duration;

use fcp_async_core::Cx;
use fcp_async_core::http::HttpClientBuilder;
use fcp_openai_compat::{
    ChatCompletionStream, ChatCompletionsRequest, ChatCompletionsResponse, EmbeddingsRequest,
    EmbeddingsResponse, ErrorMapper, HeaderList, HttpRequest, ModelInfo, OpenAiCompatClient,
    OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError, RateLimitPolicy,
    RateLimitSnapshot, redact_sensitive_text, truncate_response_body,
};
use serde::Deserialize;
use serde_json::Value;
use url::Url;

pub const DEFAULT_BASE_URL: &str = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1";
pub const BEIJING_BASE_URL: &str = "https://dashscope.aliyuncs.com/compatible-mode/v1";
pub const DEFAULT_MODEL: &str = "qwen-plus";
pub const DEFAULT_VISION_MODEL: &str = "qwen-vl-plus";
pub const DEFAULT_EMBEDDING_MODEL: &str = "text-embedding-v4";
pub const USER_AGENT: &str = "fcp-qwen/0.1.0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QwenAuth {
    ApiKey(String),
    CredentialId(String),
}

impl QwenAuth {
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".into(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

#[derive(Clone, Debug)]
pub struct QwenProvider {
    base_url: String,
    auth: QwenAuth,
}

impl QwenProvider {
    pub fn new(base_url: impl Into<String>, auth: QwenAuth) -> Self {
        Self {
            base_url: base_url.into(),
            auth,
        }
    }

    pub const fn auth(&self) -> &QwenAuth {
        &self.auth
    }
}

impl OpenAiCompatProvider for QwenProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        match &self.auth {
            QwenAuth::ApiKey(key) => req.bearer_auth(key),
            QwenAuth::CredentialId(id) => req.upsert_header("x-fcp-credential-id", id),
        }
    }

    fn user_agent(&self) -> &'static str {
        USER_AGENT
    }

    fn provider_name(&self) -> &'static str {
        "qwen"
    }

    fn error_mapper(&self) -> &dyn ErrorMapper {
        &QWEN_ERROR_MAPPER
    }
}

static QWEN_ERROR_MAPPER: QwenErrorMapper = QwenErrorMapper;

#[derive(Debug, Clone, Copy)]
struct QwenErrorMapper;

#[derive(Debug, Deserialize)]
struct QwenErrorEnvelope {
    error: Option<QwenErrorBody>,
    code: Option<Value>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QwenErrorBody {
    #[serde(rename = "type")]
    error_type: Option<String>,
    code: Option<Value>,
    message: Option<String>,
    param: Option<String>,
}

impl ErrorMapper for QwenErrorMapper {
    fn map_response(
        &self,
        provider: &str,
        status: u16,
        _headers: &HeaderList,
        body: &[u8],
        rate_limits: RateLimitSnapshot,
    ) -> OpenAiError {
        let body_text = truncate_response_body(body);
        let parsed = serde_json::from_slice::<QwenErrorEnvelope>(body).ok();
        let body_error = parsed.as_ref().and_then(|envelope| envelope.error.as_ref());
        let message = body_error
            .and_then(|error| error.message.clone())
            .or_else(|| {
                parsed
                    .as_ref()
                    .and_then(|envelope| envelope.message.clone())
            })
            .filter(|message| !message.trim().is_empty())
            .unwrap_or_else(|| {
                if body_text.trim().is_empty() {
                    format!("HTTP {status}")
                } else {
                    body_text.clone()
                }
            });
        let code = body_error
            .and_then(|error| error.code.as_ref())
            .or_else(|| parsed.as_ref().and_then(|envelope| envelope.code.as_ref()))
            .and_then(code_to_string);
        let error_type = body_error.and_then(|error| error.error_type.as_deref());
        let param = body_error.and_then(|error| error.param.clone());
        let safe_message = redact_sensitive_text(&message);

        match status {
            400 => OpenAiError::InvalidRequest {
                message: safe_message,
                param,
                code,
            },
            401 => OpenAiError::Authentication {
                message: safe_message,
            },
            403 => OpenAiError::PermissionDenied {
                message: safe_message,
            },
            404 => OpenAiError::NotFound {
                message: safe_message,
                resource: param,
            },
            429 => OpenAiError::RateLimited {
                message: safe_message,
                retry_after: rate_limits.retry_after,
            },
            500 => OpenAiError::InternalError {
                message: safe_message,
            },
            503 => OpenAiError::ServiceUnavailable {
                message: safe_message,
                retry_after: rate_limits.retry_after,
            },
            _ if matches!(error_type, Some("rate_limit" | "rate_limit_error")) => {
                OpenAiError::RateLimited {
                    message: safe_message,
                    retry_after: rate_limits.retry_after,
                }
            }
            _ => OpenAiError::Provider {
                provider: provider.to_string(),
                status,
                body: body_text,
            },
        }
    }
}

pub struct QwenClient {
    inner: OpenAiCompatClient<QwenProvider>,
}

impl QwenClient {
    pub fn new(
        provider: QwenProvider,
        request_timeout: Duration,
        model_cache_ttl: Duration,
        rate_limit_policy: RateLimitPolicy,
    ) -> Self {
        Self {
            inner: OpenAiCompatClient::new_with_config(
                provider,
                HttpClientBuilder::new().build(),
                OpenAiCompatClientConfig {
                    request_timeout,
                    model_cache_ttl,
                    rate_limit_policy,
                },
            ),
        }
    }

    pub fn provider(&self) -> &QwenProvider {
        self.inner.provider()
    }

    pub async fn chat_completions(
        &self,
        cx: &Cx,
        request: ChatCompletionsRequest,
    ) -> Result<ChatCompletionsResponse, OpenAiError> {
        self.inner.chat_completions(cx, request).await
    }

    pub async fn chat_completions_stream(
        &self,
        cx: &Cx,
        request: ChatCompletionsRequest,
    ) -> Result<ChatCompletionStream, OpenAiError> {
        self.inner.chat_completions_stream(cx, request).await
    }

    pub async fn embeddings(
        &self,
        cx: &Cx,
        request: EmbeddingsRequest,
    ) -> Result<EmbeddingsResponse, OpenAiError> {
        self.inner.embeddings(cx, request).await
    }

    pub async fn list_models(&self, cx: &Cx) -> Result<Vec<ModelInfo>, OpenAiError> {
        self.inner.list_models(cx).await
    }

    pub async fn invalidate_model_cache(&self) {
        self.inner.invalidate_model_cache().await;
    }
}

pub fn normalize_qwen_base_url(raw: Option<&str>) -> Result<String, String> {
    let value = raw.unwrap_or(DEFAULT_BASE_URL).trim();
    if value.is_empty() {
        return Err("base_url must not be empty".into());
    }
    let parsed = Url::parse(value).map_err(|err| format!("Invalid base_url: {err}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "base_url must include a host".to_string())?;
    let normalized_host = host
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    let local = matches!(normalized_host.as_str(), "localhost" | "127.0.0.1" | "::1");
    let valid_scheme = if local {
        matches!(parsed.scheme(), "http" | "https")
    } else {
        parsed.scheme() == "https"
    };
    let path = parsed.path().trim_end_matches('/');
    let allowed_host = matches!(
        normalized_host.as_str(),
        "dashscope.aliyuncs.com" | "dashscope-intl.aliyuncs.com"
    ) || local;

    if !allowed_host || !valid_scheme || path != "/compatible-mode/v1" {
        return Err(format!(
            "base_url must be {DEFAULT_BASE_URL} or {BEIJING_BASE_URL} (localhost/127.0.0.1/::1 allowed over http/https for tests): {value}"
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "base_url must not include query or fragment components: {value}"
        ));
    }
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

pub fn validate_auth_material(field: &str, value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if trimmed
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(format!(
            "{field} contains characters that are invalid in headers"
        ));
    }
    Ok(trimmed.to_string())
}

fn code_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}
