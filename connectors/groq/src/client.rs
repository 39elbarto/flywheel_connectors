use std::time::Duration;

use fcp_async_core::Cx;
use fcp_async_core::http::HttpClientBuilder;
use fcp_openai_compat::{
    ChatCompletionStream, ChatCompletionsRequest, ChatCompletionsResponse, CompletionsRequest,
    CompletionsResponse, HeaderList, HttpRequest, ModelInfo, OpenAiCompatClient,
    OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError, RateLimitPolicy,
};
use url::Url;

pub const DEFAULT_BASE_URL: &str = "https://api.groq.com/openai/v1";
pub const DEFAULT_MODEL: &str = "llama-3.1-8b-instant";
pub const USER_AGENT: &str = "fcp-groq/0.1.0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroqAuth {
    ApiKey(String),
    CredentialId(String),
}

impl GroqAuth {
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
pub struct GroqProvider {
    base_url: String,
    auth: GroqAuth,
}

impl GroqProvider {
    pub fn new(base_url: impl Into<String>, auth: GroqAuth) -> Self {
        Self {
            base_url: base_url.into(),
            auth,
        }
    }

    pub fn auth(&self) -> &GroqAuth {
        &self.auth
    }
}

impl OpenAiCompatProvider for GroqProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        match &self.auth {
            GroqAuth::ApiKey(key) => req.bearer_auth(key),
            GroqAuth::CredentialId(id) => req.upsert_header("x-fcp-credential-id", id),
        }
    }

    fn user_agent(&self) -> &'static str {
        USER_AGENT
    }

    fn provider_name(&self) -> &'static str {
        "groq"
    }

    fn extra_request_headers(&self, _model: &str) -> HeaderList {
        Vec::new()
    }
}

pub struct GroqClient {
    inner: OpenAiCompatClient<GroqProvider>,
}

impl GroqClient {
    pub fn new(
        provider: GroqProvider,
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

    pub fn provider(&self) -> &GroqProvider {
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

    pub async fn list_models(&self, cx: &Cx) -> Result<Vec<ModelInfo>, OpenAiError> {
        self.inner.list_models(cx).await
    }

    pub async fn invalidate_model_cache(&self) {
        self.inner.invalidate_model_cache().await;
    }

    pub async fn legacy_completions(
        &self,
        cx: &Cx,
        request: CompletionsRequest,
    ) -> Result<CompletionsResponse, OpenAiError> {
        self.inner.legacy_completions(cx, request).await
    }
}

pub fn normalize_groq_base_url(raw: Option<&str>) -> Result<String, String> {
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
    let path = parsed.path().trim_end_matches('/');
    let valid_path = matches!(path, "/openai/v1" | "/v1");
    let valid_scheme = if local {
        matches!(parsed.scheme(), "http" | "https")
    } else {
        parsed.scheme() == "https"
    };
    let allowed_host = normalized_host == "api.groq.com" || local;

    if !allowed_host || !valid_scheme || !valid_path {
        return Err(format!(
            "base_url must be https://api.groq.com/openai/v1 (localhost/127.0.0.1/::1 allowed over http/https for tests): {value}"
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
