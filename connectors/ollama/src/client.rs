use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use fcp_async_core::Cx;
use fcp_async_core::http::HttpClientBuilder;
use fcp_openai_compat::{
    ChatCompletionStream, ChatCompletionsRequest, ChatCompletionsResponse, EmbeddingsRequest,
    EmbeddingsResponse, HeaderList, HttpRequest, ModelInfo, OpenAiCompatClient,
    OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError, RateLimitPolicy,
};
use url::Url;

pub const DEFAULT_BASE_URL: &str = "http://localhost:11434/v1";
pub const DEFAULT_MODEL: &str = "llama3.2";
pub const DEFAULT_EMBEDDING_MODEL: &str = "nomic-embed-text";
pub const USER_AGENT: &str = "fcp-ollama/0.1.0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OllamaAuth {
    None,
    ApiKey(String),
    CredentialId(String),
}

impl OllamaAuth {
    pub fn redacted_label(&self) -> String {
        match self {
            Self::None => "none".into(),
            Self::ApiKey(_) => "api_key:redacted".into(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OllamaUrlPolicy {
    pub tailnet_only: bool,
    pub allowed_hosts: Vec<String>,
}

impl OllamaUrlPolicy {
    pub fn new(tailnet_only: bool, allowed_hosts: Vec<String>) -> Self {
        Self {
            tailnet_only,
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| canonical_host(&host))
                .filter(|host| !host.is_empty())
                .collect(),
        }
    }

    fn host_is_allowed(&self, host: &str) -> bool {
        let host = canonical_host(host);
        self.allowed_hosts.iter().any(|allowed| allowed == &host)
    }
}

#[derive(Clone, Debug)]
pub struct OllamaProvider {
    base_url: String,
    auth: OllamaAuth,
}

impl OllamaProvider {
    pub fn new(base_url: impl Into<String>, auth: OllamaAuth) -> Self {
        Self {
            base_url: base_url.into(),
            auth,
        }
    }

    pub const fn auth(&self) -> &OllamaAuth {
        &self.auth
    }
}

impl OpenAiCompatProvider for OllamaProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        match &self.auth {
            OllamaAuth::None => {}
            OllamaAuth::ApiKey(key) => req.bearer_auth(key),
            OllamaAuth::CredentialId(id) => req.upsert_header("x-fcp-credential-id", id),
        }
    }

    fn user_agent(&self) -> &'static str {
        USER_AGENT
    }

    fn provider_name(&self) -> &'static str {
        "ollama"
    }

    fn extra_request_headers(&self, _model: &str) -> HeaderList {
        Vec::new()
    }
}

pub struct OllamaClient {
    inner: OpenAiCompatClient<OllamaProvider>,
    provider: OllamaProvider,
}

impl OllamaClient {
    pub fn new(
        provider: OllamaProvider,
        request_timeout: Duration,
        model_cache_ttl: Duration,
        rate_limit_policy: RateLimitPolicy,
    ) -> Self {
        let http_client = HttpClientBuilder::new().build();
        Self {
            inner: OpenAiCompatClient::new_with_config(
                provider.clone(),
                http_client,
                OpenAiCompatClientConfig {
                    request_timeout,
                    model_cache_ttl,
                    rate_limit_policy,
                },
            ),
            provider,
        }
    }

    pub const fn provider(&self) -> &OllamaProvider {
        &self.provider
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

pub fn normalize_ollama_base_url(
    raw: Option<&str>,
    policy: &OllamaUrlPolicy,
) -> Result<String, String> {
    let value = raw.unwrap_or(DEFAULT_BASE_URL).trim();
    if value.is_empty() {
        return Err("base_url must not be empty".into());
    }
    let parsed = Url::parse(value).map_err(|err| format!("Invalid base_url: {err}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "base_url must include a host".to_string())?;
    let normalized_host = canonical_host(host);
    let loopback = is_loopback_host(&normalized_host);
    let explicit_allowed = policy.host_is_allowed(&normalized_host);
    let path = parsed.path().trim_end_matches('/');

    if path != "/v1" {
        return Err(format!("base_url path must be exactly /v1: {value}"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "base_url must not include query or fragment components: {value}"
        ));
    }
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!("base_url must use http or https: {value}"));
    }
    if policy.tailnet_only && loopback {
        return Err("tailnet_only mode rejects localhost and loopback base_url values".into());
    }
    if !loopback && !explicit_allowed {
        return Err(format!(
            "base_url host `{normalized_host}` is not loopback and is not listed in allowed_hosts"
        ));
    }

    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

pub fn classify_ollama_base_url(base_url: &str) -> &'static str {
    let Ok(parsed) = Url::parse(base_url) else {
        return "invalid";
    };
    let Some(host) = parsed.host_str() else {
        return "invalid";
    };
    let host = canonical_host(host);
    if is_loopback_host(&host) {
        "loopback"
    } else if host.ends_with(".ts.net") {
        "tailnet_dns"
    } else if host.parse::<IpAddr>().is_ok_and(is_tailscale_ip) {
        "tailnet_ip"
    } else if host.parse::<IpAddr>().is_ok_and(is_private_ip) {
        "private_ip"
    } else {
        "operator_allowed_host"
    }
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

fn canonical_host(host: &str) -> String {
    host.trim()
        .trim_matches(|c| c == '[' || c == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
        || host.parse::<IpAddr>().is_ok_and(|addr| addr.is_loopback())
}

fn is_tailscale_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(_) => false,
    }
}

fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => addr.is_private() || is_link_local(addr),
        IpAddr::V6(addr) => addr.is_unique_local() || addr.is_unicast_link_local(),
    }
}

fn is_link_local(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 169 && octets[1] == 254
}
