use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fcp_async_core::Cx;
use fcp_async_core::http::HttpClientBuilder;
use fcp_openai_compat::{
    ChatCompletionStream, ChatCompletionsRequest, ChatCompletionsResponse, EmbeddingsRequest,
    EmbeddingsResponse, ErrorMapper, HeaderList, HttpRequest, ModelInfo, OpenAiCompatClient,
    OpenAiCompatClientConfig, OpenAiCompatProvider, OpenAiError, RateLimitPolicy,
    RateLimitSnapshot, redact_sensitive_text, truncate_response_body,
};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::Value;
use sha2::Sha256;
use url::Url;

pub const DEFAULT_BASE_URL: &str = "https://open.bigmodel.cn/api/paas/v4";
pub const DEFAULT_MODEL: &str = "glm-5.1";
pub const DEFAULT_EMBEDDING_MODEL: &str = "embedding-3";
pub const USER_AGENT: &str = "fcp-glm/0.1.0";
const JWT_CACHE_REFRESH_SKEW_MS: i64 = 5_000;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub enum GlmAuth {
    ApiKey(String),
    Jwt(GlmJwtAuth),
    CredentialId(String),
}

impl GlmAuth {
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".into(),
            Self::Jwt(_) => "jwt:hs256:redacted".into(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    pub const fn uses_host_credential_reference(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }

    fn apply(&self, req: &mut HttpRequest) {
        match self {
            Self::ApiKey(key) => req.bearer_auth(key),
            Self::Jwt(jwt) => req.bearer_auth(&jwt.token_for_now()),
            Self::CredentialId(id) => req.upsert_header("x-fcp-credential-id", id),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GlmJwtAuth {
    api_key_id: String,
    signing_material: String,
    ttl: Duration,
    cache: Arc<Mutex<Option<CachedJwt>>>,
}

#[derive(Clone, Debug)]
struct CachedJwt {
    token: String,
    expires_at_ms: i64,
}

impl GlmJwtAuth {
    #[must_use]
    pub fn new(
        api_key_id: impl Into<String>,
        signing_material: impl Into<String>,
        ttl: Duration,
    ) -> Self {
        Self {
            api_key_id: api_key_id.into(),
            signing_material: signing_material.into(),
            ttl,
            cache: Arc::new(Mutex::new(None)),
        }
    }

    #[must_use]
    pub fn token_for_now(&self) -> String {
        self.token_at(now_millis())
    }

    pub fn token_at(&self, issued_at_ms: i64) -> String {
        let mut guard = self.cache.lock().expect("GLM JWT cache mutex poisoned");
        if let Some(cached) = guard.as_ref() {
            if issued_at_ms + JWT_CACHE_REFRESH_SKEW_MS < cached.expires_at_ms {
                return cached.token.clone();
            }
        }
        let jwt_value = generate_glm_jwt(
            &self.api_key_id,
            &self.signing_material,
            issued_at_ms,
            self.ttl,
        )
        .expect("validated GLM JWT material should sign");
        let expires_at_ms = issued_at_ms.saturating_add(duration_millis_i64(self.ttl));
        *guard = Some(CachedJwt {
            token: jwt_value.clone(),
            expires_at_ms,
        });
        jwt_value
    }
}

#[derive(Clone, Debug)]
pub struct GlmProvider {
    base_url: String,
    auth: GlmAuth,
}

impl GlmProvider {
    #[must_use]
    pub fn new(base_url: impl Into<String>, auth: GlmAuth) -> Self {
        Self {
            base_url: base_url.into(),
            auth,
        }
    }

    #[must_use]
    pub const fn auth(&self) -> &GlmAuth {
        &self.auth
    }
}

impl OpenAiCompatProvider for GlmProvider {
    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn auth_header(&self, req: &mut HttpRequest) {
        self.auth.apply(req);
    }

    fn user_agent(&self) -> &'static str {
        USER_AGENT
    }

    fn provider_name(&self) -> &'static str {
        "glm"
    }

    fn error_mapper(&self) -> &dyn ErrorMapper {
        &GLM_ERROR_MAPPER
    }
}

static GLM_ERROR_MAPPER: GlmErrorMapper = GlmErrorMapper;

#[derive(Debug, Clone, Copy)]
struct GlmErrorMapper;

#[derive(Debug, serde::Deserialize)]
struct GlmErrorEnvelope {
    error: Option<GlmErrorBody>,
    code: Option<Value>,
    message: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct GlmErrorBody {
    code: Option<Value>,
    message: Option<String>,
    #[serde(rename = "type")]
    error_type: Option<String>,
    param: Option<String>,
}

impl ErrorMapper for GlmErrorMapper {
    fn map_response(
        &self,
        provider: &str,
        status: u16,
        _headers: &HeaderList,
        body: &[u8],
        rate_limits: RateLimitSnapshot,
    ) -> OpenAiError {
        let body_text = truncate_response_body(body);
        let parsed = serde_json::from_slice::<GlmErrorEnvelope>(body).ok();
        let error = parsed.as_ref().and_then(|envelope| envelope.error.as_ref());
        let message = error
            .and_then(|body| body.message.clone())
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
        let code = error
            .and_then(|body| body.code.as_ref())
            .or_else(|| parsed.as_ref().and_then(|envelope| envelope.code.as_ref()))
            .and_then(code_to_string);
        let error_type = error.and_then(|body| body.error_type.as_deref());
        let param = error.and_then(|body| body.param.clone());
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
            403 | 434 => OpenAiError::PermissionDenied {
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
            _ if matches!(
                code.as_deref(),
                Some("1302" | "1303" | "1305" | "1308" | "1312")
            ) =>
            {
                OpenAiError::RateLimited {
                    message: safe_message,
                    retry_after: rate_limits.retry_after,
                }
            }
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

pub struct GlmClient {
    inner: OpenAiCompatClient<GlmProvider>,
}

impl GlmClient {
    #[must_use]
    pub fn new(
        provider: GlmProvider,
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

    #[must_use]
    pub fn provider(&self) -> &GlmProvider {
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

    pub async fn list_models(&self, _cx: &Cx) -> Result<Vec<ModelInfo>, OpenAiError> {
        Ok(static_glm_models())
    }

    pub async fn invalidate_model_cache(&self) {}
}

#[must_use]
pub fn static_glm_models() -> Vec<ModelInfo> {
    [
        DEFAULT_MODEL,
        "glm-4.7",
        "glm-4.6",
        "glm-4.5",
        DEFAULT_EMBEDDING_MODEL,
        "embedding-2",
    ]
    .into_iter()
    .map(|id| ModelInfo {
        id: id.to_string(),
        object: Some("model".to_string()),
        owned_by: Some("zhipu-ai".to_string()),
        created: None,
    })
    .collect()
}

pub fn normalize_glm_base_url(raw: Option<&str>) -> Result<String, String> {
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
    let valid_path = matches!(path, "/api/paas/v4" | "/api/coding/paas/v4");
    let valid_scheme = if local {
        matches!(parsed.scheme(), "http" | "https")
    } else {
        parsed.scheme() == "https"
    };
    let allowed_host = normalized_host == "open.bigmodel.cn" || local;

    if !allowed_host || !valid_scheme || !valid_path {
        return Err(format!(
            "base_url must be https://open.bigmodel.cn/api/paas/v4 (localhost/127.0.0.1/::1 allowed over http/https for tests): {value}"
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

pub fn split_bigmodel_api_key(value: &str) -> Result<(String, String), String> {
    let trimmed = validate_auth_material("jwt_api_key", value)?;
    let mut parts = trimmed.splitn(2, '.');
    let id = parts.next().unwrap_or_default();
    let material = parts.next().unwrap_or_default();
    if id.is_empty() || material.is_empty() || material.contains('.') {
        return Err(
            "jwt_api_key must have the documented '<api_key_id>.<signing-material>' shape".into(),
        );
    }
    Ok((id.to_string(), material.to_string()))
}

pub fn generate_glm_jwt(
    api_key_id: &str,
    signing_material: &str,
    issued_at_ms: i64,
    ttl: Duration,
) -> Result<String, String> {
    let api_key_id = validate_auth_material("api_key_id", api_key_id)?;
    let signing_material = validate_auth_material("api_key_signing_material", signing_material)?;
    let header = JwtHeader {
        alg: "HS256",
        sign_type: "SIGN",
    };
    let claims = JwtClaims {
        api_key: &api_key_id,
        exp: issued_at_ms.saturating_add(duration_millis_i64(ttl)),
        timestamp: issued_at_ms,
    };
    let header = encode_json_segment(&header)?;
    let payload = encode_json_segment(&claims)?;
    let signing_input = format!("{header}.{payload}");
    let mut mac = HmacSha256::new_from_slice(signing_material.as_bytes())
        .map_err(|err| format!("invalid HMAC key: {err}"))?;
    mac.update(signing_input.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Ok(format!("{signing_input}.{signature}"))
}

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'a str,
    sign_type: &'a str,
}

#[derive(Serialize)]
struct JwtClaims<'a> {
    api_key: &'a str,
    exp: i64,
    timestamp: i64,
}

fn encode_json_segment<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|err| format!("failed to serialize JWT segment: {err}"))
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, duration_millis_i64)
}

fn duration_millis_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn code_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}
