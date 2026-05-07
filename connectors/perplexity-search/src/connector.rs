//! Perplexity Search connector implementation.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_manifest::{ConnectorManifest, ManifestApprovalMode};
use fcp_prelude::{
    ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier, ConnectorId,
    ConnectorMetrics, EventCaps, FcpConnector, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, Introspection, InvokeRequest, InvokeResponse, OperationId,
    OperationInfo, SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};
use fcp_sdk::migration::HttpRetryConfig;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;

use crate::client::PerplexityClient;
use crate::types::{
    ChatCompletionRequest, ChatMessage, PerplexityAuth, SearchApiRequest, SearchApiResult,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");

const OP_SEARCH: &str = "perplexity-search.query";
const OP_NATIVE_SEARCH: &str = "perplexity-search.search";

const CAP_SEARCH: &str = "perplexity-search.query";
const CAP_NATIVE_SEARCH: &str = "perplexity-search.search";
const OPERATION_ORDER: [&str; 2] = [OP_SEARCH, OP_NATIVE_SEARCH];

const DIRECT_PERPLEXITY_BASE_URL: &str = "https://api.perplexity.ai";
const OPENROUTER_BASE_URL: &str = "https://openrouter.ai/api/v1";
const OPENROUTER_DEFAULT_MODEL: &str = "perplexity/sonar-pro";

// ── Config ──

#[derive(Clone, Deserialize)]
struct RawPerplexityConfig {
    #[serde(default)]
    base_url: Option<String>,
    #[serde(flatten)]
    auth: PerplexityAuth,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    request_timeout_ms: u64,
    #[serde(default)]
    default_model: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PerplexityTransport {
    Direct,
    OpenRouter,
    Custom,
}

#[derive(Clone)]
pub struct PerplexityConfig {
    pub base_url: String,
    pub auth: PerplexityAuth,
    pub retry: HttpRetryConfig,
    pub request_timeout_ms: u64,
    /// Default model to use when the caller does not specify one.
    pub default_model: String,
    transport: PerplexityTransport,
}

fn default_base_url() -> String {
    DIRECT_PERPLEXITY_BASE_URL.into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

fn default_model() -> String {
    "sonar".into()
}

impl std::fmt::Debug for PerplexityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerplexityConfig")
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("default_model", &self.default_model)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

fn trim_string(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        trimmed.to_string()
    }
}

fn is_openrouter_api_key(api_key: &str) -> bool {
    api_key.trim().to_ascii_lowercase().starts_with("sk-or-")
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

const fn is_sensitive_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            let documentation_range = matches!(
                octets,
                [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
            );
            ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || documentation_range
                || ip.is_unspecified()
                || ip.is_multicast()
        }
        IpAddr::V6(ip) => {
            let [first, second, ..] = ip.segments();
            let documentation_range = first == 0x2001 && second == 0x0db8;
            ip.is_unique_local()
                || ip.is_unicast_link_local()
                || documentation_range
                || ip.is_unspecified()
                || ip.is_multicast()
        }
    }
}

fn is_direct_perplexity_base_url(base_url: &str) -> bool {
    Url::parse(base_url).is_ok_and(|url| {
        url.host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("api.perplexity.ai"))
    })
}

fn is_openrouter_base_url(base_url: &str) -> bool {
    Url::parse(base_url).is_ok_and(|url| {
        url.host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("openrouter.ai"))
    })
}

fn validate_base_url(base_url: &str) -> Result<Url, String> {
    let parsed =
        Url::parse(base_url).map_err(|e| format!("base_url must be a valid absolute URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("base_url must use http or https".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("base_url must not contain embedded credentials".into());
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("base_url must not contain a query string or fragment".into());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "base_url must include a host".to_string())?;
    if parsed.scheme() == "http" && !is_loopback_host(host) {
        return Err("base_url may only use public http for loopback test endpoints".into());
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !ip.is_loopback() && is_sensitive_ip(ip) {
            return Err(
                "base_url must not target private, link-local, or documentation IP ranges".into(),
            );
        }
    }
    Ok(parsed)
}

fn resolve_transport(base_url: &str) -> PerplexityTransport {
    if is_openrouter_base_url(base_url) {
        PerplexityTransport::OpenRouter
    } else if is_direct_perplexity_base_url(base_url) {
        PerplexityTransport::Direct
    } else {
        PerplexityTransport::Custom
    }
}

impl PerplexityConfig {
    fn validate(&self) -> Result<(), String> {
        let base_url = self.base_url.trim();
        if base_url.is_empty() {
            return Err("base_url cannot be empty".into());
        }
        validate_base_url(base_url)?;
        if self.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than zero".into());
        }
        if self.default_model.trim().is_empty() {
            return Err("default_model must not be empty".into());
        }
        Ok(())
    }

    fn from_value(value: serde_json::Value) -> FcpResult<Self> {
        let raw: RawPerplexityConfig =
            serde_json::from_value(value).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {e}"),
            })?;

        let explicit_base_url = raw.base_url.as_deref().map(trim_string);
        let base_url = explicit_base_url.unwrap_or_else(|| {
            if is_openrouter_api_key(&raw.auth.api_key) {
                OPENROUTER_BASE_URL.into()
            } else {
                default_base_url()
            }
        });
        let transport = resolve_transport(&base_url);
        let default_model = match raw.default_model.as_deref().map(trim_string) {
            Some(model) => model,
            None if transport == PerplexityTransport::OpenRouter => OPENROUTER_DEFAULT_MODEL.into(),
            None => default_model(),
        };

        let config = Self {
            base_url,
            auth: raw.auth,
            retry: raw.retry,
            request_timeout_ms: raw.request_timeout_ms,
            default_model,
            transport,
        };
        config
            .validate()
            .map_err(|message| FcpError::InvalidRequest {
                code: 1001,
                message,
            })?;
        Ok(config)
    }
}

// ── Doctor ──

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorResult {
    pub passed: bool,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let passed = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        Self { passed, checks }
    }
}

// ── Connector ──

#[derive(Debug)]
pub struct PerplexitySearchConnector {
    base: BaseConnector,
    config: Option<PerplexityConfig>,
    client: Option<PerplexityClient>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl PerplexitySearchConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.perplexity-search")),
            config: None,
            client: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    fn manifest_hash() -> String {
        let mut digest = Sha256::new();
        digest.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(digest.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: self
                .config
                .as_ref()
                .map(|_| "Configuration loaded".into())
                .or_else(|| Some("Not configured".into())),
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client".into(),
            passed: self.client.is_some(),
            message: self
                .client
                .as_ref()
                .map(|_| "Client initialized".into())
                .or_else(|| Some("Client not initialized".into())),
            critical: true,
        });

        if let Some(config) = &self.config {
            checks.push(DoctorCheck {
                name: "base_url".into(),
                passed: config.base_url.starts_with("https://"),
                message: Some(format!("API URL: {}", config.base_url)),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "auth".into(),
                passed: !config.auth.is_secretless(),
                message: Some(if config.auth.is_secretless() {
                    "API key not configured (credential injection required)".into()
                } else {
                    "API key configured".into()
                }),
                critical: false,
            });
            checks.push(DoctorCheck {
                name: "model".into(),
                passed: true,
                message: Some(format!("Default model: {}", config.default_model)),
                critical: false,
            });
        }

        DoctorResult::from_checks(checks)
    }

    fn capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
        match operation {
            OP_SEARCH => Ok(CapabilityId::from_static(CAP_SEARCH)),
            OP_NATIVE_SEARCH => Ok(CapabilityId::from_static(CAP_NATIVE_SEARCH)),
            _ => Err(FcpError::InvalidRequest {
                code: 1004,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value =
            input
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Missing string field: {key}"),
                })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }

    fn optional_str(input: &serde_json::Value, key: &str) -> FcpResult<Option<String>> {
        let Some(value) = input.get(key) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }
        let Some(raw) = value.as_str() else {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must be a string"),
            });
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(Some(trimmed.to_string()))
    }

    fn optional_bool(input: &serde_json::Value, key: &str) -> FcpResult<Option<bool>> {
        let Some(value) = input.get(key) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }
        value
            .as_bool()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must be a boolean"),
            })
    }

    fn optional_f64(input: &serde_json::Value, key: &str) -> FcpResult<Option<f64>> {
        let Some(value) = input.get(key) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }
        value
            .as_f64()
            .map(Some)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must be a number"),
            })
    }

    fn optional_u32(
        input: &serde_json::Value,
        key: &str,
        min: u32,
        max: u32,
    ) -> FcpResult<Option<u32>> {
        let Some(value) = input.get(key) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }
        let number = value.as_u64().ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Field '{key}' must be a positive integer"),
        })?;
        if number < u64::from(min) || number > u64::from(max) {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must be between {min} and {max}"),
            });
        }
        Ok(Some(u32::try_from(number).unwrap_or(max)))
    }

    fn optional_string_array(
        input: &serde_json::Value,
        key: &str,
    ) -> FcpResult<Option<Vec<String>>> {
        let Some(value) = input.get(key) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }
        let array = value.as_array().ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("Field '{key}' must be an array of strings"),
        })?;
        let mut values = Vec::with_capacity(array.len());
        for entry in array {
            let Some(raw) = entry.as_str() else {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Field '{key}' must contain only strings"),
                });
            };
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Field '{key}' must not contain empty strings"),
                });
            }
            values.push(trimmed.to_string());
        }
        Ok(Some(values))
    }

    fn field_present(input: &serde_json::Value, key: &str) -> bool {
        input.get(key).is_some_and(|value| !value.is_null())
    }

    fn unsupported_chat_filter(input: &serde_json::Value) -> FcpResult<()> {
        for key in [
            "country",
            "language",
            "date_after",
            "date_before",
            "domain_filter",
            "max_tokens_per_page",
        ] {
            if Self::field_present(input, key) {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!(
                        "Field '{key}' is only supported by {OP_NATIVE_SEARCH}; use search_domain_filter for chat-completions domain filtering"
                    ),
                });
            }
        }
        Ok(())
    }

    fn recency_filter(input: &serde_json::Value, allow_hour: bool) -> FcpResult<Option<String>> {
        let freshness = Self::optional_str(input, "freshness")?;
        let search_recency_filter = Self::optional_str(input, "search_recency_filter")?;
        if let (Some(left), Some(right)) = (&freshness, &search_recency_filter) {
            if left != right {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message:
                        "freshness and search_recency_filter must match when both are provided"
                            .into(),
                });
            }
        }
        let Some(value) = freshness.or(search_recency_filter) else {
            return Ok(None);
        };
        let allowed = if allow_hour {
            matches!(value.as_str(), "hour" | "day" | "week" | "month" | "year")
        } else {
            matches!(value.as_str(), "day" | "week" | "month" | "year")
        };
        if !allowed {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: if allow_hour {
                    "freshness/search_recency_filter must be hour, day, week, month, or year".into()
                } else {
                    "freshness/search_recency_filter must be day, week, month, or year".into()
                },
            });
        }
        Ok(Some(value))
    }

    fn domain_filter(input: &serde_json::Value) -> FcpResult<Option<Vec<String>>> {
        let domain_filter = Self::optional_string_array(input, "domain_filter")?;
        let search_domain_filter = Self::optional_string_array(input, "search_domain_filter")?;
        if let (Some(left), Some(right)) = (&domain_filter, &search_domain_filter) {
            if left != right {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message:
                        "domain_filter and search_domain_filter must match when both are provided"
                            .into(),
                });
            }
        }
        let filter = domain_filter.or(search_domain_filter);
        if let Some(values) = &filter {
            Self::validate_domain_filter(values)?;
        }
        Ok(filter)
    }

    fn validate_domain_filter(values: &[String]) -> FcpResult<()> {
        if values.len() > 20 {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "domain_filter supports a maximum of 20 domains".into(),
            });
        }
        let has_deny = values.iter().any(|entry| entry.starts_with('-'));
        let has_allow = values.iter().any(|entry| !entry.starts_with('-'));
        if has_deny && has_allow {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "domain_filter cannot mix allowlist and denylist entries".into(),
            });
        }
        Ok(())
    }

    fn iso_to_perplexity_date(value: &str, field: &str) -> FcpResult<String> {
        let mut parts = value.split('-');
        let (Some(year_raw), Some(month_raw), Some(day_raw), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("{field} must be YYYY-MM-DD format"),
            });
        };
        if year_raw.len() != 4 || month_raw.len() != 2 || day_raw.len() != 2 {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("{field} must be YYYY-MM-DD format"),
            });
        }
        let year = year_raw
            .parse::<u32>()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1005,
                message: format!("{field} must be YYYY-MM-DD format"),
            })?;
        let month = month_raw
            .parse::<u32>()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1005,
                message: format!("{field} must be YYYY-MM-DD format"),
            })?;
        let day = day_raw
            .parse::<u32>()
            .map_err(|_| FcpError::InvalidRequest {
                code: 1005,
                message: format!("{field} must be YYYY-MM-DD format"),
            })?;
        let max_day = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
            2 => 28,
            _ => 0,
        };
        if day == 0 || day > max_day {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("{field} must be a real calendar date"),
            });
        }
        Ok(format!("{month}/{day}/{year}"))
    }

    fn validate_country_or_language(value: Option<&str>, key: &str) -> FcpResult<()> {
        if let Some(value) = value {
            if value.len() != 2 || !value.chars().all(|ch| ch.is_ascii_alphabetic()) {
                return Err(FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("{key} must be a 2-letter code"),
                });
            }
        }
        Ok(())
    }

    fn site_name(url: &str) -> Option<String> {
        Url::parse(url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(ToOwned::to_owned))
    }

    fn external_content() -> serde_json::Value {
        json!({
            "untrusted": true,
            "source": "web_search",
            "provider": "perplexity",
            "wrapped": true
        })
    }

    fn wrap_untrusted_web_content(value: &str) -> String {
        format!("<untrusted-web-search>\n{value}\n</untrusted-web-search>")
    }

    fn search_result_json(result: &SearchApiResult) -> serde_json::Value {
        let title = result.title.as_deref().unwrap_or_default();
        let description = result.snippet.as_deref().unwrap_or_default();
        let url = result.url.as_deref().unwrap_or_default();
        json!({
            "title": Self::wrap_untrusted_web_content(title),
            "url": url,
            "description": Self::wrap_untrusted_web_content(description),
            "published": result.date,
            "site_name": Self::site_name(url),
            "external_content": Self::external_content()
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        let Some(verifier) = &self.verifier else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        };
        let capability = Self::capability_for_operation(operation)?;
        verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])?;

        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Perplexity client".into(),
        })?;
        let config = self.config.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing config".into(),
        })?;

        let output = match operation {
            OP_SEARCH => {
                let query = Self::require_str(&req.input, "query")?;
                Self::unsupported_chat_filter(&req.input)?;
                let model = req
                    .input
                    .get("model")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&config.default_model);

                // Build system prompt if provided
                let system_prompt = req.input.get("system_prompt").and_then(|v| v.as_str());

                let mut messages = Vec::new();
                if let Some(sys) = system_prompt {
                    messages.push(ChatMessage {
                        role: "system".into(),
                        content: sys.to_string(),
                    });
                }
                messages.push(ChatMessage {
                    role: "user".into(),
                    content: query.to_string(),
                });

                let max_tokens = Self::optional_u32(&req.input, "max_tokens", 1, u32::MAX)?;
                let temperature = Self::optional_f64(&req.input, "temperature")?;
                let top_p = Self::optional_f64(&req.input, "top_p")?;
                let top_k = Self::optional_u32(&req.input, "top_k", 1, u32::MAX)?;
                let search_domain_filter =
                    Self::optional_string_array(&req.input, "search_domain_filter")?;
                if let Some(values) = &search_domain_filter {
                    Self::validate_domain_filter(values)?;
                }
                let return_images = Self::optional_bool(&req.input, "return_images")?;
                let return_related_questions =
                    Self::optional_bool(&req.input, "return_related_questions")?;
                let search_recency_filter = Self::recency_filter(&req.input, true)?;
                let presence_penalty = Self::optional_f64(&req.input, "presence_penalty")?;
                let frequency_penalty = Self::optional_f64(&req.input, "frequency_penalty")?;

                let chat_req = ChatCompletionRequest {
                    model: model.to_string(),
                    messages,
                    max_tokens,
                    temperature,
                    top_p,
                    search_domain_filter,
                    return_images,
                    return_related_questions,
                    search_recency_filter,
                    top_k,
                    stream: Some(false),
                    presence_penalty,
                    frequency_penalty,
                };

                let resp = client
                    .chat_completions(&chat_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;

                // Build a user-friendly output
                let answer = resp
                    .choices
                    .first()
                    .map_or("", |c| c.message.content.as_str());

                json!({
                    "answer": answer,
                    "model": resp.model,
                    "citations": resp.citations.unwrap_or_default(),
                    "usage": resp.usage,
                    "id": resp.id,
                    "finish_reason": resp.choices.first().and_then(|c| c.finish_reason.as_deref()),
                    "external_content": Self::external_content(),
                })
            }
            OP_NATIVE_SEARCH => {
                if config.transport == PerplexityTransport::OpenRouter {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message: "Native Perplexity Search API is not available through OpenRouter; use perplexity-search.query for OpenRouter chat-completions routing".into(),
                    });
                }

                let query = Self::require_str(&req.input, "query")?;
                let count = Self::optional_u32(&req.input, "count", 1, 10)?
                    .or(Self::optional_u32(&req.input, "max_results", 1, 10)?)
                    .unwrap_or(10);
                let country = Self::optional_str(&req.input, "country")?;
                let language = Self::optional_str(&req.input, "language")?;
                Self::validate_country_or_language(country.as_deref(), "country")?;
                Self::validate_country_or_language(language.as_deref(), "language")?;
                let search_recency_filter = Self::recency_filter(&req.input, false)?;
                let search_domain_filter = Self::domain_filter(&req.input)?;
                let max_tokens = Self::optional_u32(&req.input, "max_tokens", 1, 1_000_000)?;
                let max_tokens_per_page =
                    Self::optional_u32(&req.input, "max_tokens_per_page", 1, 1_000_000)?;

                let raw_date_after = Self::optional_str(&req.input, "date_after")?;
                let raw_date_before = Self::optional_str(&req.input, "date_before")?;
                if search_recency_filter.is_some()
                    && (raw_date_after.is_some() || raw_date_before.is_some())
                {
                    return Err(FcpError::InvalidRequest {
                        code: 1005,
                        message:
                            "freshness/search_recency_filter cannot be combined with date filters"
                                .into(),
                    });
                }
                let search_after_date = raw_date_after
                    .as_deref()
                    .map(|value| Self::iso_to_perplexity_date(value, "date_after"))
                    .transpose()?;
                let search_before_date = raw_date_before
                    .as_deref()
                    .map(|value| Self::iso_to_perplexity_date(value, "date_before"))
                    .transpose()?;
                if let (Some(after), Some(before)) = (&raw_date_after, &raw_date_before) {
                    if after > before {
                        return Err(FcpError::InvalidRequest {
                            code: 1005,
                            message: "date_after must be before date_before".into(),
                        });
                    }
                }

                let search_req = SearchApiRequest {
                    query: query.to_string(),
                    max_results: count,
                    country,
                    search_domain_filter,
                    search_recency_filter,
                    search_language_filter: language.map(|value| vec![value]),
                    search_after_date,
                    search_before_date,
                    max_tokens,
                    max_tokens_per_page,
                };

                let resp = client
                    .native_search(&search_req)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let results = resp
                    .results
                    .iter()
                    .map(Self::search_result_json)
                    .collect::<Vec<_>>();

                json!({
                    "query": query,
                    "provider": "perplexity",
                    "count": results.len(),
                    "results": results,
                    "external_content": Self::external_content(),
                })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };

        Ok(InvokeResponse::ok(req.id, output))
    }
}

impl Default for PerplexitySearchConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ──

fn operations_info() -> Vec<OperationInfo> {
    let manifest = ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
        .expect("embedded Perplexity Search manifest should parse before hash validation");
    let mut operations: Vec<_> = manifest.provides.operations.into_iter().collect();
    operations.sort_by(|(left, _), (right, _)| {
        let left_index = operation_order(left);
        let right_index = operation_order(right);
        left_index.cmp(&right_index).then_with(|| left.cmp(right))
    });
    operations
        .into_iter()
        .map(|(id, operation)| operation_info_from_manifest(id, operation))
        .collect()
}

fn operation_order(operation_id: &str) -> usize {
    OPERATION_ORDER
        .iter()
        .position(|candidate| *candidate == operation_id)
        .unwrap_or(usize::MAX)
}

fn approval_mode_from_manifest(mode: ManifestApprovalMode) -> Option<ApprovalMode> {
    match mode {
        ManifestApprovalMode::None => None,
        other => Some(ApprovalMode::from(other)),
    }
}

fn operation_info_from_manifest(
    id: String,
    operation: fcp_manifest::OperationSection,
) -> OperationInfo {
    let description = operation.description;
    OperationInfo {
        id: OperationId::new(id).expect("manifest operation id should be canonical"),
        summary: description.clone(),
        description: Some(description),
        input_schema: operation.input_schema,
        output_schema: operation.output_schema,
        capability: operation.capability,
        risk_level: operation.risk_level,
        safety_tier: operation.safety_tier,
        idempotency: operation.idempotency,
        ai_hints: operation.ai_hints,
        rate_limit: operation.rate_limit.map(|rate_limit| rate_limit.0),
        requires_approval: approval_mode_from_manifest(operation.requires_approval),
    }
}

// ── FcpConnector trait impl ──

fcp_core::impl_fcp_sealed!(PerplexitySearchConnector);

#[async_trait]
impl FcpConnector for PerplexitySearchConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let perplexity = PerplexityConfig::from_value(config)?;
        let client = PerplexityClient::new(
            perplexity.auth.clone(),
            perplexity.retry.clone(),
            Duration::from_millis(perplexity.request_timeout_ms),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?
        .with_base_url(&perplexity.base_url);

        self.client = Some(client);
        self.config = Some(perplexity);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if let Some(requested_instance_id) = req.requested_instance_id {
            self.base.instance_id = requested_instance_id;
        }
        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let capabilities_granted = req
            .capabilities_requested
            .into_iter()
            .map(|capability| CapabilityGrant {
                capability,
                operation: None,
            })
            .collect();

        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snapshot = if self.config.is_some() && self.client.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not configured")
        };
        snapshot.uptime_ms =
            u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snapshot
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(client) = &self.client else {
            return Ok(SelfCheckReport::degraded(
                "not_configured",
                "Connector is not configured",
            ));
        };

        if client.is_secretless() {
            return Ok(SelfCheckReport::degraded(
                "credential_injection_required",
                "API key not configured; credential injection is required for health checks",
            ));
        }

        match client.health_check().await {
            Ok(()) => Ok(SelfCheckReport::ok()),
            Err(e) if e.is_retryable() => Ok(SelfCheckReport::degraded(
                "self_check_retryable",
                e.to_string(),
            )),
            Err(e) => Ok(SelfCheckReport::failed("self_check_failed", e.to_string())),
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match Self::capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };
        if self.client.is_none() || self.config.is_none() {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector is not configured",
                FcpError::NotConfigured.error_code(),
            ));
        }
        let Some(verifier) = self.verifier.as_ref() else {
            return Ok(SimulateResponse::denied(
                req.id,
                "Connector handshake not completed",
                FcpError::NotHandshaken.error_code(),
            ));
        };
        if let Err(error) =
            verifier.verify_bound(req.capability_token, &capability, &req.operation, &[])
        {
            let mut response =
                SimulateResponse::denied(req.id, error.to_string(), error.error_code());
            if error.error_code() == "FCP-3001" {
                response =
                    response.with_missing_capabilities(vec![capability.as_str().to_string()]);
            }
            return Ok(response);
        }
        Ok(SimulateResponse::allowed(req.id))
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }

    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as ChronoDuration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::{
        CapabilityConstraints, CapabilityToken, ConnectorId, RequestId, RiskLevel, SafetyTier,
        SelfCheckStatus, ZoneId,
    };
    use jsonschema::Validator;
    use serde_json::Value;

    fn perplexity_manifest_unchecked() -> ConnectorManifest {
        ConnectorManifest::parse_str_unchecked(MANIFEST_TOML)
            .expect("Perplexity Search manifest should parse before hash validation")
    }

    fn operation_input_schema<'a>(
        manifest: &'a ConnectorManifest,
        operation_id: &str,
    ) -> &'a Value {
        &manifest
            .provides
            .operations
            .get(operation_id)
            .expect("operation should be declared")
            .input_schema
    }

    fn validator_for(schema: &Value) -> Validator {
        Validator::new(schema).expect("manifest operation schema should compile")
    }

    fn assert_schema_accepts(schema: &Value, payload: &Value) {
        let validator = validator_for(schema);
        let errors: Vec<_> = validator
            .iter_errors(payload)
            .map(|error| error.to_string())
            .collect();
        assert!(
            errors.is_empty(),
            "schema should accept {payload}; errors: {errors:?}"
        );
    }

    fn assert_schema_rejects(schema: &Value, payload: &Value) {
        let validator = validator_for(schema);
        assert!(
            validator.iter_errors(payload).next().is_some(),
            "schema should reject {payload}"
        );
    }

    fn valid_config() -> serde_json::Value {
        json!({
            "api_key": "pplx-test-key"
        })
    }

    fn signing_key_and_pub() -> (Ed25519SigningKey, [u8; 32]) {
        let sk = Ed25519SigningKey::generate();
        let pk = sk.verifying_key().to_bytes();
        (sk, pk)
    }

    fn handshake_req(host_public_key: [u8; 32]) -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key,
            nonce: [7u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_SEARCH),
                CapabilityId::from_static(CAP_NATIVE_SEARCH),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn generate_test_capability_for(
        signing_key: &Ed25519SigningKey,
        capability_id: &'static str,
        operations: &[&'static str],
        target_instance: Option<&str>,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
        let mut builder = CapabilityTokenBuilder::new()
            .capability_id(capability_id)
            .zone_id("z:work")
            .principal("user:test")
            .operations(operations)
            .issuer("node:test")
            .validity(now, now + ChronoDuration::hours(1));
        if let Some(instance_id) = target_instance {
            builder = builder.target_instance(instance_id);
        }
        let raw = builder
            .try_constraints_cbor(&cbor)
            .expect("constraints CBOR should validate")
            .sign(signing_key)
            .expect("capability token signing should succeed");
        CapabilityToken::from_raw(raw)
    }

    fn generate_test_capability_with_operations(
        signing_key: &Ed25519SigningKey,
        operations: &[&'static str],
    ) -> CapabilityToken {
        generate_test_capability_for(signing_key, CAP_SEARCH, operations, None)
    }

    fn generate_test_capability(signing_key: &Ed25519SigningKey) -> CapabilityToken {
        generate_test_capability_with_operations(signing_key, &[OP_SEARCH])
    }

    fn generate_bound_test_capability_with_operations(
        signing_key: &Ed25519SigningKey,
        connector: &PerplexitySearchConnector,
        operations: &[&'static str],
    ) -> CapabilityToken {
        generate_test_capability_for(
            signing_key,
            CAP_SEARCH,
            operations,
            Some(connector.base.instance_id.as_str()),
        )
    }

    fn generate_bound_test_capability(
        signing_key: &Ed25519SigningKey,
        connector: &PerplexitySearchConnector,
    ) -> CapabilityToken {
        generate_bound_test_capability_with_operations(signing_key, connector, &[OP_SEARCH])
    }

    fn generate_bound_native_search_capability(
        signing_key: &Ed25519SigningKey,
        connector: &PerplexitySearchConnector,
    ) -> CapabilityToken {
        generate_test_capability_for(
            signing_key,
            CAP_NATIVE_SEARCH,
            &[OP_NATIVE_SEARCH],
            Some(connector.base.instance_id.as_str()),
        )
    }

    fn invoke_req_for_operation(
        operation: &'static str,
        input: serde_json::Value,
        capability: CapabilityToken,
    ) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("pp-test-1"),
            connector_id: ConnectorId::from_static("fcp.perplexity-search"),
            operation: OperationId::from_static(operation),
            zone_id: ZoneId::work(),
            input,
            capability_token: capability,
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        }
    }

    fn invoke_req(input: serde_json::Value, capability: CapabilityToken) -> InvokeRequest {
        invoke_req_for_operation(OP_SEARCH, input, capability)
    }

    fn simulate_req(capability: CapabilityToken) -> SimulateRequest {
        SimulateRequest {
            r#type: "simulate".into(),
            id: RequestId::new("pp-sim-1"),
            connector_id: ConnectorId::from_static("fcp.perplexity-search"),
            operation: OperationId::from_static(OP_SEARCH),
            zone_id: ZoneId::work(),
            input: json!({ "query": "rust async runtimes" }),
            capability_token: capability,
            estimate_cost: false,
            check_availability: false,
            context: None,
            correlation_id: None,
        }
    }

    #[test]
    fn new_connector_starts_unconfigured() {
        assert!(PerplexitySearchConnector::new().config.is_none());
    }

    #[test]
    fn manifest_hash_is_stable() {
        assert_eq!(
            PerplexitySearchConnector::manifest_hash(),
            PerplexitySearchConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_accepts_api_key() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            assert!(connector.config.is_some());
            assert!(connector.client.is_some());
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_empty_base_url() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            let err = connector
                .configure(json!({
                    "api_key": "pplx-test",
                    "base_url": ""
                }))
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::InvalidRequest { code: 1001, .. }));
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_zero_timeout() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            let err = connector
                .configure(json!({
                    "api_key": "pplx-test",
                    "request_timeout_ms": 0
                }))
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::InvalidRequest { code: 1001, .. }));
        })
        .unwrap();
    }

    #[test]
    fn configure_uses_defaults() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let config = connector.config.as_ref().unwrap();
            assert_eq!(config.base_url, "https://api.perplexity.ai");
            assert_eq!(config.default_model, "sonar");
            assert_eq!(config.request_timeout_ms, 30_000);
        })
        .unwrap();
    }

    #[test]
    fn configure_custom_model() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector
                .configure(json!({
                    "api_key": "pplx-test",
                    "default_model": "sonar-pro"
                }))
                .await
                .unwrap();
            assert_eq!(
                connector.config.as_ref().unwrap().default_model,
                "sonar-pro"
            );
        })
        .unwrap();
    }

    #[test]
    fn configure_infers_openrouter_from_key_prefix() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector
                .configure(json!({
                    "api_key": "sk-or-v1-test"
                }))
                .await
                .unwrap();
            let config = connector.config.as_ref().unwrap();
            assert_eq!(config.base_url, OPENROUTER_BASE_URL);
            assert_eq!(config.default_model, OPENROUTER_DEFAULT_MODEL);
            assert_eq!(config.transport, PerplexityTransport::OpenRouter);
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_public_http_base_url() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            let err = connector
                .configure(json!({
                    "api_key": "pplx-test",
                    "base_url": "http://api.perplexity.ai"
                }))
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::InvalidRequest { code: 1001, .. }));
        })
        .unwrap();
    }

    #[test]
    fn configure_allows_loopback_http_base_url() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector
                .configure(json!({
                    "api_key": "pplx-test",
                    "base_url": "http://127.0.0.1:8080"
                }))
                .await
                .unwrap();
            assert_eq!(
                connector.config.as_ref().unwrap().transport,
                PerplexityTransport::Custom
            );
        })
        .unwrap();
    }

    #[test]
    fn configure_rejects_private_ip_base_url() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            let err = connector
                .configure(json!({
                    "api_key": "pplx-test",
                    "base_url": "https://10.0.0.5"
                }))
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::InvalidRequest { code: 1001, .. }));
        })
        .unwrap();
    }

    #[test]
    fn health_degraded_before_configure() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = PerplexitySearchConnector::new();
            let health = connector.health().await;
            assert!(!health.is_ready());
        })
        .unwrap();
    }

    #[test]
    fn health_ready_after_configure() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let health = connector.health().await;
            assert!(health.is_ready());
        })
        .unwrap();
    }

    #[test]
    fn self_check_degraded_before_configure() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = PerplexitySearchConnector::new();
            let report = connector.self_check().await.unwrap();
            assert_eq!(report.status, SelfCheckStatus::Degraded);
        })
        .unwrap();
    }

    #[test]
    fn self_check_degraded_for_secretless() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(json!({ "api_key": "" })).await.unwrap();
            let report = connector.self_check().await.unwrap();
            assert_eq!(report.status, SelfCheckStatus::Degraded);
        })
        .unwrap();
    }

    #[test]
    fn doctor_passes_after_configure() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let result = connector.doctor();
            assert!(result.passed);
        })
        .unwrap();
    }

    #[test]
    fn doctor_fails_before_configure() {
        let connector = PerplexitySearchConnector::new();
        let result = connector.doctor();
        assert!(!result.passed);
    }

    #[test]
    fn simulate_requires_configuration() {
        fcp_async_core::runtime::block_on_sync(async {
            let (sk, _) = signing_key_and_pub();
            let connector = PerplexitySearchConnector::new();
            let response = connector
                .simulate(simulate_req(generate_test_capability(&sk)))
                .await
                .unwrap();

            assert!(!response.would_succeed);
            assert_eq!(
                response.denial_code,
                Some(FcpError::NotConfigured.error_code())
            );
        })
        .unwrap();
    }

    #[test]
    fn simulate_checks_capability_grant() {
        fcp_async_core::runtime::block_on_sync(async {
            let (sk, pk) = signing_key_and_pub();
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            connector.handshake(handshake_req(pk)).await.unwrap();

            let under_scoped_grant = generate_bound_test_capability_with_operations(
                &sk,
                &connector,
                &["perplexity-search.other"],
            );
            let response = connector
                .simulate(simulate_req(under_scoped_grant))
                .await
                .unwrap();

            assert!(!response.would_succeed);
            assert_eq!(response.denial_code.as_deref(), Some("FCP-3003"));
            assert!(response.missing_capabilities.is_empty());
        })
        .unwrap();
    }

    #[test]
    fn manifest_declares_valid_perplexity_operations_metadata() {
        let unchecked = perplexity_manifest_unchecked();
        let expected_hash = unchecked
            .compute_interface_hash()
            .expect("interface hash should compute");
        assert_eq!(
            unchecked.manifest.interface_hash.to_string(),
            expected_hash.to_string(),
            "update connectors/perplexity-search/manifest.toml interface_hash to {expected_hash}"
        );

        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should validate");
        assert_eq!(manifest.provides.operations.len(), OPERATION_ORDER.len());

        let search = manifest
            .provides
            .operations
            .get(OP_SEARCH)
            .expect("chat-completions search operation should be declared");
        assert_eq!(search.capability.as_str(), CAP_SEARCH);
        assert_eq!(json!(search.risk_level), json!("medium"));
        assert_eq!(json!(search.safety_tier), json!("safe"));
        assert_eq!(json!(search.idempotency), json!("none"));
        assert_eq!(search.input_schema["required"], json!(["query"]));
        assert_eq!(
            search.input_schema["properties"]["freshness"]["enum"],
            json!(["year", "month", "week", "day", "hour"])
        );
        let search_network = search
            .network_constraints
            .as_ref()
            .expect("chat-completions operation should declare network constraints");
        assert_eq!(
            search_network.host_allow,
            vec!["api.perplexity.ai".to_string(), "openrouter.ai".to_string()]
        );
        assert_eq!(search_network.port_allow, vec![443]);
        assert!(search_network.require_sni);
        assert!(search_network.deny_private_ranges);

        let native_search = manifest
            .provides
            .operations
            .get(OP_NATIVE_SEARCH)
            .expect("native search operation should be declared");
        assert_eq!(native_search.capability.as_str(), CAP_NATIVE_SEARCH);
        assert_eq!(
            native_search.input_schema["properties"]["count"]["maximum"],
            json!(10)
        );
        assert_eq!(
            native_search.input_schema["properties"]["freshness"]["enum"],
            json!(["year", "month", "week", "day"])
        );
        let native_network = native_search
            .network_constraints
            .as_ref()
            .expect("native operation should declare network constraints");
        assert_eq!(
            native_network.host_allow,
            vec!["api.perplexity.ai".to_string()]
        );
        assert!(native_network.deny_ip_literals);
    }

    #[test]
    fn introspection_uses_manifest_operation_metadata() {
        let manifest =
            ConnectorManifest::parse_str(MANIFEST_TOML).expect("embedded manifest should validate");
        let connector = PerplexitySearchConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), manifest.provides.operations.len());

        for (operation, expected_id) in intro.operations.iter().zip(OPERATION_ORDER) {
            let manifest_operation = manifest
                .provides
                .operations
                .get(expected_id)
                .expect("operation should be declared");
            assert_eq!(operation.id.as_str(), expected_id);
            assert_eq!(operation.summary, manifest_operation.description);
            assert_eq!(
                operation.description.as_deref(),
                Some(manifest_operation.description.as_str())
            );
            assert_eq!(operation.capability, manifest_operation.capability);
            assert_eq!(operation.input_schema, manifest_operation.input_schema);
            assert_eq!(operation.output_schema, manifest_operation.output_schema);
            assert_eq!(
                operation.ai_hints.when_to_use,
                manifest_operation.ai_hints.when_to_use
            );
        }
    }

    #[test]
    fn manifest_input_schemas_validate_representative_payloads() {
        let manifest = perplexity_manifest_unchecked();
        let query_schema = operation_input_schema(&manifest, OP_SEARCH);
        assert_schema_accepts(
            query_schema,
            &json!({
                "query": "latest Rust async runtime guidance",
                "model": "sonar-pro",
                "system_prompt": "Answer concisely.",
                "max_tokens": 512,
                "temperature": 0.3,
                "top_p": 0.9,
                "top_k": 20,
                "search_domain_filter": ["rust-lang.org", "doc.rust-lang.org"],
                "return_images": false,
                "return_related_questions": true,
                "freshness": "hour",
                "presence_penalty": -0.25,
                "frequency_penalty": 0.1,
                "future_provider_option": {"preserve": "unknown runtime options"}
            }),
        );
        assert_schema_rejects(query_schema, &json!({}));
        assert_schema_rejects(query_schema, &json!({"query": ""}));
        assert_schema_rejects(query_schema, &json!({"query": "q", "max_tokens": 0}));
        assert_schema_rejects(query_schema, &json!({"query": "q", "top_k": 0}));
        assert_schema_rejects(query_schema, &json!({"query": "q", "freshness": "minute"}));
        assert_schema_rejects(query_schema, &json!({"query": "q", "return_images": "yes"}));

        let native_schema = operation_input_schema(&manifest, OP_NATIVE_SEARCH);
        assert_schema_accepts(
            native_schema,
            &json!({
                "query": "Rust async runtimes",
                "count": 3,
                "country": "US",
                "language": "en",
                "domain_filter": ["rust-lang.org"],
                "date_after": "2026-05-01",
                "date_before": "2026-05-31",
                "max_tokens": 2000,
                "max_tokens_per_page": 500,
                "future_native_option": true
            }),
        );
        assert_schema_accepts(native_schema, &json!({"query": "Rust", "max_results": 10}));
        assert_schema_rejects(native_schema, &json!({}));
        assert_schema_rejects(native_schema, &json!({"query": ""}));
        assert_schema_rejects(native_schema, &json!({"query": "q", "count": 0}));
        assert_schema_rejects(native_schema, &json!({"query": "q", "max_results": 11}));
        assert_schema_rejects(native_schema, &json!({"query": "q", "country": "USA"}));
        assert_schema_rejects(native_schema, &json!({"query": "q", "freshness": "hour"}));
        assert_schema_rejects(
            native_schema,
            &json!({"query": "q", "date_after": "2026/05/01"}),
        );
        assert_schema_rejects(
            native_schema,
            &json!({"query": "q", "max_tokens_per_page": 0}),
        );
    }

    #[test]
    fn introspect_lists_search_operation() {
        let connector = PerplexitySearchConnector::new();
        let intro = connector.introspect();
        assert_eq!(intro.operations.len(), 2);
        assert_eq!(intro.operations[0].id.as_str(), OP_SEARCH);
        assert_eq!(intro.operations[1].id.as_str(), OP_NATIVE_SEARCH);
        assert_eq!(intro.operations[0].risk_level, RiskLevel::Medium);
        assert_eq!(intro.operations[0].safety_tier, SafetyTier::Safe);
        assert_eq!(intro.operations[1].capability.as_str(), CAP_NATIVE_SEARCH);
    }

    #[test]
    fn shutdown_clears_state() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            assert!(connector.config.is_some());
            connector
                .shutdown(ShutdownRequest {
                    r#type: "shutdown".into(),
                    deadline_ms: 5_000,
                    drain: false,
                    reason: None,
                })
                .await
                .unwrap();
            assert!(connector.config.is_none());
            assert!(connector.client.is_none());
        })
        .unwrap();
    }

    #[test]
    fn invoke_rejects_unknown_operation() {
        fcp_async_core::runtime::block_on_sync(async {
            let (sk, pk) = signing_key_and_pub();
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            connector.handshake(handshake_req(pk)).await.unwrap();

            let cap = generate_bound_test_capability(&sk, &connector);
            let req = InvokeRequest {
                r#type: "invoke".into(),
                id: RequestId::new("pp-unknown-op"),
                connector_id: ConnectorId::from_static("fcp.perplexity-search"),
                operation: OperationId::from_static("perplexity-search.nonexistent"),
                zone_id: ZoneId::work(),
                input: json!({}),
                capability_token: cap,
                holder_proof: None,
                context: None,
                idempotency_key: None,
                lease_seq: None,
                deadline_ms: None,
                correlation_id: None,
                provenance: None,
                approval_tokens: vec![],
            };
            let err = connector.invoke(req).await.unwrap_err();
            assert!(matches!(err, FcpError::InvalidRequest { code: 1004, .. }));
        })
        .unwrap();
    }

    #[test]
    fn invoke_rejects_missing_query() {
        fcp_async_core::runtime::block_on_sync(async {
            let (sk, pk) = signing_key_and_pub();
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            connector.handshake(handshake_req(pk)).await.unwrap();

            let cap = generate_bound_test_capability(&sk, &connector);
            let req = invoke_req(json!({}), cap);
            let err = connector.invoke(req).await.unwrap_err();
            match err {
                FcpError::InvalidRequest { code, message } => {
                    assert_eq!(code, 1005);
                    assert!(message.contains("query"));
                }
                other => assert!(
                    matches!(other, FcpError::InvalidRequest { .. }),
                    "expected InvalidRequest"
                ),
            }
        })
        .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_with_mock_server() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .and(header("authorization", "Bearer pplx-test-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chatcmpl-test-123",
                "model": "sonar",
                "object": "chat.completion",
                "created": 1_700_000_000u64,
                "choices": [{
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "Rust is a systems programming language focused on safety and performance."
                    },
                    "delta": null
                }],
                "usage": {
                    "prompt_tokens": 12,
                    "completion_tokens": 15,
                    "total_tokens": 27
                },
                "citations": [
                    "https://www.rust-lang.org/",
                    "https://doc.rust-lang.org/book/"
                ]
            })))
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-test-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let cap = generate_bound_test_capability(&sk, &connector);
        let req = invoke_req(
            json!({
                "query": "What is Rust?",
                "temperature": 0.5
            }),
            cap,
        );

        let resp = connector.invoke(req).await.unwrap();
        let output = resp.result.expect("result should be present");
        assert_eq!(
            output["answer"],
            "Rust is a systems programming language focused on safety and performance."
        );
        assert_eq!(output["model"], "sonar");
        assert_eq!(output["citations"].as_array().unwrap().len(), 2);
        assert_eq!(output["usage"]["total_tokens"], 27);
        assert_eq!(output["finish_reason"], "stop");
        assert_eq!(output["id"], "chatcmpl-test-123");
        assert_eq!(output["external_content"]["untrusted"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_native_search_with_mock_server() {
        use wiremock::matchers::{body_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/search"))
            .and(header("authorization", "Bearer pplx-test-key"))
            .and(body_json(json!({
                "query": "rust async runtimes",
                "max_results": 2,
                "country": "US",
                "search_domain_filter": ["rust-lang.org"],
                "search_language_filter": ["en"],
                "search_after_date": "5/1/2026",
                "max_tokens": 1000,
                "max_tokens_per_page": 250
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "title": "Rust",
                    "url": "https://www.rust-lang.org/",
                    "snippet": "Rust is a language empowering everyone to build reliable software.",
                    "date": "2026-05-02"
                }]
            })))
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-test-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let cap = generate_bound_native_search_capability(&sk, &connector);
        let req = invoke_req_for_operation(
            OP_NATIVE_SEARCH,
            json!({
                "query": "rust async runtimes",
                "count": 2,
                "country": "US",
                "domain_filter": ["rust-lang.org"],
                "language": "en",
                "date_after": "2026-05-01",
                "max_tokens": 1000,
                "max_tokens_per_page": 250
            }),
            cap,
        );

        let resp = connector.invoke(req).await.unwrap();
        let output = resp.result.expect("result should be present");
        assert_eq!(output["provider"], "perplexity");
        assert_eq!(output["count"], 1);
        assert_eq!(output["results"][0]["url"], "https://www.rust-lang.org/");
        assert_eq!(output["results"][0]["site_name"], "www.rust-lang.org");
        assert!(
            output["results"][0]["title"]
                .as_str()
                .unwrap()
                .contains("<untrusted-web-search>")
        );
        assert_eq!(output["external_content"]["untrusted"], true);
    }

    #[test]
    fn native_search_rejects_invalid_filters_before_http() {
        fcp_async_core::runtime::block_on_sync(async {
            let (sk, pk) = signing_key_and_pub();
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            connector.handshake(handshake_req(pk)).await.unwrap();

            let cap = generate_bound_native_search_capability(&sk, &connector);
            let req = invoke_req_for_operation(
                OP_NATIVE_SEARCH,
                json!({
                    "query": "test",
                    "freshness": "week",
                    "date_after": "2026-05-01"
                }),
                cap,
            );

            let err = connector.invoke(req).await.unwrap_err();
            match err {
                FcpError::InvalidRequest { code, message } => {
                    assert_eq!(code, 1005);
                    assert!(message.contains("cannot be combined"));
                }
                other => assert!(
                    matches!(other, FcpError::InvalidRequest { .. }),
                    "expected InvalidRequest, got {other:?}"
                ),
            }
        })
        .unwrap();
    }

    #[test]
    fn native_search_rejects_mixed_domain_filter() {
        fcp_async_core::runtime::block_on_sync(async {
            let (sk, pk) = signing_key_and_pub();
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            connector.handshake(handshake_req(pk)).await.unwrap();

            let cap = generate_bound_native_search_capability(&sk, &connector);
            let req = invoke_req_for_operation(
                OP_NATIVE_SEARCH,
                json!({
                    "query": "test",
                    "domain_filter": ["example.com", "-blocked.example"]
                }),
                cap,
            );

            let err = connector.invoke(req).await.unwrap_err();
            match err {
                FcpError::InvalidRequest { message, .. } => {
                    assert!(message.contains("cannot mix"));
                }
                other => assert!(
                    matches!(other, FcpError::InvalidRequest { .. }),
                    "expected InvalidRequest, got {other:?}"
                ),
            }
        })
        .unwrap();
    }

    #[test]
    fn chat_query_rejects_native_only_filters() {
        fcp_async_core::runtime::block_on_sync(async {
            let (sk, pk) = signing_key_and_pub();
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            connector.handshake(handshake_req(pk)).await.unwrap();

            let cap = generate_bound_test_capability(&sk, &connector);
            let req = invoke_req(
                json!({
                    "query": "test",
                    "date_after": "2026-05-01"
                }),
                cap,
            );

            let err = connector.invoke(req).await.unwrap_err();
            match err {
                FcpError::InvalidRequest { message, .. } => {
                    assert!(message.contains(OP_NATIVE_SEARCH));
                }
                other => assert!(
                    matches!(other, FcpError::InvalidRequest { .. }),
                    "expected InvalidRequest, got {other:?}"
                ),
            }
        })
        .unwrap();
    }

    #[test]
    fn native_search_rejects_openrouter_transport() {
        fcp_async_core::runtime::block_on_sync(async {
            let (sk, pk) = signing_key_and_pub();
            let mut connector = PerplexitySearchConnector::new();
            connector
                .configure(json!({ "api_key": "sk-or-v1-test" }))
                .await
                .unwrap();
            connector.handshake(handshake_req(pk)).await.unwrap();

            let cap = generate_bound_native_search_capability(&sk, &connector);
            let req = invoke_req_for_operation(OP_NATIVE_SEARCH, json!({ "query": "test" }), cap);

            let err = connector.invoke(req).await.unwrap_err();
            match err {
                FcpError::InvalidRequest { message, .. } => {
                    assert!(message.contains("OpenRouter"));
                }
                other => assert!(
                    matches!(other, FcpError::InvalidRequest { .. }),
                    "expected InvalidRequest, got {other:?}"
                ),
            }
        })
        .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_handles_401() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "error": {
                    "message": "Invalid API Key",
                    "type": "authentication_error"
                }
            })))
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-bad-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let cap = generate_bound_test_capability(&sk, &connector);
        let req = invoke_req(json!({ "query": "test" }), cap);

        let err = connector.invoke(req).await.unwrap_err();
        assert!(matches!(err, FcpError::Unauthorized { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_handles_429() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "error": {
                    "message": "Rate limit exceeded",
                    "type": "rate_limit_error"
                }
            })))
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-test-key",
                "base_url": mock_server.uri(),
                "retry": { "max_retries": 0 }
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let cap = generate_bound_test_capability(&sk, &connector);
        let req = invoke_req(json!({ "query": "test" }), cap);

        let err = connector.invoke(req).await.unwrap_err();
        assert!(matches!(err, FcpError::RateLimited { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_rejects_malformed_provider_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chatcmpl-malformed"
            })))
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-test-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let cap = generate_bound_test_capability(&sk, &connector);
        let req = invoke_req(json!({ "query": "test" }), cap);

        let err = connector.invoke(req).await.unwrap_err();
        match err {
            FcpError::Internal { message } => {
                assert!(message.contains("JSON parse error"));
            }
            other => assert!(
                matches!(other, FcpError::Internal { .. }),
                "expected Internal JSON parse error"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_times_out_slow_provider_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_millis(100))
                    .set_body_json(json!({
                        "id": "chatcmpl-slow",
                        "model": "sonar",
                        "object": "chat.completion",
                        "created": 1_700_000_000u64,
                        "choices": []
                    })),
            )
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-test-key",
                "base_url": mock_server.uri(),
                "request_timeout_ms": 5,
                "retry": { "max_retries": 0 }
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let cap = generate_bound_test_capability(&sk, &connector);
        let req = invoke_req(json!({ "query": "test" }), cap);

        let err = connector.invoke(req).await.unwrap_err();
        match err {
            FcpError::External {
                service, retryable, ..
            } => {
                assert_eq!(service, "perplexity");
                assert!(retryable);
            }
            other => assert!(
                matches!(other, FcpError::External { .. }),
                "expected retryable External timeout"
            ),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn invoke_search_with_system_prompt() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "chatcmpl-sys-prompt",
                "model": "sonar",
                "object": "chat.completion",
                "created": 1_700_000_000u64,
                "choices": [{
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": "Guided answer with system context."
                    },
                    "delta": null
                }],
                "citations": []
            })))
            .mount(&mock_server)
            .await;

        let (sk, pk) = signing_key_and_pub();
        let mut connector = PerplexitySearchConnector::new();
        connector
            .configure(json!({
                "api_key": "pplx-test-key",
                "base_url": mock_server.uri()
            }))
            .await
            .unwrap();
        connector.handshake(handshake_req(pk)).await.unwrap();

        let cap = generate_bound_test_capability(&sk, &connector);
        let req = invoke_req(
            json!({
                "query": "What is Rust?",
                "system_prompt": "You are a concise technical writer."
            }),
            cap,
        );

        let resp = connector.invoke(req).await.unwrap();
        let output = resp.result.expect("result should be present");
        assert_eq!(output["answer"], "Guided answer with system context.");
    }

    #[test]
    fn config_debug_redacts_api_key() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut connector = PerplexitySearchConnector::new();
            connector.configure(valid_config()).await.unwrap();
            let debug = format!("{:?}", connector.config.as_ref().unwrap());
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("pplx-test-key"));
        })
        .unwrap();
    }

    #[test]
    fn subscribe_returns_not_supported() {
        fcp_async_core::runtime::block_on_sync(async {
            let connector = PerplexitySearchConnector::new();
            let err = connector
                .subscribe(SubscribeRequest {
                    r#type: "subscribe".into(),
                    id: RequestId::new("sub-test"),
                    topics: vec![],
                    since: None,
                    max_events_per_sec: None,
                    batch_ms: None,
                    window_size: None,
                    capability_token: None,
                })
                .await
                .unwrap_err();
            assert!(matches!(err, FcpError::StreamingNotSupported));
        })
        .unwrap();
    }
}
