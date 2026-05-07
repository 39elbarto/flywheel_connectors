use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tracing::debug;
use url::Url;

use crate::error::{ComfyUiError, safe_provider_message};
use crate::types::{
    HistoryResponse, PromptSubmitResponse, SubmitWorkflowInput, artifacts_from_history,
    status_from_history,
};

pub const DEFAULT_BASE_URL: &str = "http://localhost:8188";
pub const USER_AGENT: &str = "fcp-comfyui/0.1.0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComfyUiAuth {
    None,
    AuthorizationHeader(String),
    CredentialId(String),
}

impl ComfyUiAuth {
    pub fn redacted_label(&self) -> String {
        match self {
            Self::None => "none".into(),
            Self::AuthorizationHeader(_) => "authorization_header:redacted".into(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ComfyUiUrlPolicy {
    pub tailnet_only: bool,
    pub allowed_hosts: Vec<String>,
    pub allow_private_ranges: bool,
    pub allow_tailnet_ranges: bool,
}

impl ComfyUiUrlPolicy {
    pub fn new(
        tailnet_only: bool,
        allowed_hosts: Vec<String>,
        allow_private_ranges: bool,
        allow_tailnet_ranges: bool,
    ) -> Self {
        Self {
            tailnet_only,
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| canonical_host(&host))
                .filter(|host| !host.is_empty())
                .collect(),
            allow_private_ranges,
            allow_tailnet_ranges,
        }
    }

    fn host_is_allowed(&self, host: &str) -> bool {
        let host = canonical_host(host);
        self.allowed_hosts.iter().any(|allowed| allowed == &host)
    }
}

pub struct ComfyUiClient {
    client: Client,
    auth: ComfyUiAuth,
    base_url: String,
}

impl ComfyUiClient {
    pub fn new(
        auth: ComfyUiAuth,
        base_url: impl Into<String>,
        request_timeout: Duration,
    ) -> Result<Self, ComfyUiError> {
        let client = Client::builder()
            .timeout(request_timeout)
            .user_agent(USER_AGENT)
            .build()?;
        Ok(Self {
            client,
            auth,
            base_url: base_url.into(),
        })
    }

    pub const fn auth(&self) -> &ComfyUiAuth {
        &self.auth
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn submit_workflow(
        &self,
        input: &SubmitWorkflowInput,
    ) -> Result<PromptSubmitResponse, ComfyUiError> {
        let url = self.endpoint("/prompt");
        debug!(endpoint = "prompt", "submitting ComfyUI workflow");
        let response = self
            .apply_auth(self.client.post(url))
            .header("Accept", "application/json")
            .json(&input.request_body())
            .send()
            .await?;
        let response = self
            .parse_json_response::<PromptSubmitResponse>(response)
            .await?;
        if response.prompt_id.is_none() || response.node_errors != Value::Null {
            let message = response
                .error
                .as_str()
                .map_or_else(|| "ComfyUI rejected workflow".to_string(), str::to_string);
            return Err(ComfyUiError::InvalidInput(message));
        }
        Ok(response)
    }

    pub async fn history(&self, prompt_id: &str) -> Result<HistoryResponse, ComfyUiError> {
        let url = self.endpoint(&format!("/history/{prompt_id}"));
        let response = self
            .apply_auth(self.client.get(url))
            .header("Accept", "application/json")
            .send()
            .await?;
        self.parse_json_response(response).await
    }

    pub async fn workflow_status(
        &self,
        prompt_id: &str,
    ) -> Result<serde_json::Value, ComfyUiError> {
        let history = self.history(prompt_id).await?;
        Ok(serde_json::to_value(status_from_history(
            prompt_id, &history,
        ))?)
    }

    pub async fn workflow_result(
        &self,
        prompt_id: &str,
    ) -> Result<serde_json::Value, ComfyUiError> {
        let history = self.history(prompt_id).await?;
        let artifacts = artifacts_from_history(&self.base_url, prompt_id, &history)
            .map_err(|error| ComfyUiError::InvalidInput(error.to_string()))?;
        Ok(json!({
            "prompt_id": prompt_id,
            "complete": history.contains_key(prompt_id),
            "output_count": artifacts.len(),
            "artifacts": artifacts,
        }))
    }

    pub async fn cancel_workflow(
        &self,
        prompt_id: &str,
        interrupt_running: bool,
    ) -> Result<serde_json::Value, ComfyUiError> {
        let queue_url = self.endpoint("/queue");
        let body = json!({ "delete": [prompt_id] });
        let queue_response = self
            .apply_auth(self.client.post(queue_url))
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await?;
        let queue = self.parse_json_response::<Value>(queue_response).await?;
        let interrupt = if interrupt_running {
            let interrupt_url = self.endpoint("/interrupt");
            let response = self
                .apply_auth(self.client.post(interrupt_url))
                .header("Accept", "application/json")
                .json(&json!({}))
                .send()
                .await?;
            Some(self.parse_json_response::<Value>(response).await?)
        } else {
            None
        };
        Ok(json!({
            "prompt_id": prompt_id,
            "cancel_requested": true,
            "queue": queue,
            "interrupt": interrupt,
        }))
    }

    pub async fn health(&self) -> Result<serde_json::Value, ComfyUiError> {
        let response = self
            .apply_auth(self.client.get(self.endpoint("/system_stats")))
            .header("Accept", "application/json")
            .send()
            .await?;
        let stats = self.parse_json_response::<Value>(response).await?;
        Ok(json!({
            "status": "ok",
            "endpoint_class": classify_comfyui_base_url(&self.base_url),
            "system_stats": stats,
        }))
    }

    fn apply_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut headers = HeaderMap::new();
        match &self.auth {
            ComfyUiAuth::None => req,
            ComfyUiAuth::AuthorizationHeader(header) => {
                if let Ok(value) = HeaderValue::from_str(header) {
                    headers.insert(AUTHORIZATION, value);
                }
                req.headers(headers)
            }
            ComfyUiAuth::CredentialId(id) => {
                if let Ok(value) = HeaderValue::from_str(id) {
                    headers.insert(HeaderName::from_static("x-fcp-credential-id"), value);
                }
                req.headers(headers)
            }
        }
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn parse_json_response<T: DeserializeOwned>(
        &self,
        response: Response,
    ) -> Result<T, ComfyUiError> {
        let status = response.status();
        if status.is_success() {
            let text = response.text().await?;
            if text.trim().is_empty() {
                return serde_json::from_value(json!({})).map_err(ComfyUiError::from);
            }
            return serde_json::from_str(&text).map_err(ComfyUiError::from);
        }
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .map(Duration::from_secs);
        let text = response.text().await.unwrap_or_default();
        let message = provider_error_message(&text, status);
        match status {
            StatusCode::TOO_MANY_REQUESTS => Err(ComfyUiError::RateLimited { retry_after }),
            StatusCode::NOT_FOUND => Err(ComfyUiError::NotFound(message)),
            _ => Err(ComfyUiError::Provider {
                status: status.as_u16(),
                message,
            }),
        }
    }
}

pub fn normalize_comfyui_base_url(
    raw: Option<&str>,
    policy: &ComfyUiUrlPolicy,
) -> Result<String, String> {
    let value = raw.unwrap_or(DEFAULT_BASE_URL).trim();
    if value.is_empty() {
        return Err("base_url must not be empty".into());
    }
    let parsed = Url::parse(value).map_err(|err| format!("Invalid base_url: {err}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(format!("base_url must use http or https: {value}"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(format!(
            "base_url must not include query or fragment components: {value}"
        ));
    }
    let path = parsed.path().trim_end_matches('/');
    if !path.is_empty() {
        return Err(format!("base_url path must be empty or /: {value}"));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "base_url must include a host".to_string())?;
    validate_comfyui_host(host, policy)?;
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

pub fn classify_comfyui_base_url(base_url: &str) -> &'static str {
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
    HeaderValue::from_str(trimmed)
        .map_err(|err| format!("{field} is not a valid HTTP header value: {err}"))?;
    Ok(trimmed.to_string())
}

fn validate_comfyui_host(host: &str, policy: &ComfyUiUrlPolicy) -> Result<(), String> {
    let host = canonical_host(host);
    let loopback = is_loopback_host(&host);
    let tailnet = host.ends_with(".ts.net") || host.parse::<IpAddr>().is_ok_and(is_tailscale_ip);
    let private = host.parse::<IpAddr>().is_ok_and(is_private_ip);
    let explicit_allowed = policy.host_is_allowed(&host);

    if policy.tailnet_only && !tailnet {
        return Err("tailnet_only mode requires a .ts.net or Tailscale IP base_url".into());
    }
    if loopback {
        if policy.tailnet_only {
            return Err("tailnet_only mode rejects localhost and loopback base_url values".into());
        }
        return Ok(());
    }
    if !explicit_allowed {
        return Err(format!(
            "base_url host `{host}` is not loopback and is not listed in allowed_hosts"
        ));
    }
    if tailnet && !policy.allow_tailnet_ranges {
        return Err("tailnet endpoints require allow_tailnet_ranges=true".into());
    }
    if private && !tailnet && !policy.allow_private_ranges {
        return Err("private IP endpoints require allow_private_ranges=true".into());
    }
    Ok(())
}

fn provider_error_message(body: &str, status: StatusCode) -> String {
    if body.trim().is_empty() {
        return format!("HTTP {}", status.as_u16());
    }
    serde_json::from_str::<Value>(body).map_or_else(
        |_| safe_provider_message(body),
        |value| {
            value
                .get("error")
                .and_then(Value::as_str)
                .map_or_else(|| safe_provider_message(&value.to_string()), str::to_string)
        },
    )
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

fn is_private_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_link_local() || v4 == Ipv4Addr::new(169, 254, 169, 254)
        }
        IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

fn is_tailscale_ip(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (64..=127).contains(&octets[1])
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
        }
    }
}
