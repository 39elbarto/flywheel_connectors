//! n8n API client.

use fcp_prelude::log_redaction::redact_url;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use fcp_prelude::CredentialId;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Response, StatusCode, Url};
use tracing::{debug, instrument};

use crate::error::{N8nError, N8nResult};

/// Authentication mode for the n8n API.
#[derive(Clone)]
pub enum N8nAuth {
    /// API key (passed as `X-N8N-API-KEY: <key>` header).
    ApiKey(String),
    /// Host-managed credential reference. The direct client never injects or
    /// transmits the referenced secret.
    CredentialId(CredentialId),
}

impl N8nAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for N8nAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// n8n API client.
pub struct N8nClient {
    client: Client,
    auth: N8nAuth,
    base_url: Url,
    runtime: ConnectorRuntime,
}

impl fmt::Debug for N8nClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("N8nClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url.as_str())
            .finish()
    }
}

impl N8nClient {
    /// Create a new n8n client.
    ///
    /// `base_url` is required for n8n (self-hosted).
    pub fn new(auth: N8nAuth, base_url: &str) -> N8nResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("fcp-n8n/0.1.0 (FCP connector)")
            .build()?;
        let base_url = Self::canonicalize_base_url(base_url)?;
        let base_url = Url::parse(&format!("{base_url}/")).map_err(|error| {
            N8nError::InvalidInput(format!("base_url could not be canonicalized: {error}"))
        })?;

        Ok(Self {
            client,
            auth,
            base_url,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
        })
    }

    /// Canonicalize and validate the operator-approved n8n API root.
    pub fn canonicalize_base_url(base_url: &str) -> N8nResult<String> {
        let parsed = Url::parse(base_url.trim())
            .map_err(|_| N8nError::InvalidInput("base_url must be an absolute URL".into()))?;
        if parsed.username() != "" || parsed.password().is_some() {
            return Err(N8nError::InvalidInput(
                "base_url must not contain userinfo".into(),
            ));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(N8nError::InvalidInput(
                "base_url must not contain query or fragment".into(),
            ));
        }
        let Some(host) = parsed.host_str() else {
            return Err(N8nError::InvalidInput(
                "base_url must include a host".into(),
            ));
        };
        let local = is_loopback_host(host);
        let is_https = parsed.scheme() == "https";
        if !(is_https || (local && parsed.scheme() == "http")) {
            return Err(N8nError::InvalidInput(
                "base_url must use HTTPS; HTTP is allowed only for loopback tests".into(),
            ));
        }
        if !local && is_ip_literal(host) {
            return Err(N8nError::InvalidInput(
                "base_url must not use a non-loopback IP literal".into(),
            ));
        }
        let expected_port = if local { None } else { Some(443) };
        if let Some(port) = parsed.port()
            && Some(port) != expected_port
            && !local
        {
            return Err(N8nError::InvalidInput(
                "base_url must use port 443 for production HTTPS".into(),
            ));
        }
        let path = parsed.path().trim_end_matches('/');
        if path != "/api/v1" {
            return Err(N8nError::InvalidInput(
                "base_url path must be exactly /api/v1".into(),
            ));
        }
        if parsed.path().contains('%') {
            return Err(N8nError::InvalidInput(
                "base_url path must not contain percent-encoded ambiguity".into(),
            ));
        }

        let mut canonical = parsed;
        canonical.set_path("/api/v1");
        canonical.set_query(None);
        canonical.set_fragment(None);
        if canonical.port() == Some(443) {
            canonical.set_port(None).map_err(|()| {
                N8nError::InvalidInput("base_url port could not be canonicalized".into())
            })?;
        }
        Ok(canonical.to_string().trim_end_matches('/').to_string())
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            N8nAuth::ApiKey(key) => req.header("X-N8N-API-KEY", key),
            // The host-mediated egress path owns credential resolution. This
            // direct client refuses CredentialId requests before this helper
            // is reached, and never forwards the reference to the provider.
            N8nAuth::CredentialId(_) => req,
        }
    }

    fn ensure_provider_egress_allowed(&self) -> N8nResult<()> {
        if matches!(self.auth, N8nAuth::CredentialId(_)) {
            return Err(N8nError::InvalidInput(
                "credential_id requires host-mediated secret injection; direct provider egress is unavailable".into(),
            ));
        }

        let is_loopback = self.base_url.host_str().is_some_and(is_loopback_host);
        if !is_loopback {
            return Err(N8nError::InvalidInput(
                "production n8n provider egress requires host-mediated network enforcement".into(),
            ));
        }
        Ok(())
    }

    async fn handle_response(&self, resp: Response) -> N8nResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            decode_success_body(status, &body)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> N8nResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let _body = resp.text().await.unwrap_or_default();
        let detail = format!("n8n provider returned HTTP {}", status.as_u16());

        match status.as_u16() {
            401 => Err(N8nError::Unauthorized),
            403 => Err(N8nError::Forbidden),
            404 => Err(N8nError::NotFound {
                resource: "n8n resource".into(),
            }),
            429 => Err(N8nError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(N8nError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> N8nResult<serde_json::Value> {
        self.ensure_provider_egress_allowed()?;
        let url = self.resolve_path(path)?;
        debug!(url = %redact_url(url.as_str()), "GET request");
        let req = self
            .add_auth(self.client.get(url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    fn resolve_path(&self, path: &str) -> N8nResult<Url> {
        if !path.starts_with('/') || path.contains("..") || path.contains('\\') {
            return Err(N8nError::InvalidInput(
                "provider path is not a safe connector-owned path".into(),
            ));
        }
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|_| N8nError::InvalidInput("provider path could not be resolved".into()))
    }

    // -- Workflows --

    /// List all workflows.
    pub async fn list_workflows(&self) -> N8nResult<serde_json::Value> {
        self.get("/workflows").await
    }

    /// Perform a bounded read-only readiness probe and discard provider data.
    pub async fn self_check(&self) -> N8nResult<()> {
        let response = self.get("/workflows?limit=1").await?;
        let _ = response;
        Ok(())
    }

    /// Get a specific workflow by ID.
    pub async fn get_workflow(&self, id: &str) -> N8nResult<serde_json::Value> {
        let id = sanitize_path_segment(id, "workflow id")?;
        self.get(&format!("/workflows/{id}")).await
    }

    // -- Executions --

    /// List recent executions.
    pub async fn list_executions(&self) -> N8nResult<serde_json::Value> {
        self.get("/executions").await
    }

    /// Get a specific execution by ID.
    pub async fn get_execution(&self, id: &str) -> N8nResult<serde_json::Value> {
        let id = sanitize_path_segment(id, "execution id")?;
        self.get(&format!("/executions/{id}")).await
    }
}

pub(crate) fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> N8nResult<&'a str> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(N8nError::InvalidInput(format!(
            "{field} must be a non-empty single path segment"
        )));
    }

    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.contains('?')
        || value.contains('#')
        || value.contains('&')
        || value.contains('=')
        || value.contains('%')
        || value.chars().any(char::is_control)
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(N8nError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }

    Ok(value)
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

fn is_ip_literal(host: &str) -> bool {
    host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok()
}

fn decode_success_body(status: StatusCode, body: &str) -> N8nResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.trim().is_empty() {
        return Err(N8nError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    Ok(serde_json::from_str(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = N8nAuth::ApiKey("secret-api-key-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-key-12345"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let key = N8nAuth::ApiKey("key".into());
        assert!(!key.is_secretless());
        let cred = N8nAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_api_key() {
        let key = N8nAuth::ApiKey("key".into());
        assert_eq!(key.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, "").unwrap_err();
        assert!(matches!(
            err,
            N8nError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_rejects_whitespace_ok() {
        let err = decode_success_body(StatusCode::OK, "  \n\t").unwrap_err();
        assert!(matches!(
            err,
            N8nError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_allows_empty_no_content() {
        assert_eq!(
            decode_success_body(StatusCode::NO_CONTENT, "").unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1/",
        )
        .unwrap();
        assert_eq!(client.base_url.as_str(), "https://n8n.example.com/api/v1/");
    }

    #[test]
    fn client_new_no_trailing_slash() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        assert_eq!(client.base_url.as_str(), "https://n8n.example.com/api/v1/");
    }

    #[test]
    fn client_debug_redacts() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("super-secret".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone() {
        let auth = N8nAuth::ApiKey("key".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn client_base_url_preserved() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "http://localhost:5678/api/v1",
        )
        .unwrap();
        assert_eq!(client.base_url.as_str(), "http://localhost:5678/api/v1/");
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1///",
        )
        .unwrap();
        assert_eq!(client.base_url.as_str(), "https://n8n.example.com/api/v1/");
    }

    #[test]
    fn sanitize_path_segment_accepts_plain_ids() {
        assert_eq!(
            sanitize_path_segment("1001", "workflow id").unwrap(),
            "1001"
        );
        assert_eq!(
            sanitize_path_segment("exec_abc-123", "execution id").unwrap(),
            "exec_abc-123"
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal_markers() {
        let err = sanitize_path_segment("../admin", "workflow id")
            .expect_err("path traversal should be rejected");
        assert!(matches!(err, N8nError::InvalidInput(message) if message.contains("workflow id")));
        sanitize_path_segment("id/../admin", "workflow id").expect_err("slash rejected");
        sanitize_path_segment("id%2Fadmin", "workflow id").expect_err("encoded slash rejected");
        sanitize_path_segment(" id", "workflow id").expect_err("leading space rejected");
    }

    #[test]
    fn auth_api_key_is_not_secretless() {
        assert!(!N8nAuth::ApiKey("key".into()).is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        assert!(N8nAuth::CredentialId(CredentialId::new()).is_secretless());
    }

    #[test]
    fn auth_debug_bearer_shows_redacted_tuple() {
        let auth = N8nAuth::ApiKey("my-secret-key".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.starts_with("ApiKey("));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("N8nClient"));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://custom.n8n.io/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.n8n.io"));
    }

    #[test]
    fn auth_clone_credential_id() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = cred.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn auth_redacted_label_does_not_contain_key() {
        let auth = N8nAuth::ApiKey("very-secret-key-value".into());
        let label = auth.redacted_label();
        assert!(!label.contains("very-secret-key-value"));
    }

    #[test]
    fn client_new_with_localhost() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "http://127.0.0.1:5678/api/v1",
        )
        .unwrap();
        assert_eq!(client.base_url.as_str(), "http://127.0.0.1:5678/api/v1/");
    }

    #[test]
    fn client_new_with_port() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "http://localhost:8443/api/v1",
        )
        .unwrap();
        assert!(client.base_url.as_str().contains("8443"));
    }

    #[test]
    fn auth_debug_credential_does_not_say_redacted() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(!dbg.contains("redacted"));
    }

    #[test]
    fn client_new_empty_url() {
        assert!(N8nClient::new(N8nAuth::ApiKey("key".into()), "").is_err());
    }

    #[test]
    fn auth_redacted_label_does_not_leak_credential_secret() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(!label.contains("redacted"));
        assert!(label.contains("credential_id:"));
    }

    #[test]
    fn client_debug_does_not_leak_api_key_value() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("xyzzy-super-secret-key-99".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("xyzzy-super-secret-key-99"));
        assert!(dbg.contains("N8nClient"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn canonical_base_url_rejects_unsafe_components() {
        for value in [
            "https://user:pass@n8n.example.com/api/v1",
            "https://n8n.example.com/api/v1?token=secret",
            "https://n8n.example.com/api/v1#fragment",
            "https://n8n.example.com/admin",
            "https://192.0.2.1/api/v1",
            "http://n8n.example.com/api/v1",
        ] {
            assert!(
                N8nClient::canonicalize_base_url(value).is_err(),
                "unsafe base URL accepted: {value}"
            );
        }
    }

    #[test]
    fn canonical_base_url_allows_loopback_http_only_for_tests() {
        assert_eq!(
            N8nClient::canonicalize_base_url("http://127.0.0.1:5678/api/v1/").unwrap(),
            "http://127.0.0.1:5678/api/v1"
        );
        assert_eq!(
            N8nClient::canonicalize_base_url("https://n8n.example.com:443/api/v1").unwrap(),
            "https://n8n.example.com/api/v1"
        );
    }
}
