use std::fmt;
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Client, RequestBuilder};
use serde_json::{Value, json};
use tracing::debug;

use crate::error::{VertexError, VertexResult, extract_retry_after, vertex_error_from_status};
use crate::types::{
    PreparedVertexRequest, VertexStreamResponse, default_base_url_for_location, model_catalog,
    parse_sse_events, prepare_vertex_request, validate_path_component, vertex_messages_path,
};

#[derive(Debug, Clone)]
pub struct VertexClientConfig {
    pub project_id: String,
    pub location: String,
    pub auth: GoogleMaterializedAuth,
    pub retry_config: HttpRetryConfig,
    pub request_timeout_ms: u64,
    pub base_url: Option<String>,
}

pub struct AnthropicVertexClient {
    http: Client,
    project_id: String,
    location: String,
    auth: GoogleMaterializedAuth,
    retry_config: HttpRetryConfig,
    base_url: String,
    uses_default_endpoint: bool,
}

impl fmt::Debug for AnthropicVertexClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnthropicVertexClient")
            .field("project_id", &self.project_id)
            .field("location", &self.location)
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .field("uses_default_endpoint", &self.uses_default_endpoint)
            .finish_non_exhaustive()
    }
}

impl AnthropicVertexClient {
    pub fn new(config: VertexClientConfig) -> VertexResult<Self> {
        if config.request_timeout_ms == 0 {
            return Err(VertexError::Config(
                "request_timeout_ms must be greater than 0".into(),
            ));
        }
        let http = Client::builder()
            .timeout(Duration::from_millis(config.request_timeout_ms))
            .build()
            .map_err(VertexError::Http)?;
        let default_base = default_base_url_for_location(&config.location);
        let base_url = config
            .base_url
            .clone()
            .unwrap_or_else(|| default_base.clone())
            .trim_end_matches('/')
            .to_string();
        Ok(Self {
            http,
            project_id: config.project_id,
            location: config.location,
            auth: config.auth,
            retry_config: config.retry_config,
            base_url,
            uses_default_endpoint: config.base_url.is_none(),
        })
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub fn location(&self) -> &str {
        &self.location
    }

    pub const fn uses_default_endpoint(&self) -> bool {
        self.uses_default_endpoint
    }

    pub fn readiness(&self) -> Value {
        json!({
            "project_id": self.project_id,
            "location": self.location,
            "base_url": self.base_url,
            "uses_default_endpoint": self.uses_default_endpoint,
            "model_catalog_size": model_catalog().len(),
        })
    }

    pub async fn message(&self, runtime: &ConnectorRuntime, input: &Value) -> VertexResult<Value> {
        let prepared = prepare_vertex_request(input, false)?;
        self.post_prepared_json(runtime, prepared, "messages.create")
            .await
    }

    pub async fn message_stream(
        &self,
        runtime: &ConnectorRuntime,
        input: &Value,
    ) -> VertexResult<VertexStreamResponse> {
        let prepared = prepare_vertex_request(input, true)?;
        self.post_prepared_stream(runtime, prepared).await
    }

    fn endpoint_url(&self, model: &str, stream: bool) -> VertexResult<String> {
        let project_id = validate_path_component(&self.project_id, "project_id")?;
        let location = validate_path_component(&self.location, "location")?;
        let model = validate_path_component(model, "model")?;
        let path = vertex_messages_path(&project_id, &location, &model, stream);
        Ok(format!("{}{}", self.base_url, path))
    }

    async fn post_prepared_json(
        &self,
        runtime: &ConnectorRuntime,
        prepared: PreparedVertexRequest,
        op: &'static str,
    ) -> VertexResult<Value> {
        let url = self.endpoint_url(&prepared.model, false)?;
        let body = prepared.body;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let client = self.http.clone();
            let url = url.clone();
            let auth = self.auth.clone();
            let body = body.clone();
            async move {
                debug!(attempt, op, "Claude on Vertex JSON request");
                let request = client
                    .post(&url)
                    .header("accept", "application/json")
                    .header("content-type", "application/json")
                    .json(&body);
                let request = match apply_google_auth(request, &auth) {
                    Ok(request) => request,
                    Err(error) => return AttemptOutcome::Terminal(error),
                };
                match request.send().await {
                    Ok(response) => match handle_json_response(response).await {
                        Ok(value) => AttemptOutcome::Success(value),
                        Err(error) if error.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: error.retry_after(),
                            error,
                        },
                        Err(error) => AttemptOutcome::Terminal(error),
                    },
                    Err(error) if error.is_timeout() || error.is_connect() => {
                        AttemptOutcome::Retryable {
                            retry_after: None,
                            error: VertexError::Http(error),
                        }
                    }
                    Err(error) => AttemptOutcome::Terminal(VertexError::Http(error)),
                }
            }
        })
        .await
    }

    async fn post_prepared_stream(
        &self,
        runtime: &ConnectorRuntime,
        prepared: PreparedVertexRequest,
    ) -> VertexResult<VertexStreamResponse> {
        let url = self.endpoint_url(&prepared.model, true)?;
        let body = prepared.body;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let client = self.http.clone();
            let url = url.clone();
            let auth = self.auth.clone();
            let body = body.clone();
            async move {
                debug!(
                    attempt,
                    op = "messages.stream",
                    "Claude on Vertex stream request"
                );
                let request = client
                    .post(&url)
                    .header("accept", "text/event-stream")
                    .header("content-type", "application/json")
                    .json(&body);
                let request = match apply_google_auth(request, &auth) {
                    Ok(request) => request,
                    Err(error) => return AttemptOutcome::Terminal(error),
                };
                match request.send().await {
                    Ok(response) => match handle_sse_response(response).await {
                        Ok(value) => AttemptOutcome::Success(value),
                        Err(error) if error.is_retryable() => AttemptOutcome::Retryable {
                            retry_after: error.retry_after(),
                            error,
                        },
                        Err(error) => AttemptOutcome::Terminal(error),
                    },
                    Err(error) if error.is_timeout() || error.is_connect() => {
                        AttemptOutcome::Retryable {
                            retry_after: None,
                            error: VertexError::Http(error),
                        }
                    }
                    Err(error) => AttemptOutcome::Terminal(VertexError::Http(error)),
                }
            }
        })
        .await
    }
}

fn apply_google_auth(
    request: RequestBuilder,
    auth: &GoogleMaterializedAuth,
) -> VertexResult<RequestBuilder> {
    let mut auth_headers = Vec::new();
    auth.apply_headers(&mut auth_headers);
    let mut header_map = HeaderMap::new();
    for (name, value) in auth_headers {
        let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            VertexError::Config(format!("invalid auth header name `{name}`: {error}"))
        })?;
        let header_value = HeaderValue::from_str(&value).map_err(|error| {
            VertexError::Config(format!("invalid auth header value for `{name}`: {error}"))
        })?;
        header_map.insert(header_name, header_value);
    }
    Ok(request.headers(header_map))
}

async fn handle_json_response(response: reqwest::Response) -> VertexResult<Value> {
    let status = response.status();
    let retry_after = extract_retry_after(&response);
    let bytes = response.bytes().await?;
    if status.is_success() {
        serde_json::from_slice(&bytes).map_err(VertexError::Json)
    } else {
        Err(vertex_error_from_status(status, &bytes, retry_after))
    }
}

async fn handle_sse_response(response: reqwest::Response) -> VertexResult<VertexStreamResponse> {
    let status = response.status();
    let retry_after = extract_retry_after(&response);
    let bytes = response.bytes().await?;
    if status.is_success() {
        let body = String::from_utf8_lossy(&bytes);
        Ok(parse_sse_events(&body))
    } else {
        Err(vertex_error_from_status(status, &bytes, retry_after))
    }
}

#[cfg(test)]
mod tests {
    use fcp_google_discovery::auth::{GoogleAuthSourceKind, GoogleMaterializedAuth};
    use fcp_prelude::CredentialId;

    use super::{AnthropicVertexClient, HttpRetryConfig, VertexClientConfig};

    #[test]
    fn client_readiness_reports_default_endpoint() {
        let client = AnthropicVertexClient::new(VertexClientConfig {
            project_id: "fcp-test".to_string(),
            location: "global".to_string(),
            auth: GoogleMaterializedAuth::BearerToken {
                access_token: "test".to_string(),
                source: GoogleAuthSourceKind::AccessToken,
                granted_scopes: Vec::new(),
                quota_project_id: None,
            },
            retry_config: HttpRetryConfig::default(),
            request_timeout_ms: 1_000,
            base_url: None,
        })
        .expect("client");
        assert!(client.uses_default_endpoint());
        assert_eq!(
            client.readiness()["base_url"].as_str(),
            Some("https://aiplatform.googleapis.com")
        );
    }

    #[test]
    fn client_accepts_credential_reference_auth() {
        let credential_id = CredentialId::new();
        let client = AnthropicVertexClient::new(VertexClientConfig {
            project_id: "fcp-test".to_string(),
            location: "us-east5".to_string(),
            auth: GoogleMaterializedAuth::CredentialReference {
                credential_id,
                quota_project_id: Some("billing-project".to_string()),
            },
            retry_config: HttpRetryConfig::default(),
            request_timeout_ms: 1_000,
            base_url: Some("http://127.0.0.1:1".to_string()),
        })
        .expect("client");
        assert!(!client.uses_default_endpoint());
        assert_eq!(client.location(), "us-east5");
    }
}
