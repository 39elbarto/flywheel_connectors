//! Feishu/Lark API client.

use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop, classify_http_status,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use serde::de::DeserializeOwned;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{FeishuError, FeishuResult};
use crate::types::{
    ApiResponse, CalendarEventsResponse, ChatInfo, ChatListResponse, DocumentContent,
    MessageResponse, ReplyMessageRequest, SendMessageRequest, SpreadsheetInfo,
    TenantAccessTokenResponse, UserInfo,
};

/// Feishu API client with retry and runtime integration.
pub struct FeishuClient {
    client: Client,
    base_url: String,
    app_id: String,
    app_secret: String,
    tenant_access_token: Option<String>,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for FeishuClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeishuClient")
            .field("base_url", &self.base_url)
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .field(
                "tenant_access_token",
                &self.tenant_access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl FeishuClient {
    /// Create a new Feishu client.
    pub fn new(
        base_url: &str,
        app_id: &str,
        app_secret: &str,
        retry_config: HttpRetryConfig,
    ) -> FeishuResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(FeishuError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            app_id: app_id.to_string(),
            app_secret: app_secret.to_string(),
            tenant_access_token: None,
            retry_config,
        })
    }

    /// Set the tenant access token (obtained via auth flow).
    pub fn set_tenant_access_token(&mut self, token: String) {
        self.tenant_access_token = Some(token);
    }

    /// Sanitize a path segment to prevent path traversal.
    fn sanitize_path_segment(segment: &str) -> FeishuResult<&str> {
        if segment.trim().is_empty()
            || segment.contains('/')
            || segment.contains('\\')
            || segment.contains("..")
            || segment.contains('\0')
        {
            return Err(FeishuError::InvalidInput(
                "Invalid path segment: contains forbidden characters".into(),
            ));
        }
        Ok(segment)
    }

    fn auth_header(&self) -> FeishuResult<String> {
        let token = self
            .tenant_access_token
            .as_ref()
            .ok_or_else(|| FeishuError::Unauthorized("No tenant access token".into()))?;
        Ok(format!("Bearer {token}"))
    }

    /// Obtain a tenant access token from Feishu.
    pub async fn obtain_tenant_access_token(&mut self) -> FeishuResult<String> {
        let url = format!(
            "{}/open-apis/auth/v3/tenant_access_token/internal",
            self.base_url
        );
        let body = serde_json::json!({
            "app_id": self.app_id,
            "app_secret": self.app_secret,
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(FeishuError::Http)?;

        let status = resp.status().as_u16();
        if !resp.status().is_success() {
            return Err(FeishuError::HttpStatus {
                status,
                message: format!("Token request failed with HTTP {status}"),
            });
        }

        let token_resp: TenantAccessTokenResponse =
            resp.json().await.map_err(FeishuError::Http)?;

        if token_resp.code != 0 {
            return Err(FeishuError::Api {
                code: token_resp.code,
                message: token_resp.msg,
            });
        }

        let token = token_resp
            .tenant_access_token
            .ok_or_else(|| FeishuError::Api {
                code: -1,
                message: "No token in response".into(),
            })?;

        self.tenant_access_token = Some(token.clone());
        Ok(token)
    }

    /// Send a message.
    pub async fn send_message(
        &self,
        runtime: &ConnectorRuntime,
        receive_id_type: &str,
        req: &SendMessageRequest,
    ) -> FeishuResult<MessageResponse> {
        let url = format!(
            "{}/open-apis/im/v1/messages?receive_id_type={}",
            self.base_url, receive_id_type
        );
        let body = serde_json::to_value(req).map_err(FeishuError::Json)?;
        self.post_api(runtime, &url, &body).await
    }

    /// Reply to a message.
    pub async fn reply_message(
        &self,
        runtime: &ConnectorRuntime,
        message_id: &str,
        req: &ReplyMessageRequest,
    ) -> FeishuResult<MessageResponse> {
        let message_id = Self::sanitize_path_segment(message_id)?;
        let url = format!(
            "{}/open-apis/im/v1/messages/{}/reply",
            self.base_url, message_id
        );
        let body = serde_json::to_value(req).map_err(FeishuError::Json)?;
        self.post_api(runtime, &url, &body).await
    }

    /// Get a message by ID.
    pub async fn get_message(
        &self,
        runtime: &ConnectorRuntime,
        message_id: &str,
    ) -> FeishuResult<MessageResponse> {
        let message_id = Self::sanitize_path_segment(message_id)?;
        let url = format!(
            "{}/open-apis/im/v1/messages/{}",
            self.base_url, message_id
        );
        self.get_api(runtime, &url).await
    }

    /// List chats.
    pub async fn list_chats(
        &self,
        runtime: &ConnectorRuntime,
        page_token: Option<&str>,
        page_size: Option<u32>,
    ) -> FeishuResult<ChatListResponse> {
        let mut url = format!("{}/open-apis/im/v1/chats", self.base_url);
        let mut params = Vec::new();
        if let Some(token) = page_token {
            params.push(format!("page_token={token}"));
        }
        if let Some(size) = page_size {
            params.push(format!("page_size={size}"));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        self.get_api(runtime, &url).await
    }

    /// Get chat details.
    pub async fn get_chat(
        &self,
        runtime: &ConnectorRuntime,
        chat_id: &str,
    ) -> FeishuResult<ChatInfo> {
        let chat_id = Self::sanitize_path_segment(chat_id)?;
        let url = format!("{}/open-apis/im/v1/chats/{}", self.base_url, chat_id);
        self.get_api(runtime, &url).await
    }

    /// Get user info.
    pub async fn get_user(
        &self,
        runtime: &ConnectorRuntime,
        user_id: &str,
        user_id_type: &str,
    ) -> FeishuResult<UserInfo> {
        let user_id = Self::sanitize_path_segment(user_id)?;
        let url = format!(
            "{}/open-apis/contact/v3/users/{}?user_id_type={}",
            self.base_url, user_id, user_id_type
        );
        self.get_api(runtime, &url).await
    }

    /// Get document content.
    pub async fn get_document(
        &self,
        runtime: &ConnectorRuntime,
        document_id: &str,
    ) -> FeishuResult<DocumentContent> {
        let document_id = Self::sanitize_path_segment(document_id)?;
        let url = format!(
            "{}/open-apis/docx/v1/documents/{}/raw_content",
            self.base_url, document_id
        );
        self.get_api(runtime, &url).await
    }

    /// Get spreadsheet info.
    pub async fn get_spreadsheet(
        &self,
        runtime: &ConnectorRuntime,
        spreadsheet_token: &str,
    ) -> FeishuResult<SpreadsheetInfo> {
        let spreadsheet_token = Self::sanitize_path_segment(spreadsheet_token)?;
        let url = format!(
            "{}/open-apis/sheets/v3/spreadsheets/{}",
            self.base_url, spreadsheet_token
        );
        self.get_api(runtime, &url).await
    }

    /// List calendar events.
    pub async fn list_calendar_events(
        &self,
        runtime: &ConnectorRuntime,
        calendar_id: &str,
        page_token: Option<&str>,
    ) -> FeishuResult<CalendarEventsResponse> {
        let calendar_id = Self::sanitize_path_segment(calendar_id)?;
        let mut url = format!(
            "{}/open-apis/calendar/v4/calendars/{}/events",
            self.base_url, calendar_id
        );
        if let Some(token) = page_token {
            url.push_str(&format!("?page_token={token}"));
        }
        self.get_api(runtime, &url).await
    }

    /// Health check: verify the Feishu API is reachable via token request.
    pub async fn health_check(&self) -> FeishuResult<()> {
        // Use the auth endpoint as health check (it's always available)
        let url = format!(
            "{}/open-apis/auth/v3/tenant_access_token/internal",
            self.base_url
        );
        let body = serde_json::json!({
            "app_id": self.app_id,
            "app_secret": self.app_secret,
        });
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(FeishuError::Http)?;

        let status = resp.status().as_u16();
        if resp.status().is_success() {
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(60)
                * 1000;
            Err(FeishuError::RateLimited { retry_after_ms })
        } else {
            Err(FeishuError::HttpStatus {
                status,
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if credentials are configured.
    pub fn has_credentials(&self) -> bool {
        !self.app_id.is_empty() && !self.app_secret.is_empty()
    }

    /// Generic POST with API response extraction and retry.
    async fn post_api<T: DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> FeishuResult<T> {
        let auth = self.auth_header()?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        let body_clone = body.clone();
        let client = self.client.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let auth = auth.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, "Feishu API POST");
                let request = client
                    .post(&url)
                    .header("Authorization", &auth)
                    .json(&body);

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: FeishuError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: FeishuError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(FeishuError::Unauthorized(
                        "Tenant access token invalid or expired".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Feishu API request failed");
                    let decision = classify_http_status(status, None);
                    let err = FeishuError::HttpStatus {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                let api_resp: ApiResponse<T> = match resp.json().await {
                    Ok(r) => r,
                    Err(e) => return AttemptOutcome::Terminal(FeishuError::Http(e)),
                };

                if api_resp.code != 0 {
                    let err = FeishuError::Api {
                        code: api_resp.code,
                        message: api_resp.msg,
                    };
                    if err.is_retryable() {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match api_resp.data {
                    Some(data) => AttemptOutcome::Success(data),
                    None => AttemptOutcome::Terminal(FeishuError::Api {
                        code: -1,
                        message: "No data in response".into(),
                    }),
                }
            }
        })
        .await
    }

    /// Generic GET with API response extraction and retry.
    async fn get_api<T: DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> FeishuResult<T> {
        let auth = self.auth_header()?;
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let url = url.to_string();
        let client = self.client.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = client.clone();
            let auth = auth.clone();
            async move {
                debug!(attempt, url = %url, "Feishu API GET");
                let request = client.get(&url).header("Authorization", &auth);

                let resp = match request.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: FeishuError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: FeishuError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(60))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(FeishuError::Unauthorized(
                        "Tenant access token invalid or expired".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "Feishu API request failed");
                    let decision = classify_http_status(status, None);
                    let err = FeishuError::HttpStatus {
                        status,
                        message: text,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                let api_resp: ApiResponse<T> = match resp.json().await {
                    Ok(r) => r,
                    Err(e) => return AttemptOutcome::Terminal(FeishuError::Http(e)),
                };

                if api_resp.code != 0 {
                    let err = FeishuError::Api {
                        code: api_resp.code,
                        message: api_resp.msg,
                    };
                    if err.is_retryable() {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match api_resp.data {
                    Some(data) => AttemptOutcome::Success(data),
                    None => AttemptOutcome::Terminal(FeishuError::Api {
                        code: -1,
                        message: "No data in response".into(),
                    }),
                }
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn client_creation() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = FeishuClient::new(
            "https://open.feishu.cn/",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn has_credentials() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.has_credentials());
    }

    #[test]
    fn missing_credentials() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "",
            "",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.has_credentials());
    }

    #[test]
    fn debug_redacts_secrets() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "super_secret_value",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("super_secret_value"),
            "Debug must not contain raw secret"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn sanitize_path_rejects_traversal() {
        assert!(FeishuClient::sanitize_path_segment("../etc").is_err());
        assert!(FeishuClient::sanitize_path_segment("foo/bar").is_err());
        assert!(FeishuClient::sanitize_path_segment("").is_err());
        assert!(FeishuClient::sanitize_path_segment("a\0b").is_err());
    }

    #[test]
    fn sanitize_path_accepts_valid() {
        assert!(FeishuClient::sanitize_path_segment("om_abc123").is_ok());
        assert!(FeishuClient::sanitize_path_segment("oc_def456").is_ok());
    }

    #[test]
    fn auth_header_without_token() {
        let client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.auth_header().is_err());
    }

    #[test]
    fn auth_header_with_token() {
        let mut client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        client.set_tenant_access_token("t-abc123".into());
        let header = client.auth_header().unwrap();
        assert_eq!(header, "Bearer t-abc123");
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/open-apis/auth/v3/tenant_access_token/internal",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "code": 0,
                    "msg": "ok",
                    "tenant_access_token": "t-test",
                    "expire": 7200
                })),
            )
            .mount(&mock_server)
            .await;

        let client = FeishuClient::new(
            &mock_server.uri(),
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.health_check().await.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn obtain_tenant_token() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/open-apis/auth/v3/tenant_access_token/internal",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "code": 0,
                    "msg": "ok",
                    "tenant_access_token": "t-obtained",
                    "expire": 7200
                })),
            )
            .mount(&mock_server)
            .await;

        let mut client = FeishuClient::new(
            &mock_server.uri(),
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let token = client.obtain_tenant_access_token().await.unwrap();
        assert_eq!(token, "t-obtained");
        assert!(client.auth_header().is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_server_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/open-apis/auth/v3/tenant_access_token/internal",
            ))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let client = FeishuClient::new(
            &mock_server.uri(),
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.health_check().await.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn debug_redacts_token_after_set() {
        let mut client = FeishuClient::new(
            "https://open.feishu.cn",
            "cli_test",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        client.set_tenant_access_token("t-super-secret-token".into());
        let debug_output = format!("{client:?}");
        assert!(!debug_output.contains("t-super-secret-token"));
    }
}
