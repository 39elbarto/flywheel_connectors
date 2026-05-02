//! Twitch Helix API client.

use fcp_prelude::log_redaction::redact_url;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop, classify_http_status,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tracing::debug;

use crate::error::{TwitchError, TwitchResult};
use crate::types::*;

/// Twitch Helix API client with OAuth2 client credentials.
pub struct TwitchClient {
    client: Client,
    base_url: String,
    token_url: String,
    validate_url: String,
    client_id: String,
    client_secret: String,
    access_token: Option<String>,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for TwitchClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwitchClient")
            .field("base_url", &self.base_url)
            .field("token_url", &self.token_url)
            .field("validate_url", &self.validate_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("retry_config", &self.retry_config)
            .finish()
    }
}

impl TwitchClient {
    /// Create a new Twitch client.
    pub fn new(
        base_url: &str,
        token_url: &str,
        validate_url: &str,
        client_id: &str,
        client_secret: &str,
        retry_config: HttpRetryConfig,
    ) -> TwitchResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(TwitchError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            token_url: token_url.to_string(),
            validate_url: validate_url.to_string(),
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            access_token: None,
            retry_config,
        })
    }

    /// Acquire an OAuth2 token via client credentials grant.
    ///
    /// Twitch's token endpoint accepts parameters as query strings on POST.
    pub async fn acquire_token(&mut self) -> TwitchResult<()> {
        let resp = self
            .client
            .post(&self.token_url)
            .query(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("grant_type", "client_credentials"),
            ])
            .send()
            .await
            .map_err(TwitchError::Http)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(TwitchError::TokenError(format!(
                "token request failed ({status}): {text}"
            )));
        }

        let token: TokenResponse = resp.json().await.map_err(TwitchError::Http)?;
        self.access_token = Some(token.access_token);
        Ok(())
    }

    fn token(&self) -> TwitchResult<&str> {
        self.access_token.as_deref().ok_or_else(|| {
            TwitchError::Unauthorized("no access token; call acquire_token first".into())
        })
    }

    /// Validate the current OAuth token with Twitch's /validate endpoint.
    pub async fn validate_token(&self) -> TwitchResult<ValidatedToken> {
        let token = self.token()?;
        let resp = self
            .client
            .get(&self.validate_url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(TwitchError::Http)?;

        let status = resp.status().as_u16();
        if resp.status().is_success() {
            return resp
                .json::<ValidatedToken>()
                .await
                .map_err(TwitchError::Http);
        }
        if status == 401 {
            return Err(TwitchError::Unauthorized("Invalid access token".into()));
        }
        if status == 429 {
            return Err(TwitchError::RateLimited {
                retry_after_ms: 30_000,
            });
        }

        let text = resp.text().await.unwrap_or_default();
        Err(TwitchError::Api {
            status,
            message: text,
        })
    }

    /// Execute a GET request with retry.
    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        runtime: &ConnectorRuntime,
        path: &str,
        query: &[(String, String)],
    ) -> TwitchResult<HelixResponse<T>> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.token()?.to_string();
        let client_id = self.client_id.clone();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let query_owned: Vec<(String, String)> = query.to_vec();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            let client_id = client_id.clone();
            let query = query_owned.clone();
            async move {
                debug!(attempt, url = %redact_url(&url), "Twitch GET");
                let resp = match client
                    .get(&url)
                    .bearer_auth(&token)
                    .header("Client-Id", &client_id)
                    .query(&query)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: TwitchError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("ratelimit-reset")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: TwitchError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(TwitchError::Unauthorized(
                        "Invalid or expired access token".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = TwitchError::Api {
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

                match resp.json::<HelixResponse<T>>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(TwitchError::Http(e)),
                }
            }
        })
        .await
    }

    /// List live streams.
    pub async fn list_streams(
        &self,
        runtime: &ConnectorRuntime,
        game_id: Option<&str>,
        user_login: Option<&str>,
        first: Option<u32>,
    ) -> TwitchResult<HelixResponse<Stream>> {
        let mut query = Vec::new();
        if let Some(gid) = game_id {
            query.push(("game_id".into(), gid.into()));
        }
        if let Some(login) = user_login {
            query.push(("user_login".into(), login.into()));
        }
        if let Some(n) = first {
            query.push(("first".into(), n.to_string()));
        }
        self.get(runtime, "/helix/streams", &query).await
    }

    /// Get a specific stream by user login.
    pub async fn get_stream(
        &self,
        runtime: &ConnectorRuntime,
        user_login: &str,
    ) -> TwitchResult<HelixResponse<Stream>> {
        let query = vec![("user_login".into(), user_login.into())];
        self.get(runtime, "/helix/streams", &query).await
    }

    /// Get user info by login.
    pub async fn get_user(
        &self,
        runtime: &ConnectorRuntime,
        login: &str,
    ) -> TwitchResult<HelixResponse<User>> {
        let query = vec![("login".into(), login.into())];
        self.get(runtime, "/helix/users", &query).await
    }

    /// Get channel info.
    pub async fn get_channel(
        &self,
        runtime: &ConnectorRuntime,
        broadcaster_id: &str,
    ) -> TwitchResult<HelixResponse<Channel>> {
        let query = vec![("broadcaster_id".into(), broadcaster_id.into())];
        self.get(runtime, "/helix/channels", &query).await
    }

    /// Modify channel information.
    pub async fn modify_channel(
        &self,
        runtime: &ConnectorRuntime,
        broadcaster_id: &str,
        body: &ModifyChannelRequest,
    ) -> TwitchResult<()> {
        let url = format!("{}/helix/channels", self.base_url);
        let token = self.token()?.to_string();
        let client_id = self.client_id.clone();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = serde_json::to_value(body).map_err(TwitchError::Json)?;
        let bid = broadcaster_id.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            let client_id = client_id.clone();
            let body = body_clone.clone();
            let bid = bid.clone();
            async move {
                debug!(attempt, "Modifying Twitch channel");
                let resp = match client
                    .patch(&url)
                    .bearer_auth(&token)
                    .header("Client-Id", &client_id)
                    .query(&[("broadcaster_id", &bid)])
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: TwitchError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 204 {
                    return AttemptOutcome::Success(());
                }
                if status == 429 {
                    return AttemptOutcome::Retryable {
                        error: TwitchError::RateLimited {
                            retry_after_ms: 30_000,
                        },
                        retry_after: Some(Duration::from_secs(30)),
                    };
                }
                if status == 401 {
                    return AttemptOutcome::Terminal(TwitchError::Unauthorized(
                        "Invalid token".into(),
                    ));
                }
                let text = resp.text().await.unwrap_or_default();
                let decision = classify_http_status(status, None);
                let err = TwitchError::Api {
                    status,
                    message: text,
                };
                if !matches!(decision, RetryDecision::Terminal) {
                    AttemptOutcome::Retryable {
                        error: err,
                        retry_after: None,
                    }
                } else {
                    AttemptOutcome::Terminal(err)
                }
            }
        })
        .await
    }

    /// List clips for a broadcaster.
    pub async fn list_clips(
        &self,
        runtime: &ConnectorRuntime,
        broadcaster_id: &str,
        first: Option<u32>,
    ) -> TwitchResult<HelixResponse<Clip>> {
        let mut query = vec![("broadcaster_id".into(), broadcaster_id.into())];
        if let Some(n) = first {
            query.push(("first".into(), n.to_string()));
        }
        self.get(runtime, "/helix/clips", &query).await
    }

    /// Create a clip.
    pub async fn create_clip(
        &self,
        runtime: &ConnectorRuntime,
        broadcaster_id: &str,
    ) -> TwitchResult<HelixResponse<CreateClipResponse>> {
        let url = format!("{}/helix/clips", self.base_url);
        let token = self.token()?.to_string();
        let client_id = self.client_id.clone();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let bid = broadcaster_id.to_string();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            let client_id = client_id.clone();
            let bid = bid.clone();
            async move {
                debug!(attempt, "Creating Twitch clip");
                let resp = match client
                    .post(&url)
                    .bearer_auth(&token)
                    .header("Client-Id", &client_id)
                    .query(&[("broadcaster_id", &bid)])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: TwitchError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    return AttemptOutcome::Retryable {
                        error: TwitchError::RateLimited {
                            retry_after_ms: 30_000,
                        },
                        retry_after: Some(Duration::from_secs(30)),
                    };
                }
                if status == 401 {
                    return AttemptOutcome::Terminal(TwitchError::Unauthorized(
                        "Invalid token".into(),
                    ));
                }
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = TwitchError::Api {
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
                match resp.json::<HelixResponse<CreateClipResponse>>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(TwitchError::Http(e)),
                }
            }
        })
        .await
    }

    /// Send a chat message.
    pub async fn send_chat_message(
        &self,
        runtime: &ConnectorRuntime,
        broadcaster_id: &str,
        sender_id: &str,
        message: &str,
    ) -> TwitchResult<HelixResponse<SendChatMessageResponse>> {
        let url = format!("{}/helix/chat/messages", self.base_url);
        let token = self.token()?.to_string();
        let client_id = self.client_id.clone();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = json!({
            "broadcaster_id": broadcaster_id,
            "sender_id": sender_id,
            "message": message,
        });

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            let client_id = client_id.clone();
            let body = body.clone();
            async move {
                let resp = match client
                    .post(&url)
                    .bearer_auth(&token)
                    .header("Client-Id", &client_id)
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: TwitchError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    return AttemptOutcome::Retryable {
                        error: TwitchError::RateLimited {
                            retry_after_ms: 30_000,
                        },
                        retry_after: Some(Duration::from_secs(30)),
                    };
                }
                if status == 401 {
                    return AttemptOutcome::Terminal(TwitchError::Unauthorized(
                        "Invalid token".into(),
                    ));
                }
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    let decision = classify_http_status(status, None);
                    let err = TwitchError::Api {
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
                match resp.json::<HelixResponse<SendChatMessageResponse>>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(TwitchError::Http(e)),
                }
            }
        })
        .await
    }

    /// List games by name or ID.
    pub async fn list_games(
        &self,
        runtime: &ConnectorRuntime,
        name: Option<&str>,
        id: Option<&str>,
    ) -> TwitchResult<HelixResponse<Game>> {
        let mut query = Vec::new();
        if let Some(n) = name {
            query.push(("name".into(), n.into()));
        }
        if let Some(i) = id {
            query.push(("id".into(), i.into()));
        }
        self.get(runtime, "/helix/games", &query).await
    }

    /// Health check: validate the OAuth token and verify Helix reachability.
    pub async fn health_check(&self) -> TwitchResult<ValidatedToken> {
        let validation = self.validate_token().await?;
        let token = self.token()?;
        let resp = self
            .client
            .get(format!("{}/helix/users", self.base_url))
            .bearer_auth(token)
            .header("Client-Id", &self.client_id)
            .query(&[("login", "twitch")])
            .send()
            .await
            .map_err(TwitchError::Http)?;

        let status = resp.status().as_u16();
        if resp.status().is_success() {
            Ok(validation)
        } else if status == 429 {
            Err(TwitchError::RateLimited {
                retry_after_ms: 30_000,
            })
        } else if status == 401 {
            Err(TwitchError::Unauthorized("Invalid access token".into()))
        } else {
            Err(TwitchError::Api {
                status,
                message: format!("Health check failed with HTTP {status}"),
            })
        }
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if token is set.
    pub fn has_token(&self) -> bool {
        self.access_token.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn client_creation() {
        let client = TwitchClient::new(
            "https://api.twitch.tv",
            "https://id.twitch.tv/oauth2/token",
            "https://id.twitch.tv/oauth2/validate",
            "test_client_id",
            "test_client_secret",
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = TwitchClient::new(
            "https://api.twitch.tv/",
            "https://id.twitch.tv/oauth2/token",
            "https://id.twitch.tv/oauth2/validate",
            "id",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn debug_redacts_secrets() {
        let client = TwitchClient::new(
            "https://api.twitch.tv",
            "https://id.twitch.tv/oauth2/token",
            "https://id.twitch.tv/oauth2/validate",
            "my_client_id",
            "super_secret_value",
            HttpRetryConfig::default(),
        )
        .unwrap();
        let debug_output = format!("{client:?}");
        assert!(
            !debug_output.contains("super_secret_value"),
            "Debug must not contain raw client_secret"
        );
        assert!(debug_output.contains("[REDACTED]"));
    }

    #[test]
    fn no_token_initially() {
        let client = TwitchClient::new(
            "https://api.twitch.tv",
            "https://id.twitch.tv/oauth2/token",
            "https://id.twitch.tv/oauth2/validate",
            "id",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.has_token());
    }

    #[fcp_async_core::runtime::test]
    async fn acquire_token_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "test_token_value",
                "expires_in": 3600,
                "token_type": "bearer"
            })))
            .mount(&mock_server)
            .await;

        let mut client = TwitchClient::new(
            "https://api.twitch.tv",
            &format!("{}/oauth2/token", mock_server.uri()),
            &format!("{}/oauth2/validate", mock_server.uri()),
            "test_id",
            "test_secret",
            HttpRetryConfig::default(),
        )
        .unwrap();

        client.acquire_token().await.unwrap();
        assert!(client.has_token());
    }

    #[fcp_async_core::runtime::test]
    async fn acquire_token_failure() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/oauth2/token"))
            .respond_with(ResponseTemplate::new(400).set_body_string("invalid_client"))
            .mount(&mock_server)
            .await;

        let mut client = TwitchClient::new(
            "https://api.twitch.tv",
            &format!("{}/oauth2/token", mock_server.uri()),
            &format!("{}/oauth2/validate", mock_server.uri()),
            "bad_id",
            "bad_secret",
            HttpRetryConfig::default(),
        )
        .unwrap();

        let result = client.acquire_token().await;
        assert!(matches!(result, Err(TwitchError::TokenError(_))));
    }

    #[fcp_async_core::runtime::test]
    async fn validate_token_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "client_id": "cid",
                "scopes": [],
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;

        let mut client = TwitchClient::new(
            "https://api.twitch.tv",
            &format!("{}/oauth2/token", mock_server.uri()),
            &format!("{}/oauth2/validate", mock_server.uri()),
            "cid",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        client.access_token = Some("tok".into());

        let validated = client.validate_token().await.unwrap();
        assert_eq!(validated.client_id, "cid");
        assert_eq!(validated.expires_in, 3600);
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "client_id": "cid",
                "scopes": [],
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/helix/users"))
            .and(header("Client-Id", "cid"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "id": "1",
                    "login": "twitch",
                    "display_name": "Twitch",
                    "type": "",
                    "broadcaster_type": "",
                    "description": "",
                    "profile_image_url": "",
                    "offline_image_url": "",
                    "view_count": 0,
                    "created_at": "2020-01-01T00:00:00Z"
                }]
            })))
            .mount(&mock_server)
            .await;

        let mut client = TwitchClient::new(
            &mock_server.uri(),
            &format!("{}/oauth2/token", mock_server.uri()),
            &format!("{}/oauth2/validate", mock_server.uri()),
            "cid",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        client.access_token = Some("tok".into());
        let validated = client.health_check().await.unwrap();
        assert_eq!(validated.client_id, "cid");
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_401() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/oauth2/validate"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let mut client = TwitchClient::new(
            &mock_server.uri(),
            &format!("{}/oauth2/token", mock_server.uri()),
            &format!("{}/oauth2/validate", mock_server.uri()),
            "cid",
            "secret",
            HttpRetryConfig::default(),
        )
        .unwrap();
        client.access_token = Some("bad_tok".into());
        let result = client.health_check().await;
        assert!(matches!(result, Err(TwitchError::Unauthorized(_))));
    }
}
