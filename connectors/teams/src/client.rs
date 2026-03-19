//! Microsoft Teams HTTP client.
//!
//! Wraps Graph API and Bot Framework calls with retry logic.

use std::time::Duration;

use reqwest::header::HeaderValue;
use reqwest::{Client, RequestBuilder};

use crate::error::{TeamsError, TeamsResult};
use crate::types::{Channel, Chat, ChatMember, ChatMessage, GraphCollection, Team, TokenResponse};

const CREDENTIAL_ID_HEADER: &str = "x-fcp-credential-id";

/// Minimal URL encoding for form body values.
fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Percent-encode a user-supplied value for safe inclusion in a URL path segment.
///
/// This prevents path traversal attacks (e.g. `../../../admin`) by encoding `/`, `..`,
/// and all characters that are not unreserved per RFC 3986.
fn encode_path_segment(s: &str) -> String {
    use std::fmt::Write;
    let mut encoded = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

/// Validate that a tenant ID looks like a GUID/UUID before interpolating into a URL.
///
/// Accepts formats: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (with or without hyphens).
/// Rejects anything that could be used for path traversal.
fn validate_tenant_id(tenant_id: &str) -> Result<(), crate::error::TeamsError> {
    // Strip hyphens and check that it's 32 hex characters
    let stripped: String = tenant_id.chars().filter(|c| *c != '-').collect();
    if stripped.len() == 32 && stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(crate::error::TeamsError::Config(format!(
            "Invalid tenant_id: expected a UUID/GUID, got {tenant_id:?}"
        )))
    }
}

/// Teams API client.
pub struct TeamsClient {
    client: Client,
    graph_base_url: String,
    access_token: String,
    credential_id: Option<String>,
    is_secretless: bool,
}

impl std::fmt::Debug for TeamsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeamsClient")
            .field("client", &self.client)
            .field("graph_base_url", &self.graph_base_url)
            .field("access_token", &"[REDACTED]")
            .field("credential_id", &self.credential_id)
            .field("is_secretless", &self.is_secretless)
            .finish()
    }
}

impl TeamsClient {
    /// Create a client from an access token.
    ///
    /// # Errors
    /// Returns `TeamsError::Config` if the base URL is invalid.
    pub fn new(graph_base_url: &str, access_token: &str, timeout: Duration) -> TeamsResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| TeamsError::Config(format!("Failed to build HTTP client: {e}")))?;

        let base = graph_base_url.trim_end_matches('/').to_string();
        let secretless = access_token.is_empty();

        Ok(Self {
            client,
            graph_base_url: base,
            access_token: access_token.to_string(),
            credential_id: None,
            is_secretless: secretless,
        })
    }

    /// Create a client for secretless credential injection.
    ///
    /// # Errors
    /// Returns `TeamsError::Config` if the credential header is invalid or the client cannot
    /// be built.
    pub fn new_secretless(
        graph_base_url: &str,
        credential_id: &str,
        timeout: Duration,
    ) -> TeamsResult<Self> {
        HeaderValue::from_str(credential_id)
            .map_err(|e| TeamsError::Config(format!("Invalid credential_id header: {e}")))?;

        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| TeamsError::Config(format!("Failed to build HTTP client: {e}")))?;

        let base = graph_base_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            graph_base_url: base,
            access_token: String::new(),
            credential_id: Some(credential_id.to_string()),
            is_secretless: true,
        })
    }

    /// Create from client credentials flow.
    ///
    /// # Errors
    /// Returns `TeamsError::TokenError` if token acquisition fails.
    pub async fn from_client_credentials(
        graph_base_url: &str,
        client_id: &str,
        client_secret: &str,
        tenant_id: &str,
        timeout: Duration,
    ) -> TeamsResult<Self> {
        validate_tenant_id(tenant_id)?;
        let token_url = format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token");
        Self::from_client_credentials_with_token_url(
            graph_base_url,
            &token_url,
            client_id,
            client_secret,
            timeout,
        )
        .await
    }

    async fn from_client_credentials_with_token_url(
        graph_base_url: &str,
        token_url: &str,
        client_id: &str,
        client_secret: &str,
        timeout: Duration,
    ) -> TeamsResult<Self> {
        let http = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| TeamsError::Config(format!("Failed to build HTTP client: {e}")))?;

        let form_body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
            urlencoded(client_id),
            urlencoded(client_secret),
            urlencoded("https://graph.microsoft.com/.default"),
        );
        let resp = http
            .post(token_url)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .map_err(|e| TeamsError::TokenError(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(TeamsError::TokenError(format!(
                "Token request failed ({status}): {body}"
            )));
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .map_err(|e| TeamsError::TokenError(format!("Failed to parse token: {e}")))?;

        let base = graph_base_url.trim_end_matches('/').to_string();
        Ok(Self {
            client: http,
            graph_base_url: base,
            access_token: token_resp.access_token,
            credential_id: None,
            is_secretless: false,
        })
    }

    /// Whether the client is running in secretless mode.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        self.is_secretless
    }

    /// Get the Graph API base URL.
    #[must_use]
    pub fn graph_base_url(&self) -> &str {
        &self.graph_base_url
    }

    // ─── Graph API: Teams ───────────────────────────────────────────────────

    /// List teams the authenticated user is a member of.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn list_my_teams(&self) -> TeamsResult<Vec<Team>> {
        let url = format!("{}/me/joinedTeams", self.graph_base_url);
        self.graph_get_collection(&url).await
    }

    /// Get a team by ID.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn get_team(&self, team_id: &str) -> TeamsResult<Team> {
        let url = format!(
            "{}/teams/{}",
            self.graph_base_url,
            encode_path_segment(team_id)
        );
        self.graph_get(&url).await
    }

    // ─── Graph API: Channels ────────────────────────────────────────────────

    /// List channels in a team.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn list_channels(&self, team_id: &str) -> TeamsResult<Vec<Channel>> {
        let url = format!(
            "{}/teams/{}/channels",
            self.graph_base_url,
            encode_path_segment(team_id)
        );
        self.graph_get_collection(&url).await
    }

    /// Get a channel by ID.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn get_channel(&self, team_id: &str, channel_id: &str) -> TeamsResult<Channel> {
        let url = format!(
            "{}/teams/{}/channels/{}",
            self.graph_base_url,
            encode_path_segment(team_id),
            encode_path_segment(channel_id)
        );
        self.graph_get(&url).await
    }

    // ─── Graph API: Messages ────────────────────────────────────────────────

    /// List messages in a channel.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn list_channel_messages(
        &self,
        team_id: &str,
        channel_id: &str,
    ) -> TeamsResult<Vec<ChatMessage>> {
        let url = format!(
            "{}/teams/{}/channels/{}/messages",
            self.graph_base_url,
            encode_path_segment(team_id),
            encode_path_segment(channel_id)
        );
        self.graph_get_collection(&url).await
    }

    /// Send a message to a channel.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn send_channel_message(
        &self,
        team_id: &str,
        channel_id: &str,
        content: &str,
        content_type: &str,
    ) -> TeamsResult<ChatMessage> {
        let url = format!(
            "{}/teams/{}/channels/{}/messages",
            self.graph_base_url,
            encode_path_segment(team_id),
            encode_path_segment(channel_id)
        );
        let body = serde_json::json!({
            "body": {
                "contentType": content_type,
                "content": content
            }
        });
        self.graph_post(&url, &body).await
    }

    // ─── Graph API: Chats ───────────────────────────────────────────────────

    /// List the authenticated user's chats.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn list_my_chats(&self) -> TeamsResult<Vec<Chat>> {
        let url = format!("{}/me/chats", self.graph_base_url);
        self.graph_get_collection(&url).await
    }

    /// Send a message to a chat.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn send_chat_message(
        &self,
        chat_id: &str,
        content: &str,
        content_type: &str,
    ) -> TeamsResult<ChatMessage> {
        let url = format!(
            "{}/chats/{}/messages",
            self.graph_base_url,
            encode_path_segment(chat_id)
        );
        let body = serde_json::json!({
            "body": {
                "contentType": content_type,
                "content": content
            }
        });
        self.graph_post(&url, &body).await
    }

    /// List messages in a chat.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn list_chat_messages(&self, chat_id: &str) -> TeamsResult<Vec<ChatMessage>> {
        let url = format!(
            "{}/chats/{}/messages",
            self.graph_base_url,
            encode_path_segment(chat_id)
        );
        self.graph_get_collection(&url).await
    }

    /// List members of a chat.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn list_chat_members(&self, chat_id: &str) -> TeamsResult<Vec<ChatMember>> {
        let url = format!(
            "{}/chats/{}/members",
            self.graph_base_url,
            encode_path_segment(chat_id)
        );
        self.graph_get_collection(&url).await
    }

    // ─── Health ─────────────────────────────────────────────────────────────

    /// Lightweight health check against Graph API.
    ///
    /// # Errors
    /// Returns `TeamsError` if the API returns an unsuccessful status.
    pub async fn health_check(&self) -> TeamsResult<()> {
        let url = format!("{}/me", self.graph_base_url);
        let resp = self
            .authorize(self.client.get(&url))
            .send()
            .await
            .map_err(TeamsError::Http)?;

        let status = resp.status().as_u16();
        if status == 200 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(TeamsError::from_graph_response(status, &body))
        }
    }

    // ─── Internals ──────────────────────────────────────────────────────────

    async fn graph_get<T: serde::de::DeserializeOwned>(&self, url: &str) -> TeamsResult<T> {
        let resp = self
            .authorize(self.client.get(url))
            .send()
            .await
            .map_err(TeamsError::Http)?;

        self.handle_response(resp).await
    }

    async fn graph_post<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> TeamsResult<T> {
        let resp = self
            .authorize(self.client.post(url))
            .json(body)
            .send()
            .await
            .map_err(TeamsError::Http)?;

        self.handle_response(resp).await
    }

    async fn graph_get_collection<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> TeamsResult<Vec<T>> {
        let mut next_url = Some(url.to_string());
        let mut items = Vec::new();

        while let Some(current_url) = next_url.take() {
            let page: GraphCollection<T> = self.graph_get(&current_url).await?;
            items.extend(page.value);
            next_url = page.next_link;
        }

        Ok(items)
    }

    fn authorize(&self, request: RequestBuilder) -> RequestBuilder {
        if let Some(credential_id) = &self.credential_id {
            request.header(CREDENTIAL_ID_HEADER, credential_id)
        } else if self.access_token.is_empty() {
            request
        } else {
            request.bearer_auth(&self.access_token)
        }
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> TeamsResult<T> {
        let status = resp.status().as_u16();

        if status == 429 {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map_or(30_000, |s| s * 1000);
            return Err(TeamsError::RateLimited {
                retry_after_ms: retry_after,
            });
        }

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(TeamsError::from_graph_response(status, &body));
        }

        resp.json().await.map_err(TeamsError::Http)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_client_trims_trailing_slash() {
        let client = TeamsClient::new(
            "https://graph.microsoft.com/v1.0/",
            "tok",
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(client.graph_base_url(), "https://graph.microsoft.com/v1.0");
    }

    #[test]
    fn new_client_secretless_detection() {
        let client = TeamsClient::new(
            "https://graph.microsoft.com/v1.0",
            "",
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn new_secretless_client_uses_credential_id() {
        let client = TeamsClient::new_secretless(
            "https://graph.microsoft.com/v1.0",
            "cred_1",
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn new_client_not_secretless() {
        let client = TeamsClient::new(
            "https://graph.microsoft.com/v1.0",
            "tok",
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!client.is_secretless());
    }

    #[fcp_async_core::runtime::test]
    async fn list_my_teams_parses_response() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me/joinedTeams"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [
                        { "id": "t1", "displayName": "Team A" },
                        { "id": "t2", "displayName": "Team B" }
                    ]
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let teams = client.list_my_teams().await.unwrap();
        assert_eq!(teams.len(), 2);
        assert_eq!(teams[0].display_name, "Team A");
    }

    #[fcp_async_core::runtime::test]
    async fn list_my_teams_follows_odata_pagination() {
        let mock_server = wiremock::MockServer::start().await;
        let page_2 = format!("{}/page-2", mock_server.uri());

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me/joinedTeams"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [{ "id": "t1", "displayName": "Team A" }],
                    "@odata.nextLink": page_2,
                })),
            )
            .mount(&mock_server)
            .await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/page-2"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [{ "id": "t2", "displayName": "Team B" }],
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let teams = client.list_my_teams().await.unwrap();
        assert_eq!(teams.len(), 2);
        assert_eq!(teams[1].display_name, "Team B");
    }

    #[fcp_async_core::runtime::test]
    async fn secretless_client_sends_credential_header() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me/joinedTeams"))
            .and(wiremock::matchers::header(CREDENTIAL_ID_HEADER, "cred_1"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": []
                })),
            )
            .mount(&mock_server)
            .await;

        let client =
            TeamsClient::new_secretless(&mock_server.uri(), "cred_1", Duration::from_secs(10))
                .unwrap();
        let teams = client.list_my_teams().await.unwrap();
        assert!(teams.is_empty());

        let requests = mock_server.received_requests().await.unwrap_or_default();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].headers.get("authorization").is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn client_credentials_flow_materializes_access_token() {
        let mock_server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/oauth2/v2.0/token"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "graph_tok",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                })),
            )
            .mount(&mock_server)
            .await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me/joinedTeams"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer graph_tok",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [{ "id": "t1", "displayName": "Team A" }]
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::from_client_credentials_with_token_url(
            &mock_server.uri(),
            &format!("{}/oauth2/v2.0/token", mock_server.uri()),
            "client_id",
            "client_secret",
            Duration::from_secs(10),
        )
        .await
        .unwrap();

        assert!(!client.is_secretless());
        let teams = client.list_my_teams().await.unwrap();
        assert_eq!(teams.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn get_team_parses_response() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/teams/t1"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "t1",
                    "displayName": "Engineering"
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let team = client.get_team("t1").await.unwrap();
        assert_eq!(team.id, "t1");
    }

    #[fcp_async_core::runtime::test]
    async fn list_channels_parses_response() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/teams/t1/channels"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [
                        { "id": "ch1", "displayName": "General" }
                    ]
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let channels = client.list_channels("t1").await.unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].display_name, "General");
    }

    #[fcp_async_core::runtime::test]
    async fn send_channel_message_returns_message() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/teams/t1/channels/ch1/messages"))
            .respond_with(
                wiremock::ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "msg_1",
                    "body": { "contentType": "text", "content": "Hello" }
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let msg = client
            .send_channel_message("t1", "ch1", "Hello", "text")
            .await
            .unwrap();
        assert_eq!(msg.id, Some("msg_1".into()));
    }

    #[fcp_async_core::runtime::test]
    async fn send_chat_message_returns_message() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/chats/chat_1/messages"))
            .respond_with(
                wiremock::ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "msg_2",
                    "body": { "contentType": "html", "content": "<p>Hi</p>" }
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let msg = client
            .send_chat_message("chat_1", "<p>Hi</p>", "html")
            .await
            .unwrap();
        assert_eq!(msg.id, Some("msg_2".into()));
    }

    #[fcp_async_core::runtime::test]
    async fn handles_401_as_unauthorized() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me/joinedTeams"))
            .respond_with(
                wiremock::ResponseTemplate::new(401).set_body_json(serde_json::json!({
                    "error": {
                        "code": "InvalidAuthenticationToken",
                        "message": "Access token has expired."
                    }
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let result: TeamsResult<Vec<Team>> = client.list_my_teams().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TeamsError::Unauthorized(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn handles_429_as_rate_limited() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me/joinedTeams"))
            .respond_with(
                wiremock::ResponseTemplate::new(429)
                    .insert_header("retry-after", "60")
                    .set_body_string("rate limited"),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let result: TeamsResult<Vec<Team>> = client.list_my_teams().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            TeamsError::RateLimited { retry_after_ms } => {
                assert_eq!(retry_after_ms, 60_000);
            }
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn handles_404_as_not_found() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/teams/nonexistent"))
            .respond_with(
                wiremock::ResponseTemplate::new(404).set_body_json(serde_json::json!({
                    "error": {
                        "code": "NotFound",
                        "message": "Team not found."
                    }
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let result = client.get_team("nonexistent").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TeamsError::NotFound(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_200_ok() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "user_1",
                    "displayName": "Test"
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        assert!(client.health_check().await.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_401_is_unauthorized() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let err = client.health_check().await.unwrap_err();
        assert!(matches!(err, TeamsError::Unauthorized(_)));
    }

    // ─── Security: path encoding tests ─────────────────────────────────

    #[test]
    fn encode_path_segment_leaves_safe_chars_unchanged() {
        assert_eq!(encode_path_segment("abc-123_XYZ.~"), "abc-123_XYZ.~");
    }

    #[test]
    fn encode_path_segment_encodes_slashes() {
        assert_eq!(
            encode_path_segment("../../../admin"),
            "..%2F..%2F..%2Fadmin"
        );
    }

    #[test]
    fn encode_path_segment_encodes_special_characters() {
        assert_eq!(encode_path_segment("a/b?c#d e"), "a%2Fb%3Fc%23d%20e");
    }

    #[test]
    fn encode_path_segment_encodes_colons_and_at() {
        assert_eq!(encode_path_segment("user@host:8080"), "user%40host%3A8080");
    }

    #[test]
    fn encode_path_segment_handles_empty_string() {
        assert_eq!(encode_path_segment(""), "");
    }

    #[test]
    fn encode_path_segment_handles_percent_sign() {
        // Percent itself must be encoded to prevent double-encoding attacks
        assert_eq!(encode_path_segment("%2F"), "%252F");
    }

    // ─── Security: tenant_id validation tests ──────────────────────────

    #[test]
    fn validate_tenant_id_accepts_valid_uuid() {
        assert!(validate_tenant_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    }

    #[test]
    fn validate_tenant_id_accepts_uuid_without_hyphens() {
        assert!(validate_tenant_id("550e8400e29b41d4a716446655440000").is_ok());
    }

    #[test]
    fn validate_tenant_id_rejects_path_traversal() {
        let result = validate_tenant_id("../../../evil");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TeamsError::Config(_)));
    }

    #[test]
    fn validate_tenant_id_rejects_empty() {
        assert!(validate_tenant_id("").is_err());
    }

    #[test]
    fn validate_tenant_id_rejects_too_short() {
        assert!(validate_tenant_id("abc123").is_err());
    }

    #[test]
    fn validate_tenant_id_rejects_non_hex() {
        assert!(validate_tenant_id("550e8400-e29b-41d4-a716-44665544zzzz").is_err());
    }

    // ─── Security: path traversal prevention in API methods ────────────

    #[fcp_async_core::runtime::test]
    async fn get_team_encodes_traversal_in_team_id() {
        let mock_server = wiremock::MockServer::start().await;

        // The encoded path should be requested, NOT the raw traversal
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/teams/..%2F..%2Fadmin"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "safe",
                    "displayName": "Safe"
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let team = client.get_team("../../admin").await.unwrap();
        assert_eq!(team.id, "safe");
    }

    #[fcp_async_core::runtime::test]
    async fn send_chat_message_encodes_traversal_in_chat_id() {
        let mock_server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/chats/..%2F..%2Fsecret/messages"))
            .respond_with(
                wiremock::ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": "msg_safe",
                    "body": { "contentType": "text", "content": "test" }
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let msg = client
            .send_chat_message("../../secret", "test", "text")
            .await
            .unwrap();
        assert_eq!(msg.id, Some("msg_safe".into()));
    }

    #[fcp_async_core::runtime::test]
    async fn list_channel_messages_encodes_both_ids() {
        let mock_server = wiremock::MockServer::start().await;

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/teams/t%2F1/channels/c%2F2/messages",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": []
                })),
            )
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        let msgs = client.list_channel_messages("t/1", "c/2").await.unwrap();
        assert!(msgs.is_empty());
    }
}
