//! Microsoft Teams HTTP client.
//!
//! Wraps Graph API and Bot Framework calls with retry logic.

use std::time::Duration;

use reqwest::Client;

use crate::error::{TeamsError, TeamsResult};
use crate::types::{
    Channel, Chat, ChatMember, ChatMessage, GraphCollection, Team, TokenResponse,
};

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

/// Teams API client.
#[derive(Debug)]
pub struct TeamsClient {
    client: Client,
    graph_base_url: String,
    access_token: String,
    is_secretless: bool,
}

impl TeamsClient {
    /// Create a client from an access token.
    ///
    /// # Errors
    /// Returns `TeamsError::Config` if the base URL is invalid.
    pub fn new(
        graph_base_url: &str,
        access_token: &str,
        timeout: Duration,
    ) -> TeamsResult<Self> {
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
            is_secretless: secretless,
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
        let http = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| TeamsError::Config(format!("Failed to build HTTP client: {e}")))?;

        let token_url = format!(
            "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        );
        let form_body = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
            urlencoded(client_id),
            urlencoded(client_secret),
            urlencoded("https://graph.microsoft.com/.default"),
        );
        let resp = http
            .post(&token_url)
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
        let coll: GraphCollection<Team> = self.graph_get(&url).await?;
        Ok(coll.value)
    }

    /// Get a team by ID.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn get_team(&self, team_id: &str) -> TeamsResult<Team> {
        let url = format!("{}/teams/{team_id}", self.graph_base_url);
        self.graph_get(&url).await
    }

    // ─── Graph API: Channels ────────────────────────────────────────────────

    /// List channels in a team.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn list_channels(&self, team_id: &str) -> TeamsResult<Vec<Channel>> {
        let url = format!("{}/teams/{team_id}/channels", self.graph_base_url);
        let coll: GraphCollection<Channel> = self.graph_get(&url).await?;
        Ok(coll.value)
    }

    /// Get a channel by ID.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn get_channel(
        &self,
        team_id: &str,
        channel_id: &str,
    ) -> TeamsResult<Channel> {
        let url = format!(
            "{}/teams/{team_id}/channels/{channel_id}",
            self.graph_base_url
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
            "{}/teams/{team_id}/channels/{channel_id}/messages",
            self.graph_base_url
        );
        let coll: GraphCollection<ChatMessage> = self.graph_get(&url).await?;
        Ok(coll.value)
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
            "{}/teams/{team_id}/channels/{channel_id}/messages",
            self.graph_base_url
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
        let coll: GraphCollection<Chat> = self.graph_get(&url).await?;
        Ok(coll.value)
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
        let url = format!("{}/chats/{chat_id}/messages", self.graph_base_url);
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
        let url = format!("{}/chats/{chat_id}/messages", self.graph_base_url);
        let coll: GraphCollection<ChatMessage> = self.graph_get(&url).await?;
        Ok(coll.value)
    }

    /// List members of a chat.
    ///
    /// # Errors
    /// Returns `TeamsError` on transport, auth, or API errors.
    pub async fn list_chat_members(&self, chat_id: &str) -> TeamsResult<Vec<ChatMember>> {
        let url = format!("{}/chats/{chat_id}/members", self.graph_base_url);
        let coll: GraphCollection<ChatMember> = self.graph_get(&url).await?;
        Ok(coll.value)
    }

    // ─── Health ─────────────────────────────────────────────────────────────

    /// Lightweight health check against Graph API.
    ///
    /// # Errors
    /// Returns `TeamsError` if the API returns a non-200/401 status.
    pub async fn health_check(&self) -> TeamsResult<()> {
        let url = format!("{}/me", self.graph_base_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(TeamsError::Http)?;

        let status = resp.status().as_u16();
        // 200=OK, 401=auth issue but reachable
        if status == 200 || status == 401 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(TeamsError::from_graph_response(status, &body))
        }
    }

    // ─── Internals ──────────────────────────────────────────────────────────

    async fn graph_get<T: serde::de::DeserializeOwned>(&self, url: &str) -> TeamsResult<T> {
        let resp = self
            .client
            .get(url)
            .bearer_auth(&self.access_token)
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
            .client
            .post(url)
            .bearer_auth(&self.access_token)
            .json(body)
            .send()
            .await
            .map_err(TeamsError::Http)?;

        self.handle_response(resp).await
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
        let client =
            TeamsClient::new("https://graph.microsoft.com/v1.0/", "tok", Duration::from_secs(30))
                .unwrap();
        assert_eq!(client.graph_base_url(), "https://graph.microsoft.com/v1.0");
    }

    #[test]
    fn new_client_secretless_detection() {
        let client =
            TeamsClient::new("https://graph.microsoft.com/v1.0", "", Duration::from_secs(30))
                .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn new_client_not_secretless() {
        let client =
            TeamsClient::new("https://graph.microsoft.com/v1.0", "tok", Duration::from_secs(30))
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
            .respond_with(wiremock::ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {
                    "code": "InvalidAuthenticationToken",
                    "message": "Access token has expired."
                }
            })))
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
            .respond_with(wiremock::ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": {
                    "code": "NotFound",
                    "message": "Team not found."
                }
            })))
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
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "user_1",
                "displayName": "Test"
            })))
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        assert!(client.health_check().await.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_401_still_ok() {
        let mock_server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/me"))
            .respond_with(wiremock::ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = TeamsClient::new(&mock_server.uri(), "tok", Duration::from_secs(10)).unwrap();
        // 401 means reachable but auth issue, still considered "reachable"
        assert!(client.health_check().await.is_ok());
    }
}
