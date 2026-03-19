//! Matrix Client-Server API client.

use std::time::Duration;

use reqwest::Client;

use crate::error::{MatrixError, MatrixResult};
use crate::types::{
    CreateRoomRequest, CreateRoomResponse, JoinedRoomsResponse, MessagesResponse,
    SendEventResponse, SyncResponse, WhoAmIResponse,
};

/// Matrix API client.
#[derive(Debug)]
pub struct MatrixClient {
    client: Client,
    homeserver_url: String,
    access_token: String,
    is_secretless: bool,
}

impl MatrixClient {
    /// Create a new Matrix client.
    ///
    /// # Errors
    /// Returns `MatrixError::Config` if the HTTP client cannot be built.
    pub fn new(homeserver_url: &str, access_token: &str, timeout: Duration) -> MatrixResult<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| MatrixError::Config(format!("Failed to build HTTP client: {e}")))?;

        let base = homeserver_url.trim_end_matches('/').to_string();
        let secretless = access_token.is_empty();

        Ok(Self {
            client,
            homeserver_url: base,
            access_token: access_token.to_string(),
            is_secretless: secretless,
        })
    }

    /// Whether running in secretless mode.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        self.is_secretless
    }

    /// Get the homeserver URL.
    #[must_use]
    pub fn homeserver_url(&self) -> &str {
        &self.homeserver_url
    }

    // ─── Identity ───────────────────────────────────────────────────────────

    /// Get the authenticated user's identity.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or auth errors.
    pub async fn whoami(&self) -> MatrixResult<WhoAmIResponse> {
        let url = format!("{}/_matrix/client/v3/account/whoami", self.homeserver_url);
        self.api_get(&url).await
    }

    // ─── Rooms ──────────────────────────────────────────────────────────────

    /// List joined rooms.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn joined_rooms(&self) -> MatrixResult<Vec<String>> {
        let url = format!("{}/_matrix/client/v3/joined_rooms", self.homeserver_url);
        let resp: JoinedRoomsResponse = self.api_get(&url).await?;
        Ok(resp.joined_rooms)
    }

    /// Create a room.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn create_room(&self, req: &CreateRoomRequest) -> MatrixResult<CreateRoomResponse> {
        let url = format!("{}/_matrix/client/v3/createRoom", self.homeserver_url);
        self.api_post(&url, &serde_json::to_value(req).map_err(MatrixError::Json)?)
            .await
    }

    /// Join a room by ID or alias.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn join_room(&self, room_id_or_alias: &str) -> MatrixResult<serde_json::Value> {
        let encoded = urlencoded(room_id_or_alias);
        let url = format!("{}/_matrix/client/v3/join/{encoded}", self.homeserver_url);
        self.api_post(&url, &serde_json::json!({})).await
    }

    /// Leave a room.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn leave_room(&self, room_id: &str) -> MatrixResult<serde_json::Value> {
        let encoded = urlencoded(room_id);
        let url = format!(
            "{}/_matrix/client/v3/rooms/{encoded}/leave",
            self.homeserver_url
        );
        self.api_post(&url, &serde_json::json!({})).await
    }

    // ─── Messages ───────────────────────────────────────────────────────────

    /// Send a text message to a room.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn send_message(
        &self,
        room_id: &str,
        body: &str,
        msgtype: &str,
    ) -> MatrixResult<SendEventResponse> {
        let encoded = urlencoded(room_id);
        let txn_id = uuid::Uuid::new_v4();
        let url = format!(
            "{}/_matrix/client/v3/rooms/{encoded}/send/m.room.message/{txn_id}",
            self.homeserver_url
        );
        let content = serde_json::json!({
            "msgtype": msgtype,
            "body": body,
        });
        self.api_put(&url, &content).await
    }

    /// Get messages from a room (paginated).
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn get_messages(
        &self,
        room_id: &str,
        from: Option<&str>,
        limit: u32,
    ) -> MatrixResult<MessagesResponse> {
        let encoded = urlencoded(room_id);
        let mut url = format!(
            "{}/_matrix/client/v3/rooms/{encoded}/messages?dir=b&limit={limit}",
            self.homeserver_url
        );
        if let Some(from_token) = from {
            use std::fmt::Write;
            let _ = write!(url, "&from={from_token}");
        }
        self.api_get(&url).await
    }

    // ─── Sync ───────────────────────────────────────────────────────────────

    /// Perform a sync (long-poll).
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn sync(&self, since: Option<&str>, timeout_ms: u32) -> MatrixResult<SyncResponse> {
        let mut url = format!(
            "{}/_matrix/client/v3/sync?timeout={timeout_ms}",
            self.homeserver_url
        );
        if let Some(since_token) = since {
            use std::fmt::Write;
            let _ = write!(url, "&since={since_token}");
        }
        self.api_get(&url).await
    }

    // ─── Health ─────────────────────────────────────────────────────────────

    /// Lightweight health check.
    ///
    /// # Errors
    /// Returns `MatrixError` if the homeserver is unreachable.
    pub async fn health_check(&self) -> MatrixResult<()> {
        let url = format!("{}/_matrix/client/v3/account/whoami", self.homeserver_url);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(MatrixError::Http)?;
        let status = resp.status().as_u16();
        if status == 200 || status == 401 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(MatrixError::from_matrix_response(status, &body))
        }
    }

    // ─── Internals ──────────────────────────────────────────────────────────

    async fn api_get<T: serde::de::DeserializeOwned>(&self, url: &str) -> MatrixResult<T> {
        let resp = self
            .client
            .get(url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_response(resp).await
    }

    async fn api_post<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> MatrixResult<T> {
        let resp = self
            .client
            .post(url)
            .bearer_auth(&self.access_token)
            .json(body)
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_response(resp).await
    }

    async fn api_put<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> MatrixResult<T> {
        let resp = self
            .client
            .put(url)
            .bearer_auth(&self.access_token)
            .json(body)
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_response(resp).await
    }

    async fn handle_response<T: serde::de::DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> MatrixResult<T> {
        let status = resp.status().as_u16();
        if status == 429 {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .map_or(30_000, |s| s * 1000);
            return Err(MatrixError::RateLimited {
                retry_after_ms: retry_after,
            });
        }
        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(MatrixError::from_matrix_response(status, &body));
        }
        resp.json().await.map_err(MatrixError::Http)
    }
}

/// Minimal URL encoding for path segments.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_client_trims_slash() {
        let c = MatrixClient::new("https://matrix.org/", "tok", Duration::from_secs(30)).unwrap();
        assert_eq!(c.homeserver_url(), "https://matrix.org");
    }

    #[test]
    fn secretless_detection() {
        let c = MatrixClient::new("https://matrix.org", "", Duration::from_secs(30)).unwrap();
        assert!(c.is_secretless());
    }

    #[test]
    fn not_secretless() {
        let c = MatrixClient::new("https://matrix.org", "tok", Duration::from_secs(30)).unwrap();
        assert!(!c.is_secretless());
    }

    #[test]
    fn urlencoded_room_id() {
        let encoded = urlencoded("!room:matrix.org");
        assert_eq!(encoded, "%21room%3Amatrix.org");
    }

    #[fcp_async_core::runtime::test]
    async fn whoami_parses() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/_matrix/client/v3/account/whoami",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "user_id": "@bot:matrix.org",
                    "device_id": "DEV1"
                })),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let resp = c.whoami().await.unwrap();
        assert_eq!(resp.user_id, "@bot:matrix.org");
    }

    #[fcp_async_core::runtime::test]
    async fn joined_rooms_parses() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_matrix/client/v3/joined_rooms"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "joined_rooms": ["!a:m.org", "!b:m.org"]
                })),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let rooms = c.joined_rooms().await.unwrap();
        assert_eq!(rooms.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_returns_event_id() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("PUT"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "event_id": "$new_event"
                })),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let resp = c
            .send_message("!room:m.org", "Hello", "m.text")
            .await
            .unwrap();
        assert_eq!(resp.event_id, "$new_event");
    }

    #[fcp_async_core::runtime::test]
    async fn handles_401_unauthorized() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_matrix/client/v3/joined_rooms"))
            .respond_with(
                wiremock::ResponseTemplate::new(401).set_body_json(serde_json::json!({
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Unrecognised access token."
                })),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let result = c.joined_rooms().await;
        assert!(matches!(result.unwrap_err(), MatrixError::Unauthorized(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn handles_429_rate_limited() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_matrix/client/v3/joined_rooms"))
            .respond_with(
                wiremock::ResponseTemplate::new(429)
                    .insert_header("retry-after", "60")
                    .set_body_string("rate limited"),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let result = c.joined_rooms().await;
        match result.unwrap_err() {
            MatrixError::RateLimited { retry_after_ms } => assert_eq!(retry_after_ms, 60_000),
            other => panic!("Expected RateLimited, got {other:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn health_check_ok() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/_matrix/client/v3/account/whoami",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "user_id": "@bot:m.org"
                })),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        assert!(c.health_check().await.is_ok());
    }
}
