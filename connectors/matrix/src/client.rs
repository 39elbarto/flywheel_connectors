//! Matrix Client-Server API client.

use std::time::Duration;

use reqwest::header::{CONTENT_DISPOSITION, CONTENT_TYPE, HeaderValue};
use reqwest::{Client, RequestBuilder};

use crate::error::{MatrixError, MatrixResult};
use crate::types::{
    CreateRoomRequest, CreateRoomResponse, DownloadedMedia, Event, JoinedRoomsResponse,
    MediaUploadResponse, MembersResponse, MessagesResponse, SendEventResponse, SyncResponse,
    WhoAmIResponse,
};

const CREDENTIAL_ID_HEADER: &str = "x-fcp-credential-id";

/// Matrix API client.
pub struct MatrixClient {
    client: Client,
    homeserver_url: String,
    access_token: String,
    credential_id: Option<String>,
    is_secretless: bool,
}

impl std::fmt::Debug for MatrixClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatrixClient")
            .field("homeserver_url", &self.homeserver_url)
            .field("access_token", &"[REDACTED]")
            .field("credential_id", &self.credential_id)
            .field("is_secretless", &self.is_secretless)
            .finish_non_exhaustive()
    }
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
            credential_id: None,
            is_secretless: secretless,
        })
    }

    /// Create a Matrix client for secretless credential injection.
    ///
    /// # Errors
    /// Returns `MatrixError::Config` if the credential header is invalid or the client cannot be
    /// built.
    pub fn new_secretless(
        homeserver_url: &str,
        credential_id: &str,
        timeout: Duration,
    ) -> MatrixResult<Self> {
        HeaderValue::from_str(credential_id)
            .map_err(|e| MatrixError::Config(format!("Invalid credential_id header: {e}")))?;

        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| MatrixError::Config(format!("Failed to build HTTP client: {e}")))?;

        let base = homeserver_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            homeserver_url: base,
            access_token: String::new(),
            credential_id: Some(credential_id.to_string()),
            is_secretless: true,
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

    /// Fetch the full room state event set.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn get_room_state(&self, room_id: &str) -> MatrixResult<Vec<Event>> {
        let encoded = urlencoded(room_id);
        let url = format!(
            "{}/_matrix/client/v3/rooms/{encoded}/state",
            self.homeserver_url
        );
        self.api_get(&url).await
    }

    /// List room members, optionally filtering by membership state.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn list_members(
        &self,
        room_id: &str,
        membership: Option<&str>,
    ) -> MatrixResult<Vec<Event>> {
        let encoded = urlencoded(room_id);
        let mut url = reqwest::Url::parse(&format!(
            "{}/_matrix/client/v3/rooms/{encoded}/members",
            self.homeserver_url
        ))
        .map_err(|e| MatrixError::Config(format!("Invalid members URL: {e}")))?;
        if let Some(membership) = membership {
            url.query_pairs_mut().append_pair("membership", membership);
        }
        let resp: MembersResponse = self.api_get(url.as_str()).await?;
        Ok(resp.chunk)
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
        let mut url = reqwest::Url::parse(&format!(
            "{}/_matrix/client/v3/rooms/{encoded}/messages",
            self.homeserver_url
        ))
        .map_err(|e| MatrixError::Config(format!("Invalid messages URL: {e}")))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("dir", "b");
            query.append_pair("limit", &limit.to_string());
            if let Some(from_token) = from {
                query.append_pair("from", from_token);
            }
        }
        self.api_get(url.as_str()).await
    }

    /// Upload media to the homeserver.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn upload_media(
        &self,
        content_type: &str,
        data: Vec<u8>,
        filename: Option<&str>,
    ) -> MatrixResult<MediaUploadResponse> {
        let mut url =
            reqwest::Url::parse(&format!("{}/_matrix/media/v3/upload", self.homeserver_url))
                .map_err(|e| MatrixError::Config(format!("Invalid upload URL: {e}")))?;
        if let Some(filename) = filename {
            url.query_pairs_mut().append_pair("filename", filename);
        }

        let resp = self
            .authorize(self.client.post(url))
            .header(CONTENT_TYPE, content_type)
            .body(data)
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_response(resp).await
    }

    /// Download media from the homeserver.
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn download_media(
        &self,
        server_name: &str,
        media_id: &str,
        allow_remote: bool,
    ) -> MatrixResult<DownloadedMedia> {
        let encoded_server = urlencoded(server_name);
        let encoded_media = urlencoded(media_id);
        let mut url = reqwest::Url::parse(&format!(
            "{}/_matrix/media/v3/download/{encoded_server}/{encoded_media}",
            self.homeserver_url
        ))
        .map_err(|e| MatrixError::Config(format!("Invalid download URL: {e}")))?;
        if !allow_remote {
            url.query_pairs_mut().append_pair("allow_remote", "false");
        }

        let resp = self
            .authorize(self.client.get(url))
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_binary_response(resp).await
    }

    // ─── Sync ───────────────────────────────────────────────────────────────

    /// Perform a sync (long-poll).
    ///
    /// # Errors
    /// Returns `MatrixError` on transport or API errors.
    pub async fn sync(&self, since: Option<&str>, timeout_ms: u32) -> MatrixResult<SyncResponse> {
        let mut url =
            reqwest::Url::parse(&format!("{}/_matrix/client/v3/sync", self.homeserver_url))
                .map_err(|e| MatrixError::Config(format!("Invalid sync URL: {e}")))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("timeout", &timeout_ms.to_string());
            if let Some(since_token) = since {
                query.append_pair("since", since_token);
            }
        }
        self.api_get(url.as_str()).await
    }

    // ─── Health ─────────────────────────────────────────────────────────────

    /// Lightweight health check.
    ///
    /// # Errors
    /// Returns `MatrixError` if the homeserver is unreachable or authentication fails.
    pub async fn health_check(&self) -> MatrixResult<()> {
        let url = format!("{}/_matrix/client/v3/account/whoami", self.homeserver_url);
        let resp = self
            .authorize(self.client.get(&url))
            .send()
            .await
            .map_err(MatrixError::Http)?;
        let status = resp.status().as_u16();
        if status == 200 {
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(MatrixError::from_matrix_response(status, &body))
        }
    }

    // ─── Internals ──────────────────────────────────────────────────────────

    async fn api_get<T: serde::de::DeserializeOwned>(&self, url: &str) -> MatrixResult<T> {
        let resp = self
            .authorize(self.client.get(url))
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
            .authorize(self.client.post(url))
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
            .authorize(self.client.put(url))
            .json(body)
            .send()
            .await
            .map_err(MatrixError::Http)?;
        self.handle_response(resp).await
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

    async fn handle_binary_response(
        &self,
        resp: reqwest::Response,
    ) -> MatrixResult<DownloadedMedia> {
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

        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let content_disposition = resp
            .headers()
            .get(CONTENT_DISPOSITION)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let data = resp.bytes().await.map_err(MatrixError::Http)?.to_vec();
        Ok(DownloadedMedia {
            content_type,
            content_disposition,
            data,
        })
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
    fn secretless_constructor_preserves_credential_reference() {
        let c =
            MatrixClient::new_secretless("https://matrix.org", "cred_1", Duration::from_secs(30))
                .unwrap();
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
    async fn secretless_client_sends_credential_header() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/_matrix/client/v3/account/whoami",
            ))
            .and(wiremock::matchers::header(CREDENTIAL_ID_HEADER, "cred_1"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "user_id": "@bot:matrix.org"
                })),
            )
            .mount(&mock)
            .await;

        let c =
            MatrixClient::new_secretless(&mock.uri(), "cred_1", Duration::from_secs(10)).unwrap();
        let _ = c.whoami().await.unwrap();

        let requests = mock.received_requests().await.unwrap_or_default();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].headers.get("authorization").is_none());
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
    async fn get_messages_encodes_from_token() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/_matrix/client/v3/rooms/%21room%3Am.org/messages",
            ))
            .and(wiremock::matchers::query_param("dir", "b"))
            .and(wiremock::matchers::query_param("limit", "20"))
            .and(wiremock::matchers::query_param("from", "a/b+c=="))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "chunk": [],
                    "end": "next"
                })),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let resp = c
            .get_messages("!room:m.org", Some("a/b+c=="), 20)
            .await
            .unwrap();
        assert_eq!(resp.end.as_deref(), Some("next"));
    }

    #[fcp_async_core::runtime::test]
    async fn get_room_state_parses_events() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/_matrix/client/v3/rooms/%21room%3Am.org/state",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!([
                    {
                        "type": "m.room.name",
                        "state_key": "",
                        "content": { "name": "General" }
                    }
                ])),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let events = c.get_room_state("!room:m.org").await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].state_key.as_deref(), Some(""));
    }

    #[fcp_async_core::runtime::test]
    async fn list_members_supports_membership_filter() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/_matrix/client/v3/rooms/%21room%3Am.org/members",
            ))
            .and(wiremock::matchers::query_param("membership", "join"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "chunk": [
                        {
                            "type": "m.room.member",
                            "state_key": "@alice:m.org",
                            "content": { "membership": "join", "displayname": "Alice" }
                        }
                    ]
                })),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let members = c.list_members("!room:m.org", Some("join")).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].state_key.as_deref(), Some("@alice:m.org"));
    }

    #[fcp_async_core::runtime::test]
    async fn sync_includes_since_and_timeout() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/_matrix/client/v3/sync"))
            .and(wiremock::matchers::query_param("since", "batch_1"))
            .and(wiremock::matchers::query_param("timeout", "5000"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "next_batch": "batch_2"
                })),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let response = c.sync(Some("batch_1"), 5000).await.unwrap();
        assert_eq!(response.next_batch, "batch_2");
    }

    #[fcp_async_core::runtime::test]
    async fn upload_media_sends_filename_query_and_content_type() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path("/_matrix/media/v3/upload"))
            .and(wiremock::matchers::query_param("filename", "greeting.txt"))
            .and(wiremock::matchers::header("content-type", "text/plain"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "content_uri": "mxc://matrix.org/media123"
                })),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let response = c
            .upload_media("text/plain", b"hello".to_vec(), Some("greeting.txt"))
            .await
            .unwrap();
        assert_eq!(response.content_uri, "mxc://matrix.org/media123");
    }

    #[fcp_async_core::runtime::test]
    async fn download_media_returns_headers_and_bytes() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/_matrix/media/v3/download/matrix.org/media123",
            ))
            .and(wiremock::matchers::query_param("allow_remote", "false"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .insert_header("content-type", "image/png")
                    .insert_header("content-disposition", "inline; filename=\"cat.png\"")
                    .set_body_bytes(b"pngdata".to_vec()),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let media = c
            .download_media("matrix.org", "media123", false)
            .await
            .unwrap();
        assert_eq!(media.content_type.as_deref(), Some("image/png"));
        assert_eq!(
            media.content_disposition.as_deref(),
            Some("inline; filename=\"cat.png\"")
        );
        assert_eq!(media.data, b"pngdata".to_vec());
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

    #[fcp_async_core::runtime::test]
    async fn health_check_401_is_unauthorized() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(
                "/_matrix/client/v3/account/whoami",
            ))
            .respond_with(
                wiremock::ResponseTemplate::new(401).set_body_json(serde_json::json!({
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Unrecognised access token."
                })),
            )
            .mount(&mock)
            .await;

        let c = MatrixClient::new(&mock.uri(), "tok", Duration::from_secs(10)).unwrap();
        let err = c.health_check().await.unwrap_err();
        assert!(matches!(err, MatrixError::Unauthorized(_)));
    }
}
