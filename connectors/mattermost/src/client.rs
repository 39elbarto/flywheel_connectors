//! Mattermost HTTP API client.

use std::time::Duration;

use reqwest::Client;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use tracing::debug;

use crate::error::{MattermostError, MattermostResult};
use crate::types::{
    Channel, CreatePostRequest, FileInfo, MattermostAuth, Post, PostList, SearchPostsRequest, Team,
    User,
};

/// HTTP client for the Mattermost REST API v4.
#[derive(Debug)]
pub struct MattermostClient {
    client: Client,
    base_url: String,
    /// Retained for credential refresh and diagnostics.
    #[allow(dead_code)]
    auth: MattermostAuth,
}

impl MattermostClient {
    /// Create a new client with the given auth.
    ///
    /// # Errors
    ///
    /// Returns an error if the token header is invalid or the HTTP client cannot be built.
    pub fn new(base_url: &str, auth: MattermostAuth, timeout: Duration) -> MattermostResult<Self> {
        let mut headers = HeaderMap::new();
        if let MattermostAuth::Token(ref token) = auth {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|e| MattermostError::Config(format!("invalid token header: {e}")))?,
            );
        }

        let client = Client::builder()
            .timeout(timeout)
            .default_headers(headers)
            .build()
            .map_err(MattermostError::Http)?;

        let base_url = base_url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            base_url,
            auth,
        })
    }

    /// Base URL of the Mattermost server.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Token used for bearer-authenticated websocket sessions, if available.
    #[must_use]
    pub fn auth_token(&self) -> Option<&str> {
        match &self.auth {
            MattermostAuth::Token(token) => Some(token.as_str()),
            MattermostAuth::CredentialId(_) => None,
        }
    }

    /// Build the websocket endpoint URL for the current server.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured base URL is not a valid HTTP(S) URL.
    pub fn websocket_url(
        &self,
        connection_id: Option<&str>,
        sequence_number: Option<u64>,
    ) -> MattermostResult<String> {
        let websocket_base = if let Some(rest) = self.base_url.strip_prefix("https://") {
            format!("wss://{rest}/api/v4/websocket")
        } else if let Some(rest) = self.base_url.strip_prefix("http://") {
            format!("ws://{rest}/api/v4/websocket")
        } else if self.base_url.starts_with("wss://") || self.base_url.starts_with("ws://") {
            format!("{}/api/v4/websocket", self.base_url)
        } else {
            return Err(MattermostError::Config(format!(
                "unsupported base_url scheme for websocket endpoint: {}",
                self.base_url
            )));
        };

        let mut url = reqwest::Url::parse(&websocket_base)
            .map_err(|e| MattermostError::Config(format!("invalid websocket URL: {e}")))?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(connection_id) = connection_id.filter(|id| !id.is_empty()) {
                query.append_pair("connection_id", connection_id);
            }
            if let Some(sequence_number) = sequence_number {
                query.append_pair("sequence_number", &sequence_number.to_string());
            }
        }

        Ok(url.into())
    }

    /// Build read-only access paths for a file.
    #[must_use]
    pub fn file_access_paths(&self, file_id: &str) -> serde_json::Value {
        let base = format!("{}/api/v4/files/{file_id}", self.base_url);
        serde_json::json!({
            "download_url": format!("{base}?download=true"),
            "preview_url": format!("{base}/preview?download=true"),
            "thumbnail_url": format!("{base}/thumbnail?download=true")
        })
    }

    // ── Users ────────────────────────────────────────────────────────────

    /// Get the authenticated user's profile.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the server returns a non-2xx status.
    pub async fn get_me(&self) -> MattermostResult<User> {
        self.get("/api/v4/users/me").await
    }

    /// Get a user by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the user is not found.
    pub async fn get_user(&self, user_id: &str) -> MattermostResult<User> {
        self.get(&format!("/api/v4/users/{user_id}")).await
    }

    // ── Teams ────────────────────────────────────────────────────────────

    /// List teams the authenticated user belongs to.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the server returns a non-2xx status.
    pub async fn get_my_teams(&self) -> MattermostResult<Vec<Team>> {
        self.get("/api/v4/users/me/teams").await
    }

    /// Get a team by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the team is not found.
    pub async fn get_team(&self, team_id: &str) -> MattermostResult<Team> {
        self.get(&format!("/api/v4/teams/{team_id}")).await
    }

    // ── Channels ─────────────────────────────────────────────────────────

    /// List channels for a team and user.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the team is not found.
    pub async fn get_channels_for_team(
        &self,
        team_id: &str,
        user_id: &str,
        include_deleted: bool,
    ) -> MattermostResult<Vec<Channel>> {
        let include_deleted = if include_deleted { "true" } else { "false" };
        self.get(&format!(
            "/api/v4/users/{user_id}/teams/{team_id}/channels?include_deleted={include_deleted}"
        ))
        .await
    }

    /// Get a channel by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the channel is not found.
    pub async fn get_channel(&self, channel_id: &str) -> MattermostResult<Channel> {
        self.get(&format!("/api/v4/channels/{channel_id}")).await
    }

    // ── Posts ─────────────────────────────────────────────────────────────

    /// Create a new post.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the server rejects the request.
    pub async fn create_post(&self, req: &CreatePostRequest) -> MattermostResult<Post> {
        self.post("/api/v4/posts", req).await
    }

    /// Get a post by ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the post is not found.
    pub async fn get_post(&self, post_id: &str) -> MattermostResult<Post> {
        self.get(&format!("/api/v4/posts/{post_id}")).await
    }

    /// Get posts in a channel (paginated).
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the channel is not found.
    pub async fn get_posts_for_channel(
        &self,
        channel_id: &str,
        page: u32,
        per_page: u32,
    ) -> MattermostResult<PostList> {
        self.get(&format!(
            "/api/v4/channels/{channel_id}/posts?page={page}&per_page={per_page}"
        ))
        .await
    }

    /// Search posts in a team.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the team is not found.
    pub async fn search_posts(
        &self,
        team_id: &str,
        req: &SearchPostsRequest,
    ) -> MattermostResult<PostList> {
        self.post(&format!("/api/v4/teams/{team_id}/posts/search"), req)
            .await
    }

    /// Delete a post.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the post is not found or permission is denied.
    pub async fn delete_post(&self, post_id: &str) -> MattermostResult<()> {
        let url = format!("{}/api/v4/posts/{post_id}", self.base_url);
        debug!(url = %url, "DELETE");

        let response = self
            .client
            .delete(&url)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        let status = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        if (200..300).contains(&status) {
            Ok(())
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(MattermostError::from_api_response(
                status, &body, request_id,
            ))
        }
    }

    /// Get file metadata by file ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the file is not found.
    pub async fn get_file_info(&self, file_id: &str) -> MattermostResult<FileInfo> {
        self.get(&format!("/api/v4/files/{file_id}/info")).await
    }

    /// Get file metadata for all files attached to a post.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the post is not found.
    pub async fn get_file_infos_for_post(&self, post_id: &str) -> MattermostResult<Vec<FileInfo>> {
        self.get(&format!("/api/v4/posts/{post_id}/files/info"))
            .await
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    async fn get<T: DeserializeOwned>(&self, path: &str) -> MattermostResult<T> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        self.handle_response(response).await
    }

    async fn post<T: DeserializeOwned, B: serde::Serialize + Sync>(
        &self,
        path: &str,
        body: &B,
    ) -> MattermostResult<T> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "POST");

        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        self.handle_response(response).await
    }

    async fn handle_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> MattermostResult<T> {
        let status = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        if (200..300).contains(&status) {
            let body = response.text().await.map_err(MattermostError::Http)?;
            serde_json::from_str(&body).map_err(MattermostError::Json)
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(MattermostError::from_api_response(
                status, &body, request_id,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_url_uses_ws_scheme_and_query_state() {
        let client = MattermostClient::new(
            "https://chat.example.com/mattermost",
            MattermostAuth::Token("tok".into()),
            Duration::from_secs(5),
        )
        .unwrap();
        let url = client.websocket_url(Some("conn-1"), Some(99)).unwrap();
        assert_eq!(
            url,
            "wss://chat.example.com/mattermost/api/v4/websocket?connection_id=conn-1&sequence_number=99"
        );
    }

    #[test]
    fn file_access_paths_include_download_variants() {
        let client = MattermostClient::new(
            "https://chat.example.com",
            MattermostAuth::Token("tok".into()),
            Duration::from_secs(5),
        )
        .unwrap();
        let paths = client.file_access_paths("file123");
        assert_eq!(
            paths["download_url"],
            "https://chat.example.com/api/v4/files/file123?download=true"
        );
        assert_eq!(
            paths["preview_url"],
            "https://chat.example.com/api/v4/files/file123/preview?download=true"
        );
    }
}
