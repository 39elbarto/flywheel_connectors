//! Mattermost HTTP API client.

use fcp_prelude::log_redaction::redact_url;
use std::time::Duration;

use base64::Engine as _;
use fcp_streaming::WsConfig;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use reqwest::multipart::{Form, Part};
use serde::de::DeserializeOwned;
use tracing::debug;

use crate::error::{MattermostError, MattermostResult};
use crate::types::{
    Channel, CreateDirectChannelRequest, CreateGroupChannelRequest, CreatePostRequest,
    CreateReactionRequest, DeleteReactionRequest, FileDownload, FileInfo, GetThreadRequest,
    MattermostAuth, Post, PostList, Reaction, SearchPostsRequest, Team, UpdatePostRequest,
    UploadFileRequest, UploadFileResponse, User,
};

const CREDENTIAL_ID_HEADER: &str = "x-fcp-credential-id";
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// HTTP client for the Mattermost REST API v4.
#[derive(Clone)]
pub struct MattermostClient {
    client: Client,
    base_url: String,
    /// Retained for credential refresh and diagnostics.
    auth: MattermostAuth,
    timeout: Duration,
}

impl std::fmt::Debug for MattermostClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let auth_mode = match &self.auth {
            MattermostAuth::Token(_) => "token",
            MattermostAuth::CredentialId(_) => "credential_id",
        };
        f.debug_struct("MattermostClient")
            .field("base_url", &self.base_url)
            .field("auth_mode", &auth_mode)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl MattermostClient {
    /// Create a new client with the given auth.
    ///
    /// # Errors
    ///
    /// Returns an error if the token header is invalid or the HTTP client cannot be built.
    pub fn new(base_url: &str, auth: MattermostAuth, timeout: Duration) -> MattermostResult<Self> {
        let mut headers = HeaderMap::new();
        append_auth_headers(&mut headers, &auth)?;

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
            timeout,
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

    /// Websocket configuration matching the connector's auth mode.
    ///
    /// # Errors
    ///
    /// Returns an error if an auth header cannot be encoded.
    pub fn websocket_config(&self) -> MattermostResult<WsConfig> {
        let mut config = WsConfig::new()
            .with_connect_timeout(self.timeout)
            .with_ping_interval(None)
            .with_auto_reconnect(false);

        config = match &self.auth {
            MattermostAuth::Token(token) => {
                config.with_header(AUTHORIZATION.as_str(), format!("Bearer {token}"))
            }
            MattermostAuth::CredentialId(credential_id) => {
                config.with_header(CREDENTIAL_ID_HEADER, credential_id.clone())
            }
        };

        Ok(config)
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
        let connection_id = connection_id.filter(|id| !id.is_empty());
        let sequence_number = sequence_number.filter(|seq| *seq > 0);
        if connection_id.is_some() || sequence_number.is_some() {
            let mut query = url.query_pairs_mut();
            if let Some(connection_id) = connection_id {
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
        let file_id = encode_path_segment(file_id);
        let base = format!("{}/api/v4/files/{file_id}", self.base_url);
        serde_json::json!({
            "download_url": base,
            "info_url": format!("{base}/info"),
            "link_url": format!("{base}/link"),
            "preview_url": format!("{base}/preview"),
            "thumbnail_url": format!("{base}/thumbnail")
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
        let user_id = encode_path_segment(user_id);
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
        let team_id = encode_path_segment(team_id);
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
        let team_id = encode_path_segment(team_id);
        let user_id = encode_path_segment(user_id);
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
        let channel_id = encode_path_segment(channel_id);
        self.get(&format!("/api/v4/channels/{channel_id}")).await
    }

    /// Create or fetch the direct channel for the provided user pair.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the server rejects the user ID list.
    pub async fn create_direct_channel(
        &self,
        request: &CreateDirectChannelRequest,
    ) -> MattermostResult<Channel> {
        self.post("/api/v4/channels/direct", &request.user_ids)
            .await
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
        let post_id = encode_path_segment(post_id);
        self.get(&format!("/api/v4/posts/{post_id}")).await
    }

    /// Get the thread containing the given root or child post.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the post is not found.
    pub async fn get_thread(&self, req: &GetThreadRequest) -> MattermostResult<PostList> {
        let url = self.thread_url(req)?;
        self.get_url(url).await
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
        let channel_id = encode_path_segment(channel_id);
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
        let team_id = encode_path_segment(team_id);
        self.post(&format!("/api/v4/teams/{team_id}/posts/search"), req)
            .await
    }

    /// Delete a post.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the post is not found or permission is denied.
    pub async fn delete_post(&self, post_id: &str) -> MattermostResult<()> {
        let post_id = encode_path_segment(post_id);
        self.delete_path(&format!("/api/v4/posts/{post_id}")).await
    }

    /// Update (patch) an existing post.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the post is not found or permission is denied.
    pub async fn update_post(&self, req: &UpdatePostRequest) -> MattermostResult<Post> {
        let post_id = encode_path_segment(&req.id);
        self.put(&format!("/api/v4/posts/{post_id}/patch"), req)
            .await
    }

    /// Pin a post to its channel.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the post is not found or permission is denied.
    pub async fn pin_post(&self, post_id: &str) -> MattermostResult<()> {
        let post_id = encode_path_segment(post_id);
        self.post_empty(&format!("/api/v4/posts/{post_id}/pin"))
            .await
    }

    /// Unpin a post from its channel.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the post is not found or permission is denied.
    pub async fn unpin_post(&self, post_id: &str) -> MattermostResult<()> {
        let post_id = encode_path_segment(post_id);
        self.post_empty(&format!("/api/v4/posts/{post_id}/unpin"))
            .await
    }

    /// Get all reactions for a post.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the post is not found.
    pub async fn get_reactions_for_post(&self, post_id: &str) -> MattermostResult<Vec<Reaction>> {
        let post_id = encode_path_segment(post_id);
        self.get(&format!("/api/v4/posts/{post_id}/reactions"))
            .await
    }

    /// Create a group message channel (3+ users).
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the server rejects the request.
    pub async fn create_group_channel(
        &self,
        req: &CreateGroupChannelRequest,
    ) -> MattermostResult<Channel> {
        self.post("/api/v4/channels/group", &req.user_ids).await
    }

    /// Save a reaction on a post.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the server rejects the reaction.
    pub async fn create_reaction(
        &self,
        request: &CreateReactionRequest,
    ) -> MattermostResult<Reaction> {
        self.post("/api/v4/reactions", request).await
    }

    /// Delete a reaction from a post.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the server rejects the removal.
    pub async fn delete_reaction(&self, request: &DeleteReactionRequest) -> MattermostResult<()> {
        let url = self.reaction_delete_url(request)?;
        self.delete_url(url).await
    }

    /// Get file metadata by file ID.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the file is not found.
    pub async fn get_file_info(&self, file_id: &str) -> MattermostResult<FileInfo> {
        let file_id = encode_path_segment(file_id);
        self.get(&format!("/api/v4/files/{file_id}/info")).await
    }

    /// Get a public link for a file.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the file is not found.
    pub async fn get_file_link(&self, file_id: &str) -> MattermostResult<serde_json::Value> {
        let file_id = encode_path_segment(file_id);
        self.get(&format!("/api/v4/files/{file_id}/link")).await
    }

    /// Download a file body and return it as base64.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the file is not found.
    pub async fn download_file(&self, file_id: &str) -> MattermostResult<FileDownload> {
        let encoded_file_id = encode_path_segment(file_id);
        let url = format!("{}/api/v4/files/{encoded_file_id}", self.base_url);
        debug!(url = %redact_url(url.as_str()), "GET");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        self.handle_binary_response(file_id, response).await
    }

    /// Get file metadata for all files attached to a post.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure or if the post is not found.
    pub async fn get_file_infos_for_post(&self, post_id: &str) -> MattermostResult<Vec<FileInfo>> {
        let post_id = encode_path_segment(post_id);
        self.get(&format!("/api/v4/posts/{post_id}/files/info"))
            .await
    }

    /// Upload a single file to a channel via multipart form data.
    ///
    /// # Errors
    ///
    /// Returns an error on HTTP failure, invalid MIME metadata, or upload rejection.
    pub async fn upload_file(
        &self,
        request: &UploadFileRequest,
        contents: Vec<u8>,
    ) -> MattermostResult<UploadFileResponse> {
        let url = format!("{}/api/v4/files", self.base_url);
        debug!(url = %redact_url(url.as_str()), "POST multipart");

        let mut part = Part::bytes(contents).file_name(request.filename.clone());
        if let Some(content_type) = non_empty_trimmed(request.content_type.as_deref()) {
            part = part.mime_str(&content_type).map_err(|error| {
                MattermostError::Config(format!("invalid upload content_type: {error}"))
            })?;
        }

        let mut form = Form::new()
            .text("channel_id", request.channel_id.clone())
            .part("files", part);
        if let Some(client_id) = non_empty_trimmed(request.client_id.as_deref()) {
            form = form.text("client_ids", client_id);
        }

        let response = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        self.handle_response(response).await
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    async fn get<T: DeserializeOwned>(&self, path: &str) -> MattermostResult<T> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(url.as_str()), "GET");

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        self.handle_response(response).await
    }

    async fn get_url<T: DeserializeOwned>(&self, url: reqwest::Url) -> MattermostResult<T> {
        debug!(url = %redact_url(url.as_str()), "GET");

        let response = self
            .client
            .get(url)
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
        debug!(url = %redact_url(url.as_str()), "POST");

        let response = self
            .client
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        self.handle_response(response).await
    }

    async fn put<T: DeserializeOwned, B: serde::Serialize + Sync>(
        &self,
        path: &str,
        body: &B,
    ) -> MattermostResult<T> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(url.as_str()), "PUT");

        let response = self
            .client
            .put(&url)
            .json(body)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        self.handle_response(response).await
    }

    async fn post_empty(&self, path: &str) -> MattermostResult<()> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(url.as_str()), "POST (empty body)");

        let response = self
            .client
            .post(&url)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        self.handle_empty_response(response).await
    }

    async fn delete_path(&self, path: &str) -> MattermostResult<()> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %redact_url(url.as_str()), "DELETE");

        let response = self
            .client
            .delete(&url)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        self.handle_empty_response(response).await
    }

    async fn delete_url(&self, url: reqwest::Url) -> MattermostResult<()> {
        debug!(url = %redact_url(url.as_str()), "DELETE");

        let response = self
            .client
            .delete(url)
            .send()
            .await
            .map_err(MattermostError::Http)?;
        self.handle_empty_response(response).await
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

    async fn handle_binary_response(
        &self,
        file_id: &str,
        response: reqwest::Response,
    ) -> MattermostResult<FileDownload> {
        let status = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        if (200..300).contains(&status) {
            let body = response.bytes().await.map_err(MattermostError::Http)?;
            Ok(FileDownload {
                file_id: file_id.to_string(),
                content_base64: base64::engine::general_purpose::STANDARD.encode(body.as_ref()),
                content_type,
                size_bytes: body.len(),
            })
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(MattermostError::from_api_response(
                status, &body, request_id,
            ))
        }
    }

    async fn handle_empty_response(&self, response: reqwest::Response) -> MattermostResult<()> {
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

    fn thread_url(&self, request: &GetThreadRequest) -> MattermostResult<reqwest::Url> {
        let post_id = encode_path_segment(&request.post_id);
        let mut url = reqwest::Url::parse(&format!(
            "{}/api/v4/posts/{}/thread",
            self.base_url, post_id
        ))
        .map_err(|e| MattermostError::Config(format!("invalid thread URL: {e}")))?;

        let has_query = request.per_page.is_some()
            || request.from_post.is_some()
            || request.from_create_at.is_some()
            || request.from_update_at.is_some()
            || request.direction.is_some()
            || request.skip_fetch_threads.is_some()
            || request.collapsed_threads.is_some()
            || request.collapsed_threads_extended.is_some()
            || request.updates_only.is_some();

        if has_query {
            let mut query = url.query_pairs_mut();

            if let Some(per_page) = request.per_page {
                query.append_pair("perPage", &per_page.to_string());
            }
            if let Some(from_post) = request.from_post.as_deref() {
                query.append_pair("fromPost", from_post);
            }
            if let Some(from_create_at) = request.from_create_at {
                query.append_pair("fromCreateAt", &from_create_at.to_string());
            }
            if let Some(from_update_at) = request.from_update_at {
                query.append_pair("fromUpdateAt", &from_update_at.to_string());
            }
            if let Some(direction) = request.direction.as_deref() {
                query.append_pair("direction", direction);
            }
            if let Some(skip_fetch_threads) = request.skip_fetch_threads {
                query.append_pair(
                    "skipFetchThreads",
                    if skip_fetch_threads { "true" } else { "false" },
                );
            }
            if let Some(collapsed_threads) = request.collapsed_threads {
                query.append_pair(
                    "collapsedThreads",
                    if collapsed_threads { "true" } else { "false" },
                );
            }
            if let Some(collapsed_threads_extended) = request.collapsed_threads_extended {
                query.append_pair(
                    "collapsedThreadsExtended",
                    if collapsed_threads_extended {
                        "true"
                    } else {
                        "false"
                    },
                );
            }
            if let Some(updates_only) = request.updates_only {
                query.append_pair("updatesOnly", if updates_only { "true" } else { "false" });
            }
        }

        Ok(url)
    }

    fn reaction_delete_url(
        &self,
        request: &DeleteReactionRequest,
    ) -> MattermostResult<reqwest::Url> {
        let mut url = reqwest::Url::parse(&self.base_url)
            .map_err(|error| MattermostError::Config(format!("invalid base_url: {error}")))?;
        let base_path = url.path().trim_end_matches('/');
        let path = format!(
            "{base_path}/api/v4/users/{}/posts/{}/reactions/{}",
            encode_path_segment(request.user_id.as_str()),
            encode_path_segment(request.post_id.as_str()),
            encode_path_segment(request.emoji_name.as_str())
        );
        url.set_path(&path);
        Ok(url)
    }
}

fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn non_empty_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn append_auth_headers(headers: &mut HeaderMap, auth: &MattermostAuth) -> MattermostResult<()> {
    match auth {
        MattermostAuth::Token(token) => {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|e| MattermostError::Config(format!("invalid token header: {e}")))?,
            );
        }
        MattermostAuth::CredentialId(credential_id) => {
            headers.insert(
                HeaderName::from_static(CREDENTIAL_ID_HEADER),
                HeaderValue::from_str(credential_id).map_err(|e| {
                    MattermostError::Config(format!("invalid credential header: {e}"))
                })?,
            );
        }
    }

    Ok(())
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
    fn websocket_url_omits_empty_resume_state() {
        let client = MattermostClient::new(
            "https://chat.example.com",
            MattermostAuth::Token("tok".into()),
            Duration::from_secs(5),
        )
        .unwrap();
        let url = client.websocket_url(Some(""), Some(0)).unwrap();
        assert_eq!(url, "wss://chat.example.com/api/v4/websocket");
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
            "https://chat.example.com/api/v4/files/file123"
        );
        assert_eq!(
            paths["info_url"],
            "https://chat.example.com/api/v4/files/file123/info"
        );
        assert_eq!(
            paths["link_url"],
            "https://chat.example.com/api/v4/files/file123/link"
        );
        assert_eq!(
            paths["preview_url"],
            "https://chat.example.com/api/v4/files/file123/preview"
        );
    }

    #[test]
    fn websocket_config_includes_authorization_header() {
        let client = MattermostClient::new(
            "https://chat.example.com",
            MattermostAuth::Token("tok".into()),
            Duration::from_secs(5),
        )
        .unwrap();

        let config = client.websocket_config().unwrap();
        assert_eq!(
            config.headers.get("authorization").map(String::as_str),
            Some("Bearer tok")
        );
    }

    #[test]
    fn websocket_config_uses_credential_id_header() {
        let client = MattermostClient::new(
            "https://chat.example.com",
            MattermostAuth::CredentialId("cred-work".into()),
            Duration::from_secs(5),
        )
        .unwrap();

        assert_eq!(client.auth_token(), None);
        let config = client.websocket_config().unwrap();
        assert_eq!(
            config.headers.get(CREDENTIAL_ID_HEADER).map(String::as_str),
            Some("cred-work")
        );
    }

    #[test]
    fn thread_url_uses_mattermost_query_parameter_names() {
        let client = MattermostClient::new(
            "https://chat.example.com",
            MattermostAuth::Token("tok".into()),
            Duration::from_secs(5),
        )
        .unwrap();
        let request = GetThreadRequest {
            post_id: "post123".into(),
            per_page: Some(25),
            from_post: Some("cursor456".into()),
            from_create_at: Some(17),
            from_update_at: Some(18),
            direction: Some("down".into()),
            skip_fetch_threads: Some(true),
            collapsed_threads: Some(true),
            collapsed_threads_extended: Some(false),
            updates_only: Some(true),
        };

        let url = client.thread_url(&request).unwrap().to_string();
        assert!(url.contains("/api/v4/posts/post123/thread?"));
        assert!(url.contains("perPage=25"));
        assert!(url.contains("fromPost=cursor456"));
        assert!(url.contains("fromCreateAt=17"));
        assert!(url.contains("fromUpdateAt=18"));
        assert!(url.contains("direction=down"));
        assert!(url.contains("skipFetchThreads=true"));
        assert!(url.contains("collapsedThreads=true"));
        assert!(url.contains("collapsedThreadsExtended=false"));
        assert!(url.contains("updatesOnly=true"));
    }

    #[test]
    fn thread_url_without_options_has_no_query_suffix() {
        let client = MattermostClient::new(
            "https://chat.example.com",
            MattermostAuth::Token("tok".into()),
            Duration::from_secs(5),
        )
        .unwrap();

        let url = client
            .thread_url(&GetThreadRequest {
                post_id: "post123".into(),
                ..GetThreadRequest::default()
            })
            .unwrap()
            .to_string();
        assert_eq!(url, "https://chat.example.com/api/v4/posts/post123/thread");
    }

    #[test]
    fn reaction_delete_url_percent_encodes_emoji_name() {
        let client = MattermostClient::new(
            "https://chat.example.com/base",
            MattermostAuth::Token("tok".into()),
            Duration::from_secs(5),
        )
        .unwrap();

        let url = client
            .reaction_delete_url(&DeleteReactionRequest {
                user_id: "user1".into(),
                post_id: "post1".into(),
                emoji_name: "+1".into(),
            })
            .unwrap();

        assert_eq!(
            url.as_str(),
            "https://chat.example.com/base/api/v4/users/user1/posts/post1/reactions/%2B1"
        );
    }

    #[test]
    fn non_empty_trimmed_filters_blank_values() {
        assert_eq!(non_empty_trimmed(None), None);
        assert_eq!(non_empty_trimmed(Some("   ")), None);
        assert_eq!(
            non_empty_trimmed(Some("  application/json  ")),
            Some("application/json".into())
        );
    }

    #[test]
    fn encode_path_segment_encodes_slashes_and_special_chars() {
        assert_eq!(encode_path_segment("safe-id_123"), "safe-id_123");
        assert_eq!(encode_path_segment("../etc/passwd"), "..%2Fetc%2Fpasswd");
        assert_eq!(encode_path_segment("id with spaces"), "id%20with%20spaces");
        assert_eq!(encode_path_segment("a/b"), "a%2Fb");
        assert_eq!(encode_path_segment("a?b=c&d=e"), "a%3Fb%3Dc%26d%3De");
    }

    #[test]
    fn file_access_paths_encodes_malicious_file_id() {
        let client = MattermostClient::new(
            "https://chat.example.com",
            MattermostAuth::Token("tok".into()),
            Duration::from_secs(5),
        )
        .unwrap();
        let paths = client.file_access_paths("../../../etc/passwd");
        assert_eq!(
            paths["download_url"],
            "https://chat.example.com/api/v4/files/..%2F..%2F..%2Fetc%2Fpasswd"
        );
        assert_eq!(
            paths["info_url"],
            "https://chat.example.com/api/v4/files/..%2F..%2F..%2Fetc%2Fpasswd/info"
        );
    }

    #[test]
    fn thread_url_encodes_post_id_with_slashes() {
        let client = MattermostClient::new(
            "https://chat.example.com",
            MattermostAuth::Token("tok".into()),
            Duration::from_secs(5),
        )
        .unwrap();
        let url = client
            .thread_url(&GetThreadRequest {
                post_id: "a/b".into(),
                ..GetThreadRequest::default()
            })
            .unwrap()
            .to_string();
        assert_eq!(url, "https://chat.example.com/api/v4/posts/a%2Fb/thread");
    }
}
