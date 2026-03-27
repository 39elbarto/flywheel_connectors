//! Microsoft Graph REST API client.
//!
//! Uses Bearer token auth and JSON bodies for POST/PUT/PATCH.
//! Handles OData pagination via `@odata.nextLink`.

use std::fmt;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use fcp_core::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, ConnectorRuntimeConfig, HttpRetryConfig, RetryLoop,
};
use reqwest::{Client, StatusCode, header};
use tracing::warn;

use crate::{
    error::{M365Error, M365Result},
    onenote::PageContentCommand,
    types::GraphListResponse,
};

pub const DEFAULT_API_URL: &str = "https://graph.microsoft.com/v1.0";

/// Authentication mode for Microsoft Graph access.
#[derive(Clone)]
pub enum M365Auth {
    /// Direct bearer access token.
    AccessToken(String),
    /// Secretless credential reference for egress proxy injection.
    CredentialId(CredentialId),
}

impl M365Auth {
    /// Render a redacted auth label for diagnostics/logging.
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::AccessToken(_) => "access_token:redacted".to_string(),
            Self::CredentialId(id) => {
                let id_str = id.to_string();
                let prefix = id_str.chars().take(8).collect::<String>();
                format!("credential_id:{prefix}…")
            }
        }
    }

    /// True when auth depends on credential injection.
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for M365Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessToken(_) => f.debug_tuple("AccessToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Microsoft Graph REST API client.
pub struct M365Client {
    http: Client,
    auth: M365Auth,
    api_url: String,
    max_retries: u32,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
}

impl M365Client {
    /// Create a new Graph API client with a Bearer access token.
    pub fn new(access_token: &str) -> M365Result<Self> {
        Self::new_with_auth(M365Auth::AccessToken(access_token.to_string()))
    }

    /// Create a new Graph API client with explicit auth mode.
    pub fn new_with_auth(auth: M365Auth) -> M365Result<Self> {
        let http = Client::builder()
            .user_agent("fcp-microsoft365/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(M365Error::Http)?;

        Ok(Self {
            http,
            auth,
            api_url: DEFAULT_API_URL.to_string(),
            max_retries: 2,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
        })
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    /// Set a custom API URL (for testing).
    #[must_use]
    pub fn with_api_url(mut self, url: &str) -> Self {
        self.api_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    fn build_api_url(&self, relative_path: &str) -> M365Result<String> {
        let base = format!("{}/", self.api_url.trim_end_matches('/'));
        let base_url = reqwest::Url::parse(&base)
            .map_err(|e| M365Error::InvalidConfig(format!("Invalid Graph base URL: {e}")))?;
        let url = base_url
            .join(relative_path.trim_start_matches('/'))
            .map_err(|e| M365Error::InvalidConfig(format!("Invalid Graph request path: {e}")))?;
        Ok(url.to_string())
    }

    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            M365Auth::AccessToken(token) => {
                request.header(header::AUTHORIZATION, format!("Bearer {token}"))
            }
            M365Auth::CredentialId(credential_id) => {
                request.header("X-FCP-Credential-ID", credential_id.to_string())
            }
        }
    }

    /// Perform a lightweight credential/readiness check against Graph.
    ///
    /// This first probes `/me` (delegated flows) and falls back to `/organization`
    /// for application-permission tokens that do not expose `/me`.
    pub async fn health_check(&self) -> M365Result<serde_json::Value> {
        let me_url = format!("{}/me?$select=id,userPrincipalName", self.api_url);
        match self.get(&me_url).await {
            Ok(payload) => Ok(payload),
            Err(primary_err) => {
                let can_fallback = matches!(
                    primary_err,
                    M365Error::Api {
                        status_code: Some(401 | 403),
                        ..
                    }
                );
                if !can_fallback {
                    return Err(primary_err);
                }

                let org_url = format!("{}/organization?$select=id,displayName", self.api_url);
                match self.get(&org_url).await {
                    Ok(payload) => Ok(payload),
                    Err(_) => Err(primary_err),
                }
            }
        }
    }

    // ── Mail operations ──────────────────────────────────────────

    /// List messages in a user's mailbox.
    pub async fn list_messages(
        &self,
        user_id: &str,
        folder_id: Option<&str>,
        top: Option<u32>,
        skip: Option<u32>,
        filter: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let folder_part = match folder_id {
            Some(f) => {
                sanitize_path_segment(f, "folder_id")?;
                format!("/mailFolders/{f}")
            }
            None => String::new(),
        };
        let mut url = self.build_api_url(&format!(
            "{}{folder_part}/messages",
            user_scope_path(user_id)?
        ))?;
        let mut params = Vec::new();
        if let Some(t) = top {
            params.push(format!("$top={t}"));
        }
        if let Some(s) = skip {
            params.push(format!("$skip={s}"));
        }
        if let Some(f) = filter {
            params.push(format!("$filter={f}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a specific message.
    pub async fn get_message(
        &self,
        user_id: &str,
        message_id: &str,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(message_id, "message_id")?;
        let url = self.build_api_url(&format!(
            "{}/messages/{message_id}",
            user_scope_path(user_id)?
        ))?;
        self.get(&url).await
    }

    /// Send a mail message.
    pub async fn send_message(&self, user_id: &str, message: &serde_json::Value) -> M365Result<()> {
        let url = self.build_api_url(&format!("{}/sendMail", user_scope_path(user_id)?))?;
        let body = serde_json::json!({ "message": message });
        self.post_json_no_content(&url, &body).await
    }

    /// Create a draft message.
    pub async fn create_draft(
        &self,
        user_id: &str,
        message: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = self.build_api_url(&format!("{}/messages", user_scope_path(user_id)?))?;
        self.post_json(&url, message).await
    }

    /// Search messages in a mailbox using Microsoft Graph `$search`.
    pub async fn search_messages(
        &self,
        user_id: &str,
        query: &str,
        top: Option<u32>,
        skip: Option<u32>,
    ) -> M365Result<GraphListResponse> {
        let base = self.build_api_url(&format!("{}/messages", user_scope_path(user_id)?))?;
        let mut url = reqwest::Url::parse(&base)
            .map_err(|e| M365Error::InvalidConfig(format!("Invalid Graph base URL: {e}")))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("$search", &format!("\"{query}\""));
            if let Some(t) = top {
                pairs.append_pair("$top", &t.to_string());
            }
            if let Some(s) = skip {
                pairs.append_pair("$skip", &s.to_string());
            }
        }

        let data = self
            .execute(|| {
                self.apply_auth(
                    self.http
                        .get(url.as_str())
                        .header("ConsistencyLevel", "eventual"),
                )
            })
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Reply to an existing message.
    pub async fn reply_message(
        &self,
        user_id: &str,
        message_id: &str,
        comment: Option<&str>,
        message: Option<&serde_json::Value>,
    ) -> M365Result<()> {
        sanitize_path_segment(message_id, "message_id")?;
        let url = self.build_api_url(&format!(
            "{}/messages/{message_id}/reply",
            user_scope_path(user_id)?
        ))?;
        let mut body = serde_json::Map::new();
        if let Some(comment) = comment {
            body.insert(
                "comment".into(),
                serde_json::Value::String(comment.to_string()),
            );
        }
        if let Some(message) = message {
            body.insert("message".into(), message.clone());
        }
        self.post_json_no_content(&url, &serde_json::Value::Object(body))
            .await
    }

    /// Forward an existing message.
    pub async fn forward_message(
        &self,
        user_id: &str,
        message_id: &str,
        comment: Option<&str>,
        to_recipients: &[serde_json::Value],
    ) -> M365Result<()> {
        sanitize_path_segment(message_id, "message_id")?;
        let url = self.build_api_url(&format!(
            "{}/messages/{message_id}/forward",
            user_scope_path(user_id)?
        ))?;
        let mut body = serde_json::Map::new();
        body.insert(
            "toRecipients".into(),
            serde_json::Value::Array(to_recipients.to_vec()),
        );
        if let Some(comment) = comment {
            body.insert(
                "comment".into(),
                serde_json::Value::String(comment.to_string()),
            );
        }
        self.post_json_no_content(&url, &serde_json::Value::Object(body))
            .await
    }

    /// List message attachments.
    pub async fn list_attachments(
        &self,
        user_id: &str,
        message_id: &str,
        top: Option<u32>,
        skip: Option<u32>,
    ) -> M365Result<GraphListResponse> {
        sanitize_path_segment(message_id, "message_id")?;
        let mut url = self.build_api_url(&format!(
            "{}/messages/{message_id}/attachments",
            user_scope_path(user_id)?
        ))?;
        let mut params = Vec::new();
        if let Some(t) = top {
            params.push(format!("$top={t}"));
        }
        if let Some(s) = skip {
            params.push(format!("$skip={s}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Add an attachment to an existing message.
    pub async fn add_attachment(
        &self,
        user_id: &str,
        message_id: &str,
        attachment: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(message_id, "message_id")?;
        let url = self.build_api_url(&format!(
            "{}/messages/{message_id}/attachments",
            user_scope_path(user_id)?
        ))?;
        self.post_json(&url, attachment).await
    }

    // ── Files operations ─────────────────────────────────────────

    /// List files and folders in OneDrive.
    pub async fn list_items(
        &self,
        user_id: &str,
        path: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let user_scope = user_scope_path(user_id)?;
        let url = match path {
            Some(p) if !p.is_empty() => {
                let normalized_path = p.trim_matches('/');
                if normalized_path.is_empty() {
                    self.build_api_url(&format!("{user_scope}/drive/root/children"))?
                } else {
                    self.build_api_url(&format!(
                        "{user_scope}/drive/root:/{normalized_path}:/children"
                    ))?
                }
            }
            _ => self.build_api_url(&format!("{user_scope}/drive/root/children"))?,
        };
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Download a file from OneDrive. Returns base64-encoded content.
    pub async fn download_file(
        &self,
        user_id: &str,
        item_id: &str,
    ) -> M365Result<(String, serde_json::Value)> {
        let (bytes, metadata) = self.download_file_raw(user_id, item_id).await?;
        let content = BASE64.encode(&bytes);
        Ok((content, metadata))
    }

    /// Download a file from OneDrive and return the raw bytes plus metadata.
    pub async fn download_file_raw(
        &self,
        user_id: &str,
        item_id: &str,
    ) -> M365Result<(Vec<u8>, serde_json::Value)> {
        self.download_drive_item_bytes(user_id, item_id, None).await
    }

    /// Download a drive item converted into another format (for example PDF).
    pub async fn download_file_as(
        &self,
        user_id: &str,
        item_id: &str,
        format: &str,
    ) -> M365Result<(Vec<u8>, serde_json::Value)> {
        self.download_drive_item_bytes(user_id, item_id, Some(format))
            .await
    }

    /// Upload a file to OneDrive (simple upload, up to 4 MB).
    pub async fn upload_file(
        &self,
        user_id: &str,
        path: &str,
        content: &[u8],
    ) -> M365Result<serde_json::Value> {
        let normalized_path = normalize_drive_root_path(path)?;
        let url = self.build_api_url(&format!(
            "{}/drive/root:/{normalized_path}:/content",
            user_scope_path(user_id)?
        ))?;
        self.put_bytes(&url, content).await
    }

    /// Delete a drive item.
    pub async fn delete_item(&self, user_id: &str, item_id: &str) -> M365Result<()> {
        sanitize_path_segment(item_id, "item_id")?;
        let url = self.build_api_url(&format!(
            "{}/drive/items/{item_id}",
            user_scope_path(user_id)?
        ))?;
        self.delete_no_content(&url).await
    }

    /// Get metadata for a single drive item by ID.
    pub async fn get_item(&self, user_id: &str, item_id: &str) -> M365Result<serde_json::Value> {
        sanitize_path_segment(item_id, "item_id")?;
        let url = self.build_api_url(&format!(
            "{}/drive/items/{item_id}",
            user_scope_path(user_id)?
        ))?;
        self.get(&url).await
    }

    /// Search for files and folders in OneDrive.
    pub async fn search_files(&self, user_id: &str, query: &str) -> M365Result<GraphListResponse> {
        let encoded =
            percent_encoding::utf8_percent_encode(query, percent_encoding::NON_ALPHANUMERIC);
        let url = self.build_api_url(&format!(
            "{}/drive/root/search(q='{encoded}')",
            user_scope_path(user_id)?
        ))?;
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a sharing link for a drive item.
    pub async fn create_share_link(
        &self,
        user_id: &str,
        item_id: &str,
        link_type: &str,
        scope: Option<&str>,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(item_id, "item_id")?;
        let url = self.build_api_url(&format!(
            "{}/drive/items/{item_id}/createLink",
            user_scope_path(user_id)?
        ))?;
        let mut body = serde_json::json!({ "type": link_type });
        if let Some(s) = scope {
            body["scope"] = serde_json::Value::String(s.to_string());
        }
        self.post_json(&url, &body).await
    }

    /// Replace the contents of an existing drive item.
    pub async fn update_item_content(
        &self,
        user_id: &str,
        item_id: &str,
        content: &[u8],
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(item_id, "item_id")?;
        let url = self.build_api_url(&format!(
            "{}/drive/items/{item_id}/content",
            user_scope_path(user_id)?
        ))?;
        self.put_bytes(&url, content).await
    }

    // ── Calendar operations ──────────────────────────────────────

    /// List calendar events within a time range.
    pub async fn list_events(
        &self,
        user_id: &str,
        start_datetime: Option<&str>,
        end_datetime: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let user_scope = user_scope_path(user_id)?;
        let url = match (start_datetime, end_datetime) {
            (Some(start), Some(end)) => {
                let mut url = reqwest::Url::parse(
                    &self.build_api_url(&format!("{user_scope}/calendarView"))?,
                )
                .map_err(|e| M365Error::InvalidConfig(format!("Invalid calendarView URL: {e}")))?;
                {
                    let mut pairs = url.query_pairs_mut();
                    pairs.append_pair("startDateTime", start);
                    pairs.append_pair("endDateTime", end);
                }
                url.to_string()
            }
            _ => self.build_api_url(&format!("{user_scope}/events"))?,
        };
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a calendar event.
    pub async fn create_event(
        &self,
        user_id: &str,
        event: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = self.build_api_url(&format!("{}/events", user_scope_path(user_id)?))?;
        self.post_json(&url, event).await
    }

    /// Delete a calendar event.
    pub async fn delete_event(&self, user_id: &str, event_id: &str) -> M365Result<()> {
        sanitize_path_segment(event_id, "event_id")?;
        let url =
            self.build_api_url(&format!("{}/events/{event_id}", user_scope_path(user_id)?))?;
        self.delete_no_content(&url).await
    }

    /// Get a single calendar event by ID.
    pub async fn get_event(&self, user_id: &str, event_id: &str) -> M365Result<serde_json::Value> {
        sanitize_path_segment(event_id, "event_id")?;
        let url =
            self.build_api_url(&format!("{}/events/{event_id}", user_scope_path(user_id)?))?;
        self.get(&url).await
    }

    /// Update an existing calendar event (PATCH).
    pub async fn update_event(
        &self,
        user_id: &str,
        event_id: &str,
        updates: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(event_id, "event_id")?;
        let url =
            self.build_api_url(&format!("{}/events/{event_id}", user_scope_path(user_id)?))?;
        self.patch_json(&url, updates).await
    }

    /// Get free/busy schedule for users.
    pub async fn get_freebusy(
        &self,
        schedules: &[String],
        start_time: &serde_json::Value,
        end_time: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = format!("{}/me/calendar/getSchedule", self.api_url);
        let body = serde_json::json!({
            "schedules": schedules,
            "startTime": start_time,
            "endTime": end_time,
        });
        self.post_json(&url, &body).await
    }

    // ── Tasks operations ─────────────────────────────────────────

    /// List all To Do task lists.
    pub async fn list_task_lists(&self, user_id: &str) -> M365Result<GraphListResponse> {
        let url = self.build_api_url(&format!("{}/todo/lists", user_scope_path(user_id)?))?;
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List tasks in a To Do list.
    pub async fn list_tasks(&self, user_id: &str, list_id: &str) -> M365Result<GraphListResponse> {
        sanitize_path_segment(list_id, "list_id")?;
        let url = self.build_api_url(&format!(
            "{}/todo/lists/{list_id}/tasks",
            user_scope_path(user_id)?
        ))?;
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Create a task in a To Do list.
    pub async fn create_task(
        &self,
        user_id: &str,
        list_id: &str,
        task: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(list_id, "list_id")?;
        let url = self.build_api_url(&format!(
            "{}/todo/lists/{list_id}/tasks",
            user_scope_path(user_id)?
        ))?;
        self.post_json(&url, task).await
    }

    // ── OneNote operations ───────────────────────────────────────

    /// List OneNote notebooks for a user.
    pub async fn list_notebooks(
        &self,
        user_id: &str,
        top: Option<u32>,
    ) -> M365Result<GraphListResponse> {
        let mut url =
            self.build_api_url(&format!("{}/onenote/notebooks", user_scope_path(user_id)?))?;
        if let Some(top) = top {
            url = format!("{url}?$top={top}");
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List OneNote sections for a user, optionally scoped to a notebook or section group.
    pub async fn list_sections(
        &self,
        user_id: &str,
        notebook_id: Option<&str>,
        section_group_id: Option<&str>,
        top: Option<u32>,
    ) -> M365Result<GraphListResponse> {
        let user_scope = user_scope_path(user_id)?;
        let mut url = if let Some(notebook_id) = notebook_id {
            sanitize_path_segment(notebook_id, "notebook_id")?;
            self.build_api_url(&format!(
                "{user_scope}/onenote/notebooks/{notebook_id}/sections"
            ))?
        } else if let Some(section_group_id) = section_group_id {
            sanitize_path_segment(section_group_id, "section_group_id")?;
            self.build_api_url(&format!(
                "{user_scope}/onenote/sectionGroups/{section_group_id}/sections"
            ))?
        } else {
            self.build_api_url(&format!("{user_scope}/onenote/sections"))?
        };

        if let Some(top) = top {
            url = format!("{url}?$top={top}");
        }

        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List OneNote pages in a section.
    pub async fn list_pages(
        &self,
        user_id: &str,
        section_id: &str,
        top: Option<u32>,
    ) -> M365Result<GraphListResponse> {
        sanitize_path_segment(section_id, "section_id")?;
        let mut url = self.build_api_url(&format!(
            "{}/onenote/sections/{section_id}/pages",
            user_scope_path(user_id)?
        ))?;
        if let Some(top) = top {
            url = format!("{url}?$top={top}");
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get OneNote page metadata by page ID.
    pub async fn get_page(&self, user_id: &str, page_id: &str) -> M365Result<serde_json::Value> {
        sanitize_path_segment(page_id, "page_id")?;
        let url = self.build_api_url(&format!(
            "{}/onenote/pages/{page_id}",
            user_scope_path(user_id)?
        ))?;
        self.get(&url).await
    }

    /// Fetch raw HTML content for a OneNote page.
    pub async fn get_page_content(
        &self,
        user_id: &str,
        page_id: &str,
        include_ids: bool,
    ) -> M365Result<String> {
        sanitize_path_segment(page_id, "page_id")?;
        let mut url = reqwest::Url::parse(&self.build_api_url(&format!(
            "{}/onenote/pages/{page_id}/content",
            user_scope_path(user_id)?
        ))?)
        .map_err(|error| {
            M365Error::InvalidConfig(format!("Invalid OneNote content URL: {error}"))
        })?;
        if include_ids {
            url.query_pairs_mut().append_pair("includeIDs", "true");
        }
        self.get_text(url.as_str()).await
    }

    /// Create a OneNote page from HTML content.
    pub async fn create_page(
        &self,
        user_id: &str,
        section_id: &str,
        html: &str,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(section_id, "section_id")?;
        let url = self.build_api_url(&format!(
            "{}/onenote/sections/{section_id}/pages",
            user_scope_path(user_id)?
        ))?;
        self.post_html(&url, html).await
    }

    /// Update a OneNote page using Graph content commands.
    pub async fn update_page(
        &self,
        user_id: &str,
        page_id: &str,
        commands: &[PageContentCommand],
    ) -> M365Result<()> {
        sanitize_path_segment(page_id, "page_id")?;
        let body = serde_json::to_value(commands)?;
        let url = self.build_api_url(&format!(
            "{}/onenote/pages/{page_id}/content",
            user_scope_path(user_id)?
        ))?;
        self.patch_json_no_content(&url, &body).await
    }

    // ── Subscription operations ──────────────────────────────────

    /// Create a webhook subscription.
    pub async fn create_subscription(
        &self,
        subscription: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        let url = format!("{}/subscriptions", self.api_url);
        self.post_json(&url, subscription).await
    }

    /// Renew a webhook subscription.
    pub async fn renew_subscription(
        &self,
        subscription_id: &str,
        expiration_datetime: &str,
    ) -> M365Result<serde_json::Value> {
        sanitize_path_segment(subscription_id, "subscription_id")?;
        let url = format!("{}/subscriptions/{subscription_id}", self.api_url);
        let body = serde_json::json!({
            "expirationDateTime": expiration_datetime,
        });
        self.patch_json(&url, &body).await
    }

    /// Delete a webhook subscription.
    pub async fn delete_subscription(&self, subscription_id: &str) -> M365Result<()> {
        sanitize_path_segment(subscription_id, "subscription_id")?;
        let url = format!("{}/subscriptions/{subscription_id}", self.api_url);
        self.delete_no_content(&url).await
    }

    // ── Delta operations ─────────────────────────────────────────

    /// Perform a delta query for incremental sync.
    pub async fn delta_sync(
        &self,
        resource: &str,
        delta_token: Option<&str>,
    ) -> M365Result<GraphListResponse> {
        let delta_path = format!("{}/delta", resource.trim_end_matches('/'));
        let mut url = reqwest::Url::parse(&self.build_api_url(&delta_path)?)
            .map_err(|e| M365Error::InvalidConfig(format!("Invalid delta URL: {e}")))?;
        if let Some(token) = delta_token {
            url.query_pairs_mut().append_pair("$deltatoken", token);
        }

        // Follow all pages to collect all changes
        let mut all_values = Vec::new();
        let mut current_url = url.to_string();
        let mut final_delta_link;

        loop {
            let data = self.get(&current_url).await?;
            let page: GraphListResponse = serde_json::from_value(data)?;
            all_values.extend(page.value);
            final_delta_link = page.delta_link.clone();

            if let Some(next) = page.next_link {
                current_url = next;
            } else {
                break;
            }
        }

        Ok(GraphListResponse {
            value: all_values,
            next_link: None,
            delta_link: final_delta_link,
        })
    }

    // ── HTTP helpers ─────────────────────────────────────────────

    async fn get(&self, url: &str) -> M365Result<serde_json::Value> {
        self.execute(|| self.apply_auth(self.http.get(url))).await
    }

    async fn get_bytes(&self, url: &str) -> M365Result<Vec<u8>> {
        self.execute_bytes(|| self.apply_auth(self.http.get(url)))
            .await
    }

    async fn download_drive_item_bytes(
        &self,
        user_id: &str,
        item_id: &str,
        format: Option<&str>,
    ) -> M365Result<(Vec<u8>, serde_json::Value)> {
        sanitize_path_segment(item_id, "item_id")?;
        let user_scope = user_scope_path(user_id)?;
        let meta_url = self.build_api_url(&format!("{user_scope}/drive/items/{item_id}"))?;
        let metadata = self.get(&meta_url).await?;

        let content_url = match format {
            Some(format) => self.build_api_url(&format!(
                "{user_scope}/drive/items/{item_id}/content?format={format}"
            ))?,
            None => self.build_api_url(&format!("{user_scope}/drive/items/{item_id}/content"))?,
        };
        let bytes = self.get_bytes(&content_url).await?;
        Ok((bytes, metadata))
    }

    async fn get_text(&self, url: &str) -> M365Result<String> {
        self.execute_text(|| self.apply_auth(self.http.get(url)))
            .await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        self.execute(|| self.apply_auth(self.http.post(url).json(body)))
            .await
    }

    async fn post_json_no_content(&self, url: &str, body: &serde_json::Value) -> M365Result<()> {
        self.execute_no_content(|| self.apply_auth(self.http.post(url).json(body)))
            .await
    }

    async fn post_html(&self, url: &str, html: &str) -> M365Result<serde_json::Value> {
        let html = html.to_string();
        self.execute(|| {
            self.apply_auth(
                self.http
                    .post(url)
                    .header(header::ACCEPT, "application/json")
                    .header(header::CONTENT_TYPE, "text/html")
                    .body(html.clone()),
            )
        })
        .await
    }

    async fn patch_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> M365Result<serde_json::Value> {
        self.execute(|| self.apply_auth(self.http.patch(url).json(body)))
            .await
    }

    async fn patch_json_no_content(&self, url: &str, body: &serde_json::Value) -> M365Result<()> {
        self.execute_no_content(|| self.apply_auth(self.http.patch(url).json(body)))
            .await
    }

    async fn put_bytes(&self, url: &str, content: &[u8]) -> M365Result<serde_json::Value> {
        let content = content.to_vec();
        self.execute(|| {
            self.apply_auth(
                self.http
                    .put(url)
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(content.clone()),
            )
        })
        .await
    }

    async fn delete_no_content(&self, url: &str) -> M365Result<()> {
        self.execute_no_content(|| self.apply_auth(self.http.delete(url)))
            .await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> M365Result<serde_json::Value> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let build_request = &build_request;

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => return AttemptOutcome::Terminal(err),
                        ErrorAction::Retry(err) => {
                            return AttemptOutcome::Retryable {
                                retry_after: err.retry_after(),
                                error: err,
                            };
                        }
                        ErrorAction::Success => {}
                    }

                    match response.text().await {
                        Ok(body) => match serde_json::from_str(&body) {
                            Ok(data) => AttemptOutcome::Success(data),
                            Err(e) => AttemptOutcome::Terminal(M365Error::from(e)),
                        },
                        Err(e) => AttemptOutcome::Terminal(M365Error::Http(e)),
                    }
                }
                Err(e) => AttemptOutcome::Retryable {
                    retry_after: None,
                    error: M365Error::Http(e),
                },
            }
        })
        .await
    }

    async fn execute_bytes(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> M365Result<Vec<u8>> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let build_request = &build_request;

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => return AttemptOutcome::Terminal(err),
                        ErrorAction::Retry(err) => {
                            return AttemptOutcome::Retryable {
                                retry_after: err.retry_after(),
                                error: err,
                            };
                        }
                        ErrorAction::Success => {}
                    }

                    match response.bytes().await {
                        Ok(bytes) => AttemptOutcome::Success(bytes.to_vec()),
                        Err(e) => AttemptOutcome::Terminal(M365Error::Http(e)),
                    }
                }
                Err(e) => AttemptOutcome::Retryable {
                    retry_after: None,
                    error: M365Error::Http(e),
                },
            }
        })
        .await
    }

    async fn execute_text(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> M365Result<String> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let build_request = &build_request;

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => return AttemptOutcome::Terminal(err),
                        ErrorAction::Retry(err) => {
                            return AttemptOutcome::Retryable {
                                retry_after: err.retry_after(),
                                error: err,
                            };
                        }
                        ErrorAction::Success => {}
                    }

                    match response.text().await {
                        Ok(body) => AttemptOutcome::Success(body),
                        Err(e) => AttemptOutcome::Terminal(M365Error::Http(e)),
                    }
                }
                Err(e) => AttemptOutcome::Retryable {
                    retry_after: None,
                    error: M365Error::Http(e),
                },
            }
        })
        .await
    }

    async fn execute_no_content(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> M365Result<()> {
        let ctx = self.runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let build_request = &build_request;

        RetryLoop::execute(&ctx, &policy, |attempt| async move {
            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    match self.handle_error_status(status, &response, attempt).await {
                        ErrorAction::Return(err) => AttemptOutcome::Terminal(err),
                        ErrorAction::Retry(err) => AttemptOutcome::Retryable {
                            retry_after: err.retry_after(),
                            error: err,
                        },
                        ErrorAction::Success => AttemptOutcome::Success(()),
                    }
                }
                Err(e) => AttemptOutcome::Retryable {
                    retry_after: None,
                    error: M365Error::Http(e),
                },
            }
        })
        .await
    }

    async fn handle_error_status(
        &self,
        status: StatusCode,
        response: &reqwest::Response,
        attempt: u32,
    ) -> ErrorAction {
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return ErrorAction::Return(M365Error::Api {
                message: format!("Authentication failed: HTTP {status}"),
                status_code: Some(status.as_u16()),
                error_code: None,
            });
        }

        if status == StatusCode::NOT_FOUND {
            return ErrorAction::Return(M365Error::Api {
                message: format!("Resource not found: HTTP {status}"),
                status_code: Some(404),
                error_code: Some("NotFound".into()),
            });
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map_or(60_000, |s| s * 1000);

            let err = M365Error::RateLimit {
                retry_after_ms: retry_after,
            };
            if attempt < self.max_retries {
                warn!(attempt, "rate limited, will retry");
                return ErrorAction::Retry(err);
            }
            return ErrorAction::Return(err);
        }

        if status.is_server_error() {
            let err = M365Error::Api {
                message: format!("Server error: HTTP {status}"),
                status_code: Some(status.as_u16()),
                error_code: None,
            };
            if attempt < self.max_retries {
                warn!(attempt, status = %status, "server error, will retry");
                return ErrorAction::Retry(err);
            }
            return ErrorAction::Return(err);
        }

        if !status.is_success() && status != StatusCode::NO_CONTENT {
            return ErrorAction::Return(M365Error::Api {
                message: format!("HTTP {status}"),
                status_code: Some(status.as_u16()),
                error_code: None,
            });
        }

        ErrorAction::Success
    }
}

fn normalize_drive_root_path(path: &str) -> M365Result<&str> {
    let normalized = path.trim_matches('/');
    if normalized.is_empty() {
        return Err(M365Error::InvalidConfig(
            "path must not be empty or root-only".into(),
        ));
    }
    Ok(normalized)
}

/// Reject path-segment values that contain traversal characters.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> M365Result<&'a str> {
    if value.trim().is_empty() {
        return Err(M365Error::InvalidConfig(format!(
            "{field} must not be empty"
        )));
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(M365Error::InvalidConfig(format!(
            "{field} contains path traversal characters"
        )));
    }
    Ok(value)
}

fn user_scope_path(user_id: &str) -> M365Result<String> {
    if user_id.eq_ignore_ascii_case("me") {
        Ok("me".to_string())
    } else {
        // user_id can be an email address (alice@contoso.com) which is safe,
        // but must not contain path traversal characters.
        sanitize_path_segment(user_id, "user_id")?;
        Ok(format!("users/{user_id}"))
    }
}

enum ErrorAction {
    Return(M365Error),
    Retry(M365Error),
    Success,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header, method, path, query_param},
    };

    #[fcp_async_core::runtime::test]
    async fn test_list_messages() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "msg_1", "subject": "Hello" },
                    { "id": "msg_2", "subject": "World" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client
            .list_messages("me", None, None, None, None)
            .await
            .unwrap();
        assert_eq!(result.value.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_messages_explicit_user_keeps_users_prefix() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/users/alice@contoso.com/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "msg_9", "subject": "Hello Alice" }]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client
            .list_messages("alice@contoso.com", None, None, None, None)
            .await
            .unwrap();
        assert_eq!(result.value.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_message() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/messages/msg_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "msg_123",
                "subject": "Test Message"
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client.get_message("me", "msg_123").await.unwrap();
        assert_eq!(result["id"], "msg_123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/me/sendMail"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let message = serde_json::json!({
            "subject": "Hello",
            "body": { "contentType": "Text", "content": "Hi" },
            "toRecipients": [{ "emailAddress": { "address": "bob@contoso.com" } }]
        });

        client.send_message("me", &message).await.unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_search_messages() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/messages"))
            .and(query_param("$search", "\"project status\""))
            .and(query_param("$top", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "msg_1", "subject": "Project status" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());
        let result = client
            .search_messages("me", "project status", Some(10), None)
            .await
            .unwrap();
        assert_eq!(result.value.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_reply_message() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/me/messages/msg_123/reply"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());
        client
            .reply_message("me", "msg_123", Some("Thanks!"), None)
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_delta_sync_urlencodes_delta_token() {
        let mock_server = MockServer::start().await;
        let delta_token = "opaque/with?reserved=1&two";

        Mock::given(method("GET"))
            .and(path("/me/messages/delta"))
            .and(query_param("$deltatoken", delta_token))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "msg_1" }],
                "@odata.deltaLink": "https://graph.microsoft.com/v1.0/me/messages/delta?$deltatoken=next-token"
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client
            .delta_sync("/me/messages", Some(delta_token))
            .await
            .unwrap();

        assert_eq!(result.value.len(), 1);
        assert_eq!(
            result.delta_link.as_deref(),
            Some("https://graph.microsoft.com/v1.0/me/messages/delta?$deltatoken=next-token")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_forward_message() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/me/messages/msg_123/forward"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());
        let recipients = vec![serde_json::json!({
            "emailAddress": { "address": "alice@contoso.com" }
        })];
        client
            .forward_message("me", "msg_123", Some("FYI"), &recipients)
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_attachments() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/messages/msg_123/attachments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "att_1", "name": "report.pdf" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());
        let result = client
            .list_attachments("me", "msg_123", None, None)
            .await
            .unwrap();
        assert_eq!(result.value.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_add_attachment() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/me/messages/msg_123/attachments"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "att_1",
                "name": "report.pdf"
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());
        let attachment = serde_json::json!({
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": "report.pdf",
            "contentType": "application/pdf",
            "contentBytes": "dGVzdA=="
        });
        let result = client
            .add_attachment("me", "msg_123", &attachment)
            .await
            .unwrap();
        assert_eq!(result["id"], "att_1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_items() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/drive/root/children"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "item_1", "name": "Documents", "folder": { "childCount": 5 } },
                    { "id": "item_2", "name": "photo.jpg", "file": { "mimeType": "image/jpeg" } }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client.list_items("me", None).await.unwrap();
        assert_eq!(result.value.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_items_normalizes_and_encodes_path() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/drive/root:/Shared%20Documents:/children"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "item_1", "name": "Quarterly Report.docx" }]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client
            .list_items("me", Some("/Shared Documents/"))
            .await
            .unwrap();
        assert_eq!(result.value.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_download_file_as_pdf() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/drive/items/doc-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "doc-1",
                "name": "Quarterly Report.docx",
                "size": 5120
            })))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/me/drive/items/doc-1/content"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"%PDF-test".to_vec()))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let (content, metadata) = client.download_file_as("me", "doc-1", "pdf").await.unwrap();
        assert_eq!(content, b"%PDF-test".to_vec());
        assert_eq!(metadata["name"], "Quarterly Report.docx");
    }

    #[fcp_async_core::runtime::test]
    async fn test_update_item_content() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path("/me/drive/items/doc-1/content"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "doc-1",
                "name": "Updated Report.docx",
                "size": 1280
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let item = client
            .update_item_content("me", "doc-1", b"updated content")
            .await
            .unwrap();
        assert_eq!(item["name"], "Updated Report.docx");
    }

    #[fcp_async_core::runtime::test]
    async fn test_upload_file_normalizes_and_encodes_path() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PUT"))
            .and(path(
                "/me/drive/root:/Documents/Meeting%20Notes.docx:/content",
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "doc-9",
                "name": "Meeting Notes.docx",
                "size": 1024
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let item = client
            .upload_file("me", "/Documents/Meeting Notes.docx", b"payload")
            .await
            .unwrap();
        assert_eq!(item["name"], "Meeting Notes.docx");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_events() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "evt_1", "subject": "Standup" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client.list_events("me", None, None).await.unwrap();
        assert_eq!(result.value.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_task_lists() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/todo/lists"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "list_1", "displayName": "Tasks" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let result = client.list_task_lists("me").await.unwrap();
        assert_eq!(result.value.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_notebooks() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/onenote/notebooks"))
            .and(query_param("$top", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "notebook_1", "displayName": "Engineering" }
                ]
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());
        let result = client.list_notebooks("me", Some(10)).await.unwrap();
        assert_eq!(result.value.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_page_content() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/onenote/pages/page_123/content"))
            .and(query_param("includeIDs", "true"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html><body><p>Hello OneNote</p></body></html>"),
            )
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());
        let result = client
            .get_page_content("me", "page_123", true)
            .await
            .unwrap();
        assert!(result.contains("Hello OneNote"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_page() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/me/onenote/sections/section_123/pages"))
            .and(header("content-type", "text/html"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "page_123",
                "title": "Daily Notes"
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());
        let result = client
            .create_page(
                "me",
                "section_123",
                "<html><body><p>Daily Notes</p></body></html>",
            )
            .await
            .unwrap();
        assert_eq!(result["id"], "page_123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_update_page() {
        let mock_server = MockServer::start().await;

        Mock::given(method("PATCH"))
            .and(path("/me/onenote/pages/page_123/content"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());
        let commands = vec![PageContentCommand {
            target: "body".into(),
            action: "append".into(),
            position: None,
            content: Some("<p>Follow-up</p>".into()),
        }];
        client
            .update_page("me", "page_123", &commands)
            .await
            .unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_subscription() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/subscriptions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "sub_123",
                "resource": "/me/messages",
                "changeType": "created",
                "expirationDateTime": "2026-03-04T00:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        let sub = serde_json::json!({
            "changeType": "created",
            "notificationUrl": "https://webhook.example.com",
            "resource": "/me/messages",
            "expirationDateTime": "2026-03-04T00:00:00Z"
        });

        let result = client.create_subscription(&sub).await.unwrap();
        assert_eq!(result["id"], "sub_123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/messages"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("bad_token")
            .unwrap()
            .with_api_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.list_messages("me", None, None, None, None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            M365Error::Api { status_code, .. } => assert_eq!(status_code, Some(401)),
            e => panic!("Expected Api error with 401, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/messages/nonexistent"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.get_message("me", "nonexistent").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            M365Error::Api { status_code, .. } => assert_eq!(status_code, Some(404)),
            e => panic!("Expected Api error with 404, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/me/messages"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.list_messages("me", None, None, None, None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), M365Error::RateLimit { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_check_with_credential_id_header() {
        let mock_server = MockServer::start().await;
        let credential_id = CredentialId::parse("11223344-5566-7788-99aa-bbccddeeff00").unwrap();

        Mock::given(method("GET"))
            .and(path("/me"))
            .and(header("x-fcp-credential-id", credential_id.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "user-1",
                "userPrincipalName": "user@contoso.com"
            })))
            .mount(&mock_server)
            .await;

        let client = M365Client::new_with_auth(M365Auth::CredentialId(credential_id))
            .unwrap()
            .with_api_url(&mock_server.uri());
        let payload = client.health_check().await.unwrap();
        assert_eq!(payload["id"], "user-1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_delete_event() {
        let mock_server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/me/events/evt_123"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock_server)
            .await;

        let client = M365Client::new("test_token")
            .unwrap()
            .with_api_url(&mock_server.uri());

        client.delete_event("me", "evt_123").await.unwrap();
    }

    #[test]
    fn test_error_is_retryable() {
        let err = M365Error::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = M365Error::InvalidConfig("bad".into());
        assert!(!err.is_retryable());

        let err = M365Error::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert!(err.is_retryable());
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "user_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "user_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "user_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "user_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "user_id").is_err());
        assert!(sanitize_path_segment("", "user_id").is_err());
        assert!(sanitize_path_segment("  ", "user_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(
            sanitize_path_segment("msg_123", "message_id").unwrap(),
            "msg_123"
        );
        assert_eq!(
            sanitize_path_segment("alice@contoso.com", "user_id").unwrap(),
            "alice@contoso.com"
        );
    }

    #[test]
    fn user_scope_path_me_shortcut() {
        assert_eq!(user_scope_path("me").unwrap(), "me");
        assert_eq!(user_scope_path("ME").unwrap(), "me");
        assert_eq!(user_scope_path("Me").unwrap(), "me");
    }

    #[test]
    fn user_scope_path_rejects_traversal() {
        assert!(user_scope_path("../admin").is_err());
        assert!(user_scope_path("user/evil").is_err());
    }
}
