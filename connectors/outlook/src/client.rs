//! Microsoft Graph API client for Outlook operations.

use reqwest::Client;
use serde_json::{Value, json};

use crate::error::{OutlookError, OutlookResult};
use crate::types::OutlookConfig;

const GRAPH_API_VERSION: &str = "v1.0";

#[derive(Debug, Clone)]
pub struct OutlookClient {
    client: Client,
    base_url: String,
    access_token: String,
}

impl OutlookClient {
    pub fn from_config(config: &OutlookConfig) -> OutlookResult<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_millis(config.request_timeout_ms))
            .build()?;
        Ok(Self {
            client,
            base_url: format!("{}/{GRAPH_API_VERSION}", config.base_url()),
            access_token: config.access_token.clone(),
        })
    }

    fn sanitize_id(id: &str) -> OutlookResult<&str> {
        if id.contains('/') || id.contains('\\') || id.contains("..") {
            return Err(OutlookError::Config(
                "ID contains invalid path characters".into(),
            ));
        }
        Ok(id)
    }

    async fn graph_get(&self, path: &str) -> OutlookResult<Value> {
        let url = format!("{}{path}", self.base_url);
        let response = self
            .client
            .get(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await?;
        self.handle_response(response).await
    }

    async fn graph_post(&self, path: &str, body: &Value) -> OutlookResult<Value> {
        let url = format!("{}{path}", self.base_url);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&self.access_token)
            .json(body)
            .send()
            .await?;
        self.handle_response(response).await
    }

    async fn handle_response(&self, response: reqwest::Response) -> OutlookResult<Value> {
        let status = response.status();
        if status.is_success() {
            if status == reqwest::StatusCode::NO_CONTENT {
                return Ok(json!({ "status": "ok" }));
            }
            let body: Value = response.json().await.unwrap_or(json!({"status": "ok"}));
            return Ok(body);
        }
        if status == reqwest::StatusCode::UNAUTHORIZED {
            let body = response.text().await.unwrap_or_default();
            return Err(OutlookError::Unauthorized(body));
        }
        if status == reqwest::StatusCode::NOT_FOUND {
            let body = response.text().await.unwrap_or_default();
            return Err(OutlookError::NotFound(body));
        }
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(|s| s * 1000)
                .unwrap_or(60_000);
            return Err(OutlookError::RateLimited {
                retry_after_ms: retry_after,
            });
        }
        let body = response.text().await.unwrap_or_default();
        Err(OutlookError::Api {
            status_code: status.as_u16(),
            message: body,
        })
    }

    // --- Mail operations ---

    pub async fn list_messages(
        &self,
        folder_id: Option<&str>,
        top: Option<u32>,
    ) -> OutlookResult<Value> {
        let folder = folder_id.unwrap_or("inbox");
        let sanitized = Self::sanitize_id(folder)?;
        let limit = top.unwrap_or(25).min(100);
        let path = format!(
            "/me/mailFolders/{sanitized}/messages?$top={limit}&$orderby=receivedDateTime%20desc&$select=id,subject,from,receivedDateTime,isRead,bodyPreview"
        );
        self.graph_get(&path).await
    }

    pub async fn get_message(&self, message_id: &str) -> OutlookResult<Value> {
        let sanitized = Self::sanitize_id(message_id)?;
        let path = format!("/me/messages/{sanitized}?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,isRead,body,hasAttachments");
        self.graph_get(&path).await
    }

    pub async fn search_messages(&self, query: &str, top: Option<u32>) -> OutlookResult<Value> {
        if query.trim().is_empty() {
            return Err(OutlookError::Config("query must not be empty".into()));
        }
        let limit = top.unwrap_or(25).min(100);
        let encoded_query = url::form_urlencoded::byte_serialize(query.as_bytes()).collect::<String>();
        let path = format!(
            "/me/messages?$search=\"{encoded_query}\"&$top={limit}&$select=id,subject,from,receivedDateTime,bodyPreview"
        );
        self.graph_get(&path).await
    }

    pub async fn send_message(
        &self,
        to: &[String],
        subject: &str,
        body: &str,
        cc: &[String],
    ) -> OutlookResult<Value> {
        if to.is_empty() {
            return Err(OutlookError::Config(
                "at least one recipient is required".into(),
            ));
        }
        let to_recipients: Vec<Value> = to
            .iter()
            .map(|addr| {
                json!({
                    "emailAddress": { "address": addr }
                })
            })
            .collect();
        let cc_recipients: Vec<Value> = cc
            .iter()
            .map(|addr| {
                json!({
                    "emailAddress": { "address": addr }
                })
            })
            .collect();
        let message = json!({
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "Text",
                    "content": body
                },
                "toRecipients": to_recipients,
                "ccRecipients": cc_recipients
            }
        });
        self.graph_post("/me/sendMail", &message).await
    }

    // --- Calendar operations ---

    pub async fn list_events(&self, top: Option<u32>) -> OutlookResult<Value> {
        let limit = top.unwrap_or(25).min(100);
        let path = format!(
            "/me/events?$top={limit}&$orderby=start/dateTime&$select=id,subject,start,end,location,organizer,isAllDay"
        );
        self.graph_get(&path).await
    }

    pub async fn create_event(
        &self,
        subject: &str,
        start: &str,
        end: &str,
        body: Option<&str>,
        location: Option<&str>,
    ) -> OutlookResult<Value> {
        if subject.trim().is_empty() || start.trim().is_empty() || end.trim().is_empty() {
            return Err(OutlookError::Config(
                "subject, start, and end are required".into(),
            ));
        }
        let mut event = json!({
            "subject": subject,
            "start": { "dateTime": start, "timeZone": "UTC" },
            "end": { "dateTime": end, "timeZone": "UTC" }
        });
        if let Some(body_text) = body {
            event["body"] = json!({ "contentType": "Text", "content": body_text });
        }
        if let Some(loc) = location {
            event["location"] = json!({ "displayName": loc });
        }
        self.graph_post("/me/events", &event).await
    }

    // --- Folder operations ---

    pub async fn list_folders(&self) -> OutlookResult<Value> {
        self.graph_get("/me/mailFolders?$select=id,displayName,totalItemCount,unreadItemCount")
            .await
    }

    pub async fn health(&self) -> OutlookResult<Value> {
        let folders = self.list_folders().await?;
        let folder_count = folders
            .get("value")
            .and_then(|v| v.as_array())
            .map_or(0, Vec::len);
        Ok(json!({
            "status": "ok",
            "folder_count": folder_count,
            "graph_api_version": GRAPH_API_VERSION,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_id_rejects_path_traversal() {
        assert!(OutlookClient::sanitize_id("../etc/passwd").is_err());
        assert!(OutlookClient::sanitize_id("foo/bar").is_err());
        assert!(OutlookClient::sanitize_id("foo\\bar").is_err());
    }

    #[test]
    fn sanitize_id_accepts_valid_ids() {
        assert!(OutlookClient::sanitize_id("AAMkADk3YzQ5").is_ok());
        assert!(OutlookClient::sanitize_id("inbox").is_ok());
        assert!(OutlookClient::sanitize_id("Drafts").is_ok());
    }

    #[test]
    fn graph_api_version_is_v1() {
        assert_eq!(GRAPH_API_VERSION, "v1.0");
    }
}
