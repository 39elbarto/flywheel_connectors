//! Microsoft Graph API client for Outlook operations.

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::Client;
use serde_json::{Value, json};

use crate::error::{OutlookError, OutlookResult};
use crate::types::OutlookConfig;

const GRAPH_API_VERSION: &str = "v1.0";

#[derive(Clone)]
pub struct OutlookClient {
    client: Client,
    base_url: String,
    access_token: String,
}

impl std::fmt::Debug for OutlookClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutlookClient")
            .field("client", &"<reqwest::Client>")
            .field("base_url", &self.base_url)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
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

    fn encode_path_segment(id: &str) -> OutlookResult<String> {
        if id.trim().is_empty() {
            return Err(OutlookError::Config("ID must not be empty".into()));
        }
        if id.chars().any(char::is_control) {
            return Err(OutlookError::Config(
                "ID contains invalid control characters".into(),
            ));
        }
        Ok(utf8_percent_encode(id, NON_ALPHANUMERIC).to_string())
    }

    fn normalize_recipients(recipients: &[String], required: bool) -> OutlookResult<Vec<String>> {
        if required && recipients.is_empty() {
            return Err(OutlookError::Config(
                "at least one recipient is required".into(),
            ));
        }

        recipients
            .iter()
            .map(|recipient| {
                let trimmed = recipient.trim();
                if trimmed.is_empty() {
                    return Err(OutlookError::Config(
                        "recipient addresses must not be empty".into(),
                    ));
                }
                Ok(trimmed.to_string())
            })
            .collect()
    }

    fn normalize_top(top: Option<u32>) -> OutlookResult<u32> {
        match top {
            Some(0) => Err(OutlookError::Config("top must be at least 1".into())),
            Some(value) => Ok(value.min(100)),
            None => Ok(25),
        }
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
            if matches!(
                status,
                reqwest::StatusCode::NO_CONTENT | reqwest::StatusCode::ACCEPTED
            ) {
                return Ok(json!({ "status": "ok" }));
            }
            let body: Value = response.json().await?;
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
                .map_or(60_000, |s| s * 1000);
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
        let encoded_folder = Self::encode_path_segment(folder)?;
        let limit = Self::normalize_top(top)?;
        let path = format!(
            "/me/mailFolders/{encoded_folder}/messages?$top={limit}&$orderby=receivedDateTime%20desc&$select=id,subject,from,receivedDateTime,isRead,bodyPreview"
        );
        self.graph_get(&path).await
    }

    pub async fn get_message(&self, message_id: &str) -> OutlookResult<Value> {
        let encoded_message_id = Self::encode_path_segment(message_id)?;
        let path = format!(
            "/me/messages/{encoded_message_id}?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,isRead,body,hasAttachments"
        );
        self.graph_get(&path).await
    }

    pub async fn search_messages(&self, query: &str, top: Option<u32>) -> OutlookResult<Value> {
        if query.trim().is_empty() {
            return Err(OutlookError::Config("query must not be empty".into()));
        }
        let limit = Self::normalize_top(top)?;
        let encoded_query =
            url::form_urlencoded::byte_serialize(query.as_bytes()).collect::<String>();
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
        let to_recipients: Vec<Value> = Self::normalize_recipients(to, true)?
            .iter()
            .map(|addr| {
                json!({
                    "emailAddress": { "address": addr }
                })
            })
            .collect();
        let cc_recipients: Vec<Value> = Self::normalize_recipients(cc, false)?
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
        let limit = Self::normalize_top(top)?;
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn encode_path_segment_rejects_empty_or_control_ids() {
        assert!(OutlookClient::encode_path_segment("").is_err());
        assert!(OutlookClient::encode_path_segment("   ").is_err());
        assert!(OutlookClient::encode_path_segment("AAMk\u{0000}123").is_err());
    }

    #[test]
    fn encode_path_segment_escapes_reserved_characters() {
        assert_eq!(
            OutlookClient::encode_path_segment("../etc/passwd").unwrap(),
            "%2E%2E%2Fetc%2Fpasswd"
        );
        assert_eq!(
            OutlookClient::encode_path_segment("foo/bar?draft=true#frag").unwrap(),
            "foo%2Fbar%3Fdraft%3Dtrue%23frag"
        );
        assert_eq!(
            OutlookClient::encode_path_segment("foo%2Fbar").unwrap(),
            "foo%252Fbar"
        );
    }

    #[test]
    fn encode_path_segment_preserves_safe_ids() {
        assert_eq!(
            OutlookClient::encode_path_segment("AAMkADk3YzQ5").unwrap(),
            "AAMkADk3YzQ5"
        );
        assert_eq!(
            OutlookClient::encode_path_segment("inbox").unwrap(),
            "inbox"
        );
        assert_eq!(
            OutlookClient::encode_path_segment("Drafts").unwrap(),
            "Drafts"
        );
    }

    #[test]
    fn graph_api_version_is_v1() {
        assert_eq!(GRAPH_API_VERSION, "v1.0");
    }

    #[test]
    fn normalize_top_uses_defaults_and_caps_large_values() {
        assert_eq!(OutlookClient::normalize_top(None).unwrap(), 25);
        assert_eq!(OutlookClient::normalize_top(Some(10)).unwrap(), 10);
        assert_eq!(OutlookClient::normalize_top(Some(200)).unwrap(), 100);
    }

    #[test]
    fn normalize_top_rejects_zero() {
        let err = OutlookClient::normalize_top(Some(0)).expect_err("zero top should fail");
        assert!(matches!(err, OutlookError::Config(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn list_folders_rejects_non_json_success_payload() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1.0/me/mailFolders"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("ok")
                    .insert_header("content-type", "text/plain"),
            )
            .mount(&server)
            .await;

        let config = OutlookConfig {
            access_token: "tok".into(),
            graph_host: server.uri(),
            request_timeout_ms: 5_000,
        };
        let client = OutlookClient::from_config(&config).expect("client should build");
        let err = client
            .list_folders()
            .await
            .expect_err("non-json success payload should fail");

        assert!(matches!(err, OutlookError::Http(_)));
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_accepts_202_without_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/me/sendMail"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let config = OutlookConfig {
            access_token: "tok".into(),
            graph_host: server.uri(),
            request_timeout_ms: 5_000,
        };
        let client = OutlookClient::from_config(&config).expect("client should build");
        let response = client
            .send_message(&[String::from("user@example.com")], "subject", "body", &[])
            .await
            .expect("202 Accepted without a body should succeed");

        assert_eq!(response, json!({ "status": "ok" }));
    }

    #[fcp_async_core::runtime::test]
    async fn send_message_rejects_blank_recipient_addresses() {
        let config = OutlookConfig {
            access_token: "tok".into(),
            graph_host: "https://graph.microsoft.com".into(),
            request_timeout_ms: 5_000,
        };
        let client = OutlookClient::from_config(&config).expect("client should build");
        let err = client
            .send_message(&[String::from("   ")], "subject", "body", &[])
            .await
            .expect_err("blank recipients should fail validation");

        assert!(matches!(err, OutlookError::Config(_)));
    }
}
