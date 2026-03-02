//! Twilio REST API client.
//!
//! Twilio uses Basic auth (account_sid:auth_token) and JSON POST bodies.
//! Base URL: `https://api.twilio.com/2010-04-01/Accounts/{account_sid}`

use std::fmt::Write;
use std::time::Duration;

use base64::Engine;
use reqwest::{Client, Response, StatusCode, header};
use tracing::{debug, warn};

use crate::{
    error::{TwilioError, TwilioResult},
    types::{
        ApiErrorResponse, MessageListResponse, PhoneNumberListResponse, RecordingListResponse,
        TwilioAccount, TwilioCall, TwilioMessage,
    },
};

/// Twilio REST API client.
pub struct TwilioClient {
    http: Client,
    base_url: String,
    account_sid: String,
    max_retries: u32,
}

impl TwilioClient {
    /// Create a new Twilio client with account SID and auth token.
    pub fn new(account_sid: &str, auth_token: &str) -> TwilioResult<Self> {
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{account_sid}:{auth_token}"));

        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {credentials}").parse().unwrap(),
        );
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-twilio/0.1.0")
            .build()
            .map_err(TwilioError::Http)?;

        let base_url = format!("https://api.twilio.com/2010-04-01/Accounts/{account_sid}");

        Ok(Self {
            http,
            base_url,
            account_sid: account_sid.to_string(),
            max_retries: 2,
        })
    }

    /// Set a custom base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub const fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Get the account SID.
    #[must_use]
    pub fn account_sid(&self) -> &str {
        &self.account_sid
    }

    // ── Messaging operations ─────────────────────────────────────

    /// Send an SMS or MMS message.
    pub async fn send_message(
        &self,
        to: &str,
        from: &str,
        body: &str,
        media_url: Option<&[String]>,
        status_callback: Option<&str>,
    ) -> TwilioResult<TwilioMessage> {
        let url = format!("{}/Messages.json", self.base_url);
        let mut payload = serde_json::json!({
            "To": to,
            "From": from,
            "Body": body,
        });
        if let Some(urls) = media_url {
            payload["MediaUrl"] = serde_json::json!(urls);
        }
        if let Some(cb) = status_callback {
            payload["StatusCallback"] = serde_json::Value::String(cb.to_string());
        }
        let data = self.post_json(&url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a message by SID.
    pub async fn get_message(&self, message_sid: &str) -> TwilioResult<TwilioMessage> {
        let url = format!("{}/Messages/{message_sid}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List messages with optional filters.
    pub async fn list_messages(
        &self,
        to: Option<&str>,
        from: Option<&str>,
        date_sent: Option<&str>,
        page_size: Option<u32>,
        page: Option<u32>,
    ) -> TwilioResult<MessageListResponse> {
        let base_url = format!("{}/Messages.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = to {
            params.push(("To", v.to_string()));
        }
        if let Some(v) = from {
            params.push(("From", v.to_string()));
        }
        if let Some(v) = date_sent {
            params.push(("DateSent", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        if let Some(v) = page {
            params.push(("Page", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Voice operations ─────────────────────────────────────────

    /// Create (initiate) a voice call.
    pub async fn create_call(
        &self,
        to: &str,
        from: &str,
        url: &str,
        status_callback: Option<&str>,
        timeout: Option<u32>,
        record: Option<bool>,
    ) -> TwilioResult<TwilioCall> {
        let api_url = format!("{}/Calls.json", self.base_url);
        let mut payload = serde_json::json!({
            "To": to,
            "From": from,
            "Url": url,
        });
        if let Some(cb) = status_callback {
            payload["StatusCallback"] = serde_json::Value::String(cb.to_string());
        }
        if let Some(t) = timeout {
            payload["Timeout"] = serde_json::Value::Number(t.into());
        }
        if let Some(r) = record {
            payload["Record"] = serde_json::Value::Bool(r);
        }
        let data = self.post_json(&api_url, &payload).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a call by SID.
    pub async fn get_call(&self, call_sid: &str) -> TwilioResult<TwilioCall> {
        let url = format!("{}/Calls/{call_sid}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Recording operations ─────────────────────────────────────

    /// List recordings with optional filters.
    pub async fn list_recordings(
        &self,
        call_sid: Option<&str>,
        date_created: Option<&str>,
        page_size: Option<u32>,
    ) -> TwilioResult<RecordingListResponse> {
        let base_url = format!("{}/Recordings.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = call_sid {
            params.push(("CallSid", v.to_string()));
        }
        if let Some(v) = date_created {
            params.push(("DateCreated", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Download a recording, returning the base64-encoded audio data and content type.
    pub async fn download_recording(
        &self,
        recording_sid: &str,
        format: Option<&str>,
    ) -> TwilioResult<(String, String)> {
        let ext = format.unwrap_or("mp3");
        let url = format!("{}/Recordings/{recording_sid}.{ext}", self.base_url);
        let data = self.get_bytes(&url).await?;
        let content_type = if ext == "wav" {
            "audio/wav"
        } else {
            "audio/mpeg"
        };
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        Ok((b64, content_type.to_string()))
    }

    /// Download media attached to a message, returning base64-encoded data and content type.
    pub async fn download_media(
        &self,
        message_sid: &str,
        media_sid: &str,
    ) -> TwilioResult<(String, String)> {
        let url = format!("{}/Messages/{message_sid}/Media/{media_sid}", self.base_url);
        let data = self.get_bytes(&url).await?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        Ok((b64, "application/octet-stream".to_string()))
    }

    // ── Account operations ───────────────────────────────────────

    /// Get account details.
    pub async fn get_account(&self) -> TwilioResult<TwilioAccount> {
        let url = format!("{}.json", self.base_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List phone numbers on the account.
    pub async fn list_phone_numbers(
        &self,
        phone_number: Option<&str>,
        page_size: Option<u32>,
    ) -> TwilioResult<PhoneNumberListResponse> {
        let base_url = format!("{}/IncomingPhoneNumbers.json", self.base_url);
        let mut params: Vec<(&str, String)> = Vec::new();
        if let Some(v) = phone_number {
            params.push(("PhoneNumber", v.to_string()));
        }
        if let Some(v) = page_size {
            params.push(("PageSize", v.to_string()));
        }
        let data = self.get_with_params(&base_url, &params).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── HTTP helpers ─────────────────────────────────────────────

    async fn get(&self, url: &str) -> TwilioResult<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn get_with_params(
        &self,
        base_url: &str,
        params: &[(&str, String)],
    ) -> TwilioResult<serde_json::Value> {
        let mut url = base_url.to_string();
        if !params.is_empty() {
            url.push('?');
            for (i, (key, value)) in params.iter().enumerate() {
                if i > 0 {
                    url.push('&');
                }
                let encoded = percent_encoding::utf8_percent_encode(
                    value,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                let _ = write!(url, "{key}={encoded}");
            }
        }
        self.execute(|| self.http.get(&url)).await
    }

    async fn get_bytes(&self, url: &str) -> TwilioResult<Vec<u8>> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let result = self.http.get(url).send().await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempt < self.max_retries {
                            let wait = retry_result
                                .unwrap_or(Duration::from_millis(500 * u64::from(attempt + 1)));
                            warn!(attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(TwilioError::RateLimited {
                            retry_after_ms: retry_result.map_or(60_000, |d| d.as_millis() as u64),
                        });
                    }

                    let status = response.status();
                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(TwilioError::Unauthorized);
                    }
                    if status == StatusCode::NOT_FOUND {
                        return Err(TwilioError::NotFound {
                            resource: url.to_string(),
                        });
                    }
                    if !status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        return Err(TwilioError::Api {
                            message: format!("HTTP {status}: {body}"),
                            status_code: Some(status.as_u16()),
                            error_code: None,
                        });
                    }

                    let bytes = response.bytes().await.map_err(TwilioError::Http)?;
                    return Ok(bytes.to_vec());
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(TwilioError::Http(e));
                        continue;
                    }
                    return Err(TwilioError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(TwilioError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
            error_code: None,
        }))
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> TwilioResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> TwilioResult<serde_json::Value> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    if let Some(retry_result) = Self::check_rate_limit(&response) {
                        if attempt < self.max_retries {
                            let wait = retry_result
                                .unwrap_or(Duration::from_millis(500 * u64::from(attempt + 1)));
                            warn!(attempt, "Rate limited, waiting {wait:?}");
                            fcp_async_core::time::sleep(wait).await;
                            continue;
                        }
                        return Err(TwilioError::RateLimited {
                            retry_after_ms: retry_result.map_or(60_000, |d| d.as_millis() as u64),
                        });
                    }

                    let status = response.status();

                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(TwilioError::Unauthorized);
                    }

                    if status == StatusCode::NOT_FOUND {
                        let body = response.text().await.unwrap_or_default();
                        return Err(TwilioError::NotFound { resource: body });
                    }

                    if status.is_server_error() {
                        let body = response.text().await.unwrap_or_default();
                        let err = TwilioError::Api {
                            message: format!("Server error {status}: {body}"),
                            status_code: Some(status.as_u16()),
                            error_code: None,
                        };
                        if attempt < self.max_retries {
                            warn!(attempt, status = %status, "server error, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    if !status.is_success() {
                        let body = response.text().await.unwrap_or_default();
                        let api_err: Option<ApiErrorResponse> = serde_json::from_str(&body).ok();
                        let (message, error_code) = api_err
                            .as_ref()
                            .map(|e| {
                                (
                                    e.message.clone().unwrap_or(format!("HTTP {status}")),
                                    e.code.map(|c| c.to_string()),
                                )
                            })
                            .unwrap_or((format!("HTTP {status}: {body}"), None));
                        return Err(TwilioError::Api {
                            message,
                            status_code: Some(status.as_u16()),
                            error_code,
                        });
                    }

                    let body = response.text().await.map_err(TwilioError::Http)?;
                    let data: serde_json::Value = serde_json::from_str(&body)?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(TwilioError::Http(e));
                        continue;
                    }
                    return Err(TwilioError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(TwilioError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
            error_code: None,
        }))
    }

    #[allow(clippy::option_option)]
    fn check_rate_limit(response: &Response) -> Option<Option<Duration>> {
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs);
            Some(retry_after)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    fn test_client(base_url: &str) -> TwilioClient {
        TwilioClient::new("ACtest123", "test_auth_token")
            .unwrap()
            .with_base_url(base_url)
            .with_retry_config(0)
    }

    #[fcp_async_core::runtime::test]
    async fn test_send_message() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/2010-04-01/Accounts/ACtest123/Messages.json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "sid": "SMtest123",
                "status": "queued",
                "to": "+15551234567",
                "from": "+15559876543",
                "body": "Hello from FCP!",
                "date_created": "2026-03-01T00:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let msg = client
            .send_message(
                "+15551234567",
                "+15559876543",
                "Hello from FCP!",
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(msg.sid, "SMtest123");
        assert_eq!(msg.status, "queued");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_message() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Messages/SMabc.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sid": "SMabc",
                "status": "delivered",
                "to": "+15551234567",
                "from": "+15559876543",
                "body": "Test message",
                "date_created": "2026-03-01T00:00:00Z",
                "num_media": "0"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let msg = client.get_message("SMabc").await.unwrap();
        assert_eq!(msg.sid, "SMabc");
        assert_eq!(msg.status, "delivered");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_messages() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Messages.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "messages": [
                    { "sid": "SM1", "status": "delivered", "to": "+1", "from": "+2" },
                    { "sid": "SM2", "status": "sent", "to": "+3", "from": "+4" }
                ],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client
            .list_messages(None, None, None, Some(20), None)
            .await
            .unwrap();
        assert_eq!(result.messages.len(), 2);
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_call() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("POST"))
            .and(path("/2010-04-01/Accounts/ACtest123/Calls.json"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "sid": "CAtest",
                "status": "queued",
                "to": "+15551234567",
                "from": "+15559876543",
                "date_created": "2026-03-01T00:00:00Z"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let call = client
            .create_call(
                "+15551234567",
                "+15559876543",
                "https://example.com/twiml",
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(call.sid, "CAtest");
        assert_eq!(call.status, "queued");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_call() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123/Calls/CAxyz.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sid": "CAxyz",
                "status": "completed",
                "to": "+15551234567",
                "from": "+15559876543",
                "duration": "42",
                "date_created": "2026-03-01T00:00:00Z",
                "price": "-0.0100"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let call = client.get_call("CAxyz").await.unwrap();
        assert_eq!(call.sid, "CAxyz");
        assert_eq!(call.duration.as_deref(), Some("42"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_account() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sid": "ACtest123",
                "friendly_name": "Test Account",
                "status": "active",
                "type": "Full"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let account = client.get_account().await.unwrap();
        assert_eq!(account.sid, "ACtest123");
        assert_eq!(account.friendly_name.as_deref(), Some("Test Account"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_phone_numbers() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/IncomingPhoneNumbers.json",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "incoming_phone_numbers": [
                    { "sid": "PN1", "phone_number": "+15551234567", "friendly_name": "Main" }
                ],
                "next_page_uri": null
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.list_phone_numbers(None, None).await.unwrap();
        assert_eq!(result.incoming_phone_numbers.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123.json"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.get_account().await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwilioError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path(
                "/2010-04-01/Accounts/ACtest123/Messages/SMmissing.json",
            ))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "code": 20404,
                "message": "The requested resource was not found"
            })))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.get_message("SMmissing").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TwilioError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;
        let base = format!("{}/2010-04-01/Accounts/ACtest123", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/2010-04-01/Accounts/ACtest123.json"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = test_client(&base);
        let result = client.get_account().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TwilioError::RateLimited { .. }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = TwilioError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = TwilioError::Unauthorized;
        assert!(!err.is_retryable());

        let err = TwilioError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_code: None,
        };
        assert!(err.is_retryable());

        let err = TwilioError::NotFound {
            resource: "message".into(),
        };
        assert!(!err.is_retryable());
    }
}
