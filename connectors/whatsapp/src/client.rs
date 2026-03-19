//! WhatsApp Business API client.

use fcp_sdk::migration::{
    AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop, classify_http_status,
};
use fcp_sdk::retry::RetryDecision;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;
use tracing::{debug, warn};

use crate::error::{WhatsAppError, WhatsAppResult};
use crate::types::{ApiErrorResponse, ProfileResponse, SendMessageResponse};

/// WhatsApp API client with retry and runtime integration.
#[derive(Debug)]
pub struct WhatsAppClient {
    client: Client,
    base_url: String,
    phone_number_id: String,
    access_token: String,
    retry_config: HttpRetryConfig,
}

impl WhatsAppClient {
    /// Create a new WhatsApp client.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new(
        base_url: &str,
        phone_number_id: &str,
        access_token: &str,
        retry_config: HttpRetryConfig,
    ) -> WhatsAppResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(WhatsAppError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            phone_number_id: phone_number_id.to_string(),
            access_token: access_token.to_string(),
            retry_config,
        })
    }

    /// Send a text message.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn send_text_message(
        &self,
        runtime: &ConnectorRuntime,
        to: &str,
        text: &str,
        preview_url: bool,
    ) -> WhatsAppResult<SendMessageResponse> {
        let body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": to,
            "type": "text",
            "text": {
                "body": text,
                "preview_url": preview_url,
            }
        });

        self.send_message(runtime, &body).await
    }

    /// Send a template message.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn send_template_message(
        &self,
        runtime: &ConnectorRuntime,
        to: &str,
        template_name: &str,
        language_code: &str,
        components: &[serde_json::Value],
    ) -> WhatsAppResult<SendMessageResponse> {
        let mut body = json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": to,
            "type": "template",
            "template": {
                "name": template_name,
                "language": { "code": language_code }
            }
        });

        if !components.is_empty() {
            body["template"]["components"] = serde_json::Value::Array(components.to_vec());
        }

        self.send_message(runtime, &body).await
    }

    /// Send an arbitrary message payload with retry.
    async fn send_message(
        &self,
        runtime: &ConnectorRuntime,
        body: &serde_json::Value,
    ) -> WhatsAppResult<SendMessageResponse> {
        let url = format!("{}/{}/messages", self.base_url, self.phone_number_id);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body_clone = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            let body = body_clone.clone();
            async move {
                debug!(attempt, "Sending WhatsApp message");
                let resp = match client
                    .post(&url)
                    .bearer_auth(&token)
                    .json(&body)
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: WhatsAppError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 429 {
                    let retry_after = resp
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok())
                        .map(Duration::from_secs);
                    return AttemptOutcome::Retryable {
                        error: WhatsAppError::RateLimited {
                            retry_after_ms: retry_after
                                .unwrap_or(Duration::from_secs(30))
                                .as_millis() as u64,
                        },
                        retry_after,
                    };
                }

                if status == 401 {
                    return AttemptOutcome::Terminal(WhatsAppError::Unauthorized(
                        "Invalid access token".into(),
                    ));
                }

                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    if let Ok(api_err) = serde_json::from_str::<ApiErrorResponse>(&text) {
                        let decision = classify_http_status(status, None);
                        let err = WhatsAppError::Api {
                            code: api_err.error.code,
                            message: api_err.error.message,
                            error_type: api_err.error.error_type,
                            subcode: api_err.error.error_subcode,
                        };
                        if !matches!(decision, RetryDecision::Terminal) {
                            return AttemptOutcome::Retryable {
                                error: err,
                                retry_after: None,
                            };
                        }
                        return AttemptOutcome::Terminal(err);
                    }
                    let decision = classify_http_status(status, None);
                    let err = WhatsAppError::Api {
                        code: u32::from(status),
                        message: text,
                        error_type: "HttpError".into(),
                        subcode: None,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<SendMessageResponse>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(WhatsAppError::Http(e)),
                }
            }
        })
        .await
    }

    /// Get business profile.
    ///
    /// # Errors
    ///
    /// Returns an error if the API call fails.
    pub async fn get_profile(&self, runtime: &ConnectorRuntime) -> WhatsAppResult<ProfileResponse> {
        let url = format!(
            "{}/{}/whatsapp_business_profile",
            self.base_url, self.phone_number_id
        );
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            async move {
                debug!(attempt, "Fetching WhatsApp business profile");
                let resp = match client
                    .get(&url)
                    .bearer_auth(&token)
                    .query(&[("fields", "about,address,description,vertical")])
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: WhatsAppError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                if !resp.status().is_success() {
                    let status = resp.status().as_u16();
                    if status == 429 {
                        let retry_after = resp
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .map(Duration::from_secs);
                        return AttemptOutcome::Retryable {
                            error: WhatsAppError::RateLimited {
                                retry_after_ms: retry_after
                                    .unwrap_or(Duration::from_secs(30))
                                    .as_millis()
                                    as u64,
                            },
                            retry_after,
                        };
                    }
                    let text = resp.text().await.unwrap_or_default();
                    warn!(status, "WhatsApp profile request failed");
                    let decision = classify_http_status(status, None);
                    let err = WhatsAppError::Api {
                        code: u32::from(status),
                        message: text,
                        error_type: "HttpError".into(),
                        subcode: None,
                    };
                    if !matches!(decision, RetryDecision::Terminal) {
                        return AttemptOutcome::Retryable {
                            error: err,
                            retry_after: None,
                        };
                    }
                    return AttemptOutcome::Terminal(err);
                }

                match resp.json::<ProfileResponse>().await {
                    Ok(r) => AttemptOutcome::Success(r),
                    Err(e) => AttemptOutcome::Terminal(WhatsAppError::Http(e)),
                }
            }
        })
        .await
    }

    /// Health check: validate API reachability with a lightweight GET.
    ///
    /// # Errors
    ///
    /// Returns an error if the API is unreachable.
    pub async fn health_check(&self) -> WhatsAppResult<()> {
        let url = format!("{}/{}", self.base_url, self.phone_number_id);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .map_err(WhatsAppError::Http)?;
        let status = resp.status().as_u16();

        if resp.status().is_success() || status == 400 {
            // 400 is acceptable for health check (means API is reachable)
            Ok(())
        } else if status == 429 {
            let retry_after_ms = resp
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(30)
                * 1000;
            Err(WhatsAppError::RateLimited { retry_after_ms })
        } else if status == 401 {
            Err(WhatsAppError::Unauthorized("Invalid access token".into()))
        } else {
            Err(WhatsAppError::Api {
                code: u32::from(status),
                message: format!("Health check failed with HTTP {status}"),
                error_type: "HealthCheckError".into(),
                subcode: None,
            })
        }
    }

    /// Get the base URL (for diagnostics).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if using secretless mode (credential injection).
    pub fn is_secretless(&self) -> bool {
        self.access_token.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_creation() {
        let client = WhatsAppClient::new(
            "https://graph.facebook.com/v21.0",
            "123456",
            "test_token",
            HttpRetryConfig::default(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn base_url_trimmed() {
        let client = WhatsAppClient::new(
            "https://graph.facebook.com/v21.0/",
            "123456",
            "test_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.base_url().ends_with('/'));
    }

    #[test]
    fn secretless_detection() {
        let client = WhatsAppClient::new(
            "https://graph.facebook.com/v21.0",
            "123456",
            "",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(client.is_secretless());
    }

    #[test]
    fn non_secretless() {
        let client = WhatsAppClient::new(
            "https://graph.facebook.com/v21.0",
            "123456",
            "real_token",
            HttpRetryConfig::default(),
        )
        .unwrap();
        assert!(!client.is_secretless());
    }
}
