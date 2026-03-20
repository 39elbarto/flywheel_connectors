use std::sync::RwLock;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use reqwest::{Client, RequestBuilder};
use serde_json::json;
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{PayPalError, PayPalResult};
use crate::types::*;

/// Validate a user-supplied path segment to prevent URL path injection.
fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> PayPalResult<&'a str> {
    if value.trim().is_empty() {
        return Err(PayPalError::Api {
            code: 1005,
            message: format!("{field} must not be empty"),
        });
    }
    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(PayPalError::Api {
            code: 1005,
            message: format!("{field} contains invalid characters"),
        });
    }
    Ok(value)
}

/// Validate a query string parameter to prevent injection.
fn sanitize_query_param<'a>(value: &'a str, field: &str) -> PayPalResult<&'a str> {
    if value.contains('&') || value.contains('?') || value.contains('#') {
        return Err(PayPalError::Api {
            code: 1005,
            message: format!("{field} contains invalid characters"),
        });
    }
    Ok(value)
}

/// PayPal API client with OAuth2 token management and retry support.
pub struct PayPalClient {
    client: Client,
    base_url: String,
    client_id: String,
    client_secret: String,
    retry_config: HttpRetryConfig,
    access_token: RwLock<Option<String>>,
}

impl std::fmt::Debug for PayPalClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PayPalClient")
            .field("base_url", &self.base_url)
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

impl PayPalClient {
    pub async fn new(
        base_url: &str,
        client_id: String,
        client_secret: String,
        retry_config: HttpRetryConfig,
    ) -> PayPalResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(PayPalError::Http)?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            client_id,
            client_secret,
            retry_config,
            access_token: RwLock::new(None),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn is_secretless(&self) -> bool {
        self.client_id.trim().is_empty() || self.client_secret.trim().is_empty()
    }

    /// Obtain or refresh OAuth2 access token via client_credentials grant.
    async fn ensure_token(&self, runtime: &ConnectorRuntime) -> PayPalResult<String> {
        // Check if we already have a token
        {
            let guard = self.access_token.read().map_err(|e| {
                PayPalError::OAuth(format!("token lock poisoned: {e}"))
            })?;
            if let Some(ref token) = *guard {
                return Ok(token.clone());
            }
        }

        // Obtain new token
        let url = format!("{}/v1/oauth2/token", self.base_url);
        let credentials = BASE64.encode(format!("{}:{}", self.client_id, self.client_secret));
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let token_resp: TokenResponse = RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let credentials = credentials.clone();
            async move {
                debug!(attempt, "Requesting PayPal OAuth2 token");
                let resp = match client
                    .post(&url)
                    .header("Authorization", format!("Basic {credentials}"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body("grant_type=client_credentials")
                    .send()
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: PayPalError::Http(e),
                            retry_after: None,
                        };
                    }
                };

                let status = resp.status().as_u16();
                if status == 401 {
                    return AttemptOutcome::Terminal(PayPalError::OAuth(
                        "invalid client credentials".into(),
                    ));
                }
                if status == 429 {
                    return AttemptOutcome::Retryable {
                        error: PayPalError::RateLimited {
                            retry_after_ms: 5_000,
                        },
                        retry_after: Some(Duration::from_secs(5)),
                    };
                }
                if !resp.status().is_success() {
                    let text = resp.text().await.unwrap_or_default();
                    return AttemptOutcome::Terminal(PayPalError::OAuth(format!(
                        "token request failed ({status}): {text}"
                    )));
                }

                match resp.json::<TokenResponse>().await {
                    Ok(tok) => AttemptOutcome::Success(tok),
                    Err(e) => AttemptOutcome::Terminal(PayPalError::Http(e)),
                }
            }
        })
        .await?;

        let token = token_resp.access_token.clone();
        {
            let mut guard = self.access_token.write().map_err(|e| {
                PayPalError::OAuth(format!("token lock poisoned: {e}"))
            })?;
            *guard = Some(token.clone());
        }
        Ok(token)
    }

    /// Clear cached token (e.g., on 401)
    fn clear_token(&self) {
        if let Ok(mut guard) = self.access_token.write() {
            *guard = None;
        }
    }

    // ── Health check ──

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> PayPalResult<bool> {
        let token = self.ensure_token(runtime).await?;
        // Use a lightweight endpoint to verify credentials
        let url = format!("{}/v2/checkout/orders?limit=1", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, "PayPal health check");
                let resp = match client.get(&url).bearer_auth(&token).send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: PayPalError::Http(e),
                            retry_after: None,
                        };
                    }
                };
                let status = resp.status().as_u16();
                if status == 401 || status == 403 {
                    return AttemptOutcome::Terminal(PayPalError::Unauthorized(format!(
                        "Authentication failed (HTTP {status})"
                    )));
                }
                // Even a 400 from this endpoint means the API is reachable and creds work
                AttemptOutcome::Success(status < 500)
            }
        })
        .await
    }

    // ── Orders ──

    pub async fn create_order(
        &self,
        runtime: &ConnectorRuntime,
        order: &CreateOrder,
    ) -> PayPalResult<PayPalOrder> {
        let url = format!("{}/v2/checkout/orders", self.base_url);
        self.post_json(runtime, &url, &serde_json::to_value(order).unwrap_or(json!({}))).await
    }

    pub async fn get_order(
        &self,
        runtime: &ConnectorRuntime,
        order_id: &str,
    ) -> PayPalResult<PayPalOrder> {
        let order_id = sanitize_path_segment(order_id, "order_id")?;
        let url = format!("{}/v2/checkout/orders/{order_id}", self.base_url);
        self.get_json(runtime, &url).await
    }

    pub async fn capture_order(
        &self,
        runtime: &ConnectorRuntime,
        order_id: &str,
    ) -> PayPalResult<PayPalOrder> {
        let order_id = sanitize_path_segment(order_id, "order_id")?;
        let url = format!("{}/v2/checkout/orders/{order_id}/capture", self.base_url);
        self.post_json(runtime, &url, &json!({})).await
    }

    // ── Payments ──

    pub async fn list_payments(
        &self,
        runtime: &ConnectorRuntime,
        start_date: &str,
        end_date: &str,
    ) -> PayPalResult<TransactionSearchResponse> {
        let start_date = sanitize_query_param(start_date, "start_date")?;
        let end_date = sanitize_query_param(end_date, "end_date")?;
        let url = format!(
            "{}/v1/reporting/transactions?start_date={start_date}&end_date={end_date}&fields=all",
            self.base_url
        );
        self.get_json(runtime, &url).await
    }

    pub async fn get_capture(
        &self,
        runtime: &ConnectorRuntime,
        capture_id: &str,
    ) -> PayPalResult<Capture> {
        let capture_id = sanitize_path_segment(capture_id, "capture_id")?;
        let url = format!("{}/v2/payments/captures/{capture_id}", self.base_url);
        self.get_json(runtime, &url).await
    }

    pub async fn refund_capture(
        &self,
        runtime: &ConnectorRuntime,
        capture_id: &str,
        refund_req: &RefundRequest,
    ) -> PayPalResult<Refund> {
        let capture_id = sanitize_path_segment(capture_id, "capture_id")?;
        let url = format!("{}/v2/payments/captures/{capture_id}/refund", self.base_url);
        self.post_json(runtime, &url, &serde_json::to_value(refund_req).unwrap_or(json!({}))).await
    }

    // ── Invoices ──

    pub async fn create_invoice(
        &self,
        runtime: &ConnectorRuntime,
        invoice: &CreateInvoice,
    ) -> PayPalResult<Invoice> {
        let url = format!("{}/v2/invoicing/invoices", self.base_url);
        self.post_json(runtime, &url, &serde_json::to_value(invoice).unwrap_or(json!({}))).await
    }

    pub async fn list_invoices(&self, runtime: &ConnectorRuntime) -> PayPalResult<InvoicesListResponse> {
        let url = format!("{}/v2/invoicing/invoices?page=1&page_size=20", self.base_url);
        self.get_json(runtime, &url).await
    }

    pub async fn send_invoice(
        &self,
        runtime: &ConnectorRuntime,
        invoice_id: &str,
    ) -> PayPalResult<serde_json::Value> {
        let invoice_id = sanitize_path_segment(invoice_id, "invoice_id")?;
        let url = format!("{}/v2/invoicing/invoices/{invoice_id}/send", self.base_url);
        self.post_json(runtime, &url, &json!({})).await
    }

    // ── Generic HTTP helpers ──

    async fn get_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> PayPalResult<T> {
        let token = self.ensure_token(runtime).await?;
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        let result = RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            async move {
                debug!(attempt, url = %url, "GET");
                let req = client.get(&url).bearer_auth(&token);
                handle_response::<T>(req, attempt).await
            }
        })
        .await;

        if let Err(PayPalError::Unauthorized(_)) = &result {
            self.clear_token();
        }
        result
    }

    async fn post_json<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> PayPalResult<T> {
        let token = self.ensure_token(runtime).await?;
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();

        let result = RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = token.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %url, "POST");
                let req = client.post(&url).bearer_auth(&token).json(&body);
                handle_response::<T>(req, attempt).await
            }
        })
        .await;

        if let Err(PayPalError::Unauthorized(_)) = &result {
            self.clear_token();
        }
        result
    }
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    _attempt: u32,
) -> AttemptOutcome<T, PayPalError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: PayPalError::Http(e),
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
            error: PayPalError::RateLimited {
                retry_after_ms: retry_after
                    .unwrap_or(Duration::from_secs(5))
                    .as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(PayPalError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(PayPalError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = PayPalError::Api {
            code: u32::from(status),
            message: text,
        };
        if status >= 500 {
            return AttemptOutcome::Retryable {
                error: err,
                retry_after: None,
            };
        }
        return AttemptOutcome::Terminal(err);
    }

    // Handle 204 No Content for endpoints like invoice send
    if status == 204 {
        // Try to return a default empty value
        let empty = serde_json::json!({});
        match serde_json::from_value::<T>(empty) {
            Ok(v) => return AttemptOutcome::Success(v),
            Err(e) => return AttemptOutcome::Terminal(PayPalError::Json(e)),
        }
    }

    match resp.json::<T>().await {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => AttemptOutcome::Terminal(PayPalError::Http(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            PayPalClient::new(
                "https://api-m.sandbox.paypal.com",
                "client_id_123".into(),
                "secret_456".into(),
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("client_id_123"));
        assert!(!debug.contains("secret_456"));
    }

    #[test]
    fn secretless_detection() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            PayPalClient::new(
                "https://api-m.sandbox.paypal.com",
                String::new(),
                "secret".into(),
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            PayPalClient::new(
                "https://api-m.sandbox.paypal.com",
                "id".into(),
                "secret".into(),
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            PayPalClient::new(
                "https://api-m.sandbox.paypal.com/",
                "id".into(),
                "secret".into(),
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt.base_url().ends_with('/'));
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal() {
        assert!(sanitize_path_segment("../admin", "order_id").is_err());
        assert!(sanitize_path_segment("foo/bar", "order_id").is_err());
        assert!(sanitize_path_segment("foo\\bar", "order_id").is_err());
        assert!(sanitize_path_segment("foo%2fbar", "order_id").is_err());
        assert!(sanitize_path_segment("foo%5Cbar", "order_id").is_err());
        assert!(sanitize_path_segment("", "order_id").is_err());
        assert!(sanitize_path_segment("  ", "order_id").is_err());
    }

    #[test]
    fn sanitize_path_segment_accepts_valid() {
        assert_eq!(sanitize_path_segment("5O190127TN364715T", "order_id").unwrap(), "5O190127TN364715T");
    }

    #[test]
    fn sanitize_query_param_rejects_injection() {
        assert!(sanitize_query_param("2024-01-01&foo=bar", "start_date").is_err());
        assert!(sanitize_query_param("2024-01-01?x", "start_date").is_err());
        assert!(sanitize_query_param("2024-01-01#frag", "start_date").is_err());
    }

    #[test]
    fn sanitize_query_param_accepts_valid() {
        assert_eq!(
            sanitize_query_param("2024-01-01T00:00:00Z", "start_date").unwrap(),
            "2024-01-01T00:00:00Z"
        );
    }

    #[test]
    fn clear_token_works() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            PayPalClient::new(
                "https://api-m.sandbox.paypal.com",
                "id".into(),
                "secret".into(),
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        // Set a token manually
        {
            let mut guard = rt.access_token.write().unwrap();
            *guard = Some("test_token".into());
        }
        assert!(rt.access_token.read().unwrap().is_some());
        rt.clear_token();
        assert!(rt.access_token.read().unwrap().is_none());
    }
}
