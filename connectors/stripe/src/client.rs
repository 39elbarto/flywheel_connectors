//! Stripe REST API client.
//!
//! Stripe uses form-encoded POST bodies for creates and query-string GET for reads.

use reqwest::{Client, StatusCode, header};
use tracing::{debug, warn};

use crate::{
    error::{StripeError, StripeResult},
    types::{
        ApiErrorResponse, Balance, Customer, ListResponse, PaymentIntent, Refund, Subscription,
    },
};

const DEFAULT_API_URL: &str = "https://api.stripe.com/v1";

/// Stripe REST API client.
pub struct StripeClient {
    http: Client,
    api_url: String,
    max_retries: u32,
}

impl StripeClient {
    /// Create a new Stripe client with a secret key.
    pub fn new(secret_key: &str) -> StripeResult<Self> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {secret_key}").parse().unwrap(),
        );

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-stripe/0.1.0")
            .build()
            .map_err(StripeError::Http)?;

        Ok(Self {
            http,
            api_url: DEFAULT_API_URL.to_string(),
            max_retries: 2,
        })
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

    // ── Customer operations ───────────────────────────────────────

    /// Create a customer.
    pub async fn create_customer(&self, email: &str, name: Option<&str>) -> StripeResult<Customer> {
        let url = format!("{}/customers", self.api_url);
        let mut body = serde_json::json!({ "email": email });
        if let Some(n) = name {
            body["name"] = serde_json::Value::String(n.to_string());
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a customer by ID.
    pub async fn get_customer(&self, customer_id: &str) -> StripeResult<Customer> {
        let url = format!("{}/customers/{customer_id}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// List customers.
    pub async fn list_customers(
        &self,
        limit: Option<u32>,
        email: Option<&str>,
    ) -> StripeResult<ListResponse> {
        let mut url = format!("{}/customers", self.api_url);
        let mut params = Vec::new();
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if let Some(e) = email {
            params.push(format!("email={e}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Payment Intent operations ─────────────────────────────────

    /// Create a payment intent.
    pub async fn create_payment_intent(
        &self,
        amount: i64,
        currency: &str,
        customer: Option<&str>,
    ) -> StripeResult<PaymentIntent> {
        let url = format!("{}/payment_intents", self.api_url);
        let mut body = serde_json::json!({
            "amount": amount,
            "currency": currency,
        });
        if let Some(c) = customer {
            body["customer"] = serde_json::Value::String(c.to_string());
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Get a payment intent by ID.
    pub async fn get_payment_intent(&self, payment_intent_id: &str) -> StripeResult<PaymentIntent> {
        let url = format!("{}/payment_intents/{payment_intent_id}", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Refund operations ─────────────────────────────────────────

    /// Create a refund.
    pub async fn create_refund(
        &self,
        payment_intent: &str,
        amount: Option<i64>,
    ) -> StripeResult<Refund> {
        let url = format!("{}/refunds", self.api_url);
        let mut body = serde_json::json!({ "payment_intent": payment_intent });
        if let Some(a) = amount {
            body["amount"] = serde_json::Value::Number(a.into());
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Subscription operations ───────────────────────────────────

    /// Create a subscription.
    pub async fn create_subscription(
        &self,
        customer: &str,
        price: &str,
    ) -> StripeResult<Subscription> {
        let url = format!("{}/subscriptions", self.api_url);
        let body = serde_json::json!({
            "customer": customer,
            "items": [{ "price": price }],
        });
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Cancel a subscription.
    pub async fn cancel_subscription(&self, subscription_id: &str) -> StripeResult<Subscription> {
        let url = format!("{}/subscriptions/{subscription_id}", self.api_url);
        let data = self.delete(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Invoice operations ────────────────────────────────────────

    /// List invoices.
    pub async fn list_invoices(
        &self,
        customer: Option<&str>,
        limit: Option<u32>,
    ) -> StripeResult<ListResponse> {
        let mut url = format!("{}/invoices", self.api_url);
        let mut params = Vec::new();
        if let Some(c) = customer {
            params.push(format!("customer={c}"));
        }
        if let Some(l) = limit {
            params.push(format!("limit={l}"));
        }
        if !params.is_empty() {
            url = format!("{url}?{}", params.join("&"));
        }
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Balance operations ────────────────────────────────────────

    /// Get account balance.
    pub async fn get_balance(&self) -> StripeResult<Balance> {
        let url = format!("{}/balance", self.api_url);
        let data = self.get(&url).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn get(&self, url: &str) -> StripeResult<serde_json::Value> {
        self.execute(|| self.http.get(url)).await
    }

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> StripeResult<serde_json::Value> {
        self.execute(|| self.http.post(url).json(body)).await
    }

    async fn delete(&self, url: &str) -> StripeResult<serde_json::Value> {
        self.execute(|| self.http.delete(url)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> StripeResult<serde_json::Value> {
        let mut last_err = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let delay = std::time::Duration::from_millis(500 * u64::from(attempt));
                debug!(attempt, delay_ms = delay.as_millis(), "retrying request");
                fcp_async_core::time::sleep(delay).await;
            }

            let result = build_request().send().await;

            match result {
                Ok(response) => {
                    let status = response.status();

                    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                        return Err(StripeError::Unauthorized);
                    }

                    if status == StatusCode::NOT_FOUND {
                        let body = response.text().await.unwrap_or_default();
                        return Err(StripeError::NotFound { resource: body });
                    }

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .map_or(60_000, |s| s * 1000);

                        let err = StripeError::RateLimited {
                            retry_after_ms: retry_after,
                        };
                        if attempt < self.max_retries {
                            warn!(attempt, "rate limited, will retry");
                            last_err = Some(err);
                            continue;
                        }
                        return Err(err);
                    }

                    if status.is_server_error() {
                        let body = response.text().await.unwrap_or_default();
                        let err = StripeError::Api {
                            message: format!("Server error {status}: {body}"),
                            status_code: Some(status.as_u16()),
                            error_type: None,
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
                        let (message, error_type) = api_err
                            .as_ref()
                            .and_then(|e| e.error.as_ref())
                            .map(|d| {
                                (
                                    d.message.clone().unwrap_or(format!("HTTP {status}")),
                                    d.error_type.clone(),
                                )
                            })
                            .unwrap_or((format!("HTTP {status}: {body}"), None));
                        return Err(StripeError::Api {
                            message,
                            status_code: Some(status.as_u16()),
                            error_type,
                        });
                    }

                    let body = response.text().await.map_err(StripeError::Http)?;
                    let data: serde_json::Value = serde_json::from_str(&body)?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(StripeError::Http(e));
                        continue;
                    }
                    return Err(StripeError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(StripeError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
            error_type: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[fcp_async_core::runtime::test]
    async fn test_get_customer() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/customers/cus_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "cus_123",
                "object": "customer",
                "email": "test@example.com",
                "name": "Test User"
            })))
            .mount(&mock_server)
            .await;

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let customer = client.get_customer("cus_123").await.unwrap();
        assert_eq!(customer.id, "cus_123");
        assert_eq!(customer.email.as_deref(), Some("test@example.com"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_customer() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/customers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "cus_new",
                "object": "customer",
                "email": "new@example.com",
                "name": "New User"
            })))
            .mount(&mock_server)
            .await;

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let customer = client
            .create_customer("new@example.com", Some("New User"))
            .await
            .unwrap();
        assert_eq!(customer.id, "cus_new");
    }

    #[fcp_async_core::runtime::test]
    async fn test_list_customers() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/customers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "list",
                "data": [
                    { "id": "cus_1", "object": "customer" },
                    { "id": "cus_2", "object": "customer" }
                ],
                "has_more": false
            })))
            .mount(&mock_server)
            .await;

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let result = client.list_customers(Some(10), None).await.unwrap();
        assert_eq!(result.data.len(), 2);
        assert!(!result.has_more);
    }

    #[fcp_async_core::runtime::test]
    async fn test_create_payment_intent() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/payment_intents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "pi_123",
                "object": "payment_intent",
                "amount": 2000,
                "currency": "usd",
                "status": "requires_payment_method"
            })))
            .mount(&mock_server)
            .await;

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let pi = client
            .create_payment_intent(2000, "usd", None)
            .await
            .unwrap();
        assert_eq!(pi.id, "pi_123");
        assert_eq!(pi.amount, 2000);
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_balance() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/balance"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": "balance",
                "available": [{ "amount": 50000, "currency": "usd" }],
                "pending": [{ "amount": 10000, "currency": "usd" }]
            })))
            .mount(&mock_server)
            .await;

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()));

        let balance = client.get_balance().await.unwrap();
        assert_eq!(balance.available[0].amount, 50000);
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/customers/cus_123"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = StripeClient::new("bad_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_customer("cus_123").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StripeError::Unauthorized));
    }

    #[fcp_async_core::runtime::test]
    async fn test_not_found() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/customers/missing"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": { "type": "invalid_request_error", "message": "No such customer" }
            })))
            .mount(&mock_server)
            .await;

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_customer("missing").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), StripeError::NotFound { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v1/balance"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = StripeClient::new("sk_test_key")
            .unwrap()
            .with_api_url(&format!("{}/v1", mock_server.uri()))
            .with_retry_config(0);

        let result = client.get_balance().await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StripeError::RateLimited { .. }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = StripeError::RateLimited {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = StripeError::Unauthorized;
        assert!(!err.is_retryable());

        let err = StripeError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_type: None,
        };
        assert!(err.is_retryable());
    }
}
