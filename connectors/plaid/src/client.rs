//! Plaid REST API client.
//!
//! Plaid uses POST requests with JSON bodies for all API calls.
//! Authentication is via `client_id` and `secret` fields embedded in each request body.

use reqwest::{Client, StatusCode};
use tracing::{debug, warn};

use crate::{
    error::{PlaidError, PlaidResult},
    types::{
        AccessTokenResponse, Account, AuthNumbers, LiabilitiesResponse, LinkTokenResponse,
        PlaidApiError, PlaidItem, TransactionsSyncResponse,
    },
};

const DEFAULT_BASE_URL: &str = "https://sandbox.plaid.com";

/// Plaid REST API client.
pub struct PlaidClient {
    http: Client,
    base_url: String,
    client_id: String,
    secret: String,
    max_retries: u32,
}

impl PlaidClient {
    /// Create a new Plaid client with client_id and secret.
    pub fn new(client_id: &str, secret: &str) -> PlaidResult<Self> {
        let http = Client::builder()
            .user_agent("fcp-plaid/0.1.0")
            .build()
            .map_err(PlaidError::Http)?;

        Ok(Self {
            http,
            base_url: DEFAULT_BASE_URL.to_string(),
            client_id: client_id.to_string(),
            secret: secret.to_string(),
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
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Add client_id and secret to a JSON body.
    fn auth_body(&self, body: &mut serde_json::Value) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "client_id".to_string(),
                serde_json::Value::String(self.client_id.clone()),
            );
            obj.insert(
                "secret".to_string(),
                serde_json::Value::String(self.secret.clone()),
            );
        }
    }

    // ── Link operations ──────────────────────────────────────────

    /// Create a Link token for Plaid Link initialization.
    pub async fn link_token_create(
        &self,
        client_name: &str,
        products: &[String],
        country_codes: &[String],
        language: &str,
        user: Option<&serde_json::Value>,
    ) -> PlaidResult<LinkTokenResponse> {
        let url = format!("{}/link/token/create", self.base_url);
        let mut body = serde_json::json!({
            "client_name": client_name,
            "products": products,
            "country_codes": country_codes,
            "language": language,
        });
        if let Some(u) = user {
            body["user"] = u.clone();
        } else {
            body["user"] = serde_json::json!({ "client_user_id": "fcp-default-user" });
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Exchange a public token from Plaid Link for an access token.
    pub async fn token_exchange(&self, public_token: &str) -> PlaidResult<AccessTokenResponse> {
        let url = format!("{}/item/public_token/exchange", self.base_url);
        let body = serde_json::json!({
            "public_token": public_token,
        });
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Account operations ───────────────────────────────────────

    /// Get all accounts for a linked item.
    pub async fn accounts_get(
        &self,
        access_token: &str,
        options: Option<&serde_json::Value>,
    ) -> PlaidResult<(Vec<Account>, PlaidItem)> {
        let url = format!("{}/accounts/get", self.base_url);
        let mut body = serde_json::json!({
            "access_token": access_token,
        });
        if let Some(opts) = options {
            body["options"] = opts.clone();
        }
        let data = self.post_json(&url, &body).await?;
        let accounts: Vec<Account> = serde_json::from_value(
            data.get("accounts")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;
        let item: PlaidItem = serde_json::from_value(
            data.get("item")
                .cloned()
                .unwrap_or(serde_json::json!({})),
        )?;
        Ok((accounts, item))
    }

    /// Get real-time balance for accounts.
    pub async fn accounts_balance_get(
        &self,
        access_token: &str,
        options: Option<&serde_json::Value>,
    ) -> PlaidResult<Vec<Account>> {
        let url = format!("{}/accounts/balance/get", self.base_url);
        let mut body = serde_json::json!({
            "access_token": access_token,
        });
        if let Some(opts) = options {
            body["options"] = opts.clone();
        }
        let data = self.post_json(&url, &body).await?;
        let accounts: Vec<Account> = serde_json::from_value(
            data.get("accounts")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;
        Ok(accounts)
    }

    // ── Transaction operations ───────────────────────────────────

    /// Get transactions for a date range.
    pub async fn transactions_get(
        &self,
        access_token: &str,
        start_date: &str,
        end_date: &str,
        options: Option<&serde_json::Value>,
    ) -> PlaidResult<serde_json::Value> {
        let url = format!("{}/transactions/get", self.base_url);
        let mut body = serde_json::json!({
            "access_token": access_token,
            "start_date": start_date,
            "end_date": end_date,
        });
        if let Some(opts) = options {
            body["options"] = opts.clone();
        }
        self.post_json(&url, &body).await
    }

    /// Incrementally sync transactions using a cursor.
    pub async fn transactions_sync(
        &self,
        access_token: &str,
        cursor: Option<&str>,
        count: Option<u32>,
    ) -> PlaidResult<TransactionsSyncResponse> {
        let url = format!("{}/transactions/sync", self.base_url);
        let mut body = serde_json::json!({
            "access_token": access_token,
        });
        if let Some(c) = cursor {
            body["cursor"] = serde_json::Value::String(c.to_string());
        }
        if let Some(n) = count {
            body["count"] = serde_json::Value::Number(n.into());
        }
        let data = self.post_json(&url, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // ── Auth operations ──────────────────────────────────────────

    /// Get account and routing numbers for ACH.
    pub async fn auth_get(
        &self,
        access_token: &str,
    ) -> PlaidResult<(Vec<Account>, AuthNumbers)> {
        let url = format!("{}/auth/get", self.base_url);
        let body = serde_json::json!({
            "access_token": access_token,
        });
        let data = self.post_json(&url, &body).await?;
        let accounts: Vec<Account> = serde_json::from_value(
            data.get("accounts")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;
        let numbers: AuthNumbers = serde_json::from_value(
            data.get("numbers")
                .cloned()
                .unwrap_or(serde_json::json!({})),
        )?;
        Ok((accounts, numbers))
    }

    // ── Identity operations ──────────────────────────────────────

    /// Get account holder identity information.
    pub async fn identity_get(
        &self,
        access_token: &str,
    ) -> PlaidResult<Vec<serde_json::Value>> {
        let url = format!("{}/identity/get", self.base_url);
        let body = serde_json::json!({
            "access_token": access_token,
        });
        let data = self.post_json(&url, &body).await?;
        let accounts: Vec<serde_json::Value> = serde_json::from_value(
            data.get("accounts")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;
        Ok(accounts)
    }

    // ── Investment operations ────────────────────────────────────

    /// Get investment holdings.
    pub async fn investments_holdings_get(
        &self,
        access_token: &str,
    ) -> PlaidResult<serde_json::Value> {
        let url = format!("{}/investments/holdings/get", self.base_url);
        let body = serde_json::json!({
            "access_token": access_token,
        });
        self.post_json(&url, &body).await
    }

    // ── Liabilities operations ───────────────────────────────────

    /// Get liability details.
    pub async fn liabilities_get(
        &self,
        access_token: &str,
    ) -> PlaidResult<(Vec<Account>, LiabilitiesResponse)> {
        let url = format!("{}/liabilities/get", self.base_url);
        let body = serde_json::json!({
            "access_token": access_token,
        });
        let data = self.post_json(&url, &body).await?;
        let accounts: Vec<Account> = serde_json::from_value(
            data.get("accounts")
                .cloned()
                .unwrap_or(serde_json::json!([])),
        )?;
        let liabilities: LiabilitiesResponse = serde_json::from_value(
            data.get("liabilities")
                .cloned()
                .unwrap_or(serde_json::json!({})),
        )?;
        Ok((accounts, liabilities))
    }

    // ── HTTP helpers ──────────────────────────────────────────────

    async fn post_json(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> PlaidResult<serde_json::Value> {
        let mut auth_body = body.clone();
        self.auth_body(&mut auth_body);
        self.execute(|| self.http.post(url).json(&auth_body)).await
    }

    async fn execute(
        &self,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> PlaidResult<serde_json::Value> {
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
                        let body = response.text().await.unwrap_or_default();
                        let api_err: Option<PlaidApiError> =
                            serde_json::from_str(&body).ok();
                        let message = api_err
                            .as_ref()
                            .and_then(|e| e.error_message.clone())
                            .unwrap_or_else(|| format!("Authentication failed: HTTP {status}"));
                        return Err(PlaidError::Api {
                            message,
                            status_code: Some(status.as_u16()),
                            error_type: api_err.as_ref().and_then(|e| e.error_type.clone()),
                            error_code: api_err.as_ref().and_then(|e| e.error_code.clone()),
                        });
                    }

                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .map_or(60_000, |s| s * 1000);

                        let err = PlaidError::RateLimit {
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
                        let err = PlaidError::Api {
                            message: format!("Server error {status}: {body}"),
                            status_code: Some(status.as_u16()),
                            error_type: None,
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
                        let api_err: Option<PlaidApiError> =
                            serde_json::from_str(&body).ok();
                        let (message, error_type, error_code) = api_err
                            .as_ref()
                            .map(|e| {
                                (
                                    e.error_message
                                        .clone()
                                        .unwrap_or(format!("HTTP {status}")),
                                    e.error_type.clone(),
                                    e.error_code.clone(),
                                )
                            })
                            .unwrap_or((format!("HTTP {status}: {body}"), None, None));
                        return Err(PlaidError::Api {
                            message,
                            status_code: Some(status.as_u16()),
                            error_type,
                            error_code,
                        });
                    }

                    let body = response.text().await.map_err(PlaidError::Http)?;
                    let data: serde_json::Value = serde_json::from_str(&body)?;
                    return Ok(data);
                }
                Err(e) => {
                    if attempt < self.max_retries {
                        warn!(attempt, error = %e, "request failed, will retry");
                        last_err = Some(PlaidError::Http(e));
                        continue;
                    }
                    return Err(PlaidError::Http(e));
                }
            }
        }

        Err(last_err.unwrap_or(PlaidError::Api {
            message: "Max retries exceeded".into(),
            status_code: None,
            error_type: None,
            error_code: None,
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
    async fn test_link_token_create() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/link/token/create"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "link_token": "link-sandbox-abc123",
                "expiration": "2026-03-02T00:00:00Z",
                "request_id": "req-1"
            })))
            .mount(&mock_server)
            .await;

        let client = PlaidClient::new("test_client_id", "test_secret")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let result = client
            .link_token_create(
                "MyApp",
                &["transactions".to_string()],
                &["US".to_string()],
                "en",
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.link_token, "link-sandbox-abc123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_token_exchange() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/item/public_token/exchange"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access-sandbox-abc123",
                "item_id": "item-123",
                "request_id": "req-2"
            })))
            .mount(&mock_server)
            .await;

        let client = PlaidClient::new("test_client_id", "test_secret")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let result = client.token_exchange("public-sandbox-abc123").await.unwrap();
        assert_eq!(result.access_token, "access-sandbox-abc123");
        assert_eq!(result.item_id, "item-123");
    }

    #[fcp_async_core::runtime::test]
    async fn test_accounts_get() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/accounts/get"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accounts": [{
                    "account_id": "acc-1",
                    "balances": {
                        "available": 100.0,
                        "current": 110.0,
                        "limit": null,
                        "iso_currency_code": "USD",
                        "unofficial_currency_code": null
                    },
                    "mask": "0000",
                    "name": "Plaid Checking",
                    "official_name": "Plaid Gold Standard 0% Interest Checking",
                    "subtype": "checking",
                    "type": "depository"
                }],
                "item": {
                    "item_id": "item-1",
                    "institution_id": "ins_3",
                    "available_products": ["balance"],
                    "billed_products": ["transactions"]
                }
            })))
            .mount(&mock_server)
            .await;

        let client = PlaidClient::new("test_client_id", "test_secret")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let (accounts, item) = client.accounts_get("access-sandbox-xxx", None).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].account_id, "acc-1");
        assert_eq!(accounts[0].name, "Plaid Checking");
        assert_eq!(item.item_id, "item-1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_accounts_balance_get() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/accounts/balance/get"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accounts": [{
                    "account_id": "acc-1",
                    "balances": {
                        "available": 200.0,
                        "current": 210.0,
                        "limit": null,
                        "iso_currency_code": "USD",
                        "unofficial_currency_code": null
                    },
                    "mask": "0000",
                    "name": "Checking",
                    "official_name": null,
                    "subtype": "checking",
                    "type": "depository"
                }]
            })))
            .mount(&mock_server)
            .await;

        let client = PlaidClient::new("test_client_id", "test_secret")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let accounts = client.accounts_balance_get("access-sandbox-xxx", None).await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].balances.available, Some(200.0));
    }

    #[fcp_async_core::runtime::test]
    async fn test_transactions_sync() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/transactions/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "added": [{
                    "transaction_id": "tx-1",
                    "account_id": "acc-1",
                    "amount": 25.50,
                    "iso_currency_code": "USD",
                    "date": "2026-02-28",
                    "name": "Coffee Shop",
                    "merchant_name": "Starbucks",
                    "pending": false,
                    "category": ["Food and Drink", "Coffee Shop"],
                    "category_id": "13005000"
                }],
                "modified": [],
                "removed": [],
                "next_cursor": "cursor-abc",
                "has_more": false
            })))
            .mount(&mock_server)
            .await;

        let client = PlaidClient::new("test_client_id", "test_secret")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let result = client
            .transactions_sync("access-sandbox-xxx", None, Some(100))
            .await
            .unwrap();
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].transaction_id, "tx-1");
        assert_eq!(result.next_cursor, "cursor-abc");
        assert!(!result.has_more);
    }

    #[fcp_async_core::runtime::test]
    async fn test_auth_get() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/auth/get"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "accounts": [{
                    "account_id": "acc-1",
                    "balances": {
                        "available": 100.0,
                        "current": 110.0,
                        "limit": null,
                        "iso_currency_code": "USD",
                        "unofficial_currency_code": null
                    },
                    "mask": "0000",
                    "name": "Checking",
                    "official_name": null,
                    "subtype": "checking",
                    "type": "depository"
                }],
                "numbers": {
                    "ach": [{ "account_id": "acc-1", "account": "9900009606", "routing": "011401533", "wire_routing": null }],
                    "eft": [],
                    "international": [],
                    "bacs": []
                }
            })))
            .mount(&mock_server)
            .await;

        let client = PlaidClient::new("test_client_id", "test_secret")
            .unwrap()
            .with_base_url(&mock_server.uri());

        let (accounts, numbers) = client.auth_get("access-sandbox-xxx").await.unwrap();
        assert_eq!(accounts.len(), 1);
        assert!(numbers.ach.is_some());
        assert_eq!(numbers.ach.unwrap().len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/accounts/get"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = PlaidClient::new("test_client_id", "test_secret")
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.accounts_get("access-sandbox-xxx", None).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PlaidError::RateLimit { .. }));
    }

    #[fcp_async_core::runtime::test]
    async fn test_unauthorized() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/accounts/get"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error_type": "INVALID_INPUT",
                "error_code": "INVALID_API_KEYS",
                "error_message": "invalid client_id or secret provided"
            })))
            .mount(&mock_server)
            .await;

        let client = PlaidClient::new("bad_id", "bad_secret")
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_retry_config(0);

        let result = client.accounts_get("access-sandbox-xxx", None).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            PlaidError::Api { status_code, .. } => assert_eq!(status_code, Some(401)),
            e => panic!("Expected Api error, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_error_retries() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/accounts/get"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(2)
            .mount(&mock_server)
            .await;

        let client = PlaidClient::new("test_client_id", "test_secret")
            .unwrap()
            .with_base_url(&mock_server.uri())
            .with_retry_config(1);

        let result = client.accounts_get("access-sandbox-xxx", None).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_error_is_retryable() {
        let err = PlaidError::RateLimit {
            retry_after_ms: 1000,
        };
        assert!(err.is_retryable());

        let err = PlaidError::InvalidConfig("bad".into());
        assert!(!err.is_retryable());

        let err = PlaidError::Api {
            message: "Server error".into(),
            status_code: Some(500),
            error_type: None,
            error_code: None,
        };
        assert!(err.is_retryable());

        let err = PlaidError::Api {
            message: "Bad request".into(),
            status_code: Some(400),
            error_type: None,
            error_code: None,
        };
        assert!(!err.is_retryable());
    }
}
