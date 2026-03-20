use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde_json::json;
use tracing::debug;

use fcp_sdk::migration::{AttemptOutcome, ConnectorRuntime, HttpRetryConfig, RetryLoop};

use crate::error::{ShopifyError, ShopifyResult};
use crate::types::*;

/// Shopify Admin API client with retry support.
pub struct ShopifyClient {
    client: Client,
    base_url: String,
    access_token: String,
    retry_config: HttpRetryConfig,
}

impl std::fmt::Debug for ShopifyClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShopifyClient")
            .field("base_url", &self.base_url)
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

impl ShopifyClient {
    pub async fn new(
        shop_domain: &str,
        access_token: String,
        api_version: &str,
        retry_config: HttpRetryConfig,
    ) -> ShopifyResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(ShopifyError::Http)?;

        let base_url = format!(
            "https://{}/admin/api/{api_version}",
            shop_domain.trim_end_matches('/')
        );

        Ok(Self {
            client,
            base_url,
            access_token,
            retry_config,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn is_secretless(&self) -> bool {
        self.access_token.trim().is_empty()
    }

    // ── Health check (shop info) ──

    pub async fn health_check(&self, runtime: &ConnectorRuntime) -> ShopifyResult<Shop> {
        let url = format!("{}/shop.json", self.base_url);
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            async move {
                debug!(attempt, "Checking Shopify health");
                let req = authenticate(client.get(&url), &token);
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ShopifyError::Http(e),
                            retry_after: None,
                        };
                    }
                };
                let status = resp.status().as_u16();
                if let Some(outcome) = check_error_status(status) {
                    return outcome;
                }
                match resp.json::<ShopResponse>().await {
                    Ok(sr) => AttemptOutcome::Success(sr.shop),
                    Err(e) => AttemptOutcome::Terminal(ShopifyError::Http(e)),
                }
            }
        })
        .await
    }

    // ── Products ──

    pub async fn list_products(&self, runtime: &ConnectorRuntime) -> ShopifyResult<Vec<Product>> {
        let url = format!("{}/products.json?limit=50", self.base_url);
        self.get_wrapped::<ProductsResponse>(runtime, &url)
            .await
            .map(|r| r.products)
    }

    pub async fn get_product(
        &self,
        runtime: &ConnectorRuntime,
        product_id: u64,
    ) -> ShopifyResult<Product> {
        let url = format!("{}/products/{product_id}.json", self.base_url);
        self.get_wrapped::<ProductResponse>(runtime, &url)
            .await
            .map(|r| r.product)
    }

    pub async fn create_product(
        &self,
        runtime: &ConnectorRuntime,
        product: &CreateProduct,
    ) -> ShopifyResult<Product> {
        let url = format!("{}/products.json", self.base_url);
        let body = json!({ "product": product });
        self.post_wrapped::<ProductResponse>(runtime, &url, &body)
            .await
            .map(|r| r.product)
    }

    pub async fn update_product(
        &self,
        runtime: &ConnectorRuntime,
        product_id: u64,
        product: &UpdateProduct,
    ) -> ShopifyResult<Product> {
        let url = format!("{}/products/{product_id}.json", self.base_url);
        let body = json!({ "product": product });
        self.put_wrapped::<ProductResponse>(runtime, &url, &body)
            .await
            .map(|r| r.product)
    }

    pub async fn delete_product(
        &self,
        runtime: &ConnectorRuntime,
        product_id: u64,
    ) -> ShopifyResult<serde_json::Value> {
        let url = format!("{}/products/{product_id}.json", self.base_url);
        self.delete_json(runtime, &url).await
    }

    // ── Orders ──

    pub async fn list_orders(&self, runtime: &ConnectorRuntime) -> ShopifyResult<Vec<Order>> {
        let url = format!("{}/orders.json?status=any&limit=50", self.base_url);
        self.get_wrapped::<OrdersResponse>(runtime, &url)
            .await
            .map(|r| r.orders)
    }

    pub async fn get_order(
        &self,
        runtime: &ConnectorRuntime,
        order_id: u64,
    ) -> ShopifyResult<Order> {
        let url = format!("{}/orders/{order_id}.json", self.base_url);
        self.get_wrapped::<OrderResponse>(runtime, &url)
            .await
            .map(|r| r.order)
    }

    pub async fn create_order(
        &self,
        runtime: &ConnectorRuntime,
        order: &CreateOrder,
    ) -> ShopifyResult<Order> {
        let url = format!("{}/orders.json", self.base_url);
        let body = json!({ "order": order });
        self.post_wrapped::<OrderResponse>(runtime, &url, &body)
            .await
            .map(|r| r.order)
    }

    // ── Customers ──

    pub async fn list_customers(&self, runtime: &ConnectorRuntime) -> ShopifyResult<Vec<Customer>> {
        let url = format!("{}/customers.json?limit=50", self.base_url);
        self.get_wrapped::<CustomersResponse>(runtime, &url)
            .await
            .map(|r| r.customers)
    }

    pub async fn get_customer(
        &self,
        runtime: &ConnectorRuntime,
        customer_id: u64,
    ) -> ShopifyResult<Customer> {
        let url = format!("{}/customers/{customer_id}.json", self.base_url);
        self.get_wrapped::<CustomerResponse>(runtime, &url)
            .await
            .map(|r| r.customer)
    }

    // ── Inventory ──

    pub async fn list_inventory_levels(
        &self,
        runtime: &ConnectorRuntime,
        location_id: u64,
    ) -> ShopifyResult<Vec<InventoryLevel>> {
        let url = format!(
            "{}/inventory_levels.json?location_ids={location_id}",
            self.base_url
        );
        self.get_wrapped::<InventoryLevelsResponse>(runtime, &url)
            .await
            .map(|r| r.inventory_levels)
    }

    // ── Generic HTTP helpers ──

    async fn get_wrapped<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> ShopifyResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            async move {
                debug!(attempt, url = %url, "GET");
                let req = authenticate(client.get(&url), &token);
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn post_wrapped<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> ShopifyResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %url, "POST");
                let req = authenticate(client.post(&url), &token).json(&body);
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn put_wrapped<T: serde::de::DeserializeOwned + Send + 'static>(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
        body: &serde_json::Value,
    ) -> ShopifyResult<T> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();
        let body = body.clone();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            let body = body.clone();
            async move {
                debug!(attempt, url = %url, "PUT");
                let req = authenticate(client.put(&url), &token).json(&body);
                handle_response::<T>(req, attempt).await
            }
        })
        .await
    }

    async fn delete_json(
        &self,
        runtime: &ConnectorRuntime,
        url: &str,
    ) -> ShopifyResult<serde_json::Value> {
        let url = url.to_string();
        let ctx = runtime.request_context();
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |attempt| {
            let url = url.clone();
            let client = self.client.clone();
            let token = self.access_token.clone();
            async move {
                debug!(attempt, url = %url, "DELETE");
                let req = authenticate(client.delete(&url), &token);
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => {
                        return AttemptOutcome::Retryable {
                            error: ShopifyError::Http(e),
                            retry_after: None,
                        };
                    }
                };
                let status = resp.status().as_u16();
                if let Some(outcome) = check_error_status::<serde_json::Value>(status) {
                    return outcome;
                }
                if resp.status().is_success() {
                    AttemptOutcome::Success(json!({"deleted": true}))
                } else {
                    let text = resp.text().await.unwrap_or_default();
                    AttemptOutcome::Terminal(ShopifyError::Api {
                        code: u32::from(status),
                        message: text,
                    })
                }
            }
        })
        .await
    }
}

// ── Free functions ──

fn authenticate(req: RequestBuilder, token: &str) -> RequestBuilder {
    if token.is_empty() {
        req
    } else {
        req.header("X-Shopify-Access-Token", token)
    }
}

fn check_error_status<T>(status: u16) -> Option<AttemptOutcome<T, ShopifyError>> {
    if status == 429 {
        return Some(AttemptOutcome::Retryable {
            error: ShopifyError::RateLimited {
                retry_after_ms: 2_000,
            },
            retry_after: Some(Duration::from_secs(2)),
        });
    }
    if status == 401 || status == 403 {
        return Some(AttemptOutcome::Terminal(ShopifyError::Unauthorized(
            format!("Authentication failed (HTTP {status})"),
        )));
    }
    if status == 404 {
        return Some(AttemptOutcome::Terminal(ShopifyError::NotFound(format!(
            "Resource not found (HTTP {status})"
        ))));
    }
    None
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    req: RequestBuilder,
    _attempt: u32,
) -> AttemptOutcome<T, ShopifyError> {
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return AttemptOutcome::Retryable {
                error: ShopifyError::Http(e),
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
            error: ShopifyError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(Duration::from_secs(2)).as_millis() as u64,
            },
            retry_after,
        };
    }

    if status == 401 || status == 403 {
        return AttemptOutcome::Terminal(ShopifyError::Unauthorized(format!(
            "Authentication failed (HTTP {status})"
        )));
    }

    if status == 404 {
        return AttemptOutcome::Terminal(ShopifyError::NotFound(format!(
            "Resource not found (HTTP {status})"
        )));
    }

    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        let err = ShopifyError::Api {
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

    match resp.json::<T>().await {
        Ok(v) => AttemptOutcome::Success(v),
        Err(e) => AttemptOutcome::Terminal(ShopifyError::Http(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_debug_redacts_token() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            ShopifyClient::new(
                "test-store.myshopify.com",
                "shpat_secret".into(),
                "2024-01",
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        let debug = format!("{rt:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("shpat_secret"));
    }

    #[test]
    fn secretless_detection() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            ShopifyClient::new(
                "test.myshopify.com",
                String::new(),
                "2024-01",
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(rt.is_secretless());

        let rt2 = fcp_async_core::runtime::block_on_sync(async {
            ShopifyClient::new(
                "test.myshopify.com",
                "token".into(),
                "2024-01",
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt2.is_secretless());
    }

    #[test]
    fn base_url_format() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            ShopifyClient::new(
                "my-store.myshopify.com",
                "t".into(),
                "2024-01",
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert_eq!(
            rt.base_url(),
            "https://my-store.myshopify.com/admin/api/2024-01"
        );
    }

    #[test]
    fn base_url_trailing_slash_trimmed() {
        let rt = fcp_async_core::runtime::block_on_sync(async {
            ShopifyClient::new(
                "store.myshopify.com/",
                "t".into(),
                "2024-01",
                HttpRetryConfig::default(),
            )
            .await
            .unwrap()
        })
        .unwrap();
        assert!(!rt.base_url().contains("//admin"));
    }
}
