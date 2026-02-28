//! Mock HTTP server for testing connectors.
//!
//! Provides a wrapper around wiremock for common FCP testing patterns.

use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A mock API server for testing HTTP-based connectors.
///
/// Wraps wiremock with convenience methods for common patterns.
pub struct MockApiServer {
    server: MockServer,
}

/// A recorded HTTP request.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Query string
    pub query: Option<String>,
    /// Request body (if any)
    pub body: Option<String>,
    /// Request headers
    pub headers: Vec<(String, String)>,
}

impl MockApiServer {
    /// Start a new mock server.
    pub async fn start() -> Self {
        let server = MockServer::start().await;
        Self { server }
    }

    /// Get the base URL of the mock server.
    #[must_use]
    pub fn base_url(&self) -> String {
        self.server.uri()
    }

    /// Get the server address.
    #[must_use]
    pub fn address(&self) -> std::net::SocketAddr {
        *self.server.address()
    }

    /// Get the underlying wiremock server for advanced configuration.
    #[must_use]
    pub const fn inner(&self) -> &MockServer {
        &self.server
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Response Setup
    // ─────────────────────────────────────────────────────────────────────────────

    /// Expect a GET request to the given path and respond with JSON.
    pub async fn expect_get(&self, request_path: &str, response: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(request_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&self.server)
            .await;
    }

    /// Expect a POST request to the given path and respond with JSON.
    pub async fn expect_post(&self, request_path: &str, response: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path(request_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&self.server)
            .await;
    }

    /// Expect a POST request with a specific JSON body.
    pub async fn expect_post_with_body(
        &self,
        request_path: &str,
        expected_body: serde_json::Value,
        response: serde_json::Value,
    ) {
        Mock::given(method("POST"))
            .and(path(request_path))
            .and(body_json(&expected_body))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&self.server)
            .await;
    }

    /// Expect any request to the given path and respond with JSON.
    pub async fn expect_json(&self, request_path: &str, response: serde_json::Value) {
        Mock::given(path(request_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&self.server)
            .await;
    }

    /// Expect a request and respond with an error status.
    pub async fn expect_error(
        &self,
        request_path: &str,
        status: u16,
        error_body: serde_json::Value,
    ) {
        Mock::given(path(request_path))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_json(error_body)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&self.server)
            .await;
    }

    /// Expect a request and respond with a delay.
    pub async fn expect_delayed(
        &self,
        request_path: &str,
        delay: std::time::Duration,
        response: serde_json::Value,
    ) {
        Mock::given(path(request_path))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(delay)
                    .set_body_json(response)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&self.server)
            .await;
    }

    /// Expect a request with a specific header.
    pub async fn expect_with_header(
        &self,
        request_path: &str,
        header_name: &str,
        header_value: &str,
        response: serde_json::Value,
    ) {
        Mock::given(path(request_path))
            .and(header(header_name, header_value))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&self.server)
            .await;
    }

    /// Expect a request with a query parameter.
    pub async fn expect_with_query(
        &self,
        request_path: &str,
        param_name: &str,
        param_value: &str,
        response: serde_json::Value,
    ) {
        Mock::given(path(request_path))
            .and(query_param(param_name, param_value))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(response)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&self.server)
            .await;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // OAuth Mocks
    // ─────────────────────────────────────────────────────────────────────────────

    /// Set up OAuth token endpoint mock.
    pub async fn expect_oauth_token(&self, token_path: &str, access_token: &str, expires_in: u64) {
        self.expect_post(
            token_path,
            serde_json::json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": expires_in
            }),
        )
        .await;
    }

    /// Set up OAuth refresh token mock.
    pub async fn expect_oauth_refresh(
        &self,
        token_path: &str,
        new_access_token: &str,
        new_refresh_token: &str,
        expires_in: u64,
    ) {
        self.expect_post(
            token_path,
            serde_json::json!({
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer",
                "expires_in": expires_in
            }),
        )
        .await;
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Verification
    // ─────────────────────────────────────────────────────────────────────────────

    /// Verify that a specific number of requests were received.
    ///
    /// # Panics
    ///
    /// Panics if the count doesn't match.
    pub async fn assert_request_count(&self, expected: usize) {
        let received = self.server.received_requests().await.unwrap_or_default();
        assert_eq!(
            received.len(),
            expected,
            "Expected {} requests but received {}",
            expected,
            received.len()
        );
    }

    /// Verify that at least one request was received to the given path.
    ///
    /// # Panics
    ///
    /// Panics if no matching request was found.
    pub async fn assert_received(&self, request_path: &str) {
        let received = self.server.received_requests().await.unwrap_or_default();
        let found = received.iter().any(|r| r.url.path() == request_path);
        assert!(
            found,
            "No request received to path '{}'. Received: {:?}",
            request_path,
            received.iter().map(|r| r.url.path()).collect::<Vec<_>>()
        );
    }

    /// Verify that no requests were received.
    ///
    /// # Panics
    ///
    /// Panics if any requests were received.
    pub async fn assert_no_requests(&self) {
        let received = self.server.received_requests().await.unwrap_or_default();
        assert!(
            received.is_empty(),
            "Expected no requests but received {}",
            received.len()
        );
    }

    /// Get all received requests for manual inspection.
    pub async fn received_requests(&self) -> Vec<wiremock::Request> {
        self.server.received_requests().await.unwrap_or_default()
    }

    /// Reset the mock server, clearing all mounted mocks.
    pub async fn reset(&self) {
        self.server.reset().await;
    }
}

/// Builder for creating complex mock scenarios.
pub struct MockScenarioBuilder {
    server: MockServer,
    mocks: Vec<Mock>,
}

impl MockScenarioBuilder {
    /// Create a new scenario builder.
    pub async fn new() -> Self {
        Self {
            server: MockServer::start().await,
            mocks: Vec::new(),
        }
    }

    /// Add a mock to the scenario.
    #[must_use]
    pub fn with_mock(mut self, mock: Mock) -> Self {
        self.mocks.push(mock);
        self
    }

    /// Build and return the configured mock server.
    pub async fn build(self) -> MockApiServer {
        for mock in self.mocks {
            mock.mount(&self.server).await;
        }
        MockApiServer {
            server: self.server,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[fcp_async_core::runtime::test]
    async fn test_mock_server_get() {
        let mock = MockApiServer::start().await;
        mock.expect_get("/api/test", serde_json::json!({"status": "ok"}))
            .await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/api/test", mock.base_url()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["status"], "ok");
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_server_post() {
        let mock = MockApiServer::start().await;
        mock.expect_post("/api/create", serde_json::json!({"id": "123"}))
            .await;

        let client = reqwest::Client::new();
        let response = client
            .post(format!("{}/api/create", mock.base_url()))
            .json(&serde_json::json!({"name": "test"}))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        mock.assert_received("/api/create").await;
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_server_error() {
        let mock = MockApiServer::start().await;
        mock.expect_error(
            "/api/fail",
            500,
            serde_json::json!({"error": "Internal Server Error"}),
        )
        .await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/api/fail", mock.base_url()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 500);
    }
}
