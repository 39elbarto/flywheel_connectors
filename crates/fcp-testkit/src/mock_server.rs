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

    // ── MockApiServer: base_url and address ────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_server_base_url_starts_with_http() {
        let mock = MockApiServer::start().await;
        assert!(mock.base_url().starts_with("http://"));
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_address_has_port() {
        let mock = MockApiServer::start().await;
        assert!(mock.address().port() > 0);
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_inner_ref() {
        let mock = MockApiServer::start().await;
        let _inner = mock.inner();
    }

    // ── MockApiServer: expect_json (any method) ────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_json_any_method() {
        let mock = MockApiServer::start().await;
        mock.expect_json("/api/any", serde_json::json!({"any": true}))
            .await;

        let client = reqwest::Client::new();

        // GET works
        let resp = client
            .get(format!("{}/api/any", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // POST also works
        let resp = client
            .post(format!("{}/api/any", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // ── MockApiServer: expect_with_header ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_with_header() {
        let mock = MockApiServer::start().await;
        mock.expect_with_header(
            "/api/auth",
            "Authorization",
            "Bearer test-token",
            serde_json::json!({"authenticated": true}),
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/auth", mock.base_url()))
            .header("Authorization", "Bearer test-token")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["authenticated"], true);
    }

    // ── MockApiServer: expect_with_query ───────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_with_query() {
        let mock = MockApiServer::start().await;
        mock.expect_with_query(
            "/api/search",
            "q",
            "test",
            serde_json::json!({"results": []}),
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/search?q=test", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // ── MockApiServer: expect_post_with_body ───────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_post_with_body() {
        let mock = MockApiServer::start().await;
        let expected_body = serde_json::json!({"name": "test"});
        mock.expect_post_with_body(
            "/api/create",
            expected_body.clone(),
            serde_json::json!({"id": "456"}),
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/api/create", mock.base_url()))
            .json(&expected_body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["id"], "456");
    }

    // ── MockApiServer: OAuth helpers ───────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_server_oauth_token() {
        let mock = MockApiServer::start().await;
        mock.expect_oauth_token("/oauth/token", "test-access-token", 3600)
            .await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/oauth/token", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["access_token"], "test-access-token");
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 3600);
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_oauth_refresh() {
        let mock = MockApiServer::start().await;
        mock.expect_oauth_refresh("/oauth/token", "new-access", "new-refresh", 7200)
            .await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/oauth/token", mock.base_url()))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["access_token"], "new-access");
        assert_eq!(body["refresh_token"], "new-refresh");
        assert_eq!(body["expires_in"], 7200);
    }

    // ── MockApiServer: verification ────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_server_assert_no_requests() {
        let mock = MockApiServer::start().await;
        mock.assert_no_requests().await;
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_assert_request_count() {
        let mock = MockApiServer::start().await;
        mock.expect_get("/api/count", serde_json::json!({})).await;

        let client = reqwest::Client::new();
        client
            .get(format!("{}/api/count", mock.base_url()))
            .send()
            .await
            .unwrap();
        client
            .get(format!("{}/api/count", mock.base_url()))
            .send()
            .await
            .unwrap();

        mock.assert_request_count(2).await;
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_received_requests() {
        let mock = MockApiServer::start().await;
        mock.expect_get("/api/log", serde_json::json!({})).await;

        let client = reqwest::Client::new();
        client
            .get(format!("{}/api/log", mock.base_url()))
            .send()
            .await
            .unwrap();

        let requests = mock.received_requests().await;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url.path(), "/api/log");
    }

    // ── MockApiServer: reset ───────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_server_reset_clears_mocks() {
        let mock = MockApiServer::start().await;
        mock.expect_get("/api/test", serde_json::json!({})).await;
        mock.reset().await;

        // After reset, the mock should no longer respond to this path
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/test", mock.base_url()))
            .send()
            .await
            .unwrap();
        // wiremock returns 404 for unmounted paths
        assert_eq!(resp.status(), 404);
    }

    // ── MockApiServer: error status codes ──────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_server_error_401() {
        let mock = MockApiServer::start().await;
        mock.expect_error(
            "/api/unauth",
            401,
            serde_json::json!({"error": "Unauthorized"}),
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/unauth", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_error_429() {
        let mock = MockApiServer::start().await;
        mock.expect_error(
            "/api/ratelimit",
            429,
            serde_json::json!({"error": "Too Many Requests"}),
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/ratelimit", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 429);
    }

    // ── MockScenarioBuilder ────────────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn scenario_builder_empty() {
        let server = MockScenarioBuilder::new().await.build().await;
        server.assert_no_requests().await;
    }

    #[fcp_async_core::runtime::test]
    async fn scenario_builder_with_mock() {
        let server = MockScenarioBuilder::new()
            .await
            .with_mock(
                Mock::given(method("GET"))
                    .and(path("/api/scenario"))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})),
                    ),
            )
            .build()
            .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/scenario", server.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // ── RecordedRequest ────────────────────────────────────────────────

    #[test]
    fn recorded_request_debug() {
        let req = RecordedRequest {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            query: Some("key=value".to_string()),
            body: None,
            headers: vec![("Content-Type".to_string(), "application/json".to_string())],
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("RecordedRequest"));
        assert!(dbg.contains("GET"));
    }

    #[test]
    fn recorded_request_clone() {
        let req = RecordedRequest {
            method: "POST".to_string(),
            path: "/api/create".to_string(),
            query: None,
            body: Some(r#"{"name":"test"}"#.to_string()),
            headers: vec![],
        };
        let cloned = req.clone();
        assert_eq!(req.method, cloned.method);
        assert_eq!(req.path, cloned.path);
        assert_eq!(req.body, cloned.body);
    }

    // ── RecordedRequest: additional edge cases ───────────────────────

    #[test]
    fn recorded_request_with_all_fields_populated() {
        let req = RecordedRequest {
            method: "PUT".to_string(),
            path: "/api/update/42".to_string(),
            query: Some("version=2&force=true".to_string()),
            body: Some(r#"{"status":"active"}"#.to_string()),
            headers: vec![
                ("Authorization".to_string(), "Bearer tok-123".to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
            ],
        };
        assert_eq!(req.method, "PUT");
        assert!(req.query.as_ref().unwrap().contains("version=2"));
        assert_eq!(req.headers.len(), 2);
    }

    #[test]
    fn recorded_request_clone_preserves_headers() {
        let req = RecordedRequest {
            method: "DELETE".to_string(),
            path: "/api/item/7".to_string(),
            query: None,
            body: None,
            headers: vec![("X-Custom".to_string(), "val".to_string())],
        };
        let cloned = req.clone();
        assert_eq!(req.headers.len(), cloned.headers.len());
        assert_eq!(req.headers[0].0, cloned.headers[0].0);
        assert_eq!(req.headers[0].1, cloned.headers[0].1);
    }

    #[test]
    fn recorded_request_empty_body_and_query() {
        let req = RecordedRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            body: None,
            headers: vec![],
        };
        assert!(req.query.is_none());
        assert!(req.body.is_none());
        assert!(req.headers.is_empty());
    }

    #[test]
    fn recorded_request_debug_contains_path() {
        let req = RecordedRequest {
            method: "PATCH".to_string(),
            path: "/api/patch-target".to_string(),
            query: None,
            body: None,
            headers: vec![],
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("PATCH"));
        assert!(dbg.contains("/api/patch-target"));
    }

    #[test]
    fn recorded_request_clone_with_empty_query_string() {
        let req = RecordedRequest {
            method: "GET".to_string(),
            path: "/search".to_string(),
            query: Some(String::new()),
            body: None,
            headers: vec![],
        };
        let cloned = req.clone();
        assert_eq!(req.query, cloned.query);
        assert!(cloned.query.as_ref().unwrap().is_empty());
    }

    #[test]
    fn recorded_request_unicode_path() {
        let req = RecordedRequest {
            method: "GET".to_string(),
            path: "/api/caf\u{00e9}".to_string(),
            query: None,
            body: None,
            headers: vec![],
        };
        assert!(req.path.contains("caf\u{00e9}"));
    }

    #[test]
    fn recorded_request_multiple_headers() {
        let req = RecordedRequest {
            method: "POST".to_string(),
            path: "/api/data".to_string(),
            query: None,
            body: Some("payload".to_string()),
            headers: vec![
                ("Authorization".to_string(), "Bearer tok".to_string()),
                ("Content-Type".to_string(), "application/json".to_string()),
                ("X-Request-Id".to_string(), "abc-123".to_string()),
            ],
        };
        assert_eq!(req.headers.len(), 3);
        let dbg = format!("{req:?}");
        assert!(dbg.contains("abc-123"));
    }

    #[test]
    fn recorded_request_clone_large_body() {
        let large_body = "x".repeat(10_000);
        let req = RecordedRequest {
            method: "POST".to_string(),
            path: "/bulk".to_string(),
            query: None,
            body: Some(large_body),
            headers: vec![],
        };
        let cloned = req.clone();
        assert_eq!(
            req.body.as_ref().unwrap().len(),
            cloned.body.as_ref().unwrap().len()
        );
    }

    // ── MockApiServer: additional HTTP tests ─────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_error_403_forbidden() {
        let mock = MockApiServer::start().await;
        mock.expect_error(
            "/api/forbidden",
            403,
            serde_json::json!({"error": "Forbidden"}),
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/forbidden", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "Forbidden");
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_error_404_not_found() {
        let mock = MockApiServer::start().await;
        mock.expect_error(
            "/api/missing",
            404,
            serde_json::json!({"error": "Not Found"}),
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/missing", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_error_503_service_unavailable() {
        let mock = MockApiServer::start().await;
        mock.expect_error(
            "/api/down",
            503,
            serde_json::json!({"error": "Service Unavailable"}),
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/down", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 503);
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_multiple_paths() {
        let mock = MockApiServer::start().await;
        mock.expect_get("/api/a", serde_json::json!({"path": "a"}))
            .await;
        mock.expect_get("/api/b", serde_json::json!({"path": "b"}))
            .await;

        let client = reqwest::Client::new();
        let resp_a = client
            .get(format!("{}/api/a", mock.base_url()))
            .send()
            .await
            .unwrap();
        let body_a: serde_json::Value = resp_a.json().await.unwrap();
        assert_eq!(body_a["path"], "a");

        let resp_b = client
            .get(format!("{}/api/b", mock.base_url()))
            .send()
            .await
            .unwrap();
        let body_b: serde_json::Value = resp_b.json().await.unwrap();
        assert_eq!(body_b["path"], "b");

        mock.assert_request_count(2).await;
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_post_json_body_response() {
        let mock = MockApiServer::start().await;
        mock.expect_post("/api/items", serde_json::json!({"created": true, "id": 99}))
            .await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/api/items", mock.base_url()))
            .json(&serde_json::json!({"name": "widget"}))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["created"], true);
        assert_eq!(body["id"], 99);
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_reset_clears_request_count() {
        let mock = MockApiServer::start().await;
        mock.expect_get("/api/ping", serde_json::json!({})).await;

        let client = reqwest::Client::new();
        client
            .get(format!("{}/api/ping", mock.base_url()))
            .send()
            .await
            .unwrap();

        mock.assert_request_count(1).await;
        mock.reset().await;
        mock.assert_no_requests().await;
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_base_url_contains_port() {
        let mock = MockApiServer::start().await;
        let url = mock.base_url();
        let port = mock.address().port();
        assert!(url.contains(&port.to_string()));
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_with_header_wrong_value_returns_404() {
        let mock = MockApiServer::start().await;
        mock.expect_with_header(
            "/api/auth",
            "X-Api-Key",
            "correct-key",
            serde_json::json!({"ok": true}),
        )
        .await;

        let client = reqwest::Client::new();
        // Wrong header value => no match => 404
        let resp = client
            .get(format!("{}/api/auth", mock.base_url()))
            .header("X-Api-Key", "wrong-key")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[fcp_async_core::runtime::test]
    async fn scenario_builder_multiple_mocks() {
        let server = MockScenarioBuilder::new()
            .await
            .with_mock(Mock::given(method("GET")).and(path("/one")).respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"n": 1})),
            ))
            .with_mock(Mock::given(method("GET")).and(path("/two")).respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"n": 2})),
            ))
            .build()
            .await;

        let client = reqwest::Client::new();
        let r1 = client
            .get(format!("{}/one", server.base_url()))
            .send()
            .await
            .unwrap();
        let b1: serde_json::Value = r1.json().await.unwrap();
        assert_eq!(b1["n"], 1);

        let r2 = client
            .get(format!("{}/two", server.base_url()))
            .send()
            .await
            .unwrap();
        let b2: serde_json::Value = r2.json().await.unwrap();
        assert_eq!(b2["n"], 2);

        server.assert_request_count(2).await;
    }

    // ---- MockApiServer: delayed response ----

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_delayed_responds() {
        let mock = MockApiServer::start().await;
        mock.expect_delayed(
            "/api/slow",
            std::time::Duration::from_millis(10),
            serde_json::json!({"delayed": true}),
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/slow", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["delayed"], true);
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_reqwest_roundtrip_inside_spawned_task() {
        let mock = MockApiServer::start().await;
        mock.expect_get("/api/spawned", serde_json::json!({"spawned": true}))
            .await;

        let url = format!("{}/api/spawned", mock.base_url());
        let body = fcp_async_core::task::spawn(async move {
            let client = reqwest::Client::new();
            let response = client
                .get(url)
                .send()
                .await
                .expect("spawned request should succeed");
            assert_eq!(response.status(), 200);
            response
                .json::<serde_json::Value>()
                .await
                .expect("spawned response should decode")
        })
        .await
        .expect("spawned request task should join");

        assert_eq!(body["spawned"], true);
        mock.assert_request_count(1).await;
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_delayed_reqwest_honors_context_cancellation() {
        let mock = MockApiServer::start().await;
        mock.expect_delayed(
            "/api/cancelled",
            std::time::Duration::from_millis(250),
            serde_json::json!({"delayed": true}),
        )
        .await;

        let context =
            fcp_async_core::ExecutionContext::request_scoped(std::time::Duration::from_secs(5));
        let request_context = context.clone();
        let client = reqwest::Client::new();
        let url = format!("{}/api/cancelled", mock.base_url());
        let request_task = fcp_async_core::task::spawn(async move {
            request_context
                .run(async move { client.get(url).send().await })
                .await
        });

        let mut observed_request = false;
        for _ in 0..50 {
            let requests = mock.received_requests().await;
            if requests.len() == 1 {
                observed_request = true;
                break;
            }
            fcp_async_core::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            observed_request,
            "delayed request should still reach wiremock before cancellation wins"
        );

        context.cancel();
        let err = request_task
            .await
            .expect("request task should join")
            .expect_err("context cancellation should win over delayed response");
        assert!(matches!(err, fcp_async_core::AsyncError::Cancelled));
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_reqwest_follow_up_request_succeeds_after_cancellation() {
        let mock = MockApiServer::start().await;
        mock.expect_delayed(
            "/api/cancelled",
            std::time::Duration::from_millis(250),
            serde_json::json!({"delayed": true}),
        )
        .await;
        mock.expect_get("/api/recovered", serde_json::json!({"recovered": true}))
            .await;

        let context =
            fcp_async_core::ExecutionContext::request_scoped(std::time::Duration::from_secs(5));
        let request_context = context.clone();
        let client = reqwest::Client::new();
        let cancelled_client = client.clone();
        let cancelled_url = format!("{}/api/cancelled", mock.base_url());
        let request_task = fcp_async_core::task::spawn(async move {
            request_context
                .run(async move { cancelled_client.get(cancelled_url).send().await })
                .await
        });

        let mut observed_cancelled = false;
        for _ in 0..50 {
            let requests = mock.received_requests().await;
            if requests.iter().any(|request| request.url.path() == "/api/cancelled") {
                observed_cancelled = true;
                break;
            }
            fcp_async_core::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            observed_cancelled,
            "cancelled request should reach wiremock before cancellation is triggered"
        );

        context.cancel();
        let err = request_task
            .await
            .expect("request task should join")
            .expect_err("context cancellation should win over delayed response");
        assert!(matches!(err, fcp_async_core::AsyncError::Cancelled));

        let recovery_body: serde_json::Value = client
            .get(format!("{}/api/recovered", mock.base_url()))
            .send()
            .await
            .expect("follow-up request should succeed after cancellation")
            .json()
            .await
            .expect("follow-up response should decode");
        assert_eq!(recovery_body["recovered"], true);

        let mut observed_paths = Vec::new();
        for _ in 0..50 {
            observed_paths = mock
                .received_requests()
                .await
                .into_iter()
                .map(|request| request.url.path().to_owned())
                .collect();
            if observed_paths.iter().any(|path| path == "/api/cancelled")
                && observed_paths.iter().any(|path| path == "/api/recovered")
            {
                break;
            }
            fcp_async_core::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        assert!(
            observed_paths.iter().any(|path| path == "/api/cancelled"),
            "expected the cancelled request to be recorded"
        );
        assert!(
            observed_paths.iter().any(|path| path == "/api/recovered"),
            "expected a follow-up request to succeed after cancellation"
        );
    }

    // ---- MockApiServer: expect_json with various content types ----

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_json_returns_json_content_type() {
        let mock = MockApiServer::start().await;
        mock.expect_json("/api/typed", serde_json::json!({"typed": true}))
            .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/typed", mock.base_url()))
            .send()
            .await
            .unwrap();
        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.contains("application/json"));
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_expect_error_body_preserved() {
        let mock = MockApiServer::start().await;
        mock.expect_error(
            "/api/err-body",
            422,
            serde_json::json!({"error": "Unprocessable", "details": ["field_a is required"]}),
        )
        .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/api/err-body", mock.base_url()))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 422);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["error"], "Unprocessable");
        assert!(body["details"].is_array());
    }

    #[fcp_async_core::runtime::test]
    async fn mock_server_two_servers_independent() {
        let mock_a = MockApiServer::start().await;
        let mock_b = MockApiServer::start().await;
        assert_ne!(mock_a.address().port(), mock_b.address().port());

        mock_a
            .expect_get("/ping", serde_json::json!({"from": "a"}))
            .await;
        mock_b
            .expect_get("/ping", serde_json::json!({"from": "b"}))
            .await;

        let client = reqwest::Client::new();
        let resp_a: serde_json::Value = client
            .get(format!("{}/ping", mock_a.base_url()))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let resp_b: serde_json::Value = client
            .get(format!("{}/ping", mock_b.base_url()))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(resp_a["from"], "a");
        assert_eq!(resp_b["from"], "b");
    }
}
