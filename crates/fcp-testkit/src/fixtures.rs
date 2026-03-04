//! Test fixtures for common FCP types.
//!
//! Provides pre-built test data and factory functions.

use fcp_core::{CapabilityToken, ConnectorId, HealthSnapshot};

// ─────────────────────────────────────────────────────────────────────────────
// Connector Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Create a test connector ID.
///
/// # Panics
///
/// Panics if the hard-coded connector ID is invalid.
#[must_use]
pub fn test_connector_id() -> ConnectorId {
    ConnectorId::new("test-connector", "test", "1.0.0").expect("valid connector id")
}

/// Create a connector ID with custom values.
///
/// # Panics
///
/// Panics if the provided connector ID components are invalid.
#[must_use]
pub fn connector_id(name: &str, archetype: &str, version: &str) -> ConnectorId {
    ConnectorId::new(name, archetype, version).expect("valid connector id")
}

// ─────────────────────────────────────────────────────────────────────────────
// Token Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Create a test capability token.
#[must_use]
pub fn test_token() -> CapabilityToken {
    CapabilityToken::test_token()
}

// ─────────────────────────────────────────────────────────────────────────────
// Health Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Create a healthy/ready status snapshot.
#[must_use]
pub fn healthy_snapshot() -> HealthSnapshot {
    HealthSnapshot::ready()
}

/// Create an unhealthy/error status snapshot.
#[must_use]
pub fn unhealthy_snapshot(message: &str) -> HealthSnapshot {
    HealthSnapshot::error(message)
}

/// Create a degraded status snapshot.
#[must_use]
pub fn degraded_snapshot(message: &str) -> HealthSnapshot {
    HealthSnapshot::degraded(message)
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Common test JSON values.
pub mod json {
    use serde_json::json;

    /// Empty object.
    #[must_use]
    pub fn empty() -> serde_json::Value {
        json!({})
    }

    /// Simple success response.
    #[must_use]
    pub fn success() -> serde_json::Value {
        json!({"success": true})
    }

    /// Simple error response.
    #[must_use]
    pub fn error(code: &str, message: &str) -> serde_json::Value {
        json!({
            "error": {
                "code": code,
                "message": message
            }
        })
    }

    /// Paginated response.
    #[must_use]
    pub fn paginated<T: serde::Serialize>(
        items: &[T],
        total: usize,
        page: usize,
    ) -> serde_json::Value {
        json!({
            "items": items,
            "total": total,
            "page": page,
            "has_more": (page + 1) * items.len() < total
        })
    }

    /// Rate limit error response.
    #[must_use]
    pub fn rate_limited(retry_after: u64) -> serde_json::Value {
        json!({
            "error": {
                "code": "RATE_LIMITED",
                "message": "Too many requests",
                "retry_after": retry_after
            }
        })
    }

    /// Authentication error response.
    #[must_use]
    pub fn auth_error() -> serde_json::Value {
        json!({
            "error": {
                "code": "UNAUTHORIZED",
                "message": "Invalid or expired token"
            }
        })
    }

    /// Not found error response.
    #[must_use]
    pub fn not_found(resource: &str) -> serde_json::Value {
        json!({
            "error": {
                "code": "NOT_FOUND",
                "message": format!("{} not found", resource)
            }
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Config Fixtures
// ─────────────────────────────────────────────────────────────────────────────

/// Common test configuration values.
pub mod config {
    use serde_json::json;

    /// Empty configuration.
    #[must_use]
    pub fn empty() -> serde_json::Value {
        json!({})
    }

    /// API key configuration.
    #[must_use]
    pub fn api_key(key: &str) -> serde_json::Value {
        json!({
            "api_key": key
        })
    }

    /// OAuth configuration.
    #[must_use]
    pub fn oauth(client_id: &str, client_secret: &str) -> serde_json::Value {
        json!({
            "client_id": client_id,
            "client_secret": client_secret
        })
    }

    /// OAuth with tokens.
    #[must_use]
    pub fn oauth_with_tokens(
        client_id: &str,
        client_secret: &str,
        access_token: &str,
        refresh_token: &str,
    ) -> serde_json::Value {
        json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "access_token": access_token,
            "refresh_token": refresh_token
        })
    }

    /// Bot token configuration (for chat platforms).
    #[must_use]
    pub fn bot_token(token: &str) -> serde_json::Value {
        json!({
            "token": token
        })
    }

    /// Database configuration.
    #[must_use]
    pub fn database(
        host: &str,
        port: u16,
        database: &str,
        user: &str,
        password: &str,
    ) -> serde_json::Value {
        json!({
            "host": host,
            "port": port,
            "database": database,
            "user": user,
            "password": password
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Connector fixtures ----

    #[test]
    fn test_connector_id_is_valid() {
        let id = test_connector_id();
        assert!(id.as_str().contains("test-connector"));
    }

    #[test]
    fn connector_id_custom_values() {
        let id = connector_id("my-conn", "storage", "2.0.0");
        assert!(id.as_str().contains("my-conn"));
    }

    // ---- Token fixtures ----

    #[test]
    fn test_token_creates_without_panic() {
        let _token = test_token();
    }

    // ---- Health fixtures ----

    #[test]
    fn healthy_snapshot_is_ready() {
        let snap = healthy_snapshot();
        assert!(snap.is_ready());
    }

    #[test]
    fn unhealthy_snapshot_is_not_ready() {
        let snap = unhealthy_snapshot("db down");
        assert!(!snap.is_ready());
    }

    #[test]
    fn degraded_snapshot_is_healthy_but_not_ready() {
        let snap = degraded_snapshot("slow responses");
        assert!(!snap.is_ready());
        assert!(snap.is_healthy());
    }

    // ---- JSON fixtures ----

    #[test]
    fn json_empty_is_object() {
        let v = json::empty();
        assert!(v.is_object());
        assert!(v.as_object().unwrap().is_empty());
    }

    #[test]
    fn json_success_has_true() {
        let v = json::success();
        assert_eq!(v["success"], true);
    }

    #[test]
    fn json_error_structure() {
        let v = json::error("NOT_FOUND", "Item missing");
        assert_eq!(v["error"]["code"], "NOT_FOUND");
        assert_eq!(v["error"]["message"], "Item missing");
    }

    #[test]
    fn json_paginated_structure() {
        let items = vec![1, 2, 3];
        let v = json::paginated(&items, 10, 0);
        assert_eq!(v["total"], 10);
        assert_eq!(v["page"], 0);
        assert!(v["items"].is_array());
        assert_eq!(v["items"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn json_paginated_has_more() {
        let items = vec![1, 2];
        let v = json::paginated(&items, 10, 0);
        assert_eq!(v["has_more"], true);
    }

    #[test]
    fn json_paginated_no_more() {
        let items = vec![1, 2, 3];
        let v = json::paginated(&items, 3, 0);
        assert_eq!(v["has_more"], false);
    }

    #[test]
    fn json_rate_limited_structure() {
        let v = json::rate_limited(30);
        assert_eq!(v["error"]["code"], "RATE_LIMITED");
        assert_eq!(v["error"]["retry_after"], 30);
    }

    #[test]
    fn json_auth_error_structure() {
        let v = json::auth_error();
        assert_eq!(v["error"]["code"], "UNAUTHORIZED");
    }

    #[test]
    fn json_not_found_structure() {
        let v = json::not_found("User");
        assert_eq!(v["error"]["code"], "NOT_FOUND");
        assert!(v["error"]["message"].as_str().unwrap().contains("User"));
    }

    // ---- Config fixtures ----

    #[test]
    fn config_empty_is_object() {
        let v = config::empty();
        assert!(v.is_object());
        assert!(v.as_object().unwrap().is_empty());
    }

    #[test]
    fn config_api_key() {
        let v = config::api_key("sk-test-123");
        assert_eq!(v["api_key"], "sk-test-123");
    }

    #[test]
    fn config_oauth() {
        let v = config::oauth("client-id", "client-secret");
        assert_eq!(v["client_id"], "client-id");
        assert_eq!(v["client_secret"], "client-secret");
    }

    #[test]
    fn config_oauth_with_tokens() {
        let v = config::oauth_with_tokens("cid", "cs", "at", "rt");
        assert_eq!(v["client_id"], "cid");
        assert_eq!(v["access_token"], "at");
        assert_eq!(v["refresh_token"], "rt");
    }

    #[test]
    fn config_bot_token() {
        let v = config::bot_token("xoxb-123");
        assert_eq!(v["token"], "xoxb-123");
    }

    #[test]
    fn config_database() {
        let v = config::database("localhost", 5432, "mydb", "admin", "secret");
        assert_eq!(v["host"], "localhost");
        assert_eq!(v["port"], 5432);
        assert_eq!(v["database"], "mydb");
        assert_eq!(v["user"], "admin");
        assert_eq!(v["password"], "secret");
    }
}
