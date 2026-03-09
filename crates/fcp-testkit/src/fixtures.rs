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

    // ---- Additional connector fixture tests ----

    #[test]
    fn test_connector_id_contains_archetype() {
        let id = test_connector_id();
        assert!(id.as_str().contains("test"));
    }

    #[test]
    fn connector_id_different_versions_differ() {
        let v1 = connector_id("conn", "api", "1.0.0");
        let v2 = connector_id("conn", "api", "2.0.0");
        assert_ne!(v1.as_str(), v2.as_str());
    }

    #[test]
    fn connector_id_different_archetypes_differ() {
        let a = connector_id("conn", "api", "1.0.0");
        let b = connector_id("conn", "storage", "1.0.0");
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn connector_id_different_names_differ() {
        let a = connector_id("alpha", "api", "1.0.0");
        let b = connector_id("beta", "api", "1.0.0");
        assert_ne!(a.as_str(), b.as_str());
    }

    // ---- Additional health fixture tests ----

    #[test]
    fn healthy_snapshot_is_healthy() {
        let snap = healthy_snapshot();
        assert!(snap.is_healthy());
    }

    #[test]
    fn unhealthy_snapshot_preserves_message() {
        let snap = unhealthy_snapshot("connection refused");
        let debug = format!("{:?}", snap.status);
        assert!(debug.contains("connection refused"));
    }

    #[test]
    fn degraded_snapshot_preserves_reason() {
        let snap = degraded_snapshot("high latency");
        let debug = format!("{:?}", snap.status);
        assert!(debug.contains("high latency"));
    }

    // ---- Additional JSON fixture tests ----

    #[test]
    fn json_success_is_object() {
        let v = json::success();
        assert!(v.is_object());
    }

    #[test]
    fn json_error_has_two_fields_in_error() {
        let v = json::error("E001", "Something broke");
        let err_obj = v["error"].as_object().unwrap();
        assert_eq!(err_obj.len(), 2);
    }

    #[test]
    fn json_paginated_single_page() {
        let items = vec!["a", "b"];
        let v = json::paginated(&items, 2, 0);
        assert_eq!(v["has_more"], false);
        assert_eq!(v["total"], 2);
    }

    #[test]
    fn json_paginated_empty_items() {
        let items: Vec<i32> = vec![];
        let v = json::paginated(&items, 0, 0);
        assert_eq!(v["items"].as_array().unwrap().len(), 0);
        assert_eq!(v["has_more"], false);
    }

    #[test]
    fn json_rate_limited_has_message() {
        let v = json::rate_limited(60);
        assert_eq!(v["error"]["message"], "Too many requests");
    }

    #[test]
    fn json_auth_error_has_message() {
        let v = json::auth_error();
        assert_eq!(v["error"]["message"], "Invalid or expired token");
    }

    #[test]
    fn json_not_found_with_different_resources() {
        let v1 = json::not_found("Account");
        let v2 = json::not_found("Project");
        assert!(v1["error"]["message"].as_str().unwrap().contains("Account"));
        assert!(v2["error"]["message"].as_str().unwrap().contains("Project"));
    }

    #[test]
    fn json_error_serde_roundtrip() {
        let v = json::error("TIMEOUT", "Request timed out");
        let serialized = serde_json::to_string(&v).unwrap();
        let deserialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(v, deserialized);
    }

    #[test]
    fn json_paginated_serde_roundtrip() {
        let items = vec![10, 20, 30];
        let v = json::paginated(&items, 100, 2);
        let serialized = serde_json::to_string(&v).unwrap();
        let deserialized: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(v, deserialized);
    }

    // ---- Additional config fixture tests ----

    #[test]
    fn config_api_key_is_object() {
        let v = config::api_key("test");
        assert!(v.is_object());
        assert_eq!(v.as_object().unwrap().len(), 1);
    }

    #[test]
    fn config_oauth_has_two_fields() {
        let v = config::oauth("cid", "csec");
        assert_eq!(v.as_object().unwrap().len(), 2);
    }

    #[test]
    fn config_oauth_with_tokens_has_four_fields() {
        let v = config::oauth_with_tokens("c", "s", "a", "r");
        assert_eq!(v.as_object().unwrap().len(), 4);
    }

    #[test]
    fn config_database_has_five_fields() {
        let v = config::database("h", 1234, "db", "u", "p");
        assert_eq!(v.as_object().unwrap().len(), 5);
    }

    #[test]
    fn config_bot_token_serde_roundtrip() {
        let v = config::bot_token("xoxb-test");
        let s = serde_json::to_string(&v).unwrap();
        let d: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v, d);
    }

    #[test]
    fn config_database_port_is_number() {
        let v = config::database("localhost", 3306, "mydb", "root", "pw");
        assert!(v["port"].is_number());
        assert_eq!(v["port"].as_u64().unwrap(), 3306);
    }

    // ---- Unicode and edge case fixture tests ----

    #[test]
    fn connector_id_with_hyphens_and_numbers() {
        let id = connector_id("my-conn-123", "data-api", "0.1.0");
        assert!(id.as_str().contains("my-conn-123"));
    }

    #[test]
    fn json_error_with_unicode_message() {
        let v = json::error("UNICODE_ERR", "Error: caf\u{00e9}");
        assert_eq!(v["error"]["message"], "Error: caf\u{00e9}");
    }

    #[test]
    fn json_not_found_with_empty_resource() {
        let v = json::not_found("");
        assert!(v["error"]["message"].as_str().unwrap().contains("not found"));
    }

    #[test]
    fn config_api_key_empty_string() {
        let v = config::api_key("");
        assert_eq!(v["api_key"], "");
    }

    #[test]
    fn config_oauth_serde_roundtrip() {
        let v = config::oauth("client-abc", "secret-xyz");
        let s = serde_json::to_string(&v).unwrap();
        let d: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v, d);
    }

    #[test]
    fn config_database_serde_roundtrip() {
        let v = config::database("db.example.com", 5432, "mydb", "user", "pass");
        let s = serde_json::to_string(&v).unwrap();
        let d: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v, d);
    }

    #[test]
    fn json_rate_limited_zero_retry() {
        let v = json::rate_limited(0);
        assert_eq!(v["error"]["retry_after"], 0);
    }

    #[test]
    fn json_paginated_large_total() {
        let items = vec![1];
        let v = json::paginated(&items, 1_000_000, 0);
        assert_eq!(v["total"], 1_000_000);
        assert_eq!(v["has_more"], true);
    }

    #[test]
    fn json_error_with_empty_strings() {
        let v = json::error("", "");
        assert_eq!(v["error"]["code"], "");
        assert_eq!(v["error"]["message"], "");
    }

    #[test]
    fn config_oauth_with_tokens_serde_roundtrip() {
        let v = config::oauth_with_tokens("c", "s", "a", "r");
        let s = serde_json::to_string(&v).unwrap();
        let d: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v, d);
    }
}
