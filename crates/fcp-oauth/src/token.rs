//! OAuth token types and management.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::{DEFAULT_REFRESH_THRESHOLD, OAuthError, OAuthResult};

/// OAuth token response from provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,

    /// Token type (usually "Bearer").
    pub token_type: String,

    /// Lifetime in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,

    /// Refresh token (if provided).
    #[serde(default)]
    pub refresh_token: Option<String>,

    /// Granted scopes (space-separated).
    #[serde(default)]
    pub scope: Option<String>,

    /// ID token (`OpenID Connect`).
    #[serde(default)]
    pub id_token: Option<String>,
}

/// Stored OAuth tokens with metadata.
#[derive(Clone, Serialize)]
pub struct OAuthTokens {
    /// The access token.
    access_token: String,

    /// Token type (usually "Bearer").
    token_type: String,

    /// When the token expires.
    expires_at: Option<DateTime<Utc>>,

    /// Refresh token for obtaining new access tokens.
    refresh_token: Option<String>,

    /// Granted scopes.
    scopes: Vec<String>,

    /// ID token (`OpenID Connect`).
    id_token: Option<String>,

    /// When the tokens were issued.
    issued_at: DateTime<Utc>,
}

impl std::fmt::Debug for OAuthTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthTokens")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_at", &self.expires_at)
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("scopes", &self.scopes)
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("issued_at", &self.issued_at)
            .finish()
    }
}

impl OAuthTokens {
    /// Create tokens from a token response.
    #[must_use]
    pub fn from_response(response: TokenResponse) -> Self {
        let now = Utc::now();
        let expires_at = response
            .expires_in
            .map(|secs| now + chrono::Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX)));

        let scopes = response
            .scope
            .map(|s| s.split_whitespace().map(String::from).collect())
            .unwrap_or_default();

        Self {
            access_token: response.access_token,
            token_type: response.token_type,
            expires_at,
            refresh_token: response.refresh_token,
            scopes,
            id_token: response.id_token,
            issued_at: now,
        }
    }

    /// Get the access token.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// Get the token type.
    #[must_use]
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// Get the refresh token if available.
    #[must_use]
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    /// Get the granted scopes.
    #[must_use]
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Get the ID token if available.
    #[must_use]
    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    /// Check if the token has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|exp| Utc::now() >= exp)
    }

    /// Check if the token needs refresh (within threshold of expiry).
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        self.needs_refresh_within(DEFAULT_REFRESH_THRESHOLD)
    }

    /// Check if the token needs refresh within a given threshold.
    #[must_use]
    pub fn needs_refresh_within(&self, threshold: Duration) -> bool {
        self.expires_at.is_some_and(|exp| {
            // Use saturating conversion to avoid panic on extreme durations
            let threshold_chrono =
                chrono::Duration::from_std(threshold).unwrap_or(chrono::TimeDelta::MAX);
            let threshold_time = Utc::now() + threshold_chrono;
            threshold_time >= exp
        })
    }

    /// Get time until expiration.
    #[must_use]
    pub fn time_until_expiry(&self) -> Option<Duration> {
        self.expires_at.and_then(|exp| {
            let now = Utc::now();
            if exp > now {
                (exp - now).to_std().ok()
            } else {
                None
            }
        })
    }

    /// Get the authorization header value.
    #[must_use]
    pub fn authorization_header(&self) -> String {
        format!("{} {}", self.token_type, self.access_token)
    }

    /// Update tokens from a refresh response.
    pub fn update_from_response(&mut self, response: TokenResponse) {
        let now = Utc::now();

        self.access_token = response.access_token;
        self.token_type = response.token_type;
        self.expires_at = response
            .expires_in
            .map(|secs| now + chrono::Duration::seconds(i64::try_from(secs).unwrap_or(i64::MAX)));
        self.issued_at = now;

        // Only update refresh token if a new one is provided
        if let Some(rt) = response.refresh_token {
            self.refresh_token = Some(rt);
        }

        // Update scopes if provided
        if let Some(scope) = response.scope {
            self.scopes = scope.split_whitespace().map(String::from).collect();
        }

        // Update ID token if provided
        if let Some(id) = response.id_token {
            self.id_token = Some(id);
        }
    }
}

/// In-memory token storage with automatic cleanup.
#[derive(Debug, Clone)]
pub struct TokenStore {
    tokens: Arc<RwLock<HashMap<String, StoredToken>>>,
    /// Time of last cleanup.
    last_cleanup: Arc<RwLock<Instant>>,
    /// Cleanup interval.
    cleanup_interval: Duration,
}

#[derive(Debug)]
struct StoredToken {
    tokens: OAuthTokens,
    /// Optional metadata for the stored token.
    metadata: HashMap<String, String>,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore {
    /// Create a new token store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            last_cleanup: Arc::new(RwLock::new(Instant::now())),
            cleanup_interval: Duration::from_secs(60), // Cleanup every minute
        }
    }

    /// Create with custom cleanup interval.
    #[must_use]
    pub const fn with_cleanup_interval(mut self, interval: Duration) -> Self {
        self.cleanup_interval = interval;
        self
    }

    /// Store tokens with a key.
    pub fn store(&self, key: &str, tokens: OAuthTokens) {
        self.maybe_cleanup();
        let mut store = self.tokens.write();
        store.insert(
            key.to_string(),
            StoredToken {
                tokens,
                metadata: HashMap::new(),
            },
        );
    }

    /// Store tokens with metadata.
    pub fn store_with_metadata(
        &self,
        key: &str,
        tokens: OAuthTokens,
        metadata: HashMap<String, String>,
    ) {
        self.maybe_cleanup();
        let mut store = self.tokens.write();
        store.insert(key.to_string(), StoredToken { tokens, metadata });
    }

    /// Get tokens by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<OAuthTokens> {
        let store = self.tokens.read();
        store.get(key).map(|s| s.tokens.clone())
    }

    /// Get tokens with metadata.
    #[must_use]
    pub fn get_with_metadata(&self, key: &str) -> Option<(OAuthTokens, HashMap<String, String>)> {
        let store = self.tokens.read();
        store
            .get(key)
            .map(|s| (s.tokens.clone(), s.metadata.clone()))
    }

    /// Check if tokens exist and are valid.
    #[must_use]
    pub fn has_valid_token(&self, key: &str) -> bool {
        self.get(key).is_some_and(|t| !t.is_expired())
    }

    /// Remove tokens by key.
    #[must_use]
    pub fn remove(&self, key: &str) -> Option<OAuthTokens> {
        let mut store = self.tokens.write();
        store.remove(key).map(|s| s.tokens)
    }

    /// Update tokens (used after refresh).
    ///
    /// # Errors
    /// Returns [`OAuthError::TokenNotFound`] when no tokens are stored for `key`.
    pub fn update(&self, key: &str, tokens: OAuthTokens) -> OAuthResult<()> {
        let mut store = self.tokens.write();
        if let Some(stored) = store.get_mut(key) {
            stored.tokens = tokens;
            Ok(())
        } else {
            Err(OAuthError::TokenNotFound(key.to_string()))
        }
    }

    /// Get all stored keys.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.tokens.read().keys().cloned().collect()
    }

    /// Clear all tokens.
    pub fn clear(&self) {
        self.tokens.write().clear();
    }

    /// Cleanup expired tokens.
    fn maybe_cleanup(&self) {
        let should_cleanup = {
            let last = self.last_cleanup.read();
            last.elapsed() >= self.cleanup_interval
        };

        if should_cleanup {
            self.tokens.write().retain(|_, v| !v.tokens.is_expired());
            *self.last_cleanup.write() = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_token_response(expires_in: Option<u64>) -> TokenResponse {
        TokenResponse {
            access_token: "test_access_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: Some("test_refresh_token".to_string()),
            scope: Some("read write".to_string()),
            id_token: None,
        }
    }

    #[test]
    fn test_token_from_response() {
        let response = mock_token_response(Some(3600));
        let tokens = OAuthTokens::from_response(response);

        assert_eq!(tokens.access_token(), "test_access_token");
        assert_eq!(tokens.token_type(), "Bearer");
        assert_eq!(tokens.refresh_token(), Some("test_refresh_token"));
        assert_eq!(tokens.scopes(), &["read", "write"]);
        assert!(!tokens.is_expired());
    }

    #[test]
    fn test_token_expiration() {
        // Token that expires immediately
        let response = TokenResponse {
            access_token: "test".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: Some(0),
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens = OAuthTokens::from_response(response);
        assert!(tokens.is_expired());
    }

    #[test]
    fn test_token_needs_refresh() {
        // Token that expires in 2 minutes (below default 5 minute threshold)
        let response = mock_token_response(Some(120));
        let tokens = OAuthTokens::from_response(response);
        assert!(tokens.needs_refresh());

        // Token that expires in 10 minutes (above threshold)
        let response = mock_token_response(Some(600));
        let tokens = OAuthTokens::from_response(response);
        assert!(!tokens.needs_refresh());
    }

    #[test]
    fn test_authorization_header() {
        let response = mock_token_response(Some(3600));
        let tokens = OAuthTokens::from_response(response);
        assert_eq!(tokens.authorization_header(), "Bearer test_access_token");
    }

    #[test]
    fn test_token_store() {
        let store = TokenStore::new();
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));

        // Store and retrieve
        store.store("user1", tokens.clone());
        assert!(store.has_valid_token("user1"));

        let retrieved = store.get("user1").unwrap();
        assert_eq!(retrieved.access_token(), tokens.access_token());

        // Remove
        let _ = store.remove("user1");
        assert!(!store.has_valid_token("user1"));
    }

    // ── New tests ──

    #[test]
    fn test_token_response_serde_roundtrip() {
        let resp = mock_token_response(Some(3600));
        let json = serde_json::to_string(&resp).unwrap();
        let roundtrip: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.access_token, "test_access_token");
        assert_eq!(roundtrip.token_type, "Bearer");
        assert_eq!(roundtrip.expires_in, Some(3600));
        assert_eq!(
            roundtrip.refresh_token,
            Some("test_refresh_token".to_string())
        );
    }

    #[test]
    fn test_token_no_expiry_is_not_expired() {
        let tokens = OAuthTokens::from_response(mock_token_response(None));
        assert!(!tokens.is_expired());
    }

    #[test]
    fn test_token_no_expiry_does_not_need_refresh() {
        let tokens = OAuthTokens::from_response(mock_token_response(None));
        assert!(!tokens.needs_refresh());
    }

    #[test]
    fn test_token_time_until_expiry() {
        // Non-expired token should return Some
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        assert!(tokens.time_until_expiry().is_some());

        // No expiry → None
        let tokens = OAuthTokens::from_response(mock_token_response(None));
        assert!(tokens.time_until_expiry().is_none());

        // Expired → None
        let tokens = OAuthTokens::from_response(mock_token_response(Some(0)));
        assert!(tokens.time_until_expiry().is_none());
    }

    #[test]
    fn test_token_id_token() {
        let mut resp = mock_token_response(Some(3600));
        resp.id_token = Some("id_tok_abc".into());
        let tokens = OAuthTokens::from_response(resp);
        assert_eq!(tokens.id_token(), Some("id_tok_abc"));
    }

    #[test]
    fn test_token_update_from_response() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let mut tokens = tokens;

        let new_resp = TokenResponse {
            access_token: "new_access".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: Some("new_refresh".into()),
            scope: Some("read write admin".into()),
            id_token: Some("new_id".into()),
        };

        tokens.update_from_response(new_resp);
        assert_eq!(tokens.access_token(), "new_access");
        assert_eq!(tokens.refresh_token(), Some("new_refresh"));
        assert_eq!(tokens.scopes(), &["read", "write", "admin"]);
        assert_eq!(tokens.id_token(), Some("new_id"));
    }

    #[test]
    fn test_token_update_preserves_refresh_if_not_provided() {
        let mut tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        assert_eq!(tokens.refresh_token(), Some("test_refresh_token"));

        let new_resp = TokenResponse {
            access_token: "new_access".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: None,
        };

        tokens.update_from_response(new_resp);
        assert_eq!(tokens.access_token(), "new_access");
        // Original refresh token should be preserved
        assert_eq!(tokens.refresh_token(), Some("test_refresh_token"));
    }

    #[test]
    fn test_token_store_keys() {
        let store = TokenStore::new();
        store.store(
            "user1",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        store.store(
            "user2",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );

        let keys = store.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"user1".to_string()));
        assert!(keys.contains(&"user2".to_string()));
    }

    #[test]
    fn test_token_store_clear() {
        let store = TokenStore::new();
        store.store(
            "user1",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        store.clear();
        assert!(store.keys().is_empty());
    }

    #[test]
    fn test_token_store_update_nonexistent() {
        let store = TokenStore::new();
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let result = store.update("missing", tokens);
        assert!(matches!(result, Err(OAuthError::TokenNotFound(_))));
    }

    #[test]
    fn test_token_store_with_metadata() {
        let store = TokenStore::new();
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "github".to_string());

        store.store_with_metadata("user1", tokens, metadata);

        let (_, meta) = store.get_with_metadata("user1").unwrap();
        assert_eq!(meta.get("provider"), Some(&"github".to_string()));
    }

    #[test]
    fn test_token_store_default() {
        let store = TokenStore::default();
        assert!(store.keys().is_empty());
    }

    // ── Batch: token response deserialization edge cases ──

    #[test]
    fn test_token_response_minimal_json() {
        // Only required fields
        let json = r#"{"access_token":"tok","token_type":"Bearer"}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "tok");
        assert_eq!(resp.token_type, "Bearer");
        assert!(resp.expires_in.is_none());
        assert!(resp.refresh_token.is_none());
        assert!(resp.scope.is_none());
        assert!(resp.id_token.is_none());
    }

    #[test]
    fn test_token_response_with_all_fields() {
        let json = r#"{
            "access_token": "at",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rt",
            "scope": "openid email",
            "id_token": "eyJhbGciOiJSUzI1NiJ9.e30.sig"
        }"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.expires_in, Some(3600));
        assert_eq!(resp.refresh_token, Some("rt".into()));
        assert_eq!(resp.scope, Some("openid email".into()));
        assert!(resp.id_token.is_some());
    }

    #[test]
    fn test_token_response_clone() {
        let resp = mock_token_response(Some(3600));
        let cloned = resp.clone();
        assert_eq!(resp.access_token, cloned.access_token);
        assert_eq!(resp.expires_in, cloned.expires_in);
    }

    // ── Batch: OAuthTokens edge cases ──

    #[test]
    fn test_token_no_scopes() {
        let resp = TokenResponse {
            access_token: "tok".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens = OAuthTokens::from_response(resp);
        assert!(tokens.scopes().is_empty());
    }

    #[test]
    fn test_token_single_scope() {
        let resp = TokenResponse {
            access_token: "tok".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: Some("read".into()),
            id_token: None,
        };
        let tokens = OAuthTokens::from_response(resp);
        assert_eq!(tokens.scopes(), &["read"]);
    }

    #[test]
    fn test_token_needs_refresh_within_custom_threshold() {
        // Token expires in 30 seconds
        let tokens = OAuthTokens::from_response(mock_token_response(Some(30)));
        // With 60-second threshold → needs refresh
        assert!(tokens.needs_refresh_within(Duration::from_secs(60)));
        // With 10-second threshold → does not need refresh
        assert!(!tokens.needs_refresh_within(Duration::from_secs(10)));
    }

    #[test]
    fn test_token_clone() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let cloned = tokens.clone();
        assert_eq!(tokens.access_token(), cloned.access_token());
        assert_eq!(tokens.token_type(), cloned.token_type());
        assert_eq!(tokens.refresh_token(), cloned.refresh_token());
        assert_eq!(tokens.scopes(), cloned.scopes());
    }

    #[test]
    fn test_token_serialize() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let json = serde_json::to_string(&tokens).unwrap();
        assert!(json.contains("test_access_token"));
        assert!(json.contains("Bearer"));
    }

    #[test]
    fn test_token_debug_contains_type() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let debug = format!("{tokens:?}");
        assert!(debug.contains("OAuthTokens"));
    }

    // ── Security regression: Debug redaction (1fcd949) ──

    #[test]
    fn test_token_debug_redacts_access_token() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let debug = format!("{tokens:?}");
        // The actual token value must NOT appear in debug output
        assert!(
            !debug.contains("test_access_token"),
            "access_token leaked in Debug output"
        );
        // Instead, [REDACTED] should appear
        assert!(
            debug.contains("[REDACTED]"),
            "Debug output missing [REDACTED] placeholder"
        );
    }

    #[test]
    fn test_token_debug_redacts_refresh_token() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let debug = format!("{tokens:?}");
        assert!(
            !debug.contains("test_refresh_token"),
            "refresh_token leaked in Debug output"
        );
    }

    #[test]
    fn test_token_debug_redacts_id_token() {
        let mut resp = mock_token_response(Some(3600));
        resp.id_token = Some("super_secret_id_token_jwt".into());
        let tokens = OAuthTokens::from_response(resp);
        let debug = format!("{tokens:?}");
        assert!(
            !debug.contains("super_secret_id_token_jwt"),
            "id_token leaked in Debug output"
        );
    }

    #[test]
    fn test_token_debug_preserves_non_sensitive_fields() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let debug = format!("{tokens:?}");
        // Non-sensitive fields should still be visible
        assert!(
            debug.contains("Bearer"),
            "token_type should be visible in Debug"
        );
        assert!(
            debug.contains("scopes"),
            "scopes field should be visible in Debug"
        );
        assert!(
            debug.contains("issued_at"),
            "issued_at field should be visible in Debug"
        );
    }

    // ── Batch: TokenStore advanced ──

    #[test]
    fn test_token_store_overwrite() {
        let store = TokenStore::new();
        let tokens1 = OAuthTokens::from_response(mock_token_response(Some(3600)));
        store.store("key", tokens1);

        let new_resp = TokenResponse {
            access_token: "new_tok".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens2 = OAuthTokens::from_response(new_resp);
        store.store("key", tokens2);

        let retrieved = store.get("key").unwrap();
        assert_eq!(retrieved.access_token(), "new_tok");
    }

    #[test]
    fn test_token_store_update_existing() {
        let store = TokenStore::new();
        store.store(
            "key",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );

        let new_tokens = OAuthTokens::from_response(TokenResponse {
            access_token: "updated".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: None,
            scope: None,
            id_token: None,
        });

        assert!(store.update("key", new_tokens).is_ok());
        assert_eq!(store.get("key").unwrap().access_token(), "updated");
    }

    #[test]
    fn test_token_store_remove_nonexistent() {
        let store = TokenStore::new();
        assert!(store.remove("nonexistent").is_none());
    }

    #[test]
    fn test_token_store_get_nonexistent() {
        let store = TokenStore::new();
        assert!(store.get("missing").is_none());
    }

    #[test]
    fn test_token_store_get_with_metadata_nonexistent() {
        let store = TokenStore::new();
        assert!(store.get_with_metadata("missing").is_none());
    }

    #[test]
    fn test_token_store_has_valid_token_expired() {
        let store = TokenStore::new();
        store.store(
            "expired",
            OAuthTokens::from_response(mock_token_response(Some(0))),
        );
        assert!(!store.has_valid_token("expired"));
    }

    #[test]
    fn test_token_store_has_valid_token_missing() {
        let store = TokenStore::new();
        assert!(!store.has_valid_token("missing"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn test_token_store_clone() {
        let store = TokenStore::new();
        store.store(
            "key",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        let cloned = store.clone();
        assert!(cloned.has_valid_token("key"));
    }

    #[test]
    fn test_token_store_with_cleanup_interval() {
        let store = TokenStore::new().with_cleanup_interval(Duration::from_secs(120));
        // Should still work normally
        store.store(
            "key",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        assert!(store.has_valid_token("key"));
    }

    // ── Expanded tests: TokenResponse serde edge cases ──

    #[test]
    fn test_token_response_expires_in_zero() {
        let json = r#"{"access_token":"t","token_type":"Bearer","expires_in":0}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.expires_in, Some(0));
    }

    #[test]
    fn test_token_response_expires_in_very_large() {
        let json = r#"{"access_token":"t","token_type":"Bearer","expires_in":999999999}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.expires_in, Some(999_999_999));
    }

    #[test]
    fn test_token_response_debug() {
        let resp = mock_token_response(Some(3600));
        let debug = format!("{resp:?}");
        assert!(debug.contains("TokenResponse"));
        assert!(debug.contains("test_access_token"));
    }

    #[test]
    fn test_token_response_empty_scope() {
        let json = r#"{"access_token":"t","token_type":"Bearer","scope":""}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.scope, Some(String::new()));
        // Empty scope string should yield no scopes after splitting
        let tokens = OAuthTokens::from_response(resp);
        assert!(tokens.scopes().is_empty());
    }

    // ── Expanded tests: OAuthTokens from_response details ──

    #[test]
    fn test_token_from_response_long_expiry() {
        let resp = mock_token_response(Some(86400)); // 24 hours
        let tokens = OAuthTokens::from_response(resp);
        assert!(!tokens.is_expired());
        assert!(!tokens.needs_refresh());
        let ttl = tokens.time_until_expiry().unwrap();
        // Should be close to 24 hours (within a few seconds)
        assert!(ttl.as_secs() > 86300);
    }

    #[test]
    fn test_token_authorization_header_custom_type() {
        let resp = TokenResponse {
            access_token: "my_token".into(),
            token_type: "MAC".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens = OAuthTokens::from_response(resp);
        assert_eq!(tokens.authorization_header(), "MAC my_token");
    }

    #[test]
    fn test_token_multiple_scopes_whitespace_variations() {
        let resp = TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: Some("read  write\tmanage".into()),
            id_token: None,
        };
        let tokens = OAuthTokens::from_response(resp);
        // split_whitespace handles multiple spaces and tabs
        assert_eq!(tokens.scopes(), &["read", "write", "manage"]);
    }

    #[test]
    fn test_token_update_does_not_overwrite_scopes_if_none() {
        let mut tokens = OAuthTokens::from_response(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: Some("original".into()),
            id_token: None,
        });
        assert_eq!(tokens.scopes(), &["original"]);

        tokens.update_from_response(TokenResponse {
            access_token: "new_t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None, // not provided
            id_token: None,
        });
        // original scopes should be preserved
        assert_eq!(tokens.scopes(), &["original"]);
    }

    #[test]
    fn test_token_update_overwrites_scopes_if_provided() {
        let mut tokens = OAuthTokens::from_response(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: Some("original".into()),
            id_token: None,
        });
        tokens.update_from_response(TokenResponse {
            access_token: "new_t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: Some("updated".into()),
            id_token: None,
        });
        assert_eq!(tokens.scopes(), &["updated"]);
    }

    #[test]
    fn test_token_update_does_not_overwrite_id_token_if_none() {
        let mut tokens = OAuthTokens::from_response(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: Some("original_id".into()),
        });
        tokens.update_from_response(TokenResponse {
            access_token: "new_t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: None,
        });
        assert_eq!(tokens.id_token(), Some("original_id"));
    }

    // ── Expanded tests: TokenStore advanced scenarios ──

    #[test]
    fn test_token_store_many_keys() {
        let store = TokenStore::new();
        for i in 0..20 {
            store.store(
                &format!("user_{i}"),
                OAuthTokens::from_response(mock_token_response(Some(3600))),
            );
        }
        assert_eq!(store.keys().len(), 20);
        assert!(store.has_valid_token("user_0"));
        assert!(store.has_valid_token("user_19"));
    }

    #[test]
    fn test_token_store_remove_returns_tokens() {
        let store = TokenStore::new();
        store.store(
            "key",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        let removed = store.remove("key");
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().access_token(), "test_access_token");
    }

    #[test]
    fn test_token_store_update_preserves_metadata() {
        let store = TokenStore::new();
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "google".to_string());
        store.store_with_metadata(
            "key",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
            metadata,
        );

        // Update the tokens
        let new_tokens = OAuthTokens::from_response(TokenResponse {
            access_token: "updated_tok".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: None,
            scope: None,
            id_token: None,
        });
        store.update("key", new_tokens).unwrap();

        // Metadata should still be there
        let (tokens, meta) = store.get_with_metadata("key").unwrap();
        assert_eq!(tokens.access_token(), "updated_tok");
        assert_eq!(meta.get("provider"), Some(&"google".to_string()));
    }

    #[test]
    fn test_token_store_empty_key() {
        let store = TokenStore::new();
        store.store(
            "",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        assert!(store.has_valid_token(""));
        assert!(store.get("").is_some());
    }

    #[test]
    fn test_token_store_unicode_key() {
        let store = TokenStore::new();
        store.store(
            "usuario_\u{00e9}tranger",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        assert!(store.has_valid_token("usuario_\u{00e9}tranger"));
    }

    #[test]
    fn test_token_store_clear_then_add() {
        let store = TokenStore::new();
        store.store(
            "key1",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        store.clear();
        assert!(store.keys().is_empty());
        store.store(
            "key2",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        assert_eq!(store.keys().len(), 1);
        assert!(store.has_valid_token("key2"));
    }

    #[test]
    fn test_token_store_debug() {
        let store = TokenStore::new();
        let debug = format!("{store:?}");
        assert!(debug.contains("TokenStore"));
    }

    #[test]
    fn test_token_needs_refresh_within_zero_threshold() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        // With zero threshold, only expired tokens need refresh
        assert!(!tokens.needs_refresh_within(Duration::from_secs(0)));
    }

    #[test]
    fn test_token_needs_refresh_within_huge_threshold() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        // With very large threshold, any token with expiry needs refresh
        assert!(tokens.needs_refresh_within(Duration::from_secs(999_999)));
    }

    // ── Expanded: token lifecycle edge cases ──

    #[test]
    fn test_token_from_response_no_optional_fields() {
        let resp = TokenResponse {
            access_token: "minimal_tok".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens = OAuthTokens::from_response(resp);
        assert_eq!(tokens.access_token(), "minimal_tok");
        assert_eq!(tokens.token_type(), "Bearer");
        assert!(tokens.refresh_token().is_none());
        assert!(tokens.scopes().is_empty());
        assert!(tokens.id_token().is_none());
        assert!(!tokens.is_expired());
        assert!(!tokens.needs_refresh());
    }

    #[test]
    fn test_token_authorization_header_empty_type() {
        let resp = TokenResponse {
            access_token: "tok".into(),
            token_type: String::new(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let tokens = OAuthTokens::from_response(resp);
        assert_eq!(tokens.authorization_header(), " tok");
    }

    #[test]
    fn test_token_multiple_whitespace_in_scope() {
        let resp = TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: Some("  read   write   admin  ".into()),
            id_token: None,
        };
        let tokens = OAuthTokens::from_response(resp);
        assert_eq!(tokens.scopes(), &["read", "write", "admin"]);
    }

    #[test]
    fn test_token_update_replaces_access_token_type() {
        let mut tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        assert_eq!(tokens.token_type(), "Bearer");

        tokens.update_from_response(TokenResponse {
            access_token: "new".into(),
            token_type: "MAC".into(),
            expires_in: Some(1800),
            refresh_token: None,
            scope: None,
            id_token: None,
        });
        assert_eq!(tokens.token_type(), "MAC");
        assert_eq!(tokens.access_token(), "new");
    }

    #[test]
    fn test_token_update_replaces_expiry() {
        let mut tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        assert!(!tokens.is_expired());

        tokens.update_from_response(TokenResponse {
            access_token: "new".into(),
            token_type: "Bearer".into(),
            expires_in: Some(0),
            refresh_token: None,
            scope: None,
            id_token: None,
        });
        assert!(tokens.is_expired());
    }

    #[test]
    fn test_token_time_until_expiry_long_lived() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(86400)));
        let ttl = tokens.time_until_expiry().unwrap();
        assert!(ttl.as_secs() > 86000);
        assert!(ttl.as_secs() <= 86400);
    }

    #[test]
    fn test_token_serialize_contains_all_fields() {
        let mut resp = mock_token_response(Some(3600));
        resp.id_token = Some("id_jwt".into());
        let tokens = OAuthTokens::from_response(resp);
        let json = serde_json::to_string(&tokens).unwrap();
        assert!(json.contains("access_token"));
        assert!(json.contains("token_type"));
        assert!(json.contains("scopes"));
        assert!(json.contains("id_token"));
        assert!(json.contains("issued_at"));
    }

    #[test]
    fn test_token_response_missing_access_token_rejected() {
        let json = r#"{"token_type":"Bearer"}"#;
        let result: Result<TokenResponse, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_response_missing_token_type_rejected() {
        let json = r#"{"access_token":"tok"}"#;
        let result: Result<TokenResponse, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_response_extra_fields_ignored() {
        let json = r#"{"access_token":"t","token_type":"Bearer","custom_field":"val"}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.access_token, "t");
    }

    // ── Expanded: TokenStore operations ──

    #[test]
    fn test_token_store_store_and_remove_multiple() {
        let store = TokenStore::new();
        for i in 0..10 {
            store.store(
                &format!("key_{i}"),
                OAuthTokens::from_response(mock_token_response(Some(3600))),
            );
        }
        assert_eq!(store.keys().len(), 10);

        for i in 0..5 {
            let _ = store.remove(&format!("key_{i}"));
        }
        assert_eq!(store.keys().len(), 5);
        assert!(!store.has_valid_token("key_0"));
        assert!(store.has_valid_token("key_5"));
    }

    #[test]
    fn test_token_store_overwrite_preserves_key_count() {
        let store = TokenStore::new();
        store.store(
            "key",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        store.store(
            "key",
            OAuthTokens::from_response(mock_token_response(Some(7200))),
        );
        assert_eq!(store.keys().len(), 1);
    }

    #[test]
    fn test_token_store_metadata_empty_map() {
        let store = TokenStore::new();
        store.store_with_metadata(
            "key",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
            HashMap::new(),
        );
        let (_, meta) = store.get_with_metadata("key").unwrap();
        assert!(meta.is_empty());
    }

    #[test]
    fn test_token_store_metadata_multiple_entries() {
        let store = TokenStore::new();
        let mut metadata = HashMap::new();
        metadata.insert("provider".to_string(), "google".to_string());
        metadata.insert("tenant".to_string(), "org-123".to_string());
        metadata.insert("region".to_string(), "us-east-1".to_string());
        store.store_with_metadata(
            "key",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
            metadata,
        );
        let (_, meta) = store.get_with_metadata("key").unwrap();
        assert_eq!(meta.len(), 3);
        assert_eq!(meta.get("tenant"), Some(&"org-123".to_string()));
    }

    #[test]
    fn test_token_store_update_error_message_contains_key() {
        let store = TokenStore::new();
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let err = store.update("missing_key", tokens).unwrap_err();
        assert!(err.to_string().contains("missing_key"));
    }

    #[test]
    fn test_token_store_keys_order_independent() {
        let store = TokenStore::new();
        store.store(
            "b",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        store.store(
            "a",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        let keys = store.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"a".to_string()));
        assert!(keys.contains(&"b".to_string()));
    }

    #[test]
    fn test_token_store_remove_returns_correct_token() {
        let store = TokenStore::new();
        let resp = TokenResponse {
            access_token: "specific_tok".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        store.store("key", OAuthTokens::from_response(resp));
        let removed = store.remove("key").unwrap();
        assert_eq!(removed.access_token(), "specific_tok");
    }

    #[test]
    fn test_token_store_get_returns_clone_not_reference() {
        let store = TokenStore::new();
        store.store(
            "key",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        let t1 = store.get("key").unwrap();
        let t2 = store.get("key").unwrap();
        // Both should have the same access token
        assert_eq!(t1.access_token(), t2.access_token());
    }

    #[test]
    fn test_token_needs_refresh_within_no_expiry() {
        let tokens = OAuthTokens::from_response(mock_token_response(None));
        assert!(!tokens.needs_refresh_within(Duration::from_secs(999_999)));
    }

    #[test]
    fn test_token_debug_shows_scopes() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let debug = format!("{tokens:?}");
        assert!(debug.contains("read"));
        assert!(debug.contains("write"));
    }

    // ── New batch: TokenResponse serde edge cases ──

    #[test]
    fn test_token_response_unicode_access_token() {
        let json = r#"{"access_token":"tok_\u00e9tranger","token_type":"Bearer"}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(resp.access_token.contains('\u{00e9}'));
    }

    #[test]
    fn test_token_response_empty_access_token() {
        let json = r#"{"access_token":"","token_type":"Bearer"}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(resp.access_token.is_empty());
        let tokens = OAuthTokens::from_response(resp);
        assert!(tokens.access_token().is_empty());
    }

    #[test]
    fn test_token_response_empty_token_type() {
        let json = r#"{"access_token":"tok","token_type":""}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(resp.token_type.is_empty());
    }

    #[test]
    fn test_token_response_scope_with_single_space() {
        let json = r#"{"access_token":"t","token_type":"B","scope":" "}"#;
        let resp: TokenResponse = serde_json::from_str(json).unwrap();
        let tokens = OAuthTokens::from_response(resp);
        // Single space should yield empty scopes after split_whitespace
        assert!(tokens.scopes().is_empty());
    }

    #[test]
    fn test_token_response_serde_roundtrip_all_none() {
        let resp = TokenResponse {
            access_token: "min".into(),
            token_type: "Bearer".into(),
            expires_in: None,
            refresh_token: None,
            scope: None,
            id_token: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let rt: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.access_token, "min");
        assert!(rt.expires_in.is_none());
        assert!(rt.refresh_token.is_none());
        assert!(rt.scope.is_none());
        assert!(rt.id_token.is_none());
    }

    #[test]
    fn test_token_response_serde_roundtrip_all_some() {
        let resp = TokenResponse {
            access_token: "at".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: Some("rt".into()),
            scope: Some("a b c".into()),
            id_token: Some("id".into()),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let rt: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.access_token, "at");
        assert_eq!(rt.expires_in, Some(7200));
        assert_eq!(rt.refresh_token.as_deref(), Some("rt"));
        assert_eq!(rt.scope.as_deref(), Some("a b c"));
        assert_eq!(rt.id_token.as_deref(), Some("id"));
    }

    // ── New batch: OAuthTokens advanced lifecycle ──

    #[test]
    fn test_token_update_replaces_id_token_when_provided() {
        let mut tokens = OAuthTokens::from_response(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: Some("old_id".into()),
        });
        tokens.update_from_response(TokenResponse {
            access_token: "new_t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: None,
            scope: None,
            id_token: Some("new_id".into()),
        });
        assert_eq!(tokens.id_token(), Some("new_id"));
    }

    #[test]
    fn test_token_update_replaces_refresh_token_when_provided() {
        let mut tokens = OAuthTokens::from_response(TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("old_rt".into()),
            scope: None,
            id_token: None,
        });
        tokens.update_from_response(TokenResponse {
            access_token: "new_t".into(),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some("new_rt".into()),
            scope: None,
            id_token: None,
        });
        assert_eq!(tokens.refresh_token(), Some("new_rt"));
    }

    #[test]
    fn test_token_clone_preserves_all_fields() {
        let resp = TokenResponse {
            access_token: "at".into(),
            token_type: "MAC".into(),
            expires_in: Some(1800),
            refresh_token: Some("rt".into()),
            scope: Some("x y z".into()),
            id_token: Some("id_jwt".into()),
        };
        let tokens = OAuthTokens::from_response(resp);
        let cloned = tokens.clone();
        assert_eq!(tokens.access_token(), cloned.access_token());
        assert_eq!(tokens.token_type(), cloned.token_type());
        assert_eq!(tokens.refresh_token(), cloned.refresh_token());
        assert_eq!(tokens.scopes(), cloned.scopes());
        assert_eq!(tokens.id_token(), cloned.id_token());
        assert_eq!(tokens.authorization_header(), cloned.authorization_header());
    }

    #[test]
    fn test_token_serialize_deserialize_preserves_access_token() {
        let tokens = OAuthTokens::from_response(mock_token_response(Some(3600)));
        let json = serde_json::to_string(&tokens).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["access_token"].as_str(), Some("test_access_token"));
        assert_eq!(val["token_type"].as_str(), Some("Bearer"));
    }

    // ── New batch: TokenStore concurrent-style operations ──

    #[test]
    fn test_token_store_store_get_remove_cycle() {
        let store = TokenStore::new();
        let key = "cycle_key";

        // Initially empty
        assert!(store.get(key).is_none());
        assert!(!store.has_valid_token(key));

        // Store
        store.store(
            key,
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        assert!(store.get(key).is_some());
        assert!(store.has_valid_token(key));

        // Remove
        let removed = store.remove(key);
        assert!(removed.is_some());
        assert!(store.get(key).is_none());
        assert!(!store.has_valid_token(key));
    }

    #[test]
    fn test_token_store_update_then_get_with_metadata() {
        let store = TokenStore::new();
        let mut metadata = HashMap::new();
        metadata.insert("env".to_string(), "production".to_string());

        store.store_with_metadata(
            "k",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
            metadata,
        );

        let new_tokens = OAuthTokens::from_response(TokenResponse {
            access_token: "updated_at".into(),
            token_type: "Bearer".into(),
            expires_in: Some(7200),
            refresh_token: None,
            scope: None,
            id_token: None,
        });
        store.update("k", new_tokens).unwrap();

        let (tokens, meta) = store.get_with_metadata("k").unwrap();
        assert_eq!(tokens.access_token(), "updated_at");
        // Metadata should still be preserved after update
        assert_eq!(meta.get("env"), Some(&"production".to_string()));
    }

    #[test]
    fn test_token_store_clear_does_not_affect_cleanup_interval() {
        let store = TokenStore::new().with_cleanup_interval(Duration::from_secs(999));
        store.store(
            "k",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        store.clear();
        // Should still be functional after clear
        store.store(
            "k2",
            OAuthTokens::from_response(mock_token_response(Some(3600))),
        );
        assert!(store.has_valid_token("k2"));
    }
}
