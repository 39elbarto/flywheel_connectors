//! Webhook automation for real-time sync with Airtable.
//!
//! Provides types and logic for managing Airtable webhook registrations,
//! verifying HMAC-SHA256 signatures on incoming payloads, tracking cursor
//! positions, and coordinating the webhook lifecycle (registration, refresh,
//! expiration).

use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

// ── Webhook specification ──────────────────────────────────────────

/// Specification for registering a new webhook on an Airtable base.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookSpec {
    /// The table ID to watch for changes.
    pub table_id: String,
    /// The URL that Airtable will POST notifications to.
    pub notification_url: String,
    /// Optional cursor field ID for filtering changes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_field_id: Option<String>,
    /// Optional includes configuration for payload content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub includes: Option<WebhookIncludes>,
}

impl WebhookSpec {
    /// Create a new webhook spec with required fields.
    #[must_use]
    pub fn new(table_id: &str, notification_url: &str) -> Self {
        Self {
            table_id: table_id.to_string(),
            notification_url: notification_url.to_string(),
            cursor_field_id: None,
            includes: None,
        }
    }

    /// Add includes configuration.
    #[must_use]
    pub fn with_includes(mut self, includes: WebhookIncludes) -> Self {
        self.includes = Some(includes);
        self
    }

    /// Set the cursor field ID.
    #[must_use]
    pub fn with_cursor_field(mut self, field_id: &str) -> Self {
        self.cursor_field_id = Some(field_id.to_string());
        self
    }
}

/// Configuration for what data to include in webhook payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookIncludes {
    /// Field IDs whose cell values should be included in the payload.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "includeCellValuesInFieldIds"
    )]
    pub include_cell_values_in_field_ids: Option<Vec<String>>,
    /// Whether to include previous cell values in change notifications.
    #[serde(default, rename = "includePreviousCellValues")]
    pub include_previous_cell_values: bool,
    /// Whether to include previous field values in change notifications.
    #[serde(default, rename = "includePreviousFieldValues")]
    pub include_previous_field_values: bool,
}

impl Default for WebhookIncludes {
    fn default() -> Self {
        Self {
            include_cell_values_in_field_ids: None,
            include_previous_cell_values: false,
            include_previous_field_values: false,
        }
    }
}

// ── Webhook registration ───────────────────────────────────────────

/// A registered webhook, returned after successful creation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookRegistration {
    /// The unique webhook ID assigned by Airtable.
    pub id: String,
    /// Base64-encoded HMAC secret for verifying payloads.
    #[serde(rename = "macSecretBase64")]
    pub mac_secret_base64: String,
    /// The current cursor position.
    pub cursor: u64,
    /// The notification URL.
    #[serde(rename = "notificationUrl")]
    pub notification_url: String,
    /// Optional expiration time as an ISO 8601 string.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "expirationTime"
    )]
    pub expiration_time: Option<String>,
}

// ── Webhook notification payload ───────────────────────────────────

/// A single notification within a webhook payload delivery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookNotification {
    /// The base ID that the webhook is registered on.
    #[serde(rename = "baseId")]
    pub base_id: String,
    /// The webhook ID that generated this notification.
    #[serde(rename = "webhookId")]
    pub webhook_id: String,
    /// Timestamp of the change event.
    pub timestamp: String,
    /// Metadata about the action that triggered the notification.
    #[serde(default, rename = "actionMetadata")]
    pub action_metadata: serde_json::Value,
    /// Changed tables keyed by table ID.
    #[serde(default, rename = "changedTablesById")]
    pub changed_tables_by_id: serde_json::Value,
}

/// A batch of webhook notifications with cursor tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookPayload {
    /// The cursor position after processing this payload.
    pub cursor: u64,
    /// Whether there are more payloads to fetch.
    #[serde(default, rename = "mightHaveMore")]
    pub might_have_more: bool,
    /// The list of notifications in this batch.
    #[serde(default)]
    pub payloads: Vec<WebhookNotification>,
}

impl WebhookPayload {
    /// Parse a `WebhookPayload` from a JSON value.
    ///
    /// # Errors
    ///
    /// Returns an error string if required fields are missing or invalid.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, String> {
        let cursor = value
            .get("cursor")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| "missing or invalid 'cursor' field".to_string())?;

        let might_have_more = value
            .get("mightHaveMore")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);

        let payloads =
            if let Some(arr) = value.get("payloads").and_then(serde_json::Value::as_array) {
                arr.iter()
                    .enumerate()
                    .map(|(i, v)| {
                        serde_json::from_value(v.clone())
                            .map_err(|e| format!("invalid notification at index {i}: {e}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                Vec::new()
            };

        Ok(Self {
            cursor,
            might_have_more,
            payloads,
        })
    }
}

// ── Webhook cursor tracking ────────────────────────────────────────

/// Tracks the current cursor position for webhook payload consumption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookCursor {
    /// The current cursor value.
    pub cursor: u64,
    /// Whether this is the initial cursor (no payloads consumed yet).
    pub is_initial: bool,
}

impl WebhookCursor {
    /// Create the initial cursor (cursor=1, `is_initial`=true).
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            cursor: 1,
            is_initial: true,
        }
    }

    /// Advance the cursor to a new position.
    #[must_use]
    pub const fn advance(self, new_cursor: u64) -> Self {
        Self {
            cursor: new_cursor,
            is_initial: false,
        }
    }

    /// Check whether the current cursor is behind the target.
    #[must_use]
    pub const fn is_behind(&self, target: u64) -> bool {
        self.cursor < target
    }
}

// ── Webhook signature verification ─────────────────────────────────

/// Verifies HMAC-SHA256 signatures on incoming webhook payloads.
///
/// Airtable signs webhook deliveries using HMAC-SHA256 with a base64-encoded
/// secret provided at registration time.
pub struct WebhookVerifier {
    /// The decoded MAC secret bytes.
    secret: Vec<u8>,
}

impl WebhookVerifier {
    /// Create a new verifier from a base64-encoded MAC secret.
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 string cannot be decoded.
    pub fn new(mac_secret_base64: &str) -> Result<Self, String> {
        let secret = base64::engine::general_purpose::STANDARD
            .decode(mac_secret_base64)
            .map_err(|e| format!("invalid base64 secret: {e}"))?;
        if secret.is_empty() {
            return Err("MAC secret must not be empty".to_string());
        }
        Ok(Self { secret })
    }

    /// Verify an HMAC-SHA256 signature against the request body.
    ///
    /// The signature is expected to be a hex-encoded HMAC-SHA256 digest.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature does not match.
    pub fn verify(&self, body: &[u8], signature: &str) -> Result<(), String> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|e| format!("HMAC error: {e}"))?;
        mac.update(body);
        let expected = mac.finalize().into_bytes();
        let expected_hex = hex_encode(&expected);

        if constant_time_eq(expected_hex.as_bytes(), signature.as_bytes()) {
            Ok(())
        } else {
            Err("signature verification failed".to_string())
        }
    }
}

impl fmt::Debug for WebhookVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookVerifier")
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ── Webhook state ──────────────────────────────────────────────────

/// The current state of a webhook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookState {
    /// Webhook is active and receiving notifications.
    Active,
    /// Webhook has expired and needs re-registration.
    Expired,
    /// Webhook is being refreshed (extending expiration).
    Refreshing,
    /// Webhook is in an error state.
    Error(String),
}

impl fmt::Display for WebhookState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Expired => write!(f, "Expired"),
            Self::Refreshing => write!(f, "Refreshing"),
            Self::Error(msg) => write!(f, "Error: {msg}"),
        }
    }
}

// ── Webhook lifecycle manager ──────────────────────────────────────

/// Manages the lifecycle of a webhook registration: cursor tracking,
/// state management, and refresh decisions.
pub struct WebhookLifecycle {
    /// The webhook registration details.
    registration: WebhookRegistration,
    /// The current cursor position.
    cursor: WebhookCursor,
    /// The current state.
    state: WebhookState,
    /// Number of payloads processed.
    payloads_processed: u64,
}

impl WebhookLifecycle {
    /// Create a new lifecycle manager from a registration.
    #[must_use]
    pub const fn new(registration: WebhookRegistration) -> Self {
        let cursor = WebhookCursor {
            cursor: registration.cursor,
            is_initial: registration.cursor <= 1,
        };
        Self {
            registration,
            cursor,
            state: WebhookState::Active,
            payloads_processed: 0,
        }
    }

    /// Get the current webhook state.
    #[must_use]
    pub const fn state(&self) -> &WebhookState {
        &self.state
    }

    /// Get the current cursor.
    #[must_use]
    pub const fn cursor(&self) -> &WebhookCursor {
        &self.cursor
    }

    /// Get the registration details.
    #[must_use]
    pub const fn registration(&self) -> &WebhookRegistration {
        &self.registration
    }

    /// Get the number of payloads processed.
    #[must_use]
    pub const fn payloads_processed(&self) -> u64 {
        self.payloads_processed
    }

    /// Set the state to expired.
    pub fn mark_expired(&mut self) {
        self.state = WebhookState::Expired;
    }

    /// Set the state to refreshing.
    pub fn mark_refreshing(&mut self) {
        self.state = WebhookState::Refreshing;
    }

    /// Set the state to active (e.g. after a successful refresh).
    pub fn mark_active(&mut self) {
        self.state = WebhookState::Active;
    }

    /// Set the state to an error.
    pub fn mark_error(&mut self, message: String) {
        self.state = WebhookState::Error(message);
    }

    /// Process a webhook payload, advancing the cursor and returning the
    /// new notifications. Validates that the cursor is not behind the
    /// current position.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload cursor is behind our current
    /// position (indicates missed or duplicate payloads) or if the
    /// lifecycle is not in an active state.
    pub fn process_payload<'a>(
        &mut self,
        payload: &'a WebhookPayload,
    ) -> Result<Vec<&'a WebhookNotification>, String> {
        if self.state != WebhookState::Active {
            return Err(format!("cannot process payload in state: {}", self.state));
        }

        if payload.cursor < self.cursor.cursor {
            return Err(format!(
                "payload cursor {} is behind current cursor {}",
                payload.cursor, self.cursor.cursor
            ));
        }

        // Advance cursor to the payload's cursor
        self.cursor = self.cursor.advance(payload.cursor);
        self.payloads_processed += payload.payloads.len() as u64;

        Ok(payload.payloads.iter().collect())
    }

    /// Check whether the webhook needs a refresh based on expiration time.
    ///
    /// Returns true if:
    /// - The webhook has an expiration time that can be parsed as ISO 8601
    ///   and is within the next 24 hours (86400 seconds), OR
    /// - The webhook state is `Expired`.
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        if self.state == WebhookState::Expired {
            return true;
        }

        if let Some(ref exp) = self.registration.expiration_time {
            // Try to parse as ISO 8601 / RFC 3339
            if let Ok(expiration) = chrono::DateTime::parse_from_rfc3339(exp) {
                let now = chrono::Utc::now();
                let until_expiry = expiration.signed_duration_since(now);
                // Refresh if within 24 hours of expiration
                return until_expiry.num_seconds() < 86400;
            }
        }

        false
    }

    /// Update the expiration time (e.g. after a successful refresh).
    pub fn update_expiration(&mut self, new_expiration: Option<String>) {
        self.registration.expiration_time = new_expiration;
        if self.state == WebhookState::Refreshing {
            self.state = WebhookState::Active;
        }
    }
}

impl fmt::Debug for WebhookLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebhookLifecycle")
            .field("webhook_id", &self.registration.id)
            .field("cursor", &self.cursor)
            .field("state", &self.state)
            .field("payloads_processed", &self.payloads_processed)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ────────────────────────────────────────────────────

    fn sample_notification(base: &str, wh: &str, ts: &str) -> WebhookNotification {
        WebhookNotification {
            base_id: base.to_string(),
            webhook_id: wh.to_string(),
            timestamp: ts.to_string(),
            action_metadata: serde_json::json!({"source": "test"}),
            changed_tables_by_id: serde_json::json!({"tblABC": {"changedRecordsById": {}}}),
        }
    }

    fn sample_registration() -> WebhookRegistration {
        WebhookRegistration {
            id: "ach000001".to_string(),
            mac_secret_base64: "dGVzdHNlY3JldA==".to_string(), // "testsecret"
            cursor: 1,
            notification_url: "https://example.com/webhook".to_string(),
            expiration_time: Some("2030-01-01T00:00:00.000Z".to_string()),
        }
    }

    fn make_payload(cursor: u64, notifications: Vec<WebhookNotification>) -> WebhookPayload {
        WebhookPayload {
            cursor,
            might_have_more: false,
            payloads: notifications,
        }
    }

    // ── WebhookSpec builder ───────────────────────────────────────

    #[test]
    fn spec_new_sets_required_fields() {
        let spec = WebhookSpec::new("tbl123", "https://example.com/hook");
        assert_eq!(spec.table_id, "tbl123");
        assert_eq!(spec.notification_url, "https://example.com/hook");
        assert!(spec.cursor_field_id.is_none());
        assert!(spec.includes.is_none());
    }

    #[test]
    fn spec_with_includes() {
        let inc = WebhookIncludes {
            include_cell_values_in_field_ids: Some(vec!["fld1".into(), "fld2".into()]),
            include_previous_cell_values: true,
            include_previous_field_values: false,
        };
        let spec = WebhookSpec::new("tbl1", "https://hook.test").with_includes(inc.clone());
        assert_eq!(spec.includes, Some(inc));
    }

    #[test]
    fn spec_with_cursor_field() {
        let spec = WebhookSpec::new("tbl1", "https://hook.test").with_cursor_field("fldCursor");
        assert_eq!(spec.cursor_field_id.as_deref(), Some("fldCursor"));
    }

    #[test]
    fn spec_builder_chaining() {
        let spec = WebhookSpec::new("tblX", "https://cb.test")
            .with_cursor_field("fldY")
            .with_includes(WebhookIncludes::default());
        assert_eq!(spec.table_id, "tblX");
        assert_eq!(spec.cursor_field_id.as_deref(), Some("fldY"));
        assert!(spec.includes.is_some());
    }

    #[test]
    fn spec_serde_roundtrip() {
        let spec = WebhookSpec::new("tbl42", "https://a.b/c")
            .with_cursor_field("fld99")
            .with_includes(WebhookIncludes {
                include_cell_values_in_field_ids: Some(vec!["fld1".into()]),
                include_previous_cell_values: true,
                include_previous_field_values: true,
            });
        let json = serde_json::to_string(&spec).unwrap();
        let deserialized: WebhookSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, deserialized);
    }

    #[test]
    fn spec_serde_minimal() {
        let spec = WebhookSpec::new("tbl1", "https://x.y");
        let json = serde_json::to_string(&spec).unwrap();
        // Optional fields should be omitted
        assert!(!json.contains("cursor_field_id"));
        assert!(!json.contains("includes"));
        let deserialized: WebhookSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, deserialized);
    }

    #[test]
    fn spec_deserialize_unknown_fields() {
        let json = r#"{"table_id":"t","notification_url":"u","extra":"ignored"}"#;
        // serde should not fail on unknown fields (default behavior)
        let result: Result<WebhookSpec, _> = serde_json::from_str(json);
        assert!(result.is_ok());
    }

    #[test]
    fn spec_empty_table_id() {
        let spec = WebhookSpec::new("", "https://x.y");
        assert!(spec.table_id.is_empty());
    }

    // ── WebhookIncludes ───────────────────────────────────────────

    #[test]
    fn includes_default_all_false() {
        let inc = WebhookIncludes::default();
        assert!(inc.include_cell_values_in_field_ids.is_none());
        assert!(!inc.include_previous_cell_values);
        assert!(!inc.include_previous_field_values);
    }

    #[test]
    fn includes_serde_roundtrip() {
        let inc = WebhookIncludes {
            include_cell_values_in_field_ids: Some(vec!["fld1".into(), "fld2".into()]),
            include_previous_cell_values: true,
            include_previous_field_values: false,
        };
        let json = serde_json::to_string(&inc).unwrap();
        let parsed: WebhookIncludes = serde_json::from_str(&json).unwrap();
        assert_eq!(inc, parsed);
    }

    #[test]
    fn includes_serde_empty_field_ids() {
        let inc = WebhookIncludes {
            include_cell_values_in_field_ids: Some(Vec::new()),
            include_previous_cell_values: false,
            include_previous_field_values: false,
        };
        let json = serde_json::to_string(&inc).unwrap();
        let parsed: WebhookIncludes = serde_json::from_str(&json).unwrap();
        assert_eq!(inc, parsed);
    }

    #[test]
    fn includes_serde_uses_camel_case_keys() {
        let inc = WebhookIncludes {
            include_cell_values_in_field_ids: Some(vec!["fld1".into()]),
            include_previous_cell_values: true,
            include_previous_field_values: true,
        };
        let json = serde_json::to_string(&inc).unwrap();
        assert!(json.contains("includeCellValuesInFieldIds"));
        assert!(json.contains("includePreviousCellValues"));
        assert!(json.contains("includePreviousFieldValues"));
    }

    #[test]
    fn includes_clone_eq() {
        let a = WebhookIncludes {
            include_cell_values_in_field_ids: Some(vec!["f".into()]),
            include_previous_cell_values: true,
            include_previous_field_values: true,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // ── WebhookRegistration serde ─────────────────────────────────

    #[test]
    fn registration_serde_roundtrip() {
        let reg = sample_registration();
        let json = serde_json::to_string(&reg).unwrap();
        let parsed: WebhookRegistration = serde_json::from_str(&json).unwrap();
        assert_eq!(reg, parsed);
    }

    #[test]
    fn registration_serde_without_expiration() {
        let mut reg = sample_registration();
        reg.expiration_time = None;
        let json = serde_json::to_string(&reg).unwrap();
        assert!(!json.contains("expirationTime"));
        let parsed: WebhookRegistration = serde_json::from_str(&json).unwrap();
        assert!(parsed.expiration_time.is_none());
    }

    #[test]
    fn registration_serde_camel_case() {
        let reg = sample_registration();
        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("macSecretBase64"));
        assert!(json.contains("notificationUrl"));
        assert!(json.contains("expirationTime"));
    }

    #[test]
    fn registration_debug_output() {
        let reg = sample_registration();
        let dbg = format!("{reg:?}");
        assert!(dbg.contains("ach000001"));
    }

    #[test]
    fn registration_clone() {
        let reg = sample_registration();
        let cloned = reg.clone();
        assert_eq!(reg, cloned);
    }

    // ── WebhookNotification ───────────────────────────────────────

    #[test]
    fn notification_serde_roundtrip() {
        let n = sample_notification("appXYZ", "ach001", "2026-01-01T00:00:00Z");
        let json = serde_json::to_string(&n).unwrap();
        let parsed: WebhookNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(n, parsed);
    }

    #[test]
    fn notification_camel_case_keys() {
        let n = sample_notification("app1", "ach1", "2026-01-01T00:00:00Z");
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("baseId"));
        assert!(json.contains("webhookId"));
        assert!(json.contains("actionMetadata"));
        assert!(json.contains("changedTablesById"));
    }

    #[test]
    fn notification_with_empty_action_metadata() {
        let mut n = sample_notification("app1", "ach1", "t");
        n.action_metadata = serde_json::json!({});
        let json = serde_json::to_string(&n).unwrap();
        let parsed: WebhookNotification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action_metadata, serde_json::json!({}));
    }

    #[test]
    fn notification_with_null_changed_tables() {
        let mut n = sample_notification("app1", "ach1", "t");
        n.changed_tables_by_id = serde_json::Value::Null;
        let json = serde_json::to_string(&n).unwrap();
        let parsed: WebhookNotification = serde_json::from_str(&json).unwrap();
        assert!(parsed.changed_tables_by_id.is_null());
    }

    #[test]
    fn notification_clone_and_eq() {
        let n = sample_notification("app1", "ach1", "ts");
        let cloned = n.clone();
        assert_eq!(n, cloned);
    }

    // ── WebhookPayload ────────────────────────────────────────────

    #[test]
    fn payload_serde_roundtrip() {
        let p = make_payload(5, vec![sample_notification("app1", "ach1", "t1")]);
        let json = serde_json::to_string(&p).unwrap();
        let parsed: WebhookPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(p, parsed);
    }

    #[test]
    fn payload_empty_notifications() {
        let p = make_payload(1, vec![]);
        assert!(p.payloads.is_empty());
        let json = serde_json::to_string(&p).unwrap();
        let parsed: WebhookPayload = serde_json::from_str(&json).unwrap();
        assert!(parsed.payloads.is_empty());
    }

    #[test]
    fn payload_might_have_more() {
        let p = WebhookPayload {
            cursor: 10,
            might_have_more: true,
            payloads: vec![],
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(json.contains("mightHaveMore"));
        let parsed: WebhookPayload = serde_json::from_str(&json).unwrap();
        assert!(parsed.might_have_more);
    }

    #[test]
    fn payload_multiple_notifications() {
        let p = make_payload(
            3,
            vec![
                sample_notification("app1", "ach1", "t1"),
                sample_notification("app1", "ach1", "t2"),
                sample_notification("app1", "ach1", "t3"),
            ],
        );
        assert_eq!(p.payloads.len(), 3);
    }

    #[test]
    fn payload_from_json_valid() {
        let json = serde_json::json!({
            "cursor": 5,
            "mightHaveMore": false,
            "payloads": [
                {
                    "baseId": "app1",
                    "webhookId": "ach1",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actionMetadata": {},
                    "changedTablesById": {}
                }
            ]
        });
        let result = WebhookPayload::from_json(&json);
        assert!(result.is_ok());
        let payload = result.unwrap();
        assert_eq!(payload.cursor, 5);
        assert_eq!(payload.payloads.len(), 1);
    }

    #[test]
    fn payload_from_json_missing_cursor() {
        let json = serde_json::json!({
            "mightHaveMore": false,
            "payloads": []
        });
        let result = WebhookPayload::from_json(&json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cursor"));
    }

    #[test]
    fn payload_from_json_cursor_as_string() {
        let json = serde_json::json!({
            "cursor": "not_a_number",
            "payloads": []
        });
        let result = WebhookPayload::from_json(&json);
        assert!(result.is_err());
    }

    #[test]
    fn payload_from_json_missing_payloads_defaults_empty() {
        let json = serde_json::json!({
            "cursor": 1
        });
        let result = WebhookPayload::from_json(&json).unwrap();
        assert!(result.payloads.is_empty());
    }

    #[test]
    fn payload_from_json_invalid_notification() {
        let json = serde_json::json!({
            "cursor": 1,
            "payloads": [{"invalid": true}]
        });
        let result = WebhookPayload::from_json(&json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("index 0"));
    }

    #[test]
    fn payload_from_json_null_value() {
        let result = WebhookPayload::from_json(&serde_json::Value::Null);
        assert!(result.is_err());
    }

    #[test]
    fn payload_from_json_empty_object() {
        let result = WebhookPayload::from_json(&serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn payload_from_json_cursor_zero() {
        let json = serde_json::json!({
            "cursor": 0,
            "payloads": []
        });
        let result = WebhookPayload::from_json(&json).unwrap();
        assert_eq!(result.cursor, 0);
    }

    #[test]
    fn payload_from_json_large_cursor() {
        let json = serde_json::json!({
            "cursor": u64::MAX,
            "payloads": []
        });
        // u64::MAX cannot be represented exactly as f64 so as_u64() may fail
        // Depending on serde_json behavior, this might or might not parse
        let _ = WebhookPayload::from_json(&json);
    }

    #[test]
    fn payload_from_json_might_have_more_defaults_false() {
        let json = serde_json::json!({
            "cursor": 1,
            "payloads": []
        });
        let result = WebhookPayload::from_json(&json).unwrap();
        assert!(!result.might_have_more);
    }

    // ── WebhookCursor ─────────────────────────────────────────────

    #[test]
    fn cursor_initial() {
        let c = WebhookCursor::initial();
        assert_eq!(c.cursor, 1);
        assert!(c.is_initial);
    }

    #[test]
    fn cursor_advance() {
        let c = WebhookCursor::initial().advance(5);
        assert_eq!(c.cursor, 5);
        assert!(!c.is_initial);
    }

    #[test]
    fn cursor_advance_multiple_times() {
        let c = WebhookCursor::initial().advance(3).advance(7).advance(10);
        assert_eq!(c.cursor, 10);
        assert!(!c.is_initial);
    }

    #[test]
    fn cursor_is_behind_true() {
        let c = WebhookCursor::initial();
        assert!(c.is_behind(5));
    }

    #[test]
    fn cursor_is_behind_false_equal() {
        let c = WebhookCursor::initial();
        assert!(!c.is_behind(1));
    }

    #[test]
    fn cursor_is_behind_false_ahead() {
        let c = WebhookCursor::initial().advance(10);
        assert!(!c.is_behind(5));
    }

    #[test]
    fn cursor_is_behind_zero() {
        let c = WebhookCursor {
            cursor: 0,
            is_initial: true,
        };
        assert!(!c.is_behind(0));
        assert!(c.is_behind(1));
    }

    #[test]
    fn cursor_serde_roundtrip() {
        let c = WebhookCursor::initial();
        let json = serde_json::to_string(&c).unwrap();
        let parsed: WebhookCursor = serde_json::from_str(&json).unwrap();
        assert_eq!(c, parsed);
    }

    #[test]
    fn cursor_advance_to_same_value() {
        let c = WebhookCursor::initial().advance(1);
        assert_eq!(c.cursor, 1);
        assert!(!c.is_initial);
    }

    #[test]
    fn cursor_copy_semantics() {
        let c1 = WebhookCursor::initial();
        let c2 = c1;
        // Both should still work (Copy)
        assert_eq!(c1.cursor, c2.cursor);
    }

    #[test]
    fn cursor_debug_format() {
        let c = WebhookCursor::initial();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("cursor"));
        assert!(dbg.contains("is_initial"));
    }

    // ── WebhookVerifier ───────────────────────────────────────────

    #[test]
    fn verifier_new_valid_secret() {
        let v = WebhookVerifier::new("dGVzdHNlY3JldA=="); // "testsecret"
        assert!(v.is_ok());
    }

    #[test]
    fn verifier_new_invalid_base64() {
        let v = WebhookVerifier::new("not!valid!base64!!!");
        assert!(v.is_err());
        assert!(v.unwrap_err().contains("invalid base64"));
    }

    #[test]
    fn verifier_new_empty_decoded_secret() {
        // base64 of empty string is ""
        let v = WebhookVerifier::new("");
        // Empty string is invalid base64 of zero bytes... but let's check
        // Actually base64 "" decodes to empty vec
        assert!(v.is_err());
    }

    #[test]
    fn verifier_verify_valid_signature() {
        let secret = "dGVzdHNlY3JldA=="; // "testsecret"
        let verifier = WebhookVerifier::new(secret).unwrap();
        let body = b"hello world";

        // Compute expected HMAC-SHA256
        let mut mac = HmacSha256::new_from_slice(b"testsecret").unwrap();
        mac.update(body);
        let expected = mac.finalize().into_bytes();
        let signature = hex_encode(&expected);

        let result = verifier.verify(body, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn verifier_verify_invalid_signature() {
        let verifier = WebhookVerifier::new("dGVzdHNlY3JldA==").unwrap();
        let result = verifier.verify(
            b"test body",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verification failed"));
    }

    #[test]
    fn verifier_verify_wrong_body() {
        let verifier = WebhookVerifier::new("dGVzdHNlY3JldA==").unwrap();
        let body_a = b"body a";
        let body_b = b"body b";

        let mut mac = HmacSha256::new_from_slice(b"testsecret").unwrap();
        mac.update(body_a);
        let sig = hex_encode(&mac.finalize().into_bytes());

        // Verify with wrong body
        let result = verifier.verify(body_b, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn verifier_verify_empty_body() {
        let verifier = WebhookVerifier::new("dGVzdHNlY3JldA==").unwrap();
        let body = b"";

        let mut mac = HmacSha256::new_from_slice(b"testsecret").unwrap();
        mac.update(body);
        let sig = hex_encode(&mac.finalize().into_bytes());

        assert!(verifier.verify(body, &sig).is_ok());
    }

    #[test]
    fn verifier_verify_empty_signature() {
        let verifier = WebhookVerifier::new("dGVzdHNlY3JldA==").unwrap();
        let result = verifier.verify(b"body", "");
        assert!(result.is_err());
    }

    #[test]
    fn verifier_verify_short_signature() {
        let verifier = WebhookVerifier::new("dGVzdHNlY3JldA==").unwrap();
        let result = verifier.verify(b"body", "abcd");
        assert!(result.is_err());
    }

    #[test]
    fn verifier_debug_redacts_secret() {
        let verifier = WebhookVerifier::new("dGVzdHNlY3JldA==").unwrap();
        let dbg = format!("{verifier:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("testsecret"));
    }

    #[test]
    fn verifier_different_secrets_different_signatures() {
        let v1 = WebhookVerifier::new("dGVzdHNlY3JldA==").unwrap(); // "testsecret"
        let v2 = WebhookVerifier::new("b3RoZXI=").unwrap(); // "other"
        let body = b"same body";

        let mut mac1 = HmacSha256::new_from_slice(b"testsecret").unwrap();
        mac1.update(body);
        let sig1 = hex_encode(&mac1.finalize().into_bytes());

        // sig1 should work for v1 but not v2
        assert!(v1.verify(body, &sig1).is_ok());
        assert!(v2.verify(body, &sig1).is_err());
    }

    // ── WebhookState ──────────────────────────────────────────────

    #[test]
    fn state_display_active() {
        assert_eq!(WebhookState::Active.to_string(), "Active");
    }

    #[test]
    fn state_display_expired() {
        assert_eq!(WebhookState::Expired.to_string(), "Expired");
    }

    #[test]
    fn state_display_refreshing() {
        assert_eq!(WebhookState::Refreshing.to_string(), "Refreshing");
    }

    #[test]
    fn state_display_error() {
        let s = WebhookState::Error("timeout".to_string());
        assert_eq!(s.to_string(), "Error: timeout");
    }

    #[test]
    fn state_display_error_empty() {
        let s = WebhookState::Error(String::new());
        assert_eq!(s.to_string(), "Error: ");
    }

    #[test]
    fn state_eq() {
        assert_eq!(WebhookState::Active, WebhookState::Active);
        assert_ne!(WebhookState::Active, WebhookState::Expired);
    }

    #[test]
    fn state_clone() {
        let s = WebhookState::Error("oops".to_string());
        let cloned = s.clone();
        assert_eq!(s, cloned);
    }

    #[test]
    fn state_debug() {
        let dbg = format!("{:?}", WebhookState::Active);
        assert!(dbg.contains("Active"));
    }

    // ── WebhookLifecycle ──────────────────────────────────────────

    #[test]
    fn lifecycle_new_starts_active() {
        let lc = WebhookLifecycle::new(sample_registration());
        assert_eq!(*lc.state(), WebhookState::Active);
    }

    #[test]
    fn lifecycle_initial_cursor_from_registration() {
        let lc = WebhookLifecycle::new(sample_registration());
        assert_eq!(lc.cursor().cursor, 1);
        assert!(lc.cursor().is_initial);
    }

    #[test]
    fn lifecycle_cursor_not_initial_when_registration_cursor_gt_1() {
        let mut reg = sample_registration();
        reg.cursor = 5;
        let lc = WebhookLifecycle::new(reg);
        assert_eq!(lc.cursor().cursor, 5);
        assert!(!lc.cursor().is_initial);
    }

    #[test]
    fn lifecycle_payloads_processed_starts_zero() {
        let lc = WebhookLifecycle::new(sample_registration());
        assert_eq!(lc.payloads_processed(), 0);
    }

    #[test]
    fn lifecycle_registration_accessible() {
        let reg = sample_registration();
        let lc = WebhookLifecycle::new(reg.clone());
        assert_eq!(lc.registration().id, reg.id);
    }

    #[test]
    fn lifecycle_mark_expired() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.mark_expired();
        assert_eq!(*lc.state(), WebhookState::Expired);
    }

    #[test]
    fn lifecycle_mark_refreshing() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.mark_refreshing();
        assert_eq!(*lc.state(), WebhookState::Refreshing);
    }

    #[test]
    fn lifecycle_mark_active() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.mark_expired();
        lc.mark_active();
        assert_eq!(*lc.state(), WebhookState::Active);
    }

    #[test]
    fn lifecycle_mark_error() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.mark_error("connection refused".to_string());
        assert_eq!(
            *lc.state(),
            WebhookState::Error("connection refused".to_string())
        );
    }

    #[test]
    fn lifecycle_process_payload_advances_cursor() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        let payload = make_payload(5, vec![sample_notification("a", "b", "t")]);
        let result = lc.process_payload(&payload);
        assert!(result.is_ok());
        assert_eq!(lc.cursor().cursor, 5);
        assert!(!lc.cursor().is_initial);
    }

    #[test]
    fn lifecycle_process_payload_returns_notifications() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        let n1 = sample_notification("a", "b", "t1");
        let n2 = sample_notification("a", "b", "t2");
        let payload = make_payload(3, vec![n1, n2]);
        let result = lc.process_payload(&payload).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn lifecycle_process_payload_increments_count() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        let payload = make_payload(
            3,
            vec![
                sample_notification("a", "b", "t1"),
                sample_notification("a", "b", "t2"),
            ],
        );
        lc.process_payload(&payload).unwrap();
        assert_eq!(lc.payloads_processed(), 2);
    }

    #[test]
    fn lifecycle_process_multiple_payloads() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        let p1 = make_payload(3, vec![sample_notification("a", "b", "t1")]);
        let p2 = make_payload(
            7,
            vec![
                sample_notification("a", "b", "t2"),
                sample_notification("a", "b", "t3"),
            ],
        );
        lc.process_payload(&p1).unwrap();
        lc.process_payload(&p2).unwrap();
        assert_eq!(lc.cursor().cursor, 7);
        assert_eq!(lc.payloads_processed(), 3);
    }

    #[test]
    fn lifecycle_process_payload_behind_cursor_fails() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        let p1 = make_payload(5, vec![sample_notification("a", "b", "t")]);
        lc.process_payload(&p1).unwrap();

        let p2 = make_payload(3, vec![sample_notification("a", "b", "t")]);
        let result = lc.process_payload(&p2);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("behind"));
    }

    #[test]
    fn lifecycle_process_payload_same_cursor_ok() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        let p1 = make_payload(5, vec![sample_notification("a", "b", "t")]);
        lc.process_payload(&p1).unwrap();

        let p2 = make_payload(5, vec![]);
        let result = lc.process_payload(&p2);
        assert!(result.is_ok());
    }

    #[test]
    fn lifecycle_process_payload_not_active_fails() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.mark_expired();
        let payload = make_payload(2, vec![]);
        let result = lc.process_payload(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Expired"));
    }

    #[test]
    fn lifecycle_process_payload_error_state_fails() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.mark_error("broken".to_string());
        let payload = make_payload(2, vec![]);
        let result = lc.process_payload(&payload);
        assert!(result.is_err());
    }

    #[test]
    fn lifecycle_process_payload_refreshing_state_fails() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.mark_refreshing();
        let payload = make_payload(2, vec![]);
        let result = lc.process_payload(&payload);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Refreshing"));
    }

    #[test]
    fn lifecycle_needs_refresh_far_future_expiration() {
        let lc = WebhookLifecycle::new(sample_registration());
        // 2030 is far away, should not need refresh
        assert!(!lc.needs_refresh());
    }

    #[test]
    fn lifecycle_needs_refresh_expired_state() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.mark_expired();
        assert!(lc.needs_refresh());
    }

    #[test]
    fn lifecycle_needs_refresh_no_expiration() {
        let mut reg = sample_registration();
        reg.expiration_time = None;
        let lc = WebhookLifecycle::new(reg);
        // No expiration time means we can't determine — returns false
        assert!(!lc.needs_refresh());
    }

    #[test]
    fn lifecycle_needs_refresh_past_expiration() {
        let mut reg = sample_registration();
        reg.expiration_time = Some("2020-01-01T00:00:00.000Z".to_string());
        let lc = WebhookLifecycle::new(reg);
        assert!(lc.needs_refresh());
    }

    #[test]
    fn lifecycle_needs_refresh_unparseable_expiration() {
        let mut reg = sample_registration();
        reg.expiration_time = Some("not-a-date".to_string());
        let lc = WebhookLifecycle::new(reg);
        // Can't parse, falls through to false
        assert!(!lc.needs_refresh());
    }

    #[test]
    fn lifecycle_update_expiration() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.mark_refreshing();
        lc.update_expiration(Some("2035-01-01T00:00:00.000Z".to_string()));
        assert_eq!(*lc.state(), WebhookState::Active);
        assert_eq!(
            lc.registration().expiration_time.as_deref(),
            Some("2035-01-01T00:00:00.000Z")
        );
    }

    #[test]
    fn lifecycle_update_expiration_to_none() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.update_expiration(None);
        assert!(lc.registration().expiration_time.is_none());
    }

    #[test]
    fn lifecycle_update_expiration_keeps_active_if_already_active() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        assert_eq!(*lc.state(), WebhookState::Active);
        lc.update_expiration(Some("2040-01-01T00:00:00.000Z".to_string()));
        // Should stay active
        assert_eq!(*lc.state(), WebhookState::Active);
    }

    #[test]
    fn lifecycle_debug_output() {
        let lc = WebhookLifecycle::new(sample_registration());
        let dbg = format!("{lc:?}");
        assert!(dbg.contains("webhook_id"));
        assert!(dbg.contains("ach000001"));
        assert!(dbg.contains("cursor"));
        assert!(dbg.contains("payloads_processed"));
    }

    #[test]
    fn lifecycle_process_empty_payload() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        let payload = make_payload(2, vec![]);
        let result = lc.process_payload(&payload).unwrap();
        assert!(result.is_empty());
        assert_eq!(lc.payloads_processed(), 0);
    }

    // ── hex_encode ────────────────────────────────────────────────

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_single_byte() {
        assert_eq!(hex_encode(&[0xff]), "ff");
        assert_eq!(hex_encode(&[0x00]), "00");
        assert_eq!(hex_encode(&[0x0a]), "0a");
    }

    #[test]
    fn hex_encode_multiple_bytes() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    // ── constant_time_eq ──────────────────────────────────────────

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"abc", b"abc"));
    }

    #[test]
    fn constant_time_eq_not_equal() {
        assert!(!constant_time_eq(b"abc", b"abd"));
    }

    #[test]
    fn constant_time_eq_different_lengths() {
        assert!(!constant_time_eq(b"ab", b"abc"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    // ── Edge cases ────────────────────────────────────────────────

    #[test]
    fn cursor_overflow_advance() {
        let c = WebhookCursor {
            cursor: u64::MAX - 1,
            is_initial: false,
        };
        let advanced = c.advance(u64::MAX);
        assert_eq!(advanced.cursor, u64::MAX);
    }

    #[test]
    fn cursor_is_behind_max() {
        let c = WebhookCursor {
            cursor: u64::MAX,
            is_initial: false,
        };
        assert!(!c.is_behind(u64::MAX));
        assert!(!c.is_behind(0));
    }

    #[test]
    fn lifecycle_process_payload_cursor_at_max() {
        let mut reg = sample_registration();
        reg.cursor = u64::MAX - 1;
        let mut lc = WebhookLifecycle::new(reg);
        let payload = make_payload(u64::MAX, vec![]);
        let result = lc.process_payload(&payload);
        assert!(result.is_ok());
        assert_eq!(lc.cursor().cursor, u64::MAX);
    }

    #[test]
    fn duplicate_cursor_in_sequential_payloads() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        let p1 = make_payload(5, vec![sample_notification("a", "b", "t1")]);
        let p2 = make_payload(5, vec![sample_notification("a", "b", "t2")]);
        lc.process_payload(&p1).unwrap();
        // Same cursor is allowed (no new data, effectively idempotent)
        let result = lc.process_payload(&p2);
        assert!(result.is_ok());
    }

    #[test]
    fn state_transitions_full_cycle() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        assert_eq!(*lc.state(), WebhookState::Active);
        lc.mark_refreshing();
        assert_eq!(*lc.state(), WebhookState::Refreshing);
        lc.mark_active();
        assert_eq!(*lc.state(), WebhookState::Active);
        lc.mark_error("fail".to_string());
        assert_eq!(*lc.state(), WebhookState::Error("fail".to_string()));
        lc.mark_expired();
        assert_eq!(*lc.state(), WebhookState::Expired);
        lc.mark_active();
        assert_eq!(*lc.state(), WebhookState::Active);
    }

    #[test]
    fn spec_serde_from_json_with_all_fields() {
        let json = serde_json::json!({
            "table_id": "tblABC",
            "notification_url": "https://hook.example.com",
            "cursor_field_id": "fldXYZ",
            "includes": {
                "includeCellValuesInFieldIds": ["fld1", "fld2"],
                "includePreviousCellValues": true,
                "includePreviousFieldValues": false
            }
        });
        let spec: WebhookSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.table_id, "tblABC");
        assert_eq!(spec.cursor_field_id.as_deref(), Some("fldXYZ"));
        let inc = spec.includes.unwrap();
        assert!(inc.include_previous_cell_values);
        assert!(!inc.include_previous_field_values);
        assert_eq!(inc.include_cell_values_in_field_ids.unwrap().len(), 2);
    }

    #[test]
    fn notification_debug_format() {
        let n = sample_notification("app1", "ach1", "ts");
        let dbg = format!("{n:?}");
        assert!(dbg.contains("app1"));
        assert!(dbg.contains("ach1"));
    }

    #[test]
    fn payload_clone_and_eq() {
        let p = make_payload(5, vec![sample_notification("a", "b", "t")]);
        let cloned = p.clone();
        assert_eq!(p, cloned);
    }

    #[test]
    fn verifier_new_with_padding() {
        // base64 with padding
        let v = WebhookVerifier::new("aGVsbG8="); // "hello"
        assert!(v.is_ok());
    }

    #[test]
    fn lifecycle_new_with_cursor_zero() {
        let mut reg = sample_registration();
        reg.cursor = 0;
        let lc = WebhookLifecycle::new(reg);
        assert_eq!(lc.cursor().cursor, 0);
        assert!(lc.cursor().is_initial);
    }

    #[test]
    fn lifecycle_process_payload_at_cursor_1_advances() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        // Initial cursor is 1, payload cursor is 1 (same = ok)
        let payload = make_payload(1, vec![sample_notification("a", "b", "t")]);
        let result = lc.process_payload(&payload);
        assert!(result.is_ok());
        assert_eq!(lc.cursor().cursor, 1);
        assert!(!lc.cursor().is_initial);
    }

    #[test]
    fn lifecycle_needs_refresh_while_refreshing() {
        let mut lc = WebhookLifecycle::new(sample_registration());
        lc.mark_refreshing();
        // Not expired state, far future expiration
        assert!(!lc.needs_refresh());
    }

    #[test]
    fn webhook_includes_serde_no_field_ids() {
        let inc = WebhookIncludes {
            include_cell_values_in_field_ids: None,
            include_previous_cell_values: true,
            include_previous_field_values: false,
        };
        let json = serde_json::to_string(&inc).unwrap();
        // None field should be omitted
        assert!(!json.contains("includeCellValuesInFieldIds"));
        let parsed: WebhookIncludes = serde_json::from_str(&json).unwrap();
        assert!(parsed.include_cell_values_in_field_ids.is_none());
    }
}
