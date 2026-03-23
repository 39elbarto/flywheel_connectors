//! Nostr connector types, configuration, and input-parsing helpers.

use fcp_core::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─── Operation / capability constants ────────────────────────────────────
pub const OP_PUBLISH_NOTE: &str = "nostr.notes.publish";
pub const OP_QUERY_EVENTS: &str = "nostr.events.query";
pub const OP_LIST_RELAYS: &str = "nostr.relays.list";
pub const OP_HEALTH: &str = "nostr.health";
pub const OP_RELAYS_HEALTH: &str = "nostr.relays.health";

pub const CAP_NOTES_WRITE: &str = "nostr.notes.write";
pub const CAP_EVENTS_READ: &str = "nostr.events.read";
pub const CAP_RELAYS_READ: &str = "nostr.relays.read";
pub const CAP_HEALTH_READ: &str = "nostr.health.read";

pub const DEFAULT_TIMEOUT_MS: u64 = 15_000;
pub const DEFAULT_QUERY_LIMIT: u64 = 25;
pub const NIP01_KIND_TEXT: u64 = 1;

// ─── NIP-04 / NIP-44 DM event constants and types ───────────────────────

/// NIP-04 encrypted direct message event kind.
pub const NIP04_KIND_ENCRYPTED_DM: u64 = 4;

/// NIP-44 gift-wrapped event kind (used for newer encrypted DMs).
pub const NIP44_KIND_GIFT_WRAP: u64 = 1059;

/// NIP-44 sealed event kind (inner layer of gift wrap).
pub const NIP44_KIND_SEAL: u64 = 13;

/// Represents an encrypted DM event following the NIP-04 format.
///
/// The `content` field holds the NIP-04 encrypted payload (base64 + IV).
/// The connector does not encrypt or decrypt content - that is the responsibility
/// of the calling agent or upstream NIP-04 library.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedDmEvent {
    /// The hex-encoded x-only public key of the DM recipient.
    pub recipient_pubkey: String,
    /// The encrypted content in NIP-04 format (base64 ciphertext + "?iv=" + base64 IV).
    pub content: String,
    /// The event kind (must be 4 for NIP-04 DMs).
    pub kind: u64,
}

impl EncryptedDmEvent {
    /// Create a new NIP-04 encrypted DM event envelope.
    #[must_use]
    pub fn new(recipient_pubkey: String, content: String) -> Self {
        Self {
            recipient_pubkey,
            content,
            kind: NIP04_KIND_ENCRYPTED_DM,
        }
    }

    /// Validate the DM event fields.
    ///
    /// # Errors
    ///
    /// Returns an error if the recipient pubkey is malformed or content is empty.
    pub fn validate(&self) -> FcpResult<()> {
        if self.recipient_pubkey.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "recipient_pubkey must not be empty".into(),
            });
        }
        if self.recipient_pubkey.len() != 64
            || !self
                .recipient_pubkey
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "recipient_pubkey must be a 64-character hex-encoded x-only public key"
                    .into(),
            });
        }
        if self.content.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "encrypted DM content must not be empty".into(),
            });
        }
        if self.kind != NIP04_KIND_ENCRYPTED_DM {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!(
                    "EncryptedDmEvent kind must be {} (NIP-04), got {}",
                    NIP04_KIND_ENCRYPTED_DM, self.kind
                ),
            });
        }
        Ok(())
    }

    /// Build the Nostr tags array for this DM event: `[["p", recipient_pubkey]]`.
    #[must_use]
    pub fn tags(&self) -> Value {
        serde_json::json!([["p", self.recipient_pubkey]])
    }
}

// ─── Configuration ───────────────────────────────────────────────────────

#[derive(Clone, Deserialize)]
pub struct NostrConfig {
    pub relay_urls: Vec<String>,
    pub secret_key_hex: String,
    #[serde(default = "default_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_query_limit")]
    pub default_query_limit: u64,
}

impl std::fmt::Debug for NostrConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrConfig")
            .field("relay_urls", &self.relay_urls)
            .field("secret_key_hex", &"[REDACTED]")
            .field("request_timeout_ms", &self.request_timeout_ms)
            .field("default_query_limit", &self.default_query_limit)
            .finish()
    }
}

#[must_use]
pub const fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

#[must_use]
pub const fn default_query_limit() -> u64 {
    DEFAULT_QUERY_LIMIT
}

impl NostrConfig {
    /// Validate configuration without consuming it.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing, numeric limits are
    /// zero, or any relay URL is invalid.
    pub fn validate(&self) -> FcpResult<()> {
        if self.relay_urls.is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "relay_urls must not be empty".into(),
            });
        }
        if self.secret_key_hex.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "secret_key_hex must not be empty".into(),
            });
        }
        if self.secret_key_hex.len() != 64
            || !self.secret_key_hex.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "secret_key_hex must be exactly 64 hex characters".into(),
            });
        }
        if self.request_timeout_ms == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "request_timeout_ms must be greater than zero".into(),
            });
        }
        if self.default_query_limit == 0 {
            return Err(FcpError::InvalidRequest {
                code: 1001,
                message: "default_query_limit must be greater than zero".into(),
            });
        }
        for relay in &self.relay_urls {
            validate_relay_url(relay)?;
        }
        Ok(())
    }
}

/// Validate that a relay URL uses `ws://` or `wss://`.
///
/// # Errors
///
/// Returns an error if `raw` is empty, malformed, or uses a non-WebSocket
/// scheme.
pub fn validate_relay_url(raw: &str) -> FcpResult<url::Url> {
    let relay = raw.trim();
    if relay.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: "relay URLs must not be empty strings".into(),
        });
    }
    let url = url::Url::parse(relay).map_err(|error| FcpError::InvalidRequest {
        code: 1001,
        message: format!("invalid relay URL `{relay}`: {error}"),
    })?;
    if !matches!(url.scheme(), "ws" | "wss") {
        return Err(FcpError::InvalidRequest {
            code: 1001,
            message: format!("relay URL `{relay}` must use ws:// or wss://"),
        });
    }
    Ok(url)
}

// ─── Input parsing helpers ───────────────────────────────────────────────

/// Read a required non-empty string field from an input object.
///
/// # Errors
///
/// Returns an error if the field is missing, not a string, or blank.
pub fn required_string<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    let Some(raw) = value.get(field) else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} is required"),
        });
    };
    let Some(text) = raw.as_str() else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a non-empty string"),
        });
    };
    if text.trim().is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be a non-empty string"),
        });
    }
    Ok(text)
}

/// Read an optional array field whose entries must all be strings.
///
/// # Errors
///
/// Returns an error if the field exists but is not an array of strings.
pub fn string_array_field(input: &Value, field: &str) -> FcpResult<Option<Vec<Value>>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let Value::Array(items) = value else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an array of strings"),
        });
    };
    if items.iter().any(|item| !item.is_string()) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must contain only strings"),
        });
    }
    Ok(Some(items.clone()))
}

/// Read an optional array field whose entries must all be unsigned integers.
///
/// # Errors
///
/// Returns an error if the field exists but is not an array of unsigned
/// integers.
pub fn u64_array_field(input: &Value, field: &str) -> FcpResult<Option<Vec<Value>>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let Value::Array(items) = value else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an array of integers"),
        });
    };
    if items.iter().any(|item| item.as_u64().is_none()) {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must contain only integers"),
        });
    }
    Ok(Some(items.clone()))
}

/// Read an optional signed integer field from an input object.
///
/// # Errors
///
/// Returns an error if the field exists but is not an integer.
pub fn i64_field(input: &Value, field: &str) -> FcpResult<Option<i64>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    value
        .as_i64()
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an integer"),
        })
}

/// Read an optional unsigned integer field from an input object.
///
/// # Errors
///
/// Returns an error if the field exists but is not an unsigned integer.
pub fn u64_field(input: &Value, field: &str) -> FcpResult<Option<u64>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1005,
            message: format!("{field} must be an unsigned integer"),
        })
}

/// Parse `kind` from input, defaulting to `NIP01_KIND_TEXT`. Rejects non-1 kinds.
///
/// # Errors
///
/// Returns an error if `kind` is present but invalid, or if it requests an
/// unsupported note kind for this first slice.
pub fn note_kind(input: &Value) -> FcpResult<u64> {
    let kind = u64_field(input, "kind")?.unwrap_or(NIP01_KIND_TEXT);
    if kind != NIP01_KIND_TEXT {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "nostr.notes.publish only supports kind=1 public notes in this first slice"
                .into(),
        });
    }
    Ok(kind)
}

/// Parse `tags` from input, each tag must be an array of strings.
///
/// # Errors
///
/// Returns an error if `tags` is present but is not an array of string arrays.
pub fn note_tags(input: &Value) -> FcpResult<Value> {
    let Some(tags) = input.get("tags") else {
        return Ok(Value::Array(Vec::new()));
    };
    let Value::Array(tag_rows) = tags else {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "tags must be an array of string arrays".into(),
        });
    };
    for tag in tag_rows {
        let Value::Array(parts) = tag else {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "each tag must be an array of strings".into(),
            });
        };
        if parts.iter().any(|part| !part.is_string()) {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: "each tag entry must be a string".into(),
            });
        }
    }
    Ok(Value::Array(tag_rows.clone()))
}

/// Build a NIP-01 filter object from input, applying `default_limit`.
///
/// # Errors
///
/// Returns an error if any filter field has the wrong type or if the computed
/// limit is zero.
pub fn build_filter(input: &Value, default_limit: u64) -> FcpResult<Value> {
    let mut filter = serde_json::Map::new();
    if let Some(authors) = string_array_field(input, "authors")? {
        filter.insert("authors".into(), Value::Array(authors));
    }
    if let Some(ids) = string_array_field(input, "ids")? {
        filter.insert("ids".into(), Value::Array(ids));
    }
    if let Some(kinds) = u64_array_field(input, "kinds")? {
        filter.insert("kinds".into(), Value::Array(kinds));
    }
    if let Some(since) = i64_field(input, "since")? {
        filter.insert("since".into(), serde_json::json!(since));
    }
    if let Some(until) = i64_field(input, "until")? {
        filter.insert("until".into(), serde_json::json!(until));
    }
    let limit = u64_field(input, "limit")?.unwrap_or(default_limit);
    if limit == 0 {
        return Err(FcpError::InvalidRequest {
            code: 1005,
            message: "limit must be greater than zero".into(),
        });
    }
    filter.insert("limit".into(), serde_json::json!(limit));
    Ok(Value::Object(filter))
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn config_deserializes_with_defaults() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "aaaa"
        }))
        .unwrap();
        assert_eq!(config.request_timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(config.default_query_limit, DEFAULT_QUERY_LIMIT);
    }

    #[test]
    fn config_debug_redacts_secret_key() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "super_secret_deadbeef"
        }))
        .unwrap();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("super_secret_deadbeef"));
    }

    #[test]
    fn config_validates_empty_relay_urls() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": [],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111"
        }))
        .unwrap();
        assert!(matches!(
            config.validate(),
            Err(FcpError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn config_validates_empty_secret_key() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": ""
        }))
        .unwrap();
        assert!(matches!(
            config.validate(),
            Err(FcpError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn config_validates_zero_timeout() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "request_timeout_ms": 0
        }))
        .unwrap();
        assert!(matches!(
            config.validate(),
            Err(FcpError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn config_validates_zero_query_limit() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "default_query_limit": 0
        }))
        .unwrap();
        assert!(matches!(
            config.validate(),
            Err(FcpError::InvalidRequest { .. })
        ));
    }

    #[test]
    fn config_validates_secret_key_hex_length() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "aaaa"
        }))
        .unwrap();
        let err = config.validate().unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("64 hex characters"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn config_validates_secret_key_hex_non_hex_chars() {
        let config: NostrConfig = serde_json::from_value(json!({
            "relay_urls": ["wss://relay.example.com"],
            "secret_key_hex": "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        }))
        .unwrap();
        let err = config.validate().unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("64 hex characters"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_relay_url_accepts_wss() {
        assert!(validate_relay_url("wss://relay.example.com").is_ok());
    }

    #[test]
    fn validate_relay_url_accepts_ws() {
        assert!(validate_relay_url("ws://localhost:7777").is_ok());
    }

    #[test]
    fn validate_relay_url_rejects_https() {
        assert!(validate_relay_url("https://relay.example.com").is_err());
    }

    #[test]
    fn validate_relay_url_rejects_empty() {
        assert!(validate_relay_url("").is_err());
    }

    #[test]
    fn required_string_returns_value() {
        assert_eq!(
            required_string(&json!({"content": "hello"}), "content").unwrap(),
            "hello"
        );
    }

    #[test]
    fn required_string_rejects_missing() {
        assert!(required_string(&json!({}), "content").is_err());
    }

    #[test]
    fn required_string_rejects_non_string() {
        let err = required_string(&json!({"content": 7}), "content").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
        assert_eq!(
            err.to_string(),
            "Invalid request: content must be a non-empty string"
        );
    }

    #[test]
    fn required_string_rejects_blank() {
        assert!(required_string(&json!({"content": "  "}), "content").is_err());
    }

    #[test]
    fn note_kind_defaults_to_text() {
        assert_eq!(note_kind(&json!({})).unwrap(), NIP01_KIND_TEXT);
    }

    #[test]
    fn note_kind_rejects_non_note_kinds() {
        assert!(note_kind(&json!({"kind": 4})).is_err());
    }

    #[test]
    fn note_kind_rejects_non_integer_values() {
        assert!(note_kind(&json!({"kind": "1"})).is_err());
    }

    #[test]
    fn note_tags_defaults_to_empty() {
        assert_eq!(note_tags(&json!({})).unwrap(), json!([]));
    }

    #[test]
    fn note_tags_accepts_string_arrays() {
        let tags = json!({"tags": [["p", "abc"]]});
        assert!(note_tags(&tags).is_ok());
    }

    #[test]
    fn note_tags_rejects_non_string_entries() {
        assert!(note_tags(&json!({"tags": [["p", 3]]})).is_err());
    }

    #[test]
    fn build_filter_uses_default_limit() {
        let filter = build_filter(&json!({"kinds": [1]}), 25).unwrap();
        assert_eq!(filter["limit"], 25);
        assert_eq!(filter["kinds"], json!([1]));
    }

    #[test]
    fn build_filter_respects_explicit_limit() {
        let filter = build_filter(&json!({"limit": 10}), 25).unwrap();
        assert_eq!(filter["limit"], 10);
    }

    #[test]
    fn build_filter_rejects_zero_limit() {
        assert!(build_filter(&json!({"limit": 0}), 25).is_err());
    }

    #[test]
    fn build_filter_rejects_invalid_limit_type() {
        assert!(build_filter(&json!({"limit": "10"}), 25).is_err());
    }

    #[test]
    fn build_filter_rejects_non_string_authors() {
        assert!(build_filter(&json!({"authors": ["ok", 3]}), 25).is_err());
    }

    #[test]
    fn string_array_field_none_when_absent() {
        assert!(string_array_field(&json!({}), "authors").unwrap().is_none());
    }

    #[test]
    fn u64_array_field_none_when_absent() {
        assert!(u64_array_field(&json!({}), "kinds").unwrap().is_none());
    }

    #[test]
    fn i64_field_none_when_absent() {
        assert!(i64_field(&json!({}), "since").unwrap().is_none());
    }

    #[test]
    fn u64_field_none_when_absent() {
        assert!(u64_field(&json!({}), "limit").unwrap().is_none());
    }

    #[test]
    fn i64_field_parses_negative() {
        assert_eq!(i64_field(&json!({"since": -1}), "since").unwrap(), Some(-1));
    }

    #[test]
    fn u64_field_rejects_negative() {
        assert!(u64_field(&json!({"limit": -1}), "limit").is_err());
    }

    // ── NIP-04 DM event type tests ─────────────────────────────────────

    #[test]
    fn nip04_kind_constant_is_4() {
        assert_eq!(NIP04_KIND_ENCRYPTED_DM, 4);
    }

    #[test]
    fn nip44_kind_constants() {
        assert_eq!(NIP44_KIND_GIFT_WRAP, 1059);
        assert_eq!(NIP44_KIND_SEAL, 13);
    }

    #[test]
    fn encrypted_dm_event_new_sets_kind_4() {
        let dm = EncryptedDmEvent::new(
            "aaaa".repeat(16),
            "encrypted_content?iv=base64iv".into(),
        );
        assert_eq!(dm.kind, NIP04_KIND_ENCRYPTED_DM);
        assert_eq!(dm.recipient_pubkey.len(), 64);
    }

    #[test]
    fn encrypted_dm_event_serializes() {
        let dm = EncryptedDmEvent::new(
            "bbbb".repeat(16),
            "ciphertext?iv=nonce".into(),
        );
        let json = serde_json::to_value(&dm).unwrap();
        assert_eq!(json["kind"], 4);
        assert_eq!(json["content"], "ciphertext?iv=nonce");
        assert_eq!(json["recipient_pubkey"], "bbbb".repeat(16));
    }

    #[test]
    fn encrypted_dm_event_deserializes() {
        let json = json!({
            "recipient_pubkey": "cccc".repeat(16),
            "content": "encrypted_payload",
            "kind": 4
        });
        let dm: EncryptedDmEvent = serde_json::from_value(json).unwrap();
        assert_eq!(dm.kind, 4);
        assert_eq!(dm.content, "encrypted_payload");
    }

    #[test]
    fn encrypted_dm_event_roundtrip() {
        let original = EncryptedDmEvent::new(
            "dddd".repeat(16),
            "test_payload?iv=abc".into(),
        );
        let json = serde_json::to_value(&original).unwrap();
        let deserialized: EncryptedDmEvent = serde_json::from_value(json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn encrypted_dm_event_validate_valid() {
        let dm = EncryptedDmEvent::new(
            "eeee".repeat(16),
            "valid_content".into(),
        );
        assert!(dm.validate().is_ok());
    }

    #[test]
    fn encrypted_dm_event_validate_empty_pubkey() {
        let dm = EncryptedDmEvent {
            recipient_pubkey: "".into(),
            content: "content".into(),
            kind: 4,
        };
        let err = dm.validate().unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn encrypted_dm_event_validate_short_pubkey() {
        let dm = EncryptedDmEvent {
            recipient_pubkey: "aabb".into(),
            content: "content".into(),
            kind: 4,
        };
        let err = dm.validate().unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("64-character hex"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_dm_event_validate_non_hex_pubkey() {
        let dm = EncryptedDmEvent {
            recipient_pubkey: "zzzz".repeat(16),
            content: "content".into(),
            kind: 4,
        };
        assert!(dm.validate().is_err());
    }

    #[test]
    fn encrypted_dm_event_validate_empty_content() {
        let dm = EncryptedDmEvent {
            recipient_pubkey: "aaaa".repeat(16),
            content: "   ".into(),
            kind: 4,
        };
        assert!(dm.validate().is_err());
    }

    #[test]
    fn encrypted_dm_event_validate_wrong_kind() {
        let dm = EncryptedDmEvent {
            recipient_pubkey: "aaaa".repeat(16),
            content: "content".into(),
            kind: 1,
        };
        let err = dm.validate().unwrap_err();
        match err {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("kind must be 4"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn encrypted_dm_event_tags_has_p_tag() {
        let dm = EncryptedDmEvent::new(
            "ffff".repeat(16),
            "payload".into(),
        );
        let tags = dm.tags();
        assert_eq!(tags, json!([["p", "ffff".repeat(16)]]));
    }

    #[test]
    fn op_relays_health_constant() {
        assert_eq!(OP_RELAYS_HEALTH, "nostr.relays.health");
    }
}
