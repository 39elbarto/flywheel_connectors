//! `fcp_streaming::SseEvent` + `SseConfig` cross-crate conformance.
//!
//! Server-Sent Events (SSE) are how every long-lived push connector
//! (webhook bridge, dashboard relay, anthropic-stream-style readers)
//! consumes upstream events. The host serializes `SseEvent`s into
//! the receipt log and uses `SseConfig` to bound parser memory and
//! reconnection behaviour. Cross-crate contracts that no existing
//! conformance test pins:
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`SseEvent::new` constructs a data-only event** with all
//!    optional fields set to None.
//! 2. **Builder methods (`with_event`, `with_id`)** populate the
//!    optional fields without disturbing others.
//! 3. **`is_event` is exact-string match** on the event type
//!    (not substring, not case-insensitive).
//! 4. **`is_event` is false on a default event** (event field is
//!    None — every comparison MUST fail).
//! 5. **`json` deserialises payload via serde_json** and propagates
//!    deserialization errors.
//! 6. **`SseConfig::default` has documented values**:
//!    - `timeout` = None
//!    - `max_buffer_size` = 1 MiB (1 048 576)
//!    - `headers` empty
//!    - `auto_reconnect` = true
//!    - `max_reconnect_attempts` = Some(10)
//!    - `reconnect_delay` = 1 s
//! 7. **`SseConfig::Debug` redacts header VALUES** (security: bearer
//!    tokens, etc.) but NOT keys.
//! 8. **Builder methods on `SseConfig` chain mutably** without
//!    losing earlier state.
//! 9. **`max_buffer_size` clamps at 64 MiB ceiling** — the documented
//!    `MAX_SSE_BUFFER_SIZE` cap protects against unbounded buffer
//!    growth from a malicious server.

use fcp_streaming::{SseConfig, SseEvent};
use std::time::Duration;

// ─── SseEvent constructors + builders ───────────────────────────────

#[test]
fn sse_event_new_constructs_data_only_event() {
    let e = SseEvent::new("hello");
    assert_eq!(e.data, "hello");
    assert!(
        e.event.is_none(),
        "SseEvent::new MUST leave event field as None"
    );
    assert!(e.id.is_none());
    assert!(e.retry.is_none());
}

#[test]
fn with_event_sets_event_field_only() {
    let e = SseEvent::new("payload").with_event("update");
    assert_eq!(e.event.as_deref(), Some("update"));
    assert_eq!(e.data, "payload"); // preserved
    assert!(e.id.is_none());
    assert!(e.retry.is_none());
}

#[test]
fn with_id_sets_id_field_only() {
    let e = SseEvent::new("payload").with_id("evt-42");
    assert_eq!(e.id.as_deref(), Some("evt-42"));
    assert_eq!(e.data, "payload");
    assert!(e.event.is_none());
    assert!(e.retry.is_none());
}

#[test]
fn builder_chain_preserves_all_fields() {
    let e = SseEvent::new("payload")
        .with_event("update")
        .with_id("evt-1");
    assert_eq!(e.data, "payload");
    assert_eq!(e.event.as_deref(), Some("update"));
    assert_eq!(e.id.as_deref(), Some("evt-1"));
}

#[test]
fn sse_event_partial_eq_compares_all_fields() {
    let a = SseEvent::new("p").with_event("update").with_id("1");
    let b = SseEvent::new("p").with_event("update").with_id("1");
    let c = SseEvent::new("p").with_event("update").with_id("2");
    assert_eq!(a, b);
    assert_ne!(a, c, "id difference MUST register on PartialEq");
}

// ─── is_event predicate ────────────────────────────────────────────

#[test]
fn is_event_returns_true_for_exact_match() {
    let e = SseEvent::new("payload").with_event("update");
    assert!(e.is_event("update"));
}

#[test]
fn is_event_is_case_sensitive() {
    let e = SseEvent::new("payload").with_event("update");
    assert!(
        !e.is_event("UPDATE"),
        "is_event MUST be case-sensitive — SSE event types are exact strings"
    );
    assert!(!e.is_event("Update"));
}

#[test]
fn is_event_is_not_substring_match() {
    let e = SseEvent::new("payload").with_event("update");
    assert!(
        !e.is_event("upd"),
        "is_event MUST be full-string match, not substring"
    );
    assert!(!e.is_event("update.v2"));
}

#[test]
fn is_event_returns_false_when_event_field_is_none() {
    // Default SseEvent has event=None — any comparison MUST be false.
    let e = SseEvent::new("payload");
    assert!(!e.is_event("update"));
    assert!(!e.is_event(""));
}

// ─── json deserialization ──────────────────────────────────────────

#[test]
fn json_parses_valid_payload_into_target_type() {
    #[derive(serde::Deserialize, Debug, PartialEq)]
    struct Payload {
        kind: String,
        n: u32,
    }
    let e = SseEvent::new(r#"{"kind":"hello","n":42}"#);
    let p: Payload = e.json().expect("valid JSON");
    assert_eq!(
        p,
        Payload {
            kind: "hello".into(),
            n: 42,
        }
    );
}

#[test]
fn json_propagates_deserialization_error_for_malformed_payload() {
    let e = SseEvent::new("not-json-at-all");
    let r: Result<serde_json::Value, _> = e.json();
    assert!(
        r.is_err(),
        "json MUST surface serde_json::Error for malformed payloads"
    );
}

#[test]
fn json_propagates_deserialization_error_for_type_mismatch() {
    #[derive(serde::Deserialize, Debug)]
    struct ExpectsObject {
        #[allow(dead_code)]
        field: String,
    }
    let e = SseEvent::new("[1, 2, 3]"); // valid JSON, wrong shape
    let r: Result<ExpectsObject, _> = e.json();
    assert!(r.is_err(), "json MUST surface shape mismatch");
}

// ─── SseConfig defaults ─────────────────────────────────────────────

#[test]
fn sse_config_default_timeout_is_none() {
    let c = SseConfig::default();
    assert!(
        c.timeout.is_none(),
        "default SSE timeout MUST be None — long-lived streams"
    );
}

#[test]
fn sse_config_default_max_buffer_size_is_one_mib() {
    let c = SseConfig::default();
    assert_eq!(
        c.max_buffer_size,
        1024 * 1024,
        "default max_buffer_size MUST be 1 MiB"
    );
}

#[test]
fn sse_config_default_headers_are_empty() {
    let c = SseConfig::default();
    assert!(c.headers.is_empty());
}

#[test]
fn sse_config_default_auto_reconnect_is_true() {
    let c = SseConfig::default();
    assert!(
        c.auto_reconnect,
        "default auto_reconnect MUST be true — most SSE consumers want recovery"
    );
}

#[test]
fn sse_config_default_max_reconnect_attempts_is_ten() {
    let c = SseConfig::default();
    assert_eq!(c.max_reconnect_attempts, Some(10));
}

#[test]
fn sse_config_default_reconnect_delay_is_one_second() {
    let c = SseConfig::default();
    assert_eq!(c.reconnect_delay, Duration::from_secs(1));
}

#[test]
fn sse_config_new_is_alias_for_default() {
    let a = SseConfig::new();
    let b = SseConfig::default();
    assert_eq!(a.timeout, b.timeout);
    assert_eq!(a.max_buffer_size, b.max_buffer_size);
    assert_eq!(a.auto_reconnect, b.auto_reconnect);
    assert_eq!(a.max_reconnect_attempts, b.max_reconnect_attempts);
    assert_eq!(a.reconnect_delay, b.reconnect_delay);
}

// ─── SseConfig builders ─────────────────────────────────────────────

#[test]
fn sse_config_builder_chain_preserves_all_fields() {
    let c = SseConfig::new()
        .with_timeout(Duration::from_secs(30))
        .with_max_buffer_size(2048)
        .with_header("Authorization", "Bearer token")
        .with_auto_reconnect(false)
        .with_max_reconnect_attempts(5)
        .with_reconnect_delay(Duration::from_millis(500));
    assert_eq!(c.timeout, Some(Duration::from_secs(30)));
    assert_eq!(c.max_buffer_size, 2048);
    assert_eq!(
        c.headers.get("Authorization").map(String::as_str),
        Some("Bearer token")
    );
    assert!(!c.auto_reconnect);
    assert_eq!(c.max_reconnect_attempts, Some(5));
    assert_eq!(c.reconnect_delay, Duration::from_millis(500));
}

#[test]
fn with_header_replaces_value_on_duplicate_key() {
    let c = SseConfig::new()
        .with_header("X-Custom", "first")
        .with_header("X-Custom", "second");
    assert_eq!(
        c.headers.get("X-Custom").map(String::as_str),
        Some("second")
    );
    assert_eq!(c.headers.len(), 1);
}

// ─── Buffer ceiling ─────────────────────────────────────────────────

#[test]
fn with_max_buffer_size_clamps_at_sixty_four_mib_ceiling() {
    // Documented MAX_SSE_BUFFER_SIZE = 64 MiB. Anything larger MUST
    // clamp to that ceiling — protects against malicious servers
    // forcing unbounded buffer growth.
    const MAX: usize = 64 * 1024 * 1024;
    let c = SseConfig::new().with_max_buffer_size(usize::MAX);
    assert_eq!(
        c.max_buffer_size, MAX,
        "max_buffer_size MUST clamp at 64 MiB ceiling regardless of caller request"
    );
    let c2 = SseConfig::new().with_max_buffer_size(128 * 1024 * 1024);
    assert_eq!(
        c2.max_buffer_size, MAX,
        "128 MiB request MUST clamp to 64 MiB"
    );
}

#[test]
fn with_max_buffer_size_below_ceiling_is_preserved() {
    let c = SseConfig::new().with_max_buffer_size(8 * 1024); // 8 KiB
    assert_eq!(
        c.max_buffer_size,
        8 * 1024,
        "values below the ceiling MUST be preserved verbatim"
    );
}

#[test]
fn with_max_buffer_size_at_ceiling_is_preserved() {
    const MAX: usize = 64 * 1024 * 1024;
    let c = SseConfig::new().with_max_buffer_size(MAX);
    assert_eq!(c.max_buffer_size, MAX);
}

// ─── Debug redacts headers ─────────────────────────────────────────

#[test]
fn debug_format_redacts_header_values_but_not_keys() {
    // Critical security property: SseConfig::Debug MUST NOT leak
    // header VALUES (Bearer tokens, API keys). Keys are visible so
    // operators can confirm a header was set, but values are
    // [REDACTED].
    let c = SseConfig::new()
        .with_header("Authorization", "Bearer SUPER-SECRET-TOKEN-VALUE")
        .with_header("X-API-Key", "ak_live_PROD_KEY");
    let dbg = format!("{c:?}");
    assert!(
        dbg.contains("Authorization"),
        "Debug MUST surface header keys; got {dbg}"
    );
    assert!(dbg.contains("X-API-Key"));
    assert!(
        dbg.contains("[REDACTED]"),
        "Debug MUST replace header values with [REDACTED]; got {dbg}"
    );
    assert!(
        !dbg.contains("SUPER-SECRET-TOKEN-VALUE"),
        "Debug MUST NOT leak Bearer token value; got {dbg}"
    );
    assert!(
        !dbg.contains("ak_live_PROD_KEY"),
        "Debug MUST NOT leak API key value; got {dbg}"
    );
}

#[test]
fn debug_format_includes_non_header_fields_verbatim() {
    let c = SseConfig::new()
        .with_max_buffer_size(2048)
        .with_auto_reconnect(false);
    let dbg = format!("{c:?}");
    assert!(dbg.contains("2048"));
    assert!(dbg.contains("false"));
    assert!(dbg.contains("max_buffer_size") || dbg.contains("2048"));
}
