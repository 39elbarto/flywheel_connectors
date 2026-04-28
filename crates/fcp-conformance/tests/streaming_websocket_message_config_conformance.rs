//! `fcp_streaming` WebSocket message + close-frame + config
//! conformance.
//!
//! WebSocket connectors compose `WsMessage` (5 RFC 6455 frame
//! types), `WsCloseFrame` (close code + reason), and `WsConfig`
//! (timeouts + reconnect + header redaction). Cross-crate contracts
//! that no existing conformance test pins:
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`MAX_WEBSOCKET_MESSAGE_SIZE = 16 MiB`** — the documented
//!    hard ceiling for inbound payloads regardless of caller config.
//! 2. **`WsMessage` 5 variants**: Text, Binary, Ping, Pong, Close.
//!    Constructors `text/binary/ping/pong` produce the matching
//!    variant; `Close` is constructed via `WsCloseFrame`.
//! 3. **Predicate fan-out**: `is_text` ⇔ Text, `is_binary` ⇔ Binary,
//!    `is_close` ⇔ Close. Ping and Pong are NEITHER text nor binary
//!    (control frames are distinct from data frames).
//! 4. **Accessors `as_text`/`as_binary`** return data only for the
//!    matching variant (None otherwise — including for Ping/Pong
//!    payloads).
//! 5. **`json` deserialization**:
//!    - Text → parsed via `from_str`
//!    - Binary → parsed via `from_slice`
//!    - Ping/Pong/Close → error (NOT a data message)
//! 6. **`WsCloseFrame::normal` = 1000 / "Normal closure"** (RFC 6455).
//! 7. **`WsCloseFrame::going_away` = 1001 / "Going away"**.
//! 8. **`WsConfig::default` documented values**:
//!    connect_timeout=30s, ping_interval=Some(30s), pong_timeout=10s,
//!    max_message_size=16 MiB, auto_reconnect=true,
//!    max_reconnect_attempts=Some(10), reconnect_delay=1s.
//! 9. **`WsConfig::Debug` redacts header VALUES** (Bearer tokens
//!    MUST NOT leak via Debug) but keeps keys visible.

use fcp_async_core::bytes::Bytes;
use fcp_streaming::{MAX_WEBSOCKET_MESSAGE_SIZE, WsCloseFrame, WsConfig, WsMessage};
use std::time::Duration;

// ─── MAX_WEBSOCKET_MESSAGE_SIZE constant ────────────────────────────

#[test]
fn max_websocket_message_size_is_sixteen_mib() {
    assert_eq!(
        MAX_WEBSOCKET_MESSAGE_SIZE,
        16 * 1024 * 1024,
        "documented hard ceiling MUST be 16 MiB regardless of caller config"
    );
}

// ─── WsMessage constructors ─────────────────────────────────────────

#[test]
fn ws_message_text_constructor_produces_text_variant() {
    let m = WsMessage::text("hello");
    assert!(matches!(m, WsMessage::Text(_)));
    assert!(m.is_text());
    assert_eq!(m.as_text(), Some("hello"));
}

#[test]
fn ws_message_binary_constructor_produces_binary_variant() {
    let m = WsMessage::binary(Bytes::from_static(b"\x00\x01\x02"));
    assert!(matches!(m, WsMessage::Binary(_)));
    assert!(m.is_binary());
    assert_eq!(m.as_binary(), Some(&b"\x00\x01\x02"[..]));
}

#[test]
fn ws_message_ping_constructor_produces_ping_variant() {
    let m = WsMessage::ping(Bytes::from_static(b"keepalive"));
    assert!(matches!(m, WsMessage::Ping(_)));
}

#[test]
fn ws_message_pong_constructor_produces_pong_variant() {
    let m = WsMessage::pong(Bytes::from_static(b"keepalive"));
    assert!(matches!(m, WsMessage::Pong(_)));
}

// ─── Predicates ─────────────────────────────────────────────────────

#[test]
fn predicates_distinguish_data_from_control_frames() {
    let text = WsMessage::text("hi");
    let binary = WsMessage::binary(Bytes::from_static(b"x"));
    let ping = WsMessage::ping(Bytes::from_static(b""));
    let pong = WsMessage::pong(Bytes::from_static(b""));
    let close = WsMessage::Close(Some(WsCloseFrame::normal()));

    // is_text only for Text.
    assert!(text.is_text());
    assert!(!binary.is_text());
    assert!(!ping.is_text());
    assert!(!pong.is_text());
    assert!(!close.is_text());

    // is_binary only for Binary.
    assert!(!text.is_binary());
    assert!(binary.is_binary());
    assert!(!ping.is_binary());
    assert!(
        !pong.is_binary(),
        "Pong with bytes MUST NOT be 'binary' — control frames are NOT data frames"
    );
    assert!(!close.is_binary());

    // is_close only for Close.
    assert!(!text.is_close());
    assert!(!binary.is_close());
    assert!(!ping.is_close());
    assert!(!pong.is_close());
    assert!(close.is_close());
}

#[test]
fn close_with_none_payload_still_classifies_as_close() {
    // Close(None) — the variant carries Option<WsCloseFrame>.
    let close_none = WsMessage::Close(None);
    assert!(close_none.is_close());
}

// ─── Accessors ──────────────────────────────────────────────────────

#[test]
fn as_text_returns_none_for_non_text_variants() {
    assert!(
        WsMessage::binary(Bytes::from_static(b"x"))
            .as_text()
            .is_none()
    );
    assert!(WsMessage::ping(Bytes::from_static(b"x")).as_text().is_none());
    assert!(WsMessage::pong(Bytes::from_static(b"x")).as_text().is_none());
    assert!(WsMessage::Close(None).as_text().is_none());
}

#[test]
fn as_binary_returns_none_for_non_binary_variants() {
    assert!(WsMessage::text("hi").as_binary().is_none());
    assert!(
        WsMessage::ping(Bytes::from_static(b"x"))
            .as_binary()
            .is_none(),
        "Ping payload bytes MUST NOT be exposed via as_binary — Ping is a control frame"
    );
    assert!(WsMessage::pong(Bytes::from_static(b"x")).as_binary().is_none());
    assert!(WsMessage::Close(None).as_binary().is_none());
}

// ─── json deserialization ──────────────────────────────────────────

#[test]
fn json_parses_text_message_payload() {
    #[derive(serde::Deserialize, Debug, PartialEq)]
    struct Body {
        kind: String,
        n: u32,
    }
    let m = WsMessage::text(r#"{"kind":"event","n":42}"#);
    let parsed: Body = m.json().expect("text JSON");
    assert_eq!(
        parsed,
        Body {
            kind: "event".into(),
            n: 42,
        }
    );
}

#[test]
fn json_parses_binary_message_payload() {
    let m = WsMessage::binary(Bytes::from_static(br#"{"v":7}"#));
    let v: serde_json::Value = m.json().expect("binary JSON");
    assert_eq!(v["v"], 7);
}

#[test]
fn json_returns_error_for_ping_message() {
    let m = WsMessage::ping(Bytes::from_static(br#"{"v":7}"#));
    let r: Result<serde_json::Value, _> = m.json();
    assert!(
        r.is_err(),
        "Ping payload MUST NOT be parsed as JSON — control frames are not data messages"
    );
}

#[test]
fn json_returns_error_for_pong_message() {
    let m = WsMessage::pong(Bytes::from_static(br#"{"v":7}"#));
    let r: Result<serde_json::Value, _> = m.json();
    assert!(r.is_err());
}

#[test]
fn json_returns_error_for_close_message() {
    let m = WsMessage::Close(Some(WsCloseFrame::normal()));
    let r: Result<serde_json::Value, _> = m.json();
    assert!(r.is_err());
}

#[test]
fn json_propagates_serde_error_for_malformed_text_payload() {
    let m = WsMessage::text("not-json-at-all");
    let r: Result<serde_json::Value, _> = m.json();
    assert!(r.is_err());
}

// ─── WsCloseFrame ───────────────────────────────────────────────────

#[test]
fn close_frame_normal_uses_rfc_6455_code_1000_and_normal_closure() {
    let f = WsCloseFrame::normal();
    assert_eq!(f.code, 1000, "RFC 6455 normal closure code is 1000");
    assert_eq!(f.reason, "Normal closure");
}

#[test]
fn close_frame_going_away_uses_rfc_6455_code_1001() {
    let f = WsCloseFrame::going_away();
    assert_eq!(f.code, 1001);
    assert_eq!(f.reason, "Going away");
}

#[test]
fn close_frame_new_preserves_code_and_reason() {
    let f = WsCloseFrame::new(4500, "custom-app-code");
    assert_eq!(f.code, 4500);
    assert_eq!(f.reason, "custom-app-code");
}

#[test]
fn close_frame_eq_compares_both_fields() {
    let a = WsCloseFrame::new(1000, "Normal closure");
    let b = WsCloseFrame::normal();
    assert_eq!(a, b);
    let c = WsCloseFrame::new(1000, "different reason");
    assert_ne!(a, c);
}

// ─── WsConfig::default ──────────────────────────────────────────────

#[test]
fn ws_config_default_connect_timeout_is_thirty_seconds() {
    assert_eq!(
        WsConfig::default().connect_timeout,
        Duration::from_secs(30)
    );
}

#[test]
fn ws_config_default_ping_interval_is_thirty_seconds() {
    assert_eq!(
        WsConfig::default().ping_interval,
        Some(Duration::from_secs(30)),
        "default ping_interval MUST be Some(30s) — keepalive on by default"
    );
}

#[test]
fn ws_config_default_pong_timeout_is_ten_seconds() {
    assert_eq!(WsConfig::default().pong_timeout, Duration::from_secs(10));
}

#[test]
fn ws_config_default_max_message_size_is_sixteen_mib() {
    assert_eq!(
        WsConfig::default().max_message_size,
        MAX_WEBSOCKET_MESSAGE_SIZE,
        "default max_message_size MUST equal MAX_WEBSOCKET_MESSAGE_SIZE (16 MiB)"
    );
}

#[test]
fn ws_config_default_headers_are_empty() {
    assert!(WsConfig::default().headers.is_empty());
}

#[test]
fn ws_config_default_auto_reconnect_is_true() {
    assert!(WsConfig::default().auto_reconnect);
}

#[test]
fn ws_config_default_max_reconnect_attempts_is_ten() {
    assert_eq!(WsConfig::default().max_reconnect_attempts, Some(10));
}

#[test]
fn ws_config_default_reconnect_delay_is_one_second() {
    assert_eq!(
        WsConfig::default().reconnect_delay,
        Duration::from_secs(1)
    );
}

#[test]
fn ws_config_new_is_alias_for_default() {
    let a = WsConfig::new();
    let b = WsConfig::default();
    assert_eq!(a.connect_timeout, b.connect_timeout);
    assert_eq!(a.ping_interval, b.ping_interval);
    assert_eq!(a.pong_timeout, b.pong_timeout);
    assert_eq!(a.max_message_size, b.max_message_size);
    assert_eq!(a.auto_reconnect, b.auto_reconnect);
    assert_eq!(a.max_reconnect_attempts, b.max_reconnect_attempts);
    assert_eq!(a.reconnect_delay, b.reconnect_delay);
}

// ─── WsConfig builders ──────────────────────────────────────────────

#[test]
fn ws_config_builders_preserve_all_fields_in_chain() {
    let c = WsConfig::new()
        .with_connect_timeout(Duration::from_secs(5))
        .with_ping_interval(None)
        .with_max_message_size(1024)
        .with_header("Authorization", "Bearer token")
        .with_auto_reconnect(false);
    assert_eq!(c.connect_timeout, Duration::from_secs(5));
    assert!(c.ping_interval.is_none(), "with_ping_interval(None) MUST disable pings");
    assert_eq!(c.max_message_size, 1024);
    assert_eq!(
        c.headers.get("Authorization").map(String::as_str),
        Some("Bearer token")
    );
    assert!(!c.auto_reconnect);
}

#[test]
fn ws_config_with_header_replaces_value_on_duplicate_key() {
    let c = WsConfig::new()
        .with_header("X-Custom", "first")
        .with_header("X-Custom", "second");
    assert_eq!(c.headers.get("X-Custom").map(String::as_str), Some("second"));
    assert_eq!(c.headers.len(), 1);
}

// ─── WsConfig Debug redaction ──────────────────────────────────────

#[test]
fn ws_config_debug_redacts_header_values_but_not_keys() {
    // Critical security property — Bearer tokens / API keys MUST NOT
    // leak through Debug. Same contract as SseConfig.
    let c = WsConfig::new()
        .with_header("Authorization", "Bearer SUPER-SECRET-TOKEN-VALUE")
        .with_header("X-API-Key", "ak_live_PROD_KEY");
    let dbg = format!("{c:?}");
    assert!(dbg.contains("Authorization"), "header keys MUST appear; got {dbg}");
    assert!(dbg.contains("X-API-Key"));
    assert!(
        dbg.contains("[REDACTED]"),
        "header values MUST be replaced with [REDACTED]; got {dbg}"
    );
    assert!(
        !dbg.contains("SUPER-SECRET-TOKEN-VALUE"),
        "Bearer token value MUST NOT leak through Debug; got {dbg}"
    );
    assert!(
        !dbg.contains("ak_live_PROD_KEY"),
        "API key value MUST NOT leak through Debug; got {dbg}"
    );
}

#[test]
fn ws_config_debug_emits_non_header_fields_verbatim() {
    let c = WsConfig::new()
        .with_connect_timeout(Duration::from_secs(7))
        .with_auto_reconnect(false);
    let dbg = format!("{c:?}");
    assert!(dbg.contains("auto_reconnect"));
    assert!(dbg.contains("false"));
}
