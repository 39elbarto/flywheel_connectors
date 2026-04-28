//! `fcp_host::discovery` metadata-payload wire format conformance.
//!
//! Five small structs in the discovery surface that drive
//! agent-visible JSON shapes for caching, rate-limit hints, cost
//! estimation, and example invocations:
//!
//! - `CacheMetadata` (etag + last_modified + max_age + optional
//!   stale_while_revalidate) — the HTTP-cache contract for
//!   discovery responses
//! - `ResponseMeta` (status + optional message) — light status envelope
//! - `PreflightRateLimit` (limited + remaining + optional reset_at)
//! - `EstimatedCost` (api_calls + tokens + cost_cents — all optional)
//! - `ToolExample` (optional description + input + optional output)
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`CacheMetadata`** preserves all 4 fields through serde;
//!    `stale_while_revalidate_seconds` skip-when-None.
//! 2. **`ResponseMeta`** preserves status + optional message; message
//!    skip-when-None.
//! 3. **`PreflightRateLimit`** preserves limited + remaining;
//!    `reset_at` skip-when-None.
//! 4. **`EstimatedCost`** all-None serializes to `{}`; populated
//!    fields preserved through serde.
//! 5. **`ToolExample`** preserves required `input` field; optional
//!    description + output skip-when-None.
//! 6. **Field-by-field PartialEq** for the structs that derive it
//!    (`CacheMetadata`, `ResponseMeta`).

use chrono::{DateTime, Utc};
use fcp_host::{CacheMetadata, EstimatedCost, PreflightRateLimit, ResponseMeta, ToolExample};
use serde_json::json;

fn fixed_utc(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .expect("parse rfc3339")
        .with_timezone(&Utc)
}

// ─── CacheMetadata ─────────────────────────────────────────────────

#[test]
fn cache_metadata_serde_roundtrip_preserves_all_four_fields() {
    let cache = CacheMetadata {
        etag: "W/\"abc123\"".into(),
        last_modified: fixed_utc("2026-01-15T12:00:00Z"),
        max_age_seconds: 60,
        stale_while_revalidate_seconds: Some(120),
    };
    let json_str = serde_json::to_string(&cache).expect("serialize");
    let parsed: CacheMetadata = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed, cache);
}

#[test]
fn cache_metadata_omits_stale_while_revalidate_when_none() {
    let cache = CacheMetadata {
        etag: "abc".into(),
        last_modified: fixed_utc("2026-01-15T12:00:00Z"),
        max_age_seconds: 30,
        stale_while_revalidate_seconds: None,
    };
    let s = serde_json::to_string(&cache).expect("serialize");
    assert!(
        !s.contains("stale_while_revalidate_seconds"),
        "stale_while_revalidate_seconds=None MUST be omitted; got {s}"
    );
}

#[test]
fn cache_metadata_partial_eq_compares_every_field() {
    let base = CacheMetadata {
        etag: "abc".into(),
        last_modified: fixed_utc("2026-01-15T12:00:00Z"),
        max_age_seconds: 60,
        stale_while_revalidate_seconds: Some(120),
    };
    let mut diff_etag = base.clone();
    diff_etag.etag = "different".into();
    assert_ne!(base, diff_etag);

    let mut diff_max_age = base.clone();
    diff_max_age.max_age_seconds = 30;
    assert_ne!(base, diff_max_age);

    let mut diff_swr = base.clone();
    diff_swr.stale_while_revalidate_seconds = None;
    assert_ne!(base, diff_swr);
}

// ─── ResponseMeta ─────────────────────────────────────────────────

#[test]
fn response_meta_with_status_and_message_round_trips() {
    let meta = ResponseMeta {
        status: 200,
        message: Some("OK".into()),
    };
    let json_str = serde_json::to_string(&meta).expect("serialize");
    let parsed: ResponseMeta = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed, meta);
}

#[test]
fn response_meta_omits_message_when_none() {
    let meta = ResponseMeta {
        status: 304,
        message: None,
    };
    let s = serde_json::to_string(&meta).expect("serialize");
    assert!(
        !s.contains("\"message\""),
        "message=None MUST be omitted; got {s}"
    );
    // Status field MUST appear.
    let v: serde_json::Value = serde_json::from_str(&s).expect("parse");
    assert_eq!(v["status"], 304);
}

#[test]
fn response_meta_partial_eq_compares_status_and_message() {
    let a = ResponseMeta {
        status: 200,
        message: Some("OK".into()),
    };
    let b = ResponseMeta {
        status: 200,
        message: Some("OK".into()),
    };
    let c = ResponseMeta {
        status: 200,
        message: None,
    };
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn response_meta_status_can_be_any_u16_http_code() {
    let codes = [100_u16, 200, 304, 400, 500, 599, 999, u16::MAX];
    for status in codes {
        let meta = ResponseMeta {
            status,
            message: None,
        };
        let json_str = serde_json::to_string(&meta).expect("serialize");
        let parsed: ResponseMeta = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(parsed.status, status);
    }
}

// ─── PreflightRateLimit ───────────────────────────────────────────

#[test]
fn preflight_rate_limit_with_reset_at_round_trips() {
    let rl = PreflightRateLimit {
        limited: false,
        remaining: 100,
        reset_at: Some(fixed_utc("2026-01-15T13:00:00Z")),
    };
    let json_str = serde_json::to_string(&rl).expect("serialize");
    let parsed: PreflightRateLimit = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.limited, rl.limited);
    assert_eq!(parsed.remaining, rl.remaining);
    assert_eq!(parsed.reset_at, rl.reset_at);
}

#[test]
fn preflight_rate_limit_omits_reset_at_when_none() {
    let rl = PreflightRateLimit {
        limited: true,
        remaining: 0,
        reset_at: None,
    };
    let s = serde_json::to_string(&rl).expect("serialize");
    assert!(
        !s.contains("reset_at"),
        "reset_at=None MUST be omitted; got {s}"
    );
    // limited + remaining MUST appear.
    let v: serde_json::Value = serde_json::from_str(&s).expect("parse");
    assert_eq!(v["limited"], true);
    assert_eq!(v["remaining"], 0);
}

#[test]
fn preflight_rate_limit_limited_zero_remaining_is_documented_state() {
    // limited=true + remaining=0 is the natural "rate-limited now" state.
    let rl = PreflightRateLimit {
        limited: true,
        remaining: 0,
        reset_at: Some(fixed_utc("2026-01-15T13:00:00Z")),
    };
    assert!(rl.limited);
    assert_eq!(rl.remaining, 0);
    assert!(rl.reset_at.is_some());
}

// ─── EstimatedCost ────────────────────────────────────────────────

#[test]
fn estimated_cost_all_none_serializes_to_empty_object() {
    let cost = EstimatedCost {
        api_calls: None,
        tokens: None,
        cost_cents: None,
    };
    let s = serde_json::to_string(&cost).expect("serialize");
    assert_eq!(
        s, "{}",
        "all-None EstimatedCost MUST serialize to empty object"
    );
}

#[test]
fn estimated_cost_serde_roundtrip_preserves_populated_fields() {
    let cost = EstimatedCost {
        api_calls: Some(3),
        tokens: Some(1000),
        cost_cents: Some(15),
    };
    let json_str = serde_json::to_string(&cost).expect("serialize");
    let parsed: EstimatedCost = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.api_calls, cost.api_calls);
    assert_eq!(parsed.tokens, cost.tokens);
    assert_eq!(parsed.cost_cents, cost.cost_cents);
}

#[test]
fn estimated_cost_partial_population_omits_none_fields() {
    let cost = EstimatedCost {
        api_calls: Some(5),
        tokens: None,
        cost_cents: None,
    };
    let v = serde_json::to_value(&cost).expect("serialize");
    assert_eq!(v["api_calls"], 5);
    assert!(v.get("tokens").is_none());
    assert!(v.get("cost_cents").is_none());
}

#[test]
fn estimated_cost_documented_unit_for_cost_cents_is_usd_cents() {
    // cost_cents is documented as "USD cents". Pin via construction +
    // round-trip — the field name itself encodes the unit; renaming
    // to "cost" would silently change unit semantics.
    let cost = EstimatedCost {
        api_calls: None,
        tokens: None,
        cost_cents: Some(99), // 99 USD cents = $0.99
    };
    let v = serde_json::to_value(&cost).expect("serialize");
    assert_eq!(v["cost_cents"], 99);
}

// ─── ToolExample ──────────────────────────────────────────────────

#[test]
fn tool_example_minimal_with_only_input_round_trips() {
    let ex = ToolExample {
        description: None,
        input: json!({"to": "alice@example.com", "subject": "hi"}),
        output: None,
    };
    let json_str = serde_json::to_string(&ex).expect("serialize");
    let parsed: ToolExample = serde_json::from_str(&json_str).expect("deserialize");
    assert!(parsed.description.is_none());
    assert!(parsed.output.is_none());
    assert_eq!(parsed.input, ex.input);
}

#[test]
fn tool_example_omits_description_and_output_when_none() {
    let ex = ToolExample {
        description: None,
        input: json!({"x": 1}),
        output: None,
    };
    let s = serde_json::to_string(&ex).expect("serialize");
    assert!(
        !s.contains("\"description\""),
        "description=None MUST be omitted; got {s}"
    );
    assert!(
        !s.contains("\"output\""),
        "output=None MUST be omitted; got {s}"
    );
    // input MUST appear.
    let v: serde_json::Value = serde_json::from_str(&s).expect("parse");
    assert!(v.get("input").is_some());
}

#[test]
fn tool_example_full_round_trips_all_three_fields() {
    let ex = ToolExample {
        description: Some("send an email".into()),
        input: json!({"to": "bob@x.com", "body": "hi"}),
        output: Some(json!({"message_id": "m-123"})),
    };
    let json_str = serde_json::to_string(&ex).expect("serialize");
    let parsed: ToolExample = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.description.as_deref(), Some("send an email"));
    assert_eq!(parsed.input, ex.input);
    assert_eq!(parsed.output, ex.output);
}

#[test]
fn tool_example_input_is_arbitrary_json() {
    // input is serde_json::Value — accepts any JSON shape.
    for input in [
        json!(null),
        json!(42),
        json!("string"),
        json!([1, 2, 3]),
        json!({"k": "v"}),
    ] {
        let ex = ToolExample {
            description: None,
            input: input.clone(),
            output: None,
        };
        let json_str = serde_json::to_string(&ex).expect("serialize");
        let parsed: ToolExample = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(parsed.input, input);
    }
}
