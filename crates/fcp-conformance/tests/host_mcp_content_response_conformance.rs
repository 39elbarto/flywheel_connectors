//! `fcp_host` MCP content-block + tool-call-response + tool-
//! annotations conformance.
//!
//! Three closely-related agent-facing primitives:
//!
//! 1. **`McpContentBlock`** — internally-tagged enum (`type` field)
//!    with three variants (Text / Image / Resource); MCP clients
//!    deserialize this from every tool-call response.
//! 2. **`McpToolCallResponse`** — wraps `Vec<McpContentBlock>` plus
//!    an `is_error` flag (camelCase `isError` on the wire); the
//!    `text` and `error` constructors are how connectors typically
//!    emit responses.
//! 3. **`McpToolAnnotations`** — optional metadata block attached
//!    to tool listings (risk_level, safety_tier, idempotency,
//!    capability, read_only, destructive). Skip-serializing-if-None
//!    on every field for forward compat.
//!
//! Properties pinned (NORMATIVE):
//!
//! - `McpContentBlock` 3 variants with `type` tag values
//!   `text` / `image` / `resource` (NOT camelCase versions of the
//!   enum identifier).
//! - `Image.mime_type` serializes as `mimeType` (camelCase rename).
//! - `Resource.mime_type`/`Resource.text` are optional; skip when None.
//! - Constructors `text/image/resource` produce the right variant.
//! - Predicates `is_text/is_image/is_resource` are exclusive.
//! - `as_text` returns Some only for Text.
//! - `McpToolCallResponse::text` produces a single-Text-block
//!   `is_error=false` response; `::error` produces single-Text +
//!   `is_error=true`; `with_content` is a const fn that preserves
//!   both fields.
//! - `is_error` field is omitted from JSON when false (default
//!   suppression via `std::ops::Not::not`).
//! - `McpToolAnnotations` omits every None field from JSON.
//! - All 6 annotation fields round-trip through serde when populated.

use fcp_host::{McpContentBlock, McpToolAnnotations, McpToolCallResponse};
use serde_json::json;

// ─── McpContentBlock variant constructors ──────────────────────────

#[test]
fn content_block_text_constructor_produces_text_variant() {
    let b = McpContentBlock::text("hello");
    assert!(b.is_text());
    assert!(!b.is_image());
    assert!(!b.is_resource());
    assert_eq!(b.as_text(), Some("hello"));
}

#[test]
fn content_block_image_constructor_produces_image_variant() {
    let b = McpContentBlock::image("base64==", "image/png");
    assert!(b.is_image());
    assert!(!b.is_text());
    assert!(!b.is_resource());
}

#[test]
fn content_block_resource_constructor_produces_resource_variant_with_default_optionals() {
    let b = McpContentBlock::resource("file:///x.txt");
    assert!(b.is_resource());
    assert!(!b.is_text());
    assert!(!b.is_image());

    // Optional fields default to None.
    match b {
        McpContentBlock::Resource {
            uri,
            mime_type,
            text,
        } => {
            assert_eq!(uri, "file:///x.txt");
            assert!(mime_type.is_none());
            assert!(text.is_none());
        }
        _ => panic!("expected Resource"),
    }
}

#[test]
fn content_block_predicates_are_exclusive() {
    let blocks = [
        McpContentBlock::text("x"),
        McpContentBlock::image("d", "image/png"),
        McpContentBlock::resource("file:///x"),
    ];
    for b in blocks {
        let flags = [b.is_text(), b.is_image(), b.is_resource()];
        let count = flags.iter().filter(|f| **f).count();
        assert_eq!(count, 1, "exactly one predicate MUST hold for {b:?}");
    }
}

#[test]
fn as_text_returns_none_for_image_and_resource() {
    assert!(McpContentBlock::image("d", "image/png").as_text().is_none());
    assert!(McpContentBlock::resource("file:///x").as_text().is_none());
}

// ─── McpContentBlock serde wire form ───────────────────────────────

#[test]
fn content_block_text_serializes_with_type_text_tag() {
    let b = McpContentBlock::text("hello");
    let v = serde_json::to_value(&b).expect("serialize");
    assert_eq!(
        v["type"], "text",
        "Text variant MUST serialize with type=\"text\""
    );
    assert_eq!(v["text"], "hello");
}

#[test]
fn content_block_image_serializes_with_camelcase_mime_type() {
    let b = McpContentBlock::image("BASE64", "image/png");
    let v = serde_json::to_value(&b).expect("serialize");
    assert_eq!(v["type"], "image");
    assert_eq!(v["data"], "BASE64");
    assert_eq!(
        v["mimeType"], "image/png",
        "image.mime_type MUST serialize as 'mimeType' (camelCase rename)"
    );
    // Snake case version MUST NOT appear.
    assert!(v.get("mime_type").is_none());
}

#[test]
fn content_block_resource_omits_optional_fields_when_none() {
    let b = McpContentBlock::resource("file:///x.txt");
    let s = serde_json::to_string(&b).expect("serialize");
    assert!(
        !s.contains("mimeType"),
        "Resource.mime_type=None MUST be omitted; got {s}"
    );
    assert!(
        !s.contains("\"text\""),
        "Resource.text=None MUST be omitted; got {s}"
    );
}

#[test]
fn content_block_resource_with_optionals_serializes_camelcase_mime_type() {
    let b = McpContentBlock::Resource {
        uri: "file:///x.txt".into(),
        mime_type: Some("text/plain".into()),
        text: Some("contents".into()),
    };
    let v = serde_json::to_value(&b).expect("serialize");
    assert_eq!(v["type"], "resource");
    assert_eq!(v["uri"], "file:///x.txt");
    assert_eq!(v["mimeType"], "text/plain");
    assert_eq!(v["text"], "contents");
}

#[test]
fn content_block_serde_roundtrip_for_each_variant() {
    let cases = vec![
        McpContentBlock::text("hello"),
        McpContentBlock::image("BASE64DATA", "image/jpeg"),
        McpContentBlock::Resource {
            uri: "file:///x.txt".into(),
            mime_type: Some("text/plain".into()),
            text: None,
        },
    ];
    for original in cases {
        let json_str = serde_json::to_string(&original).expect("serialize");
        let parsed: McpContentBlock = serde_json::from_str(&json_str).expect("deserialize");
        // Re-serialize parsed and compare semantic JSON.
        let reserialized = serde_json::to_value(&parsed).expect("re-serialize");
        let original_value = serde_json::to_value(&original).expect("original-as-value");
        assert_eq!(reserialized, original_value);
    }
}

#[test]
fn content_block_rejects_unknown_type_tag() {
    let bogus = json!({"type": "video", "data": "x"}).to_string();
    assert!(
        serde_json::from_str::<McpContentBlock>(&bogus).is_err(),
        "unknown content type MUST be rejected"
    );
}

// ─── McpToolCallResponse ──────────────────────────────────────────

#[test]
fn tool_call_response_text_constructor_produces_single_text_block_no_error() {
    let r = McpToolCallResponse::text("payload");
    assert_eq!(r.content.len(), 1);
    assert!(r.content[0].is_text());
    assert_eq!(r.content[0].as_text(), Some("payload"));
    assert!(!r.is_error);
}

#[test]
fn tool_call_response_error_constructor_produces_single_text_block_with_error_flag() {
    let r = McpToolCallResponse::error("boom");
    assert_eq!(r.content.len(), 1);
    assert!(r.content[0].is_text());
    assert_eq!(r.content[0].as_text(), Some("boom"));
    assert!(r.is_error, "error constructor MUST set is_error=true");
}

#[test]
fn tool_call_response_with_content_const_fn_preserves_inputs() {
    let blocks = vec![
        McpContentBlock::text("a"),
        McpContentBlock::text("b"),
        McpContentBlock::resource("file:///c"),
    ];
    let r = McpToolCallResponse::with_content(blocks.clone(), false);
    assert_eq!(r.content.len(), 3);
    assert!(!r.is_error);
}

#[test]
fn tool_call_response_omits_is_error_field_when_false() {
    let r = McpToolCallResponse::text("payload");
    let s = serde_json::to_string(&r).expect("serialize");
    assert!(
        !s.contains("isError"),
        "is_error=false MUST be omitted from JSON (default suppression); got {s}"
    );
}

#[test]
fn tool_call_response_includes_is_error_field_when_true() {
    let r = McpToolCallResponse::error("oops");
    let v = serde_json::to_value(&r).expect("serialize");
    assert_eq!(
        v["isError"], true,
        "is_error=true MUST appear as 'isError' (camelCase rename)"
    );
}

#[test]
fn tool_call_response_serde_roundtrip_preserves_content_and_error_flag() {
    let r = McpToolCallResponse {
        content: vec![
            McpContentBlock::text("first"),
            McpContentBlock::text("second"),
        ],
        is_error: true,
    };
    let json_str = serde_json::to_string(&r).expect("serialize");
    let parsed: McpToolCallResponse = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.content.len(), 2);
    assert!(parsed.is_error);
}

// ─── McpToolAnnotations ───────────────────────────────────────────

#[test]
fn tool_annotations_default_omits_every_field_from_json() {
    // Construct explicitly with all-None (no Default impl).
    let ann = McpToolAnnotations {
        risk_level: None,
        safety_tier: None,
        idempotency: None,
        capability: None,
        read_only: None,
        destructive: None,
    };
    let s = serde_json::to_string(&ann).expect("serialize");
    // Every field is None → JSON should be "{}"
    assert_eq!(
        s, "{}",
        "all-None McpToolAnnotations MUST serialize to empty object (all fields skipped)"
    );
}

#[test]
fn tool_annotations_serializes_only_populated_fields() {
    let ann = McpToolAnnotations {
        risk_level: Some("high".into()),
        safety_tier: None,
        idempotency: Some("idempotent".into()),
        capability: None,
        read_only: Some(true),
        destructive: None,
    };
    let v = serde_json::to_value(&ann).expect("serialize");
    // McpToolAnnotations uses camelCase serde rename.
    assert!(v.get("riskLevel").is_some());
    assert!(v.get("idempotency").is_some());
    assert!(v.get("readOnly").is_some());
    assert!(v.get("safetyTier").is_none(), "None field MUST be omitted");
    assert!(v.get("capability").is_none());
    assert!(v.get("destructive").is_none());
}

#[test]
fn tool_annotations_serde_roundtrip_preserves_all_six_fields() {
    let ann = McpToolAnnotations {
        risk_level: Some("dangerous".into()),
        safety_tier: Some("destructive".into()),
        idempotency: Some("non_idempotent".into()),
        capability: Some("delete:repo".into()),
        read_only: Some(false),
        destructive: Some(true),
    };
    let json_str = serde_json::to_string(&ann).expect("serialize");
    let parsed: McpToolAnnotations = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.risk_level, ann.risk_level);
    assert_eq!(parsed.safety_tier, ann.safety_tier);
    assert_eq!(parsed.idempotency, ann.idempotency);
    assert_eq!(parsed.capability, ann.capability);
    assert_eq!(parsed.read_only, ann.read_only);
    assert_eq!(parsed.destructive, ann.destructive);
}

#[test]
fn tool_annotations_partial_population_round_trip() {
    let ann = McpToolAnnotations {
        risk_level: Some("safe".into()),
        safety_tier: None,
        idempotency: None,
        capability: None,
        read_only: Some(true),
        destructive: Some(false),
    };
    let json_str = serde_json::to_string(&ann).expect("serialize");
    let parsed: McpToolAnnotations = serde_json::from_str(&json_str).expect("deserialize");
    assert_eq!(parsed.risk_level.as_deref(), Some("safe"));
    assert!(parsed.safety_tier.is_none());
    assert_eq!(parsed.read_only, Some(true));
    assert_eq!(parsed.destructive, Some(false));
}
