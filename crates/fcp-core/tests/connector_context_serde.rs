//! Pin `InvokeContext` serde shape — the closest analogue to
//! "ConnectorContext serde" (flywheel_connectors-kqfbb).
//!
//! Bead asks for `ConnectorContext serde JSON+CBOR roundtrip`. No
//! type literally named `ConnectorContext` exists in fcp-core. The
//! per-request context that travels with connector invocations is
//! `InvokeContext` (protocol.rs:410), the documented context for:
//!
//!  - Internationalization (locale)
//!  - Pagination control
//!  - Distributed tracing (trace_id, request_tags)
//!
//! Field shape:
//!
//! ```text
//! InvokeContext {
//!     locale:        Option<String>          (skip_serializing_if = None)
//!     pagination:    Option<serde_json::Value>(skip_serializing_if = None)
//!     trace_id:      Option<String>          (skip_serializing_if = None)
//!     request_tags:  HashMap<String, String> (default + skip_serializing_if = HashMap::is_empty)
//! }
//! ```
//!
//! The existing inline tests in `invoke_golden_vectors.rs::invoke_context`
//! pin Default and a handful of fields. This test pins the GAPS:
//!
//!   1. **Default empty context serializes to `{}`** — every
//!      Option is None and the HashMap is empty, so all four fields
//!      are omitted via skip_serializing_if.
//!   2. **Per-field skip_serializing_if shape** — Some/None
//!      distinction on every Optional field.
//!   3. **Empty `request_tags` HashMap is omitted** via
//!      `skip_serializing_if = "HashMap::is_empty"`.
//!   4. **Default values** for unset fields when deserializing
//!      partial JSON — locale/pagination/trace_id default to None,
//!      request_tags defaults to empty.
//!   5. **JSON round-trip** preserves all 4 fields with various
//!      population shapes.
//!   6. **CBOR round-trip** preserves the same.
//!   7. **Multi-byte UTF-8 locale** preserved through both formats.
//!   8. **Pagination `serde_json::Value` is free-form** — preserved
//!      verbatim across round-trip.
//!   9. **Cross-format consistency**: JSON and CBOR decode to the
//!      same context.
//!  10. **Distinct contexts produce distinct serializations** —
//!      every field axis is observable on the wire.

use std::collections::HashMap;

use fcp_core::InvokeContext;

fn populated_context() -> InvokeContext {
    let mut tags = HashMap::new();
    tags.insert("priority".to_string(), "high".to_string());
    tags.insert("source.component".to_string(), "api_gateway".to_string());
    InvokeContext {
        locale: Some("en-US".to_string()),
        pagination: Some(serde_json::json!({"cursor": "abc", "limit": 50})),
        trace_id: Some("0af7651916cd43dd8448eb211c80319c".to_string()),
        request_tags: tags,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Default empty context serializes to `{}`
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn default_context_serializes_to_empty_json_object() {
    let ctx = InvokeContext::default();
    let json = serde_json::to_string(&ctx).expect("serialize");
    assert_eq!(
        json, "{}",
        "empty InvokeContext MUST serialize to `{{}}` since every \
         field has skip_serializing_if; got {json}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Per-field skip_serializing_if shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn locale_omitted_when_none() {
    let ctx = InvokeContext {
        locale: None,
        ..Default::default()
    };
    let value = serde_json::to_value(&ctx).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(
        !obj.contains_key("locale"),
        "locale MUST be omitted when None"
    );
}

#[test]
fn locale_present_when_some() {
    let ctx = InvokeContext {
        locale: Some("fr-FR".to_string()),
        ..Default::default()
    };
    let value = serde_json::to_value(&ctx).expect("serialize");
    let obj = value.as_object().expect("object");
    assert_eq!(obj.get("locale").and_then(|v| v.as_str()), Some("fr-FR"));
    assert_eq!(obj.len(), 1, "exactly 1 field present");
}

#[test]
fn pagination_omitted_when_none() {
    let ctx = InvokeContext {
        pagination: None,
        ..Default::default()
    };
    let value = serde_json::to_value(&ctx).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(!obj.contains_key("pagination"));
}

#[test]
fn trace_id_omitted_when_none() {
    let ctx = InvokeContext {
        trace_id: None,
        ..Default::default()
    };
    let value = serde_json::to_value(&ctx).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(!obj.contains_key("trace_id"));
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Empty request_tags HashMap is omitted
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_request_tags_hashmap_omitted_from_wire_form() {
    let ctx = InvokeContext {
        request_tags: HashMap::new(),
        ..Default::default()
    };
    let value = serde_json::to_value(&ctx).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(
        !obj.contains_key("request_tags"),
        "empty request_tags HashMap MUST be omitted via skip_serializing_if = \"HashMap::is_empty\""
    );
}

#[test]
fn non_empty_request_tags_present_in_wire_form() {
    let mut tags = HashMap::new();
    tags.insert("region".to_string(), "us-west".to_string());
    let ctx = InvokeContext {
        request_tags: tags,
        ..Default::default()
    };
    let value = serde_json::to_value(&ctx).expect("serialize");
    let obj = value.as_object().expect("object");
    assert!(obj.contains_key("request_tags"));
    let inner = obj
        .get("request_tags")
        .and_then(|v| v.as_object())
        .expect("request_tags is JSON object");
    assert_eq!(
        inner.get("region").and_then(|v| v.as_str()),
        Some("us-west")
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Default values when deserializing partial JSON
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn deserializing_empty_object_yields_default_context() {
    let ctx: InvokeContext = serde_json::from_str("{}").expect("deserialize");
    assert!(ctx.locale.is_none());
    assert!(ctx.pagination.is_none());
    assert!(ctx.trace_id.is_none());
    assert!(ctx.request_tags.is_empty());
}

#[test]
fn deserializing_partial_object_defaults_missing_fields() {
    let json = r#"{"locale": "ja-JP"}"#;
    let ctx: InvokeContext = serde_json::from_str(json).expect("deserialize");
    assert_eq!(ctx.locale, Some("ja-JP".to_string()));
    assert!(ctx.pagination.is_none());
    assert!(ctx.trace_id.is_none());
    assert!(ctx.request_tags.is_empty());
}

#[test]
fn deserializing_request_tags_only_yields_default_for_others() {
    let json = r#"{"request_tags": {"a": "1"}}"#;
    let ctx: InvokeContext = serde_json::from_str(json).expect("deserialize");
    assert!(ctx.locale.is_none());
    assert!(ctx.pagination.is_none());
    assert!(ctx.trace_id.is_none());
    assert_eq!(ctx.request_tags.len(), 1);
    assert_eq!(ctx.request_tags.get("a"), Some(&"1".to_string()));
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. JSON round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_preserves_default_context() {
    let original = InvokeContext::default();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: InvokeContext = serde_json::from_str(&json).expect("deserialize");
    assert!(back.locale.is_none());
    assert!(back.pagination.is_none());
    assert!(back.trace_id.is_none());
    assert!(back.request_tags.is_empty());
}

#[test]
fn json_roundtrip_preserves_populated_context() {
    let original = populated_context();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: InvokeContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.locale, original.locale);
    assert_eq!(back.pagination, original.pagination);
    assert_eq!(back.trace_id, original.trace_id);
    assert_eq!(back.request_tags, original.request_tags);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. CBOR round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_roundtrip_preserves_default_context() {
    let original = InvokeContext::default();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: InvokeContext = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert!(back.locale.is_none());
    assert!(back.pagination.is_none());
    assert!(back.trace_id.is_none());
    assert!(back.request_tags.is_empty());
}

#[test]
fn cbor_roundtrip_preserves_populated_context() {
    let original = populated_context();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: InvokeContext = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.locale, original.locale);
    assert_eq!(back.pagination, original.pagination);
    assert_eq!(back.trace_id, original.trace_id);
    assert_eq!(back.request_tags, original.request_tags);
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Multi-byte UTF-8 locale preserved
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn multibyte_utf8_locale_round_trips_through_json() {
    // Synthetic locale string with multi-byte UTF-8 bytes; not a
    // real locale code but exercises the UTF-8 path.
    let locale = "日本語-変体".to_string();
    let ctx = InvokeContext {
        locale: Some(locale.clone()),
        ..Default::default()
    };
    let json = serde_json::to_string(&ctx).expect("serialize");
    let back: InvokeContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.locale, Some(locale));
}

#[test]
fn multibyte_utf8_locale_round_trips_through_cbor() {
    let locale = "中文-繁體".to_string();
    let ctx = InvokeContext {
        locale: Some(locale.clone()),
        ..Default::default()
    };
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&ctx, &mut buf).expect("encode");
    let back: InvokeContext = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.locale, Some(locale));
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Pagination is free-form serde_json::Value
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn pagination_object_value_round_trips() {
    let ctx = InvokeContext {
        pagination: Some(serde_json::json!({
            "cursor": "abc",
            "limit": 100,
            "after": null,
        })),
        ..Default::default()
    };
    let json = serde_json::to_string(&ctx).expect("serialize");
    let back: InvokeContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.pagination, ctx.pagination);
}

#[test]
fn pagination_array_value_round_trips() {
    let ctx = InvokeContext {
        pagination: Some(serde_json::json!([1, 2, 3])),
        ..Default::default()
    };
    let json = serde_json::to_string(&ctx).expect("serialize");
    let back: InvokeContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.pagination, ctx.pagination);
}

#[test]
fn pagination_string_value_round_trips() {
    let ctx = InvokeContext {
        pagination: Some(serde_json::json!("opaque-cursor-token")),
        ..Default::default()
    };
    let json = serde_json::to_string(&ctx).expect("serialize");
    let back: InvokeContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.pagination, ctx.pagination);
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. Cross-format consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_and_cbor_decode_to_same_populated_context() {
    let original = populated_context();

    let json = serde_json::to_string(&original).expect("JSON serialize");
    let from_json: InvokeContext = serde_json::from_str(&json).expect("JSON deserialize");

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&original, &mut cbor).expect("CBOR encode");
    let from_cbor: InvokeContext = ciborium::de::from_reader(cbor.as_slice()).expect("CBOR decode");

    assert_eq!(from_json.locale, from_cbor.locale);
    assert_eq!(from_json.pagination, from_cbor.pagination);
    assert_eq!(from_json.trace_id, from_cbor.trace_id);
    assert_eq!(from_json.request_tags, from_cbor.request_tags);
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Distinct contexts produce distinct serializations
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_locale_produces_distinct_json() {
    let a = InvokeContext {
        locale: Some("en-US".to_string()),
        ..Default::default()
    };
    let b = InvokeContext {
        locale: Some("ja-JP".to_string()),
        ..Default::default()
    };
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn distinct_trace_id_produces_distinct_json() {
    let a = InvokeContext {
        trace_id: Some("aaaa".to_string()),
        ..Default::default()
    };
    let b = InvokeContext {
        trace_id: Some("bbbb".to_string()),
        ..Default::default()
    };
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn distinct_request_tags_produce_distinct_json() {
    let mut tags_a = HashMap::new();
    tags_a.insert("k".to_string(), "v1".to_string());
    let mut tags_b = HashMap::new();
    tags_b.insert("k".to_string(), "v2".to_string());
    let a = InvokeContext {
        request_tags: tags_a,
        ..Default::default()
    };
    let b = InvokeContext {
        request_tags: tags_b,
        ..Default::default()
    };
    assert_ne!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
}

#[test]
fn empty_vs_populated_context_serializations_distinct() {
    let empty = InvokeContext::default();
    let populated = populated_context();
    assert_ne!(
        serde_json::to_string(&empty).unwrap(),
        serde_json::to_string(&populated).unwrap()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. Empty-string locale is distinct from None
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_string_locale_distinct_from_none() {
    // Some("") and None are distinct on the wire — Some("") emits
    // the field with empty string, None omits the field entirely.
    let some_empty = InvokeContext {
        locale: Some(String::new()),
        ..Default::default()
    };
    let none = InvokeContext {
        locale: None,
        ..Default::default()
    };
    assert_ne!(
        serde_json::to_string(&some_empty).unwrap(),
        serde_json::to_string(&none).unwrap()
    );
    let some_value = serde_json::to_value(&some_empty).unwrap();
    assert_eq!(some_value.get("locale").and_then(|v| v.as_str()), Some(""));
    let none_value = serde_json::to_value(&none).unwrap();
    assert!(!none_value.as_object().unwrap().contains_key("locale"));
}
