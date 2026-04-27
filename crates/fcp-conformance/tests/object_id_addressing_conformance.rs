//! `ObjectId` content-addressing + zone/schema/key binding +
//! manifest-prefix parse conformance.
//!
//! `fcp_core::ObjectId` is the 32-byte BLAKE3-keyed hash that names
//! every content-addressed object in FCP. Two constructors:
//!
//! - `ObjectId::new(content, zone, schema, key)` — NORMATIVE
//!   security form. Zone-keyed via `ObjectIdKey` so two zones with
//!   the same content produce DIFFERENT ids (prevents cross-zone
//!   aliasing). Schema-bound so semantically-different objects
//!   with identical bytes don't collide.
//! - `ObjectId::from_unscoped_bytes` — non-normative content-only
//!   form for fixtures and debug code.
//!
//! Plus the manifest-facing parse contract: `parse_prefixed`
//! accepts both `"objectid:<hex>"` and bare hex (case-insensitive),
//! and `to_prefixed_string` round-trips.
//!
//! `ObjectIdKey::Debug` MUST redact the key bytes — it's a secret.

use fcp_cbor::SchemaId;
use fcp_core::{ObjectId, ObjectIdKey, ObjectIdParseError, ZoneId};
use semver::Version;

fn key_a() -> ObjectIdKey {
    ObjectIdKey::from_bytes([0xA1; 32])
}

fn key_b() -> ObjectIdKey {
    ObjectIdKey::from_bytes([0xB2; 32])
}

fn schema_alpha() -> SchemaId {
    SchemaId::new("fcp.test", "Alpha", Version::new(1, 0, 0))
}

fn schema_beta() -> SchemaId {
    SchemaId::new("fcp.test", "Beta", Version::new(1, 0, 0))
}

#[test]
fn from_bytes_and_as_bytes_round_trip() {
    let raw = [0x42_u8; 32];
    let id = ObjectId::from_bytes(raw);
    assert_eq!(id.as_bytes(), &raw);
}

#[test]
fn display_renders_lowercase_hex_64_chars() {
    let id = ObjectId::from_bytes([0xAB; 32]);
    let s = format!("{id}");
    assert_eq!(s.len(), 64, "ObjectId Display MUST be 64 hex chars");
    assert_eq!(
        s,
        "ab".repeat(32),
        "Display MUST be lowercase hex of all bytes"
    );
}

#[test]
fn debug_includes_hex_form_for_observability() {
    let id = ObjectId::from_bytes([0x01; 32]);
    let dbg = format!("{id:?}");
    assert!(
        dbg.contains("01"),
        "Debug MUST include the hex form so logs are debuggable; got {dbg}"
    );
}

#[test]
fn parse_prefixed_accepts_objectid_prefix() {
    let raw = [0xAB; 32];
    let bare_hex = hex::encode(raw);
    let prefixed = format!("objectid:{bare_hex}");
    let parsed = ObjectId::parse_prefixed(&prefixed).expect("must parse");
    assert_eq!(parsed.as_bytes(), &raw);
}

#[test]
fn parse_prefixed_accepts_bare_hex() {
    let raw = [0xCD; 32];
    let bare_hex = hex::encode(raw);
    let parsed = ObjectId::parse_prefixed(&bare_hex).expect("must parse bare hex");
    assert_eq!(parsed.as_bytes(), &raw);
}

#[test]
fn parse_prefixed_accepts_uppercase_hex() {
    let raw = [0x9F; 32];
    let upper_hex = hex::encode_upper(raw);
    let parsed = ObjectId::parse_prefixed(&upper_hex).expect("uppercase must parse");
    assert_eq!(parsed.as_bytes(), &raw);
}

#[test]
fn parse_prefixed_rejects_non_hex_with_invalid_hex_error() {
    let err =
        ObjectId::parse_prefixed("not-hex!!").expect_err("non-hex MUST be rejected");
    assert_eq!(err, ObjectIdParseError::InvalidHex);
}

#[test]
fn parse_prefixed_rejects_short_hex_with_wrong_length() {
    let short = hex::encode([0xAB; 16]); // 16 bytes / 32 chars — wrong
    let err = ObjectId::parse_prefixed(&short)
        .expect_err("short hex (16 bytes) MUST be rejected with WrongLength");
    match err {
        ObjectIdParseError::WrongLength { actual } => {
            assert_eq!(actual, 16, "WrongLength must report the actual length");
        }
        other => panic!("expected WrongLength, got {other:?}"),
    }
}

#[test]
fn parse_prefixed_rejects_long_hex_with_wrong_length() {
    let long = hex::encode([0xAB; 48]); // 48 bytes — wrong
    let err = ObjectId::parse_prefixed(&long).expect_err("long hex MUST be rejected");
    assert!(matches!(
        err,
        ObjectIdParseError::WrongLength { actual: 48 }
    ));
}

#[test]
fn to_prefixed_string_round_trips_with_parse_prefixed() {
    let original = ObjectId::from_bytes([0x77; 32]);
    let prefixed = original.to_prefixed_string();
    assert!(
        prefixed.starts_with("objectid:"),
        "to_prefixed_string MUST emit 'objectid:' prefix; got {prefixed}"
    );
    let parsed = ObjectId::parse_prefixed(&prefixed).expect("round-trip parse");
    assert_eq!(parsed, original);
}

#[test]
fn new_is_deterministic_for_fixed_inputs() {
    let content = b"important payload";
    let zone = ZoneId::work();
    let schema = schema_alpha();
    let key = key_a();

    let id1 = ObjectId::new(content, &zone, &schema, &key);
    let id2 = ObjectId::new(content, &zone, &schema, &key);
    assert_eq!(
        id1, id2,
        "ObjectId::new MUST be deterministic for fixed (content, zone, schema, key)"
    );
}

#[test]
fn new_zone_binding_prevents_cross_zone_aliasing() {
    // Same content + schema + key, different zones → different ids.
    // This is the SECURITY property that prevents an attacker who
    // observes an object's id in zone A from concluding the same
    // object exists in zone B.
    let content = b"sensitive";
    let key = key_a();
    let schema = schema_alpha();

    let id_work = ObjectId::new(content, &ZoneId::work(), &schema, &key);
    let id_private = ObjectId::new(content, &ZoneId::private(), &schema, &key);
    assert_ne!(
        id_work, id_private,
        "different zones with identical content+schema+key MUST yield different ids \
         (cross-zone aliasing defense)"
    );
}

#[test]
fn new_schema_binding_distinguishes_semantically_different_objects() {
    // Same content + zone + key, different schemas. Two objects
    // with identical bytes but different semantic meaning MUST
    // have different ids.
    let content = b"42";
    let zone = ZoneId::work();
    let key = key_a();

    let id_alpha = ObjectId::new(content, &zone, &schema_alpha(), &key);
    let id_beta = ObjectId::new(content, &zone, &schema_beta(), &key);
    assert_ne!(
        id_alpha, id_beta,
        "different schemas with identical content+zone+key MUST yield different ids"
    );
}

#[test]
fn new_key_binding_prevents_dictionary_attacks() {
    // The ObjectIdKey is a per-zone secret. Same content + zone +
    // schema, different keys → different ids. Without this, an
    // attacker could enumerate hashes of low-entropy objects.
    let content = b"yes";
    let zone = ZoneId::work();
    let schema = schema_alpha();

    let id_a = ObjectId::new(content, &zone, &schema, &key_a());
    let id_b = ObjectId::new(content, &zone, &schema, &key_b());
    assert_ne!(
        id_a, id_b,
        "different ObjectIdKeys with identical content+zone+schema MUST yield different ids \
         (dictionary-attack defense)"
    );
}

#[test]
fn from_unscoped_bytes_is_deterministic() {
    let id1 = ObjectId::from_unscoped_bytes(b"hello");
    let id2 = ObjectId::from_unscoped_bytes(b"hello");
    assert_eq!(
        id1, id2,
        "from_unscoped_bytes MUST be deterministic (content-addressed)"
    );
}

#[test]
fn from_unscoped_bytes_differs_for_different_content() {
    let id_a = ObjectId::from_unscoped_bytes(b"hello");
    let id_b = ObjectId::from_unscoped_bytes(b"world");
    assert_ne!(id_a, id_b);
}

#[test]
fn from_unscoped_bytes_uses_distinct_domain_separator_from_new() {
    // The two constructors use different BLAKE3 domain separators
    // ("FCP2-CONTENT-V2" vs "FCP2-OBJECT-V2"). Even with identical
    // content, an unscoped id MUST NOT collide with a security id.
    let content = b"shared content";
    let zone = ZoneId::work();
    let schema = schema_alpha();
    let key = key_a();

    let unscoped = ObjectId::from_unscoped_bytes(content);
    let scoped = ObjectId::new(content, &zone, &schema, &key);
    assert_ne!(
        unscoped, scoped,
        "unscoped and security ObjectIds MUST use distinct domain separators so an \
         attacker who knows the unscoped hash cannot infer the security id"
    );
}

#[test]
fn object_id_key_debug_redacts_secret_bytes() {
    let key = ObjectIdKey::from_bytes([0xCC; 32]);
    let dbg = format!("{key:?}");
    assert!(
        dbg.contains("[redacted"),
        "ObjectIdKey::Debug MUST redact the secret bytes; got {dbg}"
    );
    // Sanity: the byte content must NOT appear verbatim.
    assert!(
        !dbg.contains("cccccc"),
        "ObjectIdKey::Debug MUST NOT leak hex bytes; got {dbg}"
    );
}

#[test]
fn as_ref_returns_full_32_bytes() {
    let id = ObjectId::from_bytes([0xEF; 32]);
    let slice: &[u8] = id.as_ref();
    assert_eq!(slice.len(), 32);
    assert_eq!(slice, &[0xEF; 32]);
}

#[test]
fn json_serde_roundtrip_uses_hex_string_form() {
    let id = ObjectId::from_bytes([0x01; 32]);
    let json = serde_json::to_string(&id).expect("serialize");
    // hex_or_bytes serde adapter uses hex string form for JSON.
    let parsed: ObjectId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, id);
}
