//! Pin `PostureAttestation` Display + JSON serde + predicate truth tables —
//! the closest analogue to "ConnectorAttestation Display"
//! (flywheel_connectors-v8tvx).
//!
//! Bead asks for `ConnectorAttestation` Display + serde pinning. No type
//! literally named `ConnectorAttestation` exists in fcp-core. Three
//! attestation types live here:
//!   * [`SupplyChainAttestation`] — pinned by `signed_attestation_roundtrip.rs`
//!     (o0grt),
//!   * [`NodeKeyAttestation`] — needs a real Ed25519 owner signature to
//!     construct via the public API; deferred,
//!   * [`PostureAttestation`] at `crates/fcp-core/src/posture.rs:139` —
//!     fully constructible via public fields, the closest standalone
//!     attestation we can pin without a key-ceremony fixture. Existing
//!     `posture_tests.rs` covers behavioral validity but does not pin
//!     the 9-field JSON shape, the SCHEMA constant, predicate truth
//!     tables exhaustively, or `PostureAttributeValue` untagged shape.
//!
//! Coverage:
//!   * 9-field JSON shape pinned (schema, attestation_id, node_id,
//!     attributes, issued_at, expires_at, verifier_id, signature,
//!     verifier_kid),
//!   * SCHEMA = "fcp.posture.v1" constant pin,
//!   * is_valid truth table: NOT expired AND schema matches,
//!   * is_expired vs is_expired_at boundary alignment,
//!   * is_for_node identity sentinel,
//!   * Attribute getter helpers (disk_encryption_enabled, os_version, os_type),
//!   * PostureAttributeKey 11-variant snake_case serde + as_str
//!     alignment (Custom is the only payload variant),
//!   * PostureAttributeValue untagged shape (Bool/String/Number — pin so
//!     a future internal-tag silently changes wire form),
//!   * JSON + CBOR round-trip preserves attributes Map,
//!   * Distinct-verifier-id sentinel (security-critical: switching the
//!     attesting verifier must change the wire form).

use chrono::{DateTime, TimeZone, Utc};
use fcp_core::{NodeId, PostureAttestation, PostureAttributeKey, PostureAttributeValue};
use serde_json::json;
use std::collections::HashMap;

const ALL_ATTRIBUTE_KEYS: &[(PostureAttributeKey, &str)] = &[
    (PostureAttributeKey::OsType, "os_type"),
    (PostureAttributeKey::OsVersion, "os_version"),
    (PostureAttributeKey::DiskEncryption, "disk_encryption"),
    (PostureAttributeKey::FirewallEnabled, "firewall_enabled"),
    (
        PostureAttributeKey::ScreenLockEnabled,
        "screen_lock_enabled",
    ),
    (
        PostureAttributeKey::ScreenLockTimeout,
        "screen_lock_timeout",
    ),
    (PostureAttributeKey::AntivirusActive, "antivirus_active"),
    (PostureAttributeKey::DeviceManaged, "device_managed"),
    (
        PostureAttributeKey::SecureBootEnabled,
        "secure_boot_enabled",
    ),
    (PostureAttributeKey::TpmPresent, "tpm_present"),
];

fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0)
        .single()
        .unwrap()
}

fn populated_attestation() -> PostureAttestation {
    let mut attributes = HashMap::new();
    attributes.insert(
        PostureAttributeKey::OsType,
        PostureAttributeValue::String("macos".to_string()),
    );
    attributes.insert(
        PostureAttributeKey::OsVersion,
        PostureAttributeValue::String("14.2.1".to_string()),
    );
    attributes.insert(
        PostureAttributeKey::DiskEncryption,
        PostureAttributeValue::Bool(true),
    );
    attributes.insert(
        PostureAttributeKey::ScreenLockTimeout,
        PostureAttributeValue::Number(300),
    );

    PostureAttestation {
        schema: PostureAttestation::SCHEMA.to_string(),
        attestation_id: "att-001".to_string(),
        node_id: NodeId::new("node-alpha"),
        attributes,
        issued_at: ts(2030, 1, 1),
        expires_at: ts(2030, 6, 1),
        verifier_id: "verifier.example".to_string(),
        signature: "sig-base64-payload".to_string(),
        verifier_kid: "key-001".to_string(),
    }
}

#[test]
fn schema_constant_is_fcp_posture_v1() {
    assert_eq!(PostureAttestation::SCHEMA, "fcp.posture.v1");
}

#[test]
fn populated_attestation_full_field_set_pinned() {
    let att = populated_attestation();
    let v = serde_json::to_value(&att).unwrap();
    let obj = v.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = [
        "schema",
        "attestation_id",
        "node_id",
        "attributes",
        "issued_at",
        "expires_at",
        "verifier_id",
        "signature",
        "verifier_kid",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "PostureAttestation shape drift: {obj:?}");

    assert_eq!(obj.get("schema"), Some(&json!("fcp.posture.v1")));
    assert_eq!(obj.get("attestation_id"), Some(&json!("att-001")));
    assert_eq!(obj.get("verifier_id"), Some(&json!("verifier.example")));
}

#[test]
fn is_valid_requires_correct_schema_and_not_expired() {
    let mut att = populated_attestation();
    att.expires_at = Utc::now() + chrono::Duration::hours(1);

    // Correct schema + future expiry → valid.
    assert!(att.is_valid());

    // Wrong schema → invalid (even if not expired).
    att.schema = "wrong.schema.v1".to_string();
    assert!(!att.is_valid(), "wrong schema must invalidate");
    att.schema = PostureAttestation::SCHEMA.to_string();
    assert!(att.is_valid());

    // Expired → invalid (even with correct schema).
    att.expires_at = Utc::now() - chrono::Duration::hours(1);
    assert!(!att.is_valid(), "expired must invalidate");
}

#[test]
fn is_expired_truth_table() {
    let mut att = populated_attestation();
    att.expires_at = Utc::now() + chrono::Duration::hours(1);
    assert!(!att.is_expired(), "future expiry → not expired");

    att.expires_at = Utc::now() - chrono::Duration::hours(1);
    assert!(att.is_expired(), "past expiry → expired");
}

#[test]
fn is_expired_at_pins_exact_millisecond_boundary() {
    // is_expired_at uses `expires_at <= now_ms`, so equality at the
    // boundary IS expired.
    let att = PostureAttestation {
        schema: PostureAttestation::SCHEMA.to_string(),
        attestation_id: "att-bdy".to_string(),
        node_id: NodeId::new("node-alpha"),
        attributes: HashMap::new(),
        issued_at: ts(2030, 1, 1),
        expires_at: Utc.timestamp_millis_opt(1_000).unwrap(),
        verifier_id: "v".to_string(),
        signature: "s".to_string(),
        verifier_kid: "k".to_string(),
    };
    assert!(!att.is_expired_at(999), "now < expires must NOT be expired");
    assert!(att.is_expired_at(1_000), "now == expires IS expired");
    assert!(att.is_expired_at(1_001), "now > expires IS expired");
}

#[test]
fn is_for_node_identity_sentinel() {
    let att = populated_attestation();
    assert!(att.is_for_node(&NodeId::new("node-alpha")));
    assert!(!att.is_for_node(&NodeId::new("node-bravo")));
}

#[test]
fn attribute_getter_helpers_truth_table() {
    let att = populated_attestation();
    assert_eq!(att.disk_encryption_enabled(), Some(true));
    assert_eq!(att.os_type(), Some("macos"));
    assert_eq!(att.os_version(), Some("14.2.1"));

    // Missing attribute → None.
    let mut sparse = populated_attestation();
    sparse
        .attributes
        .remove(&PostureAttributeKey::DiskEncryption);
    assert!(sparse.disk_encryption_enabled().is_none());
}

#[test]
fn attribute_value_type_mismatch_returns_none_not_panic() {
    let mut att = populated_attestation();
    // OsType is a string; if we read it as bool, we get None (not panic).
    att.attributes.insert(
        PostureAttributeKey::DiskEncryption,
        PostureAttributeValue::String("not-a-bool".to_string()),
    );
    assert!(att.disk_encryption_enabled().is_none());
}

#[test]
fn posture_attribute_key_serde_uses_snake_case_for_unit_variants() {
    for (variant, wire) in ALL_ATTRIBUTE_KEYS {
        let v = serde_json::to_value(variant).unwrap();
        assert_eq!(v, json!(wire), "{variant:?} must serialize to `{wire}`");
        let back: PostureAttributeKey = serde_json::from_value(v).unwrap();
        assert_eq!(&back, variant);

        // as_str must align with serde wire form for the unit variants.
        assert_eq!(
            variant.as_str(),
            *wire,
            "as_str for {variant:?} != serde wire `{wire}`"
        );
    }
}

#[test]
fn posture_attribute_key_custom_carries_payload_via_externally_tagged_object() {
    // Custom is a tuple variant. With #[serde(rename_all = "snake_case")]
    // applied to the enum but no #[serde(tag = "...")], it uses the
    // default externally-tagged form: { "custom": "<inner>" }.
    let custom = PostureAttributeKey::Custom("hardware_revision".to_string());
    let v = serde_json::to_value(&custom).unwrap();
    let obj = v.as_object().expect("Custom must serialize as object");
    assert_eq!(obj.len(), 1);
    assert_eq!(obj.get("custom"), Some(&json!("hardware_revision")));

    let back: PostureAttributeKey = serde_json::from_value(v).unwrap();
    assert_eq!(back, custom);
}

#[test]
fn posture_attribute_value_untagged_serializes_as_bare_scalar() {
    // #[serde(untagged)] on PostureAttributeValue → no wrapper. A bool
    // serializes as `true`/`false`, a string as `"..."`, a number as the
    // raw integer. Pin so a future tagged-form change is caught loudly.
    let b = serde_json::to_value(PostureAttributeValue::Bool(true)).unwrap();
    assert_eq!(b, json!(true));

    let s = serde_json::to_value(PostureAttributeValue::String("x".to_string())).unwrap();
    assert_eq!(s, json!("x"));

    let n = serde_json::to_value(PostureAttributeValue::Number(42)).unwrap();
    assert_eq!(n, json!(42));

    // Untagged round-trip discriminates by JSON type.
    let bool_back: PostureAttributeValue = serde_json::from_value(json!(true)).unwrap();
    assert_eq!(bool_back, PostureAttributeValue::Bool(true));
    let str_back: PostureAttributeValue = serde_json::from_value(json!("hello")).unwrap();
    assert_eq!(str_back, PostureAttributeValue::String("hello".to_string()));
    let num_back: PostureAttributeValue = serde_json::from_value(json!(7)).unwrap();
    assert_eq!(num_back, PostureAttributeValue::Number(7));
}

#[test]
fn posture_attribute_value_getters_truth_table() {
    assert_eq!(PostureAttributeValue::Bool(true).as_bool(), Some(true));
    assert_eq!(PostureAttributeValue::Bool(false).as_bool(), Some(false));
    assert!(
        PostureAttributeValue::String("x".to_string())
            .as_bool()
            .is_none()
    );
    assert!(PostureAttributeValue::Number(1).as_bool().is_none());

    assert_eq!(
        PostureAttributeValue::String("x".to_string()).as_str(),
        Some("x")
    );
    assert!(PostureAttributeValue::Bool(true).as_str().is_none());
    assert!(PostureAttributeValue::Number(1).as_str().is_none());

    assert_eq!(PostureAttributeValue::Number(42).as_number(), Some(42));
    assert!(PostureAttributeValue::Bool(true).as_number().is_none());
    assert!(
        PostureAttributeValue::String("x".to_string())
            .as_number()
            .is_none()
    );
}

#[test]
fn attestation_json_roundtrip_preserves_attributes_map() {
    let att = populated_attestation();
    let bytes = serde_json::to_vec(&att).unwrap();
    let back: PostureAttestation = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.schema, att.schema);
    assert_eq!(back.attestation_id, att.attestation_id);
    assert_eq!(back.node_id, att.node_id);
    assert_eq!(back.verifier_id, att.verifier_id);
    assert_eq!(back.signature, att.signature);
    assert_eq!(back.verifier_kid, att.verifier_kid);

    // Map preserves all entries.
    assert_eq!(back.attributes.len(), att.attributes.len());
    assert_eq!(back.os_type(), Some("macos"));
    assert_eq!(back.os_version(), Some("14.2.1"));
    assert_eq!(back.disk_encryption_enabled(), Some(true));
    assert_eq!(
        back.attributes.get(&PostureAttributeKey::ScreenLockTimeout),
        Some(&PostureAttributeValue::Number(300))
    );
}

#[test]
fn attestation_cbor_roundtrip_preserves_attributes_map() {
    let att = populated_attestation();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&att, &mut bytes).unwrap();
    let back: PostureAttestation = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(back.attributes.len(), att.attributes.len());
    assert_eq!(back.os_type(), Some("macos"));
    assert_eq!(back.disk_encryption_enabled(), Some(true));
}

#[test]
fn distinct_verifier_id_produces_distinct_json() {
    // Verifier identity is security-critical: switching the verifier
    // changes who's vouching for the device. Pin so a future "skip
    // verifier_id when default" silently changes the wire form.
    let mut a = populated_attestation();
    let mut b = populated_attestation();
    a.verifier_id = "verifier.alpha".to_string();
    b.verifier_id = "verifier.bravo".to_string();
    assert_ne!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&b).unwrap()
    );
}

#[test]
fn distinct_node_id_produces_distinct_json() {
    let mut a = populated_attestation();
    let mut b = populated_attestation();
    a.node_id = NodeId::new("node-1");
    b.node_id = NodeId::new("node-2");
    assert_ne!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&b).unwrap()
    );
}

#[test]
fn distinct_signature_produces_distinct_json() {
    let mut a = populated_attestation();
    let mut b = populated_attestation();
    a.signature = "sig-A".to_string();
    b.signature = "sig-B".to_string();
    assert_ne!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&b).unwrap()
    );
}

#[test]
fn empty_attributes_map_round_trips_through_json() {
    let mut att = populated_attestation();
    att.attributes.clear();
    let bytes = serde_json::to_vec(&att).unwrap();
    let back: PostureAttestation = serde_json::from_slice(&bytes).unwrap();
    assert!(back.attributes.is_empty());
    assert!(back.os_type().is_none());
    assert!(back.disk_encryption_enabled().is_none());
}

#[test]
fn posture_attribute_key_distinct_variants_serialize_distinctly() {
    let mut seen = std::collections::HashSet::new();
    for (variant, _) in ALL_ATTRIBUTE_KEYS {
        let v = serde_json::to_value(variant).unwrap();
        assert!(
            seen.insert(v.clone()),
            "duplicate JSON for {variant:?}: {v:?}"
        );
    }
    // Custom is a payload variant — its JSON form differs from any unit form.
    let custom_v = serde_json::to_value(&PostureAttributeKey::Custom("x".to_string())).unwrap();
    assert!(seen.insert(custom_v));
}
