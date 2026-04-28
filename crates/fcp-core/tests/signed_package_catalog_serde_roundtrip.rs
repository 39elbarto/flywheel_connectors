//! Pin signed-package envelope + canonical-payload serde behavior
//! (flywheel_connectors-c8hb0).
//!
//! Bead asks for "SignedPackageCatalog Display formatting + serde
//! JSON+CBOR roundtrip". No type literally named
//! `SignedPackageCatalog` exists in fcp-core. The closest analogue
//! is `SignedManifest<T>` (connector_artifacts.rs:237) — the canonical
//! signed envelope that wraps any package payload (e.g.,
//! `ConnectorManifestObject`, `ConnectorBinaryObject`,
//! `ConnectorBinarySymbolSet`). `LocalRegistryCatalog` does exist in
//! `fcp-registry`, not `fcp-core`. None of these types implement
//! `Display`, so the bead's "Display formatting" ask has no analogue
//! either — only `ManifestVersion` has Display in this module.
//!
//! Tests pin what exists for the signed-envelope surface:
//!
//!   1. **Canonical schema IDs** for `SignedManifest`,
//!      `ConnectorManifestObject`, `ConnectorBinaryObject`, and
//!      `ConnectorBinarySymbolSet` are stable strings.
//!   2. **Sign + verify round-trip** — a signed manifest verifies
//!      under the same key and rejects under a different key.
//!   3. **`canonical_payload_bytes` is deterministic** — same payload
//!      produces identical bytes across calls.
//!   4. **JSON round-trip** preserves all envelope fields (schema,
//!      payload, signer_kid, signature) for a representative payload.
//!   5. **CBOR round-trip** preserves the same fields.
//!   6. **`to_canonical_bytes` / `from_canonical_bytes` round-trip**
//!      via the canonical schema.
//!   7. **`ManifestSignature` per-variant JSON form pinned** — the
//!      enum that tags algorithm choice.
//!   8. **Tampering detection** — flipping a payload byte in the
//!      decoded envelope fails verification.

use fcp_cbor::SchemaId;
use fcp_core::{
    ConnectorBinaryObject, ConnectorBinarySymbolSet, ConnectorBinaryTransmissionInfo,
    ConnectorManifestObject, ConnectorTarget, ManifestSignature, ObjectId, SignedManifest,
};
use fcp_crypto::ed25519::{Ed25519SigningKey, SECRET_KEY_SIZE};
use semver::Version;

fn deterministic_key(seed: u8) -> Ed25519SigningKey {
    let mut bytes = [0u8; SECRET_KEY_SIZE];
    bytes[0] = seed;
    Ed25519SigningKey::from_bytes(&bytes).expect("deterministic ed25519 secret")
}

fn fixture_manifest() -> ConnectorManifestObject {
    ConnectorManifestObject {
        manifest_toml: "[connector]\nname = \"fcp.example\"\nversion = \"1.0.0\"".to_string(),
        manifest_hash: "blake3-256:1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
    }
}

fn fixture_binary_object() -> ConnectorBinaryObject {
    ConnectorBinaryObject {
        target: ConnectorTarget {
            os: "linux".into(),
            arch: "amd64".into(),
        },
        binary_hash: "blake3-256:2222222222222222222222222222222222222222222222222222222222222222"
            .to_string(),
        binary: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Canonical schema IDs are stable strings
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signed_manifest_schema_is_stable() {
    let id = SignedManifest::<ConnectorManifestObject>::schema();
    assert_eq!(
        id,
        SchemaId::new("fcp.core", "SignedManifest", Version::new(1, 0, 0)),
        "SignedManifest envelope schema MUST be fcp.core:SignedManifest@1.0.0"
    );
    // The schema is independent of the payload type parameter.
    assert_eq!(
        SignedManifest::<ConnectorBinaryObject>::schema(),
        SchemaId::new("fcp.core", "SignedManifest", Version::new(1, 0, 0)),
        "envelope schema MUST be the same regardless of T"
    );
}

#[test]
fn package_payload_schemas_are_stable() {
    assert_eq!(
        ConnectorManifestObject::schema(),
        SchemaId::new("fcp.core", "ConnectorManifestObject", Version::new(1, 0, 0))
    );
    assert_eq!(
        ConnectorBinaryObject::schema(),
        SchemaId::new("fcp.core", "ConnectorBinaryObject", Version::new(1, 0, 0))
    );
    assert_eq!(
        ConnectorBinarySymbolSet::schema(),
        SchemaId::new(
            "fcp.core",
            "ConnectorBinarySymbolSet",
            Version::new(1, 0, 0)
        )
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Sign + verify round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signed_manifest_verifies_under_same_key() {
    let key = deterministic_key(0xAA);
    let envelope =
        SignedManifest::sign(ConnectorManifestObject::schema(), fixture_manifest(), &key)
            .expect("sign");
    envelope
        .verify(&key.verifying_key())
        .expect("verify under signing key");
    assert_eq!(envelope.signer_kid, key.key_id(), "signer_kid MUST match");
}

#[test]
fn signed_manifest_rejects_unrelated_key() {
    let signer = deterministic_key(0x01);
    let attacker = deterministic_key(0x02);
    let envelope = SignedManifest::sign(
        ConnectorManifestObject::schema(),
        fixture_manifest(),
        &signer,
    )
    .expect("sign");
    let err = envelope
        .verify(&attacker.verifying_key())
        .expect_err("MUST reject unrelated key");
    assert!(matches!(err, fcp_core::FcpError::InvalidSignature));
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Canonical payload bytes are deterministic
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn canonical_payload_bytes_are_deterministic_across_calls() {
    let key = deterministic_key(0x33);
    let envelope = SignedManifest::sign(
        ConnectorManifestObject::schema(),
        fixture_manifest(),
        &key,
    )
    .expect("sign");

    let bytes_a = envelope
        .canonical_payload_bytes()
        .expect("first canonical encode");
    let bytes_b = envelope
        .canonical_payload_bytes()
        .expect("second canonical encode");
    assert_eq!(
        bytes_a, bytes_b,
        "canonical_payload_bytes MUST be deterministic"
    );
    assert!(!bytes_a.is_empty(), "canonical bytes MUST be non-empty");
}

#[test]
fn canonical_payload_bytes_change_with_payload_content() {
    let key = deterministic_key(0x33);
    let env_a = SignedManifest::sign(
        ConnectorManifestObject::schema(),
        fixture_manifest(),
        &key,
    )
    .expect("sign a");

    let mut other = fixture_manifest();
    other.manifest_hash =
        "blake3-256:abcdef0000000000000000000000000000000000000000000000000000000000".to_string();
    let env_b = SignedManifest::sign(ConnectorManifestObject::schema(), other, &key).expect("sign b");

    assert_ne!(
        env_a.canonical_payload_bytes().unwrap(),
        env_b.canonical_payload_bytes().unwrap(),
        "different payloads MUST produce different canonical bytes"
    );
    assert_ne!(
        env_a.signature, env_b.signature,
        "different canonical bytes MUST produce different signatures"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. JSON round-trip preserves all envelope fields
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_roundtrip_preserves_envelope_fields_for_manifest_payload() {
    let key = deterministic_key(0x44);
    let original = SignedManifest::sign(
        ConnectorManifestObject::schema(),
        fixture_manifest(),
        &key,
    )
    .expect("sign");

    let json = serde_json::to_string(&original).expect("serialize");
    let back: SignedManifest<ConnectorManifestObject> =
        serde_json::from_str(&json).expect("deserialize");

    assert_eq!(back.payload_schema, original.payload_schema);
    assert_eq!(back.payload, original.payload);
    assert_eq!(back.signer_kid, original.signer_kid);
    assert_eq!(back.signature, original.signature);

    // After round-trip, signature still verifies.
    back.verify(&key.verifying_key())
        .expect("post-roundtrip signature MUST verify");
}

#[test]
fn json_roundtrip_preserves_envelope_fields_for_binary_payload() {
    let key = deterministic_key(0x55);
    let original = SignedManifest::sign(
        ConnectorBinaryObject::schema(),
        fixture_binary_object(),
        &key,
    )
    .expect("sign");

    let json = serde_json::to_string(&original).expect("serialize");
    let back: SignedManifest<ConnectorBinaryObject> =
        serde_json::from_str(&json).expect("deserialize");

    assert_eq!(back.payload_schema, original.payload_schema);
    assert_eq!(back.payload, original.payload);
    assert_eq!(back.signer_kid, original.signer_kid);
    assert_eq!(back.signature, original.signature);

    back.verify(&key.verifying_key())
        .expect("post-roundtrip signature MUST verify (binary payload)");
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. CBOR round-trip preserves all envelope fields
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_roundtrip_preserves_envelope_fields() {
    let key = deterministic_key(0x66);
    let original = SignedManifest::sign(
        ConnectorManifestObject::schema(),
        fixture_manifest(),
        &key,
    )
    .expect("sign");

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: SignedManifest<ConnectorManifestObject> =
        ciborium::de::from_reader(buf.as_slice()).expect("decode");

    assert_eq!(back.payload_schema, original.payload_schema);
    assert_eq!(back.payload, original.payload);
    assert_eq!(back.signer_kid, original.signer_kid);
    assert_eq!(back.signature, original.signature);

    back.verify(&key.verifying_key())
        .expect("post-CBOR-roundtrip signature MUST verify");
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. to_canonical_bytes / from_canonical_bytes round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn canonical_bytes_roundtrip_via_envelope_schema() {
    let key = deterministic_key(0x77);
    let original = SignedManifest::sign(
        ConnectorManifestObject::schema(),
        fixture_manifest(),
        &key,
    )
    .expect("sign");

    let bytes = original
        .to_canonical_bytes()
        .expect("encode canonical envelope");
    let back: SignedManifest<ConnectorManifestObject> =
        SignedManifest::from_canonical_bytes(&bytes).expect("decode canonical envelope");

    assert_eq!(back.payload, original.payload);
    assert_eq!(back.signer_kid, original.signer_kid);
    assert_eq!(back.signature, original.signature);
    back.verify(&key.verifying_key())
        .expect("post-canonical-roundtrip signature MUST verify");
}

#[test]
fn canonical_bytes_are_deterministic() {
    let key = deterministic_key(0x88);
    let envelope = SignedManifest::sign(
        ConnectorManifestObject::schema(),
        fixture_manifest(),
        &key,
    )
    .expect("sign");
    let a = envelope.to_canonical_bytes().expect("encode a");
    let b = envelope.to_canonical_bytes().expect("encode b");
    assert_eq!(
        a, b,
        "to_canonical_bytes MUST be deterministic across calls"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. ManifestSignature per-variant JSON form pinned
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn manifest_signature_per_variant_json_form_pinned() {
    // The default serde derive (no explicit #[serde(rename_all = ...)]) for
    // a unit-variant enum produces the variant name verbatim — pin the
    // exact wire tokens so registry tooling can dispatch on them.
    let cases = [
        (ManifestSignature::Ed25519, r#""Ed25519""#),
        (ManifestSignature::RsaPss, r#""RsaPss""#),
        (ManifestSignature::EcdsaP256, r#""EcdsaP256""#),
    ];
    for (variant, expected) in cases {
        let json = serde_json::to_string(&variant).expect("serialize");
        assert_eq!(json, expected, "ManifestSignature tag drift on {variant:?}");
        let back: ManifestSignature = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, variant);
    }
}

#[test]
fn manifest_signature_cbor_roundtrip_for_every_variant() {
    for variant in [
        ManifestSignature::Ed25519,
        ManifestSignature::RsaPss,
        ManifestSignature::EcdsaP256,
    ] {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&variant, &mut buf).expect("encode");
        let back: ManifestSignature =
            ciborium::de::from_reader(buf.as_slice()).expect("decode");
        assert_eq!(variant, back, "CBOR round-trip lost {variant:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. Tampering detection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn payload_tampering_after_roundtrip_fails_verification() {
    let key = deterministic_key(0x99);
    let original = SignedManifest::sign(
        ConnectorManifestObject::schema(),
        fixture_manifest(),
        &key,
    )
    .expect("sign");

    let json = serde_json::to_string(&original).expect("serialize");
    let mut tampered: SignedManifest<ConnectorManifestObject> =
        serde_json::from_str(&json).expect("deserialize");
    // Flip one byte in the payload — same schema, same signer_kid, same
    // signature, but now the canonical bytes don't match.
    tampered.payload.manifest_hash = "blake3-256:dead000000000000000000000000000000000000000000000000000000000000"
        .to_string();

    let err = tampered
        .verify(&key.verifying_key())
        .expect_err("tampered payload MUST fail verification");
    assert!(matches!(err, fcp_core::FcpError::InvalidSignature));
}

#[test]
fn signature_tampering_after_roundtrip_fails_verification() {
    let key = deterministic_key(0xAB);
    let original = SignedManifest::sign(
        ConnectorManifestObject::schema(),
        fixture_manifest(),
        &key,
    )
    .expect("sign");

    let mut tampered = original.clone();
    // Replace the signature with the all-zero signature — well-formed
    // shape, wrong cryptographic content.
    tampered.signature = fcp_crypto::ed25519::Ed25519Signature::from_bytes(&[0u8; 64]);

    let err = tampered
        .verify(&key.verifying_key())
        .expect_err("zeroed signature MUST fail verification");
    assert!(matches!(err, fcp_core::FcpError::InvalidSignature));
}

// ─────────────────────────────────────────────────────────────────────────────
// 9. ConnectorBinarySymbolSet round-trip (the third package artifact kind)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn connector_binary_symbol_set_serde_roundtrip() {
    // Pin that the third package-artifact kind also round-trips
    // through both JSON and CBOR — completing the trio of canonical
    // package artifacts the registry mirrors.
    let symbol_set = ConnectorBinarySymbolSet {
        manifest_object_id: ObjectId::from_bytes([0x11; 32]),
        binary_object_id: ObjectId::from_bytes([0x22; 32]),
        target: ConnectorTarget {
            os: "macos".into(),
            arch: "arm64".into(),
        },
        binary_hash: "blake3-256:3333333333333333333333333333333333333333333333333333333333333333"
            .to_string(),
        encoded_body_hash:
            "blake3-256:4444444444444444444444444444444444444444444444444444444444444444"
                .to_string(),
        oti: ConnectorBinaryTransmissionInfo::new(1024, 256, 4, 1, 1),
        source_symbols: 4,
        total_symbols: 6,
        mirrored_at: 1_700_000_000,
    };

    let json = serde_json::to_string(&symbol_set).expect("JSON serialize");
    let from_json: ConnectorBinarySymbolSet =
        serde_json::from_str(&json).expect("JSON deserialize");
    assert_eq!(from_json, symbol_set);

    let mut buf = Vec::new();
    ciborium::ser::into_writer(&symbol_set, &mut buf).expect("CBOR encode");
    let from_cbor: ConnectorBinarySymbolSet =
        ciborium::de::from_reader(buf.as_slice()).expect("CBOR decode");
    assert_eq!(from_cbor, symbol_set);
}
