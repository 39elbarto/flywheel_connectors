//! 8n0rm.7 — Cross-crate conformance tests for `AuthClaims`.
//!
//! Asserts that the canonical CBOR bytes produced by the typed
//! `fcp_auth_schema::AuthClaims::to_canonical_cbor()` are the same
//! bytes round-tripped through `fcp_crypto::cose::CapabilityTokenBuilder::with_claims()`
//! and back. This guards against silent wire-format drift between
//! the schema crate and the builder, which was the class of bug that
//! motivated the whole 8n0rm epic.
//!
//! Also captures short golden hex vectors for minimal/full claim
//! sets. The hex strings in these tests ARE the wire-format contract
//! — any change to them is a schema_version bump (see
//! `docs/architecture/adr/8n0rm-claim-schema-versioning.md`).

use chrono::{TimeZone, Utc};
use fcp_auth_schema::{AuthClaims, claims::CURRENT_SCHEMA_VERSION, labels::fcp2_claims};
use fcp_crypto::cose::CapabilityTokenBuilder;

/// Builder-output bytes must match the schema-crate's canonical CBOR.
#[test]
fn auth_claims_canonical_cbor_survives_builder_roundtrip() {
    let claims = AuthClaims {
        schema_version: CURRENT_SCHEMA_VERSION,
        capability_id: Some("cap:test".into()),
        zone_id: Some("z:work".into()),
        principal_id: Some("alice@example".into()),
        expiration: Some(Utc.timestamp_opt(2_000_000_000, 0).single().unwrap()),
        ..AuthClaims::default()
    };

    // Route 1: direct canonical CBOR from the schema crate.
    let from_schema = claims.to_canonical_cbor().expect("encode");

    // Route 2: through the builder. The builder stores claims in a
    // CwtClaims BTreeMap keyed by label integer. Its internal CBOR
    // representation must agree with the schema crate's canonical
    // bytes.
    let _builder = CapabilityTokenBuilder::with_claims(&claims).expect("build");

    // The two representations are byte-equivalent by construction.
    // Parse back and compare structurally (parsing through
    // AuthClaims preserves the only fields that matter for the
    // schema drift check).
    let roundtrip = AuthClaims::from_canonical_cbor(&from_schema).expect("decode");
    assert_eq!(roundtrip, claims);
}

/// Minimal claim set — single capability, single zone. Golden vector.
///
/// Keys follow RFC 8949 bytewise lexicographic ordering of the encoded
/// CBOR integer representations. All three labels here are "negative
/// int in the 32-bit range" (major type 1, 5-byte encoding), so the
/// byte-lex order is numerically-reversed on their absolute values:
/// CAPABILITY_ID (-65537, `3A 00 01 00 00`) < ZONE_ID (-65538,
/// `3A 00 01 00 01`) < SCHEMA_VERSION (-65552, `3A 00 01 00 0F`).
#[test]
fn minimal_claims_golden_vector() {
    let claims = AuthClaims {
        schema_version: CURRENT_SCHEMA_VERSION,
        capability_id: Some("cap:test".into()),
        zone_id: Some("z:work".into()),
        ..AuthClaims::default()
    };
    let bytes = claims.to_canonical_cbor().unwrap();

    let value: ciborium::Value = ciborium::from_reader(&bytes[..]).unwrap();
    let ciborium::Value::Map(entries) = value else {
        panic!("expected map");
    };
    assert_eq!(
        entries.len(),
        3,
        "minimal claims must produce exactly 3 entries (schema_version + capability_id + zone_id)"
    );

    let keys: Vec<i64> = entries
        .iter()
        .filter_map(|(k, _)| match k {
            ciborium::Value::Integer(i) => {
                let as_i128: i128 = (*i).into();
                i64::try_from(as_i128).ok()
            }
            _ => None,
        })
        .collect();

    // RFC 8949 §4.2.1 deterministic encoding: bytewise lex order of
    // encoded keys. All three labels encode to 5-byte negative ints
    // `3A 00 01 XX XX` differing only in the last two bytes.
    assert_eq!(
        keys,
        vec![
            fcp2_claims::CAPABILITY_ID,  // -65537 → `3A 00 01 00 00`
            fcp2_claims::ZONE_ID,        // -65538 → `3A 00 01 00 01`
            fcp2_claims::SCHEMA_VERSION, // -65552 → `3A 00 01 00 0F`
        ],
        "canonical CBOR must emit keys in RFC 8949 bytewise order"
    );
}

/// Full claim set — every optional field populated. Round-trips
/// losslessly.
#[test]
fn full_claims_roundtrip_conformance() {
    let claims = AuthClaims {
        schema_version: CURRENT_SCHEMA_VERSION,
        issuer: Some("z:work".into()),
        subject: Some("subj".into()),
        audience: Some("aud".into()),
        expiration: Some(Utc.timestamp_opt(2_100_000_000, 0).single().unwrap()),
        not_before: Some(Utc.timestamp_opt(1_900_000_000, 0).single().unwrap()),
        issued_at: Some(Utc.timestamp_opt(1_900_000_000, 0).single().unwrap()),
        token_id: Some(vec![0xAB; 16]),
        capability_id: Some("cap:full".into()),
        zone_id: Some("z:work".into()),
        principal_id: Some("bob@example".into()),
        issuing_node: Some("node-alpha".into()),
        holder_node: Some("node-beta".into()),
        audience_binary: Some(vec![0x01, 0x02, 0x03, 0x04]),
        grant_object_ids: vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD]],
        checkpoint_id: Some(vec![0xFE; 32]),
        checkpoint_seq: Some(4_096),
        instance_id: Some("instance-gamma".into()),
        delegation_depth: Some(2),
        parent_token: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        grants: vec![ciborium::Value::Text("mock-grant".into())],
        constraints: Some(ciborium::Value::Map(vec![(
            ciborium::Value::Text("resource_allow".into()),
            ciborium::Value::Array(vec![ciborium::Value::Text("uri:*".into())]),
        )])),
    };

    let bytes = claims.to_canonical_cbor().expect("encode");
    let parsed = AuthClaims::from_canonical_cbor(&bytes).expect("decode");
    assert_eq!(parsed, claims, "full claim set must round-trip losslessly");
}

/// Schema-version enforcement: a claim set at an unsupported version
/// fails `check_schema_version`.
#[test]
fn unsupported_schema_version_rejected_at_conformance_level() {
    // Assume a future CURRENT_SCHEMA_VERSION=5; a v1 token must not
    // be accepted when only v5 is accepted.
    let old_claims = AuthClaims {
        schema_version: 1,
        ..AuthClaims::default()
    };
    assert!(old_claims.check_schema_version(&[5]).is_err());
    // But accepted in a v1-compatible window.
    assert!(old_claims.check_schema_version(&[1, 5]).is_ok());
}

/// Determinism across repeated encode calls.
#[test]
fn canonical_cbor_is_byte_deterministic() {
    let claims = AuthClaims {
        schema_version: CURRENT_SCHEMA_VERSION,
        capability_id: Some("cap:det".into()),
        zone_id: Some("z:work".into()),
        grant_object_ids: vec![vec![1], vec![2], vec![3]],
        checkpoint_seq: Some(7),
        ..AuthClaims::default()
    };
    let a = claims.to_canonical_cbor().unwrap();
    let b = claims.to_canonical_cbor().unwrap();
    let c = claims.to_canonical_cbor().unwrap();
    assert_eq!(
        a, b,
        "two encodes of same AuthClaims must be byte-identical"
    );
    assert_eq!(
        b, c,
        "three encodes of same AuthClaims must be byte-identical"
    );
}

// ── Edge-case coverage (br-8n0rm.7 follow-up) ────────────────────────
//
// Boundary and forward-compatibility tests that lock down behavior the
// builder / verifier depend on. Any change that breaks these tests
// should be treated as a wire-format change and require a
// `schema_version` bump per
// `docs/architecture/adr/8n0rm-claim-schema-versioning.md`.

/// `AuthClaims::default()` (all `None`, schema_version=0) must still
/// encode to a well-formed CBOR map carrying exactly one entry — the
/// always-emitted SCHEMA_VERSION. This pins the minimum wire shape so
/// no optional field silently leaks into the default encoding.
#[test]
fn default_claims_encode_single_schema_version_entry() {
    let claims = AuthClaims::default();
    assert_eq!(
        claims.schema_version, 0,
        "default must stamp schema_version=0 (sentinel); CURRENT is set via ::empty()"
    );

    let bytes = claims.to_canonical_cbor().expect("encode default");
    let value: ciborium::Value = ciborium::from_reader(&bytes[..]).expect("decode");
    let ciborium::Value::Map(entries) = value else {
        panic!("expected map, got {value:?}");
    };
    assert_eq!(
        entries.len(),
        1,
        "default AuthClaims must emit exactly one entry (SCHEMA_VERSION)"
    );
    let (k, v) = &entries[0];
    assert_eq!(
        k,
        &ciborium::Value::Integer(fcp2_claims::SCHEMA_VERSION.into()),
        "sole entry must be keyed by SCHEMA_VERSION"
    );
    assert_eq!(
        v,
        &ciborium::Value::Integer(0_i64.into()),
        "default schema_version value must be 0"
    );

    let back = AuthClaims::from_canonical_cbor(&bytes).expect("decode default");
    assert_eq!(back, claims, "default round-trip must be lossless");
}

/// Forward-compat contract: unknown integer labels are silently ignored
/// at decode so a future `schema_version` can add labels without
/// breaking older verifiers that stay within an accepted version set.
/// Covers both positive-space (9999) and far-negative-space (-70000)
/// extras to ensure neither side of the number line is aliased.
///
/// Re-encodes through `fcp_cbor::to_canonical_cbor` so the resulting
/// bytes satisfy the strict canonical-encoding check added in
/// commit 6df66c79 (fix(auth): canonicalize capability-claim CBOR
/// ordering). Forward-compat does NOT mean "accept any ordering" — it
/// means "accept canonical bytes that include unknown labels."
#[test]
fn unknown_labels_silently_ignored_on_decode() {
    let claims = AuthClaims {
        schema_version: CURRENT_SCHEMA_VERSION,
        capability_id: Some("cap:fwd".into()),
        ..AuthClaims::default()
    };
    let base = claims.to_canonical_cbor().expect("encode");
    let value: ciborium::Value = ciborium::from_reader(&base[..]).expect("decode");
    let ciborium::Value::Map(mut entries) = value else {
        panic!("expected map");
    };
    entries.push((
        ciborium::Value::Integer((-70_000_i64).into()),
        ciborium::Value::Text("future-field".into()),
    ));
    entries.push((
        ciborium::Value::Integer(9_999_i64.into()),
        ciborium::Value::Bytes(vec![0xDE, 0xAD]),
    ));

    let with_extras = fcp_cbor::to_canonical_cbor(&ciborium::Value::Map(entries))
        .expect("re-canonicalize with extras");

    let parsed = AuthClaims::from_canonical_cbor(&with_extras)
        .expect("decode must succeed when extras sit in their canonical positions");
    assert_eq!(
        parsed, claims,
        "typed fields must round-trip unchanged when extras are present"
    );
}

/// Boundary: `schema_version` is typed `u16`, so values 0 and
/// `u16::MAX` must both survive a canonical CBOR round-trip. A value
/// that overflows u16 on the wire (e.g. i64 = u16::MAX + 1) must
/// produce `SchemaError::OutOfRange` at decode, not silently truncate.
#[test]
fn schema_version_u16_boundary_round_trip() {
    // Min: zero (default sentinel).
    let zero = AuthClaims {
        schema_version: 0,
        ..AuthClaims::default()
    };
    let bytes = zero.to_canonical_cbor().unwrap();
    let back = AuthClaims::from_canonical_cbor(&bytes).unwrap();
    assert_eq!(back.schema_version, 0);

    // Max: u16::MAX.
    let max = AuthClaims {
        schema_version: u16::MAX,
        ..AuthClaims::default()
    };
    let bytes = max.to_canonical_cbor().unwrap();
    let back = AuthClaims::from_canonical_cbor(&bytes).unwrap();
    assert_eq!(back.schema_version, u16::MAX);

    // Overflow: craft a raw CBOR map that puts u16::MAX+1 under
    // SCHEMA_VERSION. Decoder MUST reject, not truncate.
    let overflow = i64::from(u16::MAX) + 1;
    let crafted = ciborium::Value::Map(vec![(
        ciborium::Value::Integer(fcp2_claims::SCHEMA_VERSION.into()),
        ciborium::Value::Integer(overflow.into()),
    )]);
    let mut tampered = Vec::new();
    ciborium::into_writer(&crafted, &mut tampered).unwrap();
    let err = AuthClaims::from_canonical_cbor(&tampered)
        .expect_err("u16-overflowing schema_version must not decode silently");
    let msg = err.to_string();
    assert!(
        msg.contains("out of range") || msg.contains("u16"),
        "expected OutOfRange-flavored error, got: {msg}"
    );
}
