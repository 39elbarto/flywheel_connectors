//! Expanded golden vector tests for fcp-crypto.
//!
//! Covers:
//! - COSE_Sign1 capability token signing + verification with deterministic Ed25519 keys
//! - HPKE AAD encoding determinism and purpose string validation
//! - Canonical signing-bytes construction and schema hash stability

use fcp_crypto::canonicalize::{
    canonical_signing_bytes, schema_hash, to_deterministic_cbor, SCHEMA_HASH_SIZE, SIGNING_DOMAIN,
};
use fcp_crypto::cose::{CoseToken, CwtClaims, COSE_ALG_EDDSA};
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_crypto::hpke_seal::{
    hpke_open, hpke_seal, Fcp2Aad, HpkeSealedBox, HPKE_ENC_SIZE, HPKE_TAG_SIZE,
};
use fcp_crypto::x25519::X25519SecretKey;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;

// ─────────────────────────────────────────────────────────────────────────────
// Vector File Structures
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SigningBytesVectors {
    constants: SigningConstants,
    schema_hash_vectors: Vec<SchemaHashVector>,
    schema_hash_properties: Vec<SchemaHashProperty>,
    signing_bytes_vectors: Vec<SigningBytesVector>,
}

#[derive(Debug, Deserialize)]
struct SigningConstants {
    signing_domain_ascii: String,
    signing_domain_hex: String,
    schema_hash_size: usize,
    signing_domain_size: usize,
}

#[derive(Debug, Deserialize)]
struct SchemaHashVector {
    name: String,
    schema_id: String,
    expected_hash_hex: String,
}

#[derive(Debug, Deserialize)]
struct SchemaHashProperty {
    name: String,
    schema_id_a: String,
    schema_id_b: String,
    expected: String,
}

#[derive(Debug, Deserialize)]
struct SigningBytesVector {
    name: String,
    schema_id: String,
    cbor_hex: String,
    expected_signing_bytes_hex: String,
}

#[derive(Debug, Deserialize)]
struct HpkeVectors {
    size_invariants: SizeInvariants,
    purpose_strings: Vec<PurposeString>,
    aad_encoding_vectors: Vec<AadVector>,
    roundtrip_test_cases: Vec<RoundtripCase>,
}

#[derive(Debug, Deserialize)]
struct SizeInvariants {
    enc_size: usize,
    tag_size: usize,
    ciphertext_overhead: usize,
}

#[derive(Debug, Deserialize)]
struct PurposeString {
    name: String,
    ascii: String,
    hex: String,
}

#[derive(Debug, Deserialize)]
struct AadVector {
    name: String,
    zone_id_hex: String,
    recipient_node_id_hex: String,
    purpose: String,
    issued_at: u64,
    expected_aad_hex: String,
}

#[derive(Debug, Deserialize)]
struct RoundtripCase {
    name: String,
    plaintext_hex: String,
    expected_ciphertext_len: usize,
}

#[derive(Debug, Deserialize)]
struct CoseCapabilityVectors {
    signing_key: SigningKeyInfo,
    token_vectors: Vec<TokenVector>,
}

#[derive(Debug, Deserialize)]
struct SigningKeyInfo {
    secret_key_hex: String,
    #[allow(dead_code)]
    public_key_hex: String,
    key_id_hex: String,
}

#[derive(Debug, Deserialize)]
struct TokenVector {
    name: String,
    claims_cbor_hex: String,
    token_cbor_hex: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    if hex.is_empty() {
        return Vec::new();
    }
    hex::decode(hex).unwrap_or_else(|e| panic!("invalid hex '{hex}': {e}"))
}

fn load_signing_bytes_vectors() -> SigningBytesVectors {
    let content =
        fs::read_to_string("tests/vectors/canonicalize/signing_bytes_vectors.json")
            .expect("Failed to read signing_bytes_vectors.json");
    serde_json::from_str(&content).expect("Failed to parse signing_bytes_vectors.json")
}

fn load_hpke_vectors() -> HpkeVectors {
    let content = fs::read_to_string("tests/vectors/hpke/hpke_vectors.json")
        .expect("Failed to read hpke_vectors.json");
    serde_json::from_str(&content).expect("Failed to parse hpke_vectors.json")
}

fn load_cose_capability_vectors() -> CoseCapabilityVectors {
    let content = fs::read_to_string("tests/vectors/cose/cose_capability_token_vectors.json")
        .expect("Failed to read cose_capability_token_vectors.json");
    serde_json::from_str(&content).expect("Failed to parse cose_capability_token_vectors.json")
}

fn signing_key_from_rfc8032_tv1() -> Ed25519SigningKey {
    let bytes = hex_to_bytes(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    );
    let arr: [u8; 32] = bytes.try_into().expect("key must be 32 bytes");
    Ed25519SigningKey::from_bytes(&arr).expect("valid RFC 8032 TV1 key")
}

// ─────────────────────────────────────────────────────────────────────────────
// Signing Bytes / Schema Hash Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_signing_domain_constant() {
    let vectors = load_signing_bytes_vectors();
    assert_eq!(
        vectors.constants.signing_domain_ascii, "FCP2-SIGN-V1",
        "signing domain string"
    );
    assert_eq!(
        hex::encode(SIGNING_DOMAIN),
        vectors.constants.signing_domain_hex,
        "signing domain hex"
    );
    assert_eq!(
        vectors.constants.schema_hash_size, SCHEMA_HASH_SIZE,
        "schema hash size"
    );
    assert_eq!(
        vectors.constants.signing_domain_size,
        SIGNING_DOMAIN.len(),
        "signing domain size"
    );
}

#[test]
fn test_schema_hashes_from_vectors() {
    let vectors = load_signing_bytes_vectors();

    for v in &vectors.schema_hash_vectors {
        let hash = schema_hash(&v.schema_id);
        let hash_hex = hex::encode(hash);

        if v.expected_hash_hex == "__GENERATE__" {
            // Print for vector file population
            eprintln!(
                "GENERATE schema_hash(\"{}\"): \"{}\"",
                v.schema_id, hash_hex
            );
        } else {
            assert_eq!(
                hash_hex, v.expected_hash_hex,
                "schema_hash mismatch for '{}' ({})",
                v.name, v.schema_id
            );
        }

        // Verify determinism: running again gives same result
        let hash2 = schema_hash(&v.schema_id);
        assert_eq!(hash, hash2, "schema_hash not deterministic for {}", v.name);
    }
}

#[test]
fn test_schema_hash_sensitivity_properties() {
    let vectors = load_signing_bytes_vectors();

    for prop in &vectors.schema_hash_properties {
        let hash_a = schema_hash(&prop.schema_id_a);
        let hash_b = schema_hash(&prop.schema_id_b);

        match prop.expected.as_str() {
            "different_hashes" => {
                assert_ne!(
                    hash_a, hash_b,
                    "property '{}': hashes should differ for '{}' vs '{}'",
                    prop.name, prop.schema_id_a, prop.schema_id_b
                );
            }
            _ => panic!("unknown expected value: {}", prop.expected),
        }
    }
}

#[test]
fn test_signing_bytes_construction() {
    let vectors = load_signing_bytes_vectors();

    for v in &vectors.signing_bytes_vectors {
        let cbor = hex_to_bytes(&v.cbor_hex);
        let signing_bytes = canonical_signing_bytes(&v.schema_id, &cbor);
        let signing_bytes_hex = hex::encode(&signing_bytes);

        if v.expected_signing_bytes_hex == "__GENERATE__" {
            eprintln!(
                "GENERATE signing_bytes(\"{}\", \"{}\"): \"{}\"",
                v.schema_id, v.cbor_hex, signing_bytes_hex
            );
        } else {
            assert_eq!(
                signing_bytes_hex, v.expected_signing_bytes_hex,
                "signing_bytes mismatch for '{}'",
                v.name
            );
        }

        // Structural validation
        assert!(
            signing_bytes.starts_with(SIGNING_DOMAIN),
            "signing bytes must start with domain prefix for '{}'",
            v.name
        );
        assert_eq!(
            signing_bytes.len(),
            SIGNING_DOMAIN.len() + SCHEMA_HASH_SIZE + cbor.len(),
            "signing bytes length for '{}'",
            v.name
        );
        assert!(
            signing_bytes.ends_with(&cbor),
            "signing bytes must end with CBOR payload for '{}'",
            v.name
        );
    }
}

#[test]
fn test_schema_hash_deterministic_100_iterations() {
    let schema_ids = [
        "fcp.core.CapabilityObject/1.0.0",
        "fcp.core.OperationIntent/1.0.0",
        "fcp.zone.ZoneKeyManifest/1.0.0",
    ];

    for schema_id in &schema_ids {
        let reference = schema_hash(schema_id);
        for i in 0..100 {
            let hash = schema_hash(schema_id);
            assert_eq!(
                hash, reference,
                "schema_hash({schema_id}) differed on iteration {i}"
            );
        }
    }
}

#[test]
fn test_deterministic_cbor_map_key_ordering() {
    // Maps with same entries inserted in different order must produce identical CBOR
    let mut map1 = BTreeMap::new();
    map1.insert("zone_id", "z:work");
    map1.insert("action", "read");
    map1.insert("node_id", "node-123");

    let mut map2 = BTreeMap::new();
    map2.insert("action", "read");
    map2.insert("node_id", "node-123");
    map2.insert("zone_id", "z:work");

    let cbor1 = to_deterministic_cbor(&map1).unwrap();
    let cbor2 = to_deterministic_cbor(&map2).unwrap();

    assert_eq!(cbor1, cbor2, "CBOR encoding must be insertion-order independent");

    // CBOR must start with map marker
    assert_eq!(cbor1[0] & 0xe0, 0xa0, "must be a CBOR map (major type 5)");
}

// ─────────────────────────────────────────────────────────────────────────────
// HPKE Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_hpke_size_invariants() {
    let vectors = load_hpke_vectors();

    assert_eq!(vectors.size_invariants.enc_size, HPKE_ENC_SIZE);
    assert_eq!(vectors.size_invariants.tag_size, HPKE_TAG_SIZE);
    assert_eq!(vectors.size_invariants.ciphertext_overhead, HPKE_TAG_SIZE);
}

#[test]
fn test_hpke_purpose_strings() {
    let vectors = load_hpke_vectors();
    use fcp_crypto::hpke_seal::purpose;

    for ps in &vectors.purpose_strings {
        let actual_bytes = match ps.name.as_str() {
            "ZONE_KEY" => purpose::ZONE_KEY,
            "OBJECTID_KEY" => purpose::OBJECTID_KEY,
            "OWNER_SHARE" => purpose::OWNER_SHARE,
            "SECRET_SHARE" => purpose::SECRET_SHARE,
            other => panic!("unknown purpose: {other}"),
        };

        assert_eq!(
            std::str::from_utf8(actual_bytes).unwrap(),
            ps.ascii,
            "purpose ASCII for {}",
            ps.name
        );
        assert_eq!(
            hex::encode(actual_bytes),
            ps.hex,
            "purpose hex for {}",
            ps.name
        );
    }
}

#[test]
fn test_hpke_aad_encoding_determinism() {
    let vectors = load_hpke_vectors();

    for v in &vectors.aad_encoding_vectors {
        let zone_id = hex_to_bytes(&v.zone_id_hex);
        let node_id = hex_to_bytes(&v.recipient_node_id_hex);
        let purpose_bytes = v.purpose.as_bytes();

        let aad = Fcp2Aad {
            zone_id: zone_id.clone(),
            recipient_node_id: node_id.clone(),
            purpose: purpose_bytes.to_vec(),
            issued_at: v.issued_at,
        };

        let encoded = aad.encode();
        let encoded_hex = hex::encode(&encoded);

        if v.expected_aad_hex == "__GENERATE__" {
            eprintln!("GENERATE aad(\"{}\") = \"{}\"", v.name, encoded_hex);
        } else {
            assert_eq!(
                encoded_hex, v.expected_aad_hex,
                "AAD encoding mismatch for '{}'",
                v.name
            );
        }

        // Structural: must be a CBOR map with 4 entries
        assert_eq!(encoded[0], 0xA4, "AAD must be CBOR map(4) for '{}'", v.name);

        // Determinism: encode twice → same bytes
        let encoded2 = aad.encode();
        assert_eq!(
            encoded, encoded2,
            "AAD encoding not deterministic for '{}'",
            v.name
        );
    }
}

#[test]
fn test_hpke_different_purposes_different_aad() {
    let zone_id = b"z:work";
    let node_id = b"node-123";
    let ts: u64 = 1_700_000_000;

    let aad_zone = Fcp2Aad::for_zone_key(zone_id, node_id, ts).encode();
    let aad_obj = Fcp2Aad::for_objectid_key(zone_id, node_id, ts).encode();
    let aad_share = Fcp2Aad::for_secret_share(zone_id, node_id, ts).encode();

    assert_ne!(aad_zone, aad_obj, "ZONE_KEY vs OBJECTID_KEY AAD must differ");
    assert_ne!(aad_zone, aad_share, "ZONE_KEY vs SECRET_SHARE AAD must differ");
    assert_ne!(aad_obj, aad_share, "OBJECTID_KEY vs SECRET_SHARE AAD must differ");
}

#[test]
fn test_hpke_roundtrip_from_vectors() {
    let vectors = load_hpke_vectors();

    let sk = X25519SecretKey::generate();
    let pk = sk.public_key();
    let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-test", 1_700_000_000);

    for tc in &vectors.roundtrip_test_cases {
        let plaintext = hex_to_bytes(&tc.plaintext_hex);

        let sealed = hpke_seal(&pk, &plaintext, &aad).unwrap();

        // Verify size invariants
        assert_eq!(
            sealed.enc.len(),
            HPKE_ENC_SIZE,
            "enc size for '{}'",
            tc.name
        );
        assert_eq!(
            sealed.ciphertext.len(),
            tc.expected_ciphertext_len,
            "ciphertext len for '{}' (plaintext {} + tag {})",
            tc.name,
            plaintext.len(),
            HPKE_TAG_SIZE
        );

        // Verify roundtrip
        let opened = hpke_open(&sk, &sealed, &aad).unwrap();
        assert_eq!(
            opened, plaintext,
            "roundtrip mismatch for '{}'",
            tc.name
        );
    }
}

#[test]
fn test_hpke_sealed_box_byte_encoding() {
    let sk = X25519SecretKey::generate();
    let pk = sk.public_key();
    let aad = Fcp2Aad::for_zone_key(b"z:work", b"node-test", 1_700_000_000);

    let sealed = hpke_seal(&pk, b"test-payload", &aad).unwrap();
    let bytes = sealed.to_bytes();

    // First 32 bytes are enc, rest is ciphertext
    assert_eq!(&bytes[..HPKE_ENC_SIZE], sealed.enc.as_slice());
    assert_eq!(&bytes[HPKE_ENC_SIZE..], sealed.ciphertext.as_slice());
    assert_eq!(bytes.len(), HPKE_ENC_SIZE + sealed.ciphertext.len());

    // Round-trip through from_bytes
    let parsed = HpkeSealedBox::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.enc, sealed.enc);
    assert_eq!(parsed.ciphertext, sealed.ciphertext);
}

#[test]
fn test_hpke_aad_binding_enforced() {
    let sk = X25519SecretKey::generate();
    let pk = sk.public_key();

    let aad_correct = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_700_000_000);
    let sealed = hpke_seal(&pk, b"secret", &aad_correct).unwrap();

    // Wrong zone_id
    let aad_bad_zone = Fcp2Aad::for_zone_key(b"z:private", b"node-123", 1_700_000_000);
    assert!(hpke_open(&sk, &sealed, &aad_bad_zone).is_err(), "wrong zone_id must fail");

    // Wrong node_id
    let aad_bad_node = Fcp2Aad::for_zone_key(b"z:work", b"node-456", 1_700_000_000);
    assert!(hpke_open(&sk, &sealed, &aad_bad_node).is_err(), "wrong node_id must fail");

    // Wrong purpose
    let aad_bad_purpose = Fcp2Aad::for_objectid_key(b"z:work", b"node-123", 1_700_000_000);
    assert!(hpke_open(&sk, &sealed, &aad_bad_purpose).is_err(), "wrong purpose must fail");

    // Wrong timestamp
    let aad_bad_ts = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_700_000_001);
    assert!(hpke_open(&sk, &sealed, &aad_bad_ts).is_err(), "wrong timestamp must fail");
}

// ─────────────────────────────────────────────────────────────────────────────
// COSE_Sign1 Capability Token Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cose_token_deterministic_with_rfc8032_key() {
    let sk = signing_key_from_rfc8032_tv1();
    let pk = sk.verifying_key();

    // Minimal claims
    let claims = CwtClaims::new()
        .issuer("node:primary")
        .zone_id("z:work")
        .capability_id("cap:test.read");

    // Sign twice: must produce identical CBOR
    let token1 = CoseToken::sign(&sk, &claims).unwrap();
    let token2 = CoseToken::sign(&sk, &claims).unwrap();

    let cbor1 = token1.to_cbor().unwrap();
    let cbor2 = token2.to_cbor().unwrap();

    assert_eq!(cbor1, cbor2, "COSE_Sign1 tokens must be deterministic");

    // Print for vector file population
    let claims_cbor = claims.to_cbor().unwrap();
    eprintln!(
        "COSE minimal: claims_cbor_hex = \"{}\"",
        hex::encode(&claims_cbor)
    );
    eprintln!(
        "COSE minimal: token_cbor_hex = \"{}\"",
        hex::encode(&cbor1)
    );
    eprintln!("COSE minimal: token_cbor_len = {}", cbor1.len());

    // Verify roundtrip
    let parsed = CoseToken::from_cbor(&cbor1).unwrap();
    let verified = parsed.verify(&pk).unwrap();
    assert_eq!(verified.get_issuer(), Some("node:primary"));
    assert_eq!(verified.get_zone_id(), Some("z:work"));
    assert_eq!(verified.get_capability_id(), Some("cap:test.read"));
}

#[test]
fn test_cose_token_full_fcp2_claims() {
    let sk = signing_key_from_rfc8032_tv1();
    let pk = sk.verifying_key();

    let claims = CwtClaims::new()
        .issuer("node:primary")
        .subject("agent:claude")
        .audience("node:target")
        .token_id(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        .zone_id("z:work")
        .capability_id("cap:discord.send")
        .principal_id("agent:claude")
        .operations(&["discord.send_message", "discord.read_messages"])
        .issuing_node("node:primary")
        .holder_node("node:mobile");

    let token = CoseToken::sign(&sk, &claims).unwrap();
    let token_cbor = token.to_cbor().unwrap();

    // Print for vector file population
    let claims_cbor = claims.to_cbor().unwrap();
    eprintln!(
        "COSE full: claims_cbor_hex = \"{}\"",
        hex::encode(&claims_cbor)
    );
    eprintln!(
        "COSE full: token_cbor_hex = \"{}\"",
        hex::encode(&token_cbor)
    );
    eprintln!("COSE full: token_cbor_len = {}", token_cbor.len());

    // Verify all claims
    let verified = token.verify(&pk).unwrap();
    assert_eq!(verified.get_issuer(), Some("node:primary"));
    assert_eq!(verified.get_subject(), Some("agent:claude"));
    assert_eq!(verified.get_capability_id(), Some("cap:discord.send"));
    assert_eq!(verified.get_zone_id(), Some("z:work"));
    assert_eq!(verified.get_holder_node(), Some("node:mobile"));

    // Determinism check
    let token2 = CoseToken::sign(&sk, &claims).unwrap();
    assert_eq!(
        token.to_cbor().unwrap(),
        token2.to_cbor().unwrap(),
        "full token must be deterministic"
    );
}

#[test]
fn test_cose_token_kid_matches_key_id() {
    let sk = signing_key_from_rfc8032_tv1();
    let expected_kid = sk.key_id();

    let claims = CwtClaims::new().issuer("test");
    let token = CoseToken::sign(&sk, &claims).unwrap();

    let kid_bytes = token.get_key_id().unwrap();
    assert_eq!(kid_bytes.len(), 8, "KID must be 8 bytes");
    assert_eq!(
        kid_bytes,
        expected_kid.as_bytes(),
        "KID in protected header must match computed KeyId"
    );

    eprintln!("KID hex = \"{}\"", hex::encode(&kid_bytes));
}

#[test]
fn test_cose_token_wrong_key_verification_fails() {
    let sk1 = signing_key_from_rfc8032_tv1();
    let sk2 = Ed25519SigningKey::generate();
    let pk2 = sk2.verifying_key();

    let claims = CwtClaims::new()
        .issuer("node:primary")
        .capability_id("cap:test");

    let token = CoseToken::sign(&sk1, &claims).unwrap();
    assert!(
        token.verify(&pk2).is_err(),
        "verification with wrong key must fail"
    );
}

#[test]
fn test_cose_token_cbor_roundtrip_preserves_bytes() {
    let sk = signing_key_from_rfc8032_tv1();

    let claims = CwtClaims::new()
        .issuer("node:primary")
        .zone_id("z:work")
        .capability_id("cap:test.read")
        .principal_id("agent:test")
        .operations(&["read", "list"]);

    let token = CoseToken::sign(&sk, &claims).unwrap();
    let cbor = token.to_cbor().unwrap();

    // Deserialize and re-serialize must preserve exact bytes
    let parsed = CoseToken::from_cbor(&cbor).unwrap();
    let cbor2 = parsed.to_cbor().unwrap();

    assert_eq!(cbor, cbor2, "CBOR roundtrip must preserve exact bytes");
}

#[test]
fn test_cwt_claims_deterministic_insertion_order() {
    // Claims inserted in different orders must produce same CBOR
    let claims_a = CwtClaims::new()
        .issuer("test")
        .zone_id("z:work")
        .capability_id("cap:test");

    let claims_b = CwtClaims::new()
        .capability_id("cap:test")
        .issuer("test")
        .zone_id("z:work");

    let cbor_a = claims_a.to_cbor().unwrap();
    let cbor_b = claims_b.to_cbor().unwrap();

    assert_eq!(
        cbor_a, cbor_b,
        "CWT claims CBOR must be insertion-order independent"
    );
}

#[test]
fn test_cose_algorithm_is_eddsa() {
    assert_eq!(COSE_ALG_EDDSA, -8, "COSE EdDSA algorithm ID must be -8");
}

#[test]
fn test_cose_token_vectors_from_file() {
    let vectors = load_cose_capability_vectors();
    let sk_bytes = hex_to_bytes(&vectors.signing_key.secret_key_hex);
    let sk_arr: [u8; 32] = sk_bytes.try_into().expect("key must be 32 bytes");
    let sk = Ed25519SigningKey::from_bytes(&sk_arr).expect("valid key");
    let pk = sk.verifying_key();

    // Verify key_id matches
    let expected_kid = hex_to_bytes(&vectors.signing_key.key_id_hex);
    assert_eq!(
        sk.key_id().as_bytes(),
        expected_kid.as_slice(),
        "KID mismatch from vector file"
    );

    // Verify each token vector
    for tv in &vectors.token_vectors {
        let token_bytes = hex_to_bytes(&tv.token_cbor_hex);
        let parsed = CoseToken::from_cbor(&token_bytes)
            .unwrap_or_else(|e| panic!("failed to parse token '{}': {e}", tv.name));

        // Must verify with the expected public key
        let claims = parsed
            .verify(&pk)
            .unwrap_or_else(|e| panic!("failed to verify token '{}': {e}", tv.name));

        // Verify claims CBOR matches
        let claims_cbor = claims.to_cbor().unwrap();
        assert_eq!(
            hex::encode(&claims_cbor),
            tv.claims_cbor_hex,
            "claims CBOR mismatch for '{}'",
            tv.name
        );

        // Re-sign should produce identical token
        let re_signed = CoseToken::sign(&sk, &claims).unwrap();
        let re_signed_cbor = re_signed.to_cbor().unwrap();
        assert_eq!(
            hex::encode(&re_signed_cbor),
            tv.token_cbor_hex,
            "re-signed token CBOR mismatch for '{}' (not deterministic)",
            tv.name
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Combined Integration: Signing Bytes + COSE Token
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_signing_bytes_used_by_cose_are_consistent() {
    let sk = signing_key_from_rfc8032_tv1();
    let pk = sk.verifying_key();

    let claims = CwtClaims::new()
        .issuer("test")
        .capability_id("cap:test");

    // The token's TBS (to-be-signed) uses Sig_structure per COSE, not our signing_bytes.
    // But we can verify that our canonical_signing_bytes function produces a
    // consistent, reproducible output for the same CBOR claims payload.
    let claims_cbor = claims.to_cbor().unwrap();
    let schema_id = "fcp.core.CapabilityObject/1.0.0";
    let signing_bytes_1 = canonical_signing_bytes(schema_id, &claims_cbor);
    let signing_bytes_2 = canonical_signing_bytes(schema_id, &claims_cbor);

    assert_eq!(
        signing_bytes_1, signing_bytes_2,
        "canonical signing bytes must be deterministic"
    );

    // Also verify the token itself works
    let token = CoseToken::sign(&sk, &claims).unwrap();
    let verified = token.verify(&pk).unwrap();
    assert_eq!(verified.get_issuer(), Some("test"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Vector Generation Helper (run with --nocapture to see output)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn generate_all_golden_vector_hex_values() {
    eprintln!("\n============================================================");
    eprintln!("GOLDEN VECTOR HEX VALUES");
    eprintln!("============================================================");

    // Schema hashes
    let schemas = [
        ("capability_object", "fcp.core.CapabilityObject/1.0.0"),
        ("operation_intent", "fcp.core.OperationIntent/1.0.0"),
        ("operation_receipt", "fcp.core.OperationReceipt/1.0.0"),
        ("audit_event", "fcp.core.AuditEvent/1.0.0"),
        ("event_envelope", "fcp.core.EventEnvelope/1.0.0"),
        ("zone_key_manifest", "fcp.zone.ZoneKeyManifest/1.0.0"),
        ("zone_definition", "fcp.zone.ZoneDefinition/1.0.0"),
        ("gossip_summary", "fcp.mesh.GossipSummary/1.0.0"),
    ];

    eprintln!("\n--- Schema Hashes ---");
    for (name, schema_id) in &schemas {
        let hash = schema_hash(schema_id);
        eprintln!("  {name}: \"{}\"", hex::encode(hash));
    }

    // Signing bytes
    eprintln!("\n--- Signing Bytes ---");
    let test_cbor = hex::decode("a16474657374f5").unwrap();
    let sb = canonical_signing_bytes("fcp.core.CapabilityObject/1.0.0", &test_cbor);
    eprintln!("  minimal_cbor: \"{}\"", hex::encode(&sb));

    // AAD encodings
    eprintln!("\n--- AAD Encodings ---");
    let aad_zone = Fcp2Aad::for_zone_key(b"z:work", b"node-123", 1_700_000_000);
    eprintln!("  zone_key_aad: \"{}\"", hex::encode(aad_zone.encode()));

    let aad_obj = Fcp2Aad::for_objectid_key(b"z:work", b"node-123", 1_700_000_000);
    eprintln!("  objectid_key_aad: \"{}\"", hex::encode(aad_obj.encode()));

    let aad_share = Fcp2Aad::for_secret_share(b"z:work", b"node-123", 1_700_000_000);
    eprintln!("  secret_share_aad: \"{}\"", hex::encode(aad_share.encode()));

    let aad_owner = Fcp2Aad {
        zone_id: b"z:owner".to_vec(),
        recipient_node_id: b"node-primary".to_vec(),
        purpose: b"FCP2-OWNER-SHARE".to_vec(),
        issued_at: 1_700_000_000,
    };
    eprintln!("  owner_share_aad: \"{}\"", hex::encode(aad_owner.encode()));

    // COSE tokens
    eprintln!("\n--- COSE Tokens ---");
    let sk = signing_key_from_rfc8032_tv1();
    let kid = sk.key_id();
    eprintln!("  key_id: \"{}\"", hex::encode(kid.as_bytes()));

    let minimal_claims = CwtClaims::new()
        .issuer("node:primary")
        .zone_id("z:work")
        .capability_id("cap:test.read");
    let minimal_claims_cbor = minimal_claims.to_cbor().unwrap();
    let minimal_token = CoseToken::sign(&sk, &minimal_claims).unwrap();
    let minimal_token_cbor = minimal_token.to_cbor().unwrap();
    eprintln!(
        "  minimal_claims_cbor: \"{}\"",
        hex::encode(&minimal_claims_cbor)
    );
    eprintln!(
        "  minimal_token_cbor: \"{}\"",
        hex::encode(&minimal_token_cbor)
    );

    let full_claims = CwtClaims::new()
        .issuer("node:primary")
        .subject("agent:claude")
        .audience("node:target")
        .token_id(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        .zone_id("z:work")
        .capability_id("cap:discord.send")
        .principal_id("agent:claude")
        .operations(&["discord.send_message", "discord.read_messages"])
        .issuing_node("node:primary")
        .holder_node("node:mobile");
    let full_claims_cbor = full_claims.to_cbor().unwrap();
    let full_token = CoseToken::sign(&sk, &full_claims).unwrap();
    let full_token_cbor = full_token.to_cbor().unwrap();
    eprintln!(
        "  full_claims_cbor: \"{}\"",
        hex::encode(&full_claims_cbor)
    );
    eprintln!(
        "  full_token_cbor: \"{}\"",
        hex::encode(&full_token_cbor)
    );

    eprintln!("\n============================================================");
}
