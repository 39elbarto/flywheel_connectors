//! Pin format invariants for the closest analogue of "CapabilityProof"
//! (flywheel_connectors-bc6x4).
//!
//! Bead asks for "CapabilityProof Display formatting + roundtrip".
//! No type literally named `CapabilityProof` exists in fcp-core. The
//! capability-binding proof in this codebase is `HolderProof`
//! (protocol.rs:307) — the Ed25519 signature that proves the
//! requesting node holds the capability token (when the token has a
//! `holder_node` claim). `HolderProof` does NOT implement `Display`,
//! so the bead's "Display formatting" ask has no direct analogue.
//!
//! Existing `tests/invoke_golden_vectors.rs::holder_proof` pins the
//! basic surface: domain-separator presence, determinism, and that
//! request_id / operation_id / jti each affect the bytes. This test
//! pins the format-contract gaps:
//!
//!   1. **Domain separator at the exact head** — the first 20 bytes
//!      MUST be `b"FCP2-HOLDER-PROOF-V1"`.
//!   2. **Length-prefix format is little-endian u32** at the
//!      documented offsets (right after each field).
//!   3. **Length prefixes match the field's actual byte length**.
//!   4. **Length-prefixing prevents cross-input collisions** —
//!      shifting bytes between fields changes the canonical bytes.
//!   5. **Empty fields encode to a zero-length prefix** with no
//!      trailing field bytes (the boundary case for length prefix
//!      injectivity).
//!   6. **JSON wire shape pinned** — signature as 128-char lowercase
//!      hex (via `hex_or_bytes`), holder_node as canonical id string.
//!   7. **JSON round-trip preserves both fields** (the closest
//!      analogue to "Display+FromStr roundtrip" — Display is absent
//!      so the round-trip surface is serde).
//!   8. **CBOR round-trip preserves both fields**.
//!   9. **CBOR signature encoded as bytes, NOT hex string** — the
//!      `hex_or_bytes` serde swap behavior.
//!  10. **Cross-format consistency** — a HolderProof decoded from
//!      JSON and one decoded from CBOR with the same input produce
//!      identical signable_bytes when re-fed.

use ciborium::value::Value as CborValue;
use fcp_core::{HolderProof, OperationId, RequestId, TailscaleNodeId};

const DOMAIN_SEPARATOR: &[u8] = b"FCP2-HOLDER-PROOF-V1";

fn fixture_proof() -> HolderProof {
    let mut sig = [0u8; 64];
    for (i, byte) in sig.iter_mut().enumerate() {
        *byte = i as u8; // 0..=63
    }
    HolderProof::new(sig, TailscaleNodeId::new("node-holder-1"))
}

fn req(s: &str) -> RequestId {
    RequestId(s.into())
}

fn op(s: &str) -> OperationId {
    OperationId::new(s).expect("operation id")
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Domain separator at exact head
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signable_bytes_starts_with_versioned_domain_separator() {
    let bytes = HolderProof::signable_bytes(&req("r"), &op("op.x"), b"j");
    assert_eq!(
        &bytes[..DOMAIN_SEPARATOR.len()],
        DOMAIN_SEPARATOR,
        "DOMAIN-SEPARATOR REGRESSION: signable_bytes MUST start with \
         the V1 domain separator at byte 0"
    );
}

#[test]
fn domain_separator_value_is_pinned() {
    assert_eq!(
        DOMAIN_SEPARATOR, b"FCP2-HOLDER-PROOF-V1",
        "If the domain-separator literal changes, every existing holder \
         proof signature is silently invalidated — pin it loudly"
    );
    assert_eq!(DOMAIN_SEPARATOR.len(), 20);
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. & 3. Length prefixes are little-endian u32 at documented offsets
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn length_prefixes_are_little_endian_u32_at_documented_offsets() {
    // Format pinned by protocol.rs:328:
    //   "FCP2-HOLDER-PROOF-V1" || len(req_id) || req_id || len(op_id) || op_id || len(jti) || jti
    // Each `len(...)` is a u32 in little-endian byte order.
    let req_id = req("req-abc");
    let op_id = op("op.example");
    let jti = b"jti-xyz";
    let bytes = HolderProof::signable_bytes(&req_id, &op_id, jti);

    // Offset 0..20: domain separator (20 bytes, pinned above).
    let mut off = DOMAIN_SEPARATOR.len();

    // Offset 20..24: little-endian u32 length of request_id.
    let req_len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    assert_eq!(
        req_len as usize,
        "req-abc".len(),
        "request_id length prefix"
    );
    off += 4;
    assert_eq!(&bytes[off..off + req_len as usize], b"req-abc");
    off += req_len as usize;

    // Next 4: u32 LE length of operation_id.
    let op_len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    assert_eq!(
        op_len as usize,
        "op.example".len(),
        "operation_id length prefix"
    );
    off += 4;
    assert_eq!(&bytes[off..off + op_len as usize], b"op.example");
    off += op_len as usize;

    // Next 4: u32 LE length of token_jti.
    let jti_len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    assert_eq!(jti_len as usize, jti.len(), "token_jti length prefix");
    off += 4;
    assert_eq!(&bytes[off..off + jti_len as usize], jti);
    off += jti_len as usize;

    // No trailing bytes.
    assert_eq!(off, bytes.len(), "no trailing bytes after final field");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Length prefix injectivity — cross-input collision prevention
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn length_prefixing_prevents_cross_field_concatenation_collision() {
    // Without length prefixes, "ab" + "cd" and "a" + "bcd" would
    // both produce the same byte stream. Length prefixing is the
    // injectivity guarantee — pin that the byte streams differ.
    let bytes_a = HolderProof::signable_bytes(&req("ab"), &op("cd.x"), b"ef");
    let bytes_b = HolderProof::signable_bytes(&req("a"), &op("bcd.x"), b"ef");
    assert_ne!(
        bytes_a, bytes_b,
        "INJECTIVITY: shifting one byte from request_id to operation_id \
         MUST produce different signable bytes (length prefixes guarantee this)"
    );

    // And shifting in the other direction.
    let bytes_c = HolderProof::signable_bytes(&req("a.x"), &op("b.x"), b"cdef");
    let bytes_d = HolderProof::signable_bytes(&req("a.x"), &op("b.xc"), b"def");
    assert_ne!(
        bytes_c, bytes_d,
        "INJECTIVITY: shifting one byte from operation_id to jti \
         MUST produce different signable bytes"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Empty fields encode to a zero-length prefix
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn empty_jti_encodes_as_zero_length_prefix_with_no_trailing_bytes() {
    let req_id = req("r");
    let op_id = op("o.x");
    let bytes = HolderProof::signable_bytes(&req_id, &op_id, b"");
    // Walk the structure to find the jti length prefix and confirm
    // it's exactly 0 with no trailing bytes after.
    let mut off = DOMAIN_SEPARATOR.len();
    let r_len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    off += 4 + r_len as usize;
    let o_len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    off += 4 + o_len as usize;
    let j_len = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    assert_eq!(j_len, 0, "empty jti MUST encode as length 0");
    off += 4;
    assert_eq!(off, bytes.len(), "no trailing bytes after empty jti");
}

#[test]
fn empty_request_id_still_produces_distinct_bytes() {
    let with_req = HolderProof::signable_bytes(&req("a"), &op("o.x"), b"j");
    let empty_req = HolderProof::signable_bytes(&req(""), &op("o.x"), b"j");
    assert_ne!(
        with_req, empty_req,
        "non-empty vs empty request_id MUST produce different bytes"
    );
    // Empty request_id encodes as length-0 prefix.
    let off = DOMAIN_SEPARATOR.len();
    assert_eq!(
        u32::from_le_bytes(empty_req[off..off + 4].try_into().unwrap()),
        0
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. & 7. JSON wire shape + round-trip
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_wire_shape_pinned_signature_as_lowercase_hex() {
    let proof = fixture_proof();
    let value = serde_json::to_value(&proof).expect("serialize");

    let sig_str = value
        .get("signature")
        .and_then(|v| v.as_str())
        .expect("signature field as string");
    assert_eq!(sig_str.len(), 128, "signature MUST be 128 hex chars");
    assert!(
        sig_str
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "signature hex MUST be all-lowercase: {sig_str}"
    );
    // The first byte of the signature is 0x00, the second 0x01, etc.
    assert!(sig_str.starts_with("000102030405"));

    let holder = value
        .get("holder_node")
        .and_then(|v| v.as_str())
        .expect("holder_node field");
    assert_eq!(
        holder, "node-holder-1",
        "holder_node serializes as the canonical id string"
    );
}

#[test]
fn json_roundtrip_preserves_signature_and_holder_node() {
    let original = fixture_proof();
    let json = serde_json::to_string(&original).expect("serialize");
    let back: HolderProof = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.signature, original.signature);
    assert_eq!(back.holder_node, original.holder_node);
}

#[test]
fn json_rejects_oversized_signature() {
    // 65-byte signature (130 hex chars) MUST be rejected — fixed
    // length is part of the wire contract.
    let bad = serde_json::json!({
        "signature": "ab".repeat(65),
        "holder_node": "node-x"
    });
    let result = serde_json::from_value::<HolderProof>(bad);
    assert!(result.is_err(), "oversized signature MUST be rejected");
}

#[test]
fn json_rejects_undersized_signature() {
    let bad = serde_json::json!({
        "signature": "ab".repeat(63),
        "holder_node": "node-x"
    });
    let result = serde_json::from_value::<HolderProof>(bad);
    assert!(result.is_err(), "undersized signature MUST be rejected");
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. & 9. CBOR round-trip + signature-as-bytes wire shape
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn cbor_roundtrip_preserves_signature_and_holder_node() {
    let original = fixture_proof();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&original, &mut buf).expect("encode");
    let back: HolderProof = ciborium::de::from_reader(buf.as_slice()).expect("decode");
    assert_eq!(back.signature, original.signature);
    assert_eq!(back.holder_node, original.holder_node);
}

#[test]
fn cbor_signature_encoded_as_byte_string_not_hex() {
    // hex_or_bytes serializes as bytes for non-human-readable
    // formats. Pin that the CBOR map's `signature` field is a
    // CBOR byte string of length 64, not a hex string.
    let proof = fixture_proof();
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&proof, &mut buf).expect("encode");
    let value: CborValue = ciborium::de::from_reader(buf.as_slice()).expect("decode as Value");
    let map = match value {
        CborValue::Map(m) => m,
        other => panic!("HolderProof MUST encode as CBOR map, got {other:?}"),
    };
    let sig_value = map
        .iter()
        .find_map(|(k, v)| match k {
            CborValue::Text(s) if s == "signature" => Some(v),
            _ => None,
        })
        .expect("signature key");
    match sig_value {
        CborValue::Bytes(b) => {
            assert_eq!(b.len(), 64, "CBOR `signature` MUST be 64-byte byte string")
        }
        CborValue::Text(t) => panic!(
            "CBOR `signature` MUST be Bytes (not Text); got Text({t:?}) — \
             hex_or_bytes serde swap regression"
        ),
        other => panic!("CBOR `signature` unexpected type: {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 10. Cross-format consistency
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn json_and_cbor_decode_to_same_holder_proof() {
    let original = fixture_proof();

    let json = serde_json::to_string(&original).expect("JSON serialize");
    let from_json: HolderProof = serde_json::from_str(&json).expect("JSON deserialize");

    let mut cbor = Vec::new();
    ciborium::ser::into_writer(&original, &mut cbor).expect("CBOR encode");
    let from_cbor: HolderProof = ciborium::de::from_reader(cbor.as_slice()).expect("CBOR decode");

    assert_eq!(from_json.signature, from_cbor.signature);
    assert_eq!(from_json.holder_node, from_cbor.holder_node);
}

// ─────────────────────────────────────────────────────────────────────────────
// 11. signable_bytes is independent of HolderProof field values
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn signable_bytes_does_not_depend_on_proof_fields() {
    // signable_bytes is a pure function of (request_id, operation_id,
    // token_jti) — it MUST NOT depend on the signature or
    // holder_node bytes the caller eventually puts into HolderProof.
    let req_id = req("r");
    let op_id = op("o.x");
    let jti = b"j";
    let bytes_a = HolderProof::signable_bytes(&req_id, &op_id, jti);
    let bytes_b = HolderProof::signable_bytes(&req_id, &op_id, jti);
    assert_eq!(
        bytes_a, bytes_b,
        "signable_bytes is a deterministic function of (req, op, jti) only"
    );
    // And construct two proofs with totally different signatures:
    // signable_bytes for the verifier MUST be the same.
    let _proof_a = HolderProof::new([0x00; 64], TailscaleNodeId::new("alpha"));
    let _proof_b = HolderProof::new([0xFF; 64], TailscaleNodeId::new("beta"));
    let bytes_c = HolderProof::signable_bytes(&req_id, &op_id, jti);
    assert_eq!(bytes_c, bytes_a);
}
