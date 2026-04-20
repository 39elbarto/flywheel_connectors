#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use chrono::{DateTime, TimeZone, Utc};
use fcp_crypto::cose::{CoseToken, CwtClaims};
use fcp_crypto::ed25519::Ed25519SigningKey;
use libfuzzer_sys::fuzz_target;
use serde::Deserialize;

const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_TEXT_LEN: usize = 64;
const MAX_OPS: usize = 8;
const MAX_BYTES_LEN: usize = 64;
const MAX_GRANT_OBJECTS: usize = 8;
const MIN_TIMESTAMP: i64 = -2_208_988_800; // 1900-01-01T00:00:00Z
const MAX_TIMESTAMP: i64 = 4_102_444_800; // 2100-01-01T00:00:00Z

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct CoseRoundTripSeed {
    issuer: String,
    subject: String,
    audience: String,
    capability_id: String,
    zone_id: String,
    principal_id: String,
    issuing_node: String,
    holder_node: String,
    target_instance: String,
    operations: Vec<String>,
    token_id: Vec<u8>,
    audience_binary: Vec<u8>,
    grant_objects: Vec<Vec<u8>>,
    checkpoint_id: Vec<u8>,
    checkpoint_seq: u64,
    issued_at: Option<i64>,
    not_before: Option<i64>,
    expiration: Option<i64>,
    include_subject: bool,
    include_audience: bool,
    include_zone_id: bool,
    include_principal_id: bool,
    include_issuing_node: bool,
    include_holder_node: bool,
    include_target_instance: bool,
    include_operations: bool,
    include_token_id: bool,
    include_audience_binary: bool,
    include_grant_objects: bool,
    include_checkpoint: bool,
}

fn bounded_len(u: &mut Unstructured<'_>, max_len: usize) -> usize {
    u.int_in_range(0..=max_len).unwrap_or(0)
}

fn bounded_bytes(u: &mut Unstructured<'_>, max_len: usize) -> Vec<u8> {
    let len = bounded_len(u, max_len);
    u.bytes(len).map(ToOwned::to_owned).unwrap_or_default()
}

fn bounded_string(u: &mut Unstructured<'_>, max_len: usize) -> String {
    String::from_utf8_lossy(&bounded_bytes(u, max_len)).into_owned()
}

fn bounded_string_vec(u: &mut Unstructured<'_>, max_items: usize, max_len: usize) -> Vec<String> {
    let count = bounded_len(u, max_items);
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(bounded_string(u, max_len));
    }
    values
}

fn bounded_bytes_vec(u: &mut Unstructured<'_>, max_items: usize, max_len: usize) -> Vec<Vec<u8>> {
    let count = bounded_len(u, max_items);
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(bounded_bytes(u, max_len));
    }
    values
}

fn optional_timestamp(u: &mut Unstructured<'_>) -> Option<i64> {
    if u.arbitrary::<bool>().unwrap_or(false) {
        Some(
            i64::arbitrary(u)
                .unwrap_or(0)
                .clamp(MIN_TIMESTAMP, MAX_TIMESTAMP),
        )
    } else {
        None
    }
}

fn seed_from_unstructured(data: &[u8]) -> CoseRoundTripSeed {
    let mut u = Unstructured::new(data);
    CoseRoundTripSeed {
        issuer: bounded_string(&mut u, MAX_TEXT_LEN),
        subject: bounded_string(&mut u, MAX_TEXT_LEN),
        audience: bounded_string(&mut u, MAX_TEXT_LEN),
        capability_id: bounded_string(&mut u, MAX_TEXT_LEN),
        zone_id: bounded_string(&mut u, MAX_TEXT_LEN),
        principal_id: bounded_string(&mut u, MAX_TEXT_LEN),
        issuing_node: bounded_string(&mut u, MAX_TEXT_LEN),
        holder_node: bounded_string(&mut u, MAX_TEXT_LEN),
        target_instance: bounded_string(&mut u, MAX_TEXT_LEN),
        operations: bounded_string_vec(&mut u, MAX_OPS, MAX_TEXT_LEN),
        token_id: bounded_bytes(&mut u, MAX_BYTES_LEN),
        audience_binary: bounded_bytes(&mut u, MAX_BYTES_LEN),
        grant_objects: bounded_bytes_vec(&mut u, MAX_GRANT_OBJECTS, MAX_BYTES_LEN),
        checkpoint_id: bounded_bytes(&mut u, MAX_BYTES_LEN),
        checkpoint_seq: u64::arbitrary(&mut u).unwrap_or(0),
        issued_at: optional_timestamp(&mut u),
        not_before: optional_timestamp(&mut u),
        expiration: optional_timestamp(&mut u),
        include_subject: u.arbitrary::<bool>().unwrap_or(false),
        include_audience: u.arbitrary::<bool>().unwrap_or(false),
        include_zone_id: u.arbitrary::<bool>().unwrap_or(false),
        include_principal_id: u.arbitrary::<bool>().unwrap_or(false),
        include_issuing_node: u.arbitrary::<bool>().unwrap_or(false),
        include_holder_node: u.arbitrary::<bool>().unwrap_or(false),
        include_target_instance: u.arbitrary::<bool>().unwrap_or(false),
        include_operations: u.arbitrary::<bool>().unwrap_or(false),
        include_token_id: u.arbitrary::<bool>().unwrap_or(false),
        include_audience_binary: u.arbitrary::<bool>().unwrap_or(false),
        include_grant_objects: u.arbitrary::<bool>().unwrap_or(false),
        include_checkpoint: u.arbitrary::<bool>().unwrap_or(false),
    }
}

fn roundtrip_input(data: &[u8]) -> CoseRoundTripSeed {
    serde_json::from_slice::<CoseRoundTripSeed>(data)
        .unwrap_or_else(|_| seed_from_unstructured(data))
}

fn clipped_text(text: &str, fallback: &str) -> String {
    let mut clipped = text.chars().take(MAX_TEXT_LEN).collect::<String>();
    if clipped.is_empty() {
        clipped = fallback.to_string();
    }
    clipped
}

fn clipped_optional_text(text: &str) -> Option<String> {
    let clipped = text.chars().take(MAX_TEXT_LEN).collect::<String>();
    if clipped.is_empty() {
        None
    } else {
        Some(clipped)
    }
}

fn clipped_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().copied().take(MAX_BYTES_LEN).collect()
}

fn clipped_timestamp(timestamp: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(timestamp.clamp(MIN_TIMESTAMP, MAX_TIMESTAMP), 0)
        .single()
        .expect("clamped timestamps must stay representable")
}

fn build_claims(seed: &CoseRoundTripSeed) -> CwtClaims {
    let mut claims = CwtClaims::new()
        .issuer(&clipped_text(&seed.issuer, "node:fuzz"))
        .capability_id(&clipped_text(&seed.capability_id, "cap:fuzz"));

    if seed.include_subject
        && let Some(subject) = clipped_optional_text(&seed.subject)
    {
        claims = claims.subject(&subject);
    }

    if seed.include_audience
        && let Some(audience) = clipped_optional_text(&seed.audience)
    {
        claims = claims.audience(&audience);
    }

    if seed.include_zone_id
        && let Some(zone_id) = clipped_optional_text(&seed.zone_id)
    {
        claims = claims.zone_id(&zone_id);
    }

    if seed.include_principal_id
        && let Some(principal_id) = clipped_optional_text(&seed.principal_id)
    {
        claims = claims.principal_id(&principal_id);
    }

    if seed.include_issuing_node
        && let Some(issuing_node) = clipped_optional_text(&seed.issuing_node)
    {
        claims = claims.issuing_node(&issuing_node);
    }

    if seed.include_holder_node
        && let Some(holder_node) = clipped_optional_text(&seed.holder_node)
    {
        claims = claims.holder_node(&holder_node);
    }

    if seed.include_target_instance
        && let Some(target_instance) = clipped_optional_text(&seed.target_instance)
    {
        claims = claims.target_instance(&target_instance);
    }

    if seed.include_operations {
        let operations = seed
            .operations
            .iter()
            .take(MAX_OPS)
            .filter_map(|op| clipped_optional_text(op))
            .collect::<Vec<_>>();
        if !operations.is_empty() {
            let operation_refs = operations.iter().map(String::as_str).collect::<Vec<_>>();
            claims = claims.operations(&operation_refs);
        }
    }

    if seed.include_token_id {
        let token_id = clipped_bytes(&seed.token_id);
        if !token_id.is_empty() {
            claims = claims.token_id(&token_id);
        }
    }

    if seed.include_audience_binary {
        let audience_binary = clipped_bytes(&seed.audience_binary);
        if !audience_binary.is_empty() {
            claims = claims.audience_binary(&audience_binary);
        }
    }

    if seed.include_grant_objects {
        let grant_objects = seed
            .grant_objects
            .iter()
            .take(MAX_GRANT_OBJECTS)
            .map(|object_id| clipped_bytes(object_id))
            .filter(|object_id| !object_id.is_empty())
            .collect::<Vec<_>>();
        if !grant_objects.is_empty() {
            let grant_refs = grant_objects.iter().map(Vec::as_slice).collect::<Vec<_>>();
            claims = claims.grant_objects(&grant_refs);
        }
    }

    if seed.include_checkpoint {
        let checkpoint_id = clipped_bytes(&seed.checkpoint_id);
        if !checkpoint_id.is_empty() {
            claims = claims.checkpoint(&checkpoint_id, seed.checkpoint_seq);
        }
    }

    if let Some(issued_at) = seed.issued_at {
        claims = claims.issued_at(clipped_timestamp(issued_at));
    }

    if let Some(not_before) = seed.not_before {
        claims = claims.not_before(clipped_timestamp(not_before));
    }

    if let Some(expiration) = seed.expiration {
        claims = claims.expiration(clipped_timestamp(expiration));
    }

    claims
}

fn exercise_cose_roundtrip(seed: CoseRoundTripSeed) {
    let claims = build_claims(&seed);
    let claims_cbor = claims
        .to_cbor()
        .expect("claims built by the library must encode");
    let parsed_claims =
        CwtClaims::from_cbor(&claims_cbor).expect("encoded claims must decode back into claims");
    let reparsed_claims_cbor = parsed_claims
        .to_cbor()
        .expect("decoded claims must re-encode deterministically");
    assert_eq!(claims_cbor, reparsed_claims_cbor);

    let signing_key =
        Ed25519SigningKey::from_bytes(&[0x5a; 32]).expect("fixed fuzz signing key must parse");
    let verifying_key = signing_key.verifying_key();
    let key_id = signing_key.key_id();

    let token = CoseToken::sign(&signing_key, &claims)
        .expect("tokens built from valid claims must sign successfully");
    let token_cbor = token
        .to_cbor()
        .expect("signed tokens must encode to CBOR successfully");
    let parsed_token =
        CoseToken::from_cbor(&token_cbor).expect("encoded COSE tokens must parse successfully");
    let reparsed_token_cbor = parsed_token
        .to_cbor()
        .expect("parsed COSE tokens must re-encode");
    assert_eq!(token_cbor, reparsed_token_cbor);

    let parsed_key_id = parsed_token
        .get_key_id()
        .expect("signed token must carry a protected key id");
    assert_eq!(parsed_key_id, key_id.as_bytes());

    let claims_unverified = parsed_token
        .claims_unverified()
        .expect("generated token payloads must decode before verification");
    assert_eq!(
        claims_unverified
            .to_cbor()
            .expect("unverified claims must re-encode"),
        claims_cbor
    );

    let verified_claims = parsed_token
        .verify(&verifying_key)
        .expect("generated tokens must verify with the matching key");
    assert_eq!(
        verified_claims
            .to_cbor()
            .expect("verified claims must re-encode"),
        claims_cbor
    );

    let looked_up_claims = parsed_token
        .verify_with_lookup(|kid| {
            if kid == &key_id {
                Some(verifying_key.clone())
            } else {
                None
            }
        })
        .expect("key lookup verification must agree with direct verification");
    assert_eq!(
        looked_up_claims
            .to_cbor()
            .expect("lookup-verified claims must re-encode"),
        claims_cbor
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let seed = roundtrip_input(data);
    exercise_cose_roundtrip(seed);
});
