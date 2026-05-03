//! Session ack attestation + transcript-binding conformance.
//!
//! The responder→initiator `MeshSessionAck` verify path enforces several
//! interlocking invariants that are scattered across `fcp-protocol/src/session.rs`
//! but have no cross-crate conformance coverage today. These tests pin the
//! public `verify_ack_attested` and `MeshSessionAck::verify` contracts so a
//! regression that, for example, drops the suite-was-offered check or stops
//! binding the ack transcript to the hello's ephemeral key fails conformance
//! directly.
//!
//! Spec clauses (from docs/protocol/session-handshake.md and the `MeshSessionAck`
//! impl in `fcp-protocol/src/session.rs`):
//!
//! - The ack's (from, to) pair MUST be the swapped form of the hello's
//!   (from, to). Otherwise the ack cannot be attributed to that hello and
//!   cross-session attribution attacks become possible.
//! - The ack's suite MUST appear in the hello's offered suites. The
//!   responder cannot pick a suite the initiator never advertised.
//! - The ack signer's `MeshIdentity::node_id` MUST equal `ack.from`.
//! - The ack timestamp MUST fall inside the time policy window.
//! - A missing or tampered signature MUST be rejected.
//! - The ack transcript MUST bind to the hello's ephemeral public key and
//!   nonce; replaying the same ack against a different hello that shares the
//!   responder's identity MUST fail signature verification.

use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
use fcp_prelude::TailscaleNodeId;
use fcp_protocol::session::{
    MeshSessionAck, MeshSessionHello, MeshSessionId, SessionCryptoSuite, SessionError,
    SessionNonce, TimePolicy, current_timestamp, verify_ack_attested,
};
use fcp_tailscale::{MeshIdentity, NodeId, NodeKeyAttestation, NodeKeys, TailscaleTag};

struct PeerFixture {
    from: TailscaleNodeId,
    identity: MeshIdentity,
    signing_key: Ed25519SigningKey,
}

impl PeerFixture {
    fn new(node_name: &str) -> Self {
        let owner_key = Ed25519SigningKey::generate();
        let signing_key = Ed25519SigningKey::generate();
        let issuance_key = Ed25519SigningKey::generate();
        let encryption_key = X25519SecretKey::generate();
        let node_id = NodeId::new(node_name);
        let tags = vec![TailscaleTag::fcp_tag("work")];
        let node_keys = NodeKeys::new(
            signing_key.verifying_key(),
            encryption_key.public_key(),
            issuance_key.verifying_key(),
        );
        let attestation = NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24)
            .expect("attest node");
        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            Vec::new(),
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);
        Self {
            from: TailscaleNodeId::new(node_name),
            identity,
            signing_key,
        }
    }
}

fn make_hello(initiator: &PeerFixture, responder: &PeerFixture) -> MeshSessionHello {
    let eph_key = X25519SecretKey::generate();
    let mut hello = MeshSessionHello {
        from: initiator.from.clone(),
        to: responder.from.clone(),
        eph_pubkey: eph_key.public_key(),
        nonce: SessionNonce([0xAA; 16]),
        cookie: None,
        timestamp: current_timestamp(),
        suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
        transport_limits: None,
        signature: None,
    };
    hello.sign(&initiator.signing_key).expect("sign hello");
    hello
}

fn make_signed_ack(
    initiator: &PeerFixture,
    responder: &PeerFixture,
    hello: &MeshSessionHello,
    suite: SessionCryptoSuite,
) -> MeshSessionAck {
    let eph_key = X25519SecretKey::generate();
    let mut ack = MeshSessionAck {
        from: responder.from.clone(),
        to: initiator.from.clone(),
        eph_pubkey: eph_key.public_key(),
        nonce: SessionNonce([0xBB; 16]),
        session_id: MeshSessionId([0x42; 16]),
        suite,
        timestamp: current_timestamp(),
        signature: None,
    };
    ack.sign(hello, &responder.signing_key).expect("sign ack");
    ack
}

#[test]
fn ack_round_trip_passes_attestation_verify() {
    let initiator = PeerFixture::new("node-initiator");
    let responder = PeerFixture::new("node-responder");
    let hello = make_hello(&initiator, &responder);
    let ack = make_signed_ack(&initiator, &responder, &hello, SessionCryptoSuite::Suite2);

    verify_ack_attested(&ack, &hello, &responder.identity, &TimePolicy::default())
        .expect("a well-formed ack signed by the responder must verify");
}

#[test]
fn ack_from_not_matching_hello_to_is_rejected_as_hello_mismatch() {
    // Spec: `ack.verify` requires ack.from == hello.to. After a clean
    // handshake fixture, mutate hello.to to a third party post-ack-signing
    // (the ack transcript binds eph_pubkey/nonce, not hello.to, so the
    // signature stays intact). The verifier must surface AckHelloMismatch
    // — not silently accept the ack against the wrong hello.
    let initiator = PeerFixture::new("node-initiator");
    let responder = PeerFixture::new("node-responder");
    let third_party = TailscaleNodeId::new("node-third-party");
    let mut hello = make_hello(&initiator, &responder);
    let ack = make_signed_ack(&initiator, &responder, &hello, SessionCryptoSuite::Suite2);

    hello.to = third_party;

    let err = verify_ack_attested(&ack, &hello, &responder.identity, &TimePolicy::default())
        .expect_err("ack.from != hello.to must be rejected");
    assert!(
        matches!(err, SessionError::AckHelloMismatch),
        "expected AckHelloMismatch, got {err:?}"
    );
}

#[test]
fn ack_to_not_matching_hello_from_is_rejected_as_hello_mismatch() {
    // Symmetric to the above: ack.to MUST equal hello.from. Mutating
    // hello.from after ack-signing leaves the transcript intact and forces
    // the verifier through the (ack.to != hello.from) branch.
    let initiator = PeerFixture::new("node-initiator");
    let responder = PeerFixture::new("node-responder");
    let third_party = TailscaleNodeId::new("node-third-party");
    let mut hello = make_hello(&initiator, &responder);
    let ack = make_signed_ack(&initiator, &responder, &hello, SessionCryptoSuite::Suite2);

    hello.from = third_party;

    let err = verify_ack_attested(&ack, &hello, &responder.identity, &TimePolicy::default())
        .expect_err("ack.to != hello.from must be rejected");
    assert!(
        matches!(err, SessionError::AckHelloMismatch),
        "expected AckHelloMismatch, got {err:?}"
    );
}

#[test]
fn ack_picks_a_suite_the_hello_did_not_offer_is_rejected() {
    // Spec: ack.suite MUST appear in hello.suites. Responder cannot select
    // a suite the initiator never advertised.
    let initiator = PeerFixture::new("node-initiator");
    let responder = PeerFixture::new("node-responder");

    // Initiator only offers Suite1; ack will pick Suite2 (not offered).
    let eph_key = X25519SecretKey::generate();
    let mut hello = MeshSessionHello {
        from: initiator.from.clone(),
        to: responder.from.clone(),
        eph_pubkey: eph_key.public_key(),
        nonce: SessionNonce([0xC1; 16]),
        cookie: None,
        timestamp: current_timestamp(),
        suites: vec![SessionCryptoSuite::Suite1],
        transport_limits: None,
        signature: None,
    };
    hello.sign(&initiator.signing_key).expect("sign hello");

    let ack = make_signed_ack(&initiator, &responder, &hello, SessionCryptoSuite::Suite2);

    let err = verify_ack_attested(&ack, &hello, &responder.identity, &TimePolicy::default())
        .expect_err("ack picking unoffered suite must be rejected");
    assert!(
        matches!(err, SessionError::AckSuiteNotOffered),
        "expected AckSuiteNotOffered, got {err:?}"
    );
}

#[test]
fn ack_signed_by_a_different_responder_is_rejected_as_node_mismatch() {
    // If the responder identity used to verify the ack does not match
    // ack.from, the verifier must reject with AttestationNodeMismatch
    // before signature verification — otherwise an attacker could submit
    // an ack that looks valid against the wrong identity.
    let initiator = PeerFixture::new("node-initiator");
    let responder = PeerFixture::new("node-responder");
    let other = PeerFixture::new("node-other");
    let hello = make_hello(&initiator, &responder);
    let ack = make_signed_ack(&initiator, &responder, &hello, SessionCryptoSuite::Suite2);

    let err = verify_ack_attested(&ack, &hello, &other.identity, &TimePolicy::default())
        .expect_err("ack from one responder must not verify against a different identity");
    assert!(
        matches!(err, SessionError::AttestationNodeMismatch),
        "expected AttestationNodeMismatch, got {err:?}"
    );
}

#[test]
fn ack_with_stale_timestamp_is_rejected_with_skew_error() {
    let initiator = PeerFixture::new("node-initiator");
    let responder = PeerFixture::new("node-responder");
    let hello = make_hello(&initiator, &responder);
    let mut ack = make_signed_ack(&initiator, &responder, &hello, SessionCryptoSuite::Suite2);

    let policy = TimePolicy::default();
    ack.timestamp = current_timestamp().saturating_sub(policy.max_skew_secs * 100);
    ack.sign(&hello, &responder.signing_key)
        .expect("re-sign after stale-timestamp mutation");

    let err = verify_ack_attested(&ack, &hello, &responder.identity, &policy)
        .expect_err("stale ack must be rejected");
    assert!(
        matches!(err, SessionError::TimestampSkew { .. }),
        "expected TimestampSkew, got {err:?}"
    );
}

#[test]
fn ack_with_tampered_signature_is_rejected_as_invalid_signature() {
    let initiator = PeerFixture::new("node-initiator");
    let responder = PeerFixture::new("node-responder");
    let hello = make_hello(&initiator, &responder);
    let mut ack = make_signed_ack(&initiator, &responder, &hello, SessionCryptoSuite::Suite2);

    // Re-sign with an attacker key. ack.from still equals responder.from,
    // hello (from, to) still swap correctly, suite is still offered, and
    // timestamp is still fresh, so the verifier reaches signature
    // verification — which must reject.
    let attacker = Ed25519SigningKey::generate();
    ack.sign(&hello, &attacker)
        .expect("re-sign with attacker key");

    let err = verify_ack_attested(&ack, &hello, &responder.identity, &TimePolicy::default())
        .expect_err("ack signed by the wrong key must be rejected");
    assert!(
        matches!(err, SessionError::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn ack_without_signature_is_rejected_as_missing_signature() {
    let initiator = PeerFixture::new("node-initiator");
    let responder = PeerFixture::new("node-responder");
    let hello = make_hello(&initiator, &responder);
    let mut ack = make_signed_ack(&initiator, &responder, &hello, SessionCryptoSuite::Suite2);

    ack.signature = None;

    let err = verify_ack_attested(&ack, &hello, &responder.identity, &TimePolicy::default())
        .expect_err("unsigned ack must be rejected");
    assert!(
        matches!(err, SessionError::MissingSignature),
        "expected MissingSignature, got {err:?}"
    );
}

#[test]
fn ack_transcript_binds_to_hello_ephemeral_pubkey() {
    // The ack transcript hashes hello.eph_pubkey, so an ack signed against
    // hello_a MUST NOT verify against a hello_b that shares the same (from,
    // to, suites, nonce) but uses a different ephemeral public key. This is
    // the property that prevents an attacker from re-attributing a captured
    // ack to a different concurrent hello between the same pair of peers.
    let initiator = PeerFixture::new("node-initiator");
    let responder = PeerFixture::new("node-responder");

    let mut hello_a = make_hello(&initiator, &responder);
    let mut hello_b = hello_a.clone();
    let other_eph = X25519SecretKey::generate();
    hello_b.eph_pubkey = other_eph.public_key();
    hello_b
        .sign(&initiator.signing_key)
        .expect("re-sign hello_b after eph swap");
    assert_ne!(
        hello_a.eph_pubkey, hello_b.eph_pubkey,
        "fixture sanity: the two hellos must differ in eph_pubkey"
    );
    // Also re-sign hello_a so both hellos are independently valid handshakes.
    hello_a
        .sign(&initiator.signing_key)
        .expect("ensure hello_a remains validly signed");

    let ack = make_signed_ack(&initiator, &responder, &hello_a, SessionCryptoSuite::Suite2);

    let err = verify_ack_attested(&ack, &hello_b, &responder.identity, &TimePolicy::default())
        .expect_err(
            "ack signed against hello_a must not verify against hello_b with a different eph",
        );
    assert!(
        matches!(err, SessionError::InvalidSignature),
        "expected InvalidSignature (transcript mismatch), got {err:?}"
    );
}

#[test]
fn ack_transcript_binds_to_hello_nonce() {
    // The ack transcript also hashes hello.nonce. An ack signed against a
    // hello with nonce N1 MUST NOT verify against a hello with nonce N2,
    // even when (from, to, eph_pubkey, suites) are otherwise identical.
    let initiator = PeerFixture::new("node-initiator");
    let responder = PeerFixture::new("node-responder");

    let mut hello_a = make_hello(&initiator, &responder);
    let mut hello_b = hello_a.clone();
    hello_b.nonce = SessionNonce([0x55; 16]);
    hello_b
        .sign(&initiator.signing_key)
        .expect("re-sign hello_b after nonce swap");
    hello_a
        .sign(&initiator.signing_key)
        .expect("ensure hello_a remains validly signed");

    let ack = make_signed_ack(&initiator, &responder, &hello_a, SessionCryptoSuite::Suite2);

    let err = verify_ack_attested(&ack, &hello_b, &responder.identity, &TimePolicy::default())
        .expect_err("ack signed against hello_a must not verify against hello_b with a new nonce");
    assert!(
        matches!(err, SessionError::InvalidSignature),
        "expected InvalidSignature (transcript mismatch), got {err:?}"
    );
}
