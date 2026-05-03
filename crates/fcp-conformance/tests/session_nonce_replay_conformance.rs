//! Session handshake nonce-replay conformance.
//!
//! These tests exercise the production responder-side hello replay helper so a
//! regression in handshake nonce tracking fails conformance directly.

use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
use fcp_prelude::TailscaleNodeId;
use fcp_protocol::session::{
    HelloReplayWindow, MeshSessionHello, SessionCryptoSuite, SessionError, SessionNonce,
    TimePolicy, current_timestamp, verify_hello_attested_with_replay,
};
use fcp_tailscale::{MeshIdentity, NodeId, NodeKeyAttestation, NodeKeys, TailscaleTag};

struct HelloPeerFixture {
    from: TailscaleNodeId,
    identity: MeshIdentity,
    signing_key: Ed25519SigningKey,
}

impl HelloPeerFixture {
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

    fn signed_hello(&self, nonce: [u8; 16]) -> MeshSessionHello {
        let eph_key = X25519SecretKey::generate();
        let mut hello = MeshSessionHello {
            from: self.from.clone(),
            to: TailscaleNodeId::new("node-responder"),
            eph_pubkey: eph_key.public_key(),
            nonce: SessionNonce(nonce),
            cookie: None,
            timestamp: current_timestamp(),
            suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
            transport_limits: None,
            signature: None,
        };
        hello.sign(&self.signing_key).expect("sign hello");
        hello
            .verify(&self.signing_key.verifying_key())
            .expect("verify hello");
        hello
    }
}

fn verify_hello(
    hello: &MeshSessionHello,
    peer: &HelloPeerFixture,
    window: &mut HelloReplayWindow,
) -> Result<(), SessionError> {
    verify_hello_attested_with_replay(hello, &peer.identity, &TimePolicy::default(), window)
}

#[test]
fn duplicate_hello_nonce_is_rejected_within_active_window() {
    let peer = HelloPeerFixture::new("node-initiator");
    let hello = peer.signed_hello([0x11; 16]);
    let replayed_hello = hello.clone();

    assert_eq!(
        hello.transcript_bytes().expect("hello transcript"),
        replayed_hello
            .transcript_bytes()
            .expect("replayed transcript"),
        "captured Hello replay should preserve the transcript inputs exactly"
    );

    let mut window = HelloReplayWindow::default();
    verify_hello(&hello, &peer, &mut window).expect("first hello accepted");

    assert!(
        matches!(
            verify_hello(&replayed_hello, &peer, &mut window),
            Err(SessionError::DuplicateHelloNonce)
        ),
        "same Hello nonce must be rejected while the responder's active window still tracks it"
    );
}

#[test]
fn distinct_hello_nonces_remain_acceptable_within_same_window() {
    let peer = HelloPeerFixture::new("node-initiator");
    let hello_a = peer.signed_hello([0x21; 16]);
    let hello_b = peer.signed_hello([0x22; 16]);

    assert_ne!(
        hello_a.transcript_bytes().expect("hello a transcript"),
        hello_b.transcript_bytes().expect("hello b transcript"),
        "changing the Hello nonce must change the transcript inputs"
    );

    let mut window = HelloReplayWindow::default();
    verify_hello(&hello_a, &peer, &mut window).expect("accept first nonce");
    verify_hello(&hello_b, &peer, &mut window).expect("accept second nonce");
}

#[test]
fn same_nonce_from_distinct_initiators_remains_acceptable() {
    let peer_a = HelloPeerFixture::new("node-initiator-a");
    let peer_b = HelloPeerFixture::new("node-initiator-b");
    let hello_a = peer_a.signed_hello([0x31; 16]);
    let hello_b = peer_b.signed_hello([0x31; 16]);

    let mut window = HelloReplayWindow::default();
    verify_hello(&hello_a, &peer_a, &mut window).expect("accept first initiator");
    verify_hello(&hello_b, &peer_b, &mut window).expect("accept second initiator");
}

#[test]
fn invalid_signature_does_not_burn_replay_nonce() {
    // Security invariant: a tampered Hello must NOT poison the replay window.
    // Otherwise, an attacker that observes a fresh nonce could pre-emptively
    // submit a forged Hello with the same nonce and lock out the legitimate
    // initiator. The replay window must only record verified Hellos.
    let peer = HelloPeerFixture::new("node-initiator");
    let nonce = [0x44; 16];

    let mut tampered = peer.signed_hello(nonce);
    let attacker = Ed25519SigningKey::generate();
    tampered
        .sign(&attacker)
        .expect("re-sign tampered hello with attacker key");

    let mut window = HelloReplayWindow::default();
    assert!(
        matches!(
            verify_hello(&tampered, &peer, &mut window),
            Err(SessionError::InvalidSignature)
        ),
        "tampered hello must fail signature verification"
    );
    assert!(
        window.check(&tampered),
        "rejected hello must not be recorded in the replay window"
    );

    let legit = peer.signed_hello(nonce);
    verify_hello(&legit, &peer, &mut window)
        .expect("legitimate hello with same nonce must still be accepted after a forgery attempt");
}

#[test]
fn timestamp_skew_rejection_does_not_burn_replay_nonce() {
    // Stale Hellos must be rejected with TimestampSkew, and the replay window
    // must not retain their nonce — otherwise a delayed packet could lock out
    // a legitimate retry that uses the same nonce.
    let peer = HelloPeerFixture::new("node-initiator");
    let nonce = [0x55; 16];

    let mut stale = peer.signed_hello(nonce);
    let policy = TimePolicy::default();
    stale.timestamp = current_timestamp().saturating_sub(policy.max_skew_secs * 100);
    stale
        .sign(&peer.signing_key)
        .expect("re-sign with stale timestamp");

    let mut window = HelloReplayWindow::default();
    assert!(
        matches!(
            verify_hello_attested_with_replay(&stale, &peer.identity, &policy, &mut window),
            Err(SessionError::TimestampSkew { .. })
        ),
        "stale hello must be rejected with TimestampSkew"
    );
    assert!(
        window.check(&stale),
        "stale hello must not be recorded in the replay window"
    );

    let fresh = peer.signed_hello(nonce);
    verify_hello(&fresh, &peer, &mut window)
        .expect("fresh hello with same nonce must still be accepted after a stale rejection");
}

#[test]
fn attestation_node_mismatch_does_not_burn_replay_nonce() {
    // If the responder verifies a Hello against the wrong identity (or an
    // attacker presents a Hello whose `from` does not match the identity it
    // claims), the responder must reject with AttestationNodeMismatch and
    // leave the replay window untouched.
    let peer_a = HelloPeerFixture::new("node-initiator-a");
    let peer_b = HelloPeerFixture::new("node-initiator-b");
    let nonce = [0x66; 16];

    let hello_a = peer_a.signed_hello(nonce);
    let mut window = HelloReplayWindow::default();
    assert!(
        matches!(
            verify_hello(&hello_a, &peer_b, &mut window),
            Err(SessionError::AttestationNodeMismatch)
        ),
        "hello.from must match identity.node_id"
    );
    assert!(
        window.check(&hello_a),
        "mismatched-attestation hello must not be recorded in the replay window"
    );

    verify_hello(&hello_a, &peer_a, &mut window)
        .expect("legitimate hello must still be accepted after an attestation-mismatch rejection");
}

#[test]
fn evicted_hello_nonce_can_be_re_accepted_after_window_overflow() {
    // FIFO retention is bounded; once a nonce has been evicted from the active
    // window, the responder must accept it again. This locks the documented
    // bounded-retention behaviour and prevents regressions to unbounded growth.
    let peer = HelloPeerFixture::new("node-initiator");
    let mut window = HelloReplayWindow::new(2);

    let hello_a = peer.signed_hello([0xA1; 16]);
    let hello_b = peer.signed_hello([0xA2; 16]);
    let hello_c = peer.signed_hello([0xA3; 16]);

    verify_hello(&hello_a, &peer, &mut window).expect("first hello accepted");
    verify_hello(&hello_b, &peer, &mut window).expect("second hello accepted");
    verify_hello(&hello_c, &peer, &mut window).expect("third hello accepted, evicts the first");

    let hello_a_again = peer.signed_hello([0xA1; 16]);
    verify_hello(&hello_a_again, &peer, &mut window)
        .expect("evicted nonce becomes acceptable again once it leaves the active window");

    // Re-accepting A pushes B out of the FIFO (capacity=2), so the active
    // window is now {C, A}. C must still be rejected as a duplicate while it
    // is tracked, otherwise the FIFO is no longer enforcing replay protection
    // for the most-recent entries.
    let replay_c = hello_c.clone();
    assert!(
        matches!(
            verify_hello(&replay_c, &peer, &mut window),
            Err(SessionError::DuplicateHelloNonce)
        ),
        "C must still be rejected — it was the most recently added entry before A re-acceptance"
    );
}
