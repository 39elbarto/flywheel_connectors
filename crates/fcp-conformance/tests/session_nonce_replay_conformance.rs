//! Session handshake nonce-replay conformance.
//!
//! These tests exercise the production responder-side hello replay helper so a
//! regression in handshake nonce tracking fails conformance directly.

use fcp_core::TailscaleNodeId;
use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
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
        replayed_hello.transcript_bytes().expect("replayed transcript"),
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
