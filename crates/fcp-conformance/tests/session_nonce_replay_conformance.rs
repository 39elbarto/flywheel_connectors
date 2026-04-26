//! Session handshake nonce-replay conformance.
//!
//! The handshake surface exposes the real `MeshSessionHello` transcript inputs,
//! but responder-side duplicate-Hello rejection is a conformance invariant rather
//! than a reusable public helper today. These tests pin the normative behavior:
//! a responder must reject a replayed Hello nonce within the active window while
//! still allowing distinct concurrent Hellos from the same initiator.

use std::collections::HashSet;

use fcp_core::TailscaleNodeId;
use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
use fcp_protocol::session::{MeshSessionHello, SessionCryptoSuite, SessionNonce};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelloReplayError {
    DuplicateHelloNonce,
}

#[derive(Default)]
struct ActiveHelloWindow {
    seen_nonces: HashSet<SessionNonce>,
}

impl ActiveHelloWindow {
    fn accept(&mut self, hello: &MeshSessionHello) -> Result<(), HelloReplayError> {
        if self.seen_nonces.insert(hello.nonce) {
            Ok(())
        } else {
            Err(HelloReplayError::DuplicateHelloNonce)
        }
    }
}

fn signed_hello(nonce: [u8; 16]) -> MeshSessionHello {
    let signing_key = Ed25519SigningKey::generate();
    let eph_key = X25519SecretKey::generate();

    let mut hello = MeshSessionHello {
        from: TailscaleNodeId::new("node-initiator"),
        to: TailscaleNodeId::new("node-responder"),
        eph_pubkey: eph_key.public_key(),
        nonce: SessionNonce(nonce),
        cookie: None,
        timestamp: 1_704_067_200,
        suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
        transport_limits: None,
        signature: None,
    };
    hello.sign(&signing_key).expect("sign hello");
    hello
        .verify(&signing_key.verifying_key())
        .expect("verify hello");
    hello
}

#[test]
fn duplicate_hello_nonce_is_rejected_within_active_window() {
    let hello = signed_hello([0x11; 16]);
    let replayed_hello = hello.clone();

    assert_eq!(
        hello.transcript_bytes().expect("hello transcript"),
        replayed_hello.transcript_bytes().expect("replayed transcript"),
        "captured Hello replay should preserve the transcript inputs exactly"
    );

    let mut window = ActiveHelloWindow::default();
    window.accept(&hello).expect("first hello accepted");

    assert_eq!(
        window.accept(&replayed_hello),
        Err(HelloReplayError::DuplicateHelloNonce),
        "same Hello nonce must be rejected while the responder's active window still tracks it"
    );
}

#[test]
fn distinct_hello_nonces_remain_acceptable_within_same_window() {
    let hello_a = signed_hello([0x21; 16]);
    let hello_b = signed_hello([0x22; 16]);

    assert_ne!(
        hello_a.transcript_bytes().expect("hello a transcript"),
        hello_b.transcript_bytes().expect("hello b transcript"),
        "changing the Hello nonce must change the transcript inputs"
    );

    let mut window = ActiveHelloWindow::default();
    window.accept(&hello_a).expect("accept first nonce");
    window.accept(&hello_b).expect("accept second nonce");
}
