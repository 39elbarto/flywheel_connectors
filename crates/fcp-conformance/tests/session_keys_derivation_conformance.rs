//! Session key-derivation conformance.
//!
//! `derive_session_keys` is the HKDF-based key schedule that produces
//! the three per-session keys (`k_mac_i2r`, `k_mac_r2i`, `k_ctx`) from
//! the ECDH shared secret and the handshake transcript:
//!
//! ```text
//! HKDF-SHA256(salt = session_id, ikm = shared_secret,
//!   info = "FCP2-SESSION-V1" || initiator_node_id || responder_node_id
//!          || hello_nonce || ack_nonce)
//! ```
//!
//! Every byte of that schedule has a security purpose. A regression
//! that dropped one of the inputs would silently allow cross-session
//! key collisions, replay-after-rekey, or role confusion. These tests
//! pin the public `fcp_protocol::session::derive_session_keys` API so
//! a divergence fails conformance directly.
//!
//! Properties pinned:
//! - determinism (verifier and initiator must agree, twice)
//! - three-key distinctness (k_mac_i2r, k_mac_r2i, k_ctx all differ)
//! - input-binding for each of shared_secret, session_id,
//!   initiator_node_id, responder_node_id, hello_nonce, ack_nonce
//! - role asymmetry (initiator/responder swap produces different keys)

use fcp_core::TailscaleNodeId;
use fcp_crypto::{X25519SecretKey, X25519SharedSecret};
use fcp_protocol::session::{MeshSessionId, SessionKeys, SessionNonce, derive_session_keys};

const ALICE_SK: [u8; 32] = [0xA1; 32];
const BOB_SK: [u8; 32] = [0xB2; 32];
const CHARLIE_SK: [u8; 32] = [0xC3; 32];
const SESSION_A: MeshSessionId = MeshSessionId([0x11; 16]);
const SESSION_B: MeshSessionId = MeshSessionId([0x22; 16]);
const HELLO_NONCE_1: SessionNonce = SessionNonce([0x71; 16]);
const HELLO_NONCE_2: SessionNonce = SessionNonce([0x72; 16]);
const ACK_NONCE_1: SessionNonce = SessionNonce([0xA1; 16]);
const ACK_NONCE_2: SessionNonce = SessionNonce([0xA2; 16]);

fn shared_secret_for(local_sk: [u8; 32], peer_sk: [u8; 32]) -> X25519SharedSecret {
    let local = X25519SecretKey::from_bytes(local_sk);
    let peer = X25519SecretKey::from_bytes(peer_sk);
    local
        .diffie_hellman(&peer.public_key())
        .expect("DH must succeed for non-low-order keys")
}

fn alice_initiator() -> TailscaleNodeId {
    TailscaleNodeId::new("node-alice")
}

fn bob_responder() -> TailscaleNodeId {
    TailscaleNodeId::new("node-bob")
}

fn baseline_keys() -> SessionKeys {
    derive_session_keys(
        &shared_secret_for(ALICE_SK, BOB_SK),
        &SESSION_A,
        &alice_initiator(),
        &bob_responder(),
        &HELLO_NONCE_1,
        &ACK_NONCE_1,
    )
    .expect("baseline derivation")
}

#[test]
fn derivation_is_deterministic_for_fixed_inputs() {
    // Both peers must derive the same keys; the contract requires the
    // function be a pure mapping from its inputs.
    let k1 = baseline_keys();
    let k2 = baseline_keys();
    assert_eq!(k1, k2, "derive_session_keys must be deterministic");
}

#[test]
fn three_derived_keys_are_distinct() {
    // The schedule expands HKDF to 96 bytes and partitions into three
    // 32-byte keys. They MUST differ — otherwise a per-direction MAC
    // would equal the context key, breaking domain separation.
    let keys = baseline_keys();
    assert_ne!(
        keys.k_mac_i2r, keys.k_mac_r2i,
        "k_mac_i2r and k_mac_r2i must differ — directional MAC keys are the \
         core defense against cross-direction frame replay"
    );
    assert_ne!(
        keys.k_mac_i2r, keys.k_ctx,
        "k_mac_i2r and k_ctx must differ — domain separation between MAC and \
         context-encryption key material"
    );
    assert_ne!(
        keys.k_mac_r2i, keys.k_ctx,
        "k_mac_r2i and k_ctx must differ — domain separation"
    );
}

#[test]
fn keys_bind_to_shared_secret() {
    let keys_alice_bob = baseline_keys();
    let keys_alice_charlie = derive_session_keys(
        &shared_secret_for(ALICE_SK, CHARLIE_SK),
        &SESSION_A,
        &alice_initiator(),
        &bob_responder(),
        &HELLO_NONCE_1,
        &ACK_NONCE_1,
    )
    .expect("alternate-secret derivation");
    assert_ne!(
        keys_alice_bob, keys_alice_charlie,
        "different ECDH shared secrets MUST yield different session keys — \
         otherwise an attacker who learns one peering's keys can read others"
    );
}

#[test]
fn keys_bind_to_session_id() {
    // session_id is the HKDF salt. Two sessions running between the
    // same peers with the same nonces but different session_ids MUST
    // produce different keys, otherwise rekey ceremonies that change
    // only the session_id are no-ops.
    let keys_a = baseline_keys();
    let keys_b = derive_session_keys(
        &shared_secret_for(ALICE_SK, BOB_SK),
        &SESSION_B,
        &alice_initiator(),
        &bob_responder(),
        &HELLO_NONCE_1,
        &ACK_NONCE_1,
    )
    .expect("alternate-session-id derivation");
    assert_ne!(
        keys_a, keys_b,
        "different MeshSessionId (HKDF salt) MUST yield different keys"
    );
}

#[test]
fn keys_bind_to_initiator_node_id() {
    let keys_alice = baseline_keys();
    let keys_eve = derive_session_keys(
        &shared_secret_for(ALICE_SK, BOB_SK),
        &SESSION_A,
        &TailscaleNodeId::new("node-eve"),
        &bob_responder(),
        &HELLO_NONCE_1,
        &ACK_NONCE_1,
    )
    .expect("alternate-initiator derivation");
    assert_ne!(
        keys_alice, keys_eve,
        "initiator_node_id MUST be mixed into the HKDF info — the schedule's \
         transcript binding depends on it"
    );
}

#[test]
fn keys_bind_to_responder_node_id() {
    let keys_bob = baseline_keys();
    let keys_dave = derive_session_keys(
        &shared_secret_for(ALICE_SK, BOB_SK),
        &SESSION_A,
        &alice_initiator(),
        &TailscaleNodeId::new("node-dave"),
        &HELLO_NONCE_1,
        &ACK_NONCE_1,
    )
    .expect("alternate-responder derivation");
    assert_ne!(
        keys_bob, keys_dave,
        "responder_node_id MUST be mixed into the HKDF info — otherwise an \
         attacker can substitute the responder identity unnoticed"
    );
}

#[test]
fn keys_bind_to_hello_nonce() {
    let keys_n1 = baseline_keys();
    let keys_n2 = derive_session_keys(
        &shared_secret_for(ALICE_SK, BOB_SK),
        &SESSION_A,
        &alice_initiator(),
        &bob_responder(),
        &HELLO_NONCE_2,
        &ACK_NONCE_1,
    )
    .expect("alternate-hello-nonce derivation");
    assert_ne!(
        keys_n1, keys_n2,
        "hello_nonce MUST contribute to the schedule — replay defense"
    );
}

#[test]
fn keys_bind_to_ack_nonce() {
    let keys_a1 = baseline_keys();
    let keys_a2 = derive_session_keys(
        &shared_secret_for(ALICE_SK, BOB_SK),
        &SESSION_A,
        &alice_initiator(),
        &bob_responder(),
        &HELLO_NONCE_1,
        &ACK_NONCE_2,
    )
    .expect("alternate-ack-nonce derivation");
    assert_ne!(
        keys_a1, keys_a2,
        "ack_nonce MUST contribute to the schedule — symmetric replay defense"
    );
}

#[test]
fn role_swap_produces_different_keys() {
    // Swapping initiator and responder identities produces a different
    // info string (the order of node ids is part of the transcript),
    // so the schedule MUST yield different keys. Otherwise a frame
    // signed under k_mac_i2r in session "alice→bob" would also verify
    // under k_mac_i2r in session "bob→alice".
    let alice_to_bob = baseline_keys();
    let bob_to_alice = derive_session_keys(
        &shared_secret_for(ALICE_SK, BOB_SK),
        &SESSION_A,
        &bob_responder(),
        &alice_initiator(),
        &HELLO_NONCE_1,
        &ACK_NONCE_1,
    )
    .expect("role-swapped derivation");
    assert_ne!(
        alice_to_bob, bob_to_alice,
        "role swap (initiator <-> responder) MUST yield different keys — \
         otherwise the i2r/r2i directional split degenerates to a single key \
         that is reusable across the role boundary"
    );
}

#[test]
fn dh_symmetry_yields_identical_keys_for_both_peers() {
    // The X25519 DH property: alice.dh(bob.pub) == bob.dh(alice.pub).
    // Both peers feed the same shared_secret + identical transcript
    // into derive_session_keys, so they MUST agree on the resulting
    // keys. This is the property that makes the session usable at all.
    let alice = X25519SecretKey::from_bytes(ALICE_SK);
    let bob = X25519SecretKey::from_bytes(BOB_SK);
    let shared_alice = alice.diffie_hellman(&bob.public_key()).expect("alice DH");
    let shared_bob = bob.diffie_hellman(&alice.public_key()).expect("bob DH");
    assert_eq!(
        shared_alice.as_bytes(),
        shared_bob.as_bytes(),
        "X25519 DH must be symmetric"
    );

    let keys_alice = derive_session_keys(
        &shared_alice,
        &SESSION_A,
        &alice_initiator(),
        &bob_responder(),
        &HELLO_NONCE_1,
        &ACK_NONCE_1,
    )
    .expect("alice derivation");
    let keys_bob = derive_session_keys(
        &shared_bob,
        &SESSION_A,
        &alice_initiator(),
        &bob_responder(),
        &HELLO_NONCE_1,
        &ACK_NONCE_1,
    )
    .expect("bob derivation");
    assert_eq!(
        keys_alice, keys_bob,
        "both peers must derive identical session keys — without this the \
         session is unusable"
    );
}
