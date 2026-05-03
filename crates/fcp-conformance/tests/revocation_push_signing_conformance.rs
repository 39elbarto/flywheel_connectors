//! `RevocationPushMessage` two-tier signing conformance.
//!
//! `RevocationPushMessage` carries two independent signatures:
//!
//! 1. **Owner signature** over `owner_signing_bytes` — the zone owner
//!    signs `(zone_id || revoked_ids || new_rev_seq)` and deliberately
//!    OMITS `from` and `timestamp` so the same signature stays valid
//!    across every forwarding peer at every forwarding time. This is
//!    the property `MeshNode::handle_revocation_push` relies on to
//!    accept a relayed push without re-attesting it.
//!
//! 2. **Node signature** over `signing_bytes` — each forwarder signs
//!    the full delivery envelope including their own `from` and the
//!    `timestamp`. This authenticates the *delivery*, not the content,
//!    and prevents an attacker from re-attributing a captured push to
//!    a different forwarder.
//!
//! The two transcripts have non-trivially different field sets and
//! the symmetry between them is the entire reason the design works.
//! These tests pin the public `fcp_mesh::gossip::RevocationPushMessage`
//! API so a regression that mixed `from` or `timestamp` into
//! `owner_signing_bytes` (breaking portability) or that dropped
//! `from`/`timestamp` from `signing_bytes` (breaking forwarder
//! attribution) fails conformance directly.

use fcp_crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use fcp_mesh::gossip::RevocationPushMessage;
use fcp_prelude::{NodeId, NodeSignature as CoreNodeSignature, ObjectId, TailscaleNodeId, ZoneId};

fn obj(label: &[u8]) -> ObjectId {
    ObjectId::from_unscoped_bytes(label)
}

fn baseline_message() -> RevocationPushMessage {
    let mut ids = vec![obj(b"obj-A"), obj(b"obj-B"), obj(b"obj-C")];
    ids.sort();
    RevocationPushMessage::new(
        TailscaleNodeId::new("node-forwarder-1"),
        ZoneId::work(),
        ids,
        42,
        1_700_000_000,
    )
}

fn sign_owner(message: &mut RevocationPushMessage, signing_key: &Ed25519SigningKey) {
    let transcript = message.owner_signing_bytes();
    let sig = signing_key.sign(&transcript).to_bytes();
    message.owner_signature = Some(CoreNodeSignature::new(
        NodeId::new("owner"),
        sig,
        message.timestamp,
    ));
}

fn sign_node(message: &mut RevocationPushMessage, signing_key: &Ed25519SigningKey) {
    let transcript = message.signing_bytes();
    let sig = signing_key.sign(&transcript).to_bytes();
    message.signature = Some(CoreNodeSignature::new(
        NodeId::new(message.from.as_str()),
        sig,
        message.timestamp,
    ));
}

#[test]
fn owner_signature_round_trip_passes_verify_owner_signature() {
    let owner = Ed25519SigningKey::generate();
    let mut msg = baseline_message();
    sign_owner(&mut msg, &owner);

    msg.verify_owner_signature(&owner.verifying_key())
        .expect("well-formed owner signature must verify");
}

#[test]
fn node_signature_round_trip_passes_verify_signature() {
    let node = Ed25519SigningKey::generate();
    let mut msg = baseline_message();
    sign_node(&mut msg, &node);

    msg.verify_signature(&node.verifying_key())
        .expect("well-formed node signature must verify");
}

#[test]
fn owner_signing_bytes_excludes_from_so_signature_is_portable_across_forwarders() {
    // The whole point of the owner sig is that any peer can forward
    // the push without invalidating the owner's signature. Mutating
    // `from` between the original sign and a downstream verify MUST
    // still verify under the owner's key.
    let owner = Ed25519SigningKey::generate();
    let mut original = baseline_message();
    sign_owner(&mut original, &owner);

    let mut forwarded = original.clone();
    forwarded.from = TailscaleNodeId::new("node-forwarder-2");

    forwarded
        .verify_owner_signature(&owner.verifying_key())
        .expect("owner signature must remain valid after a forwarder rewrites `from`");
}

#[test]
fn owner_signing_bytes_excludes_timestamp_so_signature_is_portable_in_time() {
    // Same reasoning applies to `timestamp` — a delayed forwarder
    // updates the delivery timestamp but the content signature stays
    // valid.
    let owner = Ed25519SigningKey::generate();
    let mut original = baseline_message();
    sign_owner(&mut original, &owner);

    let mut delayed = original.clone();
    delayed.timestamp = original.timestamp.saturating_add(86_400);

    delayed
        .verify_owner_signature(&owner.verifying_key())
        .expect("owner signature must remain valid after a forwarder updates `timestamp`");
}

#[test]
fn owner_signing_bytes_binds_to_zone_id() {
    // Mutating `zone_id` after signing MUST invalidate the owner sig —
    // otherwise an attacker could re-target the revocation list at a
    // different zone.
    let owner = Ed25519SigningKey::generate();
    let mut original = baseline_message();
    sign_owner(&mut original, &owner);

    let mut tampered = original.clone();
    tampered.zone_id = ZoneId::private();

    tampered
        .verify_owner_signature(&owner.verifying_key())
        .expect_err("owner signature must reject zone_id tamper");
}

#[test]
fn owner_signing_bytes_binds_to_revoked_ids() {
    // The list of revoked ids is the central security claim. Adding,
    // removing, or replacing any entry MUST invalidate the owner sig.
    let owner = Ed25519SigningKey::generate();
    let mut original = baseline_message();
    sign_owner(&mut original, &owner);

    let mut tampered = original.clone();
    tampered.revoked_ids.push(obj(b"obj-injected"));

    tampered
        .verify_owner_signature(&owner.verifying_key())
        .expect_err("owner signature must reject an injected revoked_id");
}

#[test]
fn owner_signing_bytes_binds_to_new_rev_seq() {
    // new_rev_seq is the revocation head sequence after this push.
    // Lying about it would let an attacker slot stale revocations into
    // future positions.
    let owner = Ed25519SigningKey::generate();
    let mut original = baseline_message();
    sign_owner(&mut original, &owner);

    let mut tampered = original.clone();
    tampered.new_rev_seq = original.new_rev_seq.wrapping_add(1);

    tampered
        .verify_owner_signature(&owner.verifying_key())
        .expect_err("owner signature must reject new_rev_seq tamper");
}

#[test]
fn node_signing_bytes_bind_to_from() {
    // Unlike the owner sig, the node sig DOES include `from`. A
    // captured push from forwarder-1 MUST NOT verify under
    // forwarder-2's claimed identity — that prevents an attacker who
    // reads the wire from re-presenting the push as if forwarder-2
    // sent it.
    let node = Ed25519SigningKey::generate();
    let mut original = baseline_message();
    sign_node(&mut original, &node);

    let mut tampered = original.clone();
    tampered.from = TailscaleNodeId::new("node-forwarder-2");

    tampered
        .verify_signature(&node.verifying_key())
        .expect_err("node signature must bind to from (forwarder attribution)");
}

#[test]
fn node_signing_bytes_bind_to_timestamp() {
    // The node sig also includes timestamp — without it, an attacker
    // could replay an old push as if it were fresh.
    let node = Ed25519SigningKey::generate();
    let mut original = baseline_message();
    sign_node(&mut original, &node);

    let mut tampered = original.clone();
    tampered.timestamp = original.timestamp.saturating_add(60);

    tampered
        .verify_signature(&node.verifying_key())
        .expect_err("node signature must bind to timestamp");
}

#[test]
fn owner_sig_under_wrong_key_is_rejected() {
    let owner = Ed25519SigningKey::generate();
    let attacker = Ed25519SigningKey::generate();
    assert_ne!(
        Ed25519VerifyingKey::to_bytes(&owner.verifying_key()),
        Ed25519VerifyingKey::to_bytes(&attacker.verifying_key()),
        "fixture sanity: owner and attacker keys differ"
    );

    let mut msg = baseline_message();
    sign_owner(&mut msg, &owner);

    msg.verify_owner_signature(&attacker.verifying_key())
        .expect_err("owner signature must not verify under a different key");
}

#[test]
fn revoked_ids_order_is_part_of_the_owner_transcript() {
    // The docstring on owner_signing_bytes states `revoked_ids` is
    // iterated in the slice's declared order and recommends sorting
    // by ObjectId before signing. Reordering after signing MUST
    // invalidate the owner signature — that's what gives callers a
    // meaningful "agree on order" contract.
    let owner = Ed25519SigningKey::generate();
    let mut original = baseline_message();
    sign_owner(&mut original, &owner);

    let mut reordered = original.clone();
    reordered.revoked_ids.reverse();
    assert_ne!(
        original.revoked_ids, reordered.revoked_ids,
        "fixture sanity: the reversal must change the order"
    );

    reordered
        .verify_owner_signature(&owner.verifying_key())
        .expect_err("owner signature must bind to revoked_ids order");
}
