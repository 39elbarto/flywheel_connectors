#![no_main]

//! Metamorphic fuzz target for `fcp_tailscale::NodeKeyAttestation`
//! sign/verify (identity.rs:302-387).
//!
//! `NodeKeyAttestation::sign` produces an Ed25519 signature over the
//! canonical-CBOR encoding of `(node_id, signing_kid, encryption_kid,
//! issuance_kid, sorted-dedup'd tags, issued_at, expires_at)` keyed by
//! the schema string `"fcp.attestation.v1"`. The resulting attestation
//! is what the mesh trusts when emitting a node's zone memberships:
//! `MeshIdentity::fcp_tags()` and `verified_fcp_tags()`
//! (identity.rs:227-246) refuse to surface tags unless `verify` returns
//! `Ok`. A binding regression in sign/verify therefore lets an attacker
//! spoof zone tags or substitute a key for one they control.
//!
//! Existing fuzz coverage:
//!   - `tailscale_acl`            — ZoneTagMapping zone↔tag round-trip
//!   - `tailscale_status_parse`   — TailscaleStatus JSON + peers()
//!
//! NOT covered: the attestation sign/verify binding properties.
//!
//! Properties asserted:
//!
//!   1. **Round-trip**: `sign(...) → verify(...)` succeeds for the same
//!      tuple with sufficient `validity_hours`.
//!   2. **Tag canonicalization**: signing with `tags=[A,B,C]` MUST verify
//!      under `tags=[C,B,A]` (sort) AND under `tags=[A,A,B,C]` (dedup) —
//!      `canonical_tag_strings` (identity.rs:266-271) does sort_unstable
//!      + dedup before signing.
//!   3. **Node-id binding**: verify with a different node_id MUST yield
//!      `InvalidAttestation`.
//!   4. **Key-set binding**: verify with `NodeKeys` whose signing,
//!      encryption, OR issuance verifying-key differs MUST yield
//!      `InvalidAttestation` — guards against per-role key substitution.
//!   5. **Tag-list binding**: verify with a tag set whose canonical
//!      sorted-dedup'd form differs from the signing form MUST yield
//!      `InvalidAttestation`.
//!   6. **Owner-key binding**: verify with a different owner pubkey MUST
//!      yield `InvalidAttestation` (the early signer_kid != key_id check
//!      at identity.rs:361 closes this).
//!
//!   Once-gated regression anchor:
//!     Sort and dedup are independently exercised on a hand-constructed
//!     tag pair so both halves of canonical_tag_strings are checked on
//!     every fuzz invocation, not only on fuzzer-discovered inputs.

use arbitrary::{Arbitrary, Unstructured};
use fcp_crypto::{Ed25519SigningKey, X25519SecretKey};
use fcp_tailscale::{NodeId, NodeKeyAttestation, NodeKeys, TailscaleError, TailscaleTag};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const ED25519_SK_SIZE: usize = 32;
const X25519_SK_SIZE: usize = 32;
const VALIDITY_HOURS: u32 = 24 * 365; // a year — keeps verify well clear of expiry

static TAG_CANONICALIZATION_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    owner_seed: [u8; ED25519_SK_SIZE],
    /// Alt owner key for the owner-binding MR.
    alt_owner_seed: [u8; ED25519_SK_SIZE],
    /// Three Ed25519 / X25519 secret seeds for the node's keys.
    node_signing_seed: [u8; ED25519_SK_SIZE],
    node_encryption_seed: [u8; X25519_SK_SIZE],
    node_issuance_seed: [u8; ED25519_SK_SIZE],
    /// Alt seeds for the per-role key-binding MRs.
    alt_signing_seed: [u8; ED25519_SK_SIZE],
    alt_encryption_seed: [u8; X25519_SK_SIZE],
    alt_issuance_seed: [u8; ED25519_SK_SIZE],
    /// Discriminator: which role to swap in the key-set binding MR.
    role_disc: u8,
}

fn make_owner(seed: &[u8; ED25519_SK_SIZE]) -> Option<Ed25519SigningKey> {
    Ed25519SigningKey::from_bytes(seed).ok()
}

fn make_node_keys(
    signing: &[u8; ED25519_SK_SIZE],
    encryption: &[u8; X25519_SK_SIZE],
    issuance: &[u8; ED25519_SK_SIZE],
) -> Option<NodeKeys> {
    let s = Ed25519SigningKey::from_bytes(signing).ok()?;
    let i = Ed25519SigningKey::from_bytes(issuance).ok()?;
    let e = X25519SecretKey::from_bytes(*encryption);
    Some(NodeKeys::new(
        s.verifying_key(),
        e.public_key(),
        i.verifying_key(),
    ))
}

fn make_tags(strs: &[&str]) -> Vec<TailscaleTag> {
    strs.iter()
        .filter_map(|s| TailscaleTag::new(*s).ok())
        .collect()
}

fuzz_target!(|data: &[u8]| {
    TAG_CANONICALIZATION_ANCHOR.call_once(assert_tag_canonicalization_anchored);

    let mut u = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut u) else {
        return;
    };

    // Build the principal owner + node identities. Ed25519SigningKey::from_bytes
    // can fail on degenerate seeds; bail in that case (covered separately by
    // fuzz_ed25519_verify).
    let Some(owner) = make_owner(&input.owner_seed) else {
        return;
    };
    let owner_pub = owner.verifying_key();

    let Some(node_keys) = make_node_keys(
        &input.node_signing_seed,
        &input.node_encryption_seed,
        &input.node_issuance_seed,
    ) else {
        return;
    };

    let node_id = NodeId::new("node-principal");

    // Three FCP-prefixed tags exercising both sort and dedup paths.
    let tags = make_tags(&["tag:fcp-work", "tag:fcp-private", "tag:server"]);
    if tags.len() < 3 {
        return;
    }

    // ── PROPERTY 1: round-trip ─────────────────────────────────────────
    let Ok(att) = NodeKeyAttestation::sign(&owner, &node_id, &node_keys, &tags, VALIDITY_HOURS)
    else {
        return;
    };
    att.verify(&owner_pub, &node_id, &node_keys, &tags)
        .expect("attestation MUST round-trip under identical (node, keys, tags, owner)");

    // ── PROPERTY 2: tag canonicalization (reorder + dedup) ─────────────
    let mut reordered = tags.clone();
    reordered.reverse();
    att.verify(&owner_pub, &node_id, &node_keys, &reordered)
        .expect("attestation MUST verify under reversed tag order — sort regression");

    let mut with_dups = tags.clone();
    with_dups.push(tags[0].clone()); // duplicate of first tag
    with_dups.push(tags[1].clone()); // duplicate of second tag
    att.verify(&owner_pub, &node_id, &node_keys, &with_dups)
        .expect("attestation MUST verify when tag list contains duplicates — dedup regression");

    // ── PROPERTY 3: node-id binding ────────────────────────────────────
    let alt_node_id = NodeId::new("node-impostor");
    match att.verify(&owner_pub, &alt_node_id, &node_keys, &tags) {
        Err(TailscaleError::InvalidAttestation) => {}
        Ok(()) => panic!(
            "attestation verified under a different node_id — node-id binding broken; \
             attacker could pivot a captured attestation to a different node"
        ),
        Err(other) => panic!("unexpected error {other:?} for wrong-node verify"),
    }

    // ── PROPERTY 4: key-set binding (per-role) ─────────────────────────
    // Substitute a single role's verifying key with one derived from the
    // alt seed and assert verify rejects.
    let role_swap = mutate_one_node_key(
        &node_keys,
        input.role_disc,
        &input.alt_signing_seed,
        &input.alt_encryption_seed,
        &input.alt_issuance_seed,
    );
    if let Some(alt_keys) = role_swap {
        // Skip if the alt seed happened to derive the same key (vanishingly
        // unlikely for Ed25519 / X25519 but guarded for soundness).
        let same = node_keys.signing_kid() == alt_keys.signing_kid()
            && node_keys.encryption_kid() == alt_keys.encryption_kid()
            && node_keys.issuance_kid() == alt_keys.issuance_kid();
        if !same {
            match att.verify(&owner_pub, &node_id, &alt_keys, &tags) {
                Err(TailscaleError::InvalidAttestation) => {}
                Ok(()) => panic!(
                    "attestation verified under altered NodeKeys (role_disc={}) — \
                     per-role key binding broken; attacker could substitute their own \
                     key for a node role",
                    input.role_disc
                ),
                Err(other) => panic!("unexpected error {other:?} for key-swap verify"),
            }
        }
    }

    // ── PROPERTY 5: tag-list binding ───────────────────────────────────
    // Append a fresh tag whose canonical form is NOT in the signed set.
    let mut altered_tags = tags.clone();
    if let Ok(extra) = TailscaleTag::new("tag:fcp-extra") {
        altered_tags.push(extra);
        match att.verify(&owner_pub, &node_id, &node_keys, &altered_tags) {
            Err(TailscaleError::InvalidAttestation) => {}
            Ok(()) => panic!(
                "attestation verified under tags=[..signed.., +extra] — tag-list \
                 binding broken; attacker could promote a node into an unintended zone"
            ),
            Err(other) => panic!("unexpected error {other:?} for extra-tag verify"),
        }
    }

    // ── PROPERTY 6: owner-key binding ──────────────────────────────────
    if let Some(alt_owner) = make_owner(&input.alt_owner_seed) {
        let alt_owner_pub = alt_owner.verifying_key();
        if alt_owner_pub.key_id() != owner_pub.key_id() {
            match att.verify(&alt_owner_pub, &node_id, &node_keys, &tags) {
                Err(TailscaleError::InvalidAttestation) => {}
                Ok(()) => panic!(
                    "attestation verified under a different owner pubkey — \
                     owner binding broken (signer_kid mismatch path at identity.rs:361)"
                ),
                Err(other) => panic!("unexpected error {other:?} for wrong-owner verify"),
            }
        }
    }
});

fn mutate_one_node_key(
    base: &NodeKeys,
    role_disc: u8,
    alt_signing_seed: &[u8; ED25519_SK_SIZE],
    alt_encryption_seed: &[u8; X25519_SK_SIZE],
    alt_issuance_seed: &[u8; ED25519_SK_SIZE],
) -> Option<NodeKeys> {
    match role_disc % 3 {
        0 => {
            let alt_signing = Ed25519SigningKey::from_bytes(alt_signing_seed).ok()?;
            Some(NodeKeys::new(
                alt_signing.verifying_key(),
                base.encryption_key.clone(),
                base.issuance_key.clone(),
            ))
        }
        1 => {
            let alt_encryption = X25519SecretKey::from_bytes(*alt_encryption_seed);
            Some(NodeKeys::new(
                base.signing_key.clone(),
                alt_encryption.public_key(),
                base.issuance_key.clone(),
            ))
        }
        _ => {
            let alt_issuance = Ed25519SigningKey::from_bytes(alt_issuance_seed).ok()?;
            Some(NodeKeys::new(
                base.signing_key.clone(),
                base.encryption_key.clone(),
                alt_issuance.verifying_key(),
            ))
        }
    }
}

/// Once-gated anchor independently exercising the sort and dedup branches
/// of `canonical_tag_strings` (identity.rs:266-271). Run once per process
/// so a regression that drops either branch trips on every fuzz
/// invocation, not only on fuzzer-discovered tag combinations.
fn assert_tag_canonicalization_anchored() {
    let owner_seed = [0xa1u8; ED25519_SK_SIZE];
    let node_signing_seed = [0xb2u8; ED25519_SK_SIZE];
    let node_encryption_seed = [0xc3u8; X25519_SK_SIZE];
    let node_issuance_seed = [0xd4u8; ED25519_SK_SIZE];

    let owner = Ed25519SigningKey::from_bytes(&owner_seed).expect("anchor owner");
    let owner_pub = owner.verifying_key();
    let node_keys = make_node_keys(
        &node_signing_seed,
        &node_encryption_seed,
        &node_issuance_seed,
    )
    .expect("anchor node keys");
    let node_id = NodeId::new("anchor-node");

    let tags_in_order = make_tags(&["tag:fcp-alpha", "tag:fcp-beta", "tag:fcp-gamma"]);
    assert_eq!(tags_in_order.len(), 3, "anchor tag construction");

    let att =
        NodeKeyAttestation::sign(&owner, &node_id, &node_keys, &tags_in_order, VALIDITY_HOURS)
            .expect("anchor sign");

    // Sort branch: completely reversed input MUST verify.
    let mut reversed = tags_in_order.clone();
    reversed.reverse();
    att.verify(&owner_pub, &node_id, &node_keys, &reversed)
        .expect(
            "ANCHOR REGRESSION: tag sort dropped from canonical_tag_strings — \
         attestations issued in one tag order would no longer verify in another, \
         breaking interop or letting an attacker reorder tags to bypass binding",
        );

    // Dedup branch: tags=[A,A,B,B,C,C] in arbitrary order MUST verify.
    let dup_tags = make_tags(&[
        "tag:fcp-beta",
        "tag:fcp-alpha",
        "tag:fcp-alpha",
        "tag:fcp-gamma",
        "tag:fcp-beta",
        "tag:fcp-gamma",
    ]);
    att.verify(&owner_pub, &node_id, &node_keys, &dup_tags)
        .expect(
            "ANCHOR REGRESSION: tag dedup dropped from canonical_tag_strings — \
         attestations could be replayed under tag lists carrying duplicates that \
         would not have appeared in the original signing input",
        );

    // Acceptance anchor: a strictly different tag set MUST be rejected.
    // Without this, the sort/dedup expectations above could be vacuous if
    // verify accidentally accepted everything.
    let different_tags = make_tags(&["tag:fcp-alpha", "tag:fcp-delta"]);
    match att.verify(&owner_pub, &node_id, &node_keys, &different_tags) {
        Err(TailscaleError::InvalidAttestation) => {}
        Ok(()) => panic!(
            "ANCHOR REGRESSION: attestation verified under a strictly different tag \
             set — tag-list binding has become over-accepting and the canonical-form \
             anchors above are uninformative"
        ),
        Err(other) => panic!("ANCHOR: unexpected error {other:?} on different-tags verify"),
    }
}
