//! m8j0q.A.9 throughput acceptance test.
//!
//! Bead acceptance: "Cascade is `O(walk_depth)`, not `O(num_tokens)`".
//!
//! This integration test mints 1000 distinct token ids that all share
//! the same revoked issuer key, then verifies:
//!
//! 1. Every one of the 1000 tokens is rejected by the cascade walker
//!    with the same `IssuerKeyRevoked` reason.
//! 2. Per-token cost is `O(walk_depth)` — independent of `num_tokens`
//!    and independent of `registry_size`. We assert this by counting
//!    lookup-closure invocations: each token triggers AT MOST
//!    `max_hops` calls regardless of how many tokens or how many
//!    other revocation entries exist.
//!
//! The test does NOT measure wall-clock time (which is flaky in CI);
//! it asserts the structural cost property that wall-clock time would
//! reflect.

use fcp_evidence::{
    AttestationChain, CascadeConfig, CascadeHop, CascadeRejection, RevocationRecord,
    check_revocation_chain,
};

use fcp_core::ObjectId;
use fcp_crypto::kid::KeyId;

const fn kid(byte: u8) -> KeyId {
    KeyId::from_bytes([byte; 8])
}

const fn kid_u64(value: u64) -> KeyId {
    KeyId::from_bytes(value.to_le_bytes())
}

/// Build a healthy 3-hop chain rooted at `owner_kid`.
fn chain_through(issuer_kid: KeyId, node_kid: KeyId, owner_kid: KeyId) -> AttestationChain {
    let mut chain = AttestationChain::rooted_at(owner_kid.clone());
    chain
        .attest_issuance(issuer_kid, node_kid.clone())
        .expect("issuance edge");
    chain.attest_node(node_kid, owner_kid).expect("node edge");
    chain
}

#[test]
fn issue_1000_tokens_revoke_issuer_all_reject() {
    let issuer = kid(1);
    let node = kid(2);
    let owner = kid(3);
    let chain = chain_through(issuer.clone(), node, owner);

    let mut total_lookups = 0_usize;

    for i in 0_u32..1000 {
        let token_id = ObjectId::from_unscoped_bytes(&i.to_le_bytes());
        let mut per_token_lookups = 0_usize;

        let result = check_revocation_chain(
            token_id,
            issuer.clone(),
            &chain,
            &CascadeConfig::default(),
            0,
            // No direct revocation: tokens themselves are not in the
            // registry — only the upstream issuer key is.
            |_| None,
            |kid_at_hop, scope| {
                per_token_lookups += 1;
                if scope == CascadeHop::IssuerKey && *kid_at_hop == issuer {
                    Some(RevocationRecord {
                        revoked_at_unix_ms: 1_700_000_000_000,
                    })
                } else {
                    None
                }
            },
        );

        // Acceptance: per-token cost is O(walk_depth).
        // The IssuerKey lookup hits on hop 0, so exactly 1 lookup per token.
        assert_eq!(
            per_token_lookups, 1,
            "token {i}: lookup-closure invocations must be O(walk_depth) — got {per_token_lookups}",
        );
        total_lookups += per_token_lookups;

        // Every token rejects with the same structured reason.
        match result {
            Err(CascadeRejection::HopRevoked {
                scope: CascadeHop::IssuerKey,
                hop_index: 0,
                kid: rejected_kid,
                ..
            }) => {
                assert_eq!(rejected_kid, issuer, "token {i}: wrong KID rejected");
            }
            other => panic!("token {i}: unexpected outcome {other:?}"),
        }
    }

    // 1000 tokens × O(walk_depth=1 because the rejection is at hop 0)
    // = 1000 lookups total. NOT proportional to num_tokens².
    assert_eq!(total_lookups, 1000);
}

#[test]
fn cost_is_constant_in_unrelated_attestation_count() {
    // Adding 1000 unrelated edges to the chain MUST NOT increase
    // per-token lookup cost — confirms the chain traversal is
    // O(walk_depth) per hop, with chain-edge fanout amortized into the
    // resolve_next linear scan.
    let issuer = kid(1);
    let node = kid(2);
    let owner = kid(3);
    let mut chain = chain_through(issuer.clone(), node, owner);

    // Pad with 1000 unrelated edges.
    for i in 0_u32..1000 {
        let base = 1_000_u64 + u64::from(i);
        chain
            .attest_issuance(kid_u64(base), kid_u64(base + 10_000))
            .expect("unique padding edge");
    }

    let token_id = ObjectId::from_unscoped_bytes(b"single-token");
    let mut lookups = 0_usize;
    let _receipt = check_revocation_chain(
        token_id,
        issuer,
        &chain,
        &CascadeConfig::default(),
        0,
        |_| None,
        |_, _| {
            lookups += 1;
            None
        },
    )
    .expect("clean walk to owner");

    // Walk visits 3 KIDs (issuance, node, owner) — each triggers one
    // lookup. The 1000 padding edges do NOT add to the lookup count.
    assert_eq!(lookups, 3);
}
