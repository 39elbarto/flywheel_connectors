# Masked IBLT Anti-Entropy Design

Status: implementation slice for `flywheel_connectors-angoc.17.2`.

This document records the bounded anti-entropy change shipped in the first
masked-IBLT integration pass. The target is the Phase A.bis.2 plan in
`docs/reality/2026-05-12-reality-check-bridge-plan.md`: replace raw object-ID
IBLT sketches with zone-masked sketches and add a layered Bloom+XOR membership
budget for route hints.

## Source Grounding

The `alien-graveyard` skill requires the canonical graveyard sources under
`/data/projects/alien_cs_graveyard/`. Those files were not present on this
machine during this slice, so this change is grounded in:

- the existing `fcp-mesh` gossip and IBLT implementation;
- the bead's cited Mitzenmacher-Pagh 2018 masked-IBLT target;
- the local skill catalog entries for Bloom/XOR filters and anti-entropy.

The implementation is intentionally one lever: mask existing IBLT keys and add
the layered route-hint filter without changing revocation semantics,
admission control, or transport selection.

## Wire Shape

`GossipSummary::iblt` is still a CBOR-encoded `Iblt`, preserving the existing
bounded decoder and byte-budget path. The cells no longer contain raw object-ID
XOR sums. Each object ID is XORed with `IbltMask::for_zone(zone_id)` before it is
inserted into the sketch, and decode results are unmasked after subtraction.

The mask is deterministic per zone:

```text
mask = BLAKE3("FCP-MESH-MASKED-IBLT-ZONE-V1" || zone_id)
```

Peers reconciling the same zone derive the same mask. A peer reconciling a
different zone cannot produce raw object IDs that decode correctly under the
receiver's zone mask.

## Route Hint Filter

The existing gossip membership hint now builds a layered filter on first query:

1. exact hashed-key set check for no false negatives on local state;
2. Bloom prefilter with default target `1e-4`;
3. `xorf::Xor8` confirmation for compact O(1) route hints.

This filter is only for gossip object/symbol availability. It is not a security
predicate and is not used for revocation decisions; revocation remains exact and
freshness-gated.

## Fallbacks

- Oversized summary IBLT payloads are still rejected before decode.
- Malformed CBOR still returns `IbltDecodeError::InvalidEncoding`.
- Overloaded masked sketches return incomplete decode state through
  `MaskedIbltError::DecodeIncomplete`, which is the caller's signal to use the
  existing bounded list exchange.
- If layered filter construction cannot be used, the route hint falls back to
  the existing exact-key and `Xor8` behavior.

## Proof Artifacts

Unit coverage:

- `masked_iblt_decodes_symmetric_diff`
- `masked_iblt_reports_overload_for_fallback`
- `masked_iblt_decodes_small_diff_under_latency_budget`
- `layered_filter_fpr_budget_enforced`
- `gossip_state_summary_iblt_is_masked_and_object_level`

Conformance coverage:

- `masked_iblt_conformance.rs::cross_peer_reconciliation_3way_converges_to_identical_payloads`
- `masked_iblt_conformance.rs::summary_iblt_wire_contains_masked_keys_not_raw_object_ids`
- `masked_iblt_conformance.rs::layered_filter_fpr_budget_conformance`
- `masked_iblt_conformance.rs::corrupted_summary_iblt_is_structured_rejection_without_peer_mutation`

## Remaining Work

The following acceptance items are still separate follow-up surfaces unless
landed by the same bead closeout:

- `fwc doctor --probe iblt` reporting for scheme, decode p99, overflow count,
  and observed FPR;
- explicit audit-chain verification for overflow fallback;
- production OTLP histogram aggregation for per-peer masked IBLT decode latency.
