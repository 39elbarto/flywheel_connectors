# Formal Coverage Matrix

This matrix pins each README status-table claim to either a machine-checked
formal obligation or an explicit reason that the current claim is not yet
modeled formally. It is intentionally narrower than runtime evidence: Rust
unit tests, E2E tests, golden vectors, and operational artifacts remain
necessary, but they are not a substitute for a Lean/TLA/CSP entry here.

| readme_section | claim | lean_theorem | tla_spec | csp_spec | no_formal_model_reason |
| --- | --- | --- | --- | --- | --- |
| README status table | Host-First Control Plane | - | - | - | Operational orchestration claim; current evidence is Rust/E2E host proof, not a formal model. |
| README status table | Truthful Runtime Resolution | - | - | - | CLI/catalog truthfulness is currently pinned by Rust tests and status pinning, not a formal semantics model. |
| README status table | Zone Isolation | `Fcp.Zone.Lattice.zone_flow_soundness @ lean/Fcp/Zone/Lattice.lean` | - | - | - |
| README status table | Capability Tokens (CWT/COSE) | `Fcp.Capability.Typestate.typestate_progression_no_skip @ lean/Fcp/Capability/Typestate.lean` | - | - | - |
| README status table | Tamper-Evident Audit | `Fcp.Audit.HashChain.chain_tamper_evident @ lean/Fcp/Audit/HashChain.lean` | - | - | - |
| README status table | Revocation | `Fcp.Invariants.Revocation.revocation_seal_check_use_atomicity @ lean/Fcp/Invariants/Revocation.lean` | - | - | - |
| README status table | Egress Proxy | - | - | - | Network-policy enforcement is covered by Rust/E2E denial evidence; no Lean/TLA/CSP model is attached yet. |
| README status table | Secretless Connectors | - | - | - | Secret injection and redaction are covered by hook and connector-family E2Es; no formal secrecy model is attached yet. |
| README status table | Threshold Owner Key | - | - | - | FROST ceremony/signing is implementation-backed; no formal threshold-signature proof corpus is attached yet. |
| README status table | Threshold Secrets | - | - | - | Shamir recovery coverage is runtime/test evidence; no formal threshold-secret model is attached yet. |
| README status table | Supply Chain Attestations | - | - | - | Registry/TUF/Sigstore proof is implementation and E2E evidence; no formal supply-chain model is attached yet. |
| README status table | Offline Access | - | - | - | Placement, repair, and offline drain semantics are covered by store/E2E proof; no formal availability model is attached yet. |
| README status table | Mesh-Stored Policy Objects | - | - | - | Mesh policy-object evidence is Rust/E2E based; no formal policy-object propagation model is attached yet. |
| README status table | Symbol-First Protocol | `Fcp.Invariants.Symbol.symbol_fungibility_reconstruction_guarantee @ lean/Fcp/Invariants/Symbol.lean` | - | - | - |
| README status table | Mesh-Native Architecture | - | - | - | README labels this as a target architecture, not an operational proof; Lean currently covers only sub-invariants. |
| README status table | Computation Migration | - | - | - | Migration/resume evidence is an E2E reference proof; no formal migration-state model is attached yet. |

## Lean Theorem Inventory

The entries below keep auxiliary Lean theorem statements visible to the
coverage verifier even when they are helper lemmas rather than direct README
claim gates.

- `audit_chain_hash_link_fork_resistance`
- `ancestor_period_miss_invalidates`
- `both_breaks_are_required_for_model_forgery`
- `bound_verified_predecessor_is_unbound`
- `capability_token_ladder_composes_only_through_bound`
- `chain_tamper_evident`
- `constraints_enforced_predecessor_is_bound`
- `constraints_enforced_requires_bound`
- `crdt_merge_lattice_laws`
- `dispatch_epoch_matches_observed`
- `extra_repair_symbols_preserve_decode`
- `hybrid_unforgeable_under_one_break`
- `insufficient_symbols_not_decodable`
- `lattice_delegation_chain_corruption_rejected`
- `lattice_delegation_sis_assumption_boundary_complete`
- `lattice_trapdoor_capability_unforgeability_reduces_to_sis_assumptions`
- `leaf_period_miss_alone_invalidates`
- `left_confidentiality_le_merge`
- `matching_head_verifies`
- `merge_associative`
- `merge_commutative`
- `merge_idempotent`
- `merge_integrity_le_left`
- `merge_integrity_le_right`
- `merge_preserves_integrity_and_confidentiality`
- `no_direct_unbound_to_constraints`
- `no_leak_reachable_after_pass`
- `revocation_seal_check_use_atomicity`
- `revoked_seal_cannot_dispatch`
- `right_confidentiality_le_merge`
- `same_parent_payload_extension_unique`
- `symbol_fungibility_reconstruction_guarantee`
- `typestate_progression_no_skip`
- `zone_flow_soundness`
- `zone_mismatch_alone_invalidates`
