# Audit Chain Formal Model

`lean/Fcp/Audit/HashChain.lean` models the append-only audit chain shape used by
`crates/fcp-audit/src/lib.rs`.

The Lean entry model tracks the fields that define chain integrity:

| Lean field | Rust runtime field |
| --- | --- |
| `id : Nat` | `AuditEntry::computed_id()` / `AuditEntry::id` |
| `prev : Option Nat` | `AuditEntry::prev` |
| `seq : Nat` | `AuditEntry::seq` |

The model treats `canonicalId` as the canonical hash that Rust recomputes from
the entry payload. It does not prove BLAKE3 collision resistance. The theorem
`hash_chain_collision_resistance_assumption_unique` makes that boundary
explicit by taking collision resistance as an assumption.

## Proven Properties

| Theorem | Runtime contract |
| --- | --- |
| `chain_tamper_evident` | A child with a mismatched `prev` link cannot be a valid extension. |
| `chain_matching_hash_extends` | A matching `prev` link plus adjacent sequence number is a valid extension. |
| `extension_preserves_prior_hash_link` | A valid extension preserves the parent hash in `prev`. |
| `extension_sequence_strictly_increases` | A valid extension has a strictly greater `seq`. |
| `no_retroactive_insertion` | A valid extension cannot insert an entry at or before the parent sequence. |
| `hash_chain_collision_resistance_assumption_unique` | Equal canonical ids identify the same child under the explicit collision-resistance assumption. |

`crates/fcp-conformance/tests/audit_chain_proof_alignment.rs` compiles the Lean
module and checks that the Rust verifier still exposes the aligned guards:
genesis validation, duplicate-sequence fork detection, sequence-gap rejection,
previous-link mismatch rejection, canonical id recomputation, and head/tip
agreement.
