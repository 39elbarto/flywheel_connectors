# Formal Verification Matrix

This matrix links each Lean theorem in the formal invariant gate to the Rust/E2E surface that must consume its witness before execution.

| Invariant | Lean theorem | Source | E2E gate |
| --- | --- | --- | --- |
| Capability-token type-state ladder compositional soundness | `Fcp.Invariants.Capability.capability_token_ladder_composes_only_through_bound` | `lean/Fcp/Invariants/Capability.lean` | `fcp-e2e::evidence::verify_formal_invariant_witnesses` must pass before capability-token ladder E2E scenarios run. |
| Revocation-seal check-use atomicity | `Fcp.Invariants.Revocation.revocation_seal_check_use_atomicity` | `lean/Fcp/Invariants/Revocation.lean` | Revocation E2E scenarios must attach the witness set to their evidence bundle before dispatching operations. |
| Audit-chain hash-link fork resistance | `Fcp.Invariants.Audit.audit_chain_hash_link_fork_resistance` | `lean/Fcp/Invariants/Audit.lean` | Audit-chain E2E scenarios must include `lean_witnesses` and the witness artifact path in replay bundles. |
| Zone-isolation merge correctness | `Fcp.Invariants.Zone.merge_preserves_integrity_and_confidentiality` | `lean/Fcp/Invariants/Zone.lean` | Zone merge E2E scenarios must verify the canonical witness file before evaluating MIN/MAX label composition. |
| Symbol-fungibility reconstruction guarantee | `Fcp.Invariants.Symbol.symbol_fungibility_reconstruction_guarantee` | `lean/Fcp/Invariants/Symbol.lean` | Symbol-first/RaptorQ E2E scenarios must verify the witness file before K-of-N reconstruction checks. |

Canonical witness file: `lean/witnesses/formal_invariants.v1.json`.

Replay bundles carry:

- `artifact_paths.lean_witness = lean/witnesses/formal_invariants.v1.json`
- `lean_witnesses[]` entries with `theorem`, `source_path`, `source_hash`, `lake_target`, and `verified_at`

The Rust gate recomputes each Lean source file's SHA-256 hash and refuses to run when any required theorem witness is missing, has an unsafe source path, omits `verified_at`/`lake_target`, or is stale.
