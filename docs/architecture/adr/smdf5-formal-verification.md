# ADR: Lean-Gated Formal Invariant Witnesses

Status: accepted

## Context

The FCP3 proof surface needs machine-checked evidence for security invariants that are too important to leave as comments or prose-only test assertions. The immediate scope is five invariants: capability-token typestate progression, revocation-seal atomicity, audit-chain hash linking, zone-label merge monotonicity, and symbol reconstruction.

## Decision

Add a root Lean 4 Lake package with theorem modules under `lean/Fcp/Invariants/`. CI runs `lake build` through `leanprover/lean-action@v1`.

E2E evidence bundles now understand Lean witnesses:

- `lean/witnesses/formal_invariants.v1.json` records the theorem, Lean source path, source hash, Lake target, and verification date.
- `fcp-e2e::evidence::verify_formal_invariant_witnesses` parses the witness file and recomputes Lean source hashes.
- E2E gates fail closed when witnesses are missing, stale, or malformed.
- Replay bundles expose `artifact_paths.lean_witness` and can attach `lean_witnesses[]` so offline reviewers can re-check the same proof inputs.

## Consequences

Formal proof drift now breaks at two layers: Lean CI rejects theorem regressions, and Rust E2E gates reject stale witness metadata. The initial Lean models are intentionally small and executable; stronger refinement links can extend the same witness schema without changing replay-bundle shape.
