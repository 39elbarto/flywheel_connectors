# Lean Toolchain Pin

This document is the operator-facing pin contract for the Lean formal proof
gate. The conformance test `lean_toolchain_pin_match` treats these values as
authoritative and fails if the checked-in toolchain files drift.

## Pinned Inputs

- Lean compiler: `leanprover/lean4:v4.29.1`
- Mathlib revision: `5e932f97dd25535344f80f9dd8da3aab83df0fe6`
- Lake manifest version: `1.1.0`

## Required Proof Corpus

The `make lean-verify` target must compile exactly these proof files before the
README can promote Lean-backed claims:

| proof_file | required_theorem |
| --- | --- |
| `lean/Fcp/Zone/Lattice.lean` | `zone_flow_soundness` |
| `lean/Fcp/Capability/Typestate.lean` | `typestate_progression_no_skip` |
| `lean/Fcp/Audit/HashChain.lean` | `chain_tamper_evident` |
| `lean/Fcp/Crypto/HybridSignature.lean` | `hybrid_unforgeable_under_one_break` |
| `lean/Fcp/Mesh/CrdtMerge.lean` | `crdt_merge_lattice_laws` |

## Drift Policy

Changing any pin requires the same commit to update `lean-toolchain`,
`lakefile.lean`, `lake-manifest.json`, this document, and the conformance proof
run. Floating references such as `main` are not accepted for the direct mathlib
dependency.
