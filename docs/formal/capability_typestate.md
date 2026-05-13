# Capability Typestate Proof

`lean/Fcp/Capability/Typestate.lean` models two related capability-token
surfaces:

- The compile-time verifier ladder for `CapabilityToken<S>`:
  `UnboundVerified -> BoundVerified -> ConstraintsEnforced`.
- The runtime lifecycle state machine mirrored by
  `CapabilityLifecycleState`: `Pending`, `Approved`, `Used`, `Revoked`, and
  `Expired`.

The proof keeps the Rust names as the canonical vocabulary. Earlier planning
notes used `Minted` and `Activated`; those correspond to the production
`Pending` and `Approved` variants.

## Theorems

| theorem | purpose |
| --- | --- |
| `typestate_progression_no_skip` | A token cannot jump directly from `UnboundVerified` to `ConstraintsEnforced`. |
| `typestate_promote_reaches_bound` | The verifier ladder admits the explicit instance-binding promotion to `BoundVerified`. |
| `capability_progress` | Every lifecycle state is terminal or has a valid successor. |
| `capability_preservation` | Lifecycle transitions preserve the well-typed state set. |
| `revocation_is_absorbing` | Any transition from `Revoked` remains in `Revoked`. |
| `no_use_after_revoke` | A revoked token cannot transition to `Used`. |
| `approved_use_only_from_approved` | The only transition into `Used` starts from `Approved`. |

`crates/fcp-conformance/tests/capability_typestate_proof_alignment.rs`
pins the proof to the runtime enum and transition surface, runs
`lake build Fcp.Capability.Typestate`, and rejects explicit FCP axioms,
`sorry`, or `admit`.
