# IFC Formalism

Status: `LIMITED` evidence surface for Phase C.7. This document records the
runtime evidence pointer for the zone-isolation E2E gate; it does not promote
the README Zone Isolation row to `PROVEN`.

## Evidence Pointers

| Gate | Artifact | Status |
| --- | --- | --- |
| 5-zone cross-zone leak E2E | `crates/fcp-e2e/tests/zone_isolation_full_e2e.rs` | Implements `z:public`, `z:community`, `z:work`, `z:project:alpha`, and `z:private` policy fixtures; rejects unapproved cross-zone invokes; emits structured zone-check JSONL. |
| Lean zone-flow proof | `lean/Fcp/Zone/Lattice.lean` | Required before the README status can move from `LIMITED` to `PROVEN`. |

The executable harness logs every policy decision with redaction-safe
`request_id`, `src_zone`, `dst_zone`, `capability`, `decision`, `reason_code`,
and monotone `hlc` fields. Rejections use the stable `ZoneReject` audit event
label so downstream proof and doctor surfaces can consume the same evidence.
