# Claims vs Reality Quarterly Report — Q2 2026

> Period: Q2 2026 (April–June)
> Auditor: SunnyMoose (Claude Opus 4.6)
> Prior report: N/A (first report — baseline from MOR/C2.4 audit)
> Snapshot date: 2026-04-10 20:17 UTC (commit 70978239)
> **Post-report corrections:** Two status rows drifted after this
> snapshot was written. See the post-snapshot-deltas section below
> before citing numbers from this report.

## Summary

This is the inaugural claims-vs-reality quarterly report, establishing the
baseline from the MOR/C2.4 audit conducted on 2026-04-10. All 16 feature
status labels in the README were verified against code evidence **as of
the snapshot date**.

**Result at snapshot date:** All 16 labels accurate, no overclaims, no
underclaims.

**Post-snapshot status:** Two labels were subsequently changed in the
README and the quarterly table has been re-reconciled in-place to match
(br-rx347). The original "no overclaims, no underclaims" claim above is
preserved for historical honesty; see the post-snapshot-deltas section
for the two rows that were re-audited.

## Feature Status Delta Table

Current Status reflects the latest README (re-reconciled 2026-04-23).
Snapshot Status preserves the 2026-04-10 audit answer so the drift is
visible.

| Feature | Prior Status | Snapshot Status (2026-04-10) | Current Status | Delta | Evidence | Notes |
|---------|-------------|------------------------------|----------------|-------|----------|-------|
| Host-First Control Plane | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | 240+ tests | Proven operational boundary |
| Truthful Runtime Resolution | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | 980+ tests | KnowledgeState taxonomy, TruthPrecedencePolicy |
| Zone Isolation | N/A | `PROVEN` | `LIMITED` | ↓ Downgraded 2026-04-22 (br-lse4w) | 420+ tests, E2E | README now qualifies: host-side connector zone binding enforced when `allowed_zones` is configured; empty-set permissive branch remains |
| Capability Tokens (CWT/COSE) | N/A | `PROVEN` | `PROVEN` | Baseline | 249+ tests, conformance | COSE_Sign1, phantom types, mandatory constraints |
| Tamper-Evident Audit | N/A | `PROVEN` | `PROVEN` | Baseline | 473+ tests, golden vectors | Hash-linked chain + quorum checkpoints |
| Revocation | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | 104 tests | RevocationObject, 5 scopes; E2E TBD |
| Egress Proxy | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | 270+ tests | CIDR deny defaults; hardening TBD |
| Secretless Connectors | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | credential_id path | Broader proof TBD |
| Threshold Owner Key | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | 93 tests | FROST ceremony; not universal default |
| Threshold Secrets | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | 123 tests | GF(2^8) Shamir, full reconstruction |
| Supply Chain Attestations | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | 347 tests | Schema + verification; release signing TBD |
| Offline Access | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | 185+ tests (77 E2E) | PlacementPolicy + repair controllers |
| Mesh-Stored Policy Objects | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | 128 tests | Owner-signed; mesh distribution TBD |
| Symbol-First Protocol | N/A | `IMPLEMENTED` | `IMPLEMENTED` | Baseline | 96+ tests | RaptorQ, chunking, golden vectors |
| Mesh-Native Architecture | N/A | `DESIGNED` | `IMPLEMENTED` | ↑ Upgraded 2026-04-10 21:43 (z1nkz.1 / cfd9c0f5) | 259+ tests + `fwc/src/truth.rs` (78 tests) | README now frames as "converging"; Gossip/IBLT/XOR/LiveTruthResolver all built and tested, production cutover gating in progress |
| Computation Migration | N/A | `DESIGNED` | `DESIGNED` | Baseline | 205 tests | State machines only; not operational |

## Post-snapshot deltas (br-rx347)

Two rows above diverged from the README between the 2026-04-10 snapshot
and the next quarterly review. Both README edits preceded the
reconciliation; neither was an overclaim by the README at its edit time.
Both changes were audited and accepted.

1. **Mesh-Native Architecture** `DESIGNED` → `IMPLEMENTED` (2026-04-10
   21:43, commit cfd9c0f5, z1nkz.1 teaching-surface rewrite). The
   quarterly was written ~90 minutes earlier the same day; the
   accompanying note was updated on the README side but not mirrored
   here until br-rx347.
2. **Zone Isolation** `PROVEN` → `LIMITED` (2026-04-22, commit a4ad8d5d,
   br-lse4w). The downgrade reflects that `allowed_zones` is opt-in in
   the current host-backed path and an empty set preserves a
   back-compat permissive branch. The quarterly's `PROVEN` cell
   overclaimed for the 12 days between 04-10 and 04-22.

## Overclaims Found (at re-reconciliation, 2026-04-23)

- **Zone Isolation** was recorded as `PROVEN` in this quarterly but the
  README now carries `LIMITED`. Overclaim resolved by updating this
  report's Current Status column and the README itself (br-lse4w).
  Underlying policy: when the reconciliation table itself drifts from
  the audited artifact, the quarterly must be re-run or annotated — a
  stale quarterly is itself an overclaim.

## Underclaims Found (at re-reconciliation, 2026-04-23)

- **Mesh-Native Architecture** was recorded as `DESIGNED` in this
  quarterly. The same-day README edit (z1nkz.1) moved to `IMPLEMENTED`
  with evidence (Gossip/IBLT/XOR/LiveTruthResolver all built). The
  quarterly underclaimed on this axis for 12 days.

## Debiasing Notes

- The MOR analysis (Modes of Reasoning) identified optimism bias in the
  README's teaching order (now fixed by C2.1) but not in the status labels
  themselves. The labels were already honest.
- Multi-agent development has not produced status label inflation in this
  codebase. This may be because the status legend is well-defined and agents
  check test counts before claiming status levels.
- The strongest evidence gap is between `IMPLEMENTED` and `PROVEN` — several
  features (Revocation, Egress, Secretless) have strong unit test coverage
  but limited E2E proof. Future reports should track E2E test additions.
- **Stale quarterly drift (br-rx347):** this report froze at 2026-04-10
  20:17 but two rows drifted within hours (Mesh-Native upgrade, same
  day) and 12 days (Zone Isolation downgrade). A quarterly that claims
  "all labels accurate" while its own table records stale statuses is
  itself an overclaim. Future quarterlies should either re-reconcile at
  publish time or ship with an explicit "frozen at commit X" banner and
  a subsequent drift-delta section — this one now carries both.

## Actions Taken

- README feature table now includes an Evidence column with file paths and test counts (C2.4)
- README teaching order restructured to lead with host-first reality (C2.1)
- Operational model versions documented (V1 Host-First / V2 Mesh-Native) (C2.2)
- Zone-wide TruthPrecedencePolicy implemented for consistent operator answers (C2.3)

## Next Quarter Focus

- Track which `IMPLEMENTED` features gain E2E proof and could be upgraded to `PROVEN`
- Watch for new features added without status labels
- Verify that V2 transition milestones remain accurately described as non-operational
