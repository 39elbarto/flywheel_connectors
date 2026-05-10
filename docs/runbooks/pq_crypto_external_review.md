# PQ Crypto External Review Runbook

This runbook covers the KYOPB lattice-crypto external review flow for
`flywheel_connectors-kyopb.1.3.1.1.6.3`. It is a process gate, not a substitute
for the proof gauntlet in `flywheel_connectors-kyopb.1.3.1.1.6.2`.

## Identify a Qualified Reviewer

A reviewer counts as external only when all of these are true:

- They have not contributed commits, issues, or pull requests to this repository
  in the last 12 months.
- They are not an Agent Mail swarm agent for this project.
- They have no equity, contract, revenue share, or other financial incentive in
  the project outcome.
- They have demonstrable lattice-cryptography expertise through peer-reviewed
  work, recognized industry credentials, or employment at a cryptographic review
  firm.

Acceptable channels are public lattice-cryptography academic reviewers,
cryptographic-engineering review services, or a moderated cryptography forum
thread with an auditable engagement timeline. Do not use self-nominated reviewers
unless their credentials satisfy the policy above.

## Dispatch the Packet

Build the review packet only after the proof gauntlet bead is closed with a
redaction-safe artifact path. The packet lives under:

```text
artifacts/proofs/kyopb_review_packet/<run-id>/packet.tar.gz
```

The packet must include:

- `manifest.json` with `schema_version`, `git_revision`, file SHA-256 hashes,
  `packet_id`, `generated_at`, and `primary_contact`.
- `README.md` with the reading order.
- `proofs/lean_proof_outputs.txt` when Lean output is available.
- `proofs/proof_gauntlet.jsonl` from the proof gauntlet bead.
- `parameters/rationale.md`.
- `invariants/public_material.md`.
- `binding_rationale.md`.
- `replay_denial_evidence.jsonl`.
- `side_channel_redaction.md`.
- `known_limitations.md`.

Before dispatch, scan the packet for trapdoor material, preimage coefficients,
secret seeds, expanded secret matrices, raw operation or principal text, raw zone
labels, tokens, bearer strings, private local paths, provider bodies, reviewer
private contact data, and PII. Record the packet hash and recipient list in a
Beads comment.

## Track Engagement

Add a Beads comment every two weeks while the review is pending:

```text
{review_status:"requested",last_contact:"YYYY-MM-DD",expected_response_by:"YYYY-MM-DD",blockers:[]}
```

Use `requested`, `in_progress`, `complete`, or `declined` for
`review_status`. If a reviewer declines, document the reason and move to the next
qualified reviewer. If an engaged reviewer takes more than 90 days, file a
follow-up tracking bead under the KYOPB lineage.

## Handle Findings

For every material finding, file a child bead under the external-review bead:

```text
[PQ-Crypto][F.1.x.y] <reviewer-summarized-finding>
```

The bead body should include reviewer attribution, severity, the redacted
finding text, and the recommended disposition. Leave it open until remediation or
explicit disposition is complete. Do not close the external-review bead while
material findings are unresolved.

## Closure Gate

Run the mechanical no-self-review gate before closing the external-review bead:

```bash
scripts/close_kyopb_external_review.sh \
  --bead flywheel_connectors-kyopb.1.3.1.1.6.3
```

The script queries GitHub contributors through `gh api` and checks Beads comments
for at least one qualifying non-contributor author. By default, the qualifying
comment must include:

```text
external_review_attestation: complete
```

This script is only a mechanical contributor-list gate. The operator still owns
the full reviewer-identity policy above.

## Rollback

If the wrong packet was dispatched, add a Beads comment that invalidates the
packet by hash, then dispatch a corrected packet with a new `packet_id`. Do not
delete the old packet or Beads comment; leave the invalidation trail auditable.

If the wrong reviewer was selected, mark the engagement declined or invalid in a
comment, then restart reviewer selection from the policy above.

## Recovery

If `gh` cannot query contributors, verify GitHub authentication with:

```bash
gh auth status
```

If Beads cannot list comments, stop closure and retry after the Beads database is
available. Do not close from memory.

If the packet redaction scan fails, keep the review bead open, quarantine the
packet path in a Beads comment, and file a finding bead for the redaction defect.

## Common Failures

- `no qualifying non-contributor review comment found`: the reviewer has not
  commented on the Beads thread, the author matches a GitHub contributor, or the
  required attestation marker is missing.
- `Missing required command: gh`: install or configure GitHub CLI before closure.
- `packet hash mismatch`: rebuild the packet deterministically and record the new
  hash; do not reuse a stale hash.

## Redacted Log Examples

```json
{"event_type":"fcp.pq.review.packet_dispatched","bead_id":"flywheel_connectors-kyopb.1.3.1.1.6.3","redaction_scope":"hashed","packet_id":"kyopb-20260510-a","packet_hash":"sha256:...","reviewer_id_hash":"sha256:...","timestamp":"2026-05-10T14:00:00Z"}
{"event_type":"fcp.pq.review.finding_filed","bead_id":"flywheel_connectors-kyopb.1.3.1.1.6.3","redaction_scope":"public","finding_bead":"flywheel_connectors-kyopb.1.3.1.1.6.3.1","severity":"medium","timestamp":"2026-05-10T14:10:00Z"}
{"event_type":"fcp.pq.review.close_gate","bead_id":"flywheel_connectors-kyopb.1.3.1.1.6.3","redaction_scope":"public","result":"pass","external_comment_count":1,"timestamp":"2026-05-10T14:20:00Z"}
```
