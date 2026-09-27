# n8n unarchive and lifecycle acceptance closeout

## Current closeout (2026-09-25)

The RC33 existing-version lifecycle acceptance is **PASS for the selected
workflow on EEC and the separately selected workflow on Hetzner**. This closes
the `flywheel_connectors-nqm81.24` lifecycle scope. The prior `.24` pending or
live-unaccepted wording is obsolete; do not repeat live acceptance for this
closeout.

The installed release is
`release-20260925-fd9941702-manifest-interface-hash-rc33`, with provenance
source revision `fd99417021bba2872cf9d4bbbf3b7cae670d7729`. The runner/source
checkout was `main` at `996779846cd6f659a81ddf5dcb673c6fee4472a7`.

| Server | Explicitly selected workflow | Selected version | Verdict | Evidence |
| --- | --- | --- | --- | --- |
| EEC | `kXVmpnLGECl1aHLy` | `32385eab-f3ad-4bab-a545-62104f95f42c` | PASS | `/srv/dev-ssd/fcp/nqm81.24/acceptance-eec-existing-version-rc33-20260925-01` |
| Hetzner | `uQXXNMWE2lzlCgag` | `b22acfe1-ecca-45c8-97a1-b10420dfb241` | PASS | `/srv/dev-ssd/fcp/nqm81.24/acceptance-hetzner-existing-version-uQXXNMWE2lzlCgag-20260925-01` |

Each server has its own independent evidence bundle and must be interpreted
separately. In each bundle, the exact baseline was inactive, unpublished,
unarchived, and on the selected draft version. The run used one fresh,
request-bound approval and one publish; an independent GET confirmed the same
selected version was active and published. A separate fresh approval and one
unpublish followed. The independent final GET confirmed the same workflow and
version were inactive, with `activeVersionId=null`, `published=null`, and
unarchived. Baseline and final `stateDigest` values match within each server's
bundle.

Both summaries report `retries=0`, `execution_attempts=0`,
`workflow_creation=false`, `automatic_cleanup=false`, and
`evidence_complete=true`. No workflow or Webhook invocation was issued as part
of this acceptance. The summary schema records zero execution attempts but has
no explicit `webhook_invoked` field.

The RC33 closeout supersedes the older `.24` pending status only for these two
existing-version lifecycle runs. It does not change the separate result below.

## Separate historical Hetzner create result (2026-09-25; UNKNOWN)

The disposable-create run tracked by `flywheel_connectors-nqm81.32` is a
separate **UNKNOWN**, not part of the `.24` existing-version PASS:

- Run: `fcbf7687-9ad8-4ebd-ae66-69c4cfd8b796`
- Evidence: `/srv/dev-ssd/fcp/nqm81.24/acceptance-hetzner-activation-rc33-20260925-01`
- Recorded fields: `verdict=unknown`, `create_status=1`, empty `workflow_id`,
  `retries=0`, `evidence_complete=false`, `abort_code=create_unknown`.

This receipt does not prove that creation succeeded or that no workflow was
created. Preserve the UNKNOWN as recorded: do not infer success or absence,
replay the run, or fold it into either `.24` PASS.

## Earlier unarchive result (2026-09-21; PASS)

The earlier `flywheel_connectors-nqm81.23` bounded REST unarchive acceptance
passed on both servers using RC26, release
`release-20260920-02d215cfd-unarchive-introspection-rc26`, and fix
`4ef0578dc`. Its retained server-specific evidence was:

| Server | Workflow | Evidence |
| --- | --- | --- |
| EEC | `2Zdk8MWoC70eyqeb` | `/srv/dev-ssd/fcp/nqm81.23/acceptance-eec-20260921-9c42e6a1` |
| Hetzner | `uQXXNMWE2lzlCgag` | `/srv/dev-ssd/fcp/nqm81.23/acceptance-hetzner-NZAx85` |

Those receipts prove `isArchived: true -> false` while keeping the workflow
inactive, unpublished, and without an active version; they concern unarchive,
not version publish/unpublish. Earlier NO-GO comments from before 2026-09-25
remain historical records for their candidates and attempts; they do not
replace the PASS or UNKNOWN verdicts above.

## Next scope

`flywheel_connectors-nqm81.25` covers separate test and manual execution
controls. It requires a separately selected suitable disposable fixture and
an explicit side-effect and credential review. The `.24` lifecycle fixture
must not be assumed suitable as an execution target. This closeout authorizes
no `.25` work or live operation.

## Runner scope (nqm81.23 unarchive)

This runner proves one bounded unarchive of one already-existing archived
workflow on one explicit n8n server. It performs one fresh `GET` baseline,
derives the exact unarchive precondition and parent binding, creates one fresh
13-digit-millisecond approval request, issues one approval through the existing
FD3 handoff, invokes one `n8n.workflows.unarchive`, and performs one independent
`GET` readback. It never creates, archives, publishes, deletes, retries, polls,
or calls an issuer/provider outside that single sequence.

## Invocation

```sh
scripts/n8n_unarchive_acceptance.sh \
  --server eec \
  --workflow-id WORKFLOW_ID \
  --parent-helper /srv/dev-ssd/fcp/targets/nqm81-cbor-helper-rc20/release/nqm81-cbor-helper \
  --evidence-dir /srv/dev-ssd/fcp/nqm81.23/unarchive-evidence
```

The positional form `scripts/n8n_unarchive_acceptance.sh eec WORKFLOW_ID` is
also accepted. The launcher and approval helper default to
`/usr/local/bin/fwc-n8n` and
`/home/ubuntu/Projects/flywheel_connectors/scripts/n8n_approval_once.sh`.
Callers may spell the verified parent-binding path with `--parent-helper` or
`N8N_PARENT_BINDING_HELPER`, but the guard accepts only the exact rc20 binary
path shown above; it is not a general executable override. A legacy path named
`/srv/dev-ssd/fcp/targets/nqm81-cbor-helper/release/nqm81-cbor-helper` is a
local diagnostic symlink to `/tmp` and is not a production entrypoint. Missing,
unknown, temporary, or symlinked helper paths stop before any provider call.

The fixed approval root is
`/var/lib/fwc-n8n/approval-requests`; the generated request is root-owned,
mode `0600`, and contains the exact input/precondition. Request contents are
transport-only and are never copied to evidence. Evidence, when requested,
contains only the redacted baseline/invoke/final projections and a summary;
raw provider responses, request bodies, tokens, seeds, and secrets are not
persisted there. If the bounded approval handoff fails before invocation, the
summary is still written with `verdict: "stop"` and
`abort_code: "approval_failed"`, alongside the existing numeric
`approval_helper_status` and `approval_reader_status` fields; no helper output
or other sensitive material is captured.

The approval helper runs once through `sudo -n` and a 40-second `timeout`,
inside the 45-second request TTL. Because sudo-rs closes inherited FD3, a
root `bash -c` maps the helper's FD3 to stdout and the parent maps stdout back
to its protected FD3 pipe; the token is streamed into the single launcher
invocation and is never placed in a shell variable, file, or evidence.

## Outcomes

- `pass`, exit `0`: the single invoke exited `0`, its redacted response has
  wrapper `status: "ok"`, result `status: "verified"`, the expected
  operation, and the requested workflow target in both production state
  records (`result.before.id` and `result.after.id`); the independent readback
  proves the workflow is inactive, unarchived, unpublished, has
  `activeVersionId: null`, and has the same draft graph digest. Draft/state/
  version rotation is allowed by the unarchive contract. The production result
  has no top-level `result.id`; target identity is carried by `before.id` and
  `after.id`.
- `STOP`, exit `10`: the baseline, helper, request, approval, or pre-invocation
  contract failed; no unarchive was attempted. It is also returned if the
  single post-invoke readback proves a state while requested evidence cannot be
  written; the state is known, but the acceptance artifacts are incomplete.
- `unknown`, exit `20`: the unarchive may have started but the one readback was
  unavailable or did not prove the exact postcondition, the invoke was not
  verified, or a post-invoke evidence write fails before state is proven. A
  matching final GET after an invoke failure is reconciled provider state only,
  never a full pass. Do not retry or replay this run; investigate the redacted
  evidence and start a separately approved acceptance only after the operator
  decides it is safe.

## Offline self-tests

```sh
scripts/n8n_unarchive_acceptance.sh --self-test
```

Self-test uses only temporary safe data. It checks request write/read metadata,
13-digit expiry acceptance and stale/over-limit rejection, and FD3 pipe
handoff, EOF, and callback exit-status behavior. It does not need KeePass,
`sudo`, the launcher, the parent helper, an issuer, or network access. The
self-test intentionally does not perform destructive cleanup.

The actual handoff synthetic test exercises the complete `approval_fd3_handoff`
shape without provider access:

```sh
scripts/n8n_unarchive_acceptance.sh --handoff-self-test
```

It uses a mock approval helper through the same `sudo`/root-`bash` FD3-to-
stdout bridge and a mock launcher that consumes one JSON envelope, verifies
receipt of a synthetic non-secret token, returns one production-shaped safe
verified response with target IDs nested under `before.id` and `after.id`,
and asserts one invoke, EOF, helper/reader/invoke exit status `0`, and no
retry. It does not print the token or provider body and does not add a FIFO or
another transport.
