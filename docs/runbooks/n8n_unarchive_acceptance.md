# n8n unarchive acceptance

## Current acceptance and closeout (2026-09-21; PASS)

`flywheel_connectors-nqm81.23` acceptance is complete for EEC and Hetzner.
The main fix is `4ef0578dc`; the installed candidate is
`release-20260920-02d215cfd-unarchive-introspection-rc26` (rc26).
The retained evidence is server-specific:

| Server | Workflow | PASS evidence directory |
| --- | --- | --- |
| EEC | `2Zdk8MWoC70eyqeb` | `/srv/dev-ssd/fcp/nqm81.23/acceptance-eec-20260921-9c42e6a1` |
| Hetzner | `uQXXNMWE2lzlCgag` | `/srv/dev-ssd/fcp/nqm81.23/acceptance-hetzner-NZAx85` |

Each acceptance used exactly one fresh archived baseline GET, one approval,
one typed REST unarchive, and one independent GET. Both prove
`isArchived: true -> false`, with `active=false`, `published=null`, and
`activeVersionId=null` before and after, and the draft graph digest preserved.
Draft version identifiers and state digests rotated as allowed by the contract.
The invoke projections report `status: "verified"`; the summaries report
`verdict: "pass"` and zero approval, invocation, and final-GET exit statuses.
There was no retry, and no raw provider/request bodies, tokens, seeds, or
secrets were persisted in the evidence.

This closes bounded REST unarchive acceptance only. `restore_workflow_version`
is a separate version-restore operation; this result does not repair or accept
MCP `archive_workflow`. Earlier NO-GO comments and acceptance history remain
historical records of their candidates/attempts, not the current verdict.

The typed REST activation source path is now implemented for EEC and Hetzner,
but it is not live-accepted and no release or promotion is claimed. Follow
the bounded activation procedure below only with a newly created disposable
credential-free Webhook workflow; do not reuse this unarchive runner for a
provider write and do not infer live acceptance from source or offline tests.

## Activation acceptance (source implemented; live unaccepted)

This is a separate, supervised EEC-then-Hetzner procedure for
`n8n.workflows.activate`. It is deliberately bounded to one fresh disposable
draft per server and never invokes its Webhook, archives it, deletes it, or
performs generic cleanup. The procedure is reproducible through the existing
`fwc-n8n run-once` envelope and the same fixed parent-binding and approval
helpers; it is not a generic REST runner.

Before any approval-request file or provider write, run the repository
acceptance preflight and verify the candidate's source/inventory evidence.
Stop before the first provider call if preflight, binary/manifest binding,
server selection, credential-reference readiness, or evidence-directory
checks fail. Use a unique UUID-v4 run ID and Webhook path/name for each server;
the draft graph must contain one `n8n-nodes-base.webhook` node and no
`credentials` field, with `availableInMCP` left at the connector's forced
default `false`.

For each server, in this exact order:

1. Create the disposable draft with one fresh `create_draft` approval and
   UUID idempotency key. Use only the bounded graph, no credential references,
   and retain the redacted creation projection needed to identify the new
   workflow; never persist the raw request, approval token, or provider body.
2. Read the new workflow once and require inactive, unarchived,
   `activeVersionId=null`, `published=null`, and a non-empty draft graph/state
   digest. This is the baseline for the first transition.
3. Build a fresh `n8n.workflows.activate` input with `active=true`, the exact
   current `versionId` when available, the complete baseline precondition, a
   fresh approval reference, and a fresh UUID. Bind the exact original input
   and `fwc-n8n://SERVER/workflows/ID` resource, then perform exactly one
   baseline GET, one `POST /api/v1/workflows/{id}/publish`, and one independent
   GET. Success requires active=true, matching active/published version IDs,
   matching published graph digest, and preserved ID, draft graph, and archive
   state.
4. Read back the active state before preparing deactivation. Build a second,
   independently approved input with `active=false`, a fresh approval
   reference and fresh UUID, and the exact active-state precondition. Perform
   exactly one baseline GET, one no-body
   `POST /api/v1/workflows/{id}/unpublish`, and one independent GET. Success
   requires `active=false`, `activeVersionId=null`, `published=null`, and the
   same ID, draft graph, and archive state.

Run the complete sequence on EEC first, then repeat from a newly created draft
on Hetzner. Never invoke the Webhook, call an execution operation, reuse an
approval or UUID, retry a timeout/ambiguous response, or start the other
server after an unresolved result. If any provider result is malformed,
contradictory, times out, or has a readback mismatch, retain only the redacted
projection, mark the run `unknown`/`STOP`, and stop; do not create a cleanup
request. No automatic delete, archive, or generic cleanup is part of this
acceptance—an operator must decide separately what to do with a disposable
workflow after the evidence is reviewed.

Retain only redacted baseline/invoke/readback projections and a summary with
server, workflow ID, operation sequence, fresh correlation/approval reference
hashes, statuses, postcondition verdicts, and
`raw_provider_bodies_persisted=false`, `raw_request_bodies_persisted=false`,
`tokens_persisted=false`, and `secrets_persisted=false`. A live acceptance
claim requires both server runs and durable evidence; source implementation,
focused WireMock/host tests, and an assembled candidate alone are insufficient.

The executable activation runner is an activation-specific extension of this
acceptance script; it is not a generic REST runner. Run its contract preflight
and self-test before any live invocation:

```sh
scripts/n8n_unarchive_acceptance.sh --activation-self-test
```

Then run exactly one server at a time, EEC first and Hetzner only after the EEC
run is a verified `pass`:

```sh
scripts/n8n_unarchive_acceptance.sh \
  --activation --server eec \
  --parent-helper /srv/dev-ssd/fcp/targets/nqm81-cbor-helper-rc20/release/nqm81-cbor-helper \
  --evidence-dir /srv/dev-ssd/fcp/nqm81.24/activation-eec-evidence

scripts/n8n_unarchive_acceptance.sh \
  --activation --server hetzner \
  --parent-helper /srv/dev-ssd/fcp/targets/nqm81-cbor-helper-rc20/release/nqm81-cbor-helper \
  --evidence-dir /srv/dev-ssd/fcp/nqm81.24/activation-hetzner-evidence
```

Activation mode validates a closed plan before the first provider call: one
credential-free Webhook draft with `availableInMCP=false`, one create/readback,
one publish/readback, one active-state GET, one unpublish, and one final
independent GET. The final GET must prove the same workflow ID and selected
draft version and graph, `active=false`, `activeVersionId=null`,
`published=null`, and `isArchived=false`; missing, malformed, or mismatched
state is `unknown` and can never produce `pass`. It uses only
`fwc-n8n run-once`, permits zero retries and zero execution/cleanup actions,
and the self-test reports `provider_actions:0`; it does not invoke the Webhook,
use credentials, or persist request/provider bodies, tokens, or secrets. The
activation evidence directory is mandatory, must be below the persistent SSD
root, and must be new for each run. The runner creates it with an exclusive
`mkdir`; a reused directory or existing claim refuses before a provider
mutation. Immediately after approval is available and before each create,
publish, or unpublish handoff, the runner atomically creates and syncs one
mode-0600 claim file with the operation, server, run and correlation IDs, and
bounded target. Claims are never replaced or erased. Approval or setup failure
before the first invocation handoff is `STOP`; once a create, publish, or
unpublish handoff may have started, any nonzero result, missing or invalid
create ID, empty/malformed projection, uncertain readback, timeout, or evidence
write/validation failure is terminal `unknown`. The runner emits `unknown`
even if it cannot persist a redacted projection or summary, so durable evidence
is not guaranteed for that outcome. It makes no further provider calls after
that result. Do not retry or start the next server; reconcile the workflow's
current provider state before any new invocation.

A live `pass` is emitted only after the runner has durably written, reread, and
validated the complete redacted evidence bundle. It contains
`activation-plan.json`, six `activation-*.json` projections (including
`activation-final-readback.json`), three
`activation-claim-{create,publish,unpublish}.json` receipts, three
`transition-{create,publish,unpublish}.json` records, and `summary.json`. The
summary lists the final GET and every mutation claim; its `evidence_complete`
flag and all claim, transition, and projection postconditions must validate.
After a mutation may have started, any missing file, failed write, metadata
mismatch, or validation failure returns `unknown`, never `pass` or a retry-
inviting `STOP`; the `unknown` result is emitted even when evidence cannot be
persisted. Before the first mutation, setup or evidence failures remain `STOP`.

The offline activation self-test drives this same production runner through
local launcher, approval, and parent-binding stubs. It checks the successful
sequence, one-shot unknown outcomes for each ambiguous mutation, invalid
create ID after handoff, evidence persistence failure after create,
pre-handoff approval failure, final-GET failure and mismatch, reused evidence
and claim refusal, and that raw/secret sentinels do not enter evidence. All
stubs are local and never call an issuer or provider.

## Explicit existing workflow/version acceptance (operator invoked)

This mode is only for an operator who has already selected one workflow and
one exact draft version. It never searches for a target, creates a workflow,
invokes a workflow or Webhook, retries a mutation, deletes anything, or runs
automatically as part of the disposable-workflow acceptance above. The server,
workflow ID, version ID, and durable evidence directory are all mandatory.

```sh
scripts/n8n_unarchive_acceptance.sh \
  --existing-version \
  --server eec \
  --workflow-id WORKFLOW_ID \
  --version-id DRAFT_VERSION_ID \
  --parent-helper /srv/dev-ssd/fcp/targets/nqm81-cbor-helper-rc20/release/nqm81-cbor-helper \
  --evidence-dir /srv/dev-ssd/fcp/nqm81.24/existing-version-evidence
```

Production evidence must be a fresh directory below the mounted persistent
`/srv/dev-ssd/fcp/nqm81.24` root. The runner rejects `/tmp`, path traversal,
symlinked path components, or an absent SSD mount before approval or provider
calls; it does not fall back to another location. Offline self-tests use their
private temporary fixture directory only while explicit `SELF_TEST` mode is
active.

Before approval, the runner performs one independent GET and stops unless that
exact workflow is inactive, unarchived, unpublished, has no active version,
and its current draft version equals `--version-id`. It binds a fresh
`n8n.workflows.activate` approval request to the selected version and full
current lifecycle precondition, then issues at most one publish. A publish is
accepted only after an independent GET proves that the same workflow and exact
version are active and published, the draft graph is unchanged, and the
workflow remains unarchived.

Only after that readback passes does the runner construct a new unpublish input
with a separate approval reference, UUID idempotency key, and the newly read
active-state precondition. It issues at most one unpublish and performs one
final independent GET. Success requires the same selected draft version and
graph, `active=false`, `activeVersionId=null`, `published=null`, and
`isArchived=false`.

An unknown or ambiguous publish result without a matching active-state
readback, any mismatched readback, unknown unpublish result, or inconclusive
final GET is terminal: record only redacted projections/statuses and return
`unknown`/`STOP`; never retry a mutation, delete, or invoke the workflow. The
sole bounded continuation for the known historical flat-response projection
case is described below: it requires the durable independent GET to prove the
exact published state, performs a new GET and approval, and sends at most one
unpublish. The durable evidence includes the explicit target/version plan,
baseline, mutation projections, independent readbacks, transition records,
and a summary with secret/body persistence flags. Do not reuse an approval
request or evidence directory for another run.

The focused offline regression exercises the production acceptance runner
through local launcher, parent-binding, and approval-helper stubs. The stubs
check the exact production precondition fields and BLAKE3 state-digest format
(lowercase `blake3-256:` prefix and 64 ASCII hexadecimal characters, either
case). Regression cases include malformed and missing baseline and publish
readback state digests, plus rejection of a production `/tmp` evidence path
before any approval or provider call. It does not call the approval issuer or
provider:

```sh
scripts/n8n_unarchive_acceptance.sh --existing-version-self-test
```

The test also preserves successful publish/readback/unpublish/readback, a
failing baseline precondition, ambiguous publish and unpublish results, and
mismatched publish/final readbacks. Passing this offline test is implementation
evidence, not live provider acceptance or approval.

### Continue only the unpublish after a confirmed publish readback

Do not rerun `--existing-version` against a workflow that is already published:
that mode expects an inactive baseline and would stop. Never repeat its publish.
For the specific historical case where the runner recorded
`publish_outcome_unknown` because it did not recognize the flat activation
response, continuation is allowed only when the durable independent
`existing-publish-readback.json` proves the selected workflow/version is active
and published with the original draft graph, and the prior summary proves one
publish attempt, successful publish/readback process statuses, zero unpublish
attempts, and zero retries. The historical redacted invoke projection must be
the known flat-response projection; any other source evidence is rejected.

Use a new durable output directory and name the exact source evidence directory:

```sh
scripts/n8n_unarchive_acceptance.sh \
  --continue-unpublish \
  --server eec \
  --workflow-id WORKFLOW_ID \
  --version-id DRAFT_VERSION_ID \
  --source-evidence-dir /srv/dev-ssd/fcp/nqm81.24/PRIOR-PUBLISH-EVIDENCE \
  --parent-helper /srv/dev-ssd/fcp/targets/nqm81-cbor-helper-rc20/release/nqm81-cbor-helper \
  --evidence-dir /srv/dev-ssd/fcp/nqm81.24/UNPUBLISH-CONTINUATION-EVIDENCE
```

Continuation performs one fresh GET and proceeds only if the workflow remains
active/published at that exact version, with the same state digest and draft
graph as the saved publish readback. It then creates a fresh short-lived
approval and idempotency key, durably claims the source run's one unpublish
attempt immediately before dispatch, sends at most one unpublish, and performs
one independent GET. An existing claim blocks every replay. A pre-dispatch
approval failure has no claim and no provider mutation; a claimed invocation
with an unknown response, mismatched state, or inconclusive final GET is
terminal, requires no retry, and must not be followed by another provider
write. The mode never republishes, invokes a Webhook/workflow, or deletes the
workflow.

## Runner scope

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
`approval_helper_status` and
`approval_reader_status` fields; no helper output or other sensitive material
is captured.

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

## Offline self-test

```sh
scripts/n8n_unarchive_acceptance.sh --self-test
```

Self-test uses only temporary safe data. It checks request write/read metadata,
13-digit expiry acceptance and stale/over-limit rejection, and FD3 pipe
handoff, EOF, and callback exit-status behavior. It does not need KeePass,
`sudo`, the launcher, the parent helper, an issuer, or network access.
The self-test intentionally does not perform destructive cleanup.

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
