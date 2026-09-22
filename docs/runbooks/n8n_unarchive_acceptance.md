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
one publish/readback, one active-state GET, and one unpublish/readback. It uses
only `fwc-n8n run-once`, permits zero retries and zero execution/cleanup
actions, and the self-test reports `provider_actions:0`; it does not invoke the
Webhook, use credentials, or persist request/provider bodies, tokens, or
secrets. A timeout, malformed response, or readback mismatch returns
`unknown`/`STOP`; do not retry or start the next server after an unresolved
result.

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
