# n8n unarchive acceptance

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
The parent-binding executable is configurable with `--parent-helper` or
`N8N_PARENT_BINDING_HELPER`; the verified provisioned default is the rc20
binary shown above. A legacy path named
`/srv/dev-ssd/fcp/targets/nqm81-cbor-helper/release/nqm81-cbor-helper` is a
local diagnostic symlink to `/tmp` and is not a production entrypoint. Missing,
unknown, or symlinked helper paths stop before any provider call.

The fixed approval root is
`/var/lib/fwc-n8n/approval-requests`; the generated request is root-owned,
mode `0600`, and contains the exact input/precondition. Request contents are
transport-only and are never copied to evidence. Evidence, when requested,
contains only the redacted baseline/invoke/final projections and a summary;
raw provider responses, request bodies, tokens, seeds, and secrets are not
persisted there.

The approval helper runs once through `sudo -n` and a 40-second `timeout`,
inside the 45-second request TTL. Because sudo-rs closes inherited FD3, a
root `bash -c` maps the helper's FD3 to stdout and the parent maps stdout back
to its protected FD3 pipe; the token is streamed into the single launcher
invocation and is never placed in a shell variable, file, or evidence.

## Outcomes

- `pass`, exit `0`: the independent readback proves the workflow is inactive,
  unarchived, unpublished, and has the same draft graph digest. Draft/state/
  version rotation is allowed by the unarchive contract.
- `STOP`, exit `10`: the baseline, helper, request, approval, or pre-invocation
  contract failed; no unarchive was attempted.
- `unknown`, exit `20`: the unarchive may have started but the one readback was
  unavailable or did not prove the exact postcondition. Do not retry or replay
  this run; investigate the redacted evidence and start a separately approved
  acceptance only after the operator decides it is safe.

## Offline self-test

```sh
scripts/n8n_unarchive_acceptance.sh --self-test
```

Self-test uses only temporary safe data. It checks request write/read metadata,
13-digit expiry acceptance and stale/over-limit rejection, and FD3 pipe
handoff, EOF, and callback exit-status behavior. It does not need KeePass,
`sudo`, the launcher, the parent helper, an issuer, or network access.
The self-test intentionally does not perform destructive cleanup.
