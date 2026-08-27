# `fwc-n8n` operation contract

> Status: Phase 0 accepted contract
> Contract version: `1.0.0`
> Bead: `flywheel_connectors-nqm81.1`
> Date: 2026-08-09

This document freezes the accepted public surface for the on-demand n8n
connector and remains normative for the `fwc-n8n` project. Current runtime and
installation evidence is called out explicitly below; the
`connectors/n8n` and `connectors/mcp-bridge` READMEs remain the source of truth
for implementation details.

No provider call, live workflow change, credential change, process stop, or MCP
profile change is authorized by this contract.

**Current host evidence (2026-08-25, read-only):**
`/usr/local/lib/fwc-n8n/current` points to
`release-20260824-90819213-static`, whose installed `fwc-n8n status` reports
`{"bundleAvailable":true}`. The resolved tree contains both `provenance.json`
and `provision-receipt.json`, and their release/revision metadata agrees with
this release. Receipt presence and matching metadata alone do not establish
cryptographic verification, live provider acceptance, or current-release live
acceptance; no such live/API invocation is claimed here. No release switch was
performed by this documentation update.
The fixed runtime policy records local `n8n-mcp` package version `2.69.2`;
the source update fixtures pin the same version. This is version evidence only,
not a live provider check.

Current source boundary: `fwc-n8n` is a thin typed CLI for `resolve`, `route`,
`run-once`, `update-review detect`, `provision [--mode preflight|apply]`, and
`status`. `provision` defaults to read-only `preflight`; mutation requires the
explicit owner-gated `provision --mode apply`. `run-once` supports nine Phase-1
REST reads, guarded REST draft create/update, typed source paths for lifecycle
`publish`/`unpublish` and archive, two local knowledge/validation operations,
and one official-MCP discovery operation, `n8n.capabilities.inspect`, plus the
bounded `n8n.workflows.delete_disposable` cleanup path. The latter is not a
general workflow-delete capability: it requires a host-issued receipt proving
that the same workflow was created through the bounded draft path.
draft-write
packet is source-only: the installed immutable release remains the accepted
read-only/discovery bundle until a separate owner-gated release and disposable
workflow live acceptance with rollback. Official discovery accepts only EEC or Hetzner and
an empty operation input. It requests a separate official-MCP broker purpose,
selects a fixed per-server `fcp.mcp-bridge` inventory, and maps internally only
to `mcp.tools.list`. The host issues a one-call `mcp.tools.read` capability,
injects a request-scoped bearer token over the inherited credential channel,
and reuses owned connector teardown. There is no generic MCP method, remote
tool name, URL, header, or token field on the public surface.
The bridge scans every provider description in blocking mode, then the wrapper
discards all descriptions and raw schemas. The public result retains only
sorted tool names, SHA-256 input/output schema digests, and explicit
`unknown`/`unreviewed` markers until the owner approves a capability policy.

Implementation status snapshot (2026-08-19): the host-side local
`n8n-mcp` update executor and its security primitives are implemented behind
the connector boundary. The public CLI still has no registry fetch, `npm`
invocation, or apply mode for `update-review`. Its separate explicit
`provision --mode apply` path is limited to fixed-root, proof-carrying,
owner-gated immutable release promotion; it is not a generic live update
command. The implementation status
and evidence are maintained in `connectors/n8n/README.md`; this document
continues to define the accepted public contract and owner gates.

The immutable bundle contract requires twelve exact artifacts, including
`fcp-mcp-bridge`, its manifest, and separate EEC/Hetzner official-MCP
inventories. A historical 2026-08-17 acceptance snapshot recorded the
distinct `n8n-eec-mcp` / `n8n-hetzner-mcp` owner entries and 34 discovered tools
per server; that snapshot is not the current release identity. Every discovered
capability remains `unknown`/`unreviewed` and `tools/call` remains unavailable
through the public surface. Bundle verification currently
trusts root ownership, restrictive filesystem modes, and serialized atomic
privileged updates locally. Its path-based checks do not defend against a
concurrent malicious root updater. The source packet verifies an owner-signed
`provision-receipt.json` when a release is evaluated. The installed release
above contains such a receipt with matching release metadata, but filesystem
presence does not by itself prove that signature verification was performed or
that the release was live accepted.
The source-only `fwc_n8n_provision` packet adds a typed fixed-root preflight
for owner-staged releases: it checks the existing twelve-artifact receipt,
the bounded `provision-receipt.json` covering that receipt/provenance and every
staged byte, explicit git-revision provenance, canonical non-symlink paths,
owner/mode and size bounds, strict allowlisted inventory/policy metadata with
secret-like key/value rejection, and exact per-server official-MCP schema
bindings before returning an atomic-promotion plan. `provision-receipt.json`
carries an owner Ed25519 signature over domain-separated release/git/receipt/
provision digests and the canonical complete EEC/Hetzner binding map; the
verifier accepts only explicit owner public-key/key-id configuration and never
reads private key material. `InstallPlan::revalidate` consumes the plan into
an opaque `RevalidatedInstallPlan`; the typed `OwnerAtomicInstaller::promote`
consumes that proof and exposes only fixed read-only stage/release/current/
rollback paths. The owner implementation must revalidate the proof once more
while its root-side concurrency guard is held immediately before promotion.
The Linux `FilesystemOwnerAtomicInstaller` consumes only that proof, derives
the fixed install root from proof paths, takes an exclusive root lock, repeats
proof validation under the lock, uses no-follow directory opens and
`renameat(..., NOREPLACE)` for stage-to-release promotion, fsyncs the affected
directories, and atomically replaces `current` through a temporary relative
symlink. Before reading any receipt or artifact, release-tree validation opens
only the fixed direct children `bin/`, `manifests/`, `inventory/`, and `policy/`
relative to the already validated release root with `NOFOLLOW`; each must keep
its exact relative name and parent, directory type and inode identity, expected
owner (UID 0 in production), non-writable metadata, and canonical no-symlink
traversal. These are constants, never caller-supplied subpaths. Because the
shared validation is
repeated by plan revalidation under the owner lock and after the stage rename,
it covers stage, current/rollback immutable releases, and the promoted target
before `current` changes. Its rollback seam uses the same lock and revalidation
and never deletes releases; a failed `current` promotion leaves the immutable release
and old pointer where possible. Non-Linux fails closed. The `fwc-n8n provision`
CLI provides the narrow owner wiring: it accepts only a bounded
`fwc.n8n.provision-request.v1` envelope with release metadata and the fixed
server binding map. The public trust roots come only from immutable
release-build configuration: stdin cannot select a key ID or public key,
missing or malformed production configuration fails closed, and no private key
is read or generated. During a bounded migration,
`FWC_N8N_OWNER_PUBLIC_KEY_HEX` is the active signing root and the optional
`FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX` preserves exactly one prior rollback
root. Verification selects only a configured root by the receipt key ID; the
signer accepts only the active root, and duplicate roots are rejected. Its
default mode is read-only preflight; `--mode apply` requires
effective UID 0, while the installer seam and both Linux mutation functions
enforce that requirement again independently of the CLI. Promotion accepts
only the exact direct child `/var/lib/fwc-n8n/staging/<release_id>` with a
matching basename; mismatches, nesting/traversal, and symlink aliases fail
before mutation. The existing proof-carrying installer otherwise uses only the
fixed staging/install roots.

The first promotion also has a narrow legacy-bootstrap compatibility path. A
fixed current release without `provision-receipt.json` is accepted only when
the current symlink, direct-child release layout, ownership, provenance, and
the complete old immutable-bundle verifier all pass. This fallback has no
caller-controlled path and is not used when a provision receipt exists but is
invalid. The staged candidate still requires a complete owner-signed provision
receipt. Once the first candidate is promoted, the current pointer must pass
the new signed provision-receipt contract for every later promotion.

Output is redacted and does not expose signatures, keys, or paths. No sudo,
shell, systemd, release deletion, or live n8n operation is performed; rollback
remains a separate owner-gated boundary. The proof cannot establish atomicity
against an unrelated writer that ignores the owner lock.
The rollback target is subjected to the same complete self-relative artifact,
provenance, provision-receipt, inventory, and policy validation; only its git
revision may differ from the candidate. The remaining trusted-concurrent-root
writer window is documented and requires immediate owner-side revalidation
before the atomic rename/symlink operation. Public-key provisioning, privileged
invocation, live `current` switching, systemd, and rollback acceptance remain
separate owner gates.
The source-only `fwc-n8n-owner-sign` binary is a separate feature-gated
operator boundary, not part of the runtime connector. It accepts only a safe
release identifier, a bounded non-secret `fwc.n8n.provision-request.v1` file,
and an exact Base64 seed on stdin; it derives the fixed
`/var/lib/fwc-n8n/staging/<release_id>` path internally and rejects caller
paths. Before producing a receipt it reuses the complete no-follow unsigned
release validator, including ownership/mode checks, provenance, twelve
artifact digests, inventory/policy semantics, and exact EEC/Hetzner binding
equality. The derived Ed25519 public key and key ID must match the immutable
build-time `FWC_N8N_OWNER_PUBLIC_KEY_HEX` active trust root. A migration
release may additionally embed `FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX` for
rollback verification only; seed bytes are held in zeroizing buffers and never
come from an argument, environment variable, or
the signer’s own KeePass access. The signer emits only the signed receipt and
does not call n8n, write the stage, install a release, switch `current`, or
modify workflows. Placing that receipt into a staged tree and running the
privileged preflight/apply path remain separate owner-controlled steps. This
packet has offline coverage only; it is not live or privileged acceptance.
`n8n.targets.resolve`, `n8n.runtime.status`,
`n8n.node_resources.explore`, and `n8n.evaluations.manage` are not all
representable by that enum yet. `n8n.mcp_access.reconcile` is now represented
as a typed REST intent and host operation for bounded dry-run and guarded apply
reconciliation. The apply path uses only the public workflow REST resource;
n8n requires `name`, `nodes`, `connections`, and `settings` in that transport
payload, while the logical mutation is allow-listed to
`settings.availableInMCP`. Lifecycle fields and graph semantics are excluded
from the mutation and verified by an independent detail readback. Host run-once
adds a server-wide transient lock, UUID idempotency binding, and redacted
intent/outcome receipts. The historical owner-gated bundle passed disposable
enable/disable/readback acceptance on EEC and Hetzner; the release ID and
evidence receipt are not recorded in this contract, so that record is not
current-release acceptance. The private web bulk
endpoint remains an unaccepted provider surface; future workflows require a
later bounded reconciliation run rather than a daemon or implicit policy.
The Phase-3 lifecycle packet represents `n8n.workflows.lifecycle` as typed
`publish`/`unpublish` input with exact workflow targeting, UUID idempotency,
full lifecycle/state-digest preconditions, and current-chat approval binding.
The host now builds only the exact official MCP `publish_workflow` or
`unpublish_workflow` call after fresh `tools/list` discovery and an owner-
reviewed policy entry containing both schema digests; each operation makes one
side-effecting provider attempt, decodes the typed response, and performs an
independent REST `GET /workflows/{id}` readback. The connector's direct REST
routes remain an explicit route only where proven and fail closed otherwise.
Only bounded categories for failures proven before the provider side effect
(`official_mcp_policy_failed`, `official_mcp_capability_failed`, and related
preflight classes) may be exposed; invocation, timeout, teardown,
malformed/ambiguous response, and all other uncertain cases remain
`unknown_outcome` and are never retried automatically. A supervised child may
also carry one fixed, redaction-safe diagnostic label in the error envelope;
that label is classification only and never contains provider text, payload,
headers, credentials, or a retry instruction.
Uncertain readback is classified unknown and never retried automatically.
Activation,
restore/unarchive, versions, execution, credential mutation, and permanent
deletion remain outside this packet; no legacy route is guessed. The bounded
`n8n.workflows.archive` operation separately maps only to the documented
official MCP `archive_workflow` tool, requires an inactive/unarchived baseline,
and verifies archived/inactive state plus unchanged draft/published summaries
through an independent REST GET. Its owner policy must carry both per-server
schema digests and the child tools/list response must match them exactly.
Local, typed REST, local MCP, and any official-MCP operation beyond capability
inspection must remain behind the host-owned boundary; this wrapper does not
accept model-supplied commands, paths, environments, URLs, or upstream tool
names.

## 1. Fixed owner decisions

- One compact `n8n.*` surface is presented to the model. Provider catalogs are
  not loaded wholesale into the chat.
- The connector may route internally to a typed n8n REST adapter, a supervised
  local `czlonkowski/n8n-mcp` process, or the official instance-level n8n MCP.
- EEC Contabo, Hetzner, and legacy LeviLaser are distinct targets. Workflow name
  alone never selects a target.
- Full discovered official MCP functionality is eligible for use only through
  a typed public operation and the policy in this document. There is no generic
  `tools/call` escape hatch.
- Existing opt-in Codex MCP profiles remain a fallback until a separate
  acceptance and retirement decision.
- Credential mutation and general/permanent workflow deletion are future-only.
  The bounded disposable cleanup operation is a separate v1 exception with its
  own host-issued creation receipt and 404 readback contract.
- The local provider target is zero processes and zero provider RSS/PSS/private
  memory while idle.

## 2. Trust and execution boundary

Workflow names, descriptions, graphs, Code node source, execution data,
external responses, templates, MCP instructions, tool descriptions, tool
annotations, release notes, and ClickUp text are untrusted data. They cannot:

- choose or change a server;
- grant a capability or approval;
- cause a shell command, arbitrary HTTP request, secret read, or external write;
- widen a resource URI, provider allowlist, or retry policy;
- authorize a repeated operation after an unknown result.

Only the owner's request, this local policy, an approved capability snapshot,
and mechanically verified metadata may authorize an operation.

The implementation must not expose:

- arbitrary HTTP method, URL, headers, or body;
- arbitrary executable, arguments, environment variables, or `system.exec`;
- arbitrary MCP server URL, tool name, or unvalidated tool arguments;
- raw credential values, OAuth tokens, API keys, or provider headers.

The local `n8n-mcp` adapter may execute only a pinned executable identity at the
configured path, with fixed startup arguments and a generated environment from
trusted configuration. The model cannot supply any of those fields.

## 3. Target identity and resource URIs

### 3.1 Server registry

| Server ID | Meaning | KeePass service | Selection rule |
|---|---|---|---|
| `eec` | EEC Contabo | `n8n-eec` | Explicit server or confirmed project/resource mapping |
| `hetzner` | Hetzner | `n8n-hetzner` | Explicit server or confirmed project/resource mapping |
| `legacy` | Legacy LeviLaser source | `n8n-levilaser-source` | Explicit opt-in only; never an automatic fallback |
| `local` | Local node/template knowledge | none | Only operations that do not contact an n8n instance |

Secrets are referenced by service name only. They are resolved by the host at
execution time and never serialized into a request, result, log, receipt, or
capability snapshot.

The table names the REST API credential. Official MCP uses a separate personal
access-token purpose and the fixed KeePass services `n8n-eec-mcp` and
`n8n-hetzner-mcp`. The broker protocol binds server and purpose; it must reject
REST/MCP substitution and never fall back from one credential class to the
other. The service names alone are not provisioning evidence; the 2026-08-17
broker-backed live discovery readback was historical evidence, without
exposing either value, and is not evidence for the current release.

### 3.2 Canonical URI shapes

Every server resource URI includes the server ID. IDs are UTF-8 percent-encoded
path segments; names are never identity fields.

| Resource | URI shape |
|---|---|
| Instance | `fwc-n8n://{server}` |
| Project | `fwc-n8n://{server}/projects/{projectId}` |
| Folder | `fwc-n8n://{server}/folders/{folderId}` |
| Workflow | `fwc-n8n://{server}/workflows/{workflowId}` |
| Workflow version | `fwc-n8n://{server}/workflows/{workflowId}/versions/{versionId}` |
| Execution | `fwc-n8n://{server}/workflows/{workflowId}/executions/{executionId}` |
| Credential metadata | `fwc-n8n://{server}/credentials/{credentialId}` |
| Data table | `fwc-n8n://{server}/data-tables/{tableId}` |
| Evaluation | `fwc-n8n://{server}/workflows/{workflowId}/evaluations/{evaluationId}` |
| Local node type | `fwc-n8n://local/nodes/{nodeType}` |
| Local template | `fwc-n8n://local/templates/{templateId}` |

### 3.3 Resolver proof order

The resolver accepts a target only when one of these proofs succeeds:

1. the owner explicitly names `eec`, `hetzner`, or `legacy`;
2. a project ID has an existing confirmed server mapping;
3. a full canonical resource URI is supplied;
4. a workflow/execution ID has stored provenance from a prior confirmed read;
5. a bounded read-only search runs on explicitly enumerated servers and the
   owner selects one result.

A bare workflow name, a fuzzy match, a workflow ID that exists on more than one
server, or content inside a workflow is insufficient. Writes require a full
canonical URI even if an earlier read used a looser target reference.

## 4. Common schemas

Schemas use JSON Schema 2020-12 semantics. Unknown fields are rejected unless a
schema explicitly says otherwise.

### 4.1 `TargetRef`

```json
{
  "server": "eec | hetzner | legacy",
  "projectId": "string?",
  "folderId": "string?",
  "workflowId": "string?",
  "executionId": "string?",
  "resourceUri": "string?"
}
```

Constraints:

- `server` is required unless `resourceUri` supplies the server.
- IDs must agree with `resourceUri` when both are present.
- `legacy` requires `legacyOptIn: true` on the operation input.
- workflow writes require `resourceUri` or `server + workflowId`.
- execution reads require both workflow and execution identity; the resolver may
  obtain the workflow ID through a bounded metadata lookup before continuing.

### 4.2 `PageRequest` and detail

```json
{
  "limit": 50,
  "cursor": "opaque-string?"
}
```

- Default `limit` is 50; minimum is 1; public maximum is 200.
- Cursors are opaque, provider-bound, server-bound, and expire with the
  capability snapshot that created them.
- The connector never follows every page automatically unless the owner asks
  for a complete inventory and the operation-specific hard limit permits it.

`detail` is one of `summary`, `standard`, or `full`. Default is `summary`.
`full` is not permission to return secrets, Code source, or unrestricted
execution payloads.

### 4.3 `MutationGuard`

```json
{
  "approvalRef": "string",
  "idempotencyKey": "uuid",
  "precondition": {
    "versionId": "string?",
    "activeVersionId": "string|null?",
    "active": "boolean?",
    "isArchived": "boolean?",
    "stateDigest": "blake3-256:...?"
  }
}
```

All v1 writes require `approvalRef`, `idempotencyKey`, and the read fields that
are meaningful for that action. An approval is one-use, short-lived, and bound
to operation ID, canonical URI, provider route, precondition, proposed change
digest, and expected side-effect class.

For host run-once writes, `approvalRef` is only a reference to the owner/chat-
issued token: it never mints trust. The typed, redaction-safe run-once envelope
must carry an externally signed `approval_token`, verified with
`FCP_HOST_APPROVAL_PUBLIC_KEY` or `_FILE`. Verification requires
`token_id == approvalRef`, the typed `fcp.mcp-bridge` wrapper operation
`n8n.mcp.call`, `z:work`, the canonical official-MCP payload digest, expiry, and
the exact request constraints. The constraints also carry the typed plan digest,
which binds EEC/Hetzner, the canonical workflow resource URI and workflow ID,
the official tool name/payload, lifecycle precondition, UUID idempotency key,
and expiry as one exact owner-confirmation plan. Before credential/provider access,
the host persists a private `token_id` replay marker (after signature and
binding validation) and then the request claim; a second use of that token
fails closed even if its idempotency key differs. Missing, invalid, mismatched,
or already-consumed tokens never reach provider I/O. Official-MCP lifecycle
calls bind the child `fcp.mcp-bridge` payload digest and policy constraints in
the same way. The provider-start marker is fsynced immediately before the single
`invoke_handler_inner` boundary; a restart with a pending claim, provider-start
marker, or missing terminal receipt is `unknown` and never auto-retried. Receipt
and marker fields are digests only and are checked against the reconstructed
typed plan before replay is refused.

The bounded owner-confirmation seam is typed to publish, unpublish, and archive
only. It computes a redaction-safe plan digest over the exact EEC/Hetzner
target, operation, canonical input and precondition digests, official-MCP tool
and payload digest, UUID idempotency key, and expiry; confirmation must echo
that digest. `fcp-host` reuses the
existing `ApprovalToken` canonicalization contract through a fail-closed issuer
seam and does not load or accept private key material. This module is not a
second ledger and is not wired as an independent provider gate: the existing
host run-once path remains authoritative for cryptographic verification, full
resource/workflow/input/precondition/idempotency binding, one-use claim,
provider-attempt receipts, `unknown` recovery, and no-retry behavior. A future
trusted host/Keepass adapter must map a confirmed plan into that existing path
before any lifecycle write is enabled. Fallback MCP profiles and release/systemd
profiles are unchanged.

### 4.4 Response envelope

```json
{
  "schemaVersion": "1.0",
  "operationId": "n8n.workflows.get",
  "correlationId": "uuid",
  "status": "ok | partial | pending | denied | unknown | error",
  "resourceUri": "fwc-n8n://...? | null",
  "provider": "host | rest | local_mcp | official_mcp",
  "providerFallback": false,
  "data": {},
  "page": { "nextCursor": "string|null", "count": 0, "estimated": false },
  "readback": {},
  "warnings": [],
  "truncated": false,
  "resultBytes": 0
}
```

`data`, `page`, and `readback` appear only when applicable. Provider fallback is
never silent: `providerFallback=true` requires a warning naming the failed
preferred route and the selected route, without provider response content.

### 4.5 Normalized workflow state

```json
{
  "id": "string",
  "name": "string|null",
  "projectId": "string|null",
  "folderId": "string|null",
  "versionId": "string",
  "active": false,
  "activeVersionId": "string|null",
  "isArchived": false,
  "draft": { "versionId": "string", "graphDigest": "blake3-256:..." },
  "published": null,
  "stateDigest": "blake3-256:...",
  "updatedAt": "RFC3339|null"
}
```

`draft` is the currently saved editable graph. `published`, when present, is a
separate graph summary whose version ID equals `activeVersionId`. `active` is a
provider state flag and must be read back; it is not inferred solely from a
name, trigger, or UI label. `isArchived` is independent from both draft and
published state.

Digest contract v1:

- `graphDigest` is a provider-neutral semantic comparison digest. Its preimage
  is deterministic JSON containing exactly `nodes` and `connections`; object
  keys are recursively sorted and array order is preserved. Only the top-level
  `credentials` field on each node is removed. Code source and all other graph
  semantics remain in the preimage. The domain is
  `fwc-n8n.graph-digest.v1`, followed by a zero byte, followed by the canonical
  JSON bytes, hashed with BLAKE3-256.
- `stateDigest` is a separate write-precondition digest. Its preimage includes
  workflow identity and metadata, version/lifecycle/archive fields, timestamps
  and tags, plus complete draft and published graphs including credential
  bindings. Its domain is `fwc-n8n.state-digest.v1` with the same zero-byte
  separation and canonical JSON rules.
- Raw graph values, Code source, credential bindings, pinned data, and digest
  preimages are never returned or logged. An official MCP response that hides
  credential bindings may support semantic comparison through `graphDigest`,
  but cannot be the sole authority for a write guarded by `stateDigest`; typed
  REST readback is required.

## 5. Public operation inventory

`None`, `BestEffort`, and `Strict` below are FCP idempotency classes. A write
with `BestEffort` is never automatically retried: the class describes replay
guarantees, not permission to replay.

| Operation | Capability | Safety / risk | Approval | Idempotency | Primary provider | URI / readback | Model result cap |
|---|---|---|---|---|---|---|---|
| `n8n.targets.resolve` | `n8n.targets.read` | Safe / Low | None | None | REST | instance/project/workflow URI | 32 KiB |
| `n8n.capabilities.inspect` | `n8n.capabilities.read` | Safe / Low | None | None | official MCP | fixed EEC/Hetzner server; compact capability catalog | 64 KiB |
| `n8n.runtime.status` | `n8n.runtime.read` | Safe / Low | None | None | host | local/provider status only | 32 KiB |
| `n8n.knowledge.query` | `n8n.knowledge.read` | Safe / Low | None | None | local MCP | local node/template URI | 256 KiB |
| `n8n.node_resources.explore` | `n8n.credentials.use_read` | Risky / Medium | Interactive | None | official MCP | node/credential metadata; no secret | 256 KiB |
| `n8n.validation.run` | `n8n.validation.read` | Safe / Low | None | None | local MCP | validation subject URI/digest | 256 KiB |
| `n8n.structure.search` | `n8n.structure.read` | Safe / Low | None | None | official MCP | project/folder/tag URIs | 128 KiB |
| `n8n.workflows.search` | `n8n.workflows.read` | Safe / Low | None | None | REST | workflow preview URIs | 128 KiB |
| `n8n.workflows.get` | `n8n.workflows.read` | Safe / Medium | None | None | REST | normalized state fields | 2 MiB full |
| `n8n.workflows.compare` | `n8n.workflows.read` | Safe / Medium | None | None | official MCP | both version URIs/digests | 512 KiB |
| `n8n.workflows.create_draft` | `n8n.workflows.write` | Risky / Medium | Interactive | BestEffort | typed REST | new URI; draft/readback state | 512 KiB |
| `n8n.workflows.update_draft` | `n8n.workflows.write` | Risky / High | Interactive | BestEffort | typed REST | draft version/digest; published unchanged | 512 KiB |
| `n8n.workflows.lifecycle` | `n8n.workflows.lifecycle` | Risky / High | Interactive | BestEffort | official MCP publish/unpublish with independent REST GET readback | all normalized state fields | 256 KiB |
| `n8n.workflows.archive` | `n8n.workflows.lifecycle` | Risky / High | Interactive | BestEffort | official MCP `archive_workflow` with independent REST GET readback | archived/inactive state; draft/published unchanged | 256 KiB |
| `n8n.workflows.delete_disposable` | `n8n.workflows.write` | Risky / High | Interactive | BestEffort | typed REST `DELETE /workflows/{id}` with independent REST GET requiring 404 | exact host-issued creation receipt; inactive/unarchived precondition | 256 KiB |
| `n8n.workflows.versions` | `n8n.workflows.versions` | action-dependent | action-dependent | action-dependent | local MCP/API | version URI/state readback | 256 KiB |
| `n8n.workflows.execute` | `n8n.executions.start` | Risky / High | Interactive | BestEffort | owner-gated official MCP `execute_workflow` with exact immutable EEC/Hetzner input/output schema bindings | bounded workflow/execution IDs and initial status plus independent typed execution GET readback; post-provider readback failures are terminal unknown/no-retry; live acceptance deferred | 256 KiB |
| `n8n.executions.search` | `n8n.executions.read` | Safe / Medium | None | None | REST | execution preview URIs | 128 KiB |
| `n8n.executions.get` | `n8n.executions.read` | Safe / High | None | None | REST | execution status; data opt-in | 1 MiB full |
| `n8n.credentials.list` | `n8n.credentials.metadata.read` | Safe / Medium | None | None | official MCP | credential metadata URI | 128 KiB |
| `n8n.data_tables.search` | `n8n.data_tables.read` | Safe / Medium | None | None | official MCP | data-table URI/schema only | 256 KiB |
| `n8n.data_tables.mutate` | `n8n.data_tables.write` | action-dependent | Interactive | BestEffort | official MCP | table/schema/row-count readback | 256 KiB |
| `n8n.evaluations.manage` | `n8n.evaluations.manage` | action-dependent | action-dependent | action-dependent | local MCP | evaluation URI/status | 256 KiB |
| `n8n.audit.inspect` | `n8n.audit.read` | Safe / High | None | None | REST/local MCP | instance URI; redacted findings | 512 KiB |
| `n8n.mcp_access.reconcile` | `n8n.mcp_access.write` | Risky / High | Interactive | BestEffort | typed REST settings adapter | exact server; availability and lifecycle/graph readback | 512 KiB operation-scoped; 60 s all-current budget |

The inventory above is contract-level. The executable surfaces are deliberately
separate:

- **Manifest operations:** the current `fcp.n8n` manifest declares
  `workflows.list`, `workflows.get`, `workflows.activate`, `executions.list`,
  `executions.get`, `projects.list`, `credentials.list`, `tags.list`,
  `folders.list`, `folders.get`, `workflows.create_draft`,
  `workflows.update_draft`, `workflows.lifecycle`, `workflows.archive`,
  `workflows.delete_disposable`, `workflows.execute`, and
  `mcp_access.reconcile`. A manifest declaration does
  not override an operation's fail-closed provider gate.
- **Wrapper/host-only operations:** `n8n.capabilities.inspect` is absent from
  the connector manifest. The wrapper/host path accepts an empty operation
  input, derives a fixed EEC/Hetzner server from its bounded envelope, and
  maps only to `mcp.tools.list`.
- **Router intents:** the typed router recognizes selection intents such as
  `n8n.knowledge.query`, `n8n.validation.run`, `n8n.workflows.search`,
  `n8n.executions.search`, `n8n.structure.search`, `n8n.workflows.compare`,
  `n8n.data_tables.search`, `n8n.data_tables.mutate`, `n8n.audit.inspect`,
  and `n8n.workflows.versions`. A routing decision is not a provider
  execution path and does not imply that the selected operation is available.
- **Future/unimplemented execution paths:** `n8n.runtime.status`,
  `n8n.node_resources.explore`, `n8n.evaluations.manage`, and any router intent
  without a corresponding host/connector dispatch remain future or
  unimplemented execution paths. `restore/unarchive`, `versions`, credential
  mutation, permanent/general deletion, and the provider activation path remain
  fail-closed/non-goals.

Historical live acceptance boundary (2026-08-21; release ID and evidence receipt
not recorded here): the then-installed owner-gated bundle
passed read-only and MCP-availability reconciliation checks on EEC and
Hetzner, with disposable workflows removed after exact DELETE/404 readback.
The typed official-MCP lifecycle path is not yet live-accepted: one exact EEC
webhook publish attempt returned `unknown_outcome`, the independent REST
readback remained inactive, and the contract correctly performed no retry.
This does not authorize REST lifecycle/archive fallback, restore/unarchive, or
activation/execution operations. Archive remains policy- and tools/list-gated;
no live archive acceptance is claimed here.

The provider result is fail-closed unless it contains typed `active`,
`isArchived`, `activeVersionId`, draft/published graph summaries, and
`stateDigest` fields. Publish must confirm the requested/selected version and
active publication state; unpublish must confirm inactive state, a null active
version, and a null published graph. The provider draft must equal the baseline,
and every provider lifecycle field and digest must match the independent REST
readback. Provider-side disagreement is `unknown_outcome`; provider/readback
disagreement is `readback_mismatch`.

### 5.1 Exact operation inputs and outputs

All inputs reject additional properties and all outputs use the common envelope.
The table specifies the exact operation-specific `data` shape.

| Operation | Required input | Optional input | `data` output |
|---|---|---|---|
| `targets.resolve` | one of `resourceUri`, `server`, `projectId`, `workflowId`, `executionId` | `candidateServers[1..3]`, `legacyOptIn` | `{resolution: resolved|ambiguous|not_found, target?: TargetRef, candidates?: [{resourceUri,id,name,server}]}` |
| `capabilities.inspect` | empty `{}` operation input; fixed server comes from the host envelope | none | `{capabilities:{schema:"fwc.n8n.capabilities.v1",serverId,provider:"official_mcp",toolCount,tools:[{name,inputSchemaDigest,outputSchemaDigest,class:"unknown",status:"unreviewed"}]}}` |
| `runtime.status` | none | `correlationId` | `{idle,activeRuns,providers:[{provider,pid?,pgid?,rssBytes?,pssBytes?,privateBytes?,stopped?}]}` |
| `knowledge.query` | `action`, action fields | `detail`, `limit` | discriminated result matching the action |
| `node_resources.explore` | `target`, `nodeType`, `version`, `methodName`, `methodType`, `credentialId` | `filter`, `paginationToken`, `currentNodeParameters`, `legacyOptIn` | `{results:[{name,value,url?,description?}],paginationToken?,builderHint?}` |
| `validation.run` | `subject`, subject payload | `profile`, `target`, `detail` | `{valid,errors:[{path,code,message}],warnings:[...],normalizedDigest?}` |
| `structure.search` | `target.server`, `kind` | `query`, `projectId`, `parentFolderId`, `page` | `{items:[{resourceUri,id,name,type,parentUri?}]}` |
| `workflows.search` | `target.server` | `query`, `projectId`, `folderId`, `tags`, `active`, `isArchived`, `page`, `sort` | `{workflows:[{resourceUri,id,name,description?,active,isArchived,updatedAt?,projectId?,availableInMcp?}]}` |
| `workflows.get` | exact workflow target | `detail`, `version=draft|published|both`, `includeCode=false` | `{workflow: NormalizedWorkflowState,graph?: object,codeNodes?: [{name,digest,source?}]}` |
| `workflows.compare` | exact workflow target, `leftVersion`, `rightVersion` | `detail` | `{leftUri,rightUri,semanticDiff,layoutDiff,validationDelta}` |
| `workflows.create_draft` | target server/project, `name`, one of `workflowCode` or `graph`, `guard` | `folderId`, `skillsUsed[]`, `sourceTemplateUri` | `{workflow: NormalizedWorkflowState,created:true,validation}` |
| `workflows.update_draft` | exact workflow target, `operations[1..100]`, `guard` | `skillsUsed[]`, `autofix=false` | `{workflow: NormalizedWorkflowState,appliedOperations,semanticDiff,validation}` |
| `workflows.lifecycle` | exact workflow target, `action=publish|unpublish`, full `guard.precondition` | publish `versionId` (optional) | `{before: NormalizedWorkflowState,after: NormalizedWorkflowState}` after one exact official-MCP call and independent REST GET readback |
| `workflows.versions` | exact workflow target, `action` | `versionId`, `guard`, `page` | action-specific version list/get/rollback result |
| `workflows.execute` | exact workflow target, `mode`, `versionId`, `guard` | `inputs` (bounded), `wait=false` | `{status,operation,provider,workflowId,mode,versionId,executionId,initialStatus,retry,readback}`; only bounded identifiers/status are returned. Host admission requires the exact immutable owner-provisioned EEC/Hetzner schema binding; after any provider attempt, readback transport/decode/mismatch is terminal `unknown_outcome` with no automatic retry. |
| `executions.search` | `target.server` | `workflowId`, `status[]`, `startedAfter`, `startedBefore`, `page` | `{executions:[{resourceUri,id,workflowId,status,mode,startedAt?,stoppedAt?}]}` |
| `executions.get` | exact execution target | `includeData=false`, `nodeNames[1..20]`, `maxItemsPerNode` | `{execution:{id,workflowId,status,mode,startedAt?,stoppedAt?,retryOf?,waitTill?},data?}` |
| `credentials.list` | `target.server` | `query`, `type`, `projectId`, `onlySharedWithMe`, `page` | `{credentials:[{resourceUri,id,name,type,scopes,isManaged,isGlobal,homeProject?}]}` |
| `data_tables.search` | `target.server` | `query`, `projectId`, `page`, `includeSchema=false` | `{tables:[{resourceUri,id,name,projectId?,columns?,rowCount?}]}` |
| `data_tables.mutate` | exact table target or target project for create, `action`, `guard` | action payload | `{before?,after,affectedRows?,schemaDigest}` |
| `evaluations.manage` | exact workflow target, `action` | `runId`, `status`, `page`, `guard` | action-specific `{evaluationUri?,status?,runs?,cases?,summary?}` |
| `audit.inspect` | `target.server` | `categories[]`, `detail` | `{summary,findings:[{category,severity,resourceUri?,code,message}]}` |
| `mcp_access.reconcile` | `target.server`, `scope`, `desired`, `dryRun` | `guard`, `projectId`, `folderId`, `workflowIds[]` | `{planned,changed,skipped,exceptions,readbackDigest,receipt}` |

`knowledge.query.action` is one of:

- `tool_documentation { toolName }`;
- `search_nodes { queries[1..20], source?, includeExamples? }`;
- `get_node { nodeType, mode, detail?, propertyQuery?, version? }`;
- `search_templates { query?, nodeTypes?, task?, metadata?, page? }`;
- `get_template { templateId, mode }`;
- `sdk_reference { section }`;
- `workflow_best_practices { technique }`.

For `search_templates`, at least one of `query`, `nodeTypes`, `task`, or
`metadata` is required. `search_nodes.source`, when present, is `community` or
`verified`. `get_node.mode` is `info`, `docs`, `search_properties`, `versions`,
`compare`, `breaking`, or `migrations`; `detail` is `minimal`, `standard`, or
`full`. `get_template.mode` is `nodes_only`, `structure`, or `full`.
`sdk_reference.section` is `patterns`, `patterns_detailed`, `expressions`,
`functions`, `rules`, `import`, `guidelines`, `design`, or `all`.

Its action-specific outputs are exactly:

| Action | `data` output |
|---|---|
| `tool_documentation` | `{toolName,documentation,digest}` |
| `search_nodes` | `{nodes:[{resourceUri,nodeType,displayName,version?,source?,discriminators?,exampleCount?}]}` |
| `get_node` | `{node:{resourceUri,nodeType,version?,detail,definition?,documentation?,examples?,migrations?}}` |
| `search_templates` | `{templates:[{resourceUri,id,name,description?,nodeTypes?,metadata?}],page?}` |
| `get_template` | `{template:{resourceUri,id,name,mode,graph?,nodes?,digest}}` |
| `sdk_reference` | `{section,reference,digest}` |
| `workflow_best_practices` | `{technique,guidance,digest}` |

`structure.search.kind` is exactly `projects`, `folders`, or `tags`.
`workflows.search.sort` is one of `updatedAt:desc`, `updatedAt:asc`,
`createdAt:desc`, `createdAt:asc`, `name:asc`, or `name:desc`.

`validation.run.subject` is one of:

- `nodes`, with `nodes[1..50]` containing `name?`, `type`, `typeVersion?`,
  `parameters?`, `subnodes?`, and `isToolNode?`;
- `graph`, with a workflow graph and optional validation profile;
- `workflow_code`, with Workflow SDK source;
- `remote_workflow`, with an exact workflow target and version selector.

`validation.run.profile` is `minimal`, `runtime`, `ai_friendly`, or `strict`.
The default is `runtime`; provider-specific extra profiles cannot become public
without a contract revision.

`workflows.lifecycle.action` is exactly `publish` or `unpublish`; archive is a
separate typed `n8n.workflows.archive` operation. Restore/unarchive,
activation/deactivation, version operations, and execution cannot be
represented as aliases here; each provider action is fixed by its typed enum
and route.

`workflows.execute.mode` is exactly `manual` or `production` in the bounded
input contract. Both modes are Risky/High/BestEffort and require a current-chat
guard with exact workflow/version preconditions, UUID idempotency, bounded
input class, and side-effect summary. The provider call is only the immutable
owner-policy-bound official MCP `execute_workflow` tool with `wait=false`; the
EEC and Hetzner input/output schema digests are fixed in the owner-signed
per-server binding. A legacy unavailable sentinel may remain in an older bundle
but never admits execution. The path must return only a bounded handle and
verify the execution through an independent typed `n8n.executions.get`; `test`
and `prepare_test` remain future-only. `inputs.headers`
rejects authorization, cookie, proxy authorization, API-key, and other
credential-bearing headers; secrets must come from the workflow's existing
credential references, not model input.

For `executions.get`, `includeData=false` forbids `nodeNames` and
`maxItemsPerNode`. `includeData=true` requires `nodeNames[1..20]` and
`maxItemsPerNode` from 1 through 100. This prevents an unbounded execution dump;
the provider may apply a lower bound when its own truncation support is stricter.

Execution status filters are limited to `canceled`, `crashed`, `error`, `new`,
`running`, `success`, `unknown`, and `waiting`. Timestamps are RFC 3339 UTC.

`workflows.update_draft.operations` is a discriminated `oneOf` list. The exact
v1 operation set is:

| Type | Required fields | Optional fields |
|---|---|---|
| `updateNodeParameters` | `nodeName`, `parameters` | `replace=false` |
| `setNodeParameter` | `nodeName`, `path`, `value` | none |
| `addNode` | `node.name`, `node.type`, `node.typeVersion` | `node.id`, `parameters`, `position`, `credentials`, `disabled`, `notes` |
| `removeNode` | `nodeName` | none |
| `renameNode` | `oldName`, `newName` | none |
| `addConnection` | `source`, `target` | `sourceIndex=0`, `targetIndex=0`, `connectionType=main` |
| `removeConnection` | `source`, `target` | `sourceIndex=0`, `targetIndex=0`, `connectionType=main` |
| `setNodeCredential` | `nodeName`, `credentialKey`, `credentialId` | `credentialName` |
| `setNodePosition` | `nodeName`, `position[x,y]` | none |
| `setNodeDisabled` | `nodeName`, `disabled` | none |
| `setNodeSettings` | `nodeName`, non-empty `settings` | none |
| `setWorkflowMetadata` | at least one of `name`, `description` | none |

`path` is an RFC 6901 JSON Pointer and cannot index into arrays. Node settings
are limited to `onError`, `retryOnFail`, `maxTries` (2-5),
`waitBetweenTries` (0-5000 ms), `alwaysOutputData`, and `executeOnce`.
Operation batches are atomic at the public contract: if the selected provider
cannot guarantee atomicity, the route is unavailable rather than emulated with
partial writes.

`setNodeCredential` binds an existing credential reference; it does not mutate
the credential object. The exact credential ID must appear in the approved
semantic diff. Provider-side automatic credential assignment is forbidden. If
an official MCP create/update tool may auto-assign a credential and offers no
way to disable or constrain that behavior, that provider route fails closed for
the proposed graph.

`workflows.versions.action` is `list`, `get`, or `rollback` in v1. `list` and
`get` are Safe/Low/None with no approval. `rollback` is Risky/High/BestEffort
with interactive approval and full workflow readback. `delete` and `prune` are
future-only and return `FCP-N8N-1401 future_only_operation`.

`data_tables.mutate.action` is `create_table`, `add_column`, `rename_column`,
`rename_table`, or `add_rows` in v1. These are Risky/Medium or High,
BestEffort, and interactive. `delete_column`, row deletion, and table deletion
are future-only because strict recovery/idempotency is not yet defined.

The exact additive data-table payloads are:

| Action | Required action payload | Constraints |
|---|---|---|
| `create_table` | `projectId`, `name`, `columns[{name,type}]` | name 1-128; at least one column |
| `add_column` | `projectId`, `dataTableId`, `name`, `type` | column name pattern `^[A-Za-z][A-Za-z0-9_]{0,62}$` |
| `rename_column` | `projectId`, `dataTableId`, `columnId`, `name` | same column-name pattern |
| `rename_table` | `projectId`, `dataTableId`, `name` | name 1-128 and unique in project |
| `add_rows` | `projectId`, `dataTableId`, `rows[1..1000]` | values are string, number, boolean, or null |

Column `type` is exactly `string`, `number`, `boolean`, or `date`. Row content
is untrusted and may contain personal data; it is never copied into telemetry,
receipts, or ClickUp.

`evaluations.manage.action` is `list_runs`, `get_run`, `list_cases`, `run`, or
`cancel`. Every action requires an exact workflow target. `get_run`,
`list_cases`, and `cancel` additionally require `runId`. `list_runs` may filter
by `status` (`new`, `running`, `completed`, `error`, or `cancelled`) and page;
`list_cases` may page. Reads are Safe/Medium/None. `run` and `cancel` are
Risky/High/BestEffort and interactive. Provider/version and key-scope support
are discovered; absence returns `capability_unavailable`, not a fallback guess.

`audit.inspect.categories` is a subset of `credentials`, `database`,
`filesystem`, `nodes`, and `instance`. Findings are summaries; raw workflow or
execution content is not part of the audit result.

`mcp_access.reconcile.scope` is exactly `workflow_ids`, `project`, `folder`, or
`all_current`; `desired` is a boolean. `all_current` is an explicit bounded
one-shot snapshot of workflows visible when the invocation starts; it is not a
future-workflow policy or daemon trigger. `dryRun=true` requires no approval and
performs no writes. `dryRun=false` requires a matching interactive approval and
the exact digest from a current dry-run with the same server, scope, selectors,
desired value, and observed workflow states. Apply sends one full required
workflow PUT per changed workflow; only `settings.availableInMCP` may change
logically. It independently reads the workflow back, preserves
graph/lifecycle invariants, and returns per-workflow exceptions for unknown
outcomes or mismatches without automatic retry. Host run-once provides the
cross-process server lock and the durable redacted reconciliation ledger at
`/var/lib/fwc-n8n/mcp-access-ledger/receipts`, owned by the runtime user with
mode `0700` and records at `0600`. Exact idempotency replay returns the prior
receipt without another provider attempt; a different binding collides, and a
pending claim remains `unknown` even after retention expiry. Committed receipts
and safe temporary outcome files are reaped under the ledger lock; malformed or
unavailable ledger state fails closed. Project/folder/all-current scopes apply
only to workflows present at that time; a newly created workflow is handled on
the next explicit bounded `all_current` invocation. No daemon, scheduler, or
implicit future-workflow policy is part of this operation.

For this operation only, a present REST `settings` object with no
`availableInMCP` key is normalized to `false`, matching n8n's public workflow
serializer for the default-off state. Missing, `null`, or non-object
`settings` remains unknown and fails closed. The ordinary workflow read
projection remains presence-aware and does not infer a value for its output.

The current host implementation keeps the generic owned connector frame and
RPC timeout at `64 KiB` and `10 seconds`. Only typed
`n8n.workflows.list` and `n8n.mcp_access.reconcile` receive the bounded
`512 KiB` result frame; their per-invocation budgets are `30 seconds` and
`60 seconds` respectively. The provider response remains subject to the
independent `10 MiB` body cap and is compacted to an allow-listed result before
it crosses the connector boundary. This exception is not a generic MCP or
caller-configurable frame expansion.

## 6. Provider routing

### 6.1 Selection policy

| Intent | Preferred | Allowed fallback | Reason |
|---|---|---|---|
| Known-ID workflow/execution metadata | Typed REST | Official MCP | Small schema, bounded response, predictable latency |
| Search workflows/executions/projects | Typed REST where parity exists | Official MCP | Native pagination and filters |
| Node/template knowledge | Host-owned local MCP run-once with API disabled | Official MCP builder tools | Local indexed knowledge and validation |
| Node/workflow validation | Host-owned local MCP run-once | Official MCP | Detailed local validation without server dependency |
| Draft/published comparison | Official MCP | REST plus local validation | Official server semantics expose both graphs |
| Workflow SDK create/update | Official MCP | Typed REST only after parity | Server-side SDK and node schema validation |
| Publish/unpublish/archive/restore | Typed REST after parity | Official MCP | Typed preconditions and compact readback |
| Manual/production execution | Owner-gated official MCP `execute_workflow` | No REST fallback | Input parity and exact EEC/Hetzner schema binding are implemented; live execution acceptance and test/prepare-test remain deferred |
| Credential metadata | Official MCP | Typed REST | Official MCP strips secret data |
| Data tables | Official MCP | Typed REST after parity | Current official typed surface is broader |
| Audit/evaluations/version history | Typed REST or local MCP by capability | No silent fallback | Feature/version dependent |

Fallback requires equivalent capability, safety classification, approval
binding, precondition, output redaction, and readback. If equivalence cannot be
proven, the operation fails closed.

### 6.2 Current provider catalog mapping

The mapping covers the catalogs observed on 2026-08-08. Catalog changes are
handled by capability discovery, not by silently extending this table.

Official instance-level MCP:

| Upstream tool | Public route |
|---|---|
| `search_workflows` | `workflows.search` |
| `get_workflow_details` | `workflows.get` / `workflows.compare` |
| `execute_workflow` | `workflows.execute` (`manual` or `production`) |
| `test_workflow`, `prepare_test_pin_data` | `workflows.execute` (`test` or `prepare_test`) |
| `publish_workflow`, `unpublish_workflow`, `archive_workflow` | `workflows.lifecycle` |
| `search_projects`, `search_folders`, `list_tags` | `structure.search` |
| `get_execution`, `search_executions` | `executions.get` / `executions.search` |
| `list_credentials` | `credentials.list` |
| `get_sdk_reference`, `search_nodes`, `get_node_types`, `get_workflow_best_practices` | `knowledge.query` |
| `explore_node_resources` | `node_resources.explore` |
| `validate_workflow`, `validate_node_config` | `validation.run` |
| `create_workflow_from_code`, `update_workflow` | `workflows.create_draft` / `workflows.update_draft`; blocked when unconstrained credential auto-assignment is possible |
| `search_data_tables` | `data_tables.search` |
| `create_data_table`, `add_data_table_column`, `rename_data_table_column`, `rename_data_table`, `add_data_table_rows` | `data_tables.mutate` |
| `delete_data_table_column` | future-only data-table destructive gate |

The current fixed runtime policy records local `n8n-mcp` package version
`2.69.2`, and the source update fixtures pin the same version. The earlier
observed catalog count is historical evidence, not a current tool-count claim;
catalog names and schema digests, not a human-maintained count, are
authoritative:

| Upstream tool family | Public route |
|---|---|
| `tools_documentation` | `knowledge.query.tool_documentation` |
| `search_nodes`, `get_node`, `search_templates`, `get_template` | `knowledge.query` |
| `validate_node`, `validate_workflow`, `n8n_validate_workflow` | `validation.run` |
| `n8n_list_workflows`, `n8n_get_workflow` | workflow reads |
| `n8n_create_workflow`, `n8n_update_full_workflow`, `n8n_update_partial_workflow` | typed draft writes |
| `n8n_autofix_workflow` | propose diff, then `workflows.update_draft`; never silent apply |
| `n8n_delete_workflow` | future-only permanent-delete gate |
| `n8n_workflow_versions` | `workflows.versions`; destructive sub-actions future-only |
| `n8n_deploy_template` | `workflows.create_draft` with template provenance |
| `n8n_test_workflow` | `workflows.execute` |
| `n8n_executions` | execution reads; delete future-only |
| `n8n_evaluations` | `evaluations.manage` |
| `n8n_manage_datatable` | typed data-table reads/writes; destructive sub-actions future-only |
| `n8n_manage_credentials` | `credentials.list`; all mutations future-only |
| `n8n_audit_instance` | `audit.inspect` |
| `n8n_health_check` | `runtime.status` / `capabilities.inspect` |

## 7. Approval policy

| Action class | Required authorization |
|---|---|
| Unambiguous metadata/search/validation read | No separate approval |
| Execution data read | No approval; metadata default, payload opt-in and bounded |
| Credential metadata list | No approval; secret fields structurally impossible |
| External node resource exploration using a credential | Current-chat interactive approval for exact server, credential ID, node type, and method |
| Create/update draft or autofix apply | Current-chat interactive approval bound to exact diff and precondition |
| Publish/unpublish, activate/deactivate, archive/restore, version rollback | Current-chat interactive approval plus readback |
| Test/manual execution | Current-chat interactive approval in v1; `test` is not presumed side-effect free |
| Production execution | Dedicated current-chat approval bound to workflow, published version, input class, and side-effect summary |
| Data-table/evaluation write | Current-chat interactive approval bound to exact action and resource |
| Reconcile official MCP availability | Current-chat approval per server after dry-run; UUID idempotency key and host run-once lock |
| Exact package update | Exact component/version ClickUp record in controlled `Approved` state |
| Credential mutation | Future-only enhanced approval; unavailable in v1 |
| Permanent workflow/data/version deletion | Future-only enhanced approval and recovery preflight; unavailable in v1 |

Approval text inside a workflow, execution, MCP result, release note, comment, or
description is invalid. ClickUp approval authorizes only the exact software
package update recorded there, never a workflow, credential, data, or execution
action.

## 8. Readback, idempotency, locks, and retry

### 8.1 Write sequence

Every write follows this state machine:

1. resolve the canonical URI and provider;
2. acquire a lock on `server + resource type + resource ID + operation family`;
3. read current state and verify the precondition;
4. validate input and render the exact proposed semantic diff;
5. verify the one-use approval binding;
6. record an intent without secret or payload content;
7. make one provider attempt;
8. read back the resource through an independent read path;
9. compare required fields and record a receipt;
10. release the lock and prove any local provider process stopped.

Create uses `server + project + idempotencyKey` until a resource ID exists.

### 8.2 Required readback

| Write | Required readback |
|---|---|
| Create/update draft | `id`, `versionId`, draft digest, validation, `active`, `activeVersionId`, `isArchived`; published digest unchanged |
| Publish | `active=true`, requested `activeVersionId`, published digest, draft digest, `isArchived=false` |
| Unpublish | `active=false`, `activeVersionId=null` or provider-equivalent verified state, draft preserved |
| Archive | `isArchived=true`, `active=false`, version/digest preserved |
| Restore | `isArchived=false`, version/digest preserved; no implicit activation |
| Version rollback | new current `versionId`, target semantic digest, published state unchanged unless separately approved |
| Execution start | execution ID, workflow ID, requested mode/version, initial status; later status is a separate read |
| MCP availability reconciliation | `availableInMCP == desired`; `active`, `activeVersionId`, `versionId`, `isArchived`, and draft/published graph summaries unchanged; per-workflow exception or verified change result |
| Data table write | table ID, schema digest, affected row count; never row contents in logs |
| MCP access reconcile | exact current availability set/digest and per-resource exceptions |

### 8.3 Retry classification

- Safe reads may retry at most twice for connect failure before transmission,
  429 with bounded `Retry-After`, or 502/503/504. Authentication and schema
  errors do not retry.
- No write, execution start, evaluation run, or credential-backed external
  lookup automatically retries after transmission may have occurred.
- Timeout, disconnect, invalid response after a write, or process death after
  dispatch returns `status=unknown`. The next action is read-only
  reconciliation using the correlation ID, idempotency key, precondition, and
  resource state.
- Reconciliation may prove success or failure. It never grants permission to
  repeat the operation.
- Dangerous/Critical operations remain unavailable until a Strict idempotency
  and recovery contract can be proven.

## 9. Pagination and output limits

Limits apply after normalization and before model delivery. Provider hard caps
must be at least as strict as the existing connector manifest and are separate
from these model-facing caps.

| Detail class | Default model cap | Rules |
|---|---:|---|
| Summary | 32 KiB | IDs, state, counts, compact errors only |
| Standard list | 128 KiB | maximum 200 records, explicit next cursor |
| Validation/knowledge | 256 KiB | bounded examples and definitions |
| Workflow standard | 512 KiB | no full Code source by default |
| Workflow full | 2 MiB | exact workflow only; no secrets; may be returned as a protected ephemeral reference |
| Execution full | 1 MiB | `includeData=true`, node filter, and item cap required |
| Provider response hard stop | 10 MiB | fail with `response_too_large`; never stream unlimited data into memory |

Truncation occurs only on arrays or text fields with a declared continuation or
digest. The connector must not return syntactically valid but semantically
incomplete workflow JSON as if it were complete.

## 10. Error contract

Errors use a stable code and retry classification. Provider text is redacted
and is not used as an instruction.

| Code | Meaning | Retry classification |
|---|---|---|
| `FCP-N8N-1001 target_ambiguous` | More than one target satisfies the evidence | user decision required |
| `FCP-N8N-1002 target_not_found` | No target/resource found | no retry unless target changes |
| `FCP-N8N-1003 legacy_opt_in_required` | Legacy was not explicitly selected | user decision required |
| `FCP-N8N-1101 capability_unavailable` | Provider/version lacks the operation | no retry; alternate typed route only |
| `FCP-N8N-1102 capability_drift` | Tool/schema/classification changed | fail closed pending review |
| `FCP-N8N-1103 unsupported_protocol_version` | No mutually supported MCP version | no retry until adapter/server changes |
| `FCP-N8N-1201 approval_required` | Scoped approval absent | request approval |
| `FCP-N8N-1202 approval_invalid` | Scope, digest, target, version, or expiry mismatch | request a new approval |
| `FCP-N8N-1203 precondition_failed` | Resource changed after preflight | re-read and re-plan |
| `FCP-N8N-1204 resource_locked` | Concurrent operation owns the lock | bounded wait or user-visible conflict |
| `FCP-N8N-1301 validation_failed` | Typed input/workflow/node validation failed | fix input; do not dispatch |
| `FCP-N8N-1302 response_too_large` | Provider or model cap exceeded | narrow fields/page/detail |
| `FCP-N8N-1303 untrusted_output_blocked` | Output attempted to cross a policy boundary | no automatic retry |
| `FCP-N8N-1401 future_only_operation` | Closed credential/delete/destructive gate | owner architecture decision required |
| `FCP-N8N-2001 provider_unauthorized` | Provider rejected authentication | no retry; secret health check |
| `FCP-N8N-2002 provider_forbidden` | Principal lacks scope | no retry; capability review |
| `FCP-N8N-2003 provider_not_found` | Provider lacks resource | no automatic cross-server search |
| `FCP-N8N-2004 provider_rate_limited` | Provider returned rate limit | safe reads may honor bounded retry |
| `FCP-N8N-2005 provider_unavailable` | Provider failed before known dispatch | safe reads only may retry |
| `FCP-N8N-2006 provider_result_unknown` | Mutation/run may have occurred | reconcile; never auto-repeat |
| `FCP-N8N-3001 process_start_failed` | Local provider did not start/handshake | no provider dispatch |
| `FCP-N8N-3002 process_stop_failed` | Child identity still exists after teardown | operation fails closeout and alerts |

## 11. Capability discovery and MCP compatibility

Capability discovery is per server and never copied from EEC to Hetzner or
legacy. The current wrapper emits this redacted compact result:

```json
{
  "capabilities": {
    "schema": "fwc.n8n.capabilities.v1",
    "serverId": "eec | hetzner",
    "provider": "official_mcp",
    "toolCount": 0,
    "tools": [
      {
        "name": "tool_name",
        "inputSchemaDigest": "sha256:...",
        "outputSchemaDigest": "sha256:...",
        "class": "unknown",
        "status": "unreviewed"
      }
    ]
  }
}
```

No workflow payload, Code source, execution data, tool response, credential
value, or auth header is stored in this snapshot.

### 11.1 Release-bound capability evidence (owner decision, 2026-08-25)

The canonical capability snapshot/evidence is release-bound. It is read only
from immutable `/usr/local/lib/fwc-n8n/current` or from a specifically
identified immutable release under the same `/usr/local/lib/fwc-n8n` install
root. A separate checked-in volatile catalog is not canonical. EEC and
Hetzner evidence remains separate and must not be mixed.

The release-bound files are:

- `inventory/eec.json` (EEC only);
- `inventory/hetzner.json` (Hetzner only);
- `inventory/eec-official-mcp.json` (EEC only);
- `inventory/hetzner-official-mcp.json` (Hetzner only);
- `policy/local-mcp.json`;
- `provenance.json`;
- `provision-receipt.json`.

These files are evidence inputs for the selected immutable release. The
documents retain only schema, redacted references or digests, and acceptance
status. They do not retain provider catalogs, workflow or other payloads, or
secrets.

The operator boundary is:

- the existing `status` and read-only `provision` preflight contract are for
  status and validation only; they do not install a release or switch
  `current`;
- verification must establish provenance, receipt validity, artifact digests,
  ownership/modes, and the fixed release layout before an owner-gated action;
  receipt presence or matching metadata is not proof of cryptographic
  verification, live provider acceptance, or current-release acceptance;
- rollback is owner-gated only and may target a preserved immutable release
  after the same fixed-root validation; immutable releases are not deleted;
- logs and operator receipts are redacted. No additional log path is defined
  here; the fixed runtime roots are `/usr/local/lib/fwc-n8n`,
  `/var/lib/fwc-n8n/staging`, and `/var/lib/fwc-n8n/mcp-access-ledger`.

`n8nVersion`, `mcpEra`, `protocolVersions`, `apiScopeDigest`, `capturedAt`,
`expiresAt`, `snapshotId`, and `publicRoute` are not fields emitted by the
current wrapper; they are future metadata only. The current path selects a
fixed official-MCP inventory and invokes only host-owned `mcp.tools.list`.
It has no REST fallback and accepts no caller-controlled method, URL, header,
token, or tool name.

The stateless protocol reduces connection/session state but does not itself
guarantee zero memory: a host may still keep a client process, HTTP pool, cached
catalog, or model-visible schemas resident. The host-owned local provider path
must reach zero idle provider memory through bounded process ownership and
teardown, regardless of which MCP era the remote server supports.

The connector must not assume that Codex, n8n, and the local bridge support the
same revision. Current code in `connectors/mcp-bridge` supports the reviewed
modern and legacy transport paths with bounded responses, authenticated
credential references, capability enforcement, approval enforcement, and
process teardown. It remains a provider adapter behind typed public operations,
not a generic model-visible `tools/call` surface.

Catalog policy:

- unchanged approved read tools may continue within snapshot TTL;
- a removed tool returns `capability_unavailable`;
- a new or changed write/execution/credential/destructive tool is `blocked`;
- a read tool whose schema changes in security-relevant fields is also blocked;
- no catalog description or annotation can downgrade risk;
- provider cache TTL is honored only within local maximums; deterministic tool
  order and schema digests are used for comparison and prompt-cache efficiency.

## 12. Process lifecycle and telemetry

Each local provider call gets a new process group and a correlation ID. The host
records executable identity, PID, PGID, start time, and executable digest before
dispatch. Teardown closes the protocol, sends bounded graceful termination,
escalates only to the same verified process group, and then proves no matching
process remains. PID reuse or identity mismatch is an error, not permission to
kill a process.

Allowed telemetry fields:

- server ID, operation ID, provider, correlation ID, safe resource ID/hash;
- start/end time, startup/provider/total latency;
- request and response byte counts without content;
- result code, retry classification, provider fallback flag;
- PID/PGID identity result, final process status, and `stopped=true|false`;
- RSS, PSS, and private memory before, during, 5 seconds after, and 30 seconds
  after a benchmark call.

Prohibited telemetry includes API keys, tokens, credential values, auth
headers, workflow JSON, Code source, execution payloads, customer/patient
messages, external response bodies, and raw release notes.

### 12.1 Local `n8n-mcp` update executor boundary

The trusted local-provider update path is review-first and host-owned:

- candidate, stage plan, metadata, registry URL, and exact artifact SRI are
  bound before stage creation; a mismatch performs no stage I/O;
- archive listing is streamed with a hard output bound and absolute deadline;
  timeout handling kills and waits for the same child, and non-zero, oversized,
  or I/O failures are fail-closed;
- the receipt digest is checked before and after listing and again on a fresh
  descriptor immediately before extraction, so the validated artifact cannot be
  silently replaced between those phases;
- failed materialization, extraction, re-verification, and candidate-binding
  paths discard only the exact stage through bounded descriptor-relative
  cleanup. Cleanup failure is terminal and retains both error causes; cleanup
  is never run after activation starts;
- the executor accepts only fixed stage-I/O operations. It cannot receive a
  model-supplied command, environment, path, URL, registry script, or npm
  lifecycle instruction. Registry scripts and release notes remain data, not
  authority.

The executor's apply path is tested offline, but wiring registry discovery and
live acceptance remain separate gates. A failed
exact precondition returns before the component lock is acquired; callers must
not infer lock ownership from that error.

## 13. Future-only gates

### 13.1 Credential mutation

No v1 schema accepts credential secret material. Future create/update/test/
rotate/delete operations require a separate owner decision, KeePass or a
protected host channel, consumer preflight, secret-free readback, and rollback.
OAuth refresh tokens and client secrets must never cross the model boundary.

### 13.2 Disposable workflow deletion and permanent workflow deletion

The narrowly scoped `n8n.workflows.delete_disposable` operation is the only v1
provider-delete path. It is reserved for cleanup of a workflow created by the
bounded `n8n.workflows.create_draft` path. A delete request must carry the
host-issued `creationReceipt`, the exact same-server workflow target, a full
inactive/unarchived precondition, a UUID idempotency key, and current-chat
approval. The host validates the receipt against its existing create outcome
record before provider access. The connector performs one typed
`DELETE /workflows/{id}` attempt and an independent `GET`; only a 404 readback
is success. Timeout, transport failure, malformed response, conflict, or a
still-present workflow is terminal unknown and is never retried automatically.
The durable host run-once receipt remains the sole replay/unknown boundary.

General and permanent workflow deletion remain future-only. They require prior
archive, `active=false`, `isArchived=true`, an encrypted recovery export
without credentials/sensitive execution data, dependency inspection, Strict
idempotency, a separate short-lived approval, and unknown-result reconciliation.

### 13.3 Other destructive provider sub-actions

Execution deletion, workflow-version delete/prune, credential mutation, data
table/row/column deletion, and unbounded batch mutation return
`future_only_operation` until their own recovery and Strict-idempotency contracts
are accepted.

## 14. Owner decisions (accepted)

The owner accepted all six policy decisions below together on 2026-08-09.
They are normative for v1 unless changed by a later explicit owner decision:

1. credential-backed `node_resources.explore` always requires current-chat
   approval even though it is nominally a read;
2. all test/manual workflow executions require current-chat approval in v1;
3. official MCP data-table writes are available only for additive/rename actions;
   all delete actions remain future-only;
4. version rollback and evaluation run/cancel are included in v1 as approved
   writes, while version deletion/pruning is future-only;
5. the public page maximum is 200 and full execution data requires both node and
   item bounds;
6. the current official MCP and local MCP catalogs are fully reachable only
   through the typed mappings above, never through generic `tools/call`.

The owner additionally decided on 2026-08-25 that the canonical capability
snapshot/evidence is release-bound and must be read only from immutable
`/usr/local/lib/fwc-n8n/current` or a specifically identified immutable release
under that install root. The release-bound EEC and Hetzner inventory files,
`policy/local-mcp.json`, `provenance.json`, and `provision-receipt.json` must
remain server-separated. Documentation stores only schema, redacted
references/digests, and acceptance status; it does not store catalogs,
payloads, or secrets. Status/read-only preflight, provenance/receipt/digest/
ownership verification, owner-gated rollback to a preserved immutable release,
and redacted logs remain the operator boundaries. Receipt presence is not
cryptographic or live acceptance.

Acceptance of these decisions completes the policy gate for
`flywheel_connectors-nqm81.1`. Runtime work remains governed by the individual
dependent beads and their own acceptance criteria.

## 15. Primary references

- [OpenAI Codex MCP configuration](https://developers.openai.com/codex/mcp/)
- [n8n instance-level MCP setup](https://docs.n8n.io/connect/connect-to-n8n-mcp-server/)
- [n8n MCP tool reference](https://docs.n8n.io/connect/connect-to-n8n-mcp-server/mcp-server-tools-reference/)
- [n8n public API reference](https://docs.n8n.io/api/api-reference/)
- [MCP specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP 2026-07-28 key changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [`czlonkowski/n8n-mcp`](https://github.com/czlonkowski/n8n-mcp)
