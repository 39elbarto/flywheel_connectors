# `fwc-n8n` operation contract

> Status: Phase 0 accepted contract
> Contract version: `1.0.0`
> Bead: `flywheel_connectors-nqm81.1`
> Date: 2026-08-09

This document freezes the accepted public surface for the on-demand n8n
connector before provider or runtime implementation begins. It is normative for
the `fwc-n8n` project, but it does not describe current runtime behavior. The
existing `connectors/n8n` and `connectors/mcp-bridge` READMEs remain the source
of truth for the code that exists today.

No provider call, live workflow change, credential change, process stop, or MCP
profile change is authorized by this contract.

Current source boundary: `fwc-n8n` is a thin typed CLI for `resolve`, `route`,
`run-once`, and `status`. `run-once` supports nine Phase-1 REST reads, guarded
REST draft create/update, two local knowledge/validation operations, and one
official-MCP discovery operation, `n8n.capabilities.inspect`. The draft-write
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

The immutable bundle contract now requires twelve exact artifacts, including
`fcp-mcp-bridge`, its manifest, and separate EEC/Hetzner official-MCP
inventories. Immutable release `release-20260817-nqm817-34` is installed, the
distinct `n8n-eec-mcp` / `n8n-hetzner-mcp` owner entries are provisioned, and
server-by-server read-only capability discovery has passed with 34 tools on
each server. Every discovered capability remains `unknown`/`unreviewed` and
`tools/call` remains unavailable through the public surface. Bundle verification currently
trusts root ownership, restrictive filesystem modes, and serialized atomic
privileged updates locally. Its path-based checks do not defend against a
concurrent malicious root updater, and it does not claim signature
verification; a future signed installer/update receipt can strengthen that
root of trust.
`n8n.targets.resolve`, `n8n.runtime.status`,
`n8n.node_resources.explore`, `n8n.evaluations.manage`, and
`n8n.mcp_access.reconcile` are not all representable by that enum yet. Local,
typed REST, local MCP, and any official-MCP operation beyond capability
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
- Credential mutation and permanent workflow deletion are future-only. They
  are specified as closed gates, not v1 operations.
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
other. The service names alone are not provisioning evidence; current
provisioning is established by the 2026-08-17 broker-backed live discovery
readback, without exposing either value.

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
| `n8n.capabilities.inspect` | `n8n.capabilities.read` | Safe / Low | None | None | official MCP + REST | instance URI; snapshot ID/digest | 64 KiB |
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
| `n8n.workflows.lifecycle` | `n8n.workflows.lifecycle` | Risky / High | Interactive | BestEffort | REST or official MCP | all normalized state fields | 256 KiB |
| `n8n.workflows.versions` | `n8n.workflows.versions` | action-dependent | action-dependent | action-dependent | local MCP/API | version URI/state readback | 256 KiB |
| `n8n.workflows.execute` | `n8n.executions.start` | action-dependent | action-dependent | action-dependent | official MCP | workflow version and execution URI | 256 KiB |
| `n8n.executions.search` | `n8n.executions.read` | Safe / Medium | None | None | REST | execution preview URIs | 128 KiB |
| `n8n.executions.get` | `n8n.executions.read` | Safe / High | None | None | REST | execution status; data opt-in | 1 MiB full |
| `n8n.credentials.list` | `n8n.credentials.metadata.read` | Safe / Medium | None | None | official MCP | credential metadata URI | 128 KiB |
| `n8n.data_tables.search` | `n8n.data_tables.read` | Safe / Medium | None | None | official MCP | data-table URI/schema only | 256 KiB |
| `n8n.data_tables.mutate` | `n8n.data_tables.write` | action-dependent | Interactive | BestEffort | official MCP | table/schema/row-count readback | 256 KiB |
| `n8n.evaluations.manage` | `n8n.evaluations.manage` | action-dependent | action-dependent | action-dependent | local MCP | evaluation URI/status | 256 KiB |
| `n8n.audit.inspect` | `n8n.audit.read` | Safe / High | None | None | REST/local MCP | instance URI; redacted findings | 512 KiB |
| `n8n.mcp_access.reconcile` | `n8n.mcp_access.write` | Risky / High | Interactive | BestEffort | typed admin adapter | exact server; availability readback | 256 KiB |

### 5.1 Exact operation inputs and outputs

All inputs reject additional properties and all outputs use the common envelope.
The table specifies the exact operation-specific `data` shape.

| Operation | Required input | Optional input | `data` output |
|---|---|---|---|
| `targets.resolve` | one of `resourceUri`, `server`, `projectId`, `workflowId`, `executionId` | `candidateServers[1..3]`, `legacyOptIn` | `{resolution: resolved|ambiguous|not_found, target?: TargetRef, candidates?: [{resourceUri,id,name,server}]}` |
| `capabilities.inspect` | `target.server` | `refresh=false`, `detail` | `{snapshotId,n8nVersion,protocolVersions,apiScopeDigest,tools:[{name,schemaDigest,class,status}],capturedAt,expiresAt}` |
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
| `workflows.lifecycle` | exact workflow target, `action`, `guard` | `versionId` for publish | `{before: NormalizedWorkflowState,after: NormalizedWorkflowState}` |
| `workflows.versions` | exact workflow target, `action` | `versionId`, `guard`, `page` | action-specific version list/get/rollback result |
| `workflows.execute` | exact workflow target, `mode` | `guard`, `versionId`, `inputs`, `pinData`, `triggerNodeName`, `wait=false` | `{executionUri?,executionId?,mode,status,errorClass?,pinSchemas?}` |
| `executions.search` | `target.server` | `workflowId`, `status[]`, `startedAfter`, `startedBefore`, `page` | `{executions:[{resourceUri,id,workflowId,status,mode,startedAt?,stoppedAt?}]}` |
| `executions.get` | exact execution target | `includeData=false`, `nodeNames[1..20]`, `maxItemsPerNode` | `{execution:{id,workflowId,status,mode,startedAt?,stoppedAt?,retryOf?,waitTill?},data?}` |
| `credentials.list` | `target.server` | `query`, `type`, `projectId`, `onlySharedWithMe`, `page` | `{credentials:[{resourceUri,id,name,type,scopes,isManaged,isGlobal,homeProject?}]}` |
| `data_tables.search` | `target.server` | `query`, `projectId`, `page`, `includeSchema=false` | `{tables:[{resourceUri,id,name,projectId?,columns?,rowCount?}]}` |
| `data_tables.mutate` | exact table target or target project for create, `action`, `guard` | action payload | `{before?,after,affectedRows?,schemaDigest}` |
| `evaluations.manage` | exact workflow target, `action` | `runId`, `status`, `page`, `guard` | action-specific `{evaluationUri?,status?,runs?,cases?,summary?}` |
| `audit.inspect` | `target.server` | `categories[]`, `detail` | `{summary,findings:[{category,severity,resourceUri?,code,message}]}` |
| `mcp_access.reconcile` | `target.server`, `scope`, `desired`, `dryRun` | `guard`, `projectId`, `folderId`, `workflowIds[]` | `{planned,changed,skipped,exceptions,readbackDigest}` |

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

`workflows.lifecycle.action` is exactly `publish`, `unpublish`, `archive`, or
`restore`. Activation/deactivation are normalized aliases for
publish/unpublish only after capability discovery confirms the instance's
semantics; the receipt records both the public action and provider action.

`workflows.execute.mode` is exactly `prepare_test`, `test`, `manual`, or
`production`. `prepare_test` is Safe/Low/None and requires no guard. The other
three modes are Risky/High/BestEffort and require a guard. `inputs.headers`
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
`all_current`; `desired` is a boolean. `dryRun=true` requires no approval and
performs no writes. `dryRun=false` requires a guard and a prior dry-run digest.
Project/folder/all-current scopes apply only to workflows present at that time;
future workflows require a later reconciliation.

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
| Test/manual/production execution | Official MCP | Typed API route after parity | Trigger-aware execution semantics |
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

Installed local `n8n-mcp` (`2.67.2` observed, not pinned by this contract)
currently lists 24 tool names: seven core tools and 17 management tools. Its
README heading says 16 management tools, so catalog names and schema digests,
not that human-maintained count, are authoritative:

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
| Reconcile official MCP availability | Current-chat approval per server after dry-run |
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
legacy. A safe snapshot contains:

```json
{
  "server": "eec",
  "n8nVersion": "string",
  "mcpEra": "modern | legacy",
  "protocolVersions": ["2026-07-28"],
  "authMode": "oauth | access_token",
  "apiScopeDigest": "blake3-256:...",
  "tools": [
    {
      "name": "search_workflows",
      "inputSchemaDigest": "blake3-256:...",
      "outputSchemaDigest": "blake3-256:...",
      "class": "read | write | execution | credential | destructive",
      "publicRoute": "n8n.workflows.search",
      "status": "approved | blocked | changed"
    }
  ],
  "capturedAt": "RFC3339",
  "expiresAt": "RFC3339"
}
```

No workflow payload, Code source, execution data, tool response, credential
value, or auth header is stored in this snapshot.

For MCP revision `2026-07-28` and later, the adapter uses per-request protocol
metadata and `server/discover`; it does not invent a session or initialization
handshake. For older servers, the adapter may use the legacy initialize flow
for the lifetime of one bounded operation. Era detection is cached by server
origin and re-probed when it fails.

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

## 13. Future-only gates

### 13.1 Credential mutation

No v1 schema accepts credential secret material. Future create/update/test/
rotate/delete operations require a separate owner decision, KeePass or a
protected host channel, consumer preflight, secret-free readback, and rollback.
OAuth refresh tokens and client secrets must never cross the model boundary.

### 13.2 Permanent workflow deletion

No v1 operation maps to provider delete. Future deletion requires prior archive,
`active=false`, `isArchived=true`, an encrypted recovery export without
credentials/sensitive execution data, dependency inspection, Strict
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
