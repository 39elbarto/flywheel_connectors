# n8n Connector Security Contract

> **Status**: Source implements bounded per-invocation provider paths behind the same verified wrapper boundary: typed REST reads, guarded REST draft create/update, typed official-MCP publish/unpublish and archive paths with independent REST GET readback, a typed REST `n8n.mcp_access.reconcile` dry-run/apply path, local `n8n-mcp` knowledge/validation, and the closed `n8n.capabilities.inspect` official-MCP discovery operation. The typed `n8n.workflows.execute` input/approval seam is source-only and owner-gated; immutable EEC/Hetzner policy fixtures now carry exact owner-provisioned `execute_workflow` input/output schema digests, but no live execution acceptance is claimed. The MCP-access apply path is covered by wire-level tests and a historical owner-gated bundle acceptance on disposable workflows on both EEC and Hetzner. n8n requires the full required workflow transport payload (`name`, `nodes`, `connections`, and `settings`) for `PUT`; the logical mutation remains allow-listed to `settings.availableInMCP`, with independent readback preserving lifecycle and graph invariants. The disposable workflow cleanup and acceptance statements are historical evidence, not current-release live acceptance. Discovery exposes only names and schema digests with `unknown`/`unreviewed` policy markers; it does not authorize generic `tools/call`. Existing opt-in MCP profiles remain a separate opt-in path, and prior immutable releases remain available for rollback.
> **Current host evidence (2026-08-25, read-only)**: `/usr/local/lib/fwc-n8n/current` points to `release-20260824-90819213-static`, and that installed binary reports `{"bundleAvailable":true}`. The resolved tree contains `provenance.json` and `provision-receipt.json`, with matching release/revision metadata. Their presence does **not** by itself prove cryptographic receipt verification, live provider acceptance, or current-release live acceptance; no live/API invocation is claimed here. The fixed runtime policy records local `n8n-mcp` package version `2.69.2`, and the source update fixtures pin the same version. No release switch or runtime mutation was performed by this documentation update.
> **Beads**: `flywheel_connectors-nqm81.4`, `flywheel_connectors-nqm81.6`, `flywheel_connectors-nqm81.7`, `flywheel_connectors-nqm81.9`, `flywheel_connectors-nqm81.21`
> **Focused static-provider verification**: `crates/fcp-host/tests/n8n_owned_static_smoke.rs`
> **n8n public REST API**: https://docs.n8n.io/api/
> **n8n API reference**: https://docs.n8n.io/api/api-reference/

## Purpose

This document fixes the operator-facing contract for `fcp.n8n`. The connector exposes bounded workflow, project, tag, execution, credential-metadata, and n8n 2.19+ folder reads, plus guarded draft creation/update and typed official-MCP publish/unpublish/archive writes. The `n8n.workflows.execute` seam validates its bounded manual/production contract and is admitted only by the immutable owner-provisioned EEC/Hetzner `execute_workflow` schema bindings; no live execution acceptance is claimed. Each enabled write validates exact target, UUID idempotency, full state precondition, and current-chat approval, then uses only its exact owner-approved MCP tool with an independent typed readback; direct REST lifecycle/archive/execution routes remain fail-closed and no legacy endpoint is guessed.

### Immutable release provisioner (source-only packet)

`src/bin/fwc_n8n_provision.rs` provides a typed, fixed-root preflight for an
owner-staged release. It validates the existing twelve-artifact receipt plus
`provision-receipt.json` (which covers the receipt, provenance, and all staged
bytes), `provenance.json` (including the exact git revision), BLAKE3 artifact bytes,
root ownership/restrictive modes, canonical non-symlink paths, strict
allowlisted inventory/policy metadata with secret-like key/value rejection,
and exact EEC/Hetzner official-MCP policy bindings for
`publish_workflow`, `unpublish_workflow`, `archive_workflow`, and the
owner-provisioned `execute_workflow` schema bindings. The
`provision-receipt.json` must carry an owner Ed25519 signature over
domain-separated release/git/receipt/provision digests and the canonical full
server binding map; verification accepts only an explicit owner public key and
derived key ID and never reads private key material. The result is an
`InstallPlan` that can be consumed into an opaque `RevalidatedInstallPlan` only
after a successful immediate revalidation. `OwnerAtomicInstaller::promote`
accepts and consumes that proof. On Linux, the concrete
`FilesystemOwnerAtomicInstaller` derives the install root only from the proof,
takes an exclusive root lock, revalidates under that lock, uses no-follow
directory opens and `renameat(..., NOREPLACE)` for stage-to-release promotion,
then fsyncs and atomically replaces `current` through a temporary relative
symlink. Before any receipt or artifact read, every release-tree validation
opens exactly the fixed direct children `bin/`, `manifests/`, `inventory/`, and
`policy/` relative to the validated release root with `NOFOLLOW`, and checks
directory type, inode identity, owner, non-writable metadata, canonical parent,
and exact relative name (production owner is fixed to UID 0). The same check
therefore covers stage preflight/final revalidation, the current and rollback
immutable releases, and the post-rename
release before `current` changes; callers cannot supply intermediate paths. Its
rollback seam uses the same lock/revalidation and never deletes
releases; partial promotion preserves the immutable release and old `current`
where possible. Non-Linux fails closed. The `fwc-n8n provision` command is the
bounded owner wiring:
it reads a strict `fwc.n8n.provision-request.v1` JSON envelope containing only
release metadata and the fixed server binding map. The owner public trust root
is embedded by immutable release-build configuration; stdin cannot select a
key ID or public key, missing configuration fails closed, and the provisioner
never reads or generates a private key. With no mode (or `--mode preflight`) it
performs read-only validation and returns a redacted plan summary. `--mode
apply` requires effective UID 0, and both the installer seam and its Linux
mutation boundary repeat that check independently of the CLI. The existing
proof-carrying `FilesystemOwnerAtomicInstaller` accepts only the exact direct
child `/var/lib/fwc-n8n/staging/<release_id>` and the fixed
`/usr/local/lib/fwc-n8n` install root; basename mismatch, nested/traversal paths,
and symlink aliases fail before mutation. It never accepts caller paths, private
keys, sudo, shell, systemd, or release deletion.

The first owner-gated promotion has one explicit compatibility rule for the
existing installation: if fixed `current` has no `provision-receipt.json`, the
provisioner may classify it as `legacy-bootstrap` only after the fixed current
pointer, ownership, provenance, and complete old bundle verifier all pass. This
is not a generic bypass and accepts no caller path. If the file exists but is
malformed or its signature is invalid, validation fails closed; the staged
candidate always requires its complete owner-signed `provision-receipt.json`.
After the first successful promotion, revalidation requires the new
signed-current contract, so later promotions do not use the legacy fallback.

Rollback remains a separate owner-gated boundary, and live installation/current
acceptance is still not performed by repository tests.

### Offline owner signer (source-only packet)

`fwc-n8n-owner-sign` is a separate, feature-gated operator binary. It is not
linked into the normal `fwc-n8n` runtime target, including a runtime-only
`--all-features` build, and the runtime bundle never receives Ed25519 private
key handling. The signer accepts only an exact release identifier, a bounded
non-secret `fwc.n8n.provision-request.v1` file, and the Base64 seed on stdin.
The release identifier is resolved internally to
`/var/lib/fwc-n8n/staging/<release_id>`; caller-supplied stage paths are not
accepted.

Before signing, it reuses the provisioner’s complete no-follow unsigned-tree
validator: ownership/modes, provenance, all twelve artifact digests, inventory
and policy semantics, and exact EEC/Hetzner schema bindings must pass. The
derived public key and key ID must match the immutable build-time
`FWC_N8N_OWNER_PUBLIC_KEY_HEX` trust root. The seed is accepted only as exactly
32 decoded bytes (44 Base64 characters with at most one final LF), is held in
zeroizing buffers, is never read from KeePass by the binary, and is never
accepted from an argument or environment variable.

The signer emits only the signed `provision-receipt.json` bytes on stdout and
fixed redacted errors on stderr. It does not call n8n, invoke a provider,
modify workflows, switch `current`, install a release, or write the staged
tree. A separate owner-controlled provisioning step must place the signed
receipt into the staged release and perform the already-gated preflight/apply
flow. The source packet has offline tests only; it does not claim live signing,
privileged installation, or current-release acceptance.

The connector is intentionally a bounded self-hosted n8n administration bridge. It is not a workflow authoring client or credential secret/value manager, and it does not provide project-management writes, variable management, audit access, webhook trigger runtime, event subscriptions, n8n CLI replacement, or general HTTP proxy behavior.

## Current Runtime Snapshot

The current crate exposes these operations:

- `n8n.workflows.list`
- `n8n.workflows.get`
- `n8n.workflows.activate`
- `n8n.executions.list`
- `n8n.executions.get`
- `n8n.projects.list`
- `n8n.credentials.list`
- `n8n.tags.list`
- `n8n.folders.list`
- `n8n.folders.get`
- `n8n.workflows.create_draft`
- `n8n.workflows.update_draft`
- `n8n.workflows.lifecycle` (typed `publish`/`unpublish`; one guarded provider attempt plus independent readback)
- `n8n.workflows.archive` (typed official-MCP `archive_workflow`; inactive/unarchived baseline only, one guarded provider attempt plus independent readback)
- `n8n.workflows.execute` (typed official-MCP `execute_workflow` seam; wrapper/host/connector validate identical bounded manual or production inputs, and the typed result is limited to workflow/execution IDs, initial status, mode/version, and an independent execution GET classification. Host admission requires the immutable owner-provisioned EEC/Hetzner schema binding; no live acceptance)
- `n8n.mcp_access.reconcile`

The list above is the manifest/runtime declaration surface, not a promise that
every provider path is enabled. The documentation separates the layers:

- **Manifest operations:** the 16 operations listed above are declared by
  `connectors/n8n/manifest.toml`; activation remains fail-closed because its
  provider lifecycle path is deferred.
- **Wrapper/host-only operations:** `n8n.capabilities.inspect` is not in the
  connector manifest. Its wrapper input is empty `{}`; the bounded host
  envelope supplies the fixed EEC/Hetzner server and the host maps it only to
  `mcp.tools.list`.
- **Router intents:** the typed router can recognize selection intents such as
  `n8n.knowledge.query`, `n8n.validation.run`, `n8n.workflows.search`,
  `n8n.executions.search`, `n8n.structure.search`, `n8n.workflows.compare`,
  `n8n.data_tables.search`, `n8n.data_tables.mutate`, `n8n.audit.inspect`,
  and `n8n.workflows.versions`. A routing intent selects a strategy; it does
  not provide a provider execution path.
- **Future/unimplemented:** `n8n.runtime.status`,
  `n8n.node_resources.explore`, `n8n.evaluations.manage`, and router intents
  without a corresponding host/connector dispatch remain future or
  unimplemented execution paths. Restore/unarchive, versions, credential
  mutation, permanent deletion, and provider activation remain fail-closed.

Important runtime truths:

- Package and binary name are `fcp-n8n`.
- The crate also builds the operator wrapper `fwc-n8n`. Its current commands are
  `resolve`, `route <public-operation>`, `run-once <host-operation>`,
  `update-review detect`, `provision [--mode preflight|apply]`, and `status`.
  `provision` defaults to read-only `preflight`; mutation requires the explicit
  owner-gated `provision --mode apply`. `run-once` accepts the nine Phase-1 host
  reads, guarded
  `n8n.workflows.create_draft` and `n8n.workflows.update_draft`, the typed
  publish/unpublish lifecycle path (unknown outcomes fail closed), plus the closed
  `n8n.capabilities.inspect` operation, a strict
  EEC-or-Hetzner payload, bounded deadline, and optional UUID correlation ID.
  CLI framing has a fixed five-second maximum, and the operation deadline is
  measured from before that read. It derives the fixed `z:work` host envelope
  and canonical resource URI, verifies the immutable release bundle, requests
  one credential from the fixed EEC/Hetzner broker, and passes only a
  `ZeroizingSecret` to the bridge without retry. The bridge runner can launch
  only a verified fixed `fcp-host` bundle
  with the selected EEC/Hetzner inventory, fixed zone policy, one-shot argument,
  bounded response/deadline, inherited credential frame, fixed release cwd, and
  in-memory lifecycle state. Stdin/stdout/stderr are nonblocking and share one
  cancellation/deadline budget; teardown errors take precedence over worker
  errors. A missing owner-gated broker, release, or credential entry fails
  closed before provider access.
  Per-operation input keys and scalar bounds mirror the manifest, so arbitrary
  headers, credentials, tokens, URLs, commands, paths, or nested payloads
  cannot enter the host-launch request.
  Draft writes are REST-only and accept a full typed graph, current-chat
  `approvalRef`, and UUID idempotency key. Update additionally requires the
  exact version, explicit `activeVersionId`, `active`, `isArchived`, and
  credential-sensitive state digest. The host run-once envelope must carry a
  bounded, externally signed `approval_token` (the token is redacted from
  debug/log output); `approvalRef` alone is never sufficient. The host verifies
  `FCP_HOST_APPROVAL_PUBLIC_KEY` or `_FILE`, exact operation/server/resource
  binding, expiry, and one-shot claim before credential/provider access, takes a
  per-resource lock, consumes the validated token_id==approvalRef once via a private replay marker, writes redaction-safe intent/outcome receipts,
  performs one provider attempt, and requires independent GET readback. It
  never retries an unknown result and never implicitly publishes, activates,
  deactivates, archives, or changes credential objects. Runtime files live
  under a private fixed `/run/user/<uid>/fwc-n8n` tree and reject symlink or
  hard-link substitution. The guarded write path has mock/local coverage plus
  owner-approved create, update, reconciliation, and compensating-rollback
  evidence on a disposable Hetzner workflow. This evidence does not authorize
  writes to other workflows without a fresh exact approval and precondition.
  For `n8n.capabilities.inspect`, the same wrapper requests only the distinct
  official-MCP credential purpose and selects a separate immutable inventory.
  `fcp-host` translates that public operation only to `mcp.tools.list`, issues
  a one-call `mcp.tools.read` capability, and injects the token only as an
  `Authorization: Bearer` header to the canonical `/mcp-server/http` endpoint.
  The inventory requires description scanning in blocking mode. `tools/call`,
  caller-supplied URLs, methods, tool names, headers, or tokens are rejected
  before launch. After scanning, the public wrapper replaces the provider
  catalog with a deterministic compact response containing only tool names,
  SHA-256 input/output schema digests, and `unknown`/`unreviewed` policy
  markers. Provider descriptions and raw schemas are never returned to the
  caller. Its result shape is:

  ```json
  {
    "capabilities": {
      "schema": "fwc.n8n.capabilities.v1",
      "serverId": "eec | hetzner",
      "provider": "official_mcp",
      "toolCount": 0,
      "tools": [{
        "name": "tool_name",
        "inputSchemaDigest": "sha256:...",
        "outputSchemaDigest": "sha256:...",
        "class": "unknown",
        "status": "unreviewed"
      }]
    }
  }
  ```

  `snapshotId`, `n8nVersion`, `protocolVersions`, `capturedAt`, `expiresAt`,
  and REST fallback fields are not emitted by this wrapper; they remain future
  metadata only. No caller-controlled method, URL, header, token, or tool name
  is accepted.
  `n8n.targets.resolve`, `n8n.runtime.status`,
  `n8n.node_resources.explore`, and `n8n.evaluations.manage` still need
  dedicated routing intents or host-local dispatch before they can use this
  command. `n8n.mcp_access.reconcile` is host-dispatchable for bounded dry-runs
  and guarded apply. Apply requires the exact current dry-run digest, one
  matching interactive approval, a UUID idempotency key, a host run-once
  server-wide lock, one full required workflow PUT whose only logical change is
  `settings.availableInMCP`, and an independent detail readback. The host writes
  redacted outcome receipts to the installer-provisioned private append-only
  ledger at `/var/lib/fwc-n8n/mcp-access-ledger/receipts` (owned by the
  runtime user, mode `0700`; records are mode `0600`, bounded to 1024 records
  and seven-day retention). The launcher runs as a user scope, so the
  installer must provision this fixed directory for that exact runtime user;
  the connector refuses a different owner or permissive mode. The apply path
  claims the exact idempotency binding before broker
  or provider access; an exact replay returns the prior redacted receipt without
  another provider attempt, a different binding collides, and an interrupted
  claim remains unknown and is never retried automatically. Expired committed
  receipts and safe temporary outcome files are reaped under the ledger lock;
  pending unknown claims are retained and continue to fail closed. Dry-run
  receipts are claimed and committed under a deterministic request binding for
  bounded history. Ledger
  provisioning is part of the host installer trust root; an unavailable,
  malformed, stale, or over-bound
  ledger fails closed. A stale digest, unknown provider outcome, or readback
  mismatch fails closed for that workflow and is never retried. A historical
  owner-gated bundle passed disposable EEC and Hetzner
  enable/disable/readback acceptance; its release ID and evidence receipt are
  not recorded here, so this is not current-release acceptance. `all_current` is an explicit, bounded
  one-shot reconciliation of the workflows visible when that invocation starts;
  a newly created workflow is considered only on the next explicit
  `all_current` request. There is no daemon, scheduler, or persistent policy
  that silently tracks future workflows, and daemonized replay remains out of
  scope.
- Official MCP publish/unpublish remains a static and guarded path, not a live
  acceptance claim: on 2026-08-21 the exact EEC webhook disposable publish
  attempt returned `unknown_outcome`; an independent REST readback remained
  inactive, and no retry was made. The disposable workflow was then removed
  after MCP access was disabled and DELETE/404 readback verification.
- Large workflow pages use an operation-scoped transport budget: the typed
  `n8n.workflows.list` and `n8n.mcp_access.reconcile` paths allow at most
  `512 KiB` for the compact inter-process result. Their owned invocation
  deadlines are `30 seconds` and `60 seconds` respectively; the generic
  connector/owned defaults remain `64 KiB` and `10 seconds`. The provider
  response itself remains bounded to `10 MiB`, is typed and compacted before
  crossing the connector boundary, and is never logged as raw payload.
- A historical 2026-08-19 live-smoke record reports both servers: EEC listed
  100 items and its `all_current` dry-run planned 137
  workflows (48 already disabled, 0 changes, 0 exceptions); Hetzner listed
  100 items and planned 300 (56 already disabled, 0 changes, 3 bounded
  exceptions). No workflow write, activation, deletion, or retry occurred.
  The release ID and evidence scope are not recorded here, so this is not
  current-release acceptance.
- The library now includes a compact, provider-neutral target resolver and
  provider router. It accepts explicit server, confirmed project mapping,
  workflow/execution provenance, canonical resource URI, or bounded ambiguity;
  workflow name alone never selects a server and legacy requires explicit
  opt-in.
- Provider selection is typed rather than based on arbitrary upstream tool
  names: known-ID reads prefer REST, local node/template knowledge and
  validation prefer local `n8n-mcp`, and capabilities without typed parity
  prefer official MCP. Every fallback is represented explicitly and unknown
  write capability fails closed. These are typed routing decisions only; the
  wrapper does not spawn a local provider, load a policy file, or dispatch REST
  or other official-MCP operations. All provider execution remains behind a
  host-owned boundary.
- `fwc-n8n status` is process-scan-free and reports only
  `{"bundleAvailable":true|false}`. The installed
  [`fwc-n8n-launcher`](../../deploy/bin/fwc-n8n-launcher) starts each command in
  a transient `systemd-run --user --scope` unit with `Delegate=yes`, then the
  canonical release executable derives the release root from its own path.
  The transient scope is collected after the command; no n8n-specific host
  daemon or persistent cgroup is introduced. The verifier checks the
  canonical current executable and verifies the exact versioned bundle layout,
  receipt, ownership/mode policy (including rejection of special mode bits),
  link counts, and BLAKE3 digests. A dev/test executable safely reports
  `false`. This is deliberately not named `bridgeInstalled`: it does not claim
  that the broker, credentials, or live provider acceptance are ready. Root
  ownership, restrictive modes, and serialized atomic privileged updates are
  the current local trust root; path-based verification does not defend against
  a concurrent malicious root updater. This verifier also does not claim
  signature verification. Signed `provision-receipt.json` validation belongs
  to the separate owner-gated `provision` path; the receipt's presence in the
  current runtime snapshot is not proof that cryptographic verification or
  live acceptance occurred.
- Runtime `BaseConnector` ID is `n8n`.
- Manifest and reported connector ID are `fcp.n8n`.
- The manifest interface hash is generated from the current operation surface; `fwc manifest fix connectors/n8n/manifest.toml --check --json` must report `changed=false` before release.
- Configuration requires exactly one auth source: direct `api_key` or `credential_id`.
- Direct API-key mode is usable only against loopback test fixtures. Production direct provider egress fails before DNS or HTTP.
- `credential_id` is only a host-managed reference. Every advertised read operation constructs a bounded host-egress request whose context carries the already-verified canonical resource separately from the HTTPS transport URL. The connector never resolves, stores, or sends the API key itself.
- In the Linux owned per-invocation path, the host creates a connected Unix socketpair, passes only the child endpoint as an inherited file descriptor, and binds the channel to a fresh per-launch authentication token. Connector configuration and operation input cannot select or redirect this transport.
- The sandbox process supervisor exposes a fixed-name inherited-FD channel for the verified `fwc-n8n` bridge to deliver one `fcp-host n8n-run-once` credential frame. It marks every ambient descriptor close-on-exec, makes only the selected channel inheritable, rejects reserved environment overrides, and retains exact process-group ownership.
- Official-MCP discovery and the lifecycle fallback use the separate hidden host
  action `n8n-official-mcp-run-once-supervised`. Landlock admits only the
  immutable sibling `fcp-mcp-bridge` executable for that action. Lifecycle
  calls are admitted only for owner-reviewed `publish_workflow` or
  `unpublish_workflow` policy entries with input/output schema digests; a
  missing or drifted policy fails closed before MCP provider I/O.
- The bridge launch fixes `FCP_HOST_LIFECYCLE_STATE_FILE` to the empty value, so a one-shot host cannot persist lifecycle state into a caller-controlled cwd. The code path has synchronous bundle/hash checks, whole-CLI stdin/deadline enforcement, nested process-group teardown proof, and the reviewed fixed credential broker. Missing release, broker, credential, or delegated-cgroup prerequisites fail closed.
- A historical 2026-08-17 official-MCP acceptance record used only
  `n8n.capabilities.inspect` and did not call any discovered tool. EEC
  completed in 1,448 ms with sampled aggregate peaks of 35,048 KiB RSS,
  32,516 KiB PSS, and 32,504 KiB private memory. Hetzner completed in 3,396 ms
  with peaks of 35,100 KiB RSS, 32,576 KiB PSS, and 32,564 KiB private memory.
  The 20 ms sampler observed at most two concurrent bundle processes; separate
  idle checks found zero bundle, broker, or running-scope processes immediately,
  after 5 seconds, and after 30 seconds. These are host snapshots, not
  long-term performance guarantees. The release ID and evidence scope are not
  recorded here, so this is not current-release acceptance.
- The host compares the connector's selected-operation introspection with trusted manifest metadata before activating egress, binds every egress frame to connector, operation, zone, request, correlation, and capability-token context, and proves child reap plus process-group absence before returning.
- Each n8n run-once invocation generates a fresh host-owned connector instance ID in memory, passes that exact ID through the owned handshake, and issues the capability token with the matching instance claim. A stale or inventory-pinned instance value is replaced for the one-shot launch, and a different connector instance cannot reuse the token.
- `credential_id` must be a valid UUID.
- `base_url` is required and canonicalized to the `/api/v1` root.
- Runtime endpoint shape is `{base_url}/workflows`, `{base_url}/workflows/{id}`, `{base_url}/executions`, `{base_url}/executions/{id}`, `{base_url}/projects`, `{base_url}/credentials`, `{base_url}/tags`, `{base_url}/projects/{projectId}/folders`, and `{base_url}/projects/{projectId}/folders/{folderId}`.
- Runtime request and connect timeouts come from the supplied `ConnectorRuntimeConfig` (the connector default request timeout is 30 seconds); each direct provider call or host-proxy attempt is single-attempt and has no automatic retry.
- Runtime `invoke` requires the canonical `operation` field.
- A host-key-backed `CapabilityVerifier` validates the bound capability token before provider dispatch.
- Activation additionally requires exactly one semantically matching execution approval; malformed entries fail closed. The host remains authoritative for approval signature verification.
- Reconfigure and shutdown clear client, verifier, zone, session, configured, and handshaken state.
- `self_check()` performs its read-only probe only on the loopback test path; production direct egress fails before provider traffic.

## Standalone secret broker (owner-gated)

The repository carries a zero-idle systemd socket-activation template for the
standalone `fwc-n8n-secret-broker` binary:

- [`fwc-n8n-secret-broker.socket`](../../deploy/systemd/fwc-n8n-secret-broker.socket)
  listens only on the fixed `/run/fwc/fwc-n8n-secret-broker.sock` path with
  `Accept=yes`. The tracked
  [`fwc-n8n-secret-broker.conf`](../../deploy/tmpfiles.d/fwc-n8n-secret-broker.conf)
  establishes the runtime directory as root-owned with mode `0750`; the
  socket is root-owned with mode `0660` and the owner-approved
  `fwc-n8n-broker` group is the only non-root access path. The group is an
  owner-provisioned deployment prerequisite rather than repository state. The
  broker's metadata check requires the socket GID to match the runtime-directory
  GID before serving a request.
- [`fwc-n8n-secret-broker@.service`](../../deploy/systemd/fwc-n8n-secret-broker@.service)
  runs one request per accepted connection from the fixed absolute
  `/usr/local/libexec/fwc-n8n-secret-broker` path. It receives the bidirectional
  Unix stream on fd 0 (`StandardInput=socket`), discards stdout
  (`StandardOutput=null`), logs only redacted diagnostics to the journal, and
  enforces a bounded `RuntimeMaxSec=30s`. The broker exits after one bounded
  request; it is not a daemon and has no caller-selected executable, path,
  environment, or shell.
- The packaged live-backend build uses a closed server-and-purpose mapping.
  REST API keys remain at `services/n8n-eec` and `services/n8n-hetzner`;
  distinct official MCP access tokens are reserved at
  `services/n8n-eec-mcp` and `services/n8n-hetzner-mcp`. The wire protocol keeps
  the established one-byte REST request for rollout compatibility. Official
  MCP uses a separate versioned three-byte frame with a fixed prefix, server,
  and purpose, so a legacy REST frame plus trailing bytes cannot be reinterpreted
  as another credential class. The official MCP entries are not provisioned by
  this repository and remain fail-closed until owner-gated installation. The
  legacy mapping is excluded; secret values and source paths are never placed
  in unit files or environment variables.
- The fixed KDBX trust assumption is mode `0600` with owner UID equal to the
  connecting peer UID. Only the age identity and encrypted master files are
  root-owned mode `0600`. With keepass `0.13.20`, parsed entry fields are a map,
  so duplicate raw XML `Password` keys cannot be distinguished after parsing.
  Canonical KeePass/KeePassXC files expose one field; the broker additionally
  requires exactly one `services` group, one exact service subgroup, one
  exact-title entry, and a protected `Password`. Non-canonical or manually
  generated KDBX files are unsupported; this contract must not be read as raw
  duplicate-field detection.

The tracked unit files remain installation templates. On the current owner
host, the exact broker binary and units are installed, the socket is enabled
and listening at zero idle service processes, `/run/fwc` is
`root:fwc-n8n-broker 0750`, the socket is `root:fwc-n8n-broker 0660`, and the
owner user is a member of that group. The distinct EEC and Hetzner official-MCP
entries are provisioned and passed broker-backed read-only discovery acceptance
without exposing their values. Existing opt-in Codex MCP profiles remain the
fallback until the owner separately accepts the capability policy and any
future write surface.

Reference installation commands for another host:

The binary source below is a placeholder for a previously built and verified
standalone live-backend artifact. This runbook does not prescribe an ambiguous
root-workspace `target/release` path.

```text
getent group fwc-n8n-broker
# The user-scope launcher must own its durable reconciliation ledger.
install -d -o ubuntu -g ubuntu -m 0700 /var/lib/fwc-n8n/mcp-access-ledger/receipts
stat -c '%U %G %a %F %n' /var/lib/fwc-n8n/mcp-access-ledger/receipts
install -o root -g root -m 0755 /path/to/verified/fwc-n8n-secret-broker /usr/local/libexec/fwc-n8n-secret-broker
install -o root -g root -m 0644 deploy/tmpfiles.d/fwc-n8n-secret-broker.conf /etc/tmpfiles.d/fwc-n8n-secret-broker.conf
systemd-tmpfiles --create /etc/tmpfiles.d/fwc-n8n-secret-broker.conf
install -o root -g root -m 0644 deploy/systemd/fwc-n8n-secret-broker.socket /etc/systemd/system/fwc-n8n-secret-broker.socket
install -o root -g root -m 0644 deploy/systemd/fwc-n8n-secret-broker@.service /etc/systemd/system/fwc-n8n-secret-broker@.service
systemd-analyze verify /etc/systemd/system/fwc-n8n-secret-broker.socket /etc/systemd/system/fwc-n8n-secret-broker@.service
systemctl daemon-reload
systemctl enable --now fwc-n8n-secret-broker.socket
stat -c '%U %G %a %F %n' /run/fwc /run/fwc/fwc-n8n-secret-broker.sock /usr/local/libexec/fwc-n8n-secret-broker
# Acceptance readback: verify the socket GID equals the /run/fwc GID.
systemctl status fwc-n8n-secret-broker.socket
journalctl -u 'fwc-n8n-secret-broker@*' --since=-5m --no-pager
systemctl disable --now fwc-n8n-secret-broker.socket
systemctl daemon-reload
```

The rollback commands are likewise owner-approved and not executed; until that
gate is explicitly accepted, use the existing MCP fallback profiles.

## Declarative Versus Mechanical Enforcement

The manifest declares DNS, TLS SNI, host/port, private-range, redirect, timeout,
and response-size policy for the host egress layer. Every advertised read
operation uses the SDK `HostEgressProxyClient` for credential-reference requests.
The production Linux loader accepts the reserved `inherited-fd-v1` transport,
inherited descriptor, and per-launch authentication token only as a complete
host-issued set; it does not fall back to the legacy loopback URL.
The connector wire path relies on the host to enforce those network constraints
and inject the referenced credential. Host capability verification uses the
context's canonical logical resource; network enforcement independently evaluates
the transport URL.
The direct `reqwest` path does not mechanically enforce the host's DNS, TLS SNI,
private-range, redirect, or network-allow controls and is therefore unavailable
for non-loopback provider traffic; its separate body-size and runtime-timeout
guards are described below.

The direct client prechecks `Content-Length` and streams each provider response with a
mechanical 10 MiB aggregate body cap before typed decoding. Chunked responses are
bounded by the same cap; oversized success and error bodies fail closed without
returning their bytes. The direct client also applies the supplied request and connect
timeouts. Host-policy response-size and timeout entries remain independently enforced
by the host egress layer.

The connector does mechanically enforce configuration shape, canonical API-root
validation, capability-token binding, approval semantic matching, safe path
segments, and lifecycle/session reset. These checks do not replace host egress
mediation.

## Scope

This packet documents and verifies:

- direct n8n API key and host credential-reference configuration, including the canonical-resource host-egress slice for every advertised read
- required self-hosted API base URL behavior
- local URL readiness, timeout, single-attempt provider calls, and error mapping
- workflow reads and the activation approval boundary
- safe project metadata reads
- compact tag metadata reads
- execution read operations
- typed folder list/get reads with strict redaction and project-scoped provider access
- handshake, self-check, introspection, simulation, and reset behavior
- deterministic WireMock tests and direct proof commands

## Auth, Capabilities, And Approvals

- Authentication configuration accepts exactly one of an API key or a host credential reference.
- Provisioning asks for the instance URL and credential reference only. It does not prompt for, store, or serialize a raw API key.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability surface:
  - `n8n.workflows.read` gates workflow list/get provider calls.
  - `n8n.workflows.write` gates the activation approval boundary; a valid request is then denied before provider traffic in this packet.
  - `n8n.executions.read` gates execution list/get provider calls.
  - `n8n.projects.read` gates safe project list provider calls.
  - `n8n.credentials.metadata.read` gates safe credential metadata list provider calls.
  - `n8n.tags.read` gates compact tag list provider calls.
- `n8n.folders.read` gates both folder list/get provider calls.
- FCP capability IDs are connector authorization labels, not n8n API-key scopes; mediated project access must satisfy both layers.
- Current provider mappings are `n8n.projects.read` -> upstream `project:list`, `n8n.credentials.metadata.read` -> upstream `credential:list`, `n8n.tags.read` -> upstream `tag:list`, and `n8n.folders.read` -> upstream `folder:list` / `folder:read`.
- Upstream credential listing is owner/admin-only, requires `credential:list`, and excludes secret values. The current upstream contract is [credentials.yml](https://raw.githubusercontent.com/n8n-io/n8n/master/packages/cli/src/public-api/v1/handlers/credentials/spec/paths/credentials.yml); availability and flags are version/license dependent and are not inferred here.
- Upstream project listing is license-gated by `feat:projectRole:admin`. The reviewed upstream commit has no analogous license middleware for tags.
- Folder operations require n8n `>=2.19.0` with the `feat:folders` feature enabled. A provider `403` is ambiguous among folder license, API-key scope, and project RBAC; this connector claims no current mechanical discriminator. Before n8n `2.19`, or when the route is absent, expect `404` or a failed future non-mechanical OpenAPI route probe.
- Capability tokens must bind to the current connector instance and exact resource URI. The host verifier checks the token signature; the connector performs the bound semantic check.
- Activation approval must be an exact single execution approval for connector, canonical `operation`, zone, resource, workflow state, and normalized constraints. A host-bound `input_hash` is compatible; a `request_object_id` is not. Malformed approval entries fail closed.
- The connector does not persist API keys, credential secret material, workflow definitions, execution payloads, provider error bodies, or API responses outside process memory.
- Provider responses are untrusted work-zone data. Runtime read operations return only
  the explicit safe metadata views; workflow graph/nodes/connections,
  `activeVersion`, `meta`, credential references/bodies, Code source, `pinData`,
  execution `data`/`resultData`, and unknown fields are discarded before output.
- Compact workflow-list metadata preserves provider `activeVersionId` presence:
  an omitted field is omitted, explicit `null` remains `null`, and a string is
  returned exactly. Workflow get is stricter: the field and matching
  `activeVersion` must both be explicitly present and consistent.

## Network And Runtime Invariants

- Runtime endpoint shape:
  - `GET {base_url}/workflows?limit=<1..200>&cursor=<opaque>&excludePinnedData=true`
  - `GET {base_url}/workflows/{id}`
  - `GET {base_url}/executions?limit=<1..200>&cursor=<opaque>&includeData=false&ignoreDataSizeLimit=false&redactExecutionData=true`
  - `GET {base_url}/executions/{id}`
  - `GET {base_url}/projects?limit=<1..200>&cursor=<opaque>`
  - `GET {base_url}/credentials?limit=<1..200>&cursor=<opaque>`
  - `GET {base_url}/tags?limit=<1..200>&cursor=<opaque>`
  - `GET {base_url}/projects/{projectId}/folders?select=%5B%22id%22%2C%22name%22%2C%22parentFolder%22%5D&filter=<optional-json>&skip=<n>&take=<1..200>`
  - `GET {base_url}/projects/{projectId}/folders/{folderId}`
- `n8n.workflows.activate` emits no provider request in this packet. Its capability and approval checks run first, then the operation fails closed with a deferred-lifecycle error. The mediated write path is owned by the lifecycle/egress follow-up beads.
- `n8n.workflows.lifecycle` accepts only `publish` and `unpublish`, requires an exact workflow target, UUID idempotency key, explicit `versionId`/`activeVersionId`/`active`/`isArchived`/`stateDigest` precondition, and one matching interactive approval. The host builds only the exact official MCP tool arguments after fresh `tools/list` policy verification; one side-effecting MCP call is followed by independent REST `GET /workflows/{id}` readback. Publish verifies active state, selected/provider-published version, published graph consistency, draft preservation, and `isArchived=false`; unpublish verifies inactive/null active version, archive preservation, and draft preservation. Timeout, disconnect, 409, 5xx, malformed/ambiguous response, or readback uncertainty is unknown and never retried automatically. Direct REST lifecycle remains fail-closed unless its exact route is separately proven.
- `n8n.workflows.archive` accepts only an exact inactive, unarchived workflow target with the full lifecycle precondition and external signed approval. It calls only the owner-policy-bound official MCP `archive_workflow` tool once, then performs an independent REST `GET /workflows/{id}` readback requiring `isArchived=true`, inactive/null active version, and unchanged draft/published summaries. The provider's required name field is consumed but never returned. Active or already-archived baselines, timeout, disconnect, conflict, malformed/ambiguous response, or readback uncertainty fail closed; restore/unarchive remains unsupported.
- The official-MCP provider result is accepted only when it contains typed `active`, `isArchived`, `activeVersionId`, draft/published graph summaries, and `stateDigest` fields. The provider result must agree with the requested version and baseline draft; every lifecycle field and graph/state digest must then agree with the independent REST readback. Provider-side disagreement is `unknown_outcome`; provider/readback disagreement is `readback_mismatch`.
- Deterministic lifecycle failures proven to occur before the official MCP side effect are exposed only as bounded categories such as `official_mcp_policy_failed` or `official_mcp_capability_failed`. Invocation, timeout, teardown, malformed/ambiguous response, and all other cases that could conceal a provider-side effect remain `unknown_outcome` and are never retried. When the supervised child provides one of its fixed redaction-safe invoke classes, the error envelope may additionally contain only that allowlisted `diagnostic` label; it never contains provider text, payloads, headers, credentials, or changes the retry decision.
- Runtime sends `Accept: application/json`.
- Loopback test requests with API-key mode send `X-N8N-API-KEY`.
- Owned production credential-reference reads send one typed request per provider call over the authenticated inherited-FD channel. Each strict envelope contains only the exact upstream HTTPS read URL, `GET`, safe `Accept`, the credential UUID, and verified request attribution (`fcp.n8n`, the exact operation, its canonical resource, current zone, session-derived request ID, and raw COSE CBOR capability token encoded as standard base64). The loopback HTTP `POST /rpc/egress/http` transport remains test/legacy-only.
- Production transport provenance comes only from the host-created connected descriptor plus `FCP_HOST_EGRESS_TRANSPORT=inherited-fd-v1` and a fresh host-issued `FCP_HOST_EGRESS_AUTH_TOKEN`. All host-egress transport variables are reserved and rejected in managed connector environment. Neither connector configuration nor operation input can supply them. `FCP_HOST_EGRESS_PROXY_URL` is retained only for explicit legacy/test construction and is never a production fallback.
- Credential-reference mode sends no provider credential header from this client. The host resolves and injects the credential; the connector neither receives nor returns it.
- Runtime user agent is `fcp-n8n/0.1.0 (FCP connector)`.
- Direct provider I/O is allowed only for loopback test hosts (`localhost`, `127.0.0.1`, or IPv6 loopback) with API-key mode. Production HTTPS uses only the credential-reference host-egress path. Live EEC/Hetzner reads and the bounded Hetzner disposable-workflow draft-write acceptance have exercised that path.
- Host egress treats `context.resource_uri` as the capability-constrained logical resource and treats `url` as an independent transport-policy target. Focused host tests cover matching logical-resource authorization, mismatched logical-resource denial, disallowed transport, inherited-channel identity binding, stale registry generation, pre-activation rejection, exact operation-metadata parity, bounded success, post-launch failure teardown, child reap, and process-group absence. Live acceptance supplements rather than replaces those deterministic tests.
- A missing, rejected, malformed, or failed host proxy response fails closed with no direct fallback and no second attempt. Host/provider bodies, headers, capability material, and credential UUIDs are not exposed in connector output or safe errors.
- Mediated response bodies are bounded to 10 MiB before JSON and typed projection. Host decision metadata must exactly match the connector, exact operation, zone, request identity, target host/port, allow decision, managed operation-network constraint source, and successful credential injection.
- Runtime request and connect timeouts are supplied by `ConnectorRuntimeConfig`; the connector default request timeout is `30 seconds`.
- Direct provider response bodies are mechanically bounded to `10 MiB` before JSON and typed projection, including chunked responses and error bodies.
- Direct client calls are single-attempt; no automatic retry loop is installed.
- Provider HTTP 401, 403, 404, 429, and other API errors map to typed connector/FCP errors.
- `Retry-After` on 429 is surfaced as a delay hint in the typed error; it does not trigger an automatic retry.
- Readiness diagnosis maps provider status classes without inferring a cause: a `403` is ambiguous among folder license, API-key scope, and project RBAC; pre-`2.19` or route absence is a `404` or a failed future non-mechanical OpenAPI route probe.
- The installed `/api/v1/openapi.yml` is a future non-mechanical route/capability inspection; its `info.version` is the API specification version, not the n8n product version.
- Manifest connect timeout, total timeout, DNS, private-range, redirect, and SNI entries remain host-policy declarations. The direct client independently applies the supplied runtime timeouts and the same `10 MiB` provider-body limit.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets, receive n8n webhooks, run workflows locally, or connect to n8n's internal database.

## Operation Inventory

| Operation | HTTP request | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|--------------|------------|------------|-----------|-------------|----------------|
| `n8n.workflows.list` | `GET /workflows` with bounded `limit`/opaque `cursor` | `n8n.workflows.read` | `Safe` | `Low` | `Strict` | optional `limit` and `cursor` |
| `n8n.workflows.get` | `GET /workflows/{id}` | `n8n.workflows.read` | `Safe` | `Low` | `Strict` | `id` string |
| `n8n.workflows.activate` | no provider request; lifecycle deferred | `n8n.workflows.write` | `Risky` | `Medium` | `None` | `id` string and `active` bool plus one matching approval |
| `n8n.executions.list` | `GET /executions` with bounded `limit`/opaque `cursor` | `n8n.executions.read` | `Safe` | `Low` | `Strict` | optional `limit` and `cursor` |
| `n8n.executions.get` | `GET /executions/{id}` | `n8n.executions.read` | `Safe` | `Low` | `Strict` | `workflow_id` and `id` strings |
| `n8n.projects.list` | `GET /projects` with bounded `limit`/opaque `cursor`; direct loopback API-key or canonical-resource host-egress credential reference | `n8n.projects.read` | `Safe` | `Low` | `Strict` | optional `limit` and `cursor` |
| `n8n.credentials.list` | `GET /credentials` with bounded `limit`/opaque `cursor`; owner/admin and upstream `credential:list` caveat | `n8n.credentials.metadata.read` | `Safe` | `Low` | `Strict` | optional `limit` and `cursor` |
| `n8n.tags.list` | `GET /tags` with bounded `limit`/opaque `cursor` | `n8n.tags.read` | `Safe` | `Low` | `Strict` | optional `limit` and `cursor` |
| `n8n.folders.list` | `GET /projects/{projectId}/folders` with fixed `select`, optional JSON filter, and bounded `skip`/`take` | `n8n.folders.read` | `Safe` | `Low` | `Strict` | `project_id` |
| `n8n.folders.get` | `GET /projects/{projectId}/folders/{folderId}` | `n8n.folders.read` | `Safe` | `Low` | `Strict` | `project_id`, `folder_id` |
| `n8n.workflows.create_draft` | one `POST /workflows`, then independent `GET /workflows/{id}` | `n8n.workflows.write` | `Risky` | `High` | `BestEffort` | name, typed graph, exact approval reference, UUID idempotency key |
| `n8n.workflows.update_draft` | baseline `GET`, one `PUT /workflows/{id}`, then independent `GET` | `n8n.workflows.write` | `Risky` | `High` | `BestEffort` | id, typed graph, full lifecycle/state precondition, exact approval reference, UUID idempotency key |
| `n8n.workflows.lifecycle` | baseline REST `GET`, one exact official-MCP `publish_workflow`/`unpublish_workflow` call, then independent REST detail `GET` | `n8n.workflows.lifecycle` | `Risky` | `High` | `BestEffort` | id, `action=publish|unpublish`, optional publish `versionId`, full lifecycle precondition, exact approval reference, UUID idempotency key |
| `n8n.mcp_access.reconcile` | dry-run: bounded paginated `GET /workflows`; apply: current-plan reads, one full required `PUT /workflows/{id}` with only the logical `settings.availableInMCP` change, and independent detail GET | `n8n.mcp_access.write` | `Risky` | `High` | `BestEffort` | scope, desired, dryRun; apply guard with approvalRef, exact dryRunDigest, and UUID idempotencyKey |

For `n8n.mcp_access.reconcile`, a present REST `settings` object without an
`availableInMCP` key is normalized to `false`: n8n's public workflow REST
serializer omits this default-off flag. A missing, `null`, or non-object
`settings` value remains unknown and fails closed. The general workflow-list
projection remains presence-aware and does not apply this normalization to
ordinary read output.

Read output boundary:
- Workflow list items keep the compact metadata projection (`id`, nullable `name` and
  description/state metadata, project/folder timestamps, `availableInMCP`, and tag
  `id`/`name`) and continue to discard graph content. The raw settings object is
  never returned.
- Workflow get requires explicit provider `active`, `versionId`,
  `activeVersionId` (string or null), `isArchived`, current `nodes` and
  `connections`, and `activeVersion` (object or null). It returns the normalized
  state fields `id`, `name`, `projectId`, `folderId`, `versionId`, `active`,
  `activeVersionId`, `isArchived`, `draft`, `published`, `stateDigest`, and
  `updatedAt`. Missing or contradictory publication fields fail closed.
- `draft.graphDigest` and `published.graphDigest` use domain-separated
  BLAKE3-256 over deterministic JSON containing exactly `nodes` and
  `connections`: object keys are recursively sorted, array order is preserved,
  and only each node's top-level `credentials` binding is removed. Code node
  source and all other graph semantics remain in the digest preimage but are
  never returned or logged.
- `stateDigest` uses a separate domain and includes normalized metadata,
  version/lifecycle fields, provider `createdAt`/`updatedAt`, tags, and the
  complete draft and published graphs including credential bindings. Provider
  `createdAt` remains digest-only and is not added to the normalized public
  output. `stateDigest` is the write-precondition
  digest; an official MCP representation that hides credential bindings cannot
  authorize a write without a typed REST readback that reproduces this digest.
- Raw nodes, connections, Code source, credential references, pinned data, and
  either digest preimage never cross the connector output or log boundary.
- Execution reads serialize only `id`, `finished`, `mode`, `startedAt`, `stoppedAt`,
  `workflowId`, `status`, `retryOf`, `retrySuccessId`, and `waitTill`.
- Project reads serialize only `id`, `name`, and optional `type`. Users, roles,
  memberships, credentials, workflow data, and arbitrary provider metadata are discarded.
- The project projection assumes the current provider shape includes `id`; if it is absent, the connector fails closed rather than inventing an identifier.
- Tag reads serialize only `id` and `name`; provider timestamps and arbitrary metadata
  are discarded.
- Credential reads serialize only `resourceUri`, `id`, `name`, and `type`; provider
  values, secret/config maps, auth headers, sharing entries, and unrecognized fields
  are discarded. Each item binds to `fwc-n8n://{server}/credentials/{credentialId}`.
- Folder list responses preserve the provider `{count,data}` envelope and serialize
  only `resourceUri`, `id`, `name`, and `parentFolderId`. Root folders return a null
  `parentFolderId`; each item URI is `fwc-n8n://{server}/folders/{folderId}`.
- Folder get responses serialize exactly `resourceUri`, `id`, `name`,
  `parentFolderId`, `createdAt`, `updatedAt`, `totalSubFolders`, and
  `totalWorkflows`. The provider must supply every field; only an explicit null
  `parentFolderId` is accepted as a null value. Get URIs use the same folder-only
  canonical shape.
- Folder list capability tokens bind to `fwc-n8n://{server}/projects/{projectId}`;
  folder get tokens bind to `fwc-n8n://{server}/folders/{folderId}`. The configured
  `server_id` supplies server identity; `server_id` is not an operation input.
- `name` and `finished` remain required output keys and may be `null`. List responses
  always expose one safe page in `data`; a valid provider `nextCursor` is returned
  exactly, while missing or `null` values omit the output key.
- List input accepts only `limit` (integer `1..=200`, default `50`) and `cursor`
  (non-empty opaque UTF-8 string, at most 4096 bytes, no control characters).
  Invalid input is rejected before HTTP, and unknown properties fail closed.
- Workflow get/activate, execution get, and folder get inputs are exact objects;
  unknown properties fail before capability verification or provider egress.
- Folder list input accepts required `project_id`, optional string
  `parent_folder_id`, `skip` (default `0`), and `take` (default `50`, maximum
  `200`). Unknown properties, invalid IDs, negative values, and `take > 200`
  fail before HTTP. The provider `select` is always exactly
  `["id","name","parentFolder"]`; `filter` is sent only when a parent filter
  is supplied.
- Workflow list requests force `excludePinnedData=true`. Execution list requests
  force `includeData=false`, `ignoreDataSizeLimit=false`, and
  `redactExecutionData=true`.

## Explicit Non-Goals

The current implementation does not include:

- workflow create, update, delete, import, export, clone, test-run, tag write, project write, folder write, credential write/secret retrieval, variable, user, audit, or source-control operations
- provider-specific filtering and sorting for workflow or execution list calls
- activation provider lifecycle; capability and approval gates are present, but the provider write path is deferred
- restore/unarchive, versions, test/prepare-test execution, credential mutation, and permanent deletion; execution data/result retrieval and execution management remain out of scope
- execution retry, stop, delete, log streaming, custom-data filtering, or execution-data redaction management
- API-key provisioning or secret injection inside the connector process;
  production credential injection and egress enforcement belong to the
  host/sandbox boundary, not to the connector process
- OAuth installation, API-key rotation, credential validation beyond local configuration shape, or live self-check probe
- n8n CLI behavior, server CLI behavior, embedded n8n runtime, webhook receiver, scheduler, or trigger execution
- provider credential claims: the connector does not infer or assert that a folder
  `403` is caused by folder licensing, API-key scope, or project RBAC; no current
  mechanical discriminator is claimed

These are excluded on purpose:

- Activating a workflow can start cron, webhook, polling, or other production triggers. This packet therefore denies the operation even after its capability and approval checks pass.
- Providers may supply sensitive workflow and execution payloads, but this slice
  discards those payloads at the typed provider DTO -> safe runtime view boundary;
  broad export and debugging surfaces remain non-goals.
- n8n has a large public API; this connector should grow only through manifest-aligned, capability-gated slices.

## Connector Update Review Gate

The current update subsystem is a review-first contract, not a live updater:

- `fwc-n8n update-review detect` is read-only. It compares normalized snapshots
  and emits a stable review digest and deduplication key.
- Authorization and apply are deliberately absent from the `update-review`
  command. A future owner-decision adapter must authenticate the owner and
  issue an opaque, single-use decision with a UUID, a short bounded lifetime,
  and a persistent replay ledger.
- The host-side trusted executor is now implemented as a narrow library path;
  it is not a generic command runner and is not exposed as a model-controlled
  `npm` or shell operation. It accepts only the opaque verified candidate,
  validates candidate, stage plan, metadata, registry URL, and exact artifact
  SRI binding before any stage I/O, and then uses the fixed stage-I/O contract.
- Apply accepts only an opaque verified staged-artifact handle. It consumes the
  authorization, holds a per-component lock, checks the exact active snapshot,
  and permits only compare-and-swap activation and conditional rollback.
- The local `n8n-mcp` adapter creates fixed npm metadata and generates each
  staging plan's canonical UUID-v4 internally; callers cannot choose or reuse
  the stage identifier. Its Linux
  verifier anchors the root and all traversal to file descriptors with
  `openat2`, rejects links and unsafe ownership or modes, enforces actual-byte
  bounds, and binds the exact registry URL, package manifest, strict lockfile
  graph, executable entry point, and complete BLAKE3 tree digest. Manifest,
  lockfile, executable, and receipt re-reads must match the same per-file
  content digest and file identity captured by the tree pass.
- A fixed `.registry-artifact.tgz` receipt must be present in the stage and its
  bytes must match the registry `dist.integrity` SHA-512 SRI before an opaque
  verified candidate can exist. The candidate artifact digest domain-separates
  and binds that verified tarball SRI to the extracted-tree digest. The trusted
  executor creates the empty version-plus-UUID directory, materializes the
  receipt from the exact artifact, performs a bounded streaming `tar --list`
  preflight with an absolute deadline, and rechecks the receipt digest before
  extraction. Any mismatch fails closed. The child receives an empty inherited
  environment plus an allowlisted replacement environment.
- A host-only append-only decision ledger writes and fsyncs a private pending
  record, atomically commits it with no-replace rename under an anchored
  root-owned directory fd, then fsyncs the directory. Matching replay is
  rejected; malformed or colliding committed records fail closed. A crash
  before commit may leave an ignored pending file but cannot consume the
  decision. The ledger trust root is not created by the runtime.
- The public CLI still does not fetch from the registry or invoke `npm`, and
  `update-review` exposes no apply mode. The separate `provision --mode apply`
  command performs only the fixed-root, proof-carrying owner-gated immutable
  release promotion described above; it is not this component update executor.
  The implemented executor is the
  host-side security boundary for a future adapter: it re-verifies the exact
  stage before `apply_authorized`, and on every pre-activation materialize,
  extraction, re-verification, or candidate-mismatch failure it performs a
  bounded fd-relative discard. A discard failure is terminal and preserves the
  original error. No discard is attempted after activation has begun.
- `begin_exact` returns before acquiring the component lock when its exact
  precondition fails; callers must not assume a lock exists on that error path.
- Registry lifecycle scripts are never executed and are represented only by a
  digest. Release notes are discarded. Neither registry content nor package
  content can authorize an update or directly edit documentation or skills.

The installed immutable bundle and the existing opt-in MCP fallback therefore
remain unchanged by this subsystem.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, session ID, request, and error counter state
- local URL readiness and host-mediation warning state
- failed self-check for production direct egress and credential-reference modes, without provider traffic
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny for known versus unknown `operation` values
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, health, doctor, self-check, introspection, simulation, shutdown, and counters
- all read operations through deterministic HTTP fixtures, including hostile-field redaction, bounded query encoding, cursor validation/preservation, strict workflow publication-state invariants, graph/state digest separation, and null required-key assertions, plus activation zero-traffic denial
- project list success, pagination, bounded query encoding, input rejection before HTTP, cursor presence validation, safe projection, provider error classes, timeout mapping, and malformed JSON rejection
- credential metadata list success, bounded pagination and cursor handling, owner/admin/scope caveat documentation, malformed required-field rejection, provider status/timeout/bad-JSON mapping, canonical resource binding, host-proxy envelope, no-fallback behavior, and hostile secret-field discard
- direct provider response bounds for declared and chunked oversized success/error bodies, a boundary-safe response, and a short configured timeout
- table-driven connector-to-proxy envelope/response handling for every advertised read, including exact operation/resource pairs and logical resources distinct from HTTPS transport URLs
- focused host authorization source coverage with a non-wildcard token: matching logical resource accepted, mismatched logical resource rejected, and valid logical resource plus disallowed transport rejected by network policy; a historical current-host read-only REST acceptance record also reports both configured servers, but its release ID and evidence scope are not recorded here and it is not current-release acceptance
- tag list typed projection, timestamp/unknown-field redaction, bounded pagination, input/cursor validation, provider error mapping, timeout, malformed JSON, and capability/simulation parity
- folder list/get projection and redaction, exact encoded paths and JSON query values, root/nested parent handling, defaults/bounds, invalid-input no-HTTP behavior, capability-resource binding, required-field rejection, safe 400/401/403/404/429/500/503 mapping, malformed JSON, configured timeout, and simulation parity
- invoke rejection for unknown operation and missing required inputs
- provider 401, 403, 404, 429, and 500 classes
- API-key and credential-reference modes, auth redaction, zero-traffic egress denial, provisioning readiness, and base URL policy
- reconfigure behavior and request/error counter behavior

## Source Notes

- `connectors/n8n/src/connector.rs` defines configuration parsing, lifecycle handlers, URL readiness policy, provisioning recipe, introspection, simulation, and invoke dispatch.
- `connectors/n8n/src/client.rs` defines auth headers, endpoint paths, supplied runtime timeouts, bounded provider-body reads, URL trimming, and provider error mapping.
- `connectors/n8n/src/types.rs` defines separate permissive list and strict
  workflow-detail provider DTOs, serialize-only normalized state/views and list
  envelopes, presence-aware publication state, strict folder field presence,
  and API error response shapes.
- `connectors/n8n/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/n8n/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, and rate-limit intent.
- `connectors/n8n/tests/integration.rs` contains the runtime contract proof surface, including hostile provider-payload redaction fixtures.

## Verification Bundle

The nqm81.11 security closeout (2026-08-19) is a historical verification record,
not current-release acceptance; no re-run is implied here. It passed the focused connector proof
lane: 301 library tests, the connector binary test suite (52 passed, one
approved cgroup-v2 integration ignored), 125 integration tests, three local
non-mock tests, `cargo check --locked -p fcp-n8n --all-targets`,
`cargo clippy --locked -p fcp-n8n --lib --no-deps -- -D warnings`,
`cargo fmt --all -- --check`, and `git diff --check`. Full all-target clippy
still reports 13 pre-existing warnings in unchanged n8n test binaries; those
are outside this closeout and are not silently treated as fixed.

The security tests cover bounded archive listing and timeout kill/wait,
receipt replacement between preflight and extraction, immutable
candidate/metadata/artifact binding before stage creation, hostile archive
entries, fd-relative bounded cleanup, cleanup-failure terminal reporting, and
the absence of cleanup after activation.

The static provider build must apply `+crt-static` only to the final
`fcp-n8n` crate invocation:

```bash
cargo rustc -p fcp-n8n --bin fcp-n8n --release -- -C target-feature=+crt-static
```

Do not set global `RUSTFLAGS=-Ctarget-feature=+crt-static` for this build. A
globally static dependency graph can start directly yet terminate under the
mandatory owned-invocation network seccomp before answering `introspect`.
Before assembling a release, run the ignored real-artifact smoke explicitly:

```bash
FCP_N8N_OWNED_SMOKE_BINARY=/absolute/path/to/fcp-n8n \
  cargo test -p fcp-host --test n8n_owned_static_smoke \
  static_n8n_connector_introspects_under_owned_network_filter -- --ignored --exact
```

Run these after changing this connector contract:

```bash
git diff --check -- connectors/n8n/README.md
ubs connectors/n8n/README.md
LC_ALL=C rg -n '[^ -~]' connectors/n8n/README.md
rg -n '\bmaster\b' connectors/n8n/README.md
```

For source or behavior changes, run the connector proof lane:

```bash
cargo test -p fcp-n8n --all-targets
cargo check -p fcp-n8n --all-targets
cargo clippy -p fcp-n8n --all-targets -- -D warnings
cargo fmt --all -- --check
```

## Operator Guidance

- Configure an n8n public API root, commonly shaped like `https://n8n.example.com/api/v1`.
- A host credential reference is accepted and every advertised read uses a bounded proxy envelope carrying its canonical logical resource independently of its HTTPS target. Current-host read-only acceptance has passed for EEC and Hetzner; repeat the focused test for every new release, credential rotation, or server migration.
- Direct API-key mode is for loopback fixtures only in this packet; production egress requires host mediation.
- Treat workflow activation as deferred: capability and approval checks are enforced, but no provider lifecycle request is emitted.
- Use `self_check()` as a safe readiness/probe report. Production and credential-reference modes report failure before provider traffic.
- Expect list operations to return one bounded provider page. Pass a returned
  `nextCursor` back unchanged to continue; provider-specific filtering remains unsupported.
