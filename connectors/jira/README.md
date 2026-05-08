# Jira Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Jira REST upstream**: https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/

## Purpose

This document fixes the operator-facing contract for `fcp.jira`. The connector exposes the Jira issue, workflow transition, sprint, comment, worklog, attachment, automation-rule, server-info, and Beads sync surface implemented in this crate.

The connector is intentionally a bounded Jira bridge. It is not a Jira administration client, project provisioning tool, Jira Service Management client, Forge app runtime, webhook listener, marketplace app manager, or full Atlassian organization API client.

## Current Runtime Snapshot

The current crate exposes these operations:

- `jira.create_issue`
- `jira.get_issue`
- `jira.update_issue`
- `jira.delete_issue`
- `jira.search_jql`
- `jira.list_transitions`
- `jira.transition_issue`
- `jira.list_sprints`
- `jira.move_to_sprint`
- `jira.add_comment`
- `jira.list_comments`
- `jira.worklog.list`
- `jira.worklog.add`
- `jira.worklog.update`
- `jira.worklog.delete`
- `jira.add_attachment`
- `jira.automation.rule.list`
- `jira.automation.rule.get`
- `jira.automation.rule.create`
- `jira.automation.rule.update`
- `jira.automation.rule.enable`
- `jira.automation.rule.disable`
- `jira.automation.rule.delete`
- `jira.sync.pull_issue`
- `jira.sync.push_bead`
- `jira.sync.reconcile`
- `jira.server.info`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-jira`.
- Runtime `BaseConnector` ID and manifest connector ID are both `fcp.jira`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:08898c2d611f91db9d5d8d20f232a7a35fa3dc76b1ccf5fe29b9d48157e5993e`.
- Configuration requires `domain`.
- Authentication requires exactly one auth source: direct `email` plus `api_token`, or `credential_id`.
- Direct auth sends HTTP Basic auth over the `email:api_token` pair.
- `credential_id` mode sends `X-FCP-Credential-ID` and expects host egress policy to inject real secret material.
- Deployment defaults to Jira Cloud and accepts Cloud, Server, and Data Center aliases.
- Cloud deployment uses `/rest/api/3`; Server and Data Center deployment use `/rest/api/2`.
- Default REST URL is `https://{domain}.atlassian.net/rest/api/{version}`.
- Default Agile URL is `https://{domain}.atlassian.net/rest/agile/1.0`.
- Default automation URL is `https://{domain}.atlassian.net/rest/cb-automation/latest`.
- URL overrides reject userinfo, query strings, fragments, malformed URLs, and non-loopback HTTP.
- Cloud non-loopback overrides must use the exact `{domain}.atlassian.net` host.
- Server and Data Center non-loopback overrides accept arbitrary HTTPS hosts.
- Loopback hosts are accepted for deterministic tests.
- Runtime request timeout is 30 seconds.
- The client uses the shared retry loop with `max_retries = 3`, `initial_delay_ms = 1000`, and `max_delay_ms = 60000`.
- The client retries connect and timeout failures plus retryable provider status classes.
- Runtime handshake parses a full `HandshakeRequest`, installs a `CapabilityVerifier`, records `SessionId`, optionally records `zone_dir`, and returns a SHA-256 hash over `manifest.toml`.
- `invoke` requires `operation`, `input`, and `capability_token`; it resolves the operation capability from introspection and verifies a bound capability token before provider execution.
- `simulate` validates operation inventory, configured state, handshaken state, and bound capability token before returning an allowed response.
- Runtime capability-token verification passes an empty resource URI list for all operations in this checkout.
- `health()` is local state only; `self_check()` calls Jira when direct credentials are configured and degrades for `credential_id`.
- `handle_shutdown()` shuts down the client runtime, clears config/client/verifier/session/zone directory state, and clears base configured/handshaken flags.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest operations mark risky and dangerous mutations with approval modes, but runtime introspection sets `requires_approval = None` for every Jira operation.
- Runtime verifies bound capability tokens, but does not bind those tokens to concrete Jira resource URIs.
- Manifest event caps say streaming is enabled, but runtime introspection returns empty event and resource catalogs and `event_caps = None`.
- Handshake returns event capability metadata even though no runtime event stream catalog is exposed.
- Manifest max-result limits are stricter than several runtime caps. Runtime caps `jira.search_jql`, `jira.list_sprints`, `jira.list_comments`, and worklog listing at up to 1000 results in code paths where the manifest advertises lower defaults or maxima.
- The automation URL defaults to `/rest/cb-automation/latest`, which is not part of the core Jira REST v3 base URL.
- Beads sync operations persist state under handshake `zone_dir`; calling them without a handshake-provided zone directory fails.
- Sync state is process/file local and guarded by a connector-local lease file, not by global Beads or Agent Mail ownership.
- Manifest state migration hint is `init`; runtime sync state already writes `jira_sync_state.json` under the zone directory.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align approval metadata, add resource URI binding for capability verification, reconcile manifest/runtime max-result limits, document or replace the automation API base, expose or remove event capability claims, and add a tracked verification bundle.

## First-Slice Scope

The current Jira README slice documents the existing runtime surface:

- direct Basic auth and host credential-reference configuration
- Cloud versus Server/Data Center API version selection
- endpoint override policy, timeout, retry, and provider error mapping
- issue, JQL search, transition, sprint, comment, worklog, attachment, automation-rule, server-info, and Beads sync operations
- bound capability-token verification during both `invoke` and `simulate`
- local sync-state persistence requirements
- deterministic WireMock tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms: Jira Basic auth from `email` plus `api_token`, or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability surface:
  - `jira.read` gates reads, JQL search, sprint lists, comments/worklog reads, automation-rule reads, sync pull/reconcile, and server info.
  - `jira.write` gates issue create/update, transitions, sprint moves, comments, worklog add/update, attachments, automation create/update/enable/disable, and sync push.
  - `jira.delete` gates issue delete, worklog delete, and automation rule delete.
- Manifest optional capabilities also include `media.download`, but the current runtime surface is Jira REST and sync-state oriented.
- The connector does not persist Jira tokens, email addresses, credential secret material, raw provider responses, attachments, comments, or worklog bodies outside process memory, except for Beads sync state under handshake `zone_dir`.
- Jira payloads can include private issue text, comments, attachments, user identities, project topology, worklog entries, and automation rules. Treat live output as work-zone operational data.

## Network And Runtime Invariants

- Production Cloud host shape: `{domain}.atlassian.net`.
- Production port: `443`.
- TLS and SNI are required by the manifest for provider operations.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live provider operations.
- Runtime URL override policy allows loopback URLs for deterministic tests.
- Runtime URL override policy rejects non-loopback HTTP.
- Cloud runtime URL override policy pins non-loopback hosts to the configured Atlassian Cloud domain.
- Server and Data Center runtime URL override policy accepts arbitrary HTTPS hosts.
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: three attempts with 1000 ms initial delay and 60000 ms maximum delay.
- Manifest connect timeout is `10000 ms` and total timeout is generally `30000 ms`.
- Manifest maximum response bytes range from `1048576` to `5242880`.
- Sandbox profile is `strict`, with `512 MB` memory, `50%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets or subscribe to Jira webhooks.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `jira.read` | Read Jira issues, transitions, sprints, comments, worklogs, automation rules, sync projections, and server info. |
| `jira.write` | Create or update Jira issues, workflow state, sprint membership, comments, worklogs, attachments, automation rules, and Beads sync mappings. |
| `jira.delete` | Delete Jira issues, worklogs, and automation rules. |
| `media.download` | Manifest optional capability; no distinct runtime operation is exposed in this README slice. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `jira.create_issue` | `POST /rest/api/{2 or 3}/issue` | `jira.write` | `Risky` | `Medium` | `None` | Creates a new issue in a project. |
| `jira.get_issue` | `GET /rest/api/{2 or 3}/issue/{issue_key}` | `jira.read` | `Safe` | `Low` | `Strict` | Reads one issue by key or ID. |
| `jira.update_issue` | `PUT /rest/api/{2 or 3}/issue/{issue_key}` | `jira.write` | `Risky` | `Medium` | `Strict` | Updates fields on an existing issue. |
| `jira.delete_issue` | `DELETE /rest/api/{2 or 3}/issue/{issue_key}` | `jira.delete` | `Dangerous` | `High` | `Strict` | Permanently removes an issue. |
| `jira.search_jql` | `POST /rest/api/{2 or 3}/search` | `jira.read` | `Safe` | `Low` | `Strict` | Searches issues with JQL. |
| `jira.list_transitions` | `GET /rest/api/{2 or 3}/issue/{issue_key}/transitions` | `jira.read` | `Safe` | `Low` | `Strict` | Lists legal workflow transitions for an issue. |
| `jira.transition_issue` | `POST /rest/api/{2 or 3}/issue/{issue_key}/transitions` | `jira.write` | `Risky` | `Medium` | `None` | Changes issue workflow state. |
| `jira.list_sprints` | `GET /rest/agile/1.0/board/{board_id}/sprint` | `jira.read` | `Safe` | `Low` | `Strict` | Lists sprints for a Scrum board. |
| `jira.move_to_sprint` | `POST /rest/agile/1.0/sprint/{sprint_id}/issue` | `jira.write` | `Risky` | `Medium` | `Strict` | Moves issues into a sprint. |
| `jira.add_comment` | `POST /rest/api/{2 or 3}/issue/{issue_key}/comment` | `jira.write` | `Safe` | `Low` | `None` | Adds a side-effecting issue comment, though introspection marks it safe. |
| `jira.list_comments` | `GET /rest/api/{2 or 3}/issue/{issue_key}/comment` | `jira.read` | `Safe` | `Low` | `Strict` | Lists comments for an issue. |
| `jira.worklog.list` | `GET /rest/api/{2 or 3}/issue/{issue_key}/worklog` | `jira.read` | `Safe` | `Low` | `Strict` | Lists worklog entries for an issue. |
| `jira.worklog.add` | `POST /rest/api/{2 or 3}/issue/{issue_key}/worklog` | `jira.write` | `Risky` | `Medium` | `None` | Adds time tracking to an issue. |
| `jira.worklog.update` | `PUT /rest/api/{2 or 3}/issue/{issue_key}/worklog/{worklog_id}` | `jira.write` | `Risky` | `Medium` | `Strict` | Updates a worklog entry. |
| `jira.worklog.delete` | `DELETE /rest/api/{2 or 3}/issue/{issue_key}/worklog/{worklog_id}` | `jira.delete` | `Dangerous` | `High` | `Strict` | Deletes a worklog entry. |
| `jira.add_attachment` | `POST /rest/api/{2 or 3}/issue/{issue_key}/attachments` | `jira.write` | `Risky` | `Medium` | `None` | Uploads an attachment to an issue. |
| `jira.automation.rule.list` | `GET /rest/cb-automation/latest/project/{project_id}/rule` | `jira.read` | `Safe` | `Low` | `Strict` | Lists automation rules for a project. |
| `jira.automation.rule.get` | `GET /rest/cb-automation/latest/rule/{rule_id}` | `jira.read` | `Safe` | `Low` | `Strict` | Reads one automation rule. |
| `jira.automation.rule.create` | `POST /rest/cb-automation/latest/project/{project_id}/rule` | `jira.write` | `Dangerous` | `High` | `None` | Creates a rule that can mutate Jira automatically. |
| `jira.automation.rule.update` | `PUT /rest/cb-automation/latest/rule/{rule_id}` | `jira.write` | `Dangerous` | `High` | `Strict` | Updates an existing automation rule. |
| `jira.automation.rule.enable` | `POST /rest/cb-automation/latest/rule/{rule_id}/enable` | `jira.write` | `Dangerous` | `High` | `Strict` | Enables an automation rule. |
| `jira.automation.rule.disable` | `POST /rest/cb-automation/latest/rule/{rule_id}/disable` | `jira.write` | `Dangerous` | `High` | `Strict` | Disables an automation rule. |
| `jira.automation.rule.delete` | `DELETE /rest/cb-automation/latest/rule/{rule_id}` | `jira.delete` | `Dangerous` | `High` | `Strict` | Permanently removes an automation rule. |
| `jira.sync.pull_issue` | Jira issue read plus local sync-state write | `jira.read` | `Safe` | `Low` | `Strict` | Projects one Jira issue into canonical Beads sync state. |
| `jira.sync.push_bead` | Jira issue create/update plus local sync-state write | `jira.write` | `Risky` | `Medium` | `Strict` | Creates or safely updates Jira from a Beads record. |
| `jira.sync.reconcile` | Jira issue read plus local sync-state write | `jira.read` | `Safe` | `Low` | `Strict` | Compares Jira and Beads state and returns a deterministic next action. |
| `jira.server.info` | `GET /rest/api/2/serverInfo` | `jira.read` | `Safe` | `Low` | `Strict` | Reads server metadata and deployment type. |

## Resource URIs

Runtime capability-token verification currently passes an empty resource URI list for every Jira operation. The practical authorization binding in this checkout is operation plus capability plus token validity, not concrete issue, project, sprint, rule, worklog, or attachment URI.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Issue CRUD | `jira://{domain}/issues/{issue_key}` |
| JQL search | `jira://{domain}/search` |
| Sprints | `jira://{domain}/boards/{board_id}/sprints/{sprint_id}` |
| Comments and worklogs | `jira://{domain}/issues/{issue_key}/comments` and `jira://{domain}/issues/{issue_key}/worklogs/{worklog_id}` |
| Automation rules | `jira://{domain}/automation/rules/{rule_id}` |
| Beads sync | `jira://{domain}/sync/beads/{bead_id}` |

## Beads Sync State

The sync operations are part of the runtime contract, not just documentation:

- `jira.sync.pull_issue` reads a Jira issue, maps it into a canonical Beads sync record, strips reserved `bead:<id>` labels from public labels, and persists sync state.
- `jira.sync.push_bead` creates or updates a Jira issue from a Beads record, honors `fail_closed` versus `last_write_wins`, can transition Jira status, and persists refreshed sync state.
- `jira.sync.reconcile` compares a Beads record with Jira and returns the chosen action, conflict details, reason codes, and persisted state.
- Sync state requires handshake `zone_dir`.
- Sync state file name is `jira_sync_state.json`.
- Sync lease file name is `jira_sync_lease.json`.
- Sync state writes are local to the connector zone directory and are not a replacement for Beads issue ownership or Agent Mail file reservations.

## Explicit Non-Goals

The current implementation does not include:

- Jira project, field, workflow, permission, scheme, board, user, group, organization, or site administration
- Jira Service Management queues, requests, SLAs, customers, approvals, or assets
- webhook listening, webhook signature verification, event subscriptions, or durable event replay
- Atlassian OAuth installation flow, app registration, Forge, Connect app lifecycle, or marketplace installation
- issue bulk edit, bulk transition, version management, component management, project import/export, or release management
- attachment download, media scanning, content virus checks, or durable attachment storage
- global Beads conflict locking outside the connector-local sync lease

These are excluded on purpose:

- Project and workflow administration need narrower operator approval and audit contracts.
- Webhook signature verification belongs at the host ingress boundary before connector invocation.
- Beads sync must remain explicit and inspectable because it can create or update real Jira issues.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- local configuration, client, shutdown, base URL, auth mode, and credential-injection state
- provider-backed self-check through Jira `myself` when direct auth is configured
- degraded self-check for `credential_id` mode because real connectivity depends on host-side injection
- operation metadata with capability, risk, safety tier, idempotency, schemas, and hints
- bound capability-token verification during `invoke`
- simulation denial for unknown operation, unconfigured connector, missing handshake, missing capability, or token mismatch
- typed provider/FCP error mapping

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle, configuration, base URL policy, introspection, simulation, doctor, self-check, and shutdown behavior
- issue CRUD, JQL search, workflow transitions, sprint movement, comments, worklogs, attachments, automation rules, server-info, and sync behavior through deterministic HTTP fixtures
- invoke rejection for unknown operation, missing configuration, missing handshake, missing token, wrong token, and invalid input
- provider 401, 404, 429, 500 classes and FCP error mapping
- Beads sync persistence, conflict detection, restart behavior, and singleton-writer lease behavior

## Source Notes

- `connectors/jira/src/connector.rs` defines configuration parsing, URL policy, lifecycle handlers, introspection, simulation, capability-token verification, sync state, and invoke dispatch.
- `connectors/jira/src/client.rs` defines Jira REST paths, Agile paths, automation paths, auth headers, retry dispatch, timeout, validation, and provider error mapping.
- `connectors/jira/src/types.rs` defines Jira issue, sprint, comment, worklog, automation, server-info, and sync data shapes.
- `connectors/jira/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/jira/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, and rate-limit intent.
- `connectors/jira/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/jira/README.md
ubs connectors/jira/README.md
LC_ALL=C rg -n '[^ -~]' connectors/jira/README.md
rg -n '\bmaster\b' connectors/jira/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-jira
rch exec -- cargo check -p fcp-jira --all-targets
rch exec -- cargo clippy -p fcp-jira --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Prefer `credential_id` for production so host policy owns secret injection.
- Use direct `email` plus `api_token` only in local deterministic tests or explicitly scoped environments.
- Treat `jira.delete_issue`, `jira.worklog.delete`, `jira.automation.rule.*`, and `jira.sync.push_bead` as high-review operations even though runtime approval metadata is currently absent.
- Call `jira.list_transitions` before `jira.transition_issue`; transition IDs are workflow-local.
- Call `jira.sync.reconcile` before `jira.sync.push_bead` when Jira and Beads may both have changed.
- Do not rely on capability-token resource scoping for Jira objects until resource URI binding is implemented.
- Do not interpret event capability claims as a live event stream contract in this checkout.
