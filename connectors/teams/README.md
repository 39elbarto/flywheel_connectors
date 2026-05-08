# Teams Connector V3 Contract

> **Status**: runtime contract documented; Graph/Bot Framework drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Microsoft Graph joinedTeams**: https://learn.microsoft.com/en-us/graph/api/user-list-joinedteams?view=graph-rest-1.0
> **Microsoft Graph list channels**: https://learn.microsoft.com/en-us/graph/api/channel-list?view=graph-rest-1.0
> **Microsoft Graph send chat message**: https://learn.microsoft.com/en-us/graph/api/chat-post-messages?view=graph-rest-1.0
> **Teams bot activity handlers**: https://learn.microsoft.com/en-us/microsoftteams/platform/bots/bot-concepts

## Purpose

This document fixes the operator-facing contract for `fcp.teams`. The connector currently exposes a Microsoft Graph and host-forwarded Bot Framework surface implemented in this crate: list teams/channels/chats/messages, send channel or chat messages, send adaptive cards, reply/update messages, normalize inbound Teams activities, and read cached conversation state.

The connector is intentionally a bounded Teams collaboration bridge. It is not a full Microsoft 365 SDK, Teams admin client, Graph proxy, app-registration manager, bot hosting service, durable activity store, meeting client, compliance export client, or general Microsoft Graph automation surface.

## Current Runtime Snapshot

The current crate exposes these operations:

- `teams.list_teams`
- `teams.get_team`
- `teams.list_channels`
- `teams.get_channel`
- `teams.send_channel_message`
- `teams.list_chats`
- `teams.send_chat_message`
- `teams.list_chat_messages`
- `teams.send_card`
- `teams.reply_message`
- `teams.update_message`
- `teams.ingest_activity`
- `teams.get_conversation_state`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-teams`.
- Runtime `BaseConnector` ID is `fcp.teams`.
- Manifest connector name is `fcp.teams`.
- The manifest has no `interface_hash` field; runtime computes `manifest_hash` as `sha256:` over embedded `manifest.toml`.
- Configuration requires an `auth` object.
- Default `graph_base_url` is `https://graph.microsoft.com/v1.0`.
- Default `bot_service_url` is `https://smba.trafficmanager.net`.
- Default `timeout_ms` is `30000`.
- Auth modes are `access_token`, `client_credentials`, and `credential_id`.
- Direct `access_token` mode sends bearer auth.
- `credential_id` mode sends `x-fcp-credential-id` and expects host/egress injection; it validates only that the value is a legal HTTP header value.
- `client_credentials` mode acquires a token from `https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token`.
- Client-credentials token scope is always `https://graph.microsoft.com/.default`.
- `graph_base_url` policy accepts `/v1.0`, `/v1.0/`, `/beta`, or `/beta/` on allowed Graph hosts.
- Runtime allowed Graph hosts are `graph.microsoft.com`, `graph.microsoft.us`, `dod-graph.microsoft.us`, and `microsoftgraph.chinacloudapi.cn`.
- Local Graph hosts are accepted only under `#[cfg(test)]`.
- `bot_service_url` policy accepts any HTTPS host with no userinfo, query string, or fragment; localhost and `*.localhost` are accepted for tests.
- Configure creates a `ConnectorRuntime`, Graph client, config, retry config, and clears conversation/idempotency/dedup caches.
- Configure does not clear an existing verifier or base handshaken state.
- Handshake installs a `CapabilityVerifier`, sets the base handshaken flag, and grants requested capabilities.
- Invoke requires configured plus handshaken state through `base.check_ready()`.
- Invoke verifies bound capability tokens against `teams.read` or `teams.write`.
- Invoke does not pass resource URIs into bound-token verification.
- Invoke does not verify approval tokens; the manifest marks all operations `requires_approval = "none"`.
- `simulate()` currently returns allowed for every request without operation, configuration, capability, or input validation.
- `subscribe()` and `unsubscribe()` return `StreamingNotSupported`.
- `shutdown()` only shuts down the runtime; it does not clear config, client, verifier, base flags, caches, or conversation state.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Runtime accepts Microsoft government and China Graph hosts, `/beta`, and test-local hosts, while manifest network constraints list only `graph.microsoft.com`.
- Runtime `bot_service_url_policy` accepts any clean HTTPS origin, not only Microsoft Bot Framework service hosts.
- Runtime retry config is stored and surfaced in observability, but Graph client calls use direct reqwest requests and do not run through a connector retry loop.
- Runtime `simulate()` is unconditional and does not mirror invoke authorization or input validation.
- Runtime bound-token verification uses empty resource URI lists, so tokens are capability/operation-bound but not team/channel/chat/resource-bound by this connector.
- Runtime response cache applies to send, card, reply, update, and ingest operations when an idempotency key is present; read operations are not cached.
- Runtime health can report ready before handshake if direct access-token config is valid, while invoke still requires handshake.
- Runtime health degrades for `credential_id` mode and `client_credentials` mode even when local configuration is structurally valid.
- Runtime self-check calls `/me` only for direct delegated access-token mode.
- Runtime self-check degrades for `credential_id` mode because the host must inject a bearer token.
- Runtime self-check degrades for `client_credentials` mode because this connector's `/me` and standard send/reply/update flows require delegated user context.
- Manifest sandbox uses legacy field names such as `memory_limit_mb`, while newer manifests in this repo often use `memory_mb`.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should make simulate authorization-equivalent, add resource URI binding for teams/channels/chats/messages, align manifest network constraints with runtime Graph cloud support or narrow runtime policy, decide whether runtime retries should use the stored retry config, clear verifier/session state on reconfigure/shutdown if needed, and add a tracked verification bundle.

## First-Slice Scope

The current Teams README slice documents the existing runtime surface:

- direct delegated token, client-credentials, and host credential-reference configuration
- Microsoft Graph URL policy and Bot Framework service URL policy
- Graph read/write operation paths, message payload construction, adaptive cards, threaded replies, fallback replies, and updates
- host-forwarded Bot Framework activity ingestion and conversation-state cache
- bound capability-token verification for invoke
- lifecycle, health, doctor, self-check, simulation, introspection, subscribe, and shutdown behavior
- deterministic connector tests and direct proof commands

## Auth And Scope Boundary

- Authentication mechanisms:
  - delegated bearer `access_token`
  - app-only `client_credentials`
  - host-injected `credential_id`
- Home zone: `z:work`.
- Allowed source zones: `z:work` and `z:project:*`.
- Allowed target zones: `z:work` and `z:project:*`.
- Runtime capability surface:
  - `teams.read`
  - `teams.write`
- Invoke rejects missing handshakes and invalid bound capability tokens.
- Invoke verifies `teams.read` for list/get/conversation-state operations and `teams.write` for send/reply/update/ingest operations.
- Invoke does not verify approval tokens.
- The connector does not persist access tokens, client secrets, injected bearer tokens, Graph responses, activity payloads, conversation state, dedup keys, idempotent responses, tenant IDs, team IDs, channel IDs, or chat IDs outside process memory.
- Teams messages and activities can contain private, work, credential, or regulated data. Treat live output according to the tenant, team, chat, and channel policy.

## Network And Runtime Invariants

- Default Graph endpoint: `https://graph.microsoft.com/v1.0`.
- Default Bot Framework service origin: `https://smba.trafficmanager.net`.
- Runtime trims trailing slashes from Graph base URLs.
- Runtime Graph path segments are percent-encoded, including slashes, query delimiters, percent signs, colons, and `@`.
- Runtime sends bearer auth in access-token and client-credentials modes.
- Runtime sends `x-fcp-credential-id` and no bearer auth in credential-reference mode.
- Runtime follows Graph `@odata.nextLink` pagination for collection reads.
- Runtime maps `Retry-After` on Graph 429 responses into rate-limit errors but does not retry automatically.
- Inbound Teams activity ingestion is host-forwarded through `teams.ingest_activity`; no native listener is started.
- Ingress policy can allowlist sender IDs, Azure AD object IDs, team IDs, and channel/conversation IDs.
- `bot_user_id` is dropped as a self-message before state mutation.
- File-consent invoke activities are denied unless `accept_file_consent` is explicitly true.
- Seen activity IDs are deduplicated in a bounded in-memory set of `1024`.
- Idempotent response cache is bounded to `512` entries.
- Conversation state is in-memory and keyed by conversation ID.
- Event caps report no streaming, no replay, zero minimum buffer, and no ack requirement.

## Operation Inventory

| Operation | Runtime request/behavior | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|--------------------------|------------|------------|-----------|-------------|----------------|
| `teams.list_teams` | `GET /me/joinedTeams` | `teams.read` | `Safe` | `Low` | `Strict` | none |
| `teams.get_team` | `GET /teams/{team_id}` | `teams.read` | `Safe` | `Low` | `Strict` | `team_id` |
| `teams.list_channels` | `GET /teams/{team_id}/channels` | `teams.read` | `Safe` | `Low` | `Strict` | `team_id` |
| `teams.get_channel` | `GET /teams/{team_id}/channels/{channel_id}` | `teams.read` | `Safe` | `Low` | `Strict` | `team_id`, `channel_id` |
| `teams.send_channel_message` | `POST /teams/{team_id}/channels/{channel_id}/messages` | `teams.write` | `Risky` | `Medium` | `None` | `team_id`, `channel_id`, `content` |
| `teams.list_chats` | `GET /me/chats` | `teams.read` | `Safe` | `Low` | `Strict` | none |
| `teams.send_chat_message` | `POST /chats/{chat_id}/messages` | `teams.write` | `Risky` | `Medium` | `None` | `chat_id`, `content` |
| `teams.list_chat_messages` | `GET /chats/{chat_id}/messages` | `teams.read` | `Safe` | `Low` | `Strict` | `chat_id` |
| `teams.send_card` | Send message payload with adaptive-card attachment | `teams.write` | `Risky` | `Medium` | `BestEffort` | channel target or chat target plus `adaptive_card` |
| `teams.reply_message` | Channel replies or chat `replyWithQuote`, with flat fallback on Graph 400 | `teams.write` | `Risky` | `Medium` | `BestEffort` | channel target or chat target, `message_id`, `content` or card |
| `teams.update_message` | PATCH channel/chat message or channel reply | `teams.write` | `Risky` | `Medium` | `BestEffort` | channel target or chat target, `message_id`, `content` or card |
| `teams.ingest_activity` | Normalize host-forwarded Bot Framework activity and update conversation cache | `teams.write` | `Risky` | `Medium` | `BestEffort` | valid activity with conversation |
| `teams.get_conversation_state` | Read cached conversation state | `teams.read` | `Safe` | `Low` | `Strict` | `conversation_id` |

## Explicit Non-Goals

The current implementation does not include:

- Microsoft app-registration automation, consent automation, OAuth authorization-code flow, device code flow, token refresh, or credential vaulting
- Teams admin, policy, compliance, meeting, call, presence, user, app catalog, calendar, or SharePoint/OneDrive APIs
- creating teams, channels, chats, tabs, apps, meetings, or subscriptions
- native Bot Framework listener hosting, TLS termination, JWT validation for inbound bot activities, or proactive-message service hosting
- durable conversation state, durable activity replay, delivery retries, dead-letter queues, or cross-process deduplication
- streaming subscriptions, Graph change notifications, webhook receive endpoints, or queue/pub-sub integration
- approval-token verification, per-resource token binding, per-team/channel policy storage, or payload redaction beyond normal debug redaction

These are excluded on purpose:

- Teams message operations mutate live collaboration surfaces and can notify people.
- Microsoft Graph delegated/app-only permission boundaries are subtle and should remain explicit in readiness checks.
- Bot Framework activity ingress is host-forwarded and should not be confused with a production bot hosting runtime.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, `subscribe()`, and `shutdown()` are part of the public closeout contract. They surface:

- configuration, client, runtime, handshake, manifest hash, artifact root hint, retry config, and cache/count observability
- Graph endpoint policy, Bot Framework service URL policy, auth mode, credential injection state, auth surface compatibility, and tenant hint state
- direct delegated access-token readiness through Microsoft Graph `/me`
- degraded readiness for credential injection and client-credentials modes
- typed introspection with operations, schemas, capability IDs, risk levels, safety tiers, idempotency, and event metadata
- unconditional simulation allow behavior
- provider/FCP error mapping for 401, 403, 404, 429, retryable provider errors, JSON errors, invalid input, missing conversation state, and capability denial

The deterministic integration evidence is anchored on connector-local tests covering:

- configuration modes, malicious endpoint rejection, Graph cloud URL policy, Bot Framework URL policy, health, doctor, self-check, handshake, simulate, invoke readiness, shutdown, and manifest hash stability
- all thirteen operation metadata entries and manifest/runtime operation alignment
- bound capability-token enforcement for invoke
- Graph path encoding, pagination, credential-header mode, client-credentials token acquisition, and provider error classes
- message send, card payloads, channel/chat replies, threaded-reply fallback, updates, attachments, mentions, and idempotency caching
- host-forwarded activity ingestion, self-message drop, allowlists, file-consent handling, duplicate activities, service URL validation, conversation state, and event envelope shaping

## Source Notes

- `connectors/teams/src/connector.rs` defines endpoint policy, lifecycle handlers, doctor/self-check, operation catalog, capability verification, message routing, activity normalization, idempotent cache, conversation state, simulation, introspection, and invoke dispatch.
- `connectors/teams/src/client.rs` defines Microsoft Graph transport, auth headers, credential-reference mode, client-credentials token acquisition, URL path encoding, pagination, message APIs, health probe, and provider error mapping.
- `connectors/teams/src/types.rs` defines config, auth modes, ingress policy, Graph response types, Bot Framework activity shapes, conversation state, and token response shapes.
- `connectors/teams/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/teams/manifest.toml` defines the manifest operation catalog, network constraints, sandbox boundary, zone policy, approval metadata, and operator note.
- `connectors/teams/tests/integration.rs` contains the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/teams/README.md
ubs connectors/teams/README.md
LC_ALL=C rg -n '[^ -~]' connectors/teams/README.md
rg -n '\bmaster\b' connectors/teams/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-teams
rch exec -- cargo check -p fcp-teams --all-targets
rch exec -- cargo clippy -p fcp-teams --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use a dedicated non-production Microsoft 365 tenant, team, channel, and chat for verification.
- Prefer delegated user tokens for full connector readiness; client credentials do not prove `/me`-backed flows or standard send/reply/update operations.
- Keep `credential_id` mode paired with a host or egress proxy that injects a delegated bearer token.
- Treat send, card, reply, update, and activity-ingest operations as high-review collaboration mutations even though the manifest currently declares no approvals.
- Do not rely on `simulate()` for authorization or input proof until it mirrors invoke behavior.
- Do not rely on shutdown to erase tokens, client state, verifier state, caches, or conversation state.
