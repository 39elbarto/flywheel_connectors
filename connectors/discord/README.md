# Discord Connector V3 Contract

> **Status**: runtime contract documented with known manifest/introspection drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **REST upstream**: https://discord.com/developers/docs/reference
> **Gateway upstream**: https://discord.com/developers/docs/events/gateway
> **Message upstream**: https://discord.com/developers/docs/resources/message

## Purpose

This document fixes the operator-facing contract for `fcp.discord`. The connector exposes the Discord surface implemented in this crate: bot-token REST operations for messages, channels, guilds, reactions, and threads, plus Gateway-backed inbound event streaming with local resume state and gateway lease fencing.

The connector is intentionally a bounded Discord bot bridge. It is not a full Discord SDK, OAuth user-auth workflow, slash-command management surface, webhook receiver, voice client, moderation/admin tool, attachment upload/download client, guild provisioning tool, or interaction-response framework.

## Current Runtime Snapshot

The current runtime exposes these operations:

- `discord.send_message`
- `discord.edit_message`
- `discord.delete_message`
- `discord.get_channel`
- `discord.get_guild`
- `discord.trigger_typing`
- `discord.add_reaction`
- `discord.list_channels`
- `discord.create_thread`

Important runtime truths the contract preserves:

- Configuration requires `bot_credential`.
- `bot_credential` may be supplied with or without the leading `Bot ` prefix; the client stores the token without that prefix and sends `Authorization: Bot <token>`.
- Optional configuration includes `application_id`, `api_url`, `gateway_url`, `timeout`, `retry`, `intents`, `shard`, `gateway_identify_max_concurrency`, `inbound_policy`, and `chat_coordination`.
- Default REST base URL is `https://discord.com/api/v10`.
- Gateway URL is auto-discovered with `GET /gateway/bot` unless `gateway_url` is supplied.
- Default timeout is `30 seconds`.
- Default retry policy is `max_attempts = 3`, initial delay `500 ms`, maximum delay `30_000 ms`, and jitter `0.1`.
- The connector requires the Gateway intent bits for `GUILDS`, `GUILD_MESSAGES`, `DIRECT_MESSAGES`, and `MESSAGE_CONTENT`.
- Configure validates the REST and Gateway endpoint hosts before request construction.
- Configure makes a live `GET /users/@me` probe and requires the credential to authenticate as a bot user.
- Handshake requires `zone_dir`; the connector stores Gateway resume state in `discord_gateway_state.json` and a singleton-writer lease in `discord_gateway_lease.json`.
- Gateway lease TTL is `120 seconds`; the connector renews it every `30 seconds`.
- Handshake installs a bound `CapabilityVerifier`.
- `invoke` verifies bound capability tokens against the requested operation and resource URIs such as `discord:channel:<id>` and `discord:guild:<id>`.
- `simulate` is stricter than legacy connectors: it checks readiness, operation support, input validation, and bound capability verification.
- `health`, `doctor`, and `self_check` call Discord when configured, so invalid or revoked bot credentials surface through diagnostics.
- `subscribe` currently confirms requested topics and reports no replay support; event delivery comes from the Gateway task once handshake has started streaming.

## Known Contract Gaps

The runtime, manifest, and introspection metadata are not fully aligned in this checkout:

- `manifest.toml` declares operation tables as `send_message`, `edit_message`, and similar unprefixed names, while runtime introspection and invocation use fully qualified IDs such as `discord.send_message`.
- `manifest.toml` marks `send_message`, `edit_message`, and `create_thread` as policy-approved and `delete_message` as interactive, but runtime `OperationInfo` currently sets `requires_approval` to `None` for every operation.
- `manifest.toml` declares event topics including `discord.message_update`, `discord.message_delete`, `discord.typing`, `discord.guild_create`, and `discord.ready`; runtime introspection advertises only `discord.message`.
- The Gateway event mapper can emit additional `discord.*` topics, including update/delete/guild/channel/interaction variants, but the formal introspection event list has not caught up.
- `subscribe` does not validate requested topic names against the introspection or manifest event catalogs.
- Runtime allows loopback endpoints for deterministic tests in debug/test builds, while the manifest network constraints remain production-strict.
- Hidden non-final delivery suppression exists for `discord.send_message`, but no manifest policy describes that delivery-control extension.

Operators should treat this README as the current truthfulness snapshot. A follow-up should align manifest operation IDs, approval metadata, event introspection, and subscription validation before this connector is described as fully contract-aligned.

## First-Slice Scope

The current Discord README slice documents the existing runtime surface:

- bot-token configuration and live token probe
- REST API v10 endpoint policy
- Gateway discovery, resume-state persistence, and singleton-writer lease fencing
- required Gateway intents
- inbound policy and outbound chat-coordination controls
- message send/edit/delete
- channel and guild reads
- typing indicators
- reactions
- guild channel listing
- thread creation from an existing message
- lifecycle, doctor, health, self-check, introspection, simulation, subscription, and shutdown surfaces
- deterministic WireMock and loopback Gateway tests

## Auth And Scope Boundary

- Authentication mechanism: Discord bot token from the Discord Developer Portal.
- OAuth authorization-code, user token, refresh token, and application-command installation flows are not implemented.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Capability surface:
  - `discord.send` gates message send and typing indicator operations.
  - `discord.edit` gates message edits.
  - `discord.delete` gates message deletion.
  - `discord.read` gates channel, guild, and guild-channel reads.
  - `discord.react` gates adding reactions.
  - `discord.threads` gates thread creation.
- The connector persists Gateway resume and lease state under the handshake `zone_dir`.
- The connector does not persist Discord message bodies, channel names, guild names, user names, bot credentials, provider payloads, or provider error bodies beyond in-memory request handling and normal host-managed logs.

## Network And Runtime Invariants

- Production REST host: `discord.com`.
- Production REST API prefix: `/api/v10`.
- Production Gateway host: `gateway.discord.gg`, or a Discord-provided resume Gateway URL.
- Production port: `443`.
- TLS and SNI are required for live traffic.
- Runtime endpoint validation rejects empty URLs, bad schemes, public `http` or `ws`, userinfo, query strings, and fragments.
- Runtime host policy allows `discord.com`, subdomains of `discord.com`, `discord.gg`, and subdomains of `discord.gg`.
- Runtime loopback overrides are test/debug only.
- Manifest network policy denies localhost, private ranges, tailnet ranges, and IP literals for live operations.
- Runtime request timeout defaults to `30 seconds`.
- Manifest network constraints set `10_000 ms` connect timeout and `30_000 ms` total timeout.
- Maximum manifest response bytes are `1_048_576` for REST operations and `65_536` for Gateway events.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open network listeners.

## Inbound Policy

`inbound_policy` is optional. The default policy:

- requires a bot mention for guild messages
- allows DMs
- does not restrict guild IDs, channel IDs, or user IDs

Configurable fields:

- `require_mention_in_guilds`
- `require_mention` as an alias for `require_mention_in_guilds`
- `allow_dms`
- `allowed_guilds`
- `allowed_channels`
- `allowed_users`

The policy parser accepts stable Discord snowflake IDs, selected `discord:*` prefixes, and Discord mention forms for users and channels. It rejects non-stable IDs.

## Outbound Coordination

`chat_coordination` is optional and defaults to the in-memory backend. The parser supports:

- `enabled`
- `ttl_seconds`
- `fail_open`
- `allowlist_channels`
- `backend` values `in_memory`, `agent_mail`, and `mesh_gossip`
- `dm_mode`

`discord.send_message` calls the coordination layer before visible/final sends and includes coordination audit records in the response. Hidden non-final progress/tool delivery can be suppressed before a Discord REST send and returns a delivery receipt instead.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `discord.send_message` | `POST /channels/{channel_id}/messages` | `discord.send` | `Risky` | `Medium` | `None` | Creates provider-visible message state and may notify users. |
| `discord.edit_message` | `PATCH /channels/{channel_id}/messages/{message_id}` | `discord.edit` | `Risky` | `Medium` | `Strict` | Edits bot-owned provider-visible message state. |
| `discord.delete_message` | `DELETE /channels/{channel_id}/messages/{message_id}` | `discord.delete` | `Dangerous` | `High` | `Strict` | Deletes Discord message state. |
| `discord.get_channel` | `GET /channels/{channel_id}` | `discord.read` | `Safe` | `Low` | `Strict` | Reads metadata for one channel visible to the bot. |
| `discord.get_guild` | `GET /guilds/{guild_id}` | `discord.read` | `Safe` | `Low` | `Strict` | Reads metadata for one guild visible to the bot. |
| `discord.trigger_typing` | `POST /channels/{channel_id}/typing` | `discord.send` | `Safe` | `Low` | `None` | Shows a short-lived typing indicator. |
| `discord.add_reaction` | `PUT /channels/{channel_id}/messages/{message_id}/reactions/{emoji}/@me` | `discord.react` | `Safe` | `Low` | `Strict` | Adds the bot's reaction to an existing message. |
| `discord.list_channels` | `GET /guilds/{guild_id}/channels` | `discord.read` | `Safe` | `Low` | `Strict` | Lists channels in one guild visible to the bot. |
| `discord.create_thread` | `POST /channels/{channel_id}/messages/{message_id}/threads` | `discord.threads` | `Risky` | `Medium` | `None` | Creates provider-visible thread state from an existing message. |

## Explicit Non-Goals

The current implementation does not include:

- OAuth user authorization, token refresh, application install automation, or application-command registration
- slash-command response orchestration beyond inbound Gateway event mapping
- message attachments, file upload, file download, media proxying, or CDN access
- bulk delete, pin/unpin, crosspost, webhooks, polls, scheduled events, invites, roles, members, bans, moderation, or guild administration
- voice, presence management, rich presence, activities, or stage channels
- direct REST APIs for channel creation/update/delete, guild creation/update/delete, or thread listing
- replayable event subscriptions
- provider-local credential vaulting

These are excluded on purpose:

- Runtime invocation is capability-token bound and should expose only narrow bot actions.
- Message deletion and thread creation affect shared chat state and must remain explicit operations.
- Broader Discord coverage needs separate operation contracts, permission modeling, event schemas, and provider fixtures.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, `handle_introspect()`, `handle_subscribe()`, and `handle_shutdown()` are part of the public closeout contract. They surface:

- configuration, handshake, Gateway connection, request, and error state
- token presence and live token validity through `/users/@me`
- bot-account validation
- required Gateway intent validation
- REST and Gateway endpoint readiness
- redacted inbound policy status
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- bound capability-token simulation results
- streaming capability with replay disabled
- Gateway lease and resume-state teardown on shutdown

The deterministic integration evidence is anchored on connector-local tests covering:

- configure, handshake, health, doctor, self-check, introspection, simulation, subscribe, and shutdown behavior
- REST auth header propagation and token redaction in logs
- message send/edit/delete, channel reads, guild reads, typing, reactions, guild channel listing, and thread creation
- bound capability-token verification and denial cases
- input validation for snowflake IDs, message length, embed count, embed character totals, delivery controls, and thread-name bounds
- endpoint URL policy rejection for userinfo, query strings, fragments, bad schemes, public plaintext, and non-Discord hosts
- Gateway state files, lease fencing, inbound-policy filtering, event envelope mapping, and loopback Gateway behavior

## Source Notes

- `connectors/discord/src/connector.rs` defines configuration lifecycle, inbound policy, outbound coordination, capability-token verification, lifecycle handlers, diagnostics, simulation, introspection metadata, subscription handling, Gateway task management, and invoke dispatch.
- `connectors/discord/src/api.rs` defines Discord REST request construction, auth headers, REST endpoint paths, timeout/retry dispatch, rate-limit parsing, and provider error parsing.
- `connectors/discord/src/gateway.rs` defines Gateway connect/resume behavior, heartbeat handling, Gateway event decoding, and `discord_gateway_state.json`.
- `connectors/discord/src/config.rs` defines bot credential, endpoint, timeout, retry, intent, shard, and identify-concurrency configuration.
- `connectors/discord/src/limits.rs` defines Discord payload limits used before REST dispatch.
- `connectors/discord/src/types.rs` defines REST and Gateway payload models.
- `connectors/discord/manifest.toml` defines the operation catalog, event catalog, network constraints, streaming constraints, sandbox boundary, zone policy, rate limits, and AI hints.
- `connectors/discord/tests/integration.rs` covers deterministic HTTP behavior, capability enforcement, Gateway loopback behavior, and handler lifecycle behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/discord_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation contract tests
- deterministic WireMock coverage for REST operations
- Gateway loopback and inbound-policy tests
- auth, endpoint policy, input validation, provider error, lifecycle, introspection, simulation, subscription, and shutdown tests
- formatting, check, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use a dedicated Discord application and bot token for verification.
- Enable the required Gateway intents for the bot before running Gateway tests.
- Install the bot only into disposable test guilds for live verification.
- Prefer WireMock and loopback Gateway fixtures for routine proof.

**Dedicated environment**:

- Keep live message sends confined to disposable channels.
- Never run delete-message checks against production Discord history.
- Use synthetic channel IDs, guild IDs, message IDs, thread names, and message content in logs and transcripts.

**Redaction rules**:

- Redact bot tokens, session IDs, Gateway resume URLs when sensitive, guild IDs, channel IDs, user IDs, message IDs, message bodies, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, and synthetic Discord resource identifiers.

**Common remediation**:

- If configuration fails, provide a non-empty bot token and confirm `/users/@me` succeeds for that bot.
- If configuration reports missing intents, enable `GUILDS`, `GUILD_MESSAGES`, `DIRECT_MESSAGES`, and `MESSAGE_CONTENT` or supply the correct bitmask.
- If endpoint policy fails, use `https://discord.com/api/v10` for REST and let the connector discover the Gateway URL.
- If handshake fails, provide `zone_dir` so Gateway resume state and the singleton lease can be persisted.
- If invocation fails with capability errors, mint a bound token for the exact operation ID and resource URI.
- If guild events do not arrive, check the inbound policy before assuming Gateway delivery failed.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-discord-readme cargo check -p fcp-discord --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-discord-readme cargo test -p fcp-discord --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-discord-readme cargo clippy -p fcp-discord --all-targets --no-deps -- -D warnings`
- `ubs connectors/discord/README.md`
