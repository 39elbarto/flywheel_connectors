# Nextcloud Talk Connector V3 Contract

> **Status**: runtime contract documented; manifest/runtime drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Nextcloud Talk API docs**: https://nextcloud-talk.readthedocs.io/
> **Conversation API**: https://nextcloud-talk.readthedocs.io/en/stable/conversation/
> **Chat API**: https://nextcloud-talk.readthedocs.io/en/stable/chat/
> **Bots and webhooks**: https://nextcloud-talk.readthedocs.io/en/latest/bots/

## Purpose

This document fixes the operator-facing contract for `fcp.nextcloud-talk`. The connector currently targets the Nextcloud Talk OCS surfaces implemented in this crate: server capability probing, conversations, chat history, polling, host-forwarded bot webhooks, message sending, message deletion, read markers, participants, call state, reactions, and file sharing into rooms.

The connector is intentionally a bounded Nextcloud Talk collaboration bridge. It is not a full Nextcloud Files client, federation gateway, call signaling client, WebRTC media stack, bot installer, inbound HTTP server, push notification service, general OCS proxy, or Nextcloud administration client.

## Current Runtime Snapshot

The current crate exposes these operations:

- `nextcloud_talk.health`
- `nextcloud_talk.list_conversations`
- `nextcloud_talk.get_conversation`
- `nextcloud_talk.create_conversation`
- `nextcloud_talk.get_messages`
- `nextcloud_talk.poll_conversation_events`
- `nextcloud_talk.ingest_webhook`
- `nextcloud_talk.send_message`
- `nextcloud_talk.delete_message`
- `nextcloud_talk.set_read_marker`
- `nextcloud_talk.list_participants`
- `nextcloud_talk.add_participant`
- `nextcloud_talk.remove_participant`
- `nextcloud_talk.get_call_state`
- `nextcloud_talk.add_reaction`
- `nextcloud_talk.delete_reaction`
- `nextcloud_talk.share_file`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-nextcloud-talk`.
- Runtime `BaseConnector` ID is `fcp.nextcloud-talk`.
- Manifest and reported connector ID are `fcp.nextcloud-talk`.
- Manifest format is `native`.
- Manifest interface hash is `blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000`.
- Manifest state model is `stateless`; runtime keeps client/config/replay/rate state in process memory.
- Configuration requires `server_url` and `auth`.
- `server_url` must be absolute HTTP or HTTPS and must not include a query string or fragment.
- `request_timeout_ms` defaults to `30000` and must be greater than zero.
- `long_poll_timeout_secs` defaults to `30` and must be between `1` and `60`.
- `account_id` defaults to `default`.
- The client trims trailing slashes from `server_url`.
- Runtime sends `OCS-APIRequest: true`, `Accept: application/json`, and user agent `fcp-nextcloud-talk/0.1.0`.
- Runtime always appends `format=json` and optional `forceLanguage` to OCS requests.
- Runtime uses form-encoded bodies for Talk write operations.
- Runtime request timeout comes from `request_timeout_ms`.
- Runtime retry policy comes from the configured `retry` object.
- Runtime verifies bound capability tokens after handshake for both `simulate` and `invoke`.
- Runtime `subscribe` and `unsubscribe` return streaming-not-supported errors.
- Runtime introspection returns operations plus one webhook event, `nextcloud_talk.webhook.message`.
- `self_check()` performs a live Nextcloud capabilities probe and fails if Talk capabilities are absent.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest and runtime operation catalogs are closely aligned, but the interface hash is still the all-zero placeholder.
- Manifest has no hardcoded host constraints. Runtime applies configurable public/private/tailnet URL policy at configure and doctor time.
- Runtime `handshake()` can install the verifier before configure; later invoke still requires runtime, client, and config to exist.
- `health()` reports ready when a client exists and does not require a completed capability-verifier handshake.
- `doctor()` is non-networked and can report capability verifier as a non-critical missing check.
- `self_check()` is networked and depends on the configured server exposing Talk capabilities.
- Webhook `credential_id` secret references can pass configuration readiness, but `nextcloud_talk.ingest_webhook` currently requires inline bot secret material for local HMAC verification.
- Webhook replay and rate-limit state are in memory only; no persistent replay store is configured.
- Outbound `send_message` uses chat coordination before posting, with an in-memory coordination backend by default.
- Manifest rate-limit intent is absent; runtime has webhook-specific in-memory rate checks but no general OCS operation rate limiter.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should replace the placeholder interface hash, clarify whether handshake should require configuration, add host secret injection for webhook verification, decide whether replay storage should be durable, add broader operation rate limiting where desired, and add a tracked verification bundle.

## First-Slice Scope

The current Nextcloud Talk README slice documents the existing runtime surface:

- OCS auth modes and self-hosted server URL policy
- live health probing through Nextcloud capabilities
- conversation, chat, polling, participant, call, reaction, and file-share operations
- host-forwarded webhook verification and inbound policy
- bound capability-token enforcement and simulation behavior
- deterministic HTTP/webhook tests and direct proof commands

## Auth And Scope Boundary

- OCS authentication mechanisms:
  - `basic` with username and password
  - `app_password` with username and app password
  - `bearer_token` with access token
  - `credential_id` for host-managed credential injection
- Webhook bot secret sources:
  - inline secret material
  - credential ID reference, accepted by config but not usable for local ingest HMAC verification yet
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:project:*`.
- Allowed target zones: `z:work` and `z:project:*`.
- Runtime capability surface:
  - `nextcloud_talk.read` gates health, conversations, messages, polling, participants, and call state.
  - `nextcloud_talk.write` gates send, read-marker, reaction, and file-share operations.
  - `nextcloud_talk.manage` gates conversation creation, message deletion, and participant mutation.
  - `nextcloud_talk.webhook` gates host-forwarded webhook ingestion.
- Runtime verifies bound capability tokens against the requested operation after handshake.
- The connector does not persist OCS credentials, webhook secrets, chat messages, participant lists, file-share responses, provider error bodies, or webhook event payloads outside process memory.
- Nextcloud Talk room data can include private messages, links, files, participant identity, and call presence. Treat live output as work-zone or project-zone data based on the configured server and room policy.

## Network And Runtime Invariants

- Runtime capability probe: `GET /ocs/v1.php/cloud/capabilities`.
- Conversation endpoints use `/ocs/v2.php/apps/spreed/api/v4/room`.
- Chat endpoints use `/ocs/v2.php/apps/spreed/api/v1/chat/{token}`.
- Participant endpoints use `/ocs/v2.php/apps/spreed/api/v4/room/{token}/participants` and `/attendees`.
- Call state uses `/ocs/v2.php/apps/spreed/api/v4/call/{token}`.
- Reaction endpoints use `/ocs/v2.php/apps/spreed/api/v1/reaction/{token}/{messageId}`.
- File sharing uses `/ocs/v2.php/apps/files_sharing/api/v1/shares` with share type `10` and `shareWith` set to the room token.
- Runtime accepts public hosts by default.
- Runtime rejects localhost, private, internal-name, and tailnet hosts unless `network.allow_private_networks` or `network.allow_tailnet_networks` is explicitly enabled.
- `network.allowed_hosts` may restrict public hosts by exact or wildcard host pattern.
- Runtime follows the configured request timeout and retry policy.
- Runtime decodes OCS envelopes and requires `ocs.meta.status` to be `ok`.
- Runtime treats chat 304 responses as no-change pages with cursor headers.
- Provider HTTP 401, 403, 404, 409, 412, 413, 429, 5xx, and OCS errors map to typed connector/FCP errors.
- `Retry-After` on 429 is converted to milliseconds; missing values default to 5000 ms.
- Sandbox profile is `strict`, with `64 MB` memory, `25%` CPU, no exec, and no inbound listener capability.
- The connector does not open inbound sockets, run a Nextcloud bot listener, or host a webhook endpoint inside the connector.

## Webhook Ingress Contract

`nextcloud_talk.ingest_webhook` is a host-forwarded ingress boundary:

- The host must receive the HTTP request and forward raw headers plus raw body to the connector.
- Required headers are `X-Nextcloud-Talk-Signature`, `X-Nextcloud-Talk-Random`, and `X-Nextcloud-Talk-Backend`.
- Backend URL is normalized and checked against `webhook.backend_allowlist`; if no explicit allowlist is set, the configured `server_url` is used.
- HMAC verification uses SHA-256 over `random + raw_body` with the bot secret.
- Presented signatures may include or omit a `sha256=` prefix.
- Comparison is constant-time over the normalized hex digest.
- `webhook.max_body_bytes` defaults to `1048576`.
- `webhook.body_timeout_ms` defaults to `5000`.
- `webhook.auth_failure_limit_per_minute` defaults to `10`.
- `webhook.sender_limit_per_minute` defaults to `60`.
- `webhook.replay_ttl_secs` defaults to `86400`.
- `webhook.replay_max_entries` defaults to `1000`.
- Replay keys are `(account_id, room_token, message_id)` and are kept in memory.
- Non-`Create` ActivityStreams payloads are accepted as verified but ignored.
- Duplicate and in-flight replay decisions return no fresh event.
- Retryable dispatch outcomes release the replay claim; committed or ignored paths commit it.

Inbound policy defaults are deliberately conservative:

- `dm_policy` defaults to `pairing`.
- `group_policy` defaults to `allowlist`.
- `allow_from`, `group_allow_from`, `rooms`, `disabled_rooms`, and `mention_required_rooms` are explicit pattern lists.
- Opening direct messages requires an explicit wildcard in `allow_from`.
- Opening group messages requires an explicit wildcard in `group_allow_from`.
- Group messages require mention checks by default when the host indicates a group message, unless `require_mention` or policy room lists say otherwise.
- Slash-command-looking messages require the host-forwarded `command_authorized` flag.

## Chat Coordination

`nextcloud_talk.send_message` performs a chat-coordination claim before posting:

- The default coordination backend is in-memory.
- Optional `chat_coordination` config can set `enabled`, `ttl_seconds`, `fail_open`, `allowlist_channels`, `backend`, and `dm_mode`.
- Supported backends are `in_memory`, `agent_mail`, and `mesh_gossip`.
- Supported DM modes are `skip` and `treat_as_thread`.
- The room token is normalized to a lowercase channel ID for coordination.
- Reply messages use `reply_to:{message_id}` as the thread ID.
- The output includes coordination audit records alongside the posted message.

This is a duplicate-send guardrail, not a substitute for capability-token or approval policy.

## Operation Inventory

| Operation | Upstream shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `nextcloud_talk.health` | `GET /cloud/capabilities` | `nextcloud_talk.read` | `Safe` | `Low` | `Strict` | none |
| `nextcloud_talk.list_conversations` | `GET /room` | `nextcloud_talk.read` | `Safe` | `Low` | `Strict` | optional `include_status`, `modified_since` |
| `nextcloud_talk.get_conversation` | `GET /room/{token}` | `nextcloud_talk.read` | `Safe` | `Low` | `Strict` | `token` |
| `nextcloud_talk.create_conversation` | `POST /room` | `nextcloud_talk.manage` | `Risky` | `Medium` | `None` | `room_type` |
| `nextcloud_talk.get_messages` | `GET /chat/{token}` | `nextcloud_talk.read` | `Safe` | `Low` | `Strict` | `token` |
| `nextcloud_talk.poll_conversation_events` | `GET /chat/{token}` | `nextcloud_talk.read` | `Safe` | `Low` | `Strict` | `token` |
| `nextcloud_talk.ingest_webhook` | host-forwarded raw webhook | `nextcloud_talk.webhook` | `Risky` | `Medium` | `Strict` | `headers`, `body` |
| `nextcloud_talk.send_message` | `POST /chat/{token}` | `nextcloud_talk.write` | `Risky` | `Medium` | `None` | `token`, `message` |
| `nextcloud_talk.delete_message` | `DELETE /chat/{token}/{message_id}` | `nextcloud_talk.manage` | `Dangerous` | `High` | `Strict` | `token`, `message_id` |
| `nextcloud_talk.set_read_marker` | `POST /chat/{token}/read` | `nextcloud_talk.write` | `Safe` | `Low` | `Strict` | `token` |
| `nextcloud_talk.list_participants` | `GET /room/{token}/participants` | `nextcloud_talk.read` | `Safe` | `Low` | `Strict` | `token` |
| `nextcloud_talk.add_participant` | `POST /room/{token}/participants` | `nextcloud_talk.manage` | `Risky` | `Medium` | `None` | `token`, `new_participant` |
| `nextcloud_talk.remove_participant` | `DELETE /room/{token}/attendees` | `nextcloud_talk.manage` | `Risky` | `High` | `Strict` | `token`, `attendee_id` |
| `nextcloud_talk.get_call_state` | `GET /call/{token}` | `nextcloud_talk.read` | `Safe` | `Low` | `Strict` | `token` |
| `nextcloud_talk.add_reaction` | `POST /reaction/{token}/{message_id}` | `nextcloud_talk.write` | `Safe` | `Low` | `Strict` | `token`, `message_id`, `reaction` |
| `nextcloud_talk.delete_reaction` | `DELETE /reaction/{token}/{message_id}` | `nextcloud_talk.write` | `Safe` | `Low` | `Strict` | `token`, `message_id`, `reaction` |
| `nextcloud_talk.share_file` | `POST /files_sharing/api/v1/shares` | `nextcloud_talk.write` | `Risky` | `Medium` | `None` | `token`, `path` |

## Explicit Non-Goals

The current implementation does not include:

- Nextcloud bot installation, `occ` automation, bot management API calls, or hosted webhook listener setup
- WebRTC signaling, media relay, TURN/STUN configuration, call recording, call invites, or live media controls
- persistent webhook replay storage, durable polling cursor storage, push notification integration, or server-sent event streams
- Nextcloud Files browsing outside file-share-to-room support
- message editing, conversation renaming, favorites, lobby, moderation roles, breakout rooms, polls, avatars, settings, or federation administration
- OAuth installation, app-password provisioning, token refresh, secret rotation, or credential validation beyond local configuration shape
- raw OCS proxy access or arbitrary Nextcloud app administration

These are excluded on purpose:

- Talk rooms can contain private or project-confidential collaboration data and need narrow capability gates.
- Bot webhook ingestion must remain host-forwarded until the host-level listener and secret handling policy is explicit.
- Message deletion, participant mutation, and file sharing are side-effect boundaries and need review proportional to room policy.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, and `nextcloud_talk.health` are part of the public closeout contract. They surface:

- local configuration, client, runtime, server URL policy, account label, auth mode, webhook readiness, inbound policy, and capability-verifier state
- live capabilities probe through `self_check()` and `nextcloud_talk.health`
- operation and event metadata with capability, risk, safety tier, idempotency, schemas, and hints
- simulation allow/deny based on configured client/runtime, completed handshake, and bound capability-token verification
- typed provider/FCP error mapping
- redacted secret source labels and webhook secret fingerprints

The deterministic integration evidence is anchored on connector-local tests covering:

- configuration parsing, URL policy, auth modes, retry config, doctor, health, self-check, introspection, simulation, and capability-token denial
- OCS client endpoints for conversations, chat, participants, call state, reactions, and file sharing through deterministic HTTP fixtures
- 304 chat cursor behavior, OCS envelope decoding, provider error mapping, retry behavior, and request header/form behavior
- webhook signature verification, backend allowlist, missing headers, bad signatures, replay duplicate/in-flight behavior, body limits, timeout limits, malformed payloads, inbound policy, rate limits, and no secret leakage in doctor output
- chat coordination claim behavior for outbound `send_message`

## Source Notes

- `connectors/nextcloud-talk/src/connector.rs` defines lifecycle handlers, diagnostics, operation catalog, capability-token checks, webhook verification, inbound policy, chat coordination, and invoke dispatch.
- `connectors/nextcloud-talk/src/config.rs` defines auth modes, webhook config, inbound policy, URL policy, defaults, and validation.
- `connectors/nextcloud-talk/src/client.rs` defines OCS endpoint paths, auth headers, request formatting, retry dispatch, timeout behavior, response decoding, and provider error handling.
- `connectors/nextcloud-talk/src/types.rs` defines conversation, chat, participant, call, reaction, file-share, webhook, and OCS envelope shapes.
- `connectors/nextcloud-talk/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/nextcloud-talk/manifest.toml` defines the manifest operation catalog, sandbox boundary, zone policy, and operation metadata.
- `connectors/nextcloud-talk/tests/integration.rs` and inline module tests contain the runtime contract proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/nextcloud-talk/README.md
ubs connectors/nextcloud-talk/README.md
LC_ALL=C rg -n '[^ -~]' connectors/nextcloud-talk/README.md
rg -n '\bmaster\b' connectors/nextcloud-talk/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-nextcloud-talk
rch exec -- cargo check -p fcp-nextcloud-talk --all-targets
rch exec -- cargo clippy -p fcp-nextcloud-talk --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Prefer app-password or host credential-reference auth over basic account-password auth.
- Keep `server_url` pointed at the Nextcloud instance root, not a pre-expanded OCS API path.
- Explicitly enable private or tailnet hosts only for trusted self-hosted deployments.
- Use `nextcloud_talk.health` or `self_check()` before room operations because Talk may be absent even when Nextcloud itself is reachable.
- Treat webhook mode as host-forwarded; this connector does not listen on `webhook.public_path` itself.
- Use inline webhook bot secrets only where local HMAC verification is acceptable, and plan host secret injection before relying on credential-ID bot secrets.
- Keep room and sender allowlists explicit before enabling open inbound policies.
