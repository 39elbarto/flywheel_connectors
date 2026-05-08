# iMessage Connector V3 Contract

> **Status**: runtime contract documented; shared-runtime/manifest/upstream drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **BlueBubbles server upstream**: https://docs.bluebubbles.app/server
> **BlueBubbles REST and webhooks upstream**: https://docs.bluebubbles.app/server/developer-guides/rest-api-and-webhooks
> **BlueBubbles Private API upstream**: https://docs.bluebubbles.app/private-api
> **BlueBubbles Private API setup upstream**: https://docs.bluebubbles.app/private-api/installation

## Purpose

This document fixes the operator-facing contract for `fcp.imessage`. The connector exposes the iMessage-through-BlueBubbles surface currently implemented in this crate: message send, local media send, chat and message reads, target resolution, selected Private API actions, attachment download, webhook registration, host-forwarded webhook ingress, normalized event streaming, local health, and server-info probing.

The connector is intentionally a bounded iMessage bridge through a self-hosted BlueBubbles server on a Mac signed into iMessage. It is not a native Apple Messages framework client, Apple ID login flow, BlueBubbles server installer, phone-number registration tool, full BlueBubbles client, durable message archive, generic local Contacts exporter, or arbitrary macOS automation surface.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `imessage.send_message`
- `imessage.send_media`
- `imessage.resolve_send_target`
- `imessage.create_chat`
- `imessage.get_action_availability`
- `imessage.edit_message`
- `imessage.unsend_message`
- `imessage.send_reaction`
- `imessage.set_typing`
- `imessage.get_chats`
- `imessage.get_chat`
- `imessage.get_messages`
- `imessage.sync_events`
- `imessage.download_attachment`
- `imessage.mark_read`
- `imessage.register_webhook`
- `imessage.list_webhooks`
- `imessage.unregister_webhook`
- `imessage.ingest_webhook_event`
- `imessage.ingest_webhook_request`
- `imessage.get_server_info`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-imessage`.
- Manifest ID is `fcp.imessage`.
- `BlueBubblesConnector::new()` uses runtime connector ID `fcp.imessage` and the iMessage manifest.
- The same shared `BlueBubblesConnector` implementation is reused by the dedicated `fcp.bluebubbles` wrapper.
- Manifest version is `0.1.0`.
- Manifest format table uses `[format]` with schema version `2.1`.
- The binary is a newline-delimited JSON-RPC style stdio loop with methods `configure`, `handshake`, `health`, `doctor`, `self_check`, `introspect`, `invoke`, `simulate`, `subscribe`, `unsubscribe`, and `shutdown`.
- Configuration requires `password`, mapped to the BlueBubbles server passcode.
- Configuration accepts `server_url`, `poll_interval_ms`, `attachment_dir`, `media_send`, `retry`, `request_timeout_ms`, `webhook_host`, `webhook_port`, `webhook_path`, `webhook_account_id`, `webhook_inbound`, `webhook_coalescing`, `reply_context_api_fallback`, and `contacts_enrichment`.
- `server_url` defaults to `http://localhost:1234` and is trimmed of a trailing slash.
- `request_timeout_ms` defaults to `30000`.
- `poll_interval_ms` defaults to `5000`, must be greater than zero, and is part of configuration state even though the current streaming path is webhook-backed rather than timer-backed.
- Outbound media is disabled until `media_send.local_roots` contains absolute local roots.
- `media_send` defaults to a 25 MiB file cap, `application/pdf`, `text/plain`, `audio/`, `image/`, and `video/`, with a 60000 ms upload timeout.
- Webhook callback construction defaults to `http://localhost:8645/bluebubbles-webhook?password=<server-passcode>`.
- Default webhook registration events are `new-message` and `updated-message`.
- Webhook event caps advertise streaming and replay with a minimum buffer of 64 events.
- Runtime stores inbound webhook replay dedupe in memory unless `webhook_inbound.dedupe_state_path` is configured.
- Runtime event buffers, reply-context cache, contacts enrichment cache, dedupe store, and coalescing buffers are connector-local process state.
- `health()` reports local configured state and uptime. It does not call the BlueBubbles server.
- `doctor()` checks local configuration, client initialization, runtime initialization, server URL scheme, localhost posture, password presence, inbound policy, dedupe, coalescing, reply-context fallback, and contacts enrichment posture. It does not call the BlueBubbles server.
- `self_check()` calls the live BlueBubbles server-info endpoint.
- `handshake()` honors `requested_instance_id`, installs a `CapabilityVerifier`, hashes the checked-in manifest, grants every requested capability, and reports webhook event caps.
- `invoke()` requires configured and handshaken state, maps the operation to a required capability, and verifies a bound capability token before dispatch.
- Capability verification currently passes an empty resource URI list for all operations.
- `simulate()` validates known operation, configured state, handshake state, and bound capability token. It does not validate full input schema, provider reachability, BlueBubbles server state, or Private API availability.
- `subscribe()` and `unsubscribe()` operate on the in-memory webhook event stream manager.
- `shutdown()` drains pending coalescing buffers and shuts down the runtime. It does not clear connector configuration, verifier, configured state, or handshaken state.

## Runtime API Adapter

The runtime uses these BlueBubbles request shapes:

| Operation | Capability | Required input | Runtime behavior |
|-----------|------------|----------------|------------------|
| `imessage.send_message` | `imessage.send` | `chat_guid`, `message` | POST `/api/v1/message/text`; selects AppleScript or Private API from server info; reply/effect fields fail closed when Private API cannot be proven available. |
| `imessage.send_media` | `imessage.send` | `local_path` plus exactly one target | Resolves the target, canonicalizes a local file under `media_send.local_roots`, validates size and MIME, and POSTs multipart to `/api/v1/message/attachment`. |
| `imessage.resolve_send_target` | `imessage.read` | exactly one target | Resolves `chat_guid`, `chat_id`, `chat_identifier`, or `handle` into a chat GUID without sending. |
| `imessage.create_chat` | `imessage.send` | `address`, `message` | Sends the first DM message through `/api/v1/chat/new`; requires known enabled Private API support. |
| `imessage.get_action_availability` | `imessage.admin` | none | Reads server info and returns deterministic availability for edit, unsend, reactions, typing, and read receipts. |
| `imessage.edit_message` | `imessage.send` | `message_guid`, `new_text` | POSTs `/api/v1/message/{guid}/edit`; requires known enabled Private API and fails closed on unsupported macOS. |
| `imessage.unsend_message` | `imessage.send` | `message_guid` | POSTs `/api/v1/message/{guid}/unsend`; requires known enabled Private API. |
| `imessage.send_reaction` | `imessage.send` | `chat_guid`, `message_guid`, `reaction` | POSTs `/api/v1/message/react`; normalizes reactions to love, like, dislike, laugh, emphasize, or question. |
| `imessage.set_typing` | `imessage.send` | `chat_guid` | POSTs or DELETEs `/api/v1/chat/{guid}/typing`; requires known enabled Private API. |
| `imessage.get_chats` | `imessage.read` | none | GETs `/api/v1/chat` with optional `offset` and `limit`. |
| `imessage.get_chat` | `imessage.read` | `chat_guid` | GETs `/api/v1/chat/{guid}`. |
| `imessage.get_messages` | `imessage.read` | `chat_guid` | GETs `/api/v1/chat/{chat_guid}/message` with optional pagination and timestamp filters. |
| `imessage.sync_events` | `imessage.read` | none | Polls recent messages from one chat or a bounded chat scan and returns normalized event records plus `next_after`. |
| `imessage.download_attachment` | `imessage.read` | `attachment_guid` | GETs `/api/v1/attachment/{guid}/download` and returns base64 bytes. |
| `imessage.mark_read` | `imessage.send` | `chat_guid` | POSTs `/api/v1/chat/{chat_guid}/read`; requires action availability. |
| `imessage.register_webhook` | `imessage.admin` | none | Registers a callback URL with `/api/v1/webhook`, defaulting to the configured local callback URL and skipping duplicate URLs by default. |
| `imessage.list_webhooks` | `imessage.admin` | none | GETs `/api/v1/webhook`. |
| `imessage.unregister_webhook` | `imessage.admin` | `webhook_id` or `url` | Deletes one webhook ID or all matching callback URLs. |
| `imessage.ingest_webhook_event` | `imessage.read` | `payload` or `flush_coalescing` | Normalizes a host-delivered BlueBubbles event, applies sender/chat policy, replay dedupe, optional Contacts enrichment, optional reply-context fallback, optional DM coalescing, and EventEnvelope fan-out. |
| `imessage.ingest_webhook_request` | `imessage.read` | `method`, `url`, `body` | Validates host request-region metadata, method, route, callback auth, body bounds, and service-layer metadata before invoking the normalized webhook pipeline. |
| `imessage.get_server_info` | `imessage.admin` | none | GETs `/api/v1/server/info`. |

Target resolution details:

- `send_media` and `resolve_send_target` accept exactly one of `chat_guid`, `chat_id`, `chat_identifier`, or `handle`.
- `handle` may include `service` as `imessage`, `sms`, or `auto`.
- `scan_limit` defaults to 5000 and is clamped to the same maximum.
- Handle lookup preserves explicit SMS intent and never routes a handle to a group chat only because that handle is a participant.

Webhook ingress details:

- Host-forwarded webhook requests must use POST.
- Callback auth may be supplied as the `password` query parameter or the `x-bluebubbles-auth` header.
- Output redacts the callback password.
- Ingress rejects malformed URLs, wrong paths, missing or invalid auth, non-object bodies, over-limit bodies, cancelled request regions, and exceeded deadlines before event normalization.
- Accepted events are emitted to topics `imessage.message.inbound`, `imessage.message.outbound`, `imessage.message.updated`, or `imessage.message.tapback`.
- Event resource URIs include `bluebubbles:account:<account>`, `imessage:message:<event_id>`, and `imessage:chat:<chat_guid>` when available.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- This crate is named `imessage`, but the provider implementation is explicitly BlueBubbles-backed.
- The iMessage package and BlueBubbles wrapper share one implementation. Divergent behavior between them should be treated as a bug unless it is purely connector ID or manifest text.
- The manifest network constraints allow localhost and `127.0.0.1` on port 1234, but runtime `server_url` currently accepts any `http` or `https` host and only reports non-local hosts in `doctor()`.
- Upstream BlueBubbles REST docs describe `guid`, `password`, and `token` as authentication query aliases. Runtime provider calls use `password`.
- Upstream webhooks can emit more event kinds than the default FCP registration list. Runtime defaults registration to `new-message` and `updated-message` and normalizes to the four current FCP event topics.
- Upstream Private API docs describe broader features such as group changes, pinned chats, focus status, delete operations, and FaceTime status. Runtime implements only the operation list above.
- Private API setup can require local macOS security changes. Runtime does not install, repair, or verify that setup beyond server-info-derived availability gates.
- `attachment_dir` is parsed and normalized but current download behavior returns base64 bytes rather than writing attachments there.
- `health()` and `doctor()` are local readiness surfaces, while `self_check()` and `imessage.get_server_info` are live server probes.
- `simulate()` does not validate provider action availability, input schemas, webhook policy acceptance, media path existence, local file MIME type, or server reachability.
- Runtime capability verification does not bind chat GUIDs, message GUIDs, handles, webhook IDs, account IDs, media paths, or attachment GUIDs as resource URIs.
- `handshake()` grants every requested capability unfiltered.
- `shutdown()` drains coalescing buffers but keeps configured and handshaken state.
- No dedicated tracked verification shell script exists for this connector.

A follow-up parity bead should enforce manifest host/port policy in runtime configuration, bind capability tokens to conversation and message resources, make simulation validate schemas and local policy, clarify `attachment_dir`, decide whether additional upstream Private API or webhook event kinds belong in scope, and decide whether the BlueBubbles wrapper should continue exposing the same `imessage.*` operation surface.

## First-Slice Scope

The current iMessage README slice documents the existing runtime surface:

- Canonical `fcp.imessage` package over the shared BlueBubbles-backed runtime
- BlueBubbles server configuration, password handling, retry and timeout settings, media-send policy, webhook callback construction, and inbound policy
- Message sends, media sends, target resolution, chat/message reads, sync, attachment download, Private API action gates, selected Private API actions, webhook registration, and webhook ingestion
- Local health, doctor, live self-check, introspection, simulate, invoke, subscribe, unsubscribe, and shutdown behavior
- Capability-token verification and current empty resource-URI binding
- EventEnvelope topics, stream keys, replay dedupe, coalescing, reply-context fallback, Contacts enrichment, and callback-auth redaction
- Runtime/manifest/upstream drift around BlueBubbles dependency, localhost enforcement, broader upstream API coverage, simulation, shutdown, and missing resource binding

## Auth And Zone Boundary

- Authentication mechanism: BlueBubbles server passcode.
- Provider request auth: `password=<server-passcode>` query parameter on BlueBubbles REST calls.
- Webhook callback auth: `password=<server-passcode>` query parameter in the registered callback URL, or host-forwarded `x-bluebubbles-auth`.
- Home zone: `z:private`.
- Allowed source zone: `z:private`.
- Allowed target zone: `z:private`.
- Runtime capability families:
  - `imessage.send`
  - `imessage.read`
  - `imessage.admin`
- Manifest required capabilities are `network.dns` and `network.outbound`.
- Manifest forbids `system.privileged`.
- The connector does not intentionally persist BlueBubbles server passcodes, message bodies, contact names, attachments, chat metadata, request counters, or provider errors outside process memory unless webhook dedupe persistence is explicitly configured.
- Live iMessage and BlueBubbles payloads can contain private messages, phone numbers, emails, group names, attachment metadata and bytes, read status, tapbacks, local contact names, and server details. Treat live input and output as private-zone sensitive unless the host supplies a stricter zone policy.

## Explicit Non-Goals

- No BlueBubbles server installation, update, repair, or process management.
- No Apple ID login or phone-number registration.
- No direct `chat.db` reader or direct IMCore client in FCP.
- No general BlueBubbles remote proxy provisioning.
- No OAuth or credential-ID flow.
- No group rename, participant management, chat delete, message delete, pinned-chat, focus-status, or FaceTime-status operations.
- No arbitrary local file reads for media upload.
- No remote URL media upload.
- No durable message archive.
- No cross-zone message routing.
- No inbound socket listener inside this connector; the FCP host owns HTTP ingress and forwards request-region metadata.

## Source Notes

- `connectors/imessage/src/main.rs` defines the stdio JSON-RPC entrypoint for `fcp.imessage`.
- `connectors/imessage/src/connector.rs` defines the shared lifecycle, operation catalog, invoke dispatch, webhook pipeline, event stream, doctor, simulate, and capability checks.
- `connectors/imessage/src/client.rs` defines BlueBubbles REST paths, auth query use, retries, Private API action gates, target resolution, media upload, and provider error mapping.
- `connectors/imessage/src/types.rs` defines configuration, validation, webhook normalization, media policy, coalescing, reply-context fallback, and Contacts enrichment.
- `connectors/imessage/manifest.toml` defines the iMessage-branded manifest, private-zone policy, network constraints, operations, and event topics.
- Inline tests in `connectors/imessage/src/connector.rs` and `connectors/imessage/src/types.rs` cover manifest/runtime catalog alignment, schema shape, capability denial, target resolution, webhook ingress, coalescing, dedupe, reply-context fallback, Contacts enrichment, media-send bounds, and config validation.
- `connectors/bluebubbles/src/lib.rs` proves the same runtime can be wrapped with connector ID `fcp.bluebubbles`.
- `connectors/bluebubbles/tests/integration.rs` exercises the shared runtime through the dedicated BlueBubbles package.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/imessage/README.md
LC_ALL=C rg -n '[^ -~]' connectors/imessage/README.md
rg -n '\bmaster\b' connectors/imessage/README.md
ubs connectors/imessage/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
