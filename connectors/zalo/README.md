# Zalo Connector V1 Contract

> **Status**: experimental Bot API slice documented with webhook, polling, replay, rate, and capability drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Primary upstream**: https://developers.zalo.me/docs/api/official-account-api-14737
> **Official Account upstream**: https://oa.zalo.me/
> **Developer portal**: https://developers.zalo.me/

## Purpose

This document fixes the operator-facing contract for `fcp.zalo`. The current crate exposes an experimental Zalo bot surface: bot identity, outbound text/photo sends, long-poll update normalization, host-forwarded webhook ingest, webhook setup/inspection/deletion, local webhook token verification, replay/rate guards, media URL bounds, and default-deny inbound policy.

This connector is a bounded Zalo Bot API-shaped bridge. It is not a full Zalo Official Account management client, broadcast/content-management client, ad client, analytics client, personal-account automation runtime, Zalo Web scraper, or credential vault.

## Current Runtime Snapshot

The current crate exposes these operations:

- `zalo.messages.send`
- `zalo.messages.send_photo`
- `zalo.self.get_me`
- `zalo.updates.poll`
- `zalo.webhook.delete`
- `zalo.webhook.info`
- `zalo.webhook.ingest`
- `zalo.webhook.set`
- `zalo.webhook.verify`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-zalo`.
- Runtime and manifest connector ID are `fcp.zalo`.
- Manifest status is `experimental`.
- Configuration accepts `access_token`, `bot_token`, or `token`; the first non-empty value is used as the Bot API credential.
- Default API base URL is `https://bot-api.zaloplatforms.com`.
- Loopback `http://127.0.0.1:<port>` base URLs are accepted for deterministic tests.
- Live base URLs must be the default host with no extra path.
- Runtime builds provider paths as `/bot{token}/{method}` and sends POST requests.
- Runtime request timeout defaults to `30000 ms` and is capped at `120000 ms`.
- Long-poll timeout defaults to `30 seconds` and is capped at `55 seconds`.
- Message and caption-like text are truncated to `2000` Unicode scalar values.
- Default webhook path is `/zalo/webhook`.
- Webhook body size defaults to `64 KiB` and is capped at `1 MiB`.
- Media URL size policy defaults to `8 MiB` and is capped at `64 MiB`.
- Replay TTL defaults to `600 seconds`; replay cache defaults to `1024` entries and is capped at `16384`.
- Rate limiting defaults to `120` accepted inbound attempts per `60000 ms` window and is capped at `10000`.
- `health()` is local readiness state; it reports `ready` only when configured with a token.
- `self_check()` does not perform a live identity probe. It returns `ok` after configure, handshake, and token presence.
- `invoke` accepts either `operation_id` or `operation`.
- `zalo.webhook.verify` compares the supplied token against `webhook_verify_challenge` or `webhook_token` using a constant-time byte comparison.
- `zalo.webhook.ingest` validates a host-forwarded request; the connector does not open its own listener.
- Inbound events default-deny until `allowed_sender_ids`, `allowed_chat_ids`, `allowed_group_ids`, or `paired_sender_ids` is configured.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- The manifest declares capability gates, but connector-local `handle_invoke()` currently dispatches after readiness checks and does not verify a bound capability token before upstream calls.
- `handle_simulate()` checks `zone_id` and `target_instance`, but live `invoke` does not enforce those scope checks locally.
- `zalo.media` is advertised as a live capability, but there is no standalone `zalo.media.*` operation. Photo send is gated by `zalo.messages` in the manifest.
- `self_check()` proves configuration state, not upstream token validity.
- Provider paths are Bot API-shaped and tested against loopback fixtures; live Zalo behavior needs dedicated operator proof before production claims.
- There is no tracked connector verification shell script yet.

A follow-up parity bead should add bound capability-token enforcement to `invoke`, reconcile `zalo.media` with manifest operation gates, add a tracked proof bundle, and decide whether `self_check()` should call `getMe` in direct-token mode.

## First-Slice Scope

The current Zalo README slice documents the existing runtime surface:

- token-based Bot API configuration and loopback override rules
- bot identity, text send, photo send, long-poll updates, webhook management, host-forwarded webhook ingest, and local token verification
- public HTTPS validation for photo and webhook URLs
- inbound sender/chat/group allow policy, default-deny behavior, replay cache, rate windows, and event decisions
- doctor, health, self-check, introspection, simulate, shutdown, and deterministic loopback tests
- drift around local capability-token enforcement, self-check depth, media capability naming, and missing scripted verification

## Auth And Scope Boundary

- Authentication mechanism: Zalo Bot API token supplied as `access_token`, `bot_token`, or `token`.
- Runtime does not implement Zalo app creation, Official Account verification, OAuth token refresh, OA permission review, webhook endpoint hosting, personal-account login, QR login, cookie/session extraction, or connector-local credential storage.
- Home zone: `z:community`.
- Allowed source zones: `z:owner`, `z:work`, and `z:community`.
- Allowed target zone: `z:community`.
- Forbidden capabilities: `network.listen` and `system.exec`.
- Capability families:
  - `zalo.messages` gates text/photo sends and bot identity in the manifest.
  - `zalo.updates` gates long-poll update normalization.
  - `zalo.webhook` gates webhook setup, deletion, info, and local verify.
  - `zalo.events` gates host-forwarded webhook ingest.
  - `zalo.media` is advertised for media-aware behavior but has no standalone operation in this slice.
- Zalo user IDs, chat IDs, group IDs, bot IDs, sender names, message bodies, image URLs, webhook headers, tokens, replay keys, provider error bodies, and event payloads are sensitive operational data. Do not log them in shared artifacts without redaction.

## Network And Runtime Invariants

- Default production API host: `bot-api.zaloplatforms.com`.
- Live port: `443`.
- Provider request shape: `POST /bot{token}/{method}`.
- Runtime method names:
  - `getMe`
  - `sendMessage`
  - `sendPhoto`
  - `getUpdates`
  - `setWebhook`
  - `deleteWebhook`
  - `getWebhookInfo`
- `setWebhook` and `sendPhoto` require public HTTPS URLs with no embedded credentials or URL fragments.
- Public URL validation rejects localhost, private ranges, link-local, multicast, unspecified addresses, and IP literals where applicable.
- Host-forwarded webhook ingest requires `POST`, the configured path, JSON body, and `x-bot-api-secret-token`.
- The connector maps provider 429s to rate-limited errors with `Retry-After` support.
- The connector maps transport connect failures, timeouts, non-success provider envelopes, and JSON parse errors through `ZaloError`.
- Manifest sandbox profile is `strict`, with `96 MB` memory, `25%` CPU, `60000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `zalo.messages` | Bot identity plus outbound text and photo messages. |
| `zalo.updates` | Long-poll update retrieval and policy-gated normalization. |
| `zalo.webhook` | Webhook setup, deletion, info, and local secret-token verification. |
| `zalo.events` | Host-forwarded webhook validation and normalized inbound event delivery. |
| `zalo.media` | Advertised media capability for media-aware behavior; no standalone operation in this slice. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `zalo.messages.send` | `POST /bot{token}/sendMessage` | `zalo.messages` | `safe` | `medium` | `best_effort` | `recipient_id`, `message`; runtime also accepts `chat_id`. |
| `zalo.messages.send_photo` | `POST /bot{token}/sendPhoto` | `zalo.messages` | `safe` | `medium` | `best_effort` | `recipient_id`, `photo_url`; runtime also accepts `chat_id`, `photo`, optional `caption`. |
| `zalo.self.get_me` | `POST /bot{token}/getMe` | `zalo.messages` | `safe` | `low` | `strict` | None. |
| `zalo.updates.poll` | `POST /bot{token}/getUpdates` | `zalo.updates` | `safe` | `low` | `none` | Optional `timeout_seconds`/`timeout`, optional `offset`. |
| `zalo.webhook.delete` | `POST /bot{token}/deleteWebhook` | `zalo.webhook` | `safe` | `medium` | `best_effort` | None. |
| `zalo.webhook.info` | `POST /bot{token}/getWebhookInfo` | `zalo.webhook` | `safe` | `low` | `strict` | None. |
| `zalo.webhook.ingest` | host-forwarded `POST <webhook_path>` | `zalo.events` | `safe` | `low` | `strict` | `method`, `path`, `headers`, `body`. |
| `zalo.webhook.set` | `POST /bot{token}/setWebhook` | `zalo.webhook` | `safe` | `medium` | `best_effort` | `url`; runtime may include `secret_token`. |
| `zalo.webhook.verify` | local token comparison | `zalo.webhook` | `safe` | `low` | `strict` | `token`. |

## Event Surface

`handle_introspect()` advertises these normalized event topics:

- `zalo.message.text`
- `zalo.message.image`
- `zalo.message.sticker`
- `zalo.message.unsupported`

Events come from either `host_forwarded_webhook_or_polling`. Accepted, denied, duplicate, and rate-limited counts live in memory only and reset on shutdown/configuration reset.

## Explicit Non-Goals

The current implementation does not include:

- Zalo Official Account creation, verification, permission review, admin management, article creation, broadcast send, statistics export, OA menu/chatbot configuration, ads, or ZNS/template messaging
- Zalo personal-account automation, Zalo Web automation, QR login, cookie/session management, desktop/mobile app control, or unofficial reverse-engineered APIs
- connector-owned webhook listeners or TLS termination
- persistent replay cursors, persistent event queues, durable offsets, message history storage, contact storage, or media downloads
- OAuth onboarding, token refresh, secret rotation, or provider-side permission discovery
- live quota/billing/rate-budget reporting

These are excluded on purpose:

- Personal-account automation is high risk and belongs in the quarantined `fcp.zalouser` contract.
- Inbound events are untrusted external content and must remain policy-gated.
- Outbound sends create visible side effects in Zalo conversations.
- Webhook hosting belongs to the gateway/host boundary, not this sandboxed connector.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration, token presence, base URL, request timeout, webhook verify configuration, webhook path, handshake, and inbound policy state
- implemented operation list and live capability list
- event capability posture for polling and host-forwarded webhook ingest
- degraded self-check reasons for not configured, not handshaken, and missing token
- local simulate decisions for webhook verification, webhook ingest, token presence, zone mismatch, target-instance mismatch, and unknown operations
- URL policy, replay/rate policy, provider error mapping, and redaction-safe evidence fields in tests

The deterministic integration evidence is anchored on loopback mock-server tests covering:

- configure, handshake, health, doctor, self-check, introspect, simulate, and shutdown behavior
- send text, send photo, getMe, getUpdates, setWebhook, deleteWebhook, getWebhookInfo, and webhook verify paths
- host-forwarded webhook ingest with accepted, denied, duplicate, and rate-limited events
- URL policy rejections for non-public photo/webhook URLs
- provider 429, timeout, connect, malformed JSON, invalid input, missing token, and unknown operation behavior
- redaction-shape evidence logs with hashed recipient/event identifiers

## Source Notes

- `connectors/zalo/src/connector.rs` defines configuration parsing, lifecycle handlers, invoke dispatch, public URL validation, provider call construction, webhook validation, inbound normalization, replay/rate policy, and diagnostics.
- `connectors/zalo/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/zalo/manifest.toml` defines the operation catalog, capability families, zone policy, sandbox boundary, and experimental status.
- `connectors/zalo/tests/integration.rs` covers loopback Bot API behavior, webhook ingest, event policy, and evidence logging.
- `connectors/zalo/tests/conformance_contract.rs` covers manifest/schema conformance for the operation inventory.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/zalo/README.md
ubs connectors/zalo/README.md
LC_ALL=C rg -n '[^ -~]' connectors/zalo/README.md
rg -n '\bmaster\b' connectors/zalo/README.md
```

For source or behavior changes, use an `rch`-offloaded connector proof lane:

```bash
fwc manifest fix connectors/zalo/manifest.toml --check --json
rch exec -- cargo fmt --manifest-path connectors/zalo/Cargo.toml --check
rch exec -- cargo check -p fcp-zalo --all-targets
rch exec -- cargo test -p fcp-zalo --test integration -- --nocapture
rch exec -- cargo test -p fcp-zalo --test conformance_contract -- --nocapture
rch exec -- cargo test -p fcp-zalo -- --nocapture
rch exec -- cargo clippy -p fcp-zalo --all-targets -- -D warnings
```

There is no tracked `scripts/e2e/zalo_connector_verification.sh` in this checkout. Add one before claiming a full scripted closeout bundle.

## Operator Guidance

Prerequisites:

- Use a Zalo Official Account / developer setup appropriate for Bot API testing.
- Configure a bot token as `access_token`, `bot_token`, or `token`.
- Configure `webhook_verify_challenge` or `webhook_token` before using local webhook verification or host-forwarded webhook ingest.
- Configure explicit sender/chat/group allow lists before trusting inbound events.

Dedicated environment:

- Prefer a loopback mock server or disposable Zalo bot/OA setup. Do not run send or webhook registration tests against a production OA unless visible conversation side effects are acceptable.

Redaction rules:

- Redact Bot API tokens, `/bot{token}/...` paths, `x-bot-api-secret-token`, webhook tokens, webhook URLs, user IDs, chat IDs, group IDs, sender names, message text, image URLs, provider response bodies, replay keys, and raw event payloads before sharing evidence.

Common remediation:

- If `health` reports `unconfigured`, call `configure` with a valid token and base URL.
- If `health` reports `degraded`, verify that a non-empty token is configured.
- If `self_check` reports `not_handshaken`, call handshake before invoking operations.
- If `doctor` reports missing `access_token`, provide `access_token`, `bot_token`, or `token`.
- If webhook ingest denies all events, configure an explicit inbound allow policy.
- If webhook ingest fails token verification, compare the forwarded `x-bot-api-secret-token` against `webhook_verify_challenge` or `webhook_token`.
- If photo or webhook URL validation fails, use a public HTTPS hostname that resolves outside localhost, private, link-local, multicast, unspecified, and IP-literal ranges.

Rerun commands:

- `git diff --check -- connectors/zalo/README.md`
- `ubs connectors/zalo/README.md`
- `rch exec -- cargo test -p fcp-zalo --test integration -- --nocapture`
- `rch exec -- cargo test -p fcp-zalo --test conformance_contract -- --nocapture`
