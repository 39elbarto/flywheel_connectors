# WhatsApp Connector V3 Contract

> **Status**: runtime contract documented; Cloud API boundary and lifecycle drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **WhatsApp Cloud API upstream**: https://developers.facebook.com/docs/whatsapp/cloud-api
> **Messages upstream**: https://developers.facebook.com/docs/whatsapp/cloud-api/reference/messages
> **Webhooks upstream**: https://developers.facebook.com/docs/whatsapp/cloud-api/webhooks
> **Business profile upstream**: https://developers.facebook.com/docs/whatsapp/cloud-api/reference/whatsapp-business-account

## Purpose

This document fixes the operator-facing contract for `fcp.whatsapp`. The connector exposes the WhatsApp Business Cloud API surface implemented in this crate: send text messages, send template messages, read business profile metadata, verify webhook challenges, and process host-forwarded signed webhook payloads.

The connector is intentionally a Cloud API connector. It is not a personal WhatsApp Web bridge, desktop automation wrapper, phone-number registrar, QR-code login flow, browser session manager, group chat client, media downloader, contact scraper, or durable inbox.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `whatsapp.send_text`
- `whatsapp.send_template`
- `whatsapp.get_profile`
- `whatsapp.webhook_verify`
- `whatsapp.webhook_receive`

Important runtime truths the contract preserves:

- Runtime connector ID is `fcp.whatsapp`.
- `base_url` defaults to `https://graph.facebook.com/v21.0`.
- Configuration requires `phone_number_id` and accepts `access_token`, `app_secret`, `webhook_verify_token`, `webhook_allowed_senders`, retry settings, and `request_timeout_ms`.
- Empty `access_token` enables a secretless host-injection posture. In that mode provider calls omit the bearer header and `self_check` reports degraded `credential_injection_required`.
- Non-empty `access_token` sends `Authorization: Bearer <token>`.
- `phone_number_id` is sanitized as a path segment and rejects blank values, separators, traversal, and encoded slash or backslash forms.
- Runtime `base_url` validation accepts the production Graph host and local test hosts, rejects remote plaintext HTTP, rejects userinfo/query/fragment components, and trims trailing slashes.
- Personal bridge configuration keys are rejected during configuration.
- `send_text` and `send_template` post to `/{phone_number_id}/messages`.
- `get_profile` reads `/{phone_number_id}/whatsapp_business_profile` with the current field list.
- `self_check` probes `GET /{phone_number_id}`; HTTP 400 is treated as reachable, HTTP 401 fails auth, and HTTP 429 reports degraded retryable health.
- `webhook_verify` is a local challenge-response check for `hub.mode`, `hub.verify_token`, and `hub.challenge`.
- `webhook_receive` verifies `X-Hub-Signature-256`, parses the WhatsApp Business Account webhook object, applies replay detection and sender policy, and emits normalized message or status events in the response payload.
- Status webhooks are audit-only and are not agent-turn eligible.
- The connector does not open inbound sockets. The FCP host owns HTTP ingress and forwards webhook requests to `whatsapp.webhook_receive`.
- Handshake installs a `CapabilityVerifier`.
- `invoke` requires configured and handshaken state, maps each operation to a required capability, verifies a bound capability token, and then dispatches the operation.
- `simulate` currently returns allowed for any request and does not validate configuration, input shape, capability tokens, webhook signatures, provider reachability, or operation-specific policy.
- `subscribe` and `unsubscribe` return `StreamingNotSupported`.

## Drift Visible In This Checkout

This README documents the runtime truth and keeps current drift visible:

- Manifest operation keys are unprefixed names such as `send_text`, while runtime introspection exposes prefixed operation IDs such as `whatsapp.send_text`.
- Handshake grants every requested capability rather than filtering to the manifest capability set.
- `simulate` is permissive and not policy-aware.
- The Cloud API client is built with a fixed 30 second reqwest timeout even though configuration also carries `request_timeout_ms`.
- `shutdown()` shuts down the runtime but does not clear configuration, client, verifier, configured state, or handshaken state.
- Webhook receive returns normalized events in an invoke response. It does not provide connector-owned streaming, replay buffers, acknowledgements, or inbound sockets.
- Empty `webhook_allowed_senders` means every signed message sender is accepted.
- The connector rejects personal bridge keys at configuration time, but the manifest and README are the operator-facing boundary that make this Cloud API-only stance explicit.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should align manifest operation IDs with runtime introspection, make simulation validate schemas and capability tokens, wire `request_timeout_ms` into the HTTP client, clear lifecycle state consistently during shutdown, and decide whether signed webhook sender allowlists should be mandatory outside tests.

## First-Slice Scope

The current WhatsApp README slice documents the implemented runtime surface:

- WhatsApp Business Cloud API-only configuration
- direct bearer-token and secretless host-injection auth postures
- text message sends and template message sends
- business profile reads
- webhook challenge verification
- signed webhook receive, replay detection, sender allowlist policy, status audit events, and normalized message events
- local lifecycle, health, doctor, self-check, introspection, simulation, invoke, subscribe, unsubscribe, and shutdown behavior
- bound capability-token verification during invoke
- provider error mapping for auth, validation, rate limits, transient Meta API errors, retryable server errors, timeout, JSON, webhook, and configuration failures
- deterministic WireMock and connector-suite evidence

## Auth And Scope Boundary

- Authentication mechanism: WhatsApp Cloud API access token or host-injected credential.
- Provider request auth: `Authorization: Bearer <token>` when configured.
- Webhook signature: `X-Hub-Signature-256` with HMAC-SHA256 over the raw webhook body.
- Webhook verification token: configured `webhook_verify_token`.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:work` and `z:project:*`.
- Runtime capability surface:
  - `whatsapp.send` gates text and template sends.
  - `whatsapp.read` gates business profile reads.
  - `whatsapp.webhook` gates webhook challenge verification and signed webhook receive.
- The connector does not intentionally persist access tokens, app secrets, webhook verify tokens, message bodies, contacts, profile payloads, provider responses, webhook payloads, policy decisions, or provider error bodies beyond process memory.
- WhatsApp phone numbers, message IDs, template names, template parameters, sender identifiers, delivery statuses, and profile metadata can expose work communications. Treat live request and response data as work-zone sensitive.

## Network And Runtime Invariants

- Production host: `graph.facebook.com`.
- Default production base URL: `https://graph.facebook.com/v21.0`.
- Local test hosts accepted by runtime validation: `localhost`, `.localhost`, `127.0.0.1`, and `::1`.
- Remote plaintext HTTP is rejected.
- Runtime path families:
  - `POST /{phone_number_id}/messages`
  - `GET /{phone_number_id}/whatsapp_business_profile?fields=about,address,description,vertical`
  - `GET /{phone_number_id}`
- Runtime webhook receive expects a WhatsApp Business Account webhook object.
- Duplicate logical signature headers are rejected before verification.
- Message events normalize to `message.<type>`.
- Status events normalize to `status.<status>` and are audit-only.
- Replay detection uses connector-local event claims.
- The connector does not open inbound sockets and does not implement connector-owned replay or streaming.
- Sandbox profile is strict, with no exec and no privileged system access.

## Personal Bridge Rejection

The connector rejects configuration keys that would move it toward a personal WhatsApp bridge, including:

- `personal_bridge`
- `bridge_script`
- `bridge_port`
- `session_path`
- `dm_policy`
- `allow_from`
- `allowFrom`
- `group_policy`
- `group_allow_from`
- `groupAllowFrom`
- `require_mention`
- `free_response_chats`

This is a hard scope boundary for the current crate. Personal WhatsApp automation has different legal, security, auth, rate-limit, and user-consent properties and must not be smuggled into the Cloud API connector.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `whatsapp.send` | Send WhatsApp Cloud API text and template messages. |
| `whatsapp.read` | Read WhatsApp Business profile metadata. |
| `whatsapp.webhook` | Verify webhook challenges and process signed host-forwarded webhook payloads. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `whatsapp.send_text` | `POST /{phone_number_id}/messages` | `whatsapp.send` | `Risky` | `Medium` | `None` | Sends a user-visible WhatsApp text message. |
| `whatsapp.send_template` | `POST /{phone_number_id}/messages` | `whatsapp.send` | `Risky` | `Medium` | `None` | Sends a user-visible approved template message. |
| `whatsapp.get_profile` | `GET /{phone_number_id}/whatsapp_business_profile` | `whatsapp.read` | `Safe` | `Low` | `Strict` | Reads business profile metadata. |
| `whatsapp.webhook_verify` | local challenge response | `whatsapp.webhook` | `Safe` | `Low` | `Strict` | Verifies the provider callback challenge without provider I/O. |
| `whatsapp.webhook_receive` | host-forwarded signed webhook body | `whatsapp.webhook` | `Risky` | `Medium` | `BestEffort` | Authenticates provider events, applies policy, and emits normalized event records. |

## Webhook Event Inventory

| Event class | Source | Agent-turn eligible | Replay handling | Rationale |
|-------------|--------|---------------------|-----------------|-----------|
| `message.<type>` | signed WhatsApp message webhook | yes, when sender policy accepts it | in-memory claim check | Represents inbound user or customer messages. |
| `status.<status>` | signed WhatsApp status webhook | no | in-memory claim check | Delivery and read status are audit metadata, not prompts for autonomous replies. |
| unsupported or denied payloads | signed webhook body | no | counted as dropped | Keeps unrecognized or policy-denied data out of agent-turn flow. |

## Explicit Non-Goals

The current implementation does not include:

- personal WhatsApp Web automation, QR login, desktop session reuse, browser automation, or local bridge scripts
- phone-number registration, business verification, app creation, token creation, webhook URL registration, or Meta app dashboard automation
- group messaging, group administration, contact sync, media upload, media download, sticker handling, interactive message builders beyond current template payload support, or catalog operations
- persistent webhook queues, durable replay, connector-owned HTTP listeners, event acknowledgements, or streaming subscriptions
- automatic opt-in management, customer-service window tracking, marketing consent enforcement, or template approval workflows
- account analytics, billing, quality-rating management, rate-limit dashboards, or phone-number migration

These are excluded on purpose:

- WhatsApp Cloud API messaging is production-visible communication.
- Webhook payloads can contain private customer data.
- Meta app setup and phone-number registration require explicit operator consent and external dashboard state.
- Personal bridge automation belongs to a separate connector design with a different trust model.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, `invoke()`, `subscribe()`, `unsubscribe()`, and `shutdown()` are part of the public closeout contract. They surface:

- configured state, phone-number ID posture, base URL, request timeout, token mode, webhook token posture, sender allowlist posture, and manifest hash
- operation metadata with capability, risk, safety tier, idempotency, schemas, and AI hints
- bound capability-token verification during `invoke`
- current permissive simulation behavior
- live provider reachability through `self_check`
- webhook signature verification, replay-drop counts, policy decisions, and normalized event counts in invoke responses
- non-streaming posture through `StreamingNotSupported`
- current shutdown state retention behavior

The deterministic integration evidence is anchored on connector-local tests covering:

- manifest/runtime schema parity for all runtime operations
- direct text send and template send request bodies
- business profile request path and field selection
- access-token and secretless request postures
- base URL validation and phone-number ID path sanitization
- webhook challenge verification
- signed webhook receive, duplicate signature rejection, replay dropping, sender allowlist decisions, and status audit events
- personal bridge configuration rejection
- provider error mapping for unauthorized, rate-limited, transient, retryable, timeout, malformed JSON, webhook, and validation cases
- connector-suite happy path for signed webhook payloads

## Source Notes

- `connectors/whatsapp/src/connector.rs` defines lifecycle handlers, operation metadata, capability-token verification, simulation, health, self-check, personal bridge rejection, webhook operations, and invoke dispatch.
- `connectors/whatsapp/src/client.rs` defines Cloud API paths, base URL validation, bearer auth, path sanitization, request construction, response decoding, health probing, and provider error mapping.
- `connectors/whatsapp/src/webhook.rs` defines HMAC-SHA256 signature verification, case-insensitive header handling, replay claims, sender policy, event normalization, status audit handling, and dropped-event accounting.
- `connectors/whatsapp/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/whatsapp/manifest.toml` defines the manifest operation catalog, capability catalog, network constraints, sandbox boundary, and zone policy.
- `connectors/whatsapp/tests/integration.rs` covers deterministic HTTP behavior, webhook behavior, and runtime lifecycle coverage.
- `connectors/whatsapp/tests/connector_suite_happy_path.rs` covers connector-suite webhook happy path behavior.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/whatsapp/README.md
LC_ALL=C grep -n '[^[:print:][:space:]]' connectors/whatsapp/README.md
rg -n "$(printf '\\x6d\\x61\\x73\\x74\\x65\\x72')" connectors/whatsapp/README.md
ubs connectors/whatsapp/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
