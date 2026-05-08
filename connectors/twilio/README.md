# Twilio Connector V3 Contract

> **Status**: runtime contract documented; manifest/introspection/API drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Twilio REST API upstream**: https://www.twilio.com/docs/iam/api/
> **Twilio Messages upstream**: https://www.twilio.com/docs/messaging/api/message-resource
> **Twilio webhooks upstream**: https://www.twilio.com/docs/usage/webhooks/getting-started-twilio-webhooks
> **Twilio request validation upstream**: https://www.twilio.com/docs/usage/security
> **Twilio Verify upstream**: https://www.twilio.com/docs/verify/api/verification/

## Purpose

This document fixes the operator-facing contract for `fcp.twilio`. The connector exposes the Twilio REST surfaces currently implemented in this crate: SMS/MMS, voice calls, recordings, media metadata/downloads, account and phone-number reads, WhatsApp message operations, Conversations, Verify, Video rooms, host-forwarded Media Streams frame processing, and host-forwarded webhook validation and parsing.

The connector is intentionally a bounded Twilio API bridge. It is not a Twilio SDK wrapper, webhook listener, WebSocket server, TwiML hosting service, phone-number provisioning wizard, OAuth flow, call-center application, recording transcription pipeline, contact store, message campaign tool, or long-lived provider event bus.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `twilio.send_message`
- `twilio.get_message`
- `twilio.list_messages`
- `twilio.list_media`
- `twilio.get_media`
- `twilio.create_call`
- `twilio.get_call`
- `twilio.hangup_call`
- `twilio.list_calls`
- `twilio.generate_twiml`
- `twilio.media_stream.process_events`
- `twilio.list_recordings`
- `twilio.download_recording`
- `twilio.download_media`
- `twilio.get_account`
- `twilio.list_phone_numbers`
- `twilio.whatsapp_send`
- `twilio.whatsapp_send_template`
- `twilio.whatsapp_get`
- `twilio.whatsapp_list`
- `twilio.conversation.create`
- `twilio.conversation.get`
- `twilio.conversation.list`
- `twilio.conversation.participant.add`
- `twilio.conversation.participant.remove`
- `twilio.conversation.message.send`
- `twilio.conversation.message.list`
- `twilio.verify.send`
- `twilio.verify.check`
- `twilio.verify.cancel`
- `twilio.video.room.create`
- `twilio.video.room.get`
- `twilio.video.room.list`
- `twilio.video.room.end`
- `twilio.video.room.participants`
- `twilio.video.recording.list`
- `twilio.webhook.validate_signature`
- `twilio.webhook.evaluate_inbound_policy`
- `twilio.webhook.ingest_request`
- `twilio.webhook.parse_sms_event`
- `twilio.webhook.parse_status_callback`
- `twilio.webhook.parse_voice_event`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-twilio`.
- Manifest ID is `fcp.twilio`.
- `BaseConnector` runtime ID is `twilio`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires `account_sid` and exactly one auth source:
  - `auth_token`
  - `credential_id`
- Direct token mode sends HTTP Basic auth using `account_sid:auth_token`.
- `credential_id` mode sends `X-FCP-Credential-ID: <uuid>` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- Default REST base URL is `https://api.twilio.com/2010-04-01/Accounts/{account_sid}`.
- Direct token mode only accepts `api.twilio.com` for non-loopback base URLs.
- `credential_id` mode may target a custom non-loopback base URL so the host can route through a credential-injecting egress proxy.
- The configured `base_url` only replaces the main REST account base used for SMS, calls, recordings, media, account, and phone-number helpers.
- Conversations, Verify, and Video helpers keep their own default service bases unless tests use internal setters.
- Default runtime request timeout is 30 seconds.
- The client stores a retry config and defaults to two retries for Twilio HTTP calls.
- `health()` reports local readiness, request counters, auth mode, API URL, and handshake state. It does not call Twilio.
- `doctor()` checks local configuration, client initialization, base URL policy, auth mode, network constraints, credential injection, and handshake state. It does not call Twilio.
- `self_check()` calls `get_account()` in direct-token mode.
- `self_check()` reports degraded in `credential_id` mode because live provider validation requires host egress injection outside this connector.
- Runtime `invoke` uses the JSON fields `operation`, `input`, and `capability_token`.
- Runtime `simulate` uses the FCP `SimulateRequest` shape and reads operation input from `input`.
- Runtime `invoke` and `simulate` require a bound capability token for the operation capability.
- Runtime capability verification currently passes an empty resource URI list for Twilio operations.
- Runtime `handshake()` installs a `CapabilityVerifier`, grants every requested capability unfiltered, and returns hard-coded `manifest_hash = "sha256:twilio-connector-v1"`.
- Runtime event caps report streaming support, no replay, no ack requirement, and a minimum buffer of 50 events.
- Runtime `shutdown()` clears config, client, verifier, session, and base configured/handshaken flags.

## Runtime API Adapter

The runtime uses these request shapes and local adapters:

| Operation | Capability | Required input | Runtime behavior |
|-----------|------------|----------------|------------------|
| `twilio.send_message` | `twilio.message` | `to`, `from`, `body` | Creates an SMS/MMS message; optional `media_url` and `status_callback`. |
| `twilio.get_message` | `twilio.read` | `message_sid` | Fetches message details. |
| `twilio.list_messages` | `twilio.read` | none | Lists messages with optional `to`, `from`, `date_sent`, `page_size`, and `page`. |
| `twilio.list_media` | `twilio.read` | `message_sid` | Lists media attachments for a message. |
| `twilio.get_media` | `twilio.read` | `message_sid`, `media_sid` | Fetches media metadata. |
| `twilio.create_call` | `twilio.voice` | `to`, `from`, `url` | Starts an outbound call; optional status callback, timeout, and recording flag. |
| `twilio.get_call` | `twilio.read` | `call_sid` | Fetches call details. |
| `twilio.hangup_call` | `twilio.voice` | `call_sid` | Updates an active call to completed. |
| `twilio.list_calls` | `twilio.read` | none | Lists calls with optional number, status, time, and pagination filters. |
| `twilio.generate_twiml` | `twilio.voice` | `template` | Locally generates TwiML for `say`, `play`, `gather`, `dial`, `pause`, `reject`, or `hangup`. |
| `twilio.media_stream.process_events` | `twilio.voice` | `frames` | Locally processes host-forwarded Media Streams frames and bounded outbound actions. |
| `twilio.list_recordings` | `twilio.read` | none | Lists call recordings with optional `call_sid`, `date_created`, and `page_size`. |
| `twilio.download_recording` | `twilio.read` | `recording_sid` | Downloads recording content; optional `format`. |
| `twilio.download_media` | `twilio.read` | `message_sid`, `media_sid` | Downloads MMS media content. |
| `twilio.get_account` | `twilio.read` | none | Fetches account details. |
| `twilio.list_phone_numbers` | `twilio.read` | none | Lists incoming phone numbers with optional number filter. |
| `twilio.whatsapp_send` | `twilio.whatsapp` | `to`, `from`, `body` | Sends a freeform WhatsApp message through Twilio messaging. |
| `twilio.whatsapp_send_template` | `twilio.whatsapp` | `to`, `from`, `content_sid` | Sends a template WhatsApp message; optional content variables. |
| `twilio.whatsapp_get` | `twilio.read` | `message_sid` | Fetches WhatsApp message status/details. |
| `twilio.whatsapp_list` | `twilio.read` | none | Lists WhatsApp messages with optional filters. |
| `twilio.conversation.create` | `twilio.conversations` | none | Creates a Conversation; optional friendly and unique names. |
| `twilio.conversation.get` | `twilio.read` | `conversation_sid` | Fetches Conversation details. |
| `twilio.conversation.list` | `twilio.read` | none | Lists Conversations with optional `page_size`. |
| `twilio.conversation.participant.add` | `twilio.conversations.participants` | `conversation_sid` | Adds an identity or messaging participant. |
| `twilio.conversation.participant.remove` | `twilio.conversations.participants` | `conversation_sid`, `participant_sid` | Removes a Conversation participant. |
| `twilio.conversation.message.send` | `twilio.conversations` | `conversation_sid`, `body` | Sends a Conversation message; optional `author`. |
| `twilio.conversation.message.list` | `twilio.read` | `conversation_sid` | Lists Conversation messages. |
| `twilio.verify.send` | `twilio.verify` | `service_sid`, `to`, `channel` | Sends a Verify code over SMS, call, email, or WhatsApp. |
| `twilio.verify.check` | `twilio.verify` | `service_sid`, `to`, `code` | Checks a submitted Verify code. |
| `twilio.verify.cancel` | `twilio.verify` | `service_sid`, `verification_sid` | Cancels a pending Verify verification. |
| `twilio.video.room.create` | `twilio.video.rooms.write` | none | Creates a Video room. |
| `twilio.video.room.get` | `twilio.video.rooms.read` | `room_sid` | Fetches a Video room by SID or unique name. |
| `twilio.video.room.list` | `twilio.video.rooms.read` | none | Lists Video rooms with optional status and page size. |
| `twilio.video.room.end` | `twilio.video.rooms.write` | `room_sid` | Completes a Video room. |
| `twilio.video.room.participants` | `twilio.video.participants.read` | `room_sid` | Lists Video room participants. |
| `twilio.video.recording.list` | `twilio.video.recordings.read` | `room_sid` | Lists Video room recordings. |
| `twilio.webhook.validate_signature` | `twilio.webhook` | `url`, `params`, `signature` | Locally validates `X-Twilio-Signature`; optional `auth_token` and exact host allowlist. |
| `twilio.webhook.evaluate_inbound_policy` | `twilio.webhook` | `body`, `inbound_policy` | Locally applies `open`, `allowlist`, or `disabled` inbound policy. |
| `twilio.webhook.ingest_request` | `twilio.webhook` | `method`, `url`, `headers`, `body` | Processes a host-forwarded request through signature, replay, size, timeout, policy, and parsing guardrails. |
| `twilio.webhook.parse_sms_event` | `twilio.webhook` | `body` | Parses an SMS/MMS webhook payload into a typed tainted event. |
| `twilio.webhook.parse_status_callback` | `twilio.webhook` | `body` | Parses message or voice status callbacks. |
| `twilio.webhook.parse_voice_event` | `twilio.webhook` | `body` | Parses an incoming voice webhook payload. |

Webhook and Media Streams handling:

- The connector does not listen on a port. The FCP host must accept HTTP or WebSocket traffic and forward normalized request or frame objects into `invoke`.
- `twilio.webhook.ingest_request` defaults to a 64 KiB decoded form-body cap, 5 second timeout budget, concurrency limit of 32, and 200 requests per 60 second rate window.
- Webhook signature validation normalizes the public URL, sorts form parameters, validates the HMAC-SHA1 signature, and tracks replay keys in memory.
- Inbound policy uses exact normalized sender/caller values; suffix matching is intentionally rejected.
- Parsed inbound webhook output is tainted because provider payloads are external input.
- `twilio.media_stream.process_events` expects host-forwarded Twilio WebSocket frames. It validates ordering, token/call binding when supplied, frame and media-size budgets, queue pressure, reconnect state, cancellation, and deadline flags.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Twilio documents the REST base as `https://api.twilio.com/2010-04-01`. Runtime correctly scopes the main client to `https://api.twilio.com/2010-04-01/Accounts/{account_sid}`.
- Twilio documents Basic authentication and recommends API keys for production. Runtime direct mode uses Account SID plus auth token; there is no API-key-specific configuration surface.
- The manifest and runtime both expose a broad operation catalog, but runtime introspection does not include provider approval metadata even for message sends, calls, DM-like WhatsApp sends, Verify sends, and destructive room/call actions.
- Handshake grants every requested capability unfiltered. It does not intersect requested capabilities with the actual Twilio catalog.
- Handshake returns a hard-coded manifest hash instead of hashing the checked-in manifest.
- Runtime `invoke` verifies capability tokens but does not bind resource URIs such as phone numbers, message SIDs, call SIDs, Conversation SIDs, or room SIDs.
- Runtime `simulate` validates required inputs and capability token binding, but it does not model provider rate limits, carrier acceptance, account balance, trial-account recipient restrictions, WhatsApp template approval, Verify service state, Video room existence, or webhook source IP policy.
- The configured `base_url` does not retarget the Conversations, Verify, or Video service bases in normal configure flow.
- Runtime `health()` and `doctor()` are local diagnostics only.
- Runtime `self_check()` performs a live account probe only in direct-token mode. In `credential_id` mode it reports degraded because host credential injection is required.
- `credential_id` mode sends a local `X-FCP-Credential-ID` header. Without an egress proxy, Twilio itself will not authenticate that header.
- Webhook ingestion validates Twilio signatures from host-forwarded request data but does not prove the original network edge used TLS or Twilio IP ranges; those are host responsibilities.
- Webhook replay cache is in-memory process state and is cleared on connector restart.
- No dedicated tracked verification shell script exists for this connector.

A follow-up parity bead should filter handshake grants, hash the manifest, add approval metadata for risk-bearing operations, bind capability tokens to Twilio resource URIs, expose or enforce provider scopes and trial-account limitations, support egress-proxy live self-checks, and reconcile custom base-URL behavior across all Twilio service bases.

## First-Slice Scope

The current Twilio README slice documents the existing runtime surface:

- Account SID plus auth-token or credential-ID configuration
- SMS/MMS, WhatsApp, voice, recordings, media, Conversations, Verify, Video, webhooks, and Media Streams operation groups
- Local health, doctor, self-check, introspection, simulate, invoke, and shutdown behavior
- Capability-token verification and its current empty resource-URI binding
- Webhook signature, replay, inbound policy, body-size, timeout, and parsing behavior
- Runtime/manifest/provider-doc drift around auth modes, manifest hash, approval metadata, provider constraints, base URLs, and live checks
- Existing integration-test orientation through WireMock and local webhook parsing paths

## Auth And Zone Boundary

- Authentication mechanisms: direct Account SID/auth token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability families:
  - `twilio.read`
  - `twilio.message`
  - `twilio.voice`
  - `twilio.media`
  - `twilio.whatsapp`
  - `twilio.conversations`
  - `twilio.conversations.participants`
  - `twilio.verify`
  - `twilio.video.rooms.read`
  - `twilio.video.rooms.write`
  - `twilio.video.participants.read`
  - `twilio.video.recordings.read`
  - `twilio.webhook`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, `storage.state`, and `crypto.hmac`.
- Manifest forbids `system.exec` and `network.listen`.
- The connector does not intentionally persist auth tokens, credential IDs beyond configuration metadata, Twilio payloads, media, recordings, request counters, or error counters outside process memory.
- Twilio payloads can contain phone numbers, message bodies, WhatsApp content, call metadata, recordings, media, participants, verification targets, and status callbacks. Treat live output as private or work-zone sensitive unless the host supplies a stricter zone policy.

## Explicit Non-Goals

- No incoming HTTP listener inside the connector.
- No direct Twilio WebSocket listener inside the connector.
- No TwiML hosting.
- No automatic Twilio Console provisioning.
- No phone-number purchase or registration flow.
- No token or credential persistence.
- No carrier compliance automation.
- No delivery guarantee beyond provider success/error responses.
- No webhook IP-range verification inside this crate.
- No cross-zone message fanout.

## Verification

README-only changes do not require Cargo or `rch` verification. Before committing this file, run:

```bash
git diff --check -- connectors/twilio/README.md
LC_ALL=C rg -n '[^ -~]' connectors/twilio/README.md
rg -n '\bmaster\b' connectors/twilio/README.md
ubs connectors/twilio/README.md
```

For code changes in this connector, use the workspace-required proof lane from the root `AGENTS.md`:

```bash
rch exec -- cargo check --workspace --all-targets
rch exec -- cargo clippy --workspace --all-targets -- -D warnings
rch exec -- cargo fmt --check
```
