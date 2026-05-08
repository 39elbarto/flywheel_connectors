# Microsoft Outlook Connector V3 Contract

> **Status**: runtime contract documented; Microsoft Graph scope limits documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Microsoft Graph messages upstream**: https://learn.microsoft.com/en-us/graph/api/user-list-messages?view=graph-rest-1.0
> **Microsoft Graph sendMail upstream**: https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0
> **Microsoft Graph events upstream**: https://learn.microsoft.com/en-us/graph/api/user-list-events?view=graph-rest-1.0
> **Microsoft Graph create event upstream**: https://learn.microsoft.com/en-us/graph/api/user-post-events?view=graph-rest-1.0
> **Microsoft Graph mail folders upstream**: https://learn.microsoft.com/en-us/graph/api/user-list-mailfolders?view=graph-rest-1.0

## Purpose

This document fixes the operator-facing contract for `fcp.outlook`. The connector exposes the Microsoft Outlook and Exchange surface implemented in this crate through Microsoft Graph v1.0: mail listing, message retrieval, message search, mail sending, event listing, event creation, and folder discovery.

The connector is intentionally a request-response Microsoft Graph bridge. It is not an OAuth setup flow, token refresh service, webhook listener, Microsoft Graph subscription handler, delta-sync engine, attachment client, mailbox administration tool, contact client, Teams bridge, or full Microsoft 365 connector.

## Current Runtime Snapshot

The current crate exposes these operations:

- `outlook.list_messages`
- `outlook.get_message`
- `outlook.search_messages`
- `outlook.send_message`
- `outlook.list_events`
- `outlook.create_event`
- `outlook.list_folders`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-outlook`.
- Runtime `BaseConnector` ID is `fcp.outlook`.
- Manifest and reported connector ID are `fcp.outlook`.
- Manifest version is `0.1.0`.
- Manifest format is `native`.
- Configuration requires `access_token`.
- Configuration accepts optional `graph_host`.
- Configuration accepts optional `request_timeout_ms`.
- Default `graph_host` is `https://graph.microsoft.com`.
- Supported production Graph hosts are `graph.microsoft.com` and `graph.microsoft.us`.
- `graph_host` must be an absolute URL with no userinfo, query string, fragment, or path.
- Non-local hosts must use HTTPS.
- Loopback `graph_host` values are accepted only in test/debug builds for deterministic fixtures.
- The runtime appends `/v1.0` to `graph_host`.
- Do not include `/v1.0` in `graph_host`; configure rejects paths.
- Runtime request timeout defaults to 15000 ms.
- The client uses reqwest `bearer_auth` for every request.
- The runtime does not strip a leading `Bearer ` prefix from `access_token`.
- There is no OAuth authorization-code flow, refresh-token handling, or credential-id mode in this connector.
- There is no retry loop in the Outlook client.
- `health()` reports configured client state and uptime. It does not call Microsoft Graph.
- `doctor()` performs local configuration checks only.
- `self_check()` performs a live `GET /me/mailFolders` probe through `client.health()`.
- `configure()` resets the base handshaken flag and clears the verifier.
- `handshake()` grants only requested capabilities that match `outlook.read`, `outlook.send`, or `outlook.calendar`.
- Runtime `invoke` and `simulate` both require a bound capability token and verify it against the operation capability and operation ID.
- Runtime `invoke` calls `BaseConnector::check_ready()`.
- `shutdown()` clears config, client, verifier, and base lifecycle state.
- `subscribe()` and `unsubscribe()` return streaming-not-supported errors.

## Runtime API Adapter

The runtime uses these request shapes:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `outlook.list_messages` | `GET /me/mailFolders/{folder_id}/messages?$top={limit}&$orderby=receivedDateTime%20desc&$select=id,subject,from,receivedDateTime,isRead,bodyPreview` | none | Defaults `folder_id` to `inbox` and `top` to 25. Returns Graph JSON. |
| `outlook.get_message` | `GET /me/messages/{message_id}?$select=id,subject,from,toRecipients,ccRecipients,receivedDateTime,isRead,body,hasAttachments` | `message_id` | Returns Graph JSON for one message. |
| `outlook.search_messages` | `GET /me/messages?$search={quoted_query}&$top={limit}&$select=id,subject,from,receivedDateTime,bodyPreview` | `query` | Trims, quotes, escapes, and URL-encodes the search phrase. Returns Graph JSON. |
| `outlook.send_message` | `POST /me/sendMail` | `to`, `subject`, `body` | Sends JSON mail with Text body and optional `cc`. A 202 or 204 response becomes `{ "status": "ok" }`. |
| `outlook.list_events` | `GET /me/events?$top={limit}&$orderby=start/dateTime&$select=id,subject,start,end,location,organizer,isAllDay` | none | Defaults `top` to 25. Returns Graph JSON. |
| `outlook.create_event` | `POST /me/events` | `subject`, `start`, `end` | Sends UTC `dateTimeTimeZone` metadata plus optional Text body and location. Returns Graph JSON. |
| `outlook.list_folders` | `GET /me/mailFolders?$select=id,displayName,totalItemCount,unreadItemCount` | none | Returns Graph JSON. |

Input validation is intentionally narrow:

- `top` must be an integer greater than zero when supplied.
- The manifest caps `top` at 100; the client also caps Graph requests at 100.
- `parse_top()` accepts values greater than 100 and lets the client cap them.
- Message and folder path IDs reject empty or whitespace-only values and control characters, then percent encode reserved characters.
- `search_messages` rejects empty and control-character queries.
- `search_messages` escapes backslashes and quotes, then wraps the phrase in quotes for Graph `$search`.
- `send_message` requires at least one non-empty recipient in `to`.
- `cc` is optional but rejects non-string or blank entries when present.
- `send_message` requires `subject` and `body` strings but permits empty subject and body values.
- `create_event` requires non-empty `subject`, `start`, and `end` strings in the client.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Microsoft Graph list messages supports `/me/messages` and folder-scoped `/me/mailFolders/{id}/messages`; runtime always uses the folder-scoped path and defaults to `inbox`.
- Microsoft Graph list messages supports `$top` values up to 1000. Runtime caps requests at 100 to match the manifest.
- Microsoft Graph list messages can return full message bodies by default, but runtime list calls select only metadata and `bodyPreview`. Use `outlook.get_message` for body content.
- Microsoft Graph sendMail returns `202 Accepted` without a response body when accepted. Runtime normalizes 202 and 204 success to `{ "status": "ok" }`.
- Microsoft Graph create-event examples often use `Prefer: outlook.timezone` and may use `transactionId` to reduce duplicate retries. Runtime sends no `Prefer` header and no `transactionId`.
- Runtime `create_event` always labels `start` and `end` as `UTC`, even when caller strings include an offset or local-time meaning.
- Manifest marks `outlook.send_message` and `outlook.create_event` as risky but `requires_approval = "none"`. Runtime does not perform approval checks.
- Manifest says Microsoft Graph subscriptions, notification ingress, and delta handoff are owned by `fcp.microsoft365`. Runtime has no subscription or delta surface.
- Manifest production network policy denies localhost and IP literals. Runtime accepts loopback Graph hosts in test/debug builds.
- Configuration validates the Graph host before the network policy layer. Production custom remote hosts outside `graph.microsoft.com` and `graph.microsoft.us` are rejected.
- Runtime accepts additional input properties because manifest schemas use `additionalProperties = true`; extra fields are ignored by current dispatch.
- Runtime `self_check()` performs a live folder listing and can fail due to token permissions, mailbox state, throttling, or Graph availability.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should decide whether `access_token` should explicitly reject a leading `Bearer ` prefix, add request-level idempotency support for event creation, decide whether send/create operations need approval enforcement, document or implement timezone handling, and decide whether narrow folder/message pagination helpers are needed before production promotion.

## First-Slice Scope

The current Outlook README slice documents the existing runtime surface:

- access-token configuration
- Graph host and timeout handling
- Microsoft Graph v1.0 mail, calendar, and folder operations
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, subscribe, unsubscribe, and shutdown behavior
- runtime/manifest/provider-doc drift around approval, pagination caps, timezone handling, sendMail acceptance, loopback fixture hosts, and subscription ownership
- deterministic provider-contract and unit tests

## Auth And Zone Boundary

- Authentication mechanism: caller-supplied Microsoft Graph access token.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:owner`, `z:private`, and `z:work`.
- Forbidden zone: `z:public`.
- Runtime capability families:
  - `outlook.read`
  - `outlook.send`
  - `outlook.calendar`
- Manifest required capabilities are `network.dns`, `network.egress`, and `network.tls.sni`.
- The connector does not persist access tokens, message bodies, subjects, recipients, calendar events, folder names, provider payloads, provider error bodies, request counters, or error counters outside process memory.
- Outlook payloads can include private email, recipient lists, mailbox folder names, calendar event details, locations, organizer identities, and message body content. Treat live output as owner/private/work sensitive depending on the configured host zone.

Provider permissions depend on the selected operation and token type:

| Operation family | Typical Microsoft Graph permission family |
|------------------|-------------------------------------------|
| Message and folder reads | `Mail.ReadBasic`, `Mail.Read`, or application equivalents as needed |
| Message send | `Mail.Send` |
| Event reads | `Calendars.ReadBasic`, `Calendars.Read`, or `Calendars.ReadWrite` |
| Event creation | `Calendars.ReadWrite` |

The runtime does not request or refresh these permissions. The host must supply a token that already has the needed Graph grants.

## Network And Runtime Invariants

- Default runtime base URL before version suffix: `https://graph.microsoft.com`.
- Runtime Graph API version suffix: `/v1.0`.
- Sovereign host support: `https://graph.microsoft.us`.
- Runtime request timeout default: `15000 ms`.
- No runtime retry loop is implemented.
- Manifest operation network policy allows `graph.microsoft.com` and `graph.microsoft.us` on port `443`, requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, caps redirects at zero, and caps response sizes by operation.
- Sandbox profile is `strict`, with `128 MB` memory, `25%` CPU, `30000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.
- Provider 401 maps to unauthorized.
- Provider 404 maps to not found.
- Provider 429 maps to rate limited and honors `Retry-After` seconds, defaulting to 60000 ms when absent.
- Provider 408, 429, 500, 502, 503, and 504 are considered retryable by error mapping.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `outlook.read` | Read messages, search messages, and list mail folders. |
| `outlook.send` | Send mail through Graph sendMail. |
| `outlook.calendar` | List and create events. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `outlook.list_messages` | `GET /me/mailFolders/{folder_id}/messages` | `outlook.read` | `Safe` | `Low` | `Strict` | Reads recent folder messages with a narrow select list. |
| `outlook.get_message` | `GET /me/messages/{message_id}` | `outlook.read` | `Safe` | `Low` | `Strict` | Reads one message, including body and recipients. |
| `outlook.search_messages` | `GET /me/messages?$search=...` | `outlook.read` | `Safe` | `Low` | `Strict` | Searches mailbox messages by phrase. |
| `outlook.send_message` | `POST /me/sendMail` | `outlook.send` | `Risky` | `Medium` | `None` | Sends a new outbound email. |
| `outlook.list_events` | `GET /me/events` | `outlook.calendar` | `Safe` | `Low` | `Strict` | Reads calendar events. |
| `outlook.create_event` | `POST /me/events` | `outlook.calendar` | `Risky` | `Medium` | `None` | Creates a calendar event. |
| `outlook.list_folders` | `GET /me/mailFolders` | `outlook.read` | `Safe` | `Low` | `Strict` | Discovers folder IDs for message listing. |

## Resource URIs

Runtime capability-token verification currently checks capability and operation ID, but passes an empty resource binding list to the verifier. The effective authorization binding is capability plus operation, not a provider resource URI.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| Messages | `outlook://mail/message/{message_id}` |
| Mail folders | `outlook://mail/folder/{folder_id}` |
| Mail search | `outlook://mail/search/{query_hash}` |
| Send mail | `outlook://mail/send/{recipient_hash}` |
| Events | `outlook://calendar/event/{event_id}` |

## Explicit Non-Goals

The current implementation does not include:

- OAuth login, device-code flow, token refresh, app registration, consent automation, or credential-id injection
- Microsoft Graph subscriptions, webhook validation, delta queries, notification ingress, or durable mailbox/event replay
- attachments, MIME sends, drafts, replies, forwards, delete/move/copy message operations, categories, flags, contacts, rules, mailbox settings, calendar groups, attendees, recurrence controls, or free/busy checks
- sovereign hosts beyond `graph.microsoft.us`
- paging through `@odata.nextLink`
- durable storage of messages, events, folders, access tokens, provider responses, or provider error bodies

These are excluded on purpose:

- Mailboxes and calendars contain highly sensitive personal and work data. Reads and writes need narrow zone and capability enforcement before expanding.
- Graph subscriptions and deltas are a broader Microsoft 365 responsibility and are explicitly assigned to `fcp.microsoft365` by the manifest migration hint.
- Send and create operations mutate external state. They should stay narrow until approval and idempotency policy are explicitly implemented.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, `invoke()`, `subscribe()`, `unsubscribe()`, and `shutdown()` are part of the public closeout contract. They surface:

- local configuration, client, graph host, token-present, and uptime state
- live Microsoft Graph folder health through `self_check()`
- operation metadata parsed from the manifest
- simulation authorization using the same capability-token verification path as invoke
- typed provider/FCP error mapping
- streaming-not-supported behavior for subscribe and unsubscribe
- lifecycle reset behavior during configure and shutdown

The deterministic evidence is anchored on connector-local tests covering:

- manifest operation inventory, network policy, schemas, safety tiers, risk levels, and subscription migration hint
- runtime introspection matching manifest metadata
- config parsing, graph host validation, localhost debug fixtures, timeout defaults, and redaction
- path ID encoding, top normalization, Graph API version, search escaping, non-JSON success rejection, and 202 sendMail handling
- bound capability-token verification through invoke and simulate helper paths in connector code tests
- provider error mapping for configuration, API, timeout, rate limit, unauthorized, and not-found cases

## Source Notes

- `connectors/outlook/src/connector.rs` defines lifecycle handlers, diagnostics, manifest-backed introspection, simulation, invoke dispatch, capability verification, and streaming-not-supported behavior.
- `connectors/outlook/src/client.rs` defines Microsoft Graph HTTP request construction, auth headers, endpoint paths, timeout settings, path/query encoding, response parsing, and provider error handling.
- `connectors/outlook/src/types.rs` defines configuration, Graph host validation, defaults, and token redaction.
- `connectors/outlook/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/outlook/src/main.rs` defines the stdio JSON-RPC method loop.
- `connectors/outlook/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, and migration hint.
- `connectors/outlook/tests/provider_contract.rs` contains manifest/provider contract coverage.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/outlook/README.md
LC_ALL=C rg -n '[^ -~]' connectors/outlook/README.md
rg -n '\bmaster\b' connectors/outlook/README.md
ubs connectors/outlook/README.md
```

Cargo/rch is not required for this README-only contract. If source code changes are made, run the relevant connector tests and the workspace verification lane described in the repository `AGENTS.md`.
