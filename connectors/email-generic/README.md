# Generic Email Connector V1 Contract

> **Status**: IMAP/SMTP runtime contract documented with inbound-monitor deferral and acceptance-gap boundary
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **IMAP upstream**: https://datatracker.ietf.org/doc/html/rfc3501
> **SMTP upstream**: https://datatracker.ietf.org/doc/html/rfc5321
> **SMTP STARTTLS upstream**: https://datatracker.ietf.org/doc/html/rfc3207

## Purpose

This document fixes the operator-facing contract for `fcp.email-generic`. The connector exposes the generic email surface currently implemented in this crate: local connector health metadata, IMAP mailbox listing, IMAP UID search, SMTP message sending, and redacted inbound-monitor policy configuration for one configured IMAP account and one configured SMTP identity.

The connector is intentionally a minimal IMAP/SMTP adapter. It is not a Gmail or Microsoft Graph client, OAuth client, mailbox synchronization engine, MIME parser, attachment fetcher, delivery-status tracker, inbound event stream, spam classifier, rules engine, address book client, calendar client, or generic mail-admin tool.

## Current Runtime Snapshot

The current crate exposes these runtime operation IDs:

- `email_generic.health`
- `email_generic.list_mailboxes`
- `email_generic.search_messages`
- `email_generic.send_message`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-email-generic`.
- Runtime and manifest connector ID are `fcp.email-generic`.
- Configuration requires `imap.host`, `imap.username`, `imap.password`, `smtp.host`, `smtp.username`, `smtp.password`, and `smtp.from_address`.
- `imap.port` defaults to `993`.
- `imap.tls` defaults to `true`.
- `smtp.port` defaults to `587`.
- `smtp.starttls` defaults to `true`.
- `smtp.from_name` is optional.
- `request_timeout_ms` defaults to `15000` and must be greater than zero.
- Debug output redacts IMAP and SMTP passwords.
- The IMAP client uses a direct TCP stream, optional TLS, explicit read/write timeouts, `LOGIN`, `LIST`, `SELECT`, `UID SEARCH TEXT`, and `LOGOUT`.
- The SMTP client uses `lettre`, configured credentials, optional STARTTLS relay mode, and plain message bodies.
- `health()` is local readiness state and does not prove IMAP reachability.
- The `email_generic.health` invoke operation returns local metadata, redacted monitor policy, and inbound monitor deferral state.
- `self_check()` calls the client health path, which logs in to IMAP and lists mailboxes.
- Runtime computes `manifest_hash` from `manifest.toml`.
- Runtime `invoke` verifies a bound capability token before provider dispatch.
- Runtime `simulate` uses the same capability verifier and reports missing capabilities when appropriate.
- Runtime `subscribe()` and `unsubscribe()` return `StreamingNotSupported`.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- The manifest operation keys are unprefixed suffixes such as `health`; runtime operation IDs are fully qualified IDs such as `email_generic.health`.
- The manifest summary says health reports IMAP reachability, while runtime `health()` and `email_generic.health` report local state; `self_check()` is the IMAP reachability probe.
- The manifest defers exact host constraints to runtime configuration because IMAP and SMTP hosts may be public, private, or tailnet infrastructure.
- The manifest requires `network.outbound`, while many newer connector contracts use `network.egress`; this README documents the current manifest as-is.
- The inbound monitor is deferred. Policy helpers exist for sender allowlists, automated sender suppression, body bounds, UID cache, attachment classification, and thread metadata, but no supervised poller emits FCP events today.
- There is no connector-local `tests/` directory and no tracked acceptance shell script for this connector.
- Existing evidence is unit-test heavy; project coverage inventory still classifies `email-generic` as unit-only with no acceptance path.
- IMAP parsing is intentionally narrow and does not implement full RFC 3501 mailbox, literal, BODYSTRUCTURE, MIME, or flag handling.

A follow-up parity bead should add deterministic local IMAP/SMTP fixture tests or classify this connector as requiring a live mail fixture, add a tracked verification bundle, decide whether inbound polling belongs here, and align health terminology with the actual self-check boundary.

## First-Slice Scope

The current Generic Email README slice documents the existing runtime surface:

- IMAP and SMTP credential configuration
- local health metadata and IMAP-backed self-check behavior
- mailbox listing, message UID search, and SMTP send operations
- redacted inbound monitor policy helpers and deferred event stream
- bound capability-token enforcement for read and write operations
- doctor, health, self-check, introspect, simulate, shutdown, and non-streaming posture
- drift around host constraints, health wording, inbound monitor deferral, and missing acceptance verification

## Auth And Scope Boundary

- Authentication mechanism: IMAP username/password plus SMTP username/password.
- Runtime does not implement OAuth, XOAUTH2, SASL mechanism selection, client certificates, password vault lookup, shared credential references, secret rotation, or connector-local credential persistence.
- Home zone: `z:private`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zones: `z:private` and `z:work`.
- Tailscale tag hint: `tag:fcp-private`.
- Capability families:
  - `email_generic.read` gates health metadata, mailbox listing, and message search.
  - `email_generic.write` gates SMTP sends.
- Required capabilities: `network.dns` and `network.outbound`.
- Forbidden capabilities: `system.exec`, `system.privileged`, and `network.listen`.
- Email addresses, mailbox names, UID search queries, message subjects, message bodies, headers, message IDs, thread references, SMTP recipients, provider error strings, IMAP/SMTP hosts, and credentials are sensitive private or work data. Redact them before sharing evidence.

## Network And Runtime Invariants

- IMAP endpoint is the configured `imap.host:imap.port`.
- SMTP endpoint is the configured `smtp.host:smtp.port`.
- IMAP TLS is enabled by default and uses `native_tls`.
- SMTP STARTTLS relay mode is enabled by default through `lettre::SmtpTransport::relay`.
- SMTP plaintext builder mode is used only when `smtp.starttls=false`.
- IMAP values are quoted and backslash/quote escaped before command construction.
- `list_mailboxes` sends `LIST "" "*"`.
- `search_messages` sends `SELECT "<mailbox>"` followed by `UID SEARCH TEXT "<query>"`.
- `search_messages` rejects blank mailbox or query before sending IMAP commands.
- `send_message` requires at least one `to` recipient.
- `send_message` parses `smtp.from_address`, `to`, and `cc` through `lettre` address parsing before dispatch.
- `send_message` sends plain body text and does not include attachments.
- IO errors map to retryable external FCP errors; IMAP and SMTP protocol errors map to non-retryable external FCP errors.
- TLS errors currently map to internal FCP errors.
- Sandbox profile is `strict`, with `96 MB` memory, `25%` CPU, `30000 ms` wall-clock timeout, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Inbound Monitor Policy Helpers

The inbound monitor is not active, but these policy helpers are implemented and documented for future event work:

- `allowed_senders` accepts an array or comma-separated string and is normalized before use.
- `require_allowed_sender` defaults to `true`.
- `drop_automated` defaults to `true`.
- `allow_attachments` defaults to `false`.
- `poll_interval_secs` defaults to `15` and must be between `1` and `3600`.
- `max_body_chars` defaults to `50000` and must be between `1` and `1000000`.
- `seen_uid_cap` defaults to `2000` and must be between `1` and `100000`.
- `allowed_senders` is capped at `512` entries and rejects duplicates after normalization.
- Automated sender detection checks sender patterns and common automated-message headers.
- Prepared inbound previews are marked `tainted`, bound body length, classify attachments, and carry thread reply metadata only when policy accepts the message.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `email_generic.read` | Read local health metadata, list IMAP mailboxes, and search messages by UID. |
| `email_generic.write` | Send email through the configured SMTP identity. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `email_generic.health` | local readiness plus monitor policy metadata | `email_generic.read` | `Safe` | `Low` | `Strict` | None. |
| `email_generic.list_mailboxes` | IMAP `LIST "" "*"` | `email_generic.read` | `Safe` | `Low` | `Strict` | None. |
| `email_generic.search_messages` | IMAP `SELECT` plus `UID SEARCH TEXT` | `email_generic.read` | `Safe` | `Low` | `Strict` | `mailbox`, `query`. |
| `email_generic.send_message` | SMTP message submission | `email_generic.write` | `Risky` | `Medium` | `None` | `to`, `subject`, `body`; optional `cc`. |

## Explicit Non-Goals

The current implementation does not include:

- Gmail API, Microsoft Graph, Exchange Web Services, JMAP, POP3, NNTP, CalDAV, CardDAV, or provider-specific APIs
- OAuth, XOAUTH2, SASL mechanism negotiation, app-password provisioning, password vault integration, or secret rotation
- MIME parsing, HTML rendering, attachment fetch, attachment send, inline image handling, DKIM signing, S/MIME, PGP, or spam/phishing analysis
- message fetch by UID, full body retrieval, flag mutation, folder creation, folder deletion, move/copy/delete, draft handling, or delivery status tracking
- inbound polling, streaming events, webhook delivery, replay buffers, acknowledgements, or durable UID state
- address book lookup, contact dedupe, calendar invite parsing, unsubscribe handling, or auto-reply generation

These are excluded on purpose:

- Generic email accounts can expose private and work-sensitive content with minimal provider-side boundaries.
- Sending email has external side effects and poor idempotency semantics.
- Provider-specific auth and setup flows belong in dedicated provider connectors or setup surfaces.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, and `introspect()` are part of the public closeout contract. They surface:

- configured state, IMAP host, SMTP host, manifest hash, uptime, monitor policy redacted state, and inbound monitor deferral state
- operation catalog, schemas, capabilities, risk levels, safety tiers, idempotency classes, examples, and AI hints
- IMAP mailbox-list reachability through `self_check()`
- bound capability-token acceptance and denial in both `invoke` and `simulate`
- specific degraded state when the connector is not configured
- non-streaming event capabilities and unsupported subscribe/unsubscribe behavior

The deterministic evidence currently covers:

- configuration validation and default values
- password debug redaction
- IMAP quoted-string escaping, mailbox parsing, and UID parsing
- monitor policy normalization, duplicate rejection, sender evaluation, automated sender dropping, body bounding, attachment classification, and seen-UID cache bounds
- operation inventory, manifest/introspection shape, capability assignment, handshake grants, doctor/health/self-check/shutdown behavior, and invoke health behavior
- error mapping for configuration, IMAP, SMTP, IO, TLS, and address errors

The acceptance gap remains real: no checked-in local IMAP/SMTP fixture suite or shell verification bundle exists for this connector today.

## Source Notes

- `connectors/email-generic/src/types.rs` defines configuration, monitor policy, inbound preview policy, redacted state, attachment classification, and seen-UID cache behavior.
- `connectors/email-generic/src/client.rs` defines IMAP command construction, IMAP parsing, SMTP message submission, TLS/STARTTLS behavior, and address parsing.
- `connectors/email-generic/src/connector.rs` defines lifecycle handlers, capability-token enforcement, operation metadata, diagnostics, simulate behavior, and non-streaming posture.
- `connectors/email-generic/src/error.rs` defines provider/FCP error mapping and retry classification.
- `connectors/email-generic/manifest.toml` defines the operation catalog, capability families, zone policy, sandbox boundary, and runtime-host deferral note.
- Inline `#[cfg(test)]` coverage in the source files is the current local proof surface.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/email-generic/README.md
ubs connectors/email-generic/README.md
LC_ALL=C rg -n '[^ -~]' connectors/email-generic/README.md
rg -n '\bmaster\b' connectors/email-generic/README.md
```

For source or behavior changes, use an `rch`-offloaded connector proof lane:

```bash
fwc manifest fix connectors/email-generic/manifest.toml --check --json
rch exec -- cargo fmt --manifest-path connectors/email-generic/Cargo.toml --check
rch exec -- cargo check -p fcp-email-generic --all-targets
rch exec -- cargo test -p fcp-email-generic -- --nocapture
rch exec -- cargo clippy -p fcp-email-generic --all-targets -- -D warnings
```

There is no tracked `scripts/e2e/email_generic_connector_verification.sh` in this checkout. Add one with local IMAP/SMTP fixtures before claiming a full acceptance bundle.

## Operator Guidance

Prerequisites:

- Provide an IMAP host, IMAP username, IMAP password, SMTP host, SMTP username, SMTP password, and SMTP from address.
- Prefer TLS for IMAP and STARTTLS for SMTP.
- Use a disposable test mailbox for proof.

Dedicated environment:

- Prefer a local deterministic IMAP/SMTP fixture before testing against a live mailbox.
- Use an isolated sending account and non-production recipients for SMTP proof.
- Keep search queries synthetic in archived evidence.

Redaction rules:

- Redact IMAP and SMTP passwords, usernames, hostnames when sensitive, mailbox names, search queries, message UIDs, subjects, bodies, recipients, sender addresses, message IDs, thread references, provider error strings, and raw protocol logs.

Common remediation:

- If `configure` fails, verify nonblank hosts, credentials, `smtp.from_address`, and positive `request_timeout_ms`.
- If `self_check` fails, verify IMAP host/port reachability, TLS mode, username/password, and mailbox permissions.
- If `list_mailboxes` fails after login, inspect IMAP server capabilities and mailbox namespace behavior.
- If `search_messages` rejects input, provide nonblank `mailbox` and `query`.
- If `send_message` rejects recipients, validate `to`, `cc`, and `smtp.from_address` syntax through the target SMTP provider.
- If `simulate` reports missing capabilities, mint a bound token for `email_generic.read` or `email_generic.write` according to the operation.

Rerun commands:

- `git diff --check -- connectors/email-generic/README.md`
- `ubs connectors/email-generic/README.md`
- `rch exec -- cargo test -p fcp-email-generic -- --nocapture`
