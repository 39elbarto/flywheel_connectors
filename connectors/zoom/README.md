# Zoom Connector V3 Guide

> **Status**: implementation-reviewed and verification-oriented
> **Beads**: `flywheel_connectors-j05nu.5.5.1`, `flywheel_connectors-j05nu.5.5.2`, `flywheel_connectors-j05nu.5.5.3`
> **Verification script**: `scripts/e2e/zoom_connector_verification.sh`

## Purpose

`fcp.zoom` is a request-response Zoom Meetings connector for one account-scoped
Server-to-Server OAuth application. It is designed for deterministic operational
workflows around meetings, users, recordings, webinar inventory, and connector
health checks.

This first slice is intentionally narrow. It is not a general Zoom admin
surface, chat connector, phone connector, webhook receiver, or event-streaming
runtime.

## Current Runtime Surface

The current implementation exposes these operations:

- `zoom.meetings.list`
- `zoom.meetings.get`
- `zoom.meetings.create`
- `zoom.meetings.update`
- `zoom.meetings.delete`
- `zoom.users.list`
- `zoom.users.get`
- `zoom.recordings.list`
- `zoom.webinars.list`
- `zoom.health`

## Runtime Truths

- Auth is Zoom Server-to-Server OAuth with `account_id`, `client_id`, and `client_secret`.
- OAuth token exchange targets `zoom.us`; API calls target `api.zoom.us`.
- The connector is request-response only. There is no streaming, replay, or subscription support.
- Webinar support is inventory-only in the current slice. Webinar create, update, and delete are out of scope.
- Recording support is read-only inventory. Recording delete, recover, and download mutation flows are out of scope.
- Dangerous mutation semantics are limited to `zoom.meetings.delete`, which remains interactive-approval metadata in introspection.

## Scope Boundary

In scope:

- account-level user inventory
- meeting read and mutation workflows
- recording inventory reads
- webinar inventory reads
- readiness and health checks

Out of scope:

- Zoom Chat, Phone, Whiteboard, Docs, Reports, Admin, or billing APIs
- webinar mutation workflows
- recording deletion or recovery
- webhook receiver setup or event delivery
- multi-account orchestration from one connector instance

## Capability Mapping

| Capability | Operations |
|------------|------------|
| `zoom.meetings.read` | `zoom.meetings.list`, `zoom.meetings.get` |
| `zoom.meetings.write` | `zoom.meetings.create`, `zoom.meetings.update`, `zoom.meetings.delete` |
| `zoom.users.read` | `zoom.users.list`, `zoom.users.get`, `zoom.health` |
| `zoom.recordings.read` | `zoom.recordings.list` |
| `zoom.webinars.read` | `zoom.webinars.list` |

## Verification Bundle

The readiness closeout is anchored on `scripts/e2e/zoom_connector_verification.sh`.
It writes replayable artifacts under `artifacts/e2e/zoom_connector/<timestamp>`.

The bundle captures:

- manifest validation for `connectors/zoom/manifest.toml`
- `cargo check -p fcp-zoom --all-targets`
- crate-local rustfmt verification
- targeted readiness evidence for `health`, `doctor`, `self_check`, pagination, and dangerous meeting deletion
- typed introspection compliance evidence
- the Zoom integration suite and full crate test suite
- `cargo clippy -p fcp-zoom --all-targets -- -D warnings`

## Operator Guidance

Prerequisites:

- Create a Zoom Server-to-Server OAuth app for the target account with account-level scopes for meetings, users, recordings, and webinars.
- Use a dedicated Zoom sandbox account or disposable users, meetings, and webinars for live verification.
- Ensure outbound TLS access to both `zoom.us` and `api.zoom.us`.

Dedicated environment:

- Never run the verification bundle against production meetings or customer-facing webinars. `zoom.meetings.create`, `zoom.meetings.update`, and `zoom.meetings.delete` mutate real Zoom state.

Redaction rules:

- Redact `account_id`, `client_id`, `client_secret`, bearer tokens, and Authorization headers.
- Redact meeting IDs, webinar IDs, join URLs, start URLs, user emails, and recording download URLs before sharing artifacts.
- Replace real agenda text, participant-facing metadata, and account identifiers with sanitized fixtures if artifacts leave the local machine.

Common remediation:

- If OAuth token exchange returns 401, verify that `account_id`, `client_id`, and `client_secret` belong to the same Server-to-Server OAuth app.
- If Zoom API calls return 401 or 403, confirm the app has the required account-level scopes and has been installed for the account.
- If self-check degrades on 429, wait for the provider backoff window and rerun the bundle after the indicated Retry-After delay.
- If doctor flags invalid host overrides, use the default Zoom hosts for live runs or localhost-only overrides for deterministic wiremock verification.

Rerun commands:

- `scripts/e2e/zoom_connector_verification.sh`
- `fwc manifest fix connectors/zoom/manifest.toml --check --json`
- `cargo fmt --manifest-path connectors/zoom/Cargo.toml --check`
- `rch exec -- cargo check -p fcp-zoom --all-targets`
- `rch exec -- cargo test -p fcp-zoom --test integration -- --nocapture`
- `rch exec -- cargo test -p fcp-zoom -- --nocapture`
- `rch exec -- cargo clippy -p fcp-zoom --all-targets -- -D warnings`
