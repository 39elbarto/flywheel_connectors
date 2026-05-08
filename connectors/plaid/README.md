# Plaid Connector V3 Contract

> **Status**: runtime contract documented with credential-materialization and approval-token drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Plaid API overview**: https://plaid.com/docs/api/
> **Plaid Link upstream**: https://plaid.com/docs/api/link/
> **Plaid Items upstream**: https://plaid.com/docs/api/items/
> **Plaid Transactions upstream**: https://plaid.com/docs/api/products/transactions/

## Purpose

This document fixes the operator-facing contract for `fcp.plaid`. The connector exposes the Plaid surfaces implemented in this crate: Link token creation, public-token exchange, account reads, balance reads, transaction reads, transaction cursor sync, Auth account-number reads, Identity reads, investment-holding reads, and liability reads.

The connector is intentionally a bounded private-finance data bridge. It is not a Plaid Dashboard automation client, webhook listener, OAuth redirect handler, Plaid Link frontend, institution-search client, Identity Verification backend, Transfer client, Assets client, Signal client, Statements client, payment-initiation client, or durable financial-data synchronization daemon.

## Current Runtime Snapshot

The current crate exposes these operations:

- `plaid.link_token_create`
- `plaid.token_exchange`
- `plaid.accounts_get`
- `plaid.accounts_balance_get`
- `plaid.transactions_get`
- `plaid.transactions_sync`
- `plaid.auth_get`
- `plaid.identity_get`
- `plaid.investments_holdings_get`
- `plaid.liabilities_get`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-plaid`.
- Runtime `BaseConnector` ID is `plaid`.
- Manifest connector ID is `fcp.plaid`.
- Connector version is `0.1.0`.
- Configuration requires `client_id`.
- Configuration requires exactly one auth source:
  - `secret`
  - `credential_id`
- `credential_id` must be a valid UUID.
- `environment` is required and must be `sandbox`, `development`, or `production`.
- Default base URLs are selected from the configured environment:
  - `https://sandbox.plaid.com`
  - `https://development.plaid.com`
  - `https://production.plaid.com`
- Direct-secret mode creates a Plaid client and sends `client_id` plus `secret` in each JSON request body.
- `credential_id` mode records the credential reference but does not materialize a Plaid client in this runtime.
- Runtime base URL normalization rejects empty URLs, invalid URLs, non-HTTP(S) schemes, userinfo, query strings, fragments, nonlocal IP literals, and nonlocal HTTP.
- Runtime configure does not require the URL host to match the selected Plaid environment; doctor checks that separately.
- Runtime reqwest timeout is `30 seconds`.
- Runtime request context timeout is `30 seconds`.
- Runtime retry config sets `max_retries = 2` through the shared retry loop.
- Runtime `invoke` uses `operation`, not `operation_id`.
- Runtime `invoke` requires a serialized `capability_token`.
- Runtime installs a `CapabilityVerifier` during handshake and verifies a bound capability token against the operation and capability before dispatch.
- Runtime does not verify approval tokens, even for operations marked policy-gated in the manifest.
- `simulate` returns an allowed response for the supplied simulation ID and does not validate readiness, operation identity, capability, input schema, approval state, or configured environment.
- `handle_shutdown()` shuts down the client runtime but does not clear configuration, client, verifier, session, configured, or handshaken state.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Plaid's API overview says Plaid is JSON over HTTP, uses POST requests, and accepts `client_id` and `secret` either in the JSON body or in `PLAID-CLIENT-ID` / `PLAID-SECRET` headers. Runtime uses the JSON-body form only.
- Plaid public docs currently list Sandbox and Production API hosts. Runtime also models a `development` environment and `https://development.plaid.com`.
- Manifest says state stores transaction sync cursors, access tokens, and item metadata. Runtime keeps configuration and client state in memory and does not persist access tokens, item metadata, or cursors.
- Manifest marks `plaid.link_token_create`, `plaid.token_exchange`, `plaid.auth_get`, and `plaid.identity_get` as policy-gated. Runtime introspection exposes every operation with `requires_approval = None`, and invoke checks no approval token.
- Manifest and handshake event caps advertise streaming with no replay and a minimum buffer of 100 events. Runtime introspection returns no events and no event caps, and the connector emits no provider event stream.
- Manifest endpoint policy allows only Plaid hosts on port 443 for live operations. Runtime accepts loopback HTTP for deterministic tests and can normalize arbitrary HTTPS hosts; doctor flags environment-host mismatches.
- `credential_id` mode can configure successfully, but runtime health reports `degraded_pending_secret_materialization` and direct Plaid calls are unavailable until a host or egress proxy materializes secret material.
- `self_check` uses `accounts_get("test", None)` in direct-secret mode, so it is a connectivity smoke check rather than a complete account-link proof.
- `doctor` performs a direct `link_token_create` probe in direct-secret mode and skips direct credential validation in `credential_id` mode.
- Runtime `handle_handshake()` does not require prior successful configure.
- Runtime returns a placeholder manifest hash: `sha256:plaid-connector-v1`.
- There is no tracked verification shell script for this connector.

A follow-up parity bead should enforce approval-token semantics, persist or explicitly remove the advertised cursor/access-token state contract, align event-cap advertisement with actual event delivery, enforce endpoint policy at configure time, decide whether `development` remains a first-class environment, and make credential-id materialization a real host-mediated path.

## First-Slice Scope

The current Plaid README slice documents the existing runtime surface:

- direct `client_id` plus `secret` configuration
- host credential-reference configuration and its current materialization gap
- sandbox/development/production endpoint selection
- Link token creation and public-token exchange
- account, balance, transaction, Auth, Identity, investment, and liability reads
- retry, timeout, provider error, readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- runtime/manifest drift around approval policy, state persistence, endpoint policy, event caps, credential IDs, and operation schema
- deterministic WireMock tests and direct proof commands

## Auth And Zone Boundary

- Authentication mechanisms: Plaid `client_id` plus `secret`, or host credential reference.
- Official Plaid API access is tied to Dashboard-issued `client_id` and `secret`.
- Runtime does not implement Plaid Dashboard enrollment, Link frontend initialization, OAuth redirect handling, token rotation, item removal, webhook update, webhook ingestion, or connector-local credential vaulting.
- Home zone: `z:private`.
- Allowed source zones: `z:owner` and `z:private`.
- Allowed target zone: `z:private`.
- Forbidden zones: `z:public`, `z:community`, and `z:work`.
- Handshake grants the capabilities requested by the host and stores a bound-token verifier for the host public key, zone, and connector instance ID.
- Capability families:
  - `plaid.link`
  - `plaid.accounts.read`
  - `plaid.transactions.read`
  - `plaid.auth.read`
  - `plaid.identity.read`
  - `plaid.investments.read`
  - `plaid.liabilities.read`
- Plaid access tokens, account numbers, balances, identity records, transaction histories, investment holdings, and liabilities are private financial data. Do not log raw request bodies, access tokens, account IDs where avoidable, identity payloads, routing/account numbers, balances, transaction names, provider error bodies, or Plaid request IDs in shared artifacts.

## Network And Runtime Invariants

- Default runtime base URL comes from the selected environment.
- Runtime Plaid endpoints:
  - `POST /link/token/create`
  - `POST /item/public_token/exchange`
  - `POST /accounts/get`
  - `POST /accounts/balance/get`
  - `POST /transactions/get`
  - `POST /transactions/sync`
  - `POST /auth/get`
  - `POST /identity/get`
  - `POST /investments/holdings/get`
  - `POST /liabilities/get`
- Runtime request timeout: `30 seconds`.
- Runtime retry policy: `max_retries = 2`.
- Runtime direct-secret mode adds `client_id` and `secret` to every request body.
- Runtime maps 401 and 403 to terminal API-auth failures.
- Runtime maps 429 to a retryable rate-limit error using `Retry-After`, defaulting to 60000 ms.
- Runtime maps 5xx responses to retryable provider errors.
- Runtime maps other non-success responses to terminal provider API errors with Plaid `error_type` and `error_code` when present.
- Manifest live-operation policy requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, and allows only Plaid environment hosts on port 443.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, read-only `/usr` and `/lib`, writable `$CONNECTOR_STATE`, no exec, and no ptrace.
- The connector does not open inbound sockets.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `plaid.link_token_create` | `POST /link/token/create` | `plaid.link` | `Risky` | `Medium` | `None` | `client_name`, `products`, `country_codes`, `language`; optional `user`. |
| `plaid.token_exchange` | `POST /item/public_token/exchange` | `plaid.link` | `Risky` | `High` | `Strict` | `public_token`. |
| `plaid.accounts_get` | `POST /accounts/get` | `plaid.accounts.read` | `Safe` | `Low` | `Strict` | `access_token`; optional `options`. |
| `plaid.accounts_balance_get` | `POST /accounts/balance/get` | `plaid.accounts.read` | `Safe` | `Low` | `Strict` | `access_token`; optional `options`. |
| `plaid.transactions_get` | `POST /transactions/get` | `plaid.transactions.read` | `Safe` | `Low` | `Strict` | `access_token`, `start_date`, `end_date`; optional `options`. |
| `plaid.transactions_sync` | `POST /transactions/sync` | `plaid.transactions.read` | `Safe` | `Low` | `Strict` | `access_token`; optional `cursor`, `count`. |
| `plaid.auth_get` | `POST /auth/get` | `plaid.auth.read` | `Risky` | `High` | `Strict` | `access_token`. |
| `plaid.identity_get` | `POST /identity/get` | `plaid.identity.read` | `Risky` | `High` | `Strict` | `access_token`. |
| `plaid.investments_holdings_get` | `POST /investments/holdings/get` | `plaid.investments.read` | `Safe` | `Low` | `Strict` | `access_token`. |
| `plaid.liabilities_get` | `POST /liabilities/get` | `plaid.liabilities.read` | `Safe` | `Low` | `Strict` | `access_token`. |

## Explicit Non-Goals

The current implementation does not include:

- Plaid Link frontend rendering, hosted Link session handling, or OAuth redirect handling
- `/link/token/get`, `/item/get`, `/item/remove`, `/item/webhook/update`, `/item/access_token/invalidate`, Sandbox public-token creation, or Sandbox webhook firing
- webhook verification, inbound webhook listener, event replay, or durable sync worker
- institution search, institution status, Dashboard automation, product access setup, or account-selection UX
- Transfer, Assets, Signal, Statements, Income, Payment Initiation, Enrich, Identity Verification, Processor tokens, or Plaid Layer operations
- durable storage of Plaid access tokens, item IDs, transaction cursors, account metadata, balances, identity payloads, holdings, or liabilities
- approval-token verification at connector invoke time

These are excluded on purpose:

- Plaid data is regulated, highly sensitive personal financial data.
- `plaid.token_exchange` turns an ephemeral public token into a long-lived access token.
- Auth and Identity surfaces expose account/routing numbers and PII.
- Transaction sync correctness depends on durable cursor persistence and webhook handling that this runtime does not yet implement.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configured auth mode, environment, and endpoint details
- credential-id materialization status
- client initialization status
- environment-host policy checks
- direct-secret validation through a Link token probe
- health status and request/error counters
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- provider error mapping for auth failures, forbidden responses, rate limits, server errors, JSON errors, and transport errors

The deterministic integration evidence is anchored on connector-local tests covering:

- request and response parsing for Link, token exchange, accounts, balances, transaction sync, Auth, Identity, investments, and liabilities
- `transactions_sync` pagination and empty response handling
- full invoke dispatch with bound capability tokens
- wrong-capability rejection and missing capability-token rejection
- missing required input rejection
- provider 401, 403, 429, 500, JSON, and transport behavior
- direct-secret versus credential-id configuration
- health, doctor, self-check, introspection, simulation, shutdown, and endpoint policy behavior

## Source Notes

- `connectors/plaid/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, endpoint policy, introspection, simulation, bound-token invoke verification, operation IDs, and provisioning readiness.
- `connectors/plaid/src/client.rs` defines Plaid HTTP request construction, body auth, retry/timeout behavior, provider paths, and provider error mapping.
- `connectors/plaid/src/types.rs` defines Plaid response and error envelope shapes.
- `connectors/plaid/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/plaid/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, rate-limit pools, and AI hints.
- `connectors/plaid/tests/integration.rs` covers deterministic HTTP behavior and connector-level behavior.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/plaid/README.md
ubs connectors/plaid/README.md
LC_ALL=C rg -n '[^ -~]' connectors/plaid/README.md
rg -n '\bmaster\b' connectors/plaid/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-plaid
rch exec -- cargo check -p fcp-plaid --all-targets
rch exec -- cargo clippy -p fcp-plaid --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Use Plaid Sandbox items and synthetic accounts for live proof.
- Prefer `plaid.transactions_sync` over `plaid.transactions_get` for incremental transaction updates.
- Persist `next_cursor` outside the connector if using live `transactions_sync`; the runtime does not store it.
- Loop on `transactions_sync` until `has_more` is false.
- Do not rely on `simulate` for security decisions.
- Do not rely on approval enforcement until approval-token verification is implemented.
- Treat `credential_id` mode as provisioning metadata until egress-proxy secret materialization is wired.
- Check environment and host alignment before diagnosing Plaid credentials.
- Redact `client_id` where operationally appropriate, all secrets, Plaid access tokens, public tokens, account numbers, routing numbers, names, addresses, emails, phone numbers, balances, liabilities, transaction descriptions, provider payloads, and provider error bodies.
