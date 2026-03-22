# PayPal Connector V3 Contract

> **Status**: implemented first-slice contract
> **Bead**: `flywheel_connectors-j05nu.6.2.1`
> **Unblocks**: `flywheel_connectors-j05nu.6.2.2`
> **Primary upstream**: https://developer.paypal.com/api/rest/

## Purpose

This document fixes the accepted first V3 slice for `fcp.paypal` so the existing runtime and manifest can be judged against a stable contract instead of a vague "PayPal integration" label.

The connector is a single-merchant, single-environment, request-response PayPal REST connector for checkout orders, capture inspection and refunds, invoice creation and sending, transaction reporting, and credential health verification.

## Current Runtime Snapshot

The current crate already exposes these operations:

- `paypal.orders.create`
- `paypal.orders.get`
- `paypal.orders.capture`
- `paypal.payments.list`
- `paypal.payments.get`
- `paypal.payments.refund`
- `paypal.invoices.create`
- `paypal.invoices.list`
- `paypal.invoices.send`
- `paypal.health`

Important implementation truths from `connector.rs`, `client.rs`, and `manifest.toml`:

- Configuration is `client_id`, `client_secret`, `sandbox`, `base_url`, retry policy, and bounded `request_timeout_ms`.
- One connector instance is bound to one PayPal app credential pair and exactly one environment.
- The configured environment and host must match:
  - sandbox -> `https://api-m.sandbox.paypal.com`
  - production -> `https://api-m.paypal.com`
- The live runtime is request-response only. It does not expose webhooks, event streaming, subscriptions, or background sync loops.
- `paypal.payments.list` is backed by `GET /v1/reporting/transactions` with `fields=all`.
- `paypal.health` and `self_check()` are grounded in OAuth token acquisition plus a lightweight orders probe against `GET /v2/checkout/orders?limit=1`.
- The connector currently does not propagate `InvokeRequest.idempotency_key` into PayPal replay-protection headers, so mutating operations are only `BestEffort` for retries even though PayPal supports idempotent POST handling for some APIs.

## Accepted First Slice

The accepted first slice is the currently implemented merchant-scoped REST surface:

- orders: create, get, capture
- payments: reporting list, capture get, capture refund
- invoices: create draft, list, send
- health and self-check

This is intentionally narrower than "all of PayPal". The first slice is meant to expose one truthful merchant credential boundary with clear risk semantics, not every PayPal product family.

## Auth And Scope Boundary

- One connector instance maps to one PayPal merchant context in one environment.
- Authentication is OAuth 2.0 client-credentials using one injected `client_id` and `client_secret`.
- The connector does not run browser login, merchant discovery, delegated user consent, partner onboarding, token refresh orchestration, or cross-merchant brokering.
- The accepted boundary is "single merchant, single environment, direct API credentials". Multi-merchant partner flows using `PayPal-Auth-Assertion` are out of scope.
- Transaction Search docs note that acting on behalf of third parties requires PayPal partner-network enrollment. That delegated pattern is explicitly out of scope for this connector.

## Network And Runtime Invariants

- Production REST host: `api-m.paypal.com`
- Sandbox REST host: `api-m.sandbox.paypal.com`
- TLS and SNI are required for live traffic
- No localhost, private-range, or tailnet overrides are part of the accepted contract
- Runtime is stateless aside from in-memory config, OAuth token cache, and HTTP client state
- No inbound listeners, browser steps, polling daemons, or webhook receivers are part of this slice
- PayPal's current rate-limiting guidance explicitly does not publish stable numeric limits and advises clients not to poll and to cache OAuth tokens
- The manifest rate-limit pools for this connector are therefore connector-side safety budgets, not claims about guaranteed upstream quotas

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `paypal.orders.read` | Read order state and run readiness probes |
| `paypal.orders.write` | Create and capture checkout orders |
| `paypal.payments.read` | List reporting transactions and inspect captures |
| `paypal.payments.write` | Refund captures |
| `paypal.invoices.read` | List merchant invoices |
| `paypal.invoices.write` | Create draft invoices and send them |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `paypal.health` | `GET /v2/checkout/orders?limit=1` | `paypal.orders.read` | `Safe` | `Low` | `Strict` | Auth and reachability probe. A provider `400` still counts as reachable and authenticated in the current runtime. |
| `paypal.orders.create` | `POST /v2/checkout/orders` | `paypal.orders.write` | `Risky` | `High` | `BestEffort` | Creates a real order object. Exact-once retry semantics are not wired through the connector yet. |
| `paypal.orders.get` | `GET /v2/checkout/orders/{order_id}` | `paypal.orders.read` | `Safe` | `Low` | `Strict` | Canonical point lookup for one order ID. |
| `paypal.orders.capture` | `POST /v2/checkout/orders/{order_id}/capture` | `paypal.orders.write` | `Risky` | `Critical` | `BestEffort` | Real-money side effect. Requires interactive approval. |
| `paypal.payments.list` | `GET /v1/reporting/transactions` | `paypal.payments.read` | `Safe` | `Low` | `Strict` | Requires `start_date` and `end_date`. PayPal documents a maximum 31-day window and up to three hours of reporting lag. |
| `paypal.payments.get` | `GET /v2/payments/captures/{capture_id}` | `paypal.payments.read` | `Safe` | `Low` | `Strict` | Canonical point lookup for one capture ID. |
| `paypal.payments.refund` | `POST /v2/payments/captures/{capture_id}/refund` | `paypal.payments.write` | `Risky` | `High` | `BestEffort` | Refunds a completed capture. Can be partial or full. |
| `paypal.invoices.create` | `POST /v2/invoicing/invoices` | `paypal.invoices.write` | `Risky` | `Medium` | `BestEffort` | Creates a draft invoice only. Sending is a separate operation. |
| `paypal.invoices.list` | `GET /v2/invoicing/invoices?page=1&page_size=20` | `paypal.invoices.read` | `Safe` | `Low` | `Strict` | First slice keeps a fixed first-page listing surface. |
| `paypal.invoices.send` | `POST /v2/invoicing/invoices/{invoice_id}/send` | `paypal.invoices.write` | `Risky` | `High` | `BestEffort` | Delivers or schedules an invoice to an external recipient. |

## Explicit Non-Goals

The accepted first slice does not include:

- payouts
- subscriptions, billing plans, or recurring agreements
- disputes or chargeback workflows
- partner onboarding, marketplace delegation, or `PayPal-Auth-Assertion`
- vault or saved payment method flows
- webhook ingestion, event delivery, or streaming
- multi-merchant routing from one connector instance
- order update, authorization void, shipment tracking, or stored-payment approval flows
- invoice reminders, invoice cancellation, invoice templates, or invoice payment recording

These are excluded on purpose. They either expand the trust boundary beyond one direct merchant credential pair or pull in adjacent product families that the first slice does not need.

## Implementation Notes For `flywheel_connectors-j05nu.6.2.2`

- Keep the auth boundary strict: one merchant, one environment, one client credential pair.
- Preserve the current environment validation that rejects mismatched hosts.
- Maintain the current Transaction Search input contract: explicit ISO-8601 `start_date` and `end_date`.
- Do not claim exact-once semantics for mutating operations until `InvokeRequest.idempotency_key` is actually mapped to PayPal replay-protection headers where supported.
- Keep `health` and `self_check()` tied to OAuth token acquisition plus the lightweight orders probe instead of inventing a synthetic connector-only health rule.
- Preserve clear error mapping for `401`, `403`, `404`, `429`, and retryable `5xx` failures.
- Keep the first slice request-response only. Webhooks, subscriptions, and partner delegation are follow-on work, not hidden scope.

## Source Notes

This contract is grounded in the current connector implementation and current PayPal docs:

- `connectors/paypal/src/connector.rs` defines the operation inventory, capability mapping, readiness behavior, and runtime contract details.
- `connectors/paypal/src/client.rs` defines the concrete REST endpoints, OAuth token acquisition, retry handling, and current host assumptions.
- `connectors/paypal/manifest.toml` defines the mechanical network boundary and per-operation metadata that must match the runtime.
- PayPal REST getting started: https://developer.paypal.com/api/rest/
- PayPal idempotency guidance: https://developer.paypal.com/api/rest/reference/idempotency/
- PayPal rate-limiting guidance: https://developer.paypal.com/api/rest/reference/rate-limiting/
- PayPal Transaction Search API: https://developer.paypal.com/docs/api/transaction-search/v1/
- PayPal Invoicing API v2: https://developer.paypal.com/docs/api/invoicing/v2/
