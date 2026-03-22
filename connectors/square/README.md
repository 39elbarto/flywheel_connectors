# Square Connector V3 Contract

> **Status**: implementation-reviewed contract
> **Bead**: `flywheel_connectors-j05nu.6.3.1`
> **Unblocks**: `flywheel_connectors-j05nu.6.3.2`
> **Primary upstream**: https://developer.squareup.com/reference/square

## Purpose

This document fixes the accepted first V3 slice for `fcp.square` so the existing runtime and manifest can be judged against a stable contract instead of a generic "Square integration" label.

The connector is a merchant-scoped request-response Square REST connector for payments, refunds, orders, catalog reads, customer reads, location discovery, and connectivity verification.

## Current Runtime Snapshot

The current crate already exposes these operations:

- `square.payments.list`
- `square.payments.get`
- `square.payments.create`
- `square.payments.refund`
- `square.orders.list`
- `square.orders.get`
- `square.orders.create`
- `square.catalog.list`
- `square.customers.list`
- `square.customers.get`
- `square.locations.list`
- `square.health`

Important truths from `connector.rs`, `client.rs`, and `manifest.toml`:

- Configuration is `base_url`, `access_token`, retry policy, and bounded `request_timeout_ms`.
- One connector instance is bound to one injected Square bearer token.
- The token can be a personal access token or a seller OAuth token that was provisioned out of band.
- The live runtime is request-response only. It does not expose webhook ingest, event streaming, or long-lived subscriptions.
- The connector is merchant-scoped, but location-sensitive workflows still matter. `square.orders.list` requires explicit `location_ids`, `square.orders.create` requires one `location_id`, and `square.payments.create` can optionally rely on Square's main-location default if `location_id` is omitted.
- `square.health` and `self_check()` are tied to the Locations API, which makes location visibility part of the readiness boundary.
- The current implementation already excludes invoice operations, inventory adjustments, catalog mutation, customer mutation, and OAuth installation flows.

## Accepted First Slice

The accepted first slice is the currently implemented merchant-scoped REST surface:

- payments: list, get, create, refund
- orders: list, get, create
- catalog: list
- customers: list, get
- locations: list
- health and self-check

This is intentionally narrower than "all of Square commerce". The point of the first slice is to expose one truthful seller-token boundary with clear risk semantics, not to model every Square product family.

## Auth And Scope Boundary

- One connector instance maps to one Square seller boundary.
- Accepted credentials are:
  - a production or sandbox personal access token
  - a production or sandbox seller OAuth access token obtained outside the connector
- The connector does not run OAuth install, code exchange, refresh, revocation, or merchant discovery workflows.
- Token environment and API base URL must match:
  - production token -> `https://connect.squareup.com/v2`
  - sandbox token -> `https://connect.squareupsandbox.com/v2`
- Merchant scope and location scope are related but not identical:
  - the token identifies the seller boundary
  - many operations still require explicit `location_id` or `location_ids`
  - Square's Locations docs note that some APIs such as `CreatePayment` use the seller's main location if a location is omitted

## Network And Runtime Invariants

- Production REST base URL: `https://connect.squareup.com/v2`
- Sandbox REST base URL: `https://connect.squareupsandbox.com/v2`
- TLS and SNI are required for live traffic
- No localhost override is part of the accepted contract
- Runtime is stateless aside from in-memory configuration and HTTP client state
- No inbound listeners, browser steps, or webhook receivers are part of this slice

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `square.locations.read` | Read the visible seller locations and run readiness probes |
| `square.payments.read` | List and inspect payments |
| `square.payments.write` | Create payments and refunds |
| `square.orders.read` | Search and inspect orders |
| `square.orders.write` | Create orders |
| `square.catalog.read` | List catalog objects |
| `square.customers.read` | List and inspect customer records |

## Accepted Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Notes |
|-----------|----------------|------------|------------|-----------|-------------|-------|
| `square.health` | `GET /locations` | `square.locations.read` | `Safe` | `Low` | `Strict` | Auth and reachability probe tied to seller-visible locations. |
| `square.locations.list` | `GET /locations` | `square.locations.read` | `Safe` | `Low` | `Strict` | Enumerates visible business locations for downstream workflows. |
| `square.payments.list` | `GET /payments` | `square.payments.read` | `Safe` | `Low` | `Strict` | Optional cursor and location filter. |
| `square.payments.get` | `GET /payments/{payment_id}` | `square.payments.read` | `Safe` | `Low` | `Strict` | Canonical point lookup. |
| `square.payments.create` | `POST /payments` | `square.payments.write` | `Risky` | `High` | `Strict` | Real-money side effects; requires interactive approval. |
| `square.payments.refund` | `POST /refunds` | `square.payments.write` | `Risky` | `High` | `Strict` | Real-money reversal; requires interactive approval. |
| `square.orders.list` | `POST /orders/search` | `square.orders.read` | `Safe` | `Low` | `Strict` | Requires explicit `location_ids`. |
| `square.orders.get` | `GET /orders/{order_id}` | `square.orders.read` | `Safe` | `Low` | `Strict` | Canonical point lookup. |
| `square.orders.create` | `POST /orders` | `square.orders.write` | `Risky` | `Medium` | `BestEffort` | Creates a real order record for one location. |
| `square.catalog.list` | `GET /catalog/list` | `square.catalog.read` | `Safe` | `Low` | `Strict` | Read-only catalog enumeration. |
| `square.customers.list` | `GET /customers` | `square.customers.read` | `Safe` | `Low` | `Strict` | Read-only customer listing inside one seller boundary. |
| `square.customers.get` | `GET /customers/{customer_id}` | `square.customers.read` | `Safe` | `Low` | `Strict` | Point lookup for one customer profile. |

## Explicit Non-Goals

The accepted first slice does not include:

- invoices
- customer creation or update
- order update, fulfillment orchestration, or cancellation
- catalog upsert, image management, or inventory adjustment
- gift cards, terminal flows, disputes, payouts, subscriptions, loyalty, or staff workflows
- webhook ingestion, events, or streaming
- OAuth install, refresh, revocation, or cross-merchant brokering

Invoices are explicitly out of scope for the first slice even though Square supports them. Square's current Invoices docs require additional OAuth permissions such as `INVOICES_READ`, `INVOICES_WRITE`, `ORDERS_WRITE`, and in some flows `CUSTOMERS_READ` plus `PAYMENTS_WRITE`. That is a coupled surface area we are intentionally not collapsing into the first merchant-token contract.

## Source Notes

This contract is grounded in the current connector implementation and current Square docs:

- `connectors/square/src/connector.rs` defines the operation inventory, capability mapping, safety semantics, and readiness behavior.
- `connectors/square/src/client.rs` defines the concrete REST endpoints and confirms the one-bearer-token request model.
- `connectors/square/manifest.toml` defines the network allowlist and current non-goal boundary.
- Square access tokens and environment mapping: https://developer.squareup.com/docs/build-basics/access-tokens
- Square Sandbox overview: https://developer.squareup.com/docs/devtools/sandbox/overview
- Square OAuth overview: https://developer.squareup.com/docs/oauth-api/overview
- Square Payments overview: https://developer.squareup.com/docs/payments-api/overview
- Square Locations API docs: https://developer.squareup.com/docs/locations-api
- Square Customers API workflows: https://developer.squareup.com/docs/customers-api/how-it-works
- Square Invoices API overview: https://developer.squareup.com/docs/invoices-api/overview
