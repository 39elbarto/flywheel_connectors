# Shopify Connector V3 Contract

> **Status**: runtime contract documented with single-shop REST Admin scope and legacy-API drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Shopify REST Admin upstream**: https://shopify.dev/docs/api/admin-rest
> **Shopify GraphQL Admin upstream**: https://shopify.dev/docs/api/admin-graphql/latest
> **Shopify API auth upstream**: https://shopify.dev/docs/api/usage/authentication
> **Shopify access scopes upstream**: https://shopify.dev/docs/api/usage/access-scopes

## Purpose

This document fixes the operator-facing contract for `fcp.shopify`. The current implementation is a single-shop Shopify Admin REST connector for product reads/writes, order reads and order creation, customer reads, inventory-level reads, and a `/shop.json` health probe.

The connector is intentionally a bounded Shopify store-administration bridge. It is not a multi-shop app runtime, Shopify OAuth install flow, GraphQL Admin API client, Storefront API client, webhook receiver, fulfillment-orchestration engine, payment/checkout client, bulk catalog sync worker, or connector-local credential vault.

## Current Runtime Snapshot

The current crate exposes these operations:

- `shopify.products.list`
- `shopify.products.get`
- `shopify.products.create`
- `shopify.products.update`
- `shopify.products.delete`
- `shopify.orders.list`
- `shopify.orders.get`
- `shopify.orders.create`
- `shopify.customers.list`
- `shopify.customers.get`
- `shopify.inventory.list`
- `shopify.health`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-shopify`.
- Runtime, manifest, and handshake connector ID are `fcp.shopify`.
- Connector version is `0.1.0`.
- Configuration requires `shop_domain`.
- `shop_domain` must be a bare hostname ending in `.myshopify.com`.
- Configuration requires exactly one auth source:
  - `access_token`
  - `credential_id`
- `credential_id` must be a valid UUID.
- Default API version is `2026-01`.
- `api_version` must look like `YYYY-MM`.
- Default request timeout is `30000 ms`.
- Runtime base URL shape is `https://{shop_domain}/admin/api/{api_version}`.
- Direct-token mode sends `X-Shopify-Access-Token: <token>`.
- `credential_id` mode sends `X-FCP-Credential-ID: <uuid>`.
- Runtime uses the shared retry loop with the configured `retry` object.
- Runtime config supports custom `request_timeout_ms` and `retry`.
- Runtime implements the `FcpConnector` trait surface, not the older JSON method surface.
- Runtime `invoke` uses `operation`, not `operation_id`.
- Runtime installs a `CapabilityVerifier` during handshake and verifies a bound capability token against the operation and capability before dispatch.
- Runtime `simulate` validates operation identity, required input shape, readiness, handshake verifier state, and bound capability token.
- Runtime operation metadata marks product/order writes as `ApprovalMode::Interactive`, but runtime invoke does not inspect `approval_tokens`.
- `self_check` performs a live `/shop.json` probe.
- `doctor()` is local-only and does not call Shopify.
- `subscribe` and `unsubscribe` return `StreamingNotSupported`.
- `shutdown()` shuts down the runtime and clears runtime, client, config, verifier, configured, and handshaken state.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Shopify documents the REST Admin API as legacy upstream and points new development toward the GraphQL Admin API. Runtime intentionally uses REST Admin endpoints for this first slice.
- Shopify GraphQL Admin API requests use `X-Shopify-Access-Token` and can return HTTP 200 with GraphQL errors in the response body. Runtime is REST-only and uses HTTP status/error handling, not GraphQL `errors` or `userErrors`.
- Runtime handles exactly one shop/app install per connector instance. It does not perform OAuth install, token exchange, session-token verification, or multi-shop fan-out.
- Runtime list operations return only the first fixed page with `limit=50`. They do not expose cursor pagination, `page_info`, filters, bulk operations, or reconciliation jobs.
- Runtime order reads are limited by the configured Shopify app scopes. Historical order access beyond Shopify's normal window requires the upstream `read_all_orders` scope.
- Runtime order creation creates an order record. It does not run checkout, charge payment, manage fulfillment, or perform fraud/risk review.
- Runtime product delete is destructive and marked interactive in metadata, but invoke does not verify approval tokens.
- Manifest state model is stateless and runtime keeps no durable state beyond process memory.
- Manifest format is `native`, while many older connector slices are WASI-formatted.
- Runtime health/self-check can verify `/shop.json`, but this does not prove every optional product/order/customer/inventory scope is granted.
- Runtime credential-id mode depends on a host or egress proxy to materialize `X-Shopify-Access-Token` semantics upstream.
- There is no tracked verification shell script for this connector.

A follow-up parity bead should migrate or intentionally defer GraphQL Admin coverage, add approval-token enforcement for writes and deletes, add cursor pagination or document fixed-page limits in host policy, add fulfillment/webhook follow-up beads, verify credential-id egress materialization end to end, and decide whether Storefront API belongs in a separate connector.

## First-Slice Scope

The current Shopify README slice documents the existing runtime surface:

- single-shop `.myshopify.com` configuration
- direct Admin API access-token mode and host credential-reference mode
- API version, timeout, retry, base URL, and header behavior
- product, order, customer, inventory, and health operations
- live self-check, local doctor, FCP handshake, capability-token verification, simulation, invoke, subscribe/unsubscribe, and shutdown behavior
- runtime/upstream drift around REST legacy status, GraphQL Admin non-coverage, OAuth non-coverage, pagination, approval tokens, fulfillment, webhooks, and scope boundaries
- deterministic WireMock tests and direct proof commands

## Auth And Zone Boundary

- Authentication mechanisms: Shopify Admin API access token or host credential reference.
- Official Shopify Admin API access uses `X-Shopify-Access-Token` for REST and GraphQL Admin calls.
- Runtime does not implement Shopify OAuth installation, client-credentials grant, session-token auth, Storefront API tokens, public/private storefront tokens, delegated access tokens, or connector-local credential vaulting.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Capability families:
  - `shopify.products.read`
  - `shopify.products.write`
  - `shopify.orders.read`
  - `shopify.orders.write`
  - `shopify.customers.read`
  - `shopify.inventory.read`
- Shopify products, orders, customers, inventory levels, email addresses, order totals, SKUs, and shop metadata are work-zone commerce data. Do not log access tokens, order/customer PII, financial status, line items, product draft data, inventory counts, raw provider error bodies, or webhook-like payloads in shared artifacts.

## Network And Runtime Invariants

- Runtime base URL shape: `https://{shop_domain}/admin/api/{api_version}`.
- Default API version: `2026-01`.
- Default list limit: `50`.
- Default request timeout: `30000 ms`.
- Runtime auth:
  - `access_token` uses `X-Shopify-Access-Token`.
  - `credential_id` uses `X-FCP-Credential-ID`.
- Runtime endpoint paths:
  - `GET /shop.json`
  - `GET /products.json?limit=50`
  - `GET /products/{product_id}.json`
  - `POST /products.json`
  - `PUT /products/{product_id}.json`
  - `DELETE /products/{product_id}.json`
  - `GET /orders.json?status=any&limit=50`
  - `GET /orders/{order_id}.json`
  - `POST /orders.json`
  - `GET /customers.json?limit=50`
  - `GET /customers/{customer_id}.json`
  - `GET /inventory_levels.json?location_ids={location_id}`
- Runtime wraps product, order, customer, inventory, and shop JSON in Shopify's REST response envelopes.
- Runtime passes `X-Shopify-Idempotency-Key` on product create/update and order create when `InvokeRequest.idempotency_key` is present.
- Runtime maps 401 and 403 to unauthorized, 404 to not found, 429 to retryable rate limit using `Retry-After` with a 2 second default, 5xx to retryable API errors, and other non-success statuses to terminal API errors.
- Runtime parses `Retry-After` as either delta seconds or HTTP-date.
- Manifest live-operation policy pins all operations to `$shop_domain` port 443, denies localhost, private ranges, tailnet ranges, and IP literals, and uses zero redirects.
- The connector is `native`; it does not declare the strict WASI sandbox profile used by many other connectors.
- The connector does not open inbound sockets.

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Required input |
|-----------|----------------|------------|------------|-----------|-------------|----------------|
| `shopify.products.list` | `GET /products.json?limit=50` | `shopify.products.read` | `Safe` | `Low` | `Strict` | None. |
| `shopify.products.get` | `GET /products/{product_id}.json` | `shopify.products.read` | `Safe` | `Low` | `Strict` | `product_id`. |
| `shopify.products.create` | `POST /products.json` | `shopify.products.write` | `Risky` | `Medium` | `None` | `title`; optional product fields and variants. |
| `shopify.products.update` | `PUT /products/{product_id}.json` | `shopify.products.write` | `Risky` | `Medium` | `BestEffort` | `product_id`; optional product fields. |
| `shopify.products.delete` | `DELETE /products/{product_id}.json` | `shopify.products.write` | `Dangerous` | `High` | `Strict` | `product_id`. |
| `shopify.orders.list` | `GET /orders.json?status=any&limit=50` | `shopify.orders.read` | `Safe` | `Low` | `Strict` | None. |
| `shopify.orders.get` | `GET /orders/{order_id}.json` | `shopify.orders.read` | `Safe` | `Low` | `Strict` | `order_id`. |
| `shopify.orders.create` | `POST /orders.json` | `shopify.orders.write` | `Risky` | `High` | `None` | `line_items[].variant_id`; optional `quantity`, `email`, `financial_status`. |
| `shopify.customers.list` | `GET /customers.json?limit=50` | `shopify.customers.read` | `Safe` | `Low` | `Strict` | None. |
| `shopify.customers.get` | `GET /customers/{customer_id}.json` | `shopify.customers.read` | `Safe` | `Low` | `Strict` | `customer_id`. |
| `shopify.inventory.list` | `GET /inventory_levels.json?location_ids={location_id}` | `shopify.inventory.read` | `Safe` | `Low` | `Strict` | `location_id`. |
| `shopify.health` | `GET /shop.json` | `shopify.products.read` | `Safe` | `Low` | `Strict` | None. |

## Explicit Non-Goals

The current implementation does not include:

- Shopify OAuth installation, token exchange, refresh, app uninstall handling, session tokens, or multi-shop routing
- GraphQL Admin API, Storefront API, Customer Account API, Functions, Checkout UI extensions, or Shopify Flow actions
- webhook creation, webhook verification, inbound webhook serving, reconciliation jobs, or streaming/event subscriptions
- cursor pagination, `page_info`, server-side filtering, bulk operations, GraphQL bulk queries, or product/order/customer search
- fulfillment orders, fulfillments, fulfillment events, payment capture, refunds, returns, disputes, draft orders, subscriptions, taxes, discounts, themes, files, metaobjects, metafields, locations, inventory mutations, or customer mutations
- connector-local storage of shop credentials, product catalogs, order history, customer data, inventory snapshots, cursors, webhooks, or request history
- approval-token verification at connector invoke time

These are excluded on purpose:

- Shopify write operations can mutate a live store catalog or create real order records.
- Customer/order reads expose PII and commerce data.
- Fulfillment, payment, return, and webhook correctness require a broader lifecycle model than this first slice.
- GraphQL Admin migration needs separate schema/version and error-handling work.

## Readiness And Verification Surface

`doctor()`, `health()`, `self_check()`, `simulate()`, `introspect()`, `invoke()`, `subscribe()`, and `shutdown()` are part of the public closeout contract. They surface:

- configuration, shop domain, auth mode, API version, manifest hash, runtime, client, and handshake state
- contract details that explicitly mark REST Admin as the current legacy implementation
- live `/shop.json` reachability in self-check
- local doctor checks for config, client, runtime, auth boundary, network constraints, implementation substrate, and first-slice inventory
- operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, approval metadata, and AI hints
- bound capability-token enforcement in simulate and invoke
- unsupported streaming/subscription behavior
- provider error mapping for auth, not found, rate limit, API, JSON, timeout, and transport failures

The deterministic integration evidence is anchored on connector-local tests covering:

- Shopify REST paths for products, orders, customers, inventory, and `/shop.json`
- product create/update idempotency headers and order-create idempotency headers
- auth failure, rate limit, missing resource, API error, timeout, and redaction behavior
- manifest and operation metadata contracts
- explicit rejection of webhook ingress/subscriptions
- capability-token checks in the connector test module
- config validation for shop domain, auth-mode exclusivity, API version, credential ID, and access token redaction

## Source Notes

- `connectors/shopify/src/connector.rs` defines configuration parsing, FCP trait lifecycle, diagnostics, introspection, simulation, bound-token invoke verification, operation IDs, operation metadata, and first-slice contract details.
- `connectors/shopify/src/client.rs` defines Shopify REST request construction, auth headers, retry/timeout behavior, idempotency headers, endpoint paths, and provider error mapping.
- `connectors/shopify/src/types.rs` defines product, order, customer, inventory, shop, auth, and response-envelope shapes.
- `connectors/shopify/src/error.rs` defines connector error classes and FCP error conversion.
- `connectors/shopify/manifest.toml` defines the operation catalog, single-shop network constraints, native format, zone policy, stateless model, rate-limit pools, and AI hints.
- `connectors/shopify/tests/integration.rs` covers deterministic HTTP behavior and metadata/diagnostic behavior.

## Verification Bundle

Run these after changing this connector contract:

```bash
git diff --check -- connectors/shopify/README.md
ubs connectors/shopify/README.md
LC_ALL=C rg -n '[^ -~]' connectors/shopify/README.md
rg -n '\bmaster\b' connectors/shopify/README.md
```

For source or behavior changes, also run the connector proof lane through `rch`:

```bash
rch exec -- cargo test -p fcp-shopify
rch exec -- cargo check -p fcp-shopify --all-targets
rch exec -- cargo clippy -p fcp-shopify --all-targets -- -D warnings
rch exec -- cargo fmt --check
```

## Operator Guidance

- Treat product create/update/delete and order create as approval-gated until runtime approval enforcement lands.
- Use direct `access_token` mode only with a token scoped to the configured shop and the minimum needed Admin API scopes.
- Use `credential_id` only in environments where the host egress layer is known to inject the Shopify Admin access token.
- Treat list operations as first-page snapshots, not sync jobs.
- Use `shopify.health` or self-check to prove `/shop.json` reachability, then run the specific operation needed to prove optional product/order/customer/inventory scopes.
