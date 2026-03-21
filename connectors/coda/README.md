# Coda Connector V3 Contract

> **Status**: planning contract
> **Bead**: `flywheel_connectors-j05nu.5.3.1`
> **Unblocks**: `flywheel_connectors-j05nu.5.3.2`
> **Primary upstream**: https://coda.io/developers/apis/v1

## Purpose

This document pins down the first implementation slice for `fcp.coda` so the follow-on runtime bead has a stable contract instead of inventing scope while coding.

The connector targets Coda's REST API at `https://coda.io/apis/v1` and treats Coda as a request-response SaaS surface with asynchronous document mutations.

## First-Slice Scope

The first implementation slice is intentionally narrow:

- Read account identity and token scope via `whoami`.
- Enumerate docs inside one configured workspace boundary.
- Read doc, page, table, column, row, formula, and control metadata.
- Read individual rows and formula values.
- Support controlled row upsert and row delete flows.
- Track document mutations through Coda `requestId` and `mutationStatus`.

The connector is `operational` and `stateless`.

## Auth And Scope Boundary

- Authentication is Bearer-token only.
- The token represents a single Coda user and exposes a primary workspace through `GET /whoami`.
- The connector instance binds to exactly one configured `workspace_id`.
- Per-operation `doc_id` input is allowed, but the connector MUST reject docs whose returned `workspaceId` does not match the configured workspace boundary.
- Optional `allowed_doc_ids` narrowing is permitted for higher-trust deployments, but the default contract is workspace-scoped rather than single-doc-scoped.
- Stable IDs are the contract surface: `docId`, `pageId`, `tableId`, `rowId`, `columnId`, `formulaId`, and `controlId`.
- Name-based lookups are a fallback only for safe read operations. They are forbidden for destructive operations because Coda documents that names are fragile and can resolve ambiguously.

## Network And Runtime Invariants

- Base API host: `coda.io`
- Base path: `/apis/v1`
- Port: `443`
- TLS + SNI required
- `deny_localhost = true`
- `deny_private_ranges = true`
- No redirects to other hosts
- Published rate limits currently include reads at `100 requests / 6 seconds`, general writes at `10 requests / 6 seconds`, doc-content writes at `5 requests / 10 seconds`, and doc listing at `4 requests / 6 seconds`.
- Writes MUST treat HTTP `202 Accepted` as queued work, not completion.
- Every mutation path MUST poll `GET /mutationStatus/{requestId}` until completion or timeout.
- `rows.upsert` is only valid for base tables, not views.
- `X-Coda-Doc-Version: latest` is optional caller-controlled behavior, not the default, because Coda may return `400` when the latest snapshot is unavailable.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `coda.account.read` | Token identity, workspace, and token-scope inspection |
| `coda.docs.read` | Doc, page, and high-level metadata discovery |
| `coda.tables.read` | Table and column discovery |
| `coda.rows.read` | Row listing and point lookup |
| `coda.rows.write` | Row upsert and deletion |
| `coda.formulas.read` | Formula discovery and value reads |
| `coda.controls.read` | Control discovery and inspection |
| `coda.mutations.read` | Poll queued mutation status |

## Operation Inventory

| Operation | Endpoint | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------|------------|------------|-----------|-------------|-----------|
| `coda.account.whoami` | `GET /whoami` | `coda.account.read` | `Safe` | `Low` | `None` | Read-only auth and workspace probe used during configure, doctor, and self-check. |
| `coda.docs.list` | `GET /docs` | `coda.docs.read` | `Safe` | `Low` | `None` | Read-only workspace doc discovery. |
| `coda.docs.get` | `GET /docs/{docId}` | `coda.docs.read` | `Safe` | `Low` | `None` | Read-only doc metadata, including folder, workspace, and publication state. |
| `coda.pages.list` | `GET /docs/{docId}/pages` | `coda.docs.read` | `Safe` | `Low` | `None` | Structural discovery inside a doc. |
| `coda.pages.get` | `GET /docs/{docId}/pages/{pageId}` | `coda.docs.read` | `Safe` | `Low` | `None` | Read-only page metadata and layout context. |
| `coda.tables.list` | `GET /docs/{docId}/tables` | `coda.tables.read` | `Safe` | `Low` | `None` | Read-only table discovery. |
| `coda.tables.get` | `GET /docs/{docId}/tables/{tableId}` | `coda.tables.read` | `Safe` | `Low` | `None` | Read-only table metadata including row counts and view/base-table distinctions. |
| `coda.columns.list` | `GET /docs/{docId}/tables/{tableId}/columns` | `coda.tables.read` | `Safe` | `Low` | `None` | Read-only schema discovery required before robust row writes. |
| `coda.rows.list` | `GET /docs/{docId}/tables/{tableId}/rows` | `coda.rows.read` | `Safe` | `Low` | `None` | Read-only row listing, filtering, and sync-style enumeration. |
| `coda.rows.get` | `GET /docs/{docId}/tables/{tableId}/rows/{rowId}` | `coda.rows.read` | `Safe` | `Low` | `None` | Read-only point lookup for a stable row identifier. |
| `coda.rows.upsert` | `POST /docs/{docId}/tables/{tableId}/rows` | `coda.rows.write` | `Risky` | `Medium` | `BestEffort` | Side-effecting row insertion/update with no provider-side idempotency key; connector should prefer `keyColumns` and receipt tracking, but exact-once is not guaranteed by Coda. |
| `coda.rows.delete` | `DELETE /docs/{docId}/tables/{tableId}/rows/{rowId}` | `coda.rows.write` | `Dangerous` | `High` | `Strict` | Destructive row deletion. The connector must require stable row IDs, emit intent/receipt evidence, and de-duplicate retries at the connector layer before reissuing deletes. |
| `coda.formulas.list` | `GET /docs/{docId}/formulas` | `coda.formulas.read` | `Safe` | `Low` | `None` | Read-only discovery of named formulas. |
| `coda.formulas.get` | `GET /docs/{docId}/formulas/{formulaId}` | `coda.formulas.read` | `Safe` | `Low` | `None` | Read-only formula value inspection. |
| `coda.controls.list` | `GET /docs/{docId}/controls` | `coda.controls.read` | `Safe` | `Low` | `None` | Read-only discovery of controls exposed in the doc. |
| `coda.controls.get` | `GET /docs/{docId}/controls/{controlId}` | `coda.controls.read` | `Safe` | `Low` | `None` | Read-only control inspection. |
| `coda.mutations.get_status` | `GET /mutationStatus/{requestId}` | `coda.mutations.read` | `Safe` | `Low` | `None` | Polls queued mutation completion and warnings after any async write. |

## Explicit Non-Goals

The first implementation slice does not include these surfaces:

- `docs.create`, `docs.update`, and `docs.delete`
- folder CRUD
- ACL and permission management
- publish and unpublish flows
- page create, update, delete, export, and content mutation
- bulk row delete
- push-button execution
- automations, analytics, Packs, or browser-link resolution
- multi-workspace aggregation from a single connector instance

These are excluded on purpose:

- Doc and ACL mutations expand the trust boundary from data edits into workspace governance.
- Button execution is too broad because Coda documents that a button may perform arbitrary actions elsewhere in the doc, including Pack actions.
- Analytics, publishing, and automation surfaces are useful, but they are orthogonal to the minimal document-and-table workflow this connector needs first.

## Implementation Notes For `flywheel_connectors-j05nu.5.3.2`

- `self_check()` should call `whoami` and surface token validity, token scope (`scoped`), and workspace mismatch failures explicitly.
- Config should include `workspace_id`, `api_token` or `credential_id`, bounded request timeout, mutation poll interval, and mutation deadline.
- Error mapping must preserve Coda `401`, `403`, `404`, `429`, and `400` cases distinctly.
- Write paths should treat `202` as `accepted_for_processing`, then poll `mutationStatus` until completion, timeout, or warning.
- Reads should prefer stable IDs and should not silently downgrade to name-based destructive behavior.
- Row upsert support should document that multiple rows may be updated when `keyColumns` match more than one record.
- Tests should cover snapshot-staleness behavior, rate limits, async mutation polling, workspace-boundary rejection, and name-resolution ambiguity rejection.

## Source Notes

This contract is grounded in Coda's official API reference:

- The API root is `https://coda.io/apis/v1`.
- Coda exposes docs, pages, tables, rows, formulas, controls, `whoami`, and `mutationStatus` as first-class endpoints.
- Coda publishes rate limits for reads, writes, doc-content writes, and doc listing.
- Mutating endpoints return `202` with a `requestId`, and completion is checked through `GET /mutationStatus/{requestId}`.
- `rows.upsert` supports `keyColumns`, updates multiple matching rows, and only works on base tables.
