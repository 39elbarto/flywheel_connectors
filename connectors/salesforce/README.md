# Salesforce Connector V3 Contract

> **Status**: runtime contract documented; Salesforce REST drift documented
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Salesforce REST API upstream**: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_what_is_rest_api.htm
> **Salesforce sObject REST upstream**: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_sobject_basic_info.htm
> **Salesforce query REST upstream**: https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/resources_query.htm
> **Salesforce platform API overview**: https://developer.salesforce.com/blogs/2024/04/accessing-object-data-with-salesforce-platform-apis

## Purpose

This document fixes the operator-facing contract for `fcp.salesforce`. The connector exposes the Salesforce CRM REST surface implemented in this crate: accounts, contacts, leads, opportunities, cases, SOQL query, and saved report retrieval.

The connector is intentionally a bounded CRM data bridge. It is not a full Salesforce administration client, Metadata API client, Bulk API client, Composite API planner, Platform Events subscriber, Change Data Capture consumer, OAuth token refresh daemon, schema-discovery engine, workflow automation runner, or Salesforce SDK wrapper.

## Current Runtime Snapshot

The current crate exposes these operations:

- `salesforce.accounts.get`
- `salesforce.accounts.list`
- `salesforce.contacts.list`
- `salesforce.contacts.create`
- `salesforce.contacts.delete`
- `salesforce.leads.list`
- `salesforce.leads.convert`
- `salesforce.opportunities.list`
- `salesforce.opportunities.create`
- `salesforce.cases.list`
- `salesforce.cases.create`
- `salesforce.soql.query`
- `salesforce.reports.get`

Important runtime truths the contract preserves:

- Package, library, and binary name are `fcp-salesforce`.
- Manifest ID is `fcp.salesforce`.
- `BaseConnector` runtime ID is `salesforce`.
- Manifest version is `0.1.0`.
- Manifest format is `wasi`.
- Configuration requires exactly one auth source:
  - `access_token`
  - `credential_id`
- Direct token mode sends `Authorization: Bearer <token>`.
- `credential_id` mode sends `X-FCP-Credential-Id` and expects host egress policy to inject real secret material.
- `credential_id` must be a valid UUID.
- Default runtime base URL is `https://login.salesforce.com`.
- Production direct-token `base_url` must use Salesforce or Force domains.
- Loopback URLs are accepted for deterministic tests.
- `api_version` may be configured as `66.0` or `v66.0`.
- Runtime API version precedence is explicit config, `FCP_SALESFORCE_API_PATH`, `FCP_SALESFORCE_API_VERSION`, then compiled default `66.0`.
- Runtime API path default is `/services/data/v66.0`.
- Runtime request timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- The client stores a retry config with `max_retries = 2`, but the low-level GET/POST/DELETE helpers send a single request in the current implementation.
- `health()` reports configured/session-ID state and counters. It does not call Salesforce.
- `doctor()` checks local configuration, client initialization, handshake session ID, and resolved API version. It does not call Salesforce.
- `self_check()` reports local provisioning readiness only. It does not perform a live Salesforce probe.
- Runtime `invoke` uses the JSON field `operation_id`, not `operation`.
- Runtime `invoke` does not require or verify a capability token.
- Runtime `simulate` only checks whether the `operation_id` is known.
- Runtime `simulate` does not check configuration, handshake, input shape, approval policy, or capability tokens.
- Runtime `shutdown()` calls client shutdown, clears config and client state, and clears the base configured/handshaken flags.
- Runtime `shutdown()` does not clear the stored `session_id`.

## Runtime API Adapter

The runtime uses these request shapes under `{base_url}{api_path}`:

| Operation | Runtime request | Required input | Output handling |
|-----------|-----------------|----------------|-----------------|
| `salesforce.accounts.get` | `GET /sobjects/Account/{account_id}` with optional `fields` query | `account_id` | Returns `{ "account": ... }`. |
| `salesforce.accounts.list` | `GET /query?q=SELECT ... FROM Account` | none | Returns `records`, `total_size`, and `done` when present. |
| `salesforce.contacts.list` | `GET /query?q=SELECT ... FROM Contact` | none | Optional `account_id` adds a SOQL equality filter. |
| `salesforce.contacts.create` | `POST /sobjects/Contact` | `last_name` | Sends mapped `LastName`, `FirstName`, `Email`, and `AccountId`. |
| `salesforce.contacts.delete` | `DELETE /sobjects/Contact/{contact_id}` | `contact_id` | Empty success bodies become `{}`. |
| `salesforce.leads.list` | `GET /query?q=SELECT ... FROM Lead` | none | Optional `status` adds a SOQL equality filter. |
| `salesforce.leads.convert` | `POST /actions/standard/convertLead` | `lead_id` | Sends one `inputs` entry with optional opportunity controls. |
| `salesforce.opportunities.list` | `GET /query?q=SELECT ... FROM Opportunity` | none | Optional `stage` adds a SOQL equality filter. |
| `salesforce.opportunities.create` | `POST /sobjects/Opportunity` | `name`, `stage_name`, `close_date` | Sends mapped `Name`, `StageName`, `CloseDate`, optional `Amount`, and optional `AccountId`. |
| `salesforce.cases.list` | `GET /query?q=SELECT ... FROM Case` | none | Optional `status` adds a SOQL equality filter. |
| `salesforce.cases.create` | `POST /sobjects/Case` | `subject` | Sends mapped subject, description, priority, account, and contact fields. |
| `salesforce.soql.query` | `GET /query?q={encoded}` | `query` | Returns `records`, `total_size`, and `done` when present. |
| `salesforce.reports.get` | `GET /analytics/reports/{report_id}` | `report_id` | `include_details` defaults to `true`. |

Path and query handling:

- Path IDs reject empty strings, slashes, backslashes, `..`, `%2f`, and `%5c`.
- Accepted path IDs are inserted into request paths without percent encoding.
- SOQL string filters for contact account, lead status, opportunity stage, and case status escape backslashes and single quotes before interpolation.
- Raw SOQL queries are URL-encoded by the local minimal encoder.
- Field lists are joined directly into SOQL or query strings. The runtime does not validate field names against Salesforce metadata.
- `limit` values are read as signed integers and are not clamped to the manifest maximum before SOQL generation.
- SOQL pagination is not followed. If Salesforce returns `done=false`, the runtime forwards that flag but does not chase `nextRecordsUrl`.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Salesforce REST resources are versioned under instance URLs such as `/services/data/vXX.0`. Runtime defaults to `https://login.salesforce.com/services/data/v66.0`, which is a login host, not a tenant instance URL, unless `base_url` is configured.
- Manifest state says the connector stores OAuth refresh token, instance URL, last-sync timestamps, and pagination cursors. Runtime keeps config in memory and does not persist refresh tokens, instance URLs, sync cursors, provider payloads, request counters, or error counters.
- Provisioning recipe describes an OAuth authorization-code flow, but runtime configure accepts an already-issued `access_token` or `credential_id`; there is no token refresh path in this crate.
- Manifest operation approval modes mark create, delete, and lead conversion operations as policy or interactive. Runtime does not enforce approval tokens.
- Runtime introspection reports no `requires_approval` metadata for any operation.
- Manifest rate-limit pools exist for each Salesforce capability family. Runtime introspection reports no rate-limit metadata and the client does not enforce those pools.
- Manifest response caps vary by operation. Runtime does not enforce those response byte caps before parsing JSON.
- Handshake returns all Salesforce capabilities unconditionally after configure. It does not filter requested capabilities.
- Handshake does not parse a full `HandshakeRequest`, does not install a `CapabilityVerifier`, and does not return a manifest hash.
- Health treats a configured connector without a `session_id` as degraded even though the base handshaken flag may be true.
- `self_check()` reports local readiness without a live read-only Salesforce API probe.
- Runtime `simulate` is only a known-operation check.
- Provider 401, 403, 404, and 429 are mapped as `FcpError::External` with status codes, not specialized unauthorized/resource/rate-limit FCP variants.
- There is no dedicated tracked verification shell script for this connector.

A follow-up parity bead should decide whether the default base URL should be a real instance URL, reconcile OAuth provisioning with runtime token handling, add live self-check behavior, add capability-token verification, expose approval and rate-limit metadata, validate SOQL field/limit inputs, add pagination handling for query results, and reconcile the manifest state model with in-memory runtime behavior.

## First-Slice Scope

The current Salesforce README slice documents the existing runtime surface:

- access-token and credential-id configuration
- base URL and REST API version handling
- CRM account, contact, lead, opportunity, case, SOQL, and report operations
- lifecycle, doctor, health, self-check, simulate, introspect, invoke, and shutdown behavior
- provider error mapping, retry classification, timeout behavior, path validation, and SOQL query construction
- runtime/manifest/provider-doc drift around instance URLs, OAuth, state persistence, approvals, rate limits, response caps, pagination, and capability-token verification
- deterministic WireMock integration tests

## Auth And Zone Boundary

- Authentication mechanisms: direct Salesforce access token or host credential reference.
- Home zone: `z:work`.
- Allowed source zones: `z:owner`, `z:private`, and `z:work`.
- Allowed target zone: `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime capability families:
  - `salesforce.accounts.read`
  - `salesforce.contacts.read`
  - `salesforce.contacts.write`
  - `salesforce.leads.read`
  - `salesforce.leads.write`
  - `salesforce.opportunities.read`
  - `salesforce.opportunities.write`
  - `salesforce.cases.read`
  - `salesforce.cases.write`
  - `salesforce.soql.read`
  - `salesforce.reports.read`
- Manifest required capabilities are `network.dns`, `network.egress`, `network.tls.sni`, and `storage.state`.
- Manifest forbids `system.exec`, `network.listen`, `media.upload`, and `media.download`.
- The connector does not intentionally persist access tokens, credential IDs, Salesforce records, report bodies, query results, request counters, or error counters outside process memory.
- Salesforce payloads can contain customer records, emails, account data, sales pipeline data, case history, custom fields, and report output. Treat live output as work-zone sensitive data unless the host supplies a stricter zone policy.

## Network And Runtime Invariants

- Default runtime base URL: `https://login.salesforce.com`.
- Default runtime API path: `/services/data/v66.0`.
- Direct token requests use `Authorization: Bearer <token>`.
- `credential_id` requests use `X-FCP-Credential-Id: <uuid>`.
- Runtime configure accepts `https` Salesforce/Force hosts for direct-token mode and loopback hosts for tests.
- Runtime configure rejects non-local `http`, userinfo, query strings, and fragments.
- Runtime client timeout is 30 seconds.
- Runtime request-context timeout is 30 seconds.
- Manifest operation network policy allows `*.salesforce.com` and `*.force.com` on port `443`, requires TLS/SNI, denies localhost, private ranges, tailnet ranges, and IP literals, caps redirects at three, and caps response sizes by operation.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `300000 ms` wall-clock timeout, no exec, no ptrace, read-only `/usr` and `/lib`, and writable `$CONNECTOR_STATE`.
- The connector does not open inbound sockets.
- Provider 401 and 403 are terminal authentication or authorization failures.
- Provider 404 is a terminal not-found failure.
- Provider 429 is retryable and honors `Retry-After` seconds, defaulting to 60 seconds when absent.
- Provider 5xx responses are classified as retryable API errors.
- JSON parse errors are internal failures.

## Capability Families

| Capability | Purpose |
|------------|---------|
| `salesforce.accounts.read` | Read Salesforce account records and account query results. |
| `salesforce.contacts.read` | Read contact query results. |
| `salesforce.contacts.write` | Create or delete contacts. |
| `salesforce.leads.read` | Read lead query results. |
| `salesforce.leads.write` | Convert leads. |
| `salesforce.opportunities.read` | Read opportunity query results. |
| `salesforce.opportunities.write` | Create opportunities. |
| `salesforce.cases.read` | Read case query results. |
| `salesforce.cases.write` | Create support cases. |
| `salesforce.soql.read` | Execute raw SOQL read queries. |
| `salesforce.reports.read` | Retrieve saved report results. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `salesforce.accounts.get` | `GET /sobjects/Account/{account_id}` | `salesforce.accounts.read` | `Safe` | `Low` | `Strict` | Reads one account. |
| `salesforce.accounts.list` | `GET /query` | `salesforce.accounts.read` | `Safe` | `Low` | `Strict` | Reads account records through generated SOQL. |
| `salesforce.contacts.list` | `GET /query` | `salesforce.contacts.read` | `Safe` | `Low` | `Strict` | Reads contact records through generated SOQL. |
| `salesforce.contacts.create` | `POST /sobjects/Contact` | `salesforce.contacts.write` | `Risky` | `Medium` | `None` | Creates a CRM contact. |
| `salesforce.contacts.delete` | `DELETE /sobjects/Contact/{contact_id}` | `salesforce.contacts.write` | `Dangerous` | `High` | `Strict` | Deletes a CRM contact. |
| `salesforce.leads.list` | `GET /query` | `salesforce.leads.read` | `Safe` | `Low` | `Strict` | Reads lead records through generated SOQL. |
| `salesforce.leads.convert` | `POST /actions/standard/convertLead` | `salesforce.leads.write` | `Risky` | `Medium` | `None` | Converts a lead into account/contact/opportunity records. |
| `salesforce.opportunities.list` | `GET /query` | `salesforce.opportunities.read` | `Safe` | `Low` | `Strict` | Reads opportunity records through generated SOQL. |
| `salesforce.opportunities.create` | `POST /sobjects/Opportunity` | `salesforce.opportunities.write` | `Risky` | `Medium` | `None` | Creates a sales opportunity. |
| `salesforce.cases.list` | `GET /query` | `salesforce.cases.read` | `Safe` | `Low` | `Strict` | Reads case records through generated SOQL. |
| `salesforce.cases.create` | `POST /sobjects/Case` | `salesforce.cases.write` | `Risky` | `Medium` | `None` | Creates a support case. |
| `salesforce.soql.query` | `GET /query` | `salesforce.soql.read` | `Safe` | `Low` | `Strict` | Executes caller-provided SOQL. |
| `salesforce.reports.get` | `GET /analytics/reports/{report_id}` | `salesforce.reports.read` | `Safe` | `Low` | `Strict` | Retrieves a saved report body. |

## Resource URIs

Runtime invoke currently does not verify capability tokens, so no resource binding is enforced locally. The effective authorization boundary is host-side admission plus operation dispatch.

Follow-up work should add resource URI shapes such as:

| Operation family | Candidate resource URI shape |
|------------------|------------------------------|
| sObject record | `salesforce://sobject/{object_api_name}/{record_id}` |
| sObject collection query | `salesforce://sobject/{object_api_name}/query` |
| SOQL | `salesforce://soql/query` |
| Reports | `salesforce://report/{report_id}` |

## Explicit Non-Goals

The current implementation does not include:

- OAuth token exchange or refresh
- Bulk API
- Composite API
- Metadata API
- Tooling API
- Platform Events or Change Data Capture
- Durable sync cursors or replay
- Schema describe caching
- Field-level security preflight
- Salesforce file upload/download
- Apex execution
- Assignment-rule or duplicate-rule management
- Real Salesforce integration tests

## Test And Verification Contract

The tracked tests use deterministic WireMock servers. They cover:

- configure, handshake, health, doctor, self-check, introspect, simulate, and shutdown paths
- access-token configuration
- API version reporting
- all 13 runtime operations
- missing required input fields for write/read-specific operations
- Authorization header behavior for direct-token requests
- provider 401, 403, 404, 429, and 500 responses
- path-segment rejection for traversal-like values
- SOQL encoding and output normalization

Before committing README-only changes for this connector, run:

```bash
git diff --check -- connectors/salesforce/README.md
LC_ALL=C rg -n '[^ -~]' connectors/salesforce/README.md
rg -n '\bmaster\b' connectors/salesforce/README.md
ubs connectors/salesforce/README.md
```

No Cargo/rch lane is required for README-only edits. Any runtime or test change must use the workspace verification lanes described in the root `AGENTS.md`.
