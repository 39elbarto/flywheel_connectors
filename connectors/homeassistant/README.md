# Home Assistant Connector V3 Contract

> **Status**: runtime contract documented with physical-control and event-streaming drift
> **Bead**: `flywheel_connectors-4kw5f.12`
> **Parent**: `flywheel_connectors-4kw5f`
> **Verification script**: none tracked; use the commands below
> **Home Assistant REST API upstream**: https://developers.home-assistant.io/docs/api/rest/
> **Home Assistant WebSocket API upstream**: https://developers.home-assistant.io/docs/api/websocket/
> **Home Assistant auth upstream**: https://developers.home-assistant.io/docs/auth_api/

## Purpose

This document fixes the operator-facing contract for `fcp.homeassistant`. The connector exposes the Home Assistant local REST and WebSocket surfaces implemented in this crate: entity state reads and writes, service calls, automation and scene helpers, state history, a history-backed statistics facade, and bounded event subscriptions.

The connector is intentionally a bounded smart-home bridge. It is not a full Home Assistant admin client, UI automation layer, entity-registry API client, device-registry API client, config editor, add-on manager, automation authoring IDE, media downloader, camera streaming bridge, or durable home-state warehouse.

## Current Runtime Snapshot

The current crate exposes these operations:

- `homeassistant.list_states`
- `homeassistant.get_state`
- `homeassistant.set_state`
- `homeassistant.call_service`
- `homeassistant.list_services`
- `homeassistant.list_areas`
- `homeassistant.list_devices`
- `homeassistant.list_automations`
- `homeassistant.trigger_automation`
- `homeassistant.toggle_automation`
- `homeassistant.list_scenes`
- `homeassistant.activate_scene`
- `homeassistant.get_history`
- `homeassistant.get_statistics`
- `homeassistant.subscribe_events`

Important runtime truths the contract preserves:

- Package and binary name are `fcp-homeassistant`.
- Runtime `BaseConnector` ID is `homeassistant`.
- Manifest connector ID is `fcp.homeassistant`.
- Configuration accepts exactly one of:
  - `access_token`
  - `credential_id`
- `access_token` mode sends `Authorization: Bearer <token>`.
- `credential_id` must be a valid UUID and sends `X-FCP-Credential-Id: <uuid>`.
- Default base URL is `http://homeassistant.local:8123/api`.
- Runtime HTTP timeout is `30 seconds`.
- Runtime request-context timeout is also configured to `30 seconds`.
- Runtime stores a `HttpRetryConfig` with `max_retries = 3`, but normal REST requests are currently direct reqwest sends and do not run a retry loop.
- Provider error bodies are truncated to 2048 bytes before API errors are surfaced.
- HTTP 401 maps to unauthorized, 404 maps to entity-not-found, 429 maps to rate-limited with `Retry-After` support, and 503 maps to unavailable.
- `health` reports local configured/handshaken state plus request and error counters.
- `doctor` checks configuration, client initialization, base URL policy, auth mode, handshake state, direct-token state, and credential-injection readiness.
- `self_check` calls the root API endpoint for direct-token mode and returns `credential_injection_required` for credential-id mode.
- `subscribe_events` derives `/api/websocket` from the configured REST base URL, performs the Home Assistant auth handshake, sends `subscribe_events`, filters events locally, and returns a bounded batch.
- `subscribe_events` requires `watch_all = true` or at least one `watch_domains` / `watch_entities` filter.
- `subscribe_events` defaults to `state_changed`, `max_events = 1`, `timeout_ms = 30000`, and `max_reconnect_attempts = 1`.
- `handle_shutdown` shuts down the client runtime, clears config/client state, and resets configured and handshaken flags.
- `invoke` only checks the connector ready state and operation ID. It does not require or verify an FCP capability token in this checkout.
- `simulate` only checks whether an operation ID is known. It does not check configured state, handshake state, approval policy, or capability tokens.

## Drift Visible In This Checkout

This README documents runtime truth and keeps current drift visible:

- Runtime operation metadata sets `requires_approval = None` for every operation, while the manifest marks physical write/control operations as `policy` or `interactive`.
- Runtime does not verify bound capability tokens for either `invoke` or `simulate`; capability families are advertised but not mechanically enforced at this connector boundary.
- Runtime base URL policy accepts localhost, loopback, `homeassistant.local`, `10.*`, `172.*`, `192.168.*`, and any HTTPS host. The manifest models a pinned `$ha_host` policy on ports 443 and 8123.
- Runtime base URL parsing does not reject userinfo, query strings, or fragments before request construction.
- `list_areas` is not backed by Home Assistant's area registry. It returns states whose entity IDs start with `input_select.area_`.
- `list_devices` is not backed by Home Assistant's device registry. It filters ordinary states and treats each remaining entity as a device proxy.
- `get_statistics` does not call a dedicated statistics endpoint. It reuses the history endpoint with `filter_entity_id = statistic_ids`.
- The `integration.rs` aggregation layer provides typed entity-domain mapping, normalized device controls, and control policy helpers, but the public `invoke` dispatcher does not route through those helpers.
- `credential_id` mode can be used for REST requests through host-side injection, but runtime WebSocket auth currently requires a bearer token and rejects credential-id mode.
- Manifest event caps advertise streaming with replay false. Runtime subscriptions are bounded one-shot invokes, not persistent host-managed streams.
- Runtime direct REST requests do not currently use the stored retry configuration.

A follow-up parity bead should add capability-token verification, align runtime approval metadata with the manifest, pin base URL validation to the active Home Assistant host, reject unsafe URL components, decide whether registry-backed areas/devices are in scope, wire the integration aggregation layer into public operations or mark it internal-only, and either implement a real statistics API path or rename the facade.

## First-Slice Scope

The current Home Assistant README slice documents the existing runtime surface:

- access-token and credential-id configuration
- REST state, service, history, automation, and scene operations
- bounded WebSocket event subscriptions
- local filtering, redaction, cooldown, and reconnect behavior for event batches
- local provisioning readiness, doctor, health, self-check, simulate, introspect, invoke, and shutdown surfaces
- mock-only REST and WebSocket tests
- runtime/manifest drift around approval, capability-token verification, URL policy, entity registries, and statistics behavior

## Auth And Zone Boundary

- Authentication mechanisms: Home Assistant long-lived access token or host credential reference.
- Official Home Assistant docs describe long-lived access tokens for API integrations and bearer-token auth for both HTTP and WebSocket calls.
- Runtime does not implement Home Assistant OAuth login, token creation, token rotation, refresh-token handling, signed-path creation, or connector-local credential vaulting.
- Home zone: `z:infra`.
- Allowed source zones: `z:owner`, `z:private`, `z:work`, and `z:infra`.
- Allowed target zones: `z:infra` and `z:work`.
- Forbidden zones: `z:public` and `z:community`.
- Runtime handshake advertises:
  - `homeassistant.read`
  - `homeassistant.write`
  - `homeassistant.control`
- The connector does not persist entity states, history rows, event batches, tokens, credential IDs beyond configuration metadata, provider payloads, provider error bodies, area/device registries, or automation definitions.
- Home Assistant state can expose sensitive occupancy, camera, lock, alarm, location, climate, and energy patterns. Treat live reads and writes as private infrastructure data.

## Network And Runtime Invariants

- Default runtime host: `homeassistant.local`.
- Default runtime port: `8123`.
- Default runtime API prefix: `/api`.
- Official REST examples use endpoints such as `/api/states`, `/api/services`, and `/api/history/period/<timestamp>`.
- Runtime request construction appends connector paths such as `/states` and `/services/{domain}/{service}` to the configured base URL.
- Runtime WebSocket URL construction maps the base URL to `/api/websocket` or `/api/websocket` under the active path.
- Runtime permits local and private-network HTTP because Home Assistant is commonly self-hosted on LAN addresses.
- Runtime permits arbitrary HTTPS hosts, while the manifest represents a pinned Home Assistant host policy.
- Manifest live-operation network policy allows ports 443 and 8123, allows private ranges and localhost, requires SNI, and denies no IP literal by default.
- Sandbox profile is `strict`, with `256 MB` memory, `50%` CPU, `120_000 ms` wall-clock timeout, no exec, no ptrace, and no inbound listener.

## Capability Families

| Capability | Purpose |
|-----------|---------|
| `homeassistant.read` | Read entity states, services, areas, devices, automations, scenes, history, statistics facade output, and event batches. |
| `homeassistant.write` | Write entity state via the Home Assistant states REST API. |
| `homeassistant.control` | Call services, trigger/toggle automations, and activate scenes. |

## Operation Inventory

| Operation | Endpoint shape | Capability | SafetyTier | RiskLevel | Idempotency | Rationale |
|-----------|----------------|------------|------------|-----------|-------------|-----------|
| `homeassistant.list_states` | `GET /api/states` | `homeassistant.read` | `Safe` | `Low` | `Strict` | Reads the current state list for all entities. |
| `homeassistant.get_state` | `GET /api/states/{entity_id}` | `homeassistant.read` | `Safe` | `Low` | `Strict` | Reads one entity state. |
| `homeassistant.set_state` | `POST /api/states/{entity_id}` | `homeassistant.write` | `Risky` | `Medium` | `Strict` | Writes Home Assistant state directly; this does not necessarily control physical devices. |
| `homeassistant.call_service` | `POST /api/services/{domain}/{service}` | `homeassistant.control` | `Risky` | `High` | `BestEffort` | Calls a Home Assistant service and may control physical devices. |
| `homeassistant.list_services` | `GET /api/services` | `homeassistant.read` | `Safe` | `Low` | `Strict` | Reads available service domains and service names. |
| `homeassistant.list_areas` | `GET /api/states` plus local `input_select.area_` filter | `homeassistant.read` | `Safe` | `Low` | `Strict` | Current runtime area proxy, not registry-backed area discovery. |
| `homeassistant.list_devices` | `GET /api/states` plus local exclusions | `homeassistant.read` | `Safe` | `Low` | `Strict` | Current runtime device proxy, not registry-backed device discovery. |
| `homeassistant.list_automations` | `GET /api/states` plus `automation.` filter | `homeassistant.read` | `Safe` | `Low` | `Strict` | Lists automation state entities. |
| `homeassistant.trigger_automation` | `POST /api/services/automation/trigger` | `homeassistant.control` | `Risky` | `High` | `None` | Executes an automation, optionally skipping conditions. |
| `homeassistant.toggle_automation` | `POST /api/services/automation/turn_on` or `turn_off` | `homeassistant.control` | `Risky` | `Medium` | `Strict` | Enables or disables an automation. |
| `homeassistant.list_scenes` | `GET /api/states` plus `scene.` filter | `homeassistant.read` | `Safe` | `Low` | `Strict` | Lists scene state entities. |
| `homeassistant.activate_scene` | `POST /api/services/scene/turn_on` | `homeassistant.control` | `Risky` | `High` | `BestEffort` | Activates a Home Assistant scene. |
| `homeassistant.get_history` | `GET /api/history/period/{timestamp}` | `homeassistant.read` | `Safe` | `Low` | `Strict` | Reads historical state changes with optional filters. |
| `homeassistant.get_statistics` | `GET /api/history/period/{start_time}` with `filter_entity_id` | `homeassistant.read` | `Safe` | `Low` | `Strict` | Runtime statistics facade backed by history, not a dedicated statistics endpoint. |
| `homeassistant.subscribe_events` | `WS /api/websocket` with `subscribe_events` | `homeassistant.read` | `Safe` | `Low` | `Strict` | Opens a bounded WebSocket subscription and returns matching redacted events. |

## Explicit Non-Goals

The current implementation does not include:

- Home Assistant OAuth login, token issuance, token revocation, refresh-token handling, or signed-path creation
- entity registry, area registry, device registry, config entries, integrations, add-ons, backups, users, roles, or supervisor APIs
- camera stream proxying, media download, media upload, local file access, or Lovelace/UI automation
- automation authoring, script authoring, dashboard editing, YAML editing, or add-on installation
- persistent event subscriptions, webhook listeners, replay, durable event cursors, or host-managed event acknowledgements
- direct FCP capability-token verification at connector invoke time

These are excluded on purpose:

- Home Assistant can control physical devices. Approval and capability enforcement need to be mechanical before broad write/control expansion.
- Home state exposes occupancy, security, camera, and behavior signals.
- A persistent event bridge needs host-owned lifecycle, buffering, replay, and backpressure semantics beyond a one-shot connector invoke.

## Readiness And Verification Surface

`handle_doctor()`, `handle_health()`, `handle_self_check()`, `handle_simulate()`, and `handle_introspect()` are part of the public closeout contract. They surface:

- configuration and client initialization state
- request and error counters
- auth mode as access token or credential ID
- base URL policy acceptance or failure
- credential-injection requirement for credential-id mode
- live root-API self-check in direct-token mode
- known operation metadata, schemas, capability IDs, risk levels, safety tiers, idempotency, and AI hints
- event caps and the `homeassistant.state_changed` event schema

The deterministic integration evidence is anchored on connector-local tests covering:

- lifecycle health, configure, handshake, shutdown, doctor, self-check, introspection, and simulate
- WireMock REST behavior for states, services, automations, scenes, history, statistics facade, and provider error mapping
- mock WebSocket auth handshake, `subscribe_events`, filtering, redaction, cooldown, malformed-event accounting, reconnects, and ack failure handling
- configuration validation for auth modes, credential IDs, base URLs, and provisioning readiness
- integration aggregation helpers for entity domains, capability families, device controls, control policy decisions, and audit entries

## Source Notes

- `connectors/homeassistant/src/connector.rs` defines configuration parsing, lifecycle handlers, diagnostics, introspection, simulation, invoke dispatch, operation metadata, base URL policy, and doctor/self-check behavior.
- `connectors/homeassistant/src/client.rs` defines REST request construction, auth headers, WebSocket URL derivation, WebSocket auth, event subscription collection, response parsing, and provider error handling.
- `connectors/homeassistant/src/types.rs` defines event subscription input, redacted event output, subscription stats, entity states, services, areas, devices, automations, scenes, and history/statistics shapes.
- `connectors/homeassistant/src/integration.rs` defines the typed aggregation layer for entity domains, capability families, normalized controls, control policies, and audit entries.
- `connectors/homeassistant/manifest.toml` defines the operation catalog, network constraints, sandbox boundary, zone policy, event caps, rate limits, and AI hints.
- `connectors/homeassistant/tests/integration.rs` covers mock-only REST, WebSocket, lifecycle, simulation, diagnostics, and error behavior.

## Verification Bundle

There is no dedicated tracked `scripts/e2e/homeassistant_connector_verification.sh` bundle in this checkout. The closeout surface is the crate-local test suite plus direct `rch` proof commands.

The verification surface captures:

- runtime operation inventory and policy metadata
- deterministic WireMock REST coverage
- deterministic asupersync WebSocket coverage
- auth-mode, provider-error, lifecycle, simulation, introspection, doctor, and self-check coverage
- integration aggregation helper coverage
- formatting, check, test, and clippy proof through `rch`
- UBS on changed files before commit

## Operator Guidance

**Prerequisites**:

- Use WireMock and the mock WebSocket tests for routine verification.
- Use a disposable Home Assistant instance for live checks.
- Prefer direct token mode for WebSocket event subscriptions until host token injection supports WebSocket auth frames.

**Dedicated environment**:

- Keep live service calls confined to harmless test entities, scenes, automations, and sensors.
- Never operate locks, alarms, garage doors, covers, cameras, climate systems, or high-power switches against production homes without explicit operator approval.
- Use synthetic entity IDs, service payloads, event payloads, and timestamps in logs and transcripts.

**Redaction rules**:

- Redact access tokens, credential IDs where needed, entity IDs for sensitive areas, event payloads, camera names, lock/alarm names, location/person states, local hostnames, LAN IPs, provider payloads, provider error bodies, and local paths.
- Verification output should use operation IDs, endpoint shapes, host classes, status/error classes, retry decisions, and synthetic Home Assistant resource identifiers.

**Common remediation**:

- If configuration fails, provide exactly one of `access_token` or `credential_id`.
- If self-check reports `credential_injection_required`, use direct token mode or wire host-side injection.
- If WebSocket subscription fails in credential-id mode, use direct token mode; runtime cannot authenticate Home Assistant WebSocket frames with only a credential ID.
- If service calls fail, verify the service domain/name via `homeassistant.list_services` and the target entity via `homeassistant.get_state`.
- If history calls are too large, provide `filter_entity_id`, `end_time`, `minimal_response`, and `significant_changes_only`.
- If event subscription rejects input, set `watch_all = true` or provide `watch_domains` / `watch_entities`.
- If an operation succeeds in `simulate` but should be denied by policy, remember that current simulation only checks operation IDs.

**Rerun commands**:

- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-homeassistant-readme cargo check -p fcp-homeassistant --all-targets`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-homeassistant-readme cargo test -p fcp-homeassistant --tests -- --nocapture`
- `rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-homeassistant-readme cargo clippy -p fcp-homeassistant --all-targets --no-deps -- -D warnings`
- `ubs connectors/homeassistant/README.md`
