# FCP V3 Connector Acceptance Contract

> **Status**: NORMATIVE
> **Version**: 1.1.0
> **Date**: 2026-03-23
> **Bead Reference**: `flywheel_connectors-j05nu.11.1`, `flywheel_connectors-49z0b.2`
> **Supersedes**: `STANDARD_Connector_Compliance.md` (legacy V2)

---

## Purpose

This document is the workspace-wide acceptance contract for FCP V3 connectors. It is retroactively binding on every existing implemented connector and every open new-connector bead. A connector that compiles but violates any MUST requirement below is non-compliant regardless of test count or feature coverage.

The contract answers two questions:

1. **New connector "done"**: what must be true before a brand-new connector implementation bead can be closed.
2. **Existing connector audit "done"**: what must be verified or remediated before an existing connector's compliance bead can be closed.

---

## 1. Lifecycle Ownership

### MUST

- Connector struct holds a `ConnectorRuntime` field (from `fcp_sdk::migration`), initialized during `configure()` via `ConnectorRuntime::new()`.
- Every invoke/request path creates a context via `runtime.request_context()` or `runtime.request_context_with_timeout()`.
- Long-lived operations (streaming, polling, webhook listeners) use `runtime.background_context()`.
- Connector `shutdown()` handler calls `runtime.shutdown()` to propagate cancellation to all outstanding contexts.
- Shutdown drains gracefully within bounded time; no unbounded blocking.

### SHOULD

- Health surface distinguishes: ready-but-idle, active-healthy, degraded-but-serving, draining, failed-with-retry, failed-permanent.
- Connector reports meaningful metrics (requests processed, error counts, latency) through health/introspect surfaces.

---

## 2. Retry and Timeout Policy

### MUST

- All HTTP calls to external services go through `RetryLoop::execute()` or equivalent SDK retry infrastructure. Hand-rolled retry loops are forbidden.
- Retry configuration uses `HttpRetryConfig` (serializable, with max_retries, initial_delay_ms, max_delay_ms, jitter).
- Retry decisions use `classify_http_status()` for canonical HTTP status mapping:
  - 429, 500, 502, 503, 504 are retryable.
  - 401, 403, 404, 409, 422 are terminal.
- `AttemptOutcome<T, E>` is used for retry decision flow: `Success`, `Retryable`, `Terminal`.

### MUST NOT

- Never retry indefinitely. All retry paths must be bounded by max attempts and total deadline.
- Never retry non-idempotent operations blindly. Operations with `IdempotencyClass::None` must not be retried on ambiguous failures.

---

## 3. Error Translation

### MUST

- Connector error type implements `ConnectorErrorMapping` (from `fcp_sdk::migration`):
  ```rust
  impl ConnectorErrorMapping for YourError {
      fn from_async_error(error: AsyncError) -> Self;
      fn to_fcp_error(&self) -> FcpError;
      fn is_retryable(&self) -> bool;
      fn retry_after(&self) -> Option<Duration> { None }
  }
  ```
- `to_fcp_error()` maps every error variant to the correct `FcpError` discriminant:
  - Rate limits -> `FcpError::RateLimited { retry_after_ms, violation }`
  - Auth failures -> `FcpError::Unauthorized { code, message }`
  - Input validation -> `FcpError::InvalidRequest { code, message }`
  - Upstream failures -> `FcpError::External { service, message, status_code, retryable, retry_after }`
  - Internal bugs -> `FcpError::Internal { message }`
- `is_retryable()` returns truthful retryability. Rate limits and transient server errors are retryable; auth errors, validation errors, and permanent failures are not.
- `retry_after()` returns the provider's suggested delay when available (e.g., from `Retry-After` header or rate limit response).

### MUST NOT

- Never map all errors to a generic catch-all. Every distinct failure mode the external service can produce must have a specific mapping.
- Never lose the upstream status code. If the external service returns an HTTP status, it must appear in the FcpError.

---

## 4. Typed OperationInfo

### MUST

- Every operation the connector can perform is declared as a typed `OperationInfo` struct in the introspection surface.
- Each `OperationInfo` includes all required fields:

| Field | Type | Requirement |
|-------|------|-------------|
| `id` | `OperationId` | Unique, dot-namespaced (`connector.operation`) |
| `summary` | `String` | One-line human/agent description |
| `description` | `String` | Detailed behavior description |
| `safety_tier` | `SafetyTier` | Correct classification (see Section 4a) |
| `risk_level` | `RiskLevel` | Correct classification (see Section 4b) |
| `idempotency` | `IdempotencyClass` | Correct classification (see Section 4c) |
| `input_schema` | `serde_json::Value` | JSON Schema for operation input |
| `output_schema` | `serde_json::Value` | JSON Schema for operation output |
| `capability` | `CapabilityId` | Required capability to invoke |
| `examples` | `Vec<OperationExample>` | At least one example per operation |
| `ai_hints` | `AiHints` | When to use, common mistakes, related ops |

### 4a. SafetyTier Classification Rules

| Tier | Criteria | Examples |
|------|----------|---------|
| `Safe` | Read-only, no external state mutation, no cost, no PII exposure | List items, get status, search, introspect |
| `Risky` | Creates, modifies, or sends external state; has cost; exposes PII | Send message, create resource, update record, execute query |
| `Dangerous` | Deletes data, modifies permissions/ACLs, financial transactions, irreversible actions | Delete resource, modify ACLs, transfer funds, revoke access |
| `Critical` | System-level operations requiring quorum/elevation | Key rotation, device enrollment, zone key changes |
| `Forbidden` | Never allowed under any circumstances | Operations that would violate security invariants |

### 4b. RiskLevel Classification Rules

| Level | Criteria |
|-------|----------|
| `Low` | Failure has no lasting consequence; easily recoverable |
| `Medium` | Failure may require manual intervention but is recoverable |
| `High` | Failure could cause data loss, financial impact, or security degradation |
| `Critical` | Failure could cause irreversible damage or systemic compromise |

### 4c. IdempotencyClass Rules

| Class | Criteria | Constraint |
|-------|----------|------------|
| `None` | No idempotency guarantee; unsafe to retry | Only permitted for `Safe` operations |
| `BestEffort` | Deduplication attempted but not guaranteed | Permitted for `Safe` and `Risky` operations |
| `Strict` | Exactly-once via idempotency key + receipt tracking | Required for `Dangerous` operations; recommended for `Risky` |

**Hard rule**: `Dangerous` + `IdempotencyClass::None` or `Dangerous` + `IdempotencyClass::BestEffort` is a conformance violation. Dangerous operations MUST use `Strict`.

---

## 5. Manifest, Readiness, and Prerequisites

### MUST

- Connector has a `manifest.toml` (or embedded manifest) that is extractable WITHOUT executing the connector binary.
- Manifest declares:
  - Connector identity (id, name, version, author)
  - Archetypes (from closed set: request_response, streaming, bidirectional, polling, webhook, queue_pubsub, file_blob, database, cli_process, browser)
  - Required, optional, and forbidden capabilities
  - Network constraints (allowed hosts, ports, TLS requirements)
  - Sandbox profile (memory limit, deny_exec, deny_ptrace)
  - Operations with capability mappings
- `self_check()` / doctor returns actionable diagnostics:
  - Missing credentials -> specific remediation instructions
  - Unreachable service -> network diagnostic hints
  - Misconfiguration -> exact field and expected value
- Readiness checks must be truthful: if the connector cannot actually reach the external service, it must report degraded, not healthy.
- Prerequisites (API keys, OAuth tokens, webhook URLs) are documented in manifest and surfaced through provisioning recipes.

### MUST NOT

- Never report healthy when the external service is unreachable or credentials are invalid.
- Never require the operator to read source code to understand what configuration is needed.

---

## 6. Evidence and Verification

### 6a. Testing Taxonomy and Naming Rules (MUST)

All connector evidence must be classified into exactly one of these suite classes:

| Suite Class | What It Exercises | Allowed Doubles | Counts As Final Acceptance? | Naming Rule |
|-------------|-------------------|-----------------|-----------------------------|-------------|
| `pure_unit` | In-memory helpers, schemas, mappers, risk/idempotency classification, config parsing, redaction, small protocol helpers | No network, no daemon, no subprocess, no external service | No | Use `unit` in the test name or module name |
| `deterministic_contract` | Multi-step connector behavior against deterministic mocks or fake peers | `wiremock`, local fake servers, stub connectors, fake polling APIs, fixture payloads | No | Use `contract`, `integration`, or `compliance`; MUST NOT be named `no_mock`, `acceptance`, or `live` |
| `local_non_mock` | Real local fixture boundary without provider fakery: local DB engine, object store, webhook listener, bridge daemon, browser, filesystem, or platform API | Real local processes and loopback/private-network fixtures only | Yes | Use `local_non_mock` or `fixture_acceptance` |
| `host_e2e` | Real `fcp-host` / `fwc` / connector subprocess boundary with manifests, sandbox, receipts, and policy enforcement | Real host process; mocks allowed only behind the connector when the purpose is host-boundary verification | Yes, but only for host-boundary truth, not upstream provider semantics | Use `host_e2e` or `subprocess_e2e` |
| `live` | Real provider sandbox or nightly live verification against the true upstream service | Real sandbox/test tenant/device/account only | Yes | Use `live`, `sandbox`, or `nightly_live` |

Hard naming rule:

- If a suite depends on `wiremock`, fake polling APIs, stub connectors, or mock servers, it is supplemental confidence and MUST NOT be presented as the connector's only acceptance evidence.
- `no_mock`, `acceptance`, `host_e2e`, and `live` labels are reserved for suites that cross a real non-fake boundary.
- Bead closure comments MUST name the highest suite class actually exercised. "All tests pass" is insufficient.

### 6b. Base Suite Requirements (MUST)

Every connector MUST satisfy all of the following:

- `pure_unit` coverage for config parsing, operation routing, error translation, redaction-sensitive output, and risk/idempotency classification.
- `deterministic_contract` coverage for configure -> health/self_check -> introspect -> invoke lifecycle, error propagation, and common provider failures.
- Conformance coverage via the shared `fcp-conformance` and/or `fcp-e2e` harnesses where applicable.
- At least one suite from the acceptance classes (`local_non_mock`, `host_e2e`, `live`) according to the archetype matrix in Section 6e.

### 6c. Pure Unit Tests (MUST)

- Minimum 30 unit tests for simple connectors, 50+ for connectors with multiple operations.
- Cover every operation's success path.
- Cover every distinct error path (rate limit, auth failure, malformed response, timeout, network error).
- Unit tests MUST NOT require `wiremock`, real daemons, or real external services.
- Unit tests MUST verify `ConnectorErrorMapping`, `OperationInfo`, config validation, and redaction-sensitive output paths.
- Tests for `ConnectorErrorMapping`: verify every error variant maps to the correct `FcpError` discriminant.
- Tests for `OperationInfo` completeness: verify introspection returns all declared operations.

### 6d. Deterministic Contract / Integration Tests (MUST for connectors with lib.rs)

- Multi-step flows (configure -> invoke -> verify response).
- Error propagation chains (external error -> ConnectorErrorMapping -> FcpError).
- Health check under various states (configured, degraded, not configured).
- `wiremock::MockServer` and equivalent fake peers belong in this class, not in `pure_unit`.
- Deterministic contract coverage is REQUIRED supplemental confidence, but it MUST NOT be the sole acceptance boundary for a connector.

### 6e. Minimum Acceptance Suites by Archetype (MUST)

The minimum acceptance boundary varies by connector family:

| Archetype Family | Minimum Acceptance Requirement | Notes |
|------------------|-------------------------------|-------|
| Request-response / GraphQL | `local_non_mock` when the service can be reproduced locally; otherwise `live` | `host_e2e` is SHOULD for auth-heavy or risky/dangerous connectors |
| Webhook | `local_non_mock` + `host_e2e` | Use a real local webhook listener, signature material, duplicate-delivery handling, and end-to-end host receipts |
| Streaming / Bidirectional | `local_non_mock` + `host_e2e` | Real session lifecycle, reconnect, bounded queue, shutdown drain, and replay/ack semantics must cross a non-fake boundary |
| Queue / Pub-Sub | `local_non_mock` + `host_e2e` | Use a real broker fixture when possible; fall back to `live` for managed-only providers |
| Database | `local_non_mock` | Use a real engine instance, not SQL mocks; add `host_e2e` when admin or destructive flows depend on host policy or receipts |
| File / Blob | `local_non_mock` when a real local/object-store fixture exists; otherwise `live` | Presign/ACL semantics that cannot be safely reproduced locally require provider sandbox coverage |
| CLI / Process | `local_non_mock` + `host_e2e` | The acceptance boundary is the real child process / tool invocation path, not a fake stdout fixture alone |
| Browser | `local_non_mock` + `host_e2e` | Real browser session management is required; use `live` only for auth or anti-bot flows that cannot be represented locally |
| Bridge-backed / Mobile | `local_non_mock` + `host_e2e` | Real bridge/daemon/socket behavior is required; add `live` when the bridge alone cannot validate upstream semantics |
| Local-platform | `local_non_mock` | Real platform APIs or local automation boundaries are required; add `host_e2e` when the connector is expected to run through the host subprocess boundary |

### 6f. Acceptable Exceptions When Local Non-Mock Is Impossible (MUST)

An exception is acceptable only when a real local fixture cannot truthfully reproduce the upstream boundary. Common examples include managed SaaS-only semantics, closed mobile/cloud bridges, or anti-automation login flows.

When this happens, the connector MUST provide all of the following:

- `deterministic_contract` coverage that proves input/output shape, retries, error mapping, and denial behavior.
- `host_e2e` coverage when the connector is expected to run through `fcp-host` / `fwc`.
- `live` coverage against a provider sandbox, disposable tenant, nightly account, or explicitly documented device lab.
- README guidance that states why local non-mock acceptance is impossible, what real prerequisites exist, and how the suite is replayed safely.

### 6g. Logging, Redaction, and Replay Requirements for E2E-Capable Suites (MUST)

Every `local_non_mock`, `host_e2e`, and `live` suite MUST:

- emit schema-valid JSONL according to [`docs/testing/e2e_log_schema.md`](./testing/e2e_log_schema.md)
- include `correlation_id`, `phase`, and a truthful provenance trail (`command_mode`, `provenance_markers`, host IDs or receipt IDs when applicable)
- record the suite class in structured context as one of `local_non_mock`, `host_e2e`, or `live`
- preserve replayable artifacts (`trace.jsonl`, `summary.json`, `environment.json`, `replay.sh`) when run through `fwc` or shell-based E2E harnesses, or an equivalent documented artifact bundle when the harness is connector-local
- pass secret and PII redaction checks before artifacts are accepted

These suites MUST NOT log raw:

- `Authorization` headers
- bearer tokens, API keys, client secrets, webhook secrets, or session cookies
- provider credentials embedded in URLs or query strings
- real user PII unless the fixture data is explicitly synthetic and documented as such

For destructive or provider-sandbox suites, the artifact bundle MUST also record:

- the sandbox/test tenant identity in redacted form
- cleanup expectations
- whether the run exercised live mutation, denial, or dry-run-only flows

### 6h. Conformance Tests (MUST)

- `ComplianceSuite` (from `fcp-conformance`): default-deny enforcement, capability mismatch rejection.
- `ConnectorSuite` (from `fcp-conformance`): operation count > 0 in introspection, manifest extractability.

### 6i. Quality Gates (MUST pass)

```bash
rch exec -- cargo clippy -p <connector> --all-targets -- -D warnings
rch exec -- cargo test -p <connector>
rch exec -- cargo fmt -p <connector> -- --check
```

All three must exit 0 with no warnings.

---

## 7. Security Requirements

### MUST

- Secrets (API keys, tokens, passwords) never appear in log output, error messages, or Debug impls. Use redaction (e.g., `"sk-...XXXX"`).
- Secrets never touch disk. Keep credentials in memory only.
- All external input is validated before use. Assume everything from external services is hostile.
- Every external HTTP call has a timeout. No unbounded waits.
- Auth errors fail closed: when in doubt, deny access.

### MUST NOT

- Never log raw `Authorization` headers, bearer tokens, or API keys.
- Never include secrets in `Display` or `Debug` trait implementations.
- Never store credentials in connector state objects.

---

## 8. Connector-Specific Cargo.toml

### MUST

- Declare `fcp-sdk` as a dependency (for `ConnectorErrorMapping`, `ConnectorRuntime`, `RetryLoop`).
- Declare `fcp-core` as a dependency (for `SafetyTier`, `RiskLevel`, `IdempotencyClass`, `OperationInfo`, etc.).
- Have both `[[bin]]` and `[lib]` targets if integration tests exist.
- Use workspace-inherited dependency versions where available.

---

## 9. Definition of Done

### 9a. New Connector Implementation Bead

A new connector bead is **done** when ALL of the following are true:

1. **Compiles clean**: `cargo clippy -p <connector> --all-targets -- -D warnings` exits 0.
2. **Required suite classes pass**: `cargo test -p <connector>` exits 0 and the suite inventory satisfies Sections 6b-6g for the connector's archetype.
3. **Lifecycle correct**: `ConnectorRuntime` initialized in `configure()`, used in all request paths, `shutdown()` propagated.
4. **Retry correct**: All HTTP calls use `RetryLoop` or SDK retry infrastructure. No hand-rolled retry loops.
5. **Errors mapped**: `ConnectorErrorMapping` impl covers every error variant. Tests verify each mapping.
6. **Operations typed**: Every operation has a complete `OperationInfo` with correct `SafetyTier`, `RiskLevel`, `IdempotencyClass`, schemas, and examples.
7. **Manifest present**: `manifest.toml` declares capabilities, network constraints, sandbox profile.
8. **Health truthful**: `self_check()` / health returns actionable diagnostics. Reports degraded when service unreachable.
9. **Secrets safe**: No credential leakage in logs, errors, or Debug impls.
10. **Conformance**: Passes `ComplianceSuite` (default-deny) and `ConnectorSuite` (introspection) where applicable.
11. **Acceptance boundary truthful**: the bead closure comment explicitly names which suite class provided final acceptance evidence (`local_non_mock`, `host_e2e`, or `live`) and why that class is sufficient for the archetype.

### 9b. Existing Connector Audit/Remediation Bead

An existing connector audit bead is **done** when ALL of the following are true:

1. **Gap assessment complete**: Every MUST requirement in this contract has been checked against the connector's current implementation, with findings documented.
2. **Gaps remediated or tracked**: Every non-compliant finding is either:
   - Fixed in the same bead (preferred), or
   - Filed as a blocking child bead with specific remediation instructions.
3. **Evidence collected**: The bead's closure comment includes:
   - Test count (unit + integration).
   - Suite taxonomy classification (`pure_unit`, `deterministic_contract`, `local_non_mock`, `host_e2e`, `live`) and which one supplied the final acceptance boundary.
   - Clippy clean confirmation.
   - List of `OperationInfo` operations verified.
   - `ConnectorErrorMapping` coverage confirmed.
   - `ConnectorRuntime` lifecycle confirmed.
   - Any remaining gaps with bead references.
4. **No regressions**: All pre-existing tests still pass after remediation.

---

## 10. Archetype-Specific Supplements

These requirements are additive to the base contract above.

### Request-Response

- Operations are stateless or have minimal state.
- Each invoke returns a result directly; no background processing unless explicitly modeled.
- Timeout per request is bounded.

### Streaming / Bidirectional

- Cursor/sequence semantics defined for event replay.
- `ack`/`nack` implemented for delivery guarantees.
- Connection health tracked via `StreamHealthTracker` (from `fcp-streaming`) or equivalent.
- Reconnection logic with bounded backoff.
- Graceful drain on shutdown: stop accepting new events, flush pending, close connections.

### Polling

- Cursor state externalized (not hidden in process memory).
- Polling interval configurable.
- Resume position durable across restarts.
- Deduplication window for already-seen items.

### Webhook

- Webhook registration automated where possible.
- Incoming webhook signatures verified.
- Idempotent processing of webhook events.
- Webhook URL health monitoring.

### Database

- Connection pooling with bounded pool size.
- Query timeout enforcement.
- Transaction semantics for multi-step mutations.
- Schema introspection for resource objects.
- Safe query construction (no raw string interpolation of user input).

### CLI/Process

- Environment injection is explicit (not ambient).
- Process output captured with bounded buffer.
- Execution time bounded by wall-clock timeout.
- No child process spawning unless explicitly declared in sandbox profile.

---

## 11. Reference Implementations

These connectors are the canonical exemplars for their archetypes:

| Archetype | Exemplar | Path |
|-----------|----------|------|
| Request-Response | Anthropic | `connectors/anthropic/` |
| Bidirectional + Webhook | Telegram | `connectors/telegram/` |
| Database | PostgreSQL | `connectors/postgresql/` |

New connector authors should study the exemplar for their archetype before starting implementation.

---

## 12. V3 Implementation Checklist (Quick Reference)

```
[ ] fcp-sdk dependency in Cargo.toml
[ ] fcp-core dependency in Cargo.toml
[ ] ConnectorErrorMapping impl on error type
    [ ] from_async_error()
    [ ] to_fcp_error() with correct FcpError variants
    [ ] is_retryable() truthful
    [ ] retry_after() when provider supplies it
[ ] ConnectorRuntime field on connector struct
    [ ] Initialized in configure()
    [ ] request_context() in every invoke path
    [ ] background_context() for long-lived ops
    [ ] shutdown() called in shutdown handler
[ ] RetryLoop for all HTTP calls (no hand-rolled loops)
[ ] Typed OperationInfo for every operation
    [ ] Correct SafetyTier (Safe/Risky/Dangerous/Critical/Forbidden)
    [ ] Correct RiskLevel (Low/Medium/High/Critical)
    [ ] Correct IdempotencyClass (None/BestEffort/Strict)
    [ ] Input and output JSON Schemas
    [ ] At least one example per operation
    [ ] AI hints (when_to_use, common_mistakes)
[ ] manifest.toml with capabilities, network, sandbox
[ ] Health/self_check returns truthful diagnostics
[ ] Secrets redacted in all log/error/Debug paths
[ ] Pure unit tests (30+ simple, 50+ complex)
    [ ] Success path per operation
    [ ] Error path per distinct failure mode
    [ ] ConnectorErrorMapping coverage
    [ ] OperationInfo introspection completeness
[ ] Deterministic contract / integration tests (multi-step flows, mock-backed if needed)
[ ] Acceptance suite matches archetype matrix (`local_non_mock`, `host_e2e`, or `live`)
[ ] E2E-capable suites emit schema-valid logs + replayable artifacts
[ ] cargo clippy --all-targets -- -D warnings clean
[ ] cargo test passes
[ ] cargo fmt --check passes
```

---

## Relationship to Other Documents

| Document | Relationship |
|----------|-------------|
| `FCP_Specification_V3.md` | Canonical protocol specification; this contract extracts the connector-specific requirements |
| `STANDARD_Connector_Compliance.md` | Legacy V2 checklist; superseded by this contract for all new and audit work |
| `STANDARD_Connector_Testing.md` | Legacy V2 testing requirements; this contract defines the V3 testing bar |
| `docs/testing/coverage-inventory.md` | Live inventory of the current workspace test surface; use it to plan remediation against this policy |
| `FCP3_Retirement_Kill_List.md` | Compatibility abstractions scheduled for removal; connectors must not depend on them |
| `FWC_Host_First_Truthfulness_Playbook.md` | Host-side truthfulness requirements; complementary to this connector-side contract |

---

## Changelog

- **1.1.0** (2026-03-23): Added explicit testing taxonomy, archetype-specific acceptance minimums, non-mock exception rules, and E2E logging/redaction requirements. Clarifies that mock-backed suites are supplemental confidence, not final acceptance evidence.
- **1.0.0** (2026-03-18): Initial V3 acceptance contract. Codifies non-negotiables from V3 spec, README, and implemented exemplar patterns. Defines done-definitions for new-connector and audit-remediation beads. Retroactively binding on all workspace connectors.
