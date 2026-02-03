# STANDARD: Connector Specification Template (FCP2)

> **Status**: NORMATIVE
> **Version**: 1.0.0
> **Last Updated**: January 2026
> **Bead Reference**: `flywheel_connectors-lszk.5`

---

## Purpose

This document provides a canonical copy/paste template for planning **new FCP2 connectors** in Beads. Every connector plan should be mechanically consistent with FCP2 requirements and include tests/E2E from day one.

**Goal**: Ensure every connector is V2-only compliant with single-zone binding, default deny, NetworkConstraints, receipts/audit, taint/approval, and comprehensive testing.

---

## Required Bead Structure

For each connector **epic** (e.g., `fcp.slack`, `fcp.github`), create these beads:

| Bead Suffix | Purpose | Template Section |
|-------------|---------|------------------|
| `<connector>.1` | Manifest + Capability Map (FCP2) | [Section 3](#3-template-manifest--capability-map-bead) |
| `<connector>.2` | Provisioning Automation (OAuth/webhooks/setup) | [Section 4](#4-template-provisioning-bead) |
| `<connector>.3` | TEST: Unit/Integration Tests (mock-only) | [Section 5](#5-template-test-bead) |
| `<connector>.4` | E2E: Connector Compliance Run | [Section 6](#6-template-e2e-compliance-bead) |

**Dependency Rules:**
- Feature beads under the epic MUST depend on `<connector>.1` (manifest/caps)
- Features requiring persistent cursor/dedupe/streaming state MUST depend on `flywheel_connectors-1n78.33`

---

## Scaffolded Module Layout (fcp new)

When you run `fcp new`, the connector scaffold should follow this layout:

```
connectors/<service>/src/
├── lib.rs           # re-exports + archetype declaration
├── main.rs          # stdin/stdout loop or host integration
├── connector.rs     # FcpConnector impl
├── config.rs        # config + defaults (no secrets)
├── error.rs         # error taxonomy + retryability
├── types.rs         # platform API types
├── limits.rs        # platform limits + TODOs
├── api.rs           # request-response client (if applicable)
├── stream.rs        # streaming supervisor (streaming/bidirectional)
└── polling.rs       # polling cursor + scheduler (polling only)
```

Notes:
- `api.rs` is only generated for request-response connectors.
- `stream.rs` is only generated for streaming/bidirectional connectors.
- `polling.rs` is only generated for polling connectors.

---

## 1. Template: Connector Epic Description

Copy and customize this template for new connector epic beads.

```markdown
# fcp.<service>: <Human-Readable Name> Connector

## 1. Goal

<One sentence describing what this connector enables.>

Example: "Enable AI agents to search, read, create, and manage issues in Jira for project coordination."

## 2. Hard Requirements (FCP2)

All connectors MUST satisfy:

- [ ] **Single-zone binding**: Exactly one `ZoneId` per connector instance
- [ ] **Default deny**: Every operation requires explicit CapabilityTokens
- [ ] **Sandbox + NetworkConstraints**: Enforced mechanically
- [ ] **Receipts + audit**: For all writes/dangerous operations
- [ ] **No secrets on disk**: Strict log redaction
- [ ] **Secretless preferred**: Credentials injected at network boundary via egress proxy

## 3. Manifest Archetypes

Select from the closed set (only valid options):

| Archetype | Applies? | Justification |
|-----------|----------|---------------|
| `bidirectional` | [ ] | Sends and receives messages |
| `streaming` | [ ] | Emits events (read-only) |
| `operational` | [ ] | Executes operations (write) |
| `storage` | [ ] | Stores/retrieves data |
| `knowledge` | [ ] | Provides knowledge/search |

**Note**: "webhook", "polling", "request-response", "database" are interaction patterns, not archetypes.

## 4. External Surface (Mechanical)

### NetworkConstraints Allowlist

| Host | Port | Purpose |
|------|------|---------|
| `api.<service>.com` | 443 | Primary API |
| `<other>.com` | 443 | <Purpose> |

### Redirect Policy

- [ ] Deny redirects to new hosts (default)
- [ ] Allow redirects within allowlist only
- [ ] Specific redirect rules: <describe>

### Timeouts and Limits

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `connect_timeout_ms` | 10000 | <rationale> |
| `total_timeout_ms` | 60000 | <rationale> |
| `max_response_bytes` | 10485760 | 10MB limit |
| `max_redirects` | 3 | Prevent redirect loops |

## 5. Capability Model

### Capability Families

| Family | Description | Example Operations |
|--------|-------------|-------------------|
| `<service>.read` | Read-only access | list_*, get_*, search_* |
| `<service>.write` | Modify resources | create_*, update_*, delete_* |
| `<service>.admin` | Administrative | configure_*, manage_* |

### Operation → Capability Mapping

| Operation | Required Capability | SafetyTier | Approval |
|-----------|---------------------|------------|----------|
| `list_items` | `<service>.read` | Safe | None |
| `get_item` | `<service>.read` | Safe | None |
| `create_item` | `<service>.write` | Risky | Policy |
| `delete_item` | `<service>.write` | Dangerous | Interactive |

**Rule**: Capability IDs MUST NOT encode hostnames/ports.

## 6. State Model

Declare exactly ONE:

- [ ] `stateless` — No mesh-persisted state
- [ ] `singleton_writer` — Exactly one writer via Lease (most common)
- [ ] `crdt` — Multi-writer via CRDT (rare; requires justification)

### Persisted State (if not stateless)

| State Type | Purpose | Bounded By |
|------------|---------|------------|
| `cursor` | Pagination position | Single value per query |
| `dedupe_keys` | Prevent duplicate processing | Max 10,000 entries, 24h TTL |
| `mapping_table` | External ID → ObjectId | Max 100,000 entries |

### Fork Detection (singleton_writer only)

- [ ] Implement ConnectorStateObject with `prev` pointer
- [ ] Detect two objects with same `prev` as SAFETY INCIDENT
- [ ] Pause execution and log fork event on detection

## 7. Security / Taint / Approval

### Tainted Inputs

| Source | Taint Flag | Requires |
|--------|------------|----------|
| Webhook payloads | `EXTERNAL_INPUT` | Validation |
| User-provided URLs | `UNVERIFIED_LINK` | Scanning before follow |
| API response metadata | `EXTERNAL_INPUT` | Sanitization |

### Approval Requirements

| Condition | Approval Required |
|-----------|-------------------|
| Tainted input + Safe operation | None |
| Tainted input + Risky operation | ApprovalToken |
| Tainted input + Dangerous operation | Interactive + ApprovalToken |
| Clean input + Dangerous operation | Interactive |

## 8. Observability

### Required Log Fields

```json
{
  "connector_id": "fcp.<service>",
  "operation_id": "<operation>",
  "zone_id": "z:<zone>",
  "correlation_id": "<uuid>",
  "request_id": "<external_request_id>"
}
```

### Reason Codes

| Code | Meaning |
|------|---------|
| `FCP-2001` | Operation not granted |
| `FCP-2002` | Token expired |
| `FCP-2003` | Zone mismatch |
| `FCP-2101` | Network constraint violation |
| `FCP-<XXXX>` | <Service-specific codes> |

### Redaction Rules

- [ ] API keys/tokens NEVER logged
- [ ] User PII NEVER logged
- [ ] Request bodies with sensitive data REDACTED
- [ ] External IDs MAY be logged (for correlation)

## 9. Testing Strategy

### Unit Tests (Mock-Only)

- [ ] Mock all external API calls
- [ ] Test happy path for each operation
- [ ] Test error conditions (rate limits, auth failures, malformed responses)
- [ ] Golden vectors for canonical serialization

### Integration Tests

- [ ] Multi-operation scenarios with mocked external services
- [ ] State persistence verification
- [ ] Error recovery flows

### E2E Compliance

- [ ] Run shared compliance runner
- [ ] Verify default deny behavior
- [ ] Verify NetworkConstraints enforcement
- [ ] Capture evidence bundle

## 10. Acceptance Criteria

- [ ] Passes compliance runner (static + dynamic)
- [ ] No real external calls in unit tests
- [ ] Dangerous ops audited/receipted and approval gated
- [ ] Manifest validates against schema
- [ ] All capabilities documented
- [ ] State model documented and bounded
```

---

## 2. Template: Epic Bead YAML

```yaml
# Example: fcp.jira connector epic
title: "fcp.jira: Atlassian Jira Enterprise Issue Tracking Connector"
type: epic
priority: P1
labels:
  - connectors
  - fcp2
  - tier2

depends_on:
  - flywheel_connectors-1n78.19  # Connector Manifest
  - flywheel_connectors-1n78.21.5  # Compliance Runner

description: |
  # fcp.jira: Atlassian Jira Enterprise Issue Tracking Connector

  ## Goal
  Enable AI agents to search, read, create, update, and manage issues
  in Jira for project coordination and development workflow integration.

  ## Archetypes
  - operational (issue CRUD)
  - knowledge (search, JQL queries)
  - streaming (webhooks for issue updates)

  ## NetworkConstraints
  - host_allow: ["*.atlassian.net", "*.jira.com"]
  - port_allow: [443]

  ## State Model
  singleton_writer — cursor for change tracking, webhook dedupe
```

---

## 3. Template: Manifest + Capability Map Bead

```markdown
# fcp.<service>.1: Manifest + Capability Map (FCP2)

## Goal
Define the complete connector manifest and capability mapping for fcp.<service>.

## Manifest Structure

### [connector] Section

```toml
[connector]
id = "fcp.<service>"
name = "<Human-Readable Name>"
version = "1.0.0"
archetypes = ["operational", "knowledge"]  # From closed set only

[connector.state]
model = "singleton_writer"
state_schema_version = "1"
```

### [connector.network] Section

```toml
[connector.network]
host_allow = ["api.<service>.com"]
port_allow = [443]
deny_localhost = true
deny_private_ranges = true
deny_tailnet_ranges = true
deny_ip_literals = true
require_host_canonicalization = true
max_redirects = 3
connect_timeout_ms = 10000
total_timeout_ms = 60000
max_response_bytes = 10485760
```

### [connector.credentials] Section

```toml
[connector.credentials]
# Secretless: credential injected by egress proxy
credential_id = "cred.<service>.api_key"
apply = { type = "HttpHeader", name = "Authorization", prefix = "Bearer " }
host_allow = ["api.<service>.com"]
```

## Operations

### List Operations

| Operation | Schema ID | Input | Output |
|-----------|-----------|-------|--------|
| `list_<resources>` | `schema:<hash>` | `ListRequest` | `ListResponse` |
| `get_<resource>` | `schema:<hash>` | `GetRequest` | `<Resource>` |
| `create_<resource>` | `schema:<hash>` | `CreateRequest` | `<Resource>` |
| `update_<resource>` | `schema:<hash>` | `UpdateRequest` | `<Resource>` |
| `delete_<resource>` | `schema:<hash>` | `DeleteRequest` | `DeleteResponse` |

### Capability Definitions

```rust
// Required capabilities per operation
pub const CAPABILITIES: &[(&str, &str, SafetyTier)] = &[
    ("list_<resources>", "<service>.read", SafetyTier::Safe),
    ("get_<resource>", "<service>.read", SafetyTier::Safe),
    ("create_<resource>", "<service>.write", SafetyTier::Risky),
    ("update_<resource>", "<service>.write", SafetyTier::Risky),
    ("delete_<resource>", "<service>.write", SafetyTier::Dangerous),
];
```

## Sandbox Profile

| Profile | Syscalls | Network | Justification |
|---------|----------|---------|---------------|
| Moderate | Limited | Proxy required | Standard API connector |

## Static Compliance Checks

- [ ] ConnectorId is canonical (lowercase, ASCII)
- [ ] Archetypes from closed set only
- [ ] NetworkConstraints present with deny defaults
- [ ] Credential injection configured (secretless)
- [ ] All operations have capability mappings

## Acceptance Criteria

- [ ] Manifest parses and validates
- [ ] All operations documented
- [ ] Capability families defined
- [ ] NetworkConstraints complete
```

---

## 4. Template: Provisioning Bead

```markdown
# fcp.<service>.2: Provisioning Automation

## Goal
Automate the setup of credentials, webhooks, and OAuth for fcp.<service>.

## Auth Setup (Secretless Preferred)

### Option A: API Key (Recommended)

1. User obtains API key from <service> dashboard
2. Create CredentialObject:
   ```rust
   CredentialObject {
       credential_id: "cred.<service>.api_key",
       secret_id: "sec.<service>.<user_hash>",
       apply: CredentialApply::HttpHeader {
           name: "Authorization".into(),
           prefix: Some("Bearer ".into()),
       },
       host_allow: vec!["api.<service>.com".into()],
   }
   ```
3. Egress proxy injects credential at request time
4. Connector NEVER sees raw secret bytes

### Option B: OAuth 2.0

1. `fcp setup <service>` initiates OAuth flow
2. User authenticates in browser
3. Token stored as CredentialObject
4. Refresh handled by credential manager

## Webhook Setup (if applicable)

1. Register webhook endpoint: `https://<mesh_node>/webhooks/fcp.<service>`
2. Configure events: `<list of webhook events>`
3. Verify signature using shared secret
4. Store webhook secret as CredentialObject

## Readiness Checks

```bash
fcp doctor <service>
```

Verifies:
- [ ] CredentialObject exists and is valid
- [ ] API endpoint reachable (with rate limit awareness)
- [ ] Required scopes/permissions present
- [ ] Webhook endpoint registered (if applicable)

## Mock Support

All provisioning operations MUST be mockable:
- [ ] OAuth flow mockable with test tokens
- [ ] API validation mockable with recorded responses
- [ ] Webhook registration mockable

## Acceptance Criteria

- [ ] `fcp setup <service>` completes successfully
- [ ] `fcp doctor <service>` passes all checks
- [ ] Credentials stored via CredentialObject (secretless)
- [ ] All setup paths testable with mocks
```

---

## 5. Template: Test Bead

```markdown
# fcp.<service>.3: TEST: Unit/Integration Tests

## Goal
Comprehensive test coverage for fcp.<service> with mock-only external calls.

## Test Structure

```
tests/
├── unit/
│   ├── operations/
│   │   ├── test_list_<resources>.rs
│   │   ├── test_get_<resource>.rs
│   │   ├── test_create_<resource>.rs
│   │   ├── test_update_<resource>.rs
│   │   └── test_delete_<resource>.rs
│   ├── auth/
│   │   └── test_credential_injection.rs
│   └── serialization/
│       └── test_canonical_cbor.rs
├── integration/
│   ├── test_multi_operation_flow.rs
│   ├── test_state_persistence.rs
│   └── test_error_recovery.rs
└── vectors/
    ├── <service>/
    │   ├── responses/
    │   │   ├── list_success.json
    │   │   ├── list_paginated.json
    │   │   ├── error_rate_limit.json
    │   │   └── error_auth.json
    │   └── expected/
    │       ├── list_output.json
    │       └── error_handling.json
```

## Mock Server Setup

```rust
use wiremock::{MockServer, Mock, ResponseTemplate};
use wiremock::matchers::{method, path, header};

async fn setup_mock_server() -> MockServer {
    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/<resources>"))
        .and(header("Authorization", "Bearer test_token"))
        .respond_with(ResponseTemplate::new(200)
            .set_body_json(load_vector("list_success.json")))
        .mount(&mock_server)
        .await;

    mock_server
}
```

## Required Test Cases

### Success Path Tests

- [ ] List resources (empty, single page, paginated)
- [ ] Get single resource (exists, not found)
- [ ] Create resource (valid input, all fields)
- [ ] Update resource (partial, full)
- [ ] Delete resource (exists, idempotent)

### Error Condition Tests

- [ ] Authentication failure (401)
- [ ] Authorization failure (403)
- [ ] Rate limiting (429 with retry-after)
- [ ] Server error (500, 502, 503)
- [ ] Malformed response (invalid JSON)
- [ ] Network timeout
- [ ] Invalid input (schema validation)

### Golden Vector Tests

- [ ] Canonical CBOR serialization
- [ ] Request signature generation
- [ ] Response parsing
- [ ] Error code mapping

### State Tests (if singleton_writer)

- [ ] Cursor persistence
- [ ] Dedupe key handling
- [ ] Fork detection

## Coverage Requirements

| Component | Minimum |
|-----------|---------|
| Operations | 90% |
| Error handling | 85% |
| Serialization | 95% |

## Acceptance Criteria

- [ ] All tests pass with mock server only
- [ ] No real external API calls
- [ ] Golden vectors match expected outputs
- [ ] Coverage thresholds met
- [ ] Tests run in CI without network access
```

---

## 6. Template: E2E Compliance Bead

```markdown
# fcp.<service>.4: E2E: Connector Compliance Run

## Goal
Verify fcp.<service> passes all FCP2 compliance requirements.

## Compliance Runner Execution

```bash
fcp compliance run fcp.<service> --output evidence/
```

## Validation Checklist

### Default Deny

- [ ] Operation fails without CapabilityToken
- [ ] DecisionReceipt generated on denial
- [ ] Denial reason code present

### NetworkConstraints

- [ ] Requests to non-allowlisted hosts blocked
- [ ] Requests to blocked CIDRs blocked
- [ ] IP literal requests blocked
- [ ] Redirect to new host blocked

### Capability Enforcement

- [ ] Read operations require read capability
- [ ] Write operations require write capability
- [ ] Dangerous operations require interactive approval

### Receipts and Audit

- [ ] Write operations generate receipts
- [ ] Dangerous operations generate receipts
- [ ] Receipts contain required fields
- [ ] Audit log entries present

### Taint Tracking

- [ ] External input tagged with taint
- [ ] Tainted input + risky op requires approval
- [ ] Taint cleared with SanitizerReceipt

### Observability

- [ ] Structured JSON logs emitted
- [ ] Correlation IDs present
- [ ] No secrets in logs
- [ ] Reason codes for all denials

## Evidence Bundle

The compliance run produces:

```
evidence/
├── run_metadata.json
├── test_results.json
├── logs/
│   └── structured_logs.jsonl
├── receipts/
│   └── *.cbor
├── audit/
│   └── audit_events.jsonl
└── coverage/
    └── lcov.info
```

## Failure Remediation

If compliance fails:

1. Review `test_results.json` for specific failures
2. Check `logs/structured_logs.jsonl` for denial reasons
3. Update connector implementation
4. Re-run compliance: `fcp compliance run fcp.<service>`

## Acceptance Criteria

- [ ] Compliance runner exits 0
- [ ] All validation checks pass
- [ ] Evidence bundle complete
- [ ] No manual intervention required
```

---

## Quick Reference: Bead Dependencies

```
fcp.<service> (epic)
├── fcp.<service>.1 (Manifest + Caps)
│   ├── depends_on: flywheel_connectors-1n78.19 (Connector Manifest)
│   └── depends_on: flywheel_connectors-1n78.21.5 (Compliance Runner)
├── fcp.<service>.2 (Provisioning)
│   ├── depends_on: fcp.<service>.1
│   └── depends_on: flywheel_connectors-1n78.31 (Automation Recipes)
├── fcp.<service>.3 (Tests)
│   ├── depends_on: fcp.<service>.1
│   └── depends_on: flywheel_connectors-h32 (Testing Standard)
└── fcp.<service>.4 (E2E Compliance)
    ├── depends_on: fcp.<service>.1
    ├── depends_on: fcp.<service>.3
    └── depends_on: flywheel_connectors-e3i9 (E2E Framework)
```

---

## Related Standards

| Document | Purpose |
|----------|---------|
| STANDARD_Connector_Compliance.md | Full compliance checklist |
| STANDARD_Connector_Testing.md | Connector testing requirements + quality gates |
| STANDARD_Testing_Logging.md | Testing and logging requirements |
| STANDARD_Requirements_Index.md | Spec-to-implementation matrix |
| FCP_Specification_V2.md | Canonical protocol specification |

---

## Acceptance Criteria

This standard is satisfied when:

- [ ] Template enables mechanical consistency across all new connectors
- [ ] All template sections map to FCP2 requirements
- [ ] Copy/paste workflow produces valid bead structure
- [ ] New connector beads reference this template
- [ ] Template aligns with compliance checklist and testing standards

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01 | Initial template based on FCP V2 spec |
