# FCP V2 Connector Compliance Checklist (NORMATIVE)

> **Status**: NORMATIVE
> **Version**: 1.0.0
> **Last Updated**: January 2026
> **Bead Reference**: `flywheel_connectors-dz01`

---

## Purpose

This checklist captures all NORMATIVE requirements from FCP Specification V2 and docs/fcp_model_connectors_rust.md that every connector MUST satisfy. Use this as a reference when creating or reviewing connector beads.

**Goal**: Provide a single authoritative, V2-only checklist of all mechanical connector compliance requirements so new connectors can be reviewed for conformance without re-reading the spec/docs.

---

## 1. Connector Definition (NORMATIVE)

### 1.1 Required Fields

Every connector MUST define:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `ConnectorId` | Unique identifier (canonical: lowercase ASCII, `^[a-z0-9][a-z0-9._:-]*$`) |
| `name` | `String` | Human-readable name |
| `version` | `Version` | Semantic version |
| `format` | `ConnectorFormat` | Native or WASI |
| `archetypes` | `Vec<ConnectorArchetype>` | From closed set |
| `operations` | `Vec<Operation>` | All operations provided |
| `events` | `Vec<EventType>` | Events emitted (if any) |
| `required_caps` | `Vec<CapabilityId>` | Capabilities connector requires |
| `optional_caps` | `Vec<CapabilityId>` | Optional capabilities |
| `forbidden_caps` | `Vec<CapabilityId>` | Capabilities connector must NOT have |

### 1.2 ConnectorArchetype (Closed Set)

```rust
pub enum ConnectorArchetype {
    Bidirectional, // Sends and receives messages
    Streaming,     // Emits events (read-only)
    Operational,   // Executes operations (write)
    Storage,       // Stores/retrieves data
    Knowledge,     // Provides knowledge/search
}
```

### 1.3 ConnectorFormat (NORMATIVE)

```rust
pub enum ConnectorFormat {
    Native, // Requires OS-level sandboxing (seccomp, landlock, AppArmor)
    Wasi,   // RECOMMENDED for high-risk connectors (financial, credentials, external API)
}
```

**Guidance:**
- WASI format SHOULD be used for SafetyTier::Dangerous operations
- WASI provides memory isolation, capability-gated hostcalls, cross-platform consistency

---

## 2. Connector State Model (NORMATIVE)

### 2.1 State Model Declaration

Every connector MUST declare one:

```rust
pub enum ConnectorStateModel {
    Stateless,           // No mesh-persisted state
    SingletonWriter,     // Exactly one writer via Lease
    Crdt { crdt_type },  // Multi-writer via CRDT (rare; justify)
}
```

### 2.2 State Persistence Rules

- Connectors with polling/cursors/dedup caches MUST externalize state to mesh
- Local `$CONNECTOR_STATE` is cache only
- Authoritative state lives as mesh objects
- Single-writer connectors MUST use Lease for fencing

### 2.3 Fork Detection (NORMATIVE for singleton_writer)

- Two `ConnectorStateObject` with same `prev` = SAFETY INCIDENT
- MUST pause connector execution
- MUST log fork event for audit

---

## 3. Zone Architecture (NORMATIVE)

### 3.1 Single-Zone Binding

- Connector instance MUST bind to exactly ONE zone
- Cross-zone access requires explicit policy

### 3.2 Standard Zone Hierarchy

```
z:owner         → Full owner access
z:private       → Personal data
z:work          → Work services
z:project:<name>→ Per-project isolation
z:community     → Semi-trusted communities
z:public        → Public/untrusted inputs
```

### 3.3 Zone Rules

1. **Default deny** — If capability not granted to zone, impossible to invoke
2. **No cross-connector calling** — All composition through Gateway

---

## 4. Capability System (NORMATIVE)

### 4.1 Capability Definition

```rust
pub struct Capability {
    pub id: CapabilityId,
    pub risk_level: RiskLevel,      // Low, Medium, High, Critical
    pub safety_tier: SafetyTier,    // Safe, Risky, Dangerous, Forbidden
    pub idempotency: IdempotencyClass,
    pub requires_approval: ApprovalMode,
    pub audit_level: AuditLevel,
    pub agent_hint: AgentHint,
}
```

### 4.2 SafetyTier (NORMATIVE)

```rust
pub enum SafetyTier {
    Safe,      // No approval needed
    Risky,     // Policy-based approval
    Dangerous, // Interactive human approval
    Forbidden, // Never allowed
}
```

**Mapping:**

| SafetyTier | Approval | Audit | Use Case |
|------------|----------|-------|----------|
| Safe | None | Minimal | Read-only operations |
| Risky | Policy | Standard | Write operations |
| Dangerous | Interactive | Full | Destructive/irreversible |
| Forbidden | N/A | N/A | Never allowed |

### 4.3 ApprovalMode (NORMATIVE)

```rust
pub enum ApprovalMode {
    None,              // No approval needed
    Policy,            // Policy-based auto-approval
    Interactive,       // Human approval required
    ApprovalRequired,  // Requires ApprovalToken
}
```

---

## 5. NetworkConstraints (NORMATIVE)

### 5.1 Default-Deny Allowlists

```rust
pub struct NetworkConstraints {
    pub host_allow: Vec<String>,     // Allowed hostnames
    pub port_allow: Vec<u16>,        // Allowed ports
    pub ip_allow: Vec<IpAddr>,       // Optional explicit IPs
    pub cidr_deny: Vec<String>,      // NORMATIVE defaults below
    pub deny_localhost: bool,        // NORMATIVE default: true
    pub deny_private_ranges: bool,   // NORMATIVE default: true
    pub deny_tailnet_ranges: bool,   // NORMATIVE default: true
    pub deny_ip_literals: bool,      // NORMATIVE default: true
    pub require_sni: bool,           // Enforce SNI match
    pub spki_pins: Vec<String>,      // Optional SPKI pins
    pub require_host_canonicalization: bool, // NORMATIVE default: true
}
```

### 5.2 NORMATIVE CIDR Deny Defaults

All connectors MUST deny these ranges by default:

| CIDR | Description |
|------|-------------|
| `127.0.0.0/8` | Localhost IPv4 |
| `::1` | Localhost IPv6 |
| `169.254.0.0/16` | Link-local |
| `10.0.0.0/8` | RFC1918 Private |
| `172.16.0.0/12` | RFC1918 Private |
| `192.168.0.0/16` | RFC1918 Private |
| `100.64.0.0/10` | Tailnet/CGNAT ranges |

### 5.3 Host Canonicalization (NORMATIVE)

All hostnames MUST be:
- Lowercase
- IDNA2008 encoded
- No trailing dot
- Implementations MUST reject non-canonical forms

---

## 6. Egress Proxy & Credential Injection (NORMATIVE)

### 6.1 Secretless Connectors (RECOMMENDED)

- Credentials injected by egress proxy at network boundary
- Raw secrets never enter connector memory
- Credentials declared via `credential_allow` in `CapabilityConstraints`

### 6.2 CredentialObject (NORMATIVE)

```rust
pub struct CredentialObject {
    pub credential_id: CredentialId,
    pub secret_id: SecretId,
    pub apply: CredentialApply,     // HttpHeader or QueryParam
    pub host_allow: Vec<String>,    // Defense-in-depth binding
}
```

### 6.3 CredentialApply Methods

```rust
pub enum CredentialApply {
    HttpHeader { name: String, prefix: Option<String> },
    QueryParam { name: String },
}
```

Examples:
- `HttpHeader { name: "Authorization", prefix: Some("Bearer ") }`
- `HttpHeader { name: "X-API-Key", prefix: None }`
- `QueryParam { name: "api_key" }`

### 6.4 EgressHttpRequest (NORMATIVE)

```rust
pub struct EgressHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub credential: Option<CredentialId>, // Proxy injects this
}
```

---

## 7. Provenance and Taint (NORMATIVE)

### 7.1 TaintFlags (NORMATIVE)

```rust
bitflags! {
    pub struct TaintFlags: u32 {
        const NONE            = 0;
        const PUBLIC_INPUT    = 1 << 0;  // z:public, web
        const EXTERNAL_INPUT  = 1 << 1;  // Paired external identities
        const UNVERIFIED_LINK = 1 << 2;  // URLs/attachments not scanned
        const USER_SUPPLIED   = 1 << 3;  // Direct human input
        const PROMPT_SURFACE  = 1 << 4;  // Content interpreted by LLM
    }
}
```

### 7.2 Taint Propagation Rules

| Source | Taint Applied |
|--------|---------------|
| Webhook payload | `EXTERNAL_INPUT` |
| User form input | `USER_SUPPLIED` |
| z:public zone | `PUBLIC_INPUT` |
| Unscanned URLs | `UNVERIFIED_LINK` |
| LLM input | `PROMPT_SURFACE` |

### 7.3 Taint Enforcement (NORMATIVE)

- Public-tainted input cannot directly drive Dangerous operations
- If `effective_taint() != NONE` and `operation.safety_tier >= Risky`, ApprovalToken required

### 7.4 SanitizerReceipt (NORMATIVE)

Machine-verifiable proof of sanitization:

```rust
pub struct SanitizerReceipt {
    pub sanitizer_id: String,
    pub sanitizer_version: Version,
    pub input_hash: Hash,
    pub output_hash: Hash,
    pub taints_cleared: TaintFlags,
    pub evidence: SanitizationEvidence,
    pub timestamp: DateTime<Utc>,
}
```

- Clears specific taints with evidence
- Connector version tracked for CVE auditing

---

## 8. Testing Requirements (NORMATIVE)

Full connector testing requirements and quality gates live in
`STANDARD_Connector_Testing.md`. The checklist below highlights the
minimum compliance-focused tests that must be present.

### 8.1 Unit Tests (Mock-Only)

- MUST NOT make real API calls
- Use wiremock or similar for HTTP mocking
- Test error conditions and rate limits
- Golden vectors for canonical serialization

### 8.2 Integration Tests

- Mock external services
- Test multi-component scenarios
- Verify error handling

### 8.3 E2E Compliance

Run the shared compliance runner to validate:

| Check | Requirement |
|-------|-------------|
| Default deny | Operations fail without capability |
| NetworkConstraints | Blocked hosts/ports rejected |
| Receipts | Dangerous ops generate receipts |
| Audit | Structured logs present |
| Taint | External input tracked |

Capture evidence bundle for audit trail.

---

## 9. Audit and Observability (NORMATIVE)

### 9.1 AuditEvent Requirements

- All writes/dangerous ops MUST emit AuditEvent
- Correlation IDs for tracing
- No secrets in logs
- Structured JSON format

### 9.2 Required AuditEvent Fields

```json
{
  "timestamp": "2026-01-15T10:30:00.123456Z",
  "event_type": "operation_invoked",
  "connector_id": "fcp.example",
  "operation_id": "example.write",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
  "zone_id": "z:work:project-alpha",
  "safety_tier": "risky",
  "approval_token": "apr_xyz789",
  "outcome": "success"
}
```

### 9.3 Logging Requirements

| Do | Don't |
|----|-------|
| Log operation IDs | Log API keys |
| Log correlation IDs | Log passwords |
| Log reason codes | Log PII |
| Log error types | Log request bodies with secrets |

---

## 10. Manifest Requirements

### 10.1 Required Manifest Sections

```toml
[connector]
id = "fcp.<service>"
name = "Human Name"
version = "1.0.0"
archetypes = ["operational"]  # From closed set

[connector.state]
model = "singleton_writer"  # or "stateless" or "crdt"
state_schema_version = "1"

[connector.network]
host_allow = ["api.service.com"]
port_allow = [443]
deny_localhost = true
deny_private_ranges = true
```

### 10.2 Sandbox Profile (NORMATIVE)

| Profile | Syscalls | Network | Use Case |
|---------|----------|---------|----------|
| Strict | Minimal | Egress proxy only | Financial, credentials |
| Moderate | Limited | Proxy required | Most connectors |
| Permissive | Full | Direct allowed | Development only |

---

## Quick Reference: Compliance Checklist

### Connector Definition
- [ ] ConnectorId is canonical (lowercase, ASCII, `^[a-z0-9][a-z0-9._:-]*$`)
- [ ] Archetypes from closed set only (Bidirectional/Streaming/Operational/Storage/Knowledge)
- [ ] Format specified (Native or WASI)
- [ ] WASI used for SafetyTier::Dangerous operations

### State Management
- [ ] State model declared (Stateless/SingletonWriter/Crdt)
- [ ] State externalized to mesh (not local-only)
- [ ] Fork detection implemented for singleton_writer
- [ ] Lease acquisition for single-writer model

### Security
- [ ] NetworkConstraints default-deny with explicit allowlist
- [ ] All NORMATIVE CIDR denies applied (localhost, private, tailnet)
- [ ] Host canonicalization enforced (lowercase, IDNA2008)
- [ ] Credential injection via egress proxy (secretless)
- [ ] Taint tracking for external inputs
- [ ] ApprovalToken required for tainted + risky operations

### Capabilities
- [ ] SafetyTier assigned per operation
- [ ] ApprovalMode defined per operation
- [ ] AgentHints provided for LLM guidance
- [ ] RiskLevel categorized (Low/Medium/High/Critical)

### Testing
- [ ] Unit tests mock-only (no real API calls)
- [ ] E2E compliance runner passes
- [ ] Golden vectors for serialization
- [ ] Error conditions tested
- [ ] Rate limit handling tested

### Observability
- [ ] AuditEvents for dangerous ops
- [ ] Structured JSON logs
- [ ] No secrets logged
- [ ] Correlation IDs present
- [ ] Reason codes for denials

---

## Acceptance Criteria

This standard is satisfied when:

- [ ] Checklist is V2-only and covers all NORMATIVE connector requirements
- [ ] Each section enables mechanical verification without implicit assumptions
- [ ] Checklist is synchronized with Requirements Index (flywheel_connectors-1n78.1)
- [ ] Compliance runner validates all checklist items
- [ ] New connector beads reference this checklist

---

## References

- FCP_Specification_V2.md (canonical spec)
- docs/fcp_model_connectors_rust.md (connector implementation guide)
- STANDARD_Connector_Testing.md (connector testing requirements)
- STANDARD_Testing_Logging.md (testing requirements)
- STANDARD: Connector Spec Template (flywheel_connectors-lszk.5)
