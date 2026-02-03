# FCP2 Connector Testing Requirements and Quality Gates

> **Status**: NORMATIVE
> **Version**: 1.0.0
> **Last Updated**: February 3, 2026
> **Bead Reference**: `flywheel_connectors-h32`

---

## Purpose

This document defines **mandatory** testing requirements and quality gates for all FCP2 connectors.
It is connector-specific and **adds** to the platform-wide testing/logging requirements in
`STANDARD_Testing_Logging.md`.

**Goal**: Every connector is mechanically verifiable with mock-only unit tests and deterministic E2E
compliance runs. Failures must be diagnosable from CI artifacts alone.

---

## Relationship to Other Standards

- **Platform baseline**: `STANDARD_Testing_Logging.md` (applies to all code).
- **Connector compliance**: `STANDARD_Connector_Compliance.md` (requirements checklist).
- **Connector planning**: `STANDARD_Connector_Spec_Template.md` (bead template and E2E structure).

If any requirements conflict, this document is authoritative **for connectors**.

---

## 1. Quality Gates (Connector PRs)

Every connector PR MUST pass **all** of the following:

```bash
# Compiler errors and warnings (strict)
cargo check --all-targets

# Clippy lints - pedantic + nursery enabled, warnings are errors
cargo clippy --all-targets -- -D warnings

# Formatting verification
cargo fmt --check

# Connector tests (mock-only + deterministic)
cargo test -p fcp-<connector>

# Compliance harness (static + dynamic)
# (Exact command may vary with harness evolution)
fcp compliance run fcp.<connector> --output evidence/

# Security + mutation testing
cargo audit --deny warnings
cargo mutants --timeout-multiplier=2

# Fuzz smoke (short, deterministic budget)
cargo +nightly fuzz run --release -- -max_total_time=60
```

**Coverage thresholds (connector-only):**
- Overall line coverage: **>80%**
- Critical paths (auth, parsing, token handling): **>95%**
- Security-critical code: **>98%**
- Mutation score: **>70%**

---

## 2. Unit Tests (Mock-Only)

### Required categories
- Standard method surface (`--manifest`, handshake/describe/introspect/capabilities/configure/invoke/health/shutdown)
- Configuration validation (valid + invalid)
- Capability token validation
- Each operation (success + common error paths)
- Rate limit handling
- Timeout behavior
- Error recovery

### Mocking rules
- **NEVER** make real API calls in unit tests
- Use `wiremock` or equivalent
- Inject errors (auth failure, rate limit, malformed payloads)

### Property tests (required)
```rust
proptest! {
    #[test]
    fn parse_config_doesnt_panic(input in ".*") {
        let _ = ConnectorConfig::parse(&input);
    }

    #[test]
    fn roundtrip_serialization(cfg in arb_connector_config()) {
        let json = serde_json::to_string(&cfg).unwrap();
        let decoded: ConnectorConfig = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(cfg, decoded);
    }
}
```

---

## 3. Fuzz Testing (Security-Critical)

Every connector MUST provide fuzz targets for:
- Configuration parsing
- Protocol message parsing
- Credential/token handling
- Event payload parsing

Template:
```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = connector::parse_message(data);
});
```

---

## 4. Integration Tests

- Use mock external services only
- Verify multi-component flows (auth + request + parse + error path)
- Validate redaction and no-secret logging

---

## 5. E2E Compliance (Mechanical)

All connectors MUST pass the shared compliance runner:
- Default deny enforced (no capability token => denial + DecisionReceipt)
- NetworkConstraints enforced
- Receipts emitted for risky/dangerous ops
- Audit logs emitted
- External input tainted

Evidence bundles MUST be captured for audits.

---

## 6. Security Testing

### Dependency audit
```bash
cargo audit --deny warnings
```

### Secret leakage detection
```rust
#[test]
fn no_secrets_in_logs() {
    let logs = capture_connector_logs();
    assert!(!logs.contains("api_key="));
    assert!(!logs.contains("Authorization:"));
    assert!(!logs.contains("Bearer "));
}
```

### Zeroize verification
```rust
#[test]
fn credentials_are_zeroized_on_drop() {
    let cred = Credential::new("secret");
    let ptr = cred.as_ptr();
    drop(cred);
    // Memory should be zeroed
    unsafe { assert!(std::slice::from_raw_parts(ptr, 6).iter().all(|&b| b == 0)); }
}
```

---

## 7. Logging Requirements (Connector Tests)

All connector tests MUST emit structured JSON logs per `STANDARD_Testing_Logging.md` with, at minimum:
- `timestamp` (ISO 8601 with ms)
- `test_name`
- `phase` (setup|execute|assert|teardown)
- `correlation_id`
- `duration_ms`

When applicable, include:
- `connector_id`, `zone_id`, `session_id`, `operation_id`
- For denials: `decision=deny`, `reason_code`, `evidence` object IDs

---

## Acceptance Criteria

- [ ] Connector PRs enforce the full quality gates listed above
- [ ] Unit tests are mock-only and cover success + error paths
- [ ] Fuzz targets exist for config/protocol/credential/event parsing
- [ ] Compliance runner passes with evidence bundle
- [ ] Structured JSON logs meet required fields

---

## References

- `STANDARD_Testing_Logging.md` (platform testing + logging baseline)
- `STANDARD_Connector_Compliance.md` (compliance checklist)
- `STANDARD_Connector_Spec_Template.md` (connector bead template)
- `FCP_Specification_V2.md` (canonical spec)
