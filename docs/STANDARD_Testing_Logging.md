# FCP2 Platform Testing & Logging Requirements

> **Status**: NORMATIVE
> **Version**: 1.0.0
> **Last Updated**: January 2026
> **Bead Reference**: `flywheel_connectors-1n78.35`

---

## Purpose

This document defines **mandatory** testing and logging standards for the FCP2 platform. Every platform subsystem, connector, and integration test MUST comply with these requirements.

**Goal**: Failures are diagnosable from CI artifacts alone. A new contributor can debug any failure without rerunning tests locally.

**Connector-specific requirements**: See `STANDARD_Connector_Testing.md` for additional connector-only quality gates.

---

## 1. Quality Gates (Required for All PRs)

Every pull request MUST pass these checks before merge:

```bash
# Compiler errors and warnings (strict)
cargo check --all-targets

# Clippy lints - pedantic + nursery enabled, warnings are errors
cargo clippy --all-targets -- -D warnings

# Formatting verification
cargo fmt --check

# Full test suite with output capture
cargo test --workspace -- --nocapture
```

### Pre-Commit Checklist

Before committing:
1. Run `cargo fmt` to format code
2. Run `cargo clippy --fix` to auto-fix lint warnings
3. Run `cargo test` to verify all tests pass
4. Review any new warnings in CI output

---

## 2. Unit Test Requirements

Every platform subsystem MUST have comprehensive unit tests covering:

### 2.1 Success-Path Tests
- Happy path with valid inputs
- Nominal operation scenarios
- Expected state transitions

### 2.2 Negative Tests
- Malformed inputs (invalid JSON, corrupt CBOR, truncated data)
- Invalid signatures (wrong key, tampered payload)
- Expired tokens (past expiry timestamp)
- Stale revocations (old epoch, superseded)
- Out-of-bounds parameters (negative values, overflow attempts)

### 2.3 Bounds Tests
- Timeout handling (operations complete within budget)
- Size limits (reject payloads exceeding limits)
- Decode DoS prevention (reject deeply nested structures)
- Memory bounds (no unbounded allocations)

### 2.4 Golden Vectors
- Canonical test data with expected outputs
- Reproducible across platforms
- Version-pinned for regression detection

---

## 3. Golden Vector Format

### 3.1 Directory Structure

```
tests/vectors/<subsystem>/
├── README.md              # Describes vectors and their sources
├── <test_case>.json       # Human-readable test parameters
├── <test_case>.cbor       # Binary canonical data (where applicable)
└── <test_case>_expected.json  # Expected outputs
```

### 3.2 Subsystem Directories

```
tests/vectors/
├── crypto/
│   ├── ed25519_sign_verify.json
│   ├── x25519_key_exchange.json
│   ├── hpke_seal_unseal.cbor
│   └── cose_sign1_vectors.cbor
├── capabilities/
│   ├── token_verification.json
│   └── grant_enforcement.json
├── zones/
│   ├── zone_key_manifest.cbor
│   └── hpke_zone_sealing.json
├── protocol/
│   ├── fcps_frames.cbor
│   └── fcpc_frames.cbor
├── serialization/
│   ├── deterministic_cbor.json
│   └── core_vectors.json
└── revocation/
    ├── freshness_checks.json
    └── chain_integrity.json
```

### 3.3 Vector File Format

Each JSON vector file MUST include:

```json
{
  "name": "ed25519_sign_verify",
  "description": "Ed25519 signature generation and verification vectors",
  "source": "RFC 8032 Section 7.1",
  "version": "1.0.0",
  "vectors": [
    {
      "id": "vec_001",
      "description": "Test vector 1 from RFC 8032",
      "input": {
        "secret_key": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "message": ""
      },
      "expected": {
        "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
      }
    }
  ]
}
```

---

## 4. Property & Fuzz Testing Requirements

### 4.1 Property Tests (Required)

Use `proptest` or `quickcheck` for property-based testing:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn serialize_deserialize_roundtrip(value: MyType) {
        let encoded = value.encode_cbor();
        let decoded = MyType::decode_cbor(&encoded).unwrap();
        prop_assert_eq!(value, decoded);
    }

    #[test]
    fn sorted_collections_maintain_order(mut items: Vec<Item>) {
        items.sort();
        let sorted = SortedCollection::from(items.clone());
        prop_assert!(sorted.iter().is_sorted());
    }
}
```

Required property tests:
- **Invariant tests**: Deterministic behavior under valid inputs
- **Round-trip tests**: Encode/decode preserves data
- **Ordering tests**: Sorted collections maintain order
- **Idempotency tests**: Repeated operations produce same result

### 4.2 Fuzz Targets (Required for Security Surfaces)

Mandatory fuzz targets in `fuzz/` directory:

| Target | Location | Purpose |
|--------|----------|---------|
| `fuzz_fcps_frame` | `fuzz/fuzz_targets/fcps_frame.rs` | FCPS protocol frame parsing |
| `fuzz_fcpc_frame` | `fuzz/fuzz_targets/fcpc_frame.rs` | FCPC protocol frame parsing |
| `fuzz_session_handshake` | `fuzz/fuzz_targets/session.rs` | Session handshake transcript |
| `fuzz_capability_token` | `fuzz/fuzz_targets/capability.rs` | Capability token verification |
| `fuzz_zone_key_manifest` | `fuzz/fuzz_targets/zone.rs` | ZoneKeyManifest parsing |
| `fuzz_cbor_deserialize` | `fuzz/fuzz_targets/cbor.rs` | CBOR deserialization |

### 4.3 Fuzz Directory Structure

```
fuzz/
├── Cargo.toml
├── fuzz_targets/
│   ├── fcps_frame.rs
│   ├── fcpc_frame.rs
│   ├── session.rs
│   ├── capability.rs
│   ├── zone.rs
│   └── cbor.rs
└── corpus/
    ├── fcps_frame/
    ├── fcpc_frame/
    ├── session/
    ├── capability/
    ├── zone/
    └── cbor/
```

### 4.4 Fuzz Target Template

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;
use fcp_core::protocol::FcpsFrame;

fuzz_target!(|data: &[u8]| {
    // Should not panic on any input
    let _ = FcpsFrame::decode(data);
});
```

---

## 5. E2E Scenario Requirements

At minimum, ship tests/scripts that exercise these scenarios:

### 5.1 Happy Path
```
install → invoke → receipt → audit → verify
```
- Connector installation succeeds
- Operation invocation succeeds with valid capability
- Receipt is generated and persisted
- Audit trail is complete
- Verification passes

### 5.2 Default Deny
```
invoke without cap → denial + DecisionReceipt
```
- Attempt operation without capability token
- Request is denied
- DecisionReceipt explains denial reason
- Audit trail records denial

### 5.3 Revocation Flow
```
issue → use → revoke → denial
```
- Issue capability token
- Successfully use token
- Revoke token
- Subsequent use is denied
- Denial receipt references revocation

### 5.4 Taint/Approval Flow
```
tainted input → denial → approval → success
```
- Submit request with tainted input
- Initial request denied (requires approval)
- Obtain ApprovalToken
- Resubmit with approval
- Request succeeds

### 5.5 Offline/Repair Flow
```
reduced availability → repair → recovery
```
- Simulate node/network failure
- Verify graceful degradation
- Trigger repair mechanism
- Verify recovery to normal operation

---

## 6. Logging Requirements (CRITICAL)

### 6.1 Structured JSON Format

All tests MUST emit structured JSON logs. Use the `tracing` crate with JSON subscriber:

```rust
use tracing_subscriber::fmt::format::FmtSpan;

fn init_test_logging() {
    tracing_subscriber::fmt()
        .json()
        .with_span_events(FmtSpan::CLOSE)
        .with_current_span(true)
        .with_test_writer()
        .init();
}
```

#### 6.1.1 E2E Log JSONL Schema (Required)

The canonical JSON Schema for E2E log entries lives at:

- `crates/fcp-conformance/src/schemas/E2E_Log_v1.schema.json`

Validation helpers are available via:

- `fcp_conformance::schemas::validate_e2e_log_entry`
- `fcp_conformance::schemas::validate_e2e_log_jsonl`

All E2E harness outputs MUST validate against the v1 schema.
The schema supports multiple entry shapes (conformance harness, fcp-e2e harness,
and shell scripts). See `docs/testing/e2e_log_schema.md` for the required
fields by entry shape.

### 6.2 Required Log Fields

Required fields depend on the entry shape (see `docs/testing/e2e_log_schema.md`).
The example below shows a typical structured entry:

```json
{
  "timestamp": "2026-01-15T10:30:00.123456Z",
  "level": "info",
  "target": "fcp_core::capabilities",
  "test_name": "test_capability_verification",
  "module": "fcp-core",
  "phase": "execute",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Capability token verified successfully"
}
```

### 6.3 Phase Values

| Phase | Description |
|-------|-------------|
| `setup` | Test fixture preparation |
| `execute` | Main test logic execution |
| `verify` | Assertion and validation |
| `teardown` | Cleanup and resource release |

### 6.4 Context-Specific Fields

Add context fields as appropriate:

```json
{
  "zone_id": "z:work:project-alpha",
  "connector_id": "fcp.anthropic",
  "operation_id": "invoke:fcp.anthropic:complete",
  "session_id": "sess_abc123",
  "token_id": "cap_xyz789",
  "object_id": "obj_def456"
}
```

### 6.5 Test Result Logging

At test completion, emit a summary:

```json
{
  "timestamp": "2026-01-15T10:30:01.456789Z",
  "level": "info",
  "test_name": "test_capability_verification",
  "result": "pass",
  "duration_ms": 45,
  "assertions": {
    "passed": 10,
    "failed": 0
  }
}
```

### 6.6 Denial Logging

For security denials, include full context:

```json
{
  "timestamp": "2026-01-15T10:30:00.789Z",
  "level": "warn",
  "test_name": "test_missing_capability_denial",
  "decision": "deny",
  "reason_code": "FCP-2101",
  "reason_message": "Missing capability token for requested operation",
  "evidence": {
    "required_capability": "invoke:fcp.anthropic:complete",
    "provided_capabilities": [],
    "request_id": "req_123abc",
    "zone_id": "z:work:project-alpha"
  }
}
```

### 6.7 Secrets/PII Protection (MANDATORY)

**NEVER log actual secret values.** Violations are security incidents.

| Do | Don't |
|----|-------|
| `"token_id": "cap_xyz789"` | `"token": "eyJhbG..."` |
| `"secret_id": "sec_123"` | `"api_key": "sk-..."` |
| `"credential": "redacted"` | `"password": "hunter2"` |
| `"user_id": "usr_456"` | `"email": "user@example.com"` |

---

## 7. Test Output Format

### 7.1 Console Output (Human-Readable)

```
running 3 tests
[PASS] test_capability_verification (45ms)
[PASS] test_token_expiry_denial (12ms)
[FAIL] test_revocation_chain - assertion failed: expected denial after revocation

test result: FAILED. 2 passed; 1 failed; 0 ignored
```

### 7.2 JSON Output (Machine-Readable)

Generate JSON test results for CI:

```bash
cargo test --workspace -- --format json > test_results.jsonl
```

Output format (JSON Lines):

```json
{"type":"suite","event":"started","test_count":3}
{"type":"test","event":"started","name":"test_capability_verification"}
{"type":"test","event":"ok","name":"test_capability_verification","exec_time":0.045}
{"type":"test","event":"started","name":"test_token_expiry_denial"}
{"type":"test","event":"ok","name":"test_token_expiry_denial","exec_time":0.012}
{"type":"test","event":"started","name":"test_revocation_chain"}
{"type":"test","event":"failed","name":"test_revocation_chain","stdout":"assertion failed..."}
{"type":"suite","event":"failed","passed":2,"failed":1,"ignored":0}
```

---

## 8. CI Integration

### 8.1 GitHub Actions Workflow

```yaml
name: Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-action@stable

      - name: Cache cargo registry
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - name: Check formatting
        run: cargo fmt --check

      - name: Run clippy
        run: cargo clippy --all-targets -- -D warnings

      - name: Run tests
        run: |
          cargo test --workspace -- --nocapture 2>&1 | tee test.log
          if grep -q "FAILED" test.log; then
            echo "::error::Tests failed"
            exit 1
          fi

      - name: Upload test logs
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: test-logs
          path: |
            test.log
            tests/vectors/
          retention-days: 30

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install cargo-llvm-cov
        uses: taiki-e/install-action@cargo-llvm-cov

      - name: Generate coverage report
        run: cargo llvm-cov --workspace --lcov --output-path lcov.info

      - name: Upload coverage
        uses: codecov/codecov-action@v4
        with:
          files: lcov.info
          fail_ci_if_error: true

  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install cargo-fuzz
        run: cargo install cargo-fuzz

      - name: Run fuzz targets (quick check)
        run: |
          for target in $(cargo fuzz list); do
            cargo fuzz run $target -- -max_total_time=60
          done
```

### 8.2 Required Artifacts

Every CI run MUST preserve:
- `test.log` - Full test output with structured logs
- `tests/vectors/` - Golden vectors for reproduction

---

## 9. Connector-Specific Testing Requirements (NORMATIVE)

> **Bead Reference**: `flywheel_connectors-h32`

These requirements apply to **every connector** in addition to the platform-wide rules above.

### 9.1 Required Connector Test Categories

Each connector MUST include unit/integration tests for:
- **Standard methods**: `--manifest`, `configure`, `handshake`, `health`, `introspect`,
  `invoke`, `subscribe`/`unsubscribe` (if supported), `shutdown`.
- **Configuration validation**: valid/invalid config payloads, missing fields, type errors.
- **Capability token validation**: expired tokens, wrong zone, missing operation grant.
- **Operation coverage**: each operation's success path + common failure paths + edge cases.
- **Rate limiting + timeouts**: enforce limits and retry/backoff where defined.
- **Event lifecycle**: streaming/polling connectors must test subscribe → emit → ack (if required).

### 9.2 Mocking + Isolation (MANDATORY)

- **No real API calls** in unit tests.
- Use `wiremock` for HTTP mocks; use local in-process mock servers for WebSocket/SSE.
- Deterministic fixtures only (no wall-clock or random data without fixed seeds).

### 9.3 Property + Fuzz Targets (Connector Scope)

Required property tests:
- **Config parsing** never panics on arbitrary input.
- **Serde round-trip** for connector config and operation input/output schemas.

Required fuzz targets (per connector):
- Configuration parsing
- Protocol message parsing
- Credential/token handling
- Event payload parsing (where applicable)

### 9.4 Security Regression Tests

Each connector MUST include:
- **No-secrets-in-logs** tests (deny raw tokens, API keys, auth headers).
- **Credential zeroization** tests where credentials are stored in memory types.
- **Network constraints enforcement** tests (deny-by-default egress).

### 9.5 Connector Release Quality Gates

In addition to Section 1 quality gates, connector releases MUST pass:
- **Coverage**: >80% overall, >95% critical paths, >98% security-sensitive code.
- **Mutation testing**: `cargo mutants` score >70%.
- **Security audit**: `cargo audit --deny warnings`.
- **E2E compliance harness**: mechanical compliance runner (static + dynamic).

### 9.6 Mechanical Compliance (E2E)

Every connector MUST pass the platform E2E/compliance harness:
- Default deny (no capability token → denial + DecisionReceipt)
- Zone binding enforcement
- Sandbox/network constraints enforced
- Tool descriptor validation (SEP-1382 compliance)
- `lcov.info` - Coverage report
- `fuzz/corpus/` - Fuzz corpus updates (on failure)

---

## 9. Coverage Requirements

### 9.1 Minimum Coverage Thresholds

| Component | Minimum Coverage |
|-----------|------------------|
| Core library (`fcp-core`) | 95% |
| Security surfaces (crypto, auth, zones) | 90% |
| Protocol handling (FCPS, FCPC) | 85% |
| Overall workspace | 80% |

### 9.2 Coverage Enforcement

```bash
# Generate coverage report
cargo llvm-cov --workspace --html

# Check thresholds
cargo llvm-cov --workspace --fail-under-lines 80
```

### 9.3 Excluded from Coverage

The following are excluded from coverage calculations:
- Test code itself (`#[cfg(test)]` modules)
- Debug-only code (`#[cfg(debug_assertions)]`)
- Panic handlers and unreachable code
- Generated code (derive macros output)

---

## 10. Test Naming Conventions

### 10.1 Unit Tests

```rust
#[test]
fn test_<function>_<scenario>_<expected_outcome>() {
    // test_verify_signature_valid_input_succeeds
    // test_verify_signature_invalid_key_fails
    // test_verify_signature_expired_token_denies
}
```

### 10.2 Integration Tests

```rust
#[tokio::test]
async fn integration_<component>_<scenario>() {
    // integration_connector_installation_succeeds
    // integration_capability_revocation_propagates
}
```

### 10.3 E2E Tests

```rust
#[tokio::test]
async fn e2e_<workflow>() {
    // e2e_happy_path_install_invoke_verify
    // e2e_denial_path_missing_capability
    // e2e_revocation_flow_issue_use_revoke
}
```

---

## 11. Acceptance Criteria

This standard is satisfied when:

- [ ] CI artifacts include structured logs for all test failures
- [ ] A new contributor can debug failures without rerunning locally
- [ ] All test beads reference this standard as a dependency
- [ ] No test passes without producing required log fields
- [ ] Golden vectors exist for all security-critical code paths
- [ ] Fuzz targets cover all protocol parsing surfaces
- [ ] Coverage thresholds are enforced in CI
- [ ] E2E scenarios cover all five required flows

---

## References

- FCP Specification V2 (canonical)
- [Rust API Guidelines - Documentation](https://rust-lang.github.io/api-guidelines/documentation.html)
- [cargo-fuzz Book](https://rust-fuzz.github.io/book/)
- [tracing Crate Documentation](https://docs.rs/tracing/)
