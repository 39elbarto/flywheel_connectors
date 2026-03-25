# Testing Completeness Maintainer Guide

> Bead: `flywheel_connectors-49z0b.15.4`
>
> How to operate the testing program day-to-day: rerun suites,
> quarantine flakes, promote evidence, and triage regressions.

## Quick Reference

| Task | Command |
| --- | --- |
| **See what needs tests** | `bash scripts/ci/test_coverage_scan.sh` |
| **Generate dashboard** | `bash scripts/ci/coverage_dashboard.sh --scan-json /tmp/scan.json --markdown-out /tmp/dash.md` |
| **Validate artifacts** | `bash scripts/ci/validate_e2e_artifacts.sh --bundle-dir /path/to/bundle` |
| **Run live suites** | `FCP_LIVE_SANDBOX=1 bash scripts/e2e/live_connector_smoke_suite.sh` |
| **Run platform tests** | `rch exec -- cargo test -p fcp-core -p fcp-sdk -p fcp-host` |
| **Check pure-unit floor** | `bash scripts/ci/pure_unit_floor.sh` |

## Daily Workflow

### Before starting connector work

1. Run platform verification:
   ```bash
   rch exec -- cargo test -p fcp-testkit --test runtime_lifecycle_acceptance
   ```

2. Check coverage for your target connector:
   ```bash
   bash scripts/ci/test_coverage_scan.sh --only connectors --json-out /tmp/scan.json
   python3 -c "import json; d=json.load(open('/tmp/scan.json')); [print(c['id'], c['status']) for c in d['connectors'] if 'YOUR_CONNECTOR' in c['id']]"
   ```

### After finishing connector work

1. Run the connector's tests:
   ```bash
   rch exec -- cargo test -p fcp-YOUR_CONNECTOR
   ```

2. Re-run coverage scanner to verify improvement:
   ```bash
   bash scripts/ci/test_coverage_scan.sh --only connectors
   ```

3. Validate any evidence artifacts:
   ```bash
   bash scripts/ci/validate_e2e_artifacts.sh --artifact-dir /path/to/artifacts
   ```

## Rerun Playbook

### Rerun a single connector

```bash
rch exec -- cargo test -p fcp-CONNECTOR -- --nocapture
```

### Rerun with specific test filter

```bash
rch exec -- cargo test -p fcp-CONNECTOR -- test_name_filter --nocapture
```

### Rerun live suite for one connector

```bash
export FCP_LIVE_SANDBOX=1
export CONNECTOR_API_KEY=...
rch exec -- cargo test -p fcp-CONNECTOR -- live --nocapture
```

### Rerun from replay script

```bash
bash /tmp/fcp-live-smoke-AGENT-TIMESTAMP/replay.sh
```

### Rerun all platform crates

```bash
rch exec -- cargo test -p fcp-core -p fcp-protocol -p fcp-crypto -p fcp-sdk -p fcp-host -p fcp-streaming -p fcp-webhook
```

## Flaky Test Quarantine

### Identifying a flaky test

A test is flaky if:
- It fails intermittently with no code changes
- The failure depends on timing, load, or environment
- It passes when run in isolation

### Quarantine process

1. **Document the flake** in the connector's test file:
   ```rust
   #[test]
   #[ignore] // QUARANTINE: flaky under load, see bead XXXX
   fn test_timing_sensitive_operation() { ... }
   ```

2. **File a bead**:
   ```bash
   br create --title="Flaky: CONNECTOR test_name" --type=bug --priority=2 --label=flaky
   ```

3. **Add to known flakes** in `docs/testing/core_platform_evidence_index.md`

### Promoting out of quarantine

1. Fix the underlying issue (widen margins, remove timing dependency)
2. Run the test 10x in a loop to verify stability:
   ```bash
   for i in $(seq 1 10); do
     rch exec -- cargo test -p fcp-CONNECTOR -- test_name || echo "FAIL on run $i"
   done
   ```
3. Remove the `#[ignore]` annotation
4. Close the flake bead

## Evidence Promotion

### What constitutes valid evidence

- JSONL entries with required fields (timestamp, test_name, phase, correlation_id)
- No raw secrets or PII in artifacts
- Replay bundle with summary.json and replay.sh
- Budget tracking showing spending within limits
- Cleanup results showing all resources cleaned

### Promoting evidence to the coverage inventory

1. Run the coverage scanner after your changes
2. Generate a diff report:
   ```bash
   # Save current state as baseline
   bash scripts/ci/test_coverage_scan.sh --json-out baseline.json

   # Make changes...

   # Compare
   bash scripts/ci/test_coverage_scan.sh --json-out current.json
   bash scripts/ci/coverage_dashboard.sh --scan-json current.json --baseline baseline.json --diff-out diff.md
   ```

3. Commit the evidence alongside code changes:
   ```bash
   git add .
   git commit -m "test(CONNECTOR): add acceptance suite [br-XXXX]"
   ```

## Regression Triage

### When CI fails

1. **Read the failure message** — what crate, what test?
2. **Check known flakes** in `docs/testing/core_platform_evidence_index.md`
3. **Run in isolation** to confirm it's not flaky
4. **Check recent changes** with `git log --oneline -10 -- crates/CRATE/`
5. **Fix or escalate** — see escalation rules in `docs/testing/live_suite_operator_playbook.md`

### When live suite fails

1. **Check the evidence bundle** in `/tmp/fcp-live-smoke-*/`
2. **Check `quarantine_candidates.json`** — is it a known flaky test?
3. **Check `summary.json`** — how many connectors failed?
4. **Follow the operator playbook** in `docs/testing/live_suite_operator_playbook.md`

## Testing Taxonomy Reference

| Suite Class | What It Proves | Where |
| --- | --- | --- |
| `pure_unit` | Function-level correctness | `src/*.rs` `#[cfg(test)]` |
| `deterministic_contract` | Serialization, golden vectors | `tests/integration.rs` |
| `local_non_mock` | Real local boundary (Docker, embedded DB) | `tests/local_acceptance.rs` |
| `host_e2e` | Real fcp-host subprocess lifecycle | `crates/fcp-e2e/tests/` |
| `live` | Real provider sandbox or upstream | `tests/live_acceptance.rs` |

## Related Documents

| Document | Contents |
| --- | --- |
| `docs/testing/core_platform_evidence_index.md` | Platform crate rerun commands, known flakes |
| `docs/testing/live_suite_operator_playbook.md` | Live/nightly suite operations |
| `docs/testing/live-suite-classification.md` | Connector tier classification (A-E) |
| `docs/testing/coverage-inventory.md` | Full coverage inventory |
| `docs/testing/e2e_log_schema.md` | JSONL log schema reference |
| `scripts/ci/test_coverage_scan.sh` | Coverage scanner |
| `scripts/ci/coverage_dashboard.sh` | Dashboard generator |
| `scripts/ci/validate_e2e_artifacts.sh` | Artifact validator |
| `scripts/ci/pure_unit_floor.sh` | Pure-unit floor enforcement |
| `scripts/e2e/live_connector_smoke_suite.sh` | Nightly live-suite orchestrator |
