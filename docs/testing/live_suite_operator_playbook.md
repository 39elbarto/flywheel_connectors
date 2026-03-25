# Live Suite Operator Playbook

> Bead: `flywheel_connectors-49z0b.14.4`
>
> How to run, triage, and maintain the live/nightly test lane. A future
> maintainer can follow this document without guessing at policy.

## When to Run Live Suites

| Trigger | What Runs | Gate Variables |
| --- | --- | --- |
| **Every PR** | `pure_unit` + `deterministic_contract` only | None |
| **Merge to main** | `local_non_mock` + `host_e2e` for Tier A | None |
| **Nightly (automated)** | Tier B sandbox + Tier D read-only | `FCP_LIVE_SANDBOX=1`, `FCP_LIVE_READ=1` |
| **Weekly (manual)** | Tier C device + Tier E write | `FCP_LIVE_DEVICE=1`, `FCP_LIVE_WRITE=1` |
| **On demand** | Any specific connector | Set appropriate gate + secrets |

## Running the Live Suite

### Full nightly run

```bash
# Set gates and secrets
export FCP_LIVE_SANDBOX=1
export FCP_LIVE_READ=1

# Run the orchestrator
bash scripts/e2e/live_connector_smoke_suite.sh

# Output appears in: /tmp/fcp-live-smoke-<agent>-<timestamp>/
#   environment.json  — redacted env summary
#   replay.sh         — rerun script
#   quarantine_candidates.json — flaky test candidates
#   summary.json      — aggregate results
#   suite.jsonl       — per-connector results
```

### Single connector

```bash
export FCP_LIVE_SANDBOX=1
export STRIPE_TEST_KEY=sk_test_...

rch exec -- cargo test -p fcp-stripe --test live_acceptance
```

### Coverage scanner pre-flight

```bash
bash scripts/ci/test_coverage_scan.sh --only connectors --json-out /tmp/scan.json
```

## Interpreting Results

### Success

```json
{"connector": "stripe", "status": "pass", "tests_run": 5, "budget_spent_usd": 0.02}
```

No action needed.

### Gated Skip

```json
{"connector": "stripe", "status": "skipped", "reason": "FCP_LIVE_SANDBOX not set"}
```

Expected in environments without live credentials. Not a failure.

### Budget Exceeded

```json
{"connector": "aws", "status": "fail", "budget": {"alert_level": "exceeded", "spent": 1.50, "max": 1.00}}
```

**Action:**
1. Review which API calls are expensive
2. Reduce test scope or increase budget ceiling in `EnvironmentManifest`
3. File an issue if the connector has a cost regression

### Secret Missing

```json
{"connector": "discord", "status": "skipped", "reason": "Missing required secret: bot_token"}
```

**Action:**
1. Check CI secret configuration
2. Verify secret name matches `EnvironmentManifest` declaration
3. If intentionally removed, update the manifest

### Provider Error

```json
{"connector": "telegram", "status": "fail", "error": "HTTP 429 Too Many Requests"}
```

**Action:**
1. Check rate limit configuration in manifest
2. If transient: add to quarantine, retry on next nightly
3. If persistent: update `RateLimitConfig.max_rps` or add backoff

## Failure Taxonomy

| Category | Severity | Action |
| --- | --- | --- |
| **Auth failure** | High | Check secret rotation, credential expiry |
| **Rate limit (429)** | Medium | Adjust `RateLimitConfig`, add delays |
| **Budget exceeded** | Medium | Review cost per operation, adjust ceiling |
| **Provider outage (5xx)** | Low | Quarantine, retry next run |
| **Schema mismatch** | High | Provider API changed — update connector types |
| **Timeout** | Medium | Increase timeout or reduce test payload |
| **Cleanup failure** | High | Manual cleanup needed — check stale resources |

## Quarantine Rules

### When to quarantine

A test enters quarantine when:
- It fails 2+ times in 7 days with the same transient error
- The failure is clearly external (provider outage, rate limit)
- The fix requires provider-side action (sandbox reset, key rotation)

### How to quarantine

The nightly orchestrator emits `quarantine_candidates.json`:

```json
{
  "candidates": [
    {
      "connector": "amplitude",
      "test": "test_event_ingestion",
      "reason": "429 rate limited on 2 consecutive nights",
      "last_failure": "2026-03-24T04:00:00Z"
    }
  ]
}
```

To quarantine: add the test to the connector's `QUARANTINED_TESTS` in
`live_connector_smoke_suite.sh`.

### When to promote out of quarantine

- The underlying issue is fixed (provider reset, rate limit increased)
- The test has been rewritten to work within constraints
- Manual verification passes once

## Cleanup Expectations

### Synthetic tenant resources

All mutable resources are created with the `fcp-test-{connector}-{suffix}-{run_id}-{date}` prefix.

```bash
# Find stale resources (older than 30 days)
# Use per-provider SDK tools or the StaleResourceReport API:
```

```rust
use fcp_testkit::live_suite::StaleResourceReport;
let report = StaleResourceReport::scan(&resource_names, 30);
if report.has_stale() {
    eprintln!("Found {} stale resources", report.stale.len());
}
```

### Cleanup strategies by tier

| Tier | Default Strategy | Manual Required? |
| --- | --- | --- |
| Tier A (local) | No cleanup | No |
| Tier B (sandbox) | `PrefixDelete` or `AutoExpire` | Only on failure |
| Tier C (device) | None (no cloud state) | Only if device-local state persists |
| Tier D (read-only) | None | No |
| Tier E (write) | `PrefixDelete` | Yes, verify after each run |

### Post-run cleanup verification

After each live run, verify cleanup:
1. Check `cleanup_succeeded` / `cleanup_failed` in the evidence bundle
2. For failed cleanups: manually remove stale `fcp-test-*` resources
3. Run `StaleResourceReport::scan()` against provider resource lists

## Redaction Requirements

Live suite evidence must never contain:
- Raw API keys, tokens, or credentials
- OAuth refresh tokens or client secrets
- Personal email addresses or phone numbers
- Provider-specific account IDs that could identify the owner

The following are safe to include:
- Secret key names (not values)
- Provider names and service endpoints
- Synthetic tenant prefixes and run IDs
- Redacted credential presence (loaded/missing counts)
- Budget amounts and API call counts

Use `SecretBag::Debug` (which redacts values) and `LiveEnvironment::evidence_summary()`
(which only includes counts and key names) for evidence output.

## Escalation Rules

### When to escalate to a human

1. **Repeated budget overruns** (3+ consecutive nightly runs)
2. **Cleanup failures** leaving production-like resources in provider accounts
3. **Auth failures** requiring credential rotation
4. **Schema changes** breaking multiple connectors simultaneously
5. **Device failures** in Tier C requiring physical access

### How to escalate

1. File a bead: `br create --title="Live suite: <connector> <issue>" --type=bug --priority=1`
2. Add the `live` and `e2e` labels
3. Include the relevant evidence bundle path
4. Tag the connector owner if known

## Rerun Commands

### Rerun a specific failed connector

```bash
# From the replay script in the evidence bundle
bash /tmp/fcp-live-smoke-<agent>-<timestamp>/replay.sh

# Or manually
export FCP_LIVE_SANDBOX=1
export <SECRET_VARS>=...
rch exec -- cargo test -p fcp-<connector> -- --nocapture
```

### Rerun the full nightly suite

```bash
export FCP_LIVE_SANDBOX=1 FCP_LIVE_READ=1
bash scripts/e2e/live_connector_smoke_suite.sh
```

### Rerun with increased budget

```bash
export FCP_LIVE_SANDBOX=1
export FCP_LIVE_BUDGET_MULTIPLIER=2  # Double all budgets
bash scripts/e2e/live_connector_smoke_suite.sh
```

## Evidence Bundle Structure

Each nightly run produces:

```
/tmp/fcp-live-smoke-<agent>-<timestamp>/
  environment.json              — redacted env summary (gates, secrets loaded)
  summary.json                  — aggregate pass/fail/skip counts
  suite.jsonl                   — per-connector JSONL results
  replay.sh                     — one-command rerun script
  quarantine_candidates.json    — tests that should be quarantined
  per-connector/
    <connector>/
      evidence.json             — LiveEnvironment::evidence_summary()
      prerequisite_report.json  — PrerequisiteReport for pre-flight
      cost_log.json             — CostBudget entries
      cleanup_results.json      — CleanupGuard outcomes
```

## Related Documents

- `docs/testing/live-suite-classification.md` — tier assignments (A-E)
- `docs/testing/core_platform_evidence_index.md` — platform crate rerun commands
- `docs/testing/coverage-inventory.md` — full coverage inventory
- `docs/testing/e2e_log_schema.md` — E2E log schema reference
- `docs/Session_Lifecycle_Debug_Guide.md` — debug guide for E2E artifacts
