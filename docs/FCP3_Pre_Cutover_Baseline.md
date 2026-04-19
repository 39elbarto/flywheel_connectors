# FCP3 Pre-Cutover Baseline Definition

> **Bead**: `flywheel_connectors-34q27.1` -- [FCP3/P6.6]
> **Author**: SunnyMoose, 2026-04-07
> **Purpose**: Freeze the canonical scenario set, environment capture, and comparison metadata so phase-7 proof beads can compare against preserved pre-deletion reality.

---

## Canonical Scenario Set

These scenarios define the operator-critical flows that must be preserved through the FCP3 cutover. Each scenario has a verification command and expected outcome.

### Discovery Scenarios

| ID | Scenario | Command | Expected Outcome | Proof |
|----|----------|---------|-----------------|-------|
| D1 | List connectors (offline) | `fwc list --offline` | TOON output with 150+ connectors | fwc unit tests |
| D2 | Search operations | `fwc search "send message" --offline` | Matching operations from Slack/Telegram/Discord | fwc search tests |
| D3 | Show connector details | `fwc show github --offline` | Operations, capabilities, zone policy | fwc show tests |
| D4 | Schema introspection | `fwc schema github issues.create --offline` | JSON Schema for input/output | fwc schema tests |

### Lifecycle Scenarios

| ID | Scenario | Command | Expected Outcome | Proof |
|----|----------|---------|-----------------|-------|
| L1 | Health check | `fwc --host <url> health github` | Health status from fcp-host | fcp-host health tests |
| L2 | Doctor diagnostics | `fwc --host <url> doctor github` | Diagnostic checks with pass/fail | fwc doctor tests |
| L3 | Status query | `fwc --host <url> status github` | Connector runtime status | fwc status tests |

### Invoke Scenarios

| ID | Scenario | Command | Expected Outcome | Proof |
|----|----------|---------|-----------------|-------|
| I1 | Invoke through host | `fwc --host <url> invoke github get_repo` | Full chain: fwc->fcp-host->connector->API | 423bu.3.1 (CLOSED) |
| I2 | Simulate (dry run) | `fwc --host <url> simulate github issues.create` | Preflight checks without side effects | 423bu.3.6 (CLOSED) |
| I3 | Capability rejection | Invoke with wrong zone token | Structured FcpError::OperationNotGranted | 423bu.3.3 (CLOSED) |
| I4 | Rate limit enforcement | Burst beyond limit | Structured FcpError::RateLimited with retry_after | 423bu.3.9 (CLOSED) |

### Truth Resolution Scenarios

| ID | Scenario | Command | Expected Outcome | Proof |
|----|----------|---------|-----------------|-------|
| T1 | Offline resolution | `fwc list --offline` | KnowledgeState::Offline, confidence 0.4 | truth.rs tests (kpj16) |
| T2 | Node-local resolution | Status without mesh | KnowledgeState::NodeLocal, confidence 0.6 | truth.rs tests |
| T3 | Host-backed resolution | `fwc --host <url> status` | KnowledgeState::HostBacked, confidence 0.9 | truth.rs tests |
| T4 | Mesh-backed resolution | Full mesh query | KnowledgeState::MeshBacked, confidence 1.0 | truth.rs tests |
| T5 | Degraded fallback | Partial mesh failure | KnowledgeState::Degraded with fallback chain | truth.rs tests |

### Security Scenarios

| ID | Scenario | Description | Expected Outcome | Proof |
|----|----------|-------------|-----------------|-------|
| S1 | Egress credential injection | Connector request through proxy | Bearer token injected, connector never sees secret | vzpxn.1 (CLOSED) |
| S2 | CIDR deny enforcement | Request to localhost/private range | Blocked by egress proxy | vzpxn.2 (CLOSED) |
| S3 | Revocation enforcement | Revoked capability token | Rejected before operation | 423bu.3.8 (CLOSED) |
| S4 | Trace context propagation | W3C traceparent through chain | trace_id shared across fwc/host/connector | 423bu.3.7 (CLOSED) |

---

## Environment Capture

### Required Metadata

```json
{
  "baseline_version": "2026-04-07",
  "git_sha": "<commit hash at capture time>",
  "rust_toolchain": "nightly (from rust-toolchain.toml)",
  "workspace_crate_count": 31,
  "connector_count": 150,
  "total_test_count": "35000+",
  "bead_status": {
    "total": 2200,
    "open": 68,
    "closed": 2100,
    "in_progress": 12
  }
}
```

### Known Transition Seams

These are intentional differences between the current (host-first) and target (mesh-first) architectures. Phase-7 comparisons should treat changes in these areas as expected, not as regressions.

1. **Host-first invoke path**: `fwc -> fcp-host HTTP -> connector subprocess` will eventually become `fwc -> mesh object -> connector`, but the invoke semantics and error taxonomy should remain identical.

2. **IbltPlaceholder**: gossip.rs still uses `IbltPlaceholder` for change-tracking alongside the production `Iblt`. Phase-7 may remove the placeholder entirely.

3. **ConnectorErrorMapping / ConnectorRuntime**: these shims in fcp-sdk bridge V2->V3 patterns. Phase-7 may inline them or remove the indirection.

4. **fcp-core re-exports**: fcp-kernel, fcp-policy, and fcp-evidence currently re-export from fcp-core. Phase-7 may invert the dependency direction.

5. **XorFilterPlaceholder naming**: the type retains its placeholder name despite using real `xorf::Xor8` internally. Phase-7 may rename.

---

## Comparison Protocol

When phase-7 proof beads compare against this baseline:

1. **Test counts**: Total tests should not decrease. New tests replacing removed ones are acceptable.
2. **Scenario coverage**: Every scenario in the canonical set must still pass or be explicitly superseded with documented rationale.
3. **Error taxonomy**: FcpError variants and their mapping from connector errors must be stable.
4. **Trace propagation**: W3C trace_id must flow through any new invoke path the same way it flows through the current host-backed path.
5. **Transition seams**: Changes in the seams listed above are expected and should not be flagged as regressions.
6. **Performance**: CI benchmark gate (tr2xx.5) enforces that gossip, PCS, and FWC benchmarks don't regress beyond thresholds.

---

## Deletion-Wave Preservation Anchors

Phase-7 deletion work should compare post-cutover behavior against this
baseline through named preservation anchors rather than through commit diffs
alone.

| Wave | Baseline anchor | Post-deletion anchor | Notes |
|------|-----------------|----------------------|-------|
| `flywheel_connectors-z1nkz.1` teaching rewrite | The scenario tables above, plus the pre-cutover statement that host-first is an intentional transitional seam | README, `docs/OPERATIONAL_MODEL_VERSIONS.md`, `docs/FWC_Host_First_Truthfulness_Playbook.md`, and `crates/fwc/docs/truthfulness-model.md` after the rewrite commits | The preserved workflow is truthful operator guidance, not identical wording |
| `flywheel_connectors-z1nkz.2` runtime/control-plane deletion | The “Known Transition Seams” list and the proof obligations attached to each quarantine row | `docs/FCP3_Retirement_Kill_List.md` and `docs/FCP3_Transition_Scorecard.md` after the seam state updates | The preserved workflow is the ability to audit what was deleted, why it was safe, and what replaced it |
| `flywheel_connectors-z1nkz.3` final preservation bundle | This baseline document plus the named scenario and seam tables | Final proof-bundle indexes that cite the two earlier waves and their rerun commands or artifact pointers | The preserved workflow is reviewability without reconstructing history by hand |

---

*Frozen at 2026-04-07. Do not modify after phase-7 deletions begin -- this document IS the baseline.*
