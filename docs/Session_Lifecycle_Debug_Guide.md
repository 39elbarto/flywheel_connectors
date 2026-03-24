# Session Lifecycle Debug Guide

How to diagnose reconnect, ingress, ordering, and shutdown failures from session E2E artifacts.

---

## Artifact Overview

Every session E2E run produces a self-sufficient artifact set:

| Artifact | Location | Purpose |
|----------|----------|---------|
| **Phase logs** | `SessionE2eResult.phase_logs` | Phase-annotated JSONL entries with correlation IDs |
| **Transcript** | `SessionE2eResult.transcript` | Per-step outcomes from the session script |
| **Evidence bundle** | `SessionE2eResult.evidence` | Archival-grade scenario script with assertions and replay instructions |
| **Replay command** | `SessionE2eResult.replay_command` | Copy-paste command to reproduce the failure |
| **Phase durations** | `SessionE2eResult.phase_durations` | Breakdown by setup/lifecycle/execute/verify/teardown |

---

## Phase Markers

Every log entry carries a `phase` field for filtering:

| Phase | What Happens | What to Look For |
|-------|-------------|------------------|
| `setup` | Fixture server address, config validation | Missing fixture, wrong address, timeout too short |
| `lifecycle` | Connector configure + handshake | Auth failures, capability mismatches, handshake timeouts |
| `execute` | Session script step-by-step execution | Step failures, unexpected messages, fault injection results |
| `verify` | Transcript outcome check, secret scan | Failed assertions, secret leakage warnings |
| `teardown` | Evidence assembly, replay command | Bundle errors (unusual) |

### Filtering Logs by Phase

```bash
# Show only execute-phase errors:
cat result.json | jq '.phase_logs[] | select(.phase == "execute" and .level == "error")'

# Show all phases with timing:
cat result.json | jq '[.phase_logs[] | {phase, timestamp, message}]'
```

---

## Correlation IDs

Every entry in a session E2E run shares a `correlation_id` of the form:

```
sess-e2e-{connector_id}-{scenario_id}
```

This ID appears in:
- Phase logs (`.correlation_id`)
- Transcript entries (`.correlation_id`)
- Evidence bundle steps (`.correlation_id`)

Use it to filter across all artifact types:

```bash
rg "sess-e2e-discord-ws.reconnect" artifacts/
```

---

## Transcript Analysis

The `SessionTranscript` records what actually happened during script execution:

```json
{
  "scenario_id": "ws.reconnect_after_drop",
  "entries": [
    { "step_index": 0, "step": "Connect(WebSocket, /gateway)", "outcome": "Pass", "duration": "12ms" },
    { "step_index": 1, "step": "ExpectMessage(Any)", "outcome": "Pass", "duration": "3ms" },
    { "step_index": 2, "step": "InjectFault(ConnectionDrop)", "outcome": "Pass", "duration": "1ms" },
    { "step_index": 3, "step": "AssertHealth(Reconnecting)", "outcome": "Fail", "duration": "501ms",
      "detail": "Health was Connected, expected Reconnecting" }
  ],
  "outcome": "Fail",
  "summary": { "total": 4, "passed": 3, "failed": 1, "skipped": 0, "timed_out": 0 }
}
```

### Common Failure Patterns

| Pattern | Symptom | Likely Cause |
|---------|---------|-------------|
| **Health assertion fail** | `AssertHealth(Reconnecting)` fails, actual is `Connected` | Connector reconnected faster than expected; increase `Wait` before assertion |
| **ExpectMessage timeout** | Step times out waiting for message | Fixture server didn't send event, or connector isn't connected to fixture |
| **Webhook ack timeout** | `WebhookExpectAck` times out | Connector didn't process webhook, or ack channel not wired |
| **Fault injection no-op** | Steps after `InjectFault` still pass | Connector didn't react to the fault; check fault type matches transport |
| **Ordering mismatch** | `ExpectMessage(Exact)` fails | Messages arrived out of order; use `ExpectMessage(Contains)` or `ExpectCount` |

---

## Replay Commands

Every result includes a `replay_command` for reproduction:

```bash
# Replay session E2E:
# Run ID: run-20260324T192000Z-ws.reconnect_after_drop
# Correlation: sess-e2e-discord-ws.reconnect_after_drop
fwc simulate discord --scenario ws.reconnect_after_drop --fixture-addr 127.0.0.1:8080
# Or re-run the full session:
cargo test -p fcp-e2e --test session_lifecycle_e2e -- ws_reconnect_after_drop --nocapture
```

Environment variables are redacted in replay commands. To reproduce with real credentials, set them manually:

```bash
export DISCORD_TOKEN=<your-token>
cargo test -p fcp-e2e --test session_lifecycle_e2e -- ws_reconnect_after_drop --nocapture
```

---

## Debugging Workflow

### 1. Start with the summary

```bash
cat result.json | jq '{passed, scenario_id, duration_ms, transcript_summary}'
```

### 2. Find the first failure

```bash
cat result.json | jq '.transcript.entries[] | select(.outcome != "Pass") | {step_index, step, outcome, detail}'
```

### 3. Check the phase context

```bash
cat result.json | jq '.phase_logs[] | select(.phase == "execute") | {timestamp, message, context}'
```

### 4. Look at the evidence bundle

```bash
cat result.json | jq '.evidence.script.steps[] | select(.assertions[0].passed == false)'
```

### 5. Reproduce

Copy the replay command from the result and run it with `--nocapture` for full output.

---

## Integration with `fcp-e2e::host_e2e`

### Basic Usage

```rust
use fcp_e2e::host_e2e::{SessionE2eRunner, SessionE2eConfig};
use fcp_e2e::{SessionScript, ScriptStep, Transport};

let mut runner = SessionE2eRunner::new(SessionE2eConfig {
    connector_id: "discord".into(),
    scenario_id: "ws.reconnect".into(),
    tags: vec!["streaming".into()],
    ..Default::default()
});

let script = SessionScript::new("ws.reconnect")
    .step(ScriptStep::connect(Transport::WebSocket, "/gateway"))
    .step(ScriptStep::expect_any_message())
    .step(ScriptStep::disconnect());

let result = runner.execute(&script);
assert!(result.passed);
```

### With Streaming Fixture Server

```rust
use fcp_e2e::{StreamingFixtureServer, StreamingAction, SseEvent};

let fixture = StreamingFixtureServer::start().unwrap();
fixture.enqueue_action(StreamingAction::SendSse {
    event: SseEvent::typed("message", r#"{"text":"hello"}"#),
});

let mut runner = SessionE2eRunner::new(SessionE2eConfig {
    connector_id: "webhook-receiver".into(),
    scenario_id: "sse.receive".into(),
    fixture_address: Some(fixture.address()),
    ..Default::default()
});
```

### Recording External Transcripts

When you manage the connector lifecycle and WebSocket connection yourself:

```rust
// ... run your connector, execute operations, build transcript ...
let result = runner.record_external_transcript(&script, transcript);
// result.evidence contains the full archival bundle
```

---

## Evidence Bundle Structure

```
EvidenceBundle
  script: ScenarioScript
    meta: { name, description, tags, environment, created_at, author }
    steps[]: { index, kind, description, correlation_id, timestamp, duration_ms, assertions[], evidence[] }
    outcome: Pass | Fail { step_index, reason } | Skip { reason } | Degraded { passed, failed, details }
  redacted_fields: []
  replay_instructions: "fwc simulate ..."
  retention_days: 90
```

Bundles are JSON-serializable and can be stored as CI artifacts, attached to issue trackers, or compared across runs.

---

## Secret Scanning

Every session E2E run automatically scans phase logs for secret leakage using `LogRedactionScanner`. Findings appear in the verify phase:

```
Log scan found 2 findings (1 errors, 1 warnings)
```

If the scan finds issues, check:
1. Connector is not logging raw tokens or API keys
2. Fixture server responses don't contain real credentials
3. Environment variables with secrets are not captured in log context

---

## Connector Adoption Checklist

To adopt the session E2E framework for a new connector:

1. Identify the connector's transport: WebSocket, SSE, LongPoll, or WebhookIngress
2. Write a `SessionScript` covering: connect, receive, fault injection, health assertions, disconnect
3. Set up the appropriate fixture server (`StreamingFixtureServer` for SSE, manual WebSocket for WS)
4. Create a test in `crates/fcp-e2e/tests/` using `SessionE2eRunner`
5. Verify the evidence bundle contains useful debugging artifacts
6. Add the replay command to CI artifacts for regression triage
