E2E Log Schema (JSONL)
======================

This document defines the single structured logging schema used by:
- fcp-e2e harness logs (`crates/fcp-e2e`)
- conformance harness logs (`crates/fcp-conformance`)
- shell-based E2E scripts (`scripts/e2e/*.sh`)

The goal is **machine-parseable, uniform logs** with minimal required fields and
clear compatibility between harness and script outputs.

Canonical Schema
----------------

The canonical JSON Schemas live at:

- `crates/fcp-conformance/src/schemas/E2E_Log_v1.schema.json`
- `crates/fcp-conformance/src/schemas/E2E_Log_v2.schema.json`

Versioning rules:
- If `log_version` is **missing**, the validator treats the entry as **v1**.
- If `log_version` is present, it MUST be `v1` or `v2` and the matching schema is used.

It accepts **three entry shapes** (all are valid under the single schema).

1. Conformance Harness Entry (fcp-conformance)
----------------------------------------------

Required fields (v1 allows `log_version` optional; v2 requires `log_version: \"v2\"`):

- `timestamp` (string, RFC3339 UTC)
- `real_time` (string, RFC3339 UTC)
- `node_id` (string)
- `test_name` (string)
- `phase` (string)
- `correlation_id` (string)
- `event_type` (string)
- `details` (object/array/string/number/boolean/null)

2. fcp-e2e Harness Entry (fcp-e2e)
----------------------------------

Required fields (v1 allows `log_version` optional; v2 requires `log_version: \"v2\"`):

- `timestamp` (string, RFC3339 UTC)
- `test_name` (string)
- `module` (string)
- `phase` (string)
- `correlation_id` (string)
- `result` (string: `pass` | `fail`)
- `duration_ms` (u64)
- `assertions` (object: `passed`, `failed`)

3. Script Entry (scripts/e2e/*.sh)
----------------------------------

Required fields (v1 allows `log_version` optional; v2 requires `log_version: \"v2\"`):

- `timestamp` (string, RFC3339 UTC)
- `script` (string)
- `step` (string)
- `correlation_id` (string)
- `duration_ms` (u64)
- `result` (string: `pass` | `fail`)

Optional Fields (All Shapes)
----------------------------

- `level` (string: info|warn|error)
- `step_number` (u64)
- `step_id` (string; stable logical step label for report/bundle correlation)
- `attempt` (u64; retry/attempt number for the step)
- `artifacts` (array of strings)
- `context` (object/array/string/number/boolean/null; free-form context)
- `error_code` (string; stable FCP error code when `result=fail`)
- `details` (object/array/string/number/boolean/null; extra error metadata)
- `summary` (object/array/string/number/boolean/null; compact run/step summary payload)
- `command` (object/array/string/number/boolean/null; per-step command metadata)
- `scan` (object/array/string/number/boolean/null; secret-scan evidence)
- `prerequisites` (object/array/string/number/boolean/null; prerequisite state snapshot)
- `failure_summary` (object/array/string/number/boolean/null; short debugging summary)
- `run_id` (string; stable run-level identifier)
- `scenario_id` (string; stable scenario identifier when the run is scenario-backed)

Truthfulness Context Conventions
--------------------------------

For host-first truthfulness scenarios, prefer carrying the following fields
inside `context` (or `details` when the harness shape makes that more natural):

- `command_mode` with the same tags used by `CommandAvailability`
  (`live-runtime`, `offline-artifact`, `unsupported`, `planned`,
  `unavailable`, `denied`, `unknown`)
- `provenance_markers` as an array of explicit source labels such as
  `live-host-introspection`, `live-host-inventory`, `workspace-manifest`,
  `local-catalog-cache`, or `static-schema`
- `phase` as one of `setup`, `offline-artifact`, `host-discovery`,
  `preflight`, `simulate`, `invoke`, `host-receipt`, `reconnect`,
  `cancellation`, or `teardown`
- `host_request_id`, `host_response_id`, and `receipt_id` when the scenario
  crossed the live host boundary
- `reconnect_event` and `cancellation_event` when long-lived or interruptible
  flows are being exercised

These markers are not just debugging decoration. They are the evidence that a
future engineer can use to prove whether a scenario exercised live runtime
truth, explicit offline artifact work, or a refusal/remediation path.

Session Script DSL and Transcript Contract
-----------------------------------------

The canonical typed carriers for session-oriented acceptance work live in:

- `crates/fcp-testkit/src/session_script.rs`
  - `SessionScript`
  - `ScriptStep`
  - `SessionTranscript`
  - `TranscriptEntry`
  - `TranscriptSummary`

These types define the shared vocabulary for websocket, SSE, long-poll, and
webhook acceptance runs before any connector-specific harness layers are added.

Session script fields:

- `scenario_id`
- `default_transport`: `websocket`, `sse`, `long_poll`, or `webhook_ingress`
- `labels[]`, `description`
- `steps[]`:
  - typed enum variants such as `Connect`, `SendMessage`, `ExpectMessage`, `ExpectCount`, `ExpectSilence`, `Wait`, `AssertHealth`, `InjectFault`, `WebhookDeliver`, and `Annotate`
  - timeout and ack semantics live on the relevant expect-style variants
  - reconnect, silence, webhook, and fault behavior are represented as explicit step actions rather than free-form metadata

Session transcript fields:

- `scenario_id`, `run_id`
- `transport`, `started_at`, `finished_at`, `total_duration`
- `outcome`
- `entries[]`:
  - `timestamp`
  - `step_index` as the canonical 0-based ordinal
  - `step` with the original typed `ScriptStep`
  - `outcome`, `duration`
  - optional `detail`, optional `correlation_id`
- `summary`:
  - `total`
  - `passed`
  - `failed`
  - `skipped`
  - `timed_out`

Alignment with the E2E evidence model:

- `fcp-e2e::E2eRunReport` may carry the full typed `session_transcript`.
- `E2eLogEntry::with_session_transcript_entry(...)` maps one transcript event into the existing per-step log vocabulary.
- `E2eLogEntry::with_session_transcript_summary(...)` maps the transcript aggregate into the existing `summary` payload.
- `E2eLogEntry` derives a 1-based `step_number` and synthetic `step_id` from the transcript's 0-based `step_index` so JSONL evidence stays readable without maintaining a second session schema.

Compatibility Rules
-------------------

1. fcp-e2e harness logs use `test_name` + `phase`.
2. Conformance harness logs use `test_name` + `phase` plus `event_type`.
3. Script logs use `script` + `step`.
4. `result` is strictly `pass` or `fail` where present.
5. Any secrets in `context`/`details` are redacted by the harness.
6. v2 entries MUST include `log_version: \"v2\"` (v1 entries may omit it).

Harness Example (fcp-e2e)
-------------------------

```json
{
  "timestamp": "2026-01-27T00:00:00Z",
  "level": "info",
  "test_name": "connector_happy_path",
  "module": "fcp-e2e",
  "phase": "execute",
  "correlation_id": "00000000-0000-4000-8000-000000000000",
  "result": "pass",
  "duration_ms": 12,
  "assertions": { "passed": 3, "failed": 0 },
  "context": { "zone_id": "z:work", "connector_id": "fcp.test-echo" }
}
```

Script Example (scripts/e2e/*.sh)
---------------------------------

```json
{
  "timestamp": "2026-01-27T00:00:00Z",
  "script": "e2e_happy_path",
  "step": "invoke",
  "step_number": 4,
  "correlation_id": "00000000-0000-4000-8000-000000000000",
  "duration_ms": 25,
  "result": "pass",
  "artifacts": ["receipt.cbor"]
}
```

Validator
---------

The canonical validator lives in `crates/fcp-conformance/src/schemas/` as:
- `fcp_conformance::schemas::validate_e2e_log_entry`
- `fcp_conformance::schemas::validate_e2e_log_jsonl`

The fcp-e2e wrapper lives in `crates/fcp-e2e/src/logging.rs` as:
- `validate_log_entry_value(value: &serde_json::Value)`
- `E2eLogEntry::validate()`

These checks enforce the required fields and minimal typing guarantees so
E2E logs are always parsable by downstream tooling.

CLI Validation
--------------

Use the fcp-e2e CLI to validate script-generated JSONL logs:

```bash
fcp-e2e --validate-log scripts/e2e/out/e2e_happy_path.jsonl
```

The CLI will exit non-zero on the first invalid line and print a line number
plus the schema violation.

Rich Run Reports (fcp-e2e CLI)
------------------------------

The `fcp-e2e` CLI now supports a richer reporting/bundle flow for connector and
interop runs:

```bash
fcp-e2e --connector-cmd ./target/debug/fcp-example \
  --request-file ./requests/happy.json \
  --output ./artifacts/logs.jsonl \
  --stable-output ./artifacts/logs.stable.jsonl \
  --report-json ./artifacts/report.json \
  --summary-output ./artifacts/summary.txt \
  --bundle-dir ./artifacts/run-001
```

Bundle/report expectations:
- `logs.jsonl` remains the canonical schema-validated event stream.
- `logs.stable.jsonl` normalizes nondeterministic fields for deterministic diffs.
- `report.json` is the machine-readable run report with per-step command metadata,
  artifact paths, prerequisite state, failure summaries, and aggregate scan
  results.
- `summary.txt` is the human-readable triage summary.
- `bundle-dir` stores per-step request/response/stderr artifacts so failures are
  replayable without rerunning interactively.

The `fwc` observability bundle contract in
`crates/fwc/src/test_observability.rs` uses the same vocabulary for artifact
paths, replay scripts, redaction, and truthfulness summaries even though its
trace entries are stored in a separate type system.

Shared Verification Bundle Contract
-----------------------------------

Placeholder-eradication beads should treat replayable verification evidence as
one logical contract even when concrete filenames differ across harnesses.

Machine-readable carriers:

- `crates/fcp-e2e/src/evidence.rs`
  - `EvidenceBundle.schema_version = "fcp-verification-bundle/v1"`
  - stable `scenario_id`
  - `layer`
  - `artifact_paths`
  - `commands.local`, `commands.ci`, `commands.validate`
  - `redacted_fields`
- `crates/fwc/src/test_observability.rs`
  - `ArtifactManifest.schema_version = "fcp-verification-bundle/v1"`
  - `layer`
  - `bundle_root`
  - `artifact_paths`
  - trace/truthfulness rollups

Canonical artifact labels:

- `environment_json`
- `replay_sh`
- `session_transcript_json` when the scenario is session-backed
- `logs_jsonl`, `report_json`, `summary_txt` for `fcp-e2e` and shell-style suites
- `trace_jsonl`, `summary_json` for `fwc` truthfulness bundles

Contract rules:

1. Every bundle must carry a stable `scenario_id` and layer tag.
2. Every bundle must expose canonical artifact labels, not just ad hoc paths in prose.
3. Every bundle must expose a local rerun path and, when replay depends on Cargo, a CI/offloaded rerun command that preserves `rch exec --`.
4. Every bundle must carry an explicit validation command. The canonical validator is:
   `bash scripts/ci/validate_e2e_artifacts.sh --bundle-dir <bundle-dir>`
5. Secret-bearing fields must be redacted before archival, and the redacted field list must remain in the bundle.

This contract is intentionally layered on top of crate-local and connector-local
test surfaces rather than replacing them. Unit coverage stays next to the code,
integration coverage stays in crate-local `tests/`, and host/e2e bundles add
the replayable evidence layer that downstream proof beads and closure audits
consume.

Scenario Matrix Runner
----------------------

Run the full E2E script matrix via:

```bash
./scripts/e2e/run_matrix.sh --run-id 235t-e2e-baseline
```

The runner writes:
- `artifacts/asupersync/e2e/<run-id>/results.jsonl` (one record per scenario)
- `artifacts/asupersync/e2e/<run-id>/summary.json` (aggregate summary)
- `artifacts/asupersync/e2e/<run-id>/manifest.json` (run envelope + totals)
- `artifacts/asupersync/e2e/<run-id>/scenario_plan.json` (scenario id/seed/replay contract)
- `artifacts/asupersync/e2e/<run-id>/replay.sh` (deterministic full + per-scenario replay commands)
- `artifacts/asupersync/e2e/<run-id>/scenarios/<scenario>/...` (command.txt, execution.log, scenario.json, artifacts/)

For any cargo-backed replay or validation step emitted by these artifacts, the
replay contract should preserve the required remote-offload prefix:

```bash
rch exec -- cargo ...
```

Required scenarios are listed in `scripts/e2e/run_matrix.sh` and should exit
`pass` with schema-valid JSONL logs. Optional scenarios may be skipped until
the underlying harness APIs are implemented.

Scenario ID Governance
----------------------

The canonical machine-consumable registry is:

- `scripts/e2e/scenario_registry.json`

Validation command:

```bash
./scripts/e2e/validate_scenario_registry.sh
```

Governance guarantees:
- Stable scenario IDs (`asupersync.e2e.<key>`) for every matrix scenario.
- One-to-one mapping of scenario -> script -> contract id.
- Duplicate/ambiguous keys, IDs, scripts, or contracts are rejected.
