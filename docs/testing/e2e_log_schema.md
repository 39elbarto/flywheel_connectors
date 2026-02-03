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
- `artifacts` (array of strings)
- `context` (object/array/string/number/boolean/null; free-form context)
- `error_code` (string; stable FCP error code when `result=fail`)
- `details` (object/array/string/number/boolean/null; extra error metadata)

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

Scenario Matrix Runner
----------------------

Run the full E2E script matrix via:

```bash
./scripts/e2e/run_matrix.sh
```

The runner writes:
- `out/e2e_matrix_runner/summary.jsonl` (one record per scenario)
- `out/e2e_matrix_runner/summary.json` (aggregate summary)

Required scenarios are listed in `scripts/e2e/run_matrix.sh` and should exit
`pass` with schema-valid JSONL logs. Optional scenarios may be skipped until
the underlying harness APIs are implemented.
