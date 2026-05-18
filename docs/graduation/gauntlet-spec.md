# Connector Graduation Gauntlet

This document defines the first mechanical graduation gate for connector
readiness. The gate is intentionally non-mutating: it reports why a connector
does not satisfy the checklist and leaves any status demotion or audit-chain
write to an explicit future operator command.

## Status Scope

The project README uses `PROVEN` for repository-backed feature evidence. The
connector gauntlet treats a connector as graduation-bound only when its own
`connectors/<name>/README.md` status line contains the literal token `PROVEN`.
Current connector README statuses mostly use phrases such as
`implementation-reviewed and verification-backed`; those are not rewritten by
this runner.

## Runner Contract

Run the gauntlet with:

```bash
scripts/graduation/run_gauntlet.sh connectors/<name>
```

The runner emits one JSONL record per evaluated check:

```json
{"connector":"connectors/example","check":"manifest_present","verdict":"pass","duration_ms":0,"stderr_excerpt":""}
```

On the first failure it prints a structured stderr line containing
`check=<name>` and exits with that check's stable exit code. A fully passing
connector exits `0`.

Use `--list-checks` to print the stable check table as
`check_id|exit_code|description`.

Batch 1 status is generated with:

```bash
scripts/graduation/run_gauntlet.sh --batch batch1 --status-md docs/graduation/batch1_status.md
```

Batch 2 status is generated with:

```bash
scripts/graduation/run_gauntlet.sh --batch batch2 --status-md docs/graduation/batch2_status.md
```

Batch 3 status is generated with:

```bash
scripts/graduation/run_gauntlet.sh --batch batch3 --status-md docs/graduation/batch3_status.md
```

Batch 4 status is generated from the scanner-derived long-tail inventory:

```bash
scripts/graduation/batch4_inventory.sh --markdown
scripts/graduation/run_gauntlet.sh --batch batch4 --status-md docs/graduation/batch4_status.md
```

The batch mode runs the same checks against the Phase G connector batch and
writes a Markdown status artifact. It does not graduate or demote connectors;
it records the first blocking check for each connector so follow-up work can be
split without claiming PROVEN status prematurely.

## Check Matrix

| Check | Exit | Requirement |
|-------|------|-------------|
| `connector_path` | 1 | The connector argument resolves to a directory. |
| `operations_info` | 2 | The connector source exposes an `operations_info` surface. |
| `manifest_present` | 3 | `manifest.toml` exists in the connector directory. |
| `readme_present` | 4 | `README.md` exists in the connector directory. |
| `verification_script_declared` | 5 | The README declares a `scripts/e2e/...` verification script. |
| `manifest_operations` | 6 | The manifest declares at least one `[provides.operations.*]` entry. |
| `local_non_mock` | 7 | `tests/local_non_mock.rs` exists for local non-mock proof. |
| `readme_status_match` | 8 | A literal `PROVEN` README status has manifest status `proven`. |
| `operation_inventory` | 9 | The README has an operation inventory containing a manifest operation ID. |
| `network_policy` | 10 | Manifest operation policy denies localhost and private ranges. |
| `sandbox_profile` | 11 | The manifest declares a `[sandbox]` profile. |
| `operator_guidance` | 12 | The README has operator guidance and rerun commands. |

## Conformance Coverage

`crates/fcp-conformance/tests/graduation_gauntlet_conformance.rs` verifies the
stable 12-check table, required failure codes, and the current corpus rule that
every connector README with a literal `PROVEN` status must pass the gauntlet.
If there are no literal `PROVEN` connector statuses, the corpus test is
vacuously green and prints that distinction instead of treating project-level
README `PROVEN` rows as connector graduations.
