#!/usr/bin/env bash
# =============================================================================
# placeholder_inventory_scan_fixture.sh — Seeded fixture verification for the
# production-placeholder scanner
# =============================================================================
# Bead: flywheel_connectors-24llg.1.2
#
# Builds a deterministic temporary fixture repo, runs the placeholder-inventory
# scanner against it, and asserts the three critical branches:
#   1. known_gap_blocking
#   2. approved_exception
#   3. unexpected_match

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT=""

usage() {
  cat <<'EOF'
Usage: scripts/e2e/placeholder_inventory_scan_fixture.sh [options]

Creates a seeded fixture repo, runs the production-placeholder scanner against
it, and verifies the expected gate statuses for known gaps, approved
exceptions, and unexpected placeholder spread.

Options:
  --run-id <id>     Stable run identifier (default: UTC timestamp)
  --out-root <path> Artifact root (default: artifacts/e2e/placeholder-inventory-scan/<run-id>)
  -h, --help        Show this help
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)
      RUN_ID="${2:-}"
      shift 2
      ;;
    --out-root)
      OUT_ROOT="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_cmd bash
require_cmd jq

if [[ -z "${RUN_ID}" ]]; then
  echo "--run-id must not be empty" >&2
  exit 2
fi

if [[ -z "${OUT_ROOT}" ]]; then
  OUT_ROOT="${REPO_ROOT}/artifacts/e2e/placeholder-inventory-scan/${RUN_ID}"
fi

FIXTURE_ROOT="${OUT_ROOT}/fixture_repo"
REPORT_JSON="${OUT_ROOT}/fixture-scan.json"
REPORT_LOG="${OUT_ROOT}/fixture-scan.log"
SUMMARY_TXT="${OUT_ROOT}/summary.txt"

mkdir -p \
  "${FIXTURE_ROOT}/docs/testing" \
  "${FIXTURE_ROOT}/crates/fixture/src" \
  "${FIXTURE_ROOT}/crates/fixture/tests"

cat > "${FIXTURE_ROOT}/docs/testing/placeholder-inventory.json" <<'EOF'
{
  "version": 1,
  "generated_at": "2026-04-03T00:00:00Z",
  "purpose": "Seeded fixture inventory for placeholder scanner verification.",
  "approved_exception_classes": [
    {
      "id": "test_only",
      "description": "Fixture test-only placeholder allowance.",
      "allowed_path_globs": [
        "tests/**",
        "**/tests/**"
      ],
      "closure_rule": "Placeholder markers must remain inside dedicated test-only surfaces.",
      "owner_bead": "flywheel_connectors-24llg.1.2"
    }
  ],
  "findings": [
    {
      "id": "fixture-known-gap",
      "title": "Known runtime placeholder remains anchored",
      "classification": "runtime_blocker",
      "allowed_scaffold_candidate": false,
      "approved_exception_class": null,
      "owner_bead": "flywheel_connectors-24llg.1.2",
      "rationale": "Seeded runtime placeholder for known-gap coverage.",
      "exit_strategy": "Remove the runtime placeholder.",
      "verification_expectation": "Scanner should report known_gap_blocking.",
      "anchors": [
        {
          "path": "crates/fixture/src/known_gap.rs",
          "needle": "KNOWN_RUNTIME_PLACEHOLDER"
        }
      ]
    },
    {
      "id": "fixture-approved-exception",
      "title": "Approved exception stays inside test-only path",
      "classification": "approved_exception",
      "allowed_scaffold_candidate": true,
      "approved_exception_class": "test_only",
      "owner_bead": "flywheel_connectors-24llg.1.2",
      "rationale": "Seeded allowlisted placeholder for test-only coverage.",
      "exit_strategy": "Keep the marker quarantined to tests or remove it.",
      "verification_expectation": "Scanner should classify the finding as an approved exception.",
      "anchors": [
        {
          "path": "crates/fixture/tests/allowlisted_placeholder.rs",
          "needle": "ALLOWLISTED_TEST_PLACEHOLDER"
        }
      ]
    },
    {
      "id": "fixture-unexpected-spread",
      "title": "Runtime placeholder spreads outside its anchored path",
      "classification": "runtime_blocker",
      "allowed_scaffold_candidate": false,
      "approved_exception_class": null,
      "owner_bead": "flywheel_connectors-24llg.1.2",
      "rationale": "Seeded unexpected spread coverage for repo-wide scanning.",
      "exit_strategy": "Confine or remove the placeholder marker.",
      "verification_expectation": "Scanner should report unexpected_match with the extra path.",
      "anchors": [
        {
          "path": "crates/fixture/src/spread_a.rs",
          "needle": "SPREAD_RUNTIME_PLACEHOLDER"
        }
      ]
    }
  ]
}
EOF

cat > "${FIXTURE_ROOT}/crates/fixture/src/known_gap.rs" <<'EOF'
pub const MESSAGE: &str = "KNOWN_RUNTIME_PLACEHOLDER";
EOF

cat > "${FIXTURE_ROOT}/crates/fixture/tests/allowlisted_placeholder.rs" <<'EOF'
pub const MESSAGE: &str = "ALLOWLISTED_TEST_PLACEHOLDER";
EOF

cat > "${FIXTURE_ROOT}/crates/fixture/src/spread_a.rs" <<'EOF'
pub const MESSAGE: &str = "SPREAD_RUNTIME_PLACEHOLDER";
EOF

cat > "${FIXTURE_ROOT}/crates/fixture/src/spread_b.rs" <<'EOF'
pub const MESSAGE: &str = "SPREAD_RUNTIME_PLACEHOLDER";
EOF

set +e
bash "${REPO_ROOT}/scripts/ci/placeholder_inventory_scan.sh" \
  --repo-root "${FIXTURE_ROOT}" \
  --json-out "${REPORT_JSON}" \
  --log-out "${REPORT_LOG}"
SCAN_EXIT=$?
set -e

if [[ "${SCAN_EXIT}" -ne 1 ]]; then
  echo "Expected seeded fixture scan to fail with exit 1, got ${SCAN_EXIT}" >&2
  exit 1
fi

jq -e '.summary.total_findings == 3' "${REPORT_JSON}" >/dev/null
jq -e '.summary.present == 3' "${REPORT_JSON}" >/dev/null
jq -e '.summary.drifted == 0' "${REPORT_JSON}" >/dev/null
jq -e '.summary.failing_findings == 2' "${REPORT_JSON}" >/dev/null
jq -e '.summary.approved_exception_findings == 1' "${REPORT_JSON}" >/dev/null
jq -e '.findings[] | select(.id == "fixture-known-gap") | .gate_status == "known_gap_blocking" and (.anchored_matches | length) == 1' "${REPORT_JSON}" >/dev/null
jq -e '.findings[] | select(.id == "fixture-approved-exception") | .gate_status == "approved_exception" and (.anchored_matches | length) == 1' "${REPORT_JSON}" >/dev/null
jq -e '.findings[] | select(.id == "fixture-unexpected-spread") | .gate_status == "unexpected_match" and (.anchored_matches | length) == 1 and (.unexpected_matches | length) == 1 and (.unexpected_matches[0].path == "crates/fixture/src/spread_b.rs")' "${REPORT_JSON}" >/dev/null

cat > "${SUMMARY_TXT}" <<EOF
Seeded placeholder scanner fixture passed expected assertions.
Run ID: ${RUN_ID}
Fixture root: ${FIXTURE_ROOT}
Report JSON: ${REPORT_JSON}
Report log: ${REPORT_LOG}
EOF

printf '%s\n' "Seeded placeholder scanner fixture passed."
printf '%s\n' "Artifacts: ${OUT_ROOT}"
