#!/usr/bin/env bash
# pure_unit_floor.sh — connector-focused wrapper around the shared coverage scanner.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MINIMUM_TESTS="${MINIMUM_TESTS:-5}"

exec "${SCRIPT_DIR}/test_coverage_scan.sh" \
  --check pure-unit-floor \
  --only connectors \
  --connector-minimum-tests "${MINIMUM_TESTS}"
