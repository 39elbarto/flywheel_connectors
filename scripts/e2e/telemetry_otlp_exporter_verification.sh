#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

target_dir="${FCP_TELEMETRY_OTLP_TARGET_DIR:-/tmp/fcp-telemetry-otlp-e2e-target}"
git_revision="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"

run_fixture() {
  local test_name="$1"
  local test_command="cargo test -p fcp-telemetry --test ${test_name} --features otlp -- --nocapture"

  local env_args=(
    "CARGO_TARGET_DIR=$target_dir"
    "CARGO_INCREMENTAL=0"
    "FCP_GIT_REVISION=$git_revision"
    "FCP_TEST_COMMAND_LINE=$test_command"
  )

  if [[ -n "${FCP_TELEMETRY_OTLP_EVIDENCE:-}" ]]; then
    env_args+=("FCP_TELEMETRY_OTLP_EVIDENCE=$FCP_TELEMETRY_OTLP_EVIDENCE")
  fi

  rch exec -- env \
    "${env_args[@]}" \
    cargo test -p fcp-telemetry --test "$test_name" --features otlp -- --nocapture
}

run_fixture otlp_collector_fixture
run_fixture otlp_unavailable_fixture
run_fixture otlp_backpressure_fixture
