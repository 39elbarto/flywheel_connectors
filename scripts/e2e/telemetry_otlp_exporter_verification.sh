#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

target_dir="${FCP_TELEMETRY_OTLP_TARGET_DIR:-/tmp/fcp-telemetry-otlp-e2e-target}"
test_command="cargo test -p fcp-telemetry --test otlp_collector_fixture --features otlp -- --nocapture"
git_revision="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"

env_args=(
  "CARGO_TARGET_DIR=$target_dir"
  "CARGO_INCREMENTAL=0"
  "FCP_GIT_REVISION=$git_revision"
  "FCP_TEST_COMMAND_LINE=$test_command"
)

if [[ -n "${FCP_TELEMETRY_OTLP_EVIDENCE:-}" ]]; then
  env_args+=("FCP_TELEMETRY_OTLP_EVIDENCE=$FCP_TELEMETRY_OTLP_EVIDENCE")
fi

exec rch exec -- env \
  "${env_args[@]}" \
  cargo test -p fcp-telemetry --test otlp_collector_fixture --features otlp -- --nocapture
