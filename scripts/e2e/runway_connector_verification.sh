#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

export RUNWAY_E2E_GIT_REVISION="${RUNWAY_E2E_GIT_REVISION:-$(git rev-parse --short=12 HEAD 2>/dev/null || printf unknown)}"

run_rch() {
  local label="$1"
  shift
  printf 'RUNWAY_E2E_STEP %s\n' "$label"
  rch exec -- env CARGO_TARGET_DIR=/tmp/fcp-runway-e2e CARGO_INCREMENTAL=0 "$@"
}

run_rch "check" cargo check -p fcp-runway --all-targets
run_rch "test" cargo test -p fcp-runway --all-targets -- --nocapture
run_rch "clippy" cargo clippy -p fcp-runway --all-targets --no-deps -- -D warnings
run_rch "fmt" cargo fmt --package fcp-runway --check
run_rch "manifest_check" cargo run -p fwc -- manifest fix --check connectors/runway/manifest.toml

if [[ -z "${RUNWAY_API_KEY:-}" ]]; then
  printf 'RUNWAY_E2E_JSONL %s\n' '{"event":"runway_live_operation","mode":"live","operation":"runway.video.image_to_video","status":"skipped","skip_reason":"RUNWAY_API_KEY not set","cleanup_result":"not_started"}'
else
  printf 'RUNWAY_E2E_JSONL %s\n' '{"event":"runway_live_operation","mode":"live","operation":"runway.video.image_to_video","status":"skipped","skip_reason":"RUNWAY_API_KEY present but live paid generation is not run by default script","cleanup_result":"not_started"}'
fi
