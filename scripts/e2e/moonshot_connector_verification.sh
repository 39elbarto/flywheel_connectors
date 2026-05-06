#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

target_dir="${CARGO_TARGET_DIR:-/tmp/fcp-moonshot-e2e-target}"
export CARGO_TARGET_DIR="$target_dir"
export CARGO_INCREMENTAL=0
export GIT_REVISION="${GIT_REVISION:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"

echo "MOONSHOT_E2E_JSONL {\"event\":\"moonshot_verifier_start\",\"command_line\":\"$0\",\"git_revision\":\"$GIT_REVISION\",\"target_dir\":\"$CARGO_TARGET_DIR\",\"status\":\"running\"}"

run_rch() {
  local label="$1"
  shift
  echo "MOONSHOT_E2E_JSONL {\"event\":\"moonshot_verifier_step\",\"step\":\"$label\",\"command_line\":\"rch exec -- $*\",\"git_revision\":\"$GIT_REVISION\",\"status\":\"running\"}"
  rch exec -- "$@"
  echo "MOONSHOT_E2E_JSONL {\"event\":\"moonshot_verifier_step\",\"step\":\"$label\",\"git_revision\":\"$GIT_REVISION\",\"status\":\"passed\"}"
}

run_rch "manifest_check" cargo run -p fwc -- manifest fix --check connectors/moonshot/manifest.toml
run_rch "cargo_check" cargo check -p fcp-moonshot --all-targets
run_rch "cargo_test_loopback" cargo test -p fcp-moonshot --test integration moonshot_loopback_e2e_jsonl_matrix -- --nocapture
run_rch "cargo_test_all" cargo test -p fcp-moonshot --all-targets -- --nocapture
run_rch "cargo_clippy" cargo clippy -p fcp-moonshot --all-targets --no-deps -- -D warnings
run_rch "cargo_fmt" cargo fmt --package fcp-moonshot --check

echo "MOONSHOT_E2E_JSONL {\"event\":\"moonshot_verifier_complete\",\"command_line\":\"$0\",\"git_revision\":\"$GIT_REVISION\",\"target_dir\":\"$CARGO_TARGET_DIR\",\"status\":\"passed\"}"
