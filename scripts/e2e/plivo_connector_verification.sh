#!/usr/bin/env bash
set -euo pipefail

RCH_BIN="${RCH_BIN:-rch}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
export RCH_FORCE_REMOTE=1

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_remote_cargo() {
  local log_path="${TMPDIR:-/tmp}/fcp-plivo-rch-proof-${RUN_ID:-manual}-$$.log"
  local rc

  set +e
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" \
    "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" \
    "PLIVO_E2E_LOG_DIR=${PLIVO_E2E_LOG_DIR}" \
    "$@" 2> >(tee "${log_path}" >&2)
  rc="$?"
  set -e

  if ! grep -Fq "[RCH] remote" "${log_path}"; then
    echo "[plivo-verification] ${REMOTE_RUNNER}: rch command did not produce remote proof" >&2
    return 2
  fi

  return "${rc}"
}

if [[ "${PLIVO_LIVE_E2E:-0}" == "1" && ( -z "${PLIVO_AUTH_ID:-}" || -z "${PLIVO_AUTH_TOKEN:-}" ) ]]; then
  git_revision="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
  printf '{"record_type":"plivo_voice_call_connector_boundary_e2e","command_line":"bash scripts/e2e/plivo_connector_verification.sh","git_revision":"%s","provider":"plivo","provider_fixture_id":"plivo-live-credentials","scenario":"live_credentials","outcome":"skipped","http_status":null,"websocket_status":"not_started","cleanup_result":"not_applicable","skip_reason":"PLIVO_LIVE_E2E=1 but PLIVO_AUTH_ID or PLIVO_AUTH_TOKEN is not set"}\n' "$git_revision"
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-plivo-e2e-target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export PLIVO_E2E_LOG_DIR="${PLIVO_E2E_LOG_DIR:-target/fcp-plivo/${RUN_ID:-manual}/e2e}"

require_cmd "${RCH_BIN}"

run_remote_cargo cargo test -p fcp-plivo --test integration plivo_loopback_e2e_jsonl_covers_provider_edges -- --nocapture
