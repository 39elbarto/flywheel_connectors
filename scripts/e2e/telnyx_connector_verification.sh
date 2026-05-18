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
  local log_path="${TMPDIR:-/tmp}/fcp-telnyx-rch-proof-${RUN_ID:-manual}-$$.log"
  local rc

  set +e
  env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env \
    "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" \
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" \
    "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" \
    "$@" 2> >(tee "${log_path}" >&2)
  rc="$?"
  set -e

  if ! grep -Fq "[RCH] remote" "${log_path}"; then
    echo "[telnyx-verification] ${REMOTE_RUNNER}: rch command did not produce remote proof" >&2
    return 2
  fi

  return "${rc}"
}

if [[ "${TELNYX_LIVE_E2E:-0}" == "1" && -z "${TELNYX_API_KEY:-}" ]]; then
  git_revision="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
  printf '{"record_type":"telnyx_voice_call_connector_boundary_e2e","command_line":"bash scripts/e2e/telnyx_connector_verification.sh","git_revision":"%s","provider":"telnyx","provider_fixture_id":"telnyx-live-credentials","scenario":"live_credentials","outcome":"skipped","http_status":null,"websocket_status":"not_started","cleanup_result":"not_applicable","skip_reason":"TELNYX_LIVE_E2E=1 but TELNYX_API_KEY is not set"}\n' "$git_revision"
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-telnyx-e2e-target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

require_cmd "${RCH_BIN}"

run_remote_cargo cargo test -p fcp-telnyx --test integration telnyx_loopback_e2e_jsonl_covers_provider_edges -- --nocapture
