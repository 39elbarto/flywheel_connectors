#!/usr/bin/env bash
set -euo pipefail

if [[ "${PLIVO_LIVE_E2E:-0}" == "1" && ( -z "${PLIVO_AUTH_ID:-}" || -z "${PLIVO_AUTH_TOKEN:-}" ) ]]; then
  git_revision="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
  printf '{"record_type":"plivo_voice_call_connector_boundary_e2e","command_line":"bash scripts/e2e/plivo_connector_verification.sh","git_revision":"%s","provider":"plivo","provider_fixture_id":"plivo-live-credentials","scenario":"live_credentials","outcome":"skipped","http_status":null,"websocket_status":"not_started","cleanup_result":"not_applicable","skip_reason":"PLIVO_LIVE_E2E=1 but PLIVO_AUTH_ID or PLIVO_AUTH_TOKEN is not set"}\n' "$git_revision"
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-plivo-e2e-target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

cargo test -p fcp-plivo --test integration plivo_loopback_e2e_jsonl_covers_provider_edges -- --nocapture
