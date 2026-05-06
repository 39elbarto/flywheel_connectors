#!/usr/bin/env bash
set -euo pipefail

if [[ "${TELNYX_LIVE_E2E:-0}" == "1" && -z "${TELNYX_API_KEY:-}" ]]; then
  git_revision="$(git rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
  printf '{"record_type":"telnyx_voice_call_connector_boundary_e2e","command_line":"bash scripts/e2e/telnyx_connector_verification.sh","git_revision":"%s","provider":"telnyx","provider_fixture_id":"telnyx-live-credentials","scenario":"live_credentials","outcome":"skipped","http_status":null,"websocket_status":"not_started","cleanup_result":"not_applicable","skip_reason":"TELNYX_LIVE_E2E=1 but TELNYX_API_KEY is not set"}\n' "$git_revision"
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-telnyx-e2e-target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

cargo test -p fcp-telnyx --test integration telnyx_loopback_e2e_jsonl_covers_provider_edges -- --nocapture
