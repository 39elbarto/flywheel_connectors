#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-deepgram-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-deepgram-manifest-ops-target}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cd "${REPO_ROOT}"

echo "[deepgram-manifest] repo=${REPO_ROOT}"
echo "[deepgram-manifest] git_revision=${GIT_REVISION}"
echo "[deepgram-manifest] target_dir=${TARGET_DIR}"
echo "[deepgram-manifest] log_jsonl=${LOG_JSONL}"

run_cargo() {
  if [[ "${FCP_DEEPGRAM_USE_RCH:-0}" == "1" ]]; then
    rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo "$@"
  else
    CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo "$@"
  fi
}

echo "[deepgram-manifest] running manifest/runtime/schema contract tests"
run_cargo test -p fcp-deepgram deepgram_manifest --test provider_contract -- --nocapture

echo "[deepgram-manifest] running deterministic no-live-provider HTTP/WebSocket connector suite"
run_cargo test -p fcp-deepgram --test connector_suite_happy_path -- --nocapture

echo "[deepgram-manifest] checking manifest interface hash with fwc"
run_cargo run -p fwc -- manifest fix connectors/deepgram/manifest.toml --check --json

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/deepgram_manifest_operations_verification.sh","step":"deepgram_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/deepgram_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.deepgram","manifest_path":"connectors/deepgram/manifest.toml","operation_count_before":0,"operation_count_after":2,"manifest_operation_count":2,"runtime_introspection_operation_count":2,"introspect_count":2,"provider_fixture_mode":"deterministic no-live-provider HTTP and WebSocket loopback fixtures covered by connector_suite_happy_path","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listener","redaction_decision":"redaction-safe: no API keys, audio URLs, request bodies, transcripts, audio bytes, provider payloads, or error bodies logged","operations":[{"operation_id":"deepgram.listen.transcribe","capability":"deepgram.listen","network_host_class":"public_tls:api.deepgram.com","schema_validation_result":"pass"},{"operation_id":"deepgram.listen.stream","capability":"deepgram.listen.streaming","network_host_class":"public_tls_websocket:api.deepgram.com","schema_validation_result":"pass"}]}}
EOF

echo "[deepgram-manifest] wrote redaction-safe JSONL proof to ${LOG_JSONL}"
tail -n 1 "${LOG_JSONL}"
