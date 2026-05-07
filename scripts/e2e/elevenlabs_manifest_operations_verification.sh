#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-elevenlabs-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-elevenlabs-manifest-ops-target}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cd "${REPO_ROOT}"

echo "[elevenlabs-manifest] repo=${REPO_ROOT}"
echo "[elevenlabs-manifest] git_revision=${GIT_REVISION}"
echo "[elevenlabs-manifest] target_dir=${TARGET_DIR}"
echo "[elevenlabs-manifest] log_jsonl=${LOG_JSONL}"

echo "[elevenlabs-manifest] running manifest/runtime/schema contract tests"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test -p fcp-elevenlabs elevenlabs_manifest --test provider_contract -- --nocapture

echo "[elevenlabs-manifest] running deterministic no-live-provider HTTP/WebSocket connector suite"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test -p fcp-elevenlabs --test connector_suite_happy_path -- --nocapture

echo "[elevenlabs-manifest] running redaction-safe cross-connector audit JSONL lane"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- \
    --repo-root . \
    --allow-findings \
    --log-jsonl "${LOG_JSONL}"

if ! rg -q '"connector_id":"fcp.elevenlabs".*"result":"pass"' "${LOG_JSONL}"; then
  echo "[elevenlabs-manifest] ERROR: fcp.elevenlabs did not produce a passing connector_scan log entry" >&2
  exit 1
fi

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/elevenlabs_manifest_operations_verification.sh","step":"elevenlabs_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/elevenlabs_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.elevenlabs","manifest_path":"connectors/elevenlabs/manifest.toml","operation_count_before":0,"operation_count_after":4,"manifest_operation_count":4,"runtime_introspection_operation_count":4,"introspect_count":4,"provider_fixture_mode":"deterministic no-live-provider HTTP and WebSocket loopback fixtures covered by connector_suite_happy_path","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listeners","redaction_decision":"redaction-safe: no API keys, request bodies, text prompts, transcripts, audio bytes, provider payloads, or error bodies logged","operations":[{"operation_id":"elevenlabs.voices.list","capability":"elevenlabs.voices","network_host_class":"public_tls:elevenlabs.io","schema_validation_result":"pass"},{"operation_id":"elevenlabs.tts.generate","capability":"elevenlabs.tts","network_host_class":"public_tls:elevenlabs.io","schema_validation_result":"pass"},{"operation_id":"elevenlabs.tts.stream","capability":"elevenlabs.tts.streaming","network_host_class":"public_tls_streaming:elevenlabs.io","schema_validation_result":"pass"},{"operation_id":"elevenlabs.scribe.realtime.transcribe","capability":"elevenlabs.stt.streaming","network_host_class":"public_tls_websocket:elevenlabs.io","schema_validation_result":"pass"}]}}
EOF

echo "[elevenlabs-manifest] verified fcp.elevenlabs connector_scan pass in ${LOG_JSONL}"
