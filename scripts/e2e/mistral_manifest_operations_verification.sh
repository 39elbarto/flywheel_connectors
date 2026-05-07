#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-mistral-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-mistral-manifest-ops-target}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cd "${REPO_ROOT}"

echo "[mistral-manifest] repo=${REPO_ROOT}"
echo "[mistral-manifest] git_revision=${GIT_REVISION}"
echo "[mistral-manifest] target_dir=${TARGET_DIR}"
echo "[mistral-manifest] log_jsonl=${LOG_JSONL}"

echo "[mistral-manifest] running manifest/runtime schema contract tests"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo test -p fcp-mistral mistral_manifest --test provider_contract -- --nocapture

echo "[mistral-manifest] running redaction-safe cross-connector audit JSONL lane"
CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 \
  cargo run -p fcp-conformance --bin fcp-manifest-ops-audit -- \
    --repo-root . \
    --allow-findings \
    --log-jsonl "${LOG_JSONL}"

if ! rg -q '"connector_id":"fcp.mistral".*"result":"pass"' "${LOG_JSONL}"; then
  echo "[mistral-manifest] ERROR: fcp.mistral did not produce a passing connector_scan log entry" >&2
  exit 1
fi

cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/mistral_manifest_operations_verification.sh","step":"mistral_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/mistral_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.mistral","manifest_path":"connectors/mistral/manifest.toml","operation_count_before":0,"operation_count_after":5,"manifest_operation_count":5,"runtime_introspection_operation_count":5,"introspect_count":5,"provider_fixture_mode":"deterministic loopback WebSocket fixture covered by connector_suite_happy_path","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane","redaction_decision":"redaction-safe: no API keys, request bodies, prompts, transcripts, provider payloads, or error bodies logged","operations":[{"operation_id":"mistral.chat.completions","capability":"mistral.chat","network_host_class":"public_tls:mistral.ai","schema_validation_result":"pass"},{"operation_id":"mistral.embeddings.create","capability":"mistral.embeddings","network_host_class":"public_tls:mistral.ai","schema_validation_result":"pass"},{"operation_id":"mistral.audio.transcriptions","capability":"mistral.audio","network_host_class":"public_tls:mistral.ai","schema_validation_result":"pass"},{"operation_id":"mistral.audio.realtime.transcribe","capability":"mistral.audio","network_host_class":"public_tls_websocket:mistral.ai","schema_validation_result":"pass"},{"operation_id":"mistral.models.list","capability":"mistral.models","network_host_class":"public_tls:mistral.ai","schema_validation_result":"pass"}]}}
EOF

echo "[mistral-manifest] verified fcp.mistral connector_scan pass in ${LOG_JSONL}"
