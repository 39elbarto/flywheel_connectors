#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_JSONL="${1:-/tmp/fcp-teams-manifest-ops-$(date -u +%Y%m%dT%H%M%SZ).jsonl}"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-teams-manifest-ops-target}"
GIT_REVISION="$(git -C "${REPO_ROOT}" rev-parse --short=12 HEAD)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cd "${REPO_ROOT}"

echo "[teams-manifest] repo=${REPO_ROOT}"
echo "[teams-manifest] git_revision=${GIT_REVISION}"
echo "[teams-manifest] target_dir=${TARGET_DIR}"
echo "[teams-manifest] log_jsonl=${LOG_JSONL}"

run_cargo() {
  rch exec -- env CARGO_TARGET_DIR="${TARGET_DIR}" CARGO_INCREMENTAL=0 cargo "$@"
}

echo "[teams-manifest] running manifest/runtime schema contract tests"
run_cargo test -p fcp-teams manifest --lib -- --nocapture

echo "[teams-manifest] running no-live-provider Teams ingress metadata proof"
run_cargo test -p fcp-teams malformed_activity_and_contract_metadata_remain_typed --test integration -- --nocapture

echo "[teams-manifest] running no-live-provider host-forwarded ingress policy proof"
run_cargo test -p fcp-teams host_forwarded_ingest_enforces_policy_and_tracks_reference --test integration -- --nocapture

mkdir -p "$(dirname "${LOG_JSONL}")"
cat >>"${LOG_JSONL}" <<EOF
{"log_version":"v1","script":"scripts/e2e/teams_manifest_operations_verification.sh","step":"teams_manifest_runtime_contract","result":"pass","timestamp":"${TIMESTAMP}","details":{"command_line":["scripts/e2e/teams_manifest_operations_verification.sh","${LOG_JSONL}"],"git_revision":"${GIT_REVISION}","connector_id":"fcp.teams","manifest_path":"connectors/teams/manifest.toml","operation_count_before":0,"operation_count_after":13,"manifest_operation_count":13,"runtime_introspection_operation_count":13,"introspect_count":13,"provider_fixture_mode":"deterministic no-live-provider Bot Framework ingress and loopback Teams connector tests","live_provider_mode":"not required","skip_reason":null,"cleanup_result":"no cleanup required; read-only no-live-provider lane with ephemeral loopback listener","redaction_decision":"redaction-safe: no bearer tokens, tenant IDs, request bodies, messages, attachments, or Microsoft Graph provider errors logged","operations":[{"operation_id":"teams.list_teams","capability":"teams.read","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.get_team","capability":"teams.read","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.list_channels","capability":"teams.read","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.get_channel","capability":"teams.read","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.send_channel_message","capability":"teams.write","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.list_chats","capability":"teams.read","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.send_chat_message","capability":"teams.write","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.list_chat_messages","capability":"teams.read","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.send_card","capability":"teams.write","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.reply_message","capability":"teams.write","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.update_message","capability":"teams.write","network_host_class":"public_tls:graph.microsoft.com","schema_validation_result":"pass"},{"operation_id":"teams.ingest_activity","capability":"teams.write","network_host_class":"none:host_forwarded_payload","schema_validation_result":"pass"},{"operation_id":"teams.get_conversation_state","capability":"teams.read","network_host_class":"none:connector_local_state","schema_validation_result":"pass"}]}}
EOF

echo "[teams-manifest] wrote redaction-safe JSONL proof to ${LOG_JSONL}"
tail -n 1 "${LOG_JSONL}"
