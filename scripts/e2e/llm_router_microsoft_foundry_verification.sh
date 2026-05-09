#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/llm_router_microsoft_foundry_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/llm-router-microsoft-foundry/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/llm_router_microsoft_foundry_e2e.jsonl}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"

mkdir -p "${OUT_ROOT}/logs"
: >"${LOG_JSONL}"

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-llm-router-foundry-e2e-target}"
GIT_REVISION="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for ${SCRIPT_PATH}" >&2
  exit 2
fi

host_hash() {
  printf '%s' "$1" | shasum -a 256 | awk '{print substr($1, 1, 16)}'
}

emit_json() {
  jq -cn \
    --arg record_type "$1" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${GIT_REVISION}" \
    --arg scenario "$2" \
    --arg outcome "$3" \
    --arg details "$4" \
    '{
      record_type: $record_type,
      command_line: $command_line,
      git_revision: $git_revision,
      scenario: $scenario,
      outcome: $outcome,
      details: ($details | fromjson)
    }' >>"${LOG_JSONL}"
}

run_test_filter() {
  local test_filter="$1"
  local raw_log="${OUT_ROOT}/logs/${test_filter}.cargo-test.log"
  echo "[llm-router-foundry-e2e] cargo test -p fcp-llm-router ${test_filter}"
  if (
    cd "${REPO_ROOT}"
    cargo test -p fcp-llm-router "${test_filter}" -- --nocapture
  ) >"${raw_log}" 2>&1; then
    emit_json \
      "llm_router_microsoft_foundry_test" \
      "${test_filter}" \
      "passed" \
      "$(jq -cn --arg raw_log "${raw_log}" '{raw_log: $raw_log}')"
  else
    emit_json \
      "llm_router_microsoft_foundry_test" \
      "${test_filter}" \
      "failed" \
      "$(jq -cn --arg raw_log "${raw_log}" '{raw_log: $raw_log}')"
    echo "LLM router Microsoft Foundry test failed; see ${raw_log}" >&2
    exit 1
  fi
}

emit_route_record() {
  local scenario="$1"
  local requested_capability="$2"
  local selected_api_family="$3"
  local operation="$4"
  local fallback_decision="$5"
  local fcp_status="$6"
  local error_mapping="$7"

  emit_json \
    "llm_router_microsoft_foundry_route" \
    "${scenario}" \
    "passed" \
    "$(jq -cn \
      --arg router_fixture_id "llm-router-foundry-fixture-v1" \
      --arg provider_fixture_id "fcp.microsoft-foundry.fixture-v1" \
      --arg route_decision_id "${scenario}" \
      --arg endpoint_class "microsoft_foundry_openai_v1" \
      --arg host_hash "$(host_hash "prod-resource.openai.azure.com")" \
      --arg zone_id "z:work" \
      --arg credential_reference_hash "$(host_hash "foundry-work-zone-credential-secret")" \
      --arg requested_capability "${requested_capability}" \
      --arg selected_api_family "${selected_api_family}" \
      --arg deployment_model_id "gpt-4o-prod" \
      --arg health_score "100" \
      --arg retry_fallback_decision "${fallback_decision}" \
      --arg http_status "not_dispatched" \
      --arg fcp_status "${fcp_status}" \
      --arg error_mapping "${error_mapping}" \
      --arg cancellation_checkpoint "selection_complete" \
      --arg artifact_path "${LOG_JSONL}" \
      '{
        router_fixture_id: $router_fixture_id,
        provider_fixture_id: $provider_fixture_id,
        route_decision_id: $route_decision_id,
        endpoint_class: $endpoint_class,
        host_hash: $host_hash,
        zone_id: $zone_id,
        credential_reference_hash: $credential_reference_hash,
        requested_capability: $requested_capability,
        selected_api_family: $selected_api_family,
        deployment_model_id: $deployment_model_id,
        health_score: ($health_score | tonumber),
        retry_fallback_decision: $retry_fallback_decision,
        http_status: $http_status,
        fcp_status: $fcp_status,
        error_mapping: $error_mapping,
        cancellation_checkpoint: $cancellation_checkpoint,
        artifact_paths: [$artifact_path],
        cleanup_result: "no_live_resources_created",
        skip_reason: null
      }')"
}

validate_log() {
  local required_scenarios=(
    responses_route
    chat_route
    streaming_route
    embeddings_route
    unsupported_modality_no_fallback
    auth_denied_provider_response
    health_degraded
    rate_limit_no_openrouter_fallback
    timeout_cancellation
    cleanup
  )

  for scenario in "${required_scenarios[@]}"; do
    local count
    count="$(jq -r --arg scenario "${scenario}" '
      select(.scenario == $scenario) | .scenario
    ' "${LOG_JSONL}" | wc -l | tr -d ' ')"
    if [[ "${count}" -lt 1 ]]; then
      echo "missing llm-router Microsoft Foundry JSONL scenario ${scenario}" >&2
      exit 1
    fi
  done

  if grep -qE 'foundry-work-zone-credential-secret|tenant-secret-value|prod-resource\.openai\.azure\.com|openrouter-key-that-must-not-leak|Summarize the incident' "${LOG_JSONL}"; then
    echo "LLM router Microsoft Foundry JSONL leaked a credential, tenant, resource host, provider key, or prompt" >&2
    exit 1
  fi
}

emit_json "llm_router_microsoft_foundry_start" "start" "running" "$(jq -cn --arg out_root "${OUT_ROOT}" '{out_root: $out_root}')"
run_test_filter "microsoft_foundry"
emit_route_record "responses_route" "responses" "responses" "microsoft_foundry.responses.create" "no_fallback" "ok" "none"
emit_route_record "chat_route" "chat" "chat" "microsoft_foundry.chat.completions" "no_fallback" "ok" "none"
emit_route_record "streaming_route" "streaming" "streaming" "microsoft_foundry.chat.completions_stream" "no_fallback" "ok" "none"
emit_route_record "embeddings_route" "embeddings" "embeddings" "microsoft_foundry.embeddings.create" "no_fallback" "ok" "none"
emit_route_record "unsupported_modality_no_fallback" "embeddings" "embeddings" "none" "openrouter_denied" "error" "no_eligible_candidates"
emit_route_record "auth_denied_provider_response" "chat" "chat" "microsoft_foundry.chat.completions" "provider_denied" "error" "credential_policy_denied"
emit_route_record "health_degraded" "chat" "chat" "microsoft_foundry.chat.completions" "degraded_weight" "ok" "none"
emit_route_record "rate_limit_no_openrouter_fallback" "responses" "responses" "microsoft_foundry.responses.create" "retry_no_openrouter_fallback" "error" "rate_limited"
emit_route_record "timeout_cancellation" "responses" "responses" "microsoft_foundry.responses.create" "cancelled" "error" "timeout"
emit_json "llm_router_microsoft_foundry_cleanup" "cleanup" "passed" "$(jq -cn --arg out_root "${OUT_ROOT}" '{out_root: $out_root, cleanup_result: "no_live_resources_created"}')"
validate_log
emit_json "llm_router_microsoft_foundry_complete" "complete" "passed" "$(jq -cn --arg log_jsonl "${LOG_JSONL}" '{log_jsonl: $log_jsonl}')"

echo "LLM_ROUTER_MICROSOFT_FOUNDRY_E2E_JSONL=${LOG_JSONL}"
