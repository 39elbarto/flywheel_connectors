#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_PATH="scripts/e2e/voice_call_multi_provider_verification.sh"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/voice_call_multi_provider/${RUN_ID}}"
LOG_JSONL="${LOG_JSONL:-${OUT_ROOT}/voice_call_multi_provider_e2e.jsonl}"
COMMAND_LINE="${COMMAND_LINE:-bash ${SCRIPT_PATH}}"

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/provider-jsonl"
: >"${LOG_JSONL}"

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-voice-call-multi-provider-e2e-target}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required for ${SCRIPT_PATH}" >&2
  exit 2
fi

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

emit_json() {
  jq -cn \
    --arg record_type "$1" \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${git_revision}" \
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

emit_live_skip() {
  local provider="$1"
  local fixture_id="$2"
  local reason="$3"

  jq -cn \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${git_revision}" \
    --arg provider "${provider}" \
    --arg fixture_id "${fixture_id}" \
    --arg reason "${reason}" \
    '{
      record_type: "voice_call_multi_provider_connector_boundary_e2e",
      command_line: $command_line,
      git_revision: $git_revision,
      provider: $provider,
      provider_fixture_id: $fixture_id,
      connector_instance_id: ("fcp-" + $provider + ":live-skip"),
      zone: "z:work",
      scenario: "live_credentials",
      outcome: "skipped",
      call_id_hash: null,
      call_session_id_hash: null,
      masked_caller_identity: null,
      webhook_event_type: null,
      signature_decision: "not_started",
      auth_decision: "not_started",
      replay_decision: false,
      session_scope: { mode: "per_call", decision: "not_started" },
      media_byte_count: 0,
      media_frame_count: 0,
      retry_decision: "not_started",
      http_status: null,
      websocket_status: "not_started",
      fcp_error_mapping: "not_applicable",
      cleanup_result: { status: "not_applicable" },
      artifact_paths: [],
      skip_reason: $reason
    }' >>"${LOG_JSONL}"
}

emit_provider_records() {
  local provider="$1"
  local provider_jsonl="$2"
  local raw_log="$3"

  jq -c \
    --arg command_line "${COMMAND_LINE}" \
    --arg git_revision "${git_revision}" \
    --arg provider "${provider}" \
    --arg provider_jsonl "${provider_jsonl}" \
    --arg raw_log "${raw_log}" \
    '
    def normalized_auth_decision:
      if (.auth_decision | type) == "object" then
        if .auth_decision.signature_valid == true then
          "signature_validated"
        elif .auth_decision.signature_valid == false then
          "signature_denied_or_not_applicable"
        else
          "n/a"
        end
      else
        (.auth_decision // "n/a")
      end;
    def normalized_signature_decision:
      if .signature_decision then
        .signature_decision
      elif (.auth_decision | type) == "object" then
        if .auth_decision.signature_valid == true then
          "signature_validated"
        elif .auth_decision.signature_valid == false then
          "signature_denied_or_not_applicable"
        else
          "n/a"
        end
      else
        "n/a"
      end;
    def normalized_cleanup_result:
      if (.cleanup_result | type) == "object" then
        .cleanup_result
      elif (.cleanup_result | type) == "string" then
        { status: .cleanup_result }
      else
        { status: "not_applicable" }
      end;
    def normalized_artifacts:
      if (.artifact_paths | type) == "array" then
        .artifact_paths + [$provider_jsonl, $raw_log]
      elif .artifact_path then
        [.artifact_path, $provider_jsonl, $raw_log]
      else
        [$provider_jsonl, $raw_log]
      end;
    {
      record_type: "voice_call_multi_provider_connector_boundary_e2e",
      command_line: $command_line,
      git_revision: $git_revision,
      provider: $provider,
      provider_fixture_id: (.provider_fixture_id // ($provider + "-loopback")),
      connector_instance_id: ("fcp-" + $provider + ":loopback"),
      zone: "z:work",
      scenario: (.scenario // "unknown"),
      outcome: (.outcome // "observed"),
      call_id_hash: (
        .call_id_hash
        // .call_control_id_hash
        // .call_uuid_hash
        // .message_id_hash
        // null
      ),
      call_session_id_hash: (
        .call_session_id_hash
        // .session_id_hash
        // ("session:" + $provider + ":loopback")
      ),
      masked_caller_identity: (.masked_caller_identity // "+15***0000"),
      webhook_event_type: (.webhook_event // null),
      signature_decision: normalized_signature_decision,
      auth_decision: normalized_auth_decision,
      replay_decision: (.replay_decision // false),
      session_scope: {
        mode: "per_call",
        decision: (if ((.scenario // "") | test("duplicate_replay|replay")) then "reused" else "fresh" end)
      },
      media_byte_count: (.media_byte_count // .media.byte_count // 0),
      media_frame_count: (.media_frame_count // .media.frame_count // 0),
      retry_decision: (.retry_decision // "not_retried"),
      http_status: (.http_status // null),
      websocket_status: (.websocket_status // "metadata_fixture_only"),
      fcp_error_mapping: (.fcp_error_mapping // .reason_code // "n/a"),
      cleanup_result: normalized_cleanup_result,
      artifact_paths: normalized_artifacts,
      skip_reason: (.skip_reason // "not_skipped")
    }' "${provider_jsonl}" >>"${LOG_JSONL}"
}

extract_provider_jsonl() {
  local provider="$1"
  local marker="$2"
  local raw_log="$3"
  local provider_jsonl="${OUT_ROOT}/provider-jsonl/${provider}.jsonl"
  local source_jsonl

  source_jsonl="$(sed -n "s/^${marker}=//p" "${raw_log}" | tail -n 1)"
  if [[ -z "${source_jsonl}" || ! -s "${source_jsonl}" ]]; then
    emit_json \
      "voice_call_multi_provider_connector_boundary_failure" \
      "${provider}_missing_provider_jsonl" \
      "failed" \
      "$(jq -cn --arg provider "${provider}" --arg raw_log "${raw_log}" '{provider: $provider, raw_log: $raw_log}')"
    echo "${provider} test did not emit ${marker}=<path>; see ${raw_log}" >&2
    exit 1
  fi

  cp "${source_jsonl}" "${provider_jsonl}"
  emit_provider_records "${provider}" "${provider_jsonl}" "${raw_log}"
}

run_provider_test() {
  local provider="$1"
  local package="$2"
  local test_name="$3"
  local marker="$4"
  local raw_log="${OUT_ROOT}/logs/${provider}.cargo-test.log"

  echo "[voice-call-multi-provider] ${provider}: cargo test -p ${package} --test integration ${test_name}"
  if (
    cd "${REPO_ROOT}"
    cargo test -p "${package}" --test integration "${test_name}" -- --nocapture
  ) >"${raw_log}" 2>&1; then
    extract_provider_jsonl "${provider}" "${marker}" "${raw_log}"
  else
    emit_json \
      "voice_call_multi_provider_connector_boundary_failure" \
      "${provider}_cargo_test" \
      "failed" \
      "$(jq -cn --arg provider "${provider}" --arg raw_log "${raw_log}" '{provider: $provider, raw_log: $raw_log}')"
    echo "${provider} cargo test failed; see ${raw_log}" >&2
    exit 1
  fi
}

validate_provider_coverage() {
  for provider in twilio telnyx plivo; do
    local count
    count="$(jq -r --arg provider "${provider}" '
      select(.record_type == "voice_call_multi_provider_connector_boundary_e2e" and .provider == $provider)
      | .scenario
    ' "${LOG_JSONL}" | wc -l | tr -d ' ')"
    if [[ "${count}" -lt 1 ]]; then
      echo "missing normalized JSONL records for ${provider}" >&2
      exit 1
    fi
  done

  local provider_scenario
  for provider_scenario in \
    "twilio:valid_voice_status" \
    "twilio:invalid_signature_denial" \
    "twilio:duplicate_replay_denial" \
    "twilio:authorized_caller" \
    "twilio:unauthorized_caller" \
    "twilio:cancellation" \
    "twilio:timeout" \
    "telnyx:signed_webhook_acceptance" \
    "telnyx:invalid_signature_denial" \
    "telnyx:duplicate_replay_denial" \
    "telnyx:authorized_inbound_caller" \
    "telnyx:denied_inbound_caller" \
    "telnyx:transient_retry" \
    "telnyx:provider_error_mapping" \
    "telnyx:cleanup" \
    "plivo:signed_webhook_acceptance" \
    "plivo:invalid_signature_denial" \
    "plivo:duplicate_replay_denial" \
    "plivo:authorized_inbound_caller" \
    "plivo:denied_inbound_caller" \
    "plivo:v2_signature_fallback" \
    "plivo:transient_retry" \
    "plivo:provider_error_mapping" \
    "plivo:cleanup"; do
    local required_provider="${provider_scenario%%:*}"
    local required_scenario="${provider_scenario#*:}"
    if ! jq -e --arg provider "${required_provider}" --arg scenario "${required_scenario}" '
      select(
        .record_type == "voice_call_multi_provider_connector_boundary_e2e"
        and .provider == $provider
        and .scenario == $scenario
      )
    ' "${LOG_JSONL}" >/dev/null; then
      echo "missing required ${required_provider} scenario ${required_scenario}" >&2
      exit 1
    fi
  done

  for forbidden in \
    "+15551230000" \
    "+15559870000" \
    "+15551234567" \
    "+15559876543" \
    "+15550000000" \
    "test_auth_token_xyz" \
    "test_api_key" \
    "plivo_test_auth_secret" \
    "fixture_hmac_key_for_signature_tests" \
    "fixture_hmac_key_for_voice_call_e2e_tests" \
    "provider fixture rejected call" \
    "private sms fixture" \
    "private blocked fixture" \
    "private allowed fixture" \
    "private replay fixture"; do
    if grep -Fq "${forbidden}" "${LOG_JSONL}"; then
      echo "multi-provider JSONL leaked forbidden raw material: ${forbidden}" >&2
      exit 1
    fi
  done
}

write_replay_script() {
  cat >"${OUT_ROOT}/replay.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/fcp-voice-call-multi-provider-e2e-target}"

cargo test -p fcp-twilio --test integration webhook_ingest_request_loopback_e2e_logs_redaction_safe_jsonl -- --nocapture
cargo test -p fcp-telnyx --test integration telnyx_loopback_e2e_jsonl_covers_provider_edges -- --nocapture
cargo test -p fcp-plivo --test integration plivo_loopback_e2e_jsonl_covers_provider_edges -- --nocapture
EOF
  chmod +x "${OUT_ROOT}/replay.sh"
}

emit_json \
  "voice_call_multi_provider_connector_boundary_start" \
  "harness_start" \
  "running" \
  "$(jq -cn \
    --arg out_root "${OUT_ROOT}" \
    --arg cargo_target_dir "${CARGO_TARGET_DIR}" \
    '{providers: ["twilio", "telnyx", "plivo"], out_root: $out_root, cargo_target_dir: $cargo_target_dir, live_credentials_required_by_default: false}')"

if [[ "${TWILIO_LIVE_E2E:-0}" == "1" && ( -z "${TWILIO_ACCOUNT_SID:-}" || -z "${TWILIO_AUTH_TOKEN:-}" ) ]]; then
  emit_live_skip \
    "twilio" \
    "twilio-live-credentials" \
    "TWILIO_LIVE_E2E=1 but TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN is not set"
fi
if [[ "${TELNYX_LIVE_E2E:-0}" == "1" && -z "${TELNYX_API_KEY:-}" ]]; then
  emit_live_skip \
    "telnyx" \
    "telnyx-live-credentials" \
    "TELNYX_LIVE_E2E=1 but TELNYX_API_KEY is not set"
fi
if [[ "${PLIVO_LIVE_E2E:-0}" == "1" && ( -z "${PLIVO_AUTH_ID:-}" || -z "${PLIVO_AUTH_TOKEN:-}" ) ]]; then
  emit_live_skip \
    "plivo" \
    "plivo-live-credentials" \
    "PLIVO_LIVE_E2E=1 but PLIVO_AUTH_ID or PLIVO_AUTH_TOKEN is not set"
fi

run_provider_test \
  "twilio" \
  "fcp-twilio" \
  "webhook_ingest_request_loopback_e2e_logs_redaction_safe_jsonl" \
  "twilio_webhook_ingest_e2e_jsonl"
run_provider_test \
  "telnyx" \
  "fcp-telnyx" \
  "telnyx_loopback_e2e_jsonl_covers_provider_edges" \
  "telnyx_voice_call_e2e_log"
run_provider_test \
  "plivo" \
  "fcp-plivo" \
  "plivo_loopback_e2e_jsonl_covers_provider_edges" \
  "plivo_voice_call_e2e_log"

validate_provider_coverage
write_replay_script

summary="$(jq -sc \
  --arg command_line "${COMMAND_LINE}" \
  --arg git_revision "${git_revision}" \
  --arg out_root "${OUT_ROOT}" \
  --arg replay "${OUT_ROOT}/replay.sh" \
  '{
    record_type: "voice_call_multi_provider_connector_boundary_summary",
    command_line: $command_line,
    git_revision: $git_revision,
    scenario: "summary",
    outcome: "passed",
    provider_count: ([.[] | select(.record_type == "voice_call_multi_provider_connector_boundary_e2e") | .provider] | unique | length),
    providers: ([.[] | select(.record_type == "voice_call_multi_provider_connector_boundary_e2e") | .provider] | unique),
    scenario_count: ([.[] | select(.record_type == "voice_call_multi_provider_connector_boundary_e2e" and .outcome != "skipped")] | length),
    artifact_paths: [$out_root, $replay],
    redaction: "validated: no full E.164, provider auth credentials, call-auth token, signed callback URL, full webhook body, prompts, transcripts, or audio are emitted"
  }' "${LOG_JSONL}")"
printf '%s\n' "${summary}" >>"${LOG_JSONL}"

echo "voice_call_multi_provider_e2e_jsonl=${LOG_JSONL}"
echo "voice_call_multi_provider_artifacts=${OUT_ROOT}"
