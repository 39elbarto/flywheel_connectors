#!/usr/bin/env bash
set -u -o pipefail

# Bounded, fail-closed acceptance runner for one already-existing archived n8n
# workflow.  This file intentionally delegates transport and cryptography to
# the installed fwc-n8n launcher, approval-once helper, and parent-binding
# helper.  It never prints or stores request bodies, tokens, provider bodies,
# seed material, or secrets in evidence; the required request file is only the
# root-owned transport handoff below the fixed approval root.

umask 077
export LC_ALL=C

readonly SCHEMA="fwc.n8n.unarchive-acceptance.v1"
readonly OPERATION="n8n.workflows.unarchive"
readonly DEFAULT_REQUEST_ROOT="/var/lib/fwc-n8n/approval-requests"
REQUEST_ROOT="$DEFAULT_REQUEST_ROOT"
readonly APPROVAL_TTL_MS=45000
readonly APPROVAL_TIMEOUT_SECONDS=40
readonly DEADLINE_MS=30000
readonly JQ_BIN="/usr/bin/jq"
readonly STAT_BIN="/usr/bin/stat"
readonly UUIDGEN_BIN="/usr/bin/uuidgen"
readonly TIMEOUT_BIN="/usr/bin/timeout"
readonly DEFAULT_LAUNCHER="/usr/local/bin/fwc-n8n"
readonly DEFAULT_APPROVAL_HELPER="/home/ubuntu/Projects/flywheel_connectors/scripts/n8n_approval_once.sh"
# This is the verified provisioned binary.  The similarly named path below
# nqm81-cbor-helper/ is a local legacy diagnostic symlink to /tmp and is not a
# production default.
readonly DEFAULT_PARENT_HELPER="/srv/dev-ssd/fcp/targets/nqm81-cbor-helper-rc20/release/nqm81-cbor-helper"

LAUNCHER_PATH="${FWC_N8N_LAUNCHER:-$DEFAULT_LAUNCHER}"
APPROVAL_HELPER_PATH="${FWC_N8N_APPROVAL_ONCE:-$DEFAULT_APPROVAL_HELPER}"
PARENT_HELPER_PATH="${N8N_PARENT_BINDING_HELPER:-$DEFAULT_PARENT_HELPER}"
EVIDENCE_DIR="${N8N_UNARCHIVE_EVIDENCE_DIR:-}"

SELF_TEST=0
SERVER=""
WORKFLOW_ID=""
RUN_ID=""
RESOURCE_URI=""
REQUEST_BASENAME=""
REQUEST_PATH=""
BASELINE_PROJECTION=""
INVOKE_PROJECTION=""
FINAL_PROJECTION=""
BASELINE_GRAPH_DIGEST=""
BASELINE_STATE_DIGEST=""
BASELINE_VERSION_ID=""
UNARCHIVE_INPUT=""
PARENT_BINDING=""
INVOCATION_STATUS=125
FINAL_GET_STATUS=125

emit_stop() {
  local code="${1:-${LAST_ERROR:-unknown_stop}}"
  printf '{"schema":"%s","verdict":"STOP","abort_code":"%s"}\n' \
    "$SCHEMA" "$code"
}

emit_unknown() {
  local code="${1:-unknown_outcome}"
  printf '{"schema":"%s","verdict":"unknown","abort_code":"%s","server":"%s","workflow_id":"%s"}\n' \
    "$SCHEMA" "$code" "$SERVER" "$WORKFLOW_ID"
}

emit_pass() {
  printf '{"schema":"%s","verdict":"pass","server":"%s","workflow_id":"%s","evidence_directory":%s}\n' \
    "$SCHEMA" "$SERVER" "$WORKFLOW_ID" \
    "$(if [[ -n "$EVIDENCE_DIR" ]]; then "$JQ_BIN" -Rn --arg value "$EVIDENCE_DIR" '$value'; else printf 'null'; fi)"
}

usage() {
  cat <<'EOF'
Usage:
  n8n_unarchive_acceptance.sh --server eec|hetzner --workflow-id ID [options]
  n8n_unarchive_acceptance.sh eec ID [options]
  n8n_unarchive_acceptance.sh --self-test

Options:
  --launcher PATH         fwc-n8n launcher (default: /usr/local/bin/fwc-n8n)
  --approval-helper PATH  n8n_approval_once.sh (default: /home/ubuntu/Projects/flywheel_connectors/scripts/n8n_approval_once.sh)
  --parent-helper PATH    provisioned nqm81 parent-binding executable
  --evidence-dir DIR      redaction-safe evidence directory (optional)
  --help                  show this help

Production writes one short-lived approval request below the fixed
/var/lib/fwc-n8n/approval-requests root.  The request is root:root 0600.
The parent helper is invoked exactly once; no fallback or crypto is embedded.
EOF
}

uuid() {
  local value
  value="$($UUIDGEN_BIN 2>/dev/null | tr '[:upper:]' '[:lower:]')" || return 1
  [[ "$value" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
  printf '%s' "$value"
}

now_ms() {
  local value
  # Keep the known date fix exactly: nanoseconds are truncated to 13 digits.
  value="$(date +%s%N | cut -c1-13)" || return 1
  [[ "$value" =~ ^[0-9]{13}$ ]] || return 1
  printf '%s' "$value"
}

valid_server() {
  [[ "$1" == eec || "$1" == hetzner ]]
}

valid_workflow_id() {
  # The host's canonical resource encoder leaves only ASCII alphanumerics
  # unescaped.  Reject other IDs rather than guessing a URI encoding.
  [[ "$1" =~ ^[A-Za-z0-9]{1,256}$ ]]
}

valid_executable() {
  [[ -n "$1" && -x "$1" ]]
}

valid_parent_helper() {
  [[ -n "$1" && -x "$1" && ! -L "$1" ]]
}

safe_response_projection() {
  # Deliberately select only the closed redaction-safe state projection.  In
  # particular, never carry .result.provider, .result.body, or raw errors.
  "$JQ_BIN" -c '
    def graph:
      if type == "object" then
        {versionId:(.versionId // null), graphDigest:(.graphDigest // null)}
      else null end;
    def state:
      if type == "object" then
        {id:(.id // null), versionId:(.versionId // null),
         active:(if has("active") then .active else null end),
         activeVersionId:(.activeVersionId // null),
         isArchived:(if has("isArchived") then .isArchived else null end),
         stateDigest:(.stateDigest // null), draft:(.draft | graph),
         published:(.published | graph)}
      else null end;
    if (.type == "response") and (.status == "ok")
       and ((.error? // null) == null) and ((.result | type) == "object") then
      {type:.type, id:(.id // null), status:.status, result:{
        status:(.result.status // null), operation:(.result.operation // null),
        provider:(.result.provider // null), readback:(.result.readback // null),
        id:(.result.id // null), versionId:(.result.versionId // null),
        graphDigest:(.result.graphDigest // null),
        stateDigest:(.result.stateDigest // null),
        active:(if (.result | has("active")) then .result.active else null end),
        activeVersionId:(.result.activeVersionId // null),
        isArchived:(if (.result | has("isArchived")) then .result.isArchived else null end),
        draft:(.result.draft | graph), published:(.result.published | graph),
        before:(.result.before | state), after:(.result.after | state)}}
    else
      {type:(.type // null), status:(.status // "unknown"),
       error_code:(.error.code // .code // null)}
    end
  '
}

project_one_response() {
  local raw="$1"
  local projected
  [[ -n "$raw" ]] || return 1
  projected="$(printf '%s\n' "$raw" | "$JQ_BIN" -c -s \
    'if length == 1 then .[0] else error("one response required") end' \
    2>/dev/null)" || return 1
  safe_response_projection <<<"$projected"
}

persist_projection() {
  local name="$1"
  local projection="$2"
  [[ -z "$EVIDENCE_DIR" ]] && return 0
  printf '%s\n' "$projection" >"$EVIDENCE_DIR/$name.json" || return 1
  chmod 600 "$EVIDENCE_DIR/$name.json" || return 1
}

persist_summary() {
  local verdict="$1"
  local code="${2:-null}"
  [[ -z "$EVIDENCE_DIR" ]] && return 0
  "$JQ_BIN" -cn \
    --arg server "$SERVER" --arg workflow_id "$WORKFLOW_ID" \
    --arg verdict "$verdict" --argjson abort_code "$code" \
    --arg evidence_directory "$EVIDENCE_DIR" \
    --arg request_file "$REQUEST_BASENAME" \
    --argjson invocation_status "$INVOCATION_STATUS" \
    --argjson final_get_status "$FINAL_GET_STATUS" \
    '{schema:"fwc.n8n.unarchive-acceptance.v1",server:$server,workflow_id:$workflow_id,
      verdict:$verdict,abort_code:$abort_code,evidence_directory:$evidence_directory,
      sequence:["baseline_get","parent_binding","approval_once","unarchive_once","independent_get"],
      request_file:$request_file,invocation_status:$invocation_status,
      final_get_status:$final_get_status,raw_provider_bodies_persisted:false,
      raw_request_bodies_persisted:false,tokens_persisted:false,seeds_persisted:false}' \
    >"$EVIDENCE_DIR/summary.json" || return 1
  chmod 600 "$EVIDENCE_DIR/summary.json" || return 1
}

init_evidence() {
  [[ -z "$EVIDENCE_DIR" ]] && return 0
  [[ "$EVIDENCE_DIR" == /* ]] || return 1
  mkdir -p -- "$EVIDENCE_DIR" || return 1
  chmod 700 -- "$EVIDENCE_DIR" || return 1
}

validate_digest() {
  [[ "$1" =~ ^blake3-256:[0-9a-f]{64}$ ]]
}

validate_expiry() {
  local expiry="$1"
  local current="$2"
  local maximum
  [[ "$current" =~ ^[0-9]{13}$ && "$expiry" =~ ^[0-9]{13}$ ]] || return 1
  maximum="$((current + 60000))"
  (( expiry > current && expiry <= maximum ))
}

write_request_file() {
  local request_json="$1"
  local request_path="$REQUEST_ROOT/$REQUEST_BASENAME"
  [[ "$REQUEST_BASENAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || return 1
  if (( SELF_TEST == 1 )); then
    printf '%s\n' "$request_json" >"$request_path" || return 1
    chmod 600 -- "$request_path" || return 1
    REQUEST_PATH="$request_path"
    return 0
  fi
  fixed_request_root_is_safe || return 1
  # The fixed root is owned 0700 by root, so basename resolution cannot escape
  # it.  Install/truncate, write, and reassert the exact required metadata.
  sudo -n install -o root -g root -m 600 /dev/null -- "$request_path" || return 1
  printf '%s\n' "$request_json" | sudo -n tee -- "$request_path" >/dev/null || return 1
  sudo -n chown root:root -- "$request_path" || return 1
  sudo -n chmod 600 -- "$request_path" || return 1
  REQUEST_PATH="$request_path"
}

read_request_metadata() {
  local path="$1"
  local metadata
  metadata="$($STAT_BIN -c '%u:%g:%a:%h:%F:%s' -- "$path" 2>/dev/null)" || return 1
  if (( SELF_TEST == 1 )); then
    [[ "$metadata" =~ ^[0-9]+:[0-9]+:600:1:regular\ file:[0-9]+$ ]]
  else
    [[ "$metadata" =~ ^0:0:600:1:regular\ file:[0-9]+$ ]]
  fi
}

fixed_request_root_is_safe() {
  [[ "$($STAT_BIN -c '%u:%g:%a:%F' -- "$REQUEST_ROOT" 2>/dev/null)" == "0:0:700:directory" ]]
}

run_read_once() {
  local input_json="$1"
  local raw
  local status
  local projection_status
  raw="$(printf '%s\n' "$input_json" | "$JQ_BIN" -cn \
    --arg server "$SERVER" --argjson input "$input_json" --arg correlation "$(uuid)" \
    '{server_id:$server,input:$input,correlation_id:$correlation}' |
    "$LAUNCHER_PATH" run-once n8n.workflows.get 2>/dev/null)"
  status=$?
  if [[ -z "$raw" ]]; then
    printf '%s' ""
    return "$status"
  fi
  project_one_response "$raw"
  projection_status=$?
  (( projection_status == 0 )) || return 1
  return "$status"
}

approval_fd3_handoff() {
  local basename="$1"
  local reader_fd
  local writer_fd
  local reader_pid
  local helper_status
  local reader_status
  local invoke_fd
  local invoke_pid
  local invoke_status
  local output_status
  local invoke_output

  # Start the reader and writer together in this one bounded function.  No
  # FIFO, polling, or long-lived approval request is used.  The helper is
  # bounded below its 45-second request TTL.  sudo-rs closes inherited FD3, so
  # root bash maps the helper's FD3 to stdout and this parent maps stdout back
  # to the already-open FD3 pipe.
  coproc FWC_APPROVAL_READER { cat; }
  reader_fd="${FWC_APPROVAL_READER[0]}"
  writer_fd="${FWC_APPROVAL_READER[1]}"
  reader_pid="$FWC_APPROVAL_READER_PID"
  exec 3>&"$writer_fd"
  exec {writer_fd}>&-

  if sudo -n /usr/bin/bash -c '
      exec 3>&1
      exec "$1" --signal=TERM --kill-after=2s "$2" "$3" \
        --request-file "$4" 2>/dev/null
    ' _ "$TIMEOUT_BIN" "${APPROVAL_TIMEOUT_SECONDS}s" \
    "$APPROVAL_HELPER_PATH" "$basename" 1>&3 2>/dev/null; then
    helper_status=0
  else
    helper_status=$?
  fi
  exec 3>&-

  if (( helper_status != 0 )); then
    cat <&"$reader_fd" >/dev/null 2>/dev/null || true
    if wait "$reader_pid"; then
      reader_status=0
    else
      reader_status=$?
    fi
    exec {reader_fd}<&-
    (( reader_status == 0 )) || return 1
    return 1
  fi

  # The token travels from FD3 -> cat -> jq stdin -> exactly one launcher
  # invocation.  It never enters a shell variable, argv, file, or evidence.
  coproc FWC_UNARCHIVE_INVOKE {
    run_unarchive_once "$reader_fd";
  }
  invoke_fd="${FWC_UNARCHIVE_INVOKE[0]}"
  invoke_pid="$FWC_UNARCHIVE_INVOKE_PID"
  exec {reader_fd}<&-

  invoke_output="$(cat <&"$invoke_fd")"
  output_status=$?
  if wait "$invoke_pid"; then
    invoke_status=0
  else
    invoke_status=$?
  fi
  exec {invoke_fd}<&-
  if wait "$reader_pid"; then
    reader_status=0
  else
    reader_status=$?
  fi
  (( output_status == 0 && reader_status == 0 )) || invoke_status=125
  INVOCATION_STATUS="$invoke_status"
  if [[ -z "$invoke_output" ]]; then
    INVOKE_PROJECTION='{"type":null,"status":"unknown","error_code":"empty_response"}'
  else
    INVOKE_PROJECTION="$(project_one_response "$invoke_output" 2>/dev/null)" ||
      INVOKE_PROJECTION='{"type":null,"status":"unknown","error_code":"invalid_response"}'
  fi
}

run_unarchive_once() {
  local approval_reader_fd="$1"
  "$JQ_BIN" -cn --slurpfile approval /dev/stdin \
      --arg server "$SERVER" --argjson input "$UNARCHIVE_INPUT" \
      --arg correlation "$(uuid)" --argjson deadline "$DEADLINE_MS" \
      '{server_id:$server,input:$input,approval_token:$approval[0],
        deadline_ms:$deadline,correlation_id:$correlation}' <&"$approval_reader_fd" |
    "$LAUNCHER_PATH" run-once "$OPERATION" 2>/dev/null
}

bounded_approval_and_invoke() {
  # The request TTL and host deadline bound this whole section.  The helper's
  # FD3 reader/writer lifetime is nested inside the same one-shot function.
  approval_fd3_handoff "$REQUEST_BASENAME"
}

validate_baseline() {
  local projection="$1"
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" '
    .status == "ok" and .result.id == $workflow
    and .result.active == false and .result.activeVersionId == null
    and .result.isArchived == true and .result.published == null
    and (.result.versionId | type) == "string" and (.result.versionId | length) > 0
    and (.result.draft.versionId | type) == "string"
    and (.result.draft.graphDigest | type) == "string"
    and (.result.stateDigest | type) == "string"
  ' <<<"$projection" >/dev/null 2>&1
}

validate_final() {
  local projection="$1"
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" --arg graph "$BASELINE_GRAPH_DIGEST" '
    .status == "ok" and .result.id == $workflow
    and .result.active == false and .result.activeVersionId == null
    and .result.isArchived == false and .result.published == null
    and (.result.draft.graphDigest | type) == "string"
    and .result.draft.graphDigest == $graph
  ' <<<"$projection" >/dev/null 2>&1
}

run_self_test() {
  local root
  local request_json
  local request_read
  local current=1700000000000
  local valid=$((current + 1000))
  local stale=$((current - 1))
  local over=$((current + 60001))
  local reader_fd
  local writer_fd
  local reader_pid
  local handed_off
  local callback_status

  SELF_TEST=1
  root="$(mktemp -d "${TMPDIR:-/tmp}/n8n-unarchive-self-test.XXXXXX")" || return 1
  REQUEST_ROOT="$root/approval-requests"
  mkdir -m 700 -- "$REQUEST_ROOT" || return 1
  REQUEST_BASENAME="self-test.json"
  request_json='{"schema":"test","expires_at_ms":1700000001000}'
  write_request_file "$request_json" || return 1
  read_request_metadata "$REQUEST_PATH" || return 1
  request_read="$(cat -- "$REQUEST_PATH")" || return 1
  [[ "$request_read" == "$request_json" ]] || return 1
  validate_expiry "$valid" "$current" || return 1
  if validate_expiry "$stale" "$current"; then return 1; fi
  if validate_expiry "$over" "$current"; then return 1; fi
  if validate_expiry 1700000000 "$current"; then return 1; fi

  # Safe marker only: this proves FD3 pipe delivery, EOF after close, and
  # preservation of a non-zero callback status without invoking approval.
  coproc FWC_SELFTEST_READER { cat; }
  reader_fd="${FWC_SELFTEST_READER[0]}"
  writer_fd="${FWC_SELFTEST_READER[1]}"
  reader_pid="$FWC_SELFTEST_READER_PID"
  exec 3>&"$writer_fd"
  exec {writer_fd}>&-
  printf '%s\n' fd3-safe-marker >&3
  exec 3>&-
  handed_off="$(cat <&"$reader_fd")" || return 1
  if wait "$reader_pid"; then :; else return 1; fi
  exec {reader_fd}<&-
  [[ "$handed_off" == fd3-safe-marker ]] || return 1

  coproc FWC_SELFTEST_READER { cat; }
  reader_fd="${FWC_SELFTEST_READER[0]}"
  writer_fd="${FWC_SELFTEST_READER[1]}"
  reader_pid="$FWC_SELFTEST_READER_PID"
  exec 3>&"$writer_fd"
  exec {writer_fd}>&-
  if { printf '%s\n' fd3-status-marker >&3; false; }; then
    callback_status=0
  else
    callback_status=$?
  fi
  exec 3>&-
  handed_off="$(cat <&"$reader_fd")" || return 1
  if wait "$reader_pid"; then :; else return 1; fi
  exec {reader_fd}<&-
  [[ "$handed_off" == fd3-status-marker && "$callback_status" -eq 1 ]] || return 1

  printf '{"schema":"%s","verdict":"pass","mode":"self-test","acceptance":false,"cases":4}\n' "$SCHEMA"
}

parse_args() {
  local positional=()
  while (( $# > 0 )); do
    case "$1" in
      --server)
        (( $# >= 2 )) || return 1
        SERVER="$2"
        shift 2
        ;;
      --workflow-id)
        (( $# >= 2 )) || return 1
        WORKFLOW_ID="$2"
        shift 2
        ;;
      --launcher)
        (( $# >= 2 )) || return 1
        LAUNCHER_PATH="$2"
        shift 2
        ;;
      --approval-helper)
        (( $# >= 2 )) || return 1
        APPROVAL_HELPER_PATH="$2"
        shift 2
        ;;
      --parent-helper)
        (( $# >= 2 )) || return 1
        PARENT_HELPER_PATH="$2"
        shift 2
        ;;
      --evidence-dir)
        (( $# >= 2 )) || return 1
        EVIDENCE_DIR="$2"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      --*)
        return 1
        ;;
      *)
        positional+=("$1")
        shift
        ;;
    esac
  done
  [[ -n "$SERVER" ]] || [[ "${#positional[@]}" -ge 1 ]] || return 1
  [[ -n "$WORKFLOW_ID" ]] || [[ "${#positional[@]}" -ge 2 ]] || return 1
  [[ -n "$SERVER" ]] || SERVER="${positional[0]}"
  [[ -n "$WORKFLOW_ID" ]] || WORKFLOW_ID="${positional[1]}"
  [[ "${#positional[@]}" -le 2 ]] || return 1
  valid_server "$SERVER" && valid_workflow_id "$WORKFLOW_ID"
}

main() {
  local current_ms
  local expiry_ms
  local correlation_id
  local approval_ref
  local raw_baseline
  local raw_final
  local baseline_input
  local baseline_status
  local request_json

  if [[ "${1:-}" == --self-test && "$#" -eq 1 ]]; then
    run_self_test || {
      printf '{"schema":"%s","verdict":"STOP","abort_code":"self_test_failed"}\n' "$SCHEMA"
      return 1
    }
    return 0
  fi
  if ! parse_args "$@"; then
    usage >&2
    emit_stop invalid_arguments
    return 10
  fi
  if [[ ! -x "$JQ_BIN" || ! -x "$STAT_BIN" || ! -x "$UUIDGEN_BIN" || ! -x "$TIMEOUT_BIN" ]]; then
    emit_stop dependency_missing
    return 10
  fi
  if ! valid_executable "$LAUNCHER_PATH"; then
    emit_stop launcher_unavailable
    return 10
  fi
  if ! valid_executable "$APPROVAL_HELPER_PATH"; then
    emit_stop approval_helper_unavailable
    return 10
  fi
  if ! valid_parent_helper "$PARENT_HELPER_PATH"; then
    emit_stop parent_helper_unavailable
    return 10
  fi
  if ! init_evidence; then
    emit_stop evidence_directory_unavailable
    return 10
  fi

  RUN_ID="$(uuid)" || { emit_stop uuid_failed; return 10; }
  RESOURCE_URI="fwc-n8n://$SERVER/workflows/$WORKFLOW_ID"

  # Exactly one fresh baseline GET.  Its raw response remains in memory only.
  baseline_input="$("$JQ_BIN" -cn --arg id "$WORKFLOW_ID" '{id:$id}')" || {
    emit_stop baseline_input_failed
    return 10
  }
  raw_baseline="$(run_read_once "$baseline_input")"
  baseline_status=$?
  if (( baseline_status != 0 )); then
    emit_stop baseline_get_failed
    return 10
  fi
  BASELINE_PROJECTION="$raw_baseline"
  if ! validate_baseline "$BASELINE_PROJECTION"; then
    persist_projection baseline "$BASELINE_PROJECTION" || true
    emit_stop baseline_contract_mismatch
    return 10
  fi
  BASELINE_GRAPH_DIGEST="$("$JQ_BIN" -er '.result.draft.graphDigest' <<<"$BASELINE_PROJECTION")" || {
    emit_stop baseline_graph_digest_missing
    return 10
  }
  BASELINE_STATE_DIGEST="$("$JQ_BIN" -er '.result.stateDigest' <<<"$BASELINE_PROJECTION")" || {
    emit_stop baseline_state_digest_missing
    return 10
  }
  BASELINE_VERSION_ID="$("$JQ_BIN" -er '.result.versionId' <<<"$BASELINE_PROJECTION")" || {
    emit_stop baseline_version_missing
    return 10
  }
  validate_digest "$BASELINE_GRAPH_DIGEST" || { emit_stop baseline_graph_digest_invalid; return 10; }
  validate_digest "$BASELINE_STATE_DIGEST" || { emit_stop baseline_state_digest_invalid; return 10; }
  persist_projection baseline "$BASELINE_PROJECTION" || { emit_stop evidence_write_failed; return 10; }

  correlation_id="$RUN_ID"
  approval_ref="nqm81.23-$SERVER-unarchive-$RUN_ID"
  UNARCHIVE_INPUT="$("$JQ_BIN" -cn \
    --arg id "$WORKFLOW_ID" --arg approval_ref "$approval_ref" \
    --arg correlation "$correlation_id" --arg version "$BASELINE_VERSION_ID" \
    --arg state "$BASELINE_STATE_DIGEST" \
    '{id:$id,guard:{approvalRef:$approval_ref,idempotencyKey:$correlation,
      precondition:{versionId:$version,activeVersionId:null,active:false,
        isArchived:true,stateDigest:$state}}}')" || {
    emit_stop unarchive_input_failed
    return 10
  }

  # The canonical helper owns the binding/crypto.  Do not replace it with a
  # shell digest or silently fall back to a diagnostic / /tmp path.
  PARENT_BINDING="$("$PARENT_HELPER_PATH" "$SERVER" "$RESOURCE_URI" "$OPERATION" "$UNARCHIVE_INPUT" 2>/dev/null)" || {
    emit_stop parent_binding_failed
    return 10
  }
  [[ "$PARENT_BINDING" =~ ^[0-9a-f]{64}$ ]] || { emit_stop parent_binding_invalid; return 10; }

  current_ms="$(now_ms)" || { emit_stop clock_failed; return 10; }
  expiry_ms="$((current_ms + APPROVAL_TTL_MS))"
  validate_expiry "$expiry_ms" "$current_ms" || { emit_stop expiry_invalid; return 10; }
  REQUEST_BASENAME="nqm81.23-unarchive-$SERVER-$RUN_ID.json"
  request_json="$("$JQ_BIN" -cn \
    --arg server "$SERVER" --arg workflow_id "$WORKFLOW_ID" \
    --arg operation "$OPERATION" --argjson input "$UNARCHIVE_INPUT" \
    --arg parent "$PARENT_BINDING" --argjson expiry "$expiry_ms" \
    '{schema:"fwc.n8n.owner-approval-request.v1",server:$server,
      workflow_id:$workflow_id,operation:$operation,input:$input,
      official_mcp_tool:"",official_mcp_resource_uri:"",
      official_mcp_payload_digest:"",parent_binding_sha256:$parent,
      expires_at_ms:$expiry}')" || {
    emit_stop approval_request_build_failed
    return 10
  }

  # Request creation is immediately adjacent to the one bounded approval +
  # invoke section.  There is no polling, replay, or second approval.
  write_request_file "$request_json" || { emit_stop approval_request_write_failed; return 10; }
  read_request_metadata "$REQUEST_PATH" || { emit_stop approval_request_metadata_failed; return 10; }
  bounded_approval_and_invoke || {
    emit_stop approval_failed
    return 10
  }
  persist_projection invoke "$INVOKE_PROJECTION" || { emit_stop evidence_write_failed; return 10; }

  # Exactly one independent GET after the one unarchive attempt, including an
  # invocation error/timeout.  Its readback is the lifecycle authority.
  raw_final="$(run_read_once "$baseline_input")"
  FINAL_GET_STATUS=$?
  if [[ -z "$raw_final" ]]; then
    FINAL_PROJECTION='{"type":null,"status":"unknown","error_code":"empty_response"}'
  else
    FINAL_PROJECTION="$(project_one_response "$raw_final" 2>/dev/null)" ||
      FINAL_PROJECTION='{"type":null,"status":"unknown","error_code":"invalid_response"}'
  fi
  persist_projection final "$FINAL_PROJECTION" || { emit_stop evidence_write_failed; return 10; }
  if (( FINAL_GET_STATUS == 0 )) && validate_final "$FINAL_PROJECTION"; then
    persist_summary pass null || { emit_stop evidence_write_failed; return 10; }
    emit_pass
    return 0
  fi
  if (( FINAL_GET_STATUS != 0 )); then
    persist_summary unknown '"unknown_outcome"' || true
    emit_unknown unknown_outcome
    return 20
  fi
  persist_summary unknown '"readback_mismatch"' || true
  emit_unknown readback_mismatch
  return 20
}

main "$@"
