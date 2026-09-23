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
readonly ACTIVATION_SCHEMA="fwc.n8n.activation-acceptance.v1"
readonly ACTIVATION_CREATE_OPERATION="n8n.workflows.create_draft"
readonly ACTIVATION_OPERATION="n8n.workflows.activate"
# The FCP launcher/parent-binding operation and the owner-approval request
# intentionally use different wire names.  The production issuer deserializes
# this field as N8nLifecycleOperation::Unarchive (snake_case: "unarchive").
readonly APPROVAL_OPERATION="unarchive"
readonly DEFAULT_REQUEST_ROOT="/var/lib/fwc-n8n/approval-requests"
REQUEST_ROOT="$DEFAULT_REQUEST_ROOT"
readonly APPROVAL_TTL_MS=45000
readonly APPROVAL_TIMEOUT_SECONDS=40
readonly DEADLINE_MS=30000
readonly JQ_BIN="/usr/bin/jq"
readonly AWK_BIN="/usr/bin/awk"
readonly STAT_BIN="/usr/bin/stat"
readonly UUIDGEN_BIN="/usr/bin/uuidgen"
readonly TIMEOUT_BIN="/usr/bin/timeout"
readonly SYNC_BIN="/usr/bin/sync"
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
ACTIVATION_MODE=0
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
INVOKE_CORRELATION_ID=""
INVOCATION_STATUS=125
FINAL_GET_STATUS=125
APPROVAL_HELPER_STATUS=125
APPROVAL_READER_STATUS=125
HANDOFF_TEST_SUDO=""
HANDOFF_OPERATION=""
HANDOFF_INPUT=""
HANDOFF_CORRELATION_ID=""
HANDOFF_DEADLINE_MS="$DEADLINE_MS"

ACTIVATION_PLAN=""
ACTIVATION_CREATE_INPUT=""
ACTIVATION_BASELINE_INPUT=""
ACTIVATION_PUBLISH_INPUT=""
ACTIVATION_UNPUBLISH_INPUT=""
ACTIVATION_CREATE_PROJECTION=""
ACTIVATION_BASELINE_PROJECTION=""
ACTIVATION_PUBLISH_PROJECTION=""
ACTIVATION_ACTIVE_PROJECTION=""
ACTIVATION_UNPUBLISH_PROJECTION=""
ACTIVATION_WORKFLOW_ID=""
ACTIVATION_GRAPH_DIGEST=""
ACTIVATION_STATE_DIGEST=""
ACTIVATION_VERSION_ID=""
ACTIVATION_ACTIVE_VERSION_ID=""
ACTIVATION_CREATE_IDEMPOTENCY=""
ACTIVATION_PUBLISH_IDEMPOTENCY=""
ACTIVATION_UNPUBLISH_IDEMPOTENCY=""
ACTIVATION_CREATE_APPROVAL=""
ACTIVATION_PUBLISH_APPROVAL=""
ACTIVATION_UNPUBLISH_APPROVAL=""
ACTIVATION_CREATE_STATUS=125
ACTIVATION_BASELINE_STATUS=125
ACTIVATION_ACTIVE_STATUS=125
ACTIVATION_PUBLISH_STATUS=125
ACTIVATION_UNPUBLISH_STATUS=125

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

emit_activation_stop() {
  local code="${1:-unknown_stop}"
  printf '{"schema":"%s","verdict":"STOP","abort_code":"%s","server":"%s"}\n' \
    "$ACTIVATION_SCHEMA" "$code" "$SERVER"
}

emit_activation_unknown() {
  local code="${1:-unknown_outcome}"
  printf '{"schema":"%s","verdict":"unknown","abort_code":"%s","server":"%s","workflow_id":"%s"}\n' \
    "$ACTIVATION_SCHEMA" "$code" "$SERVER" "$ACTIVATION_WORKFLOW_ID"
}

emit_activation_pass() {
  validate_activation_evidence_bundle || {
    emit_activation_stop evidence_validation_failed
    return 10
  }
  printf '{"schema":"%s","verdict":"pass","server":"%s","workflow_id":"%s","evidence_directory":%s}\n' \
    "$ACTIVATION_SCHEMA" "$SERVER" "$ACTIVATION_WORKFLOW_ID" \
    "$(if [[ -n "$EVIDENCE_DIR" ]]; then "$JQ_BIN" -Rn --arg value "$EVIDENCE_DIR" '$value'; else printf 'null'; fi)"
}

usage() {
  cat <<'EOF'
Usage:
  n8n_unarchive_acceptance.sh --server eec|hetzner --workflow-id ID [options]
  n8n_unarchive_acceptance.sh eec ID [options]
  n8n_unarchive_acceptance.sh --activation --server eec|hetzner [options]
  n8n_unarchive_acceptance.sh --self-test
  n8n_unarchive_acceptance.sh --handoff-self-test
  n8n_unarchive_acceptance.sh --activation-self-test
  n8n_unarchive_acceptance.sh --activation-create-input-self-test

Options:
  --launcher PATH         fwc-n8n launcher (default: /usr/local/bin/fwc-n8n)
  --approval-helper PATH  n8n_approval_once.sh (default: /home/ubuntu/Projects/flywheel_connectors/scripts/n8n_approval_once.sh)
  --parent-helper PATH    verified rc20 parent-binding path (exact path required)
  --evidence-dir DIR      redaction-safe evidence directory (optional)
  --help                  show this help

Production writes one short-lived approval request below the fixed
/var/lib/fwc-n8n/approval-requests root.  The request is root:root 0600.
The parent helper is invoked exactly once; no fallback or crypto is embedded.
Activation mode creates one disposable credential-free Webhook draft, then
performs one publish and one unpublish transition with independent readbacks;
it never invokes the Webhook or performs cleanup.
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
  # The parent-binding contract is provided only by the provisioned rc20
  # binary.  Do not allow an arbitrary executable override, even when it is
  # a regular non-symlink file; the guard must fail before any provider call.
  [[ "$1" == "$DEFAULT_PARENT_HELPER" && -x "$1" && ! -L "$1" ]]
}

build_activation_plan() {
  "$JQ_BIN" -cn \
    --arg server "$SERVER" \
    '{schema:"fwc.n8n.activation-acceptance-plan.v1",server:$server,
      server_order:["eec","hetzner"],
      sequence:["create_draft_once","draft_readback_once","publish_once",
        "publish_readback_once","active_readback_once","unpublish_once",
        "unpublish_readback_once"],
      draft:{node_type:"n8n-nodes-base.webhook",node_count:1,
        credentials_allowed:false,available_in_mcp:false,webhook_invoked:false},
      transitions:{publish_route:"POST /api/v1/workflows/{id}/publish",
        unpublish_route:"POST /api/v1/workflows/{id}/unpublish",
        publish_body:"versionId",unpublish_body:"empty",
        independent_readback:true},
      limits:{create_attempts:1,publish_attempts:1,unpublish_attempts:1,
        retries:0,automatic_cleanup:false,execution_attempts:0},
      invocation:{launcher_mode:"run-once",generic_rest_runner:false,
        provider_action_in_self_test:false},
      evidence:{raw_provider_bodies:false,raw_request_bodies:false,
        tokens:false,secrets:false}}'
}

build_activation_create_input() {
  local name="$1"
  local path="$2"
  local idempotency="$3"
  local approval_ref="$4"

  "$JQ_BIN" -cn \
    --arg name "$name" --arg path "$path" \
    --arg idempotency "$idempotency" --arg approval_ref "$approval_ref" \
    '{name:$name,graph:{nodes:[{parameters:{path:$path,httpMethod:"POST",
      responseMode:"lastNode"},type:"n8n-nodes-base.webhook",typeVersion:2.1,
      position:[0,0],id:"fwc-activation-webhook"}],connections:{},
      settings:{availableInMCP:false}},
      guard:{approvalRef:$approval_ref,idempotencyKey:$idempotency,
        precondition:{}}}'
}

validate_activation_create_input() {
  local input="$1"
  "$JQ_BIN" -e '
    ((keys_unsorted | sort) == ["graph","guard","name"])
    and (.name | type) == "string" and (.name | length) > 0
    and ((.graph | keys_unsorted | sort) == ["connections","nodes","settings"])
    and (.graph.nodes | type) == "array" and (.graph.nodes | length) == 1
    and (.graph.connections | type) == "object"
    and .graph.settings == {availableInMCP:false}
    and ((.guard | keys_unsorted | sort) ==
      ["approvalRef","idempotencyKey","precondition"])
    and (.guard.approvalRef | type) == "string"
    and (.guard.idempotencyKey |
      test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
    and .guard.precondition == {}
  ' <<<"$input" >/dev/null 2>&1
}

validate_activation_plan() {
  local plan="$1"
  "$JQ_BIN" -e --arg server "$SERVER" '
    ((keys_unsorted | sort) ==
      ["draft","evidence","invocation","limits","schema","sequence",
       "server","server_order","transitions"])
    and .schema == "fwc.n8n.activation-acceptance-plan.v1"
    and .server == $server
    and .server_order == ["eec","hetzner"]
    and .sequence == ["create_draft_once","draft_readback_once","publish_once",
      "publish_readback_once","active_readback_once","unpublish_once",
      "unpublish_readback_once"]
    and .draft.node_type == "n8n-nodes-base.webhook"
    and .draft.node_count == 1
    and .draft.credentials_allowed == false
    and .draft.available_in_mcp == false
    and .draft.webhook_invoked == false
    and .transitions.publish_route == "POST /api/v1/workflows/{id}/publish"
    and .transitions.unpublish_route == "POST /api/v1/workflows/{id}/unpublish"
    and .transitions.publish_body == "versionId"
    and .transitions.unpublish_body == "empty"
    and .transitions.independent_readback == true
    and .limits.create_attempts == 1
    and .limits.publish_attempts == 1
    and .limits.unpublish_attempts == 1
    and .limits.retries == 0
    and .limits.automatic_cleanup == false
    and .limits.execution_attempts == 0
    and .invocation.launcher_mode == "run-once"
    and .invocation.generic_rest_runner == false
    and .invocation.provider_action_in_self_test == false
    and (all(.evidence[]; . == false))
  ' <<<"$plan" >/dev/null 2>&1
}

activation_preflight() {
  if ! valid_server "$SERVER"; then
    emit_activation_stop invalid_server
    return 1
  fi
  if ! [[ "$SERVER" == "eec" || "$SERVER" == "hetzner" ]]; then
    emit_activation_stop activation_server_not_allowed
    return 1
  fi
  if [[ ! -x "$JQ_BIN" || ! -x "$AWK_BIN" || ! -x "$STAT_BIN" || ! -x "$UUIDGEN_BIN" || ! -x "$TIMEOUT_BIN" || ! -x "$SYNC_BIN" ]]; then
    emit_activation_stop dependency_missing
    return 1
  fi
  if ! valid_executable "$LAUNCHER_PATH"; then
    emit_activation_stop launcher_unavailable
    return 1
  fi
  if ! valid_executable "$APPROVAL_HELPER_PATH"; then
    emit_activation_stop approval_helper_unavailable
    return 1
  fi
  if ! valid_parent_helper "$PARENT_HELPER_PATH"; then
    emit_activation_stop parent_helper_unavailable
    return 1
  fi
  if ! init_evidence; then
    emit_activation_stop evidence_directory_unavailable
    return 1
  fi
  ACTIVATION_PLAN="$(build_activation_plan)" || {
    emit_activation_stop activation_plan_build_failed
    return 1
  }
  if ! validate_activation_plan "$ACTIVATION_PLAN"; then
    emit_activation_stop activation_plan_contract_failed
    return 1
  fi
  if ! persist_activation_plan; then
    emit_activation_stop evidence_write_failed
    return 1
  fi
}

run_activation_self_test() {
  local base
  local fixture
  local create_input
  local root
  local output
  local diagnostics
  SELF_TEST=1
  ACTIVATION_MODE=1
  SERVER="hetzner"
  base="$(build_activation_plan)" || return 1
  validate_activation_plan "$base" || return 1
  create_input="$(build_activation_create_input \
    "fwc activation self-test" "fwc-activation-self-test" \
    "00000000-0000-4000-8000-000000000001" \
    "n8n-activation-self-test")" || return 1
  validate_activation_create_input "$create_input" || return 1
  diagnostics="$(printf '%s\n' \
    'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network' \
    'FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_5xx' \
    'FCP-N8N-HOST-ERROR-DETAIL/v1 bearer-secret-marker' \
    'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network token=PRIVATE-CANARY' \
    'raw provider response must not pass' | filter_n8n_run_once_diagnostics)" || return 1
  [[ "$diagnostics" == $'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network\nFCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_5xx' ]] || return 1
  ACTIVATION_PLAN="$base"
  EVIDENCE_DIR=""
  if persist_activation_plan; then return 1; fi
  root="$(mktemp -d "${TMPDIR:-/tmp}/n8n-activation-evidence-self-test.XXXXXX")" || return 1
  EVIDENCE_DIR="$root/evidence"
  init_evidence || return 1
  persist_activation_plan || return 1
  validate_activation_record_file activation-plan || return 1
  validate_activation_plan "$(read_activation_record activation-plan)" || return 1
  if output="$(emit_activation_pass 2>/dev/null)"; then return 1; fi
  [[ "$output" == *'"verdict":"STOP"'* ]] || return 1
  EVIDENCE_DIR="$root/write-failure"
  printf '%s\n' evidence-target-is-not-a-directory >"$EVIDENCE_DIR" || return 1
  if persist_activation_plan 2>/dev/null; then return 1; fi
  fixture="$("$JQ_BIN" -c '.limits.publish_attempts = 2' <<<"$base")" || return 1
  if validate_activation_plan "$fixture"; then return 1; fi
  fixture="$("$JQ_BIN" -c '.draft.credentials_allowed = true' <<<"$base")" || return 1
  if validate_activation_plan "$fixture"; then return 1; fi
  fixture="$("$JQ_BIN" -c '.sequence[5] = "publish_once"' <<<"$base")" || return 1
  if validate_activation_plan "$fixture"; then return 1; fi
  printf '{"schema":"%s","verdict":"pass","mode":"activation-self-test","acceptance":false,"provider_actions":0,"cases":10}\n' \
    "$ACTIVATION_SCHEMA"
}

run_activation_create_input_self_test() {
  local create_input
  SELF_TEST=1
  ACTIVATION_MODE=1
  SERVER="eec"
  create_input="$(build_activation_create_input \
    "fwc activation input self-test" "fwc-activation-input-self-test" \
    "00000000-0000-4000-8000-000000000001" \
    "n8n-activation-input-self-test")" || return 1
  validate_activation_create_input "$create_input" || return 1
  printf '%s\n' "$create_input"
}

safe_response_projection() {
  # Deliberately select only the closed redaction-safe state/status projection.
  # In particular, never carry provider or readback payloads.
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
      {type:.type, status:.status, result:{
        status:(.result.status // null), operation:(.result.operation // null),
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
  if (( ACTIVATION_MODE == 1 )); then
    persist_activation_record "$name" "$projection"
    return $?
  fi
  [[ -z "$EVIDENCE_DIR" ]] && return 0
  printf '%s\n' "$projection" >"$EVIDENCE_DIR/$name.json" || return 1
  chmod 600 "$EVIDENCE_DIR/$name.json" || return 1
}

persist_activation_record() {
  local name="$1"
  local record="$2"
  local path
  local persisted
  local metadata

  (( ACTIVATION_MODE == 1 )) || return 1
  [[ -n "$EVIDENCE_DIR" ]] || return 1
  [[ "$name" =~ ^[a-z0-9-]+$ ]] || return 1
  [[ -n "$record" ]] || return 1
  "$JQ_BIN" -e . <<<"$record" >/dev/null 2>&1 || return 1
  path="$EVIDENCE_DIR/$name.json"
  printf '%s\n' "$record" >"$path" || return 1
  chmod 600 -- "$path" || return 1
  "$SYNC_BIN" -d "$path" "$EVIDENCE_DIR" >/dev/null 2>&1 || return 1
  metadata="$($STAT_BIN -c '%u:%g:%a:%h:%F:%s' -- "$path" 2>/dev/null)" || return 1
  [[ "$metadata" =~ ^[0-9]+:[0-9]+:600:1:regular\ file:[1-9][0-9]*$ ]] || return 1
  persisted="$(cat -- "$path")" || return 1
  [[ "$persisted" == "$record" ]] || return 1
  "$JQ_BIN" -e . <<<"$persisted" >/dev/null 2>&1 || return 1
}

read_activation_record() {
  local name="$1"
  (( ACTIVATION_MODE == 1 )) || return 1
  [[ -n "$EVIDENCE_DIR" ]] || return 1
  [[ "$name" =~ ^[a-z0-9-]+$ ]] || return 1
  cat -- "$EVIDENCE_DIR/$name.json"
}

validate_activation_record_file() {
  local name="$1"
  local path
  local metadata
  local record

  path="$EVIDENCE_DIR/$name.json"
  metadata="$($STAT_BIN -c '%u:%g:%a:%h:%F:%s' -- "$path" 2>/dev/null)" || return 1
  [[ "$metadata" =~ ^[0-9]+:[0-9]+:600:1:regular\ file:[1-9][0-9]*$ ]] || return 1
  record="$(read_activation_record "$name")" || return 1
  "$JQ_BIN" -e . <<<"$record" >/dev/null 2>&1
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
    --arg invoke_correlation_id "$INVOKE_CORRELATION_ID" \
    --argjson approval_helper_status "$APPROVAL_HELPER_STATUS" \
    --argjson approval_reader_status "$APPROVAL_READER_STATUS" \
    --argjson invocation_status "$INVOCATION_STATUS" \
    --argjson final_get_status "$FINAL_GET_STATUS" \
    '{schema:"fwc.n8n.unarchive-acceptance.v1",server:$server,workflow_id:$workflow_id,
      verdict:$verdict,abort_code:$abort_code,evidence_directory:$evidence_directory,
      sequence:["baseline_get","parent_binding","approval_once","unarchive_once","independent_get"],
      request_file:$request_file,invoke_correlation_id:$invoke_correlation_id,
      approval_helper_status:$approval_helper_status,approval_reader_status:$approval_reader_status,
      invocation_status:$invocation_status,
      final_get_status:$final_get_status,raw_provider_bodies_persisted:false,
      raw_request_bodies_persisted:false,tokens_persisted:false,seeds_persisted:false}' \
    >"$EVIDENCE_DIR/summary.json" || return 1
  chmod 600 "$EVIDENCE_DIR/summary.json" || return 1
}

init_evidence() {
  if (( ACTIVATION_MODE == 1 )); then
    [[ -n "$EVIDENCE_DIR" && "$EVIDENCE_DIR" == /* ]] || return 1
    if [[ -L "$EVIDENCE_DIR" || ( -e "$EVIDENCE_DIR" && ! -d "$EVIDENCE_DIR" ) ]]; then
      return 1
    fi
    mkdir -p -- "$EVIDENCE_DIR" || return 1
    chmod 700 -- "$EVIDENCE_DIR" || return 1
    [[ "$($STAT_BIN -c '%a:%F' -- "$EVIDENCE_DIR" 2>/dev/null)" == "700:directory" ]] || return 1
    return 0
  fi
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
  if (( SELF_TEST == 1 )); then
    metadata="$($STAT_BIN -c '%u:%g:%a:%h:%F:%s' -- "$path" 2>/dev/null)" || return 1
    [[ "$metadata" =~ ^[0-9]+:[0-9]+:600:1:regular\ file:[0-9]+$ ]]
  else
    metadata="$(sudo -n "$STAT_BIN" -c '%u:%g:%a:%h:%F:%s' -- "$path" 2>/dev/null)" || return 1
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
    "$LAUNCHER_PATH" run-once n8n.workflows.get \
      2> >(filter_n8n_run_once_diagnostics >&2))"
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

# The launcher can emit only stable, redacted diagnostic labels through these
# prefixes. Do not forward arbitrary stderr: it may contain provider data,
# request details, or secrets from child processes.
filter_n8n_run_once_diagnostics() {
  "$AWK_BIN" '
    /^FCP-N8N-HOST-ERROR-DETAIL\/v1 policy\.(approval|capability|deployment|network|lease|binding|decision|other)$/ ||
    /^FCP-N8N-HOST-ERROR-DETAIL\/v1 host\.other$/ ||
    /^FCP-N8N-INVOKE-DIAGNOSTIC\/v1 dispatch_(4xx|5xx|other)$/ ||
    /^FCP-N8N-INVOKE-DIAGNOSTIC\/v1 response_(protocol|auth|rate_limited|capability|zone|connector|resource|external_(4xx|5xx|other|unknown)|upstream_timeout|dependency_unavailable|internal)$/ {
      print
      fflush()
    }
  '
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
  local invoke_reader_fd
  local sudo_bin

  APPROVAL_HELPER_STATUS=125
  APPROVAL_READER_STATUS=125
  sudo_bin="/usr/bin/sudo"
  if (( SELF_TEST == 1 )); then
    sudo_bin="$HANDOFF_TEST_SUDO"
  fi

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

  if "$sudo_bin" -n /usr/bin/bash -c '
      exec 3>&1
      exec "$1" --signal=TERM --kill-after=2s "$2" "$3" \
        --request-file "$4" 2>/dev/null
    ' _ "$TIMEOUT_BIN" "${APPROVAL_TIMEOUT_SECONDS}s" \
    "$APPROVAL_HELPER_PATH" "$basename" 1>&3 2>/dev/null; then
    helper_status=0
  else
    helper_status=$?
  fi
  APPROVAL_HELPER_STATUS="$helper_status"
  exec 3>&-

  if (( helper_status != 0 )); then
    cat <&"$reader_fd" >/dev/null 2>/dev/null || true
    if wait "$reader_pid"; then
      reader_status=0
    else
      reader_status=$?
    fi
    APPROVAL_READER_STATUS="$reader_status"
    exec {reader_fd}<&-
    (( reader_status == 0 )) || return 1
    return 1
  fi

  # The token travels from FD3 -> cat -> jq stdin -> exactly one launcher
  # invocation.  It never enters a shell variable, argv, file, or evidence.
  # Bash's coproc descriptors are not guaranteed to survive into a second
  # coproc child. Duplicate the reader to an ordinary descriptor first.
  if ! exec {invoke_reader_fd}<&"$reader_fd"; then
    cat <&"$reader_fd" >/dev/null 2>/dev/null || true
    if wait "$reader_pid"; then
      reader_status=0
    else
      reader_status=$?
    fi
    APPROVAL_READER_STATUS="$reader_status"
    exec {reader_fd}<&-
    return 1
  fi
  if (( ACTIVATION_MODE == 1 )); then
    coproc FWC_ACTIVATION_INVOKE {
      run_activation_once "$invoke_reader_fd";
    }
    invoke_fd="${FWC_ACTIVATION_INVOKE[0]}"
    invoke_pid="$FWC_ACTIVATION_INVOKE_PID"
  else
    coproc FWC_UNARCHIVE_INVOKE {
      run_unarchive_once "$invoke_reader_fd";
    }
    invoke_fd="${FWC_UNARCHIVE_INVOKE[0]}"
    invoke_pid="$FWC_UNARCHIVE_INVOKE_PID"
  fi
  exec {invoke_reader_fd}<&-
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
  APPROVAL_READER_STATUS="$reader_status"
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
      --arg correlation "$INVOKE_CORRELATION_ID" --argjson deadline "$DEADLINE_MS" \
      '{server_id:$server,input:$input,approval_token:$approval[0],
        deadline_ms:$deadline,correlation_id:$correlation}' <&"$approval_reader_fd" |
    "$LAUNCHER_PATH" run-once "$OPERATION" \
      2> >(filter_n8n_run_once_diagnostics >&2)
}

run_activation_once() {
  local approval_reader_fd="$1"
  "$JQ_BIN" -cn --slurpfile approval /dev/stdin \
      --arg server "$SERVER" --argjson input "$HANDOFF_INPUT" \
      --arg correlation "$HANDOFF_CORRELATION_ID" --argjson deadline "$HANDOFF_DEADLINE_MS" \
      '{server_id:$server,input:$input,approval_token:$approval[0],
        deadline_ms:$deadline,correlation_id:$correlation}' <&"$approval_reader_fd" |
    "$LAUNCHER_PATH" run-once "$HANDOFF_OPERATION" \
      2> >(filter_n8n_run_once_diagnostics >&2)
}

build_approval_request_json() {
  local expiry_ms="$1"
  local server="$2"
  local workflow_id="$3"
  local input_json="$4"
  local parent_binding="$5"
  local operation="${6:-$APPROVAL_OPERATION}"

  "$JQ_BIN" -cn \
    --arg server "$server" --arg workflow_id "$workflow_id" \
    --arg operation "$operation" --argjson input "$input_json" \
    --arg parent "$parent_binding" --argjson expiry "$expiry_ms" \
    '{schema:"fwc.n8n.owner-approval-request.v1",server:$server,
      workflow_id:$workflow_id,operation:$operation,input:$input,
      official_mcp_tool:"",official_mcp_resource_uri:"",
      official_mcp_payload_digest:"",parent_binding_sha256:$parent,
      expires_at_ms:$expiry}'
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

validate_invoke() {
  local projection="$1"
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" \
    --arg operation "$OPERATION" '
    .type == "response" and .status == "ok"
    and .result.status == "verified"
    and .result.operation == $operation
    and .result.before.id == $workflow
    and .result.after.id == $workflow
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

validate_unchanged() {
  local projection="$1"
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" \
    --arg version "$BASELINE_VERSION_ID" --arg graph "$BASELINE_GRAPH_DIGEST" \
    --arg state "$BASELINE_STATE_DIGEST" '
    .status == "ok" and .result.id == $workflow
    and .result.active == false and .result.activeVersionId == null
    and .result.isArchived == true and .result.published == null
    and .result.versionId == $version
    and .result.draft.graphDigest == $graph
    and .result.stateDigest == $state
  ' <<<"$projection" >/dev/null 2>&1
}

validate_activation_create() {
  local projection="$1"
  "$JQ_BIN" -e '
    .type == "response" and .status == "ok"
    and .result.status == "verified"
    and .result.operation == "n8n.workflows.create_draft"
    and (.result.id | type) == "string" and (.result.id | length) > 0
    and .result.active == false and .result.activeVersionId == null
    and .result.isArchived == false and .result.published == null
    and (.result.versionId | type) == "string" and (.result.versionId | length) > 0
    and (.result.graphDigest | type) == "string"
    and (.result.stateDigest | type) == "string"
  ' <<<"$projection" >/dev/null 2>&1
}

validate_activation_baseline() {
  local projection="$1"
  "$JQ_BIN" -e --arg workflow "$ACTIVATION_WORKFLOW_ID" '
    .status == "ok" and .result.id == $workflow
    and .result.active == false and .result.activeVersionId == null
    and .result.isArchived == false and .result.published == null
    and (.result.versionId | type) == "string" and (.result.versionId | length) > 0
    and (.result.draft.versionId | type) == "string"
    and (.result.draft.graphDigest | type) == "string"
    and (.result.stateDigest | type) == "string"
  ' <<<"$projection" >/dev/null 2>&1
}

validate_activation_publish() {
  local projection="$1"
  "$JQ_BIN" -e --arg workflow "$ACTIVATION_WORKFLOW_ID" '
    .type == "response" and .status == "ok"
    and .result.status == "verified"
    and .result.operation == "n8n.workflows.activate"
    and .result.active == true
    and .result.before.id == $workflow and .result.after.id == $workflow
    and .result.after.active == true
    and (.result.after.activeVersionId | type) == "string"
    and .result.after.published.versionId == .result.after.activeVersionId
    and (.result.after.published.graphDigest | type) == "string"
    and .result.after.published.graphDigest == .result.after.draft.graphDigest
    and .result.after.isArchived == false
  ' <<<"$projection" >/dev/null 2>&1
}

validate_activation_active_readback() {
  local projection="$1"
  "$JQ_BIN" -e --arg workflow "$ACTIVATION_WORKFLOW_ID" '
    .status == "ok" and .result.id == $workflow
    and .result.active == true
    and .result.activeVersionId == .result.published.versionId
    and .result.published.graphDigest == .result.draft.graphDigest
    and .result.isArchived == false
  ' <<<"$projection" >/dev/null 2>&1
}

validate_activation_unpublish() {
  local projection="$1"
  "$JQ_BIN" -e --arg workflow "$ACTIVATION_WORKFLOW_ID" '
    .type == "response" and .status == "ok"
    and .result.status == "verified"
    and .result.operation == "n8n.workflows.activate"
    and .result.active == false
    and .result.before.id == $workflow and .result.after.id == $workflow
    and .result.after.active == false
    and .result.after.activeVersionId == null
    and .result.after.published == null
    and .result.after.isArchived == false
  ' <<<"$projection" >/dev/null 2>&1
}

persist_activation_plan() {
  local persisted
  persist_activation_record activation-plan "$ACTIVATION_PLAN" || return 1
  persisted="$(read_activation_record activation-plan)" || return 1
  validate_activation_plan "$persisted"
}

validate_activation_transition_record() {
  local record="$1"
  local transition="$2"
  local operation="$3"
  local workflow="$4"
  local projection_file="$5"
  "$JQ_BIN" -e \
    --arg server "$SERVER" --arg run_id "$RUN_ID" \
    --arg workflow "$workflow" --arg transition "$transition" \
    --arg operation "$operation" --arg projection_file "$projection_file" '
      .schema == "fwc.n8n.activation-transition.v1"
      and .server == $server and .run_id == $run_id
      and .workflow_id == $workflow and .transition == $transition
      and .operation == $operation and .projection_file == $projection_file
      and (.correlation_id | type) == "string"
      and (.correlation_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
      and .verdict == "verified"
      and .raw_provider_bodies_persisted == false
      and .raw_request_bodies_persisted == false
      and .tokens_persisted == false and .secrets_persisted == false
    ' <<<"$record" >/dev/null 2>&1
}

persist_activation_transition() {
  local transition="$1"
  local operation="$2"
  local projection_file="$3"
  local workflow="$4"
  local record
  local persisted

  record="$($JQ_BIN -cn \
    --arg server "$SERVER" --arg run_id "$RUN_ID" \
    --arg workflow "$workflow" --arg transition "$transition" \
    --arg operation "$operation" --arg projection_file "$projection_file" \
    --arg correlation "$HANDOFF_CORRELATION_ID" \
    '{schema:"fwc.n8n.activation-transition.v1",server:$server,
      run_id:$run_id,workflow_id:$workflow,transition:$transition,
      operation:$operation,projection_file:$projection_file,
      correlation_id:$correlation,verdict:"verified",
      raw_provider_bodies_persisted:false,raw_request_bodies_persisted:false,
      tokens_persisted:false,secrets_persisted:false}')" || return 1
  persist_activation_record "transition-$transition" "$record" || return 1
  persisted="$(read_activation_record "transition-$transition")" || return 1
  validate_activation_transition_record \
    "$persisted" "$transition" "$operation" "$workflow" "$projection_file"
}

validate_activation_summary() {
  local summary="$1"
  local verdict="$2"
  "$JQ_BIN" -e \
    --arg server "$SERVER" --arg run_id "$RUN_ID" \
    --arg workflow "$ACTIVATION_WORKFLOW_ID" --arg verdict "$verdict" '
      .schema == "fwc.n8n.activation-acceptance.v1"
      and .server == $server and .run_id == $run_id
      and .workflow_id == $workflow and .verdict == $verdict
      and .sequence == ["create_draft_once","draft_readback_once",
        "publish_once","publish_readback_once","active_readback_once",
        "unpublish_once","unpublish_readback_once"]
      and .evidence_files == ["activation-plan.json","activation-create.json",
        "activation-baseline.json","activation-publish.json",
        "activation-active.json","activation-unpublish.json"]
      and .transition_records == ["transition-create.json",
        "transition-publish.json","transition-unpublish.json"]
      and .retries == 0 and .automatic_cleanup == false
      and .webhook_invoked == false
      and .raw_provider_bodies_persisted == false
      and .raw_request_bodies_persisted == false
      and .tokens_persisted == false and .secrets_persisted == false
      and (if $verdict == "pass"
           then .evidence_complete == true
             and .create_status == 0 and .baseline_status == 0
             and .publish_status == 0 and .active_status == 0
             and .unpublish_status == 0
           else true end)
    ' <<<"$summary" >/dev/null 2>&1
}

validate_activation_evidence_bundle() {
  local plan
  local create
  local baseline
  local publish
  local active
  local unpublish
  local summary

  (( ACTIVATION_MODE == 1 )) || return 1
  [[ -n "$EVIDENCE_DIR" ]] || return 1
  for name in activation-plan activation-create activation-baseline \
    activation-publish activation-active activation-unpublish \
    transition-create transition-publish transition-unpublish summary; do
    validate_activation_record_file "$name" || return 1
  done
  plan="$(read_activation_record activation-plan)" || return 1
  create="$(read_activation_record activation-create)" || return 1
  baseline="$(read_activation_record activation-baseline)" || return 1
  publish="$(read_activation_record activation-publish)" || return 1
  active="$(read_activation_record activation-active)" || return 1
  unpublish="$(read_activation_record activation-unpublish)" || return 1
  summary="$(read_activation_record summary)" || return 1
  validate_activation_plan "$plan" || return 1
  validate_activation_create "$create" || return 1
  validate_activation_baseline "$baseline" || return 1
  validate_activation_publish "$publish" || return 1
  validate_activation_active_readback "$active" || return 1
  validate_activation_unpublish "$unpublish" || return 1
  validate_activation_transition_record \
    "$(read_activation_record transition-create)" create \
    "$ACTIVATION_CREATE_OPERATION" "$ACTIVATION_WORKFLOW_ID" activation-create || return 1
  validate_activation_transition_record \
    "$(read_activation_record transition-publish)" publish \
    "$ACTIVATION_OPERATION" "$ACTIVATION_WORKFLOW_ID" activation-publish || return 1
  validate_activation_transition_record \
    "$(read_activation_record transition-unpublish)" unpublish \
    "$ACTIVATION_OPERATION" "$ACTIVATION_WORKFLOW_ID" activation-unpublish || return 1
  validate_activation_summary "$summary" pass
}

activation_invoke_step() {
  local operation="$1"
  local approval_operation="$2"
  local input_json="$3"
  local workflow_id="$4"
  local resource_uri="$5"
  local evidence_name="$6"
  local correlation_id
  local current_ms
  local expiry_ms
  local request_json

  correlation_id="$(uuid)" || return 1
  HANDOFF_OPERATION="$operation"
  HANDOFF_INPUT="$input_json"
  HANDOFF_CORRELATION_ID="$correlation_id"
  HANDOFF_DEADLINE_MS="$DEADLINE_MS"
  PARENT_BINDING="$("$PARENT_HELPER_PATH" "$SERVER" "$resource_uri" "$operation" "$input_json" 2>/dev/null)" || return 1
  [[ "$PARENT_BINDING" =~ ^[0-9a-f]{64}$ ]] || return 1
  current_ms="$(now_ms)" || return 1
  expiry_ms="$((current_ms + APPROVAL_TTL_MS))"
  validate_expiry "$expiry_ms" "$current_ms" || return 1
  REQUEST_BASENAME="n8n-activation-$SERVER-$correlation_id-$evidence_name.json"
  request_json="$(build_approval_request_json \
    "$expiry_ms" "$SERVER" "$workflow_id" "$input_json" "$PARENT_BINDING" \
    "$approval_operation")" || return 1
  write_request_file "$request_json" || return 1
  read_request_metadata "$REQUEST_PATH" || return 1
  bounded_approval_and_invoke
}

persist_activation_summary() {
  local verdict="$1"
  local code="${2:-null}"
  local summary
  local persisted

  if (( ACTIVATION_MODE == 1 )); then
    [[ -n "$EVIDENCE_DIR" ]] || return 1
  else
    [[ -z "$EVIDENCE_DIR" ]] && return 0
  fi
  summary="$($JQ_BIN -cn \
    --arg server "$SERVER" --arg workflow_id "$ACTIVATION_WORKFLOW_ID" \
    --arg verdict "$verdict" --argjson abort_code "$code" \
    --arg evidence_directory "$EVIDENCE_DIR" \
    --arg run_id "$RUN_ID" \
    --argjson create_status "$ACTIVATION_CREATE_STATUS" \
    --argjson baseline_status "$ACTIVATION_BASELINE_STATUS" \
    --argjson publish_status "$ACTIVATION_PUBLISH_STATUS" \
    --argjson active_status "$ACTIVATION_ACTIVE_STATUS" \
    --argjson unpublish_status "$ACTIVATION_UNPUBLISH_STATUS" \
    '{schema:"fwc.n8n.activation-acceptance.v1",server:$server,
      workflow_id:$workflow_id,run_id:$run_id,verdict:$verdict,
      abort_code:$abort_code,evidence_directory:$evidence_directory,
      sequence:["create_draft_once","draft_readback_once","publish_once",
        "publish_readback_once","active_readback_once","unpublish_once",
        "unpublish_readback_once"],
      create_status:$create_status,baseline_status:$baseline_status,
      publish_status:$publish_status,active_status:$active_status,
      unpublish_status:$unpublish_status,retries:0,
      automatic_cleanup:false,webhook_invoked:false,
      evidence_complete:($verdict == "pass"),
      evidence_files:["activation-plan.json","activation-create.json",
        "activation-baseline.json","activation-publish.json",
        "activation-active.json","activation-unpublish.json"],
      transition_records:["transition-create.json","transition-publish.json",
        "transition-unpublish.json"],
      raw_provider_bodies_persisted:false,raw_request_bodies_persisted:false,
      tokens_persisted:false,secrets_persisted:false}')" || return 1
  persist_activation_record summary "$summary" || return 1
  if [[ "$verdict" == pass ]]; then
    persisted="$(read_activation_record summary)" || return 1
    validate_activation_summary "$persisted" pass || return 1
  fi
}

run_activation_acceptance() {
  local raw_projection
  local baseline_input
  local create_name
  local create_path

  ACTIVATION_MODE=1
  if ! activation_preflight; then
    return 10
  fi
  RUN_ID="$(uuid)" || { emit_activation_stop uuid_failed; return 10; }
  INVOKE_CORRELATION_ID="$RUN_ID"
  ACTIVATION_CREATE_IDEMPOTENCY="$(uuid)" || {
    emit_activation_stop create_idempotency_failed
    return 10
  }
  ACTIVATION_CREATE_APPROVAL="n8n-activation-$SERVER-create-$ACTIVATION_CREATE_IDEMPOTENCY"
  create_name="fwc activation $SERVER $RUN_ID"
  create_path="fwc-activation-$RUN_ID"
  ACTIVATION_CREATE_INPUT="$(build_activation_create_input \
    "$create_name" "$create_path" "$ACTIVATION_CREATE_IDEMPOTENCY" \
    "$ACTIVATION_CREATE_APPROVAL")" || {
    emit_activation_stop create_input_failed
    return 10
  }
  if ! activation_invoke_step "$ACTIVATION_CREATE_OPERATION" "create_draft" \
    "$ACTIVATION_CREATE_INPUT" "" "fwc-n8n://$SERVER" create; then
    persist_activation_summary stop '"create_failed"' || true
    emit_activation_stop create_failed
    return 10
  fi
  ACTIVATION_CREATE_STATUS="$INVOCATION_STATUS"
  raw_projection="$INVOKE_PROJECTION"
  if (( INVOCATION_STATUS != 0 )) || ! validate_activation_create "$raw_projection"; then
    if ! persist_projection activation-create "$raw_projection"; then
      emit_activation_stop evidence_write_failed
      return 10
    fi
    persist_activation_summary unknown '"create_unknown"' || true
    emit_activation_unknown create_unknown
    return 20
  fi
  ACTIVATION_CREATE_PROJECTION="$raw_projection"
  ACTIVATION_WORKFLOW_ID="$("$JQ_BIN" -er '.result.id' <<<"$raw_projection")" || {
    emit_activation_stop create_id_missing
    return 10
  }
  valid_workflow_id "$ACTIVATION_WORKFLOW_ID" || {
    emit_activation_stop create_id_invalid
    return 10
  }
  persist_projection activation-create "$ACTIVATION_CREATE_PROJECTION" || {
    emit_activation_stop evidence_write_failed
    return 10
  }
  if ! persist_activation_transition create "$ACTIVATION_CREATE_OPERATION" \
    activation-create "$ACTIVATION_WORKFLOW_ID"; then
    persist_activation_summary stop '"evidence_write_failed"' || true
    emit_activation_stop evidence_write_failed
    return 10
  fi

  baseline_input="$("$JQ_BIN" -cn --arg id "$ACTIVATION_WORKFLOW_ID" '{id:$id}')" || {
    emit_activation_stop baseline_input_failed
    return 10
  }
  ACTIVATION_BASELINE_INPUT="$baseline_input"
  ACTIVATION_BASELINE_PROJECTION="$(run_read_once "$baseline_input")"
  ACTIVATION_BASELINE_STATUS=$?
  if (( ACTIVATION_BASELINE_STATUS != 0 )) \
    || ! validate_activation_baseline "$ACTIVATION_BASELINE_PROJECTION"; then
    if ! persist_projection activation-baseline "$ACTIVATION_BASELINE_PROJECTION"; then
      emit_activation_stop evidence_write_failed
      return 10
    fi
    persist_activation_summary unknown '"baseline_unknown"' || true
    emit_activation_unknown baseline_unknown
    return 20
  fi
  ACTIVATION_GRAPH_DIGEST="$("$JQ_BIN" -er '.result.draft.graphDigest' \
    <<<"$ACTIVATION_BASELINE_PROJECTION")" || {
    emit_activation_stop baseline_graph_missing
    return 10
  }
  ACTIVATION_STATE_DIGEST="$("$JQ_BIN" -er '.result.stateDigest' \
    <<<"$ACTIVATION_BASELINE_PROJECTION")" || {
    emit_activation_stop baseline_state_missing
    return 10
  }
  ACTIVATION_VERSION_ID="$("$JQ_BIN" -er '.result.versionId' \
    <<<"$ACTIVATION_BASELINE_PROJECTION")" || {
    emit_activation_stop baseline_version_missing
    return 10
  }
  validate_digest "$ACTIVATION_GRAPH_DIGEST" || {
    emit_activation_stop baseline_graph_invalid
    return 10
  }
  validate_digest "$ACTIVATION_STATE_DIGEST" || {
    emit_activation_stop baseline_state_invalid
    return 10
  }
  persist_projection activation-baseline "$ACTIVATION_BASELINE_PROJECTION" || {
    emit_activation_stop evidence_write_failed
    return 10
  }

  ACTIVATION_PUBLISH_IDEMPOTENCY="$(uuid)" || {
    emit_activation_stop publish_idempotency_failed
    return 10
  }
  ACTIVATION_PUBLISH_APPROVAL="n8n-activation-$SERVER-publish-$ACTIVATION_PUBLISH_IDEMPOTENCY"
  ACTIVATION_PUBLISH_INPUT="$("$JQ_BIN" -cn \
    --arg id "$ACTIVATION_WORKFLOW_ID" --arg version "$ACTIVATION_VERSION_ID" \
    --arg state "$ACTIVATION_STATE_DIGEST" \
    --arg approval_ref "$ACTIVATION_PUBLISH_APPROVAL" \
    --arg idempotency "$ACTIVATION_PUBLISH_IDEMPOTENCY" \
    '{id:$id,active:true,versionId:$version,
      guard:{approvalRef:$approval_ref,idempotencyKey:$idempotency,
        precondition:{versionId:$version,activeVersionId:null,active:false,
          isArchived:false,stateDigest:$state}}}')" || {
    emit_activation_stop publish_input_failed
    return 10
  }
  if ! activation_invoke_step "$ACTIVATION_OPERATION" "activate" \
    "$ACTIVATION_PUBLISH_INPUT" "$ACTIVATION_WORKFLOW_ID" \
    "fwc-n8n://$SERVER/workflows/$ACTIVATION_WORKFLOW_ID" publish; then
    persist_activation_summary stop '"publish_failed"' || true
    emit_activation_stop publish_failed
    return 10
  fi
  ACTIVATION_PUBLISH_STATUS="$INVOCATION_STATUS"
  ACTIVATION_PUBLISH_PROJECTION="$INVOKE_PROJECTION"
  if (( INVOCATION_STATUS != 0 )) || ! validate_activation_publish "$ACTIVATION_PUBLISH_PROJECTION"; then
    if ! persist_projection activation-publish "$ACTIVATION_PUBLISH_PROJECTION"; then
      emit_activation_stop evidence_write_failed
      return 10
    fi
    persist_activation_summary unknown '"publish_unknown"' || true
    emit_activation_unknown publish_unknown
    return 20
  fi
  if ! persist_projection activation-publish "$ACTIVATION_PUBLISH_PROJECTION"; then
    persist_activation_summary stop '"evidence_write_failed"' || true
    emit_activation_stop evidence_write_failed
    return 10
  fi
  if ! persist_activation_transition publish "$ACTIVATION_OPERATION" \
    activation-publish "$ACTIVATION_WORKFLOW_ID"; then
    persist_activation_summary stop '"evidence_write_failed"' || true
    emit_activation_stop evidence_write_failed
    return 10
  fi

  ACTIVATION_ACTIVE_PROJECTION="$(run_read_once "$baseline_input")"
  ACTIVATION_ACTIVE_STATUS=$?
  if (( ACTIVATION_ACTIVE_STATUS != 0 )) \
    || ! validate_activation_active_readback "$ACTIVATION_ACTIVE_PROJECTION"; then
    if ! persist_projection activation-active "$ACTIVATION_ACTIVE_PROJECTION"; then
      emit_activation_stop evidence_write_failed
      return 10
    fi
    persist_activation_summary unknown '"active_readback_mismatch"' || true
    emit_activation_unknown active_readback_mismatch
    return 20
  fi
  if ! persist_projection activation-active "$ACTIVATION_ACTIVE_PROJECTION"; then
    persist_activation_summary stop '"evidence_write_failed"' || true
    emit_activation_stop evidence_write_failed
    return 10
  fi
  ACTIVATION_ACTIVE_VERSION_ID="$("$JQ_BIN" -er '.result.activeVersionId' \
    <<<"$ACTIVATION_ACTIVE_PROJECTION")" || {
    emit_activation_stop active_version_missing
    return 10
  }
  ACTIVATION_UNPUBLISH_IDEMPOTENCY="$(uuid)" || {
    emit_activation_stop unpublish_idempotency_failed
    return 10
  }
  ACTIVATION_UNPUBLISH_APPROVAL="n8n-activation-$SERVER-unpublish-$ACTIVATION_UNPUBLISH_IDEMPOTENCY"
  ACTIVATION_UNPUBLISH_INPUT="$("$JQ_BIN" -cn \
    --arg id "$ACTIVATION_WORKFLOW_ID" --arg version "$ACTIVATION_VERSION_ID" \
    --arg active_version "$ACTIVATION_ACTIVE_VERSION_ID" \
    --arg state "$("$JQ_BIN" -er '.result.stateDigest' <<<"$ACTIVATION_ACTIVE_PROJECTION")" \
    --arg approval_ref "$ACTIVATION_UNPUBLISH_APPROVAL" \
    --arg idempotency "$ACTIVATION_UNPUBLISH_IDEMPOTENCY" \
    '{id:$id,active:false,
      guard:{approvalRef:$approval_ref,idempotencyKey:$idempotency,
        precondition:{versionId:$version,activeVersionId:$active_version,
          active:true,isArchived:false,stateDigest:$state}}}')" || {
    emit_activation_stop unpublish_input_failed
    return 10
  }
  if ! activation_invoke_step "$ACTIVATION_OPERATION" "activate" \
    "$ACTIVATION_UNPUBLISH_INPUT" "$ACTIVATION_WORKFLOW_ID" \
    "fwc-n8n://$SERVER/workflows/$ACTIVATION_WORKFLOW_ID" unpublish; then
    persist_activation_summary stop '"unpublish_failed"' || true
    emit_activation_stop unpublish_failed
    return 10
  fi
  ACTIVATION_UNPUBLISH_STATUS="$INVOCATION_STATUS"
  ACTIVATION_UNPUBLISH_PROJECTION="$INVOKE_PROJECTION"
  if (( INVOCATION_STATUS != 0 )) || ! validate_activation_unpublish "$ACTIVATION_UNPUBLISH_PROJECTION"; then
    if ! persist_projection activation-unpublish "$ACTIVATION_UNPUBLISH_PROJECTION"; then
      emit_activation_stop evidence_write_failed
      return 10
    fi
    persist_activation_summary unknown '"unpublish_unknown"' || true
    emit_activation_unknown unpublish_unknown
    return 20
  fi
  if ! persist_projection activation-unpublish "$ACTIVATION_UNPUBLISH_PROJECTION"; then
    persist_activation_summary stop '"evidence_write_failed"' || true
    emit_activation_stop evidence_write_failed
    return 10
  fi
  if ! persist_activation_transition unpublish "$ACTIVATION_OPERATION" \
    activation-unpublish "$ACTIVATION_WORKFLOW_ID"; then
    persist_activation_summary stop '"evidence_write_failed"' || true
    emit_activation_stop evidence_write_failed
    return 10
  fi

  persist_activation_summary pass null || {
    emit_activation_stop evidence_write_failed
    return 10
  }
  emit_activation_pass
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
  local approval_request_json

  SELF_TEST=1
  root="$(mktemp -d "${TMPDIR:-/tmp}/n8n-unarchive-self-test.XXXXXX")" || return 1
  REQUEST_ROOT="$root/approval-requests"
  mkdir -m 700 -- "$REQUEST_ROOT" || return 1
  approval_request_json="$(build_approval_request_json \
    "$valid" "hetzner" "synthetic-workflow" '{"id":"synthetic-workflow"}' \
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")" || return 1
  "$JQ_BIN" -e '
    .schema == "fwc.n8n.owner-approval-request.v1"
    and .operation == "unarchive"
    and .operation != "n8n.workflows.unarchive"
    and .workflow_id == "synthetic-workflow"
  ' <<<"$approval_request_json" >/dev/null || return 1
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

run_handoff_self_test() {
  local root
  local mock_sudo
  local mock_approval
  local mock_launcher
  local count_file
  local eof_file
  local handoff_status
  local count
  local eof

  SELF_TEST=1
  SERVER="synthetic"
  WORKFLOW_ID="synthetic-workflow"
  INVOKE_CORRELATION_ID="00000000-0000-4000-8000-000000000001"
  UNARCHIVE_INPUT='{"id":"synthetic-workflow"}'
  root="$(mktemp -d "${TMPDIR:-/tmp}/n8n-unarchive-handoff-test.XXXXXX")" || return 1
  REQUEST_ROOT="$root/approval-requests"
  mkdir -m 700 -- "$REQUEST_ROOT" || return 1
  REQUEST_BASENAME="handoff-self-test.json"
  write_request_file '{"schema":"handoff-test"}' || return 1

  mock_sudo="$root/sudo"
  mock_approval="$root/approval-helper"
  mock_launcher="$root/launcher"
  count_file="$root/invoke-count"
  eof_file="$root/launcher-eof"

  # This wrapper deliberately preserves the production argument shape and
  # runs the same root-bash FD3/stdout bridge without invoking sudo/provider.
  cat >"$mock_sudo" <<'EOF'
#!/usr/bin/env bash
set -u
[[ "${1:-}" == "-n" ]] || exit 64
shift
[[ "${1:-}" == "/usr/bin/bash" && "${2:-}" == "-c" ]] || exit 64
shift 2
exec /usr/bin/bash -c "$@"
EOF
  chmod 700 -- "$mock_sudo" || return 1

  cat >"$mock_approval" <<'EOF'
#!/usr/bin/env bash
set -u
[[ -e /proc/$$/fd/3 ]] || exit 70
printf '%s\n' '"synthetic-fd3-token"' >&3
EOF
  chmod 700 -- "$mock_approval" || return 1

  cat >"$mock_launcher" <<'EOF'
#!/usr/bin/env bash
set -u
count_file="$HANDOFF_TEST_INVOKE_COUNT"
eof_file="$HANDOFF_TEST_EOF_FILE"
count=0
if [[ -f "$count_file" ]]; then
  count="$(cat -- "$count_file")" || exit 71
fi
[[ "$count" =~ ^[0-9]+$ ]] || exit 72
printf '%s\n' "$((count + 1))" >"$count_file" || exit 73
[[ "${1:-}" == "run-once" && "${2:-}" == "n8n.workflows.unarchive" ]] || exit 74
IFS= read -r envelope || exit 75
if IFS= read -r extra; then
  exit 76
fi
printf '1\n' >"$eof_file" || exit 77
/usr/bin/jq -e \
  --arg server "$HANDOFF_TEST_SERVER" \
  --arg workflow "$HANDOFF_TEST_WORKFLOW" \
  --arg correlation "$HANDOFF_TEST_CORRELATION" \
  '.server_id == $server
   and .input.id == $workflow
   and .approval_token == "synthetic-fd3-token"
   and .correlation_id == $correlation' \
  <<<"$envelope" >/dev/null || exit 78
printf '{"type":"response","status":"ok","result":{"status":"verified","operation":"n8n.workflows.unarchive","provider":"rest","retry":"never_automatic","readback":"independent_get","before":{"id":"%s"},"after":{"id":"%s"}}}\n' \
  "$HANDOFF_TEST_WORKFLOW" "$HANDOFF_TEST_WORKFLOW"
EOF
  chmod 700 -- "$mock_launcher" || return 1

  HANDOFF_TEST_SUDO="$mock_sudo"
  APPROVAL_HELPER_PATH="$mock_approval"
  LAUNCHER_PATH="$mock_launcher"
  export HANDOFF_TEST_INVOKE_COUNT="$count_file"
  export HANDOFF_TEST_EOF_FILE="$eof_file"
  export HANDOFF_TEST_SERVER="$SERVER"
  export HANDOFF_TEST_WORKFLOW="$WORKFLOW_ID"
  export HANDOFF_TEST_CORRELATION="$INVOKE_CORRELATION_ID"

  if approval_fd3_handoff "$REQUEST_BASENAME"; then
    handoff_status=0
  else
    handoff_status=$?
  fi
  count="$(cat -- "$count_file" 2>/dev/null || true)"
  eof="$(cat -- "$eof_file" 2>/dev/null || true)"
  [[ "$handoff_status" -eq 0 ]] || return 1
  [[ "$APPROVAL_HELPER_STATUS" -eq 0 ]] || return 1
  [[ "$APPROVAL_READER_STATUS" -eq 0 ]] || return 1
  [[ "$INVOCATION_STATUS" -eq 0 ]] || return 1
  validate_invoke "$INVOKE_PROJECTION" || return 1
  [[ "$count" == 1 && "$eof" == 1 ]] || return 1

  printf '{"schema":"%s","verdict":"pass","mode":"handoff-self-test","acceptance":false,"cases":7}\n' "$SCHEMA"
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
      --activation)
        ACTIVATION_MODE=1
        shift
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
  local server_option_set=0
  [[ -n "$SERVER" ]] && server_option_set=1
  [[ -n "$SERVER" ]] || [[ "${#positional[@]}" -ge 1 ]] || return 1
  [[ -n "$SERVER" ]] || SERVER="${positional[0]}"
  if (( ACTIVATION_MODE == 1 )); then
    [[ -z "$WORKFLOW_ID" ]] || return 1
    if (( server_option_set == 1 )); then
      [[ "${#positional[@]}" -eq 0 ]] || return 1
    else
      [[ "${#positional[@]}" -eq 1 ]] || return 1
    fi
    valid_server "$SERVER"
  else
    [[ -n "$WORKFLOW_ID" ]] || [[ "${#positional[@]}" -ge 2 ]] || return 1
    [[ -n "$WORKFLOW_ID" ]] || WORKFLOW_ID="${positional[1]}"
    [[ "${#positional[@]}" -le 2 ]] || return 1
    valid_server "$SERVER" && valid_workflow_id "$WORKFLOW_ID"
  fi
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
  local evidence_status
  local invoke_proves_verified
  local readback_proves_final
  local readback_proves_original

  if [[ "${1:-}" == --self-test && "$#" -eq 1 ]]; then
    run_self_test || {
      printf '{"schema":"%s","verdict":"STOP","abort_code":"self_test_failed"}\n' "$SCHEMA"
      return 1
    }
    return 0
  fi
  if [[ "${1:-}" == --handoff-self-test && "$#" -eq 1 ]]; then
    run_handoff_self_test || {
      printf '{"schema":"%s","verdict":"STOP","abort_code":"handoff_self_test_failed"}\n' "$SCHEMA"
      return 1
    }
    return 0
  fi
  if [[ "${1:-}" == --activation-self-test && "$#" -eq 1 ]]; then
    run_activation_self_test || {
      printf '{"schema":"%s","verdict":"STOP","mode":"activation-self-test","abort_code":"self_test_failed"}\n' \
        "$ACTIVATION_SCHEMA"
      return 1
    }
    return 0
  fi
  if [[ "${1:-}" == --activation-create-input-self-test && "$#" -eq 1 ]]; then
    run_activation_create_input_self_test || {
      printf '{"schema":"%s","verdict":"STOP","mode":"activation-create-input-self-test","abort_code":"self_test_failed"}\n' \
        "$ACTIVATION_SCHEMA"
      return 1
    }
    return 0
  fi
  if ! parse_args "$@"; then
    usage >&2
    emit_stop invalid_arguments
    return 10
  fi
  if (( ACTIVATION_MODE == 1 )); then
    run_activation_acceptance
    return $?
  fi
  if [[ ! -x "$JQ_BIN" || ! -x "$AWK_BIN" || ! -x "$STAT_BIN" || ! -x "$UUIDGEN_BIN" || ! -x "$TIMEOUT_BIN" ]]; then
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
  INVOKE_CORRELATION_ID="$RUN_ID"
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
  request_json="$(build_approval_request_json \
    "$expiry_ms" "$SERVER" "$WORKFLOW_ID" "$UNARCHIVE_INPUT" "$PARENT_BINDING")" || {
    emit_stop approval_request_build_failed
    return 10
  }

  # Request creation is immediately adjacent to the one bounded approval +
  # invoke section.  There is no polling, replay, or second approval.
  write_request_file "$request_json" || { emit_stop approval_request_write_failed; return 10; }
  read_request_metadata "$REQUEST_PATH" || { emit_stop approval_request_metadata_failed; return 10; }
  bounded_approval_and_invoke || {
    persist_summary stop '"approval_failed"' || true
    emit_stop approval_failed
    return 10
  }

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

  readback_proves_final=0
  readback_proves_original=0
  invoke_proves_verified=0
  if (( INVOCATION_STATUS == 0 )) && validate_invoke "$INVOKE_PROJECTION"; then
    invoke_proves_verified=1
  fi
  if (( FINAL_GET_STATUS == 0 )) && validate_final "$FINAL_PROJECTION"; then
    readback_proves_final=1
  elif (( FINAL_GET_STATUS == 0 )) && validate_unchanged "$FINAL_PROJECTION"; then
    readback_proves_original=1
  fi

  # Reconciliation is complete before any post-invoke evidence write.  A
  # failed evidence write must not skip the readback or trigger a replay.
  evidence_status=0
  persist_projection invoke "$INVOKE_PROJECTION" || evidence_status=1
  persist_projection final "$FINAL_PROJECTION" || evidence_status=1
  if (( evidence_status != 0 )); then
    if (( readback_proves_final == 1 || readback_proves_original == 1 )); then
      persist_summary stop '"evidence_write_failed"' || true
      emit_stop evidence_write_failed
      return 10
    fi
    persist_summary unknown '"evidence_write_failed"' || true
    emit_unknown evidence_write_failed
    return 20
  fi

  if (( readback_proves_final == 1 && invoke_proves_verified == 1 )); then
    persist_summary pass null || { emit_stop evidence_write_failed; return 10; }
    emit_pass
    return 0
  fi
  if (( readback_proves_final == 1 && invoke_proves_verified == 0 )); then
    persist_summary unknown '"invoke_not_verified"' || true
    emit_unknown invoke_not_verified
    return 20
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
