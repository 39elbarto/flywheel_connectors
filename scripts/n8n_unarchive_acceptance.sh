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
readonly EXISTING_VERSION_SCHEMA="fwc.n8n.existing-version-acceptance.v1"
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
EXISTING_VERSION_MODE=0
CONTINUE_UNPUBLISH_MODE=0
SERVER=""
WORKFLOW_ID=""
VERSION_ID=""
SOURCE_EVIDENCE_DIR=""
PREINVOKE_CLAIM_PATH=""
PREINVOKE_CLAIM_JSON=""
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
APPROVAL_ABORT_CODE=""
HANDOFF_INVOKE_STARTED=0
ACTIVATION_MUTATION_MAY_HAVE_STARTED=0
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
ACTIVATION_FINAL_READBACK=""
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
ACTIVATION_FINAL_STATUS=125
ACTIVATION_CLAIM_PATH=""
ACTIVATION_CLAIM_JSON=""
HANDOFF_EVIDENCE_NAME=""
HANDOFF_RESOURCE_URI=""
HANDOFF_WORKFLOW_ID=""

EXISTING_BASELINE_PROJECTION=""
EXISTING_PUBLISH_PROJECTION=""
EXISTING_PUBLISH_READBACK=""
EXISTING_UNPUBLISH_PROJECTION=""
EXISTING_FINAL_READBACK=""
EXISTING_STATE_DIGEST=""
EXISTING_GRAPH_DIGEST=""
EXISTING_RUN_ID=""
EXISTING_PUBLISH_HELPER_STATUS=125
EXISTING_PUBLISH_APPROVAL_ABORT_CODE=""
EXISTING_UNPUBLISH_HELPER_STATUS=125
EXISTING_UNPUBLISH_APPROVAL_ABORT_CODE=""
EXISTING_DIAGNOSTIC_CAPTURE_FAILED=0
EXISTING_CONTINUATION_BASELINE=""
EXISTING_PRIOR_SUMMARY=""
EXISTING_PRIOR_PUBLISH_STATE_DIGEST=""
CONTINUATION_UNPUBLISH_ATTEMPTED=0
EXISTING_SOURCE_VALIDATION_EMITTED=0

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
  printf '{"schema":"%s","verdict":"unknown","abort_code":"%s","server":"%s","workflow_id":"%s","evidence_complete":false}\n' \
    "$ACTIVATION_SCHEMA" "$code" "$SERVER" "$ACTIVATION_WORKFLOW_ID"
}

activation_finish_failure() {
  local code="${1:-activation_failed}"
  if (( ACTIVATION_MUTATION_MAY_HAVE_STARTED == 1 )); then
    persist_activation_summary unknown "\"$code\"" || true
    emit_activation_unknown "$code"
    return 20
  fi
  persist_activation_summary stop "\"$code\"" || true
  emit_activation_stop "$code"
  return 10
}

emit_activation_pass() {
  validate_activation_evidence_bundle || {
    activation_finish_failure evidence_validation_failed
    return $?
  }
  printf '{"schema":"%s","verdict":"pass","server":"%s","workflow_id":"%s","evidence_directory":%s}\n' \
    "$ACTIVATION_SCHEMA" "$SERVER" "$ACTIVATION_WORKFLOW_ID" \
    "$(if [[ -n "$EVIDENCE_DIR" ]]; then "$JQ_BIN" -Rn --arg value "$EVIDENCE_DIR" '$value'; else printf 'null'; fi)"
}

emit_existing_stop() {
  printf '{"schema":"%s","verdict":"STOP","abort_code":"%s","server":"%s","workflow_id":"%s","version_id":"%s"}\n' \
    "$EXISTING_VERSION_SCHEMA" "${1:-unknown_stop}" "$SERVER" "$WORKFLOW_ID" "$VERSION_ID"
}

emit_existing_unknown() {
  printf '{"schema":"%s","verdict":"unknown","abort_code":"%s","server":"%s","workflow_id":"%s","version_id":"%s"}\n' \
    "$EXISTING_VERSION_SCHEMA" "${1:-unknown_outcome}" "$SERVER" "$WORKFLOW_ID" "$VERSION_ID"
}

emit_existing_pass() {
  local summary plan baseline publish publish_readback unpublish final_readback
  local publish_diagnostics unpublish_diagnostics
  for name in existing-version-plan existing-baseline existing-publish \
    existing-publish-diagnostics existing-publish-readback existing-unpublish \
    existing-unpublish-diagnostics existing-final-readback \
    transition-publish transition-unpublish summary; do
    validate_activation_record_file "$name" || {
      emit_existing_stop evidence_validation_failed
      return 10
    }
  done
  summary="$(read_activation_record summary)" || {
    emit_existing_stop evidence_validation_failed
    return 10
  }
  plan="$(read_activation_record existing-version-plan)" || return 10
  baseline="$(read_activation_record existing-baseline)" || return 10
  publish="$(read_activation_record existing-publish)" || return 10
  publish_readback="$(read_activation_record existing-publish-readback)" || return 10
  unpublish="$(read_activation_record existing-unpublish)" || return 10
  publish_diagnostics="$(read_activation_record existing-publish-diagnostics)" || return 10
  unpublish_diagnostics="$(read_activation_record existing-unpublish-diagnostics)" || return 10
  final_readback="$(read_activation_record existing-final-readback)" || return 10
  validate_existing_version_plan "$plan" \
    && validate_existing_baseline "$baseline" \
    && validate_existing_publish_invoke "$publish" \
    && validate_existing_invoke_diagnostics "$publish_diagnostics" existing-publish \
    && validate_existing_publish_readback "$publish_readback" \
    && validate_existing_unpublish_invoke "$unpublish" \
    && validate_existing_invoke_diagnostics "$unpublish_diagnostics" existing-unpublish \
    && validate_existing_final_readback "$final_readback" \
    && validate_activation_transition_record \
      "$(read_activation_record transition-publish)" publish \
      "$ACTIVATION_OPERATION" "$WORKFLOW_ID" existing-publish \
    && validate_activation_transition_record \
      "$(read_activation_record transition-unpublish)" unpublish \
      "$ACTIVATION_OPERATION" "$WORKFLOW_ID" existing-unpublish \
    || {
      emit_existing_stop evidence_validation_failed
      return 10
    }
  "$JQ_BIN" -e --arg server "$SERVER" --arg workflow "$WORKFLOW_ID" \
    --arg version "$VERSION_ID" \
    '.schema == "fwc.n8n.existing-version-acceptance.v1"
      and .verdict == "pass" and .evidence_complete == true
      and .server == $server and .workflow_id == $workflow
      and .version_id == $version and .publish_attempts == 1
      and .unpublish_attempts == 1 and .retries == 0
      and .baseline_status == 0 and .publish_status == 0
      and .publish_readback_status == 0 and .unpublish_status == 0
      and .final_readback_status == 0
      and .sequence == ["baseline_get_once","publish_approval_once",
        "publish_once","publish_independent_get_once",
        "unpublish_approval_once","unpublish_once",
        "unpublish_independent_get_once"]
      and .evidence_files == ["existing-version-plan.json",
        "existing-baseline.json","existing-publish.json",
        "existing-publish-diagnostics.json","existing-publish-readback.json",
        "existing-unpublish.json","existing-unpublish-diagnostics.json",
        "existing-final-readback.json","transition-publish.json",
        "transition-unpublish.json"]
      and .automatic_cleanup == false and .workflow_creation == false
      and .raw_provider_bodies_persisted == false
      and .raw_request_bodies_persisted == false
      and .tokens_persisted == false and .secrets_persisted == false' \
    <<<"$summary" >/dev/null 2>&1 || {
      emit_existing_stop evidence_validation_failed
      return 10
    }
  printf '{"schema":"%s","verdict":"pass","server":"%s","workflow_id":"%s","version_id":"%s","evidence_directory":%s}\n' \
    "$EXISTING_VERSION_SCHEMA" "$SERVER" "$WORKFLOW_ID" "$VERSION_ID" \
    "$("$JQ_BIN" -Rn --arg value "$EVIDENCE_DIR" '$value')"
}

usage() {
  cat <<'EOF'
Usage:
  n8n_unarchive_acceptance.sh --server eec|hetzner --workflow-id ID [options]
  n8n_unarchive_acceptance.sh eec ID [options]
  n8n_unarchive_acceptance.sh --activation --server eec|hetzner [options]
  n8n_unarchive_acceptance.sh --existing-version --server eec|hetzner \
    --workflow-id ID --version-id VERSION --evidence-dir DIR [options]
  n8n_unarchive_acceptance.sh --continue-unpublish --server eec|hetzner \
    --workflow-id ID --version-id VERSION --source-evidence-dir DIR \
    --evidence-dir DIR [options]
  n8n_unarchive_acceptance.sh --self-test
  n8n_unarchive_acceptance.sh --handoff-self-test
  n8n_unarchive_acceptance.sh --activation-self-test
  n8n_unarchive_acceptance.sh --activation-create-input-self-test
  n8n_unarchive_acceptance.sh --existing-version-self-test

Options:
  --launcher PATH         fwc-n8n launcher (default: /usr/local/bin/fwc-n8n)
  --approval-helper PATH  n8n_approval_once.sh (default: /home/ubuntu/Projects/flywheel_connectors/scripts/n8n_approval_once.sh)
  --parent-helper PATH    verified rc20 parent-binding path (exact path required)
  --evidence-dir DIR      redaction-safe evidence directory (required for acceptance modes)
  --help                  show this help

Production writes one short-lived approval request below the fixed
/var/lib/fwc-n8n/approval-requests root.  The request is root:root 0600.
The parent helper is invoked exactly once; no fallback or crypto is embedded.
Activation mode creates one disposable credential-free Webhook draft, then
performs one publish and one unpublish transition with independent readbacks;
it never invokes the Webhook or performs cleanup.
Existing-version mode explicitly publishes the selected existing draft version
once, then unpublishes only after exact independent readback and a fresh approval.
Continuation mode never repeats publish: it requires the prior unknown run's
durable active readback, obtains one fresh matching GET and one unpublish approval,
then permits one unpublish attempt only.
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

valid_version_id() {
  local trimmed="$1"
  trimmed="${trimmed#"${trimmed%%[![:space:]]*}"}"
  trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
  [[ -n "$1" && ${#1} -le 256 && "$trimmed" == "$1" \
    && "$1" != *[[:cntrl:]]* ]]
}

valid_executable() {
  [[ -n "$1" && -x "$1" ]]
}

valid_parent_helper() {
  # The parent-binding contract is provided only by the provisioned rc20
  # binary.  Do not allow an arbitrary executable override, even when it is
  # a regular non-symlink file; the guard must fail before any provider call.
  if (( SELF_TEST == 1 )); then
    [[ -x "$1" ]]
  else
    [[ "$1" == "$DEFAULT_PARENT_HELPER" && -x "$1" && ! -L "$1" ]]
  fi
}

build_activation_plan() {
  "$JQ_BIN" -cn \
    --arg server "$SERVER" \
    '{schema:"fwc.n8n.activation-acceptance-plan.v1",server:$server,
      server_order:["eec","hetzner"],
      sequence:["create_draft_once","draft_readback_once","publish_once",
        "publish_readback_once","active_readback_once","unpublish_once",
        "final_unpublish_get_once"],
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

build_existing_version_plan() {
  "$JQ_BIN" -cn --arg server "$SERVER" --arg workflow "$WORKFLOW_ID" \
    --arg version "$VERSION_ID" \
    '{schema:"fwc.n8n.existing-version-acceptance-plan.v1",
      mode:"explicit-existing-workflow-version",server:$server,
      workflow_id:$workflow,version_id:$version,
      sequence:["baseline_get_once","publish_approval_once",
        "publish_once","publish_independent_get_once",
        "unpublish_approval_once","unpublish_once",
        "unpublish_independent_get_once"],
      precondition:{active:false,activeVersionId:null,isArchived:false,
        published:null,draftVersionId:$version},
      limits:{publish_attempts:1,unpublish_attempts:1,retries:0,
        automatic_cleanup:false,workflow_creation:false,execution_attempts:0},
      evidence:{raw_provider_bodies:false,raw_request_bodies:false,
        tokens:false,secrets:false}}'
}

validate_existing_version_plan() {
  "$JQ_BIN" -e --arg server "$SERVER" --arg workflow "$WORKFLOW_ID" \
    --arg version "$VERSION_ID" '
      ((keys_unsorted | sort) ==
        ["evidence","limits","mode","precondition","schema","sequence",
         "server","version_id","workflow_id"])
      and .schema == "fwc.n8n.existing-version-acceptance-plan.v1"
      and .mode == "explicit-existing-workflow-version"
      and .server == $server and .workflow_id == $workflow
      and .version_id == $version
      and .sequence == ["baseline_get_once","publish_approval_once",
        "publish_once","publish_independent_get_once",
        "unpublish_approval_once","unpublish_once",
        "unpublish_independent_get_once"]
      and .precondition == {active:false,activeVersionId:null,
        isArchived:false,published:null,draftVersionId:$version}
      and .limits.publish_attempts == 1 and .limits.unpublish_attempts == 1
      and .limits.retries == 0 and .limits.automatic_cleanup == false
      and .limits.workflow_creation == false and .limits.execution_attempts == 0
      and (all(.evidence[]; . == false))
    ' <<<"$1" >/dev/null 2>&1
}

validate_existing_baseline() {
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" --arg version "$VERSION_ID" '
    .status == "ok" and .result.id == $workflow
    and .result.active == false and .result.activeVersionId == null
    and .result.isArchived == false and .result.published == null
    and .result.versionId == $version and .result.draft.versionId == $version
    and (.result.draft.graphDigest | type) == "string"
    and (.result.stateDigest | type) == "string"
  ' <<<"$1" >/dev/null 2>&1
}

validate_existing_publish_invoke() {
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" --arg version "$VERSION_ID" '
    .type == "response" and .status == "ok"
    and .result.status == "verified"
    and .result.operation == "n8n.workflows.activate"
    and .result.before.id == $workflow and .result.after.id == $workflow
    and .result.after.active == true
    and .result.after.activeVersionId == $version
    and .result.after.published.versionId == $version
    and .result.after.isArchived == false
  ' <<<"$1" >/dev/null 2>&1
}

validate_existing_publish_readback() {
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" --arg version "$VERSION_ID" \
    --arg graph "$EXISTING_GRAPH_DIGEST" '
    .status == "ok" and .result.id == $workflow
    and .result.active == true and .result.activeVersionId == $version
    and .result.published.versionId == $version
    and .result.versionId == $version and .result.draft.versionId == $version
    and .result.draft.graphDigest == $graph
    and .result.published.graphDigest == $graph
    and .result.isArchived == false
  ' <<<"$1" >/dev/null 2>&1
}

validate_existing_unpublish_invoke() {
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" '
    .type == "response" and .status == "ok"
    and .result.status == "verified"
    and .result.operation == "n8n.workflows.activate"
    and .result.before.id == $workflow and .result.after.id == $workflow
    and .result.after.active == false
    and .result.after.activeVersionId == null
    and .result.after.published == null
    and .result.after.isArchived == false
  ' <<<"$1" >/dev/null 2>&1
}

validate_existing_final_readback() {
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" --arg version "$VERSION_ID" \
    --arg graph "$EXISTING_GRAPH_DIGEST" '
    .status == "ok" and .result.id == $workflow
    and .result.active == false and .result.activeVersionId == null
    and .result.published == null and .result.isArchived == false
    and .result.versionId == $version and .result.draft.versionId == $version
    and .result.draft.graphDigest == $graph
  ' <<<"$1" >/dev/null 2>&1
}

read_secure_evidence_record() {
  local directory="$1"
  local name="$2"
  local path metadata
  [[ "$name" =~ ^[a-z0-9-]+$ && -d "$directory" && ! -L "$directory" ]] || return 1
  path="$directory/$name.json"
  [[ -f "$path" && ! -L "$path" ]] || return 1
  metadata="$("$STAT_BIN" -c '%a:%h:%F:%s' -- "$path" 2>/dev/null)" || return 1
  [[ "$metadata" =~ ^600:1:regular\ file:[1-9][0-9]*$ ]] || return 1
  cat -- "$path"
}

validate_prior_unknown_publish_summary() {
  "$JQ_BIN" -e --arg server "$SERVER" --arg workflow "$WORKFLOW_ID" \
    --arg version "$VERSION_ID" '
      .schema == "fwc.n8n.existing-version-acceptance.v1"
      and .server == $server and .workflow_id == $workflow
      and .version_id == $version
      and (.run_id | type) == "string"
      and (.run_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"))
      and .verdict == "unknown" and .abort_code == "publish_outcome_unknown"
      and .baseline_status == 0 and .publish_status == 0
      and .publish_readback_status == 0 and .publish_attempts == 1
      and .publish_helper_status == 0
      and .unpublish_attempts == 0 and .unpublish_status == 125
      and .final_readback_status == 125
      and .retries == 0 and .automatic_cleanup == false
      and .workflow_creation == false and .execution_attempts == 0
      and .raw_provider_bodies_persisted == false
      and .raw_request_bodies_persisted == false
      and .tokens_persisted == false and .secrets_persisted == false
    ' <<<"$1" >/dev/null 2>&1
}

validate_historical_flat_publish_projection() {
  "$JQ_BIN" -e '
    . == {type:null,status:"verified",error_code:null}
  ' <<<"$1" >/dev/null 2>&1
}

validate_existing_unpublish_source() {
  local directory_metadata
  local plan baseline publish readback
  if ! validate_production_evidence_path "$SOURCE_EVIDENCE_DIR"; then
    EXISTING_SOURCE_VALIDATION_EMITTED=1
    emit_existing_stop source_evidence_directory_not_durable
    return 1
  fi
  directory_metadata="$("$STAT_BIN" -c '%a:%F' -- "$SOURCE_EVIDENCE_DIR" 2>/dev/null)" || return 1
  [[ "$directory_metadata" == "700:directory" ]] || return 1
  [[ ! -e "$SOURCE_EVIDENCE_DIR/unpublish-attempt-claimed.json" \
    && ! -L "$SOURCE_EVIDENCE_DIR/unpublish-attempt-claimed.json" \
    && ! -e "$SOURCE_EVIDENCE_DIR/existing-unpublish.json" \
    && ! -L "$SOURCE_EVIDENCE_DIR/existing-unpublish.json" \
    && ! -e "$SOURCE_EVIDENCE_DIR/existing-final-readback.json" \
    && ! -L "$SOURCE_EVIDENCE_DIR/existing-final-readback.json" \
    && ! -e "$SOURCE_EVIDENCE_DIR/transition-unpublish.json" \
    && ! -L "$SOURCE_EVIDENCE_DIR/transition-unpublish.json" ]] || {
      EXISTING_SOURCE_VALIDATION_EMITTED=1
      emit_existing_stop source_unpublish_already_attempted
      return 1
    }
  EXISTING_PRIOR_SUMMARY="$(read_secure_evidence_record "$SOURCE_EVIDENCE_DIR" summary)" || {
    EXISTING_SOURCE_VALIDATION_EMITTED=1
    emit_existing_stop source_summary_unavailable
    return 1
  }
  validate_prior_unknown_publish_summary "$EXISTING_PRIOR_SUMMARY" || {
    EXISTING_SOURCE_VALIDATION_EMITTED=1
    emit_existing_stop source_publish_not_confirmed
    return 1
  }
  EXISTING_RUN_ID="$("$JQ_BIN" -er '.run_id' <<<"$EXISTING_PRIOR_SUMMARY")" || return 1
  RUN_ID="$EXISTING_RUN_ID"
  plan="$(read_secure_evidence_record "$SOURCE_EVIDENCE_DIR" existing-version-plan)" || return 1
  baseline="$(read_secure_evidence_record "$SOURCE_EVIDENCE_DIR" existing-baseline)" || return 1
  publish="$(read_secure_evidence_record "$SOURCE_EVIDENCE_DIR" existing-publish)" || return 1
  readback="$(read_secure_evidence_record "$SOURCE_EVIDENCE_DIR" existing-publish-readback)" || return 1
  validate_existing_version_plan "$plan" \
    && validate_existing_baseline "$baseline" \
    && validate_historical_flat_publish_projection "$publish" || {
      EXISTING_SOURCE_VALIDATION_EMITTED=1
      emit_existing_stop source_evidence_contract_failed
      return 1
    }
  EXISTING_GRAPH_DIGEST="$("$JQ_BIN" -er '.result.draft.graphDigest' <<<"$baseline")" || return 1
  EXISTING_STATE_DIGEST="$("$JQ_BIN" -er '.result.stateDigest' <<<"$baseline")" || return 1
  EXISTING_PRIOR_PUBLISH_STATE_DIGEST="$("$JQ_BIN" -er '.result.stateDigest' <<<"$readback")" || return 1
  validate_existing_state_digest "$EXISTING_STATE_DIGEST" \
    && validate_existing_state_digest "$EXISTING_PRIOR_PUBLISH_STATE_DIGEST" \
    && validate_existing_publish_readback "$readback" || {
      EXISTING_SOURCE_VALIDATION_EMITTED=1
      emit_existing_stop source_publish_readback_not_confirmed
      return 1
    }
}

copy_prior_existing_evidence() {
  local source_name="$1"
  local output_name="$2"
  local record
  record="$(read_secure_evidence_record "$SOURCE_EVIDENCE_DIR" "$source_name")" || return 1
  persist_activation_record "$output_name" "$record"
}

copy_unpublish_claim_to_output() {
  local claim
  claim="$(read_secure_evidence_record "$SOURCE_EVIDENCE_DIR" unpublish-attempt-claimed)" || return 1
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" --arg version "$VERSION_ID" \
    --arg run_id "$EXISTING_RUN_ID" '
      .schema == "fwc.n8n.existing-version-unpublish-claim.v1"
      and .workflow_id == $workflow and .version_id == $version
      and .run_id == $run_id and .operation == "n8n.workflows.activate"
      and .action == "unpublish" and .claim == "invoke_may_start_once"
    ' <<<"$claim" >/dev/null 2>&1 || return 1
  persist_activation_record unpublish-attempt-claim "$claim"
}

persist_existing_continuation_summary() {
  local verdict="$1"
  local code="$2"
  local summary
  summary="$("$JQ_BIN" -cn \
    --arg server "$SERVER" --arg workflow "$WORKFLOW_ID" \
    --arg version "$VERSION_ID" --arg run_id "$EXISTING_RUN_ID" \
    --arg source "$SOURCE_EVIDENCE_DIR" --arg verdict "$verdict" \
    --arg code "$code" \
    --argjson baseline_status "$ACTIVATION_BASELINE_STATUS" \
    --argjson continuation_baseline_status "$ACTIVATION_ACTIVE_STATUS" \
    --argjson unpublish_status "$ACTIVATION_UNPUBLISH_STATUS" \
    --argjson final_status "$FINAL_GET_STATUS" \
    --argjson unpublish_helper_status "$EXISTING_UNPUBLISH_HELPER_STATUS" \
    --argjson unpublish_attempted "$CONTINUATION_UNPUBLISH_ATTEMPTED" \
    '{schema:"fwc.n8n.existing-version-acceptance.v1",server:$server,
      workflow_id:$workflow,version_id:$version,run_id:$run_id,
      continued_from_run_id:$run_id,prior_evidence_directory:$source,
      verdict:$verdict,abort_code:$code,
      sequence:["prior_publish_independent_get_verified",
        "fresh_active_get_once","unpublish_approval_once","unpublish_once",
        "independent_get_once"],
      baseline_status:$baseline_status,publish_status:0,
      publish_readback_status:0,
      continuation_baseline_status:$continuation_baseline_status,
      unpublish_status:$unpublish_status,final_readback_status:$final_status,
      publish_attempts:1,unpublish_attempts:$unpublish_attempted,retries:0,
      unpublish_helper_status:$unpublish_helper_status,
      prior_publish_verdict:"unknown_readback_confirmed_state",
      raw_publish_invoke_projection:"historically_redacted_flat_response",
      automatic_cleanup:false,workflow_creation:false,execution_attempts:0,
      evidence_complete:($verdict == "pass"),
      evidence_files:["existing-version-plan.json","prior-summary.json",
        "prior-existing-version-plan.json","prior-existing-baseline.json",
        "prior-existing-publish.json","prior-existing-publish-readback.json",
        "existing-continuation-baseline.json","existing-unpublish.json",
        "existing-final-readback.json","unpublish-attempt-claim.json",
        "transition-unpublish.json"],
      raw_provider_bodies_persisted:false,raw_request_bodies_persisted:false,
      tokens_persisted:false,secrets_persisted:false}')" || return 1
  persist_activation_record summary "$summary"
}

persist_existing_summary() {
  local verdict="$1" code="$2"
  local summary
  summary="$("$JQ_BIN" -cn --arg server "$SERVER" --arg workflow "$WORKFLOW_ID" \
    --arg version "$VERSION_ID" --arg run_id "$EXISTING_RUN_ID" \
    --arg verdict "$verdict" --arg code "$code" \
    --arg publish_approval_abort_code "$EXISTING_PUBLISH_APPROVAL_ABORT_CODE" \
    --arg unpublish_approval_abort_code "$EXISTING_UNPUBLISH_APPROVAL_ABORT_CODE" \
    --argjson publish_status "$ACTIVATION_PUBLISH_STATUS" \
    --argjson unpublish_status "$ACTIVATION_UNPUBLISH_STATUS" \
    --argjson baseline_status "$ACTIVATION_BASELINE_STATUS" \
    --argjson publish_readback_status "$ACTIVATION_ACTIVE_STATUS" \
    --argjson final_readback_status "$FINAL_GET_STATUS" \
    --argjson publish_helper_status "$EXISTING_PUBLISH_HELPER_STATUS" \
    --argjson unpublish_helper_status "$EXISTING_UNPUBLISH_HELPER_STATUS" \
    '{schema:"fwc.n8n.existing-version-acceptance.v1",server:$server,
      workflow_id:$workflow,version_id:$version,run_id:$run_id,
      verdict:$verdict,abort_code:$code,
      sequence:["baseline_get_once","publish_approval_once","publish_once",
        "publish_independent_get_once","unpublish_approval_once",
        "unpublish_once","unpublish_independent_get_once"],
      publish_status:$publish_status,unpublish_status:$unpublish_status,
      baseline_status:$baseline_status,
      publish_readback_status:$publish_readback_status,
      final_readback_status:$final_readback_status,
      publish_helper_status:$publish_helper_status,
      unpublish_helper_status:$unpublish_helper_status,
      publish_attempts:(if $publish_helper_status == 0 then 1 else 0 end),
      unpublish_attempts:(if $unpublish_helper_status == 0 then 1 else 0 end),
      retries:0,automatic_cleanup:false,workflow_creation:false,
      execution_attempts:0,evidence_complete:($verdict == "pass"),
      evidence_files:["existing-version-plan.json","existing-baseline.json",
        "existing-publish.json","existing-publish-diagnostics.json",
        "existing-publish-readback.json","existing-unpublish.json",
        "existing-unpublish-diagnostics.json","existing-final-readback.json",
        "transition-publish.json","transition-unpublish.json"],
      raw_provider_bodies_persisted:false,raw_request_bodies_persisted:false,
      tokens_persisted:false,secrets_persisted:false}
      + (if $publish_approval_abort_code == "" then {}
         else {publish_approval_abort_code:$publish_approval_abort_code} end)
      + (if $unpublish_approval_abort_code == "" then {}
         else {unpublish_approval_abort_code:$unpublish_approval_abort_code} end)')" || return 1
  persist_activation_record summary "$summary"
}

persist_existing_projection() {
  local name="$1" projection="$2"
  persist_activation_record "existing-$name" "$projection"
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
      "final_unpublish_get_once"]
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

run_activation_runner_self_test() {
  local root scenario evidence log status output
  [[ -n "${ACTIVATION_TEST_ROOT:-}" && -d "$ACTIVATION_TEST_ROOT" ]] || return 1
  root="$ACTIVATION_TEST_ROOT/runner"
  mkdir -m 700 -- "$root" || return 1
  REQUEST_ROOT="$root/requests"
  mkdir -m 700 -- "$REQUEST_ROOT" || return 1
  cat >"$root/sudo" <<'EOF'
#!/usr/bin/env bash
set -u
[[ "${1:-}" == -n ]] || exit 64
shift
[[ "${1:-}" == /usr/bin/bash && "${2:-}" == -c ]] || exit 64
shift 2
exec /usr/bin/bash -c "$@"
EOF
  cat >"$root/approval" <<'EOF'
#!/usr/bin/env bash
set -u
[[ "${1:-}" == --request-file && -n "${2:-}" ]] || exit 64
request="$ACTIVATION_TEST_REQUESTS/$2"
/usr/bin/jq -e '
  .schema == "fwc.n8n.owner-approval-request.v1"
  and (.operation == "create_draft" or .operation == "activate")
  and (.input.guard.approvalRef | type) == "string"
  and (.input.guard.idempotencyKey | type) == "string"
' "$request" >/dev/null 2>&1 || exit 73
if [[ "$ACTIVATION_TEST_SCENARIO" == approval_failure ]]; then
  printf '%s\n' '{"schema":"fwc.n8n.approval-once.v1","verdict":"stop","abort_code":"invalid_seed"}' >&2
  exit 76
fi
if [[ "$ACTIVATION_TEST_SCENARIO" == preexisting_claim ]]; then
  printf '%s\n' '{}' >"$ACTIVATION_TEST_EVIDENCE/activation-claim-create.json"
  chmod 600 -- "$ACTIVATION_TEST_EVIDENCE/activation-claim-create.json"
fi
printf '%s\n' '"offline-stub-token"' >&3
EOF
  cat >"$root/parent" <<'EOF'
#!/usr/bin/env bash
set -u
[[ "$#" == 4 ]] || exit 92
printf '%064d\n' 1
EOF
  cat >"$root/launcher" <<'EOF'
#!/usr/bin/env bash
set -u
op="${2:-}"
body="$(cat)" || exit 80
printf_line() { printf '%s\n' "$1" >>"$ACTIVATION_TEST_LOG"; }
if [[ "$op" == n8n.workflows.get ]]; then
  n=0; [[ ! -f "$ACTIVATION_TEST_GETS" ]] || n="$(cat "$ACTIVATION_TEST_GETS")"
  n=$((n + 1)); printf '%s\n' "$n" >"$ACTIVATION_TEST_GETS"; printf_line get
  if [[ "$n" == 3 && "$ACTIVATION_TEST_SCENARIO" == final_get_failure ]]; then exit 44; fi
  active=false; av=null; pub=null; state=blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  if [[ "$n" == 2 || ( "$n" == 3 && "$ACTIVATION_TEST_SCENARIO" == final_get_mismatch ) ]]; then
    active=true; av='"selected-version"'; pub='{"versionId":"selected-version","graphDigest":"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    state=blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  fi
  /usr/bin/jq -cn --argjson active "$active" --argjson av "$av" --argjson pub "$pub" --arg state "$state" \
    '{type:"response",status:"ok",result:{id:"syntheticworkflow",versionId:"selected-version",active:$active,activeVersionId:$av,isArchived:false,stateDigest:$state,draft:{versionId:"selected-version",graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},published:$pub},private_canary:"PRIVATE-CANARY"}'
  exit 0
fi
if [[ "$op" == n8n.workflows.create_draft ]]; then
  printf_line create
  if [[ "$ACTIVATION_TEST_SCENARIO" == diagnostic_persist_failure ]]; then
    printf '%s\n' 'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network' \
      'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network token=PRIVATE-CANARY' >&2
    exit 42
  fi
  if [[ "$ACTIVATION_TEST_SCENARIO" == create_diagnostic ]]; then
    i=0
    while (( i < 128 )); do
      printf '%s\n' 'unrecognized diagnostic filler line that must be drained' >&2
      ((i += 1))
    done
    printf '%s\n' 'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network' \
      'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network token=PRIVATE-CANARY' >&2
    exit 42
  fi
  if [[ "$ACTIVATION_TEST_SCENARIO" == create_diagnostic_cap ]]; then
    i=0
    while (( i < 40 )); do
      printf '%s\n' 'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network' >&2
      ((i += 1))
    done
    i=0
    while (( i < 2048 )); do
      printf '%s\n' 'unrecognized diagnostic filler line that must be drained' >&2
      ((i += 1))
    done
    printf '%s\n' 'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network secret=PRIVATE-CANARY' >&2
    exit 42
  fi
  [[ "$ACTIVATION_TEST_SCENARIO" != create_ambiguous ]] || { printf '%s\n' '{"private_canary":"PRIVATE-CANARY"}'; exit 42; }
  if [[ "$ACTIVATION_TEST_SCENARIO" == evidence_persist_failure ]]; then
    mkdir -m 700 -- "$ACTIVATION_TEST_EVIDENCE/activation-create.json" || exit 84
  fi
  id="syntheticworkflow"
  [[ "$ACTIVATION_TEST_SCENARIO" != invalid_create_id ]] || id="invalid/workflow-id"
  /usr/bin/jq -cn --arg id "$id" '{type:"response",status:"ok",result:{status:"verified",operation:"n8n.workflows.create_draft",id:$id,versionId:"selected-version",graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",stateDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",active:false,activeVersionId:null,isArchived:false,published:null},private_canary:"PRIVATE-CANARY"}'
  exit 0
fi
[[ "$op" == n8n.workflows.activate ]] || exit 82
active="$(/usr/bin/jq -r '.input.active' <<<"$body")" || exit 83
if [[ "$active" == true ]]; then
  printf_line publish
  [[ "$ACTIVATION_TEST_SCENARIO" != publish_ambiguous ]] || { printf '%s\n' '{"private_canary":"PRIVATE-CANARY"}'; exit 42; }
  /usr/bin/jq -cn '{type:"response",status:"ok",result:{status:"verified",operation:"n8n.workflows.activate",active:true,before:{id:"syntheticworkflow"},after:{id:"syntheticworkflow",active:true,activeVersionId:"selected-version",isArchived:false,stateDigest:"blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",draft:{versionId:"selected-version",graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},published:{versionId:"selected-version",graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}},private_canary:"PRIVATE-CANARY"}'
else
  printf_line unpublish
  [[ "$ACTIVATION_TEST_SCENARIO" != unpublish_ambiguous ]] || { printf '%s\n' '{"private_canary":"PRIVATE-CANARY"}'; exit 43; }
  /usr/bin/jq -cn '{type:"response",status:"ok",result:{status:"verified",operation:"n8n.workflows.activate",active:false,before:{id:"syntheticworkflow"},after:{id:"syntheticworkflow",active:false,activeVersionId:null,isArchived:false,stateDigest:"blake3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",draft:{versionId:"selected-version",graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},published:null}},private_canary:"PRIVATE-CANARY"}'
fi
EOF
  chmod 700 -- "$root/sudo" "$root/approval" "$root/parent" "$root/launcher" || return 1
  HANDOFF_TEST_SUDO="$root/sudo"
  APPROVAL_HELPER_PATH="$root/approval"
  PARENT_HELPER_PATH="$root/parent"
  LAUNCHER_PATH="$root/launcher"
  export ACTIVATION_TEST_REQUESTS="$REQUEST_ROOT"
  for scenario in success create_ambiguous create_diagnostic create_diagnostic_cap diagnostic_persist_failure publish_ambiguous unpublish_ambiguous \
    invalid_create_id evidence_persist_failure approval_failure \
    final_get_failure final_get_mismatch preexisting_claim; do
    evidence="$root/evidence-$scenario"; log="$root/$scenario.log"
    export ACTIVATION_TEST_SCENARIO="$scenario" ACTIVATION_TEST_EVIDENCE="$evidence"
    export ACTIVATION_TEST_LOG="$log" ACTIVATION_TEST_GETS="$root/$scenario-gets"
    EVIDENCE_DIR="$evidence"
    if [[ "$scenario" == evidence_persist_failure ]]; then
      if ( SELF_TEST=1; ACTIVATION_MODE=1; SERVER=eec; ACTIVATION_WORKFLOW_ID=""; RUN_ID=""; \
        ACTIVATION_FINAL_STATUS=125; ACTIVATION_CREATE_STATUS=125; ACTIVATION_BASELINE_STATUS=125; \
        ACTIVATION_PUBLISH_STATUS=125; ACTIVATION_ACTIVE_STATUS=125; ACTIVATION_UNPUBLISH_STATUS=125; \
        HANDOFF_INVOKE_STARTED=0; run_activation_acceptance >"$root/$scenario-output" 2>/dev/null ); then
        status=0
      else
        status=$?
      fi
    elif ( SELF_TEST=1; ACTIVATION_MODE=1; SERVER=eec; ACTIVATION_WORKFLOW_ID=""; RUN_ID=""; \
      ACTIVATION_FINAL_STATUS=125; ACTIVATION_CREATE_STATUS=125; ACTIVATION_BASELINE_STATUS=125; \
      ACTIVATION_PUBLISH_STATUS=125; ACTIVATION_ACTIVE_STATUS=125; ACTIVATION_UNPUBLISH_STATUS=125; \
      HANDOFF_INVOKE_STARTED=0; run_activation_acceptance >"$root/$scenario-output" ); then
      status=0
    else
      status=$?
    fi
    output="$(cat -- "$root/$scenario-output")" || return 1
    if [[ "$scenario" == success ]]; then
      [[ "$status" == 0 && "$output" == *'"verdict":"pass"'* ]] || return 1
      [[ "$(cat -- "$log")" == $'create\nget\npublish\nget\nunpublish\nget' ]] || return 1
      "$JQ_BIN" -e '.final_status == 0 and .mutation_claims == ["activation-claim-create.json","activation-claim-publish.json","activation-claim-unpublish.json"]' "$evidence/summary.json" >/dev/null || return 1
    elif [[ "$scenario" == create_ambiguous ]]; then
      [[ "$status" == 20 && "$output" == *'"verdict":"unknown"'* && "$(cat "$log")" == create ]] || return 1
    elif [[ "$scenario" == create_diagnostic ]]; then
      [[ "$status" == 20 && "$output" == *'"verdict":"unknown"'* \
        && "$(cat "$log")" == create ]] || return 1
      "$JQ_BIN" -e '.labels == ["FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network"]' \
        "$evidence/activation-create-diagnostics.json" >/dev/null || return 1
      "$JQ_BIN" -e '.evidence_files | index("activation-create-diagnostics.json") != null' \
        "$evidence/summary.json" >/dev/null || return 1
      ! rg -q 'PRIVATE-CANARY|token=' "$evidence/activation-create-diagnostics.json" || return 1
    elif [[ "$scenario" == create_diagnostic_cap ]]; then
      [[ "$status" == 20 && "$(cat "$log")" == create ]] || return 1
      "$JQ_BIN" -e '.labels | length == 32 and all(.[]; . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network")' \
        "$evidence/activation-create-diagnostics.json" >/dev/null || return 1
      ! rg -q 'PRIVATE-CANARY|secret=' "$evidence/activation-create-diagnostics.json" || return 1
    elif [[ "$scenario" == diagnostic_persist_failure ]]; then
      [[ "$status" == 125 && "$output" == *'"verdict":"unknown"'* \
        && "$output" == *'"evidence_complete":false'* \
        && "$(cat "$log")" == create && ! -e "$evidence/activation-create.json" \
        && ! -e "$evidence/summary.json" ]] || return 1
    elif [[ "$scenario" == invalid_create_id || "$scenario" == evidence_persist_failure ]]; then
      [[ "$status" == 20 && "$output" == *'"verdict":"unknown"'* \
        && "$output" != *'"verdict":"pass"'* && "$(cat "$log")" == create ]] || return 1
      if [[ -f "$evidence/summary.json" ]]; then
        "$JQ_BIN" -e '.verdict == "unknown" and .evidence_complete == false' \
          "$evidence/summary.json" >/dev/null || return 1
      fi
    elif [[ "$scenario" == publish_ambiguous ]]; then
      [[ "$status" == 20 && "$output" == *'"verdict":"unknown"'* && "$(cat "$log")" == $'create\nget\npublish' ]] || return 1
    elif [[ "$scenario" == unpublish_ambiguous ]]; then
      [[ "$status" == 20 && "$output" == *'"verdict":"unknown"'* && "$(cat "$log")" == $'create\nget\npublish\nget\nunpublish' ]] || return 1
    elif [[ "$scenario" == approval_failure || "$scenario" == preexisting_claim ]]; then
      [[ "$status" == 10 && "$output" == *'"verdict":"STOP"'* && ! -s "$log" ]] || return 1
    else
      [[ "$status" == 20 && "$output" == *'"verdict":"unknown"'* ]] || return 1
      [[ "$(cat "$log")" == $'create\nget\npublish\nget\nunpublish\nget' ]] || return 1
      [[ -f "$evidence/activation-final-readback.json" ]] || return 1
    fi
    if [[ -d "$evidence" ]] && rg -q 'PRIVATE-CANARY|offline-stub-token|approval_token' "$evidence"; then return 1; fi
  done
  evidence="$root/evidence-reused"; mkdir -m 700 -- "$evidence" || return 1
  printf '%s\n' '{}' >"$evidence/activation-claim-create.json"
  chmod 600 -- "$evidence/activation-claim-create.json"
  EVIDENCE_DIR="$evidence"; ACTIVATION_TEST_SCENARIO=success; export ACTIVATION_TEST_SCENARIO
  if ( SELF_TEST=1; ACTIVATION_MODE=1; SERVER=eec; run_activation_acceptance >"$root/reused-output" ); then return 1; else status=$?; fi
  output="$(cat -- "$root/reused-output")" || return 1
  [[ "$status" == 10 && "$output" == *'"verdict":"STOP"'* && ! -s "$log" ]]
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
  ACTIVATION_TEST_ROOT="$root"
  trap 'if [[ -n "${ACTIVATION_TEST_ROOT:-}" && -d "$ACTIVATION_TEST_ROOT" ]]; then rm -r -- "$ACTIVATION_TEST_ROOT"; fi' EXIT
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
  run_activation_runner_self_test || return 1
  printf '{"schema":"%s","verdict":"pass","mode":"activation-self-test","acceptance":false,"provider_actions":0,"cases":23}\n' \
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
    def response_result:
      if (.type == "response") and (.status == "ok")
         and ((.error? // null) == null) and ((.result | type) == "object") then
        .result
      elif (.status == "verified")
           and (.operation == "n8n.workflows.activate")
           and ((.before | type) == "object") and ((.after | type) == "object") then
        .
      else null end;
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
    if (response_result | type) == "object" then
      response_result as $result
      | {type:"response", status:"ok", result:{
        status:($result.status // null), operation:($result.operation // null),
        id:($result.id // null), versionId:($result.versionId // null),
        graphDigest:($result.graphDigest // null),
        stateDigest:($result.stateDigest // null),
        active:(if ($result | has("active")) then $result.active else null end),
        activeVersionId:($result.activeVersionId // null),
        isArchived:(if ($result | has("isArchived")) then $result.isArchived else null end),
        draft:($result.draft | graph), published:($result.published | graph),
        before:($result.before | state), after:($result.after | state)}}
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
    validate_production_evidence_path || return 1
    # Activation evidence is a one-run receipt directory. mkdir without -p is
    # the atomic freshness check: an existing directory, claim, or receipt is
    # never reused or truncated by a later invocation.
    mkdir -- "$EVIDENCE_DIR" 2>/dev/null || return 1
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

validate_existing_state_digest() {
  [[ "$1" =~ ^blake3-256:[0-9A-Fa-f]{64}$ ]]
}

validate_production_evidence_path() {
  local evidence_path="${1:-$EVIDENCE_DIR}"
  local root="/srv/dev-ssd/fcp/nqm81.24"
  local relative component current
  local IFS=/

  (( SELF_TEST == 1 )) && return 0
  [[ "$evidence_path" == "$root"/* ]] || return 1
  relative="${evidence_path#"$root"/}"
  [[ "$relative" =~ ^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*$ ]] || return 1
  [[ -x /usr/bin/mountpoint ]] || return 1
  /usr/bin/mountpoint -q /srv/dev-ssd || return 1

  for current in /srv /srv/dev-ssd /srv/dev-ssd/fcp "$root"; do
    [[ -d "$current" && ! -L "$current" ]] || return 1
  done
  current="$root"
  for component in $relative; do
    current="$current/$component"
    [[ ! -L "$current" ]] || return 1
    if [[ -e "$current" ]]; then
      [[ -d "$current" ]] || return 1
    fi
  done
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

capture_existing_invoke_diagnostics() {
  local action="$1"
  local path
  local metadata
  local persisted
  case "$action" in
    existing-publish|existing-unpublish) ;;
    *) return 125 ;;
  esac
  [[ -n "$EVIDENCE_DIR" ]] || return 125
  path="$EVIDENCE_DIR/$action-diagnostics.json"
  [[ ! -e "$path" && ! -L "$path" ]] || return 125
  (
    umask 077
    set -o noclobber
    exec 3>"$path" || exit 125
    "$AWK_BIN" -v action="$action" '
      function allowed(line) {
        return line ~ /^FCP-N8N-HOST-ERROR-DETAIL\/v1 policy\.(approval|capability|deployment|network|lease|binding|decision|other)$/ ||
          line ~ /^FCP-N8N-HOST-ERROR-DETAIL\/v1 host\.other$/ ||
          line ~ /^FCP-N8N-INVOKE-DIAGNOSTIC\/v1 dispatch_(4xx|5xx|other)$/ ||
          line ~ /^FCP-N8N-INVOKE-DIAGNOSTIC\/v1 response_(protocol|auth|rate_limited|capability|zone|connector|resource|external_(4xx|5xx|other|unknown)|upstream_timeout|dependency_unavailable|internal)$/
      }
      BEGIN {
        count = 0
        printf "{\"schema\":\"fwc.n8n.existing-version-diagnostics.v1\",\"operation\":\"%s\",\"labels\":[", action
      }
      {
        if (count < 32 && allowed($0)) {
          if (count > 0) printf ","
          printf "\"%s\"", $0
          count++
        }
      }
      END { printf "]}\n" }
    ' <&0 >&3 || exit 125
    exec 3>&-
    chmod 600 -- "$path" || exit 125
    "$SYNC_BIN" -d "$path" "$EVIDENCE_DIR" >/dev/null 2>&1 || exit 125
    metadata="$("$STAT_BIN" -c '%u:%g:%a:%h:%F:%s' -- "$path" 2>/dev/null)" || exit 125
    [[ "$metadata" =~ ^[0-9]+:[0-9]+:600:1:regular\ file:[1-9][0-9]*$ ]] || exit 125
    persisted="$(cat -- "$path")" || exit 125
    "$JQ_BIN" -e --arg action "$action" '
      .schema == "fwc.n8n.existing-version-diagnostics.v1"
      and .operation == $action and (.labels | length) <= 32
      and all(.labels[]; . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.approval"
        or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.capability"
        or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.deployment"
        or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network"
        or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.lease"
        or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.binding"
        or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.decision"
        or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.other"
        or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 host.other"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 dispatch_4xx"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 dispatch_5xx"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 dispatch_other"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_protocol"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_auth"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_rate_limited"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_capability"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_zone"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_connector"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_resource"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_4xx"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_5xx"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_other"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_unknown"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_upstream_timeout"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_dependency_unavailable"
        or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_internal")
    ' <<<"$persisted" >/dev/null 2>&1 || exit 125
    if (( SELF_TEST == 1 )) \
      && { [[ "${EXISTING_TEST_SCENARIO:-}" == publish_diagnostic_persist_failure \
        && "$action" == existing-publish ]] \
        || [[ "${EXISTING_TEST_SCENARIO:-}" == unpublish_diagnostic_persist_failure \
          && "$action" == existing-unpublish ]]; }; then
      "$SYNC_BIN" -d "$EVIDENCE_DIR/.missing-diagnostic-sync-target" \
        >/dev/null 2>&1 || exit 125
      exit 125
    fi
  )
}

validate_existing_invoke_diagnostics() {
  local record="$1"
  local action="$2"
  "$JQ_BIN" -e --arg action "$action" '
    .schema == "fwc.n8n.existing-version-diagnostics.v1"
    and .operation == $action and (.labels | type) == "array"
    and (.labels | length) <= 32
    and all(.labels[]; test("^(FCP-N8N-HOST-ERROR-DETAIL/v1 policy\\.(approval|capability|deployment|network|lease|binding|decision|other)|FCP-N8N-HOST-ERROR-DETAIL/v1 host\\.other|FCP-N8N-INVOKE-DIAGNOSTIC/v1 dispatch_(4xx|5xx|other)|FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_(protocol|auth|rate_limited|capability|zone|connector|resource|external_(4xx|5xx|other|unknown)|upstream_timeout|dependency_unavailable|internal))$"))
  ' <<<"$record" >/dev/null 2>&1
}

capture_activation_create_diagnostics() {
  local path="$EVIDENCE_DIR/activation-create-diagnostics.json"
  [[ -n "$EVIDENCE_DIR" && ! -e "$path" ]] || return 125
  (
    set -o noclobber
    exec 3>"$path" || exit 125
    "$AWK_BIN" '
      function allowed(line) {
        return line ~ /^FCP-N8N-HOST-ERROR-DETAIL\/v1 policy\.(approval|capability|deployment|network|lease|binding|decision|other)$/ ||
          line ~ /^FCP-N8N-HOST-ERROR-DETAIL\/v1 host\.other$/ ||
          line ~ /^FCP-N8N-INVOKE-DIAGNOSTIC\/v1 dispatch_(4xx|5xx|other)$/ ||
          line ~ /^FCP-N8N-INVOKE-DIAGNOSTIC\/v1 response_(protocol|auth|rate_limited|capability|zone|connector|resource|external_(4xx|5xx|other|unknown)|upstream_timeout|dependency_unavailable|internal)$/
      }
      BEGIN {
        count = 0
        printf "{\"schema\":\"fwc.n8n.activation-diagnostics.v1\",\"operation\":\"create_draft\",\"labels\":["
      }
      {
        if (count < 32 && allowed($0)) {
          if (count > 0) printf ","
          printf "\"%s\"", $0
          count++
        }
      }
      END { printf "]}\n" }
    ' <&0 >&3 || exit 125
    exec 3>&-
    chmod 600 -- "$path" || exit 125
    "$SYNC_BIN" -d "$path" "$EVIDENCE_DIR" >/dev/null 2>&1 || exit 125
    if [[ "${ACTIVATION_TEST_SCENARIO:-}" == diagnostic_persist_failure ]]; then
      "$SYNC_BIN" -d "$EVIDENCE_DIR/.missing-diagnostic-sync-target" \
        >/dev/null 2>&1 || exit 125
      exit 125
    fi
  )
}

capture_approval_abort_code() {
  local helper_status="$1"
  APPROVAL_ABORT_CODE=""
  case "$helper_status" in
    201) APPROVAL_ABORT_CODE=clock_failed ;;
    202) APPROVAL_ABORT_CODE=clock_invalid ;;
    203) APPROVAL_ABORT_CODE=expiry_not_13_digits ;;
    204) APPROVAL_ABORT_CODE=expiry_not_integer ;;
    205) APPROVAL_ABORT_CODE=expiry_over_60s ;;
    206) APPROVAL_ABORT_CODE=expiry_stale ;;
    207) APPROVAL_ABORT_CODE=invalid_request_file ;;
    208) APPROVAL_ABORT_CODE=invalid_request_json ;;
    209) APPROVAL_ABORT_CODE=issuer_failed ;;
    210) APPROVAL_ABORT_CODE=issuer_unavailable ;;
    211) APPROVAL_ABORT_CODE=public_key_unavailable ;;
    212) APPROVAL_ABORT_CODE=request_busy ;;
    213) APPROVAL_ABORT_CODE=request_changed ;;
    214) APPROVAL_ABORT_CODE=request_digest_failed ;;
    215) APPROVAL_ABORT_CODE=request_unreadable ;;
    216) APPROVAL_ABORT_CODE=safe_plan_mismatch ;;
    217) APPROVAL_ABORT_CODE=secret_reader_unavailable ;;
    218) APPROVAL_ABORT_CODE=invalid_arguments ;;
    219) APPROVAL_ABORT_CODE=internal_error ;;
    220) APPROVAL_ABORT_CODE=secret_reader_failed ;;
    221) APPROVAL_ABORT_CODE=seed_decode_failed ;;
    222) APPROVAL_ABORT_CODE=invalid_request ;;
    223) APPROVAL_ABORT_CODE=invalid_seed ;;
    224) APPROVAL_ABORT_CODE=trusted_key_unavailable ;;
    225) APPROVAL_ABORT_CODE=untrusted_seed ;;
    226) APPROVAL_ABORT_CODE=signing_failed ;;
    227) APPROVAL_ABORT_CODE=output_failed ;;
    *) return 1 ;;
  esac
}

write_preinvoke_claim() {
  local metadata
  local persisted
  [[ -n "$PREINVOKE_CLAIM_PATH" && -n "$PREINVOKE_CLAIM_JSON" ]] || return 1
  [[ "$PREINVOKE_CLAIM_PATH" == "$SOURCE_EVIDENCE_DIR/unpublish-attempt-claimed.json" ]] || return 1
  [[ ! -e "$PREINVOKE_CLAIM_PATH" && ! -L "$PREINVOKE_CLAIM_PATH" ]] || return 1
  "$JQ_BIN" -e --arg workflow "$WORKFLOW_ID" --arg version "$VERSION_ID" \
    --arg run_id "$EXISTING_RUN_ID" '
    .schema == "fwc.n8n.existing-version-unpublish-claim.v1"
    and .workflow_id == $workflow and .version_id == $version
    and .run_id == $run_id and .operation == "n8n.workflows.activate"
    and .action == "unpublish" and .claim == "invoke_may_start_once"
  ' <<<"$PREINVOKE_CLAIM_JSON" >/dev/null 2>&1 || return 1
  (
    umask 077
    set -o noclobber
    printf '%s\n' "$PREINVOKE_CLAIM_JSON" >"$PREINVOKE_CLAIM_PATH"
  ) || return 1
  chmod 600 -- "$PREINVOKE_CLAIM_PATH" || return 1
  "$SYNC_BIN" -d "$PREINVOKE_CLAIM_PATH" "$SOURCE_EVIDENCE_DIR" >/dev/null 2>&1 || return 1
  metadata="$(/usr/bin/stat -c '%a:%h:%F:%s' -- "$PREINVOKE_CLAIM_PATH" 2>/dev/null)" || return 1
  [[ "$metadata" =~ ^600:1:regular\ file:[1-9][0-9]*$ ]] || return 1
  persisted="$(cat -- "$PREINVOKE_CLAIM_PATH")" || return 1
  [[ "$persisted" == "$PREINVOKE_CLAIM_JSON" ]]
}

write_activation_claim() {
  local action="$1"
  local workflow_id="$2"
  local path metadata persisted
  [[ "$action" == create || "$action" == publish || "$action" == unpublish ]] || return 1
  [[ -n "$EVIDENCE_DIR" && -n "$RUN_ID" && -n "$HANDOFF_CORRELATION_ID" ]] || return 1
  [[ "$workflow_id" == "" || "$workflow_id" == "$ACTIVATION_WORKFLOW_ID" ]] || return 1
  path="$EVIDENCE_DIR/activation-claim-$action.json"
  [[ ! -e "$path" && ! -L "$path" ]] || return 1
  ACTIVATION_CLAIM_JSON="$("$JQ_BIN" -cn \
    --arg server "$SERVER" --arg run_id "$RUN_ID" \
    --arg correlation "$HANDOFF_CORRELATION_ID" \
    --arg operation "$HANDOFF_OPERATION" --arg action "$action" \
    --arg workflow "$workflow_id" --arg resource "$HANDOFF_RESOURCE_URI" \
    --argjson input "$HANDOFF_INPUT" \
    '{schema:"fwc.n8n.activation-mutation-claim.v1",server:$server,
      run_id:$run_id,correlation_id:$correlation,operation:$operation,
      action:$action,claim:"invoke_may_start_once",
      target:{workflow_id:(if $workflow == "" then null else $workflow end),
        resource_uri:$resource,
        idempotency_key:($input.guard.idempotencyKey // null),
        workflow_name:(if $action == "create" then $input.name else null end),
        webhook_path:(if $action == "create" then $input.graph.nodes[0].parameters.path else null end)},
      raw_provider_bodies_persisted:false,
      raw_request_bodies_persisted:false,tokens_persisted:false,secrets_persisted:false}')" || return 1
  "$JQ_BIN" -e --arg server "$SERVER" --arg run_id "$RUN_ID" \
    --arg correlation "$HANDOFF_CORRELATION_ID" \
    --arg operation "$HANDOFF_OPERATION" --arg action "$action" \
    --arg workflow "$workflow_id" --arg resource "$HANDOFF_RESOURCE_URI" '
      .schema == "fwc.n8n.activation-mutation-claim.v1"
      and .server == $server and .run_id == $run_id
      and .correlation_id == $correlation and .operation == $operation
      and .action == $action and .claim == "invoke_may_start_once"
      and .target.workflow_id == (if $workflow == "" then null else $workflow end)
      and .target.resource_uri == $resource
      and .raw_provider_bodies_persisted == false
      and .raw_request_bodies_persisted == false
      and .tokens_persisted == false and .secrets_persisted == false
    ' <<<"$ACTIVATION_CLAIM_JSON" >/dev/null 2>&1 || return 1
  (
    umask 077
    set -o noclobber
    printf '%s\n' "$ACTIVATION_CLAIM_JSON" >"$path"
  ) || return 1
  chmod 600 -- "$path" || return 1
  "$SYNC_BIN" -d "$path" "$EVIDENCE_DIR" >/dev/null 2>&1 || return 1
  metadata="$("$STAT_BIN" -c '%u:%g:%a:%h:%F:%s' -- "$path" 2>/dev/null)" || return 1
  [[ "$metadata" =~ ^[0-9]+:[0-9]+:600:1:regular\ file:[1-9][0-9]*$ ]] || return 1
  persisted="$(cat -- "$path")" || return 1
  [[ "$persisted" == "$ACTIVATION_CLAIM_JSON" ]] || return 1
  "$JQ_BIN" -e . <<<"$persisted" >/dev/null 2>&1 || return 1
  ACTIVATION_CLAIM_PATH="$path"
}

approval_fd3_handoff() {
  local basename="$1"
  local reader_fd
  local reader_pipe_fd
  local writer_fd
  local reader_pid
  local helper_status
  local helper_status_for_abort
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
  APPROVAL_ABORT_CODE=""
  HANDOFF_INVOKE_STARTED=0
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
  reader_pipe_fd="${FWC_APPROVAL_READER[0]}"
  writer_fd="${FWC_APPROVAL_READER[1]}"
  reader_pid="$FWC_APPROVAL_READER_PID"
  exec {reader_fd}<&"$reader_pipe_fd"
  exec {reader_pipe_fd}<&-
  exec 3>&"$writer_fd"
  exec {writer_fd}>&-

  if "$sudo_bin" -n /usr/bin/bash -c '
      set -o pipefail
      exec 3>&1
      if diagnostic_code=$("$1" --signal=TERM --kill-after=2s "$2" "$3" \
          --request-file "$4" 2>&1 1>&3 | "$5" "$6"); then
        exit 0
      else
        helper_status=$?
      fi
      case "$diagnostic_code" in
        clock_failed) exit 201 ;;
        clock_invalid) exit 202 ;;
        expiry_not_13_digits) exit 203 ;;
        expiry_not_integer) exit 204 ;;
        expiry_over_60s) exit 205 ;;
        expiry_stale) exit 206 ;;
        invalid_request_file) exit 207 ;;
        invalid_request_json) exit 208 ;;
        issuer_failed) exit 209 ;;
        issuer_unavailable) exit 210 ;;
        public_key_unavailable) exit 211 ;;
        request_busy) exit 212 ;;
        request_changed) exit 213 ;;
        request_digest_failed) exit 214 ;;
        request_unreadable) exit 215 ;;
        safe_plan_mismatch) exit 216 ;;
        secret_reader_unavailable) exit 217 ;;
        invalid_arguments) exit 218 ;;
        internal_error) exit 219 ;;
        secret_reader_failed) exit 220 ;;
        seed_decode_failed) exit 221 ;;
        invalid_request) exit 222 ;;
        invalid_seed) exit 223 ;;
        trusted_key_unavailable) exit 224 ;;
        untrusted_seed) exit 225 ;;
        signing_failed) exit 226 ;;
        output_failed) exit 227 ;;
        *) exit "$helper_status" ;;
      esac
    ' _ "$TIMEOUT_BIN" "${APPROVAL_TIMEOUT_SECONDS}s" \
    "$APPROVAL_HELPER_PATH" "$basename" "$AWK_BIN" \
    'NR == 1 && $0 ~ /^\{"schema":"fwc\.n8n\.approval-once\.v1","verdict":"stop","abort_code":"(clock_failed|clock_invalid|expiry_not_13_digits|expiry_not_integer|expiry_over_60s|expiry_stale|invalid_request_file|invalid_request_json|issuer_failed|issuer_unavailable|public_key_unavailable|request_busy|request_changed|request_digest_failed|request_unreadable|safe_plan_mismatch|secret_reader_unavailable|secret_reader_failed|seed_decode_failed|invalid_request|invalid_seed|trusted_key_unavailable|untrusted_seed|signing_failed|output_failed|invalid_arguments|internal_error)"\}$/ { code=$0; sub(/^.*"abort_code":"/, "", code); sub(/"}$/, "", code) } END { if (NR == 1 && code != "") print code }' \
    1>&3 2>/dev/null; then
    helper_status=0
  else
    helper_status=$?
    helper_status_for_abort="$helper_status"
    if capture_approval_abort_code "$helper_status_for_abort"; then
      helper_status=1
    fi
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
  if [[ -n "$PREINVOKE_CLAIM_PATH" ]] && ! write_preinvoke_claim; then
    cat <&"$invoke_reader_fd" >/dev/null 2>/dev/null || true
    if wait "$reader_pid"; then
      reader_status=0
    else
      reader_status=$?
    fi
    APPROVAL_READER_STATUS="$reader_status"
    exec {invoke_reader_fd}<&-
    exec {reader_fd}<&-
    return 1
  fi
  if (( ACTIVATION_MODE == 1 )); then
    local claim_action="$HANDOFF_EVIDENCE_NAME"
    local claim_workflow="$HANDOFF_WORKFLOW_ID"
    if [[ "$claim_action" == create ]]; then
      claim_workflow=""
    fi
    if (( EXISTING_VERSION_MODE == 0 && CONTINUE_UNPUBLISH_MODE == 0 )) \
      && ! write_activation_claim "$claim_action" "$claim_workflow"; then
      cat <&"$invoke_reader_fd" >/dev/null 2>/dev/null || true
      if wait "$reader_pid"; then reader_status=0; else reader_status=$?; fi
      APPROVAL_READER_STATUS="$reader_status"
      exec {invoke_reader_fd}<&-
      exec {reader_fd}<&-
      return 1
    fi
    HANDOFF_INVOKE_STARTED=1
    if (( EXISTING_VERSION_MODE == 0 && CONTINUE_UNPUBLISH_MODE == 0 )); then
      ACTIVATION_MUTATION_MAY_HAVE_STARTED=1
    fi
    coproc FWC_ACTIVATION_INVOKE {
      run_activation_once "$invoke_reader_fd";
    }
    invoke_fd="${FWC_ACTIVATION_INVOKE[0]}"
    invoke_pid="$FWC_ACTIVATION_INVOKE_PID"
  else
    HANDOFF_INVOKE_STARTED=1
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
  if (( EXISTING_VERSION_MODE == 1 && CONTINUE_UNPUBLISH_MODE == 0 )) \
    && [[ "$HANDOFF_EVIDENCE_NAME" == existing-publish \
      || "$HANDOFF_EVIDENCE_NAME" == existing-unpublish ]] \
    && (( invoke_status == 124 )); then
    EXISTING_DIAGNOSTIC_CAPTURE_FAILED=1
    invoke_status=125
  fi
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
  local status
  local -a pipeline_status=()
  if [[ "$HANDOFF_EVIDENCE_NAME" == create ]]; then
    exec 3>&1 || return 125
    "$JQ_BIN" -cn --slurpfile approval /dev/stdin \
      --arg server "$SERVER" --argjson input "$HANDOFF_INPUT" \
      --arg correlation "$HANDOFF_CORRELATION_ID" --argjson deadline "$HANDOFF_DEADLINE_MS" \
      '{server_id:$server,input:$input,approval_token:$approval[0],
        deadline_ms:$deadline,correlation_id:$correlation}' <&"$approval_reader_fd" |
      "$LAUNCHER_PATH" run-once "$HANDOFF_OPERATION" \
        4>&3 2>&1 1>&4 |
      capture_activation_create_diagnostics
    status=$?
    exec 3>&-
    return "$status"
  fi
  if (( EXISTING_VERSION_MODE == 1 && CONTINUE_UNPUBLISH_MODE == 0 )) \
    && [[ "$HANDOFF_EVIDENCE_NAME" == existing-publish \
      || "$HANDOFF_EVIDENCE_NAME" == existing-unpublish ]]; then
    exec 3>&1 || return 124
    "$JQ_BIN" -cn --slurpfile approval /dev/stdin \
        --arg server "$SERVER" --argjson input "$HANDOFF_INPUT" \
        --arg correlation "$HANDOFF_CORRELATION_ID" --argjson deadline "$HANDOFF_DEADLINE_MS" \
        '{server_id:$server,input:$input,approval_token:$approval[0],
          deadline_ms:$deadline,correlation_id:$correlation}' <&"$approval_reader_fd" |
      "$LAUNCHER_PATH" run-once "$HANDOFF_OPERATION" \
        4>&3 2>&1 1>&4 |
      capture_existing_invoke_diagnostics "$HANDOFF_EVIDENCE_NAME"
    pipeline_status=("${PIPESTATUS[@]}")
    exec 3>&-
    if (( ${pipeline_status[2]:-125} != 0 )); then
      return 124
    fi
    status="${pipeline_status[1]:-125}"
    # Reserve 124 for diagnostic capture failure and normalize colliding
    # launcher exits so the parent can distinguish the sticky stop condition.
    (( status == 124 || status == 125 )) && status=1
    return "$status"
  fi
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

validate_activation_final_readback() {
  "$JQ_BIN" -e --arg workflow "$ACTIVATION_WORKFLOW_ID" \
    --arg version "$ACTIVATION_VERSION_ID" --arg graph "$ACTIVATION_GRAPH_DIGEST" '
    .status == "ok" and .result.id == $workflow
    and .result.versionId == $version
    and .result.draft.versionId == $version
    and .result.draft.graphDigest == $graph
    and .result.active == false and .result.activeVersionId == null
    and .result.published == null and .result.isArchived == false
  ' <<<"$1" >/dev/null 2>&1
}

validate_activation_claim_record() {
  local record="$1" action="$2" operation="$3" workflow="$4"
  local resource="$5" correlation="$6"
  "$JQ_BIN" -e --arg server "$SERVER" --arg run_id "$RUN_ID" \
    --arg action "$action" --arg operation "$operation" \
    --arg workflow "$workflow" --arg resource "$resource" \
    --arg correlation "$correlation" '
      .schema == "fwc.n8n.activation-mutation-claim.v1"
      and .server == $server and .run_id == $run_id
      and .correlation_id == $correlation
      and (.correlation_id | test("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"))
      and .operation == $operation and .action == $action
      and .claim == "invoke_may_start_once"
      and .target.workflow_id == (if $workflow == "" then null else $workflow end)
      and .target.resource_uri == $resource
      and (.target.idempotency_key | type) == "string"
      and (if $action == "create"
           then (.target.workflow_name | type) == "string"
             and (.target.webhook_path | type) == "string"
           else .target.workflow_name == null and .target.webhook_path == null end)
      and .raw_provider_bodies_persisted == false
      and .raw_request_bodies_persisted == false
      and .tokens_persisted == false and .secrets_persisted == false
    ' <<<"$record" >/dev/null 2>&1
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
        "unpublish_once","final_unpublish_get_once"]
      and .evidence_files == ["activation-plan.json","activation-create.json",
        "activation-baseline.json","activation-publish.json",
        "activation-active.json","activation-unpublish.json",
        "activation-final-readback.json","activation-create-diagnostics.json"]
      and .transition_records == ["transition-create.json",
        "transition-publish.json","transition-unpublish.json"]
      and .mutation_claims == ["activation-claim-create.json",
        "activation-claim-publish.json","activation-claim-unpublish.json"]
      and .retries == 0 and .automatic_cleanup == false
      and .webhook_invoked == false
      and .raw_provider_bodies_persisted == false
      and .raw_request_bodies_persisted == false
      and .tokens_persisted == false and .secrets_persisted == false
      and (if $verdict == "pass"
           then .evidence_complete == true
             and .create_status == 0 and .baseline_status == 0
             and .publish_status == 0 and .active_status == 0
             and .unpublish_status == 0 and .final_status == 0
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
  local final_readback
  local claim_create claim_publish claim_unpublish
  local transition_create transition_publish transition_unpublish
  local create_diagnostics
  local summary

  (( ACTIVATION_MODE == 1 )) || return 1
  [[ -n "$EVIDENCE_DIR" ]] || return 1
  for name in activation-plan activation-create activation-create-diagnostics activation-baseline \
    activation-publish activation-active activation-unpublish \
    activation-final-readback activation-claim-create \
    activation-claim-publish activation-claim-unpublish \
    transition-create transition-publish transition-unpublish summary; do
    validate_activation_record_file "$name" || return 1
  done
  plan="$(read_activation_record activation-plan)" || return 1
  create="$(read_activation_record activation-create)" || return 1
  baseline="$(read_activation_record activation-baseline)" || return 1
  publish="$(read_activation_record activation-publish)" || return 1
  active="$(read_activation_record activation-active)" || return 1
  unpublish="$(read_activation_record activation-unpublish)" || return 1
  final_readback="$(read_activation_record activation-final-readback)" || return 1
  claim_create="$(read_activation_record activation-claim-create)" || return 1
  claim_publish="$(read_activation_record activation-claim-publish)" || return 1
  claim_unpublish="$(read_activation_record activation-claim-unpublish)" || return 1
  transition_create="$(read_activation_record transition-create)" || return 1
  transition_publish="$(read_activation_record transition-publish)" || return 1
  transition_unpublish="$(read_activation_record transition-unpublish)" || return 1
  create_diagnostics="$(read_activation_record activation-create-diagnostics)" || return 1
  summary="$(read_activation_record summary)" || return 1
  validate_activation_plan "$plan" || return 1
  validate_activation_create "$create" || return 1
  validate_activation_baseline "$baseline" || return 1
  validate_activation_publish "$publish" || return 1
  validate_activation_active_readback "$active" || return 1
  validate_activation_unpublish "$unpublish" || return 1
  validate_activation_final_readback "$final_readback" || return 1
  "$JQ_BIN" -e '
    .schema == "fwc.n8n.activation-diagnostics.v1"
    and .operation == "create_draft"
    and (.labels | type) == "array" and (.labels | length) <= 32
    and all(.labels[];
      . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.approval"
      or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.capability"
      or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.deployment"
      or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network"
      or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.lease"
      or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.binding"
      or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.decision"
      or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.other"
      or . == "FCP-N8N-HOST-ERROR-DETAIL/v1 host.other"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 dispatch_4xx"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 dispatch_5xx"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 dispatch_other"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_protocol"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_auth"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_rate_limited"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_capability"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_zone"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_connector"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_resource"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_4xx"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_5xx"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_other"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_unknown"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_upstream_timeout"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_dependency_unavailable"
      or . == "FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_internal")
  ' <<<"$create_diagnostics" >/dev/null || return 1
  validate_activation_transition_record \
    "$transition_create" create \
    "$ACTIVATION_CREATE_OPERATION" "$ACTIVATION_WORKFLOW_ID" activation-create || return 1
  validate_activation_transition_record \
    "$transition_publish" publish \
    "$ACTIVATION_OPERATION" "$ACTIVATION_WORKFLOW_ID" activation-publish || return 1
  validate_activation_transition_record \
    "$transition_unpublish" unpublish \
    "$ACTIVATION_OPERATION" "$ACTIVATION_WORKFLOW_ID" activation-unpublish || return 1
  validate_activation_claim_record "$claim_create" create \
    "$ACTIVATION_CREATE_OPERATION" "" "fwc-n8n://$SERVER" \
    "$("$JQ_BIN" -er '.correlation_id' <<<"$transition_create")" || return 1
  validate_activation_claim_record "$claim_publish" publish \
    "$ACTIVATION_OPERATION" "$ACTIVATION_WORKFLOW_ID" \
    "fwc-n8n://$SERVER/workflows/$ACTIVATION_WORKFLOW_ID" \
    "$("$JQ_BIN" -er '.correlation_id' <<<"$transition_publish")" || return 1
  validate_activation_claim_record "$claim_unpublish" unpublish \
    "$ACTIVATION_OPERATION" "$ACTIVATION_WORKFLOW_ID" \
    "fwc-n8n://$SERVER/workflows/$ACTIVATION_WORKFLOW_ID" \
    "$("$JQ_BIN" -er '.correlation_id' <<<"$transition_unpublish")" || return 1
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

  HANDOFF_INVOKE_STARTED=0
  correlation_id="$(uuid)" || return 1
  HANDOFF_OPERATION="$operation"
  HANDOFF_INPUT="$input_json"
  HANDOFF_CORRELATION_ID="$correlation_id"
  HANDOFF_DEADLINE_MS="$DEADLINE_MS"
  HANDOFF_EVIDENCE_NAME="$evidence_name"
  HANDOFF_RESOURCE_URI="$resource_uri"
  HANDOFF_WORKFLOW_ID="$workflow_id"
  if (( EXISTING_VERSION_MODE == 1 && CONTINUE_UNPUBLISH_MODE == 0 )) \
    && [[ "$evidence_name" == existing-publish \
      || "$evidence_name" == existing-unpublish ]]; then
    if [[ -z "$EVIDENCE_DIR" \
      || -e "$EVIDENCE_DIR/$evidence_name-diagnostics.json" \
      || -L "$EVIDENCE_DIR/$evidence_name-diagnostics.json" ]]; then
      EXISTING_DIAGNOSTIC_CAPTURE_FAILED=1
      INVOCATION_STATUS=125
      return 1
    fi
  fi
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

existing_version_preflight() {
  if ! valid_server "$SERVER" || ! valid_workflow_id "$WORKFLOW_ID" \
    || [[ -z "$VERSION_ID" || ${#VERSION_ID} -gt 256 ]] \
    || ! "$JQ_BIN" -en --arg value "$VERSION_ID" \
      '$value == ($value | gsub("^[[:space:]]+|[[:space:]]+$"; ""))
       and ($value | test("[[:cntrl:]]") | not)' >/dev/null; then
    emit_existing_stop invalid_target
    return 1
  fi
  if ! validate_production_evidence_path; then
    emit_existing_stop evidence_directory_not_durable
    return 1
  fi
  if [[ ! -x "$JQ_BIN" || ! -x "$AWK_BIN" || ! -x "$STAT_BIN" \
    || ! -x "$UUIDGEN_BIN" || ! -x "$TIMEOUT_BIN" || ! -x "$SYNC_BIN" ]]; then
    emit_existing_stop dependency_missing
    return 1
  fi
  if ! valid_executable "$LAUNCHER_PATH"; then
    emit_existing_stop launcher_unavailable
    return 1
  fi
  if ! valid_executable "$APPROVAL_HELPER_PATH"; then
    emit_existing_stop approval_helper_unavailable
    return 1
  fi
  if ! valid_parent_helper "$PARENT_HELPER_PATH"; then
    emit_existing_stop parent_helper_unavailable
    return 1
  fi
  if [[ -e "$EVIDENCE_DIR" || -L "$EVIDENCE_DIR" ]]; then
    emit_existing_stop evidence_directory_not_fresh
    return 1
  fi
  if ! init_evidence; then
    emit_existing_stop evidence_directory_unavailable
    return 1
  fi
  ACTIVATION_PLAN="$(build_existing_version_plan)" || {
    emit_existing_stop plan_build_failed
    return 1
  }
  if ! validate_existing_version_plan "$ACTIVATION_PLAN" \
    || ! persist_activation_record existing-version-plan "$ACTIVATION_PLAN"; then
    emit_existing_stop plan_contract_failed
    return 1
  fi
}

stop_existing_diagnostic_capture_failed() {
  if (( HANDOFF_INVOKE_STARTED == 1 )); then
    case "$HANDOFF_EVIDENCE_NAME" in
      existing-publish) EXISTING_PUBLISH_HELPER_STATUS=0 ;;
      existing-unpublish) EXISTING_UNPUBLISH_HELPER_STATUS=0 ;;
    esac
    persist_existing_summary unknown diagnostic_capture_failed_ambiguous || true
    emit_existing_unknown diagnostic_capture_failed_ambiguous
  else
    persist_existing_summary stop diagnostic_capture_failed || true
    emit_existing_stop diagnostic_capture_failed
  fi
  return 125
}

run_existing_version_acceptance() {
  local baseline_input publish_ref publish_key unpublish_ref unpublish_key
  local preinvoke_code
  local baseline_state active_state
  EXISTING_VERSION_MODE=1
  ACTIVATION_MODE=1
  ACTIVATION_BASELINE_STATUS=125
  ACTIVATION_ACTIVE_STATUS=125
  ACTIVATION_PUBLISH_STATUS=125
  ACTIVATION_UNPUBLISH_STATUS=125
  ACTIVATION_BASELINE_STATUS=125
  ACTIVATION_ACTIVE_STATUS=125
  FINAL_GET_STATUS=125
  EXISTING_PUBLISH_HELPER_STATUS=125
  EXISTING_PUBLISH_APPROVAL_ABORT_CODE=""
  EXISTING_UNPUBLISH_HELPER_STATUS=125
  EXISTING_UNPUBLISH_APPROVAL_ABORT_CODE=""
  EXISTING_DIAGNOSTIC_CAPTURE_FAILED=0
  if ! existing_version_preflight; then return 10; fi
  EXISTING_RUN_ID="$(uuid)" || { emit_existing_stop run_id_failed; return 10; }
  RUN_ID="$EXISTING_RUN_ID"
  ACTIVATION_WORKFLOW_ID="$WORKFLOW_ID"
  baseline_input="$("$JQ_BIN" -cn --arg id "$WORKFLOW_ID" '{id:$id}')" || {
    emit_existing_stop baseline_input_failed; return 10;
  }

  EXISTING_BASELINE_PROJECTION="$(run_read_once "$baseline_input")"
  ACTIVATION_BASELINE_STATUS=$?
  if ! persist_existing_projection baseline "$EXISTING_BASELINE_PROJECTION"; then
    emit_existing_stop evidence_write_failed; return 10
  fi
  if (( ACTIVATION_BASELINE_STATUS != 0 )) \
    || ! validate_existing_baseline "$EXISTING_BASELINE_PROJECTION"; then
    persist_existing_summary stop baseline_precondition_failed || true
    emit_existing_stop baseline_precondition_failed
    return 10
  fi
  EXISTING_GRAPH_DIGEST="$("$JQ_BIN" -er '.result.draft.graphDigest' \
    <<<"$EXISTING_BASELINE_PROJECTION")" || {
    persist_existing_summary stop baseline_graph_missing || true
    emit_existing_stop baseline_graph_missing; return 10;
  }
  EXISTING_STATE_DIGEST="$("$JQ_BIN" -er '.result.stateDigest' \
    <<<"$EXISTING_BASELINE_PROJECTION")" || {
    persist_existing_summary stop baseline_state_missing || true
    emit_existing_stop baseline_state_missing; return 10;
  }
  validate_existing_state_digest "$EXISTING_STATE_DIGEST" || {
    persist_existing_summary stop baseline_state_invalid || true
    emit_existing_stop baseline_state_invalid; return 10;
  }
  baseline_state="$EXISTING_STATE_DIGEST"

  publish_ref="n8n-existing-$SERVER-publish-$(uuid)" || {
    persist_existing_summary stop approval_reference_failed || true
    emit_existing_stop approval_reference_failed; return 10;
  }
  APPROVAL_HELPER_STATUS=125
  publish_key="$(uuid)" || {
    persist_existing_summary stop idempotency_failed || true
    emit_existing_stop idempotency_failed; return 10;
  }
  ACTIVATION_PUBLISH_INPUT="$("$JQ_BIN" -cn \
    --arg id "$WORKFLOW_ID" --arg version "$VERSION_ID" \
    --arg state "$baseline_state" \
    --arg approval "$publish_ref" --arg key "$publish_key" \
    '{id:$id,active:true,versionId:$version,
      guard:{approvalRef:$approval,idempotencyKey:$key,
        precondition:{versionId:$version,activeVersionId:null,
          active:false,isArchived:false,stateDigest:$state}}}')" || {
    persist_existing_summary stop publish_input_failed || true
    emit_existing_stop publish_input_failed; return 10;
  }
  if ! activation_invoke_step "$ACTIVATION_OPERATION" "activate" \
    "$ACTIVATION_PUBLISH_INPUT" "$WORKFLOW_ID" \
    "fwc-n8n://$SERVER/workflows/$WORKFLOW_ID" existing-publish; then
    EXISTING_PUBLISH_HELPER_STATUS="$APPROVAL_HELPER_STATUS"
    EXISTING_PUBLISH_APPROVAL_ABORT_CODE="$APPROVAL_ABORT_CODE"
    if (( EXISTING_DIAGNOSTIC_CAPTURE_FAILED == 1 )); then
      stop_existing_diagnostic_capture_failed
      return $?
    fi
    if (( HANDOFF_INVOKE_STARTED == 0 )); then
      preinvoke_code="${APPROVAL_ABORT_CODE:-preinvoke_failed}"
      persist_existing_summary stop "$preinvoke_code" || true
      emit_existing_stop "$preinvoke_code"
      return 10
    fi
    persist_existing_summary unknown publish_outcome_unknown || true
    emit_existing_unknown publish_outcome_unknown
    return 20
  fi
  if (( EXISTING_DIAGNOSTIC_CAPTURE_FAILED == 1 )); then
    stop_existing_diagnostic_capture_failed
    return $?
  fi
  EXISTING_PUBLISH_HELPER_STATUS="$APPROVAL_HELPER_STATUS"
  ACTIVATION_PUBLISH_STATUS="$INVOCATION_STATUS"
  EXISTING_PUBLISH_PROJECTION="$INVOKE_PROJECTION"
  if (( INVOCATION_STATUS != 0 )) \
    || ! validate_existing_publish_invoke "$EXISTING_PUBLISH_PROJECTION"; then
    persist_existing_projection publish "$EXISTING_PUBLISH_PROJECTION" || true
    EXISTING_PUBLISH_READBACK="$(run_read_once "$baseline_input")"
    ACTIVATION_ACTIVE_STATUS=$?
    persist_existing_projection publish-readback "$EXISTING_PUBLISH_READBACK" || true
    persist_existing_summary unknown publish_outcome_unknown || true
    emit_existing_unknown publish_outcome_unknown
    return 20
  fi
  if ! persist_existing_projection publish "$EXISTING_PUBLISH_PROJECTION"; then
    persist_existing_summary stop evidence_write_failed || true
    emit_existing_stop evidence_write_failed; return 10
  fi

  EXISTING_PUBLISH_READBACK="$(run_read_once "$baseline_input")"
  ACTIVATION_ACTIVE_STATUS=$?
  if ! persist_existing_projection publish-readback "$EXISTING_PUBLISH_READBACK"; then
    persist_existing_summary stop evidence_write_failed || true
    emit_existing_stop evidence_write_failed; return 10
  fi
  if (( ACTIVATION_ACTIVE_STATUS != 0 )) \
    || ! validate_existing_publish_readback "$EXISTING_PUBLISH_READBACK"; then
    persist_existing_summary unknown publish_readback_inconclusive || true
    emit_existing_unknown publish_readback_inconclusive
    return 20
  fi
  if ! persist_activation_transition publish "$ACTIVATION_OPERATION" \
    existing-publish "$WORKFLOW_ID"; then
    persist_existing_summary stop evidence_write_failed || true
    emit_existing_stop evidence_write_failed; return 10
  fi
  active_state="$("$JQ_BIN" -er '.result.stateDigest' \
    <<<"$EXISTING_PUBLISH_READBACK")" || {
    persist_existing_summary unknown publish_readback_inconclusive || true
    emit_existing_unknown publish_readback_inconclusive; return 20;
  }
  validate_existing_state_digest "$active_state" || {
    persist_existing_summary unknown publish_readback_inconclusive || true
    emit_existing_unknown publish_readback_inconclusive; return 20;
  }

  unpublish_ref="n8n-existing-$SERVER-unpublish-$(uuid)" || {
    persist_existing_summary stop unpublish_approval_reference_failed || true
    emit_existing_stop unpublish_approval_reference_failed; return 10;
  }
  APPROVAL_HELPER_STATUS=125
  unpublish_key="$(uuid)" || {
    persist_existing_summary stop unpublish_idempotency_failed || true
    emit_existing_stop unpublish_idempotency_failed; return 10;
  }
  ACTIVATION_UNPUBLISH_INPUT="$("$JQ_BIN" -cn \
    --arg id "$WORKFLOW_ID" --arg version "$VERSION_ID" \
    --arg state "$active_state" \
    --arg approval "$unpublish_ref" --arg key "$unpublish_key" \
    '{id:$id,active:false,
      guard:{approvalRef:$approval,idempotencyKey:$key,
        precondition:{versionId:$version,activeVersionId:$version,
          active:true,isArchived:false,stateDigest:$state}}}')" || {
    persist_existing_summary stop unpublish_input_failed || true
    emit_existing_stop unpublish_input_failed; return 10;
  }
  if ! activation_invoke_step "$ACTIVATION_OPERATION" "activate" \
    "$ACTIVATION_UNPUBLISH_INPUT" "$WORKFLOW_ID" \
    "fwc-n8n://$SERVER/workflows/$WORKFLOW_ID" existing-unpublish; then
    ACTIVATION_UNPUBLISH_STATUS="$INVOCATION_STATUS"
    EXISTING_UNPUBLISH_HELPER_STATUS="$APPROVAL_HELPER_STATUS"
    EXISTING_UNPUBLISH_APPROVAL_ABORT_CODE="$APPROVAL_ABORT_CODE"
    if (( EXISTING_DIAGNOSTIC_CAPTURE_FAILED == 1 )); then
      stop_existing_diagnostic_capture_failed
      return $?
    fi
    if (( HANDOFF_INVOKE_STARTED == 0 )); then
      preinvoke_code="${APPROVAL_ABORT_CODE:-preinvoke_failed}"
      persist_existing_summary stop "$preinvoke_code" || true
      emit_existing_stop "$preinvoke_code"
      return 10
    fi
    persist_existing_summary unknown unpublish_outcome_unknown || true
    emit_existing_unknown unpublish_outcome_unknown
    return 20
  fi
  if (( EXISTING_DIAGNOSTIC_CAPTURE_FAILED == 1 )); then
    stop_existing_diagnostic_capture_failed
    return $?
  fi
  EXISTING_UNPUBLISH_HELPER_STATUS="$APPROVAL_HELPER_STATUS"
  ACTIVATION_UNPUBLISH_STATUS="$INVOCATION_STATUS"
  EXISTING_UNPUBLISH_PROJECTION="$INVOKE_PROJECTION"
  if (( INVOCATION_STATUS != 0 )) \
    || ! validate_existing_unpublish_invoke "$EXISTING_UNPUBLISH_PROJECTION"; then
    persist_existing_projection unpublish "$EXISTING_UNPUBLISH_PROJECTION" || true
    EXISTING_FINAL_READBACK="$(run_read_once "$baseline_input")"
    FINAL_GET_STATUS=$?
    persist_existing_projection final-readback "$EXISTING_FINAL_READBACK" || true
    persist_existing_summary unknown unpublish_outcome_unknown || true
    emit_existing_unknown unpublish_outcome_unknown
    return 20
  fi
  if ! persist_existing_projection unpublish "$EXISTING_UNPUBLISH_PROJECTION"; then
    persist_existing_summary stop evidence_write_failed || true
    emit_existing_stop evidence_write_failed; return 10
  fi
  if ! persist_activation_transition unpublish "$ACTIVATION_OPERATION" \
    existing-unpublish "$WORKFLOW_ID"; then
    persist_existing_summary stop evidence_write_failed || true
    emit_existing_stop evidence_write_failed; return 10
  fi

  EXISTING_FINAL_READBACK="$(run_read_once "$baseline_input")"
  FINAL_GET_STATUS=$?
  if ! persist_existing_projection final-readback "$EXISTING_FINAL_READBACK"; then
    persist_existing_summary stop evidence_write_failed || true
    emit_existing_stop evidence_write_failed; return 10
  fi
  if (( FINAL_GET_STATUS != 0 )) \
    || ! validate_existing_final_readback "$EXISTING_FINAL_READBACK"; then
    persist_existing_summary unknown unpublish_readback_inconclusive || true
    emit_existing_unknown unpublish_readback_inconclusive
    return 20
  fi
  if ! persist_existing_summary pass none; then
    emit_existing_stop evidence_write_failed; return 10
  fi
  emit_existing_pass
}

emit_existing_continuation_pass() {
  local summary plan prior_plan prior_summary prior_baseline prior_publish prior_readback
  local continuation_baseline unpublish final_readback claim source_claim name
  for name in existing-version-plan prior-summary prior-existing-version-plan \
    prior-existing-baseline prior-existing-publish prior-existing-publish-readback \
    existing-continuation-baseline existing-unpublish existing-final-readback \
    unpublish-attempt-claim transition-unpublish summary; do
    validate_activation_record_file "$name" || {
      emit_existing_stop evidence_validation_failed
      return 10
    }
  done
  summary="$(read_activation_record summary)" || return 10
  plan="$(read_activation_record existing-version-plan)" || return 10
  prior_plan="$(read_activation_record prior-existing-version-plan)" || return 10
  prior_summary="$(read_activation_record prior-summary)" || return 10
  prior_baseline="$(read_activation_record prior-existing-baseline)" || return 10
  prior_publish="$(read_activation_record prior-existing-publish)" || return 10
  prior_readback="$(read_activation_record prior-existing-publish-readback)" || return 10
  continuation_baseline="$(read_activation_record existing-continuation-baseline)" || return 10
  unpublish="$(read_activation_record existing-unpublish)" || return 10
  final_readback="$(read_activation_record existing-final-readback)" || return 10
  claim="$(read_activation_record unpublish-attempt-claim)" || return 10
  source_claim="$(read_secure_evidence_record "$SOURCE_EVIDENCE_DIR" unpublish-attempt-claimed)" || return 10
  [[ "$claim" == "$source_claim" ]] || {
    emit_existing_stop evidence_validation_failed
    return 10
  }
  validate_existing_version_plan "$plan" \
    && validate_existing_version_plan "$prior_plan" \
    && validate_prior_unknown_publish_summary "$prior_summary" \
    && validate_existing_baseline "$prior_baseline" \
    && validate_historical_flat_publish_projection "$prior_publish" \
    && validate_existing_publish_readback "$prior_readback" \
    && validate_existing_publish_readback "$continuation_baseline" \
    && "$JQ_BIN" -e --arg state "$EXISTING_PRIOR_PUBLISH_STATE_DIGEST" \
      '.result.stateDigest == $state' <<<"$continuation_baseline" >/dev/null 2>&1 \
    && validate_existing_unpublish_invoke "$unpublish" \
    && validate_existing_final_readback "$final_readback" \
    && validate_activation_transition_record \
      "$(read_activation_record transition-unpublish)" unpublish \
      "$ACTIVATION_OPERATION" "$WORKFLOW_ID" existing-unpublish \
    || {
      emit_existing_stop evidence_validation_failed
      return 10
    }
  "$JQ_BIN" -e --arg run_id "$EXISTING_RUN_ID" \
    --arg server "$SERVER" --arg workflow "$WORKFLOW_ID" \
    --arg version "$VERSION_ID" --arg source "$SOURCE_EVIDENCE_DIR" '
      .schema == "fwc.n8n.existing-version-acceptance.v1"
      and .verdict == "pass" and .evidence_complete == true
      and .server == $server and .workflow_id == $workflow
      and .version_id == $version and .run_id == $run_id
      and .continued_from_run_id == $run_id
      and .prior_evidence_directory == $source
      and .prior_publish_verdict == "unknown_readback_confirmed_state"
      and .publish_attempts == 1 and .unpublish_attempts == 1
      and .retries == 0 and .unpublish_status == 0
      and .continuation_baseline_status == 0 and .final_readback_status == 0
      and .automatic_cleanup == false and .workflow_creation == false
      and .execution_attempts == 0
      and .raw_provider_bodies_persisted == false
      and .raw_request_bodies_persisted == false
      and .tokens_persisted == false and .secrets_persisted == false
    ' \
    <<<"$summary" >/dev/null 2>&1 || {
      emit_existing_stop evidence_validation_failed
      return 10
    }
  printf '{"schema":"%s","verdict":"pass","server":"%s","workflow_id":"%s","version_id":"%s","continued_from_run_id":"%s","evidence_directory":%s}\n' \
    "$EXISTING_VERSION_SCHEMA" "$SERVER" "$WORKFLOW_ID" "$VERSION_ID" \
    "$EXISTING_RUN_ID" "$("$JQ_BIN" -Rn --arg value "$EVIDENCE_DIR" '$value')"
}

run_existing_unpublish_continuation() {
  local baseline_input baseline_state unpublish_ref unpublish_key
  local preinvoke_code source_run_id invoke_return
  CONTINUE_UNPUBLISH_MODE=1
  EXISTING_VERSION_MODE=1
  ACTIVATION_MODE=1
  ACTIVATION_BASELINE_STATUS=125
  ACTIVATION_ACTIVE_STATUS=125
  ACTIVATION_PUBLISH_STATUS=0
  ACTIVATION_UNPUBLISH_STATUS=125
  FINAL_GET_STATUS=125
  EXISTING_PUBLISH_HELPER_STATUS=0
  EXISTING_PUBLISH_APPROVAL_ABORT_CODE=""
  EXISTING_UNPUBLISH_HELPER_STATUS=125
  EXISTING_UNPUBLISH_APPROVAL_ABORT_CODE=""
  CONTINUATION_UNPUBLISH_ATTEMPTED=0
  EXISTING_SOURCE_VALIDATION_EMITTED=0
  PREINVOKE_CLAIM_PATH=""
  PREINVOKE_CLAIM_JSON=""

  if [[ -z "$SOURCE_EVIDENCE_DIR" || "$SOURCE_EVIDENCE_DIR" == "$EVIDENCE_DIR" ]]; then
    emit_existing_stop source_evidence_invalid
    return 10
  fi
  if ! validate_existing_unpublish_source; then
    if (( EXISTING_SOURCE_VALIDATION_EMITTED == 0 )); then
      emit_existing_stop source_evidence_invalid
    fi
    return 10
  fi
  source_run_id="$EXISTING_RUN_ID"
  if ! existing_version_preflight; then return 10; fi
  EXISTING_RUN_ID="$source_run_id"
  RUN_ID="$source_run_id"
  ACTIVATION_WORKFLOW_ID="$WORKFLOW_ID"
  EXISTING_PRIOR_SUMMARY="$(read_secure_evidence_record "$SOURCE_EVIDENCE_DIR" summary)" || {
    emit_existing_stop source_summary_unavailable
    return 10
  }
  ACTIVATION_BASELINE_STATUS="$("$JQ_BIN" -er '.baseline_status' <<<"$EXISTING_PRIOR_SUMMARY")" || return 10
  EXISTING_PUBLISH_HELPER_STATUS="$("$JQ_BIN" -er '.publish_helper_status' <<<"$EXISTING_PRIOR_SUMMARY")" || return 10
  copy_prior_existing_evidence summary prior-summary \
    && copy_prior_existing_evidence existing-version-plan prior-existing-version-plan \
    && copy_prior_existing_evidence existing-baseline prior-existing-baseline \
    && copy_prior_existing_evidence existing-publish prior-existing-publish \
    && copy_prior_existing_evidence existing-publish-readback prior-existing-publish-readback \
    || {
      emit_existing_stop source_evidence_copy_failed
      return 10
    }

  baseline_input="$("$JQ_BIN" -cn --arg id "$WORKFLOW_ID" '{id:$id}')" || {
    emit_existing_stop continuation_baseline_input_failed
    return 10
  }
  EXISTING_CONTINUATION_BASELINE="$(run_read_once "$baseline_input")"
  ACTIVATION_ACTIVE_STATUS=$?
  if ! persist_activation_record existing-continuation-baseline \
    "$EXISTING_CONTINUATION_BASELINE"; then
    emit_existing_stop evidence_write_failed
    return 10
  fi
  if (( ACTIVATION_ACTIVE_STATUS != 0 )) \
    || ! validate_existing_publish_readback "$EXISTING_CONTINUATION_BASELINE" \
    || ! "$JQ_BIN" -e --arg state "$EXISTING_PRIOR_PUBLISH_STATE_DIGEST" \
      '.result.stateDigest == $state' <<<"$EXISTING_CONTINUATION_BASELINE" >/dev/null 2>&1; then
    persist_existing_continuation_summary stop continuation_baseline_mismatch || true
    emit_existing_stop continuation_baseline_mismatch
    return 10
  fi
  baseline_state="$("$JQ_BIN" -er '.result.stateDigest' \
    <<<"$EXISTING_CONTINUATION_BASELINE")" || {
    persist_existing_continuation_summary stop continuation_state_digest_missing || true
    emit_existing_stop continuation_state_digest_missing
    return 10
  }
  validate_existing_state_digest "$baseline_state" || {
    persist_existing_continuation_summary stop continuation_state_digest_invalid || true
    emit_existing_stop continuation_state_digest_invalid
    return 10
  }
  unpublish_ref="n8n-existing-$SERVER-unpublish-$(uuid)" || {
    persist_existing_continuation_summary stop unpublish_approval_reference_failed || true
    emit_existing_stop unpublish_approval_reference_failed
    return 10
  }
  unpublish_key="$(uuid)" || {
    persist_existing_continuation_summary stop unpublish_idempotency_failed || true
    emit_existing_stop unpublish_idempotency_failed
    return 10
  }
  ACTIVATION_UNPUBLISH_INPUT="$("$JQ_BIN" -cn \
    --arg id "$WORKFLOW_ID" --arg version "$VERSION_ID" \
    --arg state "$baseline_state" --arg approval "$unpublish_ref" \
    --arg key "$unpublish_key" \
    '{id:$id,active:false,
      guard:{approvalRef:$approval,idempotencyKey:$key,
        precondition:{versionId:$version,activeVersionId:$version,
          active:true,isArchived:false,stateDigest:$state}}}')" || {
    persist_existing_continuation_summary stop unpublish_input_failed || true
    emit_existing_stop unpublish_input_failed
    return 10
  }
  PREINVOKE_CLAIM_PATH="$SOURCE_EVIDENCE_DIR/unpublish-attempt-claimed.json"
  PREINVOKE_CLAIM_JSON="$("$JQ_BIN" -cn \
    --arg workflow "$WORKFLOW_ID" --arg version "$VERSION_ID" \
    --arg run_id "$EXISTING_RUN_ID" \
    '{schema:"fwc.n8n.existing-version-unpublish-claim.v1",
      workflow_id:$workflow,version_id:$version,run_id:$run_id,
      operation:"n8n.workflows.activate",action:"unpublish",
      claim:"invoke_may_start_once"}')" || {
    persist_existing_continuation_summary stop unpublish_claim_build_failed || true
    emit_existing_stop unpublish_claim_build_failed
    return 10
  }
  if activation_invoke_step "$ACTIVATION_OPERATION" "activate" \
    "$ACTIVATION_UNPUBLISH_INPUT" "$WORKFLOW_ID" \
    "fwc-n8n://$SERVER/workflows/$WORKFLOW_ID" existing-unpublish; then
    invoke_return=0
  else
    invoke_return=$?
  fi
  EXISTING_UNPUBLISH_HELPER_STATUS="$APPROVAL_HELPER_STATUS"
  ACTIVATION_UNPUBLISH_STATUS="$INVOCATION_STATUS"
  if (( HANDOFF_INVOKE_STARTED == 0 )); then
    preinvoke_code="${APPROVAL_ABORT_CODE:-preinvoke_failed}"
    persist_existing_continuation_summary stop "$preinvoke_code" || true
    emit_existing_stop "$preinvoke_code"
    return 10
  fi
  CONTINUATION_UNPUBLISH_ATTEMPTED=1
  if ! copy_unpublish_claim_to_output \
    || ! persist_activation_record existing-unpublish "$INVOKE_PROJECTION"; then
    persist_existing_continuation_summary unknown evidence_write_failed || true
    emit_existing_unknown evidence_write_failed
    return 20
  fi
  if (( invoke_return != 0 || ACTIVATION_UNPUBLISH_STATUS != 0 )) \
    || ! validate_existing_unpublish_invoke "$INVOKE_PROJECTION"; then
    EXISTING_FINAL_READBACK="$(run_read_once "$baseline_input")"
    FINAL_GET_STATUS=$?
    persist_activation_record existing-final-readback "$EXISTING_FINAL_READBACK" || true
    persist_existing_continuation_summary unknown unpublish_outcome_unknown || true
    emit_existing_unknown unpublish_outcome_unknown
    return 20
  fi
  if ! persist_activation_transition unpublish "$ACTIVATION_OPERATION" \
    existing-unpublish "$WORKFLOW_ID"; then
    EXISTING_FINAL_READBACK="$(run_read_once "$baseline_input")"
    FINAL_GET_STATUS=$?
    persist_activation_record existing-final-readback "$EXISTING_FINAL_READBACK" || true
    persist_existing_continuation_summary unknown evidence_write_failed || true
    emit_existing_unknown evidence_write_failed
    return 20
  fi
  EXISTING_FINAL_READBACK="$(run_read_once "$baseline_input")"
  FINAL_GET_STATUS=$?
  if ! persist_activation_record existing-final-readback "$EXISTING_FINAL_READBACK"; then
    persist_existing_continuation_summary stop evidence_write_failed || true
    emit_existing_stop evidence_write_failed
    return 10
  fi
  if (( FINAL_GET_STATUS != 0 )) \
    || ! validate_existing_final_readback "$EXISTING_FINAL_READBACK"; then
    persist_existing_continuation_summary unknown unpublish_readback_inconclusive || true
    emit_existing_unknown unpublish_readback_inconclusive
    return 20
  fi
  if ! persist_existing_continuation_summary pass none; then
    emit_existing_stop evidence_write_failed
    return 10
  fi
  emit_existing_continuation_pass
}

run_existing_version_self_test() {
  local root mock_sudo mock_approval mock_parent mock_launcher
  local scenario status get_count publish_count unpublish_count approval_count
  local evidence rejected_evidence flat_publish projected malformed_publish
  local source_dir stale_source unknown_source source_plan source_baseline source_publish
  local source_readback source_summary
  SELF_TEST=1
  ACTIVATION_MODE=1
  EXISTING_VERSION_MODE=1
  SERVER="eec"
  WORKFLOW_ID="syntheticworkflow"
  VERSION_ID="selected-version"
  validate_existing_state_digest \
    "blake3-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    || return 1
  validate_existing_state_digest \
    "blake3-256:GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG" \
    && return 1
  validate_existing_state_digest \
    "BLAKE3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
    && return 1
  flat_publish="$("$JQ_BIN" -cn \
    '{status:"verified",operation:"n8n.workflows.activate",
      before:{id:"syntheticworkflow",active:false},
      after:{id:"syntheticworkflow",active:true,
        activeVersionId:"selected-version",isArchived:false,
        published:{versionId:"selected-version",
          graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
      secret_canary:"must-not-persist"}')" || return 1
  projected="$(safe_response_projection <<<"$flat_publish")" || return 1
  validate_existing_publish_invoke "$projected" || return 1
  if rg -q 'secret_canary|must-not-persist' <<<"$projected"; then return 1; fi
  malformed_publish='{"status":"verified","operation":"n8n.workflows.activate","before":{"id":"syntheticworkflow"}}'
  projected="$(safe_response_projection <<<"$malformed_publish")" || return 1
  if validate_existing_publish_invoke "$projected"; then return 1; fi
  root="$(mktemp -d "${TMPDIR:-/tmp}/n8n-existing-version-self-test.XXXXXX")" || return 1
  REQUEST_ROOT="$root/approval-requests"
  mkdir -m 700 -- "$REQUEST_ROOT" || return 1
  mock_sudo="$root/sudo"
  mock_approval="$root/approval-helper"
  mock_parent="$root/parent-helper"
  mock_launcher="$root/launcher"
  cat >"$mock_sudo" <<'EOF'
#!/usr/bin/env bash
set -u
[[ "${1:-}" == "-n" ]] || exit 64
shift
[[ "${1:-}" == "/usr/bin/bash" && "${2:-}" == "-c" ]] || exit 64
shift 2
exec /usr/bin/bash -c "$@"
EOF
  cat >"$mock_approval" <<'EOF'
#!/usr/bin/env bash
set -u
[[ "${1:-}" == "--request-file" ]] || exit 75
[[ -n "${2:-}" ]] || exit 74
[[ -e "/proc/$$/fd/3" ]] || exit 77
request="$EXISTING_TEST_REQUEST_ROOT/$2"
[[ -f "$request" ]] || exit 72
/usr/bin/jq -e '
  (.input.guard.precondition | keys_unsorted | sort) ==
    ["active","activeVersionId","isArchived","stateDigest","versionId"]
  and (.input.guard.precondition.stateDigest |
    test("^blake3-256:[0-9A-Fa-f]{64}$"))
  and ((.input.active == true and .input.guard.precondition.active == false)
    or (.input.active == false and .input.guard.precondition.active == true))
' "$request" >/dev/null || exit 73
request_active="$(/usr/bin/jq -r '.input.active' "$request")" || exit 73
if [[ "$EXISTING_TEST_SCENARIO" == publish_approval_failed \
    && "$request_active" == true ]] \
  || [[ "$EXISTING_TEST_SCENARIO" == unpublish_approval_failed \
    && "$request_active" == false ]]; then
  printf '%s\n' '{"schema":"fwc.n8n.approval-once.v1","verdict":"stop","abort_code":"invalid_seed"}' >&2
  exit 76
fi
if [[ "$EXISTING_TEST_SCENARIO" == publish_approval_code_propagated \
    && "$request_active" == true ]]; then
  printf '%s\n' '{"schema":"fwc.n8n.approval-once.v1","verdict":"stop","abort_code":"clock_failed"}' >&2
  exit 76
fi
if [[ "$EXISTING_TEST_SCENARIO" == publish_approval_unrecognized \
    && "$request_active" == true ]] \
  || [[ "$EXISTING_TEST_SCENARIO" == unpublish_approval_unrecognized \
    && "$request_active" == false ]]; then
  printf '%s\n' 'PRIVATE-CANARY-UNRECOGNIZED approval helper diagnostic' >&2
  exit 76
fi
count=0
[[ -f "$EXISTING_TEST_APPROVAL_COUNT" ]] && count="$(cat "$EXISTING_TEST_APPROVAL_COUNT")"
printf '%s\n' "$((count + 1))" >"$EXISTING_TEST_APPROVAL_COUNT" || exit 71
printf '%s\n' '"offline-stub-token"' >&3
EOF
  cat >"$mock_parent" <<'EOF'
#!/usr/bin/env bash
set -u
[[ "$#" == 4 && -n "${EXISTING_TEST_PARENT_ARGS:-}" ]] || exit 92
/usr/bin/jq -cn --arg server "$1" --arg resource_uri "$2" \
  --arg operation "$3" --argjson input "$4" \
  '{server:$server,resource_uri:$resource_uri,operation:$operation,input:$input}' \
  >>"$EXISTING_TEST_PARENT_ARGS" || exit 93
printf '%064d\n' 1
EOF
  cat >"$mock_launcher" <<'EOF'
#!/usr/bin/env bash
set -u
op="${2:-}"
envelope="$(cat)" || exit 80
if [[ "$op" == "n8n.workflows.get" ]]; then
  count=0
  [[ -f "$EXISTING_TEST_GET_COUNT" ]] && count="$(cat "$EXISTING_TEST_GET_COUNT")"
  count=$((count + 1))
  printf '%s\n' "$count" >"$EXISTING_TEST_GET_COUNT" || exit 81
  if [[ "$EXISTING_TEST_SCENARIO" == publish_diagnostic_preinvoke_failure \
    && "$count" == 1 ]]; then
    printf '%s\n' stale >"$EVIDENCE_DIR/existing-publish-diagnostics.json" || exit 81
  fi
  state=inactive
  if [[ "$EXISTING_TEST_SCENARIO" == baseline_bad && "$count" == 1 ]]; then state=active; fi
  if [[ "$EXISTING_TEST_SCENARIO" == publish_readback_bad && "$count" == 2 ]]; then state=inactive; fi
  inactive_digest=blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  missing_digest=false
  if [[ "$EXISTING_TEST_SCENARIO" == baseline_digest_missing && "$count" == 1 ]] \
    || [[ "$EXISTING_TEST_SCENARIO" == publish_readback_digest_missing && "$count" == 2 ]]; then
    missing_digest=true
  fi
  if [[ "$EXISTING_TEST_SCENARIO" == unpublish_readback_bad && "$count" == 3 ]]; then state=active; fi
  if [[ "$EXISTING_TEST_SCENARIO" == unpublish_unknown && "$count" -gt 1 ]]; then state=active; fi
  if [[ "$count" == 2 && "$state" == inactive && "$EXISTING_TEST_SCENARIO" != publish_readback_bad ]]; then state=active; fi
  if [[ "$EXISTING_TEST_SCENARIO" == continuation_success \
      || "$EXISTING_TEST_SCENARIO" == continuation_unknown ]]; then
    if [[ "$count" == 1 || "$EXISTING_TEST_SCENARIO" == continuation_unknown ]]; then
      state=active
    elif [[ "$count" == 2 ]]; then
      state=inactive
    fi
  fi
  if [[ "$EXISTING_TEST_SCENARIO" == continuation_stale_baseline ]]; then state=inactive; fi
  active=false active_version=null published=null digest="$inactive_digest"
  if [[ "$state" == active ]]; then
    active=true active_version='"selected-version"'
    published='{"versionId":"selected-version","graphDigest":"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    digest=blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  fi
  if [[ "$EXISTING_TEST_SCENARIO" == baseline_digest_bad && "$count" == 1 ]] \
    || [[ "$EXISTING_TEST_SCENARIO" == publish_readback_digest_bad && "$count" == 2 ]]; then
    digest=invalid-state-digest
  fi
  if [[ "$missing_digest" == true ]]; then
    /usr/bin/jq -cn --arg active "$active" --argjson active_version "$active_version" \
      --argjson published "$published" \
      '{type:"response",status:"ok",result:{id:"syntheticworkflow",
        versionId:"selected-version",active:($active=="true"),
        activeVersionId:$active_version,isArchived:false,
        draft:{versionId:"selected-version",graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        published:$published}}'
  else
    /usr/bin/jq -cn --arg active "$active" --argjson active_version "$active_version" \
      --argjson published "$published" --arg digest "$digest" \
      '{type:"response",status:"ok",result:{id:"syntheticworkflow",
        versionId:"selected-version",active:($active=="true"),
        activeVersionId:$active_version,isArchived:false,stateDigest:$digest,
        draft:{versionId:"selected-version",graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        published:$published}}'
  fi
  exit 0
fi
[[ "$op" == "n8n.workflows.activate" ]] || exit 82
active="$(/usr/bin/jq -r '.input.active' <<<"$envelope")" || exit 83
approval="$(/usr/bin/jq -er '.approval_token' <<<"$envelope")" || exit 84
[[ "$approval" == "offline-stub-token" ]] || exit 85
if [[ "$active" == true ]]; then
  /usr/bin/jq -e '.input.guard.precondition |
    (keys_unsorted | sort) == ["active","activeVersionId","isArchived","stateDigest","versionId"]
    and (.stateDigest | test("^blake3-256:[0-9A-Fa-f]{64}$"))
    and .active == false and .activeVersionId == null
    and .isArchived == false' <<<"$envelope" >/dev/null || exit 90
  count=0
  [[ -f "$EXISTING_TEST_PUBLISH_COUNT" ]] && count="$(cat "$EXISTING_TEST_PUBLISH_COUNT")"
  printf '%s\n' "$((count + 1))" >"$EXISTING_TEST_PUBLISH_COUNT" || exit 86
  /usr/bin/jq -e '.input.versionId == "selected-version"
    and .input.guard.precondition.versionId == "selected-version"
    and .input.guard.precondition.active == false
    and .input.guard.precondition.isArchived == false' <<<"$envelope" >/dev/null || exit 87
  if [[ "$EXISTING_TEST_SCENARIO" == publish_diagnostic_failure \
      || "$EXISTING_TEST_SCENARIO" == publish_diagnostic_persist_failure ]]; then
    printf '%s\n' 'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network' >&2
    printf '%s\n' 'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network PRIVATE-CANARY' >&2
    for ((i = 0; i < 2048; i++)); do
      printf '%s\n' 'unrecognized diagnostic filler that must be drained' >&2
    done
    exit 42
  fi
  if [[ "$EXISTING_TEST_SCENARIO" == publish_diagnostic_cap ]]; then
    for ((i = 0; i < 40; i++)); do
      printf '%s\n' 'FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network' >&2
    done
    for ((i = 0; i < 2048; i++)); do
      printf '%s\n' 'unrecognized diagnostic filler that must be drained' >&2
    done
    printf '%s\n' drained >"$EXISTING_TEST_DRAIN_MARKER" || exit 94
    exit 42
  fi
  [[ "$EXISTING_TEST_SCENARIO" != publish_unknown ]] || exit 42
  after='{"id":"syntheticworkflow","versionId":"selected-version","active":true,"activeVersionId":"selected-version","isArchived":false,"stateDigest":"blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","draft":{"versionId":"selected-version","graphDigest":"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"published":{"versionId":"selected-version","graphDigest":"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
  before='{"id":"syntheticworkflow","versionId":"selected-version","active":false,"activeVersionId":null,"isArchived":false,"stateDigest":"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","draft":{"versionId":"selected-version","graphDigest":"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"published":null}'
else
  /usr/bin/jq -e '.input.guard.precondition |
    (keys_unsorted | sort) == ["active","activeVersionId","isArchived","stateDigest","versionId"]
    and (.stateDigest | test("^blake3-256:[0-9A-Fa-f]{64}$"))
    and .active == true and .activeVersionId == "selected-version"
    and .isArchived == false' <<<"$envelope" >/dev/null || exit 91
  count=0
  [[ -f "$EXISTING_TEST_UNPUBLISH_COUNT" ]] && count="$(cat "$EXISTING_TEST_UNPUBLISH_COUNT")"
  printf '%s\n' "$((count + 1))" >"$EXISTING_TEST_UNPUBLISH_COUNT" || exit 88
  /usr/bin/jq -e '.input.versionId == null
    and .input.guard.precondition.versionId == "selected-version"
    and .input.guard.precondition.active == true
    and .input.guard.precondition.activeVersionId == "selected-version"' \
    <<<"$envelope" >/dev/null || exit 89
  if [[ "$EXISTING_TEST_SCENARIO" == unpublish_diagnostic_failure \
    || "$EXISTING_TEST_SCENARIO" == unpublish_diagnostic_persist_failure ]]; then
    printf '%s\n' 'FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_5xx' >&2
    printf '%s\n' 'FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_5xx secret=PRIVATE-CANARY' >&2
    for ((i = 0; i < 2048; i++)); do
      printf '%s\n' 'unrecognized diagnostic filler that must be drained' >&2
    done
    exit 43
  fi
  [[ "$EXISTING_TEST_SCENARIO" != unpublish_unknown ]] || exit 43
  [[ "$EXISTING_TEST_SCENARIO" != continuation_unknown ]] || exit 43
  before='{"id":"syntheticworkflow","versionId":"selected-version","active":true,"activeVersionId":"selected-version","isArchived":false,"stateDigest":"blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","draft":{"versionId":"selected-version","graphDigest":"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"published":{"versionId":"selected-version","graphDigest":"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}'
  after='{"id":"syntheticworkflow","versionId":"selected-version","active":false,"activeVersionId":null,"isArchived":false,"stateDigest":"blake3-256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","draft":{"versionId":"selected-version","graphDigest":"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"published":null}'
fi
if [[ "$EXISTING_TEST_SCENARIO" == continuation_success && "$active" == false ]]; then
  /usr/bin/jq -cn --argjson before "$before" --argjson after "$after" \
    '{status:"verified",operation:"n8n.workflows.activate",
      active:$after.active,before:$before,after:$after,private_canary:"redact-me"}'
else
  /usr/bin/jq -cn --argjson before "$before" --argjson after "$after" \
    '{type:"response",status:"ok",result:{status:"verified",
      operation:"n8n.workflows.activate",active:$after.active,
      before:$before,after:$after}}'
fi
EOF
  chmod 700 -- "$mock_sudo" "$mock_approval" "$mock_parent" "$mock_launcher" || return 1
  HANDOFF_TEST_SUDO="$mock_sudo"
  APPROVAL_HELPER_PATH="$mock_approval"
  PARENT_HELPER_PATH="$mock_parent"
  LAUNCHER_PATH="$mock_launcher"
  export EXISTING_TEST_APPROVAL_COUNT="$root/approval-count"
  export EXISTING_TEST_GET_COUNT="$root/get-count"
  export EXISTING_TEST_PUBLISH_COUNT="$root/publish-count"
  export EXISTING_TEST_UNPUBLISH_COUNT="$root/unpublish-count"
  export EXISTING_TEST_REQUEST_ROOT="$REQUEST_ROOT"

  for scenario in baseline_bad baseline_digest_bad baseline_digest_missing \
    publish_approval_failed publish_approval_code_propagated \
    publish_approval_unrecognized \
    publish_diagnostic_failure publish_diagnostic_cap \
    publish_diagnostic_persist_failure publish_diagnostic_preinvoke_failure \
    publish_unknown publish_readback_bad publish_readback_digest_bad \
    publish_readback_digest_missing unpublish_approval_failed \
    unpublish_approval_unrecognized unpublish_diagnostic_failure \
    unpublish_diagnostic_persist_failure unpublish_unknown \
    unpublish_readback_bad success; do
    EXISTING_TEST_SCENARIO="$scenario"
    export EXISTING_TEST_SCENARIO
    EXISTING_TEST_APPROVAL_COUNT="$root/$scenario-approval-count"
    EXISTING_TEST_GET_COUNT="$root/$scenario-get-count"
    EXISTING_TEST_PUBLISH_COUNT="$root/$scenario-publish-count"
    EXISTING_TEST_UNPUBLISH_COUNT="$root/$scenario-unpublish-count"
    EXISTING_TEST_PARENT_ARGS="$root/$scenario-parent-args"
    EXISTING_TEST_DRAIN_MARKER="$root/$scenario-drained"
    export EXISTING_TEST_APPROVAL_COUNT EXISTING_TEST_GET_COUNT \
      EXISTING_TEST_PUBLISH_COUNT EXISTING_TEST_UNPUBLISH_COUNT \
      EXISTING_TEST_PARENT_ARGS EXISTING_TEST_DRAIN_MARKER
    EVIDENCE_DIR="$root/evidence-$scenario"
    export EVIDENCE_DIR
    REQUEST_ROOT="$root/approval-requests"
    ACTIVATION_PUBLISH_STATUS=125
    ACTIVATION_UNPUBLISH_STATUS=125
    if run_existing_version_acceptance >"$root/$scenario-output"; then status=0; else status=$?; fi
    get_count="$(cat "$EXISTING_TEST_GET_COUNT" 2>/dev/null || printf 0)"
    publish_count="$(cat "$EXISTING_TEST_PUBLISH_COUNT" 2>/dev/null || printf 0)"
    unpublish_count="$(cat "$EXISTING_TEST_UNPUBLISH_COUNT" 2>/dev/null || printf 0)"
    approval_count="$(cat "$EXISTING_TEST_APPROVAL_COUNT" 2>/dev/null || printf 0)"
    evidence="$EVIDENCE_DIR"
    [[ -f "$evidence/summary.json" ]] || return 1
    if [[ "$scenario" == publish_diagnostic_failure ]]; then
      [[ "$status" == 20 && "$get_count" == 2 && "$publish_count" == 1 \
        && "$unpublish_count" == 0 && "$approval_count" == 1 ]] || return 1
      "$JQ_BIN" -e '.labels == ["FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network"]' \
        "$evidence/existing-publish-diagnostics.json" >/dev/null || return 1
      [[ "$("$STAT_BIN" -c '%a' -- "$evidence/existing-publish-diagnostics.json")" == 600 ]] || return 1
      "$JQ_BIN" -e '.evidence_files | index("existing-publish-diagnostics.json") != null' \
        "$evidence/summary.json" >/dev/null || return 1
      if rg -q 'PRIVATE-CANARY|secret=' "$evidence" "$root/$scenario-output"; then return 1; fi
    elif [[ "$scenario" == unpublish_diagnostic_failure ]]; then
      [[ "$status" == 20 && "$get_count" == 3 && "$publish_count" == 1 \
        && "$unpublish_count" == 1 && "$approval_count" == 2 ]] || return 1
      "$JQ_BIN" -e '.labels == ["FCP-N8N-INVOKE-DIAGNOSTIC/v1 response_external_5xx"]' \
        "$evidence/existing-unpublish-diagnostics.json" >/dev/null || return 1
      [[ "$("$STAT_BIN" -c '%a' -- "$evidence/existing-unpublish-diagnostics.json")" == 600 ]] || return 1
      if rg -q 'PRIVATE-CANARY|secret=' "$evidence" "$root/$scenario-output"; then return 1; fi
    elif [[ "$scenario" == publish_diagnostic_cap ]]; then
      [[ "$status" == 20 && "$get_count" == 2 && "$publish_count" == 1 \
        && "$unpublish_count" == 0 && -f "$EXISTING_TEST_DRAIN_MARKER" \
        && "$(cat "$EXISTING_TEST_DRAIN_MARKER")" == drained ]] || return 1
      "$JQ_BIN" -e '.labels | length == 32 and all(.[]; . == "FCP-N8N-HOST-ERROR-DETAIL/v1 policy.network")' \
        "$evidence/existing-publish-diagnostics.json" >/dev/null || return 1
      if rg -q 'PRIVATE-CANARY|secret=' "$evidence" "$root/$scenario-output"; then return 1; fi
    elif [[ "$scenario" == publish_diagnostic_persist_failure ]]; then
      [[ "$status" == 125 && "$get_count" == 1 && "$publish_count" == 1 \
        && "$unpublish_count" == 0 && "$approval_count" == 1 ]] || return 1
      "$JQ_BIN" -e '.verdict == "unknown" and .abort_code == "diagnostic_capture_failed_ambiguous"
        and .evidence_complete == false' "$evidence/summary.json" >/dev/null || return 1
      if rg -q 'PRIVATE-CANARY|secret=' "$evidence" "$root/$scenario-output"; then return 1; fi
    elif [[ "$scenario" == publish_diagnostic_preinvoke_failure ]]; then
      [[ "$status" == 125 && "$get_count" == 1 && "$publish_count" == 0 \
        && "$unpublish_count" == 0 && "$approval_count" == 0 ]] || return 1
      "$JQ_BIN" -e '.verdict == "stop" and .abort_code == "diagnostic_capture_failed"
        and .evidence_complete == false and .publish_attempts == 0' \
        "$evidence/summary.json" >/dev/null || return 1
    elif [[ "$scenario" == unpublish_diagnostic_persist_failure ]]; then
      [[ "$status" == 125 && "$get_count" == 2 && "$publish_count" == 1 \
        && "$unpublish_count" == 1 && "$approval_count" == 2 ]] || return 1
      "$JQ_BIN" -e '.verdict == "unknown" and .abort_code == "diagnostic_capture_failed_ambiguous"
        and .evidence_complete == false and .publish_attempts == 1
        and .unpublish_attempts == 1' "$evidence/summary.json" >/dev/null || return 1
      if rg -q 'PRIVATE-CANARY|secret=' "$evidence" "$root/$scenario-output"; then return 1; fi
    elif [[ "$scenario" == baseline_bad || "$scenario" == baseline_digest_bad \
      || "$scenario" == baseline_digest_missing ]]; then
      [[ "$status" == 10 && "$get_count" == 1 && "$publish_count" == 0 \
        && "$unpublish_count" == 0 && "$approval_count" == 0 ]] || return 1
    elif [[ "$scenario" == publish_approval_failed ]]; then
      [[ "$status" == 10 && "$get_count" == 1 && "$publish_count" == 0 \
        && "$unpublish_count" == 0 && "$approval_count" == 0 ]] || return 1
      "$JQ_BIN" -e '.verdict == "stop" and .abort_code == "invalid_seed"
        and .publish_approval_abort_code == "invalid_seed"
        and .publish_attempts == 0 and .retries == 0' \
        "$evidence/summary.json" >/dev/null || return 1
      "$JQ_BIN" -e '.verdict == "STOP" and .abort_code == "invalid_seed"' \
        "$root/$scenario-output" >/dev/null || return 1
    elif [[ "$scenario" == publish_approval_code_propagated ]]; then
      [[ "$status" == 10 && "$get_count" == 1 && "$publish_count" == 0 \
        && "$unpublish_count" == 0 && "$approval_count" == 0 ]] || return 1
      "$JQ_BIN" -e '.verdict == "stop" and .abort_code == "clock_failed"
        and .publish_approval_abort_code == "clock_failed"
        and .publish_attempts == 0 and .retries == 0' \
        "$evidence/summary.json" >/dev/null || return 1
      "$JQ_BIN" -e '.verdict == "STOP" and .abort_code == "clock_failed"' \
        "$root/$scenario-output" >/dev/null || return 1
    elif [[ "$scenario" == publish_approval_unrecognized ]]; then
      [[ "$status" == 10 && "$get_count" == 1 && "$publish_count" == 0 \
        && "$unpublish_count" == 0 && "$approval_count" == 0 ]] || return 1
      "$JQ_BIN" -e '.verdict == "stop" and .abort_code == "preinvoke_failed"
        and (has("publish_approval_abort_code") | not)
        and .publish_attempts == 0 and .retries == 0' \
        "$evidence/summary.json" >/dev/null || return 1
      "$JQ_BIN" -e '.verdict == "STOP" and .abort_code == "preinvoke_failed"' \
        "$root/$scenario-output" >/dev/null || return 1
      if rg -q 'PRIVATE-CANARY-UNRECOGNIZED' "$root/$scenario-output" "$evidence"; then
        return 1
      fi
    elif [[ "$scenario" == unpublish_approval_failed ]]; then
      [[ "$status" == 10 && "$get_count" == 2 && "$publish_count" == 1 \
        && "$unpublish_count" == 0 && "$approval_count" == 1 ]] || return 1
      "$JQ_BIN" -e '.verdict == "stop" and .abort_code == "invalid_seed"
        and .unpublish_approval_abort_code == "invalid_seed"
        and (has("publish_approval_abort_code") | not)
        and .publish_status == 0 and .publish_readback_status == 0
        and .publish_attempts == 1 and .unpublish_attempts == 0 and .retries == 0' \
        "$evidence/summary.json" >/dev/null || return 1
      "$JQ_BIN" -e '.verdict == "STOP" and .abort_code == "invalid_seed"' \
        "$root/$scenario-output" >/dev/null || return 1
    elif [[ "$scenario" == unpublish_approval_unrecognized ]]; then
      [[ "$status" == 10 && "$get_count" == 2 && "$publish_count" == 1 \
        && "$unpublish_count" == 0 && "$approval_count" == 1 ]] || return 1
      "$JQ_BIN" -e '.verdict == "stop" and .abort_code == "preinvoke_failed"
        and (has("publish_approval_abort_code") | not)
        and (has("unpublish_approval_abort_code") | not)
        and .publish_status == 0 and .publish_readback_status == 0
        and .publish_attempts == 1 and .unpublish_attempts == 0 and .retries == 0' \
        "$evidence/summary.json" >/dev/null || return 1
      "$JQ_BIN" -e '.verdict == "STOP" and .abort_code == "preinvoke_failed"' \
        "$root/$scenario-output" >/dev/null || return 1
      if rg -q 'PRIVATE-CANARY-UNRECOGNIZED' "$root/$scenario-output" "$evidence"; then
        return 1
      fi
    elif [[ "$scenario" == publish_unknown ]]; then
      [[ "$status" == 20 && "$get_count" == 2 && "$publish_count" == 1 \
        && "$unpublish_count" == 0 && "$approval_count" == 1 ]] || return 1
    elif [[ "$scenario" == publish_readback_bad ]]; then
      [[ "$status" == 20 && "$get_count" == 2 && "$publish_count" == 1 \
        && "$unpublish_count" == 0 && "$approval_count" == 1 ]] || return 1
    elif [[ "$scenario" == publish_readback_digest_bad \
      || "$scenario" == publish_readback_digest_missing ]]; then
      [[ "$status" == 20 && "$get_count" == 2 && "$publish_count" == 1 \
        && "$unpublish_count" == 0 && "$approval_count" == 1 ]] || return 1
    elif [[ "$scenario" == unpublish_unknown ]]; then
      [[ "$status" == 20 && "$get_count" == 3 && "$publish_count" == 1 \
        && "$unpublish_count" == 1 && "$approval_count" == 2 ]] || return 1
    elif [[ "$scenario" == unpublish_readback_bad ]]; then
      [[ "$status" == 20 && "$get_count" == 3 && "$publish_count" == 1 \
        && "$unpublish_count" == 1 && "$approval_count" == 2 ]] || return 1
    else
      [[ "$status" == 0 && "$get_count" == 3 && "$publish_count" == 1 \
        && "$unpublish_count" == 1 && "$approval_count" == 2 ]] || return 1
      "$JQ_BIN" -e '.verdict == "pass" and .evidence_complete == true
        and .publish_attempts == 1 and .unpublish_attempts == 1' \
        "$evidence/summary.json" >/dev/null || return 1
      "$JQ_BIN" -s -e --arg resource_uri \
        "fwc-n8n://$SERVER/workflows/$WORKFLOW_ID" \
        --arg workflow "$WORKFLOW_ID" --arg operation "$ACTIVATION_OPERATION" '
        length == 2
        and all(.[]; .server == "eec" and .resource_uri == $resource_uri
          and .operation == $operation and .input.id == $workflow
          and (.input.guard.precondition | keys_unsorted | sort) ==
            ["active","activeVersionId","isArchived","stateDigest","versionId"]
          and (.input.guard.precondition.stateDigest |
            test("^blake3-256:[0-9A-Fa-f]{64}$"))
          and .input.guard.precondition.isArchived == false)
        and .[0].input.active == true
        and .[0].input.versionId == "selected-version"
        and .[0].input.guard.precondition.active == false
        and .[0].input.guard.precondition.activeVersionId == null
        and (.[0].input | keys_unsorted | sort) ==
          ["active","guard","id","versionId"]
        and .[1].input.active == false
        and (.[1].input | has("versionId") | not)
        and .[1].input.guard.precondition.active == true
        and .[1].input.guard.precondition.activeVersionId == "selected-version"
        and (.[1].input | keys_unsorted | sort) == ["active","guard","id"]
      ' "$EXISTING_TEST_PARENT_ARGS" >/dev/null || return 1
    fi
    if rg -q 'offline-stub-token|PRIVATE-CANARY|raw provider body' "$evidence" \
      "$root/$scenario-output"; then return 1; fi
  done

  rejected_evidence="/tmp/${root##*/}-production-reject"
  [[ ! -e "$rejected_evidence" && ! -L "$rejected_evidence" ]] || return 1
  EXISTING_TEST_SCENARIO=production_tmp_rejected
  export EXISTING_TEST_SCENARIO
  EXISTING_TEST_APPROVAL_COUNT="$root/preflight-approval-count"
  EXISTING_TEST_GET_COUNT="$root/preflight-get-count"
  EXISTING_TEST_PUBLISH_COUNT="$root/preflight-publish-count"
  EXISTING_TEST_UNPUBLISH_COUNT="$root/preflight-unpublish-count"
  export EXISTING_TEST_APPROVAL_COUNT EXISTING_TEST_GET_COUNT \
    EXISTING_TEST_PUBLISH_COUNT EXISTING_TEST_UNPUBLISH_COUNT
  EVIDENCE_DIR="$rejected_evidence"
  SELF_TEST=0
  if run_existing_version_acceptance >"$root/production-preflight.json"; then
    SELF_TEST=1
    return 1
  else
    status=$?
  fi
  SELF_TEST=1
  [[ "$status" == 10 && ! -e "$rejected_evidence" ]] || return 1
  rg -q 'evidence_directory_not_durable' "$root/production-preflight.json" || return 1
  [[ ! -e "$EXISTING_TEST_APPROVAL_COUNT" && ! -e "$EXISTING_TEST_GET_COUNT" \
    && ! -e "$EXISTING_TEST_PUBLISH_COUNT" \
    && ! -e "$EXISTING_TEST_UNPUBLISH_COUNT" ]] || return 1

  source_dir="$root/continuation-source"
  stale_source="$root/continuation-stale-source"
  unknown_source="$root/continuation-unknown-source"
  mkdir -m 700 -- "$source_dir" || return 1
  source_plan="$(build_existing_version_plan)" || return 1
  source_baseline="$("$JQ_BIN" -cn \
    '{type:"response",status:"ok",result:{id:"syntheticworkflow",
      versionId:"selected-version",active:false,activeVersionId:null,
      isArchived:false,stateDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      draft:{versionId:"selected-version",
        graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
      published:null}}')" || return 1
  source_publish='{"type":null,"status":"verified","error_code":null}'
  source_readback="$("$JQ_BIN" -cn \
    '{type:"response",status:"ok",result:{id:"syntheticworkflow",
      versionId:"selected-version",active:true,activeVersionId:"selected-version",
      isArchived:false,stateDigest:"blake3-256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      draft:{versionId:"selected-version",
        graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
      published:{versionId:"selected-version",
        graphDigest:"blake3-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}')" || return 1
  source_summary="$("$JQ_BIN" -cn \
    '{schema:"fwc.n8n.existing-version-acceptance.v1",server:"eec",
      workflow_id:"syntheticworkflow",version_id:"selected-version",
      run_id:"00000000-0000-4000-8000-000000000001",
      verdict:"unknown",abort_code:"publish_outcome_unknown",
      baseline_status:0,publish_status:0,publish_readback_status:0,
      unpublish_status:125,final_readback_status:125,
      publish_helper_status:0,publish_attempts:1,unpublish_attempts:0,
      retries:0,automatic_cleanup:false,workflow_creation:false,execution_attempts:0,
      raw_provider_bodies_persisted:false,raw_request_bodies_persisted:false,
      tokens_persisted:false,secrets_persisted:false}')" || return 1
  printf '%s\n' "$source_plan" >"$source_dir/existing-version-plan.json"
  printf '%s\n' "$source_baseline" >"$source_dir/existing-baseline.json"
  printf '%s\n' "$source_publish" >"$source_dir/existing-publish.json"
  printf '%s\n' "$source_readback" >"$source_dir/existing-publish-readback.json"
  printf '%s\n' "$source_summary" >"$source_dir/summary.json"
  chmod 600 -- "$source_dir"/*.json || return 1
  cp -a -- "$source_dir" "$stale_source" || return 1
  cp -a -- "$source_dir" "$unknown_source" || return 1

  EXISTING_TEST_SCENARIO=continuation_stale_baseline
  export EXISTING_TEST_SCENARIO
  SOURCE_EVIDENCE_DIR="$stale_source"
  EXISTING_TEST_APPROVAL_COUNT="$root/continuation-stale-approval-count"
  EXISTING_TEST_GET_COUNT="$root/continuation-stale-get-count"
  EXISTING_TEST_PUBLISH_COUNT="$root/continuation-stale-publish-count"
  EXISTING_TEST_UNPUBLISH_COUNT="$root/continuation-stale-unpublish-count"
  EXISTING_TEST_PARENT_ARGS="$root/continuation-stale-parent-args"
  export EXISTING_TEST_APPROVAL_COUNT EXISTING_TEST_GET_COUNT \
    EXISTING_TEST_PUBLISH_COUNT EXISTING_TEST_UNPUBLISH_COUNT \
    EXISTING_TEST_PARENT_ARGS
  EVIDENCE_DIR="$root/continuation-stale-output"
  if run_existing_unpublish_continuation >"$root/continuation-stale-output.json"; then
    status=0
  else
    status=$?
  fi
  [[ "$status" == 10 \
    && "$(cat "$EXISTING_TEST_GET_COUNT" 2>/dev/null || printf 0)" == 1 \
    && ! -e "$EXISTING_TEST_APPROVAL_COUNT" \
    && ! -e "$EXISTING_TEST_PUBLISH_COUNT" \
    && ! -e "$EXISTING_TEST_UNPUBLISH_COUNT" \
    && ! -e "$stale_source/unpublish-attempt-claimed.json" ]] || return 1

  EXISTING_TEST_SCENARIO=continuation_success
  export EXISTING_TEST_SCENARIO
  SOURCE_EVIDENCE_DIR="$source_dir"
  EXISTING_TEST_APPROVAL_COUNT="$root/continuation-approval-count"
  EXISTING_TEST_GET_COUNT="$root/continuation-get-count"
  EXISTING_TEST_PUBLISH_COUNT="$root/continuation-publish-count"
  EXISTING_TEST_UNPUBLISH_COUNT="$root/continuation-unpublish-count"
  EXISTING_TEST_PARENT_ARGS="$root/continuation-parent-args"
  export EXISTING_TEST_APPROVAL_COUNT EXISTING_TEST_GET_COUNT \
    EXISTING_TEST_PUBLISH_COUNT EXISTING_TEST_UNPUBLISH_COUNT \
    EXISTING_TEST_PARENT_ARGS
  EVIDENCE_DIR="$root/continuation-output"
  if run_existing_unpublish_continuation >"$root/continuation-output.json"; then
    status=0
  else
    status=$?
  fi
  [[ "$status" == 0 \
    && "$(cat "$EXISTING_TEST_GET_COUNT" 2>/dev/null || printf 0)" == 2 \
    && ! -e "$EXISTING_TEST_PUBLISH_COUNT" \
    && "$(cat "$EXISTING_TEST_UNPUBLISH_COUNT" 2>/dev/null || printf 0)" == 1 \
    && "$(cat "$EXISTING_TEST_APPROVAL_COUNT" 2>/dev/null || printf 0)" == 1 \
    && -f "$source_dir/unpublish-attempt-claimed.json" ]] || return 1
  "$JQ_BIN" -e '.verdict == "pass" and .continued_from_run_id ==
      "00000000-0000-4000-8000-000000000001"' \
    "$root/continuation-output.json" >/dev/null || return 1
  "$JQ_BIN" -e '.verdict == "pass" and .unpublish_attempts == 1
      and .publish_attempts == 1 and .retries == 0' \
    "$EVIDENCE_DIR/summary.json" >/dev/null || return 1
  if rg -q 'private_canary|redact-me|offline-stub-token' "$EVIDENCE_DIR"; then return 1; fi

  EXISTING_TEST_SCENARIO=continuation_unknown
  export EXISTING_TEST_SCENARIO
  SOURCE_EVIDENCE_DIR="$unknown_source"
  EXISTING_TEST_APPROVAL_COUNT="$root/continuation-unknown-approval-count"
  EXISTING_TEST_GET_COUNT="$root/continuation-unknown-get-count"
  EXISTING_TEST_PUBLISH_COUNT="$root/continuation-unknown-publish-count"
  EXISTING_TEST_UNPUBLISH_COUNT="$root/continuation-unknown-unpublish-count"
  EXISTING_TEST_PARENT_ARGS="$root/continuation-unknown-parent-args"
  export EXISTING_TEST_APPROVAL_COUNT EXISTING_TEST_GET_COUNT \
    EXISTING_TEST_PUBLISH_COUNT EXISTING_TEST_UNPUBLISH_COUNT \
    EXISTING_TEST_PARENT_ARGS
  EVIDENCE_DIR="$root/continuation-unknown-output"
  if run_existing_unpublish_continuation >"$root/continuation-unknown-output.json"; then
    status=0
  else
    status=$?
  fi
  [[ "$status" == 20 \
    && "$(cat "$EXISTING_TEST_GET_COUNT" 2>/dev/null || printf 0)" == 2 \
    && ! -e "$EXISTING_TEST_PUBLISH_COUNT" \
    && "$(cat "$EXISTING_TEST_UNPUBLISH_COUNT" 2>/dev/null || printf 0)" == 1 \
    && "$(cat "$EXISTING_TEST_APPROVAL_COUNT" 2>/dev/null || printf 0)" == 1 \
    && -f "$unknown_source/unpublish-attempt-claimed.json" ]] || return 1
  "$JQ_BIN" -e '.verdict == "unknown" and .unpublish_attempts == 1
      and .retries == 0' \
    "$EVIDENCE_DIR/summary.json" >/dev/null || return 1
  EXISTING_TEST_SCENARIO=continuation_replay
  export EXISTING_TEST_SCENARIO
  EXISTING_TEST_APPROVAL_COUNT="$root/continuation-replay-approval-count"
  EXISTING_TEST_GET_COUNT="$root/continuation-replay-get-count"
  EXISTING_TEST_PUBLISH_COUNT="$root/continuation-replay-publish-count"
  EXISTING_TEST_UNPUBLISH_COUNT="$root/continuation-replay-unpublish-count"
  export EXISTING_TEST_APPROVAL_COUNT EXISTING_TEST_GET_COUNT \
    EXISTING_TEST_PUBLISH_COUNT EXISTING_TEST_UNPUBLISH_COUNT
  EVIDENCE_DIR="$root/continuation-replay-output"
  if run_existing_unpublish_continuation >"$root/continuation-replay-output.json"; then
    return 1
  else
    status=$?
  fi
  [[ "$status" == 10 \
    && ! -e "$EXISTING_TEST_GET_COUNT" \
    && ! -e "$EXISTING_TEST_APPROVAL_COUNT" \
    && ! -e "$EXISTING_TEST_UNPUBLISH_COUNT" ]] || return 1

  printf '{"schema":"%s","verdict":"pass","mode":"existing-version-self-test","acceptance":false,"provider_actions":0,"scenarios":27}\n' \
    "$EXISTING_VERSION_SCHEMA"
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
    --argjson final_status "$ACTIVATION_FINAL_STATUS" \
    '{schema:"fwc.n8n.activation-acceptance.v1",server:$server,
      workflow_id:$workflow_id,run_id:$run_id,verdict:$verdict,
      abort_code:$abort_code,evidence_directory:$evidence_directory,
      sequence:["create_draft_once","draft_readback_once","publish_once",
        "publish_readback_once","active_readback_once","unpublish_once",
        "final_unpublish_get_once"],
      create_status:$create_status,baseline_status:$baseline_status,
      publish_status:$publish_status,active_status:$active_status,
      unpublish_status:$unpublish_status,final_status:$final_status,retries:0,
      automatic_cleanup:false,webhook_invoked:false,
      evidence_complete:($verdict == "pass"),
      evidence_files:["activation-plan.json","activation-create.json",
        "activation-baseline.json","activation-publish.json",
        "activation-active.json","activation-unpublish.json",
        "activation-final-readback.json","activation-create-diagnostics.json"],
      transition_records:["transition-create.json","transition-publish.json",
        "transition-unpublish.json"],
      mutation_claims:["activation-claim-create.json",
        "activation-claim-publish.json","activation-claim-unpublish.json"],
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
  ACTIVATION_MUTATION_MAY_HAVE_STARTED=0
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
    ACTIVATION_CREATE_STATUS="$INVOCATION_STATUS"
    if (( HANDOFF_INVOKE_STARTED == 1 && INVOCATION_STATUS == 125 )); then
      emit_activation_unknown diagnostic_capture_failed
      return 125
    fi
    raw_projection="${INVOKE_PROJECTION:-{\"type\":null,\"status\":\"unknown\",\"error_code\":\"handoff_failed\"}}"
    persist_projection activation-create "$raw_projection" || true
    activation_finish_failure create_unknown
    return $?
  fi
  ACTIVATION_CREATE_STATUS="$INVOCATION_STATUS"
  raw_projection="$INVOKE_PROJECTION"
  if (( INVOCATION_STATUS != 0 )) || ! validate_activation_create "$raw_projection"; then
    if (( HANDOFF_INVOKE_STARTED == 1 && INVOCATION_STATUS == 125 )); then
      emit_activation_unknown diagnostic_capture_failed
      return 125
    fi
    if ! persist_projection activation-create "$raw_projection"; then
      activation_finish_failure evidence_write_failed
      return $?
    fi
    activation_finish_failure create_unknown
    return $?
  fi
  ACTIVATION_CREATE_PROJECTION="$raw_projection"
  ACTIVATION_WORKFLOW_ID="$("$JQ_BIN" -er '.result.id' <<<"$raw_projection")" || {
    activation_finish_failure create_id_missing
    return $?
  }
  valid_workflow_id "$ACTIVATION_WORKFLOW_ID" || {
    activation_finish_failure create_id_invalid
    return $?
  }
  persist_projection activation-create "$ACTIVATION_CREATE_PROJECTION" || {
    activation_finish_failure evidence_write_failed
    return $?
  }
  if ! persist_activation_transition create "$ACTIVATION_CREATE_OPERATION" \
    activation-create "$ACTIVATION_WORKFLOW_ID"; then
    activation_finish_failure evidence_write_failed
    return $?
  fi

  baseline_input="$("$JQ_BIN" -cn --arg id "$ACTIVATION_WORKFLOW_ID" '{id:$id}')" || {
    activation_finish_failure baseline_input_failed
    return $?
  }
  ACTIVATION_BASELINE_INPUT="$baseline_input"
  ACTIVATION_BASELINE_PROJECTION="$(run_read_once "$baseline_input")"
  ACTIVATION_BASELINE_STATUS=$?
  if (( ACTIVATION_BASELINE_STATUS != 0 )) \
    || ! validate_activation_baseline "$ACTIVATION_BASELINE_PROJECTION"; then
    if ! persist_projection activation-baseline "$ACTIVATION_BASELINE_PROJECTION"; then
      activation_finish_failure evidence_write_failed
      return $?
    fi
    persist_activation_summary unknown '"baseline_unknown"' || true
    emit_activation_unknown baseline_unknown
    return 20
  fi
  ACTIVATION_GRAPH_DIGEST="$("$JQ_BIN" -er '.result.draft.graphDigest' \
    <<<"$ACTIVATION_BASELINE_PROJECTION")" || {
    activation_finish_failure baseline_graph_missing
    return $?
  }
  ACTIVATION_STATE_DIGEST="$("$JQ_BIN" -er '.result.stateDigest' \
    <<<"$ACTIVATION_BASELINE_PROJECTION")" || {
    activation_finish_failure baseline_state_missing
    return $?
  }
  ACTIVATION_VERSION_ID="$("$JQ_BIN" -er '.result.versionId' \
    <<<"$ACTIVATION_BASELINE_PROJECTION")" || {
    activation_finish_failure baseline_version_missing
    return $?
  }
  validate_digest "$ACTIVATION_GRAPH_DIGEST" || {
    activation_finish_failure baseline_graph_invalid
    return $?
  }
  validate_digest "$ACTIVATION_STATE_DIGEST" || {
    activation_finish_failure baseline_state_invalid
    return $?
  }
  persist_projection activation-baseline "$ACTIVATION_BASELINE_PROJECTION" || {
    activation_finish_failure evidence_write_failed
    return $?
  }

  ACTIVATION_PUBLISH_IDEMPOTENCY="$(uuid)" || {
    activation_finish_failure publish_idempotency_failed
    return $?
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
    activation_finish_failure publish_input_failed
    return $?
  }
  if ! activation_invoke_step "$ACTIVATION_OPERATION" "activate" \
    "$ACTIVATION_PUBLISH_INPUT" "$ACTIVATION_WORKFLOW_ID" \
    "fwc-n8n://$SERVER/workflows/$ACTIVATION_WORKFLOW_ID" publish; then
    ACTIVATION_PUBLISH_STATUS="$INVOCATION_STATUS"
    ACTIVATION_PUBLISH_PROJECTION="${INVOKE_PROJECTION:-{\"type\":null,\"status\":\"unknown\",\"error_code\":\"handoff_failed\"}}"
    persist_projection activation-publish "$ACTIVATION_PUBLISH_PROJECTION" || true
    activation_finish_failure publish_unknown
    return $?
  fi
  ACTIVATION_PUBLISH_STATUS="$INVOCATION_STATUS"
  ACTIVATION_PUBLISH_PROJECTION="$INVOKE_PROJECTION"
  if (( INVOCATION_STATUS != 0 )) || ! validate_activation_publish "$ACTIVATION_PUBLISH_PROJECTION"; then
    if ! persist_projection activation-publish "$ACTIVATION_PUBLISH_PROJECTION"; then
      activation_finish_failure evidence_write_failed
      return $?
    fi
    persist_activation_summary unknown '"publish_unknown"' || true
    emit_activation_unknown publish_unknown
    return 20
  fi
  if ! persist_projection activation-publish "$ACTIVATION_PUBLISH_PROJECTION"; then
    activation_finish_failure evidence_write_failed
    return $?
  fi
  if ! persist_activation_transition publish "$ACTIVATION_OPERATION" \
    activation-publish "$ACTIVATION_WORKFLOW_ID"; then
    activation_finish_failure evidence_write_failed
    return $?
  fi

  ACTIVATION_ACTIVE_PROJECTION="$(run_read_once "$baseline_input")"
  ACTIVATION_ACTIVE_STATUS=$?
  if (( ACTIVATION_ACTIVE_STATUS != 0 )) \
    || ! validate_activation_active_readback "$ACTIVATION_ACTIVE_PROJECTION"; then
    if ! persist_projection activation-active "$ACTIVATION_ACTIVE_PROJECTION"; then
      activation_finish_failure evidence_write_failed
      return $?
    fi
    persist_activation_summary unknown '"active_readback_mismatch"' || true
    emit_activation_unknown active_readback_mismatch
    return 20
  fi
  if ! persist_projection activation-active "$ACTIVATION_ACTIVE_PROJECTION"; then
    activation_finish_failure evidence_write_failed
    return $?
  fi
  ACTIVATION_ACTIVE_VERSION_ID="$("$JQ_BIN" -er '.result.activeVersionId' \
    <<<"$ACTIVATION_ACTIVE_PROJECTION")" || {
    activation_finish_failure active_version_missing
    return $?
  }
  ACTIVATION_UNPUBLISH_IDEMPOTENCY="$(uuid)" || {
    activation_finish_failure unpublish_idempotency_failed
    return $?
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
    activation_finish_failure unpublish_input_failed
    return $?
  }
  if ! activation_invoke_step "$ACTIVATION_OPERATION" "activate" \
    "$ACTIVATION_UNPUBLISH_INPUT" "$ACTIVATION_WORKFLOW_ID" \
    "fwc-n8n://$SERVER/workflows/$ACTIVATION_WORKFLOW_ID" unpublish; then
    ACTIVATION_UNPUBLISH_STATUS="$INVOCATION_STATUS"
    ACTIVATION_UNPUBLISH_PROJECTION="${INVOKE_PROJECTION:-{\"type\":null,\"status\":\"unknown\",\"error_code\":\"handoff_failed\"}}"
    persist_projection activation-unpublish "$ACTIVATION_UNPUBLISH_PROJECTION" || true
    activation_finish_failure unpublish_unknown
    return $?
  fi
  ACTIVATION_UNPUBLISH_STATUS="$INVOCATION_STATUS"
  ACTIVATION_UNPUBLISH_PROJECTION="$INVOKE_PROJECTION"
  if (( INVOCATION_STATUS != 0 )) || ! validate_activation_unpublish "$ACTIVATION_UNPUBLISH_PROJECTION"; then
    if ! persist_projection activation-unpublish "$ACTIVATION_UNPUBLISH_PROJECTION"; then
      activation_finish_failure evidence_write_failed
      return $?
    fi
    persist_activation_summary unknown '"unpublish_unknown"' || true
    emit_activation_unknown unpublish_unknown
    return 20
  fi
  if ! persist_projection activation-unpublish "$ACTIVATION_UNPUBLISH_PROJECTION"; then
    activation_finish_failure evidence_write_failed
    return $?
  fi
  if ! persist_activation_transition unpublish "$ACTIVATION_OPERATION" \
    activation-unpublish "$ACTIVATION_WORKFLOW_ID"; then
    activation_finish_failure evidence_write_failed
    return $?
  fi

  ACTIVATION_FINAL_READBACK="$(run_read_once "$baseline_input")"
  ACTIVATION_FINAL_STATUS=$?
  if [[ -z "$ACTIVATION_FINAL_READBACK" ]]; then
    ACTIVATION_FINAL_READBACK='{"status":"unknown","error_code":"empty_response"}'
  fi
  if ! persist_projection activation-final-readback "$ACTIVATION_FINAL_READBACK"; then
    persist_activation_summary unknown '"final_readback_evidence_failed"' || true
    emit_activation_unknown final_readback_unknown
    return 20
  fi
  if (( ACTIVATION_FINAL_STATUS != 0 )) \
    || ! validate_activation_final_readback "$ACTIVATION_FINAL_READBACK"; then
    persist_activation_summary unknown '"final_readback_inconclusive"' || true
    emit_activation_unknown final_readback_inconclusive
    return 20
  fi

  persist_activation_summary pass null || {
    persist_activation_summary unknown '"evidence_write_failed"' || true
    emit_activation_unknown evidence_write_failed
    return 20
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
  local positional_count=0
  local server_option_set=0
  local workflow_option_set=0
  local version_option_set=0
  local evidence_option_set=0
  local source_evidence_option_set=0
  while (( $# > 0 )); do
    case "$1" in
      --server)
        (( $# >= 2 )) || return 1
        SERVER="$2"
        server_option_set=1
        shift 2
        ;;
      --workflow-id)
        (( $# >= 2 )) || return 1
        WORKFLOW_ID="$2"
        workflow_option_set=1
        shift 2
        ;;
      --version-id)
        (( $# >= 2 )) || return 1
        VERSION_ID="$2"
        version_option_set=1
        shift 2
        ;;
      --existing-version)
        EXISTING_VERSION_MODE=1
        shift
        ;;
      --continue-unpublish)
        CONTINUE_UNPUBLISH_MODE=1
        shift
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
        evidence_option_set=1
        shift 2
        ;;
      --source-evidence-dir)
        (( $# >= 2 )) || return 1
        SOURCE_EVIDENCE_DIR="$2"
        source_evidence_option_set=1
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
        positional_count=$((positional_count + 1))
        shift
        ;;
    esac
  done
  if (( CONTINUE_UNPUBLISH_MODE == 1 )); then
    (( EXISTING_VERSION_MODE == 0 && ACTIVATION_MODE == 0 \
      && server_option_set == 1 && workflow_option_set == 1 \
      && version_option_set == 1 && evidence_option_set == 1 \
      && source_evidence_option_set == 1 && positional_count == 0 )) || return 1
    [[ "$EVIDENCE_DIR" == /* && "$SOURCE_EVIDENCE_DIR" == /* ]] || return 1
    valid_server "$SERVER" && valid_workflow_id "$WORKFLOW_ID" \
      && valid_version_id "$VERSION_ID"
    return $?
  fi
  if (( EXISTING_VERSION_MODE == 1 )); then
    (( ACTIVATION_MODE == 0 && server_option_set == 1 \
      && workflow_option_set == 1 && version_option_set == 1 \
      && evidence_option_set == 1 && source_evidence_option_set == 0 )) || return 1
    [[ "${#positional[@]}" -eq 0 && "$EVIDENCE_DIR" == /* ]] || return 1
    valid_server "$SERVER" && valid_workflow_id "$WORKFLOW_ID" \
      && valid_version_id "$VERSION_ID"
    return $?
  fi
  [[ -n "$SERVER" ]] || [[ "${#positional[@]}" -ge 1 ]] || return 1
  [[ -n "$SERVER" ]] || SERVER="${positional[0]}"
  if (( ACTIVATION_MODE == 1 )); then
    (( version_option_set == 0 && EXISTING_VERSION_MODE == 0 \
      && source_evidence_option_set == 0 )) || return 1
    [[ -z "$WORKFLOW_ID" ]] || return 1
    if (( server_option_set == 1 )); then
      [[ "${#positional[@]}" -eq 0 ]] || return 1
    else
      [[ "${#positional[@]}" -eq 1 ]] || return 1
    fi
    valid_server "$SERVER"
  else
    (( version_option_set == 0 && source_evidence_option_set == 0 )) || return 1
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
  if [[ "${1:-}" == --existing-version-self-test && "$#" -eq 1 ]]; then
    run_existing_version_self_test || {
      printf '{"schema":"%s","verdict":"STOP","mode":"existing-version-self-test","abort_code":"self_test_failed"}\n' \
        "$EXISTING_VERSION_SCHEMA"
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
  if (( EXISTING_VERSION_MODE == 1 )); then
    run_existing_version_acceptance
    return $?
  fi
  if (( CONTINUE_UNPUBLISH_MODE == 1 )); then
    run_existing_unpublish_continuation
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
