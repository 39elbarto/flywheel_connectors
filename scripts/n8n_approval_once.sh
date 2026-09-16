#!/usr/bin/env bash
set -euo pipefail

# One-shot owner approval boundary for the installed n8n issuer.
#
# Production mode intentionally has no issuer/helper arguments.  It accepts
# only a basename below the fixed approval root, validates the bytes of that
# final request immediately before the fixed issuer call, then obtains the
# signing seed through the existing protected stdin handoff.  The script never
# prints request data, seed bytes, tokens, or provider output.

readonly REQUEST_ROOT="/var/lib/fwc-n8n/approval-requests"
readonly ISSUER_PATH="/usr/local/sbin/fcp-n8n-approval-issue"
readonly SECRET_GET_PATH="/home/ubuntu/.local/bin/secret-get"
readonly PUBLIC_KEY_FILE="/etc/fwc-n8n/approval-public-key"
readonly JQ_PATH="/usr/bin/jq"
readonly CAT_PATH="/usr/bin/cat"
readonly DATE_PATH="/usr/bin/date"
readonly READLINK_PATH="/usr/bin/readlink"
readonly SHA256_PATH="/usr/bin/sha256sum"
readonly CUT_PATH="/usr/bin/cut"
readonly STAT_PATH="/usr/bin/stat"
readonly FLOCK_PATH="/usr/bin/flock"
readonly AWK_PATH="/usr/bin/awk"
readonly BASE64_PATH="/usr/bin/base64"
readonly MAX_REQUEST_BYTES=65536
readonly MAX_APPROVAL_TTL_MS=60000

export LC_ALL=C

LAST_ERROR=""
SELF_TEST_MODE=0
TEST_REQUEST_JSON=""
TEST_FINAL_REQUEST_JSON=""
TEST_FINAL_NOW_MS=""
FAKE_SEED_CALLS=0
FAKE_ISSUER_CALLS=0
FAKE_ISSUER_FAILURE=0
FAKE_SECRET_CALLS=0
FAKE_TOKEN_CONSUMER_CALLS=0
FAKE_TOKEN_CAPTURE=""
REQUEST_LOCK_FD=""
readonly TEST_SEED_B64="BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="

fail() {
  LAST_ERROR="$1"
  return 1
}

emit_error() {
  local code="${1:-internal_error}"
  printf '{"schema":"fwc.n8n.approval-once.v1","verdict":"stop","abort_code":"%s"}\n' "$code" >&2
}

emit_success() {
  printf '%s\n' '{"schema":"fwc.n8n.approval-once.v1","verdict":"issued"}'
}

is_safe_basename() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]
}

fixed_root_is_safe() {
  [[ -d "$REQUEST_ROOT" ]] || return 1
  [[ "$($READLINK_PATH -f "$REQUEST_ROOT" 2>/dev/null)" == "$REQUEST_ROOT" ]] || return 1
  [[ "$($STAT_PATH -c '%u:%g:%a:%F' "$REQUEST_ROOT" 2>/dev/null)" == "0:0:700:directory" ]] || return 1
}

request_metadata_is_safe() {
  local request_path="$1"
  local metadata
  [[ -f "$request_path" ]] || return 1
  [[ "$($READLINK_PATH -f "$request_path" 2>/dev/null)" == "$request_path" ]] || return 1
  metadata="$($STAT_PATH -c '%u:%g:%a:%h:%F:%s' "$request_path" 2>/dev/null)" || return 1
  [[ "$metadata" == 0:0:600:1:regular:* ]] || return 1
  local size="${metadata##*:}"
  [[ "$size" =~ ^[0-9]+$ ]] || return 1
  (( size <= MAX_REQUEST_BYTES )) || return 1
}

read_request_json() {
  local request_basename="$1"
  local request_path="$REQUEST_ROOT/$request_basename"
  local size

  if (( SELF_TEST_MODE == 1 )); then
    printf '%s' "$TEST_REQUEST_JSON"
    return 0
  fi

  fixed_root_is_safe || return 1
  request_metadata_is_safe "$request_path" || return 1
  size="$($STAT_PATH -c '%s' "$request_path" 2>/dev/null)" || return 1
  (( size <= MAX_REQUEST_BYTES )) || return 1
  "$CAT_PATH" -- "$request_path" 2>/dev/null
}

lock_request_for_one_shot() {
  local request_path="$1"

  # Keep an advisory lock on the exact request inode through the issuer call.
  # The producer must honor this cooperative lock; the final re-read below
  # separately rejects a replacement observed before the issuer boundary.
  exec {REQUEST_LOCK_FD}<"$request_path" || return 1
  "$FLOCK_PATH" -n "$REQUEST_LOCK_FD" 2>/dev/null
}

canonical_digest() {
  local json="$1"
  local canonical
  canonical="$($JQ_PATH -cS . <<<"$json" 2>/dev/null)" || return 1
  "$SHA256_PATH" <<<"$canonical" 2>/dev/null | "$CUT_PATH" -d' ' -f1
}

strict_decode_seed() {
  # The KeePass field is a single standard-base64 line for exactly 32 bytes,
  # optionally terminated by one LF.  awk buffers only this bounded encoded
  # field and emits it only after the complete framing check; the raw seed is
  # then streamed directly to the issuer and never enters a shell variable.
  "$AWK_PATH" '
    BEGIN { valid = 1 }
    {
      if (NR == 1) {
        encoded = $0
      } else {
        valid = 0
      }
    }
    END {
      if (!valid || length(encoded) != 44 || encoded !~ /^[[:alnum:]+\/]+=$/) {
        exit 1
      }
      printf "%s", encoded
    }
  ' | "$BASE64_PATH" --decode 2>/dev/null
}

strict_decode_fixture() {
  local encoded="$1"
  local payload="$encoded"
  local decoded

  if [[ "$payload" == *$'\n' ]]; then
    payload="${payload%$'\n'}"
    [[ "$payload" != *$'\n' ]] || return 1
  fi
  [[ "$payload" =~ ^[A-Za-z0-9+/]{43}=$ ]] || return 1
  decoded="$($BASE64_PATH --decode <<<"$payload" 2>/dev/null)" || return 1
  [[ "${#decoded}" == 32 ]]
}

validate_now_ms() {
  [[ "$1" =~ ^[0-9]{13}$ ]] || fail clock_invalid
}

current_now_ms() {
  local now_ms
  now_ms="$($DATE_PATH +%s%3N 2>/dev/null)" || return 1
  [[ "$now_ms" =~ ^[0-9]{13}$ ]] || return 1
  printf '%s' "$now_ms"
}

validate_expiry() {
  local request_json="$1"
  local now_ms="$2"
  local max_now_ms

  validate_now_ms "$now_ms" || return 1
  max_now_ms="$((now_ms + MAX_APPROVAL_TTL_MS))"
  "$JQ_PATH" -e '.expires_at_ms != null and (.expires_at_ms | type) == "number" and ((.expires_at_ms | floor) == .expires_at_ms)' \
    <<<"$request_json" >/dev/null 2>&1 || fail expiry_not_integer || return 1
  "$JQ_PATH" -e '.expires_at_ms | tostring | test("^[0-9]{13}$")' \
    <<<"$request_json" >/dev/null 2>&1 || fail expiry_not_13_digits || return 1
  "$JQ_PATH" -e --argjson now "$now_ms" '.expires_at_ms > $now' \
    <<<"$request_json" >/dev/null 2>&1 || fail expiry_stale || return 1
  "$JQ_PATH" -e --argjson max_now "$max_now_ms" '.expires_at_ms <= $max_now' \
    <<<"$request_json" >/dev/null 2>&1 || fail expiry_over_60s || return 1
}

request_guard() {
  local request_basename="$1"
  local expected_plan_digest="${2:-}"
  local now_ms="$3"
  local request_json
  local request_digest
  local final_request_json
  local final_now_ms
  local initial_fingerprint=""
  local final_fingerprint=""

  if (( SELF_TEST_MODE == 0 )); then
    is_safe_basename "$request_basename" || fail invalid_request_file || return 1
    [[ -x "$ISSUER_PATH" ]] || fail issuer_unavailable || return 1
    [[ -x "$SECRET_GET_PATH" ]] || fail secret_reader_unavailable || return 1
    [[ -f "$PUBLIC_KEY_FILE" ]] || fail public_key_unavailable || return 1
    request_metadata_is_safe "$REQUEST_ROOT/$request_basename" || fail request_unreadable || return 1
    lock_request_for_one_shot "$REQUEST_ROOT/$request_basename" || fail request_busy || return 1
    now_ms="$(current_now_ms)" || fail clock_failed || return 1
    initial_fingerprint="$($STAT_PATH -c '%d:%i:%s:%Y:%Z:%u:%g:%a:%h' "$REQUEST_ROOT/$request_basename")" || {
      fail request_unreadable
      return 1
    }
  fi

  request_json="$(read_request_json "$request_basename" 2>/dev/null)" || {
    fail request_unreadable
    return 1
  }
  "$JQ_PATH" -e . <<<"$request_json" >/dev/null 2>&1 || {
    fail invalid_request_json
    return 1
  }
  validate_expiry "$request_json" "$now_ms" || return 1

  if [[ -n "$expected_plan_digest" ]]; then
    request_digest="$(canonical_digest "$request_json" 2>/dev/null)" || {
      fail request_digest_failed
      return 1
    }
    [[ "$request_digest" == "$expected_plan_digest" ]] || {
      fail safe_plan_mismatch
      return 1
    }
  fi

  # Re-read and re-validate the exact final request immediately before the
  # issuer boundary.  The issuer receives this same basename; no safe-plan
  # expiry is copied into or substituted for the request.
  if (( SELF_TEST_MODE == 1 )) && [[ -n "$TEST_FINAL_REQUEST_JSON" ]]; then
    final_request_json="$TEST_FINAL_REQUEST_JSON"
  else
    final_request_json="$(read_request_json "$request_basename" 2>/dev/null)" || {
      fail request_changed
      return 1
    }
  fi
  [[ "$final_request_json" == "$request_json" ]] || {
    fail request_changed
    return 1
  }
  if (( SELF_TEST_MODE == 1 )); then
    final_now_ms="${TEST_FINAL_NOW_MS:-$now_ms}"
  else
    final_fingerprint="$($STAT_PATH -c '%d:%i:%s:%Y:%Z:%u:%g:%a:%h' "$REQUEST_ROOT/$request_basename")" || {
      fail request_changed
      return 1
    }
    [[ "$final_fingerprint" == "$initial_fingerprint" ]] || {
      fail request_changed
      return 1
    }
    final_now_ms="$(current_now_ms)" || fail clock_failed || return 1
  fi
  validate_expiry "$final_request_json" "$final_now_ms" || return 1
}

fake_secret_reader() {
  printf '%s\n' "$TEST_SEED_B64"
}

fake_decode_seed() {
  local encoded
  encoded="$($CAT_PATH)"
  strict_decode_fixture "$encoded" || return 1
  printf '%s' raw-seed-marker
}

fake_issuer() {
  local request_basename="$1"
  local raw_seed="$2"
  [[ -n "$request_basename" && "$raw_seed" == raw-seed-marker ]] || return 1
  FAKE_ISSUER_CALLS=$((FAKE_ISSUER_CALLS + 1))
  if (( FAKE_ISSUER_FAILURE != 0 )); then
    return 1
  fi
  fake_token_consumer fake-token
}

fake_token_consumer() {
  [[ "$1" == fake-token ]] || return 1
  FAKE_TOKEN_CONSUMER_CALLS=$((FAKE_TOKEN_CONSUMER_CALLS + 1))
  FAKE_TOKEN_CAPTURE="$1"
}

issue_once() {
  local request_basename="$1"

  if (( SELF_TEST_MODE == 1 )); then
    local encoded_seed
    local raw_seed
    encoded_seed="$(fake_secret_reader)" || return 1
    FAKE_SECRET_CALLS=$((FAKE_SECRET_CALLS + 1))
    raw_seed="$(fake_decode_seed <<<"$encoded_seed")" || return 1
    FAKE_SEED_CALLS=$((FAKE_SEED_CALLS + 1))
    fake_issuer "$request_basename" "$raw_seed"
    return $?
  fi

  token_consumer_is_safe || return 1

  # pipefail makes a secret-reader/decoder failure fail the one issuer
  # attempt.  The base64 field and decoded seed are streamed through fixed
  # processes; neither enters a shell variable, argv, environment, file, or
  # report.  The signed token is handed to the already-open protected FD 3.
  "$SECRET_GET_PATH" fwc-n8n-approval-signing private_key_b64 2>/dev/null \
    | strict_decode_seed \
    | FCP_HOST_APPROVAL_PUBLIC_KEY_FILE="$PUBLIC_KEY_FILE" "$ISSUER_PATH" \
        --request-file "$request_basename" >&3 2>/dev/null
}

token_consumer_is_safe() {
  local fd_type
  [[ -e /proc/$$/fd/3 && ! -t 3 ]] || return 1
  fd_type="$($STAT_PATH -Lc '%F' /proc/$$/fd/3 2>/dev/null)" || return 1
  [[ "$fd_type" == fifo || "$fd_type" == pipe ]]
}

run_once() {
  local request_basename="$1"
  local expected_plan_digest="${2:-}"
  local now_ms="$3"

  LAST_ERROR=""
  request_guard "$request_basename" "$expected_plan_digest" "$now_ms" || return 1
  issue_once "$request_basename" || {
    fail issuer_failed
    return 1
  }
}

reset_fake_state() {
  FAKE_SEED_CALLS=0
  FAKE_ISSUER_CALLS=0
  FAKE_ISSUER_FAILURE=0
  FAKE_SECRET_CALLS=0
  FAKE_TOKEN_CONSUMER_CALLS=0
  FAKE_TOKEN_CAPTURE=""
  TEST_FINAL_REQUEST_JSON=""
  TEST_FINAL_NOW_MS=""
}

json_with_expiry() {
  local expiry="$1"
  "$JQ_PATH" -cn --argjson expiry "$expiry" '{schema:"test",expires_at_ms:$expiry}'
}

expect_stop_without_calls() {
  local label="$1"
  local request_json="$2"
  local now_ms="$3"
  local expected_code="$4"
  local expected_plan_digest="${5:-}"
  local final_now_ms="${6:-}"
  local status

  reset_fake_state
  TEST_REQUEST_JSON="$request_json"
  if [[ -n "$final_now_ms" ]]; then
    TEST_FINAL_NOW_MS="$final_now_ms"
  fi
  if run_once self-test.json "$expected_plan_digest" "$now_ms"; then
    return 1
  else
    status=$?
  fi
  [[ "$status" -ne 0 ]] || return 1
  [[ "$LAST_ERROR" == "$expected_code" ]] || return 1
  [[ "$FAKE_SEED_CALLS" == 0 && "$FAKE_ISSUER_CALLS" == 0 ]] || return 1
  [[ -n "$label" ]]
}

expect_issued_once() {
  local request_json="$1"
  local now_ms="$2"
  local expected_plan_digest="${3:-}"

  reset_fake_state
  TEST_REQUEST_JSON="$request_json"
  run_once self-test.json "$expected_plan_digest" "$now_ms" || return 1
  [[ "$FAKE_SECRET_CALLS" == 1 \
    && "$FAKE_SEED_CALLS" == 1 \
    && "$FAKE_ISSUER_CALLS" == 1 \
    && "$FAKE_TOKEN_CONSUMER_CALLS" == 1 \
    && "$FAKE_TOKEN_CAPTURE" == fake-token ]]
}

expect_request_replacement_stop() {
  local request_json="$1"
  local replacement_json="$2"
  local now_ms="$3"

  reset_fake_state
  TEST_REQUEST_JSON="$request_json"
  TEST_FINAL_REQUEST_JSON="$replacement_json"
  if run_once self-test.json "" "$now_ms"; then
    return 1
  fi
  [[ "$LAST_ERROR" == request_changed \
    && "$FAKE_SECRET_CALLS" == 0 \
    && "$FAKE_SEED_CALLS" == 0 \
    && "$FAKE_ISSUER_CALLS" == 0 ]]
}

expect_lock_conflict_is_redacted() {
  local held_fd
  local error_record

  exec {held_fd}</dev/null
  "$FLOCK_PATH" -n "$held_fd" 2>/dev/null || return 1
  if lock_request_for_one_shot /dev/null; then
    return 1
  fi
  error_record="$(emit_error request_busy 2>&1 >/dev/null)"
  [[ "$error_record" == '{"schema":"fwc.n8n.approval-once.v1","verdict":"stop","abort_code":"request_busy"}' ]]
}

expect_protected_fd_is_a_pipe() {
  exec 3> >("$CAT_PATH" >/dev/null)
  token_consumer_is_safe
  local result=$?
  exec 3>&-
  return "$result"
}

run_self_test() {
  local now_ms=1700000000000
  local valid
  local crossing
  local safe_plan
  local safe_plan_digest

  SELF_TEST_MODE=1
  valid="$(json_with_expiry $((now_ms + 1000)))"
  crossing="$(json_with_expiry $((now_ms + 60000)))"
  safe_plan="$(json_with_expiry $((now_ms + 2000)))"
  safe_plan_digest="$(canonical_digest "$safe_plan")"

  expect_stop_without_calls non_integer \
    "$(json_with_expiry "$((now_ms + 1000)).5")" "$now_ms" expiry_not_integer || return 1
  expect_stop_without_calls nanoseconds \
    "$(json_with_expiry 1789527255404548511)" "$now_ms" expiry_not_13_digits || return 1
  expect_stop_without_calls seconds \
    "$(json_with_expiry 1700000000)" "$now_ms" expiry_not_13_digits || return 1
  expect_stop_without_calls stale \
    "$(json_with_expiry $((now_ms - 1)))" "$now_ms" expiry_stale || return 1
  expect_stop_without_calls over_limit \
    "$(json_with_expiry $((now_ms + 60001)))" "$now_ms" expiry_over_60s || return 1
  expect_stop_without_calls safe_plan_mismatch "$valid" "$now_ms" safe_plan_mismatch "$safe_plan_digest" || return 1
  expect_stop_without_calls expiry_crossed "$crossing" "$now_ms" expiry_stale "" "$((now_ms + 60001))" || return 1
  expect_request_replacement_stop "$valid" "$safe_plan" "$now_ms" || return 1
  expect_issued_once "$valid" "$now_ms" || return 1

  strict_decode_fixture "$TEST_SEED_B64" || return 1
  strict_decode_fixture "$TEST_SEED_B64"$'\n' || return 1
  if strict_decode_fixture "$TEST_SEED_B64"$'\n\n'; then
    return 1
  fi
  if strict_decode_fixture "${TEST_SEED_B64%?}"; then
    return 1
  fi
  expect_lock_conflict_is_redacted || return 1
  expect_protected_fd_is_a_pipe || return 1

  reset_fake_state
  TEST_REQUEST_JSON="$valid"
  FAKE_ISSUER_FAILURE=1
  if run_once self-test.json "" "$now_ms"; then
    return 1
  fi
  [[ "$LAST_ERROR" == issuer_failed ]] || return 1
  [[ "$FAKE_SECRET_CALLS" == 1 \
    && "$FAKE_SEED_CALLS" == 1 \
    && "$FAKE_ISSUER_CALLS" == 1 \
    && "$FAKE_TOKEN_CONSUMER_CALLS" == 0 ]] || return 1

  printf '%s\n' '{"schema":"fwc.n8n.approval-once.v1","verdict":"pass","mode":"self-test","acceptance":false,"cases":16}'
}

main() {
  local request_basename
  local now_ms

  if [[ "${1:-}" == "--self-test" && "$#" == 1 ]]; then
    run_self_test || {
      emit_error "self_test_failed"
      return 1
    }
    return 0
  fi
  if [[ "${1:-}" != "--request-file" || "$#" != 2 ]]; then
    emit_error invalid_arguments
    return 1
  fi
  request_basename="$2"
  is_safe_basename "$request_basename" || {
    emit_error invalid_request_file
    return 1
  }
  if ! run_once "$request_basename" "" ""; then
    emit_error "$LAST_ERROR"
    return 1
  fi
  emit_success >&2
}

main "$@"
