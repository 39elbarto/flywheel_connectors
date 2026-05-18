#!/usr/bin/env bash
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/speech-media/${RUN_ID}}"
TARGET_DIR="${SPEECH_MEDIA_CARGO_TARGET_DIR:-/tmp/fcp-speech-media-e2e-target}"
RCH_BIN="${RCH_BIN:-rch}"
REPO_TOOLCHAIN="${REPO_TOOLCHAIN:-nightly-2026-02-19}"
REMOTE_RUNNER="rch:remote-required"
export RCH_FORCE_REMOTE=1

mkdir -p "${OUT_ROOT}/logs" "${OUT_ROOT}/evidence"

OVERALL_STATUS="ok"
EXIT_CODE=0
LAST_STEP_STATUS="not_run"

promote_overall_status() {
  local next_status="$1"
  case "${next_status}" in
    failed)
      OVERALL_STATUS="failed"
      EXIT_CODE=1
      ;;
    infra_blocked)
      if [[ "${OVERALL_STATUS}" == "ok" ]]; then
        OVERALL_STATUS="infra_blocked"
        EXIT_CODE=2
      fi
      ;;
  esac
}

classify_failure() {
  local log_path="$1"
  if grep -Eq 'timeout: failed to execute process|No such file or directory|RCH-E|remote required; refusing local fallback|rch command did not produce remote proof|\[RCH\] local|missing worker|No space left on device|Backend unavailable|unable to update registry|spurious network error|failed to get successful HTTP response' "${log_path}"; then
    echo "infra_blocked"
  else
    echo "failed"
  fi
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

require_rch_remote_proof() {
  local name="$1"
  local log_path="$2"

  if grep -Fq "[RCH] remote" "${log_path}"; then
    return 0
  fi

  echo "[speech-media-verification] ${name}: rch command did not produce remote proof" >&2
  echo "rch command did not produce remote proof" >>"${log_path}"
  return 1
}

run_logged() {
  local name="$1"
  shift
  local log_path="${OUT_ROOT}/logs/${name}.log"
  local rc

  echo "[speech-media-verification] ${name}: $*" >&2
  (
    cd "${REPO_ROOT}" || exit
    "$@"
  ) >"${log_path}" 2>&1
  rc="$?"
  if [[ "${rc}" -eq 0 ]] && ! require_rch_remote_proof "${name}" "${log_path}"; then
    return 1
  fi
  return "${rc}"
}

run_step() {
  local name="$1"
  shift
  if run_logged "${name}" "$@"; then
    LAST_STEP_STATUS="passed"
  else
    local status
    status="$(classify_failure "${OUT_ROOT}/logs/${name}.log")"
    promote_overall_status "${status}"
    LAST_STEP_STATUS="${status}"
  fi
}

git_revision="$(cd "${REPO_ROOT}" && git rev-parse --short HEAD 2>/dev/null || echo unknown)"

require_cmd "${RCH_BIN}"

run_step cargo_check env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo check -p fcp-deepgram -p fcp-elevenlabs --all-targets
cargo_check_status="${LAST_STEP_STATUS}"
run_step format_check env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo fmt -p fcp-deepgram -p fcp-elevenlabs -p fcp-e2e -- --check
format_check_status="${LAST_STEP_STATUS}"
run_step e2e_fixture env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo test -p fcp-e2e --no-default-features --features deepgram,elevenlabs --test speech_media_provider_e2e -- --nocapture
e2e_status="${LAST_STEP_STATUS}"
run_step clippy env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy -p fcp-deepgram -p fcp-elevenlabs --all-targets --no-deps -- -D warnings
clippy_status="${LAST_STEP_STATUS}"
run_step e2e_clippy env RCH_VISIBILITY=verbose "${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="${TARGET_DIR}" cargo clippy -p fcp-e2e --no-default-features --features deepgram,elevenlabs --test speech_media_provider_e2e --no-deps -- -D warnings
e2e_clippy_status="${LAST_STEP_STATUS}"

if grep -a '^SPEECH_MEDIA_FIXTURE_JSONL ' "${OUT_ROOT}/logs/e2e_fixture.log" \
  | sed 's/^SPEECH_MEDIA_FIXTURE_JSONL //' >"${OUT_ROOT}/evidence/fixture_boundary.jsonl"
then
  if [[ ! -s "${OUT_ROOT}/evidence/fixture_boundary.jsonl" ]]; then
    cat >"${OUT_ROOT}/evidence/fixture_boundary.jsonl" <<EOF
{"event":"speech_media_fixture_missing_jsonl","status":"failed","reason":"e2e fixture emitted no SPEECH_MEDIA_FIXTURE_JSONL records","git_revision":"${git_revision}","fixture_mode":"wiremock","log":"${OUT_ROOT}/logs/e2e_fixture.log"}
EOF
    if [[ "${e2e_status}" == "passed" ]]; then
      e2e_status="failed"
      promote_overall_status failed
    fi
  fi
else
  cat >"${OUT_ROOT}/evidence/fixture_boundary.jsonl" <<EOF
{"event":"speech_media_fixture_missing_jsonl","status":"${e2e_status}","reason":"e2e fixture did not produce extractable SPEECH_MEDIA_FIXTURE_JSONL records","git_revision":"${git_revision}","fixture_mode":"wiremock","log":"${OUT_ROOT}/logs/e2e_fixture.log"}
EOF
  if [[ "${e2e_status}" == "passed" ]]; then
    e2e_status="failed"
    promote_overall_status failed
  fi
fi

cat >"${OUT_ROOT}/environment.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "bead": "flywheel_connectors-4kw5f.2.5",
  "connectors": ["fcp-deepgram", "fcp-elevenlabs"],
  "repo_root": "${REPO_ROOT}",
  "verification_script": "scripts/e2e/speech_media_connector_verification.sh",
  "artifact_root": "${OUT_ROOT}",
  "cargo_target_dir": "${TARGET_DIR}",
  "rch_bin": "${RCH_BIN}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "git_revision": "${git_revision}",
  "scope": "deterministic loopback for prerecorded Deepgram Listen plus ElevenLabs voices/TTS; realtime streaming remains out of this proof slice"
}
EOF

cat >"${OUT_ROOT}/replay.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
SPEECH_MEDIA_CARGO_TARGET_DIR="\${SPEECH_MEDIA_CARGO_TARGET_DIR:-${TARGET_DIR}}"
RCH_BIN="\${RCH_BIN:-${RCH_BIN}}"
REPO_TOOLCHAIN="\${REPO_TOOLCHAIN:-${REPO_TOOLCHAIN}}"
export RCH_FORCE_REMOTE=1

env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${SPEECH_MEDIA_CARGO_TARGET_DIR}" cargo check -p fcp-deepgram -p fcp-elevenlabs --all-targets
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${SPEECH_MEDIA_CARGO_TARGET_DIR}" cargo fmt -p fcp-deepgram -p fcp-elevenlabs -p fcp-e2e -- --check
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${SPEECH_MEDIA_CARGO_TARGET_DIR}" cargo test -p fcp-e2e --no-default-features --features deepgram,elevenlabs --test speech_media_provider_e2e -- --nocapture
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${SPEECH_MEDIA_CARGO_TARGET_DIR}" cargo clippy -p fcp-deepgram -p fcp-elevenlabs --all-targets --no-deps -- -D warnings
env RCH_VISIBILITY=verbose "\${RCH_BIN}" exec -- env "RUSTUP_TOOLCHAIN=\${REPO_TOOLCHAIN}" CARGO_TARGET_DIR="\${SPEECH_MEDIA_CARGO_TARGET_DIR}" cargo clippy -p fcp-e2e --no-default-features --features deepgram,elevenlabs --test speech_media_provider_e2e --no-deps -- -D warnings
EOF
chmod +x "${OUT_ROOT}/replay.sh"

cat >"${OUT_ROOT}/summary.json" <<EOF
{
  "run_id": "${RUN_ID}",
  "overall_status": "${OVERALL_STATUS}",
  "artifacts_root": "${OUT_ROOT}",
  "runner": "${REMOTE_RUNNER}",
  "toolchain": "${REPO_TOOLCHAIN}",
  "steps": {
    "cargo_check": "${cargo_check_status}",
    "format_check": "${format_check_status}",
    "e2e_fixture": "${e2e_status}",
    "clippy": "${clippy_status}",
    "e2e_clippy": "${e2e_clippy_status}"
  },
  "artifacts": {
    "cargo_check_log": "${OUT_ROOT}/logs/cargo_check.log",
    "format_check_log": "${OUT_ROOT}/logs/format_check.log",
    "e2e_fixture_log": "${OUT_ROOT}/logs/e2e_fixture.log",
    "fixture_boundary_jsonl": "${OUT_ROOT}/evidence/fixture_boundary.jsonl",
    "clippy_log": "${OUT_ROOT}/logs/clippy.log",
    "e2e_clippy_log": "${OUT_ROOT}/logs/e2e_clippy.log",
    "environment": "${OUT_ROOT}/environment.json",
    "replay": "${OUT_ROOT}/replay.sh"
  }
}
EOF

echo "Speech/media verification artifacts written to ${OUT_ROOT}"
exit "${EXIT_CODE}"
