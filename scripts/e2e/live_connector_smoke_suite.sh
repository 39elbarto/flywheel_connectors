#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCRIPT_NAME="live_connector_smoke_suite"

OUT_ROOT="${OUT_ROOT:-${REPO_ROOT}/artifacts/e2e/live_connector_smoke/$(date -u +%Y%m%dT%H%M%SZ)}"
CONNECTORS="${CONNECTORS:-anthropic,openai,telegram,discord,twitter}"
BIN_DIR="${BIN_DIR:-${REPO_ROOT}/target/debug}"
SKIP_BUILD=false
STEP_COUNTER=0

usage() {
  cat <<'EOF'
Usage: scripts/e2e/live_connector_smoke_suite.sh [options]

Manual live-service smoke suite for Anthropic, OpenAI, Telegram, Discord, and Twitter/X.
This script keeps secrets out of command-line arguments by generating request files from
environment variables, then runs `fcp-e2e --connector-cmd` with those files.
Cargo-backed build/run steps are offloaded through `rch exec -- cargo ...`.

Options:
  --connectors <csv>   Comma-separated connectors to run (default: anthropic,openai,telegram,discord,twitter)
  --out-root <path>    Artifact root (default: artifacts/e2e/live_connector_smoke/<timestamp>)
  --bin-dir <path>     Directory containing built connector binaries (default: target/debug)
  --skip-build         Skip the initial cargo build step
  -h, --help           Show this help

Required baseline environment variables:
  ANTHROPIC_API_KEY
  OPENAI_API_KEY
  TELEGRAM_BOT_TOKEN
  DISCORD_BOT_TOKEN
  TWITTER_CONSUMER_KEY
  TWITTER_CONSUMER_SECRET
  TWITTER_ACCESS_TOKEN
  TWITTER_ACCESS_TOKEN_SECRET

Optional invoke environment variables:
  FCP_LIVE_CAPABILITY_TOKEN      Real capability token for direct connector invoke tests
  ANTHROPIC_PROMPT               Defaults to a tiny ping prompt
  OPENAI_PROMPT                  Defaults to a tiny ping prompt
  TELEGRAM_CHAT_ID               Enables Telegram invoke smoke when set with capability token
  TELEGRAM_TEXT                  Message text for Telegram invoke (default provided)
  DISCORD_CHANNEL_ID             Enables Discord invoke smoke when set with capability token
  DISCORD_CONTENT                Message content for Discord invoke (default provided)
  TWITTER_TWEET_ID               Enables Twitter read invoke when set with capability token
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

run_cargo() {
  require_cmd rch
  rch exec -- cargo "$@"
}

run_fcp_e2e() {
  if command -v fcp-e2e >/dev/null 2>&1; then
    fcp-e2e "$@"
    return $?
  fi
  run_cargo run -q -p fcp-e2e --bin fcp-e2e -- "$@"
}

now_ms() {
  local now
  now=$(date +%s%3N 2>/dev/null || true)
  if [[ -z "${now}" || "${now}" == *N ]]; then
    now="$(date +%s)000"
  fi
  printf '%s' "${now}"
}

hash256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
    return 0
  fi
  if command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 | awk '{print $NF}'
    return 0
  fi
  echo "Missing required command: sha256sum/shasum/openssl" >&2
  exit 1
}

correlation_id_for_step() {
  local connector="$1"
  local hex
  hex=$(printf '%s-%s-%s' "${SCRIPT_NAME}" "${connector}" "${STEP_COUNTER}" | hash256)
  printf '%s-%s-%s-%s-%s' \
    "${hex:0:8}" "${hex:8:4}" "${hex:12:4}" "${hex:16:4}" "${hex:20:12}"
}

emit_step_log() {
  local connector="$1"
  local result="$2"
  local duration_ms="$3"
  local artifacts_json="$4"
  local details_json="$5"
  local correlation_id timestamp

  STEP_COUNTER=$((STEP_COUNTER + 1))
  correlation_id="$(correlation_id_for_step "${connector}")"
  timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf '{"timestamp":"%s","script":"%s","step":"%s","step_number":%s,"correlation_id":"%s","duration_ms":%s,"result":"%s","artifacts":%s,"details":%s}\n' \
    "${timestamp}" "${SCRIPT_NAME}" "${connector}" "${STEP_COUNTER}" "${correlation_id}" \
    "${duration_ms}" "${result}" "${artifacts_json}" "${details_json}" >> "${SUITE_LOG}"
}

is_selected_connector() {
  local connector="$1"
  local entry
  IFS=',' read -r -a entries <<< "${CONNECTORS}"
  for entry in "${entries[@]}"; do
    entry="${entry//[[:space:]]/}"
    if [[ "${entry}" == "${connector}" ]]; then
      return 0
    fi
  done
  return 1
}

write_json_file() {
  local path="$1"
  local jq_program="$2"
  jq -n "${jq_program}" > "${path}"
}

write_handshake_request() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "2",
      method: "handshake",
      params: {
        protocol_version: "2.0",
        zone: "z:work",
        zone_dir: null,
        host_public_key: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        nonce: [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
        capabilities_requested: []
      }
    }
  '
}

write_health_request() {
  local path="$1"
  write_json_file "${path}" '{jsonrpc: "2.0", id: "3", method: "health", params: {}}'
}

write_introspect_request() {
  local path="$1"
  write_json_file "${path}" '{jsonrpc: "2.0", id: "4", method: "introspect", params: {}}'
}

write_openai_config() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "1",
      method: "configure",
      params: {
        api_key: env.OPENAI_API_KEY
      }
    }
  '
}

write_anthropic_config() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "1",
      method: "configure",
      params: {
        api_key: env.ANTHROPIC_API_KEY
      }
    }
  '
}

write_telegram_config() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "1",
      method: "configure",
      params: {
        token: env.TELEGRAM_BOT_TOKEN
      }
    }
  '
}

write_discord_config() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "1",
      method: "configure",
      params: {
        bot_token: env.DISCORD_BOT_TOKEN
      }
    }
  '
}

write_twitter_config() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "1",
      method: "configure",
      params: {
        consumer_key: env.TWITTER_CONSUMER_KEY,
        consumer_secret: env.TWITTER_CONSUMER_SECRET,
        access_token: env.TWITTER_ACCESS_TOKEN,
        access_token_secret: env.TWITTER_ACCESS_TOKEN_SECRET
      }
    }
  '
}

write_openai_invoke() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "5",
      method: "invoke",
      params: {
        operation: "openai.chat",
        input: {
          model: (env.OPENAI_MODEL // "gpt-4o-mini"),
          messages: [
            {role: "user", content: (env.OPENAI_PROMPT // "Reply with the single word pong.")}
          ]
        },
        capability_token: env.FCP_LIVE_CAPABILITY_TOKEN
      }
    }
  '
}

write_anthropic_invoke() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "5",
      method: "invoke",
      params: {
        operation: "anthropic.chat",
        input: {
          model: (env.ANTHROPIC_MODEL // "claude-3-5-haiku-latest"),
          message: (env.ANTHROPIC_PROMPT // "Reply with the single word pong.")
        },
        capability_token: env.FCP_LIVE_CAPABILITY_TOKEN
      }
    }
  '
}

write_telegram_invoke() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "5",
      method: "invoke",
      params: {
        operation: "telegram.send_message",
        input: {
          chat_id: env.TELEGRAM_CHAT_ID,
          text: (env.TELEGRAM_TEXT // "FCP live smoke ping")
        },
        capability_token: env.FCP_LIVE_CAPABILITY_TOKEN
      }
    }
  '
}

write_discord_invoke() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "5",
      method: "invoke",
      params: {
        operation: "discord.send_message",
        input: {
          channel_id: env.DISCORD_CHANNEL_ID,
          content: (env.DISCORD_CONTENT // "FCP live smoke ping")
        },
        capability_token: env.FCP_LIVE_CAPABILITY_TOKEN
      }
    }
  '
}

write_twitter_invoke() {
  local path="$1"
  write_json_file "${path}" '
    {
      jsonrpc: "2.0",
      id: "5",
      method: "invoke",
      params: {
        operation: "twitter.tweet.get",
        args: {
          tweet_id: env.TWITTER_TWEET_ID
        },
        capability_token: env.FCP_LIVE_CAPABILITY_TOKEN
      }
    }
  '
}

require_envs() {
  local missing=0
  local var
  for var in "$@"; do
    if [[ -z "${!var:-}" ]]; then
      echo "Missing required environment variable: ${var}" >&2
      missing=1
    fi
  done
  if [[ ${missing} -ne 0 ]]; then
    exit 1
  fi
}

build_selected_targets() {
  local packages=(-p fcp-e2e)
  if is_selected_connector anthropic; then packages+=(-p fcp-anthropic); fi
  if is_selected_connector openai; then packages+=(-p fcp-openai); fi
  if is_selected_connector telegram; then packages+=(-p fcp-telegram); fi
  if is_selected_connector discord; then packages+=(-p fcp-discord); fi
  if is_selected_connector twitter; then packages+=(-p fcp-twitter); fi
  (cd "${REPO_ROOT}" && run_cargo build "${packages[@]}")
}

run_connector_smoke() {
  local connector="$1"
  local binary="$2"
  local cost_profile="$3"
  local configure_writer="$4"
  local invoke_writer="$5"
  shift 5
  local -a required_envs=("$@")

  require_envs "${required_envs[@]}"

  local connector_dir requests_dir log_path scan_log scan_report
  local config_request handshake_request health_request introspect_request invoke_request
  local -a request_flags=()
  local invoke_enabled=false
  local start_ms duration_ms result="pass"
  local details_json artifacts_json

  connector_dir="${OUT_ROOT}/${connector}"
  requests_dir="${connector_dir}/requests"
  mkdir -p "${requests_dir}"
  chmod 700 "${connector_dir}" "${requests_dir}"

  config_request="${requests_dir}/01-configure.json"
  handshake_request="${requests_dir}/02-handshake.json"
  health_request="${requests_dir}/03-health.json"
  introspect_request="${requests_dir}/04-introspect.json"
  invoke_request="${requests_dir}/05-invoke.json"
  log_path="${connector_dir}/run.jsonl"
  scan_log="${connector_dir}/scan.jsonl"
  scan_report="${connector_dir}/scan_report.json"

  "${configure_writer}" "${config_request}"
  write_handshake_request "${handshake_request}"
  write_health_request "${health_request}"
  write_introspect_request "${introspect_request}"

  request_flags+=(
    --request-file "${config_request}"
    --request-file "${handshake_request}"
    --request-file "${health_request}"
    --request-file "${introspect_request}"
  )

  if [[ -n "${FCP_LIVE_CAPABILITY_TOKEN:-}" ]]; then
    case "${connector}" in
      anthropic)
        invoke_enabled=true
        ;;
      openai)
        invoke_enabled=true
        ;;
      telegram)
        if [[ -n "${TELEGRAM_CHAT_ID:-}" ]]; then
          invoke_enabled=true
        fi
        ;;
      discord)
        if [[ -n "${DISCORD_CHANNEL_ID:-}" ]]; then
          invoke_enabled=true
        fi
        ;;
      twitter)
        if [[ -n "${TWITTER_TWEET_ID:-}" ]]; then
          invoke_enabled=true
        fi
        ;;
    esac
  fi

  if [[ "${invoke_enabled}" == true ]]; then
    "${invoke_writer}" "${invoke_request}"
    request_flags+=(--request-file "${invoke_request}")
  fi

  start_ms="$(now_ms)"
  set +e
  (
    cd "${REPO_ROOT}"
    run_fcp_e2e \
      --connector-cmd "${BIN_DIR}/${binary}" \
      --module "${connector}" \
      --test-name "${connector}_live_smoke" \
      "${request_flags[@]}" \
      --output "${log_path}"
  )
  local rc=$?
  set -e
  duration_ms=$(( $(now_ms) - start_ms ))

  if [[ ${rc} -ne 0 ]]; then
    result="fail"
  else
    set +e
    (
      cd "${REPO_ROOT}"
      run_fcp_e2e --validate-log "${log_path}" &&
      run_fcp_e2e \
        --scan-log "${log_path}" \
        --output "${scan_log}" \
        --scan-report "${scan_report}" \
        --module "${connector}" \
        --test-name "${connector}_live_scan"
    )
    rc=$?
    set -e
    if [[ ${rc} -ne 0 ]]; then
      result="fail"
    fi
  fi

  artifacts_json="$(jq -n \
    --arg log "${log_path}" \
    --arg scan_log "${scan_log}" \
    --arg scan_report "${scan_report}" \
    '[$log, $scan_log, $scan_report]')"
  details_json="$(jq -n \
    --arg connector "${connector}" \
    --arg binary "${binary}" \
    --arg cost_profile "${cost_profile}" \
    --argjson command_exit_code "${rc}" \
    --argjson request_count "$((${#request_flags[@]} / 2))" \
    --argjson invoke_enabled "$( [[ "${invoke_enabled}" == true ]] && echo true || echo false )" \
    '{connector: $connector, binary: $binary, estimated_cost_profile: $cost_profile, command_exit_code: $command_exit_code, request_count: $request_count, invoke_enabled: $invoke_enabled}')"
  emit_step_log "${connector}" "${result}" "${duration_ms}" "${artifacts_json}" "${details_json}"

  if [[ "${result}" != "pass" ]]; then
    echo "Live smoke failed for ${connector}. See ${log_path}" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --connectors) CONNECTORS="$2"; shift 2 ;;
    --out-root) OUT_ROOT="$2"; shift 2 ;;
    --bin-dir) BIN_DIR="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
  esac
done

require_cmd jq
mkdir -p "${OUT_ROOT}"
SUITE_LOG="${OUT_ROOT}/suite.jsonl"
: > "${SUITE_LOG}"

if [[ "${SKIP_BUILD}" != true ]]; then
  build_selected_targets
fi

if is_selected_connector anthropic; then
  run_connector_smoke anthropic fcp-anthropic low-cost-model write_anthropic_config write_anthropic_invoke ANTHROPIC_API_KEY
fi
if is_selected_connector openai; then
  run_connector_smoke openai fcp-openai low-cost-model write_openai_config write_openai_invoke OPENAI_API_KEY
fi
if is_selected_connector telegram; then
  run_connector_smoke telegram fcp-telegram free-sandbox write_telegram_config write_telegram_invoke TELEGRAM_BOT_TOKEN
fi
if is_selected_connector discord; then
  run_connector_smoke discord fcp-discord free-sandbox write_discord_config write_discord_invoke DISCORD_BOT_TOKEN
fi
if is_selected_connector twitter; then
  run_connector_smoke twitter fcp-twitter free-sandbox write_twitter_config write_twitter_invoke \
    TWITTER_CONSUMER_KEY TWITTER_CONSUMER_SECRET TWITTER_ACCESS_TOKEN TWITTER_ACCESS_TOKEN_SECRET
fi

run_fcp_e2e --validate-log "${SUITE_LOG}"
echo "Live connector smoke artifacts written to ${OUT_ROOT}"
