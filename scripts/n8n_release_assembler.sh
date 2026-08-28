#!/usr/bin/env bash
set -euo pipefail

# Owner-side, HDD-only assembler for one immutable fwc-n8n release.  This
# script stages a candidate; signing and promotion are deliberately separate.

readonly INSTALL_ROOT="/usr/local/lib/fwc-n8n"
readonly CURRENT_PATH="${INSTALL_ROOT}/current"
readonly STAGING_ROOT="/var/lib/fwc-n8n/staging"
readonly HDD_ROOT="/srv/hdd500gb-internal"
readonly PROVISION_REQUEST_SCHEMA="fwc.n8n.provision-request.v1"
readonly EXTERNAL_APPROVAL_ISSUER="fcp-n8n-approval-issue"
readonly EXTERNAL_APPROVAL_ISSUER_INSTALL_PATH="/usr/local/sbin/fcp-n8n-approval-issue"
readonly ARTIFACTS=(
  "bin/fwc-n8n"
  "bin/fcp-host"
  "bin/fcp-n8n"
  "bin/fcp-mcp-bridge"
  "manifests/fcp-n8n.toml"
  "manifests/fcp-mcp-bridge.toml"
  "inventory/eec.json"
  "inventory/hetzner.json"
  "inventory/eec-official-mcp.json"
  "inventory/hetzner-official-mcp.json"
  "policy/zone-policies.json"
  "policy/local-mcp.json"
)
readonly EEC_PUBLISH_INPUT_SCHEMA_DIGEST="sha256:b5fd649c299287d5bbf4091589d2e0c2cf54d3d8a87e5b4e97f5022d0bd74fcf"
readonly EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST="sha256:ec97a0fe010542c1aa3fcf484cc4531f27dfb72ce6d4a161d7dcd31d7f0b8ddf"
readonly EEC_UNPUBLISH_INPUT_SCHEMA_DIGEST="sha256:4d365469269cb9f2e3d2629cd2d86bdb23b1687cbff015895b59c78228d96115"
readonly EEC_UNPUBLISH_OUTPUT_SCHEMA_DIGEST="sha256:31e476b490845afb45d0354ecdfb3fe26015d14d3967747119c5eecef0d2d00c"
readonly HETZNER_PUBLISH_INPUT_SCHEMA_DIGEST="sha256:0df0eb8d4d0c0940bde97d3e2e3af5f9a184ed492dd98a23581bc72c8a17dba4"
readonly HETZNER_PUBLISH_OUTPUT_SCHEMA_DIGEST="sha256:ff5dd02b739450a5567394322bf7b0c97ff303f91d6980ed480608f41ecbcdd0"
readonly HETZNER_UNPUBLISH_INPUT_SCHEMA_DIGEST="sha256:cc4142a9a5e7c283600ea6f34b6da198d618a2e05de7173f013986ad895a8a1a"
readonly HETZNER_UNPUBLISH_OUTPUT_SCHEMA_DIGEST="sha256:2ef9307e809a33df73e644c134abad7756d76e5dc7db5484f1786b87bea04957"

die() {
  echo "n8n_release_assembler: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage: sudo FWC_N8N_OWNER_PUBLIC_KEY_HEX=<64 lowercase hex chars> \
  [FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX=<64 lowercase hex chars>] \
  scripts/n8n_release_assembler.sh \
  --release-id <safe-release-id> \
  [--target-dir /srv/hdd500gb-internal/fwc-build-cache/<name>]

Builds and stages a release only. It does not sign, install, switch current,
invoke n8n, read API keys, or run a provider operation.
The script adds /home/ubuntu/.cargo/bin to PATH for the host Rust toolchain.
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

is_safe_release_id() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]
}

is_hdd_target() {
  [[ "$1" == "${HDD_ROOT}/fwc-build-cache/"* ]] \
    && [[ "$1" != *".."* ]] \
    && [[ "$1" != *$'\n'* ]] \
    && [[ "$1" != *$'\r'* ]]
}

require_safe_directory() {
  local path="$1"
  [[ -d "$path" ]] || die "directory is missing: $path"
  [[ "$(readlink -f "$path")" == "$path" ]] || die "directory path is symlinked: $path"
  local mode
  mode="$(stat -c '%a' "$path")"
  (( (8#$mode & 0022) == 0 )) || die "directory is group/world writable: $path"
}

require_hdd_mount() {
  need_cmd findmnt
  [[ "$(findmnt -no SOURCE --target "$HDD_ROOT")" == "/dev/sdc1" ]] \
    || die "${HDD_ROOT} is not mounted from the approved HDD /dev/sdc1"
  require_safe_directory "$HDD_ROOT"
}

find_blake3_rlib() {
  local candidate
  candidate="$(find "${TARGET_DIR}/release/deps" -maxdepth 1 -type f \
    -name 'libblake3-*.rlib' -printf '%T@ %p\n' 2>/dev/null \
    | sort -n | tail -1 | cut -d' ' -f2-)"
  [[ -n "$candidate" && -f "$candidate" ]] || die "Cargo did not produce the blake3 library"
  printf '%s\n' "$candidate"
}

build_hash_helper() {
  local helper="$TARGET_DIR/release/fwc-n8n-blake3-helper"
  local rlib
  rlib="$(find_blake3_rlib)"
  printf '%s\n' \
    'extern crate blake3;' \
    'use std::{env,fs::File,io::{Read,Write}};' \
    'fn main(){let p=env::args().nth(1).expect("path");let mut f=File::open(p).expect("open");let mut h=blake3::Hasher::new();let mut b=[0u8;65536];loop{let n=f.read(&mut b).expect("read");if n==0{break}h.update(&b[..n]);}writeln!(std::io::stdout(),"{}",h.finalize().to_hex()).expect("write");}' \
    | TMPDIR="$TARGET_DIR/tmp" rustc - --edition=2024 \
        -L "dependency=${TARGET_DIR}/release/deps" \
        --extern "blake3=${rlib}" \
        -o "$helper"
  chmod 0755 "$helper"
}

build_one() {
  echo "[build] $*" >&2
  if [[ -n "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX:-}" ]]; then
    env \
      CARGO_HOME="${CARGO_HOME}" \
      CARGO_NET_OFFLINE=true \
      CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" \
      CARGO_INCREMENTAL=0 \
      CARGO_TARGET_DIR="$TARGET_DIR" \
      TMPDIR="$TARGET_DIR/tmp" \
      FWC_N8N_OWNER_PUBLIC_KEY_HEX="$FWC_N8N_OWNER_PUBLIC_KEY_HEX" \
      FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX="$FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX" \
      cargo --locked --offline "$@"
  else
    env \
      CARGO_HOME="${CARGO_HOME}" \
      CARGO_NET_OFFLINE=true \
      CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" \
      CARGO_INCREMENTAL=0 \
      CARGO_TARGET_DIR="$TARGET_DIR" \
      TMPDIR="$TARGET_DIR/tmp" \
      FWC_N8N_OWNER_PUBLIC_KEY_HEX="$FWC_N8N_OWNER_PUBLIC_KEY_HEX" \
      cargo --locked --offline "$@"
  fi
}

require_clean_tracked_head() {
  [[ "$(git -C "$REPO_ROOT" rev-parse --show-toplevel)" == "$REPO_ROOT" ]] \
    || die "run from the flywheel_connectors checkout"
  git -C "$REPO_ROOT" diff --quiet HEAD -- \
    || die "tracked worktree changes exist; assemble only a committed HEAD"
  git -C "$REPO_ROOT" diff --cached --quiet -- \
    || die "staged worktree changes exist; assemble only a committed HEAD"
  local unexpected
  unexpected="$(git -C "$REPO_ROOT" ls-files --others --exclude-standard | while IFS= read -r path; do
    case "$path" in
      .beads/.br-*.lock|crates/fcp-host/.fcp/*|rustc-ice-*.txt) ;;
      *) printf '%s\n' "$path" ;;
    esac
  done)"
  [[ -z "$unexpected" ]] || die "unexpected untracked source input(s): $unexpected"
}

require_immutable_template_release() {
  local source_release="$1"
  [[ "$(readlink -f "$source_release")" == "$source_release" ]] || die "template release is symlinked"
  require_safe_directory "$source_release"
  [[ "$(stat -c '%u:%g' "$source_release")" == "0:0" ]] || die "template release is not root-owned"
  while IFS= read -r -d '' path; do
    [[ "$(readlink -f "$path")" == "$path" ]] || die "template contains symlink: $path"
    [[ "$(stat -c '%u:%g' "$path")" == "0:0" ]] || die "template is not root-owned: $path"
    local mode
    mode="$(stat -c '%a' "$path")"
    (( (8#$mode & 0022) == 0 )) || die "template is group/world writable: $path"
  done < <(find "$source_release" -mindepth 1 -print0)
}

run_static_smoke() {
  echo "[test] owned static fcp-n8n smoke" >&2
  env \
    CARGO_HOME="$CARGO_HOME" \
    CARGO_NET_OFFLINE=true \
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}" \
    CARGO_INCREMENTAL=0 \
    CARGO_TARGET_DIR="$TARGET_DIR" \
    TMPDIR="$TARGET_DIR/tmp" \
    FCP_N8N_OWNED_SMOKE_BINARY="$TARGET_DIR/release/fcp-n8n" \
    cargo --locked --offline test --release -p fcp-host --test n8n_owned_static_smoke \
      static_n8n_connector_introspects_under_owned_network_filter -- --ignored --exact
}

build_external_approval_issuer() {
  echo "[build] external approval issuer (kept outside runtime release)" >&2
  build_one build --release --package fcp-host --features n8n-approval-issuer \
    --bin "$EXTERNAL_APPROVAL_ISSUER"
  [[ -x "$TARGET_DIR/release/$EXTERNAL_APPROVAL_ISSUER" ]] \
    || die "Cargo did not produce the external approval issuer"
}

assert_external_approval_issuer_is_not_staged() {
  local stage_root="$1"
  [[ ! -e "$stage_root/bin/$EXTERNAL_APPROVAL_ISSUER" ]] \
    || die "external approval issuer must not be staged in the runtime release"
}

copy_templates() {
  local source_release="$1"
  local stage_root="$2"

  install -d -o root -g root -m 0755 \
    "$stage_root" "$stage_root/bin" "$stage_root/manifests" \
    "$stage_root/inventory" "$stage_root/policy"
  install -o root -g root -m 0755 "$TARGET_DIR/release/fwc-n8n" "$stage_root/bin/fwc-n8n"
  install -o root -g root -m 0755 "$TARGET_DIR/release/fcp-host" "$stage_root/bin/fcp-host"
  install -o root -g root -m 0755 "$TARGET_DIR/release/fcp-n8n" "$stage_root/bin/fcp-n8n"
  install -o root -g root -m 0755 "$TARGET_DIR/release/fcp-mcp-bridge" "$stage_root/bin/fcp-mcp-bridge"
  install -o root -g root -m 0644 "$REPO_ROOT/connectors/n8n/manifest.toml" "$stage_root/manifests/fcp-n8n.toml"
  install -o root -g root -m 0644 "$REPO_ROOT/connectors/mcp-bridge/manifest.toml" "$stage_root/manifests/fcp-mcp-bridge.toml"

  for server in eec hetzner; do
    install -o root -g root -m 0644 "$source_release/inventory/${server}.json" "$stage_root/inventory/${server}.json"
    install -o root -g root -m 0644 "$source_release/inventory/${server}-official-mcp.json" "$stage_root/inventory/${server}-official-mcp.json"
  done
  install -o root -g root -m 0644 "$source_release/policy/zone-policies.json" "$stage_root/policy/zone-policies.json"
  install -o root -g root -m 0644 "$source_release/policy/local-mcp.json" "$stage_root/policy/local-mcp.json"
}

write_inventory_and_request() {
  local stage_root="$1"
  local source_release="$2"
  local hash_helper="$3"
  local request_path="$4"
  local git_revision="$5"
  local new_root="${INSTALL_ROOT}/releases/${RELEASE_ID}"
  local n8n_digest bridge_digest
  n8n_digest="$($hash_helper "$stage_root/bin/fcp-n8n")"
  bridge_digest="$($hash_helper "$stage_root/bin/fcp-mcp-bridge")"

  python3 - "$stage_root" "$source_release" "$new_root" "$n8n_digest" "$bridge_digest" "$request_path" "$PROVISION_REQUEST_SCHEMA" "$git_revision" \
    "$EEC_PUBLISH_INPUT_SCHEMA_DIGEST" "$EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$EEC_UNPUBLISH_INPUT_SCHEMA_DIGEST" "$EEC_UNPUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_PUBLISH_INPUT_SCHEMA_DIGEST" "$HETZNER_PUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_UNPUBLISH_INPUT_SCHEMA_DIGEST" "$HETZNER_UNPUBLISH_OUTPUT_SCHEMA_DIGEST" <<'PY'
import json
import pathlib
import sys

(
    stage,
    old_root,
    new_root,
    n8n_digest,
    bridge_digest,
    request_path,
    request_schema,
    git_revision,
    eec_publish_input,
    eec_publish_output,
    eec_unpublish_input,
    eec_unpublish_output,
    hetzner_publish_input,
    hetzner_publish_output,
    hetzner_unpublish_input,
    hetzner_unpublish_output,
) = sys.argv[1:]
stage = pathlib.Path(stage)

def load(name):
    return json.loads((stage / "inventory" / name).read_text())[0]

def save(name, value):
    (stage / "inventory" / name).write_text(json.dumps([value], indent=2) + "\n")

bindings = []
for server in ("eec", "hetzner"):
    common = load(f"{server}.json")
    official = load(f"{server}-official-mcp.json")
    for item in (common, official):
        for key in ("binary", "manifest_path"):
            item[key] = item[key].replace(old_root, new_root)
        for key in ("launcher_path", "runtime_executable"):
            item["launch_binding"][key] = item["launch_binding"][key].replace(old_root, new_root)
    common["launch_binding"]["launcher_digest"] = n8n_digest
    common["launch_binding"]["runtime_executable_digest"] = n8n_digest
    official["launch_binding"]["launcher_digest"] = bridge_digest
    official["launch_binding"]["runtime_executable_digest"] = bridge_digest
    lifecycle = {
        "eec": {
            "publish_workflow": (eec_publish_input, eec_publish_output),
            "unpublish_workflow": (eec_unpublish_input, eec_unpublish_output),
        },
        "hetzner": {
            "publish_workflow": (hetzner_publish_input, hetzner_publish_output),
            "unpublish_workflow": (hetzner_unpublish_input, hetzner_unpublish_output),
        },
    }
    for tool in official["config"]["capability_policy"]["approved_tools"]:
        schema = lifecycle[server].get(tool["name"])
        if schema is not None:
            tool["input_schema_digest"], tool["output_schema_digest"] = schema
    save(f"{server}.json", common)
    save(f"{server}-official-mcp.json", official)
    policy = official["config"]["capability_policy"]
    archive = policy["archive_workflow_schema"]
    execute = policy["execute_workflow_schema"]
    bindings.append({
        "server": server,
        "archive_input_schema_digest": archive["input_schema_digest"],
        "archive_output_schema_digest": archive["output_schema_digest"],
        "execute_input_schema_digest": execute["input_schema_digest"],
        "execute_output_schema_digest": execute["output_schema_digest"],
    })

request = {
    "schema": request_schema,
    "release_id": pathlib.Path(new_root).name,
    "git_revision": git_revision,
    "bindings": bindings,
}
pathlib.Path(request_path).write_text(json.dumps(request, separators=(",", ":")) + "\n")
PY
  chmod 0600 "$request_path"
  chown root:root "$request_path"
}

write_metadata() {
  local stage_root="$1"
  local git_revision="$2"
  local hash_helper="$3"
  python3 - "$stage_root" "$RELEASE_ID" "$git_revision" <<'PY'
import json
import pathlib
import sys
stage, release_id, git_revision = sys.argv[1:]
stage = pathlib.Path(stage)
(stage / "provenance.json").write_text(json.dumps({
    "schema": "fwc.n8n.provenance.v1",
    "release_id": release_id,
    "git_revision": git_revision,
}, indent=2) + "\n")
PY
  python3 - "$stage_root" "$RELEASE_ID" "$hash_helper" "${ARTIFACTS[@]}" <<'PY'
import json
import pathlib
import subprocess
import sys
stage = pathlib.Path(sys.argv[1])
release_id = sys.argv[2]
helper = sys.argv[3]
artifacts = sys.argv[4:]
rows = []
for relative in artifacts:
    digest = subprocess.check_output([helper, str(stage / relative)], text=True).strip()
    if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise SystemExit(f'invalid digest for {relative}')
    rows.append({'path': relative, 'digest': digest})
(stage / "receipt.json").write_text(json.dumps({
    "schema": "fwc.n8n.bundle.v1",
    "release_id": release_id,
    "artifacts": rows,
}, indent=2) + "\n")
PY
  chown root:root "$stage_root/provenance.json" "$stage_root/receipt.json"
  chmod 0644 "$stage_root/provenance.json" "$stage_root/receipt.json"
}

main() {
  local release_id=""
  TARGET_DIR="${HDD_ROOT}/fwc-build-cache/fwc-n8n-release"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --release-id) [[ $# -ge 2 ]] || die "--release-id requires a value"; release_id="$2"; shift 2 ;;
      --target-dir) [[ $# -ge 2 ]] || die "--target-dir requires a value"; TARGET_DIR="$2"; shift 2 ;;
      --help|-h) usage; return 0 ;;
      *) usage; die "unknown argument: $1" ;;
    esac
  done
  [[ "${EUID}" -eq 0 ]] || die "run the assembler as root; it creates root-owned fixed staging"
  PATH="/home/ubuntu/.cargo/bin:${PATH}"
  export PATH
  need_cmd cargo; need_cmd git; need_cmd install; need_cmd python3; need_cmd rustc
  need_cmd stat; need_cmd readlink
  is_safe_release_id "$release_id" || die "invalid release id"
  is_hdd_target "$TARGET_DIR" || die "target dir must be below ${HDD_ROOT}/fwc-build-cache"
  [[ "${FWC_N8N_OWNER_PUBLIC_KEY_HEX:-}" =~ ^[0-9a-f]{64}$ ]] || die "FWC_N8N_OWNER_PUBLIC_KEY_HEX must be 64 lowercase hex characters"
  if [[ -n "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX:-}" ]]; then
    [[ "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX}" =~ ^[0-9a-f]{64}$ ]] \
      || die "FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX must be 64 lowercase hex characters"
    [[ "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX}" != "${FWC_N8N_OWNER_PUBLIC_KEY_HEX}" ]] \
      || die "active and previous owner public keys must differ"
  fi
  CARGO_HOME="${CARGO_HOME:-${HDD_ROOT}/fwc-build-cache/cargo-home}"
  is_hdd_target "$CARGO_HOME" || die "CARGO_HOME must be below ${HDD_ROOT}/fwc-build-cache"
  require_hdd_mount
  require_safe_directory "${HDD_ROOT}/fwc-build-cache"
  [[ -d "$CARGO_HOME/registry" ]] || die "HDD CARGO_HOME is not provisioned: $CARGO_HOME"
  require_safe_directory "$CARGO_HOME"
  require_safe_directory "/var/lib/fwc-n8n"
  require_safe_directory "$STAGING_ROOT"
  if [[ -e "$TARGET_DIR" ]]; then
    require_safe_directory "$TARGET_DIR"
  else
    mkdir "$TARGET_DIR"
    require_safe_directory "$TARGET_DIR"
  fi
  if [[ -e "$TARGET_DIR/tmp" ]]; then
    require_safe_directory "$TARGET_DIR/tmp"
  else
    mkdir "$TARGET_DIR/tmp"
  fi
  require_safe_directory "$TARGET_DIR/tmp"
  local available
  available="$(df --output=avail -B1 "$HDD_ROOT" | tail -1 | tr -d ' ')"
  (( available >= 20 * 1024 * 1024 * 1024 )) || die "less than 20 GiB free on HDD"

  REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)"
  require_clean_tracked_head
  local git_revision source_release stage_root request_path hash_helper
  git_revision="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  require_safe_directory "$INSTALL_ROOT"
  require_safe_directory "$INSTALL_ROOT/releases"
  source_release="$(readlink -f "$CURRENT_PATH")"
  [[ "$source_release" == "${INSTALL_ROOT}/releases/"* && -d "$source_release" ]] || die "current is outside fixed releases root"
  require_immutable_template_release "$source_release"
  RELEASE_ID="$release_id"
  stage_root="${STAGING_ROOT}/${release_id}"
  [[ ! -e "$stage_root" ]] || die "staging target already exists; refusing to overwrite"
  request_path="$TARGET_DIR/requests/${release_id}.json"
  [[ ! -e "$request_path" ]] || die "request target already exists; refusing to overwrite"
  if [[ -e "$TARGET_DIR/requests" ]]; then
    require_safe_directory "$TARGET_DIR/requests"
  else
    mkdir "$TARGET_DIR/requests"
    require_safe_directory "$TARGET_DIR/requests"
  fi

  build_one build --release --package fcp-host --bin fcp-host
  build_one build --release --package fcp-n8n --bin fwc-n8n
  build_one rustc --release --package fcp-n8n --bin fcp-n8n -- -C target-feature=+crt-static
  build_one rustc --release --package fcp-mcp-bridge --bin fcp-mcp-bridge -- -C target-feature=+crt-static
  build_one build --release --package fcp-n8n --features owner-signing --bin fwc-n8n-owner-sign
  build_external_approval_issuer
  run_static_smoke
  build_hash_helper
  hash_helper="$TARGET_DIR/release/fwc-n8n-blake3-helper"

  copy_templates "$source_release" "$stage_root"
  assert_external_approval_issuer_is_not_staged "$stage_root"
  write_inventory_and_request "$stage_root" "$source_release" "$hash_helper" "$request_path" "$git_revision"
  write_metadata "$stage_root" "$git_revision" "$hash_helper"
  echo "assembled_release=${release_id}"
  echo "git_revision=${git_revision}"
  echo "stage_root=${stage_root}"
  echo "request_file=${request_path}"
  echo "signer=${TARGET_DIR}/release/fwc-n8n-owner-sign"
  echo "external_approval_issuer=${TARGET_DIR}/release/${EXTERNAL_APPROVAL_ISSUER}"
  echo "external_approval_issuer_install_target=${EXTERNAL_APPROVAL_ISSUER_INSTALL_PATH}"
  echo "next_step=owner-sign then fwc-n8n provision --mode preflight"
}

main "$@"
