#!/usr/bin/env bash
set -euo pipefail

# Owner-side assembler for one immutable fwc-n8n release.  Build artifacts use
# the guarded local SSD launcher; staging, signing, and promotion remain
# deliberately separate boundaries.

readonly INSTALL_ROOT="/usr/local/lib/fwc-n8n"
readonly CURRENT_PATH="${INSTALL_ROOT}/current"
readonly STAGING_ROOT="/var/lib/fwc-n8n/staging"
readonly SSD_ROOT="/srv/dev-ssd/fcp"
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
readonly EEC_PUBLISH_INPUT_SCHEMA_DIGEST="sha256:93c8bb4e57cea4ae0d368b58dad24560774905ccaa3872f85eb5511bb6162bf6"
readonly EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST="sha256:103216d1ba8bb8e017ec6c068c2764c2ef3fd7950f34f413b32204d541ccfe13"
readonly EEC_UNPUBLISH_INPUT_SCHEMA_DIGEST="sha256:0042470662fcc1488e5d5438ddb3d713675bce04315121b801a3faa7fbea415a"
readonly EEC_UNPUBLISH_OUTPUT_SCHEMA_DIGEST="sha256:78d3bfad1d60d713564c6e04028acdfcd76aa03483606d17a047ea6aab8bb983"
readonly EEC_N8N_VERSION="2.38.4"
readonly HETZNER_PUBLISH_INPUT_SCHEMA_DIGEST="sha256:93c8bb4e57cea4ae0d368b58dad24560774905ccaa3872f85eb5511bb6162bf6"
readonly HETZNER_PUBLISH_OUTPUT_SCHEMA_DIGEST="sha256:103216d1ba8bb8e017ec6c068c2764c2ef3fd7950f34f413b32204d541ccfe13"
readonly HETZNER_UNPUBLISH_INPUT_SCHEMA_DIGEST="sha256:0042470662fcc1488e5d5438ddb3d713675bce04315121b801a3faa7fbea415a"
readonly HETZNER_UNPUBLISH_OUTPUT_SCHEMA_DIGEST="sha256:78d3bfad1d60d713564c6e04028acdfcd76aa03483606d17a047ea6aab8bb983"
readonly LOCAL_MCP_PACKAGE_ID="n8n-mcp"
readonly LOCAL_MCP_PACKAGE_VERSION="2.82.1"
readonly LOCAL_MCP_NODE_PATH="/usr/bin/node"
readonly LOCAL_MCP_PACKAGE_METADATA_PATH="/usr/local/lib/node_modules/n8n-mcp/package.json"
readonly LOCAL_MCP_WRAPPER_PATH="/usr/local/lib/node_modules/n8n-mcp/dist/mcp/stdio-wrapper.js"
readonly LOCAL_MCP_PROTOCOL_VERSION="2024-11-05"
readonly LOCAL_MCP_CATALOG_TOOLS=(
  "tools_documentation"
  "search_nodes"
  "get_node"
  "validate_node"
  "get_template"
  "search_templates"
  "validate_workflow"
)
readonly LOCAL_MCP_CATALOG_DIGESTS=(
  "ab5fd93f48f93709bb2c74cbc23adfbf61ae831bec4cdf59c524a7ea6f6d706a"
  "634829f67fc0f6119133a26968ce4ff486cbd4a8279b5f8528e0f846025a0be6"
  "ed0e86592617677323c1c3319607db73e393a4e3fb16218838bb351ac89af43a"
  "db21817477044c2c28b10e968bafeafdc9f8e9a8d3deaa220f03709bd68bce62"
  "c874dcfebbe77c7b21112d5d5da28d31ae95fa68b87c037765d574efb577de88"
  "2bdd7bdc9e55d04eafdc0948d7b6584d573280dfeb77fe81767bee3d6a0b17c0"
  "0e69609101e4fe8683cd35b7a3b0558d69d3d3005810131f42b4ec53b10a8437"
)

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
  [--target-dir /srv/dev-ssd/fcp/targets/<name>]

Builds and stages a release only. It does not sign, install, switch current,
invoke n8n, read API keys, or run a provider operation.
The script adds /home/ubuntu/.cargo/bin to PATH for the host Rust toolchain.
Cargo output and temporary files are guarded below /srv/dev-ssd/fcp.
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

is_safe_release_id() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]
}

require_safe_directory() {
  local path="$1"
  [[ -d "$path" ]] || die "directory is missing: $path"
  [[ "$(readlink -f "$path")" == "$path" ]] || die "directory path is symlinked: $path"
  local mode
  mode="$(stat -c '%a' "$path")"
  (( (8#$mode & 0022) == 0 )) || die "directory is group/world writable: $path"
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
    'use std::{env,fs::File,io::{self,Read,Write}};' \
    'fn main(){let p=env::args().nth(1).expect("path");let mut f:Box<dyn Read>=if p=="-"{Box::new(io::stdin())}else{Box::new(File::open(p).expect("open"))};let mut h=blake3::Hasher::new();let mut b=[0u8;65536];loop{let n=f.read(&mut b).expect("read");if n==0{break}h.update(&b[..n]);}writeln!(io::stdout(),"{}",h.finalize().to_hex()).expect("write");}' \
    | bash "$SSD_LAUNCHER" --target-dir "$TARGET_DIR" -- rustc - --edition=2024 \
        -L "dependency=${TARGET_DIR}/release/deps" \
        --extern "blake3=${rlib}" \
        -o "$helper"
  chmod 0755 "$helper"
}

require_fixed_local_mcp_file() {
  local path="$1"
  local executable="${2:-0}"
  [[ -f "$path" ]] || die "local n8n-mcp file is missing: $path"
  [[ "$(readlink -f "$path")" == "$path" ]] || die "local n8n-mcp file is symlinked: $path"
  [[ "$(stat -c '%u:%g' "$path")" == "0:0" ]] || die "local n8n-mcp file is not root-owned: $path"
  local mode
  mode="$(stat -c '%a' "$path")"
  (( (8#$mode & 0022) == 0 )) || die "local n8n-mcp file is group/world writable: $path"
  (( (8#$mode & 07000) == 0 )) || die "local n8n-mcp file has special mode bits: $path"
  if [[ "$executable" == "1" ]]; then
    (( (8#$mode & 0111) != 0 )) || die "local n8n-mcp wrapper is not executable: $path"
  fi
}

write_local_mcp_policy() {
  local stage_root="$1"
  local hash_helper="$2"
  require_fixed_local_mcp_file "$LOCAL_MCP_NODE_PATH" 1
  require_fixed_local_mcp_file "$LOCAL_MCP_PACKAGE_METADATA_PATH"
  require_fixed_local_mcp_file "$LOCAL_MCP_WRAPPER_PATH" 1
  python3 - "$stage_root" "$hash_helper" "$LOCAL_MCP_NODE_PATH" \
    "$LOCAL_MCP_PACKAGE_METADATA_PATH" "$LOCAL_MCP_WRAPPER_PATH" \
    "$LOCAL_MCP_PACKAGE_ID" "$LOCAL_MCP_PACKAGE_VERSION" "$LOCAL_MCP_PROTOCOL_VERSION" \
    -- "${LOCAL_MCP_CATALOG_TOOLS[@]}" -- "${LOCAL_MCP_CATALOG_DIGESTS[@]}" <<'PY'
import json
import pathlib
import selectors
import subprocess
import sys
import time

args = sys.argv[1:]
first_separator = args.index("--")
second_separator = args.index("--", first_separator + 1)
(
    stage,
    hash_helper,
    node_path,
    package_metadata_path,
    wrapper_path,
    package_id,
    package_version,
    protocol_version,
) = args[:first_separator]
catalog_tools = args[first_separator + 1 : second_separator]
catalog_digests = args[second_separator + 1 :]

if len(catalog_tools) != 7 or len(catalog_digests) != len(catalog_tools):
    raise SystemExit("local n8n-mcp catalog pins are malformed")

def blake3_bytes(value):
    return subprocess.check_output([hash_helper, "-"], input=value).decode().strip()

def blake3_path(path):
    return subprocess.check_output([hash_helper, path], text=True).strip()

package_metadata = pathlib.Path(package_metadata_path).read_bytes()
try:
    package = json.loads(package_metadata)
except json.JSONDecodeError as error:
    raise SystemExit("installed n8n-mcp package metadata is not valid JSON") from error
if package.get("name") != package_id or package.get("version") != package_version:
    raise SystemExit("installed n8n-mcp package identity does not match reviewed pins")

request_frames = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            # n8n-mcp rewrites schemas for clients whose name contains "n8n";
            # this neutral identity keeps the reviewed catalog deterministic.
            "clientInfo": {"name": "fcp-release-assembler", "version": "1.0.0"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
]
request = b"".join(json.dumps(frame, separators=(",", ":")).encode() + b"\n" for frame in request_frames)
environment = {
    "PATH": "/usr/bin:/bin",
    "N8N_MCP_TELEMETRY_DISABLED": "true",
    "NODE_OPTIONS": "--no-warnings",
    "TMPDIR": "/srv/dev-ssd/fcp/tmp",
}
MAX_STDOUT_BYTES = 512 * 1024
MAX_STDERR_BYTES = 64 * 1024
class DiscoveryError(RuntimeError):
    pass

process = None
try:
    process = subprocess.Popen(
        [
            "/usr/bin/bwrap",
            "--unshare-user",
            "--uid",
            "65534",
            "--gid",
            "65534",
            "--unshare-net",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--chdir",
            str(pathlib.Path(package_metadata_path).parent),
            node_path,
            wrapper_path,
        ],
        cwd=pathlib.Path(package_metadata_path).parent,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    process.stdin.write(request)
    process.stdin.close()
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    selector.register(process.stdout, selectors.EVENT_READ, stdout)
    selector.register(process.stderr, selectors.EVENT_READ, stderr)
    deadline = time.monotonic() + 30
    while selector.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            process.kill()
            raise DiscoveryError("local n8n-mcp catalog discovery timed out")
        for key, _ in selector.select(remaining):
            chunk = key.fileobj.read1(64 * 1024)
            if not chunk:
                selector.unregister(key.fileobj)
                key.fileobj.close()
                continue
            sink = key.data
            sink.extend(chunk)
            limit = MAX_STDOUT_BYTES if sink is stdout else MAX_STDERR_BYTES
            if len(sink) > limit:
                process.kill()
                raise DiscoveryError("local n8n-mcp catalog discovery output exceeded limit")
    return_code = process.wait(timeout=2)
    selector.close()
except (OSError, subprocess.TimeoutExpired, BrokenPipeError, DiscoveryError) as error:
    if process is not None:
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
    raise SystemExit(str(error) or "local n8n-mcp catalog discovery failed") from error
if return_code != 0:
    raise SystemExit("local n8n-mcp catalog discovery failed")

messages = []
for line in stdout.splitlines():
    try:
        messages.append(json.loads(line))
    except json.JSONDecodeError as error:
        raise SystemExit("local n8n-mcp catalog discovery returned malformed JSON") from error
initialize = next((message for message in messages if message.get("id") == 1), None)
catalog = next((message for message in messages if message.get("id") == 2), None)
if (
    initialize is None
    or initialize.get("result", {}).get("protocolVersion") != protocol_version
    or catalog is None
    or not isinstance(catalog.get("result", {}).get("tools"), list)
):
    raise SystemExit("local n8n-mcp catalog discovery returned an invalid handshake")

tools = catalog["result"]["tools"]
observed_tools = {}
for tool in tools:
    if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
        raise SystemExit("installed n8n-mcp catalog has a malformed tool map")
    name = tool["name"]
    if name in observed_tools:
        raise SystemExit("installed n8n-mcp catalog has duplicate tool names")
    observed_tools[name] = tool
if len(observed_tools) != len(catalog_tools) or set(observed_tools) != set(catalog_tools):
    raise SystemExit("installed n8n-mcp catalog names do not match reviewed pins")

observed_digests = []
for name in catalog_tools:
    tool = observed_tools[name]
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        raise SystemExit("installed n8n-mcp catalog has a malformed input schema")
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    observed_digests.append(blake3_bytes(canonical))
if observed_digests != catalog_digests:
    raise SystemExit("installed n8n-mcp catalog schemas do not match reviewed pins")

stage_policy = pathlib.Path(stage) / "policy/local-mcp.json"
policy = {
    "package_id": package_id,
    "package_version": package_version,
    "launcher_path": node_path,
    "launcher_digest": blake3_path(node_path),
    "runtime_executable": node_path,
    "runtime_executable_digest": blake3_path(node_path),
    "package_metadata_path": package_metadata_path,
    "package_metadata_digest": blake3_bytes(package_metadata),
    "protocol_version": protocol_version,
    "fixed_args": [wrapper_path],
    "fixed_env": {"N8N_MCP_TELEMETRY_DISABLED": "true"},
    "allowed_methods": ["initialize", "notifications/initialized", "tools/list", "tools/call"],
    "expected_catalog": dict(zip(catalog_tools, catalog_digests)),
    "callable_tools": catalog_tools,
    "max_frame_bytes": 262144,
    "max_request_bytes": 65536,
    "max_result_bytes": 262144,
    "max_sequential_calls": 7,
    "startup_timeout_ms": 30000,
    "request_timeout_ms": 30000,
    "shutdown_timeout_ms": 2000,
    "idle_window_ms": 0,
    "network_disabled": True,
}
stage_policy.write_text(json.dumps(policy, indent=2) + "\n")
PY
  chown root:root "$stage_root/policy/local-mcp.json"
  chmod 0644 "$stage_root/policy/local-mcp.json"
}

build_one() {
  echo "[build] $*" >&2
  if [[ -n "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX:-}" ]]; then
    env \
      FWC_N8N_OWNER_PUBLIC_KEY_HEX="$FWC_N8N_OWNER_PUBLIC_KEY_HEX" \
      FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX="$FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX" \
      bash "$SSD_LAUNCHER" --target-dir "$TARGET_DIR" -- cargo --locked --offline "$@"
  else
    env \
      FWC_N8N_OWNER_PUBLIC_KEY_HEX="$FWC_N8N_OWNER_PUBLIC_KEY_HEX" \
      bash "$SSD_LAUNCHER" --target-dir "$TARGET_DIR" -- cargo --locked --offline "$@"
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
      .beads/.br-*.lock|.slb/state.db|.slb/state.db-shm|.slb/state.db-wal|crates/fcp-host/.fcp/*|rustc-ice-*.txt) ;;
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
  env FCP_N8N_OWNED_SMOKE_BINARY="$TARGET_DIR/release/fcp-n8n" \
    bash "$SSD_LAUNCHER" --target-dir "$TARGET_DIR" -- cargo --locked --offline test --release -p fcp-host --test n8n_owned_static_smoke \
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
    "$EEC_N8N_VERSION" \
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
    eec_n8n_version,
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
    diagnostics_operation = "n8n.executions.diagnostics"
    if diagnostics_operation not in common["allowed_operations"]:
        common["allowed_operations"].append(diagnostics_operation)
    diagnostics_network = common["operation_network_constraints"].get("n8n.executions.get")
    if not isinstance(diagnostics_network, dict):
        raise SystemExit(f"missing executions.get network constraint for {server}")
    common["operation_network_constraints"][diagnostics_operation] = dict(diagnostics_network)
    delete_operation = "n8n.workflows.delete_disposable"
    if delete_operation not in common["allowed_operations"]:
        common["allowed_operations"].append(delete_operation)
    delete_network = common["operation_network_constraints"].get("n8n.workflows.create_draft")
    if not isinstance(delete_network, dict):
        raise SystemExit(f"missing create_draft network constraint for {server}")
    common["operation_network_constraints"][delete_operation] = dict(delete_network)
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
    if server == "eec":
        official["config"]["capability_policy"]["n8n_version"] = eec_n8n_version
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
  TARGET_DIR="${SSD_ROOT}/targets/n8n-release"
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
  REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)"
  SSD_LAUNCHER="${REPO_ROOT}/scripts/fcp_ssd.sh"
  [[ -f "$SSD_LAUNCHER" && ! -L "$SSD_LAUNCHER" ]] \
    || die "SSD launcher is missing or symlinked: $SSD_LAUNCHER"
  is_safe_release_id "$release_id" || die "invalid release id"
  [[ "${FWC_N8N_OWNER_PUBLIC_KEY_HEX:-}" =~ ^[0-9a-f]{64}$ ]] || die "FWC_N8N_OWNER_PUBLIC_KEY_HEX must be 64 lowercase hex characters"
  if [[ -n "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX:-}" ]]; then
    [[ "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX}" =~ ^[0-9a-f]{64}$ ]] \
      || die "FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX must be 64 lowercase hex characters"
    [[ "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX}" != "${FWC_N8N_OWNER_PUBLIC_KEY_HEX}" ]] \
      || die "active and previous owner public keys must differ"
  fi
  bash "$SSD_LAUNCHER" --target-dir "$TARGET_DIR" -- true >/dev/null
  require_safe_directory "/var/lib/fwc-n8n"
  require_safe_directory "$STAGING_ROOT"
  if [[ -e "$TARGET_DIR" ]]; then
    require_safe_directory "$TARGET_DIR"
  else
    mkdir "$TARGET_DIR"
    require_safe_directory "$TARGET_DIR"
  fi
  local available
  available="$(df --output=avail -B1 "$SSD_ROOT" | tail -1 | tr -d ' ')"
  (( available >= 20 * 1024 * 1024 * 1024 )) || die "less than 20 GiB free on SSD"

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
  write_local_mcp_policy "$stage_root" "$hash_helper"
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
