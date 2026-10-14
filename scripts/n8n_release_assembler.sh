#!/usr/bin/env bash
set -euo pipefail

# Owner-side assembler for one immutable fwc-n8n release.  Build artifacts use
# the guarded local SSD launcher; staging, signing, and promotion remain
# deliberately separate boundaries.

readonly INSTALL_ROOT="/usr/local/lib/fwc-n8n"
readonly CURRENT_PATH="${INSTALL_ROOT}/current"
# Selected once from the closed current-release profiles before retained work.
RETAINED_RELEASE="${INSTALL_ROOT}/releases/release-20261012-native-diagnostics-4a2d827a-rc1"
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
readonly EEC_PUBLISH_INPUT_SCHEMA_DIGEST="${FWC_N8N_EEC_PUBLISH_INPUT_SCHEMA_DIGEST:-sha256:93c8bb4e57cea4ae0d368b58dad24560774905ccaa3872f85eb5511bb6162bf6}"
readonly EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST="${FWC_N8N_EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST:-sha256:377ede5c5c793ad7c1f123dfac17238cd69f29fd764333519c0ac170a4639ca9}"
readonly EEC_UNPUBLISH_INPUT_SCHEMA_DIGEST="${FWC_N8N_EEC_UNPUBLISH_INPUT_SCHEMA_DIGEST:-sha256:0042470662fcc1488e5d5438ddb3d713675bce04315121b801a3faa7fbea415a}"
readonly EEC_UNPUBLISH_OUTPUT_SCHEMA_DIGEST="${FWC_N8N_EEC_UNPUBLISH_OUTPUT_SCHEMA_DIGEST:-sha256:78d3bfad1d60d713564c6e04028acdfcd76aa03483606d17a047ea6aab8bb983}"
# Lifecycle schemas are owner-provisioned from a fresh official-MCP tools/list
# snapshot.  They are deliberately not guessed or copied from the current
# release: a provider/database restore can change the live schema while the
# installed bundle remains otherwise valid.  Requiring archive and execute
# values makes that drift an explicit release input instead of a silent stale
# policy that blocks every write-capability snapshot.
readonly EEC_ARCHIVE_INPUT_SCHEMA_DIGEST="${FWC_N8N_EEC_ARCHIVE_INPUT_SCHEMA_DIGEST:-}"
readonly EEC_ARCHIVE_OUTPUT_SCHEMA_DIGEST="${FWC_N8N_EEC_ARCHIVE_OUTPUT_SCHEMA_DIGEST:-}"
readonly EEC_EXECUTE_INPUT_SCHEMA_DIGEST="${FWC_N8N_EEC_EXECUTE_INPUT_SCHEMA_DIGEST:-}"
readonly EEC_EXECUTE_OUTPUT_SCHEMA_DIGEST="${FWC_N8N_EEC_EXECUTE_OUTPUT_SCHEMA_DIGEST:-}"
readonly HETZNER_PUBLISH_INPUT_SCHEMA_DIGEST="${FWC_N8N_HETZNER_PUBLISH_INPUT_SCHEMA_DIGEST:-sha256:93c8bb4e57cea4ae0d368b58dad24560774905ccaa3872f85eb5511bb6162bf6}"
readonly HETZNER_PUBLISH_OUTPUT_SCHEMA_DIGEST="${FWC_N8N_HETZNER_PUBLISH_OUTPUT_SCHEMA_DIGEST:-sha256:377ede5c5c793ad7c1f123dfac17238cd69f29fd764333519c0ac170a4639ca9}"
readonly HETZNER_UNPUBLISH_INPUT_SCHEMA_DIGEST="${FWC_N8N_HETZNER_UNPUBLISH_INPUT_SCHEMA_DIGEST:-sha256:0042470662fcc1488e5d5438ddb3d713675bce04315121b801a3faa7fbea415a}"
readonly HETZNER_UNPUBLISH_OUTPUT_SCHEMA_DIGEST="${FWC_N8N_HETZNER_UNPUBLISH_OUTPUT_SCHEMA_DIGEST:-sha256:78d3bfad1d60d713564c6e04028acdfcd76aa03483606d17a047ea6aab8bb983}"
readonly HETZNER_ARCHIVE_INPUT_SCHEMA_DIGEST="${FWC_N8N_HETZNER_ARCHIVE_INPUT_SCHEMA_DIGEST:-}"
readonly HETZNER_ARCHIVE_OUTPUT_SCHEMA_DIGEST="${FWC_N8N_HETZNER_ARCHIVE_OUTPUT_SCHEMA_DIGEST:-}"
readonly HETZNER_EXECUTE_INPUT_SCHEMA_DIGEST="${FWC_N8N_HETZNER_EXECUTE_INPUT_SCHEMA_DIGEST:-}"
readonly HETZNER_EXECUTE_OUTPUT_SCHEMA_DIGEST="${FWC_N8N_HETZNER_EXECUTE_OUTPUT_SCHEMA_DIGEST:-}"
readonly LOCAL_MCP_PACKAGE_ID="n8n-mcp"
readonly LOCAL_MCP_NODE_PATH="/usr/bin/node"
readonly LOCAL_MCP_PACKAGE_METADATA_PATH="/usr/local/lib/node_modules/n8n-mcp/package.json"
readonly LOCAL_MCP_WRAPPER_PATH="/usr/local/lib/node_modules/n8n-mcp/dist/mcp/stdio-wrapper.js"
readonly LOCAL_MCP_IMMUTABLE_ROOT="/var/lib/fwc-n8n/packages/n8n-mcp-2.91.0-fe77448f"
readonly LOCAL_MCP_PREPARATION_PATH="/usr/local/lib/fwc-n8n/admissions/local-mcp-package.json"
LOCAL_MCP_PACKAGE_INPUT=""
LOCAL_MCP_PACKAGE_INPUT_SHA256=""
readonly LOCAL_MCP_PROTOCOL_VERSION="2024-11-05"
# Explicit reviewed baselines are optional; absent baselines retain raw-only
# behavior. Never enroll ambient tools/list as reviewed compatibility policy.
readonly REVIEWED_SCHEMA_BASELINES="${FWC_N8N_REVIEWED_SCHEMA_BASELINES:-}"
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
  FWC_N8N_EEC_ARCHIVE_INPUT_SCHEMA_DIGEST=<sha256:64 lowercase hex chars> \
  FWC_N8N_EEC_ARCHIVE_OUTPUT_SCHEMA_DIGEST=<sha256:64 lowercase hex chars> \
  FWC_N8N_EEC_EXECUTE_INPUT_SCHEMA_DIGEST=<sha256:64 lowercase hex chars> \
  FWC_N8N_EEC_EXECUTE_OUTPUT_SCHEMA_DIGEST=<sha256:64 lowercase hex chars> \
  FWC_N8N_HETZNER_ARCHIVE_INPUT_SCHEMA_DIGEST=<sha256:64 lowercase hex chars> \
  FWC_N8N_HETZNER_ARCHIVE_OUTPUT_SCHEMA_DIGEST=<sha256:64 lowercase hex chars> \
  FWC_N8N_HETZNER_EXECUTE_INPUT_SCHEMA_DIGEST=<sha256:64 lowercase hex chars> \
  FWC_N8N_HETZNER_EXECUTE_OUTPUT_SCHEMA_DIGEST=<sha256:64 lowercase hex chars> \
  [FWC_N8N_LOCAL_CALL_BUDGET_SHA256=<64 lowercase hex chars>] \
  [FWC_N8N_REUSE_RETAINED=1 FWC_N8N_EXECUTION_SEARCH=1 \
   FWC_N8N_BLAKE3_HELPER=<admitted canonical helper> \
   FWC_N8N_BLAKE3_HELPER_SHA256=<64 lowercase hex chars> \
   FWC_N8N_BLAKE3_HELPER_BYTES=<exact byte count> \
   FWC_N8N_BLAKE3_RLIB=<admitted canonical rlib> \
   FWC_N8N_BLAKE3_RLIB_SHA256=<64 lowercase hex chars> \
   FWC_N8N_BLAKE3_RLIB_BYTES=<exact byte count>] \
  scripts/n8n_release_assembler.sh \
  --release-id <safe-release-id> \
  [--target-dir /srv/dev-ssd/fcp/targets/<name>]

Builds and stages a release only. It does not sign, install, switch current,
invoke n8n, read API keys, or run a provider operation.
The script adds /home/ubuntu/.cargo/bin to PATH for the host Rust toolchain.
Cargo output and temporary files are guarded below /srv/dev-ssd/fcp.
The optional local-call-budget digest binds separately admitted root:root 0600
/srv/dev-ssd/rc41-inputs/local-call-budget.json with exactly
{"schema":"fwc.n8n.local-call-budget.v1","max_sequential_calls":20}.
Without this opt-in, the generated signed policy retains 7 calls.
Retained reuse requires an admitted read profile and the exact pinned rc1
runtime/template set. It builds only the CLI and guarded admin, retains the
native package and local policy, and never builds or substitutes the issuer.
The closed runtime provenance identifies the new recipe/CLI source; a separate
review ledger must retain the three runtime binaries' actual 4a source identity.
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
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
    require_pinned_build_input "${FWC_N8N_BLAKE3_RLIB:-}" "${FWC_N8N_BLAKE3_RLIB_SHA256:-}" rlib
    return
  fi
  local candidate
  candidate="$(find "${TARGET_DIR}/release/deps" -maxdepth 1 -type f \
    -name 'libblake3-*.rlib' -printf '%T@ %p\n' 2>/dev/null \
    | sort -n | tail -1 | cut -d' ' -f2-)"
  [[ -n "$candidate" && -f "$candidate" ]] || die "Cargo did not produce the blake3 library"
  printf '%s\n' "$candidate"
}

build_hash_helper() {
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
    require_pinned_build_input "${FWC_N8N_BLAKE3_HELPER:-}" "${FWC_N8N_BLAKE3_HELPER_SHA256:-}" helper >/dev/null
    find_blake3_rlib >/dev/null
    return
  fi
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

# Pure producer boundary also exercised offline. It emits only catalog policy
# bindings and never discovers a provider, installs, signs or approves anything.
assemble_local_catalog_bindings() {
  local source_binary="$1"
  python3 - "$source_binary" "${LOCAL_MCP_CATALOG_TOOLS[@]}" 3<&0 <<'PY'
import json
import os
import subprocess
import sys

MAX_BYTES = 262144
binary = sys.argv[1]
names = sys.argv[2:]

def fail():
    raise SystemExit("local catalog policy binding invalid")

def unique_object(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            fail()
        value[key] = child
    return value

raw = os.fdopen(3, "rb").read(MAX_BYTES + 1)
if len(raw) > MAX_BYTES:
    fail()
request = json.loads(raw, object_pairs_hook=unique_object)
pins = request["expected_catalog"]
baselines = request.get("reviewed_baselines", {})
catalog = request["catalog"]
if (set(pins) != set(names) or not isinstance(baselines, dict)
    or not set(baselines).issubset(pins)
    or not isinstance(catalog, dict) or not isinstance(catalog.get("tools"), list)
    or catalog.get("nextCursor") is not None):
    fail()

def invoke(command, value):
    try:
        result = subprocess.run([binary, command], input=json.dumps(value).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True)
        if len(result.stdout) > MAX_BYTES:
            fail()
        return json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        fail()

observed = {}
for tool in catalog["tools"]:
    if (not isinstance(tool, dict) or not isinstance(tool.get("name"), str)
        or not tool["name"] or len(tool["name"]) > 256
        or any(character.isspace() or ord(character) < 32 for character in tool["name"])
        or tool["name"] in observed or not isinstance(tool.get("inputSchema"), dict)
        or ("outputSchema" in tool and not isinstance(tool["outputSchema"], dict))
        or any(field in tool and not isinstance(tool[field], str) for field in ("title", "description"))
        or any(field in tool and not isinstance(tool[field], dict) for field in ("annotations", "_meta"))):
        fail()
    observed[tool["name"]] = tool
if not set(names).issubset(observed):
    fail()

# Default pins are the reviewed legacy contract: no outputSchema. Discovery
# cannot change these pins. Present output requires an explicit reviewed baseline.
absence = invoke("schema-projection", {"input_schema": {}, "output_schema": None})["output_schema_digest"]
output_pins = dict.fromkeys(names, absence)
profiles = {}
for name, baseline in baselines.items():
    if (not isinstance(baseline, dict) or baseline.get("integrity") != "blake3"
        or baseline.get("input_schema_digest") != pins[name]):
        fail()
    profiles[name] = invoke("reviewed-schema-profile", baseline)
    output_pins[name] = baseline["output_schema_digest"]

for name in names:
    tool = observed[name]
    # Observation produces digests only, never an approved baseline.
    projection = invoke("schema-projection", {
        "input_schema": tool["inputSchema"], "output_schema": tool.get("outputSchema"),
    })
    if name in profiles:
        if any(projection[field] != profiles[name][field] for field in (
            "profile", "input_compatibility_digest", "output_compatibility_digest"
        )):
            fail()
    elif (projection["input_schema_digest"] != pins[name]
          or projection["output_schema_digest"] != output_pins[name]):
        fail()

policy = {"expected_catalog": pins, "expected_output_catalog": output_pins,
    "reviewed_schemas": profiles, "callable_tools": names}
encoded = json.dumps(policy, sort_keys=True, separators=(",", ":"))
if len(encoded.encode()) > MAX_BYTES:
    fail()
print(encoded)
PY
}

validate_official_schema_baselines() {
  local source_binary="$1"
  python3 - "$source_binary" "$REVIEWED_SCHEMA_BASELINES" \
    "$EEC_PUBLISH_INPUT_SCHEMA_DIGEST" "$EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$EEC_UNPUBLISH_INPUT_SCHEMA_DIGEST" "$EEC_UNPUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$EEC_ARCHIVE_INPUT_SCHEMA_DIGEST" "$EEC_ARCHIVE_OUTPUT_SCHEMA_DIGEST" \
    "$EEC_EXECUTE_INPUT_SCHEMA_DIGEST" "$EEC_EXECUTE_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_PUBLISH_INPUT_SCHEMA_DIGEST" "$HETZNER_PUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_UNPUBLISH_INPUT_SCHEMA_DIGEST" "$HETZNER_UNPUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_ARCHIVE_INPUT_SCHEMA_DIGEST" "$HETZNER_ARCHIVE_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_EXECUTE_INPUT_SCHEMA_DIGEST" "$HETZNER_EXECUTE_OUTPUT_SCHEMA_DIGEST" <<'PY'
import json
import os
import pathlib
import re
import subprocess
import sys

binary, baseline_path, *pins = sys.argv[1:]
servers = ("eec", "hetzner")
tools = ("publish_workflow", "unpublish_workflow", "archive_workflow", "execute_workflow")
directions = ("input", "output")

def fail():
    raise SystemExit("reviewed official schema baseline prebuild validation denied")

def unique_object(pairs):
    value = {}
    for key, child in pairs:
        if key in value:
            fail()
        value[key] = child
    return value

current = (
    "sha256:93c8bb4e57cea4ae0d368b58dad24560774905ccaa3872f85eb5511bb6162bf6",
    "sha256:377ede5c5c793ad7c1f123dfac17238cd69f29fd764333519c0ac170a4639ca9",
    "sha256:0042470662fcc1488e5d5438ddb3d713675bce04315121b801a3faa7fbea415a",
    "sha256:78d3bfad1d60d713564c6e04028acdfcd76aa03483606d17a047ea6aab8bb983",
)
if len(pins) != 16:
    fail()
changed = {(server, tool) for server_index, server in enumerate(servers)
    for tool_index, tool in enumerate(tools[:2])
    if pins[server_index * 8 + tool_index * 2:server_index * 8 + tool_index * 2 + 2]
        != list(current[tool_index * 2:tool_index * 2 + 2])}
if not baseline_path:
    if changed:
        fail()
    print('{"status":"current_raw_defaults","reviewed_baselines":false}')
    raise SystemExit(0)
try:
    raw = pathlib.Path(baseline_path).read_bytes()
    if len(raw) > 1048576:
        fail()
    baselines = json.loads(raw, object_pairs_hook=unique_object)
    if (not isinstance(baselines, dict) or not set(baselines).issubset({"eec", "hetzner", "local", "_authority"})):
        fail()
    supplied = set()
    # Admission and original schema capture pins are established by the protected
    # caller. This boundary validates those explicit inputs; it never discovers
    # or enrolls ambient provider schemas.
    for server_index, server in enumerate(servers):
        values = baselines.get(server, {})
        if not isinstance(values, dict) or not set(values).issubset(tools):
            fail()
        for tool_index, tool in enumerate(tools):
            if tool not in values:
                continue
            baseline = values[tool]
            offset = server_index * 8 + tool_index * 2
            if (not isinstance(baseline, dict) or baseline.get("integrity") != "sha256"
                or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", p) for p in pins[offset:offset + 2])
                or baseline.get("input_schema_digest") != pins[offset]
                or baseline.get("output_schema_digest") != pins[offset + 1]):
                fail()
            result = subprocess.run([binary, "reviewed-schema-profile"],
                input=json.dumps(baseline).encode(), stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=10, check=False)
            if result.returncode != 0 or len(result.stdout) > 262144:
                fail()
            json.loads(result.stdout)
            supplied.add((server, tool))
    if not changed.issubset(supplied):
        fail()
except (OSError, ValueError, subprocess.SubprocessError):
    fail()
print(json.dumps({"status": "reviewed_official_baselines_verified", "tools": len(supplied), "native_pins": 2 * len(supplied)}))
PY
}

# Offline candidate preparation only. This NEVER changes the installed package,
# the registry updater, a signed policy, or admission. Published dist bytes are
# patched deterministically; their output is NOT the upstream registry artifact.
prepare_derived_local_validator() {
  [[ "$EUID" -ne 0 && "${FCP_SSD_ACTIVE:-}" == 1 ]] || die "derived preparation requires rootless SSD launcher"
  python3 - "$1" "$(dirname "${BASH_SOURCE[0]}")/n8n_mcp_2_91_versioned_validation.patch" <<'PY'
import base64
import hashlib
import io
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tarfile

FIXED = {
    'dist/mcp/server.js': 'a4dfc41f48282423a610ee9ac45c0374357b7409cdaa4858e11ba58a32b2128c',
    'dist/services/workflow-validator.js': 'c0072e5cdd9169a573aa86a659915f7877a71657f304538496f72d723c38a055',
    'dist/services/config-validator.js': '14221eae947f330ab4e5729306b174d8e137c5c860656b69c91502f569d7c19c',
    'dist/services/enhanced-config-validator.js': '98672564f2f18a554be3b1bc2c9e15d41827ed0819e67724294758715c77d0ad',
    'dist/services/type-structure-service.js': '95cbe356946a59d3a3fcef4822a9e1f5cb9db2d0cb767905619d8853efc70eb1',
}
EXPECTED_PATCH = '391a6acf86de476e45a7a65ad286719dca569abe7d216c2a50eaae7efc1fd832'
BASE = pathlib.Path('/srv/dev-ssd/fcp/nqm81-35')
def fail():
    raise SystemExit('derived_validator_input_or_provenance_invalid')
def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
def read_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid not in (0, os.getuid()) or before.st_mode & 0o022 or before.st_nlink != 1 or before.st_size > limit:
            fail()
        chunks = []
        count = 0
        while True:
            chunk = os.read(fd, min(1048576, limit + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count > limit:
                fail()
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(os.lstat(path)):
            fail()
        return b''.join(chunks), stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail()
        result[key] = value
    return result
def loads(data):
    return json.loads(data, object_pairs_hook=unique)
def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
def digest(data):
    return hashlib.sha256(data).hexdigest()
def anchored(path, directory=True):
    path = pathlib.Path(path)
    if not path.is_absolute() or path.resolve() != path or not path.is_relative_to(BASE) or path == BASE:
        fail()
    for parent in [BASE, *reversed(path.parents[:-len(BASE.parents)])]:
        if parent == path:
            continue
        s = os.lstat(parent)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid not in (0, os.getuid()) or s.st_mode & 0o022:
            fail()
    if directory:
        s = os.lstat(path)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o022:
            fail()
    return path
def tree(root):
    rows = []
    total = 0
    # Match exported SHA rows and the rootless verifier's string-key ordering.
    # Path component ordering differs for sibling names beside a directory.
    for path in sorted(root.rglob('*'), key=lambda p: str(p.relative_to(root))):
        s = os.lstat(path)
        relative = str(path.relative_to(root))
        if stat.S_ISDIR(s.st_mode):
            if s.st_uid != os.getuid() or s.st_mode & 0o022:
                fail()
            rows.append({'path': relative, 'kind': 'directory', 'mode': stat.S_IMODE(s.st_mode)})
        elif stat.S_ISREG(s.st_mode):
            data, mode = read_file(path, 134217728)
            total += len(data)
            if total > 536870912:
                fail()
            rows.append({'path': relative, 'kind': 'file', 'mode': mode, 'size': len(data), 'sha256': digest(data)})
        else:
            fail()
        if len(rows) > 20000:
            fail()
    return rows
def write_new(path, data, mode=0o644):
    if mode & 0o7022:
        fail()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                fail()
            view = view[count:]
        # umask stays private; restore only the verified mode on this new FD.
        os.fchmod(fd, mode)
        if stat.S_IMODE(os.fstat(fd).st_mode) != mode:
            fail()
        os.fsync(fd)
    finally:
        os.close(fd)

try:
    request = loads(read_file(sys.argv[1], 16384)[0])
    keys = {'schema', 'version', 'upstreamRoot', 'upstreamTreeSha256', 'registryTarball', 'registryTarballSha256', 'registryTarballSha512', 'patchSha256', 'outputRoot'}
    if not isinstance(request, dict) or set(request) != keys or request['schema'] != 'fwc.n8n.derived-validator-input.v1' or request['version'] != '2.91.0':
        fail()
    if any(not isinstance(request[k], str) or not re.fullmatch('[0-9a-f]{64}', request[k]) for k in ('upstreamTreeSha256', 'registryTarballSha256', 'patchSha256')):
        fail()
    source = anchored(request['upstreamRoot'])
    output = pathlib.Path(request['outputRoot'])
    if not re.fullmatch('derived-n8n-mcp-2[.]91-[0-9a-f]{32}', output.name) or output.parent != BASE:
        fail()
    anchored(output.parent / 'unused', False)  # Validate parent only; no creation.
    if os.path.lexists(output):
        fail()
    tar_path = anchored(request['registryTarball'], False)
    tar_bytes = read_file(tar_path, 134217728)[0]
    sri = 'sha512-' + base64.b64encode(hashlib.sha512(tar_bytes).digest()).decode()
    if digest(tar_bytes) != request['registryTarballSha256'] or sri != request['registryTarballSha512']:
        fail()
    patch = read_file(sys.argv[2], 262144)[0]
    if digest(patch) != EXPECTED_PATCH or request['patchSha256'] != EXPECTED_PATCH:
        fail()
    package = source / 'node_modules/n8n-mcp'
    metadata = loads(read_file(package / 'package.json', 65536)[0])
    if metadata.get('name') != 'n8n-mcp' or metadata.get('version') != '2.91.0' or 'fwcDerivedValidation' in metadata:
        fail()
    # Bind ALL published root-package bytes to the exact verified tarball,
    # rather than treating an independent tree digest as registry provenance.
    members = {}
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode='r:gz') as archive:
        for member in archive:
            parts = tuple(member.name.rstrip('/').split('/'))
            if not parts or parts[0] != 'package' or any(p in ('', '.', '..') for p in parts):
                fail()
            relative = '/'.join(parts[1:])
            if member.isdir():
                continue
            if not member.isfile() or not relative or relative in members or member.size > 134217728:
                fail()
            expanded += member.size
            if expanded > 536870912 or len(members) >= 20000:
                fail()
            stream = archive.extractfile(member)
            if stream is None:
                fail()
            content = stream.read(member.size + 1)
            if len(content) != member.size or digest(read_file(package / relative, 134217728)[0]) != digest(content):
                fail()
            members[relative] = digest(content)
    published_files = {str(p.relative_to(package)) for p in package.rglob('*')
        if p.is_file() and 'node_modules' not in p.relative_to(package).parts}
    if published_files != set(members):
        fail()
    for relative, expected in FIXED.items():
        if digest(read_file(package / relative, 8388608)[0]) != expected:
            fail()
    original = tree(source)
    if digest(canonical(original)) != request['upstreamTreeSha256']:
        fail()
    os.mkdir(output, 0o700)
    for row in original:
        destination = output / row['path']
        if row['kind'] == 'directory':
            os.mkdir(destination, row['mode'])
        else:
            data = read_file(source / row['path'], 134217728)[0]
            if digest(data) != row['sha256']:
                fail()
            write_new(destination, data, row['mode'])
    target = output / 'node_modules/n8n-mcp'
    completed = subprocess.run(['/usr/bin/patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch', '-p2', '-d', str(target)],
        input=patch, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    if completed.returncode != 0 or len(completed.stdout) + len(completed.stderr) > 16384:
        fail()
    changed = {relative: digest(read_file(target / relative, 8388608)[0]) for relative in FIXED}
    package_files = {r['path']: r['sha256'] for r in tree(target)
        if r['kind'] == 'file' and r['path'] != 'package.json'}
    before_metadata = digest(read_file(target / 'package.json', 65536)[0])
    metadata['fwcDerivedValidation'] = {'schema': 'fwc.n8n.derived-validator.v1', 'upstreamVersion': '2.91.0',
        'upstreamMetadataSha256': before_metadata, 'patchSha256': EXPECTED_PATCH,
        'registryTarballSha256': request['registryTarballSha256'], 'registryTarballSha512': sri,
        'files': changed, 'packageFiles': package_files}
    # Only this NEW candidate metadata is replaced; installed/upstream bytes stay immutable.
    with open(target / 'package.json', 'wb') as stream:
        stream.write(canonical(metadata) + b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    if tree(source) != original:
        fail()
    result = tree(output)
    original_map = {r['path']: r for r in original}
    result_map = {r['path']: r for r in result}
    allowed = {'node_modules/n8n-mcp/' + p for p in FIXED} | {'node_modules/n8n-mcp/package.json'}
    if set(original_map) != set(result_map) or any(original_map[p] != result_map[p] for p in original_map if p not in allowed):
        fail()
    receipt = {'schema': 'fwc.n8n.derived-validator-preparation.v1', 'sourceKind': 'derived_dist_patch',
        'upstreamTreeSha256': request['upstreamTreeSha256'], 'registryTarballSha256': request['registryTarballSha256'],
        'registryTarballSha512': sri, 'patchSha256': EXPECTED_PATCH, 'resultTreeSha256': digest(canonical(result)),
        'packageMetadataSha256': digest(read_file(target / 'package.json', 4194304)[0]), 'files': result,
        'admitted': False, 'installed': False, 'dependencyClosureAuthority': 'requires_existing_registry_stage_verification'}
    write_new(output / 'derived-provenance.json', canonical(receipt) + b'\n', 0o600)
    print(json.dumps({'status': 'derived_candidate_prepared', 'admitted': False,
        'resultTreeSha256': receipt['resultTreeSha256'], 'patchSha256': EXPECTED_PATCH}))
except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, subprocess.SubprocessError):
    fail()
PY
}

write_local_mcp_policy() {
  local stage_root="$1"
  local hash_helper="$2"
  local export_binary="${3:-}"
  local sequential_calls
  local package_metadata_path="$LOCAL_MCP_PACKAGE_METADATA_PATH"
  local wrapper_path="$LOCAL_MCP_WRAPPER_PATH"
  if [[ -n "$LOCAL_MCP_PACKAGE_INPUT" ]]; then
    package_metadata_path="$LOCAL_MCP_IMMUTABLE_ROOT/node_modules/n8n-mcp/package.json"
    wrapper_path="$LOCAL_MCP_IMMUTABLE_ROOT/node_modules/n8n-mcp/dist/mcp/stdio-wrapper.js"
  fi
  sequential_calls="$(local_call_budget)"
  require_fixed_local_mcp_file "$LOCAL_MCP_NODE_PATH" 1
  require_fixed_local_mcp_file "$package_metadata_path"
  if [[ -n "$LOCAL_MCP_PACKAGE_INPUT" ]]; then
    # Node reads the immutable JS entry; its SOURCE mode0600 projects to0444.
    require_fixed_local_mcp_file "$wrapper_path"
  else
    require_fixed_local_mcp_file "$wrapper_path" 1
  fi
  python3 - "$stage_root" "$hash_helper" "$LOCAL_MCP_NODE_PATH" \
    "$package_metadata_path" "$wrapper_path" \
    "$LOCAL_MCP_PACKAGE_ID" "$LOCAL_MCP_PROTOCOL_VERSION" "${BASH_SOURCE[0]}" "$export_binary" "$sequential_calls" \
    "$LOCAL_MCP_PACKAGE_INPUT" "$LOCAL_MCP_PACKAGE_INPUT_SHA256" "${RELEASE_ID:-}" "${TARGET_DIR:-}/release/fwc-n8n" \
    -- "${LOCAL_MCP_CATALOG_TOOLS[@]}" -- "${LOCAL_MCP_CATALOG_DIGESTS[@]}" <<'PY'
import json
import pathlib
import selectors
import hashlib
import uuid
import subprocess
import sys
import time
import os

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
    protocol_version,
    assembler_path,
    export_binary,
    sequential_calls,
    package_input,
    package_input_sha256,
    release_id,
    preparation_binary,
) = args[:first_separator]
catalog_tools = args[first_separator + 1 : second_separator]
catalog_digests = args[second_separator + 1 :]

if len(catalog_tools) != 7 or len(catalog_digests) != len(catalog_tools):
    raise SystemExit("local n8n-mcp catalog pins are malformed")

def verify_prepared_package():
    if not package_input:
        return None
    checked = subprocess.run([preparation_binary, 'export-schemas', 'local', '--check-only',
        '--package-binding-file', package_input, '--package-binding-sha256', package_input_sha256,
        '--release-id', release_id], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30)
    if checked.returncode != 0 or len(checked.stdout) > 16384:
        raise SystemExit('immutable local package preparation denied')
    result = json.loads(checked.stdout)
    if result.get('schema') != 'fwc.n8n.package-preparation-check.v1' or result.get('productionAdmission') is not False:
        raise SystemExit('immutable package verifier response denied')
    binding = result.get('package_binding')
    if not isinstance(binding, dict) or binding.get('release_id') != release_id:
        raise SystemExit('immutable package release binding denied')
    return binding

package_binding = verify_prepared_package()
if export_binary and not package_input:
    # Check signed fixed current and exact public Node/package pins BEFORE spawn.
    preflight = subprocess.run([export_binary, "export-schemas", "local", "--check-only"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=20)
    if preflight.returncode != 0:
        raise SystemExit("local schema export preflight denied")

def blake3_bytes(value):
    return subprocess.check_output([hash_helper, "-"], input=value).decode().strip()

def blake3_path(path):
    return subprocess.check_output([hash_helper, path], text=True).strip()

package_metadata = pathlib.Path(package_metadata_path).read_bytes()
try:
    package = json.loads(package_metadata)
except json.JSONDecodeError as error:
    raise SystemExit("installed n8n-mcp package metadata is not valid JSON") from error
observed_version = package.get("version")
if package.get("name") != package_id or not isinstance(observed_version, str) or not observed_version:
    raise SystemExit("installed n8n-mcp package name or version is invalid")

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
            *(["--no-global-search-paths"] if package_binding is not None else []),
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

baseline_path = os.environ.get("FWC_N8N_REVIEWED_SCHEMA_BASELINES", "")
if export_binary:
    if (len(messages) != 2 or any(message.get("jsonrpc") != "2.0" for message in messages)
        or {message.get("id") for message in messages} != {1, 2}
        or any("error" in message for message in messages)):
        raise SystemExit("local schema export frame invalid")
    tools = catalog["result"]["tools"]
    names = set()
    if len(tools) > 256 or catalog["result"].get("nextCursor") is not None:
        raise SystemExit("local schema export catalog invalid")
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            raise SystemExit("local schema export catalog invalid")
        name = tool["name"]
        if name in names:
            raise SystemExit("local schema export catalog invalid")
        names.add(name)
    result = subprocess.run([export_binary, "export-schemas", "local"],
        input=json.dumps({"status":"ok", "result":catalog["result"]}).encode(),
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode != 0:
        try:
            code = json.loads(result.stdout).get("code")
        except (ValueError, AttributeError):
            code = None
        safe_codes = {"schema_export_invalid", "schema_export_too_large", "schema_export_schema_invalid",
            "schema_export_sensitive_content", "schema_export_injection_content", "schema_export_tool_missing", "input_too_large",
            "schema_export_signature_denied", "schema_export_local_pin_denied"}
        raise SystemExit(code if code in safe_codes else "local schema export validation denied")
    original_receipt = json.loads(result.stdout)
    original_path = pathlib.Path(original_receipt["path"])
    if hashlib.sha256(original_path.read_bytes()).hexdigest() != original_receipt["file_sha256"]:
        raise SystemExit("local schema export receipt invalid")
    receipt_path = pathlib.Path("/srv/dev-ssd/fcp/nqm81-34") / ("local-schema-capture-" + str(uuid.uuid4()) + ".json")
    capture = {"schema":"fwc.n8n.local-schema-capture.v1", "route":"fixed_node/bwrap_unshare_net",
        "network":"disabled", "uid":65534, "gid":65534, "exit":return_code,
        "argv":process.args, "environment":environment,
        "request_sha256":hashlib.sha256(request).hexdigest(),
        "exporter_sha256":hashlib.sha256(pathlib.Path(export_binary).read_bytes()).hexdigest(),
        "catalog_stdout_sha256":hashlib.sha256(stdout).hexdigest(),
        "catalog_sha256":hashlib.sha256(json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "originals":original_receipt, "assembler_sha256":hashlib.sha256(pathlib.Path(assembler_path).read_bytes()).hexdigest()}
    with os.fdopen(os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as receipt_file:
        json.dump(capture, receipt_file, sort_keys=True)
        receipt_file.flush()
        os.fsync(receipt_file.fileno())
    # Only a compact file/hash receipt reaches stdout, never original schemas.
    original_receipt["capture_receipt_path"] = str(receipt_path)
    original_receipt["capture_receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    print(json.dumps(original_receipt, sort_keys=True))
    raise SystemExit(0)
baselines = json.loads(pathlib.Path(baseline_path).read_text()).get("local", {}) if baseline_path else {}
bindings = json.loads(subprocess.check_output(
    ["bash", assembler_path, "--offline-catalog-bindings", str(pathlib.Path(stage) / "bin/fwc-n8n")],
    input=json.dumps({"expected_catalog": dict(zip(catalog_tools, catalog_digests)),
        "reviewed_baselines": baselines, "catalog": catalog["result"]}).encode(),
    stderr=subprocess.DEVNULL, timeout=180,
))

stage_policy = pathlib.Path(stage) / "policy/local-mcp.json"
policy = {
    "package_id": package_id,
    "package_version": observed_version,
    "launcher_path": node_path,
    "launcher_digest": blake3_path(node_path),
    "runtime_executable": node_path,
    "runtime_executable_digest": blake3_path(node_path),
    "package_metadata_path": package_metadata_path,
    "package_metadata_digest": blake3_bytes(package_metadata),
    "protocol_version": protocol_version,
    "fixed_args": (["--no-global-search-paths"] if package_binding is not None else []) + [wrapper_path],
    "fixed_env": {"N8N_MCP_TELEMETRY_DISABLED": "true"},
    "allowed_methods": ["initialize", "notifications/initialized", "tools/list", "tools/call"],
    **bindings,
    "max_frame_bytes": 262144,
    "max_request_bytes": 65536,
    "max_result_bytes": 262144,
    "max_sequential_calls": int(sequential_calls),
    "startup_timeout_ms": 30000,
    "request_timeout_ms": 30000,
    "shutdown_timeout_ms": 2000,
    "idle_window_ms": 0,
    "network_disabled": True,
}
if package_binding is not None:
    if verify_prepared_package() != package_binding:
        raise SystemExit('immutable package changed during catalog discovery')
    policy['package_binding'] = package_binding
stage_policy.write_text(json.dumps(policy, indent=2) + "\n")
PY
  if [[ -n "$export_binary" ]]; then
    return 0
  fi
  chown root:root "$stage_root/policy/local-mcp.json"
  chmod 0644 "$stage_root/policy/local-mcp.json"
}

require_pinned_build_input() {
  local path="$1" digest="$2" kind="$3"
  local size=""
  case "$kind" in
    helper) size="${FWC_N8N_BLAKE3_HELPER_BYTES:-}" ;;
    rlib) size="${FWC_N8N_BLAKE3_RLIB_BYTES:-}" ;;
    *) die "unknown pinned build input" ;;
  esac
  python3 - "$path" "$digest" "$size" "$kind" <<'PY'
import hashlib
import os
import pathlib
import re
import stat
import sys

def validate_input(path, digest, size, kind):
    if (not path.startswith('/') or not re.fullmatch('[0-9a-f]{64}', digest)
        or not re.fullmatch('[1-9][0-9]{0,8}', size) or kind not in ('helper', 'rlib')):
        raise ValueError('explicit pinned input required')
    path = pathlib.Path(path)
    if str(path.resolve(strict=True)) != str(path):
        raise ValueError('pinned path denied')
    for parent in path.parents:
        meta = parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or meta.st_mode & 0o022:
            raise ValueError('pinned ancestor denied')
    def identity(meta):
        return (meta.st_dev, meta.st_ino, meta.st_uid, meta.st_gid, meta.st_mode,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        mode = 0o755 if kind == 'helper' else 0o644
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
            or before.st_nlink != 1 or before.st_size != int(size) or stat.S_IMODE(before.st_mode) != mode):
            raise ValueError('pinned identity denied')
        raw = stream.read(int(size) + 1)
        after = os.fstat(stream.fileno())
    if (identity(before) != identity(after) or identity(after) != identity(path.lstat())
        or len(raw) != int(size) or hashlib.sha256(raw).hexdigest() != digest):
        raise ValueError('pinned drift denied')
    return str(path)

if __name__ == '__main__':
    try:
        print(validate_input(*sys.argv[1:]))
    except (OSError, ValueError, TypeError):
        raise SystemExit('pinned_build_input_denied') from None
PY
}

runtime_input() {
  case "$1" in
    fcp-host|fcp-n8n|fcp-mcp-bridge)
      if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
        printf '%s/bin/%s\n' "$RETAINED_RELEASE" "$1"
        return
      fi ;;
    fwc-n8n) ;;
    *) die "unknown runtime artifact" ;;
  esac
  printf '%s/release/%s\n' "$TARGET_DIR" "$1"
}

select_retained_release() {
  case "$1" in
    /usr/local/lib/fwc-n8n/releases/release-20261012-native-diagnostics-4a2d827a-rc1|\
    /usr/local/lib/fwc-n8n/releases/release-20261014-execution-search-a5cc0834-rc1)
      printf '%s\n' "$1" ;;
    *) die "retained current profile denied" ;;
  esac
}

validate_retained_inputs() {
  [[ "$1" == "$RETAINED_RELEASE" ]] || die "retained release path denied"
  python3 - "$@" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

ROOT = '/usr/local/lib/fwc-n8n/releases/release-20261012-native-diagnostics-4a2d827a-rc1'
SOURCE = '4a2d827aa35a85e05d7b24c61595015fb0d938e3'
# SHA-256 binds bytes; BLAKE3 additionally binds the accepted receipt rows.
PINS = {
    'bin/fwc-n8n': (3318680, '5aa23c5842780142d4c57ec27f7bdb461b8d57e6a36cba4c93a465404ed647d6', '80af5116a7b10d19e555078092c716fda1af5671356f5d99933ae9d430981082'),
    'bin/fcp-host': (22403872, '1c41af1ba7ed8cc7b664baa55fa49a98d8f8e7264d4d4e1cd6650fbb9dc8c11e', 'a9c5be2ef24ae6078bda49cf96c178af130bce2908912ba3acf0723a116797c9'),
    'bin/fcp-n8n': (9274360, '5133dc331a3f37f927b18f19f8d4b072b9bbdd724468eff6bbf9639fec8733fe', 'a18256ab6ae26a23f3f0b0d0099cf4975cb82146f53f281eb31836610fce6d28'),
    'bin/fcp-mcp-bridge': (9605016, 'bc80be0b0e79cbdafd2c12db4793d7eb09ce1a287dece99d593755ff99fdef66', 'ab7754e0da0efd82695670e2cbb15c86a5d1b132e89333f4305395682a959e3d'),
    'manifests/fcp-mcp-bridge.toml': (19608, '13b572ed7bdc5524bae6b35126a21b0be6335d4f83415bfb6cf587af8106ca20', 'dca0f62c66f45e3e58a3f2f9d7ef17c7e48acc550ce36f6b7ea996eb5122af57'),
    'inventory/eec.json': (13866, 'f6f8bf59bd6323093037f789414f771efa372584de27f53d9554290d8c8fa58a', 'c68a3eb1156744d6c8a023e8b4ad8de8022e2fbbc3df4c6e76055c8cc1c6f505'),
    'inventory/hetzner.json': (13770, '89ae8720568768338efc8489cdc26e18bab4bced5417add727df7f8338149608', 'd508957e2ab84870c6cc338db6d1ef33ca3392c9aa67fdefc478b387e2ca829c'),
    'inventory/eec-official-mcp.json': (17505, '2a2307b4b0f119f264a280b26aeea1a85e3581a0459fb36e9be6ef23874af761', 'ef69250be1fcb26884a0fe218aaca6b3649bcd46844df64015d36fe4f63a44e7'),
    'inventory/hetzner-official-mcp.json': (17497, 'dd5db4b8e459d4f4b744e578205e9ae6c3c2b4c8489ec081d4d34fe966716090', '0b42196915aac8814bf723b9b0a90602e0d3edc7b2ea12336029d518a587fbe7'),
    'policy/zone-policies.json': (828, '0f1d85d0d2be8bcb7e7936d1689d6d2b85b6e2c632ba835f5d342d17c047606a', 'ffc5620cc0c54203d7cec21df37a90233b2ae49e238a50de2f9a6f6cca3b72e7'),
    'policy/local-mcp.json': (21455, '614e2bc0799a6d3175ba29f8c52fa4e7d5ac489f096e16212af2da76f84d5cff', 'e1959a471a4199a12513d9379fe1a609a01bf7469961e2d14b19a11557cad29f'),
}
RECEIPTS = {
    'receipt.json': (1748, '5c12bd083fc5e198d0dd89105612093e6bc4c32b3dc23b38f262e652b4aec8d3'),
    'provenance.json': (170, '18cb471770acb87c555f80a555763e8b5bdb0c4de56f56dad115a9bca88946d9'),
    'provision-receipt.json': (2778, '9e174432e462358ca96d66a390a961f877f3f101daa9b4b843288c502b00750c'),
}

# Exact installed successor: the three runtime binaries and bridge manifest
# retain their 4a artifact identities. SOURCE identifies the recipe/new CLI,
# not a source attestation for the retained binaries.
SEARCH_ROOT = '/usr/local/lib/fwc-n8n/releases/release-20261014-execution-search-a5cc0834-rc1'
SEARCH_SOURCE = 'a5cc083424e6c83113313f782b7d82a121835b3b'
SEARCH_PINS = {
    **PINS,
    'bin/fwc-n8n': (3333736, 'cf53c594d75a2761db75f6d4787db91e27bc32aaefa2e0fbbdb8f7aa6b412935', 'a49836478051c55dd125a2006e3de3221b69b6601a1197d66537b4acf58a5eb9'),
    'manifests/fcp-n8n.toml': (120340, '4c71a7d0f0765afb4a8f9fd1d7df71539ef2495f465bd4ca4d8e6c1d603acf8c', '48afb389873be8192e6dd99173f3ab1c3d5443e8f1855d3ded0557fa1ec14457'),
    'inventory/eec.json': (14834, 'e9cea951ef6f6d610e027891d0298eaa2f542a3f4eef0287244668f0770b125b', 'fdacc955b95190e07949f75dde32733bb52d1dba21f271cc9c0cff132b1f5246'),
    'inventory/hetzner.json': (14733, '1a29354980f14fa2fa560442e4662fb6e66e91691ada4dd182a3f5fceda061ce', 'de1de1b733045c2fe24f808c05afe066101aa05e6f4f1c313780fe91763f4e7f'),
    'inventory/eec-official-mcp.json': (17497, 'f994b6e865248b298b8889c424503da9b3d4ac16d5d246fba899dd8c1f62a4c6', '757643bbf2919c93c4774a97e60982e10bc15d610ef21ec3422c3cddd6ff6bac'),
    'inventory/hetzner-official-mcp.json': (17489, 'acb9507b2ec55b1563b4ddff57d44b20c21ab4000b90ffeacfc73f3ec1613fac', 'f5d44c975ee92c672cc36511e7cbb1101e77250ae48e94825529340043a64a72'),
    'policy/local-mcp.json': (21453, 'c7b1591737d4e406cc6d73cebcd719a96e92dc06a06f061609a40f2f484dbd75', '7b954579f8516872799ccc32f3d1ecd951660790321a4a46ed971f085b277f07'),
}
SEARCH_RECEIPTS = {
    'receipt.json': (1746, '1de8818655cc1351db321f08fb733661f68e8a329eb3a941472bfece87586d8b'),
    'provenance.json': (168, 'cd567cf051602a5337b1d5c9686a3079c6229b7f585b1902f720c57dca99134b'),
    'provision-receipt.json': (2776, '50b8bd4be8869d9c9a3f97e2da24d188a4fcdca35ce0c57584aae8a7d56b142f'),
}

def retained_profile(root):
    if root == ROOT:
        return SOURCE, PINS, RECEIPTS
    if root == SEARCH_ROOT:
        return SEARCH_SOURCE, SEARCH_PINS, SEARCH_RECEIPTS
    raise ValueError('retained root denied')

def closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate retained field')
        result[key] = value
    return result

def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_uid, meta.st_gid, meta.st_mode,
        meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)

def read_pinned(path, size, digest):
    path = pathlib.Path(path)
    if str(path.resolve(strict=True)) != str(path):
        raise ValueError('retained canonical path denied')
    for parent in path.parents:
        meta = parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or meta.st_mode & 0o022:
            raise ValueError('retained ancestor denied')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
            or before.st_nlink != 1 or before.st_size != size
            or stat.S_IMODE(before.st_mode) != (0o755 if path.parent.name == 'bin' else 0o644)):
            raise ValueError('retained file identity denied')
        raw = stream.read(size + 1)
        after = os.fstat(stream.fileno())
    if (identity(before) != identity(after) or identity(after) != identity(path.lstat())
        or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest):
        raise ValueError('retained file drift denied')
    return raw

def validate_retained(root, read=read_pinned, schemas=None):
    source, pins, receipts = retained_profile(root)
    records = {name: json.loads(read(root + '/' + name, *pin), object_pairs_hook=closed_object)
        for name, pin in receipts.items()}
    release_id = pathlib.Path(root).name
    if records['provenance.json'] != {'schema': 'fwc.n8n.provenance.v1', 'release_id': release_id, 'git_revision': source}:
        raise ValueError('retained source denied')
    for name, schema in [('receipt.json', 'fwc.n8n.bundle.v1'), ('provision-receipt.json', 'fwc.n8n.provision.v1')]:
        record = records[name]
        if record['schema'] != schema or record['release_id'] != release_id:
            raise ValueError('retained receipt denied')
        rows = record['artifacts']
        digests = {row['path']: row['digest'] for row in rows}
        if len(digests) != len(rows) or any(digests.get(p) != pin[2] for p, pin in pins.items()):
            raise ValueError('retained artifact receipt denied')
    if records['provision-receipt.json']['git_revision'] != source:
        raise ValueError('retained signed source denied')
    for name, (size, digest, _) in pins.items():
        read(root + '/' + name, size, digest)
    if schemas is not None:
        if len(schemas) != 16:
            raise ValueError('retained schema input count denied')
        expected = []
        for server in ('eec', 'hetzner'):
            name = 'inventory/' + server + '-official-mcp.json'
            tools = json.loads(read(root + '/' + name, *pins[name][:2]), object_pairs_hook=closed_object)[0]['config']['capability_policy']['approved_tools']
            for operation in ('publish_workflow', 'unpublish_workflow', 'archive_workflow', 'execute_workflow'):
                tool = next(tool for tool in tools if tool['name'] == operation)
                expected += [tool['input_schema_digest'], tool['output_schema_digest']]
        if schemas != expected:
            raise ValueError('retained schema input drift denied')
    # The policy hash binds the exact immutable package/tree/receipt pins.
    # Native unsigned validation still verifies that actual package tree.

if __name__ == '__main__':
    try:
        validate_retained(sys.argv[1], schemas=sys.argv[2:] or None)
    except (OSError, ValueError, KeyError, TypeError, StopIteration):
        raise SystemExit('retained_inputs_denied') from None
PY
}

validate_retained_schema_inputs() {
  validate_retained_inputs "$RETAINED_RELEASE" \
    "$EEC_PUBLISH_INPUT_SCHEMA_DIGEST" "$EEC_PUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$EEC_UNPUBLISH_INPUT_SCHEMA_DIGEST" "$EEC_UNPUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$EEC_ARCHIVE_INPUT_SCHEMA_DIGEST" "$EEC_ARCHIVE_OUTPUT_SCHEMA_DIGEST" \
    "$EEC_EXECUTE_INPUT_SCHEMA_DIGEST" "$EEC_EXECUTE_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_PUBLISH_INPUT_SCHEMA_DIGEST" "$HETZNER_PUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_UNPUBLISH_INPUT_SCHEMA_DIGEST" "$HETZNER_UNPUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_ARCHIVE_INPUT_SCHEMA_DIGEST" "$HETZNER_ARCHIVE_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_EXECUTE_INPUT_SCHEMA_DIGEST" "$HETZNER_EXECUTE_OUTPUT_SCHEMA_DIGEST"
}

build_runtime_artifacts() {
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
    build_one build --release --package fcp-n8n --bin fwc-n8n
    build_one build --release --package fcp-n8n --features owner-signing --bin fwc-n8n-owner-sign
    return
  fi
  build_one build --release --package fcp-host --bin fcp-host
  build_one build --release --package fcp-n8n --bin fwc-n8n
  build_one rustc --release --package fcp-n8n --bin fcp-n8n -- -C target-feature=+crt-static
  build_one rustc --release --package fcp-mcp-bridge --bin fcp-mcp-bridge -- -C target-feature=+crt-static
  build_one build --release --package fcp-n8n --features owner-signing --bin fwc-n8n-owner-sign
  build_external_approval_issuer
}

validate_retained_native_package() {
  validate_retained_inputs "$RETAINED_RELEASE"
  [[ "$(readlink -e "$CURRENT_PATH")" == "$RETAINED_RELEASE" ]] || die "retained current drift"
  # Existing native signed-current/package verifier; --check-only never starts
  # Node or discovers a catalog. No helper or signer is involved in this check.
  "$RETAINED_RELEASE/bin/fwc-n8n" export-schemas local --check-only >/dev/null \
    || die "retained native package denied"
  validate_retained_inputs "$RETAINED_RELEASE"
  [[ "$(readlink -e "$CURRENT_PATH")" == "$RETAINED_RELEASE" ]] || die "retained current drift"
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
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
    validate_retained_inputs "$RETAINED_RELEASE"
  fi
  env FCP_N8N_OWNED_SMOKE_BINARY="$(runtime_input fcp-n8n)" \
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
  local bridge_manifest="$REPO_ROOT/connectors/mcp-bridge/manifest.toml"
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
    validate_retained_inputs "$source_release"
    validate_retained_native_package
    bridge_manifest="$RETAINED_RELEASE/manifests/fcp-mcp-bridge.toml"
    [[ "$(sha256sum "$REPO_ROOT/connectors/n8n/manifest.toml" | cut -d' ' -f1)" == \
      4c71a7d0f0765afb4a8f9fd1d7df71539ef2495f465bd4ca4d8e6c1d603acf8c ]] \
      || die "reuse n8n manifest denied"
    [[ ! -e "$stage_root" && ! -L "$stage_root" ]] || die "reuse stage already exists"
  fi

  install -d -o root -g root -m 0755 \
    "$stage_root" "$stage_root/bin" "$stage_root/manifests" \
    "$stage_root/inventory" "$stage_root/policy"
  local binary
  for binary in fwc-n8n fcp-host fcp-n8n fcp-mcp-bridge; do
    install -o root -g root -m 0755 "$(runtime_input "$binary")" "$stage_root/bin/$binary"
  done
  install -o root -g root -m 0644 "$REPO_ROOT/connectors/n8n/manifest.toml" "$stage_root/manifests/fcp-n8n.toml"
  install -o root -g root -m 0644 "$bridge_manifest" "$stage_root/manifests/fcp-mcp-bridge.toml"

  for server in eec hetzner; do
    install -o root -g root -m 0644 "$source_release/inventory/${server}.json" "$stage_root/inventory/${server}.json"
    install -o root -g root -m 0644 "$source_release/inventory/${server}-official-mcp.json" "$stage_root/inventory/${server}-official-mcp.json"
  done
  install -o root -g root -m 0644 "$source_release/policy/zone-policies.json" "$stage_root/policy/zone-policies.json"
  install -o root -g root -m 0644 "$source_release/policy/local-mcp.json" "$stage_root/policy/local-mcp.json"
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
    # Recheck selected sources after copy; native receipts bind staged bytes.
    validate_retained_inputs "$source_release"
    for binary in fcp-host fcp-n8n fcp-mcp-bridge; do
      cmp -s "$stage_root/bin/$binary" "$(runtime_input "$binary")" || die "retained copy drift"
    done
    cmp -s "$stage_root/manifests/fcp-mcp-bridge.toml" "$bridge_manifest" || die "retained manifest copy drift"
  fi
}

rebind_retained_local_policy() {
  local stage_root="$1"
  validate_retained_inputs "$RETAINED_RELEASE"
  python3 - "$stage_root/policy/local-mcp.json" "$RETAINED_RELEASE" "$RELEASE_ID" <<'PY'
import json
import pathlib
import re
import sys

def rebind(policy, old_release_id, new_release_id):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', new_release_id) or old_release_id == new_release_id:
        raise ValueError('retained local release denied')
    result = json.loads(json.dumps(policy))
    if result['package_binding']['release_id'] != old_release_id:
        raise ValueError('retained local binding denied')
    result['package_binding']['release_id'] = new_release_id
    return result

if __name__ == '__main__':
    try:
        path = pathlib.Path(sys.argv[1])
        original = (pathlib.Path(sys.argv[2]) / 'policy/local-mcp.json').read_bytes()
        if path.read_bytes() != original:
            raise ValueError('retained local policy drift')
        updated = rebind(json.loads(original), pathlib.Path(sys.argv[2]).name, sys.argv[3])
        path.write_text(json.dumps(updated, indent=2) + '\n')
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('retained_local_policy_denied') from None
PY
}

local_call_budget() {
  # A digest selects separately admitted protected DATA, never an ambient count.
  # This validator is not owner approval; absent opt-in retains the default 7.
  python3 - "${FWC_N8N_LOCAL_CALL_BUDGET_SHA256:-}" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys

INPUT = '/srv/dev-ssd/rc41-inputs/local-call-budget.json'

def closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result

def policy_call_budget(raw, digest):
    if raw is None and digest == '':
        return 7
    if not re.fullmatch(r'[0-9a-f]{64}', digest) or raw is None or len(raw) > 1024:
        raise ValueError('invalid admission binding')
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('admission digest mismatch')
    value = json.loads(raw, object_pairs_hook=closed_object)
    if (not isinstance(value, dict) or set(value) != {'schema', 'max_sequential_calls'}
            or value['schema'] != 'fwc.n8n.local-call-budget.v1'
            or type(value['max_sequential_calls']) is not int
            or value['max_sequential_calls'] != 20):
        raise ValueError('unsupported call budget')
    return 20

def input_identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_uid, meta.st_gid, meta.st_mode,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)

def admitted_call_budget(digest):
    if digest == '':
        return policy_call_budget(None, digest)
    if not re.fullmatch(r'[0-9a-f]{64}', digest):
        raise ValueError('invalid digest')
    for parent in ('/srv', '/srv/dev-ssd', '/srv/dev-ssd/rc41-inputs'):
        meta = os.lstat(parent)
        if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0
                or stat.S_IMODE(meta.st_mode) & 0o022):
            raise ValueError('unsafe parent')
    fd = os.open(INPUT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1):
            raise ValueError('unsafe admitted input')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(1025)
        after = os.fstat(fd)
        if input_identity(before) != input_identity(after) or input_identity(os.lstat(INPUT)) != input_identity(after):
            raise ValueError('admitted input changed')
        return policy_call_budget(raw, digest)
    finally:
        os.close(fd)

if __name__ == '__main__':
    try:
        print(admitted_call_budget(sys.argv[1]))
    except (OSError, ValueError, TypeError, UnicodeError):
        raise SystemExit('protected local call budget validation denied') from None
PY
}

search_read_policy() {
  # Opt-in data is admitted separately by the protected caller. A valid proposal
  # or this pure check is not owner approval. There is no caller-selected path.
  local admission="${FWC_N8N_SEARCH_READ_POLICY_SHA256:-}"
  local safe_admission="${FWC_N8N_SAFE_READ_POLICY_SHA256:-}"
  local execution_search="${FWC_N8N_EXECUTION_SEARCH-0}"
  [[ "$execution_search" == 0 || "$execution_search" == 1 ]] || die "execution search opt-in is invalid"
  [[ "$execution_search" == 0 || -n "$admission$safe_admission" ]] || die "execution search requires admitted read policy"
  [[ -z "$admission" || -z "$safe_admission" ]] || die "read policy inputs are mutually exclusive"
  local kind="search"
  if [[ -n "$safe_admission" ]]; then
    admission="$safe_admission"
    kind="safe"
  fi
  [[ -n "$admission" ]] || return 0
  [[ "$admission" =~ ^[0-9a-f]{64}$ ]] || die "search read policy admission digest is invalid"
  python3 - "$1" "$admission" "${2:-}" "$kind" "$execution_search" <<'PY'
import copy
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

INPUT = "/srv/dev-ssd/rc41-inputs/search-read-policy.json"
if len(sys.argv) > 4 and sys.argv[4] == "safe":
    INPUT = "/srv/dev-ssd/rc41-inputs/safe-read-policy.json"
INPUT_PIN = "sha256:179069c19267545edc43d943befdcff9743bbf4557e6a10efe7fa0cb7b91e714"
OUTPUT_PIN = "sha256:1b9737c076b6f72be4f1521911b589fce8f9954bdc7487ea12933f2bd0586206"
SAFE_PINS = {
    "search_workflows": (INPUT_PIN, OUTPUT_PIN),
    "search_projects": ("sha256:d37453c28e110141c606ef901d7651367544f8d272f183bd181978e086712200", "sha256:28c5f100b2daae7bff8225376c4bed8000f67b785f174a6ae1636ff90fc5126e"),
    "search_folders": ("sha256:20a822576c3a6e883e942dfc695ccc7114ffc18e2e3a7bf555af8b07da314269", "sha256:d0af92b84b63148c231ee85778e7af9b765cf6edc4e8d638eec067220b496487"),
    "list_workflow_tags": ("sha256:c0602bd0434d0c2aeafb763bc12512b63443448c9331dc0cb1ebf02973603e8e", "sha256:5481cbd6dedd4134020f44bdcc900e40eb9802e70d5ccedf8dda6252d55b720b"),
    "get_workflow_sdk_reference": ("sha256:c0c69d975afd16845bee57cbd37e0cf0a50b7d5741810625963dedf60279fda2", "sha256:555b1d6f84918d5b03adfd55c3f652d2b0ac0457f80e9e811963fbbbc61426dc"),
    "get_workflow_best_practices": ("sha256:d95120da8063c53d7dc379b938043cfdc81da869c40a33ce608fe76ddda31423", "sha256:9530d1f518b2640320f8ffbfd971d662b3f00558be8b3ff9418fe0d916a1728c"),
    "validate_node_config": ("sha256:37231a38664a9375573c84d8484fc30cef2e99efbca5f6172f1a4cd308c34f8d", "sha256:11fa90ee8936aa8946e5a1556d3c03ad3640dc837731c0302f4b0dc40e5920a0"),
}

def closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("search read policy denied")
        result[key] = value
    return result

def validate_read_policy(raw):
    if len(raw) > 16384:
        raise ValueError("search read policy denied")
    value = json.loads(raw, object_pairs_hook=closed_object)
    expected = {"name": "search_workflows", "class": "read",
        "input_schema_digest": INPUT_PIN, "output_schema_digest": OUTPUT_PIN,
        "input_schema_present": True, "output_schema_present": True}
    if (not isinstance(value, dict) or set(value) not in ({"schema", "servers"}, {"schema", "servers", "code_read"})
        or value["schema"] not in ("fwc.n8n.search-read-policy.v1", "fwc.n8n.safe-read-policy.v1")
        or not isinstance(value["servers"], dict)
        or set(value["servers"]) != {"eec", "hetzner"}):
        raise ValueError("search read policy denied")
    if "code_read" in value and (value["schema"] != "fwc.n8n.safe-read-policy.v1"
        or value["code_read"] != {"operation": "n8n.workflows.get_code", "capability": "n8n.workflows.code.read"}):
        raise ValueError("sensitive code read policy denied")
    for server in ("eec", "hetzner"):
        observed = value["servers"][server]
        if value["schema"] == "fwc.n8n.safe-read-policy.v1":
            if not isinstance(observed, list) or not 1 <= len(observed) <= len(SAFE_PINS):
                raise ValueError("search read policy denied")
            seen = set()
            for tool in observed:
                if not isinstance(tool, dict) or set(tool) != set(expected):
                    raise ValueError("search read policy denied")
                name = tool["name"]
                if not isinstance(name, str) or name not in SAFE_PINS or name in seen:
                    raise ValueError("search read policy denied")
                seen.add(name)
                pins = SAFE_PINS[name]
                if (tool["class"] != "read" or tool["input_schema_digest"] != pins[0]
                    or tool["output_schema_digest"] != pins[1]
                    or tool["input_schema_present"] is not True
                    or tool["output_schema_present"] is not True):
                    raise ValueError("search read policy denied")
            continue
        if (not isinstance(observed, dict) or observed != expected
            or observed["input_schema_present"] is not True
            or observed["output_schema_present"] is not True):
            raise ValueError("search read policy denied")
    return value

def add_read_inventory(official, common, server, policy):
    official, common = copy.deepcopy(official), copy.deepcopy(common)
    if (server not in ("eec", "hetzner") or official["config"]["server_id"] != server
        or common["config"]["server_id"] != server):
        raise ValueError("search read policy denied")
    tools = official["config"]["capability_policy"]["approved_tools"]
    selected = policy["servers"][server]
    if not isinstance(selected, list):
        selected = [selected]
    required_names = {"publish_workflow", "unpublish_workflow", "archive_workflow", "execute_workflow"}
    allowed_names = set(required_names)
    allowed_names.update(tool["name"] for tool in selected)
    if (not isinstance(tools, list) or any(not isinstance(tool, dict)
        or not isinstance(tool.get("name"), str) or tool["name"] not in allowed_names for tool in tools)
        or len({tool["name"] for tool in tools}) != len(tools)
        or not required_names.issubset({tool["name"] for tool in tools})):
        raise ValueError("search read policy denied")
    for selected_tool in selected:
        tool = dict(selected_tool)
        del tool["input_schema_present"], tool["output_schema_present"]
        existing = [entry for entry in tools if entry["name"] == tool["name"]]
        if existing:
            if existing != [tool]:
                raise ValueError("search read policy denied")
        else:
            tools.append(tool)
    host = "n8n.europeaneyecenter.com" if server == "eec" else "n8nhet.levilaser.com"
    legacy_network = {"cidr_deny": [], "connect_timeout_ms": 5000,
        "deny_ip_literals": True, "deny_localhost": True, "deny_private_ranges": True,
        "deny_tailnet_ranges": True, "dns_max_ips": 4, "host_allow": [host], "ip_allow": [],
        "max_redirects": 0, "max_response_bytes": 10485760, "port_allow": [443],
        "require_host_canonicalization": True, "require_sni": True, "spki_pins": [],
        "total_timeout_ms": 15000}
    for inventory, operation, source in (
        (official, "mcp.n8n.read", "mcp.tools.list"),
        (common, "n8n.workflows.compare", "n8n.workflows.get"),
        (common, "n8n.validation.run", "n8n.workflows.get"),
    ):
        network = inventory["operation_network_constraints"]
        if source not in inventory["allowed_operations"] or not isinstance(network.get(source), dict):
            raise ValueError("search read policy denied")
        source_network = copy.deepcopy(legacy_network)
        if inventory is official and server == "hetzner":
            source_network["port_allow"] = [8443]
        if network[source] != source_network:
            raise ValueError("search read policy denied")
        expected_network = copy.deepcopy(source_network)
        if operation == "n8n.validation.run":
            # Exact existing manifest denylist, not the looser GET policy.
            expected_network["cidr_deny"] = [
                "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
                "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
                "224.0.0.0/4", "240.0.0.0/4", "::1/128", "fc00::/7",
                "fe80::/10", "ff00::/8",
            ]
        if operation in network and network[operation] != expected_network:
            # Only the exact signed predecessor GET tuple is upgraded to the
            # stricter validation tuple. No arbitrary old policy is normalized.
            if operation != "n8n.validation.run" or network[operation] != source_network:
                raise ValueError("search read policy denied")
        if operation not in inventory["allowed_operations"]:
            inventory["allowed_operations"].append(operation)
        network[operation] = expected_network
    if "code_read" in policy:
        network = common["operation_network_constraints"]
        source = network.get("n8n.workflows.get")
        if not isinstance(source, dict) or source.get("port_allow") != [443]:
            raise ValueError("sensitive code read network denied")
        operation = "n8n.workflows.get_code"
        if operation in network or operation in common["allowed_operations"]:
            raise ValueError("sensitive code read duplicate denied")
        common["allowed_operations"].append(operation)
        network[operation] = copy.deepcopy(source)
    return official, common

def input_identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_uid, meta.st_gid, meta.st_mode,
        meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)

def add_execution_search_inventory(common, server):
    # One exact optional operation; this recipe is not release authority.
    common = copy.deepcopy(common)
    if server not in ("eec", "hetzner") or common["config"]["server_id"] != server:
        raise ValueError("execution search policy denied")
    operations = common["allowed_operations"]
    networks = common["operation_network_constraints"]
    operation = "n8n.executions.search"
    if (not isinstance(operations, list) or not isinstance(networks, dict)
        or any(not isinstance(entry, str) for entry in operations)
        or len(set(operations)) != len(operations)
        or "n8n.workflows.compare" not in operations
        or "n8n.validation.run" not in operations):
        raise ValueError("execution search policy denied")
    host = "n8n.europeaneyecenter.com" if server == "eec" else "n8nhet.levilaser.com"
    network = {"host_allow": [host], "port_allow": [443], "ip_allow": [],
        "cidr_deny": ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
            "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
            "240.0.0.0/4", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"],
        "deny_localhost": True, "deny_private_ranges": True, "deny_tailnet_ranges": True,
        "require_sni": True, "spki_pins": [], "deny_ip_literals": True,
        "require_host_canonicalization": True, "dns_max_ips": 4, "max_redirects": 0,
        "connect_timeout_ms": 5000, "total_timeout_ms": 15000, "max_response_bytes": 1048576}
    if operation in operations or operation in networks:
        # Reuse only the complete exact admitted tuple, without rewriting it.
        # JSON comparison also distinguishes booleans from numeric values.
        if (operations.count(operation) != 1 or operation not in networks
            or not isinstance(networks[operation], dict)
            or json.dumps(networks[operation], sort_keys=True) != json.dumps(network, sort_keys=True)):
            raise ValueError("execution search policy denied")
        return common
    operations.append(operation)
    networks[operation] = network
    return common

def admitted_input(digest):
    # All ancestors and the data file remain root-controlled and non-symlinked.
    for name in ("/srv", "/srv/dev-ssd", "/srv/dev-ssd/rc41-inputs"):
        meta = os.lstat(name)
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or meta.st_mode & 0o022:
            raise ValueError("search read policy denied")
    fd = os.open(INPUT, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
            or before.st_gid != 0 or stat.S_IMODE(before.st_mode) != 0o600):
            raise ValueError("search read policy denied")
        raw = stream.read(16385)
        after = os.fstat(stream.fileno())
    if (input_identity(before) != input_identity(after) or input_identity(os.lstat(INPUT)) != input_identity(after)
        or hashlib.sha256(raw).hexdigest() != digest):
        raise ValueError("search read policy denied")
    return validate_read_policy(raw)

def main():
    mode, digest, stage, kind, execution_search = sys.argv[1:]
    if execution_search not in ("0", "1"):
        raise ValueError("execution search policy denied")
    policy = admitted_input(digest)
    expected_schema = "fwc.n8n.safe-read-policy.v1" if kind == "safe" else "fwc.n8n.search-read-policy.v1"
    if policy["schema"] != expected_schema:
        raise ValueError("search read policy denied")
    prefix = {"check": "/usr/local/lib/fwc-n8n/releases/",
        "apply": "/var/lib/fwc-n8n/staging/"}.get(mode)
    if (prefix is None or not stage.startswith(prefix)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", stage[len(prefix):])):
        raise ValueError("search read policy denied")
    root = pathlib.Path(stage)
    for directory in (root, root / "inventory"):
        meta = directory.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or meta.st_mode & 0o022:
            raise ValueError("search read policy denied")
    updates = []
    for server in ("eec", "hetzner"):
        paths = [root / "inventory" / f"{server}-official-mcp.json",
            root / "inventory" / f"{server}.json"]
        values = []
        for path in paths:
            meta = path.lstat()
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or meta.st_mode & 0o022:
                raise ValueError("search read policy denied")
            parsed = json.loads(path.read_bytes(), object_pairs_hook=closed_object)
            if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
                raise ValueError("search read policy denied")
            values.append(parsed[0])
        outputs = add_read_inventory(*values, server, policy)
        if execution_search == "1":
            outputs = (outputs[0], add_execution_search_inventory(outputs[1], server))
        for path, output in zip(paths, outputs):
            updates.append((path, output))
    if mode == "apply":
        for path, output in updates:
            path.write_text(json.dumps([output], indent=2) + "\n")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("search read policy denied") from None
PY
}

credential_metadata_mapping() {
  # Separate owner-admitted input; search-read opt-in never enables this lane.
  local admission="${FWC_N8N_CREDENTIAL_METADATA_MAPPING_SHA256:-}"
  [[ -n "$admission" ]] || return 0
  [[ "$admission" =~ ^[0-9a-f]{64}$ ]] || die "credential metadata mapping digest is invalid"
  python3 - "$1" "$admission" "${2:-}" <<'PY'
import copy
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

INPUT = "/srv/dev-ssd/rc41-inputs/credential-metadata-mapping.json"
INPUT_PIN = "sha256:a29acfec48d5f9919cb4fb65ce44c7fe544624a4ea537638d148b5c93ee3a821"
OUTPUT_PIN = "sha256:305aeecb628786f249e9f71a2be18fc26a212b8dd4f090ff073c701a8b4563ac"

def closed_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("credential metadata mapping denied")
        result[key] = value
    return result

def validate_mapping(raw):
    if len(raw) > 8192:
        raise ValueError("credential metadata mapping denied")
    value = json.loads(raw, object_pairs_hook=closed_object)
    if (not isinstance(value, dict) or set(value) != {"schema", "servers"}
        or value["schema"] != "fwc.n8n.credential-metadata-mapping.v1"
        or not isinstance(value["servers"], dict)
        or set(value["servers"]) != {"eec", "hetzner"}):
        raise ValueError("credential metadata mapping denied")
    for mapping in value["servers"].values():
        if (not isinstance(mapping, dict)
            or set(mapping) != {"credential_id", "purpose", "tool", "class", "input_schema_digest", "output_schema_digest"}
            or not isinstance(mapping["credential_id"], str)
            or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", mapping["credential_id"])
            or mapping["purpose"] != "n8n.credentials.metadata.read"
            or mapping["tool"] != "list_credentials" or mapping["class"] != "read"
            or mapping["input_schema_digest"] != INPUT_PIN
            or mapping["output_schema_digest"] != OUTPUT_PIN):
            raise ValueError("credential metadata mapping denied")
    return value

def add_metadata_inventory(common, server, mapping):
    result = copy.deepcopy(common)
    config = result["config"]
    operation = "n8n.credentials.list"
    expected_api = "https://n8n.europeaneyecenter.com/api/v1" if server == "eec" else "https://n8nhet.levilaser.com/api/v1"
    if (server not in ("eec", "hetzner") or config.get("server_id") != server
        or config.get("base_url") != expected_api
        or set(config) != {"base_url", "credential_id", "server_id"}
        or operation not in result["allowed_operations"]):
        raise ValueError("credential metadata mapping denied")
    network = result["operation_network_constraints"][operation]
    expected_host = "n8n.europeaneyecenter.com" if server == "eec" else "n8nhet.levilaser.com"
    if network.get("host_allow") != [expected_host] or network.get("port_allow") != [443]:
        raise ValueError("credential metadata mapping denied")
    config["credential_metadata_read"] = copy.deepcopy(mapping["servers"][server])
    network["port_allow"] = [443 if server == "eec" else 8443]
    return result

def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_uid, meta.st_gid, meta.st_mode,
        meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)

def main():
    mode, digest, stage = sys.argv[1:]
    for name in ("/srv", "/srv/dev-ssd", "/srv/dev-ssd/rc41-inputs"):
        meta = os.lstat(name)
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or meta.st_mode & 0o022:
            raise ValueError("credential metadata mapping denied")
    with os.fdopen(os.open(INPUT, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0 or stat.S_IMODE(before.st_mode) != 0o600:
            raise ValueError("credential metadata mapping denied")
        raw = stream.read(8193)
        after = os.fstat(stream.fileno())
    if identity(before) != identity(after) or identity(os.lstat(INPUT)) != identity(after) or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("credential metadata mapping denied")
    mapping = validate_mapping(raw)
    prefix = {"check": "/usr/local/lib/fwc-n8n/releases/", "apply": "/var/lib/fwc-n8n/staging/"}.get(mode)
    if prefix is None or not stage.startswith(prefix) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", stage[len(prefix):]):
        raise ValueError("credential metadata mapping denied")
    root = pathlib.Path(stage)
    for directory in (root, root / "inventory"):
        meta = directory.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or meta.st_mode & 0o022:
            raise ValueError("credential metadata mapping denied")
    updates = []
    for server in ("eec", "hetzner"):
        path = root / "inventory" / f"{server}.json"
        meta = path.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 0 or meta.st_mode & 0o022:
            raise ValueError("credential metadata mapping denied")
        entries = json.loads(path.read_bytes(), object_pairs_hook=closed_object)
        if not isinstance(entries, list) or len(entries) != 1:
            raise ValueError("credential metadata mapping denied")
        updates.append((path, add_metadata_inventory(entries[0], server, mapping)))
    if mode == "apply":
        for path, output in updates:
            path.write_text(json.dumps([output], indent=2) + "\n")

if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("credential metadata mapping denied") from None
PY
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
    "$EEC_ARCHIVE_INPUT_SCHEMA_DIGEST" "$EEC_ARCHIVE_OUTPUT_SCHEMA_DIGEST" \
    "$EEC_EXECUTE_INPUT_SCHEMA_DIGEST" "$EEC_EXECUTE_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_PUBLISH_INPUT_SCHEMA_DIGEST" "$HETZNER_PUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_UNPUBLISH_INPUT_SCHEMA_DIGEST" "$HETZNER_UNPUBLISH_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_ARCHIVE_INPUT_SCHEMA_DIGEST" "$HETZNER_ARCHIVE_OUTPUT_SCHEMA_DIGEST" \
    "$HETZNER_EXECUTE_INPUT_SCHEMA_DIGEST" "$HETZNER_EXECUTE_OUTPUT_SCHEMA_DIGEST" <<'PY'
import json
import pathlib
import sys
import os
import subprocess

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
    eec_archive_input,
    eec_archive_output,
    eec_execute_input,
    eec_execute_output,
    hetzner_publish_input,
    hetzner_publish_output,
    hetzner_unpublish_input,
    hetzner_unpublish_output,
    hetzner_archive_input,
    hetzner_archive_output,
    hetzner_execute_input,
    hetzner_execute_output,
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
    delete_network = dict(delete_network)
    delete_network["max_response_bytes"] = 1048576
    common["operation_network_constraints"][delete_operation] = dict(delete_network)
    unarchive_operation = "n8n.workflows.unarchive"
    if unarchive_operation not in common["allowed_operations"]:
        common["allowed_operations"].append(unarchive_operation)
    unarchive_network = common["operation_network_constraints"].get("n8n.workflows.create_draft")
    if not isinstance(unarchive_network, dict):
        raise SystemExit(f"missing create_draft network constraint for {server}")
    unarchive_network = dict(unarchive_network)
    unarchive_network["max_response_bytes"] = 1048576
    common["operation_network_constraints"][unarchive_operation] = dict(unarchive_network)
    activation_operation = "n8n.workflows.activate"
    if activation_operation not in common["allowed_operations"]:
        common["allowed_operations"].append(activation_operation)
    activation_network = common["operation_network_constraints"].get("n8n.workflows.get")
    if not isinstance(activation_network, dict):
        raise SystemExit(f"missing workflows.get network constraint for {server}")
    activation_network = dict(activation_network)
    activation_network["max_response_bytes"] = 1048576
    common["operation_network_constraints"][activation_operation] = dict(activation_network)
    for bounded_operation in (
        "n8n.workflows.delete_disposable",
        "n8n.workflows.unarchive",
        "n8n.workflows.activate",
    ):
        bounded_network = common["operation_network_constraints"].get(bounded_operation)
        if not isinstance(bounded_network, dict) or bounded_network.get("max_response_bytes") != 1048576:
            raise SystemExit(
                f"{bounded_operation} network constraint is not the manifest-bounded 1 MiB limit for {server}"
            )
    official["launch_binding"]["launcher_digest"] = bridge_digest
    official["launch_binding"]["runtime_executable_digest"] = bridge_digest
    lifecycle = {
        "eec": {
            "publish_workflow": (eec_publish_input, eec_publish_output),
            "unpublish_workflow": (eec_unpublish_input, eec_unpublish_output),
            "archive_workflow": (eec_archive_input, eec_archive_output),
            "execute_workflow": (eec_execute_input, eec_execute_output),
        },
        "hetzner": {
            "publish_workflow": (hetzner_publish_input, hetzner_publish_output),
            "unpublish_workflow": (hetzner_unpublish_input, hetzner_unpublish_output),
            "archive_workflow": (hetzner_archive_input, hetzner_archive_output),
            "execute_workflow": (hetzner_execute_input, hetzner_execute_output),
        },
    }
    for tool in official["config"]["capability_policy"]["approved_tools"]:
        schema = lifecycle[server].get(tool["name"])
        if schema is not None:
            tool["input_schema_digest"], tool["output_schema_digest"] = schema
        baseline_path = os.environ.get("FWC_N8N_REVIEWED_SCHEMA_BASELINES", "")
        if baseline_path:
            baselines = json.loads(pathlib.Path(baseline_path).read_text())
            baseline = baselines.get(server, {}).get(tool["name"])
            if baseline is not None:
                if (baseline.get("integrity") != "sha256"
                    or baseline.get("input_schema_digest") != tool["input_schema_digest"]
                    or baseline.get("output_schema_digest") != tool["output_schema_digest"]):
                    raise SystemExit("reviewed official schema baseline pin mismatch")
                tool["reviewed_schemas"] = json.loads(subprocess.check_output(
                    [str(stage / "bin/fwc-n8n"), "reviewed-schema-profile"],
                    input=json.dumps(baseline).encode(), stderr=subprocess.DEVNULL,
                ))
    archive_schema = official["config"]["capability_policy"]["archive_workflow_schema"]
    archive_schema["input_schema_digest"], archive_schema["output_schema_digest"] = lifecycle[server][
        "archive_workflow"
    ]
    execute_schema = official["config"]["capability_policy"]["execute_workflow_schema"]
    if execute_schema.get("status") != "owner_provisioned":
        raise SystemExit(f"execute_workflow_schema is not owner-provisioned for {server}")
    execute_schema["input_schema_digest"], execute_schema["output_schema_digest"] = lifecycle[server][
        "execute_workflow"
    ]
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

release_provenance() {
  # Native runtime37936 has serde deny_unknown_fields: assembler admission is separate.
  python3 - "$@" <<'PY'
import json
import os
import pathlib
import re
import sys
mode, release_id, git_revision, *output = sys.argv[1:]
expected = {"schema": "fwc.n8n.provenance.v1", "release_id": release_id, "git_revision": git_revision}
def closed_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result
        result[key] = value
    return result
try:
    assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release_id)
    assert re.fullmatch(r"[0-9a-f]{40}", git_revision)
    if mode == "check":
        with os.fdopen(3, "rb") as source:
            raw = source.read(65537)
        assert len(raw) <= 65536
        observed = json.loads(raw, object_pairs_hook=closed_object)
        assert type(observed) is dict and observed == expected and set(observed) == set(expected)
    elif mode in ("emit", "write"):
        raw = json.dumps(expected, indent=2) + "\n"
        assert json.loads(raw) == expected
        if mode == "write":
            assert len(output) == 1
            with pathlib.Path(output[0]).open("x") as f:
                f.write(raw)
        else:
            assert not output
            print(raw, end="")
    else:
        raise ValueError()
except (AssertionError, ValueError, TypeError, OSError):
    raise SystemExit("release_metadata_invalid")
PY
}

write_metadata() {
  local stage_root="$1"
  local git_revision="$2"
  local hash_helper="$3"
  release_provenance write "$RELEASE_ID" "$git_revision" "$stage_root/provenance.json"
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
  [[ "${FWC_N8N_REUSE_RETAINED-0}" == 0 || "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]] \
    || die "retained reuse opt-in is invalid"
  [[ "${FWC_N8N_REUSE_RETAINED-0}" == 0 || "${FWC_N8N_EXECUTION_SEARCH-0}" == 1 ]] \
    || die "retained reuse requires execution search"
  # Reject malformed opt-in before any command can create or change artifacts.
  [[ "${FWC_N8N_EXECUTION_SEARCH-0}" == 0 || "${FWC_N8N_EXECUTION_SEARCH-0}" == 1 ]] \
    || die "execution search opt-in is invalid"
  [[ "${FWC_N8N_EXECUTION_SEARCH-0}" == 0 || -n "${FWC_N8N_SEARCH_READ_POLICY_SHA256:-}${FWC_N8N_SAFE_READ_POLICY_SHA256:-}" ]] \
    || die "execution search requires admitted read policy"
  if [[ "${1:-}" == "--prepare-derived-local-validator" ]]; then
    [[ "$#" == 2 ]] || die "derived preparation requires one closed input FILE"
    prepare_derived_local_validator "$2"
    return $?
  fi
  if [[ "${1:-}" == "--check-release-metadata" || "${1:-}" == "--emit-release-provenance" ]]; then
    [[ "$#" == 3 ]] || die "release metadata check requires exact release id and git revision"
    if [[ "$1" == "--check-release-metadata" ]]; then
      release_provenance check "$2" "$3" 3<&0
    else
      release_provenance emit "$2" "$3"
    fi
    return $?
  fi
  if [[ "${1:-}" == "--check-official-baselines" ]]; then
    [[ "$#" == 2 && "$2" == /* && -f "$2" && -x "$2" ]] || die "official baseline check requires an explicit source binary"
    validate_official_schema_baselines "$2"
    return $?
  fi
  if [[ "${1:-}" == "--export-local-schemas" ]]; then
    [[ "$#" == 2 && "$2" == /* && -f "$2" && -x "$2" ]] || die "local schema export requires an explicit diagnostic binary"
    if [[ "${FCP_SSD_ACTIVE:-}" != 1 ]]; then
      exec bash "$(dirname "${BASH_SOURCE[0]}")/fcp_ssd.sh" -- bash "${BASH_SOURCE[0]}" "$@"
    fi
    write_local_mcp_policy "" "" "$2"
    return $?
  fi
  if [[ "${1:-}" == "--offline-catalog-bindings" ]]; then
    [[ "$#" == 2 && -f "$2" && -x "$2" ]] || die "offline catalog bindings require an explicit source binary"
    assemble_local_catalog_bindings "$2"
    return $?
  fi
  local release_id="" explicit_repo_root=""
  TARGET_DIR="${SSD_ROOT}/targets/n8n-release"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --release-id) [[ $# -ge 2 ]] || die "--release-id requires a value"; release_id="$2"; shift 2 ;;
      --target-dir) [[ $# -ge 2 ]] || die "--target-dir requires a value"; TARGET_DIR="$2"; shift 2 ;;
      --repo-root) [[ $# -ge 2 && "$2" == /* ]] || die "--repo-root requires an absolute path"; explicit_repo_root="$2"; shift 2 ;;
      --local-package-input) [[ $# -ge 2 && "$2" == "$LOCAL_MCP_PREPARATION_PATH" ]] || die "local package input must be the fixed protected DATA file"; LOCAL_MCP_PACKAGE_INPUT="$2"; shift 2 ;;
      --local-package-input-sha256) [[ $# -ge 2 && "$2" =~ ^[0-9a-f]{64}$ ]] || die "local package input SHA256 required"; LOCAL_MCP_PACKAGE_INPUT_SHA256="$2"; shift 2 ;;
      --help|-h) usage; return 0 ;;
      *) usage; die "unknown argument: $1" ;;
    esac
  done
  [[ "${EUID}" -eq 0 ]] || die "run the assembler as root; it creates root-owned fixed staging"
  PATH="/home/ubuntu/.cargo/bin:${PATH}"
  export PATH
  need_cmd cargo; need_cmd git; need_cmd install; need_cmd python3; need_cmd rustc
  need_cmd stat; need_cmd readlink
  if [[ -n "$explicit_repo_root" ]]; then
    REPO_ROOT="$(git -C "$explicit_repo_root" rev-parse --show-toplevel)"
    [[ "$REPO_ROOT" == "$explicit_repo_root" && "$(readlink -f "$explicit_repo_root")" == "$explicit_repo_root" ]] || die "explicit repository root is not canonical"
  else
    REPO_ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)"
  fi
  cd "$REPO_ROOT"
  SSD_LAUNCHER="${REPO_ROOT}/scripts/fcp_ssd.sh"
  [[ -f "$SSD_LAUNCHER" && ! -L "$SSD_LAUNCHER" ]] \
    || die "SSD launcher is missing or symlinked: $SSD_LAUNCHER"
  is_safe_release_id "$release_id" || die "invalid release id"
  if [[ -n "$LOCAL_MCP_PACKAGE_INPUT" || -n "$LOCAL_MCP_PACKAGE_INPUT_SHA256" ]]; then
    [[ -n "$LOCAL_MCP_PACKAGE_INPUT" && -n "$LOCAL_MCP_PACKAGE_INPUT_SHA256" ]] || die "local package input and hash must be paired"
    [[ -f "$LOCAL_MCP_PACKAGE_INPUT" && ! -L "$LOCAL_MCP_PACKAGE_INPUT" \
      && "$(stat -c '%u:%g:%a:%h' "$LOCAL_MCP_PACKAGE_INPUT")" == '0:0:600:1' ]] \
      || die "local package preparation DATA identity denied"
    [[ "$(sha256sum "$LOCAL_MCP_PACKAGE_INPUT" | cut -d' ' -f1)" == "$LOCAL_MCP_PACKAGE_INPUT_SHA256" ]] \
      || die "local package preparation DATA hash denied"
  fi
  for digest_name in \
    EEC_ARCHIVE_INPUT_SCHEMA_DIGEST \
    EEC_ARCHIVE_OUTPUT_SCHEMA_DIGEST \
    EEC_EXECUTE_INPUT_SCHEMA_DIGEST \
    EEC_EXECUTE_OUTPUT_SCHEMA_DIGEST \
    HETZNER_ARCHIVE_INPUT_SCHEMA_DIGEST \
    HETZNER_ARCHIVE_OUTPUT_SCHEMA_DIGEST \
    HETZNER_EXECUTE_INPUT_SCHEMA_DIGEST \
    HETZNER_EXECUTE_OUTPUT_SCHEMA_DIGEST; do
    digest="${!digest_name}"
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] \
      || die "$digest_name must be a fresh tools/list sha256 digest"
  done
  [[ "${FWC_N8N_OWNER_PUBLIC_KEY_HEX:-}" =~ ^[0-9a-f]{64}$ ]] || die "FWC_N8N_OWNER_PUBLIC_KEY_HEX must be 64 lowercase hex characters"
  if [[ -n "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX:-}" ]]; then
    [[ "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX}" =~ ^[0-9a-f]{64}$ ]] \
      || die "FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX must be 64 lowercase hex characters"
    [[ "${FWC_N8N_OWNER_PREVIOUS_PUBLIC_KEY_HEX}" != "${FWC_N8N_OWNER_PUBLIC_KEY_HEX}" ]] \
      || die "active and previous owner public keys must differ"
  fi
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
    [[ -z "$LOCAL_MCP_PACKAGE_INPUT$LOCAL_MCP_PACKAGE_INPUT_SHA256" ]] || die "reuse retains the exact native package"
    [[ -z "${FWC_N8N_LOCAL_CALL_BUDGET_SHA256:-}${FWC_N8N_CREDENTIAL_METADATA_MAPPING_SHA256:-}" ]] \
      || die "reuse retains the exact local and credential policies"
    require_clean_tracked_head
    RETAINED_RELEASE="$(select_retained_release "$(readlink -e "$CURRENT_PATH")")"
    readonly RETAINED_RELEASE
    validate_retained_inputs "$(readlink -e "$CURRENT_PATH")"
    validate_retained_schema_inputs
    build_hash_helper
    validate_retained_native_package
    [[ "$(sha256sum "$REPO_ROOT/connectors/n8n/manifest.toml" | cut -d' ' -f1)" == \
      4c71a7d0f0765afb4a8f9fd1d7df71539ef2495f465bd4ca4d8e6c1d603acf8c ]] \
      || die "reuse n8n manifest denied"
    validate_official_schema_baselines "$RETAINED_RELEASE/bin/fwc-n8n"
    search_read_policy check "$RETAINED_RELEASE"
    credential_metadata_mapping check "$RETAINED_RELEASE"
    local_call_budget >/dev/null
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
  # Exercise the exact metadata producer before Cargo, stage creation or any seed.
  release_provenance emit "$release_id" "$git_revision" >/dev/null
  require_safe_directory "$INSTALL_ROOT"
  require_safe_directory "$INSTALL_ROOT/releases"
  source_release="$(readlink -f "$CURRENT_PATH")"
  [[ "$source_release" == "${INSTALL_ROOT}/releases/"* && -d "$source_release" ]] || die "current is outside fixed releases root"
  require_immutable_template_release "$source_release"
  # Refuse inconsistent admitted inputs before any Cargo/build or stage writes.
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" != 1 ]]; then
    validate_official_schema_baselines "$source_release/bin/fwc-n8n"
    search_read_policy check "$source_release"
    credential_metadata_mapping check "$source_release"
    local_call_budget >/dev/null
  fi
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

  build_runtime_artifacts
  run_static_smoke
  build_hash_helper
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
    hash_helper="$(require_pinned_build_input "$FWC_N8N_BLAKE3_HELPER" "$FWC_N8N_BLAKE3_HELPER_SHA256" helper)"
  else
    hash_helper="$TARGET_DIR/release/fwc-n8n-blake3-helper"
  fi

  copy_templates "$source_release" "$stage_root"
  echo "[test] staged n8n manifest production validation" >&2
  FCP_N8N_STAGED_MANIFEST_PATH="$stage_root/manifests/fcp-n8n.toml" \
    bash "$SSD_LAUNCHER" --target-dir "$TARGET_DIR" -- cargo --locked --offline test -p fcp-n8n operations_and_rate_pools_match_parsed_manifest
  echo "[test] staged MCP bridge manifest production validation" >&2
  FCP_MCP_BRIDGE_STAGED_MANIFEST_PATH="$stage_root/manifests/fcp-mcp-bridge.toml" \
    bash "$SSD_LAUNCHER" --target-dir "$TARGET_DIR" -- cargo --locked --offline test -p fcp-mcp-bridge --lib runtime_operation_catalog_matches_manifest_metadata
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
    rebind_retained_local_policy "$stage_root"
  else
    write_local_mcp_policy "$stage_root" "$hash_helper"
  fi
  assert_external_approval_issuer_is_not_staged "$stage_root"
  write_inventory_and_request "$stage_root" "$source_release" "$hash_helper" "$request_path" "$git_revision"
  search_read_policy apply "$stage_root"
  credential_metadata_mapping apply "$stage_root"
  write_metadata "$stage_root" "$git_revision" "$hash_helper"
  echo "assembled_release=${release_id}"
  echo "git_revision=${git_revision}"
  echo "stage_root=${stage_root}"
  echo "request_file=${request_path}"
  echo "signer=${TARGET_DIR}/release/fwc-n8n-owner-sign"
  if [[ "${FWC_N8N_REUSE_RETAINED-0}" == 1 ]]; then
    echo "external_approval_issuer=${EXTERNAL_APPROVAL_ISSUER_INSTALL_PATH}"
  else
    echo "external_approval_issuer=${TARGET_DIR}/release/${EXTERNAL_APPROVAL_ISSUER}"
  fi
  echo "external_approval_issuer_install_target=${EXTERNAL_APPROVAL_ISSUER_INSTALL_PATH}"
  echo "next_step=owner-sign then fwc-n8n provision --mode preflight"
}

main "$@"
