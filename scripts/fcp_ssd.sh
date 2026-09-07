#!/usr/bin/env bash
set -euo pipefail

# Shared local build launcher.  The SSD mount is an input boundary: validate it
# before creating any child directory so a missing mount can never fall back to
# the root filesystem.
readonly SSD_MOUNT="/srv/dev-ssd"
readonly SSD_ROOT="/srv/dev-ssd/fcp"
readonly SSD_UUID="7b54d2fa-66e1-499d-9c08-68ced7e00f08"
readonly DEFAULT_TARGET_DIR="${SSD_ROOT}/targets/n8n"
readonly CARGO_HOME_DIR="${SSD_ROOT}/cargo-home"
readonly TMP_DIR="${SSD_ROOT}/tmp"
readonly LOG_DIR="${SSD_ROOT}/logs"
readonly OUT_ROOT="${SSD_ROOT}/artifacts"
readonly OUT_DIR="${OUT_ROOT}/n8n"
readonly PROOF_ARTIFACT_DIR="${OUT_DIR}/proof"
readonly BUILD_LOCK="${SSD_ROOT}/build.lock"
readonly DEFAULT_JOBS=2
readonly CARGO_INCREMENTAL_VALUE=0
readonly CARGO_PROFILE_DEBUG_VALUE=0

die() {
  printf 'fcp_ssd: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/fcp_ssd.sh [--target-dir <ssd-path>] --check
  scripts/fcp_ssd.sh [--target-dir <ssd-path>] check-env
  scripts/fcp_ssd.sh [--target-dir <ssd-path>] [--] <command> [args...]

The target override must remain below /srv/dev-ssd/fcp.  Commands are passed
directly as argv; no shell evaluation is performed.
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

require_filesystem_uuid() {
  local path="$1"
  [[ "$(findmnt -no UUID --target "$path")" == "$SSD_UUID" ]] \
    || die "path is not on the approved SSD filesystem: $path"
}

require_safe_directory() {
  local path="$1"
  [[ -d "$path" && ! -L "$path" ]] || die "directory is missing or symlinked: $path"
  [[ "$(readlink -m -- "$path")" == "$path" ]] || die "directory path is symlinked: $path"
  local mode
  mode="$(stat -c '%a' -- "$path")"
  (( (8#$mode & 0022) == 0 )) || die "directory is group/world writable: $path"
}

require_safe_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || die "lock is missing or symlinked: $path"
  [[ "$(readlink -m -- "$path")" == "$path" ]] || die "lock path is symlinked: $path"
  local mode
  mode="$(stat -c '%a' -- "$path")"
  (( (8#$mode & 0022) == 0 )) || die "lock is group/world writable: $path"
}

require_existing_ancestor_on_ssd() {
  local path="$1"
  local probe="$path"
  while [[ ! -e "$probe" && ! -L "$probe" && "$probe" != "/" ]]; do
    probe="${probe%/*}"
    [[ -n "$probe" ]] || probe="/"
  done
  [[ -d "$probe" && ! -L "$probe" ]] || die "output ancestor is missing or symlinked: $probe"
  require_safe_directory "$probe"
  require_filesystem_uuid "$probe"
}

require_ssd_mount() {
  need_cmd findmnt
  need_cmd mountpoint
  need_cmd readlink
  need_cmd stat
  need_cmd flock
  need_cmd install
  need_cmd env
  [[ -d "$SSD_MOUNT" && ! -L "$SSD_MOUNT" ]] || die "SSD mount directory is missing"
  mountpoint -q -- "$SSD_MOUNT" || die "SSD mount is not mounted: $SSD_MOUNT"
  [[ "$(findmnt -no TARGET --target "$SSD_MOUNT")" == "$SSD_MOUNT" ]] \
    || die "unexpected mount target for $SSD_MOUNT"
  [[ "$(findmnt -no UUID --target "$SSD_MOUNT")" == "$SSD_UUID" ]] \
    || die "SSD mount UUID is not approved"
  require_safe_directory "$SSD_MOUNT"
  require_filesystem_uuid "$SSD_MOUNT"

  # Callers decide whether to create the child root.  In either case, reject a
  # dangling symlink before testing -e so a missing mount cannot be confused
  # with an absent directory.
  [[ ! -L "$SSD_ROOT" ]] || die "SSD root is symlinked: $SSD_ROOT"
  if [[ -e "$SSD_ROOT" ]]; then
    require_safe_directory "$SSD_ROOT"
    require_filesystem_uuid "$SSD_ROOT"
  fi
}

validate_target_path() {
  local path="$1"
  [[ "$path" == "$SSD_ROOT" || "$path" == "$SSD_ROOT"/* ]] \
    || die "target must be below $SSD_ROOT"
  [[ "$path" != *$'\n'* && "$path" != *$'\r'* ]] || die "target contains a newline"
  [[ "$path" != */../* && "$path" != */.. && "$path" != *'/./'* && "$path" != */. ]] \
    || die "target contains a path traversal component"
  [[ "$(readlink -m -- "$path")" == "$path" ]] || die "target path is symlinked: $path"
}

ensure_directory() {
  local path="$1"
  local mode="$2"
  validate_target_path "$path"
  require_existing_ancestor_on_ssd "$path"
  [[ ! -L "$path" ]] || die "directory is symlinked: $path"
  if [[ -e "$path" ]]; then
    require_safe_directory "$path"
  else
    install -d -m "$mode" -- "$path"
    require_safe_directory "$path"
  fi
  require_filesystem_uuid "$path"
}

inspect_directory() {
  local path="$1"
  validate_target_path "$path"
  require_existing_ancestor_on_ssd "$path"
  [[ ! -L "$path" ]] || die "directory is symlinked: $path"
  if [[ -e "$path" ]]; then
    require_safe_directory "$path"
    require_filesystem_uuid "$path"
  fi
}

ensure_ssd_root() {
  [[ ! -L "$SSD_ROOT" ]] || die "SSD root is symlinked: $SSD_ROOT"
  if [[ -e "$SSD_ROOT" ]]; then
    require_safe_directory "$SSD_ROOT"
  else
    require_existing_ancestor_on_ssd "$SSD_ROOT"
    install -d -m 0755 -- "$SSD_ROOT"
    require_safe_directory "$SSD_ROOT"
  fi
  require_filesystem_uuid "$SSD_ROOT"
}

validate_backend() {
  local backend="${FWC_PACKAGE_BUILD_BACKEND:-local}"
  local require_remote="${RCH_REQUIRE_REMOTE:-}"
  local force_remote="${RCH_FORCE_REMOTE:-}"
  [[ "${require_remote,,}" != true && "$require_remote" != 1 ]] \
    || die "remote-required package build backend is refused"
  [[ "${force_remote,,}" != true && "$force_remote" != 1 ]] \
    || die "remote-required package build backend is refused"
  [[ "$backend" == local ]] || die "remote-required package build backend is refused"
}

reject_nested_launcher() {
  local active="${FCP_SSD_ACTIVE:-}"
  [[ "${active,,}" != true && "$active" != 1 ]] \
    || die "nested fcp_ssd invocation is refused while the SSD lock is active"
}

prepare_environment() {
  local target_dir="$1"
  local create_dirs="$2"
  require_ssd_mount
  reject_nested_launcher
  [[ "$target_dir" != "$SSD_ROOT" ]] || die "target must be a dedicated child below $SSD_ROOT"
  if [[ "$create_dirs" == 1 ]]; then
    ensure_ssd_root
    ensure_directory "$CARGO_HOME_DIR" 0700
    ensure_directory "${SSD_ROOT}/targets" 0755
    ensure_directory "$target_dir" 0755
    ensure_directory "$TMP_DIR" 0700
    ensure_directory "$LOG_DIR" 0700
    ensure_directory "$OUT_ROOT" 0755
    ensure_directory "$OUT_DIR" 0755
    ensure_directory "$PROOF_ARTIFACT_DIR" 0755
  else
    validate_target_path "$target_dir"
    inspect_directory "$SSD_ROOT"
    inspect_directory "$CARGO_HOME_DIR"
    inspect_directory "${SSD_ROOT}/targets"
    inspect_directory "$target_dir"
    inspect_directory "$TMP_DIR"
    inspect_directory "$LOG_DIR"
    inspect_directory "$OUT_ROOT"
    inspect_directory "$OUT_DIR"
    inspect_directory "$PROOF_ARTIFACT_DIR"
  fi

  if [[ -L "$BUILD_LOCK" ]]; then
    die "lock is symlinked: $BUILD_LOCK"
  elif [[ -e "$BUILD_LOCK" ]]; then
    require_safe_file "$BUILD_LOCK"
    require_filesystem_uuid "$BUILD_LOCK"
  elif [[ "$create_dirs" == 1 ]]; then
    require_existing_ancestor_on_ssd "$BUILD_LOCK"
    (umask 077 && : > "$BUILD_LOCK")
    chmod 0600 -- "$BUILD_LOCK"
    require_safe_file "$BUILD_LOCK"
    require_filesystem_uuid "$BUILD_LOCK"
  else
    :
  fi
}

jobs_value() {
  local jobs="${FCP_SSD_JOBS:-${CARGO_BUILD_JOBS:-$DEFAULT_JOBS}}"
  [[ "$jobs" =~ ^[12]$ ]] || die "build jobs must be 1 or 2"
  printf '%s\n' "$jobs"
}

check_env() {
  local target_dir="$1"
  local jobs
  jobs="$(jobs_value)"
  validate_backend
  prepare_environment "$target_dir" 0
  printf '%s\n' \
    "FCP_SSD_ROOT=$SSD_ROOT" \
    "CARGO_HOME=$CARGO_HOME_DIR" \
    "CARGO_TARGET_DIR=$target_dir" \
    "TMPDIR=$TMP_DIR" \
    "TMP=$TMP_DIR" \
    "TEMP=$TMP_DIR" \
    "CARGO_BUILD_JOBS=$jobs" \
    "CARGO_INCREMENTAL=$CARGO_INCREMENTAL_VALUE" \
    "CARGO_PROFILE_DEV_DEBUG=$CARGO_PROFILE_DEBUG_VALUE" \
    "CARGO_PROFILE_TEST_DEBUG=$CARGO_PROFILE_DEBUG_VALUE" \
    "CARGO_PROFILE_RELEASE_DEBUG=$CARGO_PROFILE_DEBUG_VALUE" \
    "FWC_PACKAGE_BUILD_BACKEND=local" \
    "OUT_ROOT=$OUT_ROOT" \
    "OUT_DIR=$OUT_DIR" \
    "PROOF_ARTIFACT_DIR=$PROOF_ARTIFACT_DIR" \
    "LOG_DIR=$LOG_DIR" \
    "FCP_SSD_BUILD_LOCK=$BUILD_LOCK" \
    "mount_uuid=$SSD_UUID" \
    "check_mutation=none"
}

run_argv() {
  local target_dir="$1"
  shift
  local jobs="$1"
  shift
  local lock_fd status path_with_cargo
  path_with_cargo="$PATH"
  if [[ -d /home/ubuntu/.cargo/bin && ":$path_with_cargo:" != *":/home/ubuntu/.cargo/bin:"* ]]; then
    path_with_cargo="/home/ubuntu/.cargo/bin:$path_with_cargo"
  fi

  # Append-open never truncates or replaces an existing lock inode.
  exec {lock_fd}>>"$BUILD_LOCK"
  flock -x "$lock_fd"
  if env -- \
    CARGO_HOME="$CARGO_HOME_DIR" \
    CARGO_TARGET_DIR="$target_dir" \
    TMPDIR="$TMP_DIR" \
    TMP="$TMP_DIR" \
    TEMP="$TMP_DIR" \
    CARGO_BUILD_JOBS="$jobs" \
    CARGO_INCREMENTAL="$CARGO_INCREMENTAL_VALUE" \
    CARGO_PROFILE_DEV_DEBUG="$CARGO_PROFILE_DEBUG_VALUE" \
    CARGO_PROFILE_TEST_DEBUG="$CARGO_PROFILE_DEBUG_VALUE" \
    CARGO_PROFILE_RELEASE_DEBUG="$CARGO_PROFILE_DEBUG_VALUE" \
    FWC_PACKAGE_BUILD_BACKEND=local \
    OUT_ROOT="$OUT_ROOT" \
    OUT_DIR="$OUT_DIR" \
    PROOF_ARTIFACT_DIR="$PROOF_ARTIFACT_DIR" \
    LOG_DIR="$LOG_DIR" \
    FCP_SSD_ACTIVE=1 \
    PATH="$path_with_cargo" \
    "$@"; then
    status=0
  else
    status=$?
  fi
  flock -u "$lock_fd"
  exec {lock_fd}>&-
  return "$status"
}

main() {
  local target_dir="$DEFAULT_TARGET_DIR"
  local mode=exec

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --target-dir)
        [[ $# -ge 2 ]] || die "--target-dir requires a value"
        target_dir="$2"
        shift 2
        ;;
      --check|check-env)
        mode=check
        shift
        ;;
      exec)
        shift
        break
        ;;
      --)
        shift
        break
        ;;
      --help|-h)
        usage
        return 0
        ;;
      *)
        break
        ;;
    esac
  done

  if [[ "$mode" == check ]]; then
    [[ $# -eq 0 ]] || die "check-env does not accept a command"
    check_env "$target_dir"
    return 0
  fi
  [[ $# -gt 0 ]] || { usage; return 64; }

  local jobs
  jobs="$(jobs_value)"
  validate_backend
  prepare_environment "$target_dir" 1
  run_argv "$target_dir" "$jobs" "$@"
}

main "$@"
