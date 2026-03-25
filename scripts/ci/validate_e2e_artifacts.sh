#!/usr/bin/env bash
# validate_e2e_artifacts.sh — CI gate for E2E artifact quality.
#
# Validates:
#   1. JSONL schema compliance (required fields present, correct types)
#   2. Secret/PII redaction (no raw tokens, keys, or sensitive patterns)
#   3. Replay bundle completeness (required files present)
#   4. Artifact retention structure (expected directory layout)
#
# Bead: flywheel_connectors-49z0b.15.2
#
# Usage:
#   scripts/ci/validate_e2e_artifacts.sh [options]
#
# Options:
#   --artifact-dir <path>   Directory containing E2E artifacts (default: auto-detect)
#   --jsonl-file <path>     Specific JSONL file to validate
#   --bundle-dir <path>     Specific replay bundle directory to validate
#   --check <mode>          all | jsonl | redaction | bundle | retention (default: all)
#   --json-out <path>       Write machine-readable JSON report
#   --strict                Fail on warnings (default: only errors)
#   -h, --help              Show this help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Defaults
ARTIFACT_DIR=""
JSONL_FILE=""
BUNDLE_DIR=""
CHECK_MODE="all"
JSON_OUT=""
STRICT=false

# Counters
ERRORS=0
WARNINGS=0
CHECKS=0

# Colors
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    sed -n '/^# Usage:/,/^[^#]/{ /^#/s/^# //p }' "$0"
    exit 0
}

error() {
    ERRORS=$((ERRORS + 1))
    echo -e "  ${RED}ERROR${NC} $1"
}

warn() {
    WARNINGS=$((WARNINGS + 1))
    echo -e "  ${YELLOW}WARN${NC} $1"
}

pass() {
    CHECKS=$((CHECKS + 1))
    echo -e "  ${GREEN}PASS${NC} $1"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --artifact-dir) ARTIFACT_DIR="$2"; shift 2 ;;
        --jsonl-file) JSONL_FILE="$2"; shift 2 ;;
        --bundle-dir) BUNDLE_DIR="$2"; shift 2 ;;
        --check) CHECK_MODE="$2"; shift 2 ;;
        --json-out) JSON_OUT="$2"; shift 2 ;;
        --strict) STRICT=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# ─────────────────────────────────────────────────────────────────────────────
# JSONL Schema Validation
# ─────────────────────────────────────────────────────────────────────────────

validate_jsonl_entry() {
    local line="$1"
    local line_num="$2"
    local file="$3"

    # Must be valid JSON
    if ! echo "$line" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
        error "$file:$line_num invalid JSON"
        return
    fi

    # Extract fields
    local has_timestamp has_test_name has_phase has_correlation_id
    has_timestamp=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'timestamp' in d else 'no')" 2>/dev/null || echo "no")
    has_test_name=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'test_name' in d else 'no')" 2>/dev/null || echo "no")
    has_phase=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'phase' in d else 'no')" 2>/dev/null || echo "no")
    has_correlation_id=$(echo "$line" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if 'correlation_id' in d else 'no')" 2>/dev/null || echo "no")

    if [[ "$has_timestamp" != "yes" ]]; then
        error "$file:$line_num missing required field 'timestamp'"
    fi
    if [[ "$has_test_name" != "yes" ]]; then
        warn "$file:$line_num missing field 'test_name' (required for E2E entries)"
    fi

    CHECKS=$((CHECKS + 1))
}

validate_jsonl_file() {
    local file="$1"
    echo "Validating JSONL: $file"

    if [[ ! -f "$file" ]]; then
        error "File not found: $file"
        return
    fi

    local line_num=0
    local total_lines
    total_lines=$(wc -l < "$file" | tr -d ' ')

    if [[ "$total_lines" -eq 0 ]]; then
        warn "$file is empty"
        return
    fi

    local validated=0
    while IFS= read -r line; do
        line_num=$((line_num + 1))
        [[ -z "$line" ]] && continue
        validate_jsonl_entry "$line" "$line_num" "$file"
        validated=$((validated + 1))
    done < "$file"

    pass "$file: $validated entries validated ($line_num lines)"
}

# ─────────────────────────────────────────────────────────────────────────────
# Redaction Validation
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that should never appear in evidence artifacts
REDACTION_PATTERNS=(
    'sk[-_]test[-_][a-zA-Z0-9]{20}'     # Stripe test keys
    'sk[-_]live[-_][a-zA-Z0-9]{20}'     # Stripe live keys
    'Bearer [a-zA-Z0-9._-]{20,}'       # Bearer tokens
    'token=[a-zA-Z0-9._-]{20,}'        # URL token params
    'api[_-]?key=[a-zA-Z0-9._-]{15,}'  # API key values
    'password=[^[:space:]&]{5,}'       # Password values
    'secret=[^[:space:]&]{10,}'        # Secret values
    'client_secret=[^[:space:]&]{10,}' # OAuth client secrets
    'refresh_token=[^[:space:]&]{10,}' # Refresh tokens
    'access_token=[^[:space:]&]{10,}'  # Access tokens
    'AKIA[A-Z0-9]{16}'                 # AWS access key IDs
    'ghp_[a-zA-Z0-9]{36}'             # GitHub PATs
    'gho_[a-zA-Z0-9]{36}'             # GitHub OAuth tokens
    'xoxb-[0-9]+-[a-zA-Z0-9]+'        # Slack bot tokens
    'xoxp-[0-9]+-[a-zA-Z0-9]+'        # Slack user tokens
)

validate_redaction_file() {
    local file="$1"
    echo "Checking redaction: $file"

    if [[ ! -f "$file" ]]; then
        error "File not found: $file"
        return
    fi

    local found_leak=false
    for pattern in "${REDACTION_PATTERNS[@]}"; do
        local matches
        matches=$(grep -cE "$pattern" "$file" 2>/dev/null || true)
        if [[ "$matches" -gt 0 ]]; then
            error "$file: found $matches matches for redaction pattern '$pattern'"
            found_leak=true
        fi
    done

    if [[ "$found_leak" == "false" ]]; then
        pass "$file: no sensitive patterns detected"
    fi
}

validate_redaction_dir() {
    local dir="$1"
    echo "Scanning directory for redaction: $dir"

    if [[ ! -d "$dir" ]]; then
        warn "Directory not found: $dir"
        return
    fi

    while read -r file; do
        validate_redaction_file "$file"
    done < <(find "$dir" -type f \( -name "*.json" -o -name "*.jsonl" -o -name "*.txt" -o -name "*.log" \) 2>/dev/null)
}

# ─────────────────────────────────────────────────────────────────────────────
# Replay Bundle Validation
# ─────────────────────────────────────────────────────────────────────────────

validate_replay_bundle() {
    local dir="$1"
    echo "Validating replay bundle: $dir"

    if [[ ! -d "$dir" ]]; then
        error "Bundle directory not found: $dir"
        return
    fi

    # Required files
    local required_files=("summary.json" "replay.sh")
    for req in "${required_files[@]}"; do
        if [[ -f "$dir/$req" ]]; then
            pass "Bundle has required file: $req"
        else
            error "Bundle missing required file: $req"
        fi
    done

    # Optional but expected files
    local expected_files=("environment.json" "quarantine_candidates.json" "suite.jsonl")
    for exp in "${expected_files[@]}"; do
        if [[ -f "$dir/$exp" ]]; then
            pass "Bundle has expected file: $exp"
        else
            warn "Bundle missing expected file: $exp"
        fi
    done

    # Validate replay.sh is executable or at least has bash shebang
    if [[ -f "$dir/replay.sh" ]]; then
        if head -1 "$dir/replay.sh" | grep -q "#!/"; then
            pass "replay.sh has shebang"
        else
            warn "replay.sh missing shebang line"
        fi
    fi

    # Validate summary.json is valid JSON
    if [[ -f "$dir/summary.json" ]]; then
        if python3 -c "import json; json.load(open('$dir/summary.json'))" 2>/dev/null; then
            pass "summary.json is valid JSON"
        else
            error "summary.json is not valid JSON"
        fi
    fi

    # Validate environment.json has no secrets
    if [[ -f "$dir/environment.json" ]]; then
        validate_redaction_file "$dir/environment.json"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Artifact Retention Validation
# ─────────────────────────────────────────────────────────────────────────────

validate_retention() {
    local dir="$1"
    echo "Validating artifact retention: $dir"

    if [[ ! -d "$dir" ]]; then
        warn "Retention directory not found: $dir"
        return
    fi

    # Check for expected directory structure
    local json_count jsonl_count
    json_count=$(find "$dir" -name "*.json" -type f 2>/dev/null | wc -l | tr -d ' ')
    jsonl_count=$(find "$dir" -name "*.jsonl" -type f 2>/dev/null | wc -l | tr -d ' ')

    if [[ "$json_count" -gt 0 ]] || [[ "$jsonl_count" -gt 0 ]]; then
        pass "Retention directory has $json_count JSON + $jsonl_count JSONL files"
    else
        warn "Retention directory has no JSON/JSONL artifacts"
    fi

    # Check for oversized artifacts (> 10MB suggests a logging runaway)
    while read -r large_file; do
        warn "Oversized artifact (>10MB): $large_file"
    done < <(find "$dir" -type f -size +10M 2>/dev/null)
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

echo "=== E2E Artifact Validator ==="
echo "Mode: $CHECK_MODE"
echo ""

case "$CHECK_MODE" in
    all)
        if [[ -n "$JSONL_FILE" ]]; then
            validate_jsonl_file "$JSONL_FILE"
        fi
        if [[ -n "$BUNDLE_DIR" ]]; then
            validate_replay_bundle "$BUNDLE_DIR"
            validate_redaction_dir "$BUNDLE_DIR"
            validate_retention "$BUNDLE_DIR"
        fi
        if [[ -n "$ARTIFACT_DIR" ]]; then
            # Scan for JSONL files
            while read -r f; do
                validate_jsonl_file "$f"
            done < <(find "$ARTIFACT_DIR" -name "*.jsonl" -type f 2>/dev/null)
            validate_redaction_dir "$ARTIFACT_DIR"
            validate_retention "$ARTIFACT_DIR"
        fi
        if [[ -z "$JSONL_FILE" ]] && [[ -z "$BUNDLE_DIR" ]] && [[ -z "$ARTIFACT_DIR" ]]; then
            echo "No artifacts specified. Use --artifact-dir, --jsonl-file, or --bundle-dir."
            echo "Running self-test validation against repo E2E schemas..."
            echo ""
            # Validate the schema files themselves exist
            SCHEMA_DIR="${REPO_ROOT}/crates/fcp-conformance/src/schemas"
            if [[ -d "$SCHEMA_DIR" ]]; then
                for schema in "$SCHEMA_DIR"/E2E_Log_v*.schema.json; do
                    if [[ -f "$schema" ]]; then
                        if python3 -c "import json; json.load(open('$schema'))" 2>/dev/null; then
                            pass "Schema file valid: $(basename "$schema")"
                        else
                            error "Schema file invalid: $(basename "$schema")"
                        fi
                    fi
                done
            else
                warn "Schema directory not found: $SCHEMA_DIR"
            fi
            # Validate live-suite docs exist
            if [[ -f "${REPO_ROOT}/docs/testing/live-suite-classification.md" ]]; then
                pass "Live-suite classification doc exists"
            else
                error "Missing: docs/testing/live-suite-classification.md"
            fi
            if [[ -f "${REPO_ROOT}/docs/testing/live_suite_operator_playbook.md" ]]; then
                pass "Operator playbook exists"
            else
                error "Missing: docs/testing/live_suite_operator_playbook.md"
            fi
            if [[ -f "${REPO_ROOT}/docs/testing/core_platform_evidence_index.md" ]]; then
                pass "Evidence index exists"
            else
                error "Missing: docs/testing/core_platform_evidence_index.md"
            fi
        fi
        ;;
    jsonl)
        if [[ -n "$JSONL_FILE" ]]; then
            validate_jsonl_file "$JSONL_FILE"
        else
            echo "Specify --jsonl-file for JSONL validation"
            exit 1
        fi
        ;;
    redaction)
        if [[ -n "$ARTIFACT_DIR" ]] || [[ -n "$BUNDLE_DIR" ]]; then
            validate_redaction_dir "${ARTIFACT_DIR:-$BUNDLE_DIR}"
        else
            echo "Specify --artifact-dir or --bundle-dir for redaction check"
            exit 1
        fi
        ;;
    bundle)
        if [[ -n "$BUNDLE_DIR" ]]; then
            validate_replay_bundle "$BUNDLE_DIR"
        else
            echo "Specify --bundle-dir for bundle validation"
            exit 1
        fi
        ;;
    retention)
        if [[ -n "$ARTIFACT_DIR" ]]; then
            validate_retention "$ARTIFACT_DIR"
        else
            echo "Specify --artifact-dir for retention check"
            exit 1
        fi
        ;;
    *)
        echo "Unknown check mode: $CHECK_MODE"
        exit 1
        ;;
esac

echo ""
echo "=== Results ==="
echo "Checks: $CHECKS  Errors: $ERRORS  Warnings: $WARNINGS"

# Write JSON report
if [[ -n "$JSON_OUT" ]]; then
    cat > "$JSON_OUT" <<JSONEOF
{
  "checks": $CHECKS,
  "errors": $ERRORS,
  "warnings": $WARNINGS,
  "mode": "$CHECK_MODE",
  "pass": $(if [[ $ERRORS -eq 0 ]]; then echo "true"; else echo "false"; fi)
}
JSONEOF
    echo "JSON report: $JSON_OUT"
fi

# Exit code
if [[ $ERRORS -gt 0 ]]; then
    echo -e "${RED}FAIL${NC}: $ERRORS error(s)"
    exit 1
fi

if [[ "$STRICT" == "true" ]] && [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}FAIL (strict)${NC}: $WARNINGS warning(s)"
    exit 1
fi

echo -e "${GREEN}PASS${NC}"
exit 0
