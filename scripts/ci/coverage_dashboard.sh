#!/usr/bin/env bash
# coverage_dashboard.sh — Generate coverage dashboards and diff reports.
#
# Takes the JSON output from test_coverage_scan.sh and produces:
#   1. Markdown summary grouped by connector family and archetype
#   2. Diff report comparing current state to a baseline
#   3. Machine-readable dashboard JSON
#
# Bead: flywheel_connectors-49z0b.15.3
#
# Usage:
#   scripts/ci/coverage_dashboard.sh [options]
#
# Options:
#   --scan-json <path>     Input from test_coverage_scan.sh --json-out (required)
#   --baseline <path>      Previous scan JSON for diff report
#   --markdown-out <path>  Write markdown dashboard (default: stdout)
#   --diff-out <path>      Write diff report
#   --json-out <path>      Write machine-readable dashboard JSON
#   -h, --help             Show this help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SCAN_JSON=""
BASELINE=""
MARKDOWN_OUT=""
DIFF_OUT=""
JSON_OUT=""

usage() {
    sed -n '/^# Usage:/,/^[^#]/{ /^#/s/^# //p }' "$0"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scan-json) SCAN_JSON="$2"; shift 2 ;;
        --baseline) BASELINE="$2"; shift 2 ;;
        --markdown-out) MARKDOWN_OUT="$2"; shift 2 ;;
        --diff-out) DIFF_OUT="$2"; shift 2 ;;
        --json-out) JSON_OUT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Auto-generate scan if not provided
if [[ -z "$SCAN_JSON" ]]; then
    SCAN_JSON="/tmp/fcp-coverage-scan-$$.json"
    echo "Running coverage scan..."
    bash "${SCRIPT_DIR}/test_coverage_scan.sh" --json-out "$SCAN_JSON" 2>/dev/null
fi

if [[ ! -f "$SCAN_JSON" ]]; then
    echo "Error: Scan JSON not found: $SCAN_JSON"
    exit 1
fi

# Generate dashboard using Python for JSON processing
python3 - "$SCAN_JSON" "$BASELINE" "$MARKDOWN_OUT" "$DIFF_OUT" "$JSON_OUT" <<'PYEOF'
import json
import sys
from collections import defaultdict
from datetime import datetime

scan_path = sys.argv[1]
baseline_path = sys.argv[2] if sys.argv[2] else None
markdown_out = sys.argv[3] if sys.argv[3] else None
diff_out = sys.argv[4] if sys.argv[4] else None
json_out = sys.argv[5] if sys.argv[5] else None

with open(scan_path) as f:
    scan = json.load(f)

connectors = scan.get("connectors", [])
crates = scan.get("crates", [])

# ── Group connectors by family ──

FAMILY_MAP = {
    "messaging": ["slack", "discord", "telegram", "twitter", "teams", "mattermost",
                   "signal", "matrix", "irc", "nostr", "mastodon", "whatsapp",
                   "line", "qq", "wecom", "zalo", "zalouser", "dingtalk",
                   "feishu", "synology-chat", "bluebubbles", "imessage",
                   "nextcloud-talk", "tlon", "rocket-chat"],
    "google": ["gmail", "google-calendar", "google-drive", "google-docs",
               "google-sheets", "google-chat", "google-people", "google-places",
               "google-admin-reports", "google-workspace-events", "youtube", "bigquery"],
    "cloud": ["aws", "gcp", "azure", "cloudflare", "vercel", "netlify",
              "kubernetes", "terraform", "pulumi", "supabase", "firebase"],
    "ai_llm": ["anthropic", "openai", "google-ai", "mistral", "openrouter",
               "llm-router", "huggingface", "whisper", "deepgram", "elevenlabs"],
    "devtools": ["github", "gitlab", "bitbucket", "linear", "jira", "clickup",
                 "todoist", "trello", "asana", "circleci", "dockerhub", "sentry",
                 "package-registry"],
    "databases": ["postgresql", "mysql", "mongodb", "redis", "elasticsearch",
                  "duckdb", "snowflake", "qdrant", "pinecone", "vectordb", "sqlite"],
    "productivity": ["notion", "airtable", "figma", "confluence", "coda", "obsidian",
                     "logseq", "roam", "evernote", "pandadoc", "todoist",
                     "apple-notes", "apple-reminders", "email-generic", "calendly",
                     "monday", "retool"],
    "finance": ["stripe", "paypal", "square", "plaid", "shopify"],
    "analytics": ["mixpanel", "amplitude", "posthog", "segment", "metabase", "datadog",
                  "grafana"],
    "comms": ["sendgrid", "twilio", "mailchimp", "hubspot", "intercom", "zendesk"],
    "security": ["1password", "bitwarden"],
    "automation": ["zapier", "make", "n8n", "cron", "webhook-receiver"],
    "home_device": ["sonos", "hue", "homeassistant"],
    "content": ["reddit", "linkedin", "spotify", "arxiv", "annas-archive",
                "semanticscholar", "hackernews"],
    "other": ["browser", "mcp-bridge", "microsoft365", "salesforce", "box",
              "dropbox", "docusign"],
}

def get_family(connector_id):
    for family, members in FAMILY_MAP.items():
        if connector_id in members:
            return family
    return "uncategorized"

# ── Build dashboard data ──

by_family = defaultdict(list)
by_tier = defaultdict(list)
by_status = defaultdict(int)
issue_counts = defaultdict(int)

for c in connectors:
    cid = c["id"]
    family = get_family(cid)
    tier = c.get("live_tier", "unknown")
    status = c.get("status", "unknown")

    by_family[family].append(c)
    by_tier[tier].append(c)
    by_status[status] += 1

    for issue in c.get("issues", []):
        issue_counts[issue["code"]] += 1

total = len(connectors)
passing = by_status.get("pass", 0)
failing = by_status.get("fail", 0)

# ── Generate markdown ──

lines = []
lines.append("# Coverage Dashboard")
lines.append("")
lines.append(f"> Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
lines.append(f"> Source: `test_coverage_scan.sh`")
lines.append("")

# Summary
lines.append("## Summary")
lines.append("")
lines.append(f"| Metric | Value |")
lines.append(f"| --- | --- |")
lines.append(f"| Total connectors | {total} |")
lines.append(f"| Passing | {passing} ({100*passing//max(total,1)}%) |")
lines.append(f"| Failing | {failing} ({100*failing//max(total,1)}%) |")
lines.append(f"| Core crates | {len(crates)} |")
lines.append("")

# By tier
lines.append("## Coverage by Live Tier")
lines.append("")
lines.append("| Tier | Total | Pass | Fail | Pass Rate |")
lines.append("| --- | --- | --- | --- | --- |")
for tier in ["local_sufficient", "sandbox_required", "device_required",
             "live_read_only", "live_write_required", "unknown"]:
    items = by_tier.get(tier, [])
    if not items:
        continue
    t = len(items)
    p = sum(1 for i in items if i.get("status") == "pass")
    f = t - p
    rate = f"{100*p//max(t,1)}%"
    lines.append(f"| {tier} | {t} | {p} | {f} | {rate} |")
lines.append("")

# By family
lines.append("## Coverage by Connector Family")
lines.append("")
for family in sorted(by_family.keys()):
    items = by_family[family]
    t = len(items)
    p = sum(1 for i in items if i.get("status") == "pass")
    f = t - p

    lines.append(f"### {family.replace('_', ' ').title()} ({p}/{t} pass)")
    lines.append("")
    lines.append("| Connector | Tests | Tier | Status | Issues |")
    lines.append("| --- | --- | --- | --- | --- |")
    for c in sorted(items, key=lambda x: x["id"]):
        tests = c.get("source_adjacent", {}).get("total_tests", 0)
        tier = c.get("live_tier", "?")
        status = c.get("status", "?")
        issues = ", ".join(i["code"] for i in c.get("issues", []))[:60]
        icon = "pass" if status == "pass" else "FAIL"
        lines.append(f"| {c['id']} | {tests} | {tier} | {icon} | {issues} |")
    lines.append("")

# Top issues
lines.append("## Top Issues")
lines.append("")
lines.append("| Issue | Count |")
lines.append("| --- | --- |")
for issue, count in sorted(issue_counts.items(), key=lambda x: -x[1]):
    lines.append(f"| {issue} | {count} |")
lines.append("")

markdown = "\n".join(lines)

# ── Output ──

if markdown_out:
    with open(markdown_out, "w") as f:
        f.write(markdown)
    print(f"Dashboard written to: {markdown_out}")
else:
    print(markdown)

# ── Diff report ──

if baseline_path and diff_out:
    try:
        with open(baseline_path) as f:
            baseline = json.load(f)

        old_connectors = {c["id"]: c for c in baseline.get("connectors", [])}
        new_connectors = {c["id"]: c for c in connectors}

        diff_lines = ["# Coverage Diff Report", ""]

        # New connectors
        new_ids = set(new_connectors) - set(old_connectors)
        if new_ids:
            diff_lines.append(f"## New Connectors (+{len(new_ids)})")
            for cid in sorted(new_ids):
                diff_lines.append(f"- {cid}")
            diff_lines.append("")

        # Removed connectors
        removed_ids = set(old_connectors) - set(new_connectors)
        if removed_ids:
            diff_lines.append(f"## Removed Connectors (-{len(removed_ids)})")
            for cid in sorted(removed_ids):
                diff_lines.append(f"- {cid}")
            diff_lines.append("")

        # Status changes
        changes = []
        for cid in sorted(set(old_connectors) & set(new_connectors)):
            old_status = old_connectors[cid].get("status")
            new_status = new_connectors[cid].get("status")
            if old_status != new_status:
                changes.append((cid, old_status, new_status))

        if changes:
            diff_lines.append(f"## Status Changes ({len(changes)})")
            diff_lines.append("")
            diff_lines.append("| Connector | Old | New |")
            diff_lines.append("| --- | --- | --- |")
            for cid, old, new in changes:
                diff_lines.append(f"| {cid} | {old} | {new} |")
            diff_lines.append("")

        with open(diff_out, "w") as f:
            f.write("\n".join(diff_lines))
        print(f"Diff report written to: {diff_out}")
    except Exception as e:
        print(f"Warning: Could not generate diff report: {e}")

# ── JSON dashboard ──

if json_out:
    dashboard = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_connectors": total,
        "passing": passing,
        "failing": failing,
        "pass_rate": round(passing / max(total, 1) * 100, 1),
        "by_tier": {tier: {"total": len(items), "pass": sum(1 for i in items if i.get("status") == "pass")}
                    for tier, items in by_tier.items()},
        "by_family": {family: {"total": len(items), "pass": sum(1 for i in items if i.get("status") == "pass")}
                      for family, items in by_family.items()},
        "top_issues": dict(sorted(issue_counts.items(), key=lambda x: -x[1])),
    }
    with open(json_out, "w") as f:
        json.dump(dashboard, f, indent=2)
    print(f"JSON dashboard written to: {json_out}")
PYEOF
