#!/usr/bin/env python3
"""Generate a V3 Section 6 acceptance coverage matrix from scanner JSON.

This script consumes the machine-readable output from
scripts/ci/test_coverage_scan.sh and produces a clause-oriented accounting
matrix for docs/V3_Connector_Acceptance_Contract.md Section 6.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MUST_THRESHOLD = 0.95


@dataclass(frozen=True)
class MatrixRowSpec:
    row_id: str
    section: str
    level: str
    requirement: str
    scanner_issue_codes: tuple[str, ...]
    total_scope: str
    scanner_backing: str
    evidence_command: str
    notes: str
    weak_presence_only: bool = False


ROW_SPECS: tuple[MatrixRowSpec, ...] = (
    MatrixRowSpec(
        row_id="V3-6A-TAXONOMY-NAMING",
        section="6a",
        level="MUST",
        requirement=(
            "Evidence must be classified into exactly one suite class, and "
            "reserved no_mock/acceptance/host_e2e/live names must only be used "
            "for real non-fake boundaries."
        ),
        scanner_issue_codes=(
            "misnamed_no_mock_integration",
            "reserved_acceptance_name_without_acceptance_boundary",
            "live_suite_missing_env_gate",
            "src_mock_leakage",
        ),
        total_scope="all_connectors",
        scanner_backing="yes",
        evidence_command=(
            "bash scripts/ci/test_coverage_scan.sh --only connectors --json-out "
            "<scan.json>"
        ),
        notes=(
            "Scanner-backed for fake-source leakage and reserved-name violations; "
            "score uses unique affected connector ids rather than raw issue counts."
        ),
    ),
    MatrixRowSpec(
        row_id="V3-6B-PURE-UNIT-BASELINE",
        section="6b",
        level="MUST",
        requirement=(
            "Every connector has clean pure_unit coverage for config parsing, "
            "operation routing, error translation, redaction-sensitive output, "
            "and risk/idempotency classification."
        ),
        scanner_issue_codes=(
            "missing_pure_unit_signal",
            "pure_unit_floor_below_minimum",
            "src_mock_leakage",
        ),
        total_scope="all_connectors",
        scanner_backing="yes",
        evidence_command=(
            "bash scripts/ci/test_coverage_scan.sh --only connectors --check "
            "pure-unit-floor --json-out <scan.json>"
        ),
        notes=(
            "The scanner cannot prove semantic coverage of every listed behavior, "
            "but it does enforce the clean source-adjacent floor and mock leakage."
        ),
    ),
    MatrixRowSpec(
        row_id="V3-6B-DETERMINISTIC-CONTRACT",
        section="6b/6d",
        level="MUST",
        requirement=(
            "Every connector with lib.rs has deterministic_contract coverage for "
            "configure -> health/self_check -> introspect -> invoke lifecycle, "
            "error propagation, and provider failure behavior."
        ),
        scanner_issue_codes=("missing_deterministic_contract",),
        total_scope="all_connectors",
        scanner_backing="yes",
        evidence_command=(
            "bash scripts/ci/test_coverage_scan.sh --only connectors --check "
            "acceptance --json-out <scan.json>"
        ),
        notes=(
            "Presence is scanner-backed, but lifecycle depth still requires "
            "focused connector proof before calling a connector fully accepted."
        ),
        weak_presence_only=True,
    ),
    MatrixRowSpec(
        row_id="V3-6B-ACCEPTANCE-SUITE-PRESENCE",
        section="6b/6e",
        level="MUST",
        requirement=(
            "Every connector has at least one final acceptance suite from "
            "local_non_mock, host_e2e, or live according to the archetype matrix."
        ),
        scanner_issue_codes=("missing_acceptance_suite",),
        total_scope="all_connectors",
        scanner_backing="yes",
        evidence_command=(
            "bash scripts/ci/test_coverage_scan.sh --only connectors --check "
            "acceptance --json-out <scan.json>"
        ),
        notes="Dominant scanner-backed acceptance gap for the connector corpus.",
    ),
    MatrixRowSpec(
        row_id="V3-6C-PURE-UNIT-FLOOR",
        section="6c",
        level="MUST",
        requirement=(
            "Pure unit tests meet the configured source-adjacent floor and do not "
            "require wiremock, daemons, subprocesses, or external services."
        ),
        scanner_issue_codes=(
            "missing_pure_unit_signal",
            "pure_unit_floor_below_minimum",
            "src_mock_leakage",
        ),
        total_scope="all_connectors",
        scanner_backing="yes",
        evidence_command=(
            "bash scripts/ci/test_coverage_scan.sh --only connectors --check "
            "pure-unit-floor --json-out <scan.json>"
        ),
        notes=(
            "The scanner's numeric floor is configurable and currently lower than "
            "the aspirational 30/50+ text in Section 6c."
        ),
    ),
    MatrixRowSpec(
        row_id="V3-6E-ARCHETYPE-MINIMUMS",
        section="6e",
        level="MUST",
        requirement=(
            "Connector archetypes map to the required minimum acceptance boundary: "
            "local_non_mock, host_e2e, live, or combinations."
        ),
        scanner_issue_codes=(
            "missing_acceptance_suite",
            "missing_required_live_suite",
        ),
        total_scope="all_connectors",
        scanner_backing="partial",
        evidence_command=(
            "bash scripts/ci/test_coverage_scan.sh --only connectors --check "
            "acceptance --json-out <scan.json>"
        ),
        notes=(
            "Scanner verifies acceptance presence and live-tier requirements; it "
            "does not yet emit a complete archetype-by-connector clause map."
        ),
    ),
    MatrixRowSpec(
        row_id="V3-6E-HOST-E2E-SHOULD-RISKY",
        section="6e",
        level="SHOULD",
        requirement=(
            "Auth-heavy or risky/dangerous request-response connectors should add "
            "host_e2e proof in addition to their minimum acceptance class."
        ),
        scanner_issue_codes=(),
        total_scope="auth_or_risky_connectors",
        scanner_backing="no",
        evidence_command=(
            "future scanner enhancement: join manifest risk/auth metadata with "
            "suite_counts.host_e2e"
        ),
        notes=(
            "Section 6e contains this SHOULD, but the current scanner does not "
            "classify auth-heavy or risky/dangerous connectors for this row."
        ),
    ),
    MatrixRowSpec(
        row_id="V3-6F-LIVE-EXCEPTIONS",
        section="6f",
        level="MUST",
        requirement=(
            "When local non-mock is impossible, the connector provides "
            "deterministic_contract, host_e2e when expected, live sandbox/device "
            "coverage, and README replay guidance."
        ),
        scanner_issue_codes=(
            "missing_required_live_suite",
            "live_suite_missing_env_gate",
        ),
        total_scope="live_required_connectors",
        scanner_backing="partial",
        evidence_command=(
            "bash scripts/ci/test_coverage_scan.sh --only connectors --check "
            "acceptance --json-out <scan.json>"
        ),
        notes=(
            "Scanner-backed for required live suite presence and live gate naming; "
            "README replay guidance and host_e2e expectation still need separate proof."
        ),
    ),
    MatrixRowSpec(
        row_id="V3-6G-E2E-LOGGING-REDACTION-REPLAY",
        section="6g",
        level="MUST",
        requirement=(
            "Every local_non_mock, host_e2e, and live suite emits schema-valid "
            "JSONL, suite class, replay artifacts, provenance, and redaction-safe logs."
        ),
        scanner_issue_codes=("live_suite_missing_env_gate",),
        total_scope="acceptance_suite_connectors",
        scanner_backing="partial",
        evidence_command=(
            "bash scripts/ci/validate_e2e_artifacts.sh <artifact-root> and "
            "connector-specific replay bundle checks"
        ),
        notes=(
            "The scanner only detects one live-gate class of issue. Full JSONL, "
            "replay, and redaction validation remains unverified by this matrix."
        ),
        weak_presence_only=True,
    ),
    MatrixRowSpec(
        row_id="V3-6H-CONFORMANCE-SUITES",
        section="6h",
        level="MUST",
        requirement=(
            "ComplianceSuite and ConnectorSuite cover default-deny enforcement, "
            "capability mismatch rejection, introspection operation count, and "
            "manifest extractability."
        ),
        scanner_issue_codes=(),
        total_scope="all_connectors",
        scanner_backing="no",
        evidence_command=(
            "rch exec -- cargo test -p fcp-conformance --test <relevant-suite> "
            "-- --nocapture"
        ),
        notes="Requires fcp-conformance/fcp-e2e proof, not just coverage scanner output.",
    ),
    MatrixRowSpec(
        row_id="V3-6I-QUALITY-GATES",
        section="6i",
        level="MUST",
        requirement=(
            "Required cargo fmt, connector tests, and clippy quality gates pass "
            "for touched connectors."
        ),
        scanner_issue_codes=(),
        total_scope="touched_connectors",
        scanner_backing="no",
        evidence_command=(
            "rch exec -- cargo fmt -p <connector> -- --check; "
            "rch exec -- cargo test -p <connector>; "
            "rch exec -- cargo clippy -p <connector> --all-targets -- -D warnings"
        ),
        notes=(
            "This row is per-change proof. It is intentionally not inferred from "
            "the repository-wide coverage scanner."
        ),
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-json", required=True, type=Path)
    parser.add_argument("--json-out", required=True, type=Path)
    parser.add_argument("--markdown-out", required=True, type=Path)
    parser.add_argument(
        "--baseline-note",
        default=(
            "Supersedes the off-repo 2026-05-11 draft artifacts recorded on "
            "flywheel_connectors-iqw2n creation: "
            "/Volumes/USB_NVME/flywheel_connectors-v3-section6-coverage-matrix-20260511.*"
        ),
    )
    return parser.parse_args()


def load_scan(path: Path) -> dict[str, Any]:
    try:
        data = json.JSONDecoder().decode(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(f"{path} is not valid JSON: {error}") from error
    if data.get("$schema") != "fcp-test-coverage-scan-v1":
        raise SystemExit(f"{path} is not fcp-test-coverage-scan-v1 JSON")
    if not isinstance(data.get("connectors"), list):
        raise SystemExit(f"{path} does not contain a connectors array")
    return data


def connector_issue_codes(connector: dict[str, Any]) -> set[str]:
    return {
        issue.get("code", "")
        for issue in connector.get("issues", [])
        if issue.get("code")
    }


def connectors_for_scope(connectors: list[dict[str, Any]], scope: str) -> list[dict[str, Any]]:
    if scope == "all_connectors":
        return connectors
    if scope == "live_required_connectors":
        return [connector for connector in connectors if connector.get("requires_live_suite")]
    if scope == "acceptance_suite_connectors":
        return [connector for connector in connectors if connector.get("has_acceptance_suite")]
    if scope in {"auth_or_risky_connectors", "touched_connectors"}:
        return []
    raise ValueError(f"unknown scope {scope}")


def score_status(level: str, score: float | None, weak: bool, backing: str) -> str:
    if score is None:
        return "unverified" if backing in {"no", "partial"} else "not_evaluated"
    if level == "MUST" and score < MUST_THRESHOLD:
        return "not_conformant"
    if weak:
        return "scanner_pass_weak"
    return "conformant"


def build_row(spec: MatrixRowSpec, connectors: list[dict[str, Any]]) -> dict[str, Any]:
    scoped = connectors_for_scope(connectors, spec.total_scope)

    affected = []
    active_issue_codes: set[str] = set()
    if spec.scanner_issue_codes:
        code_set = set(spec.scanner_issue_codes)
        for connector in scoped:
            connector_codes = connector_issue_codes(connector) & code_set
            if connector_codes:
                affected.append(connector["id"])
                active_issue_codes.update(connector_codes)
    affected = sorted(set(affected))

    if spec.scanner_backing == "no" or not scoped:
        tested_count = 0
        passing_count = None
        divergent_count = None
        score = None
    else:
        tested_count = len(scoped)
        divergent_count = len(affected)
        passing_count = max(len(scoped) - divergent_count, 0)
        score = passing_count / len(scoped) if scoped else None

    return {
        "id": spec.row_id,
        "section": spec.section,
        "level": spec.level,
        "requirement": spec.requirement,
        "scanner_issue_codes": list(spec.scanner_issue_codes),
        "active_scanner_issue_codes": sorted(active_issue_codes),
        "scanner_backing": spec.scanner_backing,
        "total_scope": spec.total_scope,
        "total_count": len(scoped) if scoped else None,
        "tested_count": tested_count,
        "passing_count": passing_count,
        "divergent_count": divergent_count,
        "score": round(score, 6) if score is not None else None,
        "status": score_status(spec.level, score, spec.weak_presence_only, spec.scanner_backing),
        "affected_connectors": affected,
        "affected_connector_count": len(affected),
        "sample_affected_connectors": affected[:25],
        "evidence_command": spec.evidence_command,
        "notes": spec.notes,
    }


def issue_count_map(scan: dict[str, Any]) -> dict[str, int]:
    counts = scan.get("summary", {}).get("connectors", {}).get("issue_counts", [])
    return {entry["code"]: entry["count"] for entry in counts}


def build_matrix(scan: dict[str, Any], scan_path: Path, baseline_note: str) -> dict[str, Any]:
    connectors = scan["connectors"]
    rows = [build_row(spec, connectors) for spec in ROW_SPECS]
    must_rows = [row for row in rows if row["level"] == "MUST"]
    should_rows = [row for row in rows if row["level"] == "SHOULD"]
    must_scored = [row for row in must_rows if row["score"] is not None]
    must_not_conformant = [
        row
        for row in must_rows
        if row["score"] is None or row["score"] < MUST_THRESHOLD
    ]
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    return {
        "$schema": "fcp-v3-section6-acceptance-matrix-v1",
        "generated_at": generated_at,
        "source": {
            "scan_json": str(scan_path),
            "scan_generated_at": scan.get("generated_at"),
            "scan_config": scan.get("config", {}),
            "scan_sources": scan.get("sources", {}),
            "scanner_command": (
                "bash scripts/ci/test_coverage_scan.sh --only connectors "
                "--json-out /tmp/fcp-section6-scan.json "
                "--summary-out /tmp/fcp-section6-scan.txt"
            ),
            "matrix_command": (
                "python3 scripts/ci/v3_section6_acceptance_matrix.py "
                "--scan-json /tmp/fcp-section6-scan.json "
                "--json-out docs/testing/v3-section6-acceptance-coverage-matrix.json "
                "--markdown-out docs/testing/v3-section6-acceptance-coverage-matrix.md"
            ),
            "baseline_note": baseline_note,
        },
        "thresholds": {
            "must_score_threshold": MUST_THRESHOLD,
            "null_must_score_means": "unverified_not_conformant",
        },
        "scanner_summary": scan.get("summary", {}).get("connectors", {}),
        "issue_counts": issue_count_map(scan),
        "rows": rows,
        "overall": {
            "must_clause_rows": len(must_rows),
            "should_clause_rows": len(should_rows),
            "scored_must_rows": len(must_scored),
            "must_rows_below_threshold_or_unverified": len(must_not_conformant),
            "conclusion": "conformant" if not must_not_conformant else "not_conformant",
        },
    }


def markdown_table(rows: list[dict[str, Any]]) -> str:
    lines = [
        "| ID | Section | Level | Backing | Tested | Passing | Divergent | Score | Status | Primary Gap |",
        "| --- | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for row in rows:
        score = "n/a" if row["score"] is None else f"{row['score']:.3f}"
        passing = "n/a" if row["passing_count"] is None else str(row["passing_count"])
        divergent = "n/a" if row["divergent_count"] is None else str(row["divergent_count"])
        primary_gap = ", ".join(row["active_scanner_issue_codes"])
        if not primary_gap:
            primary_gap = (
                "requires separate proof"
                if not row["scanner_issue_codes"] or row["scanner_backing"] == "no"
                else "none"
            )
        lines.append(
            "| `{id}` | {section} | {level} | {backing} | {tested} | {passing} | "
            "{divergent} | {score} | {status} | {gap} |".format(
                id=row["id"],
                section=row["section"],
                level=row["level"],
                backing=row["scanner_backing"],
                tested=row["tested_count"],
                passing=passing,
                divergent=divergent,
                score=score,
                status=row["status"],
                gap=primary_gap,
            )
        )
    return "\n".join(lines)


def render_markdown(matrix: dict[str, Any]) -> str:
    summary = matrix["scanner_summary"]
    issue_counts = matrix["issue_counts"]
    rows = matrix["rows"]

    issue_lines = [
        "| Issue Code | Count |",
        "| --- | ---: |",
    ]
    for code, count in sorted(issue_counts.items(), key=lambda item: (-item[1], item[0])):
        issue_lines.append(f"| `{code}` | {count} |")

    row_details = []
    for row in rows:
        affected = row["sample_affected_connectors"]
        affected_text = ", ".join(f"`{item}`" for item in affected) if affected else "none"
        if row["affected_connector_count"] > len(affected):
            remaining = row["affected_connector_count"] - len(affected)
            affected_text += f", ... plus {remaining} more"
        row_details.append(
            "\n".join(
                [
                    f"### `{row['id']}`",
                    "",
                    row["requirement"],
                    "",
                    f"- Status: `{row['status']}`",
                    f"- Evidence command: `{row['evidence_command']}`",
                    f"- Affected connectors ({row['affected_connector_count']}): {affected_text}",
                    f"- Notes: {row['notes']}",
                ]
            )
        )

    return "\n".join(
        [
            "# V3 Section 6 Acceptance Coverage Matrix",
            "",
            "<!-- Generated by scripts/ci/v3_section6_acceptance_matrix.py. -->",
            "",
            f"Generated: `{matrix['generated_at']}`",
            "",
            "This report maps `docs/V3_Connector_Acceptance_Contract.md` Section 6 "
            "MUST/SHOULD rows to the current connector coverage scanner output.",
            "",
            "Scores below `0.95` for MUST rows are non-conformant. A null score is "
            "not proof of success; it means the current scanner does not cover that row.",
            "",
            "## Regeneration",
            "",
            "```bash",
            matrix["source"]["scanner_command"],
            matrix["source"]["matrix_command"],
            "```",
            "",
            "Primary outputs:",
            "",
            "- `docs/testing/v3-section6-acceptance-coverage-matrix.json`",
            "- `docs/testing/v3-section6-acceptance-coverage-matrix.md`",
            "",
            f"Baseline note: {matrix['source']['baseline_note']}",
            "",
            "## Scanner Summary",
            "",
            "| Metric | Count |",
            "| --- | ---: |",
            f"| Total connectors | {summary.get('total', 0)} |",
            f"| Failing entities | {summary.get('failing_entities', 0)} |",
            f"| Clean pure-unit signal | {summary.get('with_clean_pure_unit_signal', 0)} |",
            f"| Meeting pure-unit floor | {summary.get('meeting_pure_unit_floor', 0)} |",
            f"| Source mock leakage | {summary.get('with_src_mock_leakage', 0)} |",
            f"| Deterministic contract present | {summary.get('with_deterministic_contract', 0)} |",
            f"| Acceptance suite present | {summary.get('with_acceptance_suite', 0)} |",
            f"| Requiring live suite | {summary.get('requiring_live_suite', 0)} |",
            f"| Required live suite present | {summary.get('with_required_live_suite', 0)} |",
            "",
            "## Issue Counts",
            "",
            "\n".join(issue_lines),
            "",
            "## Clause Matrix",
            "",
            markdown_table(rows),
            "",
            "## Overall",
            "",
            f"- MUST rows: {matrix['overall']['must_clause_rows']}",
            f"- SHOULD rows: {matrix['overall']['should_clause_rows']}",
            f"- Scored MUST rows: {matrix['overall']['scored_must_rows']}",
            "- MUST rows below threshold or unverified: "
            f"{matrix['overall']['must_rows_below_threshold_or_unverified']}",
            f"- Conclusion: `{matrix['overall']['conclusion']}`",
            "",
            "## Row Details",
            "",
            "\n\n".join(row_details),
            "",
        ]
    )


def write_outputs(matrix: dict[str, Any], json_out: Path, markdown_out: Path) -> None:
    json_out.parent.mkdir(parents=True, exist_ok=True)
    markdown_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_out.write_text(render_markdown(matrix), encoding="utf-8")


def main() -> None:
    args = parse_args()
    scan = load_scan(args.scan_json)
    matrix = build_matrix(scan, args.scan_json, args.baseline_note)
    write_outputs(matrix, args.json_out, args.markdown_out)


if __name__ == "__main__":
    main()
