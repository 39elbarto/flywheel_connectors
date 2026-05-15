# Proof Bundle Source Inventory

Bead: `flywheel_connectors-8fhsm.1`

This inventory defines the first source set for the proof-bundle registry schema
in `docs/proof-ops/proof_bundle_registry.schema.json` and the typed Rust
contract in `crates/fcp-evidence/src/proof_bundle_registry.rs`.

The registry is a gate input, not a proof claim by itself. A row may be green
only when it has an owning bead, rerun command, expected artifact digests, git
revision, verifier result, and a fresh enough timestamp. Static docs, replay
bundles, offline corpora, and structured skips cannot set `live_claim=true`.

## Source Inventory

| Source id | Kind | Path | Default proof class | Owner | Registry notes |
|-----------|------|------|---------------------|-------|----------------|
| `fcp3-final-proof-manifest` | `final_proof_manifest` | `docs/FCP3_Final_Proof_Manifest.md` | `static_doc` | `flywheel_connectors-8bqme.3` | Represents the final review entry point, proof-section table, consolidated rerun commands, and artifact manifest. It can anchor claims but cannot be live proof without a verifier observation and digested artifacts. |
| `fcp3-operational-proof-index` | `section_proof_index` | `docs/FCP3_Operational_Proof_Index.md` | `static_doc` | `flywheel_connectors-8bqme.2` | Represents one section proof index with row labels, proof anchors, and rerun anchors. It maps cleanly to `source_document.section`, `source_document.row_label`, and `rerun.argv`. |
| `core-platform-evidence-index` | `core_platform_evidence_index` | `docs/testing/core_platform_evidence_index.md` | `offline_static` | `flywheel_connectors-y2mlu` family | Represents platform evidence bundle contracts, including `swarm-evidence-bundle/v1`, required artifact names, source kind, execution mode, revision, worker identity, content digests, and redaction policy. |
| `rollback-drill-bundle-producer` | `e2e_bundle_manifest_producer` | `scripts/e2e/e2e_rollback_drill_consistency.sh` | `replay` | `235t.34.1`, `235t.28.4`, `235t.33.4`, `235t.26.6.4`, `235t.27.4` | Emits `BUNDLE_MANIFEST.json` with `bundle_type=rollback-drill`, required artifacts, dependency evidence, and replay instructions. Live status depends on the concrete run, not the script text. |
| `performance-reliability-bundle-producer` | `e2e_bundle_manifest_producer` | `scripts/e2e/e2e_performance_reliability_gate.sh` | `replay` | `235t.28.2`, `235t.28.3`, `235t.27.4` | Emits `BUNDLE_MANIFEST.json` with `bundle_type=performance-reliability-gate`, required gate artifacts, dependency evidence, and replay instructions. |
| `unified-validation-bundle-producer` | `e2e_bundle_manifest_producer` | `scripts/e2e/e2e_unified_validation_report.sh` | `replay` | `235t.27.4` | Emits `BUNDLE_MANIFEST.json` with `bundle_type=unified-validation`, contents, and triage guide. It represents another producer shape for registry compatibility. |
| `fcp-evidence-proof-graph-indexer` | `fwc_proof_graph_surface` | `crates/fcp-evidence/src/proof_graph_indexer.rs` | `offline_static` | `b88ec.2` | Existing structured corpus for proof graph indexing. The new registry is stricter: it requires per-proof owner, rerun, artifact digest, freshness, and live-claim fields before green proof classification. |

## Required Field Mapping

| Registry field | Final proof manifest | Operational proof index | E2E bundle producers |
|----------------|----------------------|-------------------------|----------------------|
| `proof_id` | Derived from proof-section row, for example `fcp3.operational.indexed`. | Derived from proof table row, for example `fcp3.operational.deployment-runbook`. | Derived from bundle type and scenario, for example `e2e.rollback-drill.bundle`. |
| `owning_bead` | Source bead column or manifest bead header. | Bead / proof anchors column. | `dependency_evidence` keys plus the supervising bead for the producer. |
| `claim_text` | Reviewer question or artifact role. | Reviewer question. | Bundle verdict or gate purpose. |
| `source_document` | Document path, section name, table row label, line hint when known. | Document path, `Operational Proof Table`, row label. | Script path, bundle manifest phase, artifact name. |
| `rerun` | Consolidated command from the manifest. | Rerun anchors column. | `replay_instructions.full_*` or direct script invocation. |
| `expected_artifacts` | Artifact manifest rows plus the manifest document itself. | Primary surfaces and test artifacts named by the row. | `artifacts` or `contents` entries from `BUNDLE_MANIFEST.json`. |
| `artifact.digest` | Required for required artifacts after registry materialization. | Required for required artifacts after registry materialization. | Required for required artifacts after bundle capture. |
| `git_revision_under_test` | Captured from the materializing run. | Captured from the materializing run. | Captured from bundle environment or materializing run. |
| `freshness_policy` | Static review rows should normally be `warn_only` unless promoted to a required gate. | Required operational rows should be `fail_closed` when part of a release gate. | Live/host-backed gates should be `fail_closed`; replay-only bundles can be `warn_only` or `skip_only`. |
| `verifier` | Static row verifier command and result. | Static or Cargo-backed verifier command and result. | Bundle validator command, result, log path, and `live_claim=false` unless the run records live evidence. |
| `structured_skip` | Present only when the row is an explicit structured skip. | Present only when the row is an explicit structured skip. | Present when a sub-gate emits a structured skip record. |

## Representation Checks

The initial schema and Rust contract can represent these existing sources
without lossy ad hoc fields:

- Final manifest row: `docs/FCP3_Final_Proof_Manifest.md` -> `Proof Sections` -> `Operational`.
- Section proof row: `docs/FCP3_Operational_Proof_Index.md` -> `Operational Proof Table` -> `Truthful replay bundle contract`.
- E2E producer: `scripts/e2e/e2e_rollback_drill_consistency.sh` -> `BUNDLE_MANIFEST.json` -> required rollback drill artifacts.
- E2E producer: `scripts/e2e/e2e_performance_reliability_gate.sh` -> `BUNDLE_MANIFEST.json` -> required performance reliability artifacts.
- E2E producer: `scripts/e2e/e2e_unified_validation_report.sh` -> `BUNDLE_MANIFEST.json` -> unified validation contents.

## Non-Claims

- This inventory does not mark any proof row green.
- Static docs and replay-only bundles are never promoted to live proof by this
  inventory.
- Missing artifact digests are a registry validation failure for required
  artifacts.
- Stale required proofs with `stale_action=fail_closed` are validation failures.
