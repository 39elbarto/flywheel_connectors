//! Debugging, replay, and observability field guide documentation contract (bead 21.4).
//!
//! Encodes debugging techniques, replay guides, and observability checks as
//! testable structures so that the debugging documentation stays accurate.

use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

/// A debugging technique with step-by-step instructions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DebugTechnique {
    /// Name of the technique.
    pub name: String,
    /// What this technique does.
    pub description: String,
    /// When to use this technique.
    pub when_to_use: String,
    /// Commands to run (in order).
    pub commands: Vec<String>,
    /// Tips for effective use.
    pub tips: Vec<String>,
    /// Related techniques that complement this one.
    pub related_techniques: Vec<String>,
}

/// A guide for replaying historical invocations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayGuide {
    /// Name of the replay scenario.
    pub name: String,
    /// What this replay guide covers.
    pub description: String,
    /// Steps to set up for replay.
    pub setup_steps: Vec<String>,
    /// The replay command to execute.
    pub replay_command: String,
    /// Steps to verify the replay result.
    pub verification_steps: Vec<String>,
}

/// An observability check for monitoring system health.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObservabilityCheck {
    /// Name of the check.
    pub name: String,
    /// What this check examines.
    pub what_to_check: String,
    /// The command to run.
    pub command: String,
    /// What the output should look like when healthy.
    pub expected_output: String,
    /// What to do if the check fails.
    pub failure_action: String,
}

/// One artifact-bundle file or section worth checking during incident response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArtifactSection {
    /// Human-readable section name.
    pub name: String,
    /// Relative path or logical path inside the bundle.
    pub path: String,
    /// Why this section exists.
    pub purpose: String,
    /// IDs or join keys surfaced here.
    pub identifiers: Vec<String>,
    /// Questions this section answers fastest.
    pub fastest_answers: Vec<String>,
    /// Follow-up commands that usually accompany this section.
    pub follow_up_commands: Vec<String>,
    /// Real local files or docs that anchor this section.
    pub references: Vec<String>,
}

/// A common failure class and how to debug it quickly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureClassGuide {
    /// Machine-readable or incident-friendly name.
    pub name: String,
    /// Symptom summary.
    pub symptoms: String,
    /// Bundle sections to inspect first.
    pub artifact_sections: Vec<String>,
    /// High-signal follow-up commands.
    pub first_commands: Vec<String>,
    /// Likely causes seen in this codebase.
    pub likely_causes: Vec<String>,
    /// Recovery guidance once the cause is confirmed.
    pub recovery_guidance: String,
}

/// How to extend the debugging contract when a new bug is found.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtensionGuide {
    /// Short title for the extension workflow.
    pub name: String,
    /// When this extension is warranted.
    pub when_to_add: String,
    /// Primary source files to edit.
    pub source_files: Vec<String>,
    /// Ordered implementation steps.
    pub steps: Vec<String>,
    /// Verification commands, including offloaded cargo checks.
    pub verification_commands: Vec<String>,
    /// Existing docs or fixtures that should stay aligned.
    pub references: Vec<String>,
}

/// Complete field guide combining all debugging resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldGuide {
    /// Debugging techniques.
    pub techniques: Vec<DebugTechnique>,
    /// Replay guides.
    pub replay_guides: Vec<ReplayGuide>,
    /// Observability checks.
    pub observability_checks: Vec<ObservabilityCheck>,
    /// Truthfulness boundaries that affect how artifacts should be interpreted.
    pub truthfulness_boundaries: Vec<String>,
    /// Artifact-bundle anatomy.
    pub artifact_sections: Vec<ArtifactSection>,
    /// Common failure classes mapped to artifact sections and commands.
    pub failure_classes: Vec<FailureClassGuide>,
    /// Guidance for adding new scenarios or confusion cases later.
    pub extension_guides: Vec<ExtensionGuide>,
}

// ── Data ─────────────────────────────────────────────────────────────────────

/// Returns at least 10 debugging techniques.
#[must_use]
pub fn get_debug_techniques() -> Vec<DebugTechnique> {
    vec![
        DebugTechnique {
            name: "Artifact Bundle Triage".into(),
            description:
                "Start with the bundle manifest files (`summary.json`, `trace.jsonl`, `environment.json`) before guessing at the cause."
                    .into(),
            when_to_use:
                "When a scenario, replay, or host-backed run failed and you need the fastest path to reproducible context."
                    .into(),
            commands: vec![
                "jq '.' artifacts/e2e/workflow/replayable_failure/summary.json".into(),
                "jq -c '.' artifacts/e2e/workflow/replayable_failure/trace.jsonl".into(),
                "jq '.' artifacts/e2e/workflow/replayable_failure/environment.json".into(),
                "jq '{scenario_id, run_id, transport, outcome, summary}' artifacts/e2e/workflow/replayable_failure/session_transcript.json".into(),
            ],
            tips: vec![
                "Use `summary.json` first when you need counts, join keys, or availability states.".into(),
                "Drop into `trace.jsonl` only after you know which phase or request id is suspicious."
                    .into(),
                "Use `session_transcript.json` when reconnect, duplicate-delivery, or per-step lifecycle ordering is the real question.".into(),
                "Treat `environment.json` as the replay context, not as live truth about the current host."
                    .into(),
            ],
            related_techniques: vec![
                "Trace Bundle Replay".into(),
                "Health and Truthfulness Summary Review".into(),
            ],
        },
        DebugTechnique {
            name: "Trace Bundle Replay".into(),
            description:
                "Re-run a captured trace file through the deterministic trace replay engine to compare expected vs actual routing decisions."
                    .into(),
            when_to_use:
                "When `trace.jsonl` exists and you need to verify whether the regression is in routing, decision logic, or fixture setup."
                    .into(),
            commands: vec![
                "fwc trace replay artifacts/e2e/workflow/replayable_failure/trace.jsonl --json"
                    .into(),
                "jq '.truthfulness | {phases, host_request_ids, receipt_ids}' artifacts/e2e/workflow/replayable_failure/summary.json".into(),
            ],
            tips: vec![
                "`fwc trace replay` is file-based and deterministic; use it to separate live-host drift from captured-decision drift.".into(),
                "Compare mismatched decisions with `summary.json` receipt ids to see whether the host ever acknowledged the step."
                    .into(),
                "If replay matches but the live run failed, the bug is probably outside the captured decision path."
                    .into(),
            ],
            related_techniques: vec![
                "Artifact Bundle Triage".into(),
                "Event Stream Cursor Resume".into(),
            ],
        },
        DebugTechnique {
            name: "Event Stream Cursor Resume".into(),
            description:
                "Use host-backed `tail` and `watch` with explicit `--cursor`, `--since`, and `--event-type` filters to isolate the precise live transition you care about."
                    .into(),
            when_to_use:
                "When diagnosing long-running operations, reconnect behavior, or cursor-resume bugs in live host streams."
                    .into(),
            commands: vec![
                "fwc tail github --host http://127.0.0.1:8787 --since 15m --event-type health-check --json".into(),
                "fwc tail github --host http://127.0.0.1:8787 --cursor <CURSOR> --event-type health-check --json".into(),
                "fwc watch <REQUEST_ID> --host http://127.0.0.1:8787 --json".into(),
            ],
            tips: vec![
                "Use `--cursor` only when you want resume semantics to be explicit in the payload."
                    .into(),
                "Pair `tail` with `watch` so you can correlate stream events with terminal request status."
                    .into(),
                "Expect live-host commands to report `live-runtime`; if you see `offline-artifact`, you are debugging the wrong surface."
                    .into(),
            ],
            related_techniques: vec![
                "Trace Bundle Replay".into(),
                "Session Resume Recovery".into(),
            ],
        },
        DebugTechnique {
            name: "Schema vs Template Drift".into(),
            description:
                "Compare the live or offline schema with generated templates and rendered output before blaming the invocation path."
                    .into(),
            when_to_use:
                "When validation fails, template rendering breaks, or a payload that used to work now needs different fields."
                    .into(),
            commands: vec![
                "fwc schema github issues.create --json".into(),
                "fwc template github issues.create --offline --json".into(),
                "fwc show github --template '{{json connector}}'".into(),
            ],
            tips: vec![
                "Use `--offline` on `template` when you need the workspace-manifest contract rather than host inventory."
                    .into(),
                "If template rendering fails, fall back to raw `--json` output and inspect the exact field names."
                    .into(),
                "Treat schema drift and template drift as separate problems; one is contract shape, the other is post-processing."
                    .into(),
            ],
            related_techniques: vec![
                "History Replay Planning".into(),
                "Pinned Context and Profile Drift".into(),
            ],
        },
        DebugTechnique {
            name: "Health and Truthfulness Summary Review".into(),
            description:
                "Read connector health together with bundle truthfulness summaries so you know whether a failure came from the current host or only from captured artifacts."
                    .into(),
            when_to_use:
                "When the system looks degraded but it is unclear whether the evidence is live, offline, planned, or denied."
                    .into(),
            commands: vec![
                "fwc health --json".into(),
                "fwc doctor --json".into(),
                "jq '.truthfulness.command_availabilities' artifacts/e2e/workflow/replayable_failure/summary.json".into(),
            ],
            tips: vec![
                "Look at availability tags before interpreting any artifact as current truth."
                    .into(),
                "Use `doctor` when health is ambiguous; it already emits recovery-oriented output."
                    .into(),
                "A healthy live host does not invalidate a failing replay bundle; it only narrows the blast radius."
                    .into(),
            ],
            related_techniques: vec![
                "Artifact Bundle Triage".into(),
                "Credential Status and Redaction Audit".into(),
            ],
        },
        DebugTechnique {
            name: "History Replay Planning".into(),
            description:
                "Convert one history entry into a dry-run replay plan before you attempt a live re-execution."
                    .into(),
            when_to_use:
                "When you need to confirm which input was stored, which overrides are safe, or whether replay data has already expired."
                    .into(),
            commands: vec![
                "fwc history --connector github --limit 5 --json".into(),
                "fwc replay <ENTRY_ID> --dry-run --json".into(),
                "fwc replay <ENTRY_ID> --dry-run --set config.timeout=120 --json".into(),
            ],
            tips: vec![
                "Always start with `--dry-run` when the original operation could have side effects."
                    .into(),
                "Use nested `--set` overrides to prove whether a fix is only configuration drift."
                    .into(),
                "If replay returns `input_expired` or `input_not_stored`, move back to history and rebuild context from the artifact trail."
                    .into(),
            ],
            related_techniques: vec![
                "Schema vs Template Drift".into(),
                "Session Resume Recovery".into(),
            ],
        },
        DebugTechnique {
            name: "Credential Status and Redaction Audit".into(),
            description:
                "Check credential expiry and verify that captured evidence keeps secrets redacted while still exposing enough identifiers to debug."
                    .into(),
            when_to_use:
                "When authentication breaks, tokens might be stale, or a bundle appears to have leaked sensitive values."
                    .into(),
            commands: vec![
                "fwc auth status github --json".into(),
                "fwc auth show github --json".into(),
                "rg -n '\\[REDACTED:sha256:' artifacts/e2e/workflow/replayable_failure".into(),
            ],
            tips: vec![
                "Redaction should preserve correlation through digests without exposing raw secrets."
                    .into(),
                "Inspect the credential store through `auth show` rather than searching raw state files."
                    .into(),
                "If a secret appears unredacted in a bundle, treat it as a contract regression and add a targeted `test_observability` case."
                    .into(),
            ],
            related_techniques: vec![
                "Health and Truthfulness Summary Review".into(),
                "Confusion Corpus Backtrace".into(),
            ],
        },
        DebugTechnique {
            name: "Network Policy Explanation".into(),
            description:
                "Use the network policy explainer to prove whether a failure is sandbox policy, DNS/TLS, or upstream service behavior."
                    .into(),
            when_to_use:
                "When host-backed work cannot reach an upstream endpoint and you need a deterministic allow/deny explanation."
                    .into(),
            commands: vec![
                "fwc net explain --url https://api.github.com/repos/octocat/hello-world/issues --manifest-path manifest.toml --operation issues.create --json".into(),
                "fwc guide --command net --json".into(),
            ],
            tips: vec![
                "Prefer `net explain` over guessing from timeout strings; it tells you which rule or constraint decided the outcome."
                    .into(),
                "If the manifest path is wrong, fix that first; a bad manifest path is not evidence of an egress policy bug."
                    .into(),
                "Keep network policy debugging separate from auth debugging so error ownership stays clear."
                    .into(),
            ],
            related_techniques: vec![
                "Health and Truthfulness Summary Review".into(),
                "Trace Bundle Replay".into(),
            ],
        },
        DebugTechnique {
            name: "Session Resume Recovery".into(),
            description:
                "Recover interrupted work by inspecting persisted agent session state rather than recreating context from memory."
                    .into(),
            when_to_use:
                "When an agent handoff happened mid-flight, a resumable workflow stopped, or the caller says 'continue where we left off'."
                    .into(),
            commands: vec![
                "fwc session list --status paused --json".into(),
                "fwc session show --json".into(),
                "fwc session resume <SESSION_ID> --json".into(),
            ],
            tips: vec![
                "Treat resume as a state-inspection workflow, not as a magical 'continue' button."
                    .into(),
                "Use the persisted session payload to recover goal, zone, and arbitrary context before reissuing commands."
                    .into(),
                "If no paused session exists, move to the history/task surfaces instead of inventing one."
                    .into(),
            ],
            related_techniques: vec![
                "History Replay Planning".into(),
                "Pinned Context and Profile Drift".into(),
            ],
        },
        DebugTechnique {
            name: "Pinned Context and Profile Drift".into(),
            description:
                "Verify the active host context and connector profile before assuming the same command will hit the same target as yesterday."
                    .into(),
            when_to_use:
                "When a replay or workflow suddenly targets the wrong connector, wrong zone, or wrong config profile."
                    .into(),
            commands: vec![
                "fwc context current --json".into(),
                "fwc config get github --json".into(),
                "fwc config doctor github --json".into(),
            ],
            tips: vec![
                "Wrong pinned context is a confusion category in this codebase; debug it explicitly instead of accepting hidden ambient state."
                    .into(),
                "Config profile drift is different from credential failure; inspect both if the output shape and auth symptoms disagree."
                    .into(),
                "Use `context current` first so you do not misread a connector-local config as a global system failure."
                    .into(),
            ],
            related_techniques: vec![
                "Session Resume Recovery".into(),
                "Schema vs Template Drift".into(),
            ],
        },
        DebugTechnique {
            name: "Confusion Corpus Backtrace".into(),
            description:
                "Use the confusion corpus and observability contract tests when the bug is really about misleading guidance, stale-context assumptions, or missing recovery hints."
                    .into(),
            when_to_use:
                "When the failure is not a connector bug but a workflow-debugging regression in how `fwc` explains or resumes work."
                    .into(),
            commands: vec![
                "rch exec -- cargo test -p fwc confusion_workflow -- --nocapture".into(),
                "rch exec -- cargo test -p fwc test_observability::full_workflow_replay_round_trip -- --exact --nocapture".into(),
                "jq '.' crates/fwc/testdata/golden/setup_repair.json".into(),
            ],
            tips: vec![
                "If the broken behavior is really about guidance or recovery, add a corpus case instead of bolting on more prose."
                    .into(),
                "Replayable bug reports should usually leave behind both a targeted test and a doc example."
                    .into(),
                "Use `rch exec -- ...` for cargo-based verification so debugging docs model the same workflow we expect from agents."
                    .into(),
            ],
            related_techniques: vec![
                "Credential Status and Redaction Audit".into(),
                "Artifact Bundle Triage".into(),
            ],
        },
    ]
}

/// Truthfulness boundaries that determine how to interpret artifacts.
#[must_use]
pub fn get_truthfulness_boundaries() -> Vec<String> {
    vec![
        "live-runtime: authoritative host-backed state; use this for current health, current placement, and live event conclusions.".into(),
        "offline-artifact: local manifests, cached history, or fixture data; good for planning and forensics, but not proof of current host state.".into(),
        "planned: guide or preview output only; useful for expected shape, never as evidence that the runtime path exists.".into(),
        "unsupported/denied/unknown: treat these as recovery surfaces with explicit next actions instead of silent failure or ambient fallback.".into(),
        "stale-context and wrong-pinned-context are first-class debugging categories; inspect persisted context before retrying a workflow.".into(),
    ]
}

/// Returns at least 5 replay guides.
#[must_use]
pub fn get_replay_guides() -> Vec<ReplayGuide> {
    vec![
        ReplayGuide {
            name: "History Dry-Run Replay".into(),
            description:
                "Build a replay plan from a stored history entry without re-executing the original side effects."
                    .into(),
            setup_steps: vec![
                "Find the candidate entry: `fwc history --connector github --limit 5 --json`."
                    .into(),
                "Inspect whether the original command was live, offline, or planned from the surrounding artifact summary."
                    .into(),
            ],
            replay_command: "fwc replay <ENTRY_ID> --dry-run --json".into(),
            verification_steps: vec![
                "Confirm the plan surfaces `connector_id`, `operation_id`, and `effective_input`."
                    .into(),
                "Verify no live side effects occurred because `--dry-run` was used.".into(),
            ],
        },
        ReplayGuide {
            name: "Nested Override Replay".into(),
            description:
                "Use dot-path overrides to prove whether a failure is caused by one stale field or profile-derived default."
                    .into(),
            setup_steps: vec![
                "Start from a replayable entry with stored input: `fwc history --connector github --limit 5 --json`."
                    .into(),
                "Identify which nested fields you want to replace before re-running the command."
                    .into(),
                "Prefer `--dry-run` until you have inspected the merged effective input.".into(),
            ],
            replay_command:
                "fwc replay <ENTRY_ID> --dry-run --set config.timeout=60 --set labels='[\"p1\"]' --json"
                    .into(),
            verification_steps: vec![
                "Check `overrides_applied` so the replay plan matches the fields you intended to change."
                    .into(),
                "Confirm the resulting `effective_input` contains the merged nested values."
                    .into(),
                "Only switch to a live replay after the dry-run payload looks exactly right.".into(),
            ],
        },
        ReplayGuide {
            name: "Expired Input Recovery".into(),
            description:
                "Handle `input_expired` or `input_not_stored` without pretending the original payload is still available."
                    .into(),
            setup_steps: vec![
                "Attempt the replay directly so you know whether the stored input still exists."
                    .into(),
                "Keep the original entry id handy for cross-checking the history record.".into(),
                "Treat missing replay input as a state-reconstruction task, not as a reason to guess."
                    .into(),
            ],
            replay_command: "fwc replay <ENTRY_ID> --json".into(),
            verification_steps: vec![
                "If the error is `input_expired`, inspect the entry detail and captured environment before reproducing manually."
                    .into(),
                "If the error is `input_not_stored`, rebuild the payload from schema, templates, and history summaries."
                    .into(),
                "Do not mark the issue fixed until the new reproduction path is captured in artifacts or tests."
                    .into(),
            ],
        },
        ReplayGuide {
            name: "Trace Artifact Replay".into(),
            description:
                "Re-run a captured trace file through the replay engine to isolate decision mismatches without touching the live host."
                    .into(),
            setup_steps: vec![
                "Locate the artifact bundle that contains the suspicious `trace.jsonl` file."
                    .into(),
                "Inspect `summary.json` first so you know which phases and host ids were captured."
                    .into(),
                "Keep the replay local until the trace diff is understood.".into(),
            ],
            replay_command:
                "fwc trace replay artifacts/e2e/workflow/replayable_failure/trace.jsonl --json"
                    .into(),
            verification_steps: vec![
                "Confirm whether mismatched events or mismatched decisions are non-zero.".into(),
                "Join the replay report back to `summary.json` host and receipt ids before escalating to live-host debugging."
                    .into(),
                "If replay is clean but production still fails, move to live tail/watch rather than re-debugging the bundle."
                    .into(),
            ],
        },
        ReplayGuide {
            name: "Artifact Script Rerun".into(),
            description:
                "Use the captured `replay.sh` script when you want the exact working directory, environment, and runner prefix preserved."
                    .into(),
            setup_steps: vec![
                "Inspect `environment.json` so you understand which env vars were captured and redacted."
                    .into(),
                "Read the notes in `replay.sh`; cargo-backed scripts should already stay behind `rch exec -- ...`."
                    .into(),
                "Check out the recorded git SHA first if the script expects a historical revision.".into(),
            ],
            replay_command: "bash artifacts/e2e/workflow/replayable_failure/replay.sh".into(),
            verification_steps: vec![
                "Verify the replay script starts from the captured working directory.".into(),
                "Confirm the rerun still reports the same trace id or scenario family in its notes."
                    .into(),
                "If the script diverges, compare the current environment with the captured `environment.json`."
                    .into(),
            ],
        },
        ReplayGuide {
            name: "Cargo-backed Contract Rerun".into(),
            description:
                "Reproduce the debugging contract itself through targeted tests when the artifact or replay pipeline regresses."
                    .into(),
            setup_steps: vec![
                "Pick the narrowest regression test that matches the failure class.".into(),
                "Keep the worktree on the relevant revision if the bundle captured a git SHA.".into(),
                "Offload compute-heavy cargo work with `rch exec -- ...`.".into(),
            ],
            replay_command:
                "rch exec -- cargo test -p fwc test_observability::full_workflow_replay_round_trip -- --exact --nocapture"
                    .into(),
            verification_steps: vec![
                "Confirm the targeted regression still reproduces before widening the test scope."
                    .into(),
                "If you add a new case, keep the command in `rch exec -- ...` form so the docs model the required build discipline."
                    .into(),
                "Update nearby fixtures or guide examples if the test changes the observable artifact contract."
                    .into(),
            ],
        },
    ]
}

/// Returns at least 8 observability checks.
#[must_use]
pub fn get_observability_checks() -> Vec<ObservabilityCheck> {
    vec![
        ObservabilityCheck {
            name: "Truthfulness Summary".into(),
            what_to_check:
                "Which availability tags, provenance markers, phases, host ids, and receipt ids were actually captured."
                    .into(),
            command: "jq '.truthfulness' artifacts/e2e/workflow/replayable_failure/summary.json"
                .into(),
            expected_output:
                "A `truthfulness` object with `command_availabilities`, `provenance_markers`, phase markers, and join ids."
                    .into(),
            failure_action:
                "If `truthfulness` is missing or empty, add trace truth-context coverage before debugging higher-level behavior."
                    .into(),
        },
        ObservabilityCheck {
            name: "Trace/Receipt Join Keys".into(),
            what_to_check:
                "Whether the bundle preserved the host request, host response, and receipt ids needed to correlate evidence."
                    .into(),
            command:
                "jq '.truthfulness | {host_request_ids, host_response_ids, receipt_ids}' artifacts/e2e/workflow/replayable_failure/summary.json"
                    .into(),
            expected_output:
                "Stable arrays of ids that can be joined back to trace entries, host receipts, and replay notes."
                    .into(),
            failure_action:
                "If the arrays are empty, add `TruthContext` markers before chasing downstream symptoms."
                    .into(),
        },
        ObservabilityCheck {
            name: "Replay Environment Capture".into(),
            what_to_check:
                "The captured working directory, redacted environment variables, runner prefix, and reproducibility notes."
                    .into(),
            command: "jq '.' artifacts/e2e/workflow/replayable_failure/environment.json".into(),
            expected_output:
                "A redacted environment capture that matches the replay envelope used to generate `replay.sh`."
                    .into(),
            failure_action:
                "If environment capture is missing or incomplete, extend the replay envelope before trusting rerun results."
                    .into(),
        },
        ObservabilityCheck {
            name: "Availability Boundary Review".into(),
            what_to_check:
                "Whether the run was live, offline, planned, denied, or unknown so you do not draw conclusions from the wrong surface."
                    .into(),
            command:
                "jq '.truthfulness.command_availabilities' artifacts/e2e/workflow/replayable_failure/summary.json"
                    .into(),
            expected_output:
                "A non-empty availability map with tags like `live-runtime`, `offline-artifact`, or `planned`."
                    .into(),
            failure_action:
                "If the availability states contradict your expectation, switch to the correct host-backed or offline command family before retrying."
                    .into(),
        },
        ObservabilityCheck {
            name: "Redaction Marker Scan".into(),
            what_to_check:
                "Whether secrets were replaced with stable digest placeholders instead of leaking raw values."
                    .into(),
            command: "rg -n '\\[REDACTED:sha256:' artifacts/e2e/workflow/replayable_failure"
                .into(),
            expected_output:
                "Artifact files should contain digest-based redaction markers instead of raw bearer tokens or secrets."
                    .into(),
            failure_action:
                "If redaction markers are absent where secrets should appear, treat it as a `test_observability` regression."
                    .into(),
        },
        ObservabilityCheck {
            name: "Paused Session Queue".into(),
            what_to_check:
                "Whether interrupted workflow state is still present and resumable instead of being reconstructed from memory."
                    .into(),
            command: "fwc session list --status paused --json".into(),
            expected_output:
                "A list of paused sessions with ids, goals, and persisted context ready for inspection or resume."
                    .into(),
            failure_action:
                "If no paused session exists, pivot to history/task artifacts rather than issuing an unsafe blind retry."
                    .into(),
        },
        ObservabilityCheck {
            name: "Credential Expiry Status".into(),
            what_to_check:
                "Whether auth failure is really an expiry/rotation problem rather than a schema or host regression."
                    .into(),
            command: "fwc auth status github --json".into(),
            expected_output:
                "Structured status with expiry or rotation hints for the selected credential.".into(),
            failure_action:
                "If expiry or rotation is flagged, fix credentials first and only then re-run replay or trace analysis."
                    .into(),
        },
        ObservabilityCheck {
            name: "Template Provenance Mode".into(),
            what_to_check:
                "Whether template-family output is clearly marked as offline-derived or live-derived."
                    .into(),
            command: "fwc template github issues.create --offline --json".into(),
            expected_output:
                "Template provenance should say it came from offline schema/artifact data, not from a live runtime."
                    .into(),
            failure_action:
                "If provenance is missing or misleading, fix the template provenance envelope before expanding the docs."
                    .into(),
        },
        ObservabilityCheck {
            name: "Live Stream Resume Cursor".into(),
            what_to_check:
                "Whether host-backed stream payloads expose cursor resume metadata after filtering and truncation."
                    .into(),
            command:
                "fwc tail github --host http://127.0.0.1:8787 --cursor <CURSOR> --event-type health-check --json"
                    .into(),
            expected_output:
                "A payload with `resume_mode`, `cursor_found`, `skipped_events`, and the latest cursor."
                    .into(),
            failure_action:
                "If resume metadata is missing or inconsistent, compare against the host-backed integration tests before trusting live watch output."
                    .into(),
        },
    ]
}

/// Real artifact-bundle anatomy that the field guide should point to.
#[must_use]
pub fn get_artifact_sections() -> Vec<ArtifactSection> {
    vec![
        ArtifactSection {
            name: "trace.jsonl".into(),
            path: "artifacts/<layer>/<suite>/<case>/<timestamp>/trace.jsonl".into(),
            purpose:
                "Append-only trace log with per-entry truth context, categories, levels, timings, and redaction markers."
                    .into(),
            identifiers: vec![
                "trace_id".into(),
                "host_request_id".into(),
                "host_response_id".into(),
                "receipt_id".into(),
            ],
            fastest_answers: vec![
                "Where did the run first start failing?".into(),
                "Which truthfulness phase produced the suspicious step?".into(),
                "Did the host ever acknowledge or receipt the action?".into(),
            ],
            follow_up_commands: vec![
                "jq -c '.' artifacts/e2e/workflow/replayable_failure/trace.jsonl".into(),
                "fwc trace replay artifacts/e2e/workflow/replayable_failure/trace.jsonl --json"
                    .into(),
            ],
            references: vec![
                "crates/fwc/src/test_observability.rs".into(),
                "docs/testing/e2e_log_schema.md".into(),
            ],
        },
        ArtifactSection {
            name: "summary.json".into(),
            path: "artifacts/<layer>/<suite>/<case>/<timestamp>/summary.json".into(),
            purpose:
                "Bundle summary with log counts, truthfulness summary, availability states, provenance markers, and join ids."
                    .into(),
            identifiers: vec!["trace_id".into(), "host_request_ids".into(), "receipt_ids".into()],
            fastest_answers: vec![
                "Was this run live, offline, planned, denied, or unknown?".into(),
                "Which provenance markers and phases were captured?".into(),
                "Which ids should I use to correlate trace, receipts, and replay notes?".into(),
            ],
            follow_up_commands: vec![
                "jq '.truthfulness' artifacts/e2e/workflow/replayable_failure/summary.json"
                    .into(),
                "jq '.truthfulness.command_availabilities' artifacts/e2e/workflow/replayable_failure/summary.json".into(),
            ],
            references: vec![
                "crates/fwc/src/test_observability.rs".into(),
                "crates/fwc/testdata/golden/access_plan.json".into(),
            ],
        },
        ArtifactSection {
            name: "environment.json".into(),
            path: "artifacts/<layer>/<suite>/<case>/<timestamp>/environment.json".into(),
            purpose:
                "Replay environment capture: working directory, redacted environment, runner prefix, git SHA, and toolchain context."
                    .into(),
            identifiers: vec!["working_directory".into(), "git_sha".into(), "command_runner".into()],
            fastest_answers: vec![
                "What exact environment was captured for the rerun?".into(),
                "Was cargo expected to run through `rch exec -- ...`?".into(),
                "Which revision was this bundle recorded against?".into(),
            ],
            follow_up_commands: vec![
                "jq '.' artifacts/e2e/workflow/replayable_failure/environment.json".into(),
                "bash artifacts/e2e/workflow/replayable_failure/replay.sh".into(),
            ],
            references: vec![
                "crates/fwc/src/test_observability.rs".into(),
                "docs/STANDARD_Testing_Logging.md".into(),
            ],
        },
        ArtifactSection {
            name: "session_transcript.json".into(),
            path: "artifacts/<layer>/<suite>/<case>/<timestamp>/session_transcript.json".into(),
            purpose:
                "Structured session-lifecycle transcript for websocket, SSE, long-poll, or webhook ingress runs, including per-step outcomes and aggregate counts."
                    .into(),
            identifiers: vec![
                "scenario_id".into(),
                "run_id".into(),
                "transport".into(),
                "correlation_id".into(),
            ],
            fastest_answers: vec![
                "Which step failed in the session lifecycle, and was it pass, fail, skip, or timeout?"
                    .into(),
                "Did reconnect, silence, webhook delivery, or ack-related steps occur in the expected order?"
                    .into(),
                "Which correlation id or run id should I join back to the broader E2E bundle?"
                    .into(),
            ],
            follow_up_commands: vec![
                "jq '{scenario_id, run_id, transport, outcome, summary}' artifacts/e2e/workflow/replayable_failure/session_transcript.json".into(),
                "jq '.entries[] | {step_index, outcome, correlation_id}' artifacts/e2e/workflow/replayable_failure/session_transcript.json".into(),
            ],
            references: vec![
                "crates/fcp-testkit/src/session_script.rs".into(),
                "crates/fcp-e2e/src/lib.rs".into(),
                "docs/testing/e2e_log_schema.md".into(),
            ],
        },
        ArtifactSection {
            name: "replay.sh".into(),
            path: "artifacts/<layer>/<suite>/<case>/<timestamp>/replay.sh".into(),
            purpose:
                "Shell script that reproduces the scenario with the captured environment and runner prefix."
                    .into(),
            identifiers: vec!["trace_id note".into(), "scenario id note".into()],
            fastest_answers: vec![
                "How do I rerun this scenario exactly as captured?".into(),
                "Did the original run require `rch` or a historical git checkout?".into(),
            ],
            follow_up_commands: vec![
                "bash artifacts/e2e/workflow/replayable_failure/replay.sh".into(),
                "rch exec -- cargo test -p fwc test_observability::full_workflow_replay_round_trip -- --exact --nocapture".into(),
            ],
            references: vec![
                "crates/fwc/src/test_observability.rs".into(),
                "crates/fwc/src/e2e_scenario.rs".into(),
            ],
        },
        ArtifactSection {
            name: "golden_snapshot".into(),
            path: "artifacts/<layer>/<suite>/<case>/<timestamp>/golden_snapshot".into(),
            purpose:
                "Optional baseline snapshot for output regressions that need structured or TOON diffing."
                    .into(),
            identifiers: vec!["scenario_id".into()],
            fastest_answers: vec![
                "Did the user-visible output contract drift?".into(),
                "Is this a rendering regression rather than a runtime regression?".into(),
            ],
            follow_up_commands: vec![
                "jq '.' crates/fwc/testdata/golden/setup_repair.json".into(),
                "jq '.' crates/fwc/testdata/golden/access_plan.json".into(),
            ],
            references: vec![
                "crates/fwc/testdata/golden/setup_repair.json".into(),
                "crates/fwc/testdata/golden/access_plan.json".into(),
            ],
        },
    ]
}

/// Failure classes mapped to the fastest evidence path.
#[must_use]
pub fn get_failure_class_guides() -> Vec<FailureClassGuide> {
    vec![
        FailureClassGuide {
            name: "offline-vs-live-truth-mismatch".into(),
            symptoms:
                "The caller expected current host truth, but the evidence only reflects offline artifacts or planned output."
                    .into(),
            artifact_sections: vec!["summary.json".into(), "trace.jsonl".into()],
            first_commands: vec![
                "jq '.truthfulness.command_availabilities' artifacts/e2e/workflow/replayable_failure/summary.json".into(),
                "fwc health --json".into(),
            ],
            likely_causes: vec![
                "An offline command was used where a host-backed command was required.".into(),
                "A planned or guide-only surface was misread as execution evidence.".into(),
            ],
            recovery_guidance:
                "Switch to the matching host-backed command family and re-capture evidence before drawing conclusions."
                    .into(),
        },
        FailureClassGuide {
            name: "template-render-failed-or-unsafe-macro-expansion".into(),
            symptoms:
                "A Handlebars template fails to render, or a workflow assumes macro expansion that the confusion corpus treats as unsafe."
                    .into(),
            artifact_sections: vec!["trace.jsonl".into(), "summary.json".into()],
            first_commands: vec![
                "fwc show github --json".into(),
                "fwc template github issues.create --offline --json".into(),
                "rch exec -- cargo test -p fwc confusion_workflow -- --nocapture".into(),
            ],
            likely_causes: vec![
                "The template references a field that is absent in the current JSON payload.".into(),
                "A wildcard or secret expansion path violates the confusion-workflow safety contract."
                    .into(),
            ],
            recovery_guidance:
                "Inspect raw JSON first, then either fix the template or add a confusion-corpus case if the failure is really about unsafe guidance."
                    .into(),
        },
        FailureClassGuide {
            name: "replay-input-expired-or-missing".into(),
            symptoms:
                "Replay refuses to run because the stored input is expired or was never captured."
                    .into(),
            artifact_sections: vec!["environment.json".into(), "summary.json".into()],
            first_commands: vec![
                "fwc replay <ENTRY_ID> --json".into(),
                "fwc history <ENTRY_ID> --json".into(),
            ],
            likely_causes: vec![
                "Replay store TTL expired before the rerun happened.".into(),
                "The original execution path never persisted the full input.".into(),
            ],
            recovery_guidance:
                "Reconstruct the payload from history, schema, and template scaffolding, then capture a fresh replayable case instead of guessing."
                    .into(),
        },
        FailureClassGuide {
            name: "stale-session-resume".into(),
            symptoms:
                "The caller wants to continue interrupted work, but persisted session state is absent, paused, or no longer matches current context."
                    .into(),
            artifact_sections: vec!["summary.json".into(), "trace.jsonl".into()],
            first_commands: vec![
                "fwc session list --status paused --json".into(),
                "fwc session show --json".into(),
                "fwc session resume <SESSION_ID> --json".into(),
            ],
            likely_causes: vec![
                "A previous agent paused or ended the session without a later resume.".into(),
                "The caller relied on stale conversational state instead of persisted workflow state."
                    .into(),
            ],
            recovery_guidance:
                "Use persisted session data when it exists; otherwise pivot to task/history surfaces and restate context explicitly."
                    .into(),
        },
        FailureClassGuide {
            name: "wrong-pinned-context-or-profile-drift".into(),
            symptoms:
                "The command executes against the wrong connector, wrong zone, or wrong config profile even though the syntax looks correct."
                    .into(),
            artifact_sections: vec!["summary.json".into(), "environment.json".into()],
            first_commands: vec![
                "fwc context current --json".into(),
                "fwc config get github --json".into(),
                "fwc config doctor github --json".into(),
            ],
            likely_causes: vec![
                "The active context changed since the previous run.".into(),
                "Connector-local config drift changed a pinned `profile` or adjacent setting.".into(),
            ],
            recovery_guidance:
                "Make the active context and connector config explicit before retrying so target choice never stays ambient."
                    .into(),
        },
        FailureClassGuide {
            name: "live-stream-divergence-or-reconnect".into(),
            symptoms:
                "A long-running operation behaves differently between the host event stream and the final watched status."
                    .into(),
            artifact_sections: vec![
                "trace.jsonl".into(),
                "summary.json".into(),
                "session_transcript.json".into(),
            ],
            first_commands: vec![
                "fwc tail github --host http://127.0.0.1:8787 --cursor <CURSOR> --event-type health-check --json".into(),
                "fwc watch <REQUEST_ID> --host http://127.0.0.1:8787 --json".into(),
                "jq '{transport, outcome, summary}' artifacts/e2e/workflow/replayable_failure/session_transcript.json".into(),
            ],
            likely_causes: vec![
                "The wrong cursor was resumed or the requested event type filtered out the interesting transition."
                    .into(),
                "Reconnect or cancellation markers were present in the trace but never surfaced in the summary review."
                    .into(),
            ],
            recovery_guidance:
                "Inspect resume metadata and truthfulness phase markers together; do not trust watch output alone when reconnect paths are involved."
                    .into(),
        },
        FailureClassGuide {
            name: "webhook-redelivery-or-ack-mismatch".into(),
            symptoms:
                "Webhook ingress appears flaky because duplicate delivery, retries, or acknowledgement behavior diverges from what the connector reports."
                    .into(),
            artifact_sections: vec![
                "session_transcript.json".into(),
                "summary.json".into(),
                "replay.sh".into(),
            ],
            first_commands: vec![
                "jq '.entries[] | select(.step.action == \"webhook_deliver\" or .step.action == \"webhook_expect_ack\")' artifacts/e2e/workflow/replayable_failure/session_transcript.json".into(),
                "jq '.truthfulness | {receipt_ids, host_request_ids}' artifacts/e2e/workflow/replayable_failure/summary.json".into(),
                "bash artifacts/e2e/workflow/replayable_failure/replay.sh".into(),
            ],
            likely_causes: vec![
                "The harness observed retries or duplicate deliveries, but the connector collapsed them into a single opaque success."
                    .into(),
                "Webhook acknowledgement timing or idempotency handling changed without updating the session transcript expectations."
                    .into(),
            ],
            recovery_guidance:
                "Inspect the session transcript before the raw trace so duplicate-delivery order, retry counts, and acknowledgement steps stay explicit."
                    .into(),
        },
        FailureClassGuide {
            name: "redaction-regression".into(),
            symptoms:
                "Captured artifacts contain raw secrets, or they lost the digest-based placeholders needed for safe debugging."
                    .into(),
            artifact_sections: vec!["trace.jsonl".into(), "environment.json".into()],
            first_commands: vec![
                "rg -n '\\[REDACTED:sha256:' artifacts/e2e/workflow/replayable_failure".into(),
                "rch exec -- cargo test -p fwc test_observability -- --nocapture".into(),
            ],
            likely_causes: vec![
                "A new secret shape was not covered by the default redaction rules.".into(),
                "A code path wrote raw environment or message text before the redaction engine ran."
                    .into(),
            ],
            recovery_guidance:
                "Add or tighten redaction coverage immediately, then regenerate the affected artifacts before using them in docs or incident reports."
                    .into(),
        },
    ]
}

/// Guidance for extending the debugging contract as new bugs are discovered.
#[must_use]
pub fn get_extension_guides() -> Vec<ExtensionGuide> {
    vec![
        ExtensionGuide {
            name: "Add a new replayable scenario artifact".into(),
            when_to_add:
                "Use this when a production or host-backed bug cannot be diagnosed from existing scenario ids or bundle files."
                    .into(),
            source_files: vec![
                "crates/fwc/src/e2e_scenario.rs".into(),
                "crates/fwc/src/test_observability.rs".into(),
            ],
            steps: vec![
                "Define a new `{layer}:{suite}:{case}` scenario id instead of overloading an unrelated one."
                    .into(),
                "Emit trace entries with `TruthContext` markers so `summary.json` gains the right availability states, phases, and join ids."
                    .into(),
                "Capture `trace.jsonl`, `summary.json`, `environment.json`, `session_transcript.json`, and `replay.sh` together so the rerun story stays complete."
                    .into(),
            ],
            verification_commands: vec![
                "rch exec -- cargo test -p fwc e2e_scenario -- --nocapture".into(),
                "rch exec -- cargo test -p fwc test_observability::full_workflow_replay_round_trip -- --exact --nocapture".into(),
            ],
            references: vec![
                "docs/testing/e2e_log_schema.md".into(),
                "crates/fwc/testdata/golden/access_plan.json".into(),
                "crates/fwc/testdata/golden/setup_repair.json".into(),
            ],
        },
        ExtensionGuide {
            name: "Add a new confusion-corpus recovery case".into(),
            when_to_add:
                "Use this when the failure is really about misleading guidance, stale context, unsafe expansion, or an incomplete recovery hint."
                    .into(),
            source_files: vec!["crates/fwc/src/confusion_workflow.rs".into()],
            steps: vec![
                "Add a concrete confusing input, its expected category, the expected recovery action, and a rationale."
                    .into(),
                "Prefer a new corpus case when the bug is about explanation quality rather than connector behavior."
                    .into(),
                "Keep the corpus examples aligned with the field guide so new incidents point to reusable recovery paths."
                    .into(),
            ],
            verification_commands: vec![
                "rch exec -- cargo test -p fwc confusion_workflow -- --nocapture".into(),
            ],
            references: vec![
                "crates/fwc/src/doc_agent.rs".into(),
                "crates/fwc/testdata/golden/setup_repair.toon".into(),
            ],
        },
        ExtensionGuide {
            name: "Add or revise a debugging field-guide example".into(),
            when_to_add:
                "Use this when you fix a bug and want the local docs to show the exact commands, artifacts, and truthfulness boundaries that would have found it sooner."
                    .into(),
            source_files: vec!["crates/fwc/src/doc_debugging.rs".into()],
            steps: vec![
                "Anchor every example to an actual command family or artifact path that exists in the repo."
                    .into(),
                "Be explicit about live vs offline vs planned truth surfaces; never imply ambient authority or hidden defaults."
                    .into(),
                "Write cargo-backed verification commands in `rch exec -- ...` form so the docs match operational policy."
                    .into(),
            ],
            verification_commands: vec![
                "rch exec -- cargo test -p fwc doc_debugging -- --nocapture".into(),
            ],
            references: vec![
                "docs/testing/e2e_log_schema.md".into(),
                "crates/fwc/src/doc_readme.rs".into(),
            ],
        },
    ]
}

/// Build the complete field guide from all component data.
#[must_use]
pub fn build_field_guide() -> FieldGuide {
    FieldGuide {
        techniques: get_debug_techniques(),
        replay_guides: get_replay_guides(),
        observability_checks: get_observability_checks(),
        truthfulness_boundaries: get_truthfulness_boundaries(),
        artifact_sections: get_artifact_sections(),
        failure_classes: get_failure_class_guides(),
        extension_guides: get_extension_guides(),
    }
}

// ── Formatting ───────────────────────────────────────────────────────────────

/// Format a debug technique as a human-readable string.
#[must_use]
pub fn format_technique_toon(technique: &DebugTechnique) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Technique: {}", technique.name);
    let _ = writeln!(out, "{}", technique.description);
    let _ = writeln!(out, "When to use: {}", technique.when_to_use);

    let _ = writeln!(out, "\nCommands:");
    for cmd in &technique.commands {
        let _ = writeln!(out, "  $ {cmd}");
    }

    if !technique.tips.is_empty() {
        let _ = writeln!(out, "\nTips:");
        for tip in &technique.tips {
            let _ = writeln!(out, "  - {tip}");
        }
    }

    if !technique.related_techniques.is_empty() {
        let _ = writeln!(
            out,
            "\nRelated: {}",
            technique.related_techniques.join(", ")
        );
    }

    out
}

/// Format the complete field guide as a human-readable string.
#[must_use]
pub fn format_field_guide_toon(guide: &FieldGuide) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "FWC Debugging Field Guide");
    let _ = writeln!(out, "========================");

    let _ = writeln!(
        out,
        "\n## Truthfulness Boundaries ({} total)",
        guide.truthfulness_boundaries.len()
    );
    for boundary in &guide.truthfulness_boundaries {
        let _ = writeln!(out, "- {boundary}");
    }

    let _ = writeln!(
        out,
        "\n## Artifact Bundle Anatomy ({} total)",
        guide.artifact_sections.len()
    );
    for section in &guide.artifact_sections {
        let _ = writeln!(out, "\n### {}", section.name);
        let _ = writeln!(out, "Path: {}", section.path);
        let _ = writeln!(out, "Purpose: {}", section.purpose);
        if !section.identifiers.is_empty() {
            let _ = writeln!(out, "Join keys: {}", section.identifiers.join(", "));
        }
        if !section.fastest_answers.is_empty() {
            let _ = writeln!(out, "Fastest answers:");
            for answer in &section.fastest_answers {
                let _ = writeln!(out, "  - {answer}");
            }
        }
        if !section.follow_up_commands.is_empty() {
            let _ = writeln!(out, "Follow-up commands:");
            for command in &section.follow_up_commands {
                let _ = writeln!(out, "  $ {command}");
            }
        }
    }

    let _ = writeln!(
        out,
        "\n## Debug Techniques ({} total)",
        guide.techniques.len()
    );
    for tech in &guide.techniques {
        let _ = writeln!(out, "\n### {}", tech.name);
        let _ = writeln!(out, "{}", tech.description);
        let _ = writeln!(out, "When: {}", tech.when_to_use);
        for cmd in &tech.commands {
            let _ = writeln!(out, "  $ {cmd}");
        }
    }

    let _ = writeln!(
        out,
        "\n## Replay Guides ({} total)",
        guide.replay_guides.len()
    );
    for rg in &guide.replay_guides {
        let _ = writeln!(out, "\n### {}", rg.name);
        let _ = writeln!(out, "{}", rg.description);
        let _ = writeln!(out, "Command: {}", rg.replay_command);
    }

    let _ = writeln!(
        out,
        "\n## Common Failure Classes ({} total)",
        guide.failure_classes.len()
    );
    for class in &guide.failure_classes {
        let _ = writeln!(out, "\n### {}", class.name);
        let _ = writeln!(out, "Symptoms: {}", class.symptoms);
        if !class.artifact_sections.is_empty() {
            let _ = writeln!(out, "Check first: {}", class.artifact_sections.join(", "));
        }
        for command in &class.first_commands {
            let _ = writeln!(out, "  $ {command}");
        }
        let _ = writeln!(out, "Recovery: {}", class.recovery_guidance);
    }

    let _ = writeln!(
        out,
        "\n## Observability Checks ({} total)",
        guide.observability_checks.len()
    );
    for oc in &guide.observability_checks {
        let _ = writeln!(out, "\n### {}", oc.name);
        let _ = writeln!(out, "Check: {}", oc.what_to_check);
        let _ = writeln!(out, "  $ {}", oc.command);
        let _ = writeln!(out, "Expected: {}", oc.expected_output);
    }

    let _ = writeln!(
        out,
        "\n## Extending The Guide ({} total)",
        guide.extension_guides.len()
    );
    for extension in &guide.extension_guides {
        let _ = writeln!(out, "\n### {}", extension.name);
        let _ = writeln!(out, "When to add: {}", extension.when_to_add);
        if !extension.source_files.is_empty() {
            let _ = writeln!(out, "Source files: {}", extension.source_files.join(", "));
        }
        for command in &extension.verification_commands {
            let _ = writeln!(out, "  $ {command}");
        }
    }

    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;

    fn documented_command_prefix_is_allowed(command: &str) -> bool {
        let trimmed = command.trim();
        ["fwc ", "jq ", "rg ", "bash ", "rch exec -- "]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
    }

    // ── Technique count and structure ────────────────────────────────────

    #[test]
    fn techniques_has_at_least_10() {
        let techs = get_debug_techniques();
        assert!(techs.len() >= 10, "Only {} techniques", techs.len());
    }

    #[test]
    fn techniques_have_unique_names() {
        let techs = get_debug_techniques();
        let mut names = std::collections::BTreeSet::new();
        for t in &techs {
            assert!(names.insert(&t.name), "Duplicate name: {}", t.name);
        }
    }

    #[test]
    fn techniques_have_names() {
        for t in &get_debug_techniques() {
            assert!(!t.name.is_empty());
        }
    }

    #[test]
    fn techniques_have_descriptions() {
        for t in &get_debug_techniques() {
            assert!(
                !t.description.is_empty(),
                "Technique {} missing description",
                t.name
            );
        }
    }

    #[test]
    fn techniques_have_when_to_use() {
        for t in &get_debug_techniques() {
            assert!(
                !t.when_to_use.is_empty(),
                "Technique {} missing when_to_use",
                t.name
            );
        }
    }

    #[test]
    fn techniques_have_commands() {
        for t in &get_debug_techniques() {
            assert!(
                !t.commands.is_empty(),
                "Technique {} has no commands",
                t.name
            );
        }
    }

    #[test]
    fn techniques_commands_use_supported_prefixes() {
        for t in &get_debug_techniques() {
            for cmd in &t.commands {
                assert!(
                    documented_command_prefix_is_allowed(cmd),
                    "Command in {} uses unsupported prefix: {}",
                    t.name,
                    cmd
                );
            }
        }
    }

    #[test]
    fn techniques_have_tips() {
        for t in &get_debug_techniques() {
            assert!(!t.tips.is_empty(), "Technique {} has no tips", t.name);
        }
    }

    #[test]
    fn techniques_have_related() {
        for t in &get_debug_techniques() {
            assert!(
                !t.related_techniques.is_empty(),
                "Technique {} has no related",
                t.name
            );
        }
    }

    #[test]
    fn techniques_commands_non_empty_strings() {
        for t in &get_debug_techniques() {
            for cmd in &t.commands {
                assert!(!cmd.is_empty(), "Empty command in {}", t.name);
            }
        }
    }

    #[test]
    fn techniques_tips_non_empty_strings() {
        for t in &get_debug_techniques() {
            for tip in &t.tips {
                assert!(!tip.is_empty(), "Empty tip in {}", t.name);
            }
        }
    }

    #[test]
    fn techniques_related_non_empty_strings() {
        for t in &get_debug_techniques() {
            for r in &t.related_techniques {
                assert!(!r.is_empty(), "Empty related in {}", t.name);
            }
        }
    }

    // ── Related technique cross-references ───────────────────────────────

    #[test]
    fn techniques_related_reference_valid_names() {
        let techs = get_debug_techniques();
        let names: std::collections::BTreeSet<&str> =
            techs.iter().map(|t| t.name.as_str()).collect();
        for t in &techs {
            for r in &t.related_techniques {
                assert!(
                    names.contains(r.as_str()),
                    "Technique {} references unknown: {}",
                    t.name,
                    r
                );
            }
        }
    }

    // ── Specific technique existence ─────────────────────────────────────

    #[test]
    fn technique_trace_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Trace")));
    }

    #[test]
    fn technique_event_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Event")));
    }

    #[test]
    fn technique_schema_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Schema")));
    }

    #[test]
    fn technique_health_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Health")));
    }

    #[test]
    fn technique_network_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Network")));
    }

    #[test]
    fn technique_replay_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Replay")));
    }

    #[test]
    fn technique_credential_exists() {
        let techs = get_debug_techniques();
        assert!(techs.iter().any(|t| t.name.contains("Credential")));
    }

    // ── Replay guide count and structure ─────────────────────────────────

    #[test]
    fn replay_guides_has_at_least_5() {
        let guides = get_replay_guides();
        assert!(guides.len() >= 5, "Only {} guides", guides.len());
    }

    #[test]
    fn replay_guides_have_unique_names() {
        let guides = get_replay_guides();
        let mut names = std::collections::BTreeSet::new();
        for g in &guides {
            assert!(names.insert(&g.name), "Duplicate name: {}", g.name);
        }
    }

    #[test]
    fn replay_guides_have_names() {
        for g in &get_replay_guides() {
            assert!(!g.name.is_empty());
        }
    }

    #[test]
    fn replay_guides_have_descriptions() {
        for g in &get_replay_guides() {
            assert!(
                !g.description.is_empty(),
                "Guide {} missing description",
                g.name
            );
        }
    }

    #[test]
    fn replay_guides_have_setup_steps() {
        for g in &get_replay_guides() {
            assert!(
                !g.setup_steps.is_empty(),
                "Guide {} has no setup steps",
                g.name
            );
        }
    }

    #[test]
    fn replay_guides_have_replay_command() {
        for g in &get_replay_guides() {
            assert!(
                !g.replay_command.is_empty(),
                "Guide {} has no replay command",
                g.name
            );
        }
    }

    #[test]
    fn replay_guides_commands_use_supported_prefixes() {
        for g in &get_replay_guides() {
            assert!(
                documented_command_prefix_is_allowed(&g.replay_command),
                "Command in {} uses unsupported prefix: {}",
                g.name,
                g.replay_command
            );
        }
    }

    #[test]
    fn replay_guides_have_verification_steps() {
        for g in &get_replay_guides() {
            assert!(
                !g.verification_steps.is_empty(),
                "Guide {} has no verification steps",
                g.name
            );
        }
    }

    #[test]
    fn replay_guides_setup_non_empty_strings() {
        for g in &get_replay_guides() {
            for s in &g.setup_steps {
                assert!(!s.is_empty(), "Empty setup step in {}", g.name);
            }
        }
    }

    #[test]
    fn replay_guides_verification_non_empty_strings() {
        for g in &get_replay_guides() {
            for v in &g.verification_steps {
                assert!(!v.is_empty(), "Empty verification step in {}", g.name);
            }
        }
    }

    // ── Observability check count and structure ──────────────────────────

    #[test]
    fn observability_checks_has_at_least_8() {
        let checks = get_observability_checks();
        assert!(checks.len() >= 8, "Only {} checks", checks.len());
    }

    #[test]
    fn observability_checks_have_unique_names() {
        let checks = get_observability_checks();
        let mut names = std::collections::BTreeSet::new();
        for c in &checks {
            assert!(names.insert(&c.name), "Duplicate name: {}", c.name);
        }
    }

    #[test]
    fn observability_checks_have_names() {
        for c in &get_observability_checks() {
            assert!(!c.name.is_empty());
        }
    }

    #[test]
    fn observability_checks_have_what_to_check() {
        for c in &get_observability_checks() {
            assert!(
                !c.what_to_check.is_empty(),
                "Check {} missing what_to_check",
                c.name
            );
        }
    }

    #[test]
    fn observability_checks_have_commands() {
        for c in &get_observability_checks() {
            assert!(!c.command.is_empty(), "Check {} missing command", c.name);
        }
    }

    #[test]
    fn observability_checks_commands_use_supported_prefixes() {
        for c in &get_observability_checks() {
            assert!(
                documented_command_prefix_is_allowed(&c.command),
                "Command in {} uses unsupported prefix: {}",
                c.name,
                c.command
            );
        }
    }

    #[test]
    fn observability_checks_have_expected_output() {
        for c in &get_observability_checks() {
            assert!(
                !c.expected_output.is_empty(),
                "Check {} missing expected_output",
                c.name
            );
        }
    }

    #[test]
    fn observability_checks_have_failure_action() {
        for c in &get_observability_checks() {
            assert!(
                !c.failure_action.is_empty(),
                "Check {} missing failure_action",
                c.name
            );
        }
    }

    // ── Specific check existence ─────────────────────────────────────────

    #[test]
    fn check_availability_exists() {
        let checks = get_observability_checks();
        assert!(checks.iter().any(|c| c.name.contains("Availability")));
    }

    #[test]
    fn check_truthfulness_exists() {
        let checks = get_observability_checks();
        assert!(checks.iter().any(|c| c.name.contains("Truthfulness")));
    }

    #[test]
    fn check_session_exists() {
        let checks = get_observability_checks();
        assert!(checks.iter().any(|c| c.name.contains("Session")));
    }

    #[test]
    fn check_credential_exists() {
        let checks = get_observability_checks();
        assert!(checks.iter().any(|c| c.name.contains("Credential")));
    }

    #[test]
    fn check_template_exists() {
        let checks = get_observability_checks();
        assert!(checks.iter().any(|c| c.name.contains("Template")));
    }

    // ── Field guide ──────────────────────────────────────────────────────

    #[test]
    fn field_guide_has_techniques() {
        let guide = build_field_guide();
        assert!(!guide.techniques.is_empty());
    }

    #[test]
    fn field_guide_has_replay_guides() {
        let guide = build_field_guide();
        assert!(!guide.replay_guides.is_empty());
    }

    #[test]
    fn field_guide_has_observability_checks() {
        let guide = build_field_guide();
        assert!(!guide.observability_checks.is_empty());
    }

    #[test]
    fn field_guide_has_truthfulness_boundaries() {
        let guide = build_field_guide();
        assert!(!guide.truthfulness_boundaries.is_empty());
    }

    #[test]
    fn field_guide_has_artifact_sections() {
        let guide = build_field_guide();
        assert!(!guide.artifact_sections.is_empty());
    }

    #[test]
    fn field_guide_has_failure_classes() {
        let guide = build_field_guide();
        assert!(!guide.failure_classes.is_empty());
    }

    #[test]
    fn field_guide_has_extension_guides() {
        let guide = build_field_guide();
        assert!(!guide.extension_guides.is_empty());
    }

    #[test]
    fn field_guide_technique_count_matches() {
        let guide = build_field_guide();
        assert_eq!(guide.techniques.len(), get_debug_techniques().len());
    }

    #[test]
    fn field_guide_replay_count_matches() {
        let guide = build_field_guide();
        assert_eq!(guide.replay_guides.len(), get_replay_guides().len());
    }

    #[test]
    fn field_guide_check_count_matches() {
        let guide = build_field_guide();
        assert_eq!(
            guide.observability_checks.len(),
            get_observability_checks().len()
        );
    }

    #[test]
    fn field_guide_truthfulness_count_matches() {
        let guide = build_field_guide();
        assert_eq!(
            guide.truthfulness_boundaries.len(),
            get_truthfulness_boundaries().len()
        );
    }

    #[test]
    fn field_guide_artifact_count_matches() {
        let guide = build_field_guide();
        assert_eq!(guide.artifact_sections.len(), get_artifact_sections().len());
    }

    #[test]
    fn field_guide_failure_count_matches() {
        let guide = build_field_guide();
        assert_eq!(
            guide.failure_classes.len(),
            get_failure_class_guides().len()
        );
    }

    #[test]
    fn field_guide_extension_count_matches() {
        let guide = build_field_guide();
        assert_eq!(guide.extension_guides.len(), get_extension_guides().len());
    }

    // ── Truthfulness / artifact / failure / extension sections ──────────

    #[test]
    fn truthfulness_boundaries_cover_live_and_offline() {
        let boundaries = get_truthfulness_boundaries();
        assert!(boundaries.iter().any(|b| b.contains("live-runtime")));
        assert!(boundaries.iter().any(|b| b.contains("offline-artifact")));
        assert!(boundaries.iter().any(|b| b.contains("planned")));
    }

    #[test]
    fn artifact_sections_has_expected_core_files() {
        let sections = get_artifact_sections();
        let names: std::collections::BTreeSet<&str> = sections
            .iter()
            .map(|section| section.name.as_str())
            .collect();
        assert!(names.contains("trace.jsonl"));
        assert!(names.contains("summary.json"));
        assert!(names.contains("environment.json"));
        assert!(names.contains("session_transcript.json"));
        assert!(names.contains("replay.sh"));
    }

    #[test]
    fn artifact_sections_paths_non_empty() {
        for section in &get_artifact_sections() {
            assert!(
                !section.path.is_empty(),
                "artifact section {} missing path",
                section.name
            );
            assert!(
                !section.references.is_empty(),
                "artifact section {} missing references",
                section.name
            );
        }
    }

    #[test]
    fn failure_classes_reference_valid_artifact_sections() {
        let sections = get_artifact_sections();
        let section_names: std::collections::BTreeSet<&str> = sections
            .iter()
            .map(|section| section.name.as_str())
            .collect();
        for class in &get_failure_class_guides() {
            for section in &class.artifact_sections {
                assert!(
                    section_names.contains(section.as_str()),
                    "failure class {} references unknown section {}",
                    class.name,
                    section
                );
            }
        }
    }

    #[test]
    fn extension_guides_use_rch_for_verification() {
        for guide in &get_extension_guides() {
            assert!(
                guide
                    .verification_commands
                    .iter()
                    .all(|command| command.starts_with("rch exec -- ")),
                "extension guide {} must keep verification commands behind rch",
                guide.name
            );
        }
    }

    #[test]
    fn extension_guides_reference_local_files() {
        for guide in &get_extension_guides() {
            assert!(
                !guide.source_files.is_empty(),
                "{} missing source files",
                guide.name
            );
            assert!(
                !guide.references.is_empty(),
                "{} missing references",
                guide.name
            );
        }
    }

    // ── Serialization ────────────────────────────────────────────────────

    #[test]
    fn technique_serializes() {
        let t = &get_debug_techniques()[0];
        let json = serde_json::to_string(t).unwrap();
        assert!(json.contains(&t.name));
    }

    #[test]
    fn technique_deserializes_roundtrip() {
        let t = &get_debug_techniques()[0];
        let json = serde_json::to_string(t).unwrap();
        let back: DebugTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(t.name, back.name);
    }

    #[test]
    fn replay_guide_serializes() {
        let g = &get_replay_guides()[0];
        let json = serde_json::to_string(g).unwrap();
        assert!(json.contains(&g.name));
    }

    #[test]
    fn replay_guide_deserializes_roundtrip() {
        let g = &get_replay_guides()[0];
        let json = serde_json::to_string(g).unwrap();
        let back: ReplayGuide = serde_json::from_str(&json).unwrap();
        assert_eq!(g.name, back.name);
    }

    #[test]
    fn observability_check_serializes() {
        let c = &get_observability_checks()[0];
        let json = serde_json::to_string(c).unwrap();
        assert!(json.contains(&c.name));
    }

    #[test]
    fn observability_check_deserializes_roundtrip() {
        let c = &get_observability_checks()[0];
        let json = serde_json::to_string(c).unwrap();
        let back: ObservabilityCheck = serde_json::from_str(&json).unwrap();
        assert_eq!(c.name, back.name);
    }

    #[test]
    fn field_guide_serializes() {
        let guide = build_field_guide();
        let json = serde_json::to_string(&guide).unwrap();
        assert!(json.contains("techniques"));
    }

    #[test]
    fn field_guide_deserializes_roundtrip() {
        let guide = build_field_guide();
        let json = serde_json::to_string(&guide).unwrap();
        let back: FieldGuide = serde_json::from_str(&json).unwrap();
        assert_eq!(guide.techniques.len(), back.techniques.len());
    }

    // ── Clone and Debug ──────────────────────────────────────────────────

    #[test]
    fn technique_clone() {
        let t = &get_debug_techniques()[0];
        let cloned = t.clone();
        assert_eq!(t.name, cloned.name);
    }

    #[test]
    fn technique_debug() {
        let t = &get_debug_techniques()[0];
        let dbg = format!("{t:?}");
        assert!(dbg.contains("DebugTechnique"));
    }

    #[test]
    fn replay_guide_clone() {
        let g = &get_replay_guides()[0];
        let cloned = g.clone();
        assert_eq!(g.name, cloned.name);
    }

    #[test]
    fn replay_guide_debug() {
        let g = &get_replay_guides()[0];
        let dbg = format!("{g:?}");
        assert!(dbg.contains("ReplayGuide"));
    }

    #[test]
    fn observability_check_clone() {
        let c = &get_observability_checks()[0];
        let cloned = c.clone();
        assert_eq!(c.name, cloned.name);
    }

    #[test]
    fn observability_check_debug() {
        let c = &get_observability_checks()[0];
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ObservabilityCheck"));
    }

    #[test]
    fn field_guide_clone() {
        let guide = build_field_guide();
        let cloned = guide.clone();
        assert_eq!(guide.techniques.len(), cloned.techniques.len());
    }

    #[test]
    fn field_guide_debug() {
        let guide = build_field_guide();
        let dbg = format!("{guide:?}");
        assert!(dbg.contains("FieldGuide"));
    }

    // ── Format tests ─────────────────────────────────────────────────────

    #[test]
    fn format_technique_toon_contains_name() {
        let t = &get_debug_techniques()[0];
        let out = format_technique_toon(t);
        assert!(out.contains(&t.name));
    }

    #[test]
    fn format_technique_toon_contains_when_to_use() {
        let t = &get_debug_techniques()[0];
        let out = format_technique_toon(t);
        assert!(out.contains("When to use"));
    }

    #[test]
    fn format_technique_toon_contains_commands() {
        let t = &get_debug_techniques()[0];
        let out = format_technique_toon(t);
        assert!(out.contains("Commands:"));
        assert!(out.contains("$"));
    }

    #[test]
    fn format_technique_toon_contains_tips() {
        let t = &get_debug_techniques()[0];
        let out = format_technique_toon(t);
        assert!(out.contains("Tips:"));
    }

    #[test]
    fn format_technique_toon_contains_related() {
        let t = &get_debug_techniques()[0];
        let out = format_technique_toon(t);
        assert!(out.contains("Related:"));
    }

    #[test]
    fn format_field_guide_toon_contains_header() {
        let guide = build_field_guide();
        let out = format_field_guide_toon(&guide);
        assert!(out.contains("FWC Debugging Field Guide"));
    }

    #[test]
    fn format_field_guide_toon_contains_sections() {
        let guide = build_field_guide();
        let out = format_field_guide_toon(&guide);
        assert!(out.contains("Truthfulness Boundaries"));
        assert!(out.contains("Artifact Bundle Anatomy"));
        assert!(out.contains("Debug Techniques"));
        assert!(out.contains("Replay Guides"));
        assert!(out.contains("Common Failure Classes"));
        assert!(out.contains("Observability Checks"));
        assert!(out.contains("Extending The Guide"));
    }

    #[test]
    fn format_field_guide_toon_contains_counts() {
        let guide = build_field_guide();
        let out = format_field_guide_toon(&guide);
        assert!(out.contains(&format!("{} total", guide.truthfulness_boundaries.len())));
        assert!(out.contains(&format!("{} total", guide.artifact_sections.len())));
        assert!(out.contains(&format!("{} total", guide.techniques.len())));
        assert!(out.contains(&format!("{} total", guide.replay_guides.len())));
        assert!(out.contains(&format!("{} total", guide.failure_classes.len())));
        assert!(out.contains(&format!("{} total", guide.observability_checks.len())));
        assert!(out.contains(&format!("{} total", guide.extension_guides.len())));
    }

    // ── All format without panic ─────────────────────────────────────────

    #[test]
    fn all_techniques_format_without_panic() {
        for t in &get_debug_techniques() {
            let out = format_technique_toon(t);
            assert!(!out.is_empty());
        }
    }

    #[test]
    fn field_guide_format_without_panic() {
        let guide = build_field_guide();
        let out = format_field_guide_toon(&guide);
        assert!(!out.is_empty());
    }
}
