//! Confusion test corpus for workflow/task/session/pipeline cases.
//!
//! Provides a structured corpus of confusing or ambiguous user inputs that
//! exercise the FWC intent-resolution and recovery pathways.  Each case
//! captures the raw input, the expected confusion category, the recommended
//! recovery action, and a rationale explaining why the input is confusing.
//!
//! # Purpose
//!
//! The corpus serves three roles:
//!
//! 1. **Regression guard** — new intent-resolution logic can be validated
//!    against the full corpus to avoid regressions.
//! 2. **Training data** — the rationale fields provide rich context for
//!    improving intent classifiers.
//! 3. **Documentation** — the corpus itself is the authoritative catalogue
//!    of known ambiguity patterns in FWC workflows.

use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────

/// A single confusion test case.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfusionCase {
    /// The raw user input or scenario description.
    pub input: String,
    /// The expected confusion category.
    pub expected_category: ConfusionCategory,
    /// The expected recovery action.
    pub expected_recovery: RecoveryAction,
    /// Why this input is confusing (human-readable).
    pub rationale: String,
}

/// Category of confusion in a user input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfusionCategory {
    /// The user's intent is ambiguous between two or more valid interpretations.
    AmbiguousIntent,
    /// The session context the user relies on has expired or changed.
    StaleContext,
    /// The user assumes a fact that is not present in the current state.
    MissingFact,
    /// The user's pinned context (connector, zone, etc.) is wrong.
    WrongPinnedContext,
    /// The user assumes a pipeline step or ordering that does not exist.
    BrokenPipelineAssumption,
    /// A macro or template expansion would be unsafe or nonsensical.
    UnsafeMacroExpansion,
    /// A multi-step workflow was interrupted and cannot resume cleanly.
    InterruptedWorkflow,
    /// An approval or confirmation step is blocking progress.
    BlockedApproval,
    /// A batch or multi-target operation partially completed.
    PartialCompletion,
}

impl ConfusionCategory {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::AmbiguousIntent => "ambiguous-intent",
            Self::StaleContext => "stale-context",
            Self::MissingFact => "missing-fact",
            Self::WrongPinnedContext => "wrong-pinned-context",
            Self::BrokenPipelineAssumption => "broken-pipeline-assumption",
            Self::UnsafeMacroExpansion => "unsafe-macro-expansion",
            Self::InterruptedWorkflow => "interrupted-workflow",
            Self::BlockedApproval => "blocked-approval",
            Self::PartialCompletion => "partial-completion",
        }
    }

    /// Short explanation of the category.
    pub const fn explanation(self) -> &'static str {
        match self {
            Self::AmbiguousIntent => "Multiple valid interpretations exist for the input.",
            Self::StaleContext => "Session context has expired or changed since last interaction.",
            Self::MissingFact => "The user assumes a fact not present in current state.",
            Self::WrongPinnedContext => "The pinned connector, zone, or session is incorrect.",
            Self::BrokenPipelineAssumption => "The assumed pipeline step ordering does not exist.",
            Self::UnsafeMacroExpansion => {
                "Macro or template expansion would be unsafe or nonsensical."
            }
            Self::InterruptedWorkflow => "A multi-step workflow was interrupted mid-flight.",
            Self::BlockedApproval => "An approval or confirmation step is blocking progress.",
            Self::PartialCompletion => "A batch operation partially completed with failures.",
        }
    }

    /// All variants.
    pub const fn all() -> &'static [Self] {
        &[
            Self::AmbiguousIntent,
            Self::StaleContext,
            Self::MissingFact,
            Self::WrongPinnedContext,
            Self::BrokenPipelineAssumption,
            Self::UnsafeMacroExpansion,
            Self::InterruptedWorkflow,
            Self::BlockedApproval,
            Self::PartialCompletion,
        ]
    }
}

impl std::fmt::Display for ConfusionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Recommended recovery action when confusion is detected.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// Ask the user to clarify their intent.
    AskForClarification,
    /// Suggest a concrete alternative command or workflow.
    SuggestAlternative,
    /// Show the current state so the user can orient.
    ShowCurrentState,
    /// Retry with safe defaults and report what was used.
    RetryWithDefaults,
    /// Abort the operation with a clear explanation.
    AbortWithExplanation,
    /// Escalate to a human operator.
    EscalateToHuman,
}

impl RecoveryAction {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::AskForClarification => "ask-for-clarification",
            Self::SuggestAlternative => "suggest-alternative",
            Self::ShowCurrentState => "show-current-state",
            Self::RetryWithDefaults => "retry-with-defaults",
            Self::AbortWithExplanation => "abort-with-explanation",
            Self::EscalateToHuman => "escalate-to-human",
        }
    }

    /// Template guidance message for this recovery action.
    pub const fn guidance_template(self) -> &'static str {
        match self {
            Self::AskForClarification => {
                "Your request is ambiguous. Could you clarify which of the following you meant?"
            }
            Self::SuggestAlternative => {
                "The requested operation is not available. Here is an alternative approach:"
            }
            Self::ShowCurrentState => "Here is the current state to help orient your next action:",
            Self::RetryWithDefaults => {
                "Retrying with safe defaults. The following values were used:"
            }
            Self::AbortWithExplanation => "The operation has been aborted for safety. Reason:",
            Self::EscalateToHuman => {
                "This situation requires human judgment. Please review and decide:"
            }
        }
    }

    /// All variants.
    pub const fn all() -> &'static [Self] {
        &[
            Self::AskForClarification,
            Self::SuggestAlternative,
            Self::ShowCurrentState,
            Self::RetryWithDefaults,
            Self::AbortWithExplanation,
            Self::EscalateToHuman,
        ]
    }
}

impl std::fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ── Corpus ────────────────────────────────────────────────────────────

/// Return the full workflow confusion corpus (40+ cases).
pub fn get_workflow_confusion_cases() -> Vec<ConfusionCase> {
    let mut cases = Vec::with_capacity(48);
    cases.extend(ambiguous_intent_cases());
    cases.extend(stale_context_cases());
    cases.extend(missing_fact_cases());
    cases.extend(wrong_pinned_context_cases());
    cases.extend(broken_pipeline_cases());
    cases.extend(unsafe_macro_cases());
    cases.extend(interrupted_workflow_cases());
    cases.extend(blocked_approval_cases());
    cases.extend(partial_completion_cases());
    cases.extend(edge_cases());
    cases
}

fn ambiguous_intent_cases() -> Vec<ConfusionCase> {
    vec![
        ConfusionCase {
            input: "run the deploy".into(),
            expected_category: ConfusionCategory::AmbiguousIntent,
            expected_recovery: RecoveryAction::AskForClarification,
            rationale: "No deploy pipeline is defined; 'deploy' could refer to multiple connectors or workflows.".into(),
        },
        ConfusionCase {
            input: "send it".into(),
            expected_category: ConfusionCategory::AmbiguousIntent,
            expected_recovery: RecoveryAction::AskForClarification,
            rationale: "'it' has no referent — could mean a message, file, notification, or API call.".into(),
        },
        ConfusionCase {
            input: "use the other one".into(),
            expected_category: ConfusionCategory::AmbiguousIntent,
            expected_recovery: RecoveryAction::AskForClarification,
            rationale: "'the other one' is ambiguous when multiple connectors or configs match.".into(),
        },
        ConfusionCase {
            input: "do that thing again".into(),
            expected_category: ConfusionCategory::AmbiguousIntent,
            expected_recovery: RecoveryAction::AskForClarification,
            rationale: "Vague reference to a previous action without specifying which one.".into(),
        },
        ConfusionCase {
            input: "slack message".into(),
            expected_category: ConfusionCategory::AmbiguousIntent,
            expected_recovery: RecoveryAction::AskForClarification,
            rationale: "Could mean 'send a Slack message', 'read Slack messages', or 'configure Slack'.".into(),
        },
        ConfusionCase {
            input: "connect to the database".into(),
            expected_category: ConfusionCategory::AmbiguousIntent,
            expected_recovery: RecoveryAction::AskForClarification,
            rationale: "Multiple database connectors may exist; no specific connector or operation named.".into(),
        },
    ]
}

fn stale_context_cases() -> Vec<ConfusionCase> {
    vec![
        ConfusionCase {
            input: "redo the last thing".into(),
            expected_category: ConfusionCategory::StaleContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Session has no history or history has been cleared after timeout.".into(),
        },
        ConfusionCase {
            input: "continue where I left off".into(),
            expected_category: ConfusionCategory::StaleContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Session context expired; there is no saved checkpoint to resume from."
                .into(),
        },
        ConfusionCase {
            input: "use the same settings as before".into(),
            expected_category: ConfusionCategory::StaleContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Previous session settings are no longer available after reconnect.".into(),
        },
        ConfusionCase {
            input: "apply the fix from yesterday".into(),
            expected_category: ConfusionCategory::StaleContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Session does not persist across days; 'yesterday' context is unavailable."
                .into(),
        },
        ConfusionCase {
            input: "rerun with the old parameters".into(),
            expected_category: ConfusionCategory::StaleContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Parameter history from a previous session is no longer cached.".into(),
        },
    ]
}

fn missing_fact_cases() -> Vec<ConfusionCase> {
    vec![
        ConfusionCase {
            input: "update task #42".into(),
            expected_category: ConfusionCategory::MissingFact,
            expected_recovery: RecoveryAction::SuggestAlternative,
            rationale: "Task #42 does not exist or has been deleted.".into(),
        },
        ConfusionCase {
            input: "check the status of the deploy to prod".into(),
            expected_category: ConfusionCategory::MissingFact,
            expected_recovery: RecoveryAction::SuggestAlternative,
            rationale: "No deployment to prod is tracked in the current workspace.".into(),
        },
        ConfusionCase {
            input: "show me the results from the nightly build".into(),
            expected_category: ConfusionCategory::MissingFact,
            expected_recovery: RecoveryAction::SuggestAlternative,
            rationale: "No nightly build connector or pipeline is configured.".into(),
        },
        ConfusionCase {
            input: "resume batch job batch-99".into(),
            expected_category: ConfusionCategory::MissingFact,
            expected_recovery: RecoveryAction::SuggestAlternative,
            rationale: "batch-99 is not found in the active or completed batch registry.".into(),
        },
        ConfusionCase {
            input: "roll back the migration".into(),
            expected_category: ConfusionCategory::MissingFact,
            expected_recovery: RecoveryAction::SuggestAlternative,
            rationale: "No migration operation is recorded in the current session.".into(),
        },
    ]
}

fn wrong_pinned_context_cases() -> Vec<ConfusionCase> {
    vec![
        ConfusionCase {
            input: "list issues".into(),
            expected_category: ConfusionCategory::WrongPinnedContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Pinned connector is 'slack' but 'list issues' is a Jira/GitHub operation."
                .into(),
        },
        ConfusionCase {
            input: "create a channel".into(),
            expected_category: ConfusionCategory::WrongPinnedContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Pinned zone is 'production' but channel creation requires 'staging' zone."
                .into(),
        },
        ConfusionCase {
            input: "query the metrics endpoint".into(),
            expected_category: ConfusionCategory::WrongPinnedContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Current pinned connector does not expose a metrics endpoint.".into(),
        },
        ConfusionCase {
            input: "send notification to #general".into(),
            expected_category: ConfusionCategory::WrongPinnedContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Pinned connector is 'email' but #general is a Slack channel reference."
                .into(),
        },
        ConfusionCase {
            input: "run terraform plan".into(),
            expected_category: ConfusionCategory::WrongPinnedContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale:
                "Pinned connector is 'github' but terraform plan requires the terraform connector."
                    .into(),
        },
    ]
}

fn broken_pipeline_cases() -> Vec<ConfusionCase> {
    vec![
        ConfusionCase {
            input: "skip step 3 and go to step 5".into(),
            expected_category: ConfusionCategory::BrokenPipelineAssumption,
            expected_recovery: RecoveryAction::AbortWithExplanation,
            rationale: "Pipeline has no step 5, or steps 3 and 5 have a dependency.".into(),
        },
        ConfusionCase {
            input: "run the tests before the build".into(),
            expected_category: ConfusionCategory::BrokenPipelineAssumption,
            expected_recovery: RecoveryAction::SuggestAlternative,
            rationale: "Pipeline defines build before test; reversing would skip compilation."
                .into(),
        },
        ConfusionCase {
            input: "merge and then run CI".into(),
            expected_category: ConfusionCategory::BrokenPipelineAssumption,
            expected_recovery: RecoveryAction::AbortWithExplanation,
            rationale: "CI must pass before merge; reversing the order violates policy.".into(),
        },
        ConfusionCase {
            input: "deploy without building".into(),
            expected_category: ConfusionCategory::BrokenPipelineAssumption,
            expected_recovery: RecoveryAction::AbortWithExplanation,
            rationale:
                "Deploy step depends on build artifact; skipping build makes deploy impossible."
                    .into(),
        },
        ConfusionCase {
            input: "run validation after cleanup".into(),
            expected_category: ConfusionCategory::BrokenPipelineAssumption,
            expected_recovery: RecoveryAction::SuggestAlternative,
            rationale: "Cleanup removes the resources that validation checks; order is invalid."
                .into(),
        },
    ]
}

fn unsafe_macro_cases() -> Vec<ConfusionCase> {
    vec![
        ConfusionCase {
            input: "run template deploy-all with target='*'".into(),
            expected_category: ConfusionCategory::UnsafeMacroExpansion,
            expected_recovery: RecoveryAction::AbortWithExplanation,
            rationale:
                "Wildcard target expansion would deploy to every environment including production."
                    .into(),
        },
        ConfusionCase {
            input: "expand {{env.SECRET_KEY}} in the config".into(),
            expected_category: ConfusionCategory::UnsafeMacroExpansion,
            expected_recovery: RecoveryAction::AbortWithExplanation,
            rationale: "Secret key expansion in a config template would leak credentials to logs."
                .into(),
        },
        ConfusionCase {
            input: "apply macro delete-all-users".into(),
            expected_category: ConfusionCategory::UnsafeMacroExpansion,
            expected_recovery: RecoveryAction::EscalateToHuman,
            rationale:
                "Destructive macro 'delete-all-users' requires human review before execution."
                    .into(),
        },
        ConfusionCase {
            input: "batch expand recipe cleanup-stale with scope=global".into(),
            expected_category: ConfusionCategory::UnsafeMacroExpansion,
            expected_recovery: RecoveryAction::EscalateToHuman,
            rationale: "Global scope on a cleanup recipe could affect all tenants.".into(),
        },
    ]
}

fn interrupted_workflow_cases() -> Vec<ConfusionCase> {
    vec![
        ConfusionCase {
            input: "finish the migration".into(),
            expected_category: ConfusionCategory::InterruptedWorkflow,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale:
                "Migration workflow was interrupted at step 2/4; resume requires state inspection."
                    .into(),
        },
        ConfusionCase {
            input: "complete the onboarding flow".into(),
            expected_category: ConfusionCategory::InterruptedWorkflow,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Onboarding was interrupted during credential setup; next step unclear."
                .into(),
        },
        ConfusionCase {
            input: "pick up where the import stopped".into(),
            expected_category: ConfusionCategory::InterruptedWorkflow,
            expected_recovery: RecoveryAction::RetryWithDefaults,
            rationale: "Bulk import was interrupted; some records imported, some not.".into(),
        },
        ConfusionCase {
            input: "continue the sync that crashed".into(),
            expected_category: ConfusionCategory::InterruptedWorkflow,
            expected_recovery: RecoveryAction::RetryWithDefaults,
            rationale: "Sync process crashed mid-way; checkpoint data may allow partial resume."
                .into(),
        },
    ]
}

fn blocked_approval_cases() -> Vec<ConfusionCase> {
    vec![
        ConfusionCase {
            input: "just approve it already".into(),
            expected_category: ConfusionCategory::BlockedApproval,
            expected_recovery: RecoveryAction::EscalateToHuman,
            rationale:
                "Approval requires a human with the appropriate role; CLI cannot self-approve."
                    .into(),
        },
        ConfusionCase {
            input: "skip the approval step".into(),
            expected_category: ConfusionCategory::BlockedApproval,
            expected_recovery: RecoveryAction::AbortWithExplanation,
            rationale: "Approval step is mandatory per policy; skipping is not allowed.".into(),
        },
        ConfusionCase {
            input: "force deploy to prod without review".into(),
            expected_category: ConfusionCategory::BlockedApproval,
            expected_recovery: RecoveryAction::AbortWithExplanation,
            rationale:
                "Production deployments require review approval; force-skipping violates policy."
                    .into(),
        },
        ConfusionCase {
            input: "auto-approve all pending changes".into(),
            expected_category: ConfusionCategory::BlockedApproval,
            expected_recovery: RecoveryAction::EscalateToHuman,
            rationale: "Bulk auto-approval would bypass individual change review.".into(),
        },
        ConfusionCase {
            input: "override the safety check".into(),
            expected_category: ConfusionCategory::BlockedApproval,
            expected_recovery: RecoveryAction::AbortWithExplanation,
            rationale: "Safety checks are enforced by policy and cannot be overridden from CLI."
                .into(),
        },
    ]
}

fn partial_completion_cases() -> Vec<ConfusionCase> {
    vec![
        ConfusionCase {
            input: "all connectors updated".into(),
            expected_category: ConfusionCategory::PartialCompletion,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Batch update completed for 8/12 connectors; 4 failed with auth errors."
                .into(),
        },
        ConfusionCase {
            input: "retry the failed ones".into(),
            expected_category: ConfusionCategory::PartialCompletion,
            expected_recovery: RecoveryAction::RetryWithDefaults,
            rationale: "Need to identify which subset failed and retry only those.".into(),
        },
        ConfusionCase {
            input: "clean up the partial import".into(),
            expected_category: ConfusionCategory::PartialCompletion,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Import created 200/500 records; cleanup must identify which were created."
                .into(),
        },
        ConfusionCase {
            input: "the batch is done".into(),
            expected_category: ConfusionCategory::PartialCompletion,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Batch shows 90% complete but has stalled; not actually done.".into(),
        },
        ConfusionCase {
            input: "undo the partial rollout".into(),
            expected_category: ConfusionCategory::PartialCompletion,
            expected_recovery: RecoveryAction::EscalateToHuman,
            rationale: "Rollout reached 3/10 targets; undoing requires per-target reversal.".into(),
        },
    ]
}

fn edge_cases() -> Vec<ConfusionCase> {
    vec![
        ConfusionCase {
            input: String::new(),
            expected_category: ConfusionCategory::AmbiguousIntent,
            expected_recovery: RecoveryAction::AskForClarification,
            rationale: "Empty input has no intent whatsoever.".into(),
        },
        ConfusionCase {
            input: "help".into(),
            expected_category: ConfusionCategory::AmbiguousIntent,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "Bare 'help' is ambiguous: help with what? Show available commands.".into(),
        },
        ConfusionCase {
            input: "invoke slack.send_message to jira".into(),
            expected_category: ConfusionCategory::WrongPinnedContext,
            expected_recovery: RecoveryAction::AskForClarification,
            rationale: "Mixing connector names: 'slack.send_message' cannot target 'jira'.".into(),
        },
        ConfusionCase {
            input: "pipeline run my-pipe step=nonexistent".into(),
            expected_category: ConfusionCategory::BrokenPipelineAssumption,
            expected_recovery: RecoveryAction::SuggestAlternative,
            rationale: "Referenced step 'nonexistent' is not defined in pipeline 'my-pipe'.".into(),
        },
    ]
}

// ── Classification ────────────────────────────────────────────────────

/// Classify a confusing input into a category based on keyword heuristics.
///
/// This is a lightweight classifier for demonstration and test purposes.
/// Production classifiers would use richer NLP or ML-based approaches.
pub fn classify_confusion(input: &str) -> ConfusionCategory {
    let lower = input.to_lowercase();

    // Empty or very short inputs are ambiguous.
    if lower.trim().is_empty() || lower.trim().len() < 3 {
        return ConfusionCategory::AmbiguousIntent;
    }

    // Check for pipeline ordering keywords.
    if lower.contains("skip step")
        || lower.contains("before the build")
        || lower.contains("after cleanup")
        || lower.contains("without building")
        || lower.contains("merge and then")
        || lower.contains("step=")
    {
        return ConfusionCategory::BrokenPipelineAssumption;
    }

    // Check for approval/override keywords.
    if lower.contains("approve")
        || lower.contains("skip the approval")
        || lower.contains("without review")
        || lower.contains("override the safety")
        || lower.contains("force deploy")
    {
        return ConfusionCategory::BlockedApproval;
    }

    // Check for macro/template expansion keywords.
    if lower.contains("template")
        || lower.contains("expand")
        || lower.contains("macro")
        || lower.contains("{{")
    {
        return ConfusionCategory::UnsafeMacroExpansion;
    }

    // Check for partial completion keywords.
    if lower.contains("partial")
        || lower.contains("failed ones")
        || lower.contains("the batch")
        || lower.contains("partial import")
        || lower.contains("partial rollout")
        || lower.contains("8/12")
        || lower.contains("200/500")
        || lower.contains("90%")
    {
        return ConfusionCategory::PartialCompletion;
    }

    // Check for interrupted workflow keywords.
    if lower.contains("finish the")
        || lower.contains("complete the")
        || lower.contains("pick up where")
        || lower.contains("continue the")
        || lower.contains("crashed")
        || lower.contains("interrupted")
    {
        return ConfusionCategory::InterruptedWorkflow;
    }

    // Check for stale context keywords.
    if lower.contains("last thing")
        || lower.contains("left off")
        || lower.contains("as before")
        || lower.contains("from yesterday")
        || lower.contains("old parameters")
        || lower.contains("same settings")
    {
        return ConfusionCategory::StaleContext;
    }

    // Check for wrong pinned context keywords.
    if lower.contains("list issues")
        || lower.contains("create a channel")
        || lower.contains("metrics endpoint")
        || lower.contains("#general")
        || lower.contains("terraform")
        || (lower.contains("to jira") && lower.contains("slack"))
    {
        return ConfusionCategory::WrongPinnedContext;
    }

    // Check for missing fact keywords.
    if lower.contains("task #")
        || lower.contains("batch-")
        || lower.contains("nightly build")
        || lower.contains("deploy to prod")
        || lower.contains("roll back")
        || lower.contains("migration")
    {
        return ConfusionCategory::MissingFact;
    }

    // Default to ambiguous intent.
    ConfusionCategory::AmbiguousIntent
}

/// Suggest a recovery action for a given confusion category.
pub const fn suggest_recovery(category: ConfusionCategory) -> RecoveryAction {
    match category {
        ConfusionCategory::AmbiguousIntent => RecoveryAction::AskForClarification,
        ConfusionCategory::StaleContext
        | ConfusionCategory::WrongPinnedContext
        | ConfusionCategory::InterruptedWorkflow
        | ConfusionCategory::PartialCompletion => RecoveryAction::ShowCurrentState,
        ConfusionCategory::MissingFact => RecoveryAction::SuggestAlternative,
        ConfusionCategory::BrokenPipelineAssumption | ConfusionCategory::UnsafeMacroExpansion => {
            RecoveryAction::AbortWithExplanation
        }
        ConfusionCategory::BlockedApproval => RecoveryAction::EscalateToHuman,
    }
}

/// Format recovery guidance for a confusion case.
pub fn format_recovery_guidance(case: &ConfusionCase) -> String {
    let mut lines = Vec::new();
    lines.push(format!("Confusion: {}", case.expected_category.label()));
    lines.push(format!("  Input:    \"{}\"", case.input));
    lines.push(format!("  Rationale: {}", case.rationale));
    lines.push(format!("  Recovery:  {}", case.expected_recovery.label()));
    lines.push(format!(
        "  Guidance:  {}",
        case.expected_recovery.guidance_template()
    ));
    lines.join("\n")
}

/// Count cases by category in the corpus.
pub fn count_by_category(cases: &[ConfusionCase]) -> Vec<(ConfusionCategory, usize)> {
    let mut counts: Vec<(ConfusionCategory, usize)> = ConfusionCategory::all()
        .iter()
        .map(|cat| {
            let n = cases.iter().filter(|c| c.expected_category == *cat).count();
            (*cat, n)
        })
        .collect();
    counts.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    counts
}

/// Count cases by recovery action in the corpus.
pub fn count_by_recovery(cases: &[ConfusionCase]) -> Vec<(RecoveryAction, usize)> {
    let mut counts: Vec<(RecoveryAction, usize)> = RecoveryAction::all()
        .iter()
        .map(|act| {
            let n = cases.iter().filter(|c| c.expected_recovery == *act).count();
            (*act, n)
        })
        .collect();
    counts.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    counts
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Corpus completeness ─────────────────────────────────────────

    #[test]
    fn corpus_has_at_least_40_cases() {
        let cases = get_workflow_confusion_cases();
        assert!(
            cases.len() >= 40,
            "corpus has {} cases, need at least 40",
            cases.len()
        );
    }

    #[test]
    fn corpus_covers_all_categories() {
        let cases = get_workflow_confusion_cases();
        for cat in ConfusionCategory::all() {
            let n = cases.iter().filter(|c| c.expected_category == *cat).count();
            assert!(n >= 1, "category {:?} has no cases in corpus", cat);
        }
    }

    #[test]
    fn corpus_covers_all_recovery_actions() {
        let cases = get_workflow_confusion_cases();
        for act in RecoveryAction::all() {
            let n = cases.iter().filter(|c| c.expected_recovery == *act).count();
            assert!(n >= 1, "recovery action {:?} has no cases in corpus", act);
        }
    }

    #[test]
    fn corpus_all_have_rationale() {
        let cases = get_workflow_confusion_cases();
        for case in &cases {
            assert!(
                !case.rationale.is_empty(),
                "case '{}' missing rationale",
                case.input
            );
        }
    }

    #[test]
    fn corpus_no_duplicate_inputs() {
        let cases = get_workflow_confusion_cases();
        let mut seen = std::collections::HashSet::new();
        for case in &cases {
            assert!(
                seen.insert(case.input.clone()),
                "duplicate input: '{}'",
                case.input
            );
        }
    }

    #[test]
    fn corpus_ambiguous_intent_cases() {
        let cases = get_workflow_confusion_cases();
        let n = cases
            .iter()
            .filter(|c| c.expected_category == ConfusionCategory::AmbiguousIntent)
            .count();
        assert!(
            n >= 4,
            "AmbiguousIntent should have at least 4 cases, got {n}"
        );
    }

    #[test]
    fn corpus_stale_context_cases() {
        let cases = get_workflow_confusion_cases();
        let n = cases
            .iter()
            .filter(|c| c.expected_category == ConfusionCategory::StaleContext)
            .count();
        assert!(n >= 4, "StaleContext should have at least 4 cases, got {n}");
    }

    #[test]
    fn corpus_missing_fact_cases() {
        let cases = get_workflow_confusion_cases();
        let n = cases
            .iter()
            .filter(|c| c.expected_category == ConfusionCategory::MissingFact)
            .count();
        assert!(n >= 4, "MissingFact should have at least 4 cases, got {n}");
    }

    #[test]
    fn corpus_wrong_pinned_context_cases() {
        let cases = get_workflow_confusion_cases();
        let n = cases
            .iter()
            .filter(|c| c.expected_category == ConfusionCategory::WrongPinnedContext)
            .count();
        assert!(
            n >= 4,
            "WrongPinnedContext should have at least 4 cases, got {n}"
        );
    }

    #[test]
    fn corpus_broken_pipeline_cases() {
        let cases = get_workflow_confusion_cases();
        let n = cases
            .iter()
            .filter(|c| c.expected_category == ConfusionCategory::BrokenPipelineAssumption)
            .count();
        assert!(
            n >= 4,
            "BrokenPipelineAssumption should have at least 4 cases, got {n}"
        );
    }

    #[test]
    fn corpus_unsafe_macro_cases() {
        let cases = get_workflow_confusion_cases();
        let n = cases
            .iter()
            .filter(|c| c.expected_category == ConfusionCategory::UnsafeMacroExpansion)
            .count();
        assert!(
            n >= 3,
            "UnsafeMacroExpansion should have at least 3 cases, got {n}"
        );
    }

    #[test]
    fn corpus_interrupted_workflow_cases() {
        let cases = get_workflow_confusion_cases();
        let n = cases
            .iter()
            .filter(|c| c.expected_category == ConfusionCategory::InterruptedWorkflow)
            .count();
        assert!(
            n >= 3,
            "InterruptedWorkflow should have at least 3 cases, got {n}"
        );
    }

    #[test]
    fn corpus_blocked_approval_cases() {
        let cases = get_workflow_confusion_cases();
        let n = cases
            .iter()
            .filter(|c| c.expected_category == ConfusionCategory::BlockedApproval)
            .count();
        assert!(
            n >= 4,
            "BlockedApproval should have at least 4 cases, got {n}"
        );
    }

    #[test]
    fn corpus_partial_completion_cases() {
        let cases = get_workflow_confusion_cases();
        let n = cases
            .iter()
            .filter(|c| c.expected_category == ConfusionCategory::PartialCompletion)
            .count();
        assert!(
            n >= 4,
            "PartialCompletion should have at least 4 cases, got {n}"
        );
    }

    // ── Classification accuracy ─────────────────────────────────────

    #[test]
    fn classify_empty_input() {
        assert_eq!(classify_confusion(""), ConfusionCategory::AmbiguousIntent);
    }

    #[test]
    fn classify_short_input() {
        assert_eq!(classify_confusion("hi"), ConfusionCategory::AmbiguousIntent);
    }

    #[test]
    fn classify_skip_step() {
        assert_eq!(
            classify_confusion("skip step 3 and go to step 5"),
            ConfusionCategory::BrokenPipelineAssumption
        );
    }

    #[test]
    fn classify_tests_before_build() {
        assert_eq!(
            classify_confusion("run the tests before the build"),
            ConfusionCategory::BrokenPipelineAssumption
        );
    }

    #[test]
    fn classify_deploy_without_building() {
        assert_eq!(
            classify_confusion("deploy without building"),
            ConfusionCategory::BrokenPipelineAssumption
        );
    }

    #[test]
    fn classify_merge_and_then_ci() {
        assert_eq!(
            classify_confusion("merge and then run CI"),
            ConfusionCategory::BrokenPipelineAssumption
        );
    }

    #[test]
    fn classify_approve() {
        assert_eq!(
            classify_confusion("just approve it already"),
            ConfusionCategory::BlockedApproval
        );
    }

    #[test]
    fn classify_skip_approval() {
        assert_eq!(
            classify_confusion("skip the approval step"),
            ConfusionCategory::BlockedApproval
        );
    }

    #[test]
    fn classify_force_deploy_without_review() {
        assert_eq!(
            classify_confusion("force deploy to prod without review"),
            ConfusionCategory::BlockedApproval
        );
    }

    #[test]
    fn classify_override_safety() {
        assert_eq!(
            classify_confusion("override the safety check"),
            ConfusionCategory::BlockedApproval
        );
    }

    #[test]
    fn classify_template_wildcard() {
        assert_eq!(
            classify_confusion("run template deploy-all with target='*'"),
            ConfusionCategory::UnsafeMacroExpansion
        );
    }

    #[test]
    fn classify_expand_secret() {
        assert_eq!(
            classify_confusion("expand {{env.SECRET_KEY}} in the config"),
            ConfusionCategory::UnsafeMacroExpansion
        );
    }

    #[test]
    fn classify_apply_macro() {
        assert_eq!(
            classify_confusion("apply macro delete-all-users"),
            ConfusionCategory::UnsafeMacroExpansion
        );
    }

    #[test]
    fn classify_partial_import() {
        assert_eq!(
            classify_confusion("clean up the partial import"),
            ConfusionCategory::PartialCompletion
        );
    }

    #[test]
    fn classify_failed_ones() {
        assert_eq!(
            classify_confusion("retry the failed ones"),
            ConfusionCategory::PartialCompletion
        );
    }

    #[test]
    fn classify_the_batch() {
        assert_eq!(
            classify_confusion("the batch is done"),
            ConfusionCategory::PartialCompletion
        );
    }

    #[test]
    fn classify_finish_the_migration() {
        assert_eq!(
            classify_confusion("finish the migration"),
            ConfusionCategory::InterruptedWorkflow
        );
    }

    #[test]
    fn classify_complete_onboarding() {
        assert_eq!(
            classify_confusion("complete the onboarding flow"),
            ConfusionCategory::InterruptedWorkflow
        );
    }

    #[test]
    fn classify_pick_up_where() {
        assert_eq!(
            classify_confusion("pick up where the import stopped"),
            ConfusionCategory::InterruptedWorkflow
        );
    }

    #[test]
    fn classify_continue_sync_crashed() {
        assert_eq!(
            classify_confusion("continue the sync that crashed"),
            ConfusionCategory::InterruptedWorkflow
        );
    }

    #[test]
    fn classify_last_thing() {
        assert_eq!(
            classify_confusion("redo the last thing"),
            ConfusionCategory::StaleContext
        );
    }

    #[test]
    fn classify_left_off() {
        assert_eq!(
            classify_confusion("continue where I left off"),
            ConfusionCategory::StaleContext
        );
    }

    #[test]
    fn classify_same_settings_as_before() {
        assert_eq!(
            classify_confusion("use the same settings as before"),
            ConfusionCategory::StaleContext
        );
    }

    #[test]
    fn classify_from_yesterday() {
        assert_eq!(
            classify_confusion("apply the fix from yesterday"),
            ConfusionCategory::StaleContext
        );
    }

    #[test]
    fn classify_old_parameters() {
        assert_eq!(
            classify_confusion("rerun with the old parameters"),
            ConfusionCategory::StaleContext
        );
    }

    #[test]
    fn classify_list_issues() {
        assert_eq!(
            classify_confusion("list issues"),
            ConfusionCategory::WrongPinnedContext
        );
    }

    #[test]
    fn classify_create_channel() {
        assert_eq!(
            classify_confusion("create a channel"),
            ConfusionCategory::WrongPinnedContext
        );
    }

    #[test]
    fn classify_terraform() {
        assert_eq!(
            classify_confusion("run terraform plan"),
            ConfusionCategory::WrongPinnedContext
        );
    }

    #[test]
    fn classify_task_reference() {
        assert_eq!(
            classify_confusion("update task #42"),
            ConfusionCategory::MissingFact
        );
    }

    #[test]
    fn classify_batch_reference() {
        assert_eq!(
            classify_confusion("resume batch job batch-99"),
            ConfusionCategory::MissingFact
        );
    }

    #[test]
    fn classify_nightly_build() {
        assert_eq!(
            classify_confusion("show me the results from the nightly build"),
            ConfusionCategory::MissingFact
        );
    }

    #[test]
    fn classify_roll_back() {
        assert_eq!(
            classify_confusion("roll back the migration"),
            ConfusionCategory::MissingFact
        );
    }

    #[test]
    fn classify_pipeline_nonexistent_step() {
        assert_eq!(
            classify_confusion("pipeline run my-pipe step=nonexistent"),
            ConfusionCategory::BrokenPipelineAssumption
        );
    }

    #[test]
    fn classify_validation_after_cleanup() {
        assert_eq!(
            classify_confusion("run validation after cleanup"),
            ConfusionCategory::BrokenPipelineAssumption
        );
    }

    // ── Recovery suggestions ────────────────────────────────────────

    #[test]
    fn recovery_ambiguous_intent() {
        assert_eq!(
            suggest_recovery(ConfusionCategory::AmbiguousIntent),
            RecoveryAction::AskForClarification
        );
    }

    #[test]
    fn recovery_stale_context() {
        assert_eq!(
            suggest_recovery(ConfusionCategory::StaleContext),
            RecoveryAction::ShowCurrentState
        );
    }

    #[test]
    fn recovery_missing_fact() {
        assert_eq!(
            suggest_recovery(ConfusionCategory::MissingFact),
            RecoveryAction::SuggestAlternative
        );
    }

    #[test]
    fn recovery_wrong_pinned() {
        assert_eq!(
            suggest_recovery(ConfusionCategory::WrongPinnedContext),
            RecoveryAction::ShowCurrentState
        );
    }

    #[test]
    fn recovery_broken_pipeline() {
        assert_eq!(
            suggest_recovery(ConfusionCategory::BrokenPipelineAssumption),
            RecoveryAction::AbortWithExplanation
        );
    }

    #[test]
    fn recovery_unsafe_macro() {
        assert_eq!(
            suggest_recovery(ConfusionCategory::UnsafeMacroExpansion),
            RecoveryAction::AbortWithExplanation
        );
    }

    #[test]
    fn recovery_interrupted() {
        assert_eq!(
            suggest_recovery(ConfusionCategory::InterruptedWorkflow),
            RecoveryAction::ShowCurrentState
        );
    }

    #[test]
    fn recovery_blocked_approval() {
        assert_eq!(
            suggest_recovery(ConfusionCategory::BlockedApproval),
            RecoveryAction::EscalateToHuman
        );
    }

    #[test]
    fn recovery_partial_completion() {
        assert_eq!(
            suggest_recovery(ConfusionCategory::PartialCompletion),
            RecoveryAction::ShowCurrentState
        );
    }

    // ── Format output ───────────────────────────────────────────────

    #[test]
    fn format_guidance_contains_category() {
        let case = ConfusionCase {
            input: "test input".into(),
            expected_category: ConfusionCategory::AmbiguousIntent,
            expected_recovery: RecoveryAction::AskForClarification,
            rationale: "test rationale".into(),
        };
        let guidance = format_recovery_guidance(&case);
        assert!(guidance.contains("ambiguous-intent"));
    }

    #[test]
    fn format_guidance_contains_input() {
        let case = ConfusionCase {
            input: "my confusing input".into(),
            expected_category: ConfusionCategory::StaleContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "context expired".into(),
        };
        let guidance = format_recovery_guidance(&case);
        assert!(guidance.contains("my confusing input"));
    }

    #[test]
    fn format_guidance_contains_rationale() {
        let case = ConfusionCase {
            input: "test".into(),
            expected_category: ConfusionCategory::MissingFact,
            expected_recovery: RecoveryAction::SuggestAlternative,
            rationale: "entity does not exist".into(),
        };
        let guidance = format_recovery_guidance(&case);
        assert!(guidance.contains("entity does not exist"));
    }

    #[test]
    fn format_guidance_contains_recovery() {
        let case = ConfusionCase {
            input: "test".into(),
            expected_category: ConfusionCategory::BlockedApproval,
            expected_recovery: RecoveryAction::EscalateToHuman,
            rationale: "needs human".into(),
        };
        let guidance = format_recovery_guidance(&case);
        assert!(guidance.contains("escalate-to-human"));
    }

    #[test]
    fn format_guidance_contains_template() {
        let case = ConfusionCase {
            input: "test".into(),
            expected_category: ConfusionCategory::InterruptedWorkflow,
            expected_recovery: RecoveryAction::RetryWithDefaults,
            rationale: "interrupted".into(),
        };
        let guidance = format_recovery_guidance(&case);
        assert!(guidance.contains("safe defaults"));
    }

    #[test]
    fn format_guidance_multiline() {
        let case = &get_workflow_confusion_cases()[0];
        let guidance = format_recovery_guidance(case);
        let line_count = guidance.lines().count();
        assert!(
            line_count >= 4,
            "guidance should be multi-line, got {line_count}"
        );
    }

    // ── Category/RecoveryAction enum properties ─────────────────────

    #[test]
    fn category_all_count() {
        assert_eq!(ConfusionCategory::all().len(), 9);
    }

    #[test]
    fn category_labels_unique() {
        let labels: Vec<&str> = ConfusionCategory::all().iter().map(|c| c.label()).collect();
        let set: std::collections::HashSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), set.len());
    }

    #[test]
    fn category_explanations_nonempty() {
        for cat in ConfusionCategory::all() {
            assert!(!cat.explanation().is_empty());
        }
    }

    #[test]
    fn category_display() {
        assert_eq!(
            format!("{}", ConfusionCategory::AmbiguousIntent),
            "ambiguous-intent"
        );
        assert_eq!(
            format!("{}", ConfusionCategory::PartialCompletion),
            "partial-completion"
        );
    }

    #[test]
    fn recovery_all_count() {
        assert_eq!(RecoveryAction::all().len(), 6);
    }

    #[test]
    fn recovery_labels_unique() {
        let labels: Vec<&str> = RecoveryAction::all().iter().map(|a| a.label()).collect();
        let set: std::collections::HashSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), set.len());
    }

    #[test]
    fn recovery_guidance_templates_nonempty() {
        for act in RecoveryAction::all() {
            assert!(!act.guidance_template().is_empty());
        }
    }

    #[test]
    fn recovery_display() {
        assert_eq!(
            format!("{}", RecoveryAction::AskForClarification),
            "ask-for-clarification"
        );
        assert_eq!(
            format!("{}", RecoveryAction::EscalateToHuman),
            "escalate-to-human"
        );
    }

    // ── count_by_category / count_by_recovery ───────────────────────

    #[test]
    fn count_by_category_covers_all() {
        let cases = get_workflow_confusion_cases();
        let counts = count_by_category(&cases);
        assert_eq!(counts.len(), ConfusionCategory::all().len());
        let total: usize = counts.iter().map(|(_, n)| n).sum();
        assert_eq!(total, cases.len());
    }

    #[test]
    fn count_by_category_sorted_descending() {
        let cases = get_workflow_confusion_cases();
        let counts = count_by_category(&cases);
        for w in counts.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn count_by_recovery_covers_all() {
        let cases = get_workflow_confusion_cases();
        let counts = count_by_recovery(&cases);
        assert_eq!(counts.len(), RecoveryAction::all().len());
        let total: usize = counts.iter().map(|(_, n)| n).sum();
        assert_eq!(total, cases.len());
    }

    #[test]
    fn count_by_recovery_sorted_descending() {
        let cases = get_workflow_confusion_cases();
        let counts = count_by_recovery(&cases);
        for w in counts.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    // ── Serialization round-trip ────────────────────────────────────

    #[test]
    fn serde_confusion_category_roundtrip() {
        for cat in ConfusionCategory::all() {
            let json = serde_json::to_string(cat).unwrap();
            let back: ConfusionCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    #[test]
    fn serde_recovery_action_roundtrip() {
        for act in RecoveryAction::all() {
            let json = serde_json::to_string(act).unwrap();
            let back: RecoveryAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*act, back);
        }
    }

    #[test]
    fn serde_confusion_case_roundtrip() {
        let case = ConfusionCase {
            input: "test input".into(),
            expected_category: ConfusionCategory::StaleContext,
            expected_recovery: RecoveryAction::ShowCurrentState,
            rationale: "context lost".into(),
        };
        let json = serde_json::to_string(&case).unwrap();
        let back: ConfusionCase = serde_json::from_str(&json).unwrap();
        assert_eq!(back.input, "test input");
        assert_eq!(back.expected_category, ConfusionCategory::StaleContext);
        assert_eq!(back.expected_recovery, RecoveryAction::ShowCurrentState);
    }

    #[test]
    fn serde_full_corpus_roundtrip() {
        let cases = get_workflow_confusion_cases();
        let json = serde_json::to_string(&cases).unwrap();
        let back: Vec<ConfusionCase> = serde_json::from_str(&json).unwrap();
        assert_eq!(cases.len(), back.len());
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn classify_whitespace_only() {
        assert_eq!(
            classify_confusion("   "),
            ConfusionCategory::AmbiguousIntent
        );
    }

    #[test]
    fn classify_single_char() {
        assert_eq!(classify_confusion("x"), ConfusionCategory::AmbiguousIntent);
    }

    #[test]
    fn classify_mixed_case() {
        assert_eq!(
            classify_confusion("SKIP STEP 3"),
            ConfusionCategory::BrokenPipelineAssumption
        );
    }

    #[test]
    fn classify_mixed_case_approve() {
        assert_eq!(
            classify_confusion("Just Approve It"),
            ConfusionCategory::BlockedApproval
        );
    }

    #[test]
    fn classify_unknown_input() {
        assert_eq!(
            classify_confusion("wobble wobble flibberty"),
            ConfusionCategory::AmbiguousIntent
        );
    }

    #[test]
    fn format_all_corpus_cases_no_panic() {
        let cases = get_workflow_confusion_cases();
        for case in &cases {
            let _ = format_recovery_guidance(case);
        }
    }

    #[test]
    fn classify_all_corpus_cases_no_panic() {
        let cases = get_workflow_confusion_cases();
        for case in &cases {
            let _ = classify_confusion(&case.input);
        }
    }

    #[test]
    fn suggest_recovery_all_categories_no_panic() {
        for cat in ConfusionCategory::all() {
            let _ = suggest_recovery(*cat);
        }
    }
}
