//! Prerequisite onboarding, repair, and drift detection for connectors.
//!
//! Manages the full lifecycle of connector prerequisites: checking readiness,
//! generating onboarding workflows, detecting configuration drift, planning
//! and executing repairs, and running verification matrices.

use serde::{Deserialize, Serialize};

// ── Prerequisite Descriptor ──────────────────────────────────────

/// Kind of prerequisite required by a connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrerequisiteKind {
    /// A service account with appropriate permissions.
    ServiceAccount,
    /// An API key or token.
    ApiKey,
    /// An OAuth application registration.
    #[serde(rename = "oauth_app")]
    OAuthApp,
    /// A webhook endpoint configuration.
    Webhook,
    /// An external resource (database, bucket, etc.).
    Resource,
    /// Custom prerequisite type.
    Custom,
}

impl PrerequisiteKind {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::ServiceAccount => "Service Account",
            Self::ApiKey => "API Key",
            Self::OAuthApp => "OAuth App",
            Self::Webhook => "Webhook",
            Self::Resource => "Resource",
            Self::Custom => "Custom",
        }
    }
}

impl std::fmt::Display for PrerequisiteKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Describes a single prerequisite for a connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrerequisiteDescriptor {
    /// Unique name of this prerequisite.
    pub name: String,
    /// Kind of prerequisite.
    pub kind: PrerequisiteKind,
    /// Whether the connector cannot function without this.
    pub required: bool,
    /// Human-readable description.
    pub description: String,
    /// Optional command to check if this prerequisite is satisfied.
    pub check_command: Option<String>,
}

impl PrerequisiteDescriptor {
    /// Create a new required prerequisite.
    pub fn required(name: &str, kind: PrerequisiteKind, description: &str) -> Self {
        Self {
            name: name.to_string(),
            kind,
            required: true,
            description: description.to_string(),
            check_command: None,
        }
    }

    /// Create a new optional prerequisite.
    pub fn optional(name: &str, kind: PrerequisiteKind, description: &str) -> Self {
        Self {
            name: name.to_string(),
            kind,
            required: false,
            description: description.to_string(),
            check_command: None,
        }
    }

    /// Set the check command.
    pub fn with_check_command(mut self, cmd: &str) -> Self {
        self.check_command = Some(cmd.to_string());
        self
    }
}

// ── Prerequisite Status ──────────────────────────────────────────

/// Status of a checked prerequisite.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrerequisiteStatus {
    /// Prerequisite is fully satisfied.
    Satisfied,
    /// Prerequisite is missing entirely.
    Missing,
    /// Prerequisite exists but has expired (e.g., token, cert).
    Expired,
    /// Prerequisite exists but is in a degraded state.
    Degraded,
    /// Unable to determine status.
    Unknown,
}

impl PrerequisiteStatus {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Missing => "missing",
            Self::Expired => "expired",
            Self::Degraded => "degraded",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this status indicates a healthy prerequisite.
    pub const fn is_healthy(self) -> bool {
        matches!(self, Self::Satisfied)
    }

    /// Whether this status is actionable (can attempt repair).
    pub const fn is_actionable(self) -> bool {
        matches!(self, Self::Missing | Self::Expired | Self::Degraded)
    }

    /// TOON symbol for this status.
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Satisfied => "[ok]",
            Self::Missing => "[!!]",
            Self::Expired => "[EX]",
            Self::Degraded => "[~~]",
            Self::Unknown => "[??]",
        }
    }
}

impl std::fmt::Display for PrerequisiteStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ── Prerequisite Check ───────────────────────────────────────────

/// Result of checking a single prerequisite.
#[derive(Clone, Debug, Serialize)]
pub struct PrerequisiteCheck {
    /// The prerequisite that was checked.
    pub descriptor: PrerequisiteDescriptor,
    /// Resulting status.
    pub status: PrerequisiteStatus,
    /// Diagnostic message.
    pub message: String,
    /// When the check was performed (ISO 8601).
    pub checked_at: String,
    /// Suggested remediation if not satisfied.
    pub remediation: Option<String>,
}

impl PrerequisiteCheck {
    /// Create a satisfied check result.
    pub fn satisfied(descriptor: PrerequisiteDescriptor, checked_at: &str) -> Self {
        Self {
            message: format!("{} is available and valid", descriptor.name),
            descriptor,
            status: PrerequisiteStatus::Satisfied,
            checked_at: checked_at.to_string(),
            remediation: None,
        }
    }

    /// Create a missing check result.
    pub fn missing(
        descriptor: PrerequisiteDescriptor,
        remediation: &str,
        checked_at: &str,
    ) -> Self {
        Self {
            message: format!("{} is not configured", descriptor.name),
            descriptor,
            status: PrerequisiteStatus::Missing,
            checked_at: checked_at.to_string(),
            remediation: Some(remediation.to_string()),
        }
    }

    /// Create an expired check result.
    pub fn expired(
        descriptor: PrerequisiteDescriptor,
        remediation: &str,
        checked_at: &str,
    ) -> Self {
        Self {
            message: format!("{} has expired", descriptor.name),
            descriptor,
            status: PrerequisiteStatus::Expired,
            checked_at: checked_at.to_string(),
            remediation: Some(remediation.to_string()),
        }
    }

    /// Create a degraded check result.
    pub fn degraded(
        descriptor: PrerequisiteDescriptor,
        message: &str,
        remediation: &str,
        checked_at: &str,
    ) -> Self {
        Self {
            message: message.to_string(),
            descriptor,
            status: PrerequisiteStatus::Degraded,
            checked_at: checked_at.to_string(),
            remediation: Some(remediation.to_string()),
        }
    }

    /// Create an unknown check result.
    pub fn unknown(descriptor: PrerequisiteDescriptor, message: &str, checked_at: &str) -> Self {
        Self {
            message: message.to_string(),
            descriptor,
            status: PrerequisiteStatus::Unknown,
            checked_at: checked_at.to_string(),
            remediation: None,
        }
    }
}

// ── Ready State ──────────────────────────────────────────────────

/// Aggregated readiness state for a connector.
#[derive(Clone, Debug, Serialize)]
pub struct ReadyState {
    /// Connector name.
    pub connector: String,
    /// Individual prerequisite check results.
    pub prerequisites: Vec<PrerequisiteCheck>,
    /// Whether the connector is fully ready.
    pub overall_ready: bool,
    /// Readiness score (0.0 = nothing ready, 1.0 = everything satisfied).
    pub score: f64,
}

impl ReadyState {
    /// Count of satisfied prerequisites.
    pub fn satisfied_count(&self) -> usize {
        self.prerequisites
            .iter()
            .filter(|p| p.status == PrerequisiteStatus::Satisfied)
            .count()
    }

    /// Count of required prerequisites that are not satisfied.
    pub fn blocking_count(&self) -> usize {
        self.prerequisites
            .iter()
            .filter(|p| p.descriptor.required && !p.status.is_healthy())
            .count()
    }

    /// Get all prerequisites that need attention.
    pub fn needs_attention(&self) -> Vec<&PrerequisiteCheck> {
        self.prerequisites
            .iter()
            .filter(|p| !p.status.is_healthy())
            .collect()
    }
}

// ── Onboarding ───────────────────────────────────────────────────

/// A single step in an onboarding workflow.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OnboardingStep {
    /// Step number (1-indexed).
    pub step_number: u32,
    /// Short action label.
    pub action: String,
    /// Detailed description of what to do.
    pub description: String,
    /// Whether this step blocks subsequent steps.
    pub blocking: bool,
    /// Whether this step has been completed.
    pub completed: bool,
    /// Whether this step can be skipped.
    pub skippable: bool,
}

impl OnboardingStep {
    /// Create a new blocking step.
    pub fn blocking(step_number: u32, action: &str, description: &str) -> Self {
        Self {
            step_number,
            action: action.to_string(),
            description: description.to_string(),
            blocking: true,
            completed: false,
            skippable: false,
        }
    }

    /// Create a new optional (skippable) step.
    pub fn skippable(step_number: u32, action: &str, description: &str) -> Self {
        Self {
            step_number,
            action: action.to_string(),
            description: description.to_string(),
            blocking: false,
            completed: false,
            skippable: true,
        }
    }
}

/// A guided onboarding workflow for a connector.
#[derive(Clone, Debug, Serialize)]
pub struct OnboardingWorkflow {
    /// Connector name.
    pub connector: String,
    /// Ordered steps.
    pub steps: Vec<OnboardingStep>,
    /// Current step index (0-based, None if completed or not started).
    pub current_step: Option<usize>,
    /// Whether the workflow is fully completed.
    pub completed: bool,
}

impl OnboardingWorkflow {
    /// Advance to the next incomplete step.
    pub fn advance(&mut self) {
        if let Some(current) = self.current_step {
            if current < self.steps.len() {
                self.steps[current].completed = true;
            }
            self.advance_to_next_incomplete();
        }
    }

    /// Skip the current step if it is skippable.
    pub fn skip_current(&mut self) -> bool {
        if let Some(current) = self.current_step {
            if current < self.steps.len() && self.steps[current].skippable {
                self.steps[current].completed = true;
                self.advance_to_next_incomplete();
                return true;
            }
        }
        false
    }

    /// Move `current_step` to the next incomplete step (internal helper).
    fn advance_to_next_incomplete(&mut self) {
        let next = self.steps.iter().position(|s| !s.completed);
        self.current_step = next;
        if next.is_none() {
            self.completed = true;
        }
    }

    /// Progress ratio (0.0..1.0).
    pub fn progress(&self) -> f64 {
        if self.steps.is_empty() {
            return 1.0;
        }
        let done = self.steps.iter().filter(|s| s.completed).count();
        done as f64 / self.steps.len() as f64
    }

    /// Count of remaining steps.
    pub fn remaining_steps(&self) -> usize {
        self.steps.iter().filter(|s| !s.completed).count()
    }
}

// ── Repair ───────────────────────────────────────────────────────

/// Type of repair action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepairActionType {
    /// Install a missing prerequisite.
    Install,
    /// Refresh an expired credential or resource.
    Refresh,
    /// Reconfigure an existing prerequisite.
    Reconfigure,
    /// Replace a broken prerequisite entirely.
    Replace,
}

impl RepairActionType {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Refresh => "refresh",
            Self::Reconfigure => "reconfigure",
            Self::Replace => "replace",
        }
    }
}

impl std::fmt::Display for RepairActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A single repair action for a broken prerequisite.
#[derive(Clone, Debug, Serialize)]
pub struct RepairAction {
    /// Name of the prerequisite to repair.
    pub prerequisite: String,
    /// Type of repair.
    pub action_type: RepairActionType,
    /// Whether this action can be undone.
    pub reversible: bool,
    /// Whether this action is safe to dry-run without side effects.
    pub dry_run_safe: bool,
    /// Description of what the action will do.
    pub description: String,
}

/// Result of executing a repair plan.
#[derive(Clone, Debug, Serialize)]
pub struct RepairResult {
    /// Actions that were taken.
    pub actions_taken: Vec<RepairAction>,
    /// Number of prerequisites that were fixed.
    pub prerequisites_fixed: usize,
    /// Names of prerequisites still broken after repair.
    pub still_broken: Vec<String>,
    /// Whether this was a dry-run.
    pub dry_run: bool,
}

impl RepairResult {
    /// Whether all broken prerequisites were fixed.
    pub fn all_fixed(&self) -> bool {
        self.still_broken.is_empty()
    }

    /// Total actions attempted.
    pub fn total_actions(&self) -> usize {
        self.actions_taken.len()
    }
}

// ── Drift Detection ──────────────────────────────────────────────

/// Severity of a drift entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftSeverity {
    /// Cosmetic or informational drift.
    Low,
    /// Functional but not ideal.
    Medium,
    /// Service-impacting drift.
    High,
    /// Critical drift requiring immediate action.
    Critical,
}

impl DriftSeverity {
    /// Human-readable label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl std::fmt::Display for DriftSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A single drift entry describing a deviation from expected state.
#[derive(Clone, Debug, Serialize)]
pub struct DriftEntry {
    /// Name of the prerequisite that drifted.
    pub prerequisite: String,
    /// The status we expected.
    pub expected_status: PrerequisiteStatus,
    /// The status we actually observed.
    pub actual_status: PrerequisiteStatus,
    /// When drift was first observed (ISO 8601).
    pub first_seen: String,
    /// Severity of this drift.
    pub severity: DriftSeverity,
}

impl DriftEntry {
    /// Whether this drift entry represents a mismatch.
    pub fn is_drifted(&self) -> bool {
        self.expected_status != self.actual_status
    }
}

/// Drift report for a connector.
#[derive(Clone, Debug, Serialize)]
pub struct DriftReport {
    /// Connector name.
    pub connector: String,
    /// Individual drift entries.
    pub entries: Vec<DriftEntry>,
    /// Overall drift score (0.0 = no drift, 1.0 = everything drifted).
    pub overall_drift_score: f64,
}

impl DriftReport {
    /// Whether any drift was detected.
    pub fn has_drift(&self) -> bool {
        self.entries.iter().any(DriftEntry::is_drifted)
    }

    /// Count of drifted entries.
    pub fn drift_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_drifted()).count()
    }

    /// Highest severity among all drifted entries.
    pub fn max_severity(&self) -> Option<DriftSeverity> {
        self.entries
            .iter()
            .filter(|e| e.is_drifted())
            .map(|e| e.severity)
            .max()
    }
}

// ── Verification Matrix ──────────────────────────────────────────

/// Expected outcome in a verification test case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// Test case should pass.
    Pass,
    /// Test case should fail.
    Fail,
    /// Test case should be skipped.
    Skip,
}

impl VerificationOutcome {
    /// Label for display.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }
}

impl std::fmt::Display for VerificationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A single test case in the verification matrix.
#[derive(Clone, Debug, Serialize)]
pub struct VerificationCase {
    /// Scenario name.
    pub scenario: String,
    /// The prerequisite being tested.
    pub prerequisite: String,
    /// Expected outcome for this scenario.
    pub expected: VerificationOutcome,
    /// Actual outcome after running.
    pub actual: Option<VerificationOutcome>,
    /// Diagnostic message.
    pub message: Option<String>,
}

impl VerificationCase {
    /// Whether this case passed its expected outcome.
    pub fn passed(&self) -> bool {
        self.actual == Some(self.expected)
    }

    /// Whether this case has been evaluated.
    pub const fn is_evaluated(&self) -> bool {
        self.actual.is_some()
    }
}

/// A full verification matrix for a connector's prerequisites.
#[derive(Clone, Debug, Serialize)]
pub struct VerificationMatrix {
    /// Connector name.
    pub connector: String,
    /// Test cases.
    pub cases: Vec<VerificationCase>,
}

impl VerificationMatrix {
    /// Count of passing cases.
    pub fn pass_count(&self) -> usize {
        self.cases.iter().filter(|c| c.passed()).count()
    }

    /// Count of failing cases.
    pub fn fail_count(&self) -> usize {
        self.cases
            .iter()
            .filter(|c| c.is_evaluated() && !c.passed())
            .count()
    }

    /// Count of unevaluated cases.
    pub fn pending_count(&self) -> usize {
        self.cases.iter().filter(|c| !c.is_evaluated()).count()
    }

    /// Overall pass rate (0.0..1.0).
    pub fn pass_rate(&self) -> f64 {
        let evaluated = self.cases.iter().filter(|c| c.is_evaluated()).count();
        if evaluated == 0 {
            return 0.0;
        }
        self.pass_count() as f64 / evaluated as f64
    }

    /// Whether all evaluated cases passed.
    pub fn all_passed(&self) -> bool {
        self.cases.iter().all(|c| !c.is_evaluated() || c.passed())
    }
}

// ── Core Functions ───────────────────────────────────────────────

/// Check all prerequisites for a connector.
///
/// Evaluates each descriptor and returns a `PrerequisiteCheck` with the
/// current status. In a real implementation, `check_command` would be
/// executed; here we simulate via the `checker` callback.
pub fn check_prerequisites<F>(
    descriptors: &[PrerequisiteDescriptor],
    checked_at: &str,
    checker: F,
) -> Vec<PrerequisiteCheck>
where
    F: Fn(&PrerequisiteDescriptor) -> (PrerequisiteStatus, Option<String>),
{
    descriptors
        .iter()
        .map(|desc| {
            let (status, remediation) = checker(desc);
            let message = match status {
                PrerequisiteStatus::Satisfied => {
                    format!("{} is available and valid", desc.name)
                }
                PrerequisiteStatus::Missing => {
                    format!("{} is not configured", desc.name)
                }
                PrerequisiteStatus::Expired => {
                    format!("{} has expired", desc.name)
                }
                PrerequisiteStatus::Degraded => {
                    format!("{} is in a degraded state", desc.name)
                }
                PrerequisiteStatus::Unknown => {
                    format!("Cannot determine status of {}", desc.name)
                }
            };
            PrerequisiteCheck {
                descriptor: desc.clone(),
                status,
                message,
                checked_at: checked_at.to_string(),
                remediation,
            }
        })
        .collect()
}

/// Aggregate prerequisite checks into a `ReadyState`.
pub fn build_ready_state(connector: &str, checks: Vec<PrerequisiteCheck>) -> ReadyState {
    let total = checks.len();
    let satisfied = checks
        .iter()
        .filter(|c| c.status == PrerequisiteStatus::Satisfied)
        .count();

    let score = if total == 0 {
        1.0
    } else {
        satisfied as f64 / total as f64
    };

    let overall_ready = checks
        .iter()
        .all(|c| c.status.is_healthy() || !c.descriptor.required);

    ReadyState {
        connector: connector.to_string(),
        prerequisites: checks,
        overall_ready,
        score,
    }
}

/// Generate a guided onboarding workflow for a connector based on its prerequisites.
pub fn generate_onboarding_workflow(
    connector: &str,
    descriptors: &[PrerequisiteDescriptor],
) -> OnboardingWorkflow {
    let mut steps = Vec::new();
    let mut step_num = 1u32;

    // First: required prerequisites in order.
    for desc in descriptors.iter().filter(|d| d.required) {
        let action = match desc.kind {
            PrerequisiteKind::ServiceAccount => format!("Create {}", desc.name),
            PrerequisiteKind::ApiKey => format!("Generate {}", desc.name),
            PrerequisiteKind::OAuthApp => format!("Register {}", desc.name),
            PrerequisiteKind::Webhook => format!("Configure {}", desc.name),
            PrerequisiteKind::Resource => format!("Provision {}", desc.name),
            PrerequisiteKind::Custom => format!("Set up {}", desc.name),
        };
        steps.push(OnboardingStep::blocking(
            step_num,
            &action,
            &desc.description,
        ));
        step_num += 1;
    }

    // Then: optional prerequisites.
    for desc in descriptors.iter().filter(|d| !d.required) {
        let action = format!("(Optional) Set up {}", desc.name);
        steps.push(OnboardingStep::skippable(
            step_num,
            &action,
            &desc.description,
        ));
        step_num += 1;
    }

    // Final verification step.
    steps.push(OnboardingStep::blocking(
        step_num,
        "Verify readiness",
        "Run prerequisite checks to confirm all requirements are met",
    ));

    let current_step = if steps.is_empty() { None } else { Some(0) };

    OnboardingWorkflow {
        connector: connector.to_string(),
        steps,
        current_step,
        completed: false,
    }
}

/// Detect drift between expected and actual prerequisite states.
pub fn detect_drift(connector: &str, checks: &[PrerequisiteCheck], now: &str) -> DriftReport {
    let mut entries = Vec::new();

    for check in checks {
        let expected = PrerequisiteStatus::Satisfied;
        let actual = check.status;

        if expected != actual {
            let severity = match (check.descriptor.required, actual) {
                (true, PrerequisiteStatus::Missing) => DriftSeverity::Critical,
                (true, PrerequisiteStatus::Expired | PrerequisiteStatus::Degraded) => {
                    DriftSeverity::High
                }
                (true, PrerequisiteStatus::Unknown)
                | (false, PrerequisiteStatus::Missing | PrerequisiteStatus::Expired) => {
                    DriftSeverity::Medium
                }
                (false, PrerequisiteStatus::Degraded | PrerequisiteStatus::Unknown) => {
                    DriftSeverity::Low
                }
                // Satisfied vs Satisfied is not a drift.
                (_, PrerequisiteStatus::Satisfied) => DriftSeverity::Low,
            };

            entries.push(DriftEntry {
                prerequisite: check.descriptor.name.clone(),
                expected_status: expected,
                actual_status: actual,
                first_seen: now.to_string(),
                severity,
            });
        }
    }

    let total = checks.len();
    let drifted = entries.len();
    let overall_drift_score = if total == 0 {
        0.0
    } else {
        drifted as f64 / total as f64
    };

    DriftReport {
        connector: connector.to_string(),
        entries,
        overall_drift_score,
    }
}

/// Plan repair actions for broken prerequisites (supports `dry_run`).
pub fn plan_repair(checks: &[PrerequisiteCheck], dry_run: bool) -> Vec<RepairAction> {
    let mut actions = Vec::new();

    for check in checks {
        if check.status.is_healthy() {
            continue;
        }

        let (action_type, reversible) = match check.status {
            PrerequisiteStatus::Missing => (RepairActionType::Install, false),
            PrerequisiteStatus::Expired => (RepairActionType::Refresh, true),
            PrerequisiteStatus::Degraded => (RepairActionType::Reconfigure, true),
            PrerequisiteStatus::Unknown => (RepairActionType::Replace, false),
            PrerequisiteStatus::Satisfied => unreachable!(),
        };

        let description = match action_type {
            RepairActionType::Install => {
                format!("Install missing prerequisite: {}", check.descriptor.name)
            }
            RepairActionType::Refresh => {
                format!("Refresh expired prerequisite: {}", check.descriptor.name)
            }
            RepairActionType::Reconfigure => {
                format!(
                    "Reconfigure degraded prerequisite: {}",
                    check.descriptor.name
                )
            }
            RepairActionType::Replace => {
                format!(
                    "Replace prerequisite with unknown status: {}",
                    check.descriptor.name
                )
            }
        };

        actions.push(RepairAction {
            prerequisite: check.descriptor.name.clone(),
            action_type,
            reversible,
            dry_run_safe: dry_run,
            description,
        });
    }

    actions
}

/// Execute repair actions and return the result.
///
/// In dry-run mode, actions are planned but not executed. The `executor`
/// callback performs the actual repair; it returns `true` if the repair
/// succeeded.
pub fn apply_repair<F>(checks: &[PrerequisiteCheck], dry_run: bool, executor: F) -> RepairResult
where
    F: Fn(&RepairAction) -> bool,
{
    let actions = plan_repair(checks, dry_run);
    let mut fixed = 0usize;
    let mut still_broken = Vec::new();
    let mut taken = Vec::new();

    for action in actions {
        if dry_run {
            // In dry-run mode, we plan but don't execute.
            still_broken.push(action.prerequisite.clone());
        } else {
            let success = executor(&action);
            if success {
                fixed += 1;
            } else {
                still_broken.push(action.prerequisite.clone());
            }
        }
        taken.push(action);
    }

    RepairResult {
        actions_taken: taken,
        prerequisites_fixed: fixed,
        still_broken,
        dry_run,
    }
}

/// Run the verification matrix against current prerequisite state.
///
/// The `verifier` callback evaluates each case and returns the actual outcome.
pub fn verify_prerequisites<F>(
    connector: &str,
    cases: Vec<VerificationCase>,
    verifier: F,
) -> VerificationMatrix
where
    F: Fn(&VerificationCase) -> (VerificationOutcome, Option<String>),
{
    let evaluated: Vec<VerificationCase> = cases
        .into_iter()
        .map(|mut c| {
            let (outcome, msg) = verifier(&c);
            c.actual = Some(outcome);
            c.message = msg;
            c
        })
        .collect();

    VerificationMatrix {
        connector: connector.to_string(),
        cases: evaluated,
    }
}

/// Build a standard verification matrix for a set of prerequisite descriptors.
pub fn build_verification_cases(descriptors: &[PrerequisiteDescriptor]) -> Vec<VerificationCase> {
    let mut cases = Vec::new();

    for desc in descriptors {
        // Happy path: prerequisite should be satisfied.
        cases.push(VerificationCase {
            scenario: format!("{}_present", desc.name),
            prerequisite: desc.name.clone(),
            expected: VerificationOutcome::Pass,
            actual: None,
            message: None,
        });

        // Negative path: prerequisite missing should fail if required.
        if desc.required {
            cases.push(VerificationCase {
                scenario: format!("{}_missing_required", desc.name),
                prerequisite: desc.name.clone(),
                expected: VerificationOutcome::Fail,
                actual: None,
                message: None,
            });
        }

        // Expiry path: expired should fail.
        cases.push(VerificationCase {
            scenario: format!("{}_expired", desc.name),
            prerequisite: desc.name.clone(),
            expected: VerificationOutcome::Fail,
            actual: None,
            message: None,
        });
    }

    cases
}

// ── TOON Formatters ──────────────────────────────────────────────

/// Format a `ReadyState` as TOON output lines.
pub fn format_ready_state_toon(state: &ReadyState) -> Vec<String> {
    let mut lines = Vec::new();

    let overall = if state.overall_ready {
        "READY"
    } else {
        "NOT READY"
    };
    lines.push(format!(
        "=== Prerequisite Readiness: {} ({}) ===",
        state.connector, overall
    ));
    lines.push(format!(
        "Score: {:.0}% ({}/{})",
        state.score * 100.0,
        state.satisfied_count(),
        state.prerequisites.len()
    ));
    lines.push(String::new());

    for check in &state.prerequisites {
        let req_marker = if check.descriptor.required {
            " [required]"
        } else {
            " [optional]"
        };
        lines.push(format!(
            "  {} {} ({}){}",
            check.status.symbol(),
            check.descriptor.name,
            check.descriptor.kind,
            req_marker
        ));
        lines.push(format!("      {}", check.message));
        if let Some(ref rem) = check.remediation {
            lines.push(format!("      -> {rem}"));
        }
    }

    if state.blocking_count() > 0 {
        lines.push(String::new());
        lines.push(format!(
            "!! {} blocking issue(s) must be resolved before use",
            state.blocking_count()
        ));
    }

    lines
}

/// Format an `OnboardingWorkflow` as TOON output lines.
pub fn format_onboarding_toon(workflow: &OnboardingWorkflow) -> Vec<String> {
    let mut lines = Vec::new();

    let status = if workflow.completed {
        "COMPLETED"
    } else {
        "IN PROGRESS"
    };
    lines.push(format!(
        "=== Onboarding: {} ({}) ===",
        workflow.connector, status
    ));
    lines.push(format!(
        "Progress: {:.0}% ({}/{})",
        workflow.progress() * 100.0,
        workflow.steps.iter().filter(|s| s.completed).count(),
        workflow.steps.len()
    ));
    lines.push(String::new());

    for (i, step) in workflow.steps.iter().enumerate() {
        let marker = if step.completed {
            "[x]"
        } else if workflow.current_step == Some(i) {
            "[>]"
        } else {
            "[ ]"
        };

        let skip_label = if step.skippable && !step.completed {
            " (skippable)"
        } else {
            ""
        };

        lines.push(format!(
            "  {} {}. {}{}",
            marker, step.step_number, step.action, skip_label
        ));
        lines.push(format!("      {}", step.description));
    }

    if let Some(remaining) = workflow
        .steps
        .len()
        .checked_sub(workflow.steps.iter().filter(|s| s.completed).count())
    {
        if remaining > 0 {
            lines.push(String::new());
            lines.push(format!("{remaining} step(s) remaining"));
        }
    }

    lines
}

/// Format a `DriftReport` as TOON output lines.
pub fn format_drift_toon(report: &DriftReport) -> Vec<String> {
    let mut lines = Vec::new();

    let status = if report.has_drift() {
        "DRIFT DETECTED"
    } else {
        "NO DRIFT"
    };
    lines.push(format!(
        "=== Drift Report: {} ({}) ===",
        report.connector, status
    ));
    lines.push(format!(
        "Drift Score: {:.0}% ({} drifted)",
        report.overall_drift_score * 100.0,
        report.drift_count()
    ));

    if report.entries.is_empty() {
        lines.push(String::new());
        lines.push("  All prerequisites match expected state.".to_string());
        return lines;
    }

    lines.push(String::new());

    for entry in &report.entries {
        lines.push(format!(
            "  [{:>8}] {} : expected={}, actual={}",
            entry.severity.label().to_uppercase(),
            entry.prerequisite,
            entry.expected_status,
            entry.actual_status
        ));
        lines.push(format!("             first seen: {}", entry.first_seen));
    }

    if let Some(sev) = report.max_severity() {
        lines.push(String::new());
        lines.push(format!("Highest severity: {sev}"));
    }

    lines
}

/// Format a `RepairResult` as TOON output lines.
pub fn format_repair_toon(result: &RepairResult) -> Vec<String> {
    let mut lines = Vec::new();

    let mode = if result.dry_run {
        "DRY RUN"
    } else {
        "EXECUTED"
    };
    lines.push(format!("=== Repair Result ({mode}) ==="));
    lines.push(format!(
        "Actions: {} total, {} fixed, {} still broken",
        result.total_actions(),
        result.prerequisites_fixed,
        result.still_broken.len()
    ));

    if result.actions_taken.is_empty() {
        lines.push(String::new());
        lines.push("  No repair actions needed.".to_string());
        return lines;
    }

    lines.push(String::new());

    for action in &result.actions_taken {
        let rev = if action.reversible {
            "reversible"
        } else {
            "irreversible"
        };
        lines.push(format!(
            "  [{}] {} ({}, {})",
            action.action_type.label().to_uppercase(),
            action.prerequisite,
            rev,
            if action.dry_run_safe {
                "dry-run safe"
            } else {
                "live only"
            }
        ));
        lines.push(format!("      {}", action.description));
    }

    if !result.still_broken.is_empty() {
        lines.push(String::new());
        lines.push("Still broken:".to_string());
        for name in &result.still_broken {
            lines.push(format!("  - {name}"));
        }
    }

    if result.all_fixed() && !result.dry_run {
        lines.push(String::new());
        lines.push("All prerequisites repaired successfully.".to_string());
    }

    lines
}

/// Format a `VerificationMatrix` as TOON output lines.
pub fn format_verification_toon(matrix: &VerificationMatrix) -> Vec<String> {
    let mut lines = Vec::new();

    let status = if matrix.all_passed() {
        "ALL PASSED"
    } else {
        "FAILURES DETECTED"
    };
    lines.push(format!(
        "=== Verification Matrix: {} ({}) ===",
        matrix.connector, status
    ));
    lines.push(format!(
        "Results: {} pass, {} fail, {} pending (rate: {:.0}%)",
        matrix.pass_count(),
        matrix.fail_count(),
        matrix.pending_count(),
        matrix.pass_rate() * 100.0
    ));
    lines.push(String::new());

    for case in &matrix.cases {
        let actual_label = case
            .actual
            .map_or_else(|| "pending".to_string(), |o| o.label().to_string());

        let pass_marker = if case.passed() {
            "[ok]"
        } else if case.is_evaluated() {
            "[!!]"
        } else {
            "[..]"
        };

        lines.push(format!(
            "  {} {} : expected={}, actual={}",
            pass_marker, case.scenario, case.expected, actual_label
        ));

        if let Some(ref msg) = case.message {
            lines.push(format!("      {msg}"));
        }
    }

    lines
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper factories ─────────────────────────────────────────

    fn api_key_desc(name: &str) -> PrerequisiteDescriptor {
        PrerequisiteDescriptor::required(
            name,
            PrerequisiteKind::ApiKey,
            "API key for authentication",
        )
    }

    fn oauth_desc(name: &str) -> PrerequisiteDescriptor {
        PrerequisiteDescriptor::required(name, PrerequisiteKind::OAuthApp, "OAuth app registration")
    }

    fn webhook_desc(name: &str) -> PrerequisiteDescriptor {
        PrerequisiteDescriptor::optional(name, PrerequisiteKind::Webhook, "Webhook for events")
    }

    fn service_account_desc(name: &str) -> PrerequisiteDescriptor {
        PrerequisiteDescriptor::required(
            name,
            PrerequisiteKind::ServiceAccount,
            "Service account with API access",
        )
    }

    fn resource_desc(name: &str) -> PrerequisiteDescriptor {
        PrerequisiteDescriptor::required(
            name,
            PrerequisiteKind::Resource,
            "External resource dependency",
        )
    }

    fn custom_desc(name: &str) -> PrerequisiteDescriptor {
        PrerequisiteDescriptor::optional(name, PrerequisiteKind::Custom, "Custom prerequisite")
    }

    fn sample_descriptors() -> Vec<PrerequisiteDescriptor> {
        vec![
            api_key_desc("api_token"),
            oauth_desc("oauth_app"),
            webhook_desc("event_webhook"),
        ]
    }

    const NOW: &str = "2026-03-12T10:00:00Z";

    fn all_satisfied_checks(descs: &[PrerequisiteDescriptor]) -> Vec<PrerequisiteCheck> {
        check_prerequisites(descs, NOW, |_| (PrerequisiteStatus::Satisfied, None))
    }

    fn all_missing_checks(descs: &[PrerequisiteDescriptor]) -> Vec<PrerequisiteCheck> {
        check_prerequisites(descs, NOW, |_| {
            (
                PrerequisiteStatus::Missing,
                Some("Run setup command".to_string()),
            )
        })
    }

    // ── PrerequisiteKind ─────────────────────────────────────────

    #[test]
    fn kind_labels() {
        assert_eq!(PrerequisiteKind::ServiceAccount.label(), "Service Account");
        assert_eq!(PrerequisiteKind::ApiKey.label(), "API Key");
        assert_eq!(PrerequisiteKind::OAuthApp.label(), "OAuth App");
        assert_eq!(PrerequisiteKind::Webhook.label(), "Webhook");
        assert_eq!(PrerequisiteKind::Resource.label(), "Resource");
        assert_eq!(PrerequisiteKind::Custom.label(), "Custom");
    }

    #[test]
    fn kind_display() {
        assert_eq!(format!("{}", PrerequisiteKind::ApiKey), "API Key");
        assert_eq!(
            format!("{}", PrerequisiteKind::ServiceAccount),
            "Service Account"
        );
    }

    #[test]
    fn kind_serde_roundtrip() {
        let kind = PrerequisiteKind::OAuthApp;
        let json = serde_json::to_string(&kind).unwrap();
        assert_eq!(json, "\"oauth_app\"");
        let back: PrerequisiteKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind);
    }

    #[test]
    fn kind_all_variants_serde() {
        let kinds = [
            PrerequisiteKind::ServiceAccount,
            PrerequisiteKind::ApiKey,
            PrerequisiteKind::OAuthApp,
            PrerequisiteKind::Webhook,
            PrerequisiteKind::Resource,
            PrerequisiteKind::Custom,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let back: PrerequisiteKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    // ── PrerequisiteDescriptor ───────────────────────────────────

    #[test]
    fn descriptor_required_constructor() {
        let d = PrerequisiteDescriptor::required("tok", PrerequisiteKind::ApiKey, "desc");
        assert!(d.required);
        assert_eq!(d.name, "tok");
        assert!(d.check_command.is_none());
    }

    #[test]
    fn descriptor_optional_constructor() {
        let d = PrerequisiteDescriptor::optional("hook", PrerequisiteKind::Webhook, "desc");
        assert!(!d.required);
        assert_eq!(d.name, "hook");
    }

    #[test]
    fn descriptor_with_check_command() {
        let d = api_key_desc("tok").with_check_command("fwc auth check");
        assert_eq!(d.check_command.as_deref(), Some("fwc auth check"));
    }

    #[test]
    fn descriptor_serde_roundtrip() {
        let d = api_key_desc("tok").with_check_command("check");
        let json = serde_json::to_string(&d).unwrap();
        let back: PrerequisiteDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "tok");
        assert_eq!(back.kind, PrerequisiteKind::ApiKey);
        assert!(back.required);
    }

    // ── PrerequisiteStatus ───────────────────────────────────────

    #[test]
    fn status_labels() {
        assert_eq!(PrerequisiteStatus::Satisfied.label(), "satisfied");
        assert_eq!(PrerequisiteStatus::Missing.label(), "missing");
        assert_eq!(PrerequisiteStatus::Expired.label(), "expired");
        assert_eq!(PrerequisiteStatus::Degraded.label(), "degraded");
        assert_eq!(PrerequisiteStatus::Unknown.label(), "unknown");
    }

    #[test]
    fn status_is_healthy() {
        assert!(PrerequisiteStatus::Satisfied.is_healthy());
        assert!(!PrerequisiteStatus::Missing.is_healthy());
        assert!(!PrerequisiteStatus::Expired.is_healthy());
        assert!(!PrerequisiteStatus::Degraded.is_healthy());
        assert!(!PrerequisiteStatus::Unknown.is_healthy());
    }

    #[test]
    fn status_is_actionable() {
        assert!(!PrerequisiteStatus::Satisfied.is_actionable());
        assert!(PrerequisiteStatus::Missing.is_actionable());
        assert!(PrerequisiteStatus::Expired.is_actionable());
        assert!(PrerequisiteStatus::Degraded.is_actionable());
        assert!(!PrerequisiteStatus::Unknown.is_actionable());
    }

    #[test]
    fn status_symbols() {
        assert_eq!(PrerequisiteStatus::Satisfied.symbol(), "[ok]");
        assert_eq!(PrerequisiteStatus::Missing.symbol(), "[!!]");
        assert_eq!(PrerequisiteStatus::Expired.symbol(), "[EX]");
        assert_eq!(PrerequisiteStatus::Degraded.symbol(), "[~~]");
        assert_eq!(PrerequisiteStatus::Unknown.symbol(), "[??]");
    }

    #[test]
    fn status_display() {
        assert_eq!(format!("{}", PrerequisiteStatus::Satisfied), "satisfied");
        assert_eq!(format!("{}", PrerequisiteStatus::Missing), "missing");
    }

    #[test]
    fn status_serde_roundtrip() {
        let status = PrerequisiteStatus::Expired;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"expired\"");
        let back: PrerequisiteStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }

    // ── PrerequisiteCheck constructors ───────────────────────────

    #[test]
    fn check_satisfied_constructor() {
        let d = api_key_desc("tok");
        let c = PrerequisiteCheck::satisfied(d, NOW);
        assert_eq!(c.status, PrerequisiteStatus::Satisfied);
        assert!(c.remediation.is_none());
        assert!(c.message.contains("available"));
    }

    #[test]
    fn check_missing_constructor() {
        let d = api_key_desc("tok");
        let c = PrerequisiteCheck::missing(d, "run setup", NOW);
        assert_eq!(c.status, PrerequisiteStatus::Missing);
        assert_eq!(c.remediation.as_deref(), Some("run setup"));
    }

    #[test]
    fn check_expired_constructor() {
        let d = api_key_desc("tok");
        let c = PrerequisiteCheck::expired(d, "refresh token", NOW);
        assert_eq!(c.status, PrerequisiteStatus::Expired);
        assert!(c.message.contains("expired"));
    }

    #[test]
    fn check_degraded_constructor() {
        let d = api_key_desc("tok");
        let c = PrerequisiteCheck::degraded(d, "slow response", "check network", NOW);
        assert_eq!(c.status, PrerequisiteStatus::Degraded);
        assert_eq!(c.message, "slow response");
    }

    #[test]
    fn check_unknown_constructor() {
        let d = api_key_desc("tok");
        let c = PrerequisiteCheck::unknown(d, "timeout", NOW);
        assert_eq!(c.status, PrerequisiteStatus::Unknown);
        assert!(c.remediation.is_none());
    }

    // ── check_prerequisites ──────────────────────────────────────

    #[test]
    fn check_all_satisfied() {
        let descs = sample_descriptors();
        let checks = all_satisfied_checks(&descs);
        assert_eq!(checks.len(), 3);
        assert!(
            checks
                .iter()
                .all(|c| c.status == PrerequisiteStatus::Satisfied)
        );
    }

    #[test]
    fn check_all_missing() {
        let descs = sample_descriptors();
        let checks = all_missing_checks(&descs);
        assert!(
            checks
                .iter()
                .all(|c| c.status == PrerequisiteStatus::Missing)
        );
        assert!(checks.iter().all(|c| c.remediation.is_some()));
    }

    #[test]
    fn check_mixed_statuses() {
        let descs = sample_descriptors();
        let checks = check_prerequisites(&descs, NOW, |d| {
            if d.name == "api_token" {
                (PrerequisiteStatus::Satisfied, None)
            } else if d.name == "oauth_app" {
                (PrerequisiteStatus::Expired, Some("refresh".to_string()))
            } else {
                (PrerequisiteStatus::Missing, Some("configure".to_string()))
            }
        });
        assert_eq!(checks[0].status, PrerequisiteStatus::Satisfied);
        assert_eq!(checks[1].status, PrerequisiteStatus::Expired);
        assert_eq!(checks[2].status, PrerequisiteStatus::Missing);
    }

    #[test]
    fn check_empty_descriptors() {
        let checks = check_prerequisites(&[], NOW, |_| (PrerequisiteStatus::Satisfied, None));
        assert!(checks.is_empty());
    }

    #[test]
    fn check_preserves_checked_at() {
        let descs = vec![api_key_desc("tok")];
        let ts = "2026-01-01T00:00:00Z";
        let checks = check_prerequisites(&descs, ts, |_| (PrerequisiteStatus::Satisfied, None));
        assert_eq!(checks[0].checked_at, ts);
    }

    #[test]
    fn check_service_account_kind() {
        let descs = vec![service_account_desc("sa")];
        let checks = check_prerequisites(&descs, NOW, |_| (PrerequisiteStatus::Satisfied, None));
        assert_eq!(checks[0].descriptor.kind, PrerequisiteKind::ServiceAccount);
    }

    #[test]
    fn check_resource_kind() {
        let descs = vec![resource_desc("db")];
        let checks = check_prerequisites(&descs, NOW, |_| {
            (PrerequisiteStatus::Degraded, Some("check db".to_string()))
        });
        assert_eq!(checks[0].status, PrerequisiteStatus::Degraded);
        assert!(checks[0].message.contains("degraded"));
    }

    #[test]
    fn check_custom_kind() {
        let descs = vec![custom_desc("custom_thing")];
        let checks = check_prerequisites(&descs, NOW, |_| (PrerequisiteStatus::Unknown, None));
        assert_eq!(checks[0].status, PrerequisiteStatus::Unknown);
        assert!(checks[0].message.contains("Cannot determine"));
    }

    #[test]
    fn check_messages_per_status() {
        let d = api_key_desc("tok");
        let checks =
            check_prerequisites(&[d.clone()], NOW, |_| (PrerequisiteStatus::Missing, None));
        assert!(checks[0].message.contains("not configured"));

        let checks =
            check_prerequisites(&[d.clone()], NOW, |_| (PrerequisiteStatus::Expired, None));
        assert!(checks[0].message.contains("expired"));

        let checks = check_prerequisites(&[d], NOW, |_| (PrerequisiteStatus::Satisfied, None));
        assert!(checks[0].message.contains("available"));
    }

    // ── build_ready_state ────────────────────────────────────────

    #[test]
    fn ready_state_all_satisfied() {
        let descs = sample_descriptors();
        let checks = all_satisfied_checks(&descs);
        let state = build_ready_state("myconn", checks);
        assert!(state.overall_ready);
        assert!((state.score - 1.0).abs() < f64::EPSILON);
        assert_eq!(state.satisfied_count(), 3);
        assert_eq!(state.blocking_count(), 0);
    }

    #[test]
    fn ready_state_some_missing() {
        let descs = sample_descriptors();
        let checks = check_prerequisites(&descs, NOW, |d| {
            if d.name == "api_token" {
                (PrerequisiteStatus::Satisfied, None)
            } else {
                (PrerequisiteStatus::Missing, Some("fix".to_string()))
            }
        });
        let state = build_ready_state("myconn", checks);
        assert!(!state.overall_ready);
        assert_eq!(state.satisfied_count(), 1);
        // api_token satisfied, oauth_app missing (required), webhook missing (optional)
        assert_eq!(state.blocking_count(), 1);
    }

    #[test]
    fn ready_state_all_broken() {
        let descs = sample_descriptors();
        let checks = all_missing_checks(&descs);
        let state = build_ready_state("myconn", checks);
        assert!(!state.overall_ready);
        assert!((state.score - 0.0).abs() < f64::EPSILON);
        assert_eq!(state.blocking_count(), 2); // 2 required, 1 optional
    }

    #[test]
    fn ready_state_empty_prerequisites() {
        let state = build_ready_state("myconn", vec![]);
        assert!(state.overall_ready);
        assert!((state.score - 1.0).abs() < f64::EPSILON);
        assert_eq!(state.satisfied_count(), 0);
    }

    #[test]
    fn ready_state_optional_only_missing() {
        let descs = vec![webhook_desc("hook1"), webhook_desc("hook2")];
        let checks = all_missing_checks(&descs);
        let state = build_ready_state("myconn", checks);
        // Optional only — should be "ready" even if missing.
        assert!(state.overall_ready);
        assert!((state.score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ready_state_needs_attention() {
        let descs = sample_descriptors();
        let checks = check_prerequisites(&descs, NOW, |d| {
            if d.name == "api_token" {
                (PrerequisiteStatus::Satisfied, None)
            } else {
                (PrerequisiteStatus::Expired, Some("renew".to_string()))
            }
        });
        let state = build_ready_state("myconn", checks);
        let attention = state.needs_attention();
        assert_eq!(attention.len(), 2);
    }

    #[test]
    fn ready_state_score_calculation() {
        let descs = vec![
            api_key_desc("a"),
            api_key_desc("b"),
            api_key_desc("c"),
            api_key_desc("d"),
        ];
        let checks = check_prerequisites(&descs, NOW, |d| {
            if d.name == "a" || d.name == "b" || d.name == "c" {
                (PrerequisiteStatus::Satisfied, None)
            } else {
                (PrerequisiteStatus::Missing, Some("fix".to_string()))
            }
        });
        let state = build_ready_state("test", checks);
        assert!((state.score - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn ready_state_connector_name() {
        let state = build_ready_state("my-connector", vec![]);
        assert_eq!(state.connector, "my-connector");
    }

    // ── generate_onboarding_workflow ─────────────────────────────

    #[test]
    fn onboarding_basic_workflow() {
        let descs = sample_descriptors();
        let wf = generate_onboarding_workflow("myconn", &descs);
        assert_eq!(wf.connector, "myconn");
        assert!(!wf.completed);
        assert_eq!(wf.current_step, Some(0));
        // 2 required + 1 optional + 1 verification = 4
        assert_eq!(wf.steps.len(), 4);
    }

    #[test]
    fn onboarding_required_steps_first() {
        let descs = sample_descriptors();
        let wf = generate_onboarding_workflow("myconn", &descs);
        // First two steps are for required prerequisites (blocking).
        assert!(wf.steps[0].blocking);
        assert!(wf.steps[1].blocking);
        // Third step is for optional webhook (skippable).
        assert!(wf.steps[2].skippable);
        // Last step is verification (blocking).
        assert!(wf.steps[3].blocking);
    }

    #[test]
    fn onboarding_step_numbering() {
        let descs = sample_descriptors();
        let wf = generate_onboarding_workflow("myconn", &descs);
        for (i, step) in wf.steps.iter().enumerate() {
            assert_eq!(step.step_number, (i + 1) as u32);
        }
    }

    #[test]
    fn onboarding_empty_descriptors() {
        let wf = generate_onboarding_workflow("myconn", &[]);
        // Just the verification step.
        assert_eq!(wf.steps.len(), 1);
        assert!(wf.steps[0].action.contains("Verify"));
    }

    #[test]
    fn onboarding_advance_completes_step() {
        let descs = vec![api_key_desc("tok")];
        let mut wf = generate_onboarding_workflow("myconn", &descs);
        assert_eq!(wf.current_step, Some(0));
        assert!(!wf.steps[0].completed);

        wf.advance();
        assert!(wf.steps[0].completed);
    }

    #[test]
    fn onboarding_advance_all_steps() {
        let descs = vec![api_key_desc("tok")];
        let mut wf = generate_onboarding_workflow("myconn", &descs);
        // 1 required + 1 verification = 2 steps.
        assert_eq!(wf.steps.len(), 2);

        wf.advance(); // Complete step 1.
        wf.advance(); // Complete step 2.
        assert!(wf.completed);
    }

    #[test]
    fn onboarding_skip_skippable_step() {
        let descs = vec![webhook_desc("hook")];
        let mut wf = generate_onboarding_workflow("myconn", &descs);
        // Step 1: optional hook (skippable), step 2: verification (blocking).
        assert_eq!(wf.current_step, Some(0));
        assert!(wf.steps[0].skippable);

        let skipped = wf.skip_current();
        assert!(skipped);
        assert!(wf.steps[0].completed);
    }

    #[test]
    fn onboarding_cannot_skip_blocking() {
        let descs = vec![api_key_desc("tok")];
        let mut wf = generate_onboarding_workflow("myconn", &descs);
        assert!(wf.steps[0].blocking);
        let skipped = wf.skip_current();
        assert!(!skipped);
        assert!(!wf.steps[0].completed);
    }

    #[test]
    fn onboarding_progress_ratio() {
        let descs = vec![api_key_desc("a"), api_key_desc("b")];
        let mut wf = generate_onboarding_workflow("myconn", &descs);
        // 2 required + 1 verification = 3 steps.
        assert!((wf.progress() - 0.0).abs() < f64::EPSILON);

        wf.advance();
        let expected = 1.0 / 3.0;
        assert!((wf.progress() - expected).abs() < 0.01);
    }

    #[test]
    fn onboarding_remaining_steps() {
        let descs = vec![api_key_desc("tok")];
        let mut wf = generate_onboarding_workflow("myconn", &descs);
        assert_eq!(wf.remaining_steps(), 2);
        wf.advance();
        assert_eq!(wf.remaining_steps(), 1);
    }

    #[test]
    fn onboarding_action_label_by_kind() {
        let descs = vec![
            service_account_desc("sa"),
            api_key_desc("key"),
            oauth_desc("oauth"),
            PrerequisiteDescriptor::required("wh", PrerequisiteKind::Webhook, "desc"),
            resource_desc("res"),
            PrerequisiteDescriptor::required("cust", PrerequisiteKind::Custom, "desc"),
        ];
        let wf = generate_onboarding_workflow("test", &descs);
        assert!(wf.steps[0].action.starts_with("Create"));
        assert!(wf.steps[1].action.starts_with("Generate"));
        assert!(wf.steps[2].action.starts_with("Register"));
        assert!(wf.steps[3].action.starts_with("Configure"));
        assert!(wf.steps[4].action.starts_with("Provision"));
        assert!(wf.steps[5].action.starts_with("Set up"));
    }

    #[test]
    fn onboarding_progress_empty_workflow() {
        let wf = OnboardingWorkflow {
            connector: "x".to_string(),
            steps: vec![],
            current_step: None,
            completed: true,
        };
        assert!((wf.progress() - 1.0).abs() < f64::EPSILON);
    }

    // ── detect_drift ─────────────────────────────────────────────

    #[test]
    fn drift_no_drift_when_all_satisfied() {
        let descs = sample_descriptors();
        let checks = all_satisfied_checks(&descs);
        let report = detect_drift("myconn", &checks, NOW);
        assert!(!report.has_drift());
        assert_eq!(report.drift_count(), 0);
        assert!((report.overall_drift_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn drift_detected_when_missing() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let report = detect_drift("myconn", &checks, NOW);
        assert!(report.has_drift());
        assert_eq!(report.drift_count(), 1);
    }

    #[test]
    fn drift_severity_required_missing_is_critical() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let report = detect_drift("myconn", &checks, NOW);
        assert_eq!(report.entries[0].severity, DriftSeverity::Critical);
    }

    #[test]
    fn drift_severity_required_expired_is_high() {
        let descs = vec![api_key_desc("tok")];
        let checks = check_prerequisites(&descs, NOW, |_| {
            (PrerequisiteStatus::Expired, Some("refresh".to_string()))
        });
        let report = detect_drift("myconn", &checks, NOW);
        assert_eq!(report.entries[0].severity, DriftSeverity::High);
    }

    #[test]
    fn drift_severity_required_degraded_is_high() {
        let descs = vec![api_key_desc("tok")];
        let checks = check_prerequisites(&descs, NOW, |_| {
            (PrerequisiteStatus::Degraded, Some("fix".to_string()))
        });
        let report = detect_drift("myconn", &checks, NOW);
        assert_eq!(report.entries[0].severity, DriftSeverity::High);
    }

    #[test]
    fn drift_severity_required_unknown_is_medium() {
        let descs = vec![api_key_desc("tok")];
        let checks = check_prerequisites(&descs, NOW, |_| (PrerequisiteStatus::Unknown, None));
        let report = detect_drift("myconn", &checks, NOW);
        assert_eq!(report.entries[0].severity, DriftSeverity::Medium);
    }

    #[test]
    fn drift_severity_optional_missing_is_medium() {
        let descs = vec![webhook_desc("hook")];
        let checks = all_missing_checks(&descs);
        let report = detect_drift("myconn", &checks, NOW);
        assert_eq!(report.entries[0].severity, DriftSeverity::Medium);
    }

    #[test]
    fn drift_severity_optional_degraded_is_low() {
        let descs = vec![webhook_desc("hook")];
        let checks = check_prerequisites(&descs, NOW, |_| {
            (PrerequisiteStatus::Degraded, Some("fix".to_string()))
        });
        let report = detect_drift("myconn", &checks, NOW);
        assert_eq!(report.entries[0].severity, DriftSeverity::Low);
    }

    #[test]
    fn drift_severity_optional_unknown_is_low() {
        let descs = vec![webhook_desc("hook")];
        let checks = check_prerequisites(&descs, NOW, |_| (PrerequisiteStatus::Unknown, None));
        let report = detect_drift("myconn", &checks, NOW);
        assert_eq!(report.entries[0].severity, DriftSeverity::Low);
    }

    #[test]
    fn drift_score_proportional() {
        let descs = vec![
            api_key_desc("a"),
            api_key_desc("b"),
            api_key_desc("c"),
            api_key_desc("d"),
        ];
        let checks = check_prerequisites(&descs, NOW, |d| {
            if d.name == "a" || d.name == "b" {
                (PrerequisiteStatus::Satisfied, None)
            } else {
                (PrerequisiteStatus::Missing, Some("fix".to_string()))
            }
        });
        let report = detect_drift("test", &checks, NOW);
        assert!((report.overall_drift_score - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn drift_max_severity() {
        let descs = vec![api_key_desc("tok"), webhook_desc("hook")];
        let checks = check_prerequisites(&descs, NOW, |d| {
            if d.name == "tok" {
                (PrerequisiteStatus::Missing, Some("fix".to_string()))
            } else {
                (PrerequisiteStatus::Degraded, Some("fix".to_string()))
            }
        });
        let report = detect_drift("test", &checks, NOW);
        assert_eq!(report.max_severity(), Some(DriftSeverity::Critical));
    }

    #[test]
    fn drift_max_severity_none_when_no_drift() {
        let descs = sample_descriptors();
        let checks = all_satisfied_checks(&descs);
        let report = detect_drift("test", &checks, NOW);
        assert_eq!(report.max_severity(), None);
    }

    #[test]
    fn drift_empty_checks() {
        let report = detect_drift("test", &[], NOW);
        assert!(!report.has_drift());
        assert!((report.overall_drift_score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn drift_entry_is_drifted() {
        let entry = DriftEntry {
            prerequisite: "tok".to_string(),
            expected_status: PrerequisiteStatus::Satisfied,
            actual_status: PrerequisiteStatus::Missing,
            first_seen: NOW.to_string(),
            severity: DriftSeverity::Critical,
        };
        assert!(entry.is_drifted());
    }

    #[test]
    fn drift_entry_not_drifted() {
        let entry = DriftEntry {
            prerequisite: "tok".to_string(),
            expected_status: PrerequisiteStatus::Satisfied,
            actual_status: PrerequisiteStatus::Satisfied,
            first_seen: NOW.to_string(),
            severity: DriftSeverity::Low,
        };
        assert!(!entry.is_drifted());
    }

    #[test]
    fn drift_first_seen_preserved() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let ts = "2026-06-01T00:00:00Z";
        let report = detect_drift("test", &checks, ts);
        assert_eq!(report.entries[0].first_seen, ts);
    }

    // ── RepairActionType ─────────────────────────────────────────

    #[test]
    fn repair_action_type_labels() {
        assert_eq!(RepairActionType::Install.label(), "install");
        assert_eq!(RepairActionType::Refresh.label(), "refresh");
        assert_eq!(RepairActionType::Reconfigure.label(), "reconfigure");
        assert_eq!(RepairActionType::Replace.label(), "replace");
    }

    #[test]
    fn repair_action_type_display() {
        assert_eq!(format!("{}", RepairActionType::Install), "install");
        assert_eq!(format!("{}", RepairActionType::Replace), "replace");
    }

    #[test]
    fn repair_action_type_serde_roundtrip() {
        let t = RepairActionType::Reconfigure;
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"reconfigure\"");
        let back: RepairActionType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    // ── plan_repair ──────────────────────────────────────────────

    #[test]
    fn plan_repair_all_satisfied_no_actions() {
        let descs = sample_descriptors();
        let checks = all_satisfied_checks(&descs);
        let actions = plan_repair(&checks, false);
        assert!(actions.is_empty());
    }

    #[test]
    fn plan_repair_missing_generates_install() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let actions = plan_repair(&checks, false);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].action_type, RepairActionType::Install);
        assert!(!actions[0].reversible);
    }

    #[test]
    fn plan_repair_expired_generates_refresh() {
        let descs = vec![api_key_desc("tok")];
        let checks = check_prerequisites(&descs, NOW, |_| {
            (PrerequisiteStatus::Expired, Some("renew".to_string()))
        });
        let actions = plan_repair(&checks, false);
        assert_eq!(actions[0].action_type, RepairActionType::Refresh);
        assert!(actions[0].reversible);
    }

    #[test]
    fn plan_repair_degraded_generates_reconfigure() {
        let descs = vec![api_key_desc("tok")];
        let checks = check_prerequisites(&descs, NOW, |_| {
            (PrerequisiteStatus::Degraded, Some("fix".to_string()))
        });
        let actions = plan_repair(&checks, false);
        assert_eq!(actions[0].action_type, RepairActionType::Reconfigure);
        assert!(actions[0].reversible);
    }

    #[test]
    fn plan_repair_unknown_generates_replace() {
        let descs = vec![api_key_desc("tok")];
        let checks = check_prerequisites(&descs, NOW, |_| (PrerequisiteStatus::Unknown, None));
        let actions = plan_repair(&checks, false);
        assert_eq!(actions[0].action_type, RepairActionType::Replace);
        assert!(!actions[0].reversible);
    }

    #[test]
    fn plan_repair_dry_run_flag() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let actions = plan_repair(&checks, true);
        assert!(actions[0].dry_run_safe);

        let actions = plan_repair(&checks, false);
        assert!(!actions[0].dry_run_safe);
    }

    #[test]
    fn plan_repair_multiple_broken() {
        let descs = vec![api_key_desc("a"), api_key_desc("b"), api_key_desc("c")];
        let checks = check_prerequisites(&descs, NOW, |d| {
            if d.name == "a" {
                (PrerequisiteStatus::Missing, Some("fix a".to_string()))
            } else if d.name == "b" {
                (PrerequisiteStatus::Expired, Some("fix b".to_string()))
            } else {
                (PrerequisiteStatus::Satisfied, None)
            }
        });
        let actions = plan_repair(&checks, false);
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0].prerequisite, "a");
        assert_eq!(actions[1].prerequisite, "b");
    }

    #[test]
    fn plan_repair_description_contains_name() {
        let descs = vec![api_key_desc("my_api_key")];
        let checks = all_missing_checks(&descs);
        let actions = plan_repair(&checks, false);
        assert!(actions[0].description.contains("my_api_key"));
    }

    // ── apply_repair ─────────────────────────────────────────────

    #[test]
    fn apply_repair_all_succeed() {
        let descs = vec![api_key_desc("a"), api_key_desc("b")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, false, |_| true);
        assert!(result.all_fixed());
        assert_eq!(result.prerequisites_fixed, 2);
        assert!(result.still_broken.is_empty());
        assert!(!result.dry_run);
    }

    #[test]
    fn apply_repair_some_fail() {
        let descs = vec![api_key_desc("a"), api_key_desc("b")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, false, |a| a.prerequisite == "a");
        assert!(!result.all_fixed());
        assert_eq!(result.prerequisites_fixed, 1);
        assert_eq!(result.still_broken, vec!["b"]);
    }

    #[test]
    fn apply_repair_dry_run_no_execute() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, true, |_| panic!("should not execute in dry run"));
        assert!(result.dry_run);
        assert_eq!(result.prerequisites_fixed, 0);
        assert_eq!(result.still_broken.len(), 1);
    }

    #[test]
    fn apply_repair_empty_checks() {
        let result = apply_repair(&[], false, |_| true);
        assert!(result.all_fixed());
        assert_eq!(result.total_actions(), 0);
    }

    #[test]
    fn apply_repair_total_actions() {
        let descs = vec![api_key_desc("a"), api_key_desc("b"), api_key_desc("c")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, false, |_| true);
        assert_eq!(result.total_actions(), 3);
    }

    #[test]
    fn apply_repair_all_fail() {
        let descs = vec![api_key_desc("a"), api_key_desc("b")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, false, |_| false);
        assert_eq!(result.prerequisites_fixed, 0);
        assert_eq!(result.still_broken.len(), 2);
    }

    // ── DriftSeverity ────────────────────────────────────────────

    #[test]
    fn drift_severity_labels() {
        assert_eq!(DriftSeverity::Low.label(), "low");
        assert_eq!(DriftSeverity::Medium.label(), "medium");
        assert_eq!(DriftSeverity::High.label(), "high");
        assert_eq!(DriftSeverity::Critical.label(), "critical");
    }

    #[test]
    fn drift_severity_ordering() {
        assert!(DriftSeverity::Low < DriftSeverity::Medium);
        assert!(DriftSeverity::Medium < DriftSeverity::High);
        assert!(DriftSeverity::High < DriftSeverity::Critical);
    }

    #[test]
    fn drift_severity_display() {
        assert_eq!(format!("{}", DriftSeverity::Critical), "critical");
    }

    #[test]
    fn drift_severity_serde_roundtrip() {
        let s = DriftSeverity::High;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"high\"");
        let back: DriftSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    // ── VerificationOutcome ──────────────────────────────────────

    #[test]
    fn verification_outcome_labels() {
        assert_eq!(VerificationOutcome::Pass.label(), "pass");
        assert_eq!(VerificationOutcome::Fail.label(), "fail");
        assert_eq!(VerificationOutcome::Skip.label(), "skip");
    }

    #[test]
    fn verification_outcome_display() {
        assert_eq!(format!("{}", VerificationOutcome::Pass), "pass");
    }

    #[test]
    fn verification_outcome_serde_roundtrip() {
        let o = VerificationOutcome::Skip;
        let json = serde_json::to_string(&o).unwrap();
        let back: VerificationOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, o);
    }

    // ── VerificationCase ─────────────────────────────────────────

    #[test]
    fn case_passed_when_match() {
        let case = VerificationCase {
            scenario: "test".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: Some(VerificationOutcome::Pass),
            message: None,
        };
        assert!(case.passed());
        assert!(case.is_evaluated());
    }

    #[test]
    fn case_failed_when_mismatch() {
        let case = VerificationCase {
            scenario: "test".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: Some(VerificationOutcome::Fail),
            message: None,
        };
        assert!(!case.passed());
    }

    #[test]
    fn case_not_evaluated() {
        let case = VerificationCase {
            scenario: "test".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: None,
            message: None,
        };
        assert!(!case.is_evaluated());
        assert!(!case.passed());
    }

    // ── VerificationMatrix ───────────────────────────────────────

    #[test]
    fn matrix_all_pass() {
        let cases = vec![
            VerificationCase {
                scenario: "a".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: Some(VerificationOutcome::Pass),
                message: None,
            },
            VerificationCase {
                scenario: "b".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Fail,
                actual: Some(VerificationOutcome::Fail),
                message: None,
            },
        ];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        assert!(matrix.all_passed());
        assert_eq!(matrix.pass_count(), 2);
        assert_eq!(matrix.fail_count(), 0);
        assert!((matrix.pass_rate() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn matrix_partial_pass() {
        let cases = vec![
            VerificationCase {
                scenario: "a".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: Some(VerificationOutcome::Pass),
                message: None,
            },
            VerificationCase {
                scenario: "b".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: Some(VerificationOutcome::Fail),
                message: Some("broken".to_string()),
            },
        ];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        assert!(!matrix.all_passed());
        assert_eq!(matrix.pass_count(), 1);
        assert_eq!(matrix.fail_count(), 1);
        assert!((matrix.pass_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn matrix_all_fail() {
        let cases = vec![
            VerificationCase {
                scenario: "a".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: Some(VerificationOutcome::Fail),
                message: None,
            },
            VerificationCase {
                scenario: "b".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: Some(VerificationOutcome::Fail),
                message: None,
            },
        ];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        assert!(!matrix.all_passed());
        assert_eq!(matrix.pass_count(), 0);
        assert_eq!(matrix.fail_count(), 2);
        assert!((matrix.pass_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn matrix_pending_count() {
        let cases = vec![
            VerificationCase {
                scenario: "a".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: Some(VerificationOutcome::Pass),
                message: None,
            },
            VerificationCase {
                scenario: "b".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: None,
                message: None,
            },
        ];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        assert_eq!(matrix.pending_count(), 1);
        assert!(matrix.all_passed()); // Unevaluated are not failures.
    }

    #[test]
    fn matrix_empty_cases() {
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases: vec![],
        };
        assert!(matrix.all_passed());
        assert_eq!(matrix.pass_count(), 0);
        assert!((matrix.pass_rate() - 0.0).abs() < f64::EPSILON);
    }

    // ── build_verification_cases ─────────────────────────────────

    #[test]
    fn build_cases_for_required() {
        let descs = vec![api_key_desc("tok")];
        let cases = build_verification_cases(&descs);
        // Required: present, missing_required, expired = 3 cases.
        assert_eq!(cases.len(), 3);
        assert!(cases.iter().any(|c| c.scenario.contains("present")));
        assert!(
            cases
                .iter()
                .any(|c| c.scenario.contains("missing_required"))
        );
        assert!(cases.iter().any(|c| c.scenario.contains("expired")));
    }

    #[test]
    fn build_cases_for_optional() {
        let descs = vec![webhook_desc("hook")];
        let cases = build_verification_cases(&descs);
        // Optional: present, expired = 2 cases (no missing_required).
        assert_eq!(cases.len(), 2);
        assert!(
            !cases
                .iter()
                .any(|c| c.scenario.contains("missing_required"))
        );
    }

    #[test]
    fn build_cases_empty_descriptors() {
        let cases = build_verification_cases(&[]);
        assert!(cases.is_empty());
    }

    #[test]
    fn build_cases_all_unevaluated() {
        let descs = vec![api_key_desc("tok")];
        let cases = build_verification_cases(&descs);
        assert!(cases.iter().all(|c| c.actual.is_none()));
    }

    // ── verify_prerequisites ─────────────────────────────────────

    #[test]
    fn verify_all_pass() {
        let descs = vec![api_key_desc("tok")];
        let cases = build_verification_cases(&descs);
        let matrix = verify_prerequisites("test", cases, |c| (c.expected, None));
        assert!(matrix.all_passed());
        assert_eq!(matrix.pass_count(), 3);
    }

    #[test]
    fn verify_all_fail() {
        let descs = vec![api_key_desc("tok")];
        let cases = build_verification_cases(&descs);
        let matrix = verify_prerequisites("test", cases, |c| {
            let opposite = match c.expected {
                VerificationOutcome::Pass => VerificationOutcome::Fail,
                VerificationOutcome::Fail => VerificationOutcome::Pass,
                VerificationOutcome::Skip => VerificationOutcome::Fail,
            };
            (opposite, Some("mismatch".to_string()))
        });
        assert!(!matrix.all_passed());
        assert_eq!(matrix.fail_count(), 3);
    }

    #[test]
    fn verify_partial() {
        let cases = vec![
            VerificationCase {
                scenario: "a".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: None,
                message: None,
            },
            VerificationCase {
                scenario: "b".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Fail,
                actual: None,
                message: None,
            },
        ];
        let matrix = verify_prerequisites("test", cases, |c| {
            if c.scenario == "a" {
                (VerificationOutcome::Pass, None)
            } else {
                (VerificationOutcome::Pass, Some("wrong".to_string()))
            }
        });
        assert!(!matrix.all_passed());
        assert_eq!(matrix.pass_count(), 1);
        assert_eq!(matrix.fail_count(), 1);
    }

    #[test]
    fn verify_empty_cases() {
        let matrix = verify_prerequisites("test", vec![], |_| (VerificationOutcome::Pass, None));
        assert!(matrix.all_passed());
        assert_eq!(matrix.cases.len(), 0);
    }

    #[test]
    fn verify_connector_name_preserved() {
        let matrix = verify_prerequisites("my-connector", vec![], |_| {
            (VerificationOutcome::Pass, None)
        });
        assert_eq!(matrix.connector, "my-connector");
    }

    #[test]
    fn verify_message_propagated() {
        let cases = vec![VerificationCase {
            scenario: "a".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: None,
            message: None,
        }];
        let matrix = verify_prerequisites("test", cases, |_| {
            (VerificationOutcome::Pass, Some("all good".to_string()))
        });
        assert_eq!(matrix.cases[0].message.as_deref(), Some("all good"));
    }

    // ── TOON: format_ready_state_toon ────────────────────────────

    #[test]
    fn toon_ready_state_header_ready() {
        let descs = sample_descriptors();
        let checks = all_satisfied_checks(&descs);
        let state = build_ready_state("myconn", checks);
        let lines = format_ready_state_toon(&state);
        assert!(lines[0].contains("READY"));
        assert!(lines[0].contains("myconn"));
    }

    #[test]
    fn toon_ready_state_header_not_ready() {
        let descs = sample_descriptors();
        let checks = all_missing_checks(&descs);
        let state = build_ready_state("myconn", checks);
        let lines = format_ready_state_toon(&state);
        assert!(lines[0].contains("NOT READY"));
    }

    #[test]
    fn toon_ready_state_score_line() {
        let descs = sample_descriptors();
        let checks = all_satisfied_checks(&descs);
        let state = build_ready_state("myconn", checks);
        let lines = format_ready_state_toon(&state);
        assert!(lines[1].contains("100%"));
        assert!(lines[1].contains("3/3"));
    }

    #[test]
    fn toon_ready_state_shows_status_symbols() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_satisfied_checks(&descs);
        let state = build_ready_state("test", checks);
        let lines = format_ready_state_toon(&state);
        let prereq_line = lines.iter().find(|l| l.contains("tok")).unwrap();
        assert!(prereq_line.contains("[ok]"));
    }

    #[test]
    fn toon_ready_state_shows_remediation() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let state = build_ready_state("test", checks);
        let lines = format_ready_state_toon(&state);
        assert!(lines.iter().any(|l| l.contains("->")));
    }

    #[test]
    fn toon_ready_state_blocking_message() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let state = build_ready_state("test", checks);
        let lines = format_ready_state_toon(&state);
        assert!(lines.iter().any(|l| l.contains("blocking")));
    }

    #[test]
    fn toon_ready_state_required_optional_labels() {
        let descs = vec![api_key_desc("tok"), webhook_desc("hook")];
        let checks = all_satisfied_checks(&descs);
        let state = build_ready_state("test", checks);
        let lines = format_ready_state_toon(&state);
        assert!(lines.iter().any(|l| l.contains("[required]")));
        assert!(lines.iter().any(|l| l.contains("[optional]")));
    }

    #[test]
    fn toon_ready_state_empty() {
        let state = build_ready_state("empty", vec![]);
        let lines = format_ready_state_toon(&state);
        assert!(lines[0].contains("READY"));
        assert!(lines[1].contains("100%"));
    }

    // ── TOON: format_onboarding_toon ─────────────────────────────

    #[test]
    fn toon_onboarding_header() {
        let descs = sample_descriptors();
        let wf = generate_onboarding_workflow("myconn", &descs);
        let lines = format_onboarding_toon(&wf);
        assert!(lines[0].contains("Onboarding"));
        assert!(lines[0].contains("myconn"));
        assert!(lines[0].contains("IN PROGRESS"));
    }

    #[test]
    fn toon_onboarding_completed_header() {
        let wf = OnboardingWorkflow {
            connector: "myconn".to_string(),
            steps: vec![],
            current_step: None,
            completed: true,
        };
        let lines = format_onboarding_toon(&wf);
        assert!(lines[0].contains("COMPLETED"));
    }

    #[test]
    fn toon_onboarding_progress_line() {
        let descs = sample_descriptors();
        let wf = generate_onboarding_workflow("myconn", &descs);
        let lines = format_onboarding_toon(&wf);
        assert!(lines[1].contains("0%"));
        assert!(lines[1].contains("0/4"));
    }

    #[test]
    fn toon_onboarding_current_step_marker() {
        let descs = vec![api_key_desc("tok")];
        let wf = generate_onboarding_workflow("test", &descs);
        let lines = format_onboarding_toon(&wf);
        assert!(lines.iter().any(|l| l.contains("[>]")));
    }

    #[test]
    fn toon_onboarding_completed_step_marker() {
        let descs = vec![api_key_desc("tok")];
        let mut wf = generate_onboarding_workflow("test", &descs);
        wf.advance();
        let lines = format_onboarding_toon(&wf);
        assert!(lines.iter().any(|l| l.contains("[x]")));
    }

    #[test]
    fn toon_onboarding_skippable_label() {
        let descs = vec![webhook_desc("hook")];
        let wf = generate_onboarding_workflow("test", &descs);
        let lines = format_onboarding_toon(&wf);
        assert!(lines.iter().any(|l| l.contains("(skippable)")));
    }

    #[test]
    fn toon_onboarding_remaining_count() {
        let descs = vec![api_key_desc("tok")];
        let wf = generate_onboarding_workflow("test", &descs);
        let lines = format_onboarding_toon(&wf);
        assert!(lines.iter().any(|l| l.contains("step(s) remaining")));
    }

    // ── TOON: format_drift_toon ──────────────────────────────────

    #[test]
    fn toon_drift_no_drift() {
        let descs = sample_descriptors();
        let checks = all_satisfied_checks(&descs);
        let report = detect_drift("myconn", &checks, NOW);
        let lines = format_drift_toon(&report);
        assert!(lines[0].contains("NO DRIFT"));
        assert!(lines.iter().any(|l| l.contains("match expected")));
    }

    #[test]
    fn toon_drift_detected() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let report = detect_drift("myconn", &checks, NOW);
        let lines = format_drift_toon(&report);
        assert!(lines[0].contains("DRIFT DETECTED"));
        assert!(lines.iter().any(|l| l.contains("CRITICAL")));
    }

    #[test]
    fn toon_drift_score_line() {
        let descs = vec![api_key_desc("a"), api_key_desc("b")];
        let checks = check_prerequisites(&descs, NOW, |d| {
            if d.name == "a" {
                (PrerequisiteStatus::Satisfied, None)
            } else {
                (PrerequisiteStatus::Missing, Some("fix".to_string()))
            }
        });
        let report = detect_drift("test", &checks, NOW);
        let lines = format_drift_toon(&report);
        assert!(lines[1].contains("50%"));
    }

    #[test]
    fn toon_drift_shows_expected_actual() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let report = detect_drift("test", &checks, NOW);
        let lines = format_drift_toon(&report);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("expected=") && l.contains("actual="))
        );
    }

    #[test]
    fn toon_drift_shows_first_seen() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let report = detect_drift("test", &checks, NOW);
        let lines = format_drift_toon(&report);
        assert!(lines.iter().any(|l| l.contains("first seen")));
    }

    #[test]
    fn toon_drift_highest_severity_line() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let report = detect_drift("test", &checks, NOW);
        let lines = format_drift_toon(&report);
        assert!(lines.iter().any(|l| l.contains("Highest severity")));
    }

    // ── TOON: format_repair_toon ─────────────────────────────────

    #[test]
    fn toon_repair_dry_run_header() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, true, |_| true);
        let lines = format_repair_toon(&result);
        assert!(lines[0].contains("DRY RUN"));
    }

    #[test]
    fn toon_repair_executed_header() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, false, |_| true);
        let lines = format_repair_toon(&result);
        assert!(lines[0].contains("EXECUTED"));
    }

    #[test]
    fn toon_repair_action_count_line() {
        let descs = vec![api_key_desc("a"), api_key_desc("b")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, false, |_| true);
        let lines = format_repair_toon(&result);
        assert!(lines[1].contains("2 total"));
        assert!(lines[1].contains("2 fixed"));
    }

    #[test]
    fn toon_repair_shows_action_type() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, false, |_| true);
        let lines = format_repair_toon(&result);
        assert!(lines.iter().any(|l| l.contains("[INSTALL]")));
    }

    #[test]
    fn toon_repair_shows_reversibility() {
        let descs = vec![api_key_desc("tok")];
        let checks = check_prerequisites(&descs, NOW, |_| {
            (PrerequisiteStatus::Expired, Some("fix".to_string()))
        });
        let result = apply_repair(&checks, false, |_| true);
        let lines = format_repair_toon(&result);
        assert!(lines.iter().any(|l| l.contains("reversible")));
    }

    #[test]
    fn toon_repair_still_broken_list() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, false, |_| false);
        let lines = format_repair_toon(&result);
        assert!(lines.iter().any(|l| l.contains("Still broken")));
        assert!(lines.iter().any(|l| l.contains("tok")));
    }

    #[test]
    fn toon_repair_all_fixed_message() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, false, |_| true);
        let lines = format_repair_toon(&result);
        assert!(lines.iter().any(|l| l.contains("repaired successfully")));
    }

    #[test]
    fn toon_repair_empty_no_actions() {
        let result = apply_repair(&[], false, |_| true);
        let lines = format_repair_toon(&result);
        assert!(lines.iter().any(|l| l.contains("No repair actions")));
    }

    // ── TOON: format_verification_toon ───────────────────────────

    #[test]
    fn toon_verification_all_passed_header() {
        let cases = vec![VerificationCase {
            scenario: "a".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: Some(VerificationOutcome::Pass),
            message: None,
        }];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        let lines = format_verification_toon(&matrix);
        assert!(lines[0].contains("ALL PASSED"));
    }

    #[test]
    fn toon_verification_failures_header() {
        let cases = vec![VerificationCase {
            scenario: "a".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: Some(VerificationOutcome::Fail),
            message: None,
        }];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        let lines = format_verification_toon(&matrix);
        assert!(lines[0].contains("FAILURES DETECTED"));
    }

    #[test]
    fn toon_verification_results_line() {
        let cases = vec![
            VerificationCase {
                scenario: "a".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: Some(VerificationOutcome::Pass),
                message: None,
            },
            VerificationCase {
                scenario: "b".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: Some(VerificationOutcome::Fail),
                message: None,
            },
        ];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        let lines = format_verification_toon(&matrix);
        assert!(lines[1].contains("1 pass"));
        assert!(lines[1].contains("1 fail"));
    }

    #[test]
    fn toon_verification_pass_marker() {
        let cases = vec![VerificationCase {
            scenario: "a".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: Some(VerificationOutcome::Pass),
            message: None,
        }];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        let lines = format_verification_toon(&matrix);
        assert!(lines.iter().any(|l| l.contains("[ok]")));
    }

    #[test]
    fn toon_verification_fail_marker() {
        let cases = vec![VerificationCase {
            scenario: "a".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: Some(VerificationOutcome::Fail),
            message: None,
        }];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        let lines = format_verification_toon(&matrix);
        assert!(lines.iter().any(|l| l.contains("[!!]")));
    }

    #[test]
    fn toon_verification_pending_marker() {
        let cases = vec![VerificationCase {
            scenario: "a".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: None,
            message: None,
        }];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        let lines = format_verification_toon(&matrix);
        assert!(lines.iter().any(|l| l.contains("[..]")));
    }

    #[test]
    fn toon_verification_shows_message() {
        let cases = vec![VerificationCase {
            scenario: "a".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: Some(VerificationOutcome::Fail),
            message: Some("check failed".to_string()),
        }];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        let lines = format_verification_toon(&matrix);
        assert!(lines.iter().any(|l| l.contains("check failed")));
    }

    #[test]
    fn toon_verification_shows_expected_actual() {
        let cases = vec![VerificationCase {
            scenario: "a".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: Some(VerificationOutcome::Fail),
            message: None,
        }];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        let lines = format_verification_toon(&matrix);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("expected=pass") && l.contains("actual=fail"))
        );
    }

    #[test]
    fn toon_verification_rate_percentage() {
        let cases = vec![
            VerificationCase {
                scenario: "a".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: Some(VerificationOutcome::Pass),
                message: None,
            },
            VerificationCase {
                scenario: "b".to_string(),
                prerequisite: "tok".to_string(),
                expected: VerificationOutcome::Pass,
                actual: Some(VerificationOutcome::Pass),
                message: None,
            },
        ];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        let lines = format_verification_toon(&matrix);
        assert!(lines[1].contains("100%"));
    }

    // ── Serialization integration ────────────────────────────────

    #[test]
    fn ready_state_to_json() {
        let descs = sample_descriptors();
        let checks = all_satisfied_checks(&descs);
        let state = build_ready_state("myconn", checks);
        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["connector"], "myconn");
        assert_eq!(json["overall_ready"], true);
    }

    #[test]
    fn drift_report_to_json() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let report = detect_drift("myconn", &checks, NOW);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["connector"], "myconn");
        assert!(json["entries"].as_array().unwrap().len() > 0);
    }

    #[test]
    fn repair_result_to_json() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);
        let result = apply_repair(&checks, false, |_| true);
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["prerequisites_fixed"], 1);
        assert_eq!(json["dry_run"], false);
    }

    #[test]
    fn verification_matrix_to_json() {
        let cases = vec![VerificationCase {
            scenario: "a".to_string(),
            prerequisite: "tok".to_string(),
            expected: VerificationOutcome::Pass,
            actual: Some(VerificationOutcome::Pass),
            message: None,
        }];
        let matrix = VerificationMatrix {
            connector: "test".to_string(),
            cases,
        };
        let json = serde_json::to_value(&matrix).unwrap();
        assert_eq!(json["connector"], "test");
    }

    #[test]
    fn onboarding_workflow_to_json() {
        let descs = vec![api_key_desc("tok")];
        let wf = generate_onboarding_workflow("myconn", &descs);
        let json = serde_json::to_value(&wf).unwrap();
        assert_eq!(json["connector"], "myconn");
        assert_eq!(json["completed"], false);
    }

    // ── Edge cases ───────────────────────────────────────────────

    #[test]
    fn edge_single_required_all_statuses() {
        let desc = api_key_desc("tok");
        for status in [
            PrerequisiteStatus::Satisfied,
            PrerequisiteStatus::Missing,
            PrerequisiteStatus::Expired,
            PrerequisiteStatus::Degraded,
            PrerequisiteStatus::Unknown,
        ] {
            let checks = check_prerequisites(&[desc.clone()], NOW, |_| (status, None));
            let state = build_ready_state("test", checks);
            if status == PrerequisiteStatus::Satisfied {
                assert!(state.overall_ready);
            } else {
                assert!(!state.overall_ready);
            }
        }
    }

    #[test]
    fn edge_many_prerequisites() {
        let descs: Vec<_> = (0..20)
            .map(|i| api_key_desc(&format!("key_{}", i)))
            .collect();
        let checks = all_satisfied_checks(&descs);
        let state = build_ready_state("big", checks);
        assert!(state.overall_ready);
        assert_eq!(state.satisfied_count(), 20);
    }

    #[test]
    fn edge_mixed_required_optional_drift() {
        let descs = vec![api_key_desc("required_key"), webhook_desc("optional_hook")];
        let checks = check_prerequisites(&descs, NOW, |d| {
            if d.required {
                (PrerequisiteStatus::Expired, Some("renew".to_string()))
            } else {
                (PrerequisiteStatus::Degraded, Some("check".to_string()))
            }
        });
        let report = detect_drift("mixed", &checks, NOW);
        assert_eq!(report.drift_count(), 2);
        // Required expired = High, optional degraded = Low.
        let severities: Vec<_> = report.entries.iter().map(|e| e.severity).collect();
        assert!(severities.contains(&DriftSeverity::High));
        assert!(severities.contains(&DriftSeverity::Low));
    }

    #[test]
    fn edge_repair_then_verify() {
        let descs = vec![api_key_desc("tok")];
        let checks = all_missing_checks(&descs);

        // Plan repair.
        let actions = plan_repair(&checks, false);
        assert_eq!(actions.len(), 1);

        // Apply repair (succeeds).
        let result = apply_repair(&checks, false, |_| true);
        assert!(result.all_fixed());

        // Verify after repair — verifier returns each case's expected outcome.
        let cases = build_verification_cases(&descs);
        let matrix = verify_prerequisites("test", cases, |c| (c.expected, None));
        assert!(matrix.all_passed());
    }

    #[test]
    fn edge_onboarding_full_lifecycle() {
        let descs = vec![api_key_desc("key"), webhook_desc("hook")];
        let mut wf = generate_onboarding_workflow("lifecycle", &descs);
        // Steps: key (blocking), hook (skippable), verify (blocking).
        assert_eq!(wf.steps.len(), 3);
        assert_eq!(wf.remaining_steps(), 3);

        // Complete first step.
        wf.advance();
        assert!(wf.steps[0].completed);
        assert_eq!(wf.remaining_steps(), 2);

        // Skip optional step.
        let skipped = wf.skip_current();
        assert!(skipped);
        assert_eq!(wf.remaining_steps(), 1);

        // Complete verification.
        wf.advance();
        assert!(wf.completed);
        assert_eq!(wf.remaining_steps(), 0);
    }

    #[test]
    fn edge_drift_report_connector_name() {
        let report = detect_drift("fcp.slack", &[], NOW);
        assert_eq!(report.connector, "fcp.slack");
    }

    #[test]
    fn edge_ready_state_with_all_unknown() {
        let descs = vec![api_key_desc("a"), api_key_desc("b")];
        let checks = check_prerequisites(&descs, NOW, |_| (PrerequisiteStatus::Unknown, None));
        let state = build_ready_state("test", checks);
        assert!(!state.overall_ready);
        assert!((state.score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn edge_repair_reversible_vs_irreversible() {
        let descs = vec![
            api_key_desc("missing_key"), // Missing -> Install (irreversible)
            api_key_desc("expired_key"), // need expired
        ];
        let checks = check_prerequisites(&descs, NOW, |d| {
            if d.name == "missing_key" {
                (PrerequisiteStatus::Missing, Some("install".to_string()))
            } else {
                (PrerequisiteStatus::Expired, Some("refresh".to_string()))
            }
        });
        let actions = plan_repair(&checks, false);
        assert_eq!(actions.len(), 2);
        assert!(!actions[0].reversible); // Install
        assert!(actions[1].reversible); // Refresh
    }
}
