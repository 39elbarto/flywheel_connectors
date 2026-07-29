//! Disk-class chaos scenarios.
//!
//! These plans are dry-run only: they describe the disk pressure and audit
//! write-path actions the staging harness would apply, then delegate
//! blast-radius and rollback accounting to [`crate::ChaosInjector`].

use thiserror::Error;
use tracing::{info, info_span, span::EnteredSpan};

use crate::{ChaosInjector, ChaosOutcome, ChaosScenario, Env};

/// Canonical disk scenario names.
pub const DISK_IO_SCENARIOS: &[&str] = &["disk_full", "quota_exhaustion", "audit_write_atomicity"];

/// Family of disk fault being simulated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskIoFaultClass {
    /// Filesystem reaches an exhausted free-space threshold.
    DiskFull,
    /// Per-tenant or per-zone write quota is exhausted.
    QuotaExhaustion,
    /// Audit write path is interrupted around a WAL boundary.
    AuditWriteAtomicity,
}

impl DiskIoFaultClass {
    /// Stable log label for the class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DiskFull => "disk_full",
            Self::QuotaExhaustion => "quota_exhaustion",
            Self::AuditWriteAtomicity => "audit_write_atomicity",
        }
    }
}

/// One synthetic disk step in a dry-run scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskIoStep {
    /// Stable step name.
    pub name: &'static str,
    /// Synthetic action identifier.
    pub action: &'static str,
    /// Synthetic target affected by the action.
    pub target: &'static str,
    /// Fault class for log filtering.
    pub class: DiskIoFaultClass,
}

/// Static implementation plan for a named disk scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskIoScenarioPlan {
    /// Scenario name matching the TOML `name` field.
    pub name: &'static str,
    /// Fault family.
    pub fault_class: DiskIoFaultClass,
    /// OTLP span name required by the runbook contract.
    pub span_name: &'static str,
    /// Synthetic affected units in the default dry run.
    pub affected_units: u32,
    /// Ordered dry-run steps.
    pub steps: &'static [DiskIoStep],
}

/// Dry-run result for a disk scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskIoDryRunOutcome {
    /// Static scenario plan used for the run.
    pub plan: DiskIoScenarioPlan,
    /// Step names emitted by the dry run.
    pub steps_traced: Vec<&'static str>,
    /// Guardrail outcome from the generic chaos injector.
    pub outcome: ChaosOutcome,
    /// Whether declared rollback steps include storage-state restoration.
    pub rollback_storage_state_restored: bool,
}

/// Disk scenario lookup and validation errors.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DiskIoScenarioError {
    /// Scenario name has no disk implementation plan.
    #[error("unknown disk chaos scenario `{name}`")]
    UnknownScenario {
        /// Unknown scenario name.
        name: String,
    },
}

const DISK_FULL_STEPS: &[DiskIoStep] = &[
    DiskIoStep {
        name: "reserve_wal_volume_space",
        action: "fallocate_synthetic_wal_volume",
        target: "synthetic_audit_wal",
        class: DiskIoFaultClass::DiskFull,
    },
    DiskIoStep {
        name: "append_audit_entry_under_pressure",
        action: "attempt_audit_append_at_full_threshold",
        target: "audit_write_path",
        class: DiskIoFaultClass::DiskFull,
    },
];

const QUOTA_EXHAUSTION_STEPS: &[DiskIoStep] = &[
    DiskIoStep {
        name: "lower_zone_write_quota",
        action: "apply_synthetic_zone_quota",
        target: "z:project:chaos",
        class: DiskIoFaultClass::QuotaExhaustion,
    },
    DiskIoStep {
        name: "exercise_quota_denial",
        action: "attempt_write_after_quota_exhaustion",
        target: "audit_write_path",
        class: DiskIoFaultClass::QuotaExhaustion,
    },
];

const AUDIT_WRITE_ATOMICITY_STEPS: &[DiskIoStep] = &[
    DiskIoStep {
        name: "interrupt_audit_wal_after_prepare",
        action: "simulate_wal_prepare_interruption",
        target: "audit_chain_wal",
        class: DiskIoFaultClass::AuditWriteAtomicity,
    },
    DiskIoStep {
        name: "replay_audit_wal",
        action: "verify_wal_replay_chain_head",
        target: "audit_chain_wal",
        class: DiskIoFaultClass::AuditWriteAtomicity,
    },
];

const DISK_IO_SCENARIO_PLANS: &[DiskIoScenarioPlan] = &[
    DiskIoScenarioPlan {
        name: "disk_full",
        fault_class: DiskIoFaultClass::DiskFull,
        span_name: "fcp.chaos.disk.disk_full",
        affected_units: 1,
        steps: DISK_FULL_STEPS,
    },
    DiskIoScenarioPlan {
        name: "quota_exhaustion",
        fault_class: DiskIoFaultClass::QuotaExhaustion,
        span_name: "fcp.chaos.disk.quota_exhaustion",
        affected_units: 1,
        steps: QUOTA_EXHAUSTION_STEPS,
    },
    DiskIoScenarioPlan {
        name: "audit_write_atomicity",
        fault_class: DiskIoFaultClass::AuditWriteAtomicity,
        span_name: "fcp.chaos.disk.audit_write_atomicity",
        affected_units: 1,
        steps: AUDIT_WRITE_ATOMICITY_STEPS,
    },
];

/// Find the static implementation plan for a disk scenario.
#[must_use]
pub fn plan_for_scenario(name: &str) -> Option<&'static DiskIoScenarioPlan> {
    DISK_IO_SCENARIO_PLANS.iter().find(|plan| plan.name == name)
}

/// Dry-run a disk scenario with its default bounded synthetic radius.
///
/// # Errors
///
/// Returns [`DiskIoScenarioError::UnknownScenario`] when the parsed TOML
/// scenario does not map to a disk implementation plan.
pub fn dry_run_disk_io_scenario(
    scenario: &ChaosScenario,
    env: Env,
) -> Result<DiskIoDryRunOutcome, DiskIoScenarioError> {
    let plan = require_plan(scenario)?;
    let observed_radius = plan.affected_units.min(scenario.blast_radius);
    dry_run_disk_io_scenario_with_observed_radius(scenario, env, observed_radius)
}

/// Dry-run a disk scenario with a caller-supplied observed radius.
///
/// # Errors
///
/// Returns [`DiskIoScenarioError::UnknownScenario`] when the parsed TOML
/// scenario does not map to a disk implementation plan.
pub fn dry_run_disk_io_scenario_with_observed_radius(
    scenario: &ChaosScenario,
    env: Env,
    observed_radius: u32,
) -> Result<DiskIoDryRunOutcome, DiskIoScenarioError> {
    let plan = *require_plan(scenario)?;
    let _span = enter_disk_io_span(&plan);
    let mut steps_traced = Vec::with_capacity(plan.steps.len());

    info!(
        scenario = scenario.name.as_str(),
        fault_class = plan.fault_class.as_str(),
        span = plan.span_name,
        step_count = plan.steps.len(),
        "starting disk chaos dry run"
    );
    for step in plan.steps {
        info!(
            scenario = scenario.name.as_str(),
            step = step.name,
            action = step.action,
            target = step.target,
            fault_class = step.class.as_str(),
            "disk chaos dry-run step"
        );
        steps_traced.push(step.name);
    }

    let outcome =
        ChaosInjector::new(env).run_scenario_with_observed_radius(scenario, observed_radius);
    let rollback_storage_state_restored = rollback_restores_storage_state(scenario);
    info!(
        scenario = scenario.name.as_str(),
        outcome = ?outcome.status,
        rollback_storage_state_restored,
        "disk chaos dry run ended"
    );

    Ok(DiskIoDryRunOutcome {
        plan,
        steps_traced,
        outcome,
        rollback_storage_state_restored,
    })
}

fn require_plan(
    scenario: &ChaosScenario,
) -> Result<&'static DiskIoScenarioPlan, DiskIoScenarioError> {
    plan_for_scenario(&scenario.name).ok_or_else(|| DiskIoScenarioError::UnknownScenario {
        name: scenario.name.clone(),
    })
}

fn rollback_restores_storage_state(scenario: &ChaosScenario) -> bool {
    scenario.rollback_steps.iter().any(|step| {
        step.action.contains("clear")
            || step.action.contains("restore")
            || step.action.contains("remove")
            || step.action.contains("verify_wal")
    })
}

fn enter_disk_io_span(plan: &DiskIoScenarioPlan) -> EnteredSpan {
    match plan.name {
        "disk_full" => info_span!("fcp.chaos.disk.disk_full", scenario = plan.name).entered(),
        "quota_exhaustion" => {
            info_span!("fcp.chaos.disk.quota_exhaustion", scenario = plan.name).entered()
        }
        "audit_write_atomicity" => {
            info_span!("fcp.chaos.disk.audit_write_atomicity", scenario = plan.name).entered()
        }
        _ => info_span!("fcp.chaos.disk.unknown", scenario = plan.name).entered(),
    }
}
