//! Process-class chaos scenarios.
//!
//! These plans model host process termination and memory-pressure faults in a
//! dry-run form suitable for conformance and staging preflight checks.

use thiserror::Error;
use tracing::{info, info_span, span::EnteredSpan};

use crate::{ChaosInjector, ChaosOutcome, ChaosScenario, Env};

/// Canonical process scenario names.
pub const PROCESS_SCENARIOS: &[&str] = &["oom_kill", "cgroup_memory_pressure"];

/// Family of process fault being simulated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessFaultClass {
    /// Supervisor-observed process termination.
    OomKill,
    /// Cgroup memory pressure without immediate process death.
    CgroupMemoryPressure,
}

impl ProcessFaultClass {
    /// Stable log label for the class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OomKill => "oom_kill",
            Self::CgroupMemoryPressure => "cgroup_memory_pressure",
        }
    }
}

/// One synthetic process step in a dry-run scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessStep {
    /// Stable step name.
    pub name: &'static str,
    /// Synthetic action identifier.
    pub action: &'static str,
    /// Synthetic target affected by the action.
    pub target: &'static str,
    /// Fault class for log filtering.
    pub class: ProcessFaultClass,
}

/// Static implementation plan for a named process scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessScenarioPlan {
    /// Scenario name matching the TOML `name` field.
    pub name: &'static str,
    /// Fault family.
    pub fault_class: ProcessFaultClass,
    /// OTLP span name required by the runbook contract.
    pub span_name: &'static str,
    /// Synthetic affected units in the default dry run.
    pub affected_units: u32,
    /// Ordered dry-run steps.
    pub steps: &'static [ProcessStep],
}

/// Dry-run result for a process scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessDryRunOutcome {
    /// Static scenario plan used for the run.
    pub plan: ProcessScenarioPlan,
    /// Step names emitted by the dry run.
    pub steps_traced: Vec<&'static str>,
    /// Guardrail outcome from the generic chaos injector.
    pub outcome: ChaosOutcome,
    /// Whether declared rollback steps include process-state restoration.
    pub rollback_process_state_restored: bool,
}

/// Process scenario lookup and validation errors.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ProcessScenarioError {
    /// Scenario name has no process implementation plan.
    #[error("unknown process chaos scenario `{name}`")]
    UnknownScenario {
        /// Unknown scenario name.
        name: String,
    },
}

const OOM_KILL_STEPS: &[ProcessStep] = &[
    ProcessStep {
        name: "select_supervised_host_pid",
        action: "locate_fcp_host_under_supervisor",
        target: "fcp-host",
        class: ProcessFaultClass::OomKill,
    },
    ProcessStep {
        name: "simulate_oom_kill",
        action: "send_synthetic_oom_kill_signal",
        target: "fcp-host",
        class: ProcessFaultClass::OomKill,
    },
    ProcessStep {
        name: "observe_supervisor_restart",
        action: "wait_for_supervisor_restart",
        target: "fcp-host-supervisor",
        class: ProcessFaultClass::OomKill,
    },
];

const CGROUP_MEMORY_PRESSURE_STEPS: &[ProcessStep] = &[
    ProcessStep {
        name: "lower_memory_high_watermark",
        action: "apply_cgroup_memory_high_pressure",
        target: "fcp-host-cgroup",
        class: ProcessFaultClass::CgroupMemoryPressure,
    },
    ProcessStep {
        name: "sample_admission_backpressure",
        action: "verify_admission_backpressure_signal",
        target: "host_admission_gate",
        class: ProcessFaultClass::CgroupMemoryPressure,
    },
];

const PROCESS_SCENARIO_PLANS: &[ProcessScenarioPlan] = &[
    ProcessScenarioPlan {
        name: "oom_kill",
        fault_class: ProcessFaultClass::OomKill,
        span_name: "fcp.chaos.process.oom_kill",
        affected_units: 1,
        steps: OOM_KILL_STEPS,
    },
    ProcessScenarioPlan {
        name: "cgroup_memory_pressure",
        fault_class: ProcessFaultClass::CgroupMemoryPressure,
        span_name: "fcp.chaos.process.cgroup_memory_pressure",
        affected_units: 1,
        steps: CGROUP_MEMORY_PRESSURE_STEPS,
    },
];

/// Find the static implementation plan for a process scenario.
#[must_use]
pub fn plan_for_scenario(name: &str) -> Option<&'static ProcessScenarioPlan> {
    PROCESS_SCENARIO_PLANS.iter().find(|plan| plan.name == name)
}

/// Dry-run a process scenario with its default bounded synthetic radius.
///
/// # Errors
///
/// Returns [`ProcessScenarioError::UnknownScenario`] when the parsed TOML
/// scenario does not map to a process implementation plan.
pub fn dry_run_process_scenario(
    scenario: &ChaosScenario,
    env: Env,
) -> Result<ProcessDryRunOutcome, ProcessScenarioError> {
    let plan = require_plan(scenario)?;
    let observed_radius = plan.affected_units.min(scenario.blast_radius);
    dry_run_process_scenario_with_observed_radius(scenario, env, observed_radius)
}

/// Dry-run a process scenario with a caller-supplied observed radius.
///
/// # Errors
///
/// Returns [`ProcessScenarioError::UnknownScenario`] when the parsed TOML
/// scenario does not map to a process implementation plan.
pub fn dry_run_process_scenario_with_observed_radius(
    scenario: &ChaosScenario,
    env: Env,
    observed_radius: u32,
) -> Result<ProcessDryRunOutcome, ProcessScenarioError> {
    let plan = *require_plan(scenario)?;
    let _span = enter_process_span(&plan);
    let mut steps_traced = Vec::with_capacity(plan.steps.len());

    info!(
        scenario = scenario.name.as_str(),
        fault_class = plan.fault_class.as_str(),
        span = plan.span_name,
        step_count = plan.steps.len(),
        "starting process chaos dry run"
    );
    for step in plan.steps {
        info!(
            scenario = scenario.name.as_str(),
            step = step.name,
            action = step.action,
            target = step.target,
            fault_class = step.class.as_str(),
            "process chaos dry-run step"
        );
        steps_traced.push(step.name);
    }

    let outcome =
        ChaosInjector::new(env).run_scenario_with_observed_radius(scenario, observed_radius);
    let rollback_process_state_restored = rollback_restores_process_state(scenario);
    info!(
        scenario = scenario.name.as_str(),
        outcome = ?outcome.status,
        rollback_process_state_restored,
        "process chaos dry run ended"
    );

    Ok(ProcessDryRunOutcome {
        plan,
        steps_traced,
        outcome,
        rollback_process_state_restored,
    })
}

fn require_plan(
    scenario: &ChaosScenario,
) -> Result<&'static ProcessScenarioPlan, ProcessScenarioError> {
    plan_for_scenario(&scenario.name).ok_or_else(|| ProcessScenarioError::UnknownScenario {
        name: scenario.name.clone(),
    })
}

fn rollback_restores_process_state(scenario: &ChaosScenario) -> bool {
    scenario.rollback_steps.iter().any(|step| {
        step.action.contains("restart")
            || step.action.contains("restore")
            || step.action.contains("clear")
            || step.action.contains("release")
    })
}

fn enter_process_span(plan: &ProcessScenarioPlan) -> EnteredSpan {
    match plan.name {
        "oom_kill" => info_span!("fcp.chaos.process.oom_kill", scenario = plan.name).entered(),
        "cgroup_memory_pressure" => info_span!(
            "fcp.chaos.process.cgroup_memory_pressure",
            scenario = plan.name
        )
        .entered(),
        _ => info_span!("fcp.chaos.process.unknown", scenario = plan.name).entered(),
    }
}
