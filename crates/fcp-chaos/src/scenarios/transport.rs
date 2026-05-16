//! Transport-class chaos scenarios.
//!
//! These dry-run plans describe TCP reset faults around FCP handshakes and RPC
//! execution without touching host networking.

use thiserror::Error;
use tracing::{info, info_span, span::EnteredSpan};

use crate::{ChaosInjector, ChaosOutcome, ChaosScenario, Env};

/// Canonical transport scenario names.
pub const TRANSPORT_SCENARIOS: &[&str] = &["tcp_rst_mid_handshake", "tcp_rst_during_rpc"];

/// Family of transport fault being simulated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportFaultClass {
    /// TCP reset during session handshake.
    TcpRstMidHandshake,
    /// TCP reset during an in-flight RPC.
    TcpRstDuringRpc,
}

impl TransportFaultClass {
    /// Stable log label for the class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TcpRstMidHandshake => "tcp_rst_mid_handshake",
            Self::TcpRstDuringRpc => "tcp_rst_during_rpc",
        }
    }
}

/// One synthetic transport step in a dry-run scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportStep {
    /// Stable step name.
    pub name: &'static str,
    /// Synthetic action identifier.
    pub action: &'static str,
    /// Synthetic target affected by the action.
    pub target: &'static str,
    /// Fault class for log filtering.
    pub class: TransportFaultClass,
}

/// Static implementation plan for a named transport scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportScenarioPlan {
    /// Scenario name matching the TOML `name` field.
    pub name: &'static str,
    /// Fault family.
    pub fault_class: TransportFaultClass,
    /// OTLP span name required by the runbook contract.
    pub span_name: &'static str,
    /// Synthetic affected units in the default dry run.
    pub affected_units: u32,
    /// Ordered dry-run steps.
    pub steps: &'static [TransportStep],
}

/// Dry-run result for a transport scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportDryRunOutcome {
    /// Static scenario plan used for the run.
    pub plan: TransportScenarioPlan,
    /// Step names emitted by the dry run.
    pub steps_traced: Vec<&'static str>,
    /// Guardrail outcome from the generic chaos injector.
    pub outcome: ChaosOutcome,
    /// Whether declared rollback steps include transport-state restoration.
    pub rollback_transport_state_restored: bool,
}

/// Transport scenario lookup and validation errors.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TransportScenarioError {
    /// Scenario name has no transport implementation plan.
    #[error("unknown transport chaos scenario `{name}`")]
    UnknownScenario {
        /// Unknown scenario name.
        name: String,
    },
}

const TCP_RST_MID_HANDSHAKE_STEPS: &[TransportStep] = &[
    TransportStep {
        name: "inject_rst_after_client_hello",
        action: "apply_tcp_rst_after_fcps_client_hello",
        target: "fcps_handshake",
        class: TransportFaultClass::TcpRstMidHandshake,
    },
    TransportStep {
        name: "verify_hello_retry_cookie_reuse_blocked",
        action: "assert_session_retry_fresh_cookie",
        target: "fcps_handshake",
        class: TransportFaultClass::TcpRstMidHandshake,
    },
];

const TCP_RST_DURING_RPC_STEPS: &[TransportStep] = &[
    TransportStep {
        name: "inject_rst_after_rpc_headers",
        action: "apply_tcp_rst_after_rpc_headers",
        target: "fcpc_rpc_stream",
        class: TransportFaultClass::TcpRstDuringRpc,
    },
    TransportStep {
        name: "verify_idempotent_retry_or_single_commit",
        action: "assert_rpc_retry_single_commit",
        target: "fcpc_rpc_stream",
        class: TransportFaultClass::TcpRstDuringRpc,
    },
];

const TRANSPORT_SCENARIO_PLANS: &[TransportScenarioPlan] = &[
    TransportScenarioPlan {
        name: "tcp_rst_mid_handshake",
        fault_class: TransportFaultClass::TcpRstMidHandshake,
        span_name: "fcp.chaos.transport.tcp_rst_mid_handshake",
        affected_units: 1,
        steps: TCP_RST_MID_HANDSHAKE_STEPS,
    },
    TransportScenarioPlan {
        name: "tcp_rst_during_rpc",
        fault_class: TransportFaultClass::TcpRstDuringRpc,
        span_name: "fcp.chaos.transport.tcp_rst_during_rpc",
        affected_units: 1,
        steps: TCP_RST_DURING_RPC_STEPS,
    },
];

/// Find the static implementation plan for a transport scenario.
#[must_use]
pub fn plan_for_scenario(name: &str) -> Option<&'static TransportScenarioPlan> {
    TRANSPORT_SCENARIO_PLANS
        .iter()
        .find(|plan| plan.name == name)
}

/// Dry-run a transport scenario with its default bounded synthetic radius.
///
/// # Errors
///
/// Returns [`TransportScenarioError::UnknownScenario`] when the parsed TOML
/// scenario does not map to a transport implementation plan.
pub fn dry_run_transport_scenario(
    scenario: &ChaosScenario,
    env: Env,
) -> Result<TransportDryRunOutcome, TransportScenarioError> {
    let plan = require_plan(scenario)?;
    let observed_radius = plan.affected_units.min(scenario.blast_radius);
    dry_run_transport_scenario_with_observed_radius(scenario, env, observed_radius)
}

/// Dry-run a transport scenario with a caller-supplied observed radius.
///
/// # Errors
///
/// Returns [`TransportScenarioError::UnknownScenario`] when the parsed TOML
/// scenario does not map to a transport implementation plan.
pub fn dry_run_transport_scenario_with_observed_radius(
    scenario: &ChaosScenario,
    env: Env,
    observed_radius: u32,
) -> Result<TransportDryRunOutcome, TransportScenarioError> {
    let plan = *require_plan(scenario)?;
    let _span = enter_transport_span(&plan);
    let mut steps_traced = Vec::with_capacity(plan.steps.len());

    info!(
        scenario = scenario.name.as_str(),
        fault_class = plan.fault_class.as_str(),
        span = plan.span_name,
        step_count = plan.steps.len(),
        "starting transport chaos dry run"
    );
    for step in plan.steps {
        info!(
            scenario = scenario.name.as_str(),
            step = step.name,
            action = step.action,
            target = step.target,
            fault_class = step.class.as_str(),
            "transport chaos dry-run step"
        );
        steps_traced.push(step.name);
    }

    let outcome =
        ChaosInjector::new(env).run_scenario_with_observed_radius(scenario, observed_radius);
    let rollback_transport_state_restored = rollback_restores_transport_state(scenario);
    info!(
        scenario = scenario.name.as_str(),
        outcome = ?outcome.status,
        rollback_transport_state_restored,
        "transport chaos dry run ended"
    );

    Ok(TransportDryRunOutcome {
        plan,
        steps_traced,
        outcome,
        rollback_transport_state_restored,
    })
}

fn require_plan(
    scenario: &ChaosScenario,
) -> Result<&'static TransportScenarioPlan, TransportScenarioError> {
    plan_for_scenario(&scenario.name).ok_or_else(|| TransportScenarioError::UnknownScenario {
        name: scenario.name.clone(),
    })
}

fn rollback_restores_transport_state(scenario: &ChaosScenario) -> bool {
    scenario.rollback_steps.iter().any(|step| {
        step.action.contains("clear")
            || step.action.contains("restore")
            || step.action.contains("verify")
            || step.action.contains("reconnect")
    })
}

fn enter_transport_span(plan: &TransportScenarioPlan) -> EnteredSpan {
    match plan.name {
        "tcp_rst_mid_handshake" => info_span!(
            "fcp.chaos.transport.tcp_rst_mid_handshake",
            scenario = plan.name
        )
        .entered(),
        "tcp_rst_during_rpc" => info_span!(
            "fcp.chaos.transport.tcp_rst_during_rpc",
            scenario = plan.name
        )
        .entered(),
        _ => info_span!("fcp.chaos.transport.unknown", scenario = plan.name).entered(),
    }
}
