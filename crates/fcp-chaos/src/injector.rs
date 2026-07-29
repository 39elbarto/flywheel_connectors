//! Chaos injector guardrails.

use std::time::Instant;

use thiserror::Error;
use tracing::{error, info, info_span, warn};

use crate::dsl::ChaosScenario;

/// Deployment environment for chaos runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Env {
    /// Local development environment.
    Development,
    /// Test environment.
    Test,
    /// Staging environment where chaos is allowed.
    Staging,
    /// Production environment where chaos is blocked.
    Production,
}

impl Env {
    /// Parse a deployment mode value.
    #[must_use]
    pub fn from_deploy_mode(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "production" | "prod" => Self::Production,
            "staging" | "stage" => Self::Staging,
            "test" | "testing" => Self::Test,
            _ => Self::Development,
        }
    }

    /// Return the stable log tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Test => "test",
            Self::Staging => "staging",
            Self::Production => "production",
        }
    }
}

/// Terminal status of a chaos scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaosStatus {
    /// Scenario completed within its declared blast radius.
    Completed,
    /// Scenario was aborted by a guardrail.
    Aborted,
}

/// Runtime chaos guard errors.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ChaosError {
    /// The observed effect exceeded the declared blast radius.
    #[error("blast radius exceeded: declared={declared}, observed={observed}")]
    BlastRadiusExceeded {
        /// Declared maximum.
        declared: u32,
        /// Observed affected units.
        observed: u32,
    },
}

/// Outcome of a scenario run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChaosOutcome {
    /// Scenario name.
    pub scenario: String,
    /// Environment tag.
    pub env: Env,
    /// Completion or abort status.
    pub status: ChaosStatus,
    /// Number of synthetic units affected.
    pub affected_units: u32,
    /// Rollback step names that were executed.
    pub rollback_steps_executed: Vec<String>,
    /// Guard error when the scenario was aborted.
    pub error: Option<ChaosError>,
    /// Recovery time observed by the harness.
    pub recovery_actual_secs: u64,
}

/// Staging-only chaos injector.
#[derive(Debug, Clone)]
pub struct ChaosInjector {
    env: Env,
}

impl ChaosInjector {
    /// Create a chaos injector.
    ///
    /// # Panics
    ///
    /// Panics when `env` is [`Env::Production`].
    #[must_use]
    pub fn new(env: Env) -> Self {
        assert!(
            env != Env::Production,
            "chaos injector blocked under production"
        );
        Self { env }
    }

    /// Create from a deployment-mode string such as `staging` or `production`.
    ///
    /// # Panics
    ///
    /// Panics when the parsed deployment mode is production.
    #[must_use]
    pub fn from_deploy_mode(value: &str) -> Self {
        Self::new(Env::from_deploy_mode(value))
    }

    /// Run a scenario with the default bounded synthetic effect.
    #[must_use]
    pub fn run_scenario(&self, scenario: &ChaosScenario) -> ChaosOutcome {
        let affected_units = scenario.blast_radius.min(1);
        self.run_scenario_with_observed_radius(scenario, affected_units)
    }

    /// Run a scenario with a caller-supplied observed blast radius.
    #[must_use]
    pub fn run_scenario_with_observed_radius(
        &self,
        scenario: &ChaosScenario,
        observed_radius: u32,
    ) -> ChaosOutcome {
        let started_at = Instant::now();
        let _span = info_span!(
            "fcp.chaos.scenario",
            scenario = scenario.name.as_str(),
            env = self.env.as_str(),
            outcome = tracing::field::Empty,
            recovery_actual_s = tracing::field::Empty,
        )
        .entered();
        info!(
            scenario = scenario.name.as_str(),
            env = self.env.as_str(),
            blast_radius = scenario.blast_radius,
            recovery_target_secs = scenario.recovery_objective_secs,
            outcome = "started",
            "starting chaos scenario"
        );

        if observed_radius.saturating_mul(100) >= scenario.blast_radius.saturating_mul(80) {
            warn!(
                scenario = scenario.name.as_str(),
                current = observed_radius,
                declared = scenario.blast_radius,
                "chaos scenario approaching declared blast radius"
            );
        }

        let rollback_steps_executed = rollback_step_names(scenario);
        let recovery_actual_secs = started_at.elapsed().as_secs();
        if observed_radius > scenario.blast_radius {
            let error = ChaosError::BlastRadiusExceeded {
                declared: scenario.blast_radius,
                observed: observed_radius,
            };
            error!(
                scenario = scenario.name.as_str(),
                declared = scenario.blast_radius,
                observed = observed_radius,
                abort = true,
                "BlastRadiusExceeded"
            );
            info!(
                scenario = scenario.name.as_str(),
                env = self.env.as_str(),
                blast_radius = scenario.blast_radius,
                recovery_actual_secs,
                outcome = "aborted",
                "chaos scenario ended"
            );
            return ChaosOutcome {
                scenario: scenario.name.clone(),
                env: self.env,
                status: ChaosStatus::Aborted,
                affected_units: observed_radius,
                rollback_steps_executed,
                error: Some(error),
                recovery_actual_secs,
            };
        }

        info!(
            scenario = scenario.name.as_str(),
            env = self.env.as_str(),
            blast_radius = scenario.blast_radius,
            recovery_actual_secs,
            outcome = "completed",
            "chaos scenario ended"
        );
        ChaosOutcome {
            scenario: scenario.name.clone(),
            env: self.env,
            status: ChaosStatus::Completed,
            affected_units: observed_radius,
            rollback_steps_executed,
            error: None,
            recovery_actual_secs,
        }
    }
}

/// Run a scenario in the supplied environment.
#[must_use]
pub fn run_scenario(scenario: &ChaosScenario, env: &Env) -> ChaosOutcome {
    ChaosInjector::new(*env).run_scenario(scenario)
}

fn rollback_step_names(scenario: &ChaosScenario) -> Vec<String> {
    scenario
        .rollback_steps
        .iter()
        .map(|step| step.name.clone())
        .collect()
}
