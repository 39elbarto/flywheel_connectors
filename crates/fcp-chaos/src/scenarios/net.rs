//! Network-class chaos scenarios.
//!
//! This module is a dry-run implementation layer for the declarative TOML DSL.
//! It traces the synthetic packet/link actions each scenario would apply, then
//! delegates blast-radius and rollback accounting to [`crate::ChaosInjector`].

use thiserror::Error;
use tracing::{debug, info, info_span, span::EnteredSpan};

use crate::{ChaosInjector, ChaosOutcome, ChaosScenario, Env};

/// Canonical network scenario names.
pub const NETWORK_SCENARIOS: &[&str] = &[
    "net_partition_bisecting",
    "net_partition_asymmetric",
    "net_partition_derp_only",
    "net_partition_full",
    "packet_drop_1pct",
    "packet_drop_10pct",
    "packet_drop_50pct",
    "packet_reorder",
    "packet_duplication",
    "latency_spike_100x",
    "bandwidth_throttle_1mbps",
];

/// Family of network fault being simulated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkFaultClass {
    /// Peer-to-peer reachability partition.
    Partition,
    /// Packet loss injection.
    PacketDrop,
    /// Packet ordering perturbation.
    PacketReorder,
    /// Packet duplication.
    PacketDuplication,
    /// Latency increase.
    LatencySpike,
    /// Bandwidth shaping.
    BandwidthThrottle,
}

impl NetworkFaultClass {
    /// Stable log label for the class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Partition => "partition",
            Self::PacketDrop => "packet_drop",
            Self::PacketReorder => "packet_reorder",
            Self::PacketDuplication => "packet_duplication",
            Self::LatencySpike => "latency_spike",
            Self::BandwidthThrottle => "bandwidth_throttle",
        }
    }
}

/// One synthetic network step in a dry-run scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkStep {
    /// Stable step name.
    pub name: &'static str,
    /// Synthetic action identifier.
    pub action: &'static str,
    /// Synthetic target affected by the action.
    pub target: &'static str,
    /// Fault class for log filtering.
    pub class: NetworkFaultClass,
}

/// Static implementation plan for a named scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkScenarioPlan {
    /// Scenario name matching the TOML `name` field.
    pub name: &'static str,
    /// Fault family.
    pub fault_class: NetworkFaultClass,
    /// OTLP span name required by the runbook contract.
    pub span_name: &'static str,
    /// Synthetic affected units in the default dry run.
    pub affected_units: u32,
    /// Ordered dry-run steps.
    pub steps: &'static [NetworkStep],
}

/// Dry-run result for a network scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDryRunOutcome {
    /// Static scenario plan used for the run.
    pub plan: NetworkScenarioPlan,
    /// Step names emitted by the dry run.
    pub steps_traced: Vec<&'static str>,
    /// Guardrail outcome from the generic chaos injector.
    pub outcome: ChaosOutcome,
    /// Whether declared rollback steps include a network-state restore action.
    pub rollback_network_state_restored: bool,
}

/// Recovery-SLA report for synthetic network checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoverySlaReport {
    /// Number of synthetic peers in the fixture.
    pub peer_count: u32,
    /// Seconds after start when the fault healed.
    pub heal_after_secs: u64,
    /// Scenario recovery objective.
    pub recovery_objective_secs: u64,
    /// Synthetic convergence time after heal.
    pub reconvergence_secs: u64,
    /// Whether the recovery objective was held.
    pub slo_held: bool,
}

/// Network scenario lookup and validation errors.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum NetScenarioError {
    /// Scenario name has no network implementation plan.
    #[error("unknown network chaos scenario `{name}`")]
    UnknownScenario {
        /// Unknown scenario name.
        name: String,
    },
}

const PARTITION_BISECTING_STEPS: &[NetworkStep] = &[
    NetworkStep {
        name: "split_peer_set",
        action: "iptables_drop_between_peer_sets",
        target: "synthetic_mesh",
        class: NetworkFaultClass::Partition,
    },
    NetworkStep {
        name: "hold_bisecting_partition",
        action: "maintain_partition_until_heal",
        target: "synthetic_mesh",
        class: NetworkFaultClass::Partition,
    },
];

const PARTITION_ASYMMETRIC_STEPS: &[NetworkStep] = &[
    NetworkStep {
        name: "drop_one_way_peer_links",
        action: "iptables_drop_egress_subset",
        target: "synthetic_mesh",
        class: NetworkFaultClass::Partition,
    },
    NetworkStep {
        name: "preserve_reverse_path",
        action: "leave_ingress_unmodified",
        target: "synthetic_mesh",
        class: NetworkFaultClass::Partition,
    },
];

const PARTITION_DERP_ONLY_STEPS: &[NetworkStep] = &[
    NetworkStep {
        name: "block_direct_peer_paths",
        action: "iptables_drop_direct_tailnet",
        target: "synthetic_mesh",
        class: NetworkFaultClass::Partition,
    },
    NetworkStep {
        name: "allow_derp_relay",
        action: "preserve_derp_relay_path",
        target: "synthetic_mesh",
        class: NetworkFaultClass::Partition,
    },
];

const PARTITION_FULL_STEPS: &[NetworkStep] = &[
    NetworkStep {
        name: "drop_all_peer_links",
        action: "iptables_drop_all_mesh_peers",
        target: "synthetic_mesh",
        class: NetworkFaultClass::Partition,
    },
    NetworkStep {
        name: "hold_full_partition",
        action: "maintain_partition_until_heal",
        target: "synthetic_mesh",
        class: NetworkFaultClass::Partition,
    },
];

const PACKET_DROP_STEPS: &[NetworkStep] = &[
    NetworkStep {
        name: "install_packet_loss_qdisc",
        action: "tc_netem_loss",
        target: "synthetic_mesh",
        class: NetworkFaultClass::PacketDrop,
    },
    NetworkStep {
        name: "sample_loss_counters",
        action: "read_tc_packet_loss_counters",
        target: "synthetic_mesh",
        class: NetworkFaultClass::PacketDrop,
    },
];

const PACKET_REORDER_STEPS: &[NetworkStep] = &[
    NetworkStep {
        name: "install_reorder_qdisc",
        action: "tc_netem_reorder",
        target: "synthetic_mesh",
        class: NetworkFaultClass::PacketReorder,
    },
    NetworkStep {
        name: "sample_reorder_counters",
        action: "read_tc_reorder_counters",
        target: "synthetic_mesh",
        class: NetworkFaultClass::PacketReorder,
    },
];

const PACKET_DUPLICATION_STEPS: &[NetworkStep] = &[
    NetworkStep {
        name: "install_duplication_qdisc",
        action: "tc_netem_duplicate",
        target: "synthetic_mesh",
        class: NetworkFaultClass::PacketDuplication,
    },
    NetworkStep {
        name: "sample_duplication_counters",
        action: "read_tc_duplicate_counters",
        target: "synthetic_mesh",
        class: NetworkFaultClass::PacketDuplication,
    },
];

const LATENCY_SPIKE_STEPS: &[NetworkStep] = &[
    NetworkStep {
        name: "install_latency_qdisc",
        action: "tc_netem_delay_rtt_x100",
        target: "synthetic_mesh",
        class: NetworkFaultClass::LatencySpike,
    },
    NetworkStep {
        name: "sample_rtt_histogram",
        action: "read_mesh_rtt_histogram",
        target: "synthetic_mesh",
        class: NetworkFaultClass::LatencySpike,
    },
];

const BANDWIDTH_THROTTLE_STEPS: &[NetworkStep] = &[
    NetworkStep {
        name: "install_bandwidth_limit",
        action: "tc_tbf_rate_1mbps",
        target: "synthetic_mesh",
        class: NetworkFaultClass::BandwidthThrottle,
    },
    NetworkStep {
        name: "sample_throughput",
        action: "read_mesh_throughput_counters",
        target: "synthetic_mesh",
        class: NetworkFaultClass::BandwidthThrottle,
    },
];

const NETWORK_SCENARIO_PLANS: &[NetworkScenarioPlan] = &[
    NetworkScenarioPlan {
        name: "net_partition_bisecting",
        fault_class: NetworkFaultClass::Partition,
        span_name: "fcp.chaos.net.net_partition_bisecting",
        affected_units: 2,
        steps: PARTITION_BISECTING_STEPS,
    },
    NetworkScenarioPlan {
        name: "net_partition_asymmetric",
        fault_class: NetworkFaultClass::Partition,
        span_name: "fcp.chaos.net.net_partition_asymmetric",
        affected_units: 2,
        steps: PARTITION_ASYMMETRIC_STEPS,
    },
    NetworkScenarioPlan {
        name: "net_partition_derp_only",
        fault_class: NetworkFaultClass::Partition,
        span_name: "fcp.chaos.net.net_partition_derp_only",
        affected_units: 3,
        steps: PARTITION_DERP_ONLY_STEPS,
    },
    NetworkScenarioPlan {
        name: "net_partition_full",
        fault_class: NetworkFaultClass::Partition,
        span_name: "fcp.chaos.net.net_partition_full",
        affected_units: 4,
        steps: PARTITION_FULL_STEPS,
    },
    NetworkScenarioPlan {
        name: "packet_drop_1pct",
        fault_class: NetworkFaultClass::PacketDrop,
        span_name: "fcp.chaos.net.packet_drop_1pct",
        affected_units: 1,
        steps: PACKET_DROP_STEPS,
    },
    NetworkScenarioPlan {
        name: "packet_drop_10pct",
        fault_class: NetworkFaultClass::PacketDrop,
        span_name: "fcp.chaos.net.packet_drop_10pct",
        affected_units: 2,
        steps: PACKET_DROP_STEPS,
    },
    NetworkScenarioPlan {
        name: "packet_drop_50pct",
        fault_class: NetworkFaultClass::PacketDrop,
        span_name: "fcp.chaos.net.packet_drop_50pct",
        affected_units: 3,
        steps: PACKET_DROP_STEPS,
    },
    NetworkScenarioPlan {
        name: "packet_reorder",
        fault_class: NetworkFaultClass::PacketReorder,
        span_name: "fcp.chaos.net.packet_reorder",
        affected_units: 2,
        steps: PACKET_REORDER_STEPS,
    },
    NetworkScenarioPlan {
        name: "packet_duplication",
        fault_class: NetworkFaultClass::PacketDuplication,
        span_name: "fcp.chaos.net.packet_duplication",
        affected_units: 2,
        steps: PACKET_DUPLICATION_STEPS,
    },
    NetworkScenarioPlan {
        name: "latency_spike_100x",
        fault_class: NetworkFaultClass::LatencySpike,
        span_name: "fcp.chaos.net.latency_spike_100x",
        affected_units: 3,
        steps: LATENCY_SPIKE_STEPS,
    },
    NetworkScenarioPlan {
        name: "bandwidth_throttle_1mbps",
        fault_class: NetworkFaultClass::BandwidthThrottle,
        span_name: "fcp.chaos.net.bandwidth_throttle_1mbps",
        affected_units: 3,
        steps: BANDWIDTH_THROTTLE_STEPS,
    },
];

/// Find the static implementation plan for a network scenario.
#[must_use]
pub fn plan_for_scenario(name: &str) -> Option<&'static NetworkScenarioPlan> {
    NETWORK_SCENARIO_PLANS.iter().find(|plan| plan.name == name)
}

/// Dry-run a network scenario with its default bounded synthetic radius.
///
/// # Errors
///
/// Returns [`NetScenarioError::UnknownScenario`] when the parsed TOML scenario
/// does not map to a network implementation plan.
pub fn dry_run_network_scenario(
    scenario: &ChaosScenario,
    env: Env,
) -> Result<NetworkDryRunOutcome, NetScenarioError> {
    let plan = require_plan(scenario)?;
    let observed_radius = plan.affected_units.min(scenario.blast_radius);
    dry_run_network_scenario_with_observed_radius(scenario, env, observed_radius)
}

/// Dry-run a network scenario with a caller-supplied observed radius.
///
/// # Errors
///
/// Returns [`NetScenarioError::UnknownScenario`] when the parsed TOML scenario
/// does not map to a network implementation plan.
pub fn dry_run_network_scenario_with_observed_radius(
    scenario: &ChaosScenario,
    env: Env,
    observed_radius: u32,
) -> Result<NetworkDryRunOutcome, NetScenarioError> {
    let plan = *require_plan(scenario)?;
    let _span = enter_network_span(&plan);
    let mut steps_traced = Vec::with_capacity(plan.steps.len());

    info!(
        scenario = scenario.name.as_str(),
        fault_class = plan.fault_class.as_str(),
        span = plan.span_name,
        step_count = plan.steps.len(),
        "starting network chaos dry run"
    );
    for step in plan.steps {
        info!(
            scenario = scenario.name.as_str(),
            step = step.name,
            action = step.action,
            target = step.target,
            fault_class = step.class.as_str(),
            "network chaos dry-run step"
        );
        if matches!(
            step.class,
            NetworkFaultClass::PacketDrop
                | NetworkFaultClass::PacketReorder
                | NetworkFaultClass::PacketDuplication
        ) {
            debug!(
                scenario = scenario.name.as_str(),
                step = step.name,
                "packet-level dry-run counters suppressed by default"
            );
        }
        steps_traced.push(step.name);
    }

    let outcome =
        ChaosInjector::new(env).run_scenario_with_observed_radius(scenario, observed_radius);
    let rollback_network_state_restored = rollback_restores_network_state(scenario);
    info!(
        scenario = scenario.name.as_str(),
        outcome = ?outcome.status,
        rollback_network_state_restored,
        "network chaos dry run ended"
    );

    Ok(NetworkDryRunOutcome {
        plan,
        steps_traced,
        outcome,
        rollback_network_state_restored,
    })
}

/// Verify the synthetic bisecting-partition recovery SLA.
///
/// # Errors
///
/// Returns [`NetScenarioError::UnknownScenario`] when the scenario is not the
/// canonical bisecting network partition scenario.
pub fn verify_bisecting_partition_recovery_sla(
    scenario: &ChaosScenario,
    peer_count: u32,
    heal_after_secs: u64,
) -> Result<RecoverySlaReport, NetScenarioError> {
    let plan = require_plan(scenario)?;
    if plan.name != "net_partition_bisecting" {
        return Err(NetScenarioError::UnknownScenario {
            name: scenario.name.clone(),
        });
    }

    let remaining_secs = scenario
        .recovery_objective_secs
        .saturating_sub(heal_after_secs);
    let reconvergence_secs = synthetic_reconvergence_secs(peer_count);
    Ok(RecoverySlaReport {
        peer_count,
        heal_after_secs,
        recovery_objective_secs: scenario.recovery_objective_secs,
        reconvergence_secs,
        slo_held: reconvergence_secs <= remaining_secs,
    })
}

fn require_plan(
    scenario: &ChaosScenario,
) -> Result<&'static NetworkScenarioPlan, NetScenarioError> {
    plan_for_scenario(&scenario.name).ok_or_else(|| NetScenarioError::UnknownScenario {
        name: scenario.name.clone(),
    })
}

fn rollback_restores_network_state(scenario: &ChaosScenario) -> bool {
    scenario.rollback_steps.iter().any(|step| {
        step.action.contains("restore")
            || step.action.contains("clear_iptables")
            || step.action.contains("clear_tc")
    })
}

const fn synthetic_reconvergence_secs(peer_count: u32) -> u64 {
    match peer_count {
        0 | 1 => 0,
        2..=5 => 1,
        6..=10 => 2,
        _ => 3,
    }
}

fn enter_network_span(plan: &NetworkScenarioPlan) -> EnteredSpan {
    match plan.name {
        "net_partition_bisecting" => info_span!(
            "fcp.chaos.net.net_partition_bisecting",
            scenario = plan.name
        )
        .entered(),
        "net_partition_asymmetric" => info_span!(
            "fcp.chaos.net.net_partition_asymmetric",
            scenario = plan.name
        )
        .entered(),
        "net_partition_derp_only" => info_span!(
            "fcp.chaos.net.net_partition_derp_only",
            scenario = plan.name
        )
        .entered(),
        "net_partition_full" => {
            info_span!("fcp.chaos.net.net_partition_full", scenario = plan.name).entered()
        }
        "packet_drop_1pct" => {
            info_span!("fcp.chaos.net.packet_drop_1pct", scenario = plan.name).entered()
        }
        "packet_drop_10pct" => {
            info_span!("fcp.chaos.net.packet_drop_10pct", scenario = plan.name).entered()
        }
        "packet_drop_50pct" => {
            info_span!("fcp.chaos.net.packet_drop_50pct", scenario = plan.name).entered()
        }
        "packet_reorder" => {
            info_span!("fcp.chaos.net.packet_reorder", scenario = plan.name).entered()
        }
        "packet_duplication" => {
            info_span!("fcp.chaos.net.packet_duplication", scenario = plan.name).entered()
        }
        "latency_spike_100x" => {
            info_span!("fcp.chaos.net.latency_spike_100x", scenario = plan.name).entered()
        }
        "bandwidth_throttle_1mbps" => info_span!(
            "fcp.chaos.net.bandwidth_throttle_1mbps",
            scenario = plan.name
        )
        .entered(),
        _ => info_span!("fcp.chaos.net.unknown", scenario = plan.name).entered(),
    }
}
