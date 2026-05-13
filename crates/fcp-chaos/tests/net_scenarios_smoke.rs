use std::path::PathBuf;

use fcp_chaos::scenarios::net::{NETWORK_SCENARIOS, dry_run_network_scenario};
use fcp_chaos::{ChaosScenario, ChaosStatus, Env};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn scenario_path(name: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../scenarios/net")
        .join(format!("{name}.toml"))
}

fn load_scenario(name: &str) -> Result<ChaosScenario, fcp_chaos::DslError> {
    ChaosScenario::from_path(&scenario_path(name))
}

macro_rules! net_scenario_tests {
    ($parse_name:ident, $dry_run_name:ident, $scenario_name:literal) => {
        #[test]
        fn $parse_name() -> TestResult {
            let scenario = load_scenario($scenario_name)?;
            assert_eq!(scenario.name, $scenario_name);
            assert!(scenario.blast_radius > 0);
            assert!(scenario.recovery_objective_secs > 0);
            assert!(!scenario.rollback_steps.is_empty());
            assert!(NETWORK_SCENARIOS.contains(&$scenario_name));
            Ok(())
        }

        #[test]
        fn $dry_run_name() -> TestResult {
            let scenario = load_scenario($scenario_name)?;
            let dry_run = dry_run_network_scenario(&scenario, Env::Staging)?;
            assert_eq!(dry_run.outcome.status, ChaosStatus::Completed);
            assert_eq!(
                dry_run.outcome.rollback_steps_executed.len(),
                scenario.rollback_steps.len()
            );
            assert!(dry_run.rollback_network_state_restored);
            assert!(!dry_run.steps_traced.is_empty());
            Ok(())
        }
    };
}

net_scenario_tests!(
    test_net_partition_bisecting_parses,
    test_net_partition_bisecting_dry_run_succeeds,
    "net_partition_bisecting"
);
net_scenario_tests!(
    test_net_partition_asymmetric_parses,
    test_net_partition_asymmetric_dry_run_succeeds,
    "net_partition_asymmetric"
);
net_scenario_tests!(
    test_net_partition_derp_only_parses,
    test_net_partition_derp_only_dry_run_succeeds,
    "net_partition_derp_only"
);
net_scenario_tests!(
    test_net_partition_full_parses,
    test_net_partition_full_dry_run_succeeds,
    "net_partition_full"
);
net_scenario_tests!(
    test_packet_drop_1pct_parses,
    test_packet_drop_1pct_dry_run_succeeds,
    "packet_drop_1pct"
);
net_scenario_tests!(
    test_packet_drop_10pct_parses,
    test_packet_drop_10pct_dry_run_succeeds,
    "packet_drop_10pct"
);
net_scenario_tests!(
    test_packet_drop_50pct_parses,
    test_packet_drop_50pct_dry_run_succeeds,
    "packet_drop_50pct"
);
net_scenario_tests!(
    test_packet_reorder_parses,
    test_packet_reorder_dry_run_succeeds,
    "packet_reorder"
);
net_scenario_tests!(
    test_packet_duplication_parses,
    test_packet_duplication_dry_run_succeeds,
    "packet_duplication"
);
net_scenario_tests!(
    test_latency_spike_100x_parses,
    test_latency_spike_100x_dry_run_succeeds,
    "latency_spike_100x"
);
net_scenario_tests!(
    test_bandwidth_throttle_1mbps_parses,
    test_bandwidth_throttle_1mbps_dry_run_succeeds,
    "bandwidth_throttle_1mbps"
);
