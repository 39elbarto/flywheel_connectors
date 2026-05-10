use fcp_host::{
    DeploymentMode, MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE, MeshQuorumSignals,
    TRUTH_PRECEDENCE_BOOT_CONFIG_EXIT_CODE, TruthPrecedenceBootError,
    V2_INSUFFICIENT_PEERS_BEHAVIOR_ENV, V2InsufficientPeersBehavior,
    resolve_truth_precedence_boot_resolution,
};
use fcp_policy::OperationalModelVersion;

#[test]
fn happy_path_two_peers_keeps_v2_active() {
    let resolution = resolve_truth_precedence_boot_resolution(
        MeshQuorumSignals::fully_active(2),
        Some("v2"),
        Some("refuse-boot"),
        None,
        None,
    )
    .expect("healthy peers should allow V2");

    assert_eq!(resolution.classification.mode, DeploymentMode::MeshActive);
    assert_eq!(
        resolution.selection.requested,
        OperationalModelVersion::V2MeshNative
    );
    assert_eq!(
        resolution.selection.effective,
        OperationalModelVersion::V2MeshNative
    );
    assert!(!resolution.selection.insufficient_peers);
}

#[test]
fn empty_input_zero_peers_degrades_to_v1_by_default() {
    let resolution = resolve_truth_precedence_boot_resolution(
        MeshQuorumSignals::single_host_evaluation(),
        Some("v2"),
        None,
        None,
        None,
    )
    .expect("default insufficient-peer behavior should degrade");

    assert_eq!(resolution.classification.mode, DeploymentMode::Evaluation);
    assert_eq!(
        resolution.selection.behavior_chosen,
        V2InsufficientPeersBehavior::DegradeToV1
    );
    assert_eq!(
        resolution.selection.effective,
        OperationalModelVersion::V1HostFirst
    );
    assert_eq!(
        resolution.selection.degraded_from.as_deref(),
        Some("v2-insufficient-peers")
    );
}

#[test]
fn boundary_peer_count_equal_to_minimum_keeps_v2_active() {
    let resolution = resolve_truth_precedence_boot_resolution(
        MeshQuorumSignals::fully_active(MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE),
        Some("v2"),
        Some("refuse-boot"),
        None,
        None,
    )
    .expect("peer count exactly at minimum should be active");

    assert_eq!(resolution.classification.mode, DeploymentMode::MeshActive);
    assert_eq!(
        resolution.selection.effective,
        OperationalModelVersion::V2MeshNative
    );
}

#[test]
fn conflicting_env_vars_apply_documented_precedence() {
    let resolution = resolve_truth_precedence_boot_resolution(
        MeshQuorumSignals::fully_active(1),
        Some("v1"),
        Some("degrade-to-v1"),
        Some("true"),
        None,
    )
    .expect("graduated flag should override explicit v1");

    assert!(resolution.selection.graduated_v2_default);
    assert_eq!(
        resolution.selection.requested,
        OperationalModelVersion::V2MeshNative
    );
    assert_eq!(
        resolution.selection.effective,
        OperationalModelVersion::V2MeshNative
    );
}

#[test]
fn network_failure_peer_drop_switches_to_degraded_v1_resolution() {
    let healthy = resolve_truth_precedence_boot_resolution(
        MeshQuorumSignals::fully_active(1),
        Some("v2"),
        Some("degrade-to-v1"),
        None,
        None,
    )
    .expect("healthy peer should allow V2");
    let dropped = resolve_truth_precedence_boot_resolution(
        MeshQuorumSignals::single_host_evaluation(),
        Some("v2"),
        Some("degrade-to-v1"),
        None,
        None,
    )
    .expect("peer drop should degrade, not refuse");

    assert_eq!(
        healthy.selection.effective,
        OperationalModelVersion::V2MeshNative
    );
    assert_eq!(
        dropped.selection.effective,
        OperationalModelVersion::V1HostFirst
    );
    assert!(dropped.selection.insufficient_peers);
}

#[test]
fn authorization_failure_behavior_typo_is_config_error_exit_78() {
    let error = resolve_truth_precedence_boot_resolution(
        MeshQuorumSignals::single_host_evaluation(),
        Some("v2"),
        Some("refus-boot"),
        None,
        None,
    )
    .expect_err("behavior typo must fail closed");

    assert_eq!(TRUTH_PRECEDENCE_BOOT_CONFIG_EXIT_CODE, 78);
    assert!(matches!(
        error,
        TruthPrecedenceBootError::InvalidEnvValue {
            var: V2_INSUFFICIENT_PEERS_BEHAVIOR_ENV,
            ..
        }
    ));
}

#[test]
fn recovery_after_restart_is_deterministic() {
    let degraded = resolve_truth_precedence_boot_resolution(
        MeshQuorumSignals::single_host_evaluation(),
        Some("v2"),
        Some("degrade-to-v1"),
        None,
        None,
    )
    .expect("zero peers should degrade");
    let recovered = resolve_truth_precedence_boot_resolution(
        MeshQuorumSignals::fully_active(1),
        Some("v2"),
        Some("degrade-to-v1"),
        None,
        None,
    )
    .expect("recovered peer should restore V2");

    assert_eq!(
        degraded.selection.effective,
        OperationalModelVersion::V1HostFirst
    );
    assert_eq!(
        recovered.selection.effective,
        OperationalModelVersion::V2MeshNative
    );
}

#[test]
fn configuration_error_graduated_refuse_boot_with_zero_peers_refuses() {
    let error = resolve_truth_precedence_boot_resolution(
        MeshQuorumSignals::single_host_evaluation(),
        Some("v1"),
        Some("refuse-boot"),
        Some("true"),
        None,
    )
    .expect_err("graduated V2 with refuse-boot and zero peers must refuse");

    assert!(matches!(
        error,
        TruthPrecedenceBootError::RefusedBoot {
            observed: 0,
            required: MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
            behavior: V2InsufficientPeersBehavior::RefuseBoot,
            ..
        }
    ));
}
