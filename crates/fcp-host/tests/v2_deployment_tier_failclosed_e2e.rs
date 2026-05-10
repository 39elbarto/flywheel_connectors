use fcp_host::{
    DeploymentTierRefusal, MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE, MeshQuorumSignals, admit_safety_tier,
    classify_deployment_mode_with_min_peers,
};
use fcp_prelude::SafetyTier;

#[test]
fn happy_path_peers_present_admits_risky_tier() {
    let classification = classify_deployment_mode_with_min_peers(
        MeshQuorumSignals::fully_active(MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE),
        MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
    );

    admit_safety_tier(&classification, SafetyTier::Risky)
        .expect("Risky tier should admit once mesh peer threshold is met");
}

#[test]
fn boundary_below_minimum_fails_closed_for_risky_tier() {
    let classification = classify_deployment_mode_with_min_peers(
        MeshQuorumSignals::single_host_evaluation(),
        MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
    );
    let error = admit_safety_tier(&classification, SafetyTier::Risky)
        .expect_err("Risky tier must fail closed without mesh peers");

    assert!(matches!(
        error,
        DeploymentTierRefusal::TierRequiresMeshActive {
            tier: SafetyTier::Risky,
            ..
        }
    ));
}

#[test]
fn recovery_peer_connects_admits_risky_without_restart() {
    let before = classify_deployment_mode_with_min_peers(
        MeshQuorumSignals::single_host_evaluation(),
        MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
    );
    let after = classify_deployment_mode_with_min_peers(
        MeshQuorumSignals::fully_active(MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE),
        MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
    );

    assert!(admit_safety_tier(&before, SafetyTier::Risky).is_err());
    admit_safety_tier(&after, SafetyTier::Risky)
        .expect("Risky tier should admit after a healthy peer connects");
}

#[test]
fn safe_tier_continues_during_v2_with_no_peers() {
    let classification = classify_deployment_mode_with_min_peers(
        MeshQuorumSignals::single_host_evaluation(),
        MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
    );

    admit_safety_tier(&classification, SafetyTier::Safe)
        .expect("Safe tier should continue in evaluation mode");
}
