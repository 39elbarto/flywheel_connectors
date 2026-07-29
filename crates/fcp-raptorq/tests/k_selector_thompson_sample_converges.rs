use std::time::Duration;

use fcp_raptorq::{
    ArmRegistry, CodeFamily, EncodingDecision, KSelectorArm, KSelectorObservation, RaptorQConfig,
    RaptorQEncoder,
};

const fn base_config() -> RaptorQConfig {
    RaptorQConfig {
        symbol_size: 64,
        repair_ratio_bps: 500,
        max_object_size: 16 * 1024,
        decode_timeout: Duration::from_secs(30),
        max_chunk_threshold: 8 * 1024,
        chunk_size: 1024,
    }
}

fn observation_for(arm: KSelectorArm, optimal: KSelectorArm) -> KSelectorObservation {
    if arm == optimal {
        KSelectorObservation::new(120, false)
    } else if matches!(arm.code_family, CodeFamily::HighRepairRaptorQ) {
        KSelectorObservation::new(90, true)
    } else {
        KSelectorObservation::new(2_500, false)
    }
}

#[test]
fn k_selector_thompson_sample_converges_on_optimal_arm() {
    let optimal = KSelectorArm::new(8, CodeFamily::SystematicRaptorQ, 1_000);
    let slow = KSelectorArm::new(16, CodeFamily::SystematicRaptorQ, 1_000);
    let lossy = KSelectorArm::new(8, CodeFamily::HighRepairRaptorQ, 5_000);
    let mut registry = ArmRegistry::new().with_target_decode_latency_us(1_000);
    for arm in [optimal, slow, lossy] {
        registry.register_arm(arm);
        registry.observe(arm, observation_for(arm, optimal));
    }

    for round in 0..240_u64 {
        let selected = registry
            .recommend(1024, round)
            .expect("registered arms support payload");
        registry.observe(selected, observation_for(selected, optimal));
    }

    let selected = registry
        .recommend(1024, 10_000)
        .expect("selector has a converged arm");
    assert_eq!(selected, optimal);
    let optimal_mean = registry.posterior(optimal).unwrap().mean_ppm();
    assert!(optimal_mean > registry.posterior(slow).unwrap().mean_ppm());
    assert!(optimal_mean > registry.posterior(lossy).unwrap().mean_ppm());
}

#[test]
fn selected_config_maps_arm_k_to_symbol_size() {
    let arm = KSelectorArm::new(8, CodeFamily::SystematicRaptorQ, 2_000);
    let mut registry = ArmRegistry::new();
    registry.register_arm(arm);
    let payload = vec![7_u8; 1024];
    let config = registry.selected_config(payload.len(), &base_config(), 42);

    assert_eq!(config.symbol_size, 128);
    assert_eq!(config.repair_ratio_bps, 2_000);
    let encoder = RaptorQEncoder::new_with_k_selector(&payload, &base_config(), &registry, 42)
        .expect("selected config encodes");
    assert_eq!(encoder.source_symbols(), 8);
}

#[test]
fn empty_registry_preserves_static_config_fallback() {
    let registry = ArmRegistry::new();
    let payload = vec![9_u8; 512];
    let config = base_config();

    let selected = registry.selected_config(payload.len(), &config, 7);
    assert_eq!(selected.symbol_size, config.symbol_size);
    assert_eq!(selected.repair_ratio_bps, config.repair_ratio_bps);

    let decision = EncodingDecision::for_payload_with_k_selector(&payload, &config, &registry, 7)
        .expect("static fallback encodes");
    assert!(decision.is_direct());
}
