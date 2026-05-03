#![no_main]

//! Replayability stub harness for host backpressure and conformal routing.
//!
//! This is the small profiling hand-off from `flywheel_connectors-2a1cu`: it
//! does not claim a performance win. It pins a deterministic, serializable
//! scenario shape so later conformal-backpressure profiling can replay the same
//! route/control decisions before measuring them.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::ZoneId;
use fcp_host::{
    BackpressureCalibration, BackpressureCalibrationStatus, BackpressureController,
    BackpressureControllerInput, BackpressureTelemetry, ConformalSloCalibrationSample,
    ConformalSloConfig, ConformalSloPredictor, ConformalSloRouteCandidate, RequestPriority,
};
use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

const MAX_CANDIDATES: usize = 5;
const MAX_SAMPLES: usize = 16;

#[derive(Arbitrary, Debug, Serialize, Deserialize)]
struct ReplayInput {
    subject_seed: u32,
    priority: u8,
    calibration_status: u8,
    coverage_per_mille: u16,
    min_coverage_per_mille: u16,
    queue_pressure_per_mille: Option<u16>,
    cpu_pressure_per_mille: Option<u16>,
    memory_pressure_per_mille: Option<u16>,
    downstream_retry_after_ms: Option<u64>,
    retry_amplification_per_mille: Option<u16>,
    useful_work_per_mille: Option<u16>,
    conformal_coverage_per_mille: u16,
    min_calibration_samples: u8,
    candidates: Vec<RouteSeed>,
    samples: Vec<SampleSeed>,
}

#[derive(Arbitrary, Debug, Clone, Serialize, Deserialize)]
struct RouteSeed {
    zone: u8,
    path: u8,
    estimated_latency_ms: u64,
    slo_budget_ms: u64,
    budget_remaining: Option<u64>,
}

#[derive(Arbitrary, Debug, Clone, Serialize, Deserialize)]
struct SampleSeed {
    zone: u8,
    path: u8,
    observed_latency_ms: u64,
    slo_budget_ms: u64,
    success: bool,
    budget_remaining: Option<u64>,
    observed_at_ms: u64,
}

fn zone(choice: u8) -> ZoneId {
    match choice % 5 {
        0 => ZoneId::owner(),
        1 => ZoneId::private(),
        2 => ZoneId::work(),
        3 => ZoneId::community(),
        _ => ZoneId::public(),
    }
}

fn path(choice: u8) -> &'static str {
    match choice % 4 {
        0 => "direct",
        1 => "tailnet",
        2 => "derp",
        _ => "relay",
    }
}

fn priority(choice: u8) -> RequestPriority {
    match choice % 4 {
        0 => RequestPriority::Critical,
        1 => RequestPriority::High,
        2 => RequestPriority::Normal,
        _ => RequestPriority::Low,
    }
}

fn calibration(input: &ReplayInput) -> BackpressureCalibration {
    match input.calibration_status % 5 {
        0 => BackpressureCalibration {
            status: BackpressureCalibrationStatus::Valid,
            coverage_per_mille: Some(input.coverage_per_mille.min(1_000)),
            min_coverage_per_mille: input.min_coverage_per_mille.min(1_000),
        },
        1 => BackpressureCalibration::coverage_drift(
            input.coverage_per_mille.min(1_000),
            input.min_coverage_per_mille.min(1_000),
        ),
        2 => BackpressureCalibration::fallback(BackpressureCalibrationStatus::MissingTelemetry),
        3 => BackpressureCalibration::fallback(BackpressureCalibrationStatus::ReplayMismatch),
        _ => BackpressureCalibration::fallback(
            BackpressureCalibrationStatus::ArtifactVerificationFailed,
        ),
    }
}

fn telemetry(input: &ReplayInput) -> BackpressureTelemetry {
    BackpressureTelemetry {
        queue_pressure_per_mille: input.queue_pressure_per_mille.map(|value| value.min(1_000)),
        cpu_pressure_per_mille: input.cpu_pressure_per_mille.map(|value| value.min(1_000)),
        memory_pressure_per_mille: input
            .memory_pressure_per_mille
            .map(|value| value.min(1_000)),
        downstream_retry_after_ms: input
            .downstream_retry_after_ms
            .map(|value| value.min(60_000)),
        retry_amplification_per_mille: input
            .retry_amplification_per_mille
            .map(|value| value.min(1_000)),
        useful_work_per_mille: input.useful_work_per_mille.map(|value| value.min(1_000)),
    }
}

fn candidates(input: &ReplayInput) -> Vec<ConformalSloRouteCandidate> {
    input
        .candidates
        .iter()
        .take(MAX_CANDIDATES)
        .map(|seed| {
            ConformalSloRouteCandidate::new(
                zone(seed.zone),
                path(seed.path),
                seed.estimated_latency_ms.min(60_000),
                seed.slo_budget_ms.min(60_000),
                seed.budget_remaining.map(|value| value.min(1_000_000)),
            )
        })
        .collect()
}

fn samples(input: &ReplayInput) -> Vec<ConformalSloCalibrationSample> {
    input
        .samples
        .iter()
        .take(MAX_SAMPLES)
        .map(|seed| {
            ConformalSloCalibrationSample::new(
                zone(seed.zone),
                path(seed.path),
                seed.observed_latency_ms.min(60_000),
                seed.slo_budget_ms.min(60_000),
                seed.success,
                seed.budget_remaining.map(|value| value.min(1_000_000)),
                seed.observed_at_ms,
            )
        })
        .collect()
}

fn assert_replay(input: &ReplayInput) {
    let controller = BackpressureController::default();
    let controller_input = BackpressureControllerInput::new(
        format!("connector:{:08x}", input.subject_seed),
        priority(input.priority),
        telemetry(input),
        calibration(input),
    );
    let decision = controller.decide(controller_input);
    assert!(
        decision.replay_matches(),
        "backpressure decision did not replay from embedded evidence"
    );
    let encoded = serde_json::to_vec(&decision).expect("backpressure decision serializes");
    let decoded: fcp_host::BackpressureDecision =
        serde_json::from_slice(&encoded).expect("backpressure decision deserializes");
    assert_eq!(
        decision, decoded,
        "backpressure replay record lost information through JSON"
    );
    assert!(
        decoded.replay_matches(),
        "JSON-decoded backpressure decision does not replay"
    );

    let predictor = ConformalSloPredictor::new(ConformalSloConfig::new(
        input.conformal_coverage_per_mille,
        usize::from(input.min_calibration_samples % 8),
    ));
    let route_candidates = candidates(input);
    let calibration_samples = samples(input);
    let first = predictor.choose_route(&route_candidates, &calibration_samples);

    let scenario_json = serde_json::to_vec(input).expect("conformal replay input serializes");
    let decoded_input: ReplayInput =
        serde_json::from_slice(&scenario_json).expect("conformal replay input deserializes");
    let replayed_predictor = ConformalSloPredictor::new(ConformalSloConfig::new(
        decoded_input.conformal_coverage_per_mille,
        usize::from(decoded_input.min_calibration_samples % 8),
    ));
    let second =
        replayed_predictor.choose_route(&candidates(&decoded_input), &samples(&decoded_input));
    assert_eq!(
        first, second,
        "conformal route choice is not replayable from serialized scenario input"
    );
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = ReplayInput::arbitrary(&mut unstructured) else {
        return;
    };
    assert_replay(&input);
});
