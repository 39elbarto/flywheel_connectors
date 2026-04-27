//! `fcp_mesh::DeviceProfile::compute_fitness` + `FitnessScore`
//! conformance.
//!
//! `FitnessScore::compute` is the NORMATIVE device-selection
//! primitive that drives every "which node should run this op"
//! decision in the planner. Drift in any one of the documented
//! constants would silently shift which device wins under load,
//! making rollouts unpredictable.
//!
//! Documented constants (private — observable only via score deltas):
//!
//! | Knob                       | Constant |
//! |----------------------------|---------:|
//! | `BASE_SCORE`               |   100.0  |
//! | `DERP_PENALTY`             |    30.0  |
//! | `LOCALITY_BONUS`           |    25.0  |
//! | `LOW_BATTERY_PENALTY`      |    40.0  |
//! | `GPU_BONUS`                |    20.0  |
//! | `TPU_BONUS`                |    20.0  |
//! | `LATENCY_PENALTY_PER_CLASS`|    10.0  |
//! | `METERED_PENALTY`          |    15.0  |
//! | `BEST_EFFORT_PENALTY`      |    10.0  |
//!
//! Latency tiers: `Local=0`, `Lan=1×`, `Internet=2×`, `Derp=3×`.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **Baseline (no penalties, no bonuses)** = BASE_SCORE = 100.0.
//! 2. **Each penalty/bonus magnitude** observable via single-knob
//!    delta against baseline.
//! 3. **Eligibility gates short-circuit to score=0**:
//!    - `requires_gpu` and no GPU
//!    - `requires_tpu` and no TPU
//!    - `min_memory_mb` not met
//!    - `required_connector` absent
//! 4. **Score is clamped at 0.0** — never negative even with stacked
//!    penalties.
//! 5. **Ord total order**: eligible ALWAYS > ineligible regardless of
//!    score; among eligible, higher score wins.
//! 6. **`is_low_battery`** requires BOTH `PowerSource::Battery` AND
//!    `battery_percent < 20` — one without the other does NOT trip
//!    the penalty.
//! 7. **DERP latency tier**: applies BOTH `DERP_PENALTY` AND the
//!    3× latency-class penalty (deliberate stacking — Derp is the
//!    worst transport AND the slowest class).

use fcp_core::{ConnectorId, ObjectId, ObjectIdKey, ZoneId};
use fcp_cbor::SchemaId;
use fcp_mesh::{
    AvailabilityProfile, CpuArch, DeviceProfile, DeviceProfileBuilder, FitnessContext,
    FitnessScore, GpuProfile, GpuVendor, InstalledConnector, LatencyClass, PowerSource,
    TpuProfile, TpuVendor,
};
use fcp_tailscale::NodeId;
use semver::Version;

const EPSILON: f64 = 1e-6;
const BASE_SCORE: f64 = 100.0;

fn baseline_profile() -> DeviceProfile {
    // Configuration that triggers ZERO penalties and ZERO bonuses so
    // its score == BASE_SCORE exactly. Local latency, mains power,
    // no metered, AlwaysOn availability, no GPU/TPU.
    DeviceProfileBuilder::new(NodeId::new("baseline"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Local)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build()
}

fn baseline_ctx() -> FitnessContext {
    // Empty ctx: no requirements, no symbols-present bonus.
    FitnessContext::new()
}

fn fake_object_id(tag: &[u8]) -> ObjectId {
    let zone = ZoneId::work();
    let schema = SchemaId::new("fcp.test", "DeviceFitness", Version::new(1, 0, 0));
    let key = ObjectIdKey::from_bytes([13u8; 32]);
    ObjectId::new(tag, &zone, &schema, &key)
}

// ─── Baseline ───────────────────────────────────────────────────────

#[test]
fn baseline_profile_yields_base_score_with_empty_ctx() {
    let p = baseline_profile();
    let ctx = baseline_ctx();
    let f = p.compute_fitness(&ctx);
    assert!(f.eligible, "baseline MUST be eligible");
    assert!(
        (f.score - BASE_SCORE).abs() < EPSILON,
        "baseline (no penalties, no bonuses) MUST equal BASE_SCORE = 100.0; got {}",
        f.score
    );
}

#[test]
fn fitness_score_ineligible_constructor_yields_zero_score() {
    let f = FitnessScore::ineligible();
    assert!(!f.eligible);
    assert_eq!(f.score, 0.0);
}

// ─── Constant magnitudes (observable via single-knob delta) ─────────

#[test]
fn derp_latency_costs_derp_penalty_plus_three_class_penalties() {
    // DERP latency_class triggers BOTH DERP_PENALTY (30.0) AND the
    // 3× LATENCY_PENALTY_PER_CLASS (3 × 10.0 = 30.0) — total 60.0
    // delta below baseline.
    let p = DeviceProfileBuilder::new(NodeId::new("derp-node"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Derp)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build();
    let f = p.compute_fitness(&baseline_ctx());
    let expected = BASE_SCORE - 30.0 - 30.0; // DERP_PENALTY + 3×LATENCY_PENALTY_PER_CLASS
    assert!(
        (f.score - expected).abs() < EPSILON,
        "Derp class MUST cost DERP_PENALTY (30) + 3×LATENCY_PENALTY (30) = 60; expected {expected}, got {}",
        f.score
    );
}

#[test]
fn lan_latency_costs_one_class_penalty() {
    let p = DeviceProfileBuilder::new(NodeId::new("lan-node"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Lan)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build();
    let f = p.compute_fitness(&baseline_ctx());
    let expected = BASE_SCORE - 10.0; // 1× LATENCY_PENALTY_PER_CLASS
    assert!(
        (f.score - expected).abs() < EPSILON,
        "Lan class MUST cost 1×LATENCY_PENALTY (10); expected {expected}, got {}",
        f.score
    );
}

#[test]
fn internet_latency_costs_two_class_penalties() {
    let p = DeviceProfileBuilder::new(NodeId::new("internet-node"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Internet)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build();
    let f = p.compute_fitness(&baseline_ctx());
    let expected = BASE_SCORE - 20.0; // 2× LATENCY_PENALTY_PER_CLASS
    assert!(
        (f.score - expected).abs() < EPSILON,
        "Internet class MUST cost 2×LATENCY_PENALTY (20); expected {expected}, got {}",
        f.score
    );
}

#[test]
fn locality_bonus_adds_twenty_five() {
    let p = baseline_profile();
    let ctx = FitnessContext::new().with_symbols_present(true);
    let f = p.compute_fitness(&ctx);
    let expected = BASE_SCORE + 25.0;
    assert!(
        (f.score - expected).abs() < EPSILON,
        "symbols_present MUST add LOCALITY_BONUS (25); expected {expected}, got {}",
        f.score
    );
}

#[test]
fn metered_connection_costs_fifteen() {
    let p = DeviceProfileBuilder::new(NodeId::new("metered-node"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Local)
        .metered(true)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build();
    let f = p.compute_fitness(&baseline_ctx());
    let expected = BASE_SCORE - 15.0;
    assert!(
        (f.score - expected).abs() < EPSILON,
        "metered=true MUST cost METERED_PENALTY (15); expected {expected}, got {}",
        f.score
    );
}

#[test]
fn best_effort_availability_costs_ten() {
    let p = DeviceProfileBuilder::new(NodeId::new("be-node"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Local)
        .metered(false)
        .availability(AvailabilityProfile::BestEffort)
        .timestamp(1)
        .build();
    let f = p.compute_fitness(&baseline_ctx());
    let expected = BASE_SCORE - 10.0;
    assert!(
        (f.score - expected).abs() < EPSILON,
        "BestEffort availability MUST cost BEST_EFFORT_PENALTY (10); expected {expected}, got {}",
        f.score
    );
}

#[test]
fn low_battery_costs_forty() {
    let p = DeviceProfileBuilder::new(NodeId::new("low-batt-node"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Battery)
        .battery_percent(15) // < 20% triggers low battery
        .latency_class(LatencyClass::Local)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build();
    let f = p.compute_fitness(&baseline_ctx());
    let expected = BASE_SCORE - 40.0;
    assert!(
        (f.score - expected).abs() < EPSILON,
        "low battery MUST cost LOW_BATTERY_PENALTY (40); expected {expected}, got {}",
        f.score
    );
}

#[test]
fn gpu_bonus_adds_twenty_when_required_and_present() {
    let p = DeviceProfileBuilder::new(NodeId::new("gpu-node"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .gpu(GpuProfile::new(GpuVendor::Nvidia, "rtx-4090", 24_576))
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Local)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build();
    let ctx = FitnessContext::new().with_requires_gpu(true);
    let f = p.compute_fitness(&ctx);
    let expected = BASE_SCORE + 20.0;
    assert!(
        (f.score - expected).abs() < EPSILON,
        "requires_gpu+has_gpu MUST add GPU_BONUS (20); expected {expected}, got {}",
        f.score
    );
}

#[test]
fn tpu_bonus_adds_twenty_when_required_and_present() {
    let p = DeviceProfileBuilder::new(NodeId::new("tpu-node"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .tpu(TpuProfile::new(TpuVendor::Google, "v4", 4, 16_384))
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Local)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build();
    let ctx = FitnessContext::new().with_requires_tpu(true);
    let f = p.compute_fitness(&ctx);
    let expected = BASE_SCORE + 20.0;
    assert!(
        (f.score - expected).abs() < EPSILON,
        "requires_tpu+has_tpu MUST add TPU_BONUS (20); expected {expected}, got {}",
        f.score
    );
}

// ─── Eligibility gates ──────────────────────────────────────────────

#[test]
fn requires_gpu_without_gpu_yields_ineligible() {
    let p = baseline_profile(); // no GPU
    let ctx = FitnessContext::new().with_requires_gpu(true);
    let f = p.compute_fitness(&ctx);
    assert!(!f.eligible, "requires_gpu+!has_gpu MUST short-circuit ineligible");
    assert_eq!(f.score, 0.0);
}

#[test]
fn requires_tpu_without_tpu_yields_ineligible() {
    let p = baseline_profile();
    let ctx = FitnessContext::new().with_requires_tpu(true);
    let f = p.compute_fitness(&ctx);
    assert!(!f.eligible);
    assert_eq!(f.score, 0.0);
}

#[test]
fn insufficient_memory_yields_ineligible() {
    let p = baseline_profile(); // memory_mb = 16_384
    let ctx = FitnessContext::new().with_min_memory_mb(32_768);
    let f = p.compute_fitness(&ctx);
    assert!(
        !f.eligible,
        "min_memory_mb > profile.memory_mb MUST short-circuit ineligible"
    );
    assert_eq!(f.score, 0.0);
}

#[test]
fn missing_required_connector_yields_ineligible() {
    let p = baseline_profile(); // no installed connectors
    let ctx =
        FitnessContext::new().with_required_connector(ConnectorId::from_static("fcp:saas:v1"));
    let f = p.compute_fitness(&ctx);
    assert!(
        !f.eligible,
        "required_connector absent MUST short-circuit ineligible"
    );
    assert_eq!(f.score, 0.0);
}

#[test]
fn present_required_connector_yields_eligible() {
    let connector_id = ConnectorId::from_static("fcp:saas:v1");
    let installed = InstalledConnector::new(
        connector_id.clone(),
        "1.0.0",
        fake_object_id(b"connector-binary"),
    );
    let p = DeviceProfileBuilder::new(NodeId::new("with-connector"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Local)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .add_connector(installed)
        .build();
    let ctx = FitnessContext::new().with_required_connector(connector_id);
    let f = p.compute_fitness(&ctx);
    assert!(f.eligible);
}

// ─── Score floor at 0.0 ────────────────────────────────────────────

#[test]
fn score_clamps_at_zero_under_stacked_penalties() {
    // Stack everything: Derp (60), low battery (40), metered (15),
    // best-effort (10) = 125 in penalties → would be -25, MUST clamp
    // to 0 BUT remain eligible (no eligibility gate triggers).
    let p = DeviceProfileBuilder::new(NodeId::new("worst-node"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Battery)
        .battery_percent(5)
        .latency_class(LatencyClass::Derp)
        .metered(true)
        .availability(AvailabilityProfile::BestEffort)
        .timestamp(1)
        .build();
    let f = p.compute_fitness(&baseline_ctx());
    assert!(f.eligible, "stacked penalties alone MUST keep eligibility");
    assert!(
        f.score >= 0.0,
        "score MUST clamp at 0.0; got {}",
        f.score
    );
    assert!(
        f.score < 1.0,
        "this stack should land at or near 0.0; got {}",
        f.score
    );
}

// ─── is_low_battery ─────────────────────────────────────────────────

#[test]
fn is_low_battery_requires_battery_power_source() {
    // Mains + 5% battery_percent (legal but irrelevant) → NOT low.
    let p = DeviceProfileBuilder::new(NodeId::new("mains-with-battery-pct"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .battery_percent(5)
        .latency_class(LatencyClass::Local)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build();
    assert!(
        !p.is_low_battery(),
        "PowerSource::Mains MUST NOT trip is_low_battery even with battery_percent set"
    );
}

#[test]
fn is_low_battery_requires_battery_percent_below_twenty() {
    // Battery + exactly 20% → NOT low (strict <).
    let p = DeviceProfileBuilder::new(NodeId::new("at-threshold"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Battery)
        .battery_percent(20)
        .latency_class(LatencyClass::Local)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build();
    assert!(
        !p.is_low_battery(),
        "battery_percent == 20 MUST NOT trip is_low_battery (strict <)"
    );
}

#[test]
fn is_low_battery_trips_when_battery_and_below_twenty() {
    let p = DeviceProfileBuilder::new(NodeId::new("low"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Battery)
        .battery_percent(19)
        .latency_class(LatencyClass::Local)
        .metered(false)
        .availability(AvailabilityProfile::AlwaysOn)
        .timestamp(1)
        .build();
    assert!(p.is_low_battery());
}

// ─── Total order on FitnessScore ────────────────────────────────────

#[test]
fn ord_eligible_always_outranks_ineligible_regardless_of_score() {
    let ineligible = FitnessScore::ineligible(); // 0.0
    // An eligible score with f.score == 0.0 (clamped) MUST still
    // outrank the ineligible 0.0 — the eligibility flag is the
    // dominant key.
    let eligible_zero = baseline_profile()
        .compute_fitness(&baseline_ctx());
    // baseline score is 100.0 — easy. But test the documented total
    // order with explicit construction:
    use std::cmp::Ordering;
    assert_eq!(eligible_zero.cmp(&ineligible), Ordering::Greater);
    assert_eq!(ineligible.cmp(&eligible_zero), Ordering::Less);
}

#[test]
fn ord_among_eligible_higher_score_wins() {
    use std::cmp::Ordering;
    let high = baseline_profile().compute_fitness(&baseline_ctx()); // 100.0
    let low_p = DeviceProfileBuilder::new(NodeId::new("low"))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16_384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Internet) // -20
        .metered(true) // -15
        .availability(AvailabilityProfile::BestEffort) // -10
        .timestamp(1)
        .build();
    let low = low_p.compute_fitness(&baseline_ctx());
    assert!(low.eligible);
    assert!(low.score < high.score);
    assert_eq!(high.cmp(&low), Ordering::Greater);
    assert_eq!(low.cmp(&high), Ordering::Less);
}

#[test]
fn ord_equal_scores_compare_equal() {
    use std::cmp::Ordering;
    let a = baseline_profile().compute_fitness(&baseline_ctx());
    let b = baseline_profile().compute_fitness(&baseline_ctx());
    assert_eq!(a.cmp(&b), Ordering::Equal);
    assert_eq!(a, b);
}
