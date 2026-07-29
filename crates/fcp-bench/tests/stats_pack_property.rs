#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use fcp_bench::stats::StatPack;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};

#[test]
fn test_p50_uniform_zero_one() {
    let samples = uniform_grid(10_000);
    let statpack = StatPack::from_samples(&samples);

    assert!((statpack.p50 - 0.5).abs() < 0.01, "{statpack:?}");
}

#[test]
fn test_p99_unit_normal() {
    let samples: Vec<f64> = (0..10_000)
        .map(|index| inverse_standard_normal((f64::from(index) + 0.5) / 10_000.0))
        .collect();
    let statpack = StatPack::from_samples(&samples);

    assert!((statpack.p99 - 2.326).abs() < 0.05, "{statpack:?}");
}

#[test]
fn test_welch_rejects_shifted_means() {
    let mut runner = TestRunner::new(Config {
        cases: 64,
        failure_persistence: None,
        ..Config::default()
    });
    runner
        .run(&(0.5_f64..2.0), |shift| {
            let baseline = StatPack::with_resamples(&centered_samples(500, 0.0), 64);
            let shifted = StatPack::with_resamples(&centered_samples(500, shift), 64);

            prop_assert!(shifted.welch_vs(&baseline) < 0.05);
            Ok(())
        })
        .expect("shifted means should be rejected by Welch test");
}

#[test]
fn test_welch_accepts_equal_means() {
    let mut accepted = 0_usize;
    for seed in 0..1_000_u64 {
        let sample_a = seeded_uniform_samples(seed, 160);
        let mut sample_b = sample_a.clone();
        sample_b.reverse();
        let pack_a = StatPack::with_resamples(&sample_a, 64);
        let pack_b = StatPack::with_resamples(&sample_b, 64);

        if pack_a.welch_vs(&pack_b) > 0.05 {
            accepted += 1;
        }
    }

    assert!(
        accepted >= 950,
        "expected at least 950/1000 equal-mean trials to be accepted, got {accepted}"
    );
}

#[test]
fn test_bootstrap_ci_covers_truth_95() {
    let mut covered = 0_usize;

    for seed in 0..200_u64 {
        let samples = seeded_uniform_samples(seed, 200);
        let statpack = StatPack::with_resamples(&samples, 400);
        if statpack.bootstrap_ci.0 <= 0.5 && 0.5 <= statpack.bootstrap_ci.1 {
            covered += 1;
        }
    }

    assert!(
        covered >= 184,
        "expected bootstrap CI to cover truth in at least 184/200 trials, got {covered}"
    );
}

#[test]
fn test_tail_amp_monotone() {
    let light_tail: Vec<f64> = (0..1_000).map(|index| f64::from(index) / 1_000.0).collect();
    let mut heavy_tail = light_tail.clone();
    heavy_tail.extend((0..20).map(|index| 10.0 + f64::from(index)));

    let light = StatPack::from_samples(&light_tail);
    let heavy = StatPack::from_samples(&heavy_tail);

    assert!(
        heavy.tail_amp > light.tail_amp,
        "light={light:?} heavy={heavy:?}"
    );
}

#[test]
fn test_zero_variance_samples() {
    let a = StatPack::from_samples(&[7.0; 32]);
    let b = StatPack::from_samples(&[7.0; 32]);

    assert!(a.welch_vs(&b).is_nan());
}

fn uniform_grid(len: usize) -> Vec<f64> {
    (0..len)
        .map(|index| (index as f64 + 0.5) / len as f64)
        .collect()
}

fn centered_samples(len: usize, shift: f64) -> Vec<f64> {
    let center = (len - 1) as f64 / 2.0;
    (0..len)
        .map(|index| ((index as f64 - center) / 100.0) + shift)
        .collect()
}

fn seeded_uniform_samples(seed: u64, len: usize) -> Vec<f64> {
    let mut state = seed ^ 0x4d59_5df4_d0f3_3173;
    (0..len)
        .map(|_| {
            let value = splitmix64(&mut state);
            ((value >> 11) as f64) / ((1_u64 << 53) as f64)
        })
        .collect()
}

const fn splitmix64(seed: &mut u64) -> u64 {
    *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *seed;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[allow(clippy::suboptimal_flops)]
fn inverse_standard_normal(probability: f64) -> f64 {
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838,
        -2.549_732_539_343_734,
        4.374_664_141_464_968,
        2.938_163_982_698_783,
    ];
    const D: [f64; 4] = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996,
        3.754_408_661_907_416,
    ];

    let p_low = 0.024_25;
    let p_high = 1.0 - p_low;

    if probability < p_low {
        let q = (-2.0 * probability.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if probability <= p_high {
        let q = probability - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - probability).ln()).sqrt();
        -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    }
}
