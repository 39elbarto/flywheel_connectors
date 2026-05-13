//! Bayesian K selection for `RaptorQ` workloads.
//!
//! The selector is opt-in: callers that need a fixed static K keep passing a
//! plain [`crate::RaptorQConfig`]. Callers that want workload adaptation can
//! ask an [`ArmRegistry`] for a `(K, code_family)` arm and derive a concrete
//! config for the current payload.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::RaptorQConfig;

const SCORE_SCALE: u64 = 1_000_000;
const SCORE_SCALE_U32: u32 = 1_000_000;
const DEFAULT_TARGET_DECODE_LATENCY_US: u64 = 1_000;

/// Encoding-family marker used by K-selector arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeFamily {
    /// Current systematic `RaptorQ` encoder.
    SystematicRaptorQ,
    /// Reserved for a future high-repair `RaptorQ` family.
    HighRepairRaptorQ,
}

/// Candidate arm for a workload-specific K selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KSelectorArm {
    /// Target source-symbol count K.
    pub source_symbols: u32,
    /// Encoder family to use.
    pub code_family: CodeFamily,
    /// Repair-symbol overhead in basis points.
    pub repair_ratio_bps: u16,
}

impl KSelectorArm {
    /// Build a K-selection arm.
    #[must_use]
    pub const fn new(source_symbols: u32, code_family: CodeFamily, repair_ratio_bps: u16) -> Self {
        Self {
            source_symbols,
            code_family,
            repair_ratio_bps,
        }
    }

    /// Return true if the arm can encode the payload without a zero-sized K.
    #[must_use]
    pub const fn supports_payload(self, payload_len: usize) -> bool {
        payload_len > 0 && self.source_symbols > 0
    }

    /// Derive a concrete static config from this selected arm.
    #[must_use]
    pub fn apply_to_config(self, payload_len: usize, base: &RaptorQConfig) -> RaptorQConfig {
        let mut config = base.clone();
        if self.supports_payload(payload_len) {
            config.symbol_size = symbol_size_for_k(payload_len, self.source_symbols);
        }
        config.repair_ratio_bps = self.repair_ratio_bps;
        config
    }
}

/// Observation used to update an arm posterior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KSelectorObservation {
    /// Decode latency for the workload.
    pub decode_latency_us: u64,
    /// Whether reconstruction failed.
    pub reconstruction_failed: bool,
}

impl KSelectorObservation {
    /// Build a selector observation.
    #[must_use]
    pub const fn new(decode_latency_us: u64, reconstruction_failed: bool) -> Self {
        Self {
            decode_latency_us,
            reconstruction_failed,
        }
    }

    fn reward_ppm(self, target_decode_latency_us: u64) -> u32 {
        if self.reconstruction_failed {
            return 0;
        }
        let target = target_decode_latency_us.max(1);
        let denominator = target.saturating_add(self.decode_latency_us.max(1));
        let reward = u128::from(target) * u128::from(SCORE_SCALE) / u128::from(denominator);
        u32::try_from(reward).unwrap_or(u32::MAX)
    }
}

/// Beta posterior for one selector arm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BetaPosterior {
    alpha_units: u64,
    beta_units: u64,
    observations: u64,
    last_reward_ppm: u32,
}

impl Default for BetaPosterior {
    fn default() -> Self {
        Self {
            alpha_units: 1,
            beta_units: 1,
            observations: 0,
            last_reward_ppm: 0,
        }
    }
}

impl BetaPosterior {
    /// Number of observations incorporated into this posterior.
    #[must_use]
    pub const fn observations(&self) -> u64 {
        self.observations
    }

    /// Last reward incorporated, in parts-per-million.
    #[must_use]
    pub const fn last_reward_ppm(&self) -> u32 {
        self.last_reward_ppm
    }

    /// Posterior mean in parts-per-million.
    #[must_use]
    pub fn mean_ppm(&self) -> u32 {
        let total = self.alpha_units.saturating_add(self.beta_units).max(1);
        let mean = u128::from(self.alpha_units) * u128::from(SCORE_SCALE) / u128::from(total);
        u32::try_from(mean).unwrap_or(u32::MAX)
    }

    fn observe(&mut self, observation: KSelectorObservation, target_decode_latency_us: u64) {
        let reward = observation.reward_ppm(target_decode_latency_us);
        let success_units = scaled_units(reward).max(1);
        let failure_units = scaled_units(SCORE_SCALE_U32.saturating_sub(reward)).max(1);
        self.alpha_units = self.alpha_units.saturating_add(u64::from(success_units));
        self.beta_units = self.beta_units.saturating_add(u64::from(failure_units));
        self.observations = self.observations.saturating_add(1);
        self.last_reward_ppm = reward;
    }

    fn thompson_score_ppm(&self, arm: KSelectorArm, seed: u64) -> u32 {
        let mean = u64::from(self.mean_ppm());
        let exploration_budget = SCORE_SCALE / self.observations.saturating_add(1);
        let jitter = splitmix64(seed ^ arm_seed(arm)) % exploration_budget.saturating_add(1);
        u32::try_from(mean.saturating_add(jitter).min(SCORE_SCALE)).unwrap_or(u32::MAX)
    }
}

/// Registry of K-selection arms and their posteriors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArmRegistry {
    target_decode_latency_us: u64,
    arms: BTreeMap<KSelectorArm, BetaPosterior>,
}

impl Default for ArmRegistry {
    fn default() -> Self {
        Self {
            target_decode_latency_us: DEFAULT_TARGET_DECODE_LATENCY_US,
            arms: BTreeMap::new(),
        }
    }
}

impl ArmRegistry {
    /// Build an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the target latency used to convert observations into rewards.
    #[must_use]
    pub fn with_target_decode_latency_us(mut self, target_decode_latency_us: u64) -> Self {
        self.target_decode_latency_us = target_decode_latency_us.max(1);
        self
    }

    /// Register an arm if it is not already present.
    pub fn register_arm(&mut self, arm: KSelectorArm) {
        self.arms.entry(arm).or_default();
    }

    /// Observe a decode outcome for an arm.
    pub fn observe(&mut self, arm: KSelectorArm, observation: KSelectorObservation) {
        self.arms
            .entry(arm)
            .or_default()
            .observe(observation, self.target_decode_latency_us);
    }

    /// Return the posterior for an arm.
    #[must_use]
    pub fn posterior(&self, arm: KSelectorArm) -> Option<&BetaPosterior> {
        self.arms.get(&arm)
    }

    /// Recommend an arm for a payload using Thompson-style posterior sampling.
    #[must_use]
    pub fn recommend(&self, payload_len: usize, seed: u64) -> Option<KSelectorArm> {
        self.arms
            .iter()
            .filter(|(arm, _)| arm.supports_payload(payload_len))
            .max_by_key(|(arm, posterior)| posterior.thompson_score_ppm(**arm, seed))
            .map(|(arm, _)| *arm)
    }

    /// Derive a config from the recommended arm, or return the static config.
    #[must_use]
    pub fn selected_config(
        &self,
        payload_len: usize,
        base: &RaptorQConfig,
        seed: u64,
    ) -> RaptorQConfig {
        self.recommend(payload_len, seed).map_or_else(
            || base.clone(),
            |arm| arm.apply_to_config(payload_len, base),
        )
    }
}

const fn scaled_units(score_ppm: u32) -> u32 {
    score_ppm.div_ceil(100_000)
}

fn symbol_size_for_k(payload_len: usize, source_symbols: u32) -> u16 {
    let k = usize::try_from(source_symbols).unwrap_or(usize::MAX).max(1);
    let symbol_size = payload_len.div_ceil(k).clamp(1, usize::from(u16::MAX));
    u16::try_from(symbol_size).unwrap_or(u16::MAX)
}

fn arm_seed(arm: KSelectorArm) -> u64 {
    let family = match arm.code_family {
        CodeFamily::SystematicRaptorQ => 0x9e37_79b9_7f4a_7c15,
        CodeFamily::HighRepairRaptorQ => 0xbf58_476d_1ce4_e5b9,
    };
    family ^ (u64::from(arm.source_symbols) << 17) ^ u64::from(arm.repair_ratio_bps)
}

const fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
