//! Adaptive planning helpers for device-cost ranking and Thompson sampling.

use std::cmp::Ordering;
use std::collections::HashMap;

use fcp_tailscale::NodeId;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, info_span};

use super::ResourcePoolClass;
use crate::device::{AvailabilityProfile, DeviceProfile, LatencyClass, PowerSource};

/// Default coefficients for the normalized device-cost model.
///
/// Lower costs are better. The defaults mirror the Phase J bridge-plan weights:
/// load dominates, network latency is second, direct provider cost is third,
/// and stability is a smaller but still explicit penalty.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DeviceCostWeights {
    /// Weight for current load pressure.
    pub load: f64,
    /// Weight for provider/machine cost.
    pub cost: f64,
    /// Weight for network latency.
    pub latency: f64,
    /// Weight for instability: `1.0 - stability_score`.
    pub stability: f64,
}

impl Default for DeviceCostWeights {
    fn default() -> Self {
        Self {
            load: 0.4,
            cost: 0.2,
            latency: 0.3,
            stability: 0.1,
        }
    }
}

impl DeviceCostWeights {
    /// Construct explicit cost weights.
    #[must_use]
    pub const fn new(load: f64, cost: f64, latency: f64, stability: f64) -> Self {
        Self {
            load,
            cost,
            latency,
            stability,
        }
    }
}

/// Normalized inputs for one device-cost calculation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DeviceCostInput {
    /// Current load pressure in `[0.0, 1.0]`.
    pub load: f64,
    /// Provider/machine cost pressure in `[0.0, 1.0]`.
    pub cost_weight: f64,
    /// Network latency pressure in `[0.0, 1.0]`.
    pub latency_weight: f64,
    /// Stability score in `[0.0, 1.0]`; higher is better.
    pub stability_score: f64,
}

impl DeviceCostInput {
    /// Construct a normalized device-cost input.
    #[must_use]
    pub const fn new(
        load: f64,
        cost_weight: f64,
        latency_weight: f64,
        stability_score: f64,
    ) -> Self {
        Self {
            load,
            cost_weight,
            latency_weight,
            stability_score,
        }
    }

    fn clamped(self) -> Self {
        Self {
            load: clamp01(self.load),
            cost_weight: clamp01(self.cost_weight),
            latency_weight: clamp01(self.latency_weight),
            stability_score: clamp01(self.stability_score),
        }
    }
}

/// Device-cost calculator used by adaptive mesh scheduling.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DeviceCostModel {
    weights: DeviceCostWeights,
}

impl Default for DeviceCostModel {
    fn default() -> Self {
        Self::new(DeviceCostWeights::default())
    }
}

impl DeviceCostModel {
    /// Construct a model from explicit weights.
    #[must_use]
    pub const fn new(weights: DeviceCostWeights) -> Self {
        Self { weights }
    }

    /// Return the configured weights.
    #[must_use]
    pub const fn weights(&self) -> DeviceCostWeights {
        self.weights
    }

    /// Compute normalized device cost. Lower is better.
    #[must_use]
    pub fn cost(&self, input: DeviceCostInput) -> f64 {
        let input = input.clamped();
        self.weights.load.mul_add(
            input.load,
            self.weights.cost.mul_add(
                input.cost_weight,
                self.weights.latency.mul_add(
                    input.latency_weight,
                    self.weights.stability * (1.0 - input.stability_score),
                ),
            ),
        )
    }

    /// Compute a cost estimate from a device profile plus current load.
    #[must_use]
    pub fn cost_for_profile(&self, profile: &DeviceProfile, load: f64) -> f64 {
        self.cost(DeviceCostInput::new(
            load,
            profile_cost_weight(profile),
            latency_weight(profile.latency_class),
            stability_score(profile.availability),
        ))
    }
}

/// Beta posterior for one `(node, operation_class)` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BetaPosterior {
    alpha: u32,
    beta: u32,
}

impl Default for BetaPosterior {
    fn default() -> Self {
        Self { alpha: 1, beta: 1 }
    }
}

impl BetaPosterior {
    /// Construct a posterior with non-zero alpha and beta.
    #[must_use]
    pub const fn new(alpha: u32, beta: u32) -> Self {
        Self {
            alpha: if alpha == 0 { 1 } else { alpha },
            beta: if beta == 0 { 1 } else { beta },
        }
    }

    /// Success count plus prior.
    #[must_use]
    pub const fn alpha(&self) -> u32 {
        self.alpha
    }

    /// Failure count plus prior.
    #[must_use]
    pub const fn beta(&self) -> u32 {
        self.beta
    }

    /// Posterior mean.
    #[must_use]
    pub fn mean(&self) -> f64 {
        f64::from(self.alpha) / f64::from(self.alpha.saturating_add(self.beta))
    }

    /// Posterior variance.
    #[must_use]
    pub fn variance(&self) -> f64 {
        let alpha = f64::from(self.alpha);
        let beta = f64::from(self.beta);
        let total = alpha + beta;
        let denominator = total.powi(2) * (total + 1.0);
        (alpha * beta) / denominator
    }

    /// Record one success or failure.
    pub fn record(&mut self, success: bool) {
        if success {
            self.alpha = self.alpha.saturating_add(1);
        } else {
            self.beta = self.beta.saturating_add(1);
        }
    }

    /// Retain a fraction of accumulated evidence while preserving the prior.
    pub fn decay_evidence(&mut self, retention: f64) {
        let retention = clamp01(retention);
        self.alpha = decay_count(self.alpha, retention);
        self.beta = decay_count(self.beta, retention);
    }

    /// Sample from this beta posterior.
    pub fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
        let x = sample_gamma_integer_shape(self.alpha, rng);
        let y = sample_gamma_integer_shape(self.beta, rng);
        x / (x + y)
    }
}

/// One sampled candidate from a Thompson scheduler decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThompsonChoice {
    /// Candidate node.
    pub node_id: NodeId,
    /// Operation class used for the posterior lookup.
    pub operation_class: ResourcePoolClass,
    /// Sampled Thompson value for this decision.
    pub sample: f64,
    /// Posterior mean before the decision outcome is recorded.
    pub posterior_mean: f64,
    /// Posterior variance before the decision outcome is recorded.
    pub posterior_variance: f64,
}

/// Thompson-sampling scheduler keyed by `(node, operation_class)`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThompsonScheduler {
    posteriors: HashMap<(NodeId, ResourcePoolClass), BetaPosterior>,
}

impl ThompsonScheduler {
    /// Construct an empty scheduler with `Beta(1, 1)` implicit priors.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a posterior, using the implicit prior when no outcome exists.
    #[must_use]
    pub fn posterior(&self, node_id: &NodeId, operation_class: ResourcePoolClass) -> BetaPosterior {
        self.posteriors
            .get(&(node_id.clone(), operation_class))
            .copied()
            .unwrap_or_default()
    }

    /// Record one route outcome.
    pub fn record_outcome(
        &mut self,
        node_id: NodeId,
        operation_class: ResourcePoolClass,
        success: bool,
    ) {
        let device = node_id.as_str().to_owned();
        let posterior = self
            .posteriors
            .entry((node_id, operation_class))
            .or_default();
        posterior.record(success);

        debug!(
            device = %device,
            op_class = ?operation_class,
            success,
            new_alpha = posterior.alpha(),
            new_beta = posterior.beta(),
            "updated thompson scheduler posterior"
        );
    }

    /// Decay all accumulated evidence for adaptation after drift.
    pub fn decay_all(&mut self, retention: f64) {
        for posterior in self.posteriors.values_mut() {
            posterior.decay_evidence(retention);
        }
    }

    /// Choose one candidate by Thompson sampling.
    pub fn choose_with_rng<R: Rng + ?Sized>(
        &self,
        candidates: &[NodeId],
        operation_class: ResourcePoolClass,
        rng: &mut R,
    ) -> Option<ThompsonChoice> {
        let span =
            info_span!("fcp.mesh.planner.thompson_sample", operation_class = ?operation_class);
        let _guard = span.enter();
        let mut choices: Vec<_> = candidates
            .iter()
            .map(|node_id| {
                let posterior = self.posterior(node_id, operation_class);
                ThompsonChoice {
                    node_id: node_id.clone(),
                    operation_class,
                    sample: posterior.sample(rng),
                    posterior_mean: posterior.mean(),
                    posterior_variance: posterior.variance(),
                }
            })
            .collect();

        choices.sort_by(compare_thompson_choice);
        let choice = choices.into_iter().next();
        if let Some(choice) = &choice {
            info!(
                operation_class = ?choice.operation_class,
                device_id_chosen = %choice.node_id.as_str(),
                posterior_mean = choice.posterior_mean,
                posterior_variance = choice.posterior_variance,
                sample = choice.sample,
                "thompson scheduler chose device"
            );
        }
        choice
    }

    /// Choose one candidate using the thread-local RNG.
    pub fn choose(
        &self,
        candidates: &[NodeId],
        operation_class: ResourcePoolClass,
    ) -> Option<ThompsonChoice> {
        let mut rng = rand::thread_rng();
        self.choose_with_rng(candidates, operation_class, &mut rng)
    }
}

fn compare_thompson_choice(left: &ThompsonChoice, right: &ThompsonChoice) -> Ordering {
    right
        .sample
        .partial_cmp(&left.sample)
        .unwrap_or(Ordering::Equal)
        .then_with(|| left.node_id.as_str().cmp(right.node_id.as_str()))
}

fn clamp01(value: f64) -> f64 {
    if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, 1.0)
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn decay_count(value: u32, retention: f64) -> u32 {
    1 + (f64::from(value.saturating_sub(1)) * retention).round() as u32
}

fn sample_gamma_integer_shape<R: Rng + ?Sized>(shape: u32, rng: &mut R) -> f64 {
    let mut total = 0.0;
    for _ in 0..shape.max(1) {
        let sample = rng.gen_range(f64::MIN_POSITIVE..1.0);
        total += -sample.ln();
    }
    total
}

fn latency_weight(latency_class: LatencyClass) -> f64 {
    match latency_class {
        LatencyClass::Local => 0.0,
        LatencyClass::Lan => 0.25,
        LatencyClass::Internet => 0.65,
        LatencyClass::Derp => 1.0,
    }
}

fn stability_score(availability: AvailabilityProfile) -> f64 {
    match availability {
        AvailabilityProfile::AlwaysOn => 1.0,
        AvailabilityProfile::Scheduled => 0.7,
        AvailabilityProfile::BestEffort => 0.35,
    }
}

fn profile_cost_weight(profile: &DeviceProfile) -> f64 {
    match (profile.power_source, profile.metered) {
        (PowerSource::Mains, false) => 0.2,
        (PowerSource::Mains, true) => 0.45,
        (PowerSource::Battery | PowerSource::Solar | PowerSource::Unknown, false) => 0.55,
        (PowerSource::Battery | PowerSource::Solar | PowerSource::Unknown, true) => 0.85,
    }
}
