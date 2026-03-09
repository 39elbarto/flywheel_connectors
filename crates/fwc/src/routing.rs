/// Smart connector auto-routing: ranks connectors when multiple can fulfill an intent.
///
/// Routing signals (priority order):
/// 1. Zone authorization (must be allowed)
/// 2. Connector health (must be healthy/degraded, not error)
/// 3. Rate limit headroom (prefer more quota remaining)
/// 4. Historical success rate (prefer higher success)
/// 5. User/agent preference history (learned from past choices)
/// 6. Safety tier (prefer lower risk for equivalent operations)
/// 7. Latency (prefer faster connectors)
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Health state
// ---------------------------------------------------------------------------

/// Operational health of a connector endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HealthState {
    Healthy,
    Degraded,
    Error,
    Unknown,
}

impl HealthState {
    /// Returns a normalized score in `[0.0, 1.0]` for routing purposes.
    #[must_use]
    pub const fn score(self) -> f64 {
        match self {
            Self::Healthy => 1.0,
            Self::Degraded => 0.5,
            Self::Unknown => 0.25,
            Self::Error => 0.0,
        }
    }

    /// Whether this health state is routable (not `Error`).
    #[must_use]
    pub const fn is_routable(self) -> bool {
        !matches!(self, Self::Error)
    }
}

impl std::fmt::Display for HealthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => f.write_str("healthy"),
            Self::Degraded => f.write_str("degraded"),
            Self::Error => f.write_str("error"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

impl std::str::FromStr for HealthState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "healthy" => Ok(Self::Healthy),
            "degraded" => Ok(Self::Degraded),
            "error" => Ok(Self::Error),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!("unknown health state: {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Safety rank
// ---------------------------------------------------------------------------

/// Safety classification for routing weight purposes.
///
/// Lower numeric value = safer. `Unknown` maps to 0 and is treated as
/// moderately risky (equivalent to `Risky`) during scoring so that
/// unclassified connectors are neither favoured nor completely penalised.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SafetyRank {
    Unknown = 0,
    Safe = 1,
    Risky = 2,
    Dangerous = 3,
    Critical = 4,
}

impl SafetyRank {
    /// Normalized safety score in `[0.0, 1.0]` — higher is safer.
    #[must_use]
    pub const fn score(self) -> f64 {
        match self {
            Self::Safe => 1.0,
            Self::Unknown | Self::Risky => 0.5,
            Self::Dangerous => 0.25,
            Self::Critical => 0.0,
        }
    }
}

impl std::fmt::Display for SafetyRank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("unknown"),
            Self::Safe => f.write_str("safe"),
            Self::Risky => f.write_str("risky"),
            Self::Dangerous => f.write_str("dangerous"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

impl std::str::FromStr for SafetyRank {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "safe" => Ok(Self::Safe),
            "risky" => Ok(Self::Risky),
            "dangerous" => Ok(Self::Dangerous),
            "critical" => Ok(Self::Critical),
            "unknown" => Ok(Self::Unknown),
            other => Err(format!("unknown safety rank: {other}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Connector candidate
// ---------------------------------------------------------------------------

/// A connector that *could* fulfil a particular intent/operation.
#[derive(Clone, Debug)]
pub struct ConnectorCandidate {
    pub connector_id: String,
    pub operation_id: String,
    pub zone_authorized: bool,
    pub health: HealthState,
    /// Fraction of rate-limit quota remaining, `0.0..=1.0`.
    pub rate_headroom: f64,
    /// Historical success fraction, `0.0..=1.0`.
    pub success_rate: f64,
    /// Number of times the user/agent has previously chosen this connector
    /// for this kind of operation.
    pub preference_count: u32,
    pub safety_tier: SafetyRank,
    /// Average observed latency in milliseconds.
    pub avg_latency_ms: u64,
}

// ---------------------------------------------------------------------------
// Score breakdown
// ---------------------------------------------------------------------------

/// Per-signal contribution to the final routing score.
#[derive(Clone, Debug, PartialEq)]
pub struct ScoreBreakdown {
    pub zone: f64,
    pub health: f64,
    pub rate_limit: f64,
    pub success: f64,
    pub preference: f64,
    pub safety: f64,
    pub latency: f64,
}

// ---------------------------------------------------------------------------
// Routing score
// ---------------------------------------------------------------------------

/// Final computed score for one candidate.
#[derive(Clone, Debug)]
pub struct RoutingScore {
    pub connector_id: String,
    pub operation_id: String,
    pub score: f64,
    pub breakdown: ScoreBreakdown,
    pub recommended: bool,
}

// ---------------------------------------------------------------------------
// Signal weights & config
// ---------------------------------------------------------------------------

/// Per-signal weights used to compute the weighted routing score.
#[derive(Clone, Debug, PartialEq)]
pub struct SignalWeights {
    pub zone: f64,
    pub health: f64,
    pub rate_limit: f64,
    pub success: f64,
    pub preference: f64,
    pub safety: f64,
    pub latency: f64,
}

impl Default for SignalWeights {
    fn default() -> Self {
        Self {
            zone: 100.0,
            health: 50.0,
            rate_limit: 20.0,
            success: 15.0,
            preference: 10.0,
            safety: 8.0,
            latency: 5.0,
        }
    }
}

impl SignalWeights {
    /// Sum of all weights (used for normalisation).
    fn total(&self) -> f64 {
        self.zone
            + self.health
            + self.rate_limit
            + self.success
            + self.preference
            + self.safety
            + self.latency
    }
}

/// Top-level routing configuration.
#[derive(Clone, Debug, Default)]
pub struct RoutingConfig {
    pub weights: SignalWeights,
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// Compute a normalised latency score in `[0.0, 1.0]` where lower latency
/// yields a higher score.  We use a simple inverse mapping:
///   - 0 ms  → 1.0
///   - 1000 ms → ~0.5
///   - very large → approaches 0.0
fn latency_score(avg_ms: u64) -> f64 {
    // 1000 / (1000 + ms)  gives a nice smooth curve.
    #[allow(clippy::cast_precision_loss)] // acceptable for latency scoring
    let ms = avg_ms as f64;
    1000.0 / (1000.0 + ms)
}

/// Compute a preference score in `[0.0, 1.0]`.
///
/// We use a logarithmic scale so that early preferences count more than
/// later ones (diminishing returns):  `ln(1 + count) / ln(1 + 100)`.
/// Capped at 1.0.
fn preference_score(count: u32) -> f64 {
    let raw = f64::from(count).ln_1p() / 100.0_f64.ln_1p();
    if raw > 1.0 { 1.0 } else { raw }
}

/// Compute the routing score and breakdown for a single candidate.
#[must_use]
pub fn compute_score(
    candidate: &ConnectorCandidate,
    weights: &SignalWeights,
) -> (f64, ScoreBreakdown) {
    // Zone and health are hard gates: if either is zero the whole score is 0.
    let zone_val = if candidate.zone_authorized { 1.0 } else { 0.0 };
    let health_val = candidate.health.score();

    let rate_val = candidate.rate_headroom.clamp(0.0, 1.0);
    let success_val = candidate.success_rate.clamp(0.0, 1.0);
    let pref_val = preference_score(candidate.preference_count);
    let safety_val = candidate.safety_tier.score();
    let lat_val = latency_score(candidate.avg_latency_ms);

    let breakdown = ScoreBreakdown {
        zone: zone_val * weights.zone,
        health: health_val * weights.health,
        rate_limit: rate_val * weights.rate_limit,
        success: success_val * weights.success,
        preference: pref_val * weights.preference,
        safety: safety_val * weights.safety,
        latency: lat_val * weights.latency,
    };

    // If zone or health are zero, the whole score collapses to 0.
    if zone_val == 0.0 || health_val == 0.0 {
        let zero_bd = ScoreBreakdown {
            zone: breakdown.zone,
            health: breakdown.health,
            rate_limit: 0.0,
            success: 0.0,
            preference: 0.0,
            safety: 0.0,
            latency: 0.0,
        };
        return (0.0, zero_bd);
    }

    let total_weight = weights.total();
    let raw = breakdown.zone
        + breakdown.health
        + breakdown.rate_limit
        + breakdown.success
        + breakdown.preference
        + breakdown.safety
        + breakdown.latency;
    let normalised = if total_weight > 0.0 {
        raw / total_weight
    } else {
        0.0
    };

    (normalised, breakdown)
}

// ---------------------------------------------------------------------------
// Ranking
// ---------------------------------------------------------------------------

/// Rank a set of candidates, returning scores sorted descending.
///
/// The top candidate (if any with score > 0) is marked `recommended = true`.
/// Ties are broken by connector ID (lexicographic, ascending) for
/// determinism.
#[must_use]
pub fn rank_candidates(
    candidates: &[ConnectorCandidate],
    config: &RoutingConfig,
) -> Vec<RoutingScore> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let mut scores: Vec<RoutingScore> = candidates
        .iter()
        .map(|c| {
            let (score, breakdown) = compute_score(c, &config.weights);
            RoutingScore {
                connector_id: c.connector_id.clone(),
                operation_id: c.operation_id.clone(),
                score,
                breakdown,
                recommended: false,
            }
        })
        .collect();

    // Sort: primary descending by score, secondary ascending by connector_id.
    scores.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.connector_id.cmp(&b.connector_id))
    });

    // Mark the top candidate as recommended if its score > 0.
    if let Some(first) = scores.first_mut() {
        if first.score > 0.0 {
            first.recommended = true;
        }
    }

    scores
}

// ---------------------------------------------------------------------------
// Preference store
// ---------------------------------------------------------------------------

/// File-backed store that tracks how often a user/agent chooses each
/// connector for a given intent (operation name).
///
/// On-disk format (`~/.fwc/preferences.json`):
/// ```json
/// { "send_message": { "slack": 12, "discord": 3 }, ... }
/// ```
#[derive(Clone, Debug)]
pub struct PreferenceStore {
    path: PathBuf,
    data: BTreeMap<String, BTreeMap<String, u32>>,
}

impl PreferenceStore {
    /// Create a new store backed by the given file path.
    /// Does **not** load from disk yet — call [`Self::load`] for that.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            data: BTreeMap::new(),
        }
    }

    /// Load preferences from disk. Missing file is silently treated as empty.
    ///
    /// # Errors
    ///
    /// Returns an error if the file exists but cannot be parsed.
    pub fn load(&mut self) -> Result<(), String> {
        let contents = match fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(format!("failed to read preferences: {e}")),
        };
        self.data = serde_json::from_str(&contents)
            .map_err(|e| format!("failed to parse preferences: {e}"))?;
        Ok(())
    }

    /// Persist the current preferences to disk, creating parent directories
    /// as needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn save(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create preferences directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| format!("failed to serialize preferences: {e}"))?;
        fs::write(&self.path, json).map_err(|e| format!("failed to write preferences: {e}"))?;
        Ok(())
    }

    /// Record that `connector_id` was chosen for `intent`.
    pub fn record_choice(&mut self, intent: &str, connector_id: &str) {
        *self
            .data
            .entry(intent.to_owned())
            .or_default()
            .entry(connector_id.to_owned())
            .or_insert(0) += 1;
    }

    /// Return how many times `connector_id` has been chosen for `intent`.
    #[must_use]
    pub fn get_preference(&self, intent: &str, connector_id: &str) -> u32 {
        self.data
            .get(intent)
            .and_then(|m| m.get(connector_id))
            .copied()
            .unwrap_or(0)
    }

    /// Return the backing path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return a reference to the full preference data.
    #[must_use]
    pub const fn data(&self) -> &BTreeMap<String, BTreeMap<String, u32>> {
        &self.data
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn default_candidate() -> ConnectorCandidate {
        ConnectorCandidate {
            connector_id: "slack".to_owned(),
            operation_id: "send_message".to_owned(),
            zone_authorized: true,
            health: HealthState::Healthy,
            rate_headroom: 0.8,
            success_rate: 0.95,
            preference_count: 5,
            safety_tier: SafetyRank::Safe,
            avg_latency_ms: 100,
        }
    }

    fn default_weights() -> SignalWeights {
        SignalWeights::default()
    }

    fn default_config() -> RoutingConfig {
        RoutingConfig::default()
    }

    // -----------------------------------------------------------------------
    // HealthState
    // -----------------------------------------------------------------------

    #[test]
    fn health_state_scores() {
        assert!((HealthState::Healthy.score() - 1.0).abs() < f64::EPSILON);
        assert!((HealthState::Degraded.score() - 0.5).abs() < f64::EPSILON);
        assert!((HealthState::Unknown.score() - 0.25).abs() < f64::EPSILON);
        assert!((HealthState::Error.score() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn health_state_routable() {
        assert!(HealthState::Healthy.is_routable());
        assert!(HealthState::Degraded.is_routable());
        assert!(HealthState::Unknown.is_routable());
        assert!(!HealthState::Error.is_routable());
    }

    #[test]
    fn health_state_display_roundtrip() {
        for state in [
            HealthState::Healthy,
            HealthState::Degraded,
            HealthState::Error,
            HealthState::Unknown,
        ] {
            let s = state.to_string();
            let parsed: HealthState = s.parse().unwrap();
            assert_eq!(parsed, state);
        }
    }

    #[test]
    fn health_state_parse_case_insensitive() {
        assert_eq!(
            "HEALTHY".parse::<HealthState>().unwrap(),
            HealthState::Healthy
        );
        assert_eq!(
            "Degraded".parse::<HealthState>().unwrap(),
            HealthState::Degraded
        );
    }

    #[test]
    fn health_state_parse_invalid() {
        assert!("foobar".parse::<HealthState>().is_err());
    }

    // -----------------------------------------------------------------------
    // SafetyRank
    // -----------------------------------------------------------------------

    #[test]
    fn safety_rank_scores() {
        assert!((SafetyRank::Safe.score() - 1.0).abs() < f64::EPSILON);
        assert!((SafetyRank::Risky.score() - 0.5).abs() < f64::EPSILON);
        assert!((SafetyRank::Unknown.score() - 0.5).abs() < f64::EPSILON);
        assert!((SafetyRank::Dangerous.score() - 0.25).abs() < f64::EPSILON);
        assert!((SafetyRank::Critical.score() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn safety_rank_display_roundtrip() {
        for rank in [
            SafetyRank::Unknown,
            SafetyRank::Safe,
            SafetyRank::Risky,
            SafetyRank::Dangerous,
            SafetyRank::Critical,
        ] {
            let s = rank.to_string();
            let parsed: SafetyRank = s.parse().unwrap();
            assert_eq!(parsed, rank);
        }
    }

    #[test]
    fn safety_rank_parse_case_insensitive() {
        assert_eq!("SAFE".parse::<SafetyRank>().unwrap(), SafetyRank::Safe);
        assert_eq!(
            "Critical".parse::<SafetyRank>().unwrap(),
            SafetyRank::Critical
        );
    }

    #[test]
    fn safety_rank_parse_invalid() {
        assert!("extreme".parse::<SafetyRank>().is_err());
    }

    #[test]
    fn safety_rank_ordering() {
        assert!(SafetyRank::Unknown < SafetyRank::Safe);
        assert!(SafetyRank::Safe < SafetyRank::Risky);
        assert!(SafetyRank::Risky < SafetyRank::Dangerous);
        assert!(SafetyRank::Dangerous < SafetyRank::Critical);
    }

    // -----------------------------------------------------------------------
    // Latency score helper
    // -----------------------------------------------------------------------

    #[test]
    fn latency_score_zero_ms() {
        assert!((latency_score(0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_score_1000ms_is_half() {
        assert!((latency_score(1000) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_score_decreases_monotonically() {
        let a = latency_score(100);
        let b = latency_score(500);
        let c = latency_score(2000);
        assert!(a > b);
        assert!(b > c);
        assert!(c > 0.0);
    }

    // -----------------------------------------------------------------------
    // Preference score helper
    // -----------------------------------------------------------------------

    #[test]
    fn preference_score_zero_count() {
        assert!((preference_score(0) - 0.0).abs() < 0.01);
    }

    #[test]
    fn preference_score_increases_with_count() {
        let a = preference_score(1);
        let b = preference_score(10);
        let c = preference_score(50);
        assert!(a > 0.0);
        assert!(b > a);
        assert!(c > b);
    }

    #[test]
    fn preference_score_capped_at_one() {
        assert!(preference_score(1000) <= 1.0);
        assert!(preference_score(u32::MAX) <= 1.0);
    }

    // -----------------------------------------------------------------------
    // Signal weights
    // -----------------------------------------------------------------------

    #[test]
    fn default_weights_match_spec() {
        let w = SignalWeights::default();
        assert!((w.zone - 100.0).abs() < f64::EPSILON);
        assert!((w.health - 50.0).abs() < f64::EPSILON);
        assert!((w.rate_limit - 20.0).abs() < f64::EPSILON);
        assert!((w.success - 15.0).abs() < f64::EPSILON);
        assert!((w.preference - 10.0).abs() < f64::EPSILON);
        assert!((w.safety - 8.0).abs() < f64::EPSILON);
        assert!((w.latency - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn weights_total() {
        let w = SignalWeights::default();
        assert!((w.total() - 208.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Score computation — individual signals
    // -----------------------------------------------------------------------

    #[test]
    fn score_zone_unauthorized_yields_zero() {
        let mut c = default_candidate();
        c.zone_authorized = false;
        let (score, bd) = compute_score(&c, &default_weights());
        assert!((score - 0.0).abs() < f64::EPSILON);
        assert!((bd.zone - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_health_error_yields_zero() {
        let mut c = default_candidate();
        c.health = HealthState::Error;
        let (score, _bd) = compute_score(&c, &default_weights());
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_health_degraded_reduces_score() {
        let healthy = default_candidate();
        let mut degraded = default_candidate();
        degraded.health = HealthState::Degraded;

        let (hs, _) = compute_score(&healthy, &default_weights());
        let (ds, _) = compute_score(&degraded, &default_weights());
        assert!(hs > ds);
    }

    #[test]
    fn score_rate_headroom_signal() {
        let mut high = default_candidate();
        high.rate_headroom = 1.0;
        let mut low = default_candidate();
        low.rate_headroom = 0.1;

        let w = default_weights();
        let (hs, _) = compute_score(&high, &w);
        let (ls, _) = compute_score(&low, &w);
        assert!(hs > ls);
    }

    #[test]
    fn score_success_rate_signal() {
        let mut high = default_candidate();
        high.success_rate = 1.0;
        let mut low = default_candidate();
        low.success_rate = 0.2;

        let w = default_weights();
        let (hs, _) = compute_score(&high, &w);
        let (ls, _) = compute_score(&low, &w);
        assert!(hs > ls);
    }

    #[test]
    fn score_preference_signal() {
        let mut popular = default_candidate();
        popular.preference_count = 50;
        let mut unpopular = default_candidate();
        unpopular.preference_count = 0;

        let w = default_weights();
        let (ps, _) = compute_score(&popular, &w);
        let (us, _) = compute_score(&unpopular, &w);
        assert!(ps > us);
    }

    #[test]
    fn score_safety_signal() {
        let mut safe = default_candidate();
        safe.safety_tier = SafetyRank::Safe;
        let mut crit = default_candidate();
        crit.safety_tier = SafetyRank::Critical;

        let w = default_weights();
        let (ss, _) = compute_score(&safe, &w);
        let (cs, _) = compute_score(&crit, &w);
        assert!(ss > cs);
    }

    #[test]
    fn score_latency_signal() {
        let mut fast = default_candidate();
        fast.avg_latency_ms = 10;
        let mut slow = default_candidate();
        slow.avg_latency_ms = 5000;

        let w = default_weights();
        let (fs, _) = compute_score(&fast, &w);
        let (ss, _) = compute_score(&slow, &w);
        assert!(fs > ss);
    }

    #[test]
    fn score_combined_signals_in_range() {
        let c = default_candidate();
        let (score, _) = compute_score(&c, &default_weights());
        assert!(score > 0.0);
        assert!(score <= 1.0);
    }

    #[test]
    fn score_perfect_candidate_near_one() {
        let c = ConnectorCandidate {
            connector_id: "perfect".to_owned(),
            operation_id: "op".to_owned(),
            zone_authorized: true,
            health: HealthState::Healthy,
            rate_headroom: 1.0,
            success_rate: 1.0,
            preference_count: 100,
            safety_tier: SafetyRank::Safe,
            avg_latency_ms: 0,
        };
        let (score, _) = compute_score(&c, &default_weights());
        // Should be very close to 1.0.
        assert!(score > 0.95);
    }

    #[test]
    fn score_breakdown_zone_weight_applied() {
        let c = default_candidate();
        let w = default_weights();
        let (_, bd) = compute_score(&c, &w);
        // zone_authorized=true → 1.0 * 100.0 = 100.0
        assert!((bd.zone - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_rate_headroom_clamped() {
        let mut c = default_candidate();
        c.rate_headroom = 1.5; // over 1.0
        let w = default_weights();
        let (_, bd) = compute_score(&c, &w);
        // Clamped to 1.0 * 20.0 = 20.0
        assert!((bd.rate_limit - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_success_rate_clamped_negative() {
        let mut c = default_candidate();
        c.success_rate = -0.5;
        let w = default_weights();
        let (_, bd) = compute_score(&c, &w);
        assert!((bd.success - 0.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Custom weights
    // -----------------------------------------------------------------------

    #[test]
    fn custom_weights_change_outcome() {
        let mut fast = default_candidate();
        fast.connector_id = "fast".to_owned();
        fast.avg_latency_ms = 10;
        fast.success_rate = 0.5;

        let mut reliable = default_candidate();
        reliable.connector_id = "reliable".to_owned();
        reliable.avg_latency_ms = 500;
        reliable.success_rate = 1.0;

        // Default weights: success(15) > latency(5) → reliable wins.
        let dw = default_weights();
        let (fs, _) = compute_score(&fast, &dw);
        let (rs, _) = compute_score(&reliable, &dw);
        assert!(rs > fs, "reliable should win with default weights");

        // Custom weights: latency(100) >> success(1) → fast wins.
        let cw = SignalWeights {
            zone: 100.0,
            health: 50.0,
            rate_limit: 20.0,
            success: 1.0,
            preference: 10.0,
            safety: 8.0,
            latency: 100.0,
        };
        let (fs2, _) = compute_score(&fast, &cw);
        let (rs2, _) = compute_score(&reliable, &cw);
        assert!(fs2 > rs2, "fast should win with latency-heavy weights");
    }

    // -----------------------------------------------------------------------
    // Ranking
    // -----------------------------------------------------------------------

    #[test]
    fn rank_empty_input() {
        let result = rank_candidates(&[], &default_config());
        assert!(result.is_empty());
    }

    #[test]
    fn rank_single_candidate_recommended() {
        let c = default_candidate();
        let result = rank_candidates(&[c], &default_config());
        assert_eq!(result.len(), 1);
        assert!(result[0].recommended);
        assert!(result[0].score > 0.0);
    }

    #[test]
    fn rank_single_unauthorized_not_recommended() {
        let mut c = default_candidate();
        c.zone_authorized = false;
        let result = rank_candidates(&[c], &default_config());
        assert_eq!(result.len(), 1);
        assert!(!result[0].recommended);
        assert!((result[0].score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rank_multiple_candidates_sorted_descending() {
        let mut good = default_candidate();
        good.connector_id = "good".to_owned();
        good.success_rate = 1.0;
        good.avg_latency_ms = 50;

        let mut bad = default_candidate();
        bad.connector_id = "bad".to_owned();
        bad.success_rate = 0.2;
        bad.avg_latency_ms = 3000;
        bad.rate_headroom = 0.1;

        let result = rank_candidates(&[bad, good], &default_config());
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].connector_id, "good");
        assert_eq!(result[1].connector_id, "bad");
        assert!(result[0].score >= result[1].score);
        assert!(result[0].recommended);
        assert!(!result[1].recommended);
    }

    #[test]
    fn rank_zone_unauthorized_sorted_last() {
        let mut auth = default_candidate();
        auth.connector_id = "auth".to_owned();
        auth.zone_authorized = true;

        let mut unauth = default_candidate();
        unauth.connector_id = "unauth".to_owned();
        unauth.zone_authorized = false;
        unauth.success_rate = 1.0;
        unauth.avg_latency_ms = 0;

        let result = rank_candidates(&[unauth, auth], &default_config());
        assert_eq!(result[0].connector_id, "auth");
        assert!(result[0].recommended);
        assert!((result[1].score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rank_all_unhealthy_none_recommended() {
        let mut c1 = default_candidate();
        c1.connector_id = "c1".to_owned();
        c1.health = HealthState::Error;

        let mut c2 = default_candidate();
        c2.connector_id = "c2".to_owned();
        c2.health = HealthState::Error;

        let result = rank_candidates(&[c1, c2], &default_config());
        assert_eq!(result.len(), 2);
        assert!(!result[0].recommended);
        assert!(!result[1].recommended);
    }

    #[test]
    fn rank_tie_breaking_by_connector_id() {
        // Two identical candidates except for the id.
        let mut a = default_candidate();
        a.connector_id = "alpha".to_owned();

        let mut b = default_candidate();
        b.connector_id = "beta".to_owned();

        let result = rank_candidates(&[b, a], &default_config());
        // Scores are equal; alpha < beta lexicographically → alpha first.
        assert_eq!(result[0].connector_id, "alpha");
        assert_eq!(result[1].connector_id, "beta");
    }

    #[test]
    fn rank_preserves_operation_id() {
        let mut c = default_candidate();
        c.operation_id = "list_channels".to_owned();
        let result = rank_candidates(&[c], &default_config());
        assert_eq!(result[0].operation_id, "list_channels");
    }

    #[test]
    fn rank_mixed_health_degraded_above_error() {
        let mut degraded = default_candidate();
        degraded.connector_id = "degraded".to_owned();
        degraded.health = HealthState::Degraded;

        let mut error = default_candidate();
        error.connector_id = "error".to_owned();
        error.health = HealthState::Error;

        let result = rank_candidates(&[error, degraded], &default_config());
        assert_eq!(result[0].connector_id, "degraded");
        assert!(result[0].score > 0.0);
        assert!((result[1].score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rank_three_candidates_ordered_correctly() {
        let mut best = default_candidate();
        best.connector_id = "best".to_owned();
        best.success_rate = 1.0;
        best.rate_headroom = 1.0;
        best.avg_latency_ms = 10;

        let mut mid = default_candidate();
        mid.connector_id = "mid".to_owned();
        mid.success_rate = 0.7;
        mid.rate_headroom = 0.5;
        mid.avg_latency_ms = 500;

        let mut worst = default_candidate();
        worst.connector_id = "worst".to_owned();
        worst.success_rate = 0.3;
        worst.rate_headroom = 0.1;
        worst.avg_latency_ms = 3000;

        let result = rank_candidates(&[worst, best, mid], &default_config());
        assert_eq!(result[0].connector_id, "best");
        assert_eq!(result[1].connector_id, "mid");
        assert_eq!(result[2].connector_id, "worst");
        assert!(result[0].recommended);
    }

    // -----------------------------------------------------------------------
    // Preference store
    // -----------------------------------------------------------------------

    #[test]
    fn pref_store_new_empty() {
        let store = PreferenceStore::new("/tmp/test_prefs_new.json");
        assert_eq!(store.get_preference("send_message", "slack"), 0);
        assert!(store.data().is_empty());
    }

    #[test]
    fn pref_store_record_and_get() {
        let mut store = PreferenceStore::new("/tmp/test_prefs_rg.json");
        store.record_choice("send_message", "slack");
        store.record_choice("send_message", "slack");
        store.record_choice("send_message", "discord");

        assert_eq!(store.get_preference("send_message", "slack"), 2);
        assert_eq!(store.get_preference("send_message", "discord"), 1);
        assert_eq!(store.get_preference("send_message", "teams"), 0);
    }

    #[test]
    fn pref_store_accumulate() {
        let mut store = PreferenceStore::new("/tmp/test_prefs_acc.json");
        for _ in 0..10 {
            store.record_choice("list_files", "dropbox");
        }
        assert_eq!(store.get_preference("list_files", "dropbox"), 10);
    }

    #[test]
    fn pref_store_save_load_roundtrip() {
        let path = std::env::temp_dir().join("fwc_routing_test_prefs_roundtrip.json");
        // Clean up from any previous run.
        let _ = fs::remove_file(&path);

        let mut store = PreferenceStore::new(&path);
        store.record_choice("send_message", "slack");
        store.record_choice("send_message", "slack");
        store.record_choice("list_repos", "github");
        store.save().expect("save failed");

        let mut loaded = PreferenceStore::new(&path);
        loaded.load().expect("load failed");
        assert_eq!(loaded.get_preference("send_message", "slack"), 2);
        assert_eq!(loaded.get_preference("list_repos", "github"), 1);
        assert_eq!(loaded.get_preference("missing", "x"), 0);

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn pref_store_load_missing_file_ok() {
        let mut store = PreferenceStore::new("/tmp/does_not_exist_routing_test.json");
        assert!(store.load().is_ok());
        assert!(store.data().is_empty());
    }

    #[test]
    fn pref_store_load_corrupt_file_err() {
        let path = std::env::temp_dir().join("fwc_routing_test_corrupt.json");
        fs::write(&path, "not valid json {{{{").unwrap();
        let mut store = PreferenceStore::new(&path);
        assert!(store.load().is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn pref_store_multiple_intents() {
        let mut store = PreferenceStore::new("/tmp/test_prefs_multi.json");
        store.record_choice("send_message", "slack");
        store.record_choice("list_files", "dropbox");
        store.record_choice("send_message", "discord");

        assert_eq!(store.data().len(), 2);
        assert_eq!(store.get_preference("send_message", "slack"), 1);
        assert_eq!(store.get_preference("list_files", "dropbox"), 1);
    }

    #[test]
    fn pref_store_path_accessor() {
        let store = PreferenceStore::new("/some/path/prefs.json");
        assert_eq!(store.path(), Path::new("/some/path/prefs.json"));
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn edge_all_candidates_unauthorized() {
        let mut c1 = default_candidate();
        c1.connector_id = "c1".to_owned();
        c1.zone_authorized = false;

        let mut c2 = default_candidate();
        c2.connector_id = "c2".to_owned();
        c2.zone_authorized = false;

        let result = rank_candidates(&[c1, c2], &default_config());
        for r in &result {
            assert!(!r.recommended);
            assert!((r.score - 0.0).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn edge_identical_scores_deterministic_order() {
        // Run twice to confirm determinism.
        let make = || {
            let mut a = default_candidate();
            a.connector_id = "aaa".to_owned();
            let mut b = default_candidate();
            b.connector_id = "bbb".to_owned();
            let mut c = default_candidate();
            c.connector_id = "ccc".to_owned();
            rank_candidates(&[c, a, b], &default_config())
        };

        let r1 = make();
        let r2 = make();
        for (a, b) in r1.iter().zip(r2.iter()) {
            assert_eq!(a.connector_id, b.connector_id);
        }
        // Lexicographic order for ties.
        assert_eq!(r1[0].connector_id, "aaa");
        assert_eq!(r1[1].connector_id, "bbb");
        assert_eq!(r1[2].connector_id, "ccc");
    }

    #[test]
    fn edge_zero_total_weight() {
        let w = SignalWeights {
            zone: 0.0,
            health: 0.0,
            rate_limit: 0.0,
            success: 0.0,
            preference: 0.0,
            safety: 0.0,
            latency: 0.0,
        };
        let c = default_candidate();
        let (score, _) = compute_score(&c, &w);
        // All weights zero → normalised to 0.
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn edge_unknown_health_routable_but_penalised() {
        let mut c = default_candidate();
        c.health = HealthState::Unknown;
        let w = default_weights();
        let (score, _) = compute_score(&c, &w);
        assert!(score > 0.0, "unknown health should still be routable");

        let healthy = default_candidate();
        let (hs, _) = compute_score(&healthy, &w);
        assert!(hs > score, "healthy should score higher than unknown");
    }

    #[test]
    fn edge_critical_safety_still_routable() {
        let mut c = default_candidate();
        c.safety_tier = SafetyRank::Critical;
        let (score, _) = compute_score(&c, &default_weights());
        assert!(
            score > 0.0,
            "critical safety should still produce a positive score"
        );
    }

    #[test]
    fn edge_very_high_latency() {
        let mut c = default_candidate();
        c.avg_latency_ms = u64::MAX;
        let (score, bd) = compute_score(&c, &default_weights());
        assert!(score > 0.0, "high latency should not zero out score");
        assert!(bd.latency >= 0.0);
    }

    #[test]
    fn edge_zero_latency() {
        let mut c = default_candidate();
        c.avg_latency_ms = 0;
        let w = default_weights();
        let (_, bd) = compute_score(&c, &w);
        assert!((bd.latency - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn routing_config_default() {
        let config = RoutingConfig::default();
        assert_eq!(config.weights, SignalWeights::default());
    }

    // ── Additional tests ──────────────────────────────────────────

    #[test]
    fn health_state_display_healthy() {
        assert_eq!(HealthState::Healthy.to_string(), "healthy");
    }

    #[test]
    fn health_state_display_degraded() {
        assert_eq!(HealthState::Degraded.to_string(), "degraded");
    }

    #[test]
    fn health_state_display_error() {
        assert_eq!(HealthState::Error.to_string(), "error");
    }

    #[test]
    fn health_state_display_unknown() {
        assert_eq!(HealthState::Unknown.to_string(), "unknown");
    }

    #[test]
    fn safety_rank_display_safe() {
        assert_eq!(SafetyRank::Safe.to_string(), "safe");
    }

    #[test]
    fn safety_rank_display_risky() {
        assert_eq!(SafetyRank::Risky.to_string(), "risky");
    }

    #[test]
    fn safety_rank_display_dangerous() {
        assert_eq!(SafetyRank::Dangerous.to_string(), "dangerous");
    }

    #[test]
    fn safety_rank_display_critical() {
        assert_eq!(SafetyRank::Critical.to_string(), "critical");
    }

    #[test]
    fn safety_rank_display_unknown() {
        assert_eq!(SafetyRank::Unknown.to_string(), "unknown");
    }

    #[test]
    fn safety_rank_parse_risky() {
        assert_eq!("risky".parse::<SafetyRank>().unwrap(), SafetyRank::Risky);
    }

    #[test]
    fn safety_rank_parse_dangerous() {
        assert_eq!(
            "dangerous".parse::<SafetyRank>().unwrap(),
            SafetyRank::Dangerous
        );
    }

    #[test]
    fn safety_rank_dangerous_score() {
        assert!((SafetyRank::Dangerous.score() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn latency_score_500ms() {
        let score = latency_score(500);
        // 1000 / (1000+500) = 2/3 ≈ 0.6667
        assert!((score - 2.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn latency_score_2000ms() {
        let score = latency_score(2000);
        // 1000 / 3000 ≈ 0.333
        assert!((score - 1.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn preference_score_one_choice() {
        let score = preference_score(1);
        assert!(score > 0.0);
        assert!(score < 0.5);
    }

    #[test]
    fn preference_score_hundred_choices() {
        let score = preference_score(100);
        // ln(101) / ln(101) = 1.0
        assert!((score - 1.0).abs() < 0.01);
    }

    #[test]
    fn preference_score_monotonic_increase() {
        let vals: Vec<f64> = (0..10).map(|i| preference_score(i * 10)).collect();
        for window in vals.windows(2) {
            assert!(window[1] >= window[0], "preference score should be monotonic");
        }
    }

    #[test]
    fn weights_custom_total() {
        let w = SignalWeights {
            zone: 10.0,
            health: 20.0,
            rate_limit: 30.0,
            success: 0.0,
            preference: 0.0,
            safety: 0.0,
            latency: 0.0,
        };
        assert!((w.total() - 60.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_breakdown_health_weight_applied() {
        let c = default_candidate();
        let w = default_weights();
        let (_, bd) = compute_score(&c, &w);
        // Healthy (1.0) * 50.0 = 50.0
        assert!((bd.health - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_breakdown_degraded_health_half_weight() {
        let mut c = default_candidate();
        c.health = HealthState::Degraded;
        let w = default_weights();
        let (_, bd) = compute_score(&c, &w);
        // Degraded (0.5) * 50.0 = 25.0
        assert!((bd.health - 25.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_breakdown_safety_weight_safe() {
        let c = default_candidate();
        let w = default_weights();
        let (_, bd) = compute_score(&c, &w);
        // Safe (1.0) * 8.0 = 8.0
        assert!((bd.safety - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_breakdown_safety_weight_dangerous() {
        let mut c = default_candidate();
        c.safety_tier = SafetyRank::Dangerous;
        let w = default_weights();
        let (_, bd) = compute_score(&c, &w);
        // Dangerous (0.25) * 8.0 = 2.0
        assert!((bd.safety - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_both_unauthorized_and_unhealthy_yields_zero() {
        let mut c = default_candidate();
        c.zone_authorized = false;
        c.health = HealthState::Error;
        let (score, bd) = compute_score(&c, &default_weights());
        assert!((score - 0.0).abs() < f64::EPSILON);
        assert!((bd.rate_limit - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn rank_five_candidates_correct_order() {
        let ids = ["e", "d", "c", "b", "a"];
        let rates = [0.1, 0.3, 0.5, 0.7, 0.9];
        let candidates: Vec<ConnectorCandidate> = ids
            .iter()
            .zip(rates.iter())
            .map(|(id, &rate)| {
                let mut c = default_candidate();
                c.connector_id = (*id).to_owned();
                c.success_rate = rate;
                c
            })
            .collect();

        let result = rank_candidates(&candidates, &default_config());
        assert_eq!(result.len(), 5);
        // Highest success rate first
        assert_eq!(result[0].connector_id, "a");
        assert!(result[0].recommended);
        // Only first is recommended
        for r in &result[1..] {
            assert!(!r.recommended);
        }
    }

    #[test]
    fn rank_all_error_health_no_recommended() {
        let candidates: Vec<ConnectorCandidate> = (0..3)
            .map(|i| {
                let mut c = default_candidate();
                c.connector_id = format!("c{i}");
                c.health = HealthState::Error;
                c
            })
            .collect();
        let result = rank_candidates(&candidates, &default_config());
        for r in &result {
            assert!(!r.recommended);
            assert!((r.score - 0.0).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn pref_store_data_accessor_returns_btreemap() {
        let mut store = PreferenceStore::new("/tmp/test_data_acc.json");
        store.record_choice("search", "algolia");
        let data = store.data();
        assert_eq!(data.len(), 1);
        assert!(data.contains_key("search"));
    }

    #[test]
    fn pref_store_get_preference_unknown_intent() {
        let store = PreferenceStore::new("/tmp/test_unknown_intent.json");
        assert_eq!(store.get_preference("unknown_intent", "slack"), 0);
    }

    #[test]
    fn pref_store_record_different_connectors_same_intent() {
        let mut store = PreferenceStore::new("/tmp/test_diff_conn.json");
        store.record_choice("notify", "slack");
        store.record_choice("notify", "discord");
        store.record_choice("notify", "teams");
        assert_eq!(store.get_preference("notify", "slack"), 1);
        assert_eq!(store.get_preference("notify", "discord"), 1);
        assert_eq!(store.get_preference("notify", "teams"), 1);
    }

    #[test]
    fn pref_store_record_many_increments() {
        let mut store = PreferenceStore::new("/tmp/test_many_inc.json");
        for _ in 0..100 {
            store.record_choice("deploy", "k8s");
        }
        assert_eq!(store.get_preference("deploy", "k8s"), 100);
    }

    #[test]
    fn connector_candidate_clone() {
        let c = default_candidate();
        let cloned = c.clone();
        assert_eq!(c.connector_id, cloned.connector_id);
        assert_eq!(c.operation_id, cloned.operation_id);
    }

    #[test]
    fn routing_score_contains_operation_id() {
        let mut c = default_candidate();
        c.operation_id = "custom_op".to_owned();
        let result = rank_candidates(&[c], &default_config());
        assert_eq!(result[0].operation_id, "custom_op");
    }

    #[test]
    fn score_rate_headroom_negative_clamped() {
        let mut c = default_candidate();
        c.rate_headroom = -1.0;
        let w = default_weights();
        let (_, bd) = compute_score(&c, &w);
        assert!((bd.rate_limit - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_success_rate_clamped_above_one() {
        let mut c = default_candidate();
        c.success_rate = 2.0;
        let w = default_weights();
        let (_, bd) = compute_score(&c, &w);
        // Clamped to 1.0 * 15.0 = 15.0
        assert!((bd.success - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_zone_unauthorized_breakdown_retains_zone() {
        let mut c = default_candidate();
        c.zone_authorized = false;
        let (_, bd) = compute_score(&c, &default_weights());
        assert!((bd.zone - 0.0).abs() < f64::EPSILON);
        // Other signals zeroed
        assert!((bd.success - 0.0).abs() < f64::EPSILON);
        assert!((bd.safety - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn score_error_health_breakdown_retains_health() {
        let mut c = default_candidate();
        c.health = HealthState::Error;
        let (_, bd) = compute_score(&c, &default_weights());
        assert!((bd.health - 0.0).abs() < f64::EPSILON);
        // Other signals zeroed
        assert!((bd.rate_limit - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn health_state_parse_mixed_case() {
        assert_eq!(
            "UnKnOwN".parse::<HealthState>().unwrap(),
            HealthState::Unknown
        );
        assert_eq!(
            "ERROR".parse::<HealthState>().unwrap(),
            HealthState::Error
        );
    }

    #[test]
    fn safety_rank_parse_mixed_case() {
        assert_eq!(
            "DaNgErOuS".parse::<SafetyRank>().unwrap(),
            SafetyRank::Dangerous
        );
    }
}
