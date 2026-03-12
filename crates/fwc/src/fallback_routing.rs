//! Fallback connector routing with circuit-breaker integration.
//!
//! When a primary connector fails persistently, this module:
//! 1. Tracks per-connector circuit breaker state.
//! 2. Determines if the failure is eligible for fallback routing.
//! 3. Selects the best alternative connector using the routing system.
//! 4. Reports the fallback decision transparently (never silently re-routes).
//!
//! # Design principles
//!
//! - **Transparent** — fallback decisions are always surfaced to the caller;
//!   automatic re-routing never happens silently.
//! - **Circuit-breaker first** — a connector must trip its circuit breaker
//!   before fallback routing is considered (not on first error).
//! - **Idempotency-conscious** — non-idempotent operations are never
//!   automatically rerouted; the caller gets a suggestion instead.
//! - **Honest** — the fallback decision includes confidence, risk, and
//!   cost deltas so the agent/user can make an informed choice.

use std::collections::HashMap;

use serde::Serialize;

use crate::error_taxonomy::FcpErrorCode;
use crate::reactive_rules::CircuitState;

// ── Circuit breaker registry ────────────────────────────────────────────

/// Tracks circuit breaker state for all connectors.
#[derive(Clone, Debug, Default)]
pub struct CircuitBreakerRegistry {
    breakers: HashMap<String, ConnectorCircuitState>,
    /// Error threshold before opening the circuit.
    error_threshold: u32,
    /// Window size for error rate calculation.
    window_size: u32,
}

/// Per-connector circuit state tracking.
#[derive(Clone, Debug)]
pub struct ConnectorCircuitState {
    /// Current state.
    pub state: CircuitState,
    /// Consecutive error count.
    pub error_count: u32,
    /// Total requests in the current window.
    pub window_requests: u32,
    /// Total errors in the current window.
    pub window_errors: u32,
    /// The error code that caused the circuit to open, if any.
    pub trip_code: Option<String>,
}

impl Default for ConnectorCircuitState {
    fn default() -> Self {
        Self {
            state: CircuitState::Closed,
            error_count: 0,
            window_requests: 0,
            window_errors: 0,
            trip_code: None,
        }
    }
}

impl ConnectorCircuitState {
    /// Error rate as a percentage (0–100).
    pub fn error_rate_percent(&self) -> u8 {
        if self.window_requests == 0 {
            return 0;
        }
        let rate = (self.window_errors as f64 / self.window_requests as f64) * 100.0;
        rate.round().min(100.0) as u8
    }
}

impl CircuitBreakerRegistry {
    /// Create a new registry with the given thresholds.
    pub fn new(error_threshold: u32, window_size: u32) -> Self {
        Self {
            breakers: HashMap::new(),
            error_threshold,
            window_size,
        }
    }

    /// Record a success for a connector.
    pub fn record_success(&mut self, connector_id: &str) {
        let entry = self.breakers.entry(connector_id.to_string()).or_default();

        entry.window_requests += 1;
        entry.error_count = 0;

        if entry.state == CircuitState::HalfOpen {
            entry.state = CircuitState::Closed;
            entry.window_errors = 0;
            entry.trip_code = None;
        }
    }

    /// Record a failure for a connector. Returns the new circuit state.
    pub fn record_failure(&mut self, connector_id: &str, error_code: FcpErrorCode) -> CircuitState {
        let entry = self.breakers.entry(connector_id.to_string()).or_default();

        entry.window_requests += 1;
        entry.window_errors += 1;
        entry.error_count += 1;

        // Trim window if needed.
        if entry.window_requests > self.window_size {
            // Simple sliding: halve the counts to approximate a sliding window.
            entry.window_requests /= 2;
            entry.window_errors /= 2;
        }

        // Check if we should trip the circuit.
        if entry.state == CircuitState::Closed
            && entry.error_count >= self.error_threshold
            && entry.error_rate_percent() >= 50
        {
            entry.state = CircuitState::Open;
            entry.trip_code = Some(error_code.as_str().to_string());
        }

        // HalfOpen failure → back to Open.
        if entry.state == CircuitState::HalfOpen {
            entry.state = CircuitState::Open;
            entry.trip_code = Some(error_code.as_str().to_string());
        }

        entry.state.clone()
    }

    /// Get the circuit state for a connector.
    pub fn get_state(&self, connector_id: &str) -> CircuitState {
        self.breakers
            .get(connector_id)
            .map_or(CircuitState::Closed, |e| e.state.clone())
    }

    /// Check if a connector's circuit is open.
    pub fn is_open(&self, connector_id: &str) -> bool {
        self.get_state(connector_id) == CircuitState::Open
    }

    /// Attempt to transition an open circuit to half-open (for probing).
    pub fn try_half_open(&mut self, connector_id: &str) -> bool {
        if let Some(entry) = self.breakers.get_mut(connector_id) {
            if entry.state == CircuitState::Open {
                entry.state = CircuitState::HalfOpen;
                return true;
            }
        }
        false
    }

    /// Get all connectors with open circuits.
    pub fn open_circuits(&self) -> Vec<&str> {
        self.breakers
            .iter()
            .filter(|(_, state)| state.state == CircuitState::Open)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Get the full state for a connector (for diagnostics).
    pub fn get_full_state(&self, connector_id: &str) -> Option<&ConnectorCircuitState> {
        self.breakers.get(connector_id)
    }

    /// Number of tracked connectors.
    pub fn tracked_count(&self) -> usize {
        self.breakers.len()
    }
}

// ── Fallback eligibility ────────────────────────────────────────────────

/// Whether an operation is eligible for automatic fallback routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackEligibility {
    /// Eligible for automatic fallback (idempotent, safe operation).
    Eligible,
    /// Suggest fallback but require confirmation (non-idempotent).
    SuggestOnly,
    /// Not eligible for fallback (e.g., connector-specific operation).
    NotEligible,
}

impl FallbackEligibility {
    /// Whether automatic routing is allowed.
    pub const fn allows_auto_route(&self) -> bool {
        matches!(self, Self::Eligible)
    }
}

// ── Fallback candidate ──────────────────────────────────────────────────

/// An alternative connector that could handle the failed operation.
#[derive(Clone, Debug, Serialize)]
pub struct FallbackCandidate {
    /// Alternative connector ID.
    pub connector_id: String,
    /// Operation that the alternative supports.
    pub operation_id: String,
    /// Routing score (0.0–1.0).
    pub score: f64,
    /// Circuit breaker state of this alternative.
    pub circuit_state: String,
    /// Whether this alternative's circuit is healthy (closed).
    pub circuit_healthy: bool,
    /// Risk assessment relative to the primary.
    pub risk_delta: RiskDelta,
}

/// Relative risk assessment between primary and fallback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskDelta {
    /// Fallback is equally safe or safer.
    Same,
    /// Fallback has higher risk (e.g., different safety tier).
    Higher,
    /// Fallback has lower risk.
    Lower,
    /// Risk cannot be compared (insufficient data).
    Unknown,
}

// ── Fallback decision ───────────────────────────────────────────────────

/// The outcome of evaluating fallback routing for a failed operation.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum FallbackDecision {
    /// No fallback needed — the primary connector's circuit is not tripped.
    NotNeeded {
        /// The primary connector.
        primary: String,
        /// Reason.
        reason: String,
    },
    /// An automatic fallback was selected.
    AutoFallback {
        /// The primary connector that failed.
        primary: String,
        /// The selected fallback.
        fallback: FallbackCandidate,
        /// Number of alternatives considered.
        alternatives_considered: usize,
    },
    /// A fallback is suggested but requires user/agent confirmation.
    SuggestFallback {
        /// The primary connector that failed.
        primary: String,
        /// The suggested fallback.
        suggestion: FallbackCandidate,
        /// Why confirmation is needed.
        reason: String,
        /// Number of alternatives considered.
        alternatives_considered: usize,
    },
    /// No suitable fallback found.
    NoFallbackAvailable {
        /// The primary connector that failed.
        primary: String,
        /// Why no fallback is available.
        reason: String,
        /// Number of alternatives checked (all unsuitable).
        alternatives_checked: usize,
    },
}

impl FallbackDecision {
    /// Whether a fallback connector was selected or suggested.
    pub const fn has_fallback(&self) -> bool {
        matches!(
            self,
            Self::AutoFallback { .. } | Self::SuggestFallback { .. }
        )
    }

    /// Whether the fallback was automatically selected (vs. suggestion only).
    pub const fn is_auto(&self) -> bool {
        matches!(self, Self::AutoFallback { .. })
    }

    /// Get the primary connector ID.
    pub fn primary(&self) -> &str {
        match self {
            Self::NotNeeded { primary, .. }
            | Self::AutoFallback { primary, .. }
            | Self::SuggestFallback { primary, .. }
            | Self::NoFallbackAvailable { primary, .. } => primary,
        }
    }
}

// ── Fallback evaluator ──────────────────────────────────────────────────

/// Evaluates fallback routing for a failed operation.
///
/// Takes the circuit breaker registry, available alternatives, and
/// eligibility constraints to produce a `FallbackDecision`.
pub fn evaluate_fallback(
    registry: &CircuitBreakerRegistry,
    primary_connector: &str,
    operation_id: &str,
    eligibility: FallbackEligibility,
    alternatives: &[(String, f64)], // (connector_id, routing_score)
) -> FallbackDecision {
    // If the primary circuit is not open, no fallback needed.
    if !registry.is_open(primary_connector) {
        return FallbackDecision::NotNeeded {
            primary: primary_connector.to_string(),
            reason: "Primary connector circuit is not tripped".to_string(),
        };
    }

    // If not eligible for fallback at all, report no fallback.
    if eligibility == FallbackEligibility::NotEligible {
        return FallbackDecision::NoFallbackAvailable {
            primary: primary_connector.to_string(),
            reason: "Operation is not eligible for fallback routing".to_string(),
            alternatives_checked: 0,
        };
    }

    // Filter alternatives: must have closed circuit and positive score.
    let viable: Vec<FallbackCandidate> = alternatives
        .iter()
        .filter(|(id, score)| !registry.is_open(id) && *score > 0.0 && id != primary_connector)
        .map(|(id, score)| {
            let state = registry.get_state(id);
            FallbackCandidate {
                connector_id: id.clone(),
                operation_id: operation_id.to_string(),
                score: *score,
                circuit_state: format!("{state}"),
                circuit_healthy: state == CircuitState::Closed,
                risk_delta: RiskDelta::Unknown, // would need more context
            }
        })
        .collect();

    if viable.is_empty() {
        return FallbackDecision::NoFallbackAvailable {
            primary: primary_connector.to_string(),
            reason: "All alternatives have tripped circuits or zero score".to_string(),
            alternatives_checked: alternatives.len(),
        };
    }

    // Pick the best viable alternative.
    let best = viable
        .into_iter()
        .max_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .unwrap(); // safe: viable is non-empty

    let alternatives_considered = alternatives.len();

    match eligibility {
        FallbackEligibility::Eligible => FallbackDecision::AutoFallback {
            primary: primary_connector.to_string(),
            fallback: best,
            alternatives_considered,
        },
        FallbackEligibility::SuggestOnly => FallbackDecision::SuggestFallback {
            primary: primary_connector.to_string(),
            suggestion: best,
            reason: "Non-idempotent operation requires confirmation for fallback".to_string(),
            alternatives_considered,
        },
        FallbackEligibility::NotEligible => unreachable!(), // handled above
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_taxonomy::FcpErrorCode;

    fn make_registry(threshold: u32, window: u32) -> CircuitBreakerRegistry {
        CircuitBreakerRegistry::new(threshold, window)
    }

    // ── ConnectorCircuitState ────────────────────────────────────────

    #[test]
    fn default_circuit_state_is_closed() {
        let state = ConnectorCircuitState::default();
        assert_eq!(state.state, CircuitState::Closed);
        assert_eq!(state.error_count, 0);
    }

    #[test]
    fn error_rate_zero_when_no_requests() {
        let state = ConnectorCircuitState::default();
        assert_eq!(state.error_rate_percent(), 0);
    }

    #[test]
    fn error_rate_correct_with_requests() {
        let state = ConnectorCircuitState {
            window_requests: 10,
            window_errors: 3,
            ..Default::default()
        };
        assert_eq!(state.error_rate_percent(), 30);
    }

    #[test]
    fn error_rate_100_when_all_errors() {
        let state = ConnectorCircuitState {
            window_requests: 5,
            window_errors: 5,
            ..Default::default()
        };
        assert_eq!(state.error_rate_percent(), 100);
    }

    // ── CircuitBreakerRegistry ───────────────────────────────────────

    #[test]
    fn registry_default_has_no_connectors() {
        let reg = make_registry(5, 10);
        assert_eq!(reg.tracked_count(), 0);
    }

    #[test]
    fn registry_unknown_connector_is_closed() {
        let reg = make_registry(5, 10);
        assert_eq!(reg.get_state("unknown"), CircuitState::Closed);
        assert!(!reg.is_open("unknown"));
    }

    #[test]
    fn registry_success_keeps_circuit_closed() {
        let mut reg = make_registry(5, 10);
        reg.record_success("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);
    }

    #[test]
    fn registry_single_failure_stays_closed() {
        let mut reg = make_registry(5, 10);
        let state = reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        assert_eq!(state, CircuitState::Closed);
    }

    #[test]
    fn registry_trips_after_threshold() {
        let mut reg = make_registry(3, 10);

        // First 2 failures: still closed.
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);

        // 3rd failure with ≥50% error rate: trips.
        let state = reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(state, CircuitState::Open);
        assert!(reg.is_open("conn-a"));
    }

    #[test]
    fn registry_trip_records_error_code() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);

        let full = reg.get_full_state("conn-a").unwrap();
        assert_eq!(full.trip_code.as_deref(), Some("FCP_ERR_RATE_LIMITED"));
    }

    #[test]
    fn registry_success_resets_error_count() {
        let mut reg = make_registry(5, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_success("conn-a");

        let full = reg.get_full_state("conn-a").unwrap();
        assert_eq!(full.error_count, 0);
    }

    #[test]
    fn registry_half_open_success_closes_circuit() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        assert!(reg.is_open("conn-a"));

        reg.try_half_open("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::HalfOpen);

        reg.record_success("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);
    }

    #[test]
    fn registry_half_open_failure_reopens_circuit() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        reg.try_half_open("conn-a");
        let state = reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(state, CircuitState::Open);
    }

    #[test]
    fn registry_try_half_open_on_closed_returns_false() {
        let mut reg = make_registry(5, 10);
        reg.record_success("conn-a");
        assert!(!reg.try_half_open("conn-a"));
    }

    #[test]
    fn registry_try_half_open_on_open_returns_true() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        assert!(reg.try_half_open("conn-a"));
    }

    #[test]
    fn registry_open_circuits_lists_tripped() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_success("conn-b");

        let open = reg.open_circuits();
        assert_eq!(open.len(), 1);
        assert!(open.contains(&"conn-a"));
    }

    #[test]
    fn registry_tracks_multiple_connectors() {
        let mut reg = make_registry(2, 10);
        reg.record_success("conn-a");
        reg.record_success("conn-b");
        reg.record_success("conn-c");
        assert_eq!(reg.tracked_count(), 3);
    }

    #[test]
    fn registry_high_error_rate_trips_circuit() {
        let mut reg = make_registry(3, 10);

        // 2 successes, then 3 failures: 60% error rate in window of 5.
        reg.record_success("conn-a");
        reg.record_success("conn-a");
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        let state = reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        assert_eq!(state, CircuitState::Open);
    }

    #[test]
    fn registry_mixed_success_failure_below_threshold_stays_closed() {
        let mut reg = make_registry(5, 10);

        // Alternating success/failure — error count resets on success.
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_success("conn-a");
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_success("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);
    }

    // ── FallbackEligibility ──────────────────────────────────────────

    #[test]
    fn eligible_allows_auto_route() {
        assert!(FallbackEligibility::Eligible.allows_auto_route());
    }

    #[test]
    fn suggest_only_does_not_allow_auto_route() {
        assert!(!FallbackEligibility::SuggestOnly.allows_auto_route());
    }

    #[test]
    fn not_eligible_does_not_allow_auto_route() {
        assert!(!FallbackEligibility::NotEligible.allows_auto_route());
    }

    // ── FallbackDecision ─────────────────────────────────────────────

    #[test]
    fn not_needed_has_no_fallback() {
        let d = FallbackDecision::NotNeeded {
            primary: "conn-a".to_string(),
            reason: "test".to_string(),
        };
        assert!(!d.has_fallback());
        assert!(!d.is_auto());
    }

    #[test]
    fn auto_fallback_has_fallback_and_is_auto() {
        let d = FallbackDecision::AutoFallback {
            primary: "conn-a".to_string(),
            fallback: FallbackCandidate {
                connector_id: "conn-b".to_string(),
                operation_id: "read".to_string(),
                score: 0.8,
                circuit_state: "closed".to_string(),
                circuit_healthy: true,
                risk_delta: RiskDelta::Same,
            },
            alternatives_considered: 2,
        };
        assert!(d.has_fallback());
        assert!(d.is_auto());
        assert_eq!(d.primary(), "conn-a");
    }

    #[test]
    fn suggest_fallback_has_fallback_but_not_auto() {
        let d = FallbackDecision::SuggestFallback {
            primary: "conn-a".to_string(),
            suggestion: FallbackCandidate {
                connector_id: "conn-b".to_string(),
                operation_id: "write".to_string(),
                score: 0.7,
                circuit_state: "closed".to_string(),
                circuit_healthy: true,
                risk_delta: RiskDelta::Higher,
            },
            reason: "non-idempotent".to_string(),
            alternatives_considered: 3,
        };
        assert!(d.has_fallback());
        assert!(!d.is_auto());
    }

    #[test]
    fn no_fallback_available() {
        let d = FallbackDecision::NoFallbackAvailable {
            primary: "conn-a".to_string(),
            reason: "all down".to_string(),
            alternatives_checked: 5,
        };
        assert!(!d.has_fallback());
        assert!(!d.is_auto());
    }

    // ── evaluate_fallback ────────────────────────────────────────────

    #[test]
    fn fallback_not_needed_when_circuit_closed() {
        let reg = make_registry(5, 10);
        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.8)],
        );
        assert!(matches!(decision, FallbackDecision::NotNeeded { .. }));
    }

    #[test]
    fn fallback_auto_when_eligible_and_circuit_open() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.8), ("conn-c".to_string(), 0.6)],
        );
        match &decision {
            FallbackDecision::AutoFallback {
                primary, fallback, ..
            } => {
                assert_eq!(primary, "conn-a");
                assert_eq!(fallback.connector_id, "conn-b"); // highest score
                assert!(fallback.circuit_healthy);
            }
            other => panic!("Expected AutoFallback, got {:?}", other),
        }
    }

    #[test]
    fn fallback_suggest_for_non_idempotent() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "write",
            FallbackEligibility::SuggestOnly,
            &[("conn-b".to_string(), 0.8)],
        );
        assert!(matches!(decision, FallbackDecision::SuggestFallback { .. }));
        assert!(decision.has_fallback());
        assert!(!decision.is_auto());
    }

    #[test]
    fn fallback_not_eligible_returns_no_fallback() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "custom-op",
            FallbackEligibility::NotEligible,
            &[("conn-b".to_string(), 0.8)],
        );
        assert!(matches!(
            decision,
            FallbackDecision::NoFallbackAvailable { .. }
        ));
    }

    #[test]
    fn fallback_no_viable_alternatives() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        // Alternative also has open circuit.
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.8)],
        );
        assert!(matches!(
            decision,
            FallbackDecision::NoFallbackAvailable { .. }
        ));
    }

    #[test]
    fn fallback_skips_zero_score_alternatives() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.0)],
        );
        assert!(matches!(
            decision,
            FallbackDecision::NoFallbackAvailable { .. }
        ));
    }

    #[test]
    fn fallback_selects_highest_scoring_alternative() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[
                ("conn-b".to_string(), 0.3),
                ("conn-c".to_string(), 0.9),
                ("conn-d".to_string(), 0.5),
            ],
        );
        match &decision {
            FallbackDecision::AutoFallback { fallback, .. } => {
                assert_eq!(fallback.connector_id, "conn-c");
            }
            other => panic!("Expected AutoFallback, got {:?}", other),
        }
    }

    #[test]
    fn fallback_excludes_primary_from_alternatives() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        // Only "alternative" is the primary itself.
        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-a".to_string(), 0.9)],
        );
        assert!(matches!(
            decision,
            FallbackDecision::NoFallbackAvailable { .. }
        ));
    }

    #[test]
    fn fallback_empty_alternatives_no_fallback() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision =
            evaluate_fallback(&reg, "conn-a", "read", FallbackEligibility::Eligible, &[]);
        assert!(matches!(
            decision,
            FallbackDecision::NoFallbackAvailable { .. }
        ));
    }

    // ── Serialization ────────────────────────────────────────────────

    #[test]
    fn fallback_decision_serializes_to_json() {
        let d = FallbackDecision::AutoFallback {
            primary: "conn-a".to_string(),
            fallback: FallbackCandidate {
                connector_id: "conn-b".to_string(),
                operation_id: "read".to_string(),
                score: 0.85,
                circuit_state: "closed".to_string(),
                circuit_healthy: true,
                risk_delta: RiskDelta::Same,
            },
            alternatives_considered: 3,
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "auto_fallback");
        assert_eq!(json["primary"], "conn-a");
        assert_eq!(json["fallback"]["connector_id"], "conn-b");
    }

    #[test]
    fn fallback_eligibility_serializes() {
        let json = serde_json::to_value(FallbackEligibility::Eligible).unwrap();
        assert_eq!(json, "eligible");
    }

    #[test]
    fn risk_delta_serializes() {
        let json = serde_json::to_value(RiskDelta::Higher).unwrap();
        assert_eq!(json, "higher");
    }

    #[test]
    fn no_fallback_decision_serializes() {
        let d = FallbackDecision::NoFallbackAvailable {
            primary: "conn-a".to_string(),
            reason: "all circuits tripped".to_string(),
            alternatives_checked: 2,
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "no_fallback_available");
        assert_eq!(json["alternatives_checked"], 2);
    }

    // ── Cross-cutting ────────────────────────────────────────────────

    #[test]
    fn full_lifecycle_trip_fallback_recover() {
        let mut reg = make_registry(2, 10);

        // Step 1: Normal operation.
        reg.record_success("conn-a");
        assert!(!reg.is_open("conn-a"));

        // Step 2: Failures trip the circuit.
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        assert!(reg.is_open("conn-a"));

        // Step 3: Fallback routes to conn-b.
        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.9)],
        );
        assert!(decision.is_auto());

        // Step 4: Probe with half-open.
        reg.try_half_open("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::HalfOpen);

        // Step 5: Success closes the circuit.
        reg.record_success("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);

        // Step 6: No longer needs fallback.
        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.9)],
        );
        assert!(matches!(decision, FallbackDecision::NotNeeded { .. }));
    }

    // ── ConnectorCircuitState: additional coverage ─────────────────

    #[test]
    fn error_rate_rounding_midpoint() {
        // 1 error out of 3 = 33.33...% → rounds to 33
        let state = ConnectorCircuitState {
            window_requests: 3,
            window_errors: 1,
            ..Default::default()
        };
        assert_eq!(state.error_rate_percent(), 33);
    }

    #[test]
    fn error_rate_rounding_up() {
        // 2 errors out of 3 = 66.67% → rounds to 67
        let state = ConnectorCircuitState {
            window_requests: 3,
            window_errors: 2,
            ..Default::default()
        };
        assert_eq!(state.error_rate_percent(), 67);
    }

    #[test]
    fn error_rate_single_request_single_error() {
        let state = ConnectorCircuitState {
            window_requests: 1,
            window_errors: 1,
            ..Default::default()
        };
        assert_eq!(state.error_rate_percent(), 100);
    }

    #[test]
    fn error_rate_single_request_no_error() {
        let state = ConnectorCircuitState {
            window_requests: 1,
            window_errors: 0,
            ..Default::default()
        };
        assert_eq!(state.error_rate_percent(), 0);
    }

    #[test]
    fn error_rate_high_volume_low_error() {
        // 1 error out of 100 = 1%
        let state = ConnectorCircuitState {
            window_requests: 100,
            window_errors: 1,
            ..Default::default()
        };
        assert_eq!(state.error_rate_percent(), 1);
    }

    #[test]
    fn error_rate_exact_50_percent() {
        let state = ConnectorCircuitState {
            window_requests: 10,
            window_errors: 5,
            ..Default::default()
        };
        assert_eq!(state.error_rate_percent(), 50);
    }

    #[test]
    fn connector_circuit_state_clone_preserves_fields() {
        let state = ConnectorCircuitState {
            state: CircuitState::Open,
            error_count: 7,
            window_requests: 20,
            window_errors: 15,
            trip_code: Some("FCP_ERR_TRANSPORT_FAILED".to_string()),
        };
        let cloned = state.clone();
        assert_eq!(cloned.state, CircuitState::Open);
        assert_eq!(cloned.error_count, 7);
        assert_eq!(cloned.window_requests, 20);
        assert_eq!(cloned.window_errors, 15);
        assert_eq!(
            cloned.trip_code.as_deref(),
            Some("FCP_ERR_TRANSPORT_FAILED")
        );
    }

    #[test]
    fn connector_circuit_state_debug_format() {
        let state = ConnectorCircuitState::default();
        let dbg = format!("{state:?}");
        assert!(dbg.contains("Closed"));
        assert!(dbg.contains("error_count"));
    }

    #[test]
    fn default_circuit_state_all_fields_zero() {
        let state = ConnectorCircuitState::default();
        assert_eq!(state.window_requests, 0);
        assert_eq!(state.window_errors, 0);
        assert!(state.trip_code.is_none());
    }

    // ── CircuitBreakerRegistry: additional coverage ────────────────

    #[test]
    fn registry_default_constructor() {
        let reg = CircuitBreakerRegistry::default();
        assert_eq!(reg.tracked_count(), 0);
        // With default thresholds (0, 0), any failure trips immediately.
    }

    #[test]
    fn registry_record_failure_creates_entry() {
        let mut reg = make_registry(5, 10);
        reg.record_failure("new-conn", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(reg.tracked_count(), 1);
        let full = reg.get_full_state("new-conn").unwrap();
        assert_eq!(full.error_count, 1);
        assert_eq!(full.window_requests, 1);
        assert_eq!(full.window_errors, 1);
    }

    #[test]
    fn registry_record_success_creates_entry() {
        let mut reg = make_registry(5, 10);
        reg.record_success("new-conn");
        assert_eq!(reg.tracked_count(), 1);
        let full = reg.get_full_state("new-conn").unwrap();
        assert_eq!(full.error_count, 0);
        assert_eq!(full.window_requests, 1);
        assert_eq!(full.window_errors, 0);
    }

    #[test]
    fn registry_get_full_state_none_for_unknown() {
        let reg = make_registry(5, 10);
        assert!(reg.get_full_state("unknown").is_none());
    }

    #[test]
    fn registry_window_overflow_halves_counts() {
        let mut reg = make_registry(100, 5);
        // Push 6 failures → window_requests exceeds window_size of 5.
        for _ in 0..6 {
            reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        }
        let full = reg.get_full_state("conn-a").unwrap();
        // After 6th request: window_requests was 6 > 5, so halved to 3.
        assert_eq!(full.window_requests, 3);
        assert_eq!(full.window_errors, 3);
    }

    #[test]
    fn registry_window_halving_repeated() {
        let mut reg = make_registry(100, 4);
        // Push 5 failures, triggers halving once.
        for _ in 0..5 {
            reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        }
        let full = reg.get_full_state("conn-a").unwrap();
        // After 5th: was 5 > 4, halved to 2 requests, 2 errors.
        assert_eq!(full.window_requests, 2);
        assert_eq!(full.window_errors, 2);

        // Push 3 more: 2+3=5 > 4, halves again.
        for _ in 0..3 {
            reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        }
        let full2 = reg.get_full_state("conn-a").unwrap();
        assert_eq!(full2.window_requests, 2);
        assert_eq!(full2.window_errors, 2);
    }

    #[test]
    fn registry_threshold_exactly_at_boundary() {
        let mut reg = make_registry(3, 10);
        // 2 failures: below threshold.
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);
        // 3rd failure: exactly at threshold with 100% error rate → trips.
        let state = reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(state, CircuitState::Open);
    }

    #[test]
    fn registry_threshold_not_met_when_error_rate_below_50() {
        let mut reg = make_registry(3, 20);
        // 7 successes, then 3 failures: error_rate = 3/10 = 30% < 50%.
        for _ in 0..7 {
            reg.record_success("conn-a");
        }
        for _ in 0..3 {
            reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        }
        // 3 consecutive errors meet threshold but error rate is 30%.
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);
    }

    #[test]
    fn registry_multiple_connectors_independent_states() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert!(reg.is_open("conn-a"));

        reg.record_success("conn-b");
        assert!(!reg.is_open("conn-b"));
        assert_eq!(reg.get_state("conn-b"), CircuitState::Closed);
    }

    #[test]
    fn registry_open_circuits_multiple() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);
        reg.record_success("conn-c");

        let mut open = reg.open_circuits();
        open.sort();
        assert_eq!(open, vec!["conn-a", "conn-b"]);
    }

    #[test]
    fn registry_open_circuits_empty_when_all_closed() {
        let mut reg = make_registry(5, 10);
        reg.record_success("conn-a");
        reg.record_success("conn-b");
        assert!(reg.open_circuits().is_empty());
    }

    #[test]
    fn registry_try_half_open_unknown_connector() {
        let mut reg = make_registry(5, 10);
        assert!(!reg.try_half_open("unknown"));
    }

    #[test]
    fn registry_half_open_already_half_open_returns_false() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        assert!(reg.try_half_open("conn-a"));
        // Already half-open, should return false.
        assert!(!reg.try_half_open("conn-a"));
    }

    #[test]
    fn registry_half_open_clears_trip_code_on_success() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);
        assert!(reg.get_full_state("conn-a").unwrap().trip_code.is_some());

        reg.try_half_open("conn-a");
        reg.record_success("conn-a");
        let full = reg.get_full_state("conn-a").unwrap();
        assert!(full.trip_code.is_none());
        assert_eq!(full.window_errors, 0);
    }

    #[test]
    fn registry_half_open_failure_updates_trip_code() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);

        reg.try_half_open("conn-a");
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        let full = reg.get_full_state("conn-a").unwrap();
        assert_eq!(full.trip_code.as_deref(), Some("FCP_ERR_TRANSPORT_FAILED"));
    }

    #[test]
    fn registry_success_after_failure_resets_consecutive_count() {
        let mut reg = make_registry(5, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(reg.get_full_state("conn-a").unwrap().error_count, 2);

        reg.record_success("conn-a");
        assert_eq!(reg.get_full_state("conn-a").unwrap().error_count, 0);
        // Window errors NOT reset by success (only consecutive count).
        assert_eq!(reg.get_full_state("conn-a").unwrap().window_errors, 2);
    }

    #[test]
    fn registry_different_error_codes_still_accumulate() {
        let mut reg = make_registry(3, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        let state = reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);
        assert_eq!(state, CircuitState::Open);
        // Trip code is the last error that caused the trip.
        assert_eq!(
            reg.get_full_state("conn-a").unwrap().trip_code.as_deref(),
            Some("FCP_ERR_RATE_LIMITED")
        );
    }

    #[test]
    fn registry_clone_independence() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);

        let reg2 = reg.clone();
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        // Original tripped, clone still has 1 failure.
        assert!(reg.is_open("conn-a"));
        assert!(!reg2.is_open("conn-a"));
    }

    #[test]
    fn registry_threshold_one_trips_on_first_failure() {
        let mut reg = make_registry(1, 10);
        let state = reg.record_failure("conn-a", FcpErrorCode::FcpErrInternal);
        assert_eq!(state, CircuitState::Open);
    }

    // ── FallbackEligibility: additional coverage ───────────────────

    #[test]
    fn eligibility_clone_eq() {
        let e = FallbackEligibility::SuggestOnly;
        let e2 = e;
        assert_eq!(e, e2);
    }

    #[test]
    fn eligibility_all_variants_serialization() {
        let eligible = serde_json::to_value(FallbackEligibility::Eligible).unwrap();
        let suggest = serde_json::to_value(FallbackEligibility::SuggestOnly).unwrap();
        let not_eligible = serde_json::to_value(FallbackEligibility::NotEligible).unwrap();
        assert_eq!(eligible, "eligible");
        assert_eq!(suggest, "suggest_only");
        assert_eq!(not_eligible, "not_eligible");
    }

    #[test]
    fn eligibility_debug_format() {
        let dbg = format!("{:?}", FallbackEligibility::Eligible);
        assert_eq!(dbg, "Eligible");
    }

    // ── RiskDelta: additional coverage ──────────────────────────────

    #[test]
    fn risk_delta_all_variants_serialize() {
        assert_eq!(serde_json::to_value(RiskDelta::Same).unwrap(), "same");
        assert_eq!(serde_json::to_value(RiskDelta::Higher).unwrap(), "higher");
        assert_eq!(serde_json::to_value(RiskDelta::Lower).unwrap(), "lower");
        assert_eq!(serde_json::to_value(RiskDelta::Unknown).unwrap(), "unknown");
    }

    #[test]
    fn risk_delta_eq() {
        assert_eq!(RiskDelta::Same, RiskDelta::Same);
        assert_ne!(RiskDelta::Same, RiskDelta::Higher);
        assert_ne!(RiskDelta::Lower, RiskDelta::Unknown);
    }

    #[test]
    fn risk_delta_clone() {
        let r = RiskDelta::Higher;
        let r2 = r.clone();
        assert_eq!(r, r2);
    }

    #[test]
    fn risk_delta_debug() {
        let dbg = format!("{:?}", RiskDelta::Lower);
        assert_eq!(dbg, "Lower");
    }

    // ── FallbackCandidate ──────────────────────────────────────────

    #[test]
    fn fallback_candidate_serializes() {
        let c = FallbackCandidate {
            connector_id: "conn-x".to_string(),
            operation_id: "list".to_string(),
            score: 0.75,
            circuit_state: "closed".to_string(),
            circuit_healthy: true,
            risk_delta: RiskDelta::Lower,
        };
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(json["connector_id"], "conn-x");
        assert_eq!(json["operation_id"], "list");
        assert_eq!(json["score"], 0.75);
        assert_eq!(json["circuit_healthy"], true);
        assert_eq!(json["risk_delta"], "lower");
    }

    #[test]
    fn fallback_candidate_clone() {
        let c = FallbackCandidate {
            connector_id: "conn-x".to_string(),
            operation_id: "read".to_string(),
            score: 0.5,
            circuit_state: "open".to_string(),
            circuit_healthy: false,
            risk_delta: RiskDelta::Unknown,
        };
        let c2 = c.clone();
        assert_eq!(c2.connector_id, "conn-x");
        assert_eq!(c2.score, 0.5);
        assert!(!c2.circuit_healthy);
    }

    #[test]
    fn fallback_candidate_debug() {
        let c = FallbackCandidate {
            connector_id: "conn-x".to_string(),
            operation_id: "read".to_string(),
            score: 0.9,
            circuit_state: "closed".to_string(),
            circuit_healthy: true,
            risk_delta: RiskDelta::Same,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("conn-x"));
        assert!(dbg.contains("0.9"));
    }

    // ── FallbackDecision: additional coverage ──────────────────────

    #[test]
    fn not_needed_primary() {
        let d = FallbackDecision::NotNeeded {
            primary: "my-connector".to_string(),
            reason: "circuit healthy".to_string(),
        };
        assert_eq!(d.primary(), "my-connector");
    }

    #[test]
    fn no_fallback_available_primary() {
        let d = FallbackDecision::NoFallbackAvailable {
            primary: "primary-x".to_string(),
            reason: "none viable".to_string(),
            alternatives_checked: 10,
        };
        assert_eq!(d.primary(), "primary-x");
        assert!(!d.has_fallback());
        assert!(!d.is_auto());
    }

    #[test]
    fn suggest_fallback_primary() {
        let d = FallbackDecision::SuggestFallback {
            primary: "p1".to_string(),
            suggestion: FallbackCandidate {
                connector_id: "alt".to_string(),
                operation_id: "op".to_string(),
                score: 0.6,
                circuit_state: "closed".to_string(),
                circuit_healthy: true,
                risk_delta: RiskDelta::Unknown,
            },
            reason: "test".to_string(),
            alternatives_considered: 1,
        };
        assert_eq!(d.primary(), "p1");
    }

    #[test]
    fn fallback_decision_not_needed_serializes() {
        let d = FallbackDecision::NotNeeded {
            primary: "conn-z".to_string(),
            reason: "still healthy".to_string(),
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "not_needed");
        assert_eq!(json["primary"], "conn-z");
        assert_eq!(json["reason"], "still healthy");
    }

    #[test]
    fn suggest_fallback_serializes() {
        let d = FallbackDecision::SuggestFallback {
            primary: "conn-a".to_string(),
            suggestion: FallbackCandidate {
                connector_id: "conn-b".to_string(),
                operation_id: "write".to_string(),
                score: 0.65,
                circuit_state: "closed".to_string(),
                circuit_healthy: true,
                risk_delta: RiskDelta::Higher,
            },
            reason: "non-idempotent write".to_string(),
            alternatives_considered: 4,
        };
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["decision"], "suggest_fallback");
        assert_eq!(json["suggestion"]["connector_id"], "conn-b");
        assert_eq!(json["reason"], "non-idempotent write");
        assert_eq!(json["alternatives_considered"], 4);
    }

    #[test]
    fn fallback_decision_clone() {
        let d = FallbackDecision::AutoFallback {
            primary: "p".to_string(),
            fallback: FallbackCandidate {
                connector_id: "f".to_string(),
                operation_id: "op".to_string(),
                score: 0.9,
                circuit_state: "closed".to_string(),
                circuit_healthy: true,
                risk_delta: RiskDelta::Same,
            },
            alternatives_considered: 2,
        };
        let d2 = d.clone();
        assert_eq!(d2.primary(), "p");
        assert!(d2.is_auto());
    }

    // ── evaluate_fallback: additional coverage ─────────────────────

    #[test]
    fn fallback_negative_score_excluded() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), -0.5)],
        );
        assert!(matches!(
            decision,
            FallbackDecision::NoFallbackAvailable { .. }
        ));
    }

    #[test]
    fn fallback_mixed_viable_and_non_viable() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        // conn-b also open.
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[
                ("conn-b".to_string(), 0.9), // open circuit
                ("conn-c".to_string(), 0.0), // zero score
                ("conn-d".to_string(), 0.4), // viable!
            ],
        );
        match &decision {
            FallbackDecision::AutoFallback { fallback, .. } => {
                assert_eq!(fallback.connector_id, "conn-d");
            }
            other => panic!("Expected AutoFallback, got {other:?}"),
        }
    }

    #[test]
    fn fallback_suggest_only_picks_best() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "write",
            FallbackEligibility::SuggestOnly,
            &[("conn-b".to_string(), 0.2), ("conn-c".to_string(), 0.7)],
        );
        match &decision {
            FallbackDecision::SuggestFallback {
                suggestion,
                reason,
                alternatives_considered,
                ..
            } => {
                assert_eq!(suggestion.connector_id, "conn-c");
                assert!(!reason.is_empty());
                assert_eq!(*alternatives_considered, 2);
            }
            other => panic!("Expected SuggestFallback, got {other:?}"),
        }
    }

    #[test]
    fn fallback_suggest_includes_reason() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "delete",
            FallbackEligibility::SuggestOnly,
            &[("conn-b".to_string(), 0.5)],
        );
        match &decision {
            FallbackDecision::SuggestFallback { reason, .. } => {
                assert!(reason.contains("idempotent") || reason.contains("confirmation"));
            }
            other => panic!("Expected SuggestFallback, got {other:?}"),
        }
    }

    #[test]
    fn fallback_auto_includes_operation_id() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "list_items",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.8)],
        );
        match &decision {
            FallbackDecision::AutoFallback { fallback, .. } => {
                assert_eq!(fallback.operation_id, "list_items");
            }
            other => panic!("Expected AutoFallback, got {other:?}"),
        }
    }

    #[test]
    fn fallback_alternatives_considered_count() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let alts = vec![
            ("conn-b".to_string(), 0.3),
            ("conn-c".to_string(), 0.5),
            ("conn-d".to_string(), 0.7),
            ("conn-e".to_string(), 0.1),
        ];
        let decision =
            evaluate_fallback(&reg, "conn-a", "read", FallbackEligibility::Eligible, &alts);
        match &decision {
            FallbackDecision::AutoFallback {
                alternatives_considered,
                ..
            } => {
                assert_eq!(*alternatives_considered, 4);
            }
            other => panic!("Expected AutoFallback, got {other:?}"),
        }
    }

    #[test]
    fn fallback_all_alternatives_open_circuit() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-c", FcpErrorCode::FcpErrRateLimited);
        reg.record_failure("conn-c", FcpErrorCode::FcpErrRateLimited);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.8), ("conn-c".to_string(), 0.7)],
        );
        match &decision {
            FallbackDecision::NoFallbackAvailable {
                alternatives_checked,
                ..
            } => {
                assert_eq!(*alternatives_checked, 2);
            }
            other => panic!("Expected NoFallbackAvailable, got {other:?}"),
        }
    }

    #[test]
    fn fallback_not_eligible_reason_text() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "op",
            FallbackEligibility::NotEligible,
            &[("conn-b".to_string(), 0.8)],
        );
        match &decision {
            FallbackDecision::NoFallbackAvailable { reason, .. } => {
                assert!(reason.contains("not eligible"));
            }
            other => panic!("Expected NoFallbackAvailable, got {other:?}"),
        }
    }

    #[test]
    fn fallback_not_eligible_checks_zero_alternatives() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "op",
            FallbackEligibility::NotEligible,
            &[("conn-b".to_string(), 0.8), ("conn-c".to_string(), 0.5)],
        );
        match &decision {
            FallbackDecision::NoFallbackAvailable {
                alternatives_checked,
                ..
            } => {
                // NotEligible returns 0 alternatives_checked (short-circuits).
                assert_eq!(*alternatives_checked, 0);
            }
            other => panic!("Expected NoFallbackAvailable, got {other:?}"),
        }
    }

    #[test]
    fn fallback_half_open_alternative_is_viable() {
        let mut reg = make_registry(2, 10);
        // Primary is open.
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        // Alternative was open, now half-open (probing).
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);
        reg.try_half_open("conn-b");

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.8)],
        );
        // HalfOpen is NOT open, so it's viable.
        match &decision {
            FallbackDecision::AutoFallback { fallback, .. } => {
                assert_eq!(fallback.connector_id, "conn-b");
                // HalfOpen is not Closed, so circuit_healthy is false.
                assert!(!fallback.circuit_healthy);
            }
            other => panic!("Expected AutoFallback, got {other:?}"),
        }
    }

    #[test]
    fn fallback_circuit_state_label_in_candidate() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.8)],
        );
        match &decision {
            FallbackDecision::AutoFallback { fallback, .. } => {
                // conn-b has never been recorded → Closed by default.
                assert!(fallback.circuit_healthy);
                assert!(!fallback.circuit_state.is_empty());
            }
            other => panic!("Expected AutoFallback, got {other:?}"),
        }
    }

    // ── State transition: extended scenarios ────────────────────────

    #[test]
    fn state_transition_closed_open_half_open_open() {
        let mut reg = make_registry(2, 10);
        // Closed → Open
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(reg.get_state("conn-a"), CircuitState::Open);

        // Open → HalfOpen
        reg.try_half_open("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::HalfOpen);

        // HalfOpen → Open (failure during probe)
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        assert_eq!(reg.get_state("conn-a"), CircuitState::Open);
    }

    #[test]
    fn state_transition_closed_open_half_open_closed() {
        let mut reg = make_registry(2, 10);
        // Closed → Open
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(reg.get_state("conn-a"), CircuitState::Open);

        // Open → HalfOpen
        reg.try_half_open("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::HalfOpen);

        // HalfOpen → Closed (success during probe)
        reg.record_success("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);
    }

    #[test]
    fn state_transition_repeated_open_half_open_cycles() {
        let mut reg = make_registry(2, 10);
        // Trip it.
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(reg.get_state("conn-a"), CircuitState::Open);

        // First probe fails.
        reg.try_half_open("conn-a");
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        assert_eq!(reg.get_state("conn-a"), CircuitState::Open);

        // Second probe also fails.
        reg.try_half_open("conn-a");
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);
        assert_eq!(reg.get_state("conn-a"), CircuitState::Open);

        // Third probe succeeds.
        reg.try_half_open("conn-a");
        reg.record_success("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);
    }

    #[test]
    fn state_stays_open_on_additional_failures() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(reg.get_state("conn-a"), CircuitState::Open);

        // Additional failures while open.
        let state = reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert_eq!(state, CircuitState::Open);
        let state = reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        assert_eq!(state, CircuitState::Open);
    }

    // ── Cross-cutting: extended lifecycle ───────────────────────────

    #[allow(clippy::too_many_lines)]
    #[test]
    fn lifecycle_multiple_connectors_independent_fallback() {
        let mut reg = make_registry(2, 10);

        // Trip conn-a.
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        assert!(reg.is_open("conn-a"));

        // conn-b is healthy, conn-c is healthy.
        reg.record_success("conn-b");
        reg.record_success("conn-c");

        // Fallback from conn-a picks conn-c (higher score).
        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.6), ("conn-c".to_string(), 0.9)],
        );
        match &decision {
            FallbackDecision::AutoFallback { fallback, .. } => {
                assert_eq!(fallback.connector_id, "conn-c");
            }
            other => panic!("Expected AutoFallback, got {other:?}"),
        }

        // Now trip conn-c too.
        reg.record_failure("conn-c", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-c", FcpErrorCode::FcpErrTransportFailed);

        // Fallback from conn-a now only picks conn-b.
        let decision2 = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.6), ("conn-c".to_string(), 0.9)],
        );
        match &decision2 {
            FallbackDecision::AutoFallback { fallback, .. } => {
                assert_eq!(fallback.connector_id, "conn-b");
            }
            other => panic!("Expected AutoFallback, got {other:?}"),
        }
    }

    #[test]
    fn lifecycle_trip_recover_trip_again() {
        let mut reg = make_registry(2, 10);

        // First trip.
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        assert!(reg.is_open("conn-a"));

        // Recover.
        reg.try_half_open("conn-a");
        reg.record_success("conn-a");
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);

        // After recovery, window_errors=0 but window_requests is still ~3.
        // We need enough consecutive failures so that error_rate >= 50%.
        // With ~3 existing window_requests and 4 new failures: 4/7 = 57%.
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrRateLimited);
        assert!(reg.is_open("conn-a"));
        assert_eq!(
            reg.get_full_state("conn-a").unwrap().trip_code.as_deref(),
            Some("FCP_ERR_RATE_LIMITED")
        );
    }

    #[test]
    fn fallback_with_many_alternatives_picks_best_viable() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        // Trip some alternatives.
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-b", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-d", FcpErrorCode::FcpErrTransportFailed);
        reg.record_failure("conn-d", FcpErrorCode::FcpErrTransportFailed);

        let alts = vec![
            ("conn-b".to_string(), 0.95), // open circuit
            ("conn-c".to_string(), 0.7),  // viable
            ("conn-d".to_string(), 0.85), // open circuit
            ("conn-e".to_string(), 0.8),  // viable, highest viable
            ("conn-f".to_string(), 0.0),  // zero score
        ];
        let decision =
            evaluate_fallback(&reg, "conn-a", "read", FallbackEligibility::Eligible, &alts);
        match &decision {
            FallbackDecision::AutoFallback { fallback, .. } => {
                assert_eq!(fallback.connector_id, "conn-e");
                assert_eq!(fallback.score, 0.8);
            }
            other => panic!("Expected AutoFallback, got {other:?}"),
        }
    }

    #[test]
    fn fallback_equal_scores_picks_one() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.5), ("conn-c".to_string(), 0.5)],
        );
        // Should pick one of them (non-deterministic which with equal scores, but must pick one).
        assert!(decision.has_fallback());
        assert!(decision.is_auto());
    }

    #[test]
    fn fallback_not_needed_reason_text() {
        let reg = make_registry(5, 10);
        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.8)],
        );
        match &decision {
            FallbackDecision::NotNeeded { reason, .. } => {
                assert!(reason.contains("not tripped"));
            }
            other => panic!("Expected NotNeeded, got {other:?}"),
        }
    }

    #[test]
    fn fallback_no_viable_reason_text() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.0)],
        );
        match &decision {
            FallbackDecision::NoFallbackAvailable { reason, .. } => {
                assert!(reason.contains("tripped") || reason.contains("zero"));
            }
            other => panic!("Expected NoFallbackAvailable, got {other:?}"),
        }
    }

    #[test]
    fn fallback_primary_in_alternatives_list_excluded() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        // Primary is in the list with high score, but should be excluded.
        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-a".to_string(), 0.99), ("conn-b".to_string(), 0.3)],
        );
        match &decision {
            FallbackDecision::AutoFallback { fallback, .. } => {
                assert_eq!(fallback.connector_id, "conn-b");
            }
            other => panic!("Expected AutoFallback, got {other:?}"),
        }
    }

    #[test]
    fn registry_window_size_one_always_halves() {
        let mut reg = make_registry(100, 1);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        // window_requests=1, window_size=1, not > so no halving.
        let full = reg.get_full_state("conn-a").unwrap();
        assert_eq!(full.window_requests, 1);

        reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        // window_requests was 2 > 1, halved to 1.
        let full2 = reg.get_full_state("conn-a").unwrap();
        assert_eq!(full2.window_requests, 1);
    }

    #[test]
    fn registry_large_threshold_never_trips() {
        let mut reg = make_registry(1000, 10);
        for _ in 0..50 {
            reg.record_failure("conn-a", FcpErrorCode::FcpErrTransportFailed);
        }
        // error_count=50 < 1000 threshold.
        assert_eq!(reg.get_state("conn-a"), CircuitState::Closed);
    }

    #[test]
    fn evaluate_fallback_with_single_alternative() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.5)],
        );
        match &decision {
            FallbackDecision::AutoFallback {
                fallback,
                alternatives_considered,
                ..
            } => {
                assert_eq!(fallback.connector_id, "conn-b");
                assert_eq!(*alternatives_considered, 1);
            }
            other => panic!("Expected AutoFallback, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_fallback_suggest_with_empty_alternatives() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "write",
            FallbackEligibility::SuggestOnly,
            &[],
        );
        assert!(matches!(
            decision,
            FallbackDecision::NoFallbackAvailable { .. }
        ));
    }

    #[test]
    fn evaluate_fallback_very_small_positive_score() {
        let mut reg = make_registry(2, 10);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);
        reg.record_failure("conn-a", FcpErrorCode::FcpErrUpstreamTimeout);

        // Tiny positive score is still viable.
        let decision = evaluate_fallback(
            &reg,
            "conn-a",
            "read",
            FallbackEligibility::Eligible,
            &[("conn-b".to_string(), 0.001)],
        );
        assert!(decision.has_fallback());
    }
}
