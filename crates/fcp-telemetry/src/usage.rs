//! Capability usage telemetry aggregation.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;

use fcp_core::{CapabilityUsageEvent, CapabilityUsageKey, CapabilityUsageOutcome, SafetyTier};

/// Configuration for capability usage telemetry.
#[derive(Debug, Clone, Copy)]
pub struct UsageTelemetryConfig {
    /// Retention window in seconds.
    pub retention_secs: u64,
    /// Sampling rate in basis points (0-10000).
    pub sample_rate_bps: u16,
    /// Maximum number of aggregate entries to store.
    pub max_entries: usize,
}

impl Default for UsageTelemetryConfig {
    fn default() -> Self {
        Self {
            retention_secs: 7 * 24 * 60 * 60,
            sample_rate_bps: 10_000,
            max_entries: 10_000,
        }
    }
}

/// Aggregate telemetry for a capability usage key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityUsageAggregate {
    pub key: CapabilityUsageKey,
    pub total: u64,
    pub allowed: u64,
    pub denied: u64,
    pub errors: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub last_risk_tier: SafetyTier,
}

impl CapabilityUsageAggregate {
    fn new(key: CapabilityUsageKey, event: &CapabilityUsageEvent) -> Self {
        let mut aggregate = Self {
            key,
            total: 0,
            allowed: 0,
            denied: 0,
            errors: 0,
            first_seen: event.occurred_at,
            last_seen: event.occurred_at,
            last_risk_tier: event.risk_tier,
        };
        aggregate.apply(event);
        aggregate
    }

    fn apply(&mut self, event: &CapabilityUsageEvent) {
        self.total = self.total.saturating_add(1);
        self.last_seen = self.last_seen.max(event.occurred_at);
        self.first_seen = self.first_seen.min(event.occurred_at);
        self.last_risk_tier = event.risk_tier;

        match event.outcome {
            CapabilityUsageOutcome::Allow => {
                self.allowed = self.allowed.saturating_add(1);
            }
            CapabilityUsageOutcome::Deny => {
                self.denied = self.denied.saturating_add(1);
            }
            CapabilityUsageOutcome::Error => {
                self.errors = self.errors.saturating_add(1);
            }
        }
    }
}

/// In-memory telemetry store for capability usage aggregates.
#[derive(Debug)]
pub struct CapabilityUsageStore {
    config: UsageTelemetryConfig,
    aggregates: RwLock<HashMap<CapabilityUsageKey, CapabilityUsageAggregate>>,
}

impl CapabilityUsageStore {
    /// Create a new store with the provided config.
    #[must_use]
    pub fn new(config: UsageTelemetryConfig) -> Self {
        Self {
            config,
            aggregates: RwLock::new(HashMap::new()),
        }
    }

    /// Record a usage event, applying sampling and retention.
    ///
    /// Returns `true` if the event was recorded.
    pub fn record(&self, event: &CapabilityUsageEvent) -> bool {
        if !self.should_sample(event) {
            return false;
        }

        let mut aggregates = self.aggregates.write();
        Self::prune_locked(
            &mut aggregates,
            event.occurred_at,
            self.config.retention_secs,
        );

        if aggregates.len() >= self.config.max_entries {
            return false;
        }

        let key = event.key();
        aggregates
            .entry(key.clone())
            .and_modify(|aggregate| aggregate.apply(event))
            .or_insert_with(|| CapabilityUsageAggregate::new(key, event));
        true
    }

    /// Return a deterministic snapshot of aggregates.
    #[must_use]
    pub fn snapshot(&self) -> Vec<CapabilityUsageAggregate> {
        let mut values: Vec<CapabilityUsageAggregate> = {
            let aggregates = self.aggregates.read();
            aggregates.values().cloned().collect()
        };
        values.sort_by(|a, b| {
            let key_a = (
                a.key.zone_id.as_str(),
                a.key.connector_id.as_str(),
                a.key.capability_id.as_str(),
            );
            let key_b = (
                b.key.zone_id.as_str(),
                b.key.connector_id.as_str(),
                b.key.capability_id.as_str(),
            );
            key_a.cmp(&key_b)
        });
        values
    }

    fn should_sample(&self, event: &CapabilityUsageEvent) -> bool {
        if self.config.sample_rate_bps >= 10_000 {
            return true;
        }
        if self.config.sample_rate_bps == 0 {
            return false;
        }

        let mut hasher = DefaultHasher::new();
        Hash::hash(&event.zone_id, &mut hasher);
        Hash::hash(&event.connector_id, &mut hasher);
        Hash::hash(&event.capability_id, &mut hasher);
        Hash::hash(&event.occurred_at, &mut hasher);

        let bucket = (hasher.finish() % 10_000) as u16;
        bucket < self.config.sample_rate_bps
    }

    fn prune_locked(
        aggregates: &mut HashMap<CapabilityUsageKey, CapabilityUsageAggregate>,
        now: u64,
        retention_secs: u64,
    ) {
        aggregates.retain(|_, aggregate| now.saturating_sub(aggregate.last_seen) <= retention_secs);
    }
}

/// Recommendation output type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySuggestionKind {
    /// Remove capability due to inactivity.
    RemoveUnused,
    /// Review risky capability usage.
    ReviewRisky,
    /// Keep capability as-is.
    Keep,
}

/// Recommendation for a single capability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityRecommendation {
    pub key: CapabilityUsageKey,
    pub suggestion: CapabilitySuggestionKind,
    pub reason_code: String,
    pub usage_total: u64,
    pub last_seen: u64,
    pub risk_tier: SafetyTier,
}

/// Risk summary per zone.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZoneRiskSummary {
    pub zone_id: String,
    pub safe: u64,
    pub risky: u64,
    pub dangerous: u64,
    pub critical: u64,
    pub forbidden: u64,
}

/// Configuration for recommendation generation.
#[derive(Debug, Clone, Copy)]
pub struct RecommendationConfig {
    /// Treat capabilities as unused if `last_seen` exceeds this window.
    pub unused_after_secs: u64,
}

impl Default for RecommendationConfig {
    fn default() -> Self {
        Self {
            unused_after_secs: 30 * 24 * 60 * 60,
        }
    }
}

/// Report produced by the recommendation engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityRecommendationReport {
    pub generated_at: u64,
    pub recommendations: Vec<CapabilityRecommendation>,
    pub risk_summaries: Vec<ZoneRiskSummary>,
}

/// Summary counts for recommendations (CLI-friendly).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityRecommendationSummary {
    pub total: usize,
    pub remove_unused: usize,
    pub review_risky: usize,
    pub keep: usize,
}

impl CapabilityRecommendationReport {
    /// Build a summary of recommendation counts by suggestion.
    #[must_use]
    pub fn summary(&self) -> CapabilityRecommendationSummary {
        let mut summary = CapabilityRecommendationSummary {
            total: self.recommendations.len(),
            remove_unused: 0,
            review_risky: 0,
            keep: 0,
        };
        for recommendation in &self.recommendations {
            match recommendation.suggestion {
                CapabilitySuggestionKind::RemoveUnused => summary.remove_unused += 1,
                CapabilitySuggestionKind::ReviewRisky => summary.review_risky += 1,
                CapabilitySuggestionKind::Keep => summary.keep += 1,
            }
        }
        summary
    }

    /// Return recommendations matching the requested suggestion kind.
    #[must_use]
    pub fn by_suggestion(
        &self,
        suggestion: CapabilitySuggestionKind,
    ) -> Vec<CapabilityRecommendation> {
        self.recommendations
            .iter()
            .filter(|rec| rec.suggestion == suggestion)
            .cloned()
            .collect()
    }

    /// Serialize the report as compact JSON for CLI export.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize the report as pretty JSON for human review.
    ///
    /// # Errors
    /// Returns an error if serialization fails.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Compute deterministic recommendations from usage aggregates.
#[must_use]
pub fn recommend_capabilities(
    aggregates: &[CapabilityUsageAggregate],
    now: u64,
    config: RecommendationConfig,
) -> CapabilityRecommendationReport {
    let mut recommendations: Vec<CapabilityRecommendation> = aggregates
        .iter()
        .map(|aggregate| {
            let unused = now.saturating_sub(aggregate.last_seen) > config.unused_after_secs;
            let suggestion = if unused {
                CapabilitySuggestionKind::RemoveUnused
            } else if matches!(
                aggregate.last_risk_tier,
                SafetyTier::Dangerous | SafetyTier::Critical | SafetyTier::Forbidden
            ) {
                CapabilitySuggestionKind::ReviewRisky
            } else {
                CapabilitySuggestionKind::Keep
            };

            let reason_code = match suggestion {
                CapabilitySuggestionKind::RemoveUnused => "unused_over_window",
                CapabilitySuggestionKind::ReviewRisky => "risky_usage",
                CapabilitySuggestionKind::Keep => "active_usage",
            };

            CapabilityRecommendation {
                key: aggregate.key.clone(),
                suggestion,
                reason_code: reason_code.to_string(),
                usage_total: aggregate.total,
                last_seen: aggregate.last_seen,
                risk_tier: aggregate.last_risk_tier,
            }
        })
        .collect();

    recommendations.sort_by(|a, b| {
        let key_a = (
            a.key.zone_id.as_str(),
            a.key.connector_id.as_str(),
            a.key.capability_id.as_str(),
        );
        let key_b = (
            b.key.zone_id.as_str(),
            b.key.connector_id.as_str(),
            b.key.capability_id.as_str(),
        );
        key_a.cmp(&key_b)
    });

    let mut by_zone: HashMap<&str, ZoneRiskSummary> = HashMap::new();
    for aggregate in aggregates {
        let entry = by_zone
            .entry(aggregate.key.zone_id.as_str())
            .or_insert_with(|| ZoneRiskSummary {
                zone_id: aggregate.key.zone_id.as_str().to_string(),
                safe: 0,
                risky: 0,
                dangerous: 0,
                critical: 0,
                forbidden: 0,
            });
        match aggregate.last_risk_tier {
            SafetyTier::Safe => entry.safe += aggregate.total,
            SafetyTier::Risky => entry.risky += aggregate.total,
            SafetyTier::Dangerous => entry.dangerous += aggregate.total,
            SafetyTier::Critical => entry.critical += aggregate.total,
            SafetyTier::Forbidden => entry.forbidden += aggregate.total,
        }
    }

    let mut risk_summaries: Vec<ZoneRiskSummary> = by_zone.into_values().collect();
    risk_summaries.sort_by(|a, b| a.zone_id.cmp(&b.zone_id));

    CapabilityRecommendationReport {
        generated_at: now,
        recommendations,
        risk_summaries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{CapabilityId, ConnectorId, OperationId, PrincipalId, ZoneId};
    use rand::SeedableRng;
    use rand::seq::SliceRandom;

    fn sample_event(outcome: CapabilityUsageOutcome, ts: u64) -> CapabilityUsageEvent {
        CapabilityUsageEvent::new(
            CapabilityUsageKey::new(
                ZoneId::work(),
                ConnectorId::from_static("fcp.example:request-response:1"),
                CapabilityId::from_static("fcp.example.read"),
            ),
            PrincipalId::new("user:alice").expect("principal id should be canonical"),
            SafetyTier::Risky,
            OperationId::from_static("op.list"),
            outcome,
            ts,
        )
    }

    fn event_for(
        zone: ZoneId,
        connector: ConnectorId,
        capability: CapabilityId,
        tier: SafetyTier,
        outcome: CapabilityUsageOutcome,
        ts: u64,
    ) -> CapabilityUsageEvent {
        CapabilityUsageEvent::new(
            CapabilityUsageKey::new(zone, connector, capability),
            PrincipalId::new("user:alice").expect("principal id should be canonical"),
            tier,
            OperationId::from_static("op.list"),
            outcome,
            ts,
        )
    }

    #[test]
    fn record_updates_aggregate_counts() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        let allow_event = sample_event(CapabilityUsageOutcome::Allow, 10);
        let deny_event = sample_event(CapabilityUsageOutcome::Deny, 11);
        assert!(store.record(&allow_event));
        assert!(store.record(&deny_event));

        let snapshot = store.snapshot();
        assert_eq!(snapshot.len(), 1);
        let aggregate = &snapshot[0];
        assert_eq!(aggregate.total, 2);
        assert_eq!(aggregate.allowed, 1);
        assert_eq!(aggregate.denied, 1);
        assert_eq!(aggregate.errors, 0);
        assert_eq!(aggregate.first_seen, 10);
        assert_eq!(aggregate.last_seen, 11);
    }

    #[test]
    fn sampling_respects_zero_rate() {
        let config = UsageTelemetryConfig {
            sample_rate_bps: 0,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);
        let event = sample_event(CapabilityUsageOutcome::Allow, 10);
        assert!(!store.record(&event));
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn retention_prunes_old_entries() {
        let config = UsageTelemetryConfig {
            retention_secs: 5,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);
        let first = sample_event(CapabilityUsageOutcome::Allow, 10);
        assert!(store.record(&first));

        // Record a later event to trigger prune.
        let second = sample_event(CapabilityUsageOutcome::Allow, 20);
        assert!(store.record(&second));

        let snapshot = store.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].first_seen, 20);
    }

    #[test]
    fn recommendations_flag_unused_and_risky() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.example:request-response:1"),
            CapabilityId::from_static("fcp.example.read"),
        );
        let aggregate = CapabilityUsageAggregate {
            key: key.clone(),
            total: 5,
            allowed: 5,
            denied: 0,
            errors: 0,
            first_seen: 10,
            last_seen: 10,
            last_risk_tier: SafetyTier::Dangerous,
        };

        let report = recommend_capabilities(
            &[aggregate],
            100,
            RecommendationConfig {
                unused_after_secs: 50,
            },
        );

        assert_eq!(report.recommendations.len(), 1);
        assert_eq!(
            report.recommendations[0].suggestion,
            CapabilitySuggestionKind::RemoveUnused
        );
        assert_eq!(report.risk_summaries.len(), 1);
        assert_eq!(report.risk_summaries[0].dangerous, 5);
    }

    #[test]
    fn recommendations_keep_active_safe_caps() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.example:request-response:1"),
            CapabilityId::from_static("fcp.example.write"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
            total: 2,
            allowed: 2,
            denied: 0,
            errors: 0,
            first_seen: 90,
            last_seen: 95,
            last_risk_tier: SafetyTier::Safe,
        };

        let report = recommend_capabilities(
            &[aggregate],
            100,
            RecommendationConfig {
                unused_after_secs: 50,
            },
        );
        assert_eq!(
            report.recommendations[0].suggestion,
            CapabilitySuggestionKind::Keep
        );
    }

    #[test]
    fn recommendations_are_order_independent() {
        let aggregates = vec![
            CapabilityUsageAggregate {
                key: CapabilityUsageKey::new(
                    ZoneId::work(),
                    ConnectorId::from_static("fcp.alpha:request-response:1"),
                    CapabilityId::from_static("fcp.alpha.read"),
                ),
                total: 3,
                allowed: 3,
                denied: 0,
                errors: 0,
                first_seen: 10,
                last_seen: 40,
                last_risk_tier: SafetyTier::Safe,
            },
            CapabilityUsageAggregate {
                key: CapabilityUsageKey::new(
                    ZoneId::work(),
                    ConnectorId::from_static("fcp.beta:request-response:1"),
                    CapabilityId::from_static("fcp.beta.write"),
                ),
                total: 2,
                allowed: 1,
                denied: 1,
                errors: 0,
                first_seen: 15,
                last_seen: 20,
                last_risk_tier: SafetyTier::Risky,
            },
            CapabilityUsageAggregate {
                key: CapabilityUsageKey::new(
                    ZoneId::private(),
                    ConnectorId::from_static("fcp.gamma:request-response:1"),
                    CapabilityId::from_static("fcp.gamma.admin"),
                ),
                total: 1,
                allowed: 0,
                denied: 0,
                errors: 1,
                first_seen: 5,
                last_seen: 5,
                last_risk_tier: SafetyTier::Critical,
            },
        ];

        let config = RecommendationConfig {
            unused_after_secs: 50,
        };
        let now = 100;
        let baseline = recommend_capabilities(&aggregates, now, config);

        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        for _ in 0..8 {
            let mut shuffled = aggregates.clone();
            shuffled.shuffle(&mut rng);
            let report = recommend_capabilities(&shuffled, now, config);
            assert_eq!(report, baseline);
        }
    }

    #[test]
    fn integration_usage_to_recommendations() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());

        let work_read = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.alpha:request-response:1"),
            CapabilityId::from_static("fcp.alpha.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            90,
        );
        let work_write = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.alpha:request-response:1"),
            CapabilityId::from_static("fcp.alpha.write"),
            SafetyTier::Dangerous,
            CapabilityUsageOutcome::Deny,
            30,
        );
        let private_admin = event_for(
            ZoneId::private(),
            ConnectorId::from_static("fcp.beta:request-response:1"),
            CapabilityId::from_static("fcp.beta.admin"),
            SafetyTier::Critical,
            CapabilityUsageOutcome::Error,
            10,
        );

        assert!(store.record(&work_read));
        assert!(store.record(&work_write));
        assert!(store.record(&private_admin));

        let aggregates = store.snapshot();
        assert_eq!(aggregates.len(), 3);

        let report = recommend_capabilities(
            &aggregates,
            100,
            RecommendationConfig {
                unused_after_secs: 50,
            },
        );

        assert_eq!(report.recommendations.len(), 3);
        let work_summary = report
            .risk_summaries
            .iter()
            .find(|summary| summary.zone_id == ZoneId::WORK)
            .expect("work zone summary");
        assert_eq!(work_summary.safe, 1);
        assert_eq!(work_summary.dangerous, 1);

        let private_summary = report
            .risk_summaries
            .iter()
            .find(|summary| summary.zone_id == ZoneId::PRIVATE)
            .expect("private zone summary");
        assert_eq!(private_summary.critical, 1);
    }

    #[test]
    fn report_summary_and_json_export() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.example:request-response:1"),
            CapabilityId::from_static("fcp.example.read"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
            total: 1,
            allowed: 1,
            denied: 0,
            errors: 0,
            first_seen: 10,
            last_seen: 10,
            last_risk_tier: SafetyTier::Safe,
        };

        let report = recommend_capabilities(
            &[aggregate],
            100,
            RecommendationConfig {
                unused_after_secs: 50,
            },
        );
        let summary = report.summary();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.remove_unused, 1);
        assert_eq!(summary.review_risky, 0);
        assert_eq!(summary.keep, 0);

        let json = report.to_json().expect("json export");
        assert!(json.contains("\"recommendations\""));
        let json_pretty = report.to_json_pretty().expect("pretty json export");
        assert!(json_pretty.contains("\n"));
    }
}
