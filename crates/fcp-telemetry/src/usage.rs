//! Capability usage telemetry aggregation.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;

use fcp_prelude::{CapabilityId, ConnectorId, OperationId, PrincipalId, SafetyTier, ZoneId};

/// Capability usage format identifier.
pub const CAPABILITY_USAGE_FORMAT: &str = "fcp-capability-usage";

/// Capability usage schema version.
pub const CAPABILITY_USAGE_SCHEMA_VERSION: &str = "1.0";

fn capability_usage_format() -> String {
    CAPABILITY_USAGE_FORMAT.to_string()
}

fn capability_usage_schema_version() -> String {
    CAPABILITY_USAGE_SCHEMA_VERSION.to_string()
}

/// Usage outcome for a capability invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityUsageOutcome {
    /// Capability invocation was allowed.
    Allow,
    /// Capability invocation was denied.
    Deny,
    /// Capability invocation failed with an error.
    Error,
}

/// Aggregation key for capability usage.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityUsageKey {
    pub zone_id: ZoneId,
    pub connector_id: ConnectorId,
    pub capability_id: CapabilityId,
}

impl CapabilityUsageKey {
    /// Build a new usage key.
    #[must_use]
    pub const fn new(
        zone_id: ZoneId,
        connector_id: ConnectorId,
        capability_id: CapabilityId,
    ) -> Self {
        Self {
            zone_id,
            connector_id,
            capability_id,
        }
    }
}

/// Capability usage event for telemetry aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityUsageEvent {
    /// Format identifier (always "fcp-capability-usage").
    #[serde(default = "capability_usage_format")]
    pub format: String,
    /// Schema version (always "1.0").
    #[serde(default = "capability_usage_schema_version")]
    pub schema_version: String,
    /// Zone where the capability was invoked.
    pub zone_id: ZoneId,
    /// Connector that executed the operation.
    pub connector_id: ConnectorId,
    /// Capability identifier used for the operation.
    pub capability_id: CapabilityId,
    /// Principal who initiated the request.
    pub principal_id: PrincipalId,
    /// Safety tier associated with the operation.
    pub risk_tier: SafetyTier,
    /// Operation identifier (connector-defined).
    pub operation: OperationId,
    /// Outcome for the invocation.
    pub outcome: CapabilityUsageOutcome,
    /// When the usage occurred (Unix timestamp seconds).
    pub occurred_at: u64,
}

impl CapabilityUsageEvent {
    /// Create a new capability usage event.
    #[must_use]
    pub fn new(
        key: CapabilityUsageKey,
        principal_id: PrincipalId,
        risk_tier: SafetyTier,
        operation: OperationId,
        outcome: CapabilityUsageOutcome,
        occurred_at: u64,
    ) -> Self {
        let CapabilityUsageKey {
            zone_id,
            connector_id,
            capability_id,
        } = key;
        Self {
            format: capability_usage_format(),
            schema_version: capability_usage_schema_version(),
            zone_id,
            connector_id,
            capability_id,
            principal_id,
            risk_tier,
            operation,
            outcome,
            occurred_at,
        }
    }

    /// Compute the aggregation key for this event.
    #[must_use]
    pub fn key(&self) -> CapabilityUsageKey {
        CapabilityUsageKey::new(
            self.zone_id.clone(),
            self.connector_id.clone(),
            self.capability_id.clone(),
        )
    }
}

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

        let key = event.key();

        if aggregates.len() >= self.config.max_entries && !aggregates.contains_key(&key) {
            return false;
        }

        if let Some(aggregate) = aggregates.get_mut(&key) {
            aggregate.apply(event);
        } else {
            aggregates.insert(key.clone(), CapabilityUsageAggregate::new(key, event));
        }
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
    use fcp_prelude::{CapabilityId, ConnectorId, OperationId, PrincipalId, ZoneId};
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
    fn record_updates_existing_when_full() {
        let config = UsageTelemetryConfig {
            max_entries: 1,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);

        let first = sample_event(CapabilityUsageOutcome::Allow, 10);
        assert!(store.record(&first));

        // Same key, should update even though map is at max_entries
        let second = sample_event(CapabilityUsageOutcome::Allow, 20);
        assert!(store.record(&second));

        // Different key, should be rejected because map is full
        let different = event_for(
            ZoneId::private(),
            ConnectorId::from_static("fcp.beta:request-response:1"),
            CapabilityId::from_static("fcp.beta.write"),
            SafetyTier::Risky,
            CapabilityUsageOutcome::Allow,
            30,
        );
        assert!(!store.record(&different));

        let snapshot = store.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].total, 2);
    }

    #[test]
    fn recommendations_flag_unused_and_risky() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.example:request-response:1"),
            CapabilityId::from_static("fcp.example.read"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
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
        assert!(json_pretty.contains('\n'));
    }

    #[test]
    fn config_default_values() {
        let config = UsageTelemetryConfig::default();
        assert_eq!(config.retention_secs, 7 * 24 * 60 * 60);
        assert_eq!(config.sample_rate_bps, 10_000);
        assert_eq!(config.max_entries, 10_000);
    }

    #[test]
    fn recommendation_config_default() {
        let config = RecommendationConfig::default();
        assert_eq!(config.unused_after_secs, 30 * 24 * 60 * 60);
    }

    #[test]
    fn empty_aggregates_produces_empty_report() {
        let report = recommend_capabilities(&[], 100, RecommendationConfig::default());
        assert!(report.recommendations.is_empty());
        assert!(report.risk_summaries.is_empty());
        assert_eq!(report.generated_at, 100);
    }

    #[test]
    fn by_suggestion_filter() {
        let aggregates = vec![
            CapabilityUsageAggregate {
                key: CapabilityUsageKey::new(
                    ZoneId::work(),
                    ConnectorId::from_static("fcp.a:request-response:1"),
                    CapabilityId::from_static("fcp.a.read"),
                ),
                total: 1,
                allowed: 1,
                denied: 0,
                errors: 0,
                first_seen: 90,
                last_seen: 95,
                last_risk_tier: SafetyTier::Safe,
            },
            CapabilityUsageAggregate {
                key: CapabilityUsageKey::new(
                    ZoneId::work(),
                    ConnectorId::from_static("fcp.b:request-response:1"),
                    CapabilityId::from_static("fcp.b.write"),
                ),
                total: 1,
                allowed: 0,
                denied: 1,
                errors: 0,
                first_seen: 5,
                last_seen: 5,
                last_risk_tier: SafetyTier::Dangerous,
            },
        ];

        let report = recommend_capabilities(
            &aggregates,
            100,
            RecommendationConfig {
                unused_after_secs: 50,
            },
        );

        let kept = report.by_suggestion(CapabilitySuggestionKind::Keep);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].key.capability_id.as_str(), "fcp.a.read");

        let removed = report.by_suggestion(CapabilitySuggestionKind::RemoveUnused);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].key.capability_id.as_str(), "fcp.b.write");
    }

    #[test]
    fn review_risky_active_dangerous_cap() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.d:request-response:1"),
            CapabilityId::from_static("fcp.d.delete"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
            total: 10,
            allowed: 8,
            denied: 2,
            errors: 0,
            first_seen: 90,
            last_seen: 99,
            last_risk_tier: SafetyTier::Critical,
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
            CapabilitySuggestionKind::ReviewRisky
        );
        assert_eq!(report.recommendations[0].reason_code, "risky_usage");
    }

    #[test]
    fn suggestion_kind_serde_roundtrip() {
        let kinds = [
            CapabilitySuggestionKind::RemoveUnused,
            CapabilitySuggestionKind::ReviewRisky,
            CapabilitySuggestionKind::Keep,
        ];
        for kind in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            let decoded: CapabilitySuggestionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(decoded, kind);
        }
    }

    #[test]
    fn suggestion_kind_snake_case_serialization() {
        let json = serde_json::to_string(&CapabilitySuggestionKind::RemoveUnused).unwrap();
        assert_eq!(json, "\"remove_unused\"");
        let json = serde_json::to_string(&CapabilitySuggestionKind::ReviewRisky).unwrap();
        assert_eq!(json, "\"review_risky\"");
        let json = serde_json::to_string(&CapabilitySuggestionKind::Keep).unwrap();
        assert_eq!(json, "\"keep\"");
    }

    #[test]
    fn report_serde_roundtrip() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.x:request-response:1"),
            CapabilityId::from_static("fcp.x.read"),
        );
        let report = CapabilityRecommendationReport {
            generated_at: 42,
            recommendations: vec![CapabilityRecommendation {
                key,
                suggestion: CapabilitySuggestionKind::Keep,
                reason_code: "active_usage".to_string(),
                usage_total: 5,
                last_seen: 40,
                risk_tier: SafetyTier::Safe,
            }],
            risk_summaries: vec![ZoneRiskSummary {
                zone_id: "z:work".to_string(),
                safe: 5,
                risky: 0,
                dangerous: 0,
                critical: 0,
                forbidden: 0,
            }],
        };

        let json = report.to_json().unwrap();
        let decoded: CapabilityRecommendationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, report);
    }

    #[test]
    fn aggregate_error_counting() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        let event = sample_event(CapabilityUsageOutcome::Error, 10);
        store.record(&event);
        store.record(&sample_event(CapabilityUsageOutcome::Error, 11));

        let snapshot = store.snapshot();
        assert_eq!(snapshot[0].errors, 2);
        assert_eq!(snapshot[0].allowed, 0);
        assert_eq!(snapshot[0].denied, 0);
    }

    #[test]
    fn multiple_zones_risk_summary() {
        let work_agg = CapabilityUsageAggregate {
            key: CapabilityUsageKey::new(
                ZoneId::work(),
                ConnectorId::from_static("fcp.a:request-response:1"),
                CapabilityId::from_static("fcp.a.read"),
            ),
            total: 3,
            allowed: 3,
            denied: 0,
            errors: 0,
            first_seen: 90,
            last_seen: 95,
            last_risk_tier: SafetyTier::Safe,
        };
        let priv_agg = CapabilityUsageAggregate {
            key: CapabilityUsageKey::new(
                ZoneId::private(),
                ConnectorId::from_static("fcp.b:request-response:1"),
                CapabilityId::from_static("fcp.b.admin"),
            ),
            total: 2,
            allowed: 1,
            denied: 0,
            errors: 1,
            first_seen: 80,
            last_seen: 85,
            last_risk_tier: SafetyTier::Forbidden,
        };

        let report = recommend_capabilities(
            &[work_agg, priv_agg],
            100,
            RecommendationConfig {
                unused_after_secs: 50,
            },
        );

        assert_eq!(report.risk_summaries.len(), 2);
        let work_zone = report
            .risk_summaries
            .iter()
            .find(|s| s.zone_id == ZoneId::WORK)
            .unwrap();
        assert_eq!(work_zone.safe, 3);
        let priv_zone = report
            .risk_summaries
            .iter()
            .find(|s| s.zone_id == ZoneId::PRIVATE)
            .unwrap();
        assert_eq!(priv_zone.forbidden, 2);
    }

    #[test]
    fn snapshot_deterministic_order() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());

        let e1 = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.zzz:request-response:1"),
            CapabilityId::from_static("fcp.zzz.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            10,
        );
        let e2 = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.aaa:request-response:1"),
            CapabilityId::from_static("fcp.aaa.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            10,
        );
        store.record(&e1);
        store.record(&e2);

        let snap = store.snapshot();
        assert_eq!(snap.len(), 2);
        // Should be sorted: aaa before zzz
        assert!(snap[0].key.connector_id.as_str() < snap[1].key.connector_id.as_str());
    }

    #[test]
    fn summary_counts_correct() {
        let report = CapabilityRecommendationReport {
            generated_at: 100,
            recommendations: vec![
                CapabilityRecommendation {
                    key: CapabilityUsageKey::new(
                        ZoneId::work(),
                        ConnectorId::from_static("fcp.a:request-response:1"),
                        CapabilityId::from_static("fcp.a.read"),
                    ),
                    suggestion: CapabilitySuggestionKind::Keep,
                    reason_code: "active_usage".into(),
                    usage_total: 5,
                    last_seen: 90,
                    risk_tier: SafetyTier::Safe,
                },
                CapabilityRecommendation {
                    key: CapabilityUsageKey::new(
                        ZoneId::work(),
                        ConnectorId::from_static("fcp.b:request-response:1"),
                        CapabilityId::from_static("fcp.b.write"),
                    ),
                    suggestion: CapabilitySuggestionKind::RemoveUnused,
                    reason_code: "unused_over_window".into(),
                    usage_total: 1,
                    last_seen: 10,
                    risk_tier: SafetyTier::Risky,
                },
                CapabilityRecommendation {
                    key: CapabilityUsageKey::new(
                        ZoneId::work(),
                        ConnectorId::from_static("fcp.c:request-response:1"),
                        CapabilityId::from_static("fcp.c.delete"),
                    ),
                    suggestion: CapabilitySuggestionKind::ReviewRisky,
                    reason_code: "risky_usage".into(),
                    usage_total: 3,
                    last_seen: 95,
                    risk_tier: SafetyTier::Critical,
                },
            ],
            risk_summaries: vec![],
        };

        let summary = report.summary();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.keep, 1);
        assert_eq!(summary.remove_unused, 1);
        assert_eq!(summary.review_risky, 1);
    }

    // ── Additional edge case tests ──

    #[test]
    fn sampling_full_rate_always_records() {
        let config = UsageTelemetryConfig {
            sample_rate_bps: 10_000,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);
        for ts in 0..20 {
            let event = sample_event(CapabilityUsageOutcome::Allow, ts);
            assert!(store.record(&event));
        }
        let snap = store.snapshot();
        assert_eq!(snap[0].total, 20);
    }

    #[test]
    fn aggregate_first_seen_tracks_minimum() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        // Record events out of order — first_seen should track the minimum
        store.record(&sample_event(CapabilityUsageOutcome::Allow, 50));
        store.record(&sample_event(CapabilityUsageOutcome::Allow, 20));
        store.record(&sample_event(CapabilityUsageOutcome::Allow, 80));

        let snap = store.snapshot();
        assert_eq!(snap[0].first_seen, 20);
        assert_eq!(snap[0].last_seen, 80);
    }

    #[test]
    fn aggregate_last_seen_tracks_maximum() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        store.record(&sample_event(CapabilityUsageOutcome::Allow, 100));
        store.record(&sample_event(CapabilityUsageOutcome::Allow, 50));

        let snap = store.snapshot();
        assert_eq!(snap[0].last_seen, 100);
    }

    #[test]
    fn aggregate_mixed_outcomes() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        store.record(&sample_event(CapabilityUsageOutcome::Allow, 10));
        store.record(&sample_event(CapabilityUsageOutcome::Deny, 11));
        store.record(&sample_event(CapabilityUsageOutcome::Error, 12));
        store.record(&sample_event(CapabilityUsageOutcome::Allow, 13));
        store.record(&sample_event(CapabilityUsageOutcome::Deny, 14));

        let snap = store.snapshot();
        assert_eq!(snap[0].total, 5);
        assert_eq!(snap[0].allowed, 2);
        assert_eq!(snap[0].denied, 2);
        assert_eq!(snap[0].errors, 1);
    }

    #[test]
    fn recommendation_forbidden_tier_flagged_risky() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.x:request-response:1"),
            CapabilityId::from_static("fcp.x.admin"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
            total: 1,
            allowed: 1,
            denied: 0,
            errors: 0,
            first_seen: 95,
            last_seen: 99,
            last_risk_tier: SafetyTier::Forbidden,
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
            CapabilitySuggestionKind::ReviewRisky
        );
    }

    #[test]
    fn recommendation_risky_tier_not_flagged() {
        // Risky tier (not Dangerous/Critical/Forbidden) should be Keep, not ReviewRisky
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.y:request-response:1"),
            CapabilityId::from_static("fcp.y.read"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
            total: 3,
            allowed: 3,
            denied: 0,
            errors: 0,
            first_seen: 90,
            last_seen: 99,
            last_risk_tier: SafetyTier::Risky,
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
    fn zone_risk_summary_all_tiers() {
        let tiers = [
            (SafetyTier::Safe, "fcp.s:request-response:1", "fcp.s.read"),
            (SafetyTier::Risky, "fcp.r:request-response:1", "fcp.r.read"),
            (
                SafetyTier::Dangerous,
                "fcp.d:request-response:1",
                "fcp.d.read",
            ),
            (
                SafetyTier::Critical,
                "fcp.c:request-response:1",
                "fcp.c.read",
            ),
            (
                SafetyTier::Forbidden,
                "fcp.f:request-response:1",
                "fcp.f.read",
            ),
        ];

        let aggregates: Vec<CapabilityUsageAggregate> = tiers
            .iter()
            .map(|(tier, conn, cap)| CapabilityUsageAggregate {
                key: CapabilityUsageKey::new(
                    ZoneId::work(),
                    ConnectorId::from_static(conn),
                    CapabilityId::from_static(cap),
                ),
                total: 1,
                allowed: 1,
                denied: 0,
                errors: 0,
                first_seen: 90,
                last_seen: 99,
                last_risk_tier: *tier,
            })
            .collect();

        let report = recommend_capabilities(
            &aggregates,
            100,
            RecommendationConfig {
                unused_after_secs: 50,
            },
        );

        assert_eq!(report.risk_summaries.len(), 1);
        let summary = &report.risk_summaries[0];
        assert_eq!(summary.safe, 1);
        assert_eq!(summary.risky, 1);
        assert_eq!(summary.dangerous, 1);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.forbidden, 1);
    }

    #[test]
    fn retention_does_not_prune_fresh_entries() {
        let config = UsageTelemetryConfig {
            retention_secs: 100,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);
        store.record(&sample_event(CapabilityUsageOutcome::Allow, 50));
        // Record at t=60 — first event at t=50 is within 100s retention
        store.record(&sample_event(CapabilityUsageOutcome::Allow, 60));
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].total, 2);
    }

    #[test]
    fn by_suggestion_empty_report() {
        let report = recommend_capabilities(&[], 100, RecommendationConfig::default());
        assert!(
            report
                .by_suggestion(CapabilitySuggestionKind::Keep)
                .is_empty()
        );
        assert!(
            report
                .by_suggestion(CapabilitySuggestionKind::RemoveUnused)
                .is_empty()
        );
        assert!(
            report
                .by_suggestion(CapabilitySuggestionKind::ReviewRisky)
                .is_empty()
        );
    }

    #[test]
    fn empty_report_summary() {
        let report = recommend_capabilities(&[], 100, RecommendationConfig::default());
        let summary = report.summary();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.keep, 0);
        assert_eq!(summary.remove_unused, 0);
        assert_eq!(summary.review_risky, 0);
    }

    #[test]
    fn zone_risk_summary_serde_roundtrip() {
        let summary = ZoneRiskSummary {
            zone_id: "z:work".to_string(),
            safe: 10,
            risky: 5,
            dangerous: 2,
            critical: 1,
            forbidden: 0,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let decoded: ZoneRiskSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, summary);
    }

    #[test]
    fn recommendation_summary_serde_roundtrip() {
        let summary = CapabilityRecommendationSummary {
            total: 10,
            remove_unused: 3,
            review_risky: 2,
            keep: 5,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let decoded: CapabilityRecommendationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, summary);
    }

    #[test]
    fn config_debug_and_clone() {
        let config = UsageTelemetryConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("UsageTelemetryConfig"));
        let cloned = config;
        assert_eq!(cloned.retention_secs, config.retention_secs);
    }

    #[test]
    fn recommendation_config_debug_and_clone() {
        let config = RecommendationConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("RecommendationConfig"));
        let cloned = config;
        assert_eq!(cloned.unused_after_secs, config.unused_after_secs);
    }

    // ── Usage tracking / metering ──

    #[test]
    fn record_single_allow_and_verify_totals() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        let event = sample_event(CapabilityUsageOutcome::Allow, 100);
        assert!(store.record(&event));

        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].total, 1);
        assert_eq!(snap[0].allowed, 1);
        assert_eq!(snap[0].denied, 0);
        assert_eq!(snap[0].errors, 0);
    }

    #[test]
    fn record_multiple_deny_events_accumulates() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        for ts in 0..10 {
            store.record(&sample_event(CapabilityUsageOutcome::Deny, ts));
        }
        let snap = store.snapshot();
        assert_eq!(snap[0].total, 10);
        assert_eq!(snap[0].denied, 10);
        assert_eq!(snap[0].allowed, 0);
    }

    #[test]
    fn multiple_operation_types_tracked_separately() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());

        let e1 = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.alpha:request-response:1"),
            CapabilityId::from_static("fcp.alpha.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            10,
        );
        let e2 = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.alpha:request-response:1"),
            CapabilityId::from_static("fcp.alpha.write"),
            SafetyTier::Risky,
            CapabilityUsageOutcome::Allow,
            11,
        );
        let e3 = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.beta:request-response:1"),
            CapabilityId::from_static("fcp.beta.delete"),
            SafetyTier::Dangerous,
            CapabilityUsageOutcome::Deny,
            12,
        );

        store.record(&e1);
        store.record(&e2);
        store.record(&e3);

        let snap = store.snapshot();
        assert_eq!(snap.len(), 3);
    }

    #[test]
    fn concurrent_usage_recording_from_multiple_threads() {
        use std::sync::Arc;

        let store = Arc::new(CapabilityUsageStore::new(UsageTelemetryConfig::default()));
        let mut handles = Vec::new();

        for thread_id in 0..4u64 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                for i in 0..25u64 {
                    let ts = thread_id * 1000 + i;
                    let event = sample_event(CapabilityUsageOutcome::Allow, ts);
                    store.record(&event);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].total, 100);
    }

    #[test]
    fn concurrent_recording_different_keys() {
        use std::sync::Arc;

        let store = Arc::new(CapabilityUsageStore::new(UsageTelemetryConfig::default()));
        let mut handles = Vec::new();

        for thread_id in 0..4u64 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let connector = ConnectorId::from_static(match thread_id {
                    0 => "fcp.t0:request-response:1",
                    1 => "fcp.t1:request-response:1",
                    2 => "fcp.t2:request-response:1",
                    _ => "fcp.t3:request-response:1",
                });
                for i in 0..10u64 {
                    let event = event_for(
                        ZoneId::work(),
                        connector.clone(),
                        CapabilityId::from_static("fcp.t.read"),
                        SafetyTier::Safe,
                        CapabilityUsageOutcome::Allow,
                        thread_id * 100 + i,
                    );
                    store.record(&event);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread should not panic");
        }

        let snap = store.snapshot();
        assert_eq!(snap.len(), 4);
        for agg in &snap {
            assert_eq!(agg.total, 10);
        }
    }

    #[test]
    fn empty_store_snapshot_is_empty() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        let snap = store.snapshot();
        assert!(snap.is_empty());
    }

    #[test]
    fn retention_clears_all_stale_entries() {
        let config = UsageTelemetryConfig {
            retention_secs: 10,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);

        // Record events from two different keys at early timestamps
        let e1 = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.a:request-response:1"),
            CapabilityId::from_static("fcp.a.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            5,
        );
        let e2 = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.b:request-response:1"),
            CapabilityId::from_static("fcp.b.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            8,
        );
        store.record(&e1);
        store.record(&e2);
        assert_eq!(store.snapshot().len(), 2);

        // Record a new-key event at a much later timestamp to trigger pruning
        let e3 = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.c:request-response:1"),
            CapabilityId::from_static("fcp.c.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            100,
        );
        store.record(&e3);

        // Old entries should be pruned, only the new one remains
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[0].key.connector_id.as_str(),
            "fcp.c:request-response:1"
        );
    }

    // ── Aggregation ──

    #[test]
    fn aggregate_by_zone_produces_separate_entries() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());

        let e_work = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.x:request-response:1"),
            CapabilityId::from_static("fcp.x.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            10,
        );
        let e_private = event_for(
            ZoneId::private(),
            ConnectorId::from_static("fcp.x:request-response:1"),
            CapabilityId::from_static("fcp.x.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            10,
        );

        store.record(&e_work);
        store.record(&e_private);

        let snap = store.snapshot();
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn aggregate_by_connector_produces_separate_entries() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());

        for conn in &[
            "fcp.alpha:request-response:1",
            "fcp.beta:request-response:1",
            "fcp.gamma:request-response:1",
        ] {
            let event = event_for(
                ZoneId::work(),
                ConnectorId::from_static(conn),
                CapabilityId::from_static("fcp.shared.read"),
                SafetyTier::Safe,
                CapabilityUsageOutcome::Allow,
                10,
            );
            store.record(&event);
        }

        assert_eq!(store.snapshot().len(), 3);
    }

    #[test]
    fn aggregate_by_capability_produces_separate_entries() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());

        for cap in &["fcp.x.read", "fcp.x.write", "fcp.x.delete"] {
            let event = event_for(
                ZoneId::work(),
                ConnectorId::from_static("fcp.x:request-response:1"),
                CapabilityId::from_static(cap),
                SafetyTier::Safe,
                CapabilityUsageOutcome::Allow,
                10,
            );
            store.record(&event);
        }

        assert_eq!(store.snapshot().len(), 3);
    }

    #[test]
    fn time_window_aggregation_keeps_recent_entries() {
        let config = UsageTelemetryConfig {
            retention_secs: 50,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);

        // Old event
        let old = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.old:request-response:1"),
            CapabilityId::from_static("fcp.old.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            10,
        );
        // Recent event
        let recent = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.new:request-response:1"),
            CapabilityId::from_static("fcp.new.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            90,
        );

        store.record(&old);
        store.record(&recent);

        // Record a trigger event at t=100 to prune
        let trigger = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.trigger:request-response:1"),
            CapabilityId::from_static("fcp.trigger.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            100,
        );
        store.record(&trigger);

        let snap = store.snapshot();
        // Old (last_seen=10) should be pruned (100-10=90 > 50)
        // Recent (last_seen=90) stays (100-90=10 <= 50)
        // Trigger (last_seen=100) stays
        assert_eq!(snap.len(), 2);
        let connectors: Vec<&str> = snap.iter().map(|a| a.key.connector_id.as_str()).collect();
        assert!(!connectors.contains(&"fcp.old:request-response:1"));
        assert!(connectors.contains(&"fcp.new:request-response:1"));
        assert!(connectors.contains(&"fcp.trigger:request-response:1"));
    }

    #[test]
    fn empty_aggregation_produces_empty_recommendations() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        let snap = store.snapshot();
        let report = recommend_capabilities(&snap, 100, RecommendationConfig::default());
        assert!(report.recommendations.is_empty());
        assert!(report.risk_summaries.is_empty());
    }

    // ── Quotas / Limits ──

    #[test]
    fn max_entries_enforces_quota() {
        let config = UsageTelemetryConfig {
            max_entries: 3,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);

        let connectors = [
            "fcp.a:request-response:1",
            "fcp.b:request-response:1",
            "fcp.c:request-response:1",
            "fcp.d:request-response:1",
            "fcp.e:request-response:1",
        ];

        for (i, conn) in connectors.iter().enumerate() {
            let event = event_for(
                ZoneId::work(),
                ConnectorId::from_static(conn),
                CapabilityId::from_static("fcp.x.read"),
                SafetyTier::Safe,
                CapabilityUsageOutcome::Allow,
                i as u64,
            );
            store.record(&event);
        }

        // Only the first 3 distinct keys should be stored
        assert_eq!(store.snapshot().len(), 3);
    }

    #[test]
    fn quota_exceeded_returns_false_for_new_keys() {
        let config = UsageTelemetryConfig {
            max_entries: 1,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);

        let first = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.first:request-response:1"),
            CapabilityId::from_static("fcp.first.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            10,
        );
        assert!(store.record(&first));

        let second = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.second:request-response:1"),
            CapabilityId::from_static("fcp.second.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            20,
        );
        assert!(!store.record(&second));
    }

    #[test]
    fn quota_allows_updates_to_existing_key_when_full() {
        let config = UsageTelemetryConfig {
            max_entries: 1,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);

        let event = sample_event(CapabilityUsageOutcome::Allow, 10);
        assert!(store.record(&event));

        // Same key should still be accepted even at capacity
        for ts in 11..20 {
            assert!(store.record(&sample_event(CapabilityUsageOutcome::Deny, ts)));
        }

        let snap = store.snapshot();
        assert_eq!(snap[0].total, 10);
        assert_eq!(snap[0].allowed, 1);
        assert_eq!(snap[0].denied, 9);
    }

    #[test]
    fn quota_frees_space_after_retention_prune() {
        let config = UsageTelemetryConfig {
            max_entries: 1,
            retention_secs: 10,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);

        // Fill the single slot
        let first = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.old:request-response:1"),
            CapabilityId::from_static("fcp.old.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            5,
        );
        assert!(store.record(&first));

        // New key at a much later time — old entry should be pruned first
        let second = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.new:request-response:1"),
            CapabilityId::from_static("fcp.new.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            100,
        );
        assert!(store.record(&second));

        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(
            snap[0].key.connector_id.as_str(),
            "fcp.new:request-response:1"
        );
    }

    #[test]
    fn config_custom_values_are_respected() {
        let config = UsageTelemetryConfig {
            retention_secs: 42,
            sample_rate_bps: 5000,
            max_entries: 7,
        };
        let store = CapabilityUsageStore::new(config);
        // Verify the config is used — store is created without panic
        let snap = store.snapshot();
        assert!(snap.is_empty());
    }

    // ── Serde roundtrips ──

    #[test]
    fn capability_usage_aggregate_serde_roundtrip() {
        let aggregate = CapabilityUsageAggregate {
            key: CapabilityUsageKey::new(
                ZoneId::work(),
                ConnectorId::from_static("fcp.serde:request-response:1"),
                CapabilityId::from_static("fcp.serde.read"),
            ),
            total: 42,
            allowed: 30,
            denied: 10,
            errors: 2,
            first_seen: 100,
            last_seen: 999,
            last_risk_tier: SafetyTier::Dangerous,
        };

        let json = serde_json::to_string(&aggregate).unwrap();
        let decoded: CapabilityUsageAggregate = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.total, aggregate.total);
        assert_eq!(decoded.allowed, aggregate.allowed);
        assert_eq!(decoded.denied, aggregate.denied);
        assert_eq!(decoded.errors, aggregate.errors);
        assert_eq!(decoded.first_seen, aggregate.first_seen);
        assert_eq!(decoded.last_seen, aggregate.last_seen);
        assert_eq!(decoded.last_risk_tier, aggregate.last_risk_tier);
        assert_eq!(decoded.key, aggregate.key);
    }

    #[test]
    fn capability_recommendation_serde_roundtrip() {
        let rec = CapabilityRecommendation {
            key: CapabilityUsageKey::new(
                ZoneId::private(),
                ConnectorId::from_static("fcp.rec:request-response:1"),
                CapabilityId::from_static("fcp.rec.write"),
            ),
            suggestion: CapabilitySuggestionKind::ReviewRisky,
            reason_code: "risky_usage".to_string(),
            usage_total: 15,
            last_seen: 500,
            risk_tier: SafetyTier::Critical,
        };

        let json = serde_json::to_string(&rec).unwrap();
        let decoded: CapabilityRecommendation = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, rec);
    }

    #[test]
    fn report_json_pretty_contains_all_fields() {
        let report = CapabilityRecommendationReport {
            generated_at: 1000,
            recommendations: vec![CapabilityRecommendation {
                key: CapabilityUsageKey::new(
                    ZoneId::work(),
                    ConnectorId::from_static("fcp.p:request-response:1"),
                    CapabilityId::from_static("fcp.p.read"),
                ),
                suggestion: CapabilitySuggestionKind::Keep,
                reason_code: "active_usage".to_string(),
                usage_total: 7,
                last_seen: 990,
                risk_tier: SafetyTier::Safe,
            }],
            risk_summaries: vec![ZoneRiskSummary {
                zone_id: "z:work".to_string(),
                safe: 7,
                risky: 0,
                dangerous: 0,
                critical: 0,
                forbidden: 0,
            }],
        };

        let pretty = report.to_json_pretty().unwrap();
        assert!(pretty.contains("generated_at"));
        assert!(pretty.contains("recommendations"));
        assert!(pretty.contains("risk_summaries"));
        assert!(pretty.contains("active_usage"));
        assert!(pretty.contains('\n'));
    }

    #[test]
    fn aggregate_clone_preserves_all_fields() {
        let aggregate = CapabilityUsageAggregate {
            key: CapabilityUsageKey::new(
                ZoneId::work(),
                ConnectorId::from_static("fcp.cl:request-response:1"),
                CapabilityId::from_static("fcp.cl.read"),
            ),
            total: 5,
            allowed: 3,
            denied: 1,
            errors: 1,
            first_seen: 10,
            last_seen: 50,
            last_risk_tier: SafetyTier::Risky,
        };

        let cloned = aggregate.clone();
        assert_eq!(cloned.total, aggregate.total);
        assert_eq!(cloned.allowed, aggregate.allowed);
        assert_eq!(cloned.denied, aggregate.denied);
        assert_eq!(cloned.errors, aggregate.errors);
        assert_eq!(cloned.first_seen, aggregate.first_seen);
        assert_eq!(cloned.last_seen, aggregate.last_seen);
        assert_eq!(cloned.last_risk_tier, aggregate.last_risk_tier);
        assert_eq!(cloned.key, aggregate.key);
    }

    #[test]
    fn recommendation_clone_preserves_equality() {
        let rec = CapabilityRecommendation {
            key: CapabilityUsageKey::new(
                ZoneId::work(),
                ConnectorId::from_static("fcp.rc:request-response:1"),
                CapabilityId::from_static("fcp.rc.write"),
            ),
            suggestion: CapabilitySuggestionKind::RemoveUnused,
            reason_code: "unused_over_window".to_string(),
            usage_total: 1,
            last_seen: 10,
            risk_tier: SafetyTier::Risky,
        };

        let cloned = rec.clone();
        assert_eq!(cloned, rec);
    }

    #[test]
    fn zone_risk_summary_clone_preserves_equality() {
        let summary = ZoneRiskSummary {
            zone_id: "z:work".to_string(),
            safe: 10,
            risky: 5,
            dangerous: 3,
            critical: 1,
            forbidden: 0,
        };

        let cloned = summary.clone();
        assert_eq!(cloned, summary);
    }

    #[test]
    fn report_clone_preserves_equality() {
        let report = CapabilityRecommendationReport {
            generated_at: 999,
            recommendations: vec![],
            risk_summaries: vec![],
        };

        let cloned = report.clone();
        assert_eq!(cloned, report);
    }

    #[test]
    fn suggestion_kind_debug_format() {
        let debug_remove = format!("{:?}", CapabilitySuggestionKind::RemoveUnused);
        assert_eq!(debug_remove, "RemoveUnused");
        let debug_review = format!("{:?}", CapabilitySuggestionKind::ReviewRisky);
        assert_eq!(debug_review, "ReviewRisky");
        let debug_keep = format!("{:?}", CapabilitySuggestionKind::Keep);
        assert_eq!(debug_keep, "Keep");
    }

    #[test]
    fn suggestion_kind_copy_semantics() {
        let a = CapabilitySuggestionKind::Keep;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn store_debug_format() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        let debug = format!("{store:?}");
        assert!(debug.contains("CapabilityUsageStore"));
    }

    #[test]
    fn risk_tier_updates_on_later_event() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());

        // First event with Safe tier
        let e1 = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.tier:request-response:1"),
            CapabilityId::from_static("fcp.tier.read"),
            SafetyTier::Safe,
            CapabilityUsageOutcome::Allow,
            10,
        );
        store.record(&e1);
        assert_eq!(store.snapshot()[0].last_risk_tier, SafetyTier::Safe);

        // Second event with Dangerous tier — should update last_risk_tier
        let e2 = event_for(
            ZoneId::work(),
            ConnectorId::from_static("fcp.tier:request-response:1"),
            CapabilityId::from_static("fcp.tier.read"),
            SafetyTier::Dangerous,
            CapabilityUsageOutcome::Allow,
            20,
        );
        store.record(&e2);
        assert_eq!(store.snapshot()[0].last_risk_tier, SafetyTier::Dangerous);
    }

    #[test]
    fn partial_sampling_records_subset() {
        // With a 50% sample rate, some events should be sampled and some not.
        let config = UsageTelemetryConfig {
            sample_rate_bps: 5000,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);

        let mut recorded = 0u64;
        // Use many different timestamps to get varied hash buckets
        for ts in 0..200u64 {
            let event = event_for(
                ZoneId::work(),
                ConnectorId::from_static("fcp.sample:request-response:1"),
                CapabilityId::from_static("fcp.sample.read"),
                SafetyTier::Safe,
                CapabilityUsageOutcome::Allow,
                ts,
            );
            if store.record(&event) {
                recorded += 1;
            }
        }

        // At 50% rate, we expect roughly 100, but just verify it's partial
        assert!(recorded > 0, "some events should be sampled");
        assert!(recorded < 200, "not all events should be sampled at 50%");
    }

    #[test]
    fn recommendation_report_generated_at_matches_now() {
        let report = recommend_capabilities(&[], 42_000, RecommendationConfig::default());
        assert_eq!(report.generated_at, 42_000);
    }

    #[test]
    fn snapshot_sorted_across_zones_connectors_capabilities() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());

        // Insert in reverse order to verify sorting
        let events = [
            (
                ZoneId::work(),
                "fcp.zzz:request-response:1",
                "fcp.zzz.write",
            ),
            (ZoneId::work(), "fcp.aaa:request-response:1", "fcp.aaa.read"),
            (
                ZoneId::private(),
                "fcp.m:request-response:1",
                "fcp.m.delete",
            ),
        ];

        for (zone, conn, cap) in &events {
            let event = event_for(
                zone.clone(),
                ConnectorId::from_static(conn),
                CapabilityId::from_static(cap),
                SafetyTier::Safe,
                CapabilityUsageOutcome::Allow,
                10,
            );
            store.record(&event);
        }

        let snap = store.snapshot();
        assert_eq!(snap.len(), 3);

        // Verify sorted order: zone first, then connector, then capability
        for i in 0..snap.len() - 1 {
            let key_a = (
                snap[i].key.zone_id.as_str(),
                snap[i].key.connector_id.as_str(),
                snap[i].key.capability_id.as_str(),
            );
            let key_b = (
                snap[i + 1].key.zone_id.as_str(),
                snap[i + 1].key.connector_id.as_str(),
                snap[i + 1].key.capability_id.as_str(),
            );
            assert!(
                key_a <= key_b,
                "snapshot should be sorted: {key_a:?} <= {key_b:?}"
            );
        }
    }

    // ============ UsageTelemetryConfig tests ============

    #[test]
    fn test_usage_config_default_values() {
        let config = UsageTelemetryConfig::default();
        assert_eq!(config.retention_secs, 7 * 24 * 60 * 60);
        assert_eq!(config.sample_rate_bps, 10_000);
        assert_eq!(config.max_entries, 10_000);
    }

    #[test]
    fn test_usage_config_debug() {
        let config = UsageTelemetryConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("UsageTelemetryConfig"));
        assert!(debug.contains("retention_secs"));
    }

    #[test]
    fn test_usage_config_clone() {
        let config = UsageTelemetryConfig {
            retention_secs: 3600,
            sample_rate_bps: 5000,
            max_entries: 100,
        };
        let cloned = config;
        assert_eq!(config.retention_secs, cloned.retention_secs);
        assert_eq!(config.sample_rate_bps, cloned.sample_rate_bps);
        assert_eq!(config.max_entries, cloned.max_entries);
    }

    #[test]
    fn test_usage_config_copy() {
        let config = UsageTelemetryConfig::default();
        let copied = config;
        assert_eq!(config.retention_secs, copied.retention_secs);
    }

    // ============ CapabilitySuggestionKind tests ============

    #[test]
    fn test_suggestion_kind_debug() {
        assert!(format!("{:?}", CapabilitySuggestionKind::RemoveUnused).contains("RemoveUnused"));
        assert!(format!("{:?}", CapabilitySuggestionKind::ReviewRisky).contains("ReviewRisky"));
        assert!(format!("{:?}", CapabilitySuggestionKind::Keep).contains("Keep"));
    }

    #[test]
    fn test_suggestion_kind_eq() {
        assert_eq!(
            CapabilitySuggestionKind::Keep,
            CapabilitySuggestionKind::Keep
        );
        assert_ne!(
            CapabilitySuggestionKind::Keep,
            CapabilitySuggestionKind::RemoveUnused
        );
    }

    #[test]
    fn test_suggestion_kind_serde_roundtrip() {
        let kinds = [
            CapabilitySuggestionKind::RemoveUnused,
            CapabilitySuggestionKind::ReviewRisky,
            CapabilitySuggestionKind::Keep,
        ];
        for kind in &kinds {
            let json = serde_json::to_string(kind).unwrap();
            let parsed: CapabilitySuggestionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, parsed);
        }
    }

    #[test]
    fn test_suggestion_kind_serde_values() {
        let json = serde_json::to_string(&CapabilitySuggestionKind::RemoveUnused).unwrap();
        assert_eq!(json, "\"remove_unused\"");
        let json = serde_json::to_string(&CapabilitySuggestionKind::ReviewRisky).unwrap();
        assert_eq!(json, "\"review_risky\"");
        let json = serde_json::to_string(&CapabilitySuggestionKind::Keep).unwrap();
        assert_eq!(json, "\"keep\"");
    }

    // ============ RecommendationConfig tests ============

    #[test]
    fn test_recommendation_config_default() {
        let config = RecommendationConfig::default();
        assert_eq!(config.unused_after_secs, 30 * 24 * 60 * 60);
    }

    #[test]
    fn test_recommendation_config_debug() {
        let config = RecommendationConfig::default();
        let debug = format!("{config:?}");
        assert!(debug.contains("RecommendationConfig"));
    }

    // ============ ZoneRiskSummary tests ============

    #[test]
    fn test_zone_risk_summary_serde() {
        let summary = ZoneRiskSummary {
            zone_id: "z:work".to_string(),
            safe: 10,
            risky: 5,
            dangerous: 2,
            critical: 1,
            forbidden: 0,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: ZoneRiskSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, parsed);
    }

    #[test]
    fn test_zone_risk_summary_debug() {
        let summary = ZoneRiskSummary {
            zone_id: "test".to_string(),
            safe: 0,
            risky: 0,
            dangerous: 0,
            critical: 0,
            forbidden: 0,
        };
        let debug = format!("{summary:?}");
        assert!(debug.contains("ZoneRiskSummary"));
    }

    // ============ CapabilityRecommendationSummary tests ============

    #[test]
    fn test_recommendation_summary_serde() {
        let summary = CapabilityRecommendationSummary {
            total: 10,
            remove_unused: 3,
            review_risky: 2,
            keep: 5,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let parsed: CapabilityRecommendationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, parsed);
    }

    // ============ CapabilityUsageAggregate tests ============

    #[test]
    fn test_aggregate_serde_roundtrip() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.test:request-response:1"),
            CapabilityId::from_static("fcp.test.read"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
            total: 100,
            allowed: 80,
            denied: 15,
            errors: 5,
            first_seen: 1000,
            last_seen: 2000,
            last_risk_tier: SafetyTier::Risky,
        };
        let json = serde_json::to_string(&aggregate).unwrap();
        let parsed: CapabilityUsageAggregate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total, 100);
        assert_eq!(parsed.allowed, 80);
        assert_eq!(parsed.denied, 15);
        assert_eq!(parsed.errors, 5);
    }

    #[test]
    fn test_aggregate_clone() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.clone:request-response:1"),
            CapabilityId::from_static("fcp.clone.read"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
            total: 50,
            allowed: 40,
            denied: 8,
            errors: 2,
            first_seen: 500,
            last_seen: 1500,
            last_risk_tier: SafetyTier::Safe,
        };
        let cloned = aggregate.clone();
        assert_eq!(aggregate.total, cloned.total);
        assert_eq!(aggregate.allowed, cloned.allowed);
        assert_eq!(aggregate.first_seen, cloned.first_seen);
    }

    // ============ Store edge case tests ============

    #[test]
    fn test_store_record_error_outcome() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        let event = sample_event(CapabilityUsageOutcome::Error, 100);
        assert!(store.record(&event));
        let snapshot = store.snapshot();
        assert_eq!(snapshot[0].errors, 1);
        assert_eq!(snapshot[0].allowed, 0);
        assert_eq!(snapshot[0].denied, 0);
    }

    #[test]
    fn test_store_empty_snapshot() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn test_recommendation_report_empty() {
        let report = recommend_capabilities(&[], 1000, RecommendationConfig::default());
        assert!(report.recommendations.is_empty());
        assert!(report.risk_summaries.is_empty());
        let summary = report.summary();
        assert_eq!(summary.total, 0);
        assert_eq!(summary.remove_unused, 0);
        assert_eq!(summary.review_risky, 0);
        assert_eq!(summary.keep, 0);
    }

    #[test]
    fn test_recommendation_report_to_json() {
        let report = recommend_capabilities(&[], 1000, RecommendationConfig::default());
        let json = report.to_json().unwrap();
        assert!(json.contains("recommendations"));
        assert!(json.contains("risk_summaries"));
    }

    #[test]
    fn test_recommendation_report_to_json_pretty() {
        let report = recommend_capabilities(&[], 1000, RecommendationConfig::default());
        let json = report.to_json_pretty().unwrap();
        // Pretty JSON has newlines
        assert!(json.contains('\n'));
    }

    #[test]
    fn test_aggregate_saturating_add_total() {
        let store = CapabilityUsageStore::new(UsageTelemetryConfig::default());
        // Record many events to verify saturating arithmetic
        for ts in 0..1000 {
            store.record(&sample_event(CapabilityUsageOutcome::Allow, ts));
        }
        let snap = store.snapshot();
        assert_eq!(snap[0].total, 1000);
        assert_eq!(snap[0].allowed, 1000);
    }

    #[test]
    fn test_store_with_max_entries_zero() {
        let config = UsageTelemetryConfig {
            max_entries: 0,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);
        let event = sample_event(CapabilityUsageOutcome::Allow, 10);
        // Should reject all events since max_entries is 0
        assert!(!store.record(&event));
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn test_store_with_zero_retention() {
        let config = UsageTelemetryConfig {
            retention_secs: 0,
            ..UsageTelemetryConfig::default()
        };
        let store = CapabilityUsageStore::new(config);
        let event = sample_event(CapabilityUsageOutcome::Allow, 10);
        store.record(&event);
        // With zero retention, a second event at any later time should prune previous
        let event2 = sample_event(CapabilityUsageOutcome::Allow, 11);
        store.record(&event2);
        let snap = store.snapshot();
        assert_eq!(snap.len(), 1);
        // first_seen should be 11 since t=10 was pruned
        assert_eq!(snap[0].first_seen, 11);
    }

    #[test]
    fn test_recommendation_exact_boundary_unused() {
        // Test at exact boundary: now - last_seen == unused_after_secs
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.boundary:request-response:1"),
            CapabilityId::from_static("fcp.boundary.read"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
            total: 1,
            allowed: 1,
            denied: 0,
            errors: 0,
            first_seen: 50,
            last_seen: 50,
            last_risk_tier: SafetyTier::Safe,
        };
        let report = recommend_capabilities(
            &[aggregate],
            100,
            RecommendationConfig {
                unused_after_secs: 50,
            },
        );
        // At exact boundary (100-50=50, not > 50), should be Keep
        assert_eq!(
            report.recommendations[0].suggestion,
            CapabilitySuggestionKind::Keep
        );
    }

    #[test]
    fn test_recommendation_just_past_boundary_unused() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.pastboundary:request-response:1"),
            CapabilityId::from_static("fcp.pastboundary.read"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
            total: 1,
            allowed: 1,
            denied: 0,
            errors: 0,
            first_seen: 49,
            last_seen: 49,
            last_risk_tier: SafetyTier::Safe,
        };
        let report = recommend_capabilities(
            &[aggregate],
            100,
            RecommendationConfig {
                unused_after_secs: 50,
            },
        );
        // 100-49=51 > 50, should be RemoveUnused
        assert_eq!(
            report.recommendations[0].suggestion,
            CapabilitySuggestionKind::RemoveUnused
        );
    }

    #[test]
    fn test_zone_risk_summary_clone_and_debug() {
        let summary = ZoneRiskSummary {
            zone_id: "z:test".to_string(),
            safe: 1,
            risky: 2,
            dangerous: 3,
            critical: 4,
            forbidden: 0,
        };
        let cloned = summary.clone();
        assert_eq!(cloned.safe, 1);
        assert_eq!(cloned.forbidden, 0);
        let debug = format!("{summary:?}");
        assert!(debug.contains("z:test"));
    }

    #[test]
    fn test_recommendation_summary_debug() {
        let summary = CapabilityRecommendationSummary {
            total: 10,
            remove_unused: 3,
            review_risky: 2,
            keep: 5,
        };
        let debug = format!("{summary:?}");
        assert!(debug.contains("CapabilityRecommendationSummary"));
        assert!(debug.contains("10"));
    }

    #[test]
    fn test_recommendation_report_debug() {
        let report = recommend_capabilities(&[], 100, RecommendationConfig::default());
        let debug = format!("{report:?}");
        assert!(debug.contains("CapabilityRecommendationReport"));
        assert!(debug.contains("100"));
    }

    #[test]
    fn test_report_by_suggestion_returns_none_for_missing() {
        let key = CapabilityUsageKey::new(
            ZoneId::work(),
            ConnectorId::from_static("fcp.miss:request-response:1"),
            CapabilityId::from_static("fcp.miss.read"),
        );
        let aggregate = CapabilityUsageAggregate {
            key,
            total: 1,
            allowed: 1,
            denied: 0,
            errors: 0,
            first_seen: 90,
            last_seen: 99,
            last_risk_tier: SafetyTier::Safe,
        };
        let report = recommend_capabilities(
            &[aggregate],
            100,
            RecommendationConfig {
                unused_after_secs: 50,
            },
        );
        // Should be Keep, so RemoveUnused and ReviewRisky should be empty
        assert!(
            report
                .by_suggestion(CapabilitySuggestionKind::RemoveUnused)
                .is_empty()
        );
        assert!(
            report
                .by_suggestion(CapabilitySuggestionKind::ReviewRisky)
                .is_empty()
        );
    }

    #[test]
    fn test_aggregate_debug_format() {
        let aggregate = CapabilityUsageAggregate {
            key: CapabilityUsageKey::new(
                ZoneId::work(),
                ConnectorId::from_static("fcp.dbg:request-response:1"),
                CapabilityId::from_static("fcp.dbg.read"),
            ),
            total: 42,
            allowed: 30,
            denied: 10,
            errors: 2,
            first_seen: 100,
            last_seen: 200,
            last_risk_tier: SafetyTier::Risky,
        };
        let debug = format!("{aggregate:?}");
        assert!(debug.contains("CapabilityUsageAggregate"));
        assert!(debug.contains("42"));
    }
}
