//! `fcp capabilities` command implementation.
//!
//! Reports capability usage, generates least-privilege recommendations,
//! and exports raw usage aggregates.

pub mod types;

use std::collections::BTreeMap;

use anyhow::Result;
use chrono::Utc;
use clap::{Args, Subcommand};

use fcp_core::{
    CapabilityId, CapabilityUsageEvent, CapabilityUsageOutcome, ConnectorId, OperationId,
    PrincipalId, SafetyTier, ZoneId,
};
use fcp_telemetry::{
    CapabilityUsageAggregate, CapabilityUsageStore, RecommendationConfig, UsageTelemetryConfig,
    recommend_capabilities,
};
use types::{
    CapabilitiesReport, CapabilityTotals, CapabilityUsageLine, ExportPayload, SuggestReport,
    SuggestSummary, SuggestionFilter, ZoneCapabilityReport,
};

/// Arguments for the `fcp capabilities` command.
#[derive(Args, Debug)]
pub struct CapabilitiesArgs {
    #[command(subcommand)]
    pub command: CapabilitiesCommands,
}

/// Subcommands for `fcp capabilities`.
#[derive(Subcommand, Debug)]
pub enum CapabilitiesCommands {
    /// Report capability usage per zone.
    ///
    /// Shows per-zone usage counts, unused capabilities, and risk tier breakdown.
    Report(ReportArgs),

    /// Suggest least-privilege capability grants.
    ///
    /// Recommends removing unused capabilities, reviewing risky ones,
    /// and keeping active safe ones.
    Suggest(SuggestArgs),

    /// Export raw capability usage aggregates as JSON.
    Export(ExportArgs),
}

/// Arguments for `fcp capabilities report`.
#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Filter by zone (e.g., "z:private").
    #[arg(long, short = 'z')]
    pub zone: Option<String>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `fcp capabilities suggest`.
#[derive(Args, Debug)]
pub struct SuggestArgs {
    /// Filter by zone.
    #[arg(long, short = 'z')]
    pub zone: Option<String>,

    /// Filter by connector (e.g., "fcp.slack").
    #[arg(long, short = 'c')]
    pub connector: Option<String>,

    /// Filter suggestion kind.
    #[arg(long, value_enum, default_value_t = SuggestionFilter::All)]
    pub filter: SuggestionFilter,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Arguments for `fcp capabilities export`.
#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Filter by zone.
    #[arg(long, short = 'z')]
    pub zone: Option<String>,

    /// Output compact JSON (default: pretty).
    #[arg(long, default_value_t = false)]
    pub compact: bool,
}

/// Run the capabilities command.
pub fn run(args: &CapabilitiesArgs) -> Result<()> {
    match &args.command {
        CapabilitiesCommands::Report(a) => run_report(a),
        CapabilitiesCommands::Suggest(a) => run_suggest(a),
        CapabilitiesCommands::Export(a) => run_export(a),
    }
}

fn run_report(args: &ReportArgs) -> Result<()> {
    let aggregates = simulate_usage_data();
    let report = build_report(&aggregates, args.zone.as_deref());

    if args.json {
        let json = serde_json::to_string_pretty(&report)?;
        println!("{json}");
    } else {
        print_report(&report);
    }

    Ok(())
}

fn run_suggest(args: &SuggestArgs) -> Result<()> {
    let aggregates = simulate_usage_data();
    let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
    let config = RecommendationConfig::default();

    let mut filtered = aggregates;
    if let Some(zone) = &args.zone {
        filtered.retain(|a| a.key.zone_id.as_str() == zone.as_str());
    }
    if let Some(connector) = &args.connector {
        filtered.retain(|a| a.key.connector_id.as_str() == connector.as_str());
    }

    let rec_report = recommend_capabilities(&filtered, now, config);

    let suggest = SuggestReport {
        schema_version: SuggestReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        summary: SuggestSummary::from(&rec_report),
        recommendations: rec_report,
    };

    if args.json {
        let json = serde_json::to_string_pretty(&suggest)?;
        println!("{json}");
    } else {
        print_suggest(&suggest, args.filter);
    }

    Ok(())
}

fn run_export(args: &ExportArgs) -> Result<()> {
    let mut aggregates = simulate_usage_data();
    if let Some(zone) = &args.zone {
        aggregates.retain(|a| a.key.zone_id.as_str() == zone.as_str());
    }

    let payload = ExportPayload {
        schema_version: ExportPayload::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        count: aggregates.len(),
        aggregates,
    };

    let json = if args.compact {
        serde_json::to_string(&payload)?
    } else {
        serde_json::to_string_pretty(&payload)?
    };
    println!("{json}");

    Ok(())
}

// ---------------------------------------------------------------------------
// Report building
// ---------------------------------------------------------------------------

fn build_report(
    aggregates: &[CapabilityUsageAggregate],
    zone_filter: Option<&str>,
) -> CapabilitiesReport {
    let mut by_zone: BTreeMap<String, Vec<&CapabilityUsageAggregate>> = BTreeMap::new();
    for agg in aggregates {
        let zone = agg.key.zone_id.as_str().to_string();
        if let Some(filter) = zone_filter {
            if zone != filter {
                continue;
            }
        }
        by_zone.entry(zone).or_default().push(agg);
    }

    let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
    let unused_threshold = RecommendationConfig::default().unused_after_secs;
    let mut zones = Vec::new();
    let mut total_caps = 0_usize;
    let mut total_invocations = 0_u64;
    let mut total_unused = 0_usize;
    let mut total_risky = 0_usize;

    for (zone_id, entries) in &by_zone {
        let mut capabilities: Vec<CapabilityUsageLine> = entries
            .iter()
            .map(|a| {
                let unused = now.saturating_sub(a.last_seen) > unused_threshold;
                let risky = matches!(
                    a.last_risk_tier,
                    SafetyTier::Dangerous | SafetyTier::Critical | SafetyTier::Forbidden
                );
                if unused {
                    total_unused += 1;
                }
                if risky {
                    total_risky += 1;
                }
                CapabilityUsageLine {
                    connector_id: a.key.connector_id.as_str().to_string(),
                    capability_id: a.key.capability_id.as_str().to_string(),
                    total: a.total,
                    allowed: a.allowed,
                    denied: a.denied,
                    errors: a.errors,
                    risk_tier: a.last_risk_tier,
                    first_seen: a.first_seen,
                    last_seen: a.last_seen,
                }
            })
            .collect();
        capabilities.sort_by_key(|c| std::cmp::Reverse(c.total));

        let zone_unused = capabilities
            .iter()
            .filter(|c| now.saturating_sub(c.last_seen) > unused_threshold)
            .count();
        let zone_total: u64 = capabilities.iter().map(|c| c.total).sum();

        total_caps += capabilities.len();
        total_invocations += zone_total;

        zones.push(ZoneCapabilityReport {
            zone_id: zone_id.clone(),
            capability_count: capabilities.len(),
            total_invocations: zone_total,
            unused_count: zone_unused,
            capabilities,
        });
    }

    CapabilitiesReport {
        schema_version: CapabilitiesReport::SCHEMA_VERSION.to_string(),
        generated_at: Utc::now(),
        zones,
        totals: CapabilityTotals {
            total_capabilities: total_caps,
            total_invocations,
            unused_capabilities: total_unused,
            risky_capabilities: total_risky,
        },
    }
}

// ---------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------

fn print_report(report: &CapabilitiesReport) {
    println!("Capability Usage Report (schema {})", report.schema_version);
    println!("Generated at: {}", report.generated_at.to_rfc3339());
    println!();

    if report.zones.is_empty() {
        println!("No capability data available.");
        return;
    }

    for zone in &report.zones {
        println!(
            "Zone: {} ({} capabilities, {} invocations, {} unused)",
            zone.zone_id, zone.capability_count, zone.total_invocations, zone.unused_count
        );
        if zone.capabilities.is_empty() {
            println!("  No capabilities.");
            continue;
        }
        for cap in &zone.capabilities {
            println!(
                "  {:<40} {:>6} total ({} ok, {} denied, {} err) [{:?}]",
                format!("{}/{}", cap.connector_id, cap.capability_id),
                cap.total,
                cap.allowed,
                cap.denied,
                cap.errors,
                cap.risk_tier
            );
        }
        println!();
    }

    println!("Totals:");
    println!(
        "  {} capabilities, {} invocations, {} unused, {} risky+",
        report.totals.total_capabilities,
        report.totals.total_invocations,
        report.totals.unused_capabilities,
        report.totals.risky_capabilities
    );
}

fn print_suggest(suggest: &SuggestReport, filter: SuggestionFilter) {
    println!(
        "Capability Recommendations (schema {})",
        suggest.schema_version
    );
    println!("Generated at: {}", suggest.generated_at.to_rfc3339());
    println!();

    let recs = &suggest.recommendations.recommendations;
    if recs.is_empty() {
        println!("No recommendations.");
        return;
    }

    let filter_kind = filter.to_kind();
    let filtered: Vec<_> = recs
        .iter()
        .filter(|r| filter_kind.is_none() || filter_kind == Some(r.suggestion))
        .collect();

    if filtered.is_empty() {
        println!("No recommendations matching filter.");
        return;
    }

    for rec in &filtered {
        let icon = match rec.suggestion {
            fcp_telemetry::CapabilitySuggestionKind::RemoveUnused => "[-]",
            fcp_telemetry::CapabilitySuggestionKind::ReviewRisky => "[!]",
            fcp_telemetry::CapabilitySuggestionKind::Keep => "[+]",
        };
        println!(
            "  {} {}/{} ({} uses, last seen {}, {:?}): {}",
            icon,
            rec.key.connector_id.as_str(),
            rec.key.capability_id.as_str(),
            rec.usage_total,
            rec.last_seen,
            rec.risk_tier,
            rec.reason_code
        );
    }

    println!();
    println!("Summary:");
    println!(
        "  {} total: {} remove, {} review, {} keep",
        suggest.summary.total,
        suggest.summary.remove_unused,
        suggest.summary.review_risky,
        suggest.summary.keep
    );
}

// ---------------------------------------------------------------------------
// Simulated usage data (until real telemetry pipeline is connected)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn make_event(
    zone: ZoneId,
    connector: &'static str,
    capability: &'static str,
    principal: &str,
    tier: SafetyTier,
    operation: &'static str,
    outcome: CapabilityUsageOutcome,
    occurred_at: u64,
) -> CapabilityUsageEvent {
    CapabilityUsageEvent {
        format: "fcp-capability-usage".to_string(),
        schema_version: "1.0".to_string(),
        zone_id: zone,
        connector_id: ConnectorId::from_static(connector),
        capability_id: CapabilityId::from_static(capability),
        principal_id: PrincipalId::new(principal).expect("valid principal"),
        risk_tier: tier,
        operation: OperationId::from_static(operation),
        outcome,
        occurred_at,
    }
}

fn simulate_usage_data() -> Vec<CapabilityUsageAggregate> {
    // Use 90-day retention so stale (60-day) entries survive pruning
    let store = CapabilityUsageStore::new(UsageTelemetryConfig {
        retention_secs: 90 * 24 * 60 * 60,
        ..UsageTelemetryConfig::default()
    });
    let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);

    // Active safe capability
    for i in 0..50 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.slack:request_response:0.1.0",
            "slack.send_message",
            "agent-1",
            SafetyTier::Safe,
            "send_message",
            CapabilityUsageOutcome::Allow,
            now.saturating_sub(3600) + i,
        ));
    }

    // Risky capability (Dangerous tier)
    for i in 0..10 {
        store.record(&make_event(
            ZoneId::work(),
            "fcp.github:request_response:0.1.0",
            "github.delete_repo",
            "agent-1",
            SafetyTier::Dangerous,
            "delete_repo",
            if i < 8 {
                CapabilityUsageOutcome::Allow
            } else {
                CapabilityUsageOutcome::Deny
            },
            now.saturating_sub(1800) + i,
        ));
    }

    // Stale/unused capability (last seen 60 days ago)
    store.record(&make_event(
        ZoneId::work(),
        "fcp.jira:request_response:0.1.0",
        "jira.delete_issue",
        "agent-2",
        SafetyTier::Risky,
        "delete_issue",
        CapabilityUsageOutcome::Allow,
        now.saturating_sub(60 * 86400),
    ));

    // Private zone capability
    for i in 0..20 {
        store.record(&make_event(
            ZoneId::private(),
            "fcp.gmail:request_response:0.1.0",
            "gmail.send_email",
            "agent-1",
            SafetyTier::Risky,
            "send_email",
            CapabilityUsageOutcome::Allow,
            now.saturating_sub(600) + i,
        ));
    }

    // Error capability
    for i in 0..5 {
        store.record(&make_event(
            ZoneId::private(),
            "fcp.stripe:request_response:0.1.0",
            "stripe.charge",
            "agent-3",
            SafetyTier::Dangerous,
            "charge",
            CapabilityUsageOutcome::Error,
            now.saturating_sub(300) + i,
        ));
    }

    store.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulate_usage_data_produces_aggregates() {
        let aggs = simulate_usage_data();
        assert!(!aggs.is_empty(), "should produce usage aggregates");
        // Should have at least slack, github, jira, gmail, stripe
        assert!(aggs.len() >= 5);
    }

    #[test]
    fn build_report_no_filter() {
        let aggs = simulate_usage_data();
        let report = build_report(&aggs, None);
        assert_eq!(report.schema_version, "1.0.0");
        assert!(!report.zones.is_empty());
        assert!(report.totals.total_capabilities >= 5);
        assert!(report.totals.total_invocations > 0);
    }

    #[test]
    fn build_report_zone_filter_work() {
        let aggs = simulate_usage_data();
        let report = build_report(&aggs, Some("z:work"));
        assert_eq!(report.zones.len(), 1);
        assert_eq!(report.zones[0].zone_id, "z:work");
    }

    #[test]
    fn build_report_zone_filter_private() {
        let aggs = simulate_usage_data();
        let report = build_report(&aggs, Some("z:private"));
        assert_eq!(report.zones.len(), 1);
        assert_eq!(report.zones[0].zone_id, "z:private");
    }

    #[test]
    fn build_report_zone_filter_nonexistent() {
        let aggs = simulate_usage_data();
        let report = build_report(&aggs, Some("z:nonexistent"));
        assert!(report.zones.is_empty());
        assert_eq!(report.totals.total_capabilities, 0);
    }

    #[test]
    fn build_report_capabilities_sorted_by_usage_desc() {
        let aggs = simulate_usage_data();
        let report = build_report(&aggs, Some("z:work"));
        let caps = &report.zones[0].capabilities;
        for pair in caps.windows(2) {
            assert!(
                pair[0].total >= pair[1].total,
                "capabilities should be sorted descending"
            );
        }
    }

    #[test]
    fn build_report_has_unused_in_work_zone() {
        let aggs = simulate_usage_data();
        let report = build_report(&aggs, Some("z:work"));
        // jira.delete_issue is 60 days old → unused
        assert!(
            report.zones[0].unused_count > 0,
            "should detect unused capability"
        );
    }

    #[test]
    fn build_report_has_risky_capabilities() {
        let aggs = simulate_usage_data();
        let report = build_report(&aggs, None);
        assert!(
            report.totals.risky_capabilities > 0,
            "should detect risky capabilities"
        );
    }

    #[test]
    fn report_json_roundtrip() {
        let aggs = simulate_usage_data();
        let report = build_report(&aggs, None);
        let json = serde_json::to_string(&report).unwrap();
        let back: CapabilitiesReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.schema_version, report.schema_version);
        assert_eq!(back.zones.len(), report.zones.len());
    }

    #[test]
    fn suggest_produces_recommendations() {
        let aggs = simulate_usage_data();
        let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        let config = RecommendationConfig::default();
        let rec = recommend_capabilities(&aggs, now, config);
        assert!(!rec.recommendations.is_empty());
    }

    #[test]
    fn suggest_has_remove_unused() {
        let aggs = simulate_usage_data();
        let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        let config = RecommendationConfig::default();
        let rec = recommend_capabilities(&aggs, now, config);
        let summary = rec.summary();
        assert!(summary.remove_unused > 0, "should suggest removing unused");
    }

    #[test]
    fn suggest_has_review_risky() {
        let aggs = simulate_usage_data();
        let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        let config = RecommendationConfig::default();
        let rec = recommend_capabilities(&aggs, now, config);
        let summary = rec.summary();
        assert!(summary.review_risky > 0, "should suggest reviewing risky");
    }

    #[test]
    fn suggest_has_keep() {
        let aggs = simulate_usage_data();
        let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        let config = RecommendationConfig::default();
        let rec = recommend_capabilities(&aggs, now, config);
        let summary = rec.summary();
        assert!(summary.keep > 0, "should suggest keeping active safe");
    }

    #[test]
    fn suggest_summary_from_report() {
        let aggs = simulate_usage_data();
        let now = u64::try_from(Utc::now().timestamp()).unwrap_or(0);
        let config = RecommendationConfig::default();
        let rec = recommend_capabilities(&aggs, now, config);
        let summary = SuggestSummary::from(&rec);
        assert_eq!(summary.total, rec.recommendations.len());
    }

    #[test]
    fn export_zone_filter() {
        let mut aggs = simulate_usage_data();
        let zone_id = ZoneId::work();
        aggs.retain(|a| a.key.zone_id == zone_id);
        assert!(!aggs.is_empty(), "should have work zone aggregates");
        for agg in &aggs {
            assert_eq!(agg.key.zone_id, zone_id);
        }
    }

    #[test]
    fn export_payload_serde_roundtrip() {
        let aggs = simulate_usage_data();
        let payload = ExportPayload {
            schema_version: ExportPayload::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            count: aggs.len(),
            aggregates: aggs,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: ExportPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.count, payload.count);
    }

    #[test]
    fn run_report_json_does_not_panic() {
        let args = ReportArgs {
            zone: None,
            json: true,
        };
        assert!(run_report(&args).is_ok());
    }

    #[test]
    fn run_report_human_does_not_panic() {
        let args = ReportArgs {
            zone: None,
            json: false,
        };
        assert!(run_report(&args).is_ok());
    }

    #[test]
    fn run_suggest_json_does_not_panic() {
        let args = SuggestArgs {
            zone: None,
            connector: None,
            filter: SuggestionFilter::All,
            json: true,
        };
        assert!(run_suggest(&args).is_ok());
    }

    #[test]
    fn run_suggest_human_does_not_panic() {
        let args = SuggestArgs {
            zone: None,
            connector: None,
            filter: SuggestionFilter::All,
            json: false,
        };
        assert!(run_suggest(&args).is_ok());
    }

    #[test]
    fn run_export_compact_does_not_panic() {
        let args = ExportArgs {
            zone: None,
            compact: true,
        };
        assert!(run_export(&args).is_ok());
    }

    #[test]
    fn run_export_pretty_does_not_panic() {
        let args = ExportArgs {
            zone: None,
            compact: false,
        };
        assert!(run_export(&args).is_ok());
    }

    #[test]
    fn run_suggest_with_zone_filter() {
        let args = SuggestArgs {
            zone: Some("z:work".to_string()),
            connector: None,
            filter: SuggestionFilter::All,
            json: true,
        };
        assert!(run_suggest(&args).is_ok());
    }

    #[test]
    fn run_suggest_with_connector_filter() {
        let args = SuggestArgs {
            zone: None,
            connector: Some("fcp.slack".to_string()),
            filter: SuggestionFilter::Keep,
            json: true,
        };
        assert!(run_suggest(&args).is_ok());
    }

    #[test]
    fn run_suggest_unused_filter() {
        let args = SuggestArgs {
            zone: None,
            connector: None,
            filter: SuggestionFilter::Unused,
            json: false,
        };
        assert!(run_suggest(&args).is_ok());
    }

    #[test]
    fn run_suggest_risky_filter() {
        let args = SuggestArgs {
            zone: None,
            connector: None,
            filter: SuggestionFilter::Risky,
            json: false,
        };
        assert!(run_suggest(&args).is_ok());
    }

    #[test]
    fn run_report_zone_filter_work() {
        let args = ReportArgs {
            zone: Some("z:work".to_string()),
            json: true,
        };
        assert!(run_report(&args).is_ok());
    }

    #[test]
    fn run_report_zone_filter_nonexistent() {
        let args = ReportArgs {
            zone: Some("z:nonexistent".to_string()),
            json: false,
        };
        assert!(run_report(&args).is_ok());
    }

    #[test]
    fn run_export_zone_filter() {
        let args = ExportArgs {
            zone: Some("z:private".to_string()),
            compact: false,
        };
        assert!(run_export(&args).is_ok());
    }

    #[test]
    fn build_report_totals_match_zones() {
        let aggs = simulate_usage_data();
        let report = build_report(&aggs, None);
        let zone_cap_sum: usize = report.zones.iter().map(|z| z.capability_count).sum();
        assert_eq!(
            report.totals.total_capabilities, zone_cap_sum,
            "totals should match zone sums"
        );
        let zone_inv_sum: u64 = report.zones.iter().map(|z| z.total_invocations).sum();
        assert_eq!(report.totals.total_invocations, zone_inv_sum);
    }

    #[test]
    fn usage_data_has_work_zone() {
        let aggs = simulate_usage_data();
        assert!(
            aggs.iter().any(|a| a.key.zone_id == ZoneId::work()),
            "should have work zone data"
        );
    }

    #[test]
    fn usage_data_has_private_zone() {
        let aggs = simulate_usage_data();
        assert!(
            aggs.iter().any(|a| a.key.zone_id == ZoneId::private()),
            "should have private zone data"
        );
    }

    #[test]
    fn usage_data_has_dangerous_tier() {
        let aggs = simulate_usage_data();
        assert!(
            aggs.iter()
                .any(|a| a.last_risk_tier == SafetyTier::Dangerous),
            "should have dangerous tier"
        );
    }

    #[test]
    fn build_report_debug() {
        let aggs = simulate_usage_data();
        let report = build_report(&aggs, None);
        let dbg = format!("{report:?}");
        assert!(dbg.contains("CapabilitiesReport"));
    }
}
