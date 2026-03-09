//! `fcp budget` command implementation.
//!
//! Reports current usage vs budget per zone.

pub mod types;

use anyhow::Result;
use chrono::Utc;
use clap::Args;

use fcp_core::{BudgetEnforcement, BudgetStatus, UsageMetricKind};
use types::{BudgetLineItem, BudgetReport, ZoneBudgetReport};

/// Arguments for the `fcp budget` command.
#[derive(Args, Debug)]
pub struct BudgetArgs {
    /// Filter by zone (e.g., "z:private").
    #[arg(long, short = 'z')]
    pub zone: Option<String>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run the budget command.
pub fn run(args: &BudgetArgs) -> Result<()> {
    let report = simulate_budget_report(args.zone.as_deref());

    if args.json {
        let json = serde_json::to_string_pretty(&report)?;
        println!("{json}");
    } else {
        print_budget_report(&report);
    }

    Ok(())
}

fn simulate_budget_report(zone_filter: Option<&str>) -> BudgetReport {
    let now = Utc::now();
    let now_ts = u64::try_from(now.timestamp()).unwrap_or(0);
    let zones = vec![
        ZoneBudgetReport {
            zone_id: "z:private".to_string(),
            enforcement: BudgetEnforcement::Deny,
            updated_at: now_ts,
            budgets: vec![
                BudgetLineItem {
                    metric: UsageMetricKind::Tokens,
                    used: 12_500,
                    limit: 10_000,
                    remaining: 0,
                    window_seconds: 3600,
                    window_started_at: 1_700_000_000,
                    window_resets_at: 1_700_003_600,
                    status: BudgetStatus::Exceeded,
                },
                BudgetLineItem {
                    metric: UsageMetricKind::Requests,
                    used: 120,
                    limit: 200,
                    remaining: 80,
                    window_seconds: 3600,
                    window_started_at: 1_700_000_000,
                    window_resets_at: 1_700_003_600,
                    status: BudgetStatus::Ok,
                },
            ],
        },
        ZoneBudgetReport {
            zone_id: "z:work".to_string(),
            enforcement: BudgetEnforcement::Warn,
            updated_at: now_ts,
            budgets: vec![
                BudgetLineItem {
                    metric: UsageMetricKind::Tokens,
                    used: 2_400,
                    limit: 5_000,
                    remaining: 2_600,
                    window_seconds: 3600,
                    window_started_at: 1_700_000_000,
                    window_resets_at: 1_700_003_600,
                    status: BudgetStatus::Ok,
                },
                BudgetLineItem {
                    metric: UsageMetricKind::Bytes,
                    used: 8_000_000,
                    limit: 10_000_000,
                    remaining: 2_000_000,
                    window_seconds: 3600,
                    window_started_at: 1_700_000_000,
                    window_resets_at: 1_700_003_600,
                    status: BudgetStatus::Ok,
                },
            ],
        },
    ];

    let filtered = if let Some(zone) = zone_filter {
        zones.into_iter().filter(|z| z.zone_id == zone).collect()
    } else {
        zones
    };

    BudgetReport {
        schema_version: BudgetReport::SCHEMA_VERSION.to_string(),
        generated_at: now,
        zones: filtered,
    }
}

fn print_budget_report(report: &BudgetReport) {
    println!("Usage Budgets (schema {})", report.schema_version);
    println!("Generated at: {}", report.generated_at.to_rfc3339());
    println!();

    if report.zones.is_empty() {
        println!("No budget data available for the selected zone(s).");
        return;
    }

    for zone in &report.zones {
        println!(
            "Zone: {} (enforcement: {:?})",
            zone.zone_id, zone.enforcement
        );
        if zone.budgets.is_empty() {
            println!("  No budgets configured.");
            continue;
        }
        for entry in &zone.budgets {
            let status = match entry.status {
                BudgetStatus::Ok => "ok",
                BudgetStatus::Exceeded => "exceeded",
            };
            println!(
                "  {:<12} {:>10} / {:<10} remaining {:>10} ({}; window {}s)",
                entry.metric.as_str(),
                entry.used,
                entry.limit,
                entry.remaining,
                status,
                entry.window_seconds
            );
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulate_budget_report_no_filter() {
        let report = simulate_budget_report(None);
        assert_eq!(report.schema_version, BudgetReport::SCHEMA_VERSION);
        assert_eq!(report.zones.len(), 2);
    }

    #[test]
    fn simulate_budget_report_filter_private() {
        let report = simulate_budget_report(Some("z:private"));
        assert_eq!(report.zones.len(), 1);
        assert_eq!(report.zones[0].zone_id, "z:private");
    }

    #[test]
    fn simulate_budget_report_filter_work() {
        let report = simulate_budget_report(Some("z:work"));
        assert_eq!(report.zones.len(), 1);
        assert_eq!(report.zones[0].zone_id, "z:work");
    }

    #[test]
    fn simulate_budget_report_filter_nonexistent() {
        let report = simulate_budget_report(Some("z:nonexistent"));
        assert!(report.zones.is_empty());
    }

    #[test]
    fn private_zone_has_exceeded_budget() {
        let report = simulate_budget_report(Some("z:private"));
        let zone = &report.zones[0];
        let tokens = zone
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Tokens)
            .expect("should have tokens budget");
        assert_eq!(tokens.status, BudgetStatus::Exceeded);
        assert!(tokens.used > tokens.limit);
        assert_eq!(tokens.remaining, 0);
    }

    #[test]
    fn work_zone_has_ok_budgets() {
        let report = simulate_budget_report(Some("z:work"));
        let zone = &report.zones[0];
        assert!(zone.budgets.iter().all(|b| b.status == BudgetStatus::Ok));
    }

    #[test]
    fn budget_enforcement_modes() {
        let report = simulate_budget_report(None);
        let private = report
            .zones
            .iter()
            .find(|z| z.zone_id == "z:private")
            .unwrap();
        let work = report.zones.iter().find(|z| z.zone_id == "z:work").unwrap();
        assert_eq!(private.enforcement, BudgetEnforcement::Deny);
        assert_eq!(work.enforcement, BudgetEnforcement::Warn);
    }

    #[test]
    fn budget_report_json_roundtrip() {
        let report = simulate_budget_report(None);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: BudgetReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.zones.len(), 2);
        assert_eq!(parsed.schema_version, BudgetReport::SCHEMA_VERSION);
    }

    #[test]
    fn budget_line_item_window_fields() {
        let report = simulate_budget_report(Some("z:private"));
        let item = &report.zones[0].budgets[0];
        assert!(item.window_seconds > 0);
        assert!(item.window_resets_at > item.window_started_at);
    }

    #[test]
    fn budget_report_debug() {
        let report = simulate_budget_report(None);
        let dbg = format!("{report:?}");
        assert!(dbg.contains("BudgetReport"));
    }

    // ── print_budget_report tests ─────────────────────────────

    #[test]
    fn print_budget_report_no_zones() {
        let report = simulate_budget_report(Some("z:nonexistent"));
        // Should not panic, prints "No budget data available"
        print_budget_report(&report);
    }

    #[test]
    fn print_budget_report_all_zones() {
        let report = simulate_budget_report(None);
        // Should not panic, prints both zones
        print_budget_report(&report);
    }

    #[test]
    fn print_budget_report_single_zone() {
        let report = simulate_budget_report(Some("z:private"));
        print_budget_report(&report);
    }

    #[test]
    fn print_budget_report_with_exceeded() {
        let report = simulate_budget_report(Some("z:private"));
        let tokens = report.zones[0]
            .budgets
            .iter()
            .find(|b| b.status == BudgetStatus::Exceeded);
        assert!(tokens.is_some());
        print_budget_report(&report);
    }

    #[test]
    fn print_budget_report_empty_budgets() {
        let report = BudgetReport {
            schema_version: BudgetReport::SCHEMA_VERSION.to_string(),
            generated_at: Utc::now(),
            zones: vec![ZoneBudgetReport {
                zone_id: "z:empty".to_string(),
                enforcement: BudgetEnforcement::Warn,
                budgets: vec![],
                updated_at: 0,
            }],
        };
        // Should print "No budgets configured."
        print_budget_report(&report);
    }

    // ── BudgetArgs tests ──────────────────────────────────────

    #[test]
    fn budget_args_debug_no_zone() {
        let args = BudgetArgs {
            zone: None,
            json: false,
        };
        let dbg = format!("{args:?}");
        assert!(dbg.contains("BudgetArgs"));
        assert!(dbg.contains("None"));
    }

    #[test]
    fn budget_args_debug_with_zone() {
        let args = BudgetArgs {
            zone: Some("z:private".to_string()),
            json: true,
        };
        let dbg = format!("{args:?}");
        assert!(dbg.contains("z:private"));
        assert!(dbg.contains("true"));
    }

    // ── budget metric types ───────────────────────────────────

    #[test]
    fn private_zone_has_requests_budget() {
        let report = simulate_budget_report(Some("z:private"));
        let requests = report.zones[0]
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Requests)
            .expect("should have requests budget");
        assert_eq!(requests.status, BudgetStatus::Ok);
        assert_eq!(requests.used, 120);
        assert_eq!(requests.limit, 200);
        assert_eq!(requests.remaining, 80);
    }

    #[test]
    fn work_zone_has_bytes_budget() {
        let report = simulate_budget_report(Some("z:work"));
        let bytes = report.zones[0]
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Bytes)
            .expect("should have bytes budget");
        assert_eq!(bytes.used, 8_000_000);
        assert_eq!(bytes.limit, 10_000_000);
        assert_eq!(bytes.remaining, 2_000_000);
    }

    #[test]
    fn work_zone_tokens_under_limit() {
        let report = simulate_budget_report(Some("z:work"));
        let tokens = report.zones[0]
            .budgets
            .iter()
            .find(|b| b.metric == UsageMetricKind::Tokens)
            .expect("should have tokens budget");
        assert!(tokens.used < tokens.limit);
        assert!(tokens.remaining > 0);
    }

    #[test]
    fn budget_report_json_pretty() {
        let report = simulate_budget_report(None);
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(json.contains("schema_version"));
        assert!(json.contains("z:private"));
        assert!(json.contains("z:work"));
    }

    #[test]
    fn budget_report_generated_at_is_recent() {
        let before = Utc::now();
        let report = simulate_budget_report(None);
        let after = Utc::now();
        assert!(report.generated_at >= before);
        assert!(report.generated_at <= after);
    }

    #[test]
    fn budget_zone_updated_at_is_nonzero() {
        let report = simulate_budget_report(None);
        for zone in &report.zones {
            assert!(zone.updated_at > 0);
        }
    }
}
