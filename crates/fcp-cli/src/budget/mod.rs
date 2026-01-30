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
