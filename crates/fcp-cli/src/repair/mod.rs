//! `fcp repair` command implementation.
//!
//! Reports coverage status and repair planning for offline availability.
//!
//! # Usage
//!
//! ```text
//! # Human-readable output
//! fcp repair status --zone z:private
//!
//! # JSON output
//! fcp repair status --zone z:private --json
//! ```

#![allow(clippy::cast_sign_loss)]

pub mod types;

use anyhow::Result;
use clap::{Args, Subcommand};
use fcp_core::ZoneId;

use types::{CoverageMetrics, CoverageStatus, PlacementSummary, RepairReport};

/// Arguments for the `fcp repair` command.
#[derive(Args, Debug)]
pub struct RepairArgs {
    #[command(subcommand)]
    pub command: RepairCommands,
}

/// Repair subcommands.
#[derive(Subcommand, Debug)]
pub enum RepairCommands {
    /// Show coverage status and pending repairs for a zone.
    Status(StatusArgs),
}

/// Arguments for `fcp repair status`.
#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Zone to analyze.
    #[arg(long, short = 'z')]
    pub zone: String,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// Run the repair command.
pub fn run(args: RepairArgs) -> Result<()> {
    match args.command {
        RepairCommands::Status(status_args) => run_status(&status_args),
    }
}

fn run_status(args: &StatusArgs) -> Result<()> {
    // Validate zone ID format
    let zone_id: ZoneId = args.zone.parse()?;

    // TODO: Connect to mesh node and gather real status.
    // For now, we simulate a report for demonstration.
    let report = simulate_report(&zone_id);

    if args.json {
        let output = serde_json::to_string_pretty(&report)?;
        println!("{output}");
    } else {
        print_human_readable(&report);
    }

    match report.overall_status {
        CoverageStatus::Unavailable | CoverageStatus::Critical => {
            std::process::exit(1);
        }
        CoverageStatus::Degraded => {
            std::process::exit(2);
        }
        CoverageStatus::Healthy => {}
    }

    Ok(())
}

fn simulate_report(zone_id: &ZoneId) -> RepairReport {
    RepairReport::builder(zone_id.as_str())
        .coverage(CoverageMetrics {
            distinct_nodes: 5,
            max_node_fraction_bps: 2500,
            coverage_bps: 9500,
            is_available: true,
            min_symbols_required: Some(100),
            symbols_available: Some(142),
            target_coverage_bps: Some(10000),
            deficit_bps: Some(500),
        })
        .placement(PlacementSummary {
            policy_name: "default".to_string(),
            target_replicas: 3,
            current_avg_replicas: 2.8,
            placement_nodes: vec![
                "node-0".to_string(),
                "node-1".to_string(),
                "node-2".to_string(),
                "node-3".to_string(),
                "node-4".to_string(),
            ],
            healthy_nodes: 4,
            degraded_nodes: 1,
        })
        .build()
}

fn print_human_readable(report: &RepairReport) {
    let reset = "\x1b[0m";
    let color = report.overall_status.ansi_color();
    let symbol = report.overall_status.symbol();

    println!();
    println!("FCP Repair Status Report");
    println!("========================");
    println!();
    println!("Zone:           {}", report.zone_id);
    println!("Generated:      {}", report.generated_at.to_rfc3339());
    println!(
        "Overall Status: {color}{symbol} {:?}{reset}",
        report.overall_status
    );
    println!();

    println!("Coverage:");
    println!("  Distinct Nodes:     {}", report.coverage.distinct_nodes);
    println!(
        "  Max Node Fraction:  {:.1}%",
        f64::from(report.coverage.max_node_fraction_bps) / 100.0
    );
    println!(
        "  Coverage:           {:.1}%",
        f64::from(report.coverage.coverage_bps) / 100.0
    );
    println!(
        "  Available:          {}",
        if report.coverage.is_available {
            "Yes"
        } else {
            "No"
        }
    );
    if let Some(deficit) = report.coverage.deficit_bps {
        if deficit > 0 {
            println!(
                "  Deficit:            {:.1}% below target",
                f64::from(deficit) / 100.0
            );
        }
    }
    println!();

    println!("Placement:");
    println!("  Policy:             {}", report.placement.policy_name);
    println!("  Target Replicas:    {}", report.placement.target_replicas);
    println!(
        "  Current Avg:        {:.1}",
        report.placement.current_avg_replicas
    );
    println!("  Healthy Nodes:      {}", report.placement.healthy_nodes);
    println!("  Degraded Nodes:     {}", report.placement.degraded_nodes);
    println!();

    if !report.pending_repairs.is_empty() {
        println!("Pending Repairs:");
        for action in &report.pending_repairs {
            println!(
                "  [{:?}] {} - {} symbols needed",
                action.action_type, action.object_id, action.symbols_needed
            );
            if let Some(reason) = &action.reason {
                println!("    Reason: {reason}");
            }
        }
        println!();
    }

    if let Some(cycle) = &report.last_repair_cycle {
        println!("Last Repair Cycle:");
        println!("  Completed:          {}", cycle.completed_at.to_rfc3339());
        println!("  Duration:           {}ms", cycle.duration_ms);
        println!(
            "  Actions:            {} completed, {} failed",
            cycle.actions_completed, cycle.actions_failed
        );
        println!("  Symbols Transferred: {}", cycle.symbols_transferred);
        println!(
            "  Coverage Change:    {:.1}% -> {:.1}%",
            f64::from(cycle.coverage_before_bps) / 100.0,
            f64::from(cycle.coverage_after_bps) / 100.0
        );
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_parsing() {
        let zone: ZoneId = "z:work".parse().unwrap();
        assert_eq!(zone.as_str(), "z:work");
    }

    #[test]
    fn test_simulate_report() {
        let zone: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone);

        assert_eq!(report.zone_id, "z:test");
        assert_eq!(report.overall_status, CoverageStatus::Healthy);
        assert!(report.coverage.is_available);
    }

    #[test]
    fn simulate_report_coverage_values() {
        let zone: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone);
        assert_eq!(report.coverage.distinct_nodes, 5);
        assert_eq!(report.coverage.coverage_bps, 9500);
        assert_eq!(report.coverage.max_node_fraction_bps, 2500);
        assert_eq!(report.coverage.min_symbols_required, Some(100));
        assert_eq!(report.coverage.symbols_available, Some(142));
    }

    #[test]
    fn simulate_report_placement_values() {
        let zone: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone);
        assert_eq!(report.placement.policy_name, "default");
        assert_eq!(report.placement.target_replicas, 3);
        assert_eq!(report.placement.placement_nodes.len(), 5);
        assert_eq!(report.placement.healthy_nodes, 4);
        assert_eq!(report.placement.degraded_nodes, 1);
    }

    #[test]
    fn simulate_report_no_pending_repairs() {
        let zone: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone);
        assert!(report.pending_repairs.is_empty());
        assert!(report.last_repair_cycle.is_none());
    }

    #[test]
    fn simulate_report_schema_version() {
        let zone: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone);
        assert_eq!(report.schema_version, "1.0.0");
    }

    #[test]
    fn simulate_report_json_roundtrip() {
        let zone: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone);
        let json = serde_json::to_string(&report).unwrap();
        let back: RepairReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zone_id, "z:test");
        assert_eq!(back.overall_status, CoverageStatus::Healthy);
        assert_eq!(back.coverage.distinct_nodes, 5);
    }
}
