//! `fcp doctor` command implementation.
//!
//! Diagnoses zone health, freshness, and degraded mode status.
//!
//! # Usage
//!
//! ```text
//! # Human-readable output
//! fcp doctor --zone z:private
//!
//! # JSON output
//! fcp doctor --zone z:private --json
//!
//! # Connector self-checks
//! fcp doctor --zone z:private --connector fcp.telegram:messaging:v1
//!
//! # Test specific scenarios (simulation mode)
//! fcp doctor --zone z:private --scenario degraded
//! fcp doctor --zone z:private --scenario stale-checkpoint
//! fcp doctor --zone z:private --scenario network-partition
//! ```
//!
//! # Future: Real Mesh Connectivity
//!
//! When a mesh node is available, set `FCP_MESH_ENDPOINT` to connect to real data:
//! ```text
//! export FCP_MESH_ENDPOINT=http://localhost:9090
//! fcp doctor --zone z:private
//! ```
//!
//! The CLI will POST a JSON body to `{FCP_MESH_ENDPOINT}/doctor` (or the exact
//! URL if a path is provided) with:
//! ```json
//! {"zone_id":"z:private","connectors":["fcp.telegram:messaging:v1"],"self_check":true}
//! ```

#![allow(clippy::cast_sign_loss)]

pub mod types;

use anyhow::Result;
use chrono::Utc;
use clap::{Args, ValueEnum};
use fcp_core::{ConnectorId, SelfCheckReport, SelfCheckStatus, ZoneId};
use serde::Serialize;
use std::time::Duration;
use url::Url;

use types::{
    AuditStatus, CheckResult, CheckpointStatus, ConnectorSelfCheck, DegradedModeStatus,
    DegradedReason, DoctorReport, FreshnessLevel, OverallStatus, RevocationStatus,
    StoreCoverageStatus, TransportPolicyStatus,
};

/// Simulation scenarios for testing different health states.
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum DoctorScenario {
    /// All checks pass, system healthy.
    #[default]
    Healthy,
    /// System in degraded mode but operational.
    Degraded,
    /// Checkpoint is stale, operations may be limited.
    StaleCheckpoint,
    /// Revocation list too stale, high-risk operations blocked.
    StaleRevocation,
    /// Network partition detected, limited connectivity.
    NetworkPartition,
    /// Store coverage below threshold.
    LowCoverage,
    /// Multiple failures.
    Critical,
}

/// Arguments for the `fcp doctor` command.
#[derive(Args, Debug)]
pub struct DoctorArgs {
    /// Zone to diagnose.
    #[arg(long, short = 'z')]
    pub zone: String,

    /// Connector IDs to self-check (repeatable).
    #[arg(long, value_name = "CONNECTOR", num_args = 1..)]
    pub connector: Vec<String>,

    /// Run connector self-checks (requires --connector).
    #[arg(long, default_value_t = false)]
    pub self_check: bool,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Simulation scenario for testing (ignored when connected to real mesh).
    #[arg(long, value_enum, default_value_t = DoctorScenario::Healthy)]
    pub scenario: DoctorScenario,
}

/// Run the doctor command.
pub fn run(args: &DoctorArgs, stdin_input: Option<&serde_json::Value>) -> Result<()> {
    // Validate zone ID format
    let zone_id: ZoneId = args.zone.parse()?;
    let connector_ids = parse_connector_ids(&args.connector)?;
    let enable_self_checks = args.self_check || !connector_ids.is_empty();
    if args.self_check && connector_ids.is_empty() {
        anyhow::bail!("--self-check requires at least one --connector");
    }

    let report = if let Some(input) = stdin_input {
        let report: DoctorReport = serde_json::from_value(input.clone())
            .map_err(|err| anyhow::anyhow!("Failed to parse doctor report from stdin: {err}"))?;
        if report.zone_id != zone_id.as_str() {
            anyhow::bail!(
                "stdin report zone_id '{}' does not match requested zone '{}'",
                report.zone_id,
                zone_id.as_str()
            );
        }
        report
    } else if let Ok(endpoint) = std::env::var("FCP_MESH_ENDPOINT") {
        fetch_report_from_mesh(&endpoint, &zone_id, &connector_ids, enable_self_checks)?
    } else {
        let empty = Vec::new();
        simulate_report(
            &zone_id,
            if enable_self_checks {
                &connector_ids
            } else {
                &empty
            },
            args.scenario,
        )
    };

    if args.json {
        let output = serde_json::to_string_pretty(&report)?;
        println!("{output}");
    } else {
        print_human_readable(&report);
    }

    // Exit codes: 0 = ok, 1 = fail, 2 = warn
    match report.overall_status {
        OverallStatus::Ok => {}
        OverallStatus::Warn => std::process::exit(2),
        OverallStatus::Fail => std::process::exit(1),
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct DoctorRequest {
    zone_id: String,
    connectors: Vec<String>,
    self_check: bool,
}

fn build_doctor_url(endpoint: &str) -> Result<Url> {
    let mut url = Url::parse(endpoint)
        .map_err(|err| anyhow::anyhow!("Invalid FCP_MESH_ENDPOINT URL: {err}"))?;
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("doctor");
    }
    Ok(url)
}

fn fetch_report_from_mesh(
    endpoint: &str,
    zone_id: &ZoneId,
    connector_ids: &[ConnectorId],
    enable_self_checks: bool,
) -> Result<DoctorReport> {
    let url = build_doctor_url(endpoint)?;
    let request = DoctorRequest {
        zone_id: zone_id.as_str().to_string(),
        connectors: connector_ids.iter().map(ToString::to_string).collect(),
        self_check: enable_self_checks,
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|err| anyhow::anyhow!("Failed to build HTTP client: {err}"))?;

    let response = client
        .post(url)
        .json(&request)
        .send()
        .map_err(|err| anyhow::anyhow!("Failed to contact mesh endpoint: {err}"))?
        .error_for_status()
        .map_err(|err| anyhow::anyhow!("Mesh endpoint error: {err}"))?;

    let report: DoctorReport = response
        .json()
        .map_err(|err| anyhow::anyhow!("Failed to parse doctor report: {err}"))?;

    if report.zone_id != zone_id.as_str() {
        anyhow::bail!(
            "mesh report zone_id '{}' does not match requested zone '{}'",
            report.zone_id,
            zone_id.as_str()
        );
    }

    Ok(report)
}

fn parse_connector_ids(ids: &[String]) -> Result<Vec<ConnectorId>> {
    let mut parsed = Vec::new();
    for id in ids {
        let connector_id: ConnectorId = id.parse()?;
        parsed.push(connector_id);
    }
    Ok(parsed)
}

fn simulate_report(
    zone_id: &ZoneId,
    connector_ids: &[ConnectorId],
    scenario: DoctorScenario,
) -> DoctorReport {
    let now = Utc::now().timestamp() as u64;
    let self_checks = simulate_self_checks(connector_ids, scenario);

    let mut report = match scenario {
        DoctorScenario::Healthy => build_healthy_report(zone_id, now),
        DoctorScenario::Degraded => build_degraded_report(zone_id, now),
        DoctorScenario::StaleCheckpoint => build_stale_checkpoint_report(zone_id, now),
        DoctorScenario::StaleRevocation => build_stale_revocation_report(zone_id, now),
        DoctorScenario::NetworkPartition => build_network_partition_report(zone_id, now),
        DoctorScenario::LowCoverage => build_low_coverage_report(zone_id, now),
        DoctorScenario::Critical => build_critical_report(zone_id, now),
    };

    if !self_checks.is_empty() {
        report.connector_self_checks = self_checks;
    }

    report
}

fn simulate_self_checks(
    connector_ids: &[ConnectorId],
    scenario: DoctorScenario,
) -> Vec<ConnectorSelfCheck> {
    connector_ids
        .iter()
        .map(|connector_id| {
            let report = match scenario {
                DoctorScenario::Healthy => SelfCheckReport::ok(),
                DoctorScenario::Critical => SelfCheckReport::failed(
                    "self_check_failed",
                    "Connector self-check failed (simulated)",
                ),
                DoctorScenario::Degraded
                | DoctorScenario::LowCoverage
                | DoctorScenario::NetworkPartition
                | DoctorScenario::StaleCheckpoint
                | DoctorScenario::StaleRevocation => SelfCheckReport::degraded(
                    "self_check_degraded",
                    "Connector self-check degraded (simulated)",
                ),
            };

            ConnectorSelfCheck {
                connector_id: connector_id.to_string(),
                report,
            }
        })
        .collect()
}

fn build_healthy_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            last_updated_at: Some(now - 120),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: None,
        })
        .revocation(RevocationStatus {
            head_id: Some("rev_abcdef123456".to_string()),
            head_seq: Some(50),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            reason: None,
        })
        .audit(AuditStatus {
            head_id: Some("aud_9876543210".to_string()),
            head_seq: Some(500),
            age_secs: Some(30),
            freshness: FreshnessLevel::Fresh,
            coverage: Some(1.0),
            reason: None,
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(10000),
            policy_head_coverage_bps: Some(10000),
            revocation_head_coverage_bps: Some(10000),
            store_healthy: true,
            reason: None,
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: false,
            reasons: vec![],
            since: None,
        })
        .add_check(CheckResult::ok(
            "checkpoint_integrity",
            "Checkpoint signature verified",
        ))
        .add_check(CheckResult::ok(
            "revocation_chain",
            "Revocation chain is unbroken",
        ))
        .add_check(CheckResult::ok(
            "store_replication",
            "All critical objects replicated to 3+ nodes",
        ))
        .build()
}

fn build_degraded_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(300),
            freshness: FreshnessLevel::Stale,
            last_updated_at: Some(now - 300),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: Some("Checkpoint 5 minutes old".to_string()),
        })
        .revocation(RevocationStatus {
            head_id: Some("rev_abcdef123456".to_string()),
            head_seq: Some(50),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            reason: None,
        })
        .audit(AuditStatus {
            head_id: Some("aud_9876543210".to_string()),
            head_seq: Some(500),
            age_secs: Some(30),
            freshness: FreshnessLevel::Fresh,
            coverage: Some(0.85),
            reason: None,
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(9500),
            policy_head_coverage_bps: Some(10000),
            revocation_head_coverage_bps: Some(9800),
            store_healthy: true,
            reason: None,
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![DegradedReason {
                code: "FCP-5001".to_string(),
                description: "Checkpoint older than freshness threshold".to_string(),
            }],
            since: Some(now - 180),
        })
        .add_check(CheckResult::ok(
            "checkpoint_integrity",
            "Checkpoint signature verified",
        ))
        .add_check(
            CheckResult::warn("checkpoint_age", "Checkpoint is 5 minutes old")
                .with_reason_code("FCP-5001"),
        )
        .add_check(CheckResult::ok(
            "revocation_chain",
            "Revocation chain is unbroken",
        ))
        .build()
}

fn build_stale_checkpoint_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(3600),
            freshness: FreshnessLevel::TooStale,
            last_updated_at: Some(now - 3600),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: Some("Checkpoint 1 hour old, exceeds max-stale threshold".to_string()),
        })
        .revocation(RevocationStatus {
            head_id: Some("rev_abcdef123456".to_string()),
            head_seq: Some(50),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            reason: None,
        })
        .audit(AuditStatus {
            head_id: Some("aud_9876543210".to_string()),
            head_seq: Some(500),
            age_secs: Some(30),
            freshness: FreshnessLevel::Fresh,
            coverage: Some(1.0),
            reason: None,
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(10000),
            policy_head_coverage_bps: Some(10000),
            revocation_head_coverage_bps: Some(10000),
            store_healthy: true,
            reason: None,
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![DegradedReason {
                code: "FCP-5002".to_string(),
                description: "Checkpoint too stale for safe operations".to_string(),
            }],
            since: Some(now - 3000),
        })
        .add_check(
            CheckResult::fail(
                "checkpoint_freshness",
                "Checkpoint exceeds max-stale threshold (1h > 30m)",
            )
            .with_reason_code("FCP-5002"),
        )
        .add_check(CheckResult::ok(
            "revocation_chain",
            "Revocation chain is unbroken",
        ))
        .build()
}

fn build_stale_revocation_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            last_updated_at: Some(now - 120),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: None,
        })
        .revocation(RevocationStatus {
            head_id: Some("rev_abcdef123456".to_string()),
            head_seq: Some(50),
            age_secs: Some(7200),
            freshness: FreshnessLevel::TooStale,
            reason: Some("Revocation list 2 hours old, cannot verify token validity".to_string()),
        })
        .audit(AuditStatus {
            head_id: Some("aud_9876543210".to_string()),
            head_seq: Some(500),
            age_secs: Some(30),
            freshness: FreshnessLevel::Fresh,
            coverage: Some(1.0),
            reason: None,
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(10000),
            policy_head_coverage_bps: Some(10000),
            revocation_head_coverage_bps: Some(6000),
            store_healthy: true,
            reason: Some("Revocation head under-replicated".to_string()),
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![DegradedReason {
                code: "FCP-5003".to_string(),
                description: "Revocation list too stale for high-risk operations".to_string(),
            }],
            since: Some(now - 6000),
        })
        .add_check(CheckResult::ok(
            "checkpoint_integrity",
            "Checkpoint signature verified",
        ))
        .add_check(
            CheckResult::fail(
                "revocation_freshness",
                "Revocation list exceeds max-stale threshold (2h > 1h)",
            )
            .with_reason_code("FCP-5003"),
        )
        .build()
}

fn build_network_partition_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(600),
            freshness: FreshnessLevel::Stale,
            last_updated_at: Some(now - 600),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: Some("Cannot reach checkpoint authority".to_string()),
        })
        .revocation(RevocationStatus {
            head_id: Some("rev_abcdef123456".to_string()),
            head_seq: Some(50),
            age_secs: Some(600),
            freshness: FreshnessLevel::Stale,
            reason: Some("Cannot reach revocation authority".to_string()),
        })
        .audit(AuditStatus {
            head_id: Some("aud_9876543210".to_string()),
            head_seq: Some(500),
            age_secs: Some(600),
            freshness: FreshnessLevel::Stale,
            coverage: Some(0.33),
            reason: Some("Only 1 of 3 audit nodes reachable".to_string()),
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(3300),
            policy_head_coverage_bps: Some(3300),
            revocation_head_coverage_bps: Some(3300),
            store_healthy: false,
            reason: Some("Network partition: only 1 of 3 nodes reachable".to_string()),
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![
                DegradedReason {
                    code: "FCP-6001".to_string(),
                    description: "Network partition detected".to_string(),
                },
                DegradedReason {
                    code: "FCP-6002".to_string(),
                    description: "DERP relay unavailable".to_string(),
                },
            ],
            since: Some(now - 600),
        })
        .add_check(
            CheckResult::warn("network_connectivity", "2 of 3 peer nodes unreachable")
                .with_reason_code("FCP-6001"),
        )
        .add_check(
            CheckResult::warn("derp_relay", "DERP relay connection failed")
                .with_reason_code("FCP-6002"),
        )
        .add_check(CheckResult::ok(
            "checkpoint_integrity",
            "Local checkpoint signature verified",
        ))
        .build()
}

fn build_low_coverage_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: Some("chk_1234567890abcdef".to_string()),
            checkpoint_seq: Some(100),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            last_updated_at: Some(now - 120),
            audit_head_seq: Some(500),
            revocation_head_seq: Some(50),
            reason: None,
        })
        .revocation(RevocationStatus {
            head_id: Some("rev_abcdef123456".to_string()),
            head_seq: Some(50),
            age_secs: Some(120),
            freshness: FreshnessLevel::Fresh,
            reason: None,
        })
        .audit(AuditStatus {
            head_id: Some("aud_9876543210".to_string()),
            head_seq: Some(500),
            age_secs: Some(30),
            freshness: FreshnessLevel::Fresh,
            coverage: Some(0.66),
            reason: Some("1 audit node offline".to_string()),
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(6600),
            policy_head_coverage_bps: Some(6600),
            revocation_head_coverage_bps: Some(6600),
            store_healthy: false,
            reason: Some("Coverage below 70% threshold".to_string()),
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![DegradedReason {
                code: "FCP-7001".to_string(),
                description: "Store coverage below minimum threshold".to_string(),
            }],
            since: Some(now - 300),
        })
        .add_check(CheckResult::ok(
            "checkpoint_integrity",
            "Checkpoint signature verified",
        ))
        .add_check(
            CheckResult::warn("store_coverage", "Coverage at 66%, below 70% threshold")
                .with_reason_code("FCP-7001"),
        )
        .add_check(CheckResult::ok(
            "revocation_chain",
            "Revocation chain is unbroken",
        ))
        .build()
}

fn build_critical_report(zone_id: &ZoneId, now: u64) -> DoctorReport {
    DoctorReport::builder(zone_id.as_str())
        .checkpoint(CheckpointStatus {
            checkpoint_id: None,
            checkpoint_seq: None,
            age_secs: None,
            freshness: FreshnessLevel::Missing,
            last_updated_at: None,
            audit_head_seq: None,
            revocation_head_seq: None,
            reason: Some("No checkpoint available".to_string()),
        })
        .revocation(RevocationStatus {
            head_id: None,
            head_seq: None,
            age_secs: None,
            freshness: FreshnessLevel::Missing,
            reason: Some("No revocation list available".to_string()),
        })
        .audit(AuditStatus {
            head_id: None,
            head_seq: None,
            age_secs: None,
            freshness: FreshnessLevel::Missing,
            coverage: Some(0.0),
            reason: Some("Audit chain unavailable".to_string()),
        })
        .transport_policy(TransportPolicyStatus {
            allow_lan: false,
            allow_derp: false,
            allow_funnel: false,
        })
        .store_coverage(StoreCoverageStatus {
            checkpoint_coverage_bps: Some(0),
            policy_head_coverage_bps: Some(0),
            revocation_head_coverage_bps: Some(0),
            store_healthy: false,
            reason: Some("Store unavailable".to_string()),
        })
        .degraded_mode(DegradedModeStatus {
            is_degraded: true,
            reasons: vec![
                DegradedReason {
                    code: "FCP-9001".to_string(),
                    description: "Zone bootstrap incomplete".to_string(),
                },
                DegradedReason {
                    code: "FCP-9002".to_string(),
                    description: "No transport paths available".to_string(),
                },
            ],
            since: Some(now),
        })
        .add_check(
            CheckResult::fail("zone_bootstrap", "Zone has not completed bootstrap")
                .with_reason_code("FCP-9001"),
        )
        .add_check(
            CheckResult::fail("checkpoint_availability", "No checkpoint object found")
                .with_reason_code("FCP-9003"),
        )
        .add_check(
            CheckResult::fail(
                "transport_paths",
                "No transport paths available (LAN/DERP/Funnel all disabled)",
            )
            .with_reason_code("FCP-9002"),
        )
        .build()
}

#[allow(clippy::too_many_lines)] // Output formatting is clearer as a single function
fn print_human_readable(report: &DoctorReport) {
    let reset = "\x1b[0m";
    let green = "\x1b[32m";
    let yellow = "\x1b[33m";
    let red = "\x1b[31m";
    let dim = "\x1b[2m";
    let color = report.overall_status.ansi_color();
    let symbol = report.overall_status.symbol();

    println!();
    println!("FCP Doctor Report");
    println!("═════════════════");
    println!();
    println!("Zone:           {}", report.zone_id);
    println!("Generated:      {}", report.generated_at.to_rfc3339());
    println!(
        "Overall Status: {color}{symbol} {:?}{reset}",
        report.overall_status
    );
    println!();

    // Freshness section with color coding
    println!("Freshness:");
    let chk_color = freshness_color(report.checkpoint.freshness);
    let rev_color = freshness_color(report.revocation.freshness);
    let aud_color = freshness_color(report.audit.freshness);

    println!(
        "  Checkpoint:   {chk_color}{:?}{reset} (seq={}, age={}s)",
        report.checkpoint.freshness,
        report.checkpoint.checkpoint_seq.unwrap_or(0),
        report.checkpoint.age_secs.unwrap_or(0)
    );
    if let Some(reason) = &report.checkpoint.reason {
        println!("                {dim}{reason}{reset}");
    }

    println!(
        "  Revocation:   {rev_color}{:?}{reset} (seq={}, age={}s)",
        report.revocation.freshness,
        report.revocation.head_seq.unwrap_or(0),
        report.revocation.age_secs.unwrap_or(0)
    );
    if let Some(reason) = &report.revocation.reason {
        println!("                {dim}{reason}{reset}");
    }

    println!(
        "  Audit:        {aud_color}{:?}{reset} (seq={}, coverage={:.0}%)",
        report.audit.freshness,
        report.audit.head_seq.unwrap_or(0),
        report.audit.coverage.unwrap_or(0.0) * 100.0
    );
    if let Some(reason) = &report.audit.reason {
        println!("                {dim}{reason}{reset}");
    }
    println!();

    // Transport Policy section
    println!("Transport Policy:");
    let lan_status = if report.transport_policy.allow_lan {
        format!("{green}enabled{reset}")
    } else {
        format!("{red}disabled{reset}")
    };
    let derp_status = if report.transport_policy.allow_derp {
        format!("{green}enabled{reset}")
    } else {
        format!("{yellow}disabled{reset}")
    };
    let funnel_status = if report.transport_policy.allow_funnel {
        format!("{green}enabled{reset}")
    } else {
        format!("{dim}disabled{reset}")
    };
    println!("  LAN:    {lan_status}");
    println!("  DERP:   {derp_status}");
    println!("  Funnel: {funnel_status}");
    println!();

    // Store Coverage section
    println!("Store Coverage:");
    let store_color = if report.store_coverage.store_healthy {
        green
    } else {
        red
    };
    let store_status = if report.store_coverage.store_healthy {
        "healthy"
    } else {
        "degraded"
    };
    println!("  Status:       {store_color}{store_status}{reset}");
    println!(
        "  Checkpoint:   {}%",
        report.store_coverage.checkpoint_coverage_bps.unwrap_or(0) / 100
    );
    println!(
        "  Policy:       {}%",
        report.store_coverage.policy_head_coverage_bps.unwrap_or(0) / 100
    );
    println!(
        "  Revocation:   {}%",
        report
            .store_coverage
            .revocation_head_coverage_bps
            .unwrap_or(0)
            / 100
    );
    if let Some(reason) = &report.store_coverage.reason {
        println!("                {dim}{reason}{reset}");
    }
    println!();

    // Degraded mode section (only if degraded)
    if report.degraded_mode.is_degraded {
        println!("{yellow}Degraded Mode:{reset}");
        for reason in &report.degraded_mode.reasons {
            println!(
                "  {yellow}⚠ [{}]{reset} {}",
                reason.code, reason.description
            );
        }
        if let Some(since) = report.degraded_mode.since {
            let duration = report.generated_at.timestamp() as u64 - since;
            println!("  {dim}Duration: {duration}s{reset}");
        }
        println!();
    }

    // Checks section
    if !report.checks.is_empty() {
        println!("Checks:");
        for check in &report.checks {
            let status_color = match check.status {
                types::CheckStatus::Ok => green,
                types::CheckStatus::Warn => yellow,
                types::CheckStatus::Fail => red,
            };
            let status_symbol = match check.status {
                types::CheckStatus::Ok => "✓",
                types::CheckStatus::Warn => "⚠",
                types::CheckStatus::Fail => "✗",
            };
            let code_suffix = check
                .reason_code
                .as_ref()
                .map_or(String::new(), |c| format!(" [{c}]"));
            println!(
                "  {status_color}{status_symbol} {}: {}{code_suffix}{reset}",
                check.name, check.message
            );
        }
        println!();
    }

    // Connector self-checks
    if !report.connector_self_checks.is_empty() {
        println!("Connector Self-Checks:");
        for check in &report.connector_self_checks {
            let (status_color, status_label) = match check.report.status {
                SelfCheckStatus::Ok => (green, "ok"),
                SelfCheckStatus::Degraded => (yellow, "degraded"),
                SelfCheckStatus::Failed => (red, "failed"),
                SelfCheckStatus::Unsupported => (dim, "unsupported"),
            };
            let reason = check
                .report
                .reason_code
                .as_deref()
                .map_or(String::new(), |code| format!(" [{code}]"));
            let message = check
                .report
                .message
                .as_deref()
                .map_or(String::new(), |msg| format!(" - {msg}"));
            println!(
                "  {status_color}{}{}:{reset} {}{}",
                status_label, reason, check.connector_id, message
            );
        }
        println!();
    }
}

const fn freshness_color(level: FreshnessLevel) -> &'static str {
    match level {
        FreshnessLevel::Fresh => "\x1b[32m",
        FreshnessLevel::Stale => "\x1b[33m",
        FreshnessLevel::TooStale | FreshnessLevel::Missing => "\x1b[31m",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- DoctorScenario ----

    #[test]
    fn scenario_default_is_healthy() {
        let s = DoctorScenario::default();
        assert!(matches!(s, DoctorScenario::Healthy));
    }

    #[test]
    fn scenario_debug() {
        let dbg = format!("{:?}", DoctorScenario::Critical);
        assert!(dbg.contains("Critical"));
    }

    #[test]
    fn scenario_clone_copy() {
        let s = DoctorScenario::Degraded;
        let cloned = s;
        assert!(matches!(cloned, DoctorScenario::Degraded));
    }

    // ---- build_doctor_url ----

    #[test]
    fn build_doctor_url_bare_origin() {
        let url = build_doctor_url("http://localhost:9090").unwrap();
        assert_eq!(url.path(), "/doctor");
        assert_eq!(url.host_str(), Some("localhost"));
    }

    #[test]
    fn build_doctor_url_with_trailing_slash() {
        let url = build_doctor_url("http://localhost:9090/").unwrap();
        assert_eq!(url.path(), "/doctor");
    }

    #[test]
    fn build_doctor_url_preserves_custom_path() {
        let url = build_doctor_url("http://mesh.local/v2/health").unwrap();
        assert_eq!(url.path(), "/v2/health");
    }

    #[test]
    fn build_doctor_url_invalid() {
        assert!(build_doctor_url("not a url").is_err());
    }

    // ---- parse_connector_ids ----

    #[test]
    fn parse_connector_ids_valid() {
        let ids = vec!["fcp.telegram:messaging:v1".to_string()];
        let parsed = parse_connector_ids(&ids).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].to_string(), "fcp.telegram:messaging:v1");
    }

    #[test]
    fn parse_connector_ids_multiple() {
        let ids = vec![
            "fcp.telegram:messaging:v1".to_string(),
            "fcp.slack:messaging:v1".to_string(),
        ];
        let parsed = parse_connector_ids(&ids).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parse_connector_ids_empty() {
        let ids: Vec<String> = vec![];
        let parsed = parse_connector_ids(&ids).unwrap();
        assert!(parsed.is_empty());
    }

    // ---- freshness_color ----

    #[test]
    fn freshness_color_fresh_is_green() {
        assert_eq!(freshness_color(FreshnessLevel::Fresh), "\x1b[32m");
    }

    #[test]
    fn freshness_color_stale_is_yellow() {
        assert_eq!(freshness_color(FreshnessLevel::Stale), "\x1b[33m");
    }

    #[test]
    fn freshness_color_too_stale_is_red() {
        assert_eq!(freshness_color(FreshnessLevel::TooStale), "\x1b[31m");
    }

    #[test]
    fn freshness_color_missing_is_red() {
        assert_eq!(freshness_color(FreshnessLevel::Missing), "\x1b[31m");
    }

    // ---- simulate_report scenarios ----

    #[test]
    fn simulate_healthy_report() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Healthy);
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert_eq!(report.zone_id, "z:test");
        assert!(!report.degraded_mode.is_degraded);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::Fresh);
        assert_eq!(report.revocation.freshness, FreshnessLevel::Fresh);
    }

    #[test]
    fn simulate_degraded_report() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Degraded);
        assert_eq!(report.overall_status, OverallStatus::Warn);
        assert!(report.degraded_mode.is_degraded);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::Stale);
    }

    #[test]
    fn simulate_stale_checkpoint_report() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::StaleCheckpoint);
        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::TooStale);
        assert!(report.degraded_mode.is_degraded);
    }

    #[test]
    fn simulate_stale_revocation_report() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::StaleRevocation);
        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert_eq!(report.revocation.freshness, FreshnessLevel::TooStale);
    }

    #[test]
    fn simulate_network_partition_report() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::NetworkPartition);
        assert_eq!(report.overall_status, OverallStatus::Warn);
        assert!(report.degraded_mode.is_degraded);
        assert!(report.degraded_mode.reasons.len() >= 2);
        assert!(!report.transport_policy.allow_derp);
    }

    #[test]
    fn simulate_low_coverage_report() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::LowCoverage);
        assert_eq!(report.overall_status, OverallStatus::Warn);
        assert!(!report.store_coverage.store_healthy);
    }

    #[test]
    fn simulate_critical_report() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Critical);
        assert_eq!(report.overall_status, OverallStatus::Fail);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::Missing);
        assert_eq!(report.revocation.freshness, FreshnessLevel::Missing);
        assert!(!report.transport_policy.allow_lan);
    }

    // ---- simulate_self_checks ----

    #[test]
    fn simulate_self_checks_healthy() {
        let connector: ConnectorId = "fcp.test:example:v1".parse().unwrap();
        let checks = simulate_self_checks(&[connector], DoctorScenario::Healthy);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].report.status, fcp_core::SelfCheckStatus::Ok);
    }

    #[test]
    fn simulate_self_checks_critical() {
        let connector: ConnectorId = "fcp.test:example:v1".parse().unwrap();
        let checks = simulate_self_checks(&[connector], DoctorScenario::Critical);
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].report.status, fcp_core::SelfCheckStatus::Failed);
    }

    #[test]
    fn simulate_self_checks_degraded_scenario() {
        let connector: ConnectorId = "fcp.test:example:v1".parse().unwrap();
        let checks = simulate_self_checks(&[connector], DoctorScenario::Degraded);
        assert_eq!(checks[0].report.status, fcp_core::SelfCheckStatus::Degraded);
    }

    #[test]
    fn simulate_self_checks_empty_connectors() {
        let checks = simulate_self_checks(&[], DoctorScenario::Healthy);
        assert!(checks.is_empty());
    }

    #[test]
    fn simulate_self_checks_multiple_connectors() {
        let connectors: Vec<ConnectorId> = vec![
            "fcp.test:a:v1".parse().unwrap(),
            "fcp.test:b:v1".parse().unwrap(),
        ];
        let checks = simulate_self_checks(&connectors, DoctorScenario::Healthy);
        assert_eq!(checks.len(), 2);
    }

    // ---- simulate_report with self_checks ----

    #[test]
    fn simulate_report_includes_self_checks() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let connector: ConnectorId = "fcp.test:example:v1".parse().unwrap();
        let report = simulate_report(&zone_id, &[connector], DoctorScenario::Healthy);
        assert_eq!(report.connector_self_checks.len(), 1);
    }

    #[test]
    fn simulate_report_no_self_checks_when_empty() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Healthy);
        assert!(report.connector_self_checks.is_empty());
    }

    // ---- DoctorReport JSON roundtrip ----

    #[test]
    fn simulate_report_json_roundtrip() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Healthy);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: types::DoctorReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.zone_id, "z:test");
        assert_eq!(parsed.overall_status, OverallStatus::Ok);
    }

    // ---- DoctorRequest serde ----

    #[test]
    fn doctor_request_serialize() {
        let req = DoctorRequest {
            zone_id: "z:work".to_string(),
            connectors: vec!["fcp.test:a:v1".to_string()],
            self_check: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"zone_id\":\"z:work\""));
        assert!(json.contains("\"self_check\":true"));
    }

    // ---- Report checks ----

    #[test]
    fn healthy_report_has_passing_checks() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Healthy);
        assert!(
            report
                .checks
                .iter()
                .all(|c| c.status == types::CheckStatus::Ok)
        );
    }

    #[test]
    fn degraded_report_has_warning_checks() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Degraded);
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.status == types::CheckStatus::Warn)
        );
    }

    #[test]
    fn critical_report_has_failing_checks() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Critical);
        assert!(
            report
                .checks
                .iter()
                .any(|c| c.status == types::CheckStatus::Fail)
        );
    }

    #[test]
    fn stale_checkpoint_has_reason_code() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::StaleCheckpoint);
        let failing_check = report
            .checks
            .iter()
            .find(|c| c.status == types::CheckStatus::Fail)
            .expect("should have a failing check");
        assert!(failing_check.reason_code.is_some());
    }

    // ---- Cross-scenario invariants ----

    #[test]
    fn all_scenarios_have_schema_version() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        for scenario in [
            DoctorScenario::Healthy,
            DoctorScenario::Degraded,
            DoctorScenario::StaleCheckpoint,
            DoctorScenario::StaleRevocation,
            DoctorScenario::NetworkPartition,
            DoctorScenario::LowCoverage,
            DoctorScenario::Critical,
        ] {
            let report = simulate_report(&zone_id, &[], scenario);
            assert_eq!(report.schema_version, "1.1.0", "scenario: {scenario:?}");
            assert_eq!(report.zone_id, "z:test", "scenario: {scenario:?}");
        }
    }

    #[test]
    fn all_scenarios_have_nonempty_checks() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        for scenario in [
            DoctorScenario::Healthy,
            DoctorScenario::Degraded,
            DoctorScenario::StaleCheckpoint,
            DoctorScenario::StaleRevocation,
            DoctorScenario::NetworkPartition,
            DoctorScenario::LowCoverage,
            DoctorScenario::Critical,
        ] {
            let report = simulate_report(&zone_id, &[], scenario);
            assert!(
                !report.checks.is_empty(),
                "scenario {scenario:?} has no checks"
            );
        }
    }

    // ---- Healthy scenario details ----

    #[test]
    fn healthy_report_store_is_healthy() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Healthy);
        assert!(report.store_coverage.store_healthy);
        assert_eq!(report.store_coverage.checkpoint_coverage_bps, Some(10000));
    }

    #[test]
    fn healthy_report_transport_allows_lan_and_derp() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Healthy);
        assert!(report.transport_policy.allow_lan);
        assert!(report.transport_policy.allow_derp);
        assert!(!report.transport_policy.allow_funnel);
    }

    // ---- Degraded scenario details ----

    #[test]
    fn degraded_report_has_since_timestamp() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Degraded);
        assert!(report.degraded_mode.since.is_some());
    }

    #[test]
    fn degraded_report_has_reason_code_fcp_5001() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Degraded);
        assert!(
            report
                .degraded_mode
                .reasons
                .iter()
                .any(|r| r.code == "FCP-5001")
        );
    }

    // ---- Critical scenario details ----

    #[test]
    fn critical_report_all_transport_disabled() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Critical);
        assert!(!report.transport_policy.allow_lan);
        assert!(!report.transport_policy.allow_derp);
        assert!(!report.transport_policy.allow_funnel);
    }

    #[test]
    fn critical_report_store_unhealthy() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Critical);
        assert!(!report.store_coverage.store_healthy);
        assert_eq!(report.store_coverage.checkpoint_coverage_bps, Some(0));
    }

    #[test]
    fn critical_report_all_missing() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Critical);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::Missing);
        assert_eq!(report.revocation.freshness, FreshnessLevel::Missing);
        assert_eq!(report.audit.freshness, FreshnessLevel::Missing);
    }

    #[test]
    fn critical_report_multiple_degraded_reasons() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::Critical);
        assert!(report.degraded_mode.reasons.len() >= 2);
    }

    // ---- Stale revocation details ----

    #[test]
    fn stale_revocation_has_high_age() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::StaleRevocation);
        assert!(report.revocation.age_secs.unwrap() >= 7200);
    }

    #[test]
    fn stale_revocation_has_reason_code_fcp_5003() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::StaleRevocation);
        let check = report
            .checks
            .iter()
            .find(|c| c.status == types::CheckStatus::Fail)
            .expect("should have failing check");
        assert_eq!(check.reason_code.as_deref(), Some("FCP-5003"));
    }

    // ---- Network partition details ----

    #[test]
    fn network_partition_low_store_coverage() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::NetworkPartition);
        assert!(report.store_coverage.checkpoint_coverage_bps.unwrap() < 5000);
        assert!(!report.store_coverage.store_healthy);
    }

    #[test]
    fn network_partition_multiple_reasons() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::NetworkPartition);
        assert!(report.degraded_mode.reasons.len() >= 2);
        assert!(
            report
                .degraded_mode
                .reasons
                .iter()
                .any(|r| r.code == "FCP-6001")
        );
        assert!(
            report
                .degraded_mode
                .reasons
                .iter()
                .any(|r| r.code == "FCP-6002")
        );
    }

    // ---- Low coverage details ----

    #[test]
    fn low_coverage_fresh_heads_but_unhealthy_store() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        let report = simulate_report(&zone_id, &[], DoctorScenario::LowCoverage);
        assert_eq!(report.checkpoint.freshness, FreshnessLevel::Fresh);
        assert_eq!(report.revocation.freshness, FreshnessLevel::Fresh);
        assert!(!report.store_coverage.store_healthy);
    }

    // ---- Self-check connector_id ----

    #[test]
    fn self_check_preserves_connector_id() {
        let connector: ConnectorId = "fcp.test:check:v1".parse().unwrap();
        let checks =
            simulate_self_checks(std::slice::from_ref(&connector), DoctorScenario::Healthy);
        assert_eq!(checks[0].connector_id, connector.to_string());
    }

    #[test]
    fn self_check_all_degraded_scenarios_produce_degraded() {
        let connector: ConnectorId = "fcp.test:check:v1".parse().unwrap();
        for scenario in [
            DoctorScenario::Degraded,
            DoctorScenario::LowCoverage,
            DoctorScenario::NetworkPartition,
            DoctorScenario::StaleCheckpoint,
            DoctorScenario::StaleRevocation,
        ] {
            let checks = simulate_self_checks(std::slice::from_ref(&connector), scenario);
            assert_eq!(
                checks[0].report.status,
                fcp_core::SelfCheckStatus::Degraded,
                "scenario {scenario:?}"
            );
        }
    }

    // ---- DoctorScenario all variants ----

    #[test]
    fn all_scenario_variants_debug() {
        let variants = [
            DoctorScenario::Healthy,
            DoctorScenario::Degraded,
            DoctorScenario::StaleCheckpoint,
            DoctorScenario::StaleRevocation,
            DoctorScenario::NetworkPartition,
            DoctorScenario::LowCoverage,
            DoctorScenario::Critical,
        ];
        for v in variants {
            let dbg = format!("{v:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ---- Report JSON roundtrips per scenario ----

    #[test]
    fn all_scenarios_json_roundtrip() {
        let zone_id: ZoneId = "z:test".parse().unwrap();
        for scenario in [
            DoctorScenario::Healthy,
            DoctorScenario::Degraded,
            DoctorScenario::StaleCheckpoint,
            DoctorScenario::StaleRevocation,
            DoctorScenario::NetworkPartition,
            DoctorScenario::LowCoverage,
            DoctorScenario::Critical,
        ] {
            let report = simulate_report(&zone_id, &[], scenario);
            let json = serde_json::to_string(&report).unwrap();
            let back: types::DoctorReport = serde_json::from_str(&json).unwrap();
            assert_eq!(back.zone_id, "z:test", "roundtrip failed for {scenario:?}");
            assert_eq!(
                back.overall_status, report.overall_status,
                "status mismatch for {scenario:?}"
            );
        }
    }
}
