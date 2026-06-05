//! Operator-facing swarm evidence exploration.
//!
//! Explore and replay intentionally read replayable JSONL artifacts offline.
//! Pressure is read-only but may sample local OS state, coordination status, rch
//! status, and an operator-provided host admin endpoint.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use clap::{Args, Subcommand};
use reqwest::blocking::{Client as BlockingClient, ClientBuilder as BlockingClientBuilder};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

/// Arguments for `fwc swarm-evidence`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct SwarmEvidenceArgs {
    #[command(subcommand)]
    pub command: SwarmEvidenceCommand,
}

/// Swarm evidence subcommands.
#[derive(Subcommand, Debug, Clone, Serialize)]
pub enum SwarmEvidenceCommand {
    /// List and filter swarm decision cards from a JSONL evidence bundle.
    Explore(SwarmEvidenceExploreArgs),
    /// Render stored decision-card replay details without live services.
    Replay(SwarmEvidenceReplayArgs),
    /// Forecast local swarm pressure using redaction-safe signals.
    Pressure(SwarmPressureArgs),
}

/// Common redaction-safe filters for decision cards.
#[derive(Args, Debug, Clone, Default, Serialize)]
pub struct SwarmEvidenceFilters {
    /// Match a zone string anywhere inside the decision-card record.
    #[arg(long)]
    pub zone: Option<String>,

    /// Match a connector string anywhere inside the decision-card record.
    #[arg(long)]
    pub connector: Option<String>,

    /// Match a principal string anywhere inside the decision-card record.
    #[arg(long)]
    pub principal: Option<String>,

    /// Match the card scenario id or any scenario string in the record.
    #[arg(long)]
    pub scenario: Option<String>,

    /// Match a correlation id string anywhere inside the decision-card record.
    #[arg(long = "correlation-id")]
    pub correlation_id: Option<String>,

    /// Match the selected action, for example `admit`, `delay`, or `fallback`.
    #[arg(long)]
    pub action: Option<String>,

    /// Match the fallback reason attached to the decision card.
    #[arg(long = "fallback-reason")]
    pub fallback_reason: Option<String>,

    /// Match the dominant loss-term name.
    #[arg(long = "dominant-loss-term")]
    pub dominant_loss_term: Option<String>,
}

/// Arguments for `fwc swarm-evidence explore`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct SwarmEvidenceExploreArgs {
    /// JSONL evidence bundle or log to inspect.
    pub file: PathBuf,

    #[command(flatten)]
    pub filters: SwarmEvidenceFilters,

    /// Maximum decision-card entries to return.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,

    /// Number of filtered entries to skip.
    #[arg(long, default_value_t = 0)]
    pub offset: usize,
}

/// Arguments for `fwc swarm-evidence replay`.
#[derive(Args, Debug, Clone, Serialize)]
pub struct SwarmEvidenceReplayArgs {
    /// JSONL evidence bundle or log to inspect.
    pub file: PathBuf,

    /// Restrict replay rendering to one or more decision-card ids.
    #[arg(long = "card-id")]
    pub card_ids: Vec<String>,

    #[command(flatten)]
    pub filters: SwarmEvidenceFilters,

    /// Maximum decision-card entries to return.
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
}

/// Arguments for `fwc swarm pressure`.
#[derive(Args, Debug, Clone, Default, Serialize)]
pub struct SwarmPressureArgs {
    /// Optional JSON fixture containing deterministic pressure inputs.
    #[arg(long, value_name = "PATH")]
    pub fixture: Option<PathBuf>,

    /// Override detected logical CPU count for deterministic checks.
    #[arg(long = "logical-cpus")]
    pub logical_cpus: Option<usize>,

    /// Active agent count from Beads/Agent Mail or a caller-provided snapshot.
    #[arg(long = "active-agents")]
    pub active_agents: Option<usize>,

    /// Active connector process count from host/admin evidence.
    #[arg(long = "active-connectors")]
    pub active_connectors: Option<usize>,

    /// Optional fcp-host endpoint for live connector lifecycle pressure.
    #[arg(long = "host", value_name = "ENDPOINT")]
    pub host: Option<String>,

    /// Current disk free percentage for the working volume.
    #[arg(long = "disk-free-percent")]
    pub disk_free_percent: Option<u8>,

    /// Current inode free percentage for the working volume.
    #[arg(long = "inode-free-percent")]
    pub inode_free_percent: Option<u8>,

    /// Current memory free percentage for the host.
    #[arg(long = "memory-free-percent")]
    pub memory_free_percent: Option<u8>,

    /// Queued or waiting rch jobs from a caller-provided `rch status --json` snapshot.
    #[arg(long = "rch-queued-jobs")]
    pub rch_queued_jobs: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct SwarmPressureFixture {
    #[serde(default)]
    logical_cpus: Option<usize>,
    #[serde(default)]
    active_agents: Option<usize>,
    #[serde(default)]
    active_connectors: Option<usize>,
    #[serde(default)]
    disk_free_percent: Option<u8>,
    #[serde(default)]
    inode_free_percent: Option<u8>,
    #[serde(default)]
    memory_free_percent: Option<u8>,
    #[serde(default)]
    rch_queued_jobs: Option<usize>,
    #[serde(default)]
    signals: Vec<SwarmPressureSignal>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SwarmPressureStatus {
    Green,
    Yellow,
    Red,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SwarmPressureSignal {
    name: String,
    status: SwarmPressureStatus,
    value: String,
    threshold: String,
    #[serde(default)]
    evidence: Value,
}

#[derive(Debug, Clone)]
struct SwarmPressureInputs {
    fixture_path: Option<PathBuf>,
    logical_cpus: usize,
    active_agents: Option<AgentPressureInput>,
    active_connectors: Option<ConnectorPressureInput>,
    disk_free: Option<PercentPressureInput>,
    inode_free: Option<PercentPressureInput>,
    memory_free: Option<PercentPressureInput>,
    rch_status: Option<RchPressureInput>,
    signals: Vec<SwarmPressureSignal>,
}

#[derive(Debug, Clone)]
struct PercentPressureInput {
    percent: u8,
    evidence: Value,
}

#[derive(Debug, Clone)]
struct AgentPressureInput {
    active_agents: usize,
    warning_count: usize,
    evidence: Value,
}

#[derive(Debug, Clone)]
struct BeadsPressureInput {
    in_progress_count: usize,
    unique_assignee_count: usize,
    unassigned_count: usize,
    evidence: Value,
}

#[derive(Debug, Clone)]
struct AgentMailPressureInput {
    active_agents: usize,
    warning_count: usize,
    evidence: Value,
}

#[derive(Debug, Clone)]
struct ConnectorPressureInput {
    active_connectors: usize,
    warning_count: usize,
    evidence: Value,
}

#[derive(Debug, Clone)]
struct RchPressureInput {
    queued_jobs: usize,
    active_builds: usize,
    warning_count: usize,
    evidence: Value,
}

#[derive(Debug, Clone, Default)]
struct LocalPressureSamples {
    disk_free: Option<PercentPressureInput>,
    inode_free: Option<PercentPressureInput>,
    memory_free: Option<PercentPressureInput>,
    active_connectors: Option<ConnectorPressureInput>,
    active_agents: Option<AgentPressureInput>,
    rch_status: Option<RchPressureInput>,
}

#[derive(Debug, Clone)]
struct JsonlRecord {
    line: usize,
    value: Value,
}

#[derive(Debug, Clone)]
struct DecisionCardEntry {
    line: usize,
    card_id: String,
    scenario_id: Option<String>,
    domain: Option<String>,
    subject: Option<String>,
    action: Option<String>,
    state: Option<String>,
    calibration: Option<String>,
    fallback_active: bool,
    fallback_action: Option<String>,
    fallback_reason: Option<String>,
    counterfactual_action: Option<String>,
    counterfactual_reason: Option<String>,
    dominant_loss_term: Option<Value>,
    evidence_handles: Vec<Value>,
    replayable_offline: bool,
    raw_record: Value,
}

pub fn run_with_host(args: &SwarmEvidenceArgs, explicit_host: Option<&str>) -> Result<Value> {
    match &args.command {
        SwarmEvidenceCommand::Explore(args) => explore(args),
        SwarmEvidenceCommand::Replay(args) => replay(args),
        SwarmEvidenceCommand::Pressure(args) => pressure_with_host(args, explicit_host),
    }
}

fn explore(args: &SwarmEvidenceExploreArgs) -> Result<Value> {
    let records = load_jsonl_records(&args.file)?;
    let entries = filtered_entries(&records, &args.filters, &[])?;
    let total_filtered = entries.len();
    let page = entries
        .iter()
        .skip(args.offset)
        .take(args.limit)
        .map(entry_summary)
        .collect::<Vec<_>>();
    let reports = report_links(&records);

    let mut payload = json!({
        "status": "ok",
        "command": "swarm-evidence explore",
        "source": &args.file,
        "summary": bundle_summary(&records, total_filtered),
        "filters": serde_json::to_value(&args.filters)?,
        "pagination": {
            "offset": args.offset,
            "limit": args.limit,
            "returned": page.len(),
            "total_filtered": total_filtered,
            "has_more": args.offset.saturating_add(page.len()) < total_filtered,
        },
        "entries": page,
        "reports": reports,
        "message": format!(
            "Loaded {} swarm decision card(s) from `{}`.",
            total_filtered,
            args.file.display()
        ),
        "next_actions": [
            "Use `fwc swarm-evidence replay <file> --card-id <id>` to inspect exact stored decisions.",
            "Use `--format json` for structured decision-card records and evidence pointers.",
        ],
    });
    let toon = format_explore_toon(&payload);
    insert_toon(&mut payload, toon);
    Ok(payload)
}

fn replay(args: &SwarmEvidenceReplayArgs) -> Result<Value> {
    let records = load_jsonl_records(&args.file)?;
    let mut entries = filtered_entries(&records, &args.filters, &args.card_ids)?;
    let total_filtered = entries.len();
    entries.truncate(args.limit);
    let replays = entries.iter().map(replay_summary).collect::<Vec<_>>();

    let mut payload = json!({
        "status": "ok",
        "command": "swarm-evidence replay",
        "source": &args.file,
        "summary": bundle_summary(&records, total_filtered),
        "filters": serde_json::to_value(&args.filters)?,
        "card_ids": &args.card_ids,
        "pagination": {
            "offset": 0,
            "limit": args.limit,
            "returned": replays.len(),
            "total_filtered": total_filtered,
            "has_more": replays.len() < total_filtered,
        },
        "entries": replays,
        "message": format!(
            "Rendered {} stored swarm decision card(s) from `{}`.",
            entries.len(),
            args.file.display()
        ),
        "replay_boundary": "Offline replay renders stored decision-card inputs, action, fallback, counterfactual, and evidence pointers; it does not call live services or recompute host state.",
    });
    let toon = format_replay_toon(&payload);
    insert_toon(&mut payload, toon);
    Ok(payload)
}

pub fn pressure_with_host(args: &SwarmPressureArgs, explicit_host: Option<&str>) -> Result<Value> {
    let inputs = pressure_inputs(args, explicit_host)?;
    let signals = pressure_signals(&inputs);
    let score = pressure_score(&signals);
    let verdict = pressure_verdict(&signals);
    let degraded_dependency_count = signals
        .iter()
        .filter(|signal| signal.status == SwarmPressureStatus::Degraded)
        .count();
    let recommended_agent_slots = recommended_agent_slots(
        verdict,
        inputs.logical_cpus,
        inputs
            .active_agents
            .as_ref()
            .map(|input| input.active_agents),
    );
    let recommended_cargo_lanes = recommended_cargo_lanes(verdict, inputs.logical_cpus);
    let remediation_commands = remediation_commands(&signals);

    let mut payload = json!({
        "status": "ok",
        "command": "swarm pressure",
        "schema_version": "fwc.swarm-pressure/v1",
        "generated_at": Utc::now().to_rfc3339(),
        "source": {
            "fixture": inputs.fixture_path.as_ref().map(|path| path.display().to_string()),
            "mode": if inputs.fixture_path.is_some() { "fixture" } else { "local-with-degraded-dependencies" },
            "caveat": "This command is read-only. Missing live dependencies are represented as degraded signals; live probes are limited to local OS state, coordination status, rch status, and an optional fcp-host admin endpoint. It never starts Cargo work, repairs Agent Mail, or contacts external providers.",
        },
        "pressure_score_0_100": score,
        "verdict": verdict,
        "signals": signals,
        "recommended_agent_slots": recommended_agent_slots,
        "recommended_cargo_lanes": recommended_cargo_lanes,
        "remediation_commands": remediation_commands,
        "telemetry_event": {
            "name": "fwc.swarm_pressure.run",
            "fields": {
                "verdict": verdict,
                "pressure_score": score,
                "degraded_dependency_count": degraded_dependency_count,
                "recommended_agent_slots": recommended_agent_slots,
            }
        },
        "message": format!(
            "Swarm pressure is {verdict:?} with score {score}/100; {degraded_dependency_count} signal(s) are degraded."
        ),
    });
    let toon = format_pressure_toon(&payload);
    insert_toon(&mut payload, toon);
    Ok(payload)
}

fn pressure_inputs(
    args: &SwarmPressureArgs,
    explicit_host: Option<&str>,
) -> Result<SwarmPressureInputs> {
    let fixture = match &args.fixture {
        Some(path) => load_pressure_fixture(path)?,
        None => SwarmPressureFixture::default(),
    };
    let local_samples = if args.fixture.is_some() {
        LocalPressureSamples::default()
    } else {
        collect_local_pressure_samples(resolve_pressure_host(args, explicit_host).as_deref())
    };
    let logical_cpus = args
        .logical_cpus
        .or(fixture.logical_cpus)
        .unwrap_or_else(available_logical_cpus);
    let disk_free = args
        .disk_free_percent
        .map(|percent| provided_percent_input(percent, "cli-argument"))
        .or_else(|| {
            fixture
                .disk_free_percent
                .map(|percent| provided_percent_input(percent, "fixture"))
        })
        .or(local_samples.disk_free);
    let inode_free = args
        .inode_free_percent
        .map(|percent| provided_percent_input(percent, "cli-argument"))
        .or_else(|| {
            fixture
                .inode_free_percent
                .map(|percent| provided_percent_input(percent, "fixture"))
        })
        .or(local_samples.inode_free);
    let memory_free = args
        .memory_free_percent
        .map(|percent| provided_percent_input(percent, "cli-argument"))
        .or_else(|| {
            fixture
                .memory_free_percent
                .map(|percent| provided_percent_input(percent, "fixture"))
        })
        .or(local_samples.memory_free);
    let rch_status = args
        .rch_queued_jobs
        .map(|queued_jobs| provided_rch_input(queued_jobs, "cli-argument"))
        .or_else(|| {
            fixture
                .rch_queued_jobs
                .map(|queued_jobs| provided_rch_input(queued_jobs, "fixture"))
        })
        .or(local_samples.rch_status);
    let active_agents = args
        .active_agents
        .map(|active_agents| provided_agent_input(active_agents, "cli-argument"))
        .or_else(|| {
            fixture
                .active_agents
                .map(|active_agents| provided_agent_input(active_agents, "fixture"))
        })
        .or(local_samples.active_agents);
    let active_connectors = args
        .active_connectors
        .map(|active_connectors| provided_connector_input(active_connectors, "cli-argument"))
        .or_else(|| {
            fixture
                .active_connectors
                .map(|active_connectors| provided_connector_input(active_connectors, "fixture"))
        })
        .or(local_samples.active_connectors);

    Ok(SwarmPressureInputs {
        fixture_path: args.fixture.clone(),
        logical_cpus,
        active_agents,
        active_connectors,
        disk_free,
        inode_free,
        memory_free,
        rch_status,
        signals: fixture.signals,
    })
}

fn load_pressure_fixture(path: &Path) -> Result<SwarmPressureFixture> {
    let file = File::open(path)
        .with_context(|| format!("failed to open swarm pressure fixture `{}`", path.display()))?;
    serde_json::from_reader(file).with_context(|| {
        format!(
            "failed to parse swarm pressure fixture `{}`",
            path.display()
        )
    })
}

fn available_logical_cpus() -> usize {
    thread::available_parallelism().map_or(1, usize::from)
}

fn collect_local_pressure_samples(host: Option<&str>) -> LocalPressureSamples {
    LocalPressureSamples {
        disk_free: disk_free_sample(),
        inode_free: inode_free_sample(),
        memory_free: memory_free_sample(),
        active_connectors: host.and_then(host_connector_lifecycle_sample),
        active_agents: coordination_active_agents_sample(),
        rch_status: rch_status_sample(),
    }
}

fn resolve_pressure_host(args: &SwarmPressureArgs, explicit_host: Option<&str>) -> Option<String> {
    args.host
        .as_deref()
        .or(explicit_host)
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            ["FWC_HOST", "FCP_HOST_ENDPOINT", "FCP_HOST_BIND"]
                .into_iter()
                .find_map(|env_name| {
                    std::env::var(env_name)
                        .ok()
                        .map(|value| value.trim().to_owned())
                        .filter(|value| !value.is_empty())
                })
        })
}

fn provided_percent_input(percent: u8, source: &str) -> PercentPressureInput {
    PercentPressureInput {
        percent,
        evidence: json!({
            "source": source,
            "live": false,
        }),
    }
}

fn provided_agent_input(active_agents: usize, source: &str) -> AgentPressureInput {
    AgentPressureInput {
        active_agents,
        warning_count: 0,
        evidence: json!({
            "source": source,
            "live": false,
            "agent_mail_repair_attempted": false,
            "agent_mail_service_restart_attempted": false,
            "agent_mail_process_signal_attempted": false,
        }),
    }
}

fn provided_connector_input(active_connectors: usize, source: &str) -> ConnectorPressureInput {
    ConnectorPressureInput {
        active_connectors,
        warning_count: 0,
        evidence: json!({
            "source": source,
            "live": false,
            "host_contacted": false,
        }),
    }
}

const HOST_CONNECTOR_SAMPLE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
struct PressureHostClient {
    client: BlockingClient,
    base_url: String,
}

impl PressureHostClient {
    fn new(endpoint: &str) -> Result<Self> {
        let endpoint = normalize_pressure_host_endpoint(endpoint)?;

        #[cfg(unix)]
        {
            if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
                let socket_path = endpoint.strip_prefix("unix://").unwrap_or(&endpoint);
                let client = BlockingClientBuilder::new()
                    .timeout(HOST_CONNECTOR_SAMPLE_TIMEOUT)
                    .unix_socket(socket_path)
                    .build()
                    .context("failed to build Unix-socket pressure host client")?;
                return Ok(Self {
                    client,
                    base_url: "http://localhost".to_owned(),
                });
            }
        }

        let client = BlockingClientBuilder::new()
            .timeout(HOST_CONNECTOR_SAMPLE_TIMEOUT)
            .build()
            .context("failed to build pressure host client")?;
        Ok(Self {
            client,
            base_url: endpoint,
        })
    }

    fn get_json(&self, path: &str) -> Result<Value> {
        let response = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .context("host GET request failed")?;
        json_response(response)
    }

    fn post_json(&self, path: &str, body: &Value) -> Result<Value> {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .context("host POST request failed")?;
        json_response(response)
    }
}

fn json_response(response: reqwest::blocking::Response) -> Result<Value> {
    let status = response.status();
    if !status.is_success() {
        bail!("host returned non-success status");
    }
    response
        .json::<Value>()
        .context("host returned invalid JSON")
}

fn normalize_pressure_host_endpoint(endpoint: &str) -> Result<String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        bail!("host endpoint cannot be empty");
    }
    if endpoint.contains("://")
        && !(endpoint.starts_with("http://")
            || endpoint.starts_with("https://")
            || endpoint.starts_with("tcp://")
            || endpoint.starts_with("unix://"))
    {
        bail!("host endpoint must use http, https, tcp, unix, or an absolute Unix socket path");
    }

    #[cfg(unix)]
    if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
        let socket_path = endpoint.strip_prefix("unix://").unwrap_or(endpoint);
        if socket_path.trim().is_empty() {
            bail!("Unix host endpoint must include a socket path");
        }
        return Ok(endpoint.to_owned());
    }

    let normalized = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_owned()
    } else {
        let stripped = endpoint.strip_prefix("tcp://").unwrap_or(endpoint);
        format!("http://{stripped}")
    };
    let url =
        Url::parse(&normalized).with_context(|| format!("invalid host endpoint `{endpoint}`"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("host endpoint must use http, https, tcp, unix, or an absolute Unix socket path");
    }
    if url.host_str().is_none() {
        bail!("host endpoint must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("host endpoint must not include username or password components");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("host endpoint must not include query or fragment components");
    }
    Ok(normalized.trim_end_matches('/').to_owned())
}

fn host_connector_lifecycle_sample(endpoint: &str) -> Option<ConnectorPressureInput> {
    let client = match PressureHostClient::new(endpoint) {
        Ok(client) => client,
        Err(_) => return Some(host_connector_unavailable_sample("invalid_endpoint")),
    };
    let discover = match client.post_json("/rpc/discover", &json!({ "filter": null })) {
        Ok(discover) => discover,
        Err(_) => return Some(host_connector_unavailable_sample("discover_unavailable")),
    };
    let (health, transport_warning_count) = match client.get_json("/rpc/health") {
        Ok(health) => (Some(health), 0),
        Err(_) => (None, 1),
    };
    Some(connector_pressure_from_host_values(
        &discover,
        health.as_ref(),
        transport_warning_count,
    ))
}

fn host_connector_unavailable_sample(reason: &str) -> ConnectorPressureInput {
    ConnectorPressureInput {
        active_connectors: 0,
        warning_count: 1,
        evidence: json!({
            "source": "host-admin-api",
            "live": false,
            "host_contacted": false,
            "status": reason,
            "active_connectors": 0,
            "warning_count": 1,
        }),
    }
}

fn connector_pressure_from_host_values(
    discover: &Value,
    health: Option<&Value>,
    transport_warning_count: usize,
) -> ConnectorPressureInput {
    let connectors = discover
        .get("connectors")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let mut active_connectors = 0_usize;
    let mut enabled_connectors = 0_usize;
    let mut unhealthy_enabled_connectors = 0_usize;
    let mut warning_count = transport_warning_count;

    for connector in connectors {
        let enabled = connector
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !enabled {
            continue;
        }
        enabled_connectors = enabled_connectors.saturating_add(1);
        let health_state = connector_health_state(connector);
        if !matches!(
            health_state.as_deref(),
            Some("unavailable" | "error" | "stopped" | "missing")
        ) {
            active_connectors = active_connectors.saturating_add(1);
        }
        if !matches!(health_state.as_deref(), Some("healthy")) {
            unhealthy_enabled_connectors = unhealthy_enabled_connectors.saturating_add(1);
        }
    }

    warning_count = warning_count.saturating_add(unhealthy_enabled_connectors);
    let host_health = health
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str);
    if host_health.is_some_and(|status| status != "healthy") {
        warning_count = warning_count.saturating_add(1);
    }

    ConnectorPressureInput {
        active_connectors,
        warning_count,
        evidence: json!({
            "source": "host-admin-api",
            "live": true,
            "host_contacted": true,
            "method": "POST /rpc/discover + GET /rpc/health",
            "connector_count": connectors.len(),
            "enabled_connectors": enabled_connectors,
            "active_connectors": active_connectors,
            "unhealthy_enabled_connectors": unhealthy_enabled_connectors,
            "host_health": host_health,
            "registry_version": discover.get("registry_version").and_then(Value::as_u64),
            "health_unavailable": health.is_none(),
            "warning_count": warning_count,
        }),
    }
}

fn connector_health_state(connector: &Value) -> Option<String> {
    connector
        .pointer("/health/status")
        .and_then(Value::as_str)
        .or_else(|| connector.pointer("/health/state").and_then(Value::as_str))
        .or_else(|| connector.get("health").and_then(Value::as_str))
        .map(str::to_ascii_lowercase)
}

fn provided_rch_input(queued_jobs: usize, source: &str) -> RchPressureInput {
    RchPressureInput {
        queued_jobs,
        active_builds: 0,
        warning_count: 0,
        evidence: json!({
            "source": source,
            "live": false,
            "rch_invoked": false,
        }),
    }
}

fn disk_free_sample() -> Option<PercentPressureInput> {
    let output = Command::new("df").args(["-Pk", "."]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = std::str::from_utf8(&output.stdout).ok()?;
    let sample = parse_df_disk_sample(stdout)?;
    Some(PercentPressureInput {
        percent: sample.free_percent,
        evidence: json!({
            "source": "local-os",
            "live": true,
            "method": "df -Pk .",
            "path": ".",
            "available_bytes": sample.available,
            "total_bytes": sample.total,
        }),
    })
}

fn inode_free_sample() -> Option<PercentPressureInput> {
    let output = Command::new("df").args(["-Pi", "."]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = std::str::from_utf8(&output.stdout).ok()?;
    let sample = parse_df_inode_sample(stdout)?;
    Some(PercentPressureInput {
        percent: sample.free_percent,
        evidence: json!({
            "source": "local-os",
            "live": true,
            "method": "df -Pi .",
            "path": ".",
            "available_inodes": sample.available,
            "total_inodes": sample.total,
        }),
    })
}

fn rch_status_sample() -> Option<RchPressureInput> {
    let output = Command::new("rch")
        .args(["status", "--json"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = std::str::from_utf8(&output.stdout).ok()?;
    rch_status_sample_from_json(stdout)
}

fn coordination_active_agents_sample() -> Option<AgentPressureInput> {
    let beads = beads_in_progress_sample();
    let agent_mail = agent_mail_status_sample();
    coordination_active_agents_from_samples(beads.as_ref(), agent_mail.as_ref())
}

fn beads_in_progress_sample() -> Option<BeadsPressureInput> {
    let output = Command::new("br")
        .args([
            "list",
            "--status",
            "in_progress",
            "--json",
            "--limit",
            "0",
            "--no-auto-flush",
            "--no-auto-import",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = std::str::from_utf8(&output.stdout).ok()?;
    beads_in_progress_sample_from_json(stdout)
}

fn agent_mail_status_sample() -> Option<AgentMailPressureInput> {
    let output = Command::new("am")
        .args(["status", "--json"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = std::str::from_utf8(&output.stdout).ok()?;
    agent_mail_status_sample_from_json(stdout)
}

fn coordination_active_agents_from_samples(
    beads: Option<&BeadsPressureInput>,
    agent_mail: Option<&AgentMailPressureInput>,
) -> Option<AgentPressureInput> {
    if beads.is_none() && agent_mail.is_none() {
        return None;
    }

    let beads_active_estimate = beads
        .map(|input| {
            input
                .unique_assignee_count
                .saturating_add(input.unassigned_count)
        })
        .unwrap_or(0);
    let agent_mail_active = agent_mail.map_or(0, |input| input.active_agents);
    let active_agents = beads_active_estimate.max(agent_mail_active);
    let mut missing_sources = Vec::new();
    if beads.is_none() {
        missing_sources.push("beads");
    }
    if agent_mail.is_none() {
        missing_sources.push("agent_mail");
    }
    let warning_count = missing_sources.len() + agent_mail.map_or(0, |input| input.warning_count);

    Some(AgentPressureInput {
        active_agents,
        warning_count,
        evidence: json!({
            "source": "coordination",
            "live": true,
            "active_agents": active_agents,
            "warning_count": warning_count,
            "beads_in_progress_count": beads.map(|input| input.in_progress_count),
            "missing_sources": missing_sources,
            "beads": beads.map(|input| input.evidence.clone()),
            "agent_mail": agent_mail.map(|input| input.evidence.clone()),
            "agent_mail_repair_attempted": false,
            "agent_mail_service_restart_attempted": false,
            "agent_mail_process_signal_attempted": false,
        }),
    })
}

fn beads_in_progress_sample_from_json(stdout: &str) -> Option<BeadsPressureInput> {
    let value = serde_json::from_str::<Value>(stdout).ok()?;
    let issues = value
        .get("issues")
        .and_then(Value::as_array)
        .or_else(|| value.as_array())?;
    let mut assignees = BTreeSet::new();
    let mut in_progress_count = 0_usize;
    let mut unassigned_count = 0_usize;

    for issue in issues {
        if issue
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status != "in_progress")
        {
            continue;
        }
        in_progress_count = in_progress_count.saturating_add(1);
        match issue
            .get("assignee")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|assignee| !assignee.is_empty())
        {
            Some(assignee) => {
                assignees.insert(assignee.to_owned());
            }
            None => {
                unassigned_count = unassigned_count.saturating_add(1);
            }
        }
    }

    Some(BeadsPressureInput {
        in_progress_count,
        unique_assignee_count: assignees.len(),
        unassigned_count,
        evidence: json!({
            "source": "beads",
            "live": true,
            "method": "br list --status in_progress --json --limit 0 --no-auto-flush --no-auto-import",
            "in_progress_count": in_progress_count,
            "unique_assignee_count": assignees.len(),
            "unassigned_count": unassigned_count,
        }),
    })
}

fn agent_mail_status_sample_from_json(stdout: &str) -> Option<AgentMailPressureInput> {
    let value = serde_json::from_str::<Value>(stdout).ok()?;
    let active_agents = value
        .get("active_agents")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())?;
    let health = value.get("health").and_then(Value::as_str);
    let health_warning = health.is_some_and(|status| !matches!(status, "ok" | "healthy"));
    let recovery_mode = value.pointer("/recovery/mode").and_then(Value::as_str);
    let warning_count = usize::from(health_warning);

    Some(AgentMailPressureInput {
        active_agents,
        warning_count,
        evidence: json!({
            "source": "agent-mail",
            "live": true,
            "method": "am status --json",
            "active_agents": active_agents,
            "health": health,
            "recovery_mode": recovery_mode,
            "warning_count": warning_count,
            "agent_mail_repair_attempted": false,
            "agent_mail_service_restart_attempted": false,
            "agent_mail_process_signal_attempted": false,
        }),
    })
}

#[cfg(target_os = "linux")]
fn memory_free_sample() -> Option<PercentPressureInput> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    linux_memory_sample_from_meminfo(&content)
}

#[cfg(target_os = "macos")]
fn memory_free_sample() -> Option<PercentPressureInput> {
    let total_output = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    if !total_output.status.success() {
        return None;
    }
    let total_stdout = std::str::from_utf8(&total_output.stdout).ok()?;
    let total_bytes = total_stdout.trim().parse::<u64>().ok()?;

    let vm_stat_output = Command::new("vm_stat").output().ok()?;
    if !vm_stat_output.status.success() {
        return None;
    }
    let vm_stat_stdout = std::str::from_utf8(&vm_stat_output.stdout).ok()?;
    macos_memory_sample_from_vm_stat(total_bytes, vm_stat_stdout)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn memory_free_sample() -> Option<PercentPressureInput> {
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FilesystemPressureSample {
    free_percent: u8,
    available: u64,
    total: u64,
}

fn parse_df_disk_sample(stdout: &str) -> Option<FilesystemPressureSample> {
    let line = stdout.lines().rev().find(|line| !line.trim().is_empty())?;
    let mut parts = line.split_whitespace();
    let _filesystem = parts.next()?;
    let total_kib = parts.next()?.parse::<u64>().ok()?;
    let _used_kib = parts.next()?;
    let available_kib = parts.next()?.parse::<u64>().ok()?;
    let capacity_percent = parts
        .next()?
        .trim_end_matches('%')
        .parse::<u8>()
        .ok()?
        .min(100);
    Some(FilesystemPressureSample {
        free_percent: 100_u8.saturating_sub(capacity_percent),
        available: available_kib.saturating_mul(1024),
        total: total_kib.saturating_mul(1024),
    })
}

fn parse_df_inode_sample(stdout: &str) -> Option<FilesystemPressureSample> {
    let line = stdout.lines().rev().find(|line| !line.trim().is_empty())?;
    let mut parts = line.split_whitespace();
    let _filesystem = parts.next()?;
    let total = parts.next()?.parse::<u64>().ok()?;
    let _used = parts.next()?;
    let available = parts.next()?.parse::<u64>().ok()?;
    let used_percent = parts
        .next()?
        .trim_end_matches('%')
        .parse::<u8>()
        .ok()?
        .min(100);
    Some(FilesystemPressureSample {
        free_percent: 100_u8.saturating_sub(used_percent),
        available,
        total,
    })
}

fn rch_status_sample_from_json(stdout: &str) -> Option<RchPressureInput> {
    let value = serde_json::from_str::<Value>(stdout).ok()?;
    if value.get("success").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    let data = value.get("data")?;
    let queued_jobs = data
        .get("queued_builds")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let active_builds = data
        .get("active_builds")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let reported_issue_count = data
        .get("issues")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let posture_warning_count = usize::from(
        data.get("posture")
            .and_then(Value::as_str)
            .is_some_and(|posture| posture != "remote_ready"),
    );
    let worker_pressure_warning_count = data
        .pointer("/daemon/workers")
        .and_then(Value::as_array)
        .map(|workers| {
            workers
                .iter()
                .filter(|worker| {
                    worker
                        .get("pressure_state")
                        .and_then(Value::as_str)
                        .is_some_and(|state| state != "healthy")
                })
                .count()
        })
        .unwrap_or(0);
    let warning_count =
        reported_issue_count + posture_warning_count + worker_pressure_warning_count;
    let daemon = data.pointer("/daemon/daemon");
    let slots_total = daemon
        .and_then(|daemon| daemon.get("slots_total"))
        .and_then(Value::as_u64);
    let slots_available = daemon
        .and_then(|daemon| daemon.get("slots_available"))
        .and_then(Value::as_u64);
    let workers_total = daemon
        .and_then(|daemon| daemon.get("workers_total"))
        .and_then(Value::as_u64);
    let workers_healthy = daemon
        .and_then(|daemon| daemon.get("workers_healthy"))
        .and_then(Value::as_u64);

    Some(RchPressureInput {
        queued_jobs,
        active_builds,
        warning_count,
        evidence: json!({
            "source": "rch",
            "live": true,
            "method": "rch status --json",
            "rch_invoked": true,
            "queued_builds": queued_jobs,
            "active_builds": active_builds,
            "reported_issue_count": reported_issue_count,
            "worker_pressure_warning_count": worker_pressure_warning_count,
            "slots_available": slots_available,
            "slots_total": slots_total,
            "workers_healthy": workers_healthy,
            "workers_total": workers_total,
        }),
    })
}

#[cfg(any(test, target_os = "linux"))]
fn linux_memory_sample_from_meminfo(content: &str) -> Option<PercentPressureInput> {
    let mut total_kib = None;
    let mut available_kib = None;
    for line in content.lines() {
        if total_kib.is_none() {
            total_kib = meminfo_kib(line, "MemTotal:");
        }
        if available_kib.is_none() {
            available_kib = meminfo_kib(line, "MemAvailable:");
        }
    }
    let total_kib = total_kib?;
    let available_kib = available_kib?;
    let total_bytes = total_kib.saturating_mul(1024);
    let available_bytes = available_kib.saturating_mul(1024);
    Some(PercentPressureInput {
        percent: percent_u8(available_bytes, total_bytes)?,
        evidence: json!({
            "source": "local-os",
            "live": true,
            "method": "/proc/meminfo",
            "available_bytes": available_bytes,
            "total_bytes": total_bytes,
        }),
    })
}

#[cfg(any(test, target_os = "linux"))]
fn meminfo_kib(line: &str, prefix: &str) -> Option<u64> {
    line.strip_prefix(prefix)?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()
}

#[cfg(any(test, target_os = "macos"))]
fn macos_memory_sample_from_vm_stat(
    total_bytes: u64,
    vm_stat_stdout: &str,
) -> Option<PercentPressureInput> {
    let page_size = vm_stat_page_size(vm_stat_stdout)?;
    let available_pages = ["Pages free:", "Pages inactive:", "Pages speculative:"]
        .into_iter()
        .filter_map(|label| vm_stat_pages(vm_stat_stdout, label))
        .sum::<u64>();
    let available_bytes = available_pages.saturating_mul(page_size);
    Some(PercentPressureInput {
        percent: percent_u8(available_bytes, total_bytes)?,
        evidence: json!({
            "source": "local-os",
            "live": true,
            "method": "vm_stat + sysctl hw.memsize",
            "available_bytes": available_bytes,
            "total_bytes": total_bytes,
            "page_size_bytes": page_size,
            "available_pages": available_pages,
        }),
    })
}

#[cfg(any(test, target_os = "macos"))]
fn vm_stat_page_size(stdout: &str) -> Option<u64> {
    let marker = "page size of ";
    let line = stdout.lines().find(|line| line.contains(marker))?;
    let start = line.find(marker)?.saturating_add(marker.len());
    line[start..].split_whitespace().next()?.parse::<u64>().ok()
}

#[cfg(any(test, target_os = "macos"))]
fn vm_stat_pages(stdout: &str, label: &str) -> Option<u64> {
    let line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with(label))?;
    let value = line.trim_start().strip_prefix(label)?;
    let digits = value
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>();
    digits.parse::<u64>().ok()
}

fn percent_u8(available_bytes: u64, total_bytes: u64) -> Option<u8> {
    if total_bytes == 0 {
        return None;
    }
    let percent = available_bytes.saturating_mul(100) / total_bytes;
    u8::try_from(percent.min(100)).ok()
}

fn pressure_signals(inputs: &SwarmPressureInputs) -> Vec<SwarmPressureSignal> {
    let mut signals = inputs.signals.clone();
    add_signal_if_missing(&mut signals, cpu_capacity_signal(inputs.logical_cpus));
    add_signal_if_missing(
        &mut signals,
        percent_signal(
            "memory_pressure",
            inputs.memory_free.as_ref(),
            15,
            8,
            "memory free percent",
            ">=15% green, >=8% yellow, <8% red",
            "memory pressure could not be sampled locally; pass --memory-free-percent or a fixture to make it explicit evidence",
        ),
    );
    add_signal_if_missing(
        &mut signals,
        percent_signal(
            "disk_free",
            inputs.disk_free.as_ref(),
            15,
            5,
            "disk free percent",
            ">=15% green, >=5% yellow, <5% red",
            "disk free space could not be sampled locally; pass --disk-free-percent or a fixture to make it explicit evidence",
        ),
    );
    add_signal_if_missing(
        &mut signals,
        percent_signal(
            "inode_free",
            inputs.inode_free.as_ref(),
            15,
            5,
            "inode free percent",
            ">=15% green, >=5% yellow, <5% red",
            "inode pressure could not be sampled locally; pass --inode-free-percent or a fixture to make it explicit evidence",
        ),
    );
    add_signal_if_missing(&mut signals, agent_count_signal(inputs));
    add_signal_if_missing(&mut signals, connector_count_signal(inputs));
    add_signal_if_missing(&mut signals, rch_queue_signal(inputs));
    signals
}

fn add_signal_if_missing(signals: &mut Vec<SwarmPressureSignal>, signal: SwarmPressureSignal) {
    if !signals.iter().any(|existing| existing.name == signal.name) {
        signals.push(signal);
    }
}

fn cpu_capacity_signal(logical_cpus: usize) -> SwarmPressureSignal {
    let status = if logical_cpus <= 1 {
        SwarmPressureStatus::Red
    } else if logical_cpus < 8 {
        SwarmPressureStatus::Yellow
    } else {
        SwarmPressureStatus::Green
    };
    SwarmPressureSignal {
        name: "cpu_capacity".to_owned(),
        status,
        value: format!("{logical_cpus} logical CPU(s)"),
        threshold: ">=8 green, >=2 yellow, 1 red".to_owned(),
        evidence: json!({
            "source": "std::thread::available_parallelism",
            "live": true,
        }),
    }
}

fn percent_signal(
    name: &str,
    input: Option<&PercentPressureInput>,
    green_threshold: u8,
    yellow_threshold: u8,
    value_label: &str,
    threshold: &str,
    degraded_reason: &str,
) -> SwarmPressureSignal {
    match input {
        Some(input) => {
            let capped_percent = input.percent.min(100);
            let status = if capped_percent < yellow_threshold {
                SwarmPressureStatus::Red
            } else if capped_percent < green_threshold {
                SwarmPressureStatus::Yellow
            } else {
                SwarmPressureStatus::Green
            };
            SwarmPressureSignal {
                name: name.to_owned(),
                status,
                value: format!("{capped_percent}% {value_label}"),
                threshold: threshold.to_owned(),
                evidence: input.evidence.clone(),
            }
        }
        None => degraded_signal(name, "unavailable", threshold, degraded_reason),
    }
}

fn agent_count_signal(inputs: &SwarmPressureInputs) -> SwarmPressureSignal {
    match &inputs.active_agents {
        Some(input) => {
            let active_agents = input.active_agents;
            let yellow_threshold = inputs.logical_cpus;
            let red_threshold = inputs.logical_cpus.saturating_mul(2);
            let mut status = threshold_status(active_agents, yellow_threshold, red_threshold);
            if status == SwarmPressureStatus::Green && input.warning_count > 0 {
                status = SwarmPressureStatus::Yellow;
            }
            let value = if input.warning_count == 0 {
                format!("{active_agents} active agent(s)")
            } else {
                format!(
                    "{active_agents} active agent(s), {} coordination warning(s)",
                    input.warning_count
                )
            };
            SwarmPressureSignal {
                name: "agent_mail_agents".to_owned(),
                status,
                value,
                threshold: format!(
                    "<{} green, {}-{} yellow, >{} red",
                    yellow_threshold, yellow_threshold, red_threshold, red_threshold
                ),
                evidence: input.evidence.clone(),
            }
        }
        None => degraded_signal(
            "agent_mail_agents",
            "unavailable",
            "active agents known and below logical CPU count",
            "Agent Mail was not queried by this command; callers may provide a snapshot, but this command never repairs or restarts Agent Mail",
        ),
    }
}

fn connector_count_signal(inputs: &SwarmPressureInputs) -> SwarmPressureSignal {
    match &inputs.active_connectors {
        Some(input) => {
            let active_connectors = input.active_connectors;
            let yellow_threshold = inputs.logical_cpus.saturating_mul(2);
            let red_threshold = inputs.logical_cpus.saturating_mul(4);
            let mut status = threshold_status(active_connectors, yellow_threshold, red_threshold);
            if status == SwarmPressureStatus::Green && input.warning_count > 0 {
                status = SwarmPressureStatus::Yellow;
            }
            let value = if input.warning_count == 0 {
                format!("{active_connectors} active connector(s)")
            } else {
                format!(
                    "{active_connectors} active connector(s), {} host warning(s)",
                    input.warning_count
                )
            };
            SwarmPressureSignal {
                name: "host_connectors".to_owned(),
                status,
                value,
                threshold: format!(
                    "<{} green, {}-{} yellow, >{} red",
                    yellow_threshold, yellow_threshold, red_threshold, red_threshold
                ),
                evidence: input.evidence.clone(),
            }
        }
        None => degraded_signal(
            "host_connectors",
            "unavailable",
            "host connector count available",
            "No host endpoint was configured; pass --host, FWC_HOST, FCP_HOST_ENDPOINT, FCP_HOST_BIND, --active-connectors, or a fixture to make this explicit evidence",
        ),
    }
}

fn rch_queue_signal(inputs: &SwarmPressureInputs) -> SwarmPressureSignal {
    match &inputs.rch_status {
        Some(rch_status) => {
            let yellow_threshold = inputs.logical_cpus.div_ceil(2);
            let red_threshold = inputs.logical_cpus;
            let mut status =
                threshold_status(rch_status.queued_jobs, yellow_threshold, red_threshold);
            if status == SwarmPressureStatus::Green && rch_status.warning_count > 0 {
                status = SwarmPressureStatus::Yellow;
            }
            SwarmPressureSignal {
                name: "rch_status".to_owned(),
                status,
                value: format!(
                    "{} queued rch job(s), {} active build(s), {} warning(s)",
                    rch_status.queued_jobs, rch_status.active_builds, rch_status.warning_count
                ),
                threshold: format!(
                    "<{} green, {}-{} yellow, >{} red",
                    yellow_threshold, yellow_threshold, red_threshold, red_threshold
                ),
                evidence: rch_status.evidence.clone(),
            }
        }
        None => degraded_signal(
            "rch_status",
            "unavailable",
            "rch queued jobs known and below half of logical CPU count",
            "rch status --json could not be sampled; no repair command was run and no Cargo work was started",
        ),
    }
}

fn threshold_status(
    value: usize,
    yellow_threshold: usize,
    red_threshold: usize,
) -> SwarmPressureStatus {
    if value > red_threshold {
        SwarmPressureStatus::Red
    } else if value >= yellow_threshold {
        SwarmPressureStatus::Yellow
    } else {
        SwarmPressureStatus::Green
    }
}

fn degraded_signal(
    name: &str,
    value: &str,
    threshold: &str,
    degraded_reason: &str,
) -> SwarmPressureSignal {
    SwarmPressureSignal {
        name: name.to_owned(),
        status: SwarmPressureStatus::Degraded,
        value: value.to_owned(),
        threshold: threshold.to_owned(),
        evidence: json!({
            "source": "not-yet-wired",
            "degraded_reason": degraded_reason,
        }),
    }
}

fn pressure_score(signals: &[SwarmPressureSignal]) -> u8 {
    signals
        .iter()
        .map(|signal| match signal.status {
            SwarmPressureStatus::Green => 10,
            SwarmPressureStatus::Degraded => 55,
            SwarmPressureStatus::Yellow => 65,
            SwarmPressureStatus::Red => 95,
        })
        .max()
        .unwrap_or(55)
}

fn pressure_verdict(signals: &[SwarmPressureSignal]) -> SwarmPressureStatus {
    if signals
        .iter()
        .any(|signal| signal.status == SwarmPressureStatus::Red)
    {
        SwarmPressureStatus::Red
    } else if signals.iter().any(|signal| {
        matches!(
            signal.status,
            SwarmPressureStatus::Yellow | SwarmPressureStatus::Degraded
        )
    }) {
        SwarmPressureStatus::Yellow
    } else {
        SwarmPressureStatus::Green
    }
}

fn recommended_agent_slots(
    verdict: SwarmPressureStatus,
    logical_cpus: usize,
    active_agents: Option<usize>,
) -> usize {
    let base = match verdict {
        SwarmPressureStatus::Green => logical_cpus.div_ceil(2),
        SwarmPressureStatus::Yellow | SwarmPressureStatus::Degraded => logical_cpus.div_ceil(8),
        SwarmPressureStatus::Red => 0,
    };
    let active_discount = active_agents.unwrap_or(0).div_ceil(4);
    base.saturating_sub(active_discount)
}

fn recommended_cargo_lanes(verdict: SwarmPressureStatus, logical_cpus: usize) -> usize {
    match verdict {
        SwarmPressureStatus::Green => logical_cpus.div_ceil(8).clamp(1, 4),
        SwarmPressureStatus::Yellow | SwarmPressureStatus::Degraded => 1,
        SwarmPressureStatus::Red => 0,
    }
}

fn remediation_commands(signals: &[SwarmPressureSignal]) -> Vec<String> {
    let mut commands = Vec::new();
    for signal in signals {
        match (signal.name.as_str(), signal.status) {
            ("disk_free", SwarmPressureStatus::Red | SwarmPressureStatus::Yellow) => {
                commands.push("df -h .".to_owned());
                commands.push("defer new Cargo/rch lanes until disk headroom recovers".to_owned());
            }
            ("inode_free", SwarmPressureStatus::Red | SwarmPressureStatus::Yellow) => {
                commands.push("df -ih .".to_owned());
                commands
                    .push("defer file-heavy generation until inode headroom recovers".to_owned());
            }
            ("memory_pressure", SwarmPressureStatus::Red | SwarmPressureStatus::Yellow) => {
                commands
                    .push("defer new Cargo/rch lanes until memory headroom recovers".to_owned());
            }
            ("rch_status", SwarmPressureStatus::Red | SwarmPressureStatus::Yellow) => {
                commands.push("rch status --json".to_owned());
            }
            ("agent_mail_agents", SwarmPressureStatus::Degraded) => {
                commands.push(
                    "retry Agent Mail once if needed, then proceed without restarting the shared service"
                        .to_owned(),
                );
            }
            ("host_connectors", SwarmPressureStatus::Red | SwarmPressureStatus::Yellow) => {
                commands.push("defer noncritical connector prewarm or bulk launch work".to_owned());
            }
            _ => {}
        }
    }
    if commands.is_empty() {
        commands.push("continue with normal rch-backed validation".to_owned());
    }
    commands.sort();
    commands.dedup();
    commands
}

fn insert_toon(payload: &mut Value, toon: String) {
    if let Some(object) = payload.as_object_mut() {
        object.insert("toon".to_owned(), Value::String(toon));
    }
}

fn load_jsonl_records(path: &Path) -> Result<Vec<JsonlRecord>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open swarm evidence JSONL `{}`", path.display()))?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line.with_context(|| {
            format!(
                "failed to read line {line_number} from swarm evidence JSONL `{}`",
                path.display()
            )
        })?;
        if line.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(&line).with_context(|| {
            format!(
                "line {line_number} in `{}` is not valid JSON",
                path.display()
            )
        })?;
        records.push(JsonlRecord {
            line: line_number,
            value,
        });
    }

    Ok(records)
}

fn filtered_entries(
    records: &[JsonlRecord],
    filters: &SwarmEvidenceFilters,
    card_ids: &[String],
) -> Result<Vec<DecisionCardEntry>> {
    let mut entries = records
        .iter()
        .filter_map(decision_card_entry)
        .filter(|entry| card_ids.is_empty() || card_ids.iter().any(|id| id == &entry.card_id))
        .filter(|entry| matches_filters(entry, filters))
        .collect::<Vec<_>>();

    entries.sort_by(|left, right| {
        let scenario_order = left.scenario_id.cmp(&right.scenario_id);
        if scenario_order == Ordering::Equal {
            left.card_id.cmp(&right.card_id)
        } else {
            scenario_order
        }
    });

    Ok(entries)
}

fn decision_card_entry(record: &JsonlRecord) -> Option<DecisionCardEntry> {
    if record.value.get("record_type")?.as_str()? != "swarm_decision_card" {
        return None;
    }
    let card = record.value.get("card")?;
    let card_id = string_field(card, "card_id")?;
    let fallback = card.get("fallback").unwrap_or(&Value::Null);
    let counterfactual = card.get("counterfactual").unwrap_or(&Value::Null);
    let evidence_handles = card
        .get("evidence_pointers")
        .and_then(Value::as_array)
        .map(|pointers| {
            pointers
                .iter()
                .map(|pointer| {
                    json!({
                        "kind": pointer.get("kind").and_then(Value::as_str),
                        "handle": pointer.get("handle").and_then(Value::as_str),
                        "digest": pointer.get("digest").and_then(Value::as_str),
                        "redacted": pointer.get("redacted").and_then(Value::as_bool).unwrap_or(false),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let replayable_offline = card
        .get("replay_inputs")
        .and_then(Value::as_object)
        .is_some_and(|inputs| !inputs.is_empty())
        && !evidence_handles
            .iter()
            .any(|pointer| pointer.get("kind").and_then(Value::as_str) == Some("live_service"));

    Some(DecisionCardEntry {
        line: record.line,
        card_id,
        scenario_id: string_field(card, "scenario_id"),
        domain: string_field(card, "domain"),
        subject: string_field(card, "subject"),
        action: string_field(card, "action"),
        state: string_field(card, "state"),
        calibration: string_field(card, "calibration"),
        fallback_active: fallback
            .get("active")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        fallback_action: string_field(fallback, "action"),
        fallback_reason: string_field(fallback, "reason"),
        counterfactual_action: string_field(counterfactual, "action"),
        counterfactual_reason: string_field(counterfactual, "reason"),
        dominant_loss_term: dominant_loss_term(card),
        evidence_handles,
        replayable_offline,
        raw_record: record.value.clone(),
    })
}

fn matches_filters(entry: &DecisionCardEntry, filters: &SwarmEvidenceFilters) -> bool {
    string_filter_matches(filters.zone.as_deref(), &entry.raw_record)
        && string_filter_matches(filters.connector.as_deref(), &entry.raw_record)
        && string_filter_matches(filters.principal.as_deref(), &entry.raw_record)
        && string_filter_matches(filters.correlation_id.as_deref(), &entry.raw_record)
        && exact_or_deep_match(
            filters.scenario.as_deref(),
            entry.scenario_id.as_deref(),
            entry,
        )
        && exact_filter_matches(filters.action.as_deref(), entry.action.as_deref())
        && exact_filter_matches(
            filters.fallback_reason.as_deref(),
            entry.fallback_reason.as_deref(),
        )
        && exact_filter_matches(
            filters.dominant_loss_term.as_deref(),
            entry
                .dominant_loss_term
                .as_ref()
                .and_then(|term| term.get("name"))
                .and_then(Value::as_str),
        )
}

fn exact_or_deep_match(
    filter: Option<&str>,
    exact_value: Option<&str>,
    entry: &DecisionCardEntry,
) -> bool {
    match filter {
        None => true,
        Some(expected) => {
            exact_value.is_some_and(|actual| actual == expected)
                || value_contains_string(&entry.raw_record, expected)
        }
    }
}

fn string_filter_matches(filter: Option<&str>, record: &Value) -> bool {
    match filter {
        None => true,
        Some(needle) => value_contains_string(record, needle),
    }
}

fn exact_filter_matches(filter: Option<&str>, actual: Option<&str>) -> bool {
    match filter {
        None => true,
        Some(expected) => actual == Some(expected),
    }
}

fn value_contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(text) => text.contains(needle),
        Value::Array(items) => items.iter().any(|item| value_contains_string(item, needle)),
        Value::Object(map) => map.values().any(|item| value_contains_string(item, needle)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn string_field(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn dominant_loss_term(card: &Value) -> Option<Value> {
    card.get("loss_terms")?
        .as_array()?
        .iter()
        .max_by_key(|term| {
            let value = term.get("value").and_then(Value::as_i64).unwrap_or(0);
            let weight = term
                .get("weight_microunits")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            i128::from(value).saturating_mul(i128::from(weight))
        })
        .map(|term| {
            let value = term.get("value").and_then(Value::as_i64).unwrap_or(0);
            let weight = term
                .get("weight_microunits")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            json!({
                "name": term.get("name").and_then(Value::as_str),
                "value": value,
                "weight_microunits": weight,
                "unit": term.get("unit").and_then(Value::as_str),
                "weighted_score": i128::from(value).saturating_mul(i128::from(weight)).to_string(),
            })
        })
}

fn entry_summary(entry: &DecisionCardEntry) -> Value {
    json!({
        "line": entry.line,
        "card_id": &entry.card_id,
        "scenario_id": &entry.scenario_id,
        "domain": &entry.domain,
        "subject": &entry.subject,
        "state": &entry.state,
        "action": &entry.action,
        "calibration": &entry.calibration,
        "fallback": {
            "active": entry.fallback_active,
            "action": &entry.fallback_action,
            "reason": &entry.fallback_reason,
        },
        "dominant_loss_term": &entry.dominant_loss_term,
        "counterfactual": {
            "action": &entry.counterfactual_action,
            "reason": &entry.counterfactual_reason,
        },
        "evidence_handles": &entry.evidence_handles,
        "replayable_offline": entry.replayable_offline,
    })
}

fn replay_summary(entry: &DecisionCardEntry) -> Value {
    let card = entry.raw_record.get("card").unwrap_or(&Value::Null);
    json!({
        "line": entry.line,
        "card_id": &entry.card_id,
        "answers": {
            "what_happened": {
                "scenario_id": &entry.scenario_id,
                "domain": &entry.domain,
                "subject": &entry.subject,
                "state": &entry.state,
                "selected_action": &entry.action,
            },
            "why_selected": {
                "selected_loss_score": card.get("selected_loss_score"),
                "dominant_loss_term": &entry.dominant_loss_term,
                "calibration": &entry.calibration,
            },
            "next_best_counterfactual": card
                .get("counterfactual")
                .map(redacted_value)
                .unwrap_or(Value::Null),
            "fallback": card.get("fallback").map(redacted_value).unwrap_or(Value::Null),
            "proof_locations": {
                "evidence_handles": &entry.evidence_handles,
                "replay_inputs": card
                    .get("replay_inputs")
                    .map(redacted_value)
                    .unwrap_or_else(|| json!({})),
            },
        },
        "replayable_offline": entry.replayable_offline,
        "redacted_record": redacted_value(&entry.raw_record),
    })
}

fn redacted_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(redacted_value).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| {
                    let value = if is_sensitive_key(key) {
                        json!("[redacted]")
                    } else {
                        redacted_value(item)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => value.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = key
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("authorization")
        || normalized.contains("credential")
        || normalized.contains("apikey")
        || normalized.contains("accesskey")
        || normalized.contains("privatekey")
        || normalized.contains("bearer")
}

fn bundle_summary(records: &[JsonlRecord], filtered_cards: usize) -> Value {
    let mut record_type_counts = serde_json::Map::new();
    for record in records {
        if let Some(record_type) = record.value.get("record_type").and_then(Value::as_str) {
            let count = record_type_counts
                .get(record_type)
                .and_then(Value::as_u64)
                .unwrap_or(0)
                + 1;
            record_type_counts.insert(record_type.to_owned(), json!(count));
        }
    }

    json!({
        "record_count": records.len(),
        "record_type_counts": Value::Object(record_type_counts),
        "decision_card_count": records.iter().filter_map(decision_card_entry).count(),
        "filtered_decision_card_count": filtered_cards,
    })
}

fn report_links(records: &[JsonlRecord]) -> Vec<Value> {
    records
        .iter()
        .filter_map(|record| {
            let record_type = record.value.get("record_type")?.as_str()?;
            if !matches!(
                record_type,
                "swarm_gauntlet_log"
                    | "swarm_gauntlet_summary"
                    | "swarm_controller_safety_report"
                    | "swarm_statistical_gate_report"
                    | "swarm_baseline_promotion_manifest"
                    | "swarm_promotion_skip"
            ) {
                return None;
            }
            Some(json!({
                "line": record.line,
                "record_type": record_type,
                "scenario": scenario_field(record),
                "latency_scenario_id": record_field(record, "latency_scenario_id"),
                "outcome": record_field(record, "outcome"),
                "decision_card_ids": record_field(record, "decision_card_ids"),
                "evidence_bundle_id": record_field(record, "evidence_bundle_id"),
                "raw_samples_record_type": record_field(record, "raw_samples_record_type"),
                "raw_sample_digest": record_field(record, "raw_sample_digest"),
                "summary_digest": record_field(record, "summary_digest"),
                "gate_report_digest": record_field(record, "gate_report_digest"),
                "proof_notes_digest": record_field(record, "proof_notes_digest"),
                "execution_mode": record_field(record, "execution_mode"),
                "source_kind": record_field(record, "source_kind"),
                "run_context": {
                    "command_line": record
                        .value
                        .get("command_line")
                        .map(redacted_command_line)
                        .unwrap_or(Value::Null),
                    "git_revision": record_field(record, "git_revision"),
                    "worker_id": record_field(record, "worker_id"),
                    "cargo_target_dir": record_field(record, "cargo_target_dir"),
                    "topology": record_field(record, "topology"),
                },
                "metrics": {
                    "sample_count": record_field(record, "sample_count"),
                    "p50_ns": record_field(record, "p50_ns"),
                    "p95_ns": record_field(record, "p95_ns"),
                    "p99_ns": record_field(record, "p99_ns"),
                    "p999_ns": record_field(record, "p999_ns"),
                    "throughput_ops_per_second": record_field(record, "throughput_ops_per_second"),
                    "queue_depth": record_field(record, "queue_depth"),
                    "retry_amplification_microunits": record_field(record, "retry_amplification_microunits"),
                    "rss_bytes": record_field(record, "rss_bytes"),
                    "cpu_microunits": record_field(record, "cpu_microunits"),
                },
                "evidence": {
                    "decision_card_ids": record_field(record, "decision_card_ids"),
                    "evidence_bundle_id": record_field(record, "evidence_bundle_id"),
                    "raw_samples_record_type": record_field(record, "raw_samples_record_type"),
                    "raw_sample_digest": record_field(record, "raw_sample_digest"),
                    "summary_digest": record_field(record, "summary_digest"),
                    "gate_report_digest": record_field(record, "gate_report_digest"),
                    "proof_notes_digest": record_field(record, "proof_notes_digest"),
                },
                "machine_readable_status": {
                    "skip_reason": record_field(record, "skip_reason"),
                    "failure_reason": record_field(record, "failure_reason"),
                    "machine_reason": record_field(record, "machine_reason"),
                },
                "audit": {
                    "audit_event_count": record_field(record, "audit_event_count"),
                    "same_zone_audit_appends": record_field(record, "same_zone_audit_appends"),
                    "sparse_high_k_metadata_events": record_field(record, "sparse_high_k_metadata_events"),
                },
            }))
        })
        .collect()
}

fn record_field(record: &JsonlRecord, field: &str) -> Value {
    record
        .value
        .get(field)
        .map(redacted_value)
        .unwrap_or(Value::Null)
}

fn scenario_field(record: &JsonlRecord) -> Value {
    let scenario = record_field(record, "scenario");
    if scenario.is_null() {
        record_field(record, "scenario_id")
    } else {
        scenario
    }
}

fn redacted_command_line(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(redacted_command_args(items)),
        Value::String(text) if looks_sensitive_arg(text) => json!("[redacted]"),
        _ => redacted_value(value),
    }
}

fn redacted_command_args(items: &[Value]) -> Vec<Value> {
    let mut redact_next = false;
    items
        .iter()
        .map(|item| {
            let Some(text) = item.as_str() else {
                redact_next = false;
                return redacted_value(item);
            };
            let should_redact = redact_next || looks_sensitive_arg(text);
            redact_next = is_sensitive_flag(text);
            if should_redact {
                json!("[redacted]")
            } else {
                json!(text)
            }
        })
        .collect()
}

fn looks_sensitive_arg(text: &str) -> bool {
    let normalized = text
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("authorization")
        || normalized.contains("credential")
        || normalized.contains("apikey")
        || normalized.contains("accesskey")
        || normalized.contains("privatekey")
        || normalized.contains("bearer")
}

fn is_sensitive_flag(text: &str) -> bool {
    text.starts_with('-') && looks_sensitive_arg(text) && !text.contains('=')
}

fn format_explore_toon(payload: &Value) -> String {
    let returned = payload
        .get("pagination")
        .and_then(|value| value.get("returned"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total = payload
        .get("pagination")
        .and_then(|value| value.get("total_filtered"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut lines = vec![format!(
        "swarm-evidence cards returned={returned} filtered={total}"
    )];
    if let Some(entries) = payload.get("entries").and_then(Value::as_array) {
        for entry in entries.iter().take(10) {
            let card_id = entry
                .get("card_id")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let action = entry
                .get("action")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let domain = entry
                .get("domain")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            lines.push(format!("- {card_id} {domain} action={action}"));
        }
    }
    lines.join("\n")
}

fn format_replay_toon(payload: &Value) -> String {
    let mut lines = vec!["swarm-evidence replay".to_owned()];
    if let Some(entries) = payload.get("entries").and_then(Value::as_array) {
        for entry in entries.iter().take(10) {
            let card_id = entry
                .get("card_id")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let action = entry
                .pointer("/answers/what_happened/selected_action")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let fallback_active = entry
                .pointer("/answers/fallback/active")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            lines.push(format!(
                "- {card_id} selected={action} fallback_active={fallback_active}"
            ));
        }
    }
    lines.join("\n")
}

fn format_pressure_toon(payload: &Value) -> String {
    let verdict = payload
        .get("verdict")
        .and_then(Value::as_str)
        .unwrap_or("yellow");
    let score = payload
        .get("pressure_score_0_100")
        .and_then(Value::as_u64)
        .unwrap_or(55);
    let degraded = payload
        .pointer("/telemetry_event/fields/degraded_dependency_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut lines = vec![format!(
        "swarm pressure verdict={verdict} score={score} degraded={degraded}"
    )];
    if let Some(signals) = payload.get("signals").and_then(Value::as_array) {
        for signal in signals.iter().take(8) {
            let name = signal
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            let status = signal
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("degraded");
            let value = signal
                .get("value")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            lines.push(format!("- {name} status={status} value={value}"));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use serde_json::json;

    use super::{
        PercentPressureInput, RchPressureInput, SwarmEvidenceCommand, SwarmEvidenceExploreArgs,
        SwarmEvidenceFilters, SwarmEvidenceReplayArgs, SwarmPressureArgs, SwarmPressureInputs,
        SwarmPressureSignal, SwarmPressureStatus, agent_mail_status_sample_from_json,
        beads_in_progress_sample_from_json, connector_pressure_from_host_values,
        coordination_active_agents_from_samples, explore, linux_memory_sample_from_meminfo,
        macos_memory_sample_from_vm_stat, parse_df_disk_sample, parse_df_inode_sample,
        pressure_score, pressure_signals, pressure_verdict, pressure_with_host,
        provided_agent_input, provided_connector_input, rch_status_sample_from_json, replay,
        run_with_host,
    };

    fn write_fixture() -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(
            file,
            "{}",
            json!({
                "record_type": "swarm_decision_card",
                "schema_version": "swarm-decision-card/v1",
                "card": {
                    "schema_version": "swarm-decision-card/v1",
                    "card_id": "card:1",
                    "scenario_id": "mixed_priority",
                    "domain": "scheduler",
                    "subject": "connector:fcp.github principal:user:1 zone:z:work correlation:corr-1",
                    "state": "queue_depth=12",
                    "action": "delay",
                    "selected_loss_score": 42,
                    "loss_terms": [
                        {"name": "p99_queueing", "value": 3, "weight_microunits": 1000, "unit": "ms"},
                        {"name": "zone_fairness", "value": 9, "weight_microunits": 2000, "unit": "skew"}
                    ],
                    "calibration": "valid",
                    "fallback": {"active": false, "action": "fallback", "reason": "calibration_valid"},
                    "counterfactual": {"action": "admit", "expected_loss_score": 80, "reason": "higher fairness loss"},
                    "evidence_pointers": [
                        {"kind": "bundle_artifact", "handle": "raw-samples.jsonl", "digest": "blake3:test", "redacted": true}
                    ],
                    "replay_inputs": {"queue_depth": 12, "auth_token": "must-not-leak"},
                    "created_at": "2026-05-05T00:00:00Z"
                }
            })
        )
        .expect("write fixture");
        writeln!(
            file,
            "{}",
            json!({
                "record_type": "swarm_decision_card",
                "schema_version": "swarm-decision-card/v1",
                "card": {
                    "schema_version": "swarm-decision-card/v1",
                    "card_id": "card:0",
                    "scenario_id": "capacity_baseline",
                    "domain": "scheduler",
                    "subject": "connector:fcp.slack principal:user:2 zone:z:project:alpha correlation:corr-2",
                    "state": "queue_depth=2",
                    "action": "admit",
                    "selected_loss_score": 7,
                    "loss_terms": [
                        {"name": "p99_queueing", "value": 7, "weight_microunits": 1000, "unit": "ms"}
                    ],
                    "calibration": "valid",
                    "fallback": {"active": false, "action": "delay", "reason": "healthy_capacity"},
                    "counterfactual": {"action": "delay", "expected_loss_score": 11, "reason": "unneeded queueing"},
                    "evidence_pointers": [
                        {"kind": "live_service", "handle": "runtime-host", "digest": "blake3:live", "redacted": false}
                    ],
                    "replay_inputs": {"queue_depth": 2},
                    "created_at": "2026-05-05T00:00:01Z"
                }
            })
        )
        .expect("write second fixture");
        writeln!(
            file,
            "{}",
            json!({
                "record_type": "swarm_controller_safety_report",
                "schema_version": "swarm-controller-safety/v1",
                "scenario": "mixed_priority",
                "outcome": "pass",
                "decision_card_ids": ["card:1", "card:0"]
            })
        )
        .expect("write report");
        file
    }

    #[test]
    fn explore_filters_cards_by_action_and_loss_term() {
        let file = write_fixture();
        let payload = explore(&SwarmEvidenceExploreArgs {
            file: file.path().to_path_buf(),
            filters: SwarmEvidenceFilters {
                action: Some("delay".to_owned()),
                dominant_loss_term: Some("zone_fairness".to_owned()),
                ..SwarmEvidenceFilters::default()
            },
            limit: 10,
            offset: 0,
        })
        .expect("explore");

        assert_eq!(payload["summary"]["filtered_decision_card_count"], 1);
        assert_eq!(payload["entries"][0]["card_id"], "card:1");
        assert_eq!(
            payload["entries"][0]["dominant_loss_term"]["name"],
            "zone_fairness"
        );
        assert_eq!(payload["reports"][0]["decision_card_ids"][0], "card:1");
    }

    #[test]
    fn replay_renders_operator_answers_without_live_services() {
        let file = write_fixture();
        let payload = replay(&SwarmEvidenceReplayArgs {
            file: file.path().to_path_buf(),
            card_ids: vec!["card:1".to_owned()],
            filters: SwarmEvidenceFilters::default(),
            limit: 10,
        })
        .expect("replay");

        assert_eq!(
            payload["entries"][0]["answers"]["what_happened"]["selected_action"],
            "delay"
        );
        assert_eq!(
            payload["entries"][0]["answers"]["next_best_counterfactual"]["action"],
            "admit"
        );
        assert_eq!(
            payload["entries"][0]["answers"]["proof_locations"]["evidence_handles"][0]["handle"],
            "raw-samples.jsonl"
        );
        assert_eq!(
            payload["entries"][0]["answers"]["proof_locations"]["replay_inputs"]["auth_token"],
            "[redacted]"
        );
        assert_eq!(payload["pagination"]["returned"], 1);
        assert_eq!(payload["pagination"]["total_filtered"], 1);
        assert_eq!(
            payload["entries"][0]["redacted_record"]["card"]["replay_inputs"]["auth_token"],
            "[redacted]"
        );
        assert_eq!(payload["entries"][0]["replayable_offline"], true);
    }

    #[test]
    fn explore_sorts_paginates_and_preserves_redaction_metadata() {
        let file = write_fixture();
        let first_page = explore(&SwarmEvidenceExploreArgs {
            file: file.path().to_path_buf(),
            filters: SwarmEvidenceFilters::default(),
            limit: 1,
            offset: 0,
        })
        .expect("first page");

        assert_eq!(first_page["entries"][0]["card_id"], "card:0");
        assert_eq!(first_page["pagination"]["returned"], 1);
        assert_eq!(first_page["pagination"]["total_filtered"], 2);
        assert_eq!(first_page["pagination"]["has_more"], true);
        assert!(first_page.get("toon").is_some());

        let second_page = explore(&SwarmEvidenceExploreArgs {
            file: file.path().to_path_buf(),
            filters: SwarmEvidenceFilters::default(),
            limit: 1,
            offset: 1,
        })
        .expect("second page");

        assert_eq!(second_page["entries"][0]["card_id"], "card:1");
        assert_eq!(
            second_page["entries"][0]["evidence_handles"][0]["redacted"],
            true
        );
        assert_eq!(second_page["pagination"]["has_more"], false);
        assert_eq!(
            second_page["reports"][0]["record_type"],
            "swarm_controller_safety_report"
        );
    }

    #[test]
    fn report_links_surface_detailed_log_context_without_secrets() {
        let mut file = write_fixture();
        writeln!(
            file,
            "{}",
            json!({
                "record_type": "swarm_gauntlet_log",
                "schema_version": "swarm-gauntlet-log/v1",
                "scenario_id": "mixed_priority",
                "latency_scenario_id": "p99_regression",
                "execution_mode": "smoke",
                "source_kind": "host_backed",
                "command_line": ["rch", "exec", "--capability-token", "secret-token", "--", "cargo", "test"],
                "git_revision": "abc123",
                "worker_id": "Codex",
                "cargo_target_dir": "/tmp/fcp-k3zfl5",
                "topology": {"logical_cpus": 64, "memory_bytes": 274_877_906_944_u64},
                "sample_count": 1000,
                "raw_samples_record_type": "swarm_latency_sample",
                "raw_sample_digest": "blake3:raw",
                "p50_ns": 500,
                "p95_ns": 950,
                "p99_ns": 990,
                "p999_ns": 999,
                "throughput_ops_per_second": 1_000_000,
                "queue_depth": 4096,
                "retry_amplification_microunits": 125_000,
                "rss_bytes": 8_589_934_592_u64,
                "cpu_microunits": 64_000_000,
                "decision_card_ids": ["card:1"],
                "evidence_bundle_id": "bundle:fixture",
                "skip_reason": null,
                "failure_reason": "p99_regression",
                "audit_event_count": 4
            })
        )
        .expect("write gauntlet log");

        let payload = explore(&SwarmEvidenceExploreArgs {
            file: file.path().to_path_buf(),
            filters: SwarmEvidenceFilters::default(),
            limit: 10,
            offset: 0,
        })
        .expect("explore");

        let log = payload["reports"]
            .as_array()
            .expect("reports")
            .iter()
            .find(|report| report["record_type"] == "swarm_gauntlet_log")
            .expect("gauntlet log report");
        assert_eq!(log["run_context"]["git_revision"], "abc123");
        assert_eq!(log["run_context"]["command_line"][3], "[redacted]");
        assert_eq!(log["metrics"]["p99_ns"], 990);
        assert_eq!(log["metrics"]["queue_depth"], 4096);
        assert_eq!(log["evidence"]["decision_card_ids"][0], "card:1");
        assert_eq!(
            log["machine_readable_status"]["failure_reason"],
            "p99_regression"
        );
        assert_eq!(log["audit"]["audit_event_count"], 4);
    }

    #[test]
    fn pressure_fixture_all_green_recommends_parallel_work() {
        let mut file = tempfile::NamedTempFile::new().expect("pressure fixture");
        serde_json::to_writer(
            &mut file,
            &json!({
                "logical_cpus": 64,
                "active_agents": 4,
                "active_connectors": 12,
                "disk_free_percent": 80,
                "inode_free_percent": 90,
                "memory_free_percent": 70,
                "rch_queued_jobs": 0
            }),
        )
        .expect("write pressure fixture");

        let payload = pressure_with_host(
            &SwarmPressureArgs {
                fixture: Some(file.path().to_path_buf()),
                ..SwarmPressureArgs::default()
            },
            None,
        )
        .expect("pressure");

        assert_eq!(payload["schema_version"], "fwc.swarm-pressure/v1");
        assert_eq!(payload["verdict"], "green");
        assert_eq!(payload["pressure_score_0_100"], 10);
        assert_eq!(payload["recommended_cargo_lanes"], 4);
        assert!(
            payload["recommended_agent_slots"]
                .as_u64()
                .is_some_and(|slots| slots > 0)
        );
        assert!(
            payload["toon"]
                .as_str()
                .is_some_and(|toon| { toon.contains("swarm pressure verdict=green") })
        );
        let disk_signal = payload["signals"]
            .as_array()
            .expect("signals")
            .iter()
            .find(|signal| signal["name"] == "disk_free")
            .expect("disk signal");
        assert_eq!(disk_signal["evidence"]["source"], "fixture");
    }

    #[test]
    fn pressure_disk_red_selects_worst_safe_verdict() {
        let payload = pressure_with_host(
            &SwarmPressureArgs {
                logical_cpus: Some(32),
                active_agents: Some(2),
                active_connectors: Some(8),
                disk_free_percent: Some(2),
                inode_free_percent: Some(80),
                memory_free_percent: Some(60),
                rch_queued_jobs: Some(0),
                fixture: None,
                host: None,
            },
            None,
        )
        .expect("pressure");

        assert_eq!(payload["verdict"], "red");
        assert_eq!(payload["pressure_score_0_100"], 95);
        assert_eq!(payload["recommended_agent_slots"], 0);
        assert!(
            payload["remediation_commands"]
                .as_array()
                .expect("remediation commands")
                .iter()
                .any(|command| command == "df -h .")
        );
    }

    #[test]
    fn pressure_missing_dependencies_are_degraded_yellow() {
        let mut file = tempfile::NamedTempFile::new().expect("pressure fixture");
        serde_json::to_writer(
            &mut file,
            &json!({
                "logical_cpus": 16
            }),
        )
        .expect("write pressure fixture");

        let payload = pressure_with_host(
            &SwarmPressureArgs {
                fixture: Some(file.path().to_path_buf()),
                ..SwarmPressureArgs::default()
            },
            None,
        )
        .expect("pressure");

        assert_eq!(payload["verdict"], "yellow");
        assert_eq!(payload["pressure_score_0_100"], 55);
        assert_eq!(
            payload["telemetry_event"]["fields"]["degraded_dependency_count"],
            6
        );
        assert!(
            payload["source"]["caveat"]
                .as_str()
                .is_some_and(|caveat| caveat.contains("never starts Cargo work"))
        );
    }

    #[test]
    fn pressure_parses_df_disk_sample() {
        let sample = parse_df_disk_sample(
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk1 1000 750 250 75% /Volumes/Test Drive\n",
        )
        .expect("disk sample");

        assert_eq!(sample.free_percent, 25);
        assert_eq!(sample.available, 256_000);
        assert_eq!(sample.total, 1_024_000);
    }

    #[test]
    fn pressure_parses_df_inode_sample() {
        let sample = parse_df_inode_sample(
            "Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/disk1 1000 100 900 10% /Volumes/Test Drive\n",
        )
        .expect("inode sample");

        assert_eq!(sample.free_percent, 90);
        assert_eq!(sample.available, 900);
        assert_eq!(sample.total, 1000);
    }

    #[test]
    fn pressure_parses_rch_status_without_sensitive_fields() {
        let input = rch_status_sample_from_json(
            r#"{
              "success": true,
              "data": {
                "posture": "remote_ready",
                "daemon": {
                  "daemon": {
                    "workers_total": 8,
                    "workers_healthy": 7,
                    "slots_total": 54,
                    "slots_available": 49
                  },
                  "workers": [
                    {"id": "vmi1", "host": "192.0.2.1", "pressure_state": "healthy"},
                    {"id": "vmi2", "host": "192.0.2.2", "pressure_state": "warning"}
                  ]
                },
                "active_builds": [
                  {"command": "cargo test -p private-crate", "worker_id": "vmi1"}
                ],
                "queued_builds": [{ "command": "cargo clippy" }],
                "issues": [{"summary": "storage pressure"}]
              }
            }"#,
        )
        .expect("rch sample");

        assert_eq!(input.queued_jobs, 1);
        assert_eq!(input.active_builds, 1);
        assert_eq!(input.warning_count, 2);
        assert_eq!(input.evidence["source"], "rch");
        assert_eq!(input.evidence["queued_builds"], 1);
        assert_eq!(input.evidence["worker_pressure_warning_count"], 1);
        assert!(input.evidence.get("command").is_none());
        assert!(input.evidence.get("host").is_none());
    }

    #[test]
    fn pressure_rch_warning_yellows_even_with_empty_queue() {
        let signals = pressure_signals(&SwarmPressureInputs {
            fixture_path: None,
            logical_cpus: 32,
            active_agents: Some(provided_agent_input(1, "test")),
            active_connectors: Some(provided_connector_input(1, "test")),
            disk_free: Some(PercentPressureInput {
                percent: 80,
                evidence: json!({}),
            }),
            inode_free: Some(PercentPressureInput {
                percent: 80,
                evidence: json!({}),
            }),
            memory_free: Some(PercentPressureInput {
                percent: 80,
                evidence: json!({}),
            }),
            rch_status: Some(RchPressureInput {
                queued_jobs: 0,
                active_builds: 1,
                warning_count: 1,
                evidence: json!({}),
            }),
            signals: Vec::new(),
        });
        let rch_signal = signals
            .iter()
            .find(|signal| signal.name == "rch_status")
            .expect("rch signal");

        assert_eq!(rch_signal.status, SwarmPressureStatus::Yellow);
    }

    #[test]
    fn pressure_host_lifecycle_aggregate_stays_redaction_safe() {
        let input = connector_pressure_from_host_values(
            &json!({
                "registry_version": 42,
                "connectors": [
                    {
                        "id": "fcp.github:enterprise:v1",
                        "name": "GitHub Enterprise",
                        "enabled": true,
                        "health": {"status": "healthy"}
                    },
                    {
                        "id": "fcp.slack:workspace:v1",
                        "name": "Slack Workspace",
                        "enabled": true,
                        "health": {"status": "degraded", "reason": "rate budget"}
                    },
                    {
                        "id": "fcp.gmail:workspace:v1",
                        "name": "Gmail Workspace",
                        "enabled": true,
                        "health": {"status": "unavailable", "reason": "stopped"}
                    },
                    {
                        "id": "fcp.disabled:workspace:v1",
                        "name": "Disabled Connector",
                        "enabled": false,
                        "health": {"status": "healthy"}
                    }
                ]
            }),
            Some(&json!({"status": "healthy"})),
            0,
        );

        assert_eq!(input.active_connectors, 2);
        assert_eq!(input.warning_count, 2);
        assert_eq!(input.evidence["source"], "host-admin-api");
        assert_eq!(input.evidence["connector_count"], 4);
        assert_eq!(input.evidence["enabled_connectors"], 3);
        assert_eq!(input.evidence["unhealthy_enabled_connectors"], 2);
        assert_eq!(input.evidence["registry_version"], 42);
        let evidence = serde_json::to_string(&input.evidence).expect("evidence JSON");
        assert!(!evidence.contains("fcp.github"));
        assert!(!evidence.contains("Slack Workspace"));
        assert!(!evidence.contains("rate budget"));
    }

    #[test]
    fn pressure_parses_beads_in_progress_snapshot_without_issue_details() {
        let input = beads_in_progress_sample_from_json(
            r#"{
              "issues": [
                {"id": "fc-1", "title": "private detail", "status": "in_progress", "assignee": "IcyTern"},
                {"id": "fc-2", "status": "in_progress", "assignee": "SageStork"},
                {"id": "fc-3", "status": "in_progress"},
                {"id": "fc-4", "status": "open", "assignee": "OtherAgent"}
              ],
              "total": 3
            }"#,
        )
        .expect("beads sample");

        assert_eq!(input.in_progress_count, 3);
        assert_eq!(input.unique_assignee_count, 2);
        assert_eq!(input.unassigned_count, 1);
        assert_eq!(input.evidence["source"], "beads");
        assert_eq!(input.evidence["in_progress_count"], 3);
        assert!(input.evidence.get("title").is_none());
        assert!(input.evidence.get("id").is_none());
    }

    #[test]
    fn pressure_parses_agent_mail_status_without_repair_commands() {
        let input = agent_mail_status_sample_from_json(
            r#"{
              "health": "degraded",
              "active_agents": 2,
              "recent_messages": 8,
              "recommendations": [
                {"safe_command": "am doctor check --json", "reason": "operator detail"}
              ],
              "recovery": {"mode": "degraded_read_only"}
            }"#,
        )
        .expect("agent mail sample");

        assert_eq!(input.active_agents, 2);
        assert_eq!(input.warning_count, 1);
        assert_eq!(input.evidence["source"], "agent-mail");
        assert_eq!(input.evidence["health"], "degraded");
        assert_eq!(input.evidence["recovery_mode"], "degraded_read_only");
        assert_eq!(input.evidence["agent_mail_repair_attempted"], false);
        assert!(input.evidence.get("recommendations").is_none());
        assert!(input.evidence.get("safe_command").is_none());
    }

    #[test]
    fn pressure_combines_beads_and_agent_mail_active_agents() {
        let beads = beads_in_progress_sample_from_json(
            r#"{
              "issues": [
                {"status": "in_progress", "assignee": "IcyTern"},
                {"status": "in_progress", "assignee": "SageStork"}
              ]
            }"#,
        )
        .expect("beads sample");
        let agent_mail =
            agent_mail_status_sample_from_json(r#"{"health": "ok", "active_agents": 1}"#)
                .expect("agent mail sample");
        let input = coordination_active_agents_from_samples(Some(&beads), Some(&agent_mail))
            .expect("coordination sample");

        assert_eq!(input.active_agents, 2);
        assert_eq!(input.warning_count, 0);
        assert_eq!(input.evidence["source"], "coordination");
        assert_eq!(input.evidence["beads"]["unique_assignee_count"], 2);
        assert_eq!(input.evidence["agent_mail"]["active_agents"], 1);
    }

    #[test]
    fn pressure_agent_mail_degraded_health_yellows_coordination_signal() {
        let agent_mail = agent_mail_status_sample_from_json(
            r#"{"health": "degraded", "active_agents": 1, "recovery": {"mode": "read_only"}}"#,
        )
        .expect("agent mail sample");
        let input = coordination_active_agents_from_samples(None, Some(&agent_mail))
            .expect("coordination sample");
        let signals = pressure_signals(&SwarmPressureInputs {
            fixture_path: None,
            logical_cpus: 32,
            active_agents: Some(input),
            active_connectors: Some(provided_connector_input(1, "test")),
            disk_free: Some(PercentPressureInput {
                percent: 80,
                evidence: json!({}),
            }),
            inode_free: Some(PercentPressureInput {
                percent: 80,
                evidence: json!({}),
            }),
            memory_free: Some(PercentPressureInput {
                percent: 80,
                evidence: json!({}),
            }),
            rch_status: Some(RchPressureInput {
                queued_jobs: 0,
                active_builds: 1,
                warning_count: 0,
                evidence: json!({}),
            }),
            signals: Vec::new(),
        });
        let agent_signal = signals
            .iter()
            .find(|signal| signal.name == "agent_mail_agents")
            .expect("agent signal");

        assert_eq!(agent_signal.status, SwarmPressureStatus::Yellow);
        assert_eq!(agent_signal.evidence["agent_mail"]["health"], "degraded");
        assert_eq!(agent_signal.evidence["agent_mail_repair_attempted"], false);
    }

    #[test]
    fn pressure_parses_linux_meminfo_available_percent() {
        let input = linux_memory_sample_from_meminfo(
            "MemTotal:       1000 kB\nMemFree:         100 kB\nMemAvailable:    250 kB\n",
        )
        .expect("linux memory sample");

        assert_eq!(input.percent, 25);
        assert_eq!(input.evidence["source"], "local-os");
        assert_eq!(input.evidence["method"], "/proc/meminfo");
    }

    #[test]
    fn pressure_parses_macos_vm_stat_available_percent() {
        let input = macos_memory_sample_from_vm_stat(
            409_600,
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free:                               10.\nPages inactive:                            5.\nPages speculative:                         2.\n",
        )
        .expect("macos memory sample");

        assert_eq!(input.percent, 17);
        assert_eq!(input.evidence["source"], "local-os");
        assert_eq!(input.evidence["available_pages"], 17);
    }

    #[test]
    fn pressure_run_dispatches_new_subcommand() {
        let payload = run_with_host(
            &super::SwarmEvidenceArgs {
                command: SwarmEvidenceCommand::Pressure(SwarmPressureArgs {
                    logical_cpus: Some(8),
                    active_agents: Some(1),
                    active_connectors: Some(2),
                    disk_free_percent: Some(20),
                    inode_free_percent: Some(20),
                    memory_free_percent: Some(20),
                    rch_queued_jobs: Some(0),
                    fixture: None,
                    host: None,
                }),
            },
            None,
        )
        .expect("run pressure");

        assert_eq!(payload["command"], "swarm pressure");
        assert_eq!(payload["verdict"], "green");
    }

    #[test]
    fn pressure_scoring_uses_highest_severity() {
        let signals = vec![
            SwarmPressureSignal {
                name: "cpu_capacity".to_owned(),
                status: SwarmPressureStatus::Green,
                value: "64 logical CPU(s)".to_owned(),
                threshold: ">=8 green".to_owned(),
                evidence: json!({}),
            },
            SwarmPressureSignal {
                name: "rch_status".to_owned(),
                status: SwarmPressureStatus::Yellow,
                value: "40 queued rch job(s)".to_owned(),
                threshold: "<32 green".to_owned(),
                evidence: json!({}),
            },
            SwarmPressureSignal {
                name: "disk_free".to_owned(),
                status: SwarmPressureStatus::Red,
                value: "2% disk free percent".to_owned(),
                threshold: ">=15% green".to_owned(),
                evidence: json!({}),
            },
        ];

        assert_eq!(pressure_score(&signals), 95);
        assert_eq!(pressure_verdict(&signals), SwarmPressureStatus::Red);
    }
}
