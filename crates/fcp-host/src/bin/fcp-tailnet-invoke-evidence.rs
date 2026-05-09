//! Emit redaction-safe JSONL evidence for tailnet invoke proof runs.
//!
//! This runner is intentionally conservative: it emits real-transport evidence
//! only when an operator supplies a tailnet-reachable `/rpc/invoke` endpoint,
//! the request succeeds, and LocalAPI route telemetry proves the requested
//! direct-LAN or DERP/fallback path. Otherwise it emits a structured skip record
//! instead of treating host-first or synthetic RTT measurements as tailnet proof.

use std::net::IpAddr;
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};
use std::{env, fs};

use fcp_async_core::{
    compatibility_cx,
    http::{HttpClientBuilder, Method},
    time,
};
use fcp_core::{InvokeResponse, InvokeStatus};
use fcp_host::{
    TailnetInvokeAttemptEvidence, TailnetInvokeAttemptOutcome, TailnetInvokeEvidenceRecord,
    TailnetInvokeHarnessObservation, TailnetInvokeLatencySummary, TailnetInvokeNodeEvidence,
    TailnetInvokePrerequisite, TailnetInvokeRealTransportInput, TailnetInvokeRouteMode,
};
use fcp_sandbox::is_tailnet_range;
use fcp_tailscale::TailscaleStatus;
use serde_json::Value;
use url::Url;

const USAGE: &str = "\
Usage: fcp-tailnet-invoke-evidence [OPTIONS]

Options:
  --route <direct-lan|derp-fallback|all>   Requested route mode (default: direct-lan)
  --topology <label>                       Redaction-safe topology label
  --localapi-url <url>                     HTTP-exposed Tailscale LocalAPI base URL
  --invoke-url <url>                       Tailnet-reachable fcp-host /rpc/invoke URL
  --invoke-request-json <json>             InvokeRequest JSON body to POST
  --invoke-request-file <path>             File containing InvokeRequest JSON body
  --invoke-attempts <n>                    Number of invoke samples to collect (default: 1)
  --caller-node-id <id>                    Raw caller node label; emitted only as a hash
  --responder-node-id <id>                 Raw responder node label; emitted only as a hash
  --git-revision <rev>                     Git revision under test
  -h, --help                               Print this help

Environment:
  FCP_TAILSCALE_LOCALAPI_URL               Fallback for --localapi-url
  FCP_TAILNET_INVOKE_URL                   Fallback for --invoke-url
  FCP_TAILNET_INVOKE_REQUEST_JSON          Fallback for --invoke-request-json
  FCP_TAILNET_INVOKE_REQUEST_FILE          Fallback for --invoke-request-file
  FCP_TAILNET_INVOKE_ATTEMPTS              Fallback for --invoke-attempts
  FCP_TAILNET_CALLER_NODE_ID               Fallback for --caller-node-id
  FCP_TAILNET_RESPONDER_NODE_ID            Fallback for --responder-node-id
  FCP_TAILNET_EVIDENCE_GIT_REVISION        Fallback for --git-revision
";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    route_selection: TailnetInvokeRouteSelection,
    topology: String,
    localapi_url: Option<String>,
    invoke_url: Option<String>,
    invoke_request_source: Option<InvokeRequestSource>,
    invoke_attempts: Option<usize>,
    caller_node_id: Option<String>,
    responder_node_id: Option<String>,
    git_revision: Option<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            route_selection: TailnetInvokeRouteSelection::Single(TailnetInvokeRouteMode::DirectLan),
            topology: "tailnet invoke prerequisite probe".to_string(),
            localapi_url: None,
            invoke_url: None,
            invoke_request_source: None,
            invoke_attempts: None,
            caller_node_id: None,
            responder_node_id: None,
            git_revision: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InvokeRequestSource {
    InlineJson(String),
    File(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TailnetInvokeRouteSelection {
    Single(TailnetInvokeRouteMode),
    All,
}

impl TailnetInvokeRouteSelection {
    fn parse_cli(value: &str) -> Result<Self, String> {
        if value == "all" {
            Ok(Self::All)
        } else {
            TailnetInvokeRouteMode::parse_cli(value).map(Self::Single)
        }
    }

    fn route_modes(self) -> Vec<TailnetInvokeRouteMode> {
        match self {
            Self::Single(route_mode) => vec![route_mode],
            Self::All => vec![
                TailnetInvokeRouteMode::DirectLan,
                TailnetInvokeRouteMode::DerpFallback,
            ],
        }
    }
}

fn main() -> ExitCode {
    let command_line = env::args().collect::<Vec<_>>();
    let cli = match parse_cli(&command_line) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("{error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let invoke_probe_config = match resolve_invoke_probe_config(&cli) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{error}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let localapi_url = cli
        .localapi_url
        .clone()
        .or_else(|| env::var("FCP_TAILSCALE_LOCALAPI_URL").ok());
    let git_revision = cli
        .git_revision
        .clone()
        .or_else(|| env::var("FCP_TAILNET_EVIDENCE_GIT_REVISION").ok())
        .unwrap_or_else(detect_git_revision);
    for route_mode in cli.route_selection.route_modes() {
        let route_peer_identity = invoke_probe_config
            .as_ref()
            .map(|config| &config.route_peer_identity);
        let mut observation =
            observe_tailnet(localapi_url.as_deref(), route_mode, route_peer_identity);
        let record = if let Some(config) = &invoke_probe_config {
            observation.production_mesh_invoke_transport_available = true;
            observation.production_mesh_invoke_transport_detail =
                "configured tailnet-reachable fcp-host /rpc/invoke endpoint".to_string();
            match fcp_async_core::runtime::block_on_sync(async {
                run_tailnet_invoke_probe(config).await
            }) {
                Ok(run) => evidence_record_from_probe(
                    route_mode,
                    command_line.clone(),
                    git_revision.clone(),
                    cli.topology.clone(),
                    observation,
                    config,
                    run,
                ),
                Err(error) => {
                    let mut prerequisites = observation.prerequisites(route_mode);
                    prerequisites.push(TailnetInvokePrerequisite::new(
                        "successful-tailnet-invoke",
                        false,
                        format!("runtime_error:{error}"),
                    ));
                    TailnetInvokeEvidenceRecord::structured_skip(
                        route_mode,
                        command_line.clone(),
                        git_revision.clone(),
                        cli.topology.clone(),
                        prerequisites,
                    )
                }
            }
        } else {
            observation.structured_skip_record(
                route_mode,
                command_line.clone(),
                git_revision.clone(),
                cli.topology.clone(),
            )
        };

        match record.to_jsonl_line() {
            Ok(line) => println!("{line}"),
            Err(error) => {
                eprintln!("failed to serialize tailnet invoke evidence: {error}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}

fn parse_cli(args: &[String]) -> Result<Option<Cli>, String> {
    let mut cli = Cli::default();
    let mut iter = args.iter().skip(1);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--route" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--route requires a value".to_string())?;
                cli.route_selection = TailnetInvokeRouteSelection::parse_cli(value)?;
            }
            "--topology" => {
                cli.topology = iter
                    .next()
                    .ok_or_else(|| "--topology requires a value".to_string())?
                    .clone();
            }
            "--localapi-url" => {
                cli.localapi_url = Some(
                    iter.next()
                        .ok_or_else(|| "--localapi-url requires a value".to_string())?
                        .clone(),
                );
            }
            "--invoke-url" => {
                cli.invoke_url = Some(
                    iter.next()
                        .ok_or_else(|| "--invoke-url requires a value".to_string())?
                        .clone(),
                );
            }
            "--invoke-request-json" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--invoke-request-json requires a value".to_string())?
                    .clone();
                set_invoke_request_source(
                    &mut cli.invoke_request_source,
                    InvokeRequestSource::InlineJson(value),
                )?;
            }
            "--invoke-request-file" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--invoke-request-file requires a value".to_string())?
                    .clone();
                set_invoke_request_source(
                    &mut cli.invoke_request_source,
                    InvokeRequestSource::File(value),
                )?;
            }
            "--invoke-attempts" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "--invoke-attempts requires a value".to_string())?;
                cli.invoke_attempts = Some(parse_attempt_count(value)?);
            }
            "--caller-node-id" => {
                cli.caller_node_id = Some(
                    iter.next()
                        .ok_or_else(|| "--caller-node-id requires a value".to_string())?
                        .clone(),
                );
            }
            "--responder-node-id" => {
                cli.responder_node_id = Some(
                    iter.next()
                        .ok_or_else(|| "--responder-node-id requires a value".to_string())?
                        .clone(),
                );
            }
            "--git-revision" => {
                cli.git_revision = Some(
                    iter.next()
                        .ok_or_else(|| "--git-revision requires a value".to_string())?
                        .clone(),
                );
            }
            value if value.starts_with("--route=") => {
                let value = value.split_once('=').map_or("", |(_, route)| route);
                cli.route_selection = TailnetInvokeRouteSelection::parse_cli(value)?;
            }
            value if value.starts_with("--topology=") => {
                cli.topology = value
                    .split_once('=')
                    .map_or("", |(_, topology)| topology)
                    .to_string();
            }
            value if value.starts_with("--localapi-url=") => {
                cli.localapi_url = Some(
                    value
                        .split_once('=')
                        .map_or("", |(_, localapi_url)| localapi_url)
                        .to_string(),
                );
            }
            value if value.starts_with("--invoke-url=") => {
                cli.invoke_url = Some(
                    value
                        .split_once('=')
                        .map_or("", |(_, invoke_url)| invoke_url)
                        .to_string(),
                );
            }
            value if value.starts_with("--invoke-request-json=") => {
                let value = value
                    .split_once('=')
                    .map_or("", |(_, request_json)| request_json)
                    .to_string();
                set_invoke_request_source(
                    &mut cli.invoke_request_source,
                    InvokeRequestSource::InlineJson(value),
                )?;
            }
            value if value.starts_with("--invoke-request-file=") => {
                let value = value
                    .split_once('=')
                    .map_or("", |(_, request_file)| request_file)
                    .to_string();
                set_invoke_request_source(
                    &mut cli.invoke_request_source,
                    InvokeRequestSource::File(value),
                )?;
            }
            value if value.starts_with("--invoke-attempts=") => {
                let value = value.split_once('=').map_or("", |(_, attempts)| attempts);
                cli.invoke_attempts = Some(parse_attempt_count(value)?);
            }
            value if value.starts_with("--caller-node-id=") => {
                cli.caller_node_id = Some(
                    value
                        .split_once('=')
                        .map_or("", |(_, caller)| caller)
                        .to_string(),
                );
            }
            value if value.starts_with("--responder-node-id=") => {
                cli.responder_node_id = Some(
                    value
                        .split_once('=')
                        .map_or("", |(_, responder)| responder)
                        .to_string(),
                );
            }
            value if value.starts_with("--git-revision=") => {
                cli.git_revision = Some(
                    value
                        .split_once('=')
                        .map_or("", |(_, git_revision)| git_revision)
                        .to_string(),
                );
            }
            other => return Err(format!("unknown option '{other}'")),
        }
    }

    Ok(Some(cli))
}

fn set_invoke_request_source(
    slot: &mut Option<InvokeRequestSource>,
    source: InvokeRequestSource,
) -> Result<(), String> {
    if slot.is_some() {
        return Err(
            "provide only one of --invoke-request-json or --invoke-request-file".to_string(),
        );
    }
    *slot = Some(source);
    Ok(())
}

fn parse_attempt_count(value: &str) -> Result<usize, String> {
    let attempts = value
        .parse::<usize>()
        .map_err(|error| format!("invalid --invoke-attempts value '{value}': {error}"))?;
    if attempts == 0 {
        return Err("--invoke-attempts must be greater than zero".to_string());
    }
    Ok(attempts)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TailnetInvokeProbeConfig {
    invoke_url: String,
    request_body: Vec<u8>,
    attempts: usize,
    caller_node_id: String,
    responder_node_id: String,
    route_peer_identity: TailnetInvokeRoutePeerIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TailnetInvokeRoutePeerIdentity {
    invoke_host: String,
    invoke_ip: Option<IpAddr>,
    responder_node_id: String,
}

impl TailnetInvokeRoutePeerIdentity {
    fn new(invoke_url: &str, responder_node_id: &str) -> Result<Self, String> {
        let url = Url::parse(invoke_url)
            .map_err(|error| format!("--invoke-url must be an absolute URL: {error}"))?;
        let invoke_host = url
            .host_str()
            .map(normalize_tailnet_identity)
            .ok_or_else(|| "--invoke-url must include a host".to_string())?;
        let invoke_ip = invoke_host.parse::<IpAddr>().ok();
        Ok(Self {
            invoke_host,
            invoke_ip,
            responder_node_id: normalize_tailnet_identity(responder_node_id),
        })
    }

    fn matches_peer(&self, peer_key: &str, peer: &serde_json::Map<String, Value>) -> bool {
        if self.matches_text(peer_key) {
            return true;
        }
        for field in ["ID", "HostName", "DNSName", "Name"] {
            if peer
                .get(field)
                .and_then(Value::as_str)
                .is_some_and(|value| self.matches_text(value))
            {
                return true;
            }
        }
        peer.get("TailscaleIPs")
            .and_then(Value::as_array)
            .is_some_and(|ips| {
                ips.iter()
                    .filter_map(Value::as_str)
                    .any(|value| self.matches_ip(value))
            })
    }

    fn matches_text(&self, value: &str) -> bool {
        let candidate = normalize_tailnet_identity(value);
        if candidate.is_empty() {
            return false;
        }
        candidate == self.invoke_host
            || candidate == self.responder_node_id
            || self
                .invoke_host
                .strip_prefix(&candidate)
                .is_some_and(|suffix| suffix.starts_with('.'))
    }

    fn matches_ip(&self, value: &str) -> bool {
        let Some(invoke_ip) = self.invoke_ip else {
            return false;
        };
        normalize_tailnet_identity(value)
            .parse::<IpAddr>()
            .is_ok_and(|candidate| candidate == invoke_ip)
    }
}

fn resolve_invoke_probe_config(cli: &Cli) -> Result<Option<TailnetInvokeProbeConfig>, String> {
    let invoke_url = cli
        .invoke_url
        .clone()
        .or_else(|| env::var("FCP_TAILNET_INVOKE_URL").ok());
    let request_source = resolve_invoke_request_source(cli)?;

    match (invoke_url, request_source) {
        (None, None) => Ok(None),
        (Some(_), None) => {
            Err("--invoke-url requires --invoke-request-json or --invoke-request-file".to_string())
        }
        (None, Some(_)) => {
            Err("--invoke-request-json/--invoke-request-file requires --invoke-url".to_string())
        }
        (Some(invoke_url), Some(request_source)) => {
            validate_tailnet_invoke_url(&invoke_url)?;
            let attempts = if let Some(attempts) = cli.invoke_attempts {
                attempts
            } else if let Ok(value) = env::var("FCP_TAILNET_INVOKE_ATTEMPTS") {
                parse_attempt_count(&value)?
            } else {
                1
            };
            let request_body = load_invoke_request_body(request_source)?;
            let caller_node_id = cli
                .caller_node_id
                .clone()
                .or_else(|| env::var("FCP_TAILNET_CALLER_NODE_ID").ok())
                .unwrap_or_else(|| "caller".to_string());
            let responder_node_id = cli
                .responder_node_id
                .clone()
                .or_else(|| env::var("FCP_TAILNET_RESPONDER_NODE_ID").ok())
                .unwrap_or_else(|| invoke_url.clone());
            let route_peer_identity =
                TailnetInvokeRoutePeerIdentity::new(&invoke_url, &responder_node_id)?;

            Ok(Some(TailnetInvokeProbeConfig {
                invoke_url,
                request_body,
                attempts,
                caller_node_id,
                responder_node_id,
                route_peer_identity,
            }))
        }
    }
}

fn resolve_invoke_request_source(cli: &Cli) -> Result<Option<InvokeRequestSource>, String> {
    if cli.invoke_request_source.is_some() {
        return Ok(cli.invoke_request_source.clone());
    }

    let inline_json = env::var("FCP_TAILNET_INVOKE_REQUEST_JSON").ok();
    let file = env::var("FCP_TAILNET_INVOKE_REQUEST_FILE").ok();
    match (inline_json, file) {
        (None, None) => Ok(None),
        (Some(json), None) => Ok(Some(InvokeRequestSource::InlineJson(json))),
        (None, Some(file)) => Ok(Some(InvokeRequestSource::File(file))),
        (Some(_), Some(_)) => Err(
            "set only one of FCP_TAILNET_INVOKE_REQUEST_JSON or FCP_TAILNET_INVOKE_REQUEST_FILE"
                .to_string(),
        ),
    }
}

fn load_invoke_request_body(source: InvokeRequestSource) -> Result<Vec<u8>, String> {
    let raw = match source {
        InvokeRequestSource::InlineJson(json) => json,
        InvokeRequestSource::File(path) => {
            fs::read_to_string(&path).map_err(|error| format!("read_request_file:{error}"))?
        }
    };
    let value: Value =
        serde_json::from_str(&raw).map_err(|error| format!("parse_invoke_request_json:{error}"))?;
    serde_json::to_vec(&value).map_err(|error| format!("serialize_invoke_request_json:{error}"))
}

fn validate_tailnet_invoke_url(raw_url: &str) -> Result<(), String> {
    let url = Url::parse(raw_url)
        .map_err(|error| format!("--invoke-url must be an absolute URL: {error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("--invoke-url must use http or https".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("--invoke-url must not embed credentials".to_string());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("--invoke-url must not include query strings or fragments".to_string());
    }
    if url.path() != "/rpc/invoke" {
        return Err("--invoke-url must point to the fcp-host /rpc/invoke path".to_string());
    }
    let host = url
        .host_str()
        .ok_or_else(|| "--invoke-url must include a host".to_string())?;
    if !is_tailnet_invoke_host(host) {
        return Err(
            "--invoke-url host must be a tailnet-class endpoint (.ts.net, .tailnet., or tailnet IP)"
                .to_string(),
        );
    }
    Ok(())
}

fn is_tailnet_invoke_host(host: &str) -> bool {
    let host = normalize_tailnet_identity(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_tailnet_range(ip);
    }
    host.ends_with(".ts.net") || host.contains(".tailnet.")
}

fn normalize_tailnet_identity(value: &str) -> String {
    value
        .trim_matches(|ch| ch == '[' || ch == ']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn observe_tailnet(
    localapi_url: Option<&str>,
    route_mode: TailnetInvokeRouteMode,
    route_peer_identity: Option<&TailnetInvokeRoutePeerIdentity>,
) -> TailnetInvokeHarnessObservation {
    let Some(localapi_url) = localapi_url else {
        return TailnetInvokeHarnessObservation::localapi_not_configured();
    };

    let status =
        fcp_async_core::runtime::block_on_sync(async { read_tailnet_status(localapi_url).await });

    match status {
        Ok(Ok((status, status_json))) => {
            let online_peer_count = status.peer.values().filter(|peer| peer.online).count();
            let tailscale_connected = status.backend_state == "Running" && status.self_node.online;
            let route_telemetry =
                observe_route_telemetry(&status_json, route_mode, route_peer_identity);
            TailnetInvokeHarnessObservation {
                localapi_configured: true,
                tailscale_connected,
                online_peer_count,
                route_telemetry_available: route_telemetry.available,
                route_telemetry_detail: route_telemetry.detail,
                production_mesh_invoke_transport_available: false,
                production_mesh_invoke_transport_detail:
                    "no production tailnet invoke endpoint configured".to_string(),
                localapi_detail: format!("backend_state={}", status.backend_state),
            }
        }
        Ok(Err(error)) => TailnetInvokeHarnessObservation {
            localapi_configured: true,
            tailscale_connected: false,
            online_peer_count: 0,
            route_telemetry_available: false,
            route_telemetry_detail: "LocalAPI status unavailable".to_string(),
            production_mesh_invoke_transport_available: false,
            production_mesh_invoke_transport_detail:
                "no production tailnet invoke endpoint configured".to_string(),
            localapi_detail: format!("localapi_error:{}", redact_sensitive_text(&error)),
        },
        Err(error) => {
            let error = error.to_string();
            TailnetInvokeHarnessObservation {
                localapi_configured: true,
                tailscale_connected: false,
                online_peer_count: 0,
                route_telemetry_available: false,
                route_telemetry_detail: "LocalAPI status unavailable".to_string(),
                production_mesh_invoke_transport_available: false,
                production_mesh_invoke_transport_detail:
                    "no production tailnet invoke endpoint configured".to_string(),
                localapi_detail: format!("runtime_error:{}", redact_sensitive_text(&error)),
            }
        }
    }
}

async fn read_tailnet_status(base_url: &str) -> Result<(TailscaleStatus, Value), String> {
    let base_url = base_url.trim_end_matches('/');
    let url = format!("{base_url}/localapi/v0/status");
    let cx = compatibility_cx();
    let client = HttpClientBuilder::new()
        .user_agent("fcp-tailnet-invoke-evidence/0.1.0")
        .build();

    let response = match time::timeout(
        Duration::from_secs(30),
        client.request(&cx, Method::Get, &url, Vec::new(), Vec::new()),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => return Err(format!("request_failed:{error}")),
        Err(error) => return Err(format!("request_timeout:{error}")),
    };

    if !response.is_success() {
        let status = format!("{} {}", response.status, response.reason);
        return Err(format!("http_status:{status}"));
    }

    let status_json: Value = response
        .json()
        .map_err(|error| format!("parse_json:{error}"))?;
    let status = serde_json::from_value(status_json.clone())
        .map_err(|error| format!("parse_status:{error}"))?;
    Ok((status, status_json))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TailnetInvokeProbeRun {
    attempts: Vec<TailnetInvokeAttemptEvidence>,
}

impl TailnetInvokeProbeRun {
    fn successful_attempt_count(&self) -> usize {
        self.attempts
            .iter()
            .filter(|attempt| attempt.outcome == TailnetInvokeAttemptOutcome::Success)
            .count()
    }

    fn auth_result(&self) -> String {
        if self.successful_attempt_count() > 0 {
            "capability_verified".to_string()
        } else {
            "not_verified".to_string()
        }
    }

    fn success_detail(&self) -> String {
        format!(
            "successful_attempts={},total_attempts={}",
            self.successful_attempt_count(),
            self.attempts.len()
        )
    }

    fn retries(&self) -> u64 {
        u64::try_from(self.attempts.len().saturating_sub(1)).unwrap_or(u64::MAX)
    }
}

async fn run_tailnet_invoke_probe(config: &TailnetInvokeProbeConfig) -> TailnetInvokeProbeRun {
    let cx = compatibility_cx();
    let client = HttpClientBuilder::new()
        .user_agent("fcp-tailnet-invoke-evidence/0.1.0")
        .build();
    let headers = vec![
        ("content-type".to_string(), "application/json".to_string()),
        ("accept".to_string(), "application/json".to_string()),
    ];
    let mut attempts = Vec::with_capacity(config.attempts);

    for attempt_index in 0..config.attempts {
        let started_at = Instant::now();
        let response = time::timeout(
            Duration::from_secs(30),
            client.request(
                &cx,
                Method::Post,
                &config.invoke_url,
                headers.clone(),
                config.request_body.clone(),
            ),
        )
        .await;
        let latency_ns = elapsed_nanos(started_at);
        let attempt_index = u64::try_from(attempt_index).unwrap_or(u64::MAX);

        attempts.push(match response {
            Ok(Ok(response)) => classify_invoke_response(attempt_index, latency_ns, response),
            Ok(Err(error)) => TailnetInvokeAttemptEvidence::non_success(
                attempt_index,
                TailnetInvokeAttemptOutcome::Error,
                Some(latency_ns),
                "request_failed",
                error.to_string(),
            ),
            Err(error) => TailnetInvokeAttemptEvidence::non_success(
                attempt_index,
                TailnetInvokeAttemptOutcome::Timeout,
                Some(latency_ns),
                "request_timeout",
                error.to_string(),
            ),
        });
    }

    TailnetInvokeProbeRun { attempts }
}

fn classify_invoke_response(
    attempt_index: u64,
    latency_ns: u64,
    response: fcp_async_core::http::HttpResponse,
) -> TailnetInvokeAttemptEvidence {
    if !response.is_success() {
        return TailnetInvokeAttemptEvidence::non_success(
            attempt_index,
            TailnetInvokeAttemptOutcome::Error,
            Some(latency_ns),
            format!("http_status_{}", response.status),
            format!("{} {}", response.status, response.reason),
        );
    }

    match serde_json::from_slice::<InvokeResponse>(&response.body) {
        Ok(invoke_response) if invoke_response.status == InvokeStatus::Ok => {
            TailnetInvokeAttemptEvidence::success(attempt_index, latency_ns)
        }
        Ok(invoke_response) => TailnetInvokeAttemptEvidence::non_success(
            attempt_index,
            TailnetInvokeAttemptOutcome::Error,
            Some(latency_ns),
            "invoke_response_error",
            invoke_response
                .error
                .map_or_else(|| "status=error".to_string(), |error| error.to_string()),
        ),
        Err(error) => TailnetInvokeAttemptEvidence::non_success(
            attempt_index,
            TailnetInvokeAttemptOutcome::Error,
            Some(latency_ns),
            "parse_invoke_response",
            error.to_string(),
        ),
    }
}

fn elapsed_nanos(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn evidence_record_from_probe(
    route_mode: TailnetInvokeRouteMode,
    command_line: Vec<String>,
    git_revision: String,
    topology: String,
    observation: TailnetInvokeHarnessObservation,
    config: &TailnetInvokeProbeConfig,
    run: TailnetInvokeProbeRun,
) -> TailnetInvokeEvidenceRecord {
    let mut prerequisites = observation.prerequisites(route_mode);
    prerequisites.push(TailnetInvokePrerequisite::new(
        "successful-tailnet-invoke",
        run.successful_attempt_count() > 0,
        run.success_detail(),
    ));
    let prerequisites_satisfied = prerequisites
        .iter()
        .all(|prerequisite| prerequisite.satisfied);
    let latency = TailnetInvokeLatencySummary::from_successful_attempts(&run.attempts);

    if prerequisites_satisfied && let Some(latency) = latency {
        return TailnetInvokeEvidenceRecord::real_transport(TailnetInvokeRealTransportInput {
            route_mode,
            command_line,
            git_revision,
            topology,
            nodes: vec![
                TailnetInvokeNodeEvidence::new("caller", &config.caller_node_id),
                TailnetInvokeNodeEvidence::new("responder", &config.responder_node_id),
            ],
            auth_result: run.auth_result(),
            retries: run.retries(),
            latency,
            attempts: run.attempts,
        });
    }

    TailnetInvokeEvidenceRecord::structured_skip(
        route_mode,
        command_line,
        git_revision,
        topology,
        prerequisites,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteTelemetryObservation {
    available: bool,
    detail: String,
}

fn observe_route_telemetry(
    status_json: &Value,
    route_mode: TailnetInvokeRouteMode,
    route_peer_identity: Option<&TailnetInvokeRoutePeerIdentity>,
) -> RouteTelemetryObservation {
    let Some(peers) = status_json.get("Peer").and_then(Value::as_object) else {
        return RouteTelemetryObservation {
            available: false,
            detail: "peer_map=missing".to_string(),
        };
    };

    let mut active_online_peers = 0usize;
    let mut matched_active_peers = 0usize;
    let mut direct_candidates = 0usize;
    let mut derp_candidates = 0usize;

    for (peer_key, peer) in peers
        .iter()
        .filter_map(|(peer_key, peer)| peer.as_object().map(|peer| (peer_key.as_str(), peer)))
    {
        let online = peer.get("Online").and_then(Value::as_bool).unwrap_or(false);
        let active = peer.get("Active").and_then(Value::as_bool).unwrap_or(false);
        if !(online && active) {
            continue;
        }

        active_online_peers += 1;
        if route_peer_identity.is_some_and(|identity| !identity.matches_peer(peer_key, peer)) {
            continue;
        }
        matched_active_peers += 1;
        let cur_addr = non_empty_string(peer.get("CurAddr"));
        let relay = non_empty_string(peer.get("Relay"));
        let peer_relay = non_empty_string(peer.get("PeerRelay"));
        if cur_addr && !relay && !peer_relay {
            direct_candidates += 1;
        }
        if relay || peer_relay {
            derp_candidates += 1;
        }
    }

    let available = match route_mode {
        TailnetInvokeRouteMode::DirectLan => direct_candidates > 0,
        TailnetInvokeRouteMode::DerpFallback => derp_candidates > 0,
    };
    RouteTelemetryObservation {
        available,
        detail: format!(
            "active_online_peers={active_online_peers},matched_active_peers={matched_active_peers},direct_candidates={direct_candidates},derp_candidates={derp_candidates}"
        ),
    }
}

fn non_empty_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty())
}

fn redact_sensitive_text(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    if [
        "token",
        "secret",
        "password",
        "credential",
        "bearer",
        "api_key",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        "[REDACTED]".to_string()
    } else {
        input.to_string()
    }
}

fn detect_git_revision() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                String::from_utf8(output.stdout).ok()
            } else {
                None
            }
        })
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::RequestId;
    use fcp_host::TailnetInvokeEvidenceSource;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    fn satisfied_observation(route_telemetry_available: bool) -> TailnetInvokeHarnessObservation {
        TailnetInvokeHarnessObservation {
            localapi_configured: true,
            tailscale_connected: true,
            online_peer_count: 1,
            route_telemetry_available,
            route_telemetry_detail:
                "active_online_peers=1,matched_active_peers=1,direct_candidates=1,derp_candidates=0"
                    .to_string(),
            production_mesh_invoke_transport_available: true,
            production_mesh_invoke_transport_detail:
                "configured tailnet-reachable fcp-host /rpc/invoke endpoint".to_string(),
            localapi_detail: "backend_state=Running".to_string(),
        }
    }

    fn invoke_probe_config() -> TailnetInvokeProbeConfig {
        TailnetInvokeProbeConfig {
            invoke_url: "http://responder.tailnet.ts.net/rpc/invoke".to_string(),
            request_body: br#"{"type":"invoke"}"#.to_vec(),
            attempts: 2,
            caller_node_id: "caller.tailnet.ts.net".to_string(),
            responder_node_id: "responder.tailnet.ts.net".to_string(),
            route_peer_identity: TailnetInvokeRoutePeerIdentity::new(
                "http://responder.tailnet.ts.net/rpc/invoke",
                "responder.tailnet.ts.net",
            )
            .expect("route identity"),
        }
    }

    #[test]
    fn parse_cli_defaults_to_direct_lan() {
        let cli = parse_cli(&args(&["fcp-tailnet-invoke-evidence"]))
            .expect("parse")
            .expect("not help");

        assert_eq!(
            cli.route_selection,
            TailnetInvokeRouteSelection::Single(TailnetInvokeRouteMode::DirectLan)
        );
        assert_eq!(cli.topology, "tailnet invoke prerequisite probe");
        assert!(cli.localapi_url.is_none());
    }

    #[test]
    fn parse_cli_accepts_real_invoke_probe_options() {
        let cli = parse_cli(&args(&[
            "fcp-tailnet-invoke-evidence",
            "--invoke-url=http://responder.tailnet.ts.net/rpc/invoke",
            "--invoke-request-json",
            r#"{"type":"invoke"}"#,
            "--invoke-attempts=5",
            "--caller-node-id",
            "caller-node",
            "--responder-node-id=responder-node",
        ]))
        .expect("parse")
        .expect("not help");

        assert_eq!(
            cli.invoke_url.as_deref(),
            Some("http://responder.tailnet.ts.net/rpc/invoke")
        );
        assert_eq!(
            cli.invoke_request_source,
            Some(InvokeRequestSource::InlineJson(
                r#"{"type":"invoke"}"#.to_string()
            ))
        );
        assert_eq!(cli.invoke_attempts, Some(5));
        assert_eq!(cli.caller_node_id.as_deref(), Some("caller-node"));
        assert_eq!(cli.responder_node_id.as_deref(), Some("responder-node"));
    }

    #[test]
    fn parse_cli_rejects_duplicate_invoke_request_sources() {
        let err = parse_cli(&args(&[
            "fcp-tailnet-invoke-evidence",
            "--invoke-request-json={}",
            "--invoke-request-file=request.json",
        ]))
        .expect_err("duplicate request sources should fail");

        assert!(err.contains("provide only one"));
    }

    #[test]
    fn parse_cli_rejects_zero_invoke_attempts() {
        let err = parse_cli(&args(&[
            "fcp-tailnet-invoke-evidence",
            "--invoke-attempts=0",
        ]))
        .expect_err("zero attempts should fail");

        assert!(err.contains("greater than zero"));
    }

    #[test]
    fn resolve_probe_rejects_non_tailnet_invoke_url() {
        let cli = parse_cli(&args(&[
            "fcp-tailnet-invoke-evidence",
            "--invoke-url=https://example.com/rpc/invoke",
            "--invoke-request-json={}",
        ]))
        .expect("parse")
        .expect("not help");

        let err = resolve_invoke_probe_config(&cli)
            .expect_err("public invoke URLs must not count as tailnet proof");
        assert!(err.contains("tailnet-class"));
    }

    #[test]
    fn resolve_probe_rejects_wrong_invoke_path() {
        let cli = parse_cli(&args(&[
            "fcp-tailnet-invoke-evidence",
            "--invoke-url=https://responder.tailnet.ts.net/debug",
            "--invoke-request-json={}",
        ]))
        .expect("parse")
        .expect("not help");

        let err = resolve_invoke_probe_config(&cli)
            .expect_err("only the production invoke boundary should count");
        assert!(err.contains("/rpc/invoke"));
    }

    #[test]
    fn resolve_probe_accepts_tailnet_magicdns_or_ip_invoke_url() {
        for invoke_url in [
            "https://responder.tailnet.ts.net/rpc/invoke",
            "http://100.64.0.42:8080/rpc/invoke",
            "http://[fd7a:115c:a1e0::42]:8080/rpc/invoke",
        ] {
            let cli = parse_cli(&args(&[
                "fcp-tailnet-invoke-evidence",
                "--invoke-url",
                invoke_url,
                "--invoke-request-json",
                "{}",
            ]))
            .expect("parse")
            .expect("not help");

            assert!(
                resolve_invoke_probe_config(&cli)
                    .expect("valid tailnet invoke URL")
                    .is_some()
            );
        }
    }

    #[test]
    fn parse_cli_accepts_inline_and_split_options() {
        let cli = parse_cli(&args(&[
            "fcp-tailnet-invoke-evidence",
            "--route=derp-fallback",
            "--topology",
            "two-node DERP",
            "--localapi-url=http://127.0.0.1:41112",
            "--git-revision",
            "abc123",
        ]))
        .expect("parse")
        .expect("not help");

        assert_eq!(
            cli.route_selection,
            TailnetInvokeRouteSelection::Single(TailnetInvokeRouteMode::DerpFallback)
        );
        assert_eq!(cli.topology, "two-node DERP");
        assert_eq!(cli.localapi_url.as_deref(), Some("http://127.0.0.1:41112"));
        assert_eq!(cli.git_revision.as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_cli_accepts_all_routes() {
        let cli = parse_cli(&args(&["fcp-tailnet-invoke-evidence", "--route=all"]))
            .expect("parse")
            .expect("not help");

        assert_eq!(cli.route_selection, TailnetInvokeRouteSelection::All);
        assert_eq!(
            cli.route_selection.route_modes(),
            vec![
                TailnetInvokeRouteMode::DirectLan,
                TailnetInvokeRouteMode::DerpFallback
            ]
        );
    }

    #[test]
    fn parse_cli_rejects_unknown_options() {
        let err = parse_cli(&args(&["fcp-tailnet-invoke-evidence", "--unknown"]))
            .expect_err("unknown option should fail");
        assert!(err.contains("unknown option"));
    }

    #[test]
    fn observe_tailnet_without_localapi_is_conservative() {
        let observation = observe_tailnet(None, TailnetInvokeRouteMode::DirectLan, None);
        let record = observation.structured_skip_record(
            TailnetInvokeRouteMode::DirectLan,
            args(&["fcp-tailnet-invoke-evidence"]),
            "abc123",
            "local prerequisite probe",
        );

        assert!(
            record
                .missing_prerequisites
                .contains(&"tailscale-localapi-url".to_string())
        );
        assert!(
            record
                .missing_prerequisites
                .contains(&"production-mesh-invoke-transport".to_string())
        );
    }

    #[test]
    fn classify_invoke_response_marks_fcp_ok_as_success() {
        let response_body = serde_json::to_vec(&InvokeResponse::ok(
            RequestId::new("req-1"),
            serde_json::json!({}),
        ))
        .expect("serialize invoke response");
        let attempt = classify_invoke_response(
            0,
            42,
            fcp_async_core::http::HttpResponse::new(200, "OK", response_body),
        );

        assert_eq!(attempt.outcome, TailnetInvokeAttemptOutcome::Success);
        assert_eq!(attempt.latency_ns, Some(42));
    }

    #[test]
    fn probe_record_emits_real_transport_only_when_prerequisites_succeed() {
        let config = invoke_probe_config();
        let record = evidence_record_from_probe(
            TailnetInvokeRouteMode::DirectLan,
            args(&[
                "fcp-tailnet-invoke-evidence",
                "--invoke-url=http://secret.example",
            ]),
            "abc123".to_string(),
            "two node tailnet".to_string(),
            satisfied_observation(true),
            &config,
            TailnetInvokeProbeRun {
                attempts: vec![
                    TailnetInvokeAttemptEvidence::success(0, 100),
                    TailnetInvokeAttemptEvidence::success(1, 200),
                ],
            },
        );

        assert_eq!(record.source, TailnetInvokeEvidenceSource::RealTransport);
        assert!(record.missing_prerequisites.is_empty());
        assert_eq!(record.auth_result, "capability_verified");
        assert_eq!(record.retries, 1);
        assert_eq!(record.latency.expect("latency").p99_ns, 200);
        assert!(
            record
                .nodes
                .iter()
                .all(|node| node.redacted_node_id.starts_with("blake3:"))
        );
    }

    #[test]
    fn probe_record_keeps_structured_skip_when_route_prerequisite_is_missing() {
        let config = invoke_probe_config();
        let record = evidence_record_from_probe(
            TailnetInvokeRouteMode::DirectLan,
            args(&["fcp-tailnet-invoke-evidence"]),
            "abc123".to_string(),
            "two node tailnet".to_string(),
            satisfied_observation(false),
            &config,
            TailnetInvokeProbeRun {
                attempts: vec![TailnetInvokeAttemptEvidence::success(0, 100)],
            },
        );

        assert_eq!(record.source, TailnetInvokeEvidenceSource::StructuredSkip);
        assert!(
            record
                .missing_prerequisites
                .contains(&"direct-lan-route-observed".to_string())
        );
        assert!(
            record
                .prerequisites
                .iter()
                .any(
                    |prerequisite| prerequisite.name == "successful-tailnet-invoke"
                        && prerequisite.satisfied
                )
        );
    }

    #[test]
    fn route_telemetry_detects_direct_active_peer_without_relay() {
        let status = serde_json::json!({
            "Peer": {
                "node-peer1": {
                    "Online": true,
                    "Active": true,
                    "CurAddr": "203.0.113.10:41641"
                }
            }
        });

        let observation = observe_route_telemetry(&status, TailnetInvokeRouteMode::DirectLan, None);
        assert!(observation.available);
        assert!(observation.detail.contains("direct_candidates=1"));

        let derp = observe_route_telemetry(&status, TailnetInvokeRouteMode::DerpFallback, None);
        assert!(!derp.available);
        assert!(derp.detail.contains("derp_candidates=0"));
    }

    #[test]
    fn route_telemetry_detects_derp_active_peer() {
        let status = serde_json::json!({
            "Peer": {
                "node-peer1": {
                    "Online": true,
                    "Active": true,
                    "Relay": "nyc"
                },
                "node-peer2": {
                    "Online": true,
                    "Active": true,
                    "PeerRelay": "relay.example.invalid:41641"
                }
            }
        });

        let observation =
            observe_route_telemetry(&status, TailnetInvokeRouteMode::DerpFallback, None);
        assert!(observation.available);
        assert!(observation.detail.contains("derp_candidates=2"));

        let direct = observe_route_telemetry(&status, TailnetInvokeRouteMode::DirectLan, None);
        assert!(!direct.available);
        assert!(direct.detail.contains("direct_candidates=0"));
    }

    #[test]
    fn route_telemetry_scopes_candidates_to_responder_peer() {
        let status = serde_json::json!({
            "Peer": {
                "unrelated": {
                    "ID": "unrelated",
                    "HostName": "other-node",
                    "DNSName": "other-node.tailnet.ts.net.",
                    "Online": true,
                    "Active": true,
                    "CurAddr": "203.0.113.10:41641"
                },
                "node-responder": {
                    "ID": "node-responder",
                    "HostName": "responder",
                    "DNSName": "responder.tailnet.ts.net.",
                    "Online": true,
                    "Active": true,
                    "Relay": "nyc"
                }
            }
        });
        let identity = TailnetInvokeRoutePeerIdentity::new(
            "https://responder.tailnet.ts.net/rpc/invoke",
            "node-responder",
        )
        .expect("route identity");

        let direct =
            observe_route_telemetry(&status, TailnetInvokeRouteMode::DirectLan, Some(&identity));
        assert!(!direct.available);
        assert!(direct.detail.contains("active_online_peers=2"));
        assert!(direct.detail.contains("matched_active_peers=1"));
        assert!(direct.detail.contains("direct_candidates=0"));

        let derp = observe_route_telemetry(
            &status,
            TailnetInvokeRouteMode::DerpFallback,
            Some(&identity),
        );
        assert!(derp.available);
        assert!(derp.detail.contains("matched_active_peers=1"));
        assert!(derp.detail.contains("derp_candidates=1"));
    }

    #[test]
    fn route_telemetry_matches_responder_tailnet_ip() {
        let status = serde_json::json!({
            "Peer": {
                "node-responder": {
                    "Online": true,
                    "Active": true,
                    "CurAddr": "203.0.113.10:41641",
                    "TailscaleIPs": ["100.64.0.42"]
                }
            }
        });
        let identity =
            TailnetInvokeRoutePeerIdentity::new("http://100.64.0.42:8080/rpc/invoke", "responder")
                .expect("route identity");

        let observation =
            observe_route_telemetry(&status, TailnetInvokeRouteMode::DirectLan, Some(&identity));
        assert!(observation.available);
        assert!(observation.detail.contains("matched_active_peers=1"));
        assert!(observation.detail.contains("direct_candidates=1"));
    }

    #[test]
    fn route_telemetry_ignores_idle_or_offline_peers() {
        let status = serde_json::json!({
            "Peer": {
                "idle": {
                    "Online": true,
                    "Active": false,
                    "CurAddr": "203.0.113.10:41641"
                },
                "offline": {
                    "Online": false,
                    "Active": true,
                    "Relay": "nyc"
                }
            }
        });

        let observation = observe_route_telemetry(&status, TailnetInvokeRouteMode::DirectLan, None);
        assert!(!observation.available);
        assert!(observation.detail.contains("active_online_peers=0"));
    }
}
