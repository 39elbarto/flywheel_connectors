//! Emit redaction-safe JSONL evidence for tailnet invoke proof prerequisites.
//!
//! This runner is intentionally conservative: until `fcp-host` invoke traffic is
//! routed through the production mesh/tailscale boundary, it emits a structured
//! skip record instead of treating host-first or synthetic RTT measurements as
//! live tailnet proof.

use std::env;
use std::process::{Command, ExitCode};
use std::time::Duration;

use fcp_async_core::{
    compatibility_cx,
    http::{HttpClientBuilder, Method},
    time,
};
use fcp_host::{TailnetInvokeHarnessObservation, TailnetInvokeRouteMode};
use fcp_tailscale::TailscaleStatus;
use serde_json::Value;

const USAGE: &str = "\
Usage: fcp-tailnet-invoke-evidence [OPTIONS]

Options:
  --route <direct-lan|derp-fallback>       Requested route mode (default: direct-lan)
  --topology <label>                       Redaction-safe topology label
  --localapi-url <url>                     HTTP-exposed Tailscale LocalAPI base URL
  --git-revision <rev>                     Git revision under test
  -h, --help                               Print this help

Environment:
  FCP_TAILSCALE_LOCALAPI_URL               Fallback for --localapi-url
  FCP_TAILNET_EVIDENCE_GIT_REVISION        Fallback for --git-revision
";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cli {
    route_mode: TailnetInvokeRouteMode,
    topology: String,
    localapi_url: Option<String>,
    git_revision: Option<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            route_mode: TailnetInvokeRouteMode::DirectLan,
            topology: "tailnet invoke prerequisite probe".to_string(),
            localapi_url: None,
            git_revision: None,
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

    let localapi_url = cli
        .localapi_url
        .clone()
        .or_else(|| env::var("FCP_TAILSCALE_LOCALAPI_URL").ok());
    let git_revision = cli
        .git_revision
        .clone()
        .or_else(|| env::var("FCP_TAILNET_EVIDENCE_GIT_REVISION").ok())
        .unwrap_or_else(detect_git_revision);
    let observation = observe_tailnet(localapi_url.as_deref(), cli.route_mode);
    let record = observation.structured_skip_record(
        cli.route_mode,
        command_line,
        git_revision,
        cli.topology,
    );

    match record.to_jsonl_line() {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("failed to serialize tailnet invoke evidence: {error}");
            ExitCode::FAILURE
        }
    }
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
                cli.route_mode = TailnetInvokeRouteMode::parse_cli(value)?;
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
            "--git-revision" => {
                cli.git_revision = Some(
                    iter.next()
                        .ok_or_else(|| "--git-revision requires a value".to_string())?
                        .clone(),
                );
            }
            value if value.starts_with("--route=") => {
                let value = value.split_once('=').map_or("", |(_, route)| route);
                cli.route_mode = TailnetInvokeRouteMode::parse_cli(value)?;
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

fn observe_tailnet(
    localapi_url: Option<&str>,
    route_mode: TailnetInvokeRouteMode,
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
            let route_telemetry = observe_route_telemetry(&status_json, route_mode);
            TailnetInvokeHarnessObservation {
                localapi_configured: true,
                tailscale_connected,
                online_peer_count,
                route_telemetry_available: route_telemetry.available,
                route_telemetry_detail: route_telemetry.detail,
                production_mesh_invoke_transport_available: false,
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
struct RouteTelemetryObservation {
    available: bool,
    detail: String,
}

fn observe_route_telemetry(
    status_json: &Value,
    route_mode: TailnetInvokeRouteMode,
) -> RouteTelemetryObservation {
    let Some(peers) = status_json.get("Peer").and_then(Value::as_object) else {
        return RouteTelemetryObservation {
            available: false,
            detail: "peer_map=missing".to_string(),
        };
    };

    let mut active_online_peers = 0usize;
    let mut direct_candidates = 0usize;
    let mut derp_candidates = 0usize;

    for peer in peers.values().filter_map(Value::as_object) {
        let online = peer.get("Online").and_then(Value::as_bool).unwrap_or(false);
        let active = peer.get("Active").and_then(Value::as_bool).unwrap_or(false);
        if !(online && active) {
            continue;
        }

        active_online_peers += 1;
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
            "active_online_peers={active_online_peers},direct_candidates={direct_candidates},derp_candidates={derp_candidates}"
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

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn parse_cli_defaults_to_direct_lan() {
        let cli = parse_cli(&args(&["fcp-tailnet-invoke-evidence"]))
            .expect("parse")
            .expect("not help");

        assert_eq!(cli.route_mode, TailnetInvokeRouteMode::DirectLan);
        assert_eq!(cli.topology, "tailnet invoke prerequisite probe");
        assert!(cli.localapi_url.is_none());
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

        assert_eq!(cli.route_mode, TailnetInvokeRouteMode::DerpFallback);
        assert_eq!(cli.topology, "two-node DERP");
        assert_eq!(cli.localapi_url.as_deref(), Some("http://127.0.0.1:41112"));
        assert_eq!(cli.git_revision.as_deref(), Some("abc123"));
    }

    #[test]
    fn parse_cli_rejects_unknown_options() {
        let err = parse_cli(&args(&["fcp-tailnet-invoke-evidence", "--unknown"]))
            .expect_err("unknown option should fail");
        assert!(err.contains("unknown option"));
    }

    #[test]
    fn observe_tailnet_without_localapi_is_conservative() {
        let observation = observe_tailnet(None, TailnetInvokeRouteMode::DirectLan);
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

        let observation = observe_route_telemetry(&status, TailnetInvokeRouteMode::DirectLan);
        assert!(observation.available);
        assert!(observation.detail.contains("direct_candidates=1"));

        let derp = observe_route_telemetry(&status, TailnetInvokeRouteMode::DerpFallback);
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

        let observation = observe_route_telemetry(&status, TailnetInvokeRouteMode::DerpFallback);
        assert!(observation.available);
        assert!(observation.detail.contains("derp_candidates=2"));

        let direct = observe_route_telemetry(&status, TailnetInvokeRouteMode::DirectLan);
        assert!(!direct.available);
        assert!(direct.detail.contains("direct_candidates=0"));
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

        let observation = observe_route_telemetry(&status, TailnetInvokeRouteMode::DirectLan);
        assert!(!observation.available);
        assert!(observation.detail.contains("active_online_peers=0"));
    }
}
