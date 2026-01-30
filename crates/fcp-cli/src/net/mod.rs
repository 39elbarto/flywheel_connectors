//! `fcp net` command implementation.
//!
//! Provides tools to explain egress policy decisions for `NetworkConstraints`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use fcp_manifest::{ConnectorManifest, NetworkConstraints, OperationSection};
use fcp_sandbox::{
    DenyReason, EgressError, EgressGuard, EgressHttpRequest, EgressRequest, canonicalize_hostname,
};
use serde::Serialize;

/// Arguments for the `fcp net` command.
#[derive(Args, Debug)]
pub struct NetArgs {
    #[command(subcommand)]
    pub command: NetCommand,
}

/// Network subcommands.
#[derive(Subcommand, Debug)]
pub enum NetCommand {
    /// Explain why a URL would be allowed or denied by `NetworkConstraints`.
    Explain(ExplainArgs),
}

/// Arguments for `fcp net explain`.
#[derive(Args, Debug)]
pub struct ExplainArgs {
    /// URL to evaluate.
    #[arg(long)]
    pub url: String,

    /// Path to manifest.toml containing `NetworkConstraints`.
    #[arg(long, default_value = "manifest.toml")]
    pub manifest_path: PathBuf,

    /// Operation id to select `NetworkConstraints` from the manifest.
    ///
    /// If omitted and the manifest has exactly one operation, that operation is used.
    #[arg(long)]
    pub operation: Option<String>,

    /// Optional SNI value to validate against expected SNI.
    #[arg(long)]
    pub sni: Option<String>,

    /// Optional redirect count to validate against `max_redirects`.
    #[arg(long)]
    pub redirect_count: Option<u8>,

    /// Output JSON instead of human-readable format.
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct NetExplainReport {
    url: String,
    manifest_path: String,
    operation: String,
    allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestion: Option<SuggestedChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    canonical_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_redirects: Option<u8>,
}

#[derive(Debug, Serialize)]
struct SuggestedChange {
    field: String,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

struct ParsedUrlInfo {
    host: Option<String>,
    port: Option<u16>,
}

/// Run the net command.
pub fn run(args: NetArgs) -> Result<()> {
    match args.command {
        NetCommand::Explain(args) => run_explain(&args),
    }
}

fn run_explain(args: &ExplainArgs) -> Result<()> {
    let manifest_path = &args.manifest_path;
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("failed to read manifest: {}", manifest_path.display()))?;
    let manifest = ConnectorManifest::parse_str(&raw).context("failed to parse manifest TOML")?;

    let (operation_id, operation) = select_operation(&manifest, args.operation.as_deref())?;
    let constraints = operation.network_constraints.as_ref().ok_or_else(|| {
        anyhow::anyhow!("operation `{operation_id}` does not declare network_constraints")
    })?;

    let parsed = parse_url_info(&args.url);

    let request = EgressHttpRequest {
        url: args.url.clone(),
        method: "GET".to_string(),
        headers: Vec::new(),
        body: None,
        credential_id: None,
    };

    let guard = EgressGuard::new();
    let evaluation = guard.evaluate(&EgressRequest::Http(request), constraints);

    let report = build_report(
        args,
        manifest_path.as_path(),
        operation_id,
        constraints,
        &parsed,
        evaluation,
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&report);
    }

    if !report.allowed {
        std::process::exit(1);
    }

    Ok(())
}

fn select_operation<'a>(
    manifest: &'a ConnectorManifest,
    operation: Option<&'a str>,
) -> Result<(&'a str, &'a OperationSection)> {
    if let Some(id) = operation {
        let (key, op) = manifest
            .provides
            .operations
            .get_key_value(id)
            .ok_or_else(|| anyhow::anyhow!("operation `{id}` not found in manifest"))?;
        return Ok((key.as_str(), op));
    }

    let mut iter = manifest.provides.operations.iter();
    let Some((id, op)) = iter.next() else {
        return Err(anyhow::anyhow!("manifest has no operations"));
    };

    if iter.next().is_some() {
        let ops: Vec<&str> = manifest
            .provides
            .operations
            .keys()
            .map(String::as_str)
            .collect();
        return Err(anyhow::anyhow!(
            "multiple operations found; specify --operation (available: {})",
            ops.join(", ")
        ));
    }

    Ok((id.as_str(), op))
}

fn parse_url_info(url: &str) -> ParsedUrlInfo {
    let parsed = url::Url::parse(url).ok();
    let host = parsed
        .as_ref()
        .and_then(|u| u.host_str().map(ToString::to_string));
    let port = parsed.as_ref().and_then(url::Url::port_or_known_default);
    ParsedUrlInfo { host, port }
}

fn build_report(
    args: &ExplainArgs,
    manifest_path: &Path,
    operation_id: &str,
    constraints: &NetworkConstraints,
    parsed: &ParsedUrlInfo,
    evaluation: Result<fcp_sandbox::EgressDecision, EgressError>,
) -> NetExplainReport {
    let mut report = NetExplainReport {
        url: args.url.clone(),
        manifest_path: manifest_path.display().to_string(),
        operation: operation_id.to_string(),
        allowed: false,
        reason_code: None,
        rule_id: None,
        details: None,
        suggestion: None,
        canonical_host: None,
        port: None,
        tls_required: None,
        expected_sni: None,
        max_redirects: Some(constraints.max_redirects),
    };

    match evaluation {
        Ok(decision) => {
            report.allowed = true;
            report.canonical_host = Some(decision.canonical_host.clone());
            report.port = Some(decision.port);
            report.tls_required = Some(decision.tls_required);
            report.expected_sni.clone_from(&decision.expected_sni);

            if let Some(redirects) = args.redirect_count {
                if redirects > constraints.max_redirects {
                    return deny_report(
                        report,
                        DenyReason::MaxRedirectsExceeded,
                        Some(format!(
                            "redirect count {redirects} exceeds max_redirects {}",
                            constraints.max_redirects
                        )),
                        constraints,
                        parsed,
                        Some(decision.canonical_host.as_str()),
                        Some(decision.port),
                    );
                }
            }

            if let Some(actual_sni) = args.sni.as_deref() {
                if let Some(expected) = report.expected_sni.clone() {
                    if actual_sni != expected {
                        return deny_report(
                            report,
                            DenyReason::SniMismatch,
                            Some(format!(
                                "SNI mismatch: expected `{expected}`, got `{actual_sni}`"
                            )),
                            constraints,
                            parsed,
                            None,
                            None,
                        );
                    }
                }
            }

            report
        }
        Err(EgressError::Denied { reason, code }) => deny_report(
            report,
            code,
            Some(reason),
            constraints,
            parsed,
            parsed.host.as_deref(),
            parsed.port,
        ),
        Err(err) => {
            report.allowed = false;
            report.details = Some(err.to_string());
            report.reason_code = Some(error_reason_code(&err).to_string());
            report
        }
    }
}

fn deny_report(
    mut report: NetExplainReport,
    code: DenyReason,
    details: Option<String>,
    constraints: &NetworkConstraints,
    parsed: &ParsedUrlInfo,
    host_override: Option<&str>,
    port_override: Option<u16>,
) -> NetExplainReport {
    report.allowed = false;
    report.reason_code = Some(deny_reason_code(code));
    report.rule_id = rule_id_for(code, constraints, parsed, host_override);
    report.details = details;
    report.suggestion = suggestion_for(code, constraints, parsed, host_override, port_override);
    report
}

fn deny_reason_code(code: DenyReason) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|v| v.as_str().map(ToString::to_string))
        .unwrap_or_else(|| format!("{code:?}"))
}

const fn error_reason_code(err: &EgressError) -> &'static str {
    match err {
        EgressError::InvalidRequest(_) => "invalid_request",
        EgressError::InvalidUrl(_) => "invalid_url",
        EgressError::CanonicalizationFailed(_) => "canonicalization_failed",
        EgressError::DnsResolutionFailed(_) => "dns_resolution_failed",
        EgressError::CredentialError(_) => "credential_error",
        EgressError::TlsVerificationFailed(_) => "tls_verification_failed",
        EgressError::Denied { .. } => "denied",
    }
}

fn rule_id_for(
    code: DenyReason,
    constraints: &NetworkConstraints,
    parsed: &ParsedUrlInfo,
    host_override: Option<&str>,
) -> Option<String> {
    match code {
        DenyReason::HostNotAllowed => Some("network_constraints.host_allow".to_string()),
        DenyReason::PortNotAllowed => Some("network_constraints.port_allow".to_string()),
        DenyReason::IpLiteralDenied => Some("network_constraints.deny_ip_literals".to_string()),
        DenyReason::LocalhostDenied => Some("network_constraints.deny_localhost".to_string()),
        DenyReason::PrivateRangeDenied => {
            Some("network_constraints.deny_private_ranges".to_string())
        }
        DenyReason::TailnetRangeDenied => {
            Some("network_constraints.deny_tailnet_ranges".to_string())
        }
        DenyReason::LinkLocalDenied => Some("network_constraints.deny_private_ranges".to_string()),
        DenyReason::HostnameNotCanonical => {
            Some("network_constraints.require_host_canonicalization".to_string())
        }
        DenyReason::DnsMaxIpsExceeded => Some("network_constraints.dns_max_ips".to_string()),
        DenyReason::SniMismatch => Some("network_constraints.require_sni".to_string()),
        DenyReason::SpkiPinMismatch => Some("network_constraints.spki_pins".to_string()),
        DenyReason::CredentialNotAuthorized => Some("capability.allow_credentials".to_string()),
        DenyReason::CredentialHostNotAllowed => Some("credential.host_allow".to_string()),
        DenyReason::MaxRedirectsExceeded => Some("network_constraints.max_redirects".to_string()),
        DenyReason::CidrDenyMatched => {
            let ip = resolve_ip_literal(parsed, host_override)?;
            let matched = constraints.cidr_deny.iter().find(|cidr| {
                cidr.parse::<ipnet::IpNet>()
                    .ok()
                    .is_some_and(|net| net.contains(&ip))
            })?;
            Some(format!("network_constraints.cidr_deny:{matched}"))
        }
    }
}

#[allow(clippy::too_many_lines)]
fn suggestion_for(
    code: DenyReason,
    constraints: &NetworkConstraints,
    parsed: &ParsedUrlInfo,
    host_override: Option<&str>,
    port_override: Option<u16>,
) -> Option<SuggestedChange> {
    let host = host_override.or(parsed.host.as_deref());
    let port = port_override.or(parsed.port);
    let canonical_host = canonical_or_raw(host);

    match code {
        DenyReason::HostNotAllowed => canonical_host.as_ref().map(|value| SuggestedChange {
            field: "network_constraints.host_allow".to_string(),
            action: "add".to_string(),
            value: Some(value.clone()),
            note: None,
        }),
        DenyReason::PortNotAllowed => port.map(|value| SuggestedChange {
            field: "network_constraints.port_allow".to_string(),
            action: "add".to_string(),
            value: Some(value.to_string()),
            note: None,
        }),
        DenyReason::IpLiteralDenied => Some(SuggestedChange {
            field: "network_constraints.deny_ip_literals".to_string(),
            action: "set".to_string(),
            value: Some("false".to_string()),
            note: Some("or use a hostname instead of an IP literal".to_string()),
        }),
        DenyReason::LocalhostDenied => Some(SuggestedChange {
            field: "network_constraints.deny_localhost".to_string(),
            action: "set".to_string(),
            value: Some("false".to_string()),
            note: Some("or avoid localhost destinations".to_string()),
        }),
        DenyReason::PrivateRangeDenied => Some(SuggestedChange {
            field: "network_constraints.deny_private_ranges".to_string(),
            action: "set".to_string(),
            value: Some("false".to_string()),
            note: Some("or avoid RFC1918 destinations".to_string()),
        }),
        DenyReason::TailnetRangeDenied => Some(SuggestedChange {
            field: "network_constraints.deny_tailnet_ranges".to_string(),
            action: "set".to_string(),
            value: Some("false".to_string()),
            note: Some("or avoid tailnet destinations".to_string()),
        }),
        DenyReason::LinkLocalDenied => Some(SuggestedChange {
            field: "network_constraints.deny_private_ranges".to_string(),
            action: "set".to_string(),
            value: Some("false".to_string()),
            note: Some("or avoid link-local destinations".to_string()),
        }),
        DenyReason::HostnameNotCanonical => host
            .and_then(|value| canonicalize_hostname(value).ok())
            .map(|canonical| SuggestedChange {
                field: "network_constraints.host_allow".to_string(),
                action: "use".to_string(),
                value: Some(canonical),
                note: Some("use canonical hostname".to_string()),
            })
            .or_else(|| {
                Some(SuggestedChange {
                    field: "network_constraints.require_host_canonicalization".to_string(),
                    action: "set".to_string(),
                    value: Some("false".to_string()),
                    note: Some("or use a canonical hostname".to_string()),
                })
            }),
        DenyReason::DnsMaxIpsExceeded => Some(SuggestedChange {
            field: "network_constraints.dns_max_ips".to_string(),
            action: "increase".to_string(),
            value: Some(format!("> {}", constraints.dns_max_ips)),
            note: None,
        }),
        DenyReason::SniMismatch => Some(SuggestedChange {
            field: "network_constraints.require_sni".to_string(),
            action: "set".to_string(),
            value: Some("false".to_string()),
            note: Some("or provide the expected SNI value".to_string()),
        }),
        DenyReason::SpkiPinMismatch => Some(SuggestedChange {
            field: "network_constraints.spki_pins".to_string(),
            action: "add".to_string(),
            value: Some("<spki-pin>".to_string()),
            note: Some("add the server's SPKI pin".to_string()),
        }),
        DenyReason::CredentialNotAuthorized => Some(SuggestedChange {
            field: "capability.allow_credentials".to_string(),
            action: "add".to_string(),
            value: Some("<credential_id>".to_string()),
            note: None,
        }),
        DenyReason::CredentialHostNotAllowed => Some(SuggestedChange {
            field: "credential.host_allow".to_string(),
            action: "add".to_string(),
            value: canonical_host,
            note: None,
        }),
        DenyReason::MaxRedirectsExceeded => Some(SuggestedChange {
            field: "network_constraints.max_redirects".to_string(),
            action: "increase".to_string(),
            value: Some(format!("> {}", constraints.max_redirects)),
            note: None,
        }),
        DenyReason::CidrDenyMatched => resolve_ip_literal(parsed, host_override)
            .and_then(|ip| match_cidr(ip, &constraints.cidr_deny))
            .map(|cidr| SuggestedChange {
                field: "network_constraints.cidr_deny".to_string(),
                action: "remove".to_string(),
                value: Some(cidr),
                note: Some("remove or narrow the matching CIDR".to_string()),
            }),
    }
}

fn resolve_ip_literal(parsed: &ParsedUrlInfo, host_override: Option<&str>) -> Option<IpAddr> {
    let host = host_override.or(parsed.host.as_deref())?;
    host.parse::<IpAddr>().ok()
}

fn match_cidr(ip: IpAddr, cidrs: &[String]) -> Option<String> {
    cidrs
        .iter()
        .find(|cidr| {
            cidr.parse::<ipnet::IpNet>()
                .ok()
                .is_some_and(|net| net.contains(&ip))
        })
        .cloned()
}

fn canonical_or_raw(host: Option<&str>) -> Option<String> {
    host.and_then(|value| canonicalize_hostname(value).ok())
        .or_else(|| host.map(ToString::to_string))
}

fn print_human_report(report: &NetExplainReport) {
    println!();
    println!("Net explain");
    println!("Manifest: {}", report.manifest_path);
    println!("Operation: {}", report.operation);
    println!("URL: {}", report.url);
    println!(
        "Decision: {}",
        if report.allowed { "ALLOW" } else { "DENY" }
    );

    if let Some(code) = &report.reason_code {
        print!("Reason: {code}");
        if let Some(rule_id) = &report.rule_id {
            print!(" ({rule_id})");
        }
        println!();
    }

    if let Some(details) = &report.details {
        println!("Details: {details}");
    }

    if let Some(host) = &report.canonical_host {
        println!("Canonical host: {host}");
    }
    if let Some(port) = report.port {
        println!("Port: {port}");
    }
    if let Some(tls) = report.tls_required {
        println!("TLS required: {tls}");
    }
    if let Some(sni) = &report.expected_sni {
        println!("Expected SNI: {sni}");
    }
    if let Some(max_redirects) = report.max_redirects {
        println!("Max redirects: {max_redirects}");
    }

    if let Some(suggestion) = &report.suggestion {
        println!();
        println!("Suggestion:");
        println!(
            "  - {} {}{}",
            suggestion.action,
            suggestion.field,
            suggestion
                .value
                .as_ref()
                .map(|value| format!(" = {value}"))
                .unwrap_or_default()
        );
        if let Some(note) = &suggestion.note {
            println!("  - note: {note}");
        }
    }
}
