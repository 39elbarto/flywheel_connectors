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
#[derive(Args, Debug, Clone)]
pub struct NetArgs {
    #[command(subcommand)]
    pub command: NetCommand,
}

/// Network subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum NetCommand {
    /// Explain why a URL would be allowed or denied by `NetworkConstraints`.
    Explain(ExplainArgs),
}

/// Arguments for `fcp net explain`.
#[derive(Args, Debug, Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_constraints() -> NetworkConstraints {
        NetworkConstraints {
            host_allow: vec!["api.example.com".to_string()],
            port_allow: vec![443, 80],
            ip_allow: vec![],
            cidr_deny: vec!["10.0.0.0/8".to_string()],
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: vec![],
            deny_ip_literals: true,
            require_host_canonicalization: true,
            dns_max_ips: 4,
            max_redirects: 5,
            connect_timeout_ms: 5000,
            total_timeout_ms: 30000,
            max_response_bytes: 10_485_760,
        }
    }

    // ---- parse_url_info ----

    #[test]
    fn parse_url_info_https() {
        let info = parse_url_info("https://api.example.com/v1/data");
        assert_eq!(info.host.as_deref(), Some("api.example.com"));
        assert_eq!(info.port, Some(443));
    }

    #[test]
    fn parse_url_info_http_with_port() {
        let info = parse_url_info("http://localhost:8080/test");
        assert_eq!(info.host.as_deref(), Some("localhost"));
        assert_eq!(info.port, Some(8080));
    }

    #[test]
    fn parse_url_info_invalid_url() {
        let info = parse_url_info("not a url");
        assert!(info.host.is_none());
        assert!(info.port.is_none());
    }

    #[test]
    fn parse_url_info_ip_literal() {
        let info = parse_url_info("http://192.168.1.1:3000/api");
        assert_eq!(info.host.as_deref(), Some("192.168.1.1"));
        assert_eq!(info.port, Some(3000));
    }

    // ---- deny_reason_code ----

    #[test]
    fn deny_reason_code_host_not_allowed() {
        let code = deny_reason_code(DenyReason::HostNotAllowed);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_port_not_allowed() {
        let code = deny_reason_code(DenyReason::PortNotAllowed);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_ip_literal() {
        let code = deny_reason_code(DenyReason::IpLiteralDenied);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_localhost() {
        let code = deny_reason_code(DenyReason::LocalhostDenied);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_sni_mismatch() {
        let code = deny_reason_code(DenyReason::SniMismatch);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_max_redirects() {
        let code = deny_reason_code(DenyReason::MaxRedirectsExceeded);
        assert!(!code.is_empty());
    }

    // ---- error_reason_code ----

    #[test]
    fn error_reason_code_invalid_request() {
        assert_eq!(
            error_reason_code(&EgressError::InvalidRequest("bad".into())),
            "invalid_request"
        );
    }

    #[test]
    fn error_reason_code_invalid_url() {
        assert_eq!(
            error_reason_code(&EgressError::InvalidUrl("bad url".into())),
            "invalid_url"
        );
    }

    #[test]
    fn error_reason_code_dns_failed() {
        assert_eq!(
            error_reason_code(&EgressError::DnsResolutionFailed("nxdomain".into())),
            "dns_resolution_failed"
        );
    }

    // ---- resolve_ip_literal ----

    #[test]
    fn resolve_ip_literal_from_parsed() {
        let parsed = ParsedUrlInfo {
            host: Some("192.168.1.1".to_string()),
            port: Some(80),
        };
        let ip = resolve_ip_literal(&parsed, None).unwrap();
        assert_eq!(ip, "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn resolve_ip_literal_from_override() {
        let parsed = ParsedUrlInfo {
            host: Some("example.com".to_string()),
            port: Some(443),
        };
        let ip = resolve_ip_literal(&parsed, Some("10.0.0.1")).unwrap();
        assert_eq!(ip, "10.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn resolve_ip_literal_hostname_returns_none() {
        let parsed = ParsedUrlInfo {
            host: Some("example.com".to_string()),
            port: Some(443),
        };
        assert!(resolve_ip_literal(&parsed, None).is_none());
    }

    #[test]
    fn resolve_ip_literal_no_host_returns_none() {
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        assert!(resolve_ip_literal(&parsed, None).is_none());
    }

    // ---- match_cidr ----

    #[test]
    fn match_cidr_hits() {
        let cidrs = vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()];
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let matched = match_cidr(ip, &cidrs);
        assert_eq!(matched.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn match_cidr_miss() {
        let cidrs = vec!["10.0.0.0/8".to_string()];
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(match_cidr(ip, &cidrs).is_none());
    }

    #[test]
    fn match_cidr_empty_list() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(match_cidr(ip, &[]).is_none());
    }

    // ---- canonical_or_raw ----

    #[test]
    fn canonical_or_raw_with_hostname() {
        let result = canonical_or_raw(Some("example.com"));
        assert!(result.is_some());
    }

    #[test]
    fn canonical_or_raw_none() {
        assert!(canonical_or_raw(None).is_none());
    }

    // ---- NetExplainReport serde ----

    #[test]
    fn net_explain_report_serialize_allowed() {
        let report = NetExplainReport {
            url: "https://api.example.com".to_string(),
            manifest_path: "manifest.toml".to_string(),
            operation: "send_message".to_string(),
            allowed: true,
            reason_code: None,
            rule_id: None,
            details: None,
            suggestion: None,
            canonical_host: Some("api.example.com".to_string()),
            port: Some(443),
            tls_required: Some(true),
            expected_sni: None,
            max_redirects: Some(5),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"allowed\":true"));
        assert!(json.contains("\"port\":443"));
        assert!(!json.contains("reason_code"));
    }

    #[test]
    fn net_explain_report_serialize_denied() {
        let report = NetExplainReport {
            url: "http://evil.com".to_string(),
            manifest_path: "manifest.toml".to_string(),
            operation: "fetch".to_string(),
            allowed: false,
            reason_code: Some("HostNotAllowed".to_string()),
            rule_id: Some("network_constraints.host_allow".to_string()),
            details: Some("host not in allow list".to_string()),
            suggestion: Some(SuggestedChange {
                field: "network_constraints.host_allow".to_string(),
                action: "add".to_string(),
                value: Some("evil.com".to_string()),
                note: None,
            }),
            canonical_host: None,
            port: None,
            tls_required: None,
            expected_sni: None,
            max_redirects: Some(5),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"allowed\":false"));
        assert!(json.contains("HostNotAllowed"));
        assert!(json.contains("\"action\":\"add\""));
    }

    // ---- SuggestedChange serde ----

    #[test]
    fn suggested_change_serialize() {
        let s = SuggestedChange {
            field: "network_constraints.host_allow".to_string(),
            action: "add".to_string(),
            value: Some("api.example.com".to_string()),
            note: Some("add to host allow list".to_string()),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"field\":\"network_constraints.host_allow\""));
        assert!(json.contains("\"note\":\"add to host allow list\""));
    }

    #[test]
    fn suggested_change_serialize_minimal() {
        let s = SuggestedChange {
            field: "some.field".to_string(),
            action: "set".to_string(),
            value: None,
            note: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("value"));
        assert!(!json.contains("note"));
    }

    // ---- rule_id_for ----

    #[test]
    fn rule_id_for_host_not_allowed() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: Some("example.com".to_string()),
            port: Some(443),
        };
        let id = rule_id_for(DenyReason::HostNotAllowed, &constraints, &parsed, None);
        assert_eq!(id.as_deref(), Some("network_constraints.host_allow"));
    }

    #[test]
    fn rule_id_for_port_not_allowed() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(DenyReason::PortNotAllowed, &constraints, &parsed, None);
        assert_eq!(id.as_deref(), Some("network_constraints.port_allow"));
    }

    #[test]
    fn rule_id_for_sni_mismatch() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(DenyReason::SniMismatch, &constraints, &parsed, None);
        assert_eq!(id.as_deref(), Some("network_constraints.require_sni"));
    }

    // ---- suggestion_for ----

    #[test]
    fn suggestion_for_host_not_allowed() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: Some("api.example.com".to_string()),
            port: Some(443),
        };
        let suggestion = suggestion_for(
            DenyReason::HostNotAllowed,
            &constraints,
            &parsed,
            None,
            None,
        );
        assert!(suggestion.is_some());
        let s = suggestion.unwrap();
        assert_eq!(s.field, "network_constraints.host_allow");
        assert_eq!(s.action, "add");
    }

    #[test]
    fn suggestion_for_port_not_allowed() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: Some(8080),
        };
        let suggestion = suggestion_for(
            DenyReason::PortNotAllowed,
            &constraints,
            &parsed,
            None,
            Some(8080),
        );
        assert!(suggestion.is_some());
        let s = suggestion.unwrap();
        assert_eq!(s.field, "network_constraints.port_allow");
        assert_eq!(s.value.as_deref(), Some("8080"));
    }

    #[test]
    fn suggestion_for_ip_literal() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let suggestion = suggestion_for(
            DenyReason::IpLiteralDenied,
            &constraints,
            &parsed,
            None,
            None,
        );
        assert!(suggestion.is_some());
        let s = suggestion.unwrap();
        assert_eq!(s.action, "set");
        assert_eq!(s.value.as_deref(), Some("false"));
    }

    #[test]
    fn suggestion_for_max_redirects() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let suggestion = suggestion_for(
            DenyReason::MaxRedirectsExceeded,
            &constraints,
            &parsed,
            None,
            None,
        );
        assert!(suggestion.is_some());
        let s = suggestion.unwrap();
        assert_eq!(s.field, "network_constraints.max_redirects");
        assert_eq!(s.action, "increase");
    }

    // ---- additional parse_url_info tests ----

    #[test]
    fn parse_url_info_http_default_port() {
        let info = parse_url_info("http://example.com/path");
        assert_eq!(info.host.as_deref(), Some("example.com"));
        assert_eq!(info.port, Some(80));
    }

    #[test]
    fn parse_url_info_ftp_scheme() {
        let info = parse_url_info("ftp://files.example.com/pub");
        assert_eq!(info.host.as_deref(), Some("files.example.com"));
        assert_eq!(info.port, Some(21));
    }

    #[test]
    fn parse_url_info_ipv6_literal() {
        let info = parse_url_info("http://[::1]:9090/test");
        assert_eq!(info.host.as_deref(), Some("[::1]"));
        assert_eq!(info.port, Some(9090));
    }

    #[test]
    fn parse_url_info_empty_string() {
        let info = parse_url_info("");
        assert!(info.host.is_none());
        assert!(info.port.is_none());
    }

    #[test]
    fn parse_url_info_https_no_path() {
        let info = parse_url_info("https://secure.example.com");
        assert_eq!(info.host.as_deref(), Some("secure.example.com"));
        assert_eq!(info.port, Some(443));
    }

    #[test]
    fn parse_url_info_with_query_and_fragment() {
        let info = parse_url_info("https://api.example.com/v2?key=val#section");
        assert_eq!(info.host.as_deref(), Some("api.example.com"));
        assert_eq!(info.port, Some(443));
    }

    #[test]
    fn parse_url_info_high_port() {
        let info = parse_url_info("http://example.com:65535/");
        assert_eq!(info.port, Some(65535));
    }

    // ---- additional deny_reason_code tests ----

    #[test]
    fn deny_reason_code_private_range() {
        let code = deny_reason_code(DenyReason::PrivateRangeDenied);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_tailnet_range() {
        let code = deny_reason_code(DenyReason::TailnetRangeDenied);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_link_local() {
        let code = deny_reason_code(DenyReason::LinkLocalDenied);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_cidr_deny() {
        let code = deny_reason_code(DenyReason::CidrDenyMatched);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_spki_pin() {
        let code = deny_reason_code(DenyReason::SpkiPinMismatch);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_credential_not_authorized() {
        let code = deny_reason_code(DenyReason::CredentialNotAuthorized);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_credential_host_not_allowed() {
        let code = deny_reason_code(DenyReason::CredentialHostNotAllowed);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_hostname_not_canonical() {
        let code = deny_reason_code(DenyReason::HostnameNotCanonical);
        assert!(!code.is_empty());
    }

    #[test]
    fn deny_reason_code_dns_max_ips() {
        let code = deny_reason_code(DenyReason::DnsMaxIpsExceeded);
        assert!(!code.is_empty());
    }

    // ---- additional error_reason_code tests ----

    #[test]
    fn error_reason_code_canonicalization_failed() {
        assert_eq!(
            error_reason_code(&EgressError::CanonicalizationFailed("fail".into())),
            "canonicalization_failed"
        );
    }

    #[test]
    fn error_reason_code_credential_error() {
        assert_eq!(
            error_reason_code(&EgressError::CredentialError("missing".into())),
            "credential_error"
        );
    }

    #[test]
    fn error_reason_code_tls_verification_failed() {
        assert_eq!(
            error_reason_code(&EgressError::TlsVerificationFailed("cert expired".into())),
            "tls_verification_failed"
        );
    }

    #[test]
    fn error_reason_code_denied_variant() {
        assert_eq!(
            error_reason_code(&EgressError::Denied {
                reason: "blocked".into(),
                code: DenyReason::HostNotAllowed,
            }),
            "denied"
        );
    }

    // ---- additional resolve_ip_literal tests ----

    #[test]
    fn resolve_ip_literal_ipv6_parsed() {
        let parsed = ParsedUrlInfo {
            host: Some("::1".to_string()),
            port: Some(443),
        };
        let ip = resolve_ip_literal(&parsed, None).unwrap();
        assert!(ip.is_ipv6());
    }

    #[test]
    fn resolve_ip_literal_override_takes_precedence() {
        let parsed = ParsedUrlInfo {
            host: Some("172.16.0.1".to_string()),
            port: Some(80),
        };
        let ip = resolve_ip_literal(&parsed, Some("10.0.0.5")).unwrap();
        assert_eq!(ip, "10.0.0.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn resolve_ip_literal_override_non_ip_returns_none() {
        let parsed = ParsedUrlInfo {
            host: Some("192.168.1.1".to_string()),
            port: Some(80),
        };
        // override is a hostname, not an IP
        assert!(resolve_ip_literal(&parsed, Some("not-an-ip.com")).is_none());
    }

    // ---- additional match_cidr tests ----

    #[test]
    fn match_cidr_second_rule_matches() {
        let cidrs = vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()];
        let ip: IpAddr = "172.17.0.1".parse().unwrap();
        let matched = match_cidr(ip, &cidrs);
        assert_eq!(matched.as_deref(), Some("172.16.0.0/12"));
    }

    #[test]
    fn match_cidr_ipv6() {
        let cidrs = vec!["fd00::/8".to_string()];
        let ip: IpAddr = "fd12:3456:789a::1".parse().unwrap();
        let matched = match_cidr(ip, &cidrs);
        assert_eq!(matched.as_deref(), Some("fd00::/8"));
    }

    #[test]
    fn match_cidr_invalid_cidr_is_skipped() {
        let cidrs = vec!["not-a-cidr".to_string(), "10.0.0.0/8".to_string()];
        let ip: IpAddr = "10.1.1.1".parse().unwrap();
        let matched = match_cidr(ip, &cidrs);
        assert_eq!(matched.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn match_cidr_boundary_ip() {
        // 10.255.255.255 is the last IP in 10.0.0.0/8
        let cidrs = vec!["10.0.0.0/8".to_string()];
        let ip: IpAddr = "10.255.255.255".parse().unwrap();
        assert!(match_cidr(ip, &cidrs).is_some());
    }

    #[test]
    fn match_cidr_just_outside_range() {
        let cidrs = vec!["10.0.0.0/8".to_string()];
        let ip: IpAddr = "11.0.0.0".parse().unwrap();
        assert!(match_cidr(ip, &cidrs).is_none());
    }

    // ---- additional rule_id_for tests ----

    #[test]
    fn rule_id_for_ip_literal_denied() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(DenyReason::IpLiteralDenied, &constraints, &parsed, None);
        assert_eq!(id.as_deref(), Some("network_constraints.deny_ip_literals"));
    }

    #[test]
    fn rule_id_for_localhost_denied() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(DenyReason::LocalhostDenied, &constraints, &parsed, None);
        assert_eq!(id.as_deref(), Some("network_constraints.deny_localhost"));
    }

    #[test]
    fn rule_id_for_private_range_denied() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(DenyReason::PrivateRangeDenied, &constraints, &parsed, None);
        assert_eq!(
            id.as_deref(),
            Some("network_constraints.deny_private_ranges")
        );
    }

    #[test]
    fn rule_id_for_tailnet_range_denied() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(DenyReason::TailnetRangeDenied, &constraints, &parsed, None);
        assert_eq!(
            id.as_deref(),
            Some("network_constraints.deny_tailnet_ranges")
        );
    }

    #[test]
    fn rule_id_for_link_local_denied() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(DenyReason::LinkLocalDenied, &constraints, &parsed, None);
        assert_eq!(
            id.as_deref(),
            Some("network_constraints.deny_private_ranges")
        );
    }

    #[test]
    fn rule_id_for_hostname_not_canonical() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(
            DenyReason::HostnameNotCanonical,
            &constraints,
            &parsed,
            None,
        );
        assert_eq!(
            id.as_deref(),
            Some("network_constraints.require_host_canonicalization")
        );
    }

    #[test]
    fn rule_id_for_dns_max_ips_exceeded() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(DenyReason::DnsMaxIpsExceeded, &constraints, &parsed, None);
        assert_eq!(id.as_deref(), Some("network_constraints.dns_max_ips"));
    }

    #[test]
    fn rule_id_for_spki_pin_mismatch() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(DenyReason::SpkiPinMismatch, &constraints, &parsed, None);
        assert_eq!(id.as_deref(), Some("network_constraints.spki_pins"));
    }

    #[test]
    fn rule_id_for_credential_not_authorized() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(
            DenyReason::CredentialNotAuthorized,
            &constraints,
            &parsed,
            None,
        );
        assert_eq!(id.as_deref(), Some("capability.allow_credentials"));
    }

    #[test]
    fn rule_id_for_credential_host_not_allowed() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(
            DenyReason::CredentialHostNotAllowed,
            &constraints,
            &parsed,
            None,
        );
        assert_eq!(id.as_deref(), Some("credential.host_allow"));
    }

    #[test]
    fn rule_id_for_max_redirects_exceeded() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let id = rule_id_for(
            DenyReason::MaxRedirectsExceeded,
            &constraints,
            &parsed,
            None,
        );
        assert_eq!(id.as_deref(), Some("network_constraints.max_redirects"));
    }

    #[test]
    fn rule_id_for_cidr_deny_with_matching_ip() {
        let constraints = test_constraints(); // cidr_deny has "10.0.0.0/8"
        let parsed = ParsedUrlInfo {
            host: Some("10.1.2.3".to_string()),
            port: Some(80),
        };
        let id = rule_id_for(DenyReason::CidrDenyMatched, &constraints, &parsed, None);
        assert_eq!(
            id.as_deref(),
            Some("network_constraints.cidr_deny:10.0.0.0/8")
        );
    }

    #[test]
    fn rule_id_for_cidr_deny_with_override() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: Some("example.com".to_string()),
            port: Some(443),
        };
        let id = rule_id_for(
            DenyReason::CidrDenyMatched,
            &constraints,
            &parsed,
            Some("10.5.5.5"),
        );
        assert_eq!(
            id.as_deref(),
            Some("network_constraints.cidr_deny:10.0.0.0/8")
        );
    }

    #[test]
    fn rule_id_for_cidr_deny_no_match_returns_none() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: Some("192.168.1.1".to_string()),
            port: Some(80),
        };
        // 192.168.1.1 is not in 10.0.0.0/8
        let id = rule_id_for(DenyReason::CidrDenyMatched, &constraints, &parsed, None);
        assert!(id.is_none());
    }

    #[test]
    fn rule_id_for_cidr_deny_hostname_returns_none() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: Some("example.com".to_string()),
            port: Some(443),
        };
        let id = rule_id_for(DenyReason::CidrDenyMatched, &constraints, &parsed, None);
        assert!(id.is_none());
    }

    // ---- additional suggestion_for tests ----

    #[test]
    fn suggestion_for_localhost_denied() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let s = suggestion_for(
            DenyReason::LocalhostDenied,
            &constraints,
            &parsed,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.field, "network_constraints.deny_localhost");
        assert_eq!(s.action, "set");
        assert_eq!(s.value.as_deref(), Some("false"));
        assert!(s.note.is_some());
    }

    #[test]
    fn suggestion_for_private_range_denied() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let s = suggestion_for(
            DenyReason::PrivateRangeDenied,
            &constraints,
            &parsed,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.field, "network_constraints.deny_private_ranges");
        assert_eq!(s.action, "set");
        assert_eq!(s.value.as_deref(), Some("false"));
    }

    #[test]
    fn suggestion_for_tailnet_range_denied() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let s = suggestion_for(
            DenyReason::TailnetRangeDenied,
            &constraints,
            &parsed,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.field, "network_constraints.deny_tailnet_ranges");
        assert_eq!(s.action, "set");
    }

    #[test]
    fn suggestion_for_link_local_denied() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let s = suggestion_for(
            DenyReason::LinkLocalDenied,
            &constraints,
            &parsed,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.field, "network_constraints.deny_private_ranges");
        assert!(s.note.as_deref().unwrap().contains("link-local"));
    }

    #[test]
    fn suggestion_for_sni_mismatch() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let s = suggestion_for(DenyReason::SniMismatch, &constraints, &parsed, None, None).unwrap();
        assert_eq!(s.field, "network_constraints.require_sni");
        assert_eq!(s.action, "set");
        assert_eq!(s.value.as_deref(), Some("false"));
    }

    #[test]
    fn suggestion_for_spki_pin_mismatch() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let s = suggestion_for(
            DenyReason::SpkiPinMismatch,
            &constraints,
            &parsed,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.field, "network_constraints.spki_pins");
        assert_eq!(s.action, "add");
    }

    #[test]
    fn suggestion_for_credential_not_authorized() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let s = suggestion_for(
            DenyReason::CredentialNotAuthorized,
            &constraints,
            &parsed,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.field, "capability.allow_credentials");
        assert_eq!(s.action, "add");
    }

    #[test]
    fn suggestion_for_credential_host_not_allowed() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: Some("api.example.com".to_string()),
            port: Some(443),
        };
        let s = suggestion_for(
            DenyReason::CredentialHostNotAllowed,
            &constraints,
            &parsed,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.field, "credential.host_allow");
        assert_eq!(s.action, "add");
    }

    #[test]
    fn suggestion_for_dns_max_ips_exceeded() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let s = suggestion_for(
            DenyReason::DnsMaxIpsExceeded,
            &constraints,
            &parsed,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.field, "network_constraints.dns_max_ips");
        assert_eq!(s.action, "increase");
        assert_eq!(s.value.as_deref(), Some("> 4"));
    }

    #[test]
    fn suggestion_for_hostname_not_canonical() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: Some("Example.COM".to_string()),
            port: Some(443),
        };
        let s = suggestion_for(
            DenyReason::HostnameNotCanonical,
            &constraints,
            &parsed,
            None,
            None,
        )
        .unwrap();
        // Should suggest using canonical hostname or disabling canonicalization
        assert!(
            s.field == "network_constraints.host_allow"
                || s.field == "network_constraints.require_host_canonicalization"
        );
    }

    #[test]
    fn suggestion_for_cidr_deny_with_ip() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: Some("10.0.0.1".to_string()),
            port: Some(80),
        };
        let s = suggestion_for(
            DenyReason::CidrDenyMatched,
            &constraints,
            &parsed,
            None,
            None,
        )
        .unwrap();
        assert_eq!(s.field, "network_constraints.cidr_deny");
        assert_eq!(s.action, "remove");
        assert_eq!(s.value.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn suggestion_for_cidr_deny_no_match_returns_none() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: Some("example.com".to_string()),
            port: Some(443),
        };
        // hostname, not an IP, so cidr match returns None
        let s = suggestion_for(
            DenyReason::CidrDenyMatched,
            &constraints,
            &parsed,
            None,
            None,
        );
        assert!(s.is_none());
    }

    #[test]
    fn suggestion_for_port_not_allowed_uses_override() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: Some(9090),
        };
        let s = suggestion_for(
            DenyReason::PortNotAllowed,
            &constraints,
            &parsed,
            None,
            Some(3333),
        )
        .unwrap();
        // port_override takes precedence
        assert_eq!(s.value.as_deref(), Some("3333"));
    }

    #[test]
    fn suggestion_for_host_not_allowed_with_override() {
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: Some("original.com".to_string()),
            port: Some(443),
        };
        let s = suggestion_for(
            DenyReason::HostNotAllowed,
            &constraints,
            &parsed,
            Some("override.example.com"),
            None,
        )
        .unwrap();
        assert_eq!(s.field, "network_constraints.host_allow");
        assert_eq!(s.action, "add");
        // value should be the canonical form of override.example.com
        assert!(s.value.is_some());
    }

    // ---- build_report tests ----

    fn make_explain_args(url: &str) -> ExplainArgs {
        ExplainArgs {
            url: url.to_string(),
            manifest_path: PathBuf::from("manifest.toml"),
            operation: None,
            sni: None,
            redirect_count: None,
            json: false,
        }
    }

    #[test]
    fn build_report_allowed_sets_fields() {
        let args = make_explain_args("https://api.example.com/v1");
        let constraints = test_constraints();
        let parsed = parse_url_info(&args.url);
        let decision = Ok(fcp_sandbox::EgressDecision {
            allowed: true,
            canonical_host: "api.example.com".to_string(),
            resolved_ips: vec![],
            port: 443,
            tls_required: true,
            expected_sni: Some("api.example.com".to_string()),
            spki_pins: vec![],
            credential_injected: false,
        });
        let report = build_report(
            &args,
            Path::new("manifest.toml"),
            "test_op",
            &constraints,
            &parsed,
            decision,
        );
        assert!(report.allowed);
        assert_eq!(report.canonical_host.as_deref(), Some("api.example.com"));
        assert_eq!(report.port, Some(443));
        assert_eq!(report.tls_required, Some(true));
        assert_eq!(report.expected_sni.as_deref(), Some("api.example.com"));
        assert!(report.reason_code.is_none());
    }

    #[test]
    fn build_report_denied_error_sets_reason() {
        let args = make_explain_args("https://evil.test/hack");
        let constraints = test_constraints();
        let parsed = parse_url_info(&args.url);
        let err = Err(EgressError::Denied {
            reason: "host not in allow list".into(),
            code: DenyReason::HostNotAllowed,
        });
        let report = build_report(
            &args,
            Path::new("manifest.toml"),
            "op1",
            &constraints,
            &parsed,
            err,
        );
        assert!(!report.allowed);
        assert!(report.reason_code.is_some());
        assert!(report.details.is_some());
    }

    #[test]
    fn build_report_non_deny_error_sets_error_code() {
        let args = make_explain_args("not-a-url");
        let constraints = test_constraints();
        let parsed = parse_url_info(&args.url);
        let err = Err(EgressError::InvalidUrl("bad url".into()));
        let report = build_report(
            &args,
            Path::new("manifest.toml"),
            "op1",
            &constraints,
            &parsed,
            err,
        );
        assert!(!report.allowed);
        assert_eq!(report.reason_code.as_deref(), Some("invalid_url"));
        assert!(report.details.is_some());
    }

    #[test]
    fn build_report_redirect_exceeded_denies() {
        let mut args = make_explain_args("https://api.example.com/v1");
        args.redirect_count = Some(10); // exceeds max_redirects=5
        let constraints = test_constraints();
        let parsed = parse_url_info(&args.url);
        let decision = Ok(fcp_sandbox::EgressDecision {
            allowed: true,
            canonical_host: "api.example.com".to_string(),
            resolved_ips: vec![],
            port: 443,
            tls_required: true,
            expected_sni: None,
            spki_pins: vec![],
            credential_injected: false,
        });
        let report = build_report(
            &args,
            Path::new("manifest.toml"),
            "op1",
            &constraints,
            &parsed,
            decision,
        );
        assert!(!report.allowed);
        assert!(
            report
                .details
                .as_deref()
                .unwrap()
                .contains("redirect count 10")
        );
    }

    #[test]
    fn build_report_redirect_within_limit_allows() {
        let mut args = make_explain_args("https://api.example.com/v1");
        args.redirect_count = Some(3); // within max_redirects=5
        let constraints = test_constraints();
        let parsed = parse_url_info(&args.url);
        let decision = Ok(fcp_sandbox::EgressDecision {
            allowed: true,
            canonical_host: "api.example.com".to_string(),
            resolved_ips: vec![],
            port: 443,
            tls_required: true,
            expected_sni: None,
            spki_pins: vec![],
            credential_injected: false,
        });
        let report = build_report(
            &args,
            Path::new("manifest.toml"),
            "op1",
            &constraints,
            &parsed,
            decision,
        );
        assert!(report.allowed);
    }

    #[test]
    fn build_report_sni_mismatch_denies() {
        let mut args = make_explain_args("https://api.example.com/v1");
        args.sni = Some("wrong.example.com".to_string());
        let constraints = test_constraints();
        let parsed = parse_url_info(&args.url);
        let decision = Ok(fcp_sandbox::EgressDecision {
            allowed: true,
            canonical_host: "api.example.com".to_string(),
            resolved_ips: vec![],
            port: 443,
            tls_required: true,
            expected_sni: Some("api.example.com".to_string()),
            spki_pins: vec![],
            credential_injected: false,
        });
        let report = build_report(
            &args,
            Path::new("manifest.toml"),
            "op1",
            &constraints,
            &parsed,
            decision,
        );
        assert!(!report.allowed);
        assert!(report.details.as_deref().unwrap().contains("SNI mismatch"));
    }

    #[test]
    fn build_report_sni_matches_allows() {
        let mut args = make_explain_args("https://api.example.com/v1");
        args.sni = Some("api.example.com".to_string());
        let constraints = test_constraints();
        let parsed = parse_url_info(&args.url);
        let decision = Ok(fcp_sandbox::EgressDecision {
            allowed: true,
            canonical_host: "api.example.com".to_string(),
            resolved_ips: vec![],
            port: 443,
            tls_required: true,
            expected_sni: Some("api.example.com".to_string()),
            spki_pins: vec![],
            credential_injected: false,
        });
        let report = build_report(
            &args,
            Path::new("manifest.toml"),
            "op1",
            &constraints,
            &parsed,
            decision,
        );
        assert!(report.allowed);
    }

    #[test]
    fn build_report_sni_arg_with_no_expected_sni_allows() {
        let mut args = make_explain_args("https://api.example.com/v1");
        args.sni = Some("any.example.com".to_string());
        let constraints = test_constraints();
        let parsed = parse_url_info(&args.url);
        let decision = Ok(fcp_sandbox::EgressDecision {
            allowed: true,
            canonical_host: "api.example.com".to_string(),
            resolved_ips: vec![],
            port: 443,
            tls_required: true,
            expected_sni: None, // no expected SNI
            spki_pins: vec![],
            credential_injected: false,
        });
        let report = build_report(
            &args,
            Path::new("manifest.toml"),
            "op1",
            &constraints,
            &parsed,
            decision,
        );
        // No expected SNI means no mismatch check
        assert!(report.allowed);
    }

    // ---- deny_report tests ----

    #[test]
    fn deny_report_sets_allowed_false() {
        let base = NetExplainReport {
            url: "https://test.com".to_string(),
            manifest_path: "m.toml".to_string(),
            operation: "op".to_string(),
            allowed: true, // starts as true
            reason_code: None,
            rule_id: None,
            details: None,
            suggestion: None,
            canonical_host: None,
            port: None,
            tls_required: None,
            expected_sni: None,
            max_redirects: Some(5),
        };
        let constraints = test_constraints();
        let parsed = ParsedUrlInfo {
            host: None,
            port: None,
        };
        let r = deny_report(
            base,
            DenyReason::HostNotAllowed,
            Some("denied".into()),
            &constraints,
            &parsed,
            None,
            None,
        );
        assert!(!r.allowed);
        assert!(r.reason_code.is_some());
        assert_eq!(r.details.as_deref(), Some("denied"));
    }

    // ---- NetExplainReport serialization edge cases ----

    #[test]
    fn net_explain_report_all_none_fields_omitted() {
        let report = NetExplainReport {
            url: "https://x.com".to_string(),
            manifest_path: "m.toml".to_string(),
            operation: "op".to_string(),
            allowed: true,
            reason_code: None,
            rule_id: None,
            details: None,
            suggestion: None,
            canonical_host: None,
            port: None,
            tls_required: None,
            expected_sni: None,
            max_redirects: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("reason_code"));
        assert!(!json.contains("rule_id"));
        assert!(!json.contains("details"));
        assert!(!json.contains("suggestion"));
        assert!(!json.contains("canonical_host"));
        assert!(!json.contains("port"));
        assert!(!json.contains("tls_required"));
        assert!(!json.contains("expected_sni"));
        assert!(!json.contains("max_redirects"));
    }

    #[test]
    fn net_explain_report_all_fields_present() {
        let report = NetExplainReport {
            url: "https://x.com".to_string(),
            manifest_path: "m.toml".to_string(),
            operation: "op".to_string(),
            allowed: false,
            reason_code: Some("HostNotAllowed".to_string()),
            rule_id: Some("r1".to_string()),
            details: Some("d1".to_string()),
            suggestion: Some(SuggestedChange {
                field: "f".to_string(),
                action: "a".to_string(),
                value: Some("v".to_string()),
                note: Some("n".to_string()),
            }),
            canonical_host: Some("x.com".to_string()),
            port: Some(443),
            tls_required: Some(true),
            expected_sni: Some("x.com".to_string()),
            max_redirects: Some(3),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"reason_code\":\"HostNotAllowed\""));
        assert!(json.contains("\"rule_id\":\"r1\""));
        assert!(json.contains("\"details\":\"d1\""));
        assert!(json.contains("\"canonical_host\":\"x.com\""));
        assert!(json.contains("\"tls_required\":true"));
        assert!(json.contains("\"expected_sni\":\"x.com\""));
        assert!(json.contains("\"max_redirects\":3"));
    }

    #[test]
    fn net_explain_report_pretty_json() {
        let report = NetExplainReport {
            url: "https://api.test.com".to_string(),
            manifest_path: "m.toml".to_string(),
            operation: "op".to_string(),
            allowed: true,
            reason_code: None,
            rule_id: None,
            details: None,
            suggestion: None,
            canonical_host: Some("api.test.com".to_string()),
            port: Some(443),
            tls_required: Some(true),
            expected_sni: None,
            max_redirects: Some(5),
        };
        let pretty = serde_json::to_string_pretty(&report).unwrap();
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("  "));
    }

    // ---- canonical_or_raw additional tests ----

    #[test]
    fn canonical_or_raw_ip_literal_returns_raw() {
        // IP literal cannot be canonicalized as hostname
        let result = canonical_or_raw(Some("192.168.1.1"));
        // Should still return something (the raw value as fallback)
        assert!(result.is_some());
    }

    #[test]
    fn canonical_or_raw_preserves_value_for_simple_host() {
        let result = canonical_or_raw(Some("simple.example.com")).unwrap();
        // Should be some non-empty string
        assert!(!result.is_empty());
    }

    // ---- ExplainArgs construction tests ----

    #[test]
    fn explain_args_defaults() {
        let args = ExplainArgs {
            url: "https://test.com".to_string(),
            manifest_path: PathBuf::from("manifest.toml"),
            operation: None,
            sni: None,
            redirect_count: None,
            json: false,
        };
        assert_eq!(args.manifest_path.display().to_string(), "manifest.toml");
        assert!(!args.json);
        assert!(args.operation.is_none());
        assert!(args.sni.is_none());
        assert!(args.redirect_count.is_none());
    }

    #[test]
    fn explain_args_clone() {
        let args = ExplainArgs {
            url: "https://test.com".to_string(),
            manifest_path: PathBuf::from("custom/path.toml"),
            operation: Some("my_op".to_string()),
            sni: Some("test.com".to_string()),
            redirect_count: Some(3),
            json: true,
        };
        let cloned = args.clone();
        assert_eq!(cloned.url, args.url);
        assert_eq!(cloned.manifest_path, args.manifest_path);
        assert_eq!(cloned.operation, args.operation);
        assert_eq!(cloned.sni, args.sni);
        assert_eq!(cloned.redirect_count, args.redirect_count);
        assert_eq!(cloned.json, args.json);
    }

    #[test]
    fn explain_args_debug() {
        let args = ExplainArgs {
            url: "https://test.com".to_string(),
            manifest_path: PathBuf::from("manifest.toml"),
            operation: None,
            sni: None,
            redirect_count: None,
            json: false,
        };
        let dbg = format!("{args:?}");
        assert!(dbg.contains("ExplainArgs"));
        assert!(dbg.contains("https://test.com"));
    }

    // ---- SuggestedChange tests ----

    #[test]
    fn suggested_change_debug() {
        let s = SuggestedChange {
            field: "f".to_string(),
            action: "a".to_string(),
            value: None,
            note: None,
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SuggestedChange"));
    }

    // ---- NetArgs / NetCommand tests ----

    #[test]
    fn net_command_clone() {
        let cmd = NetCommand::Explain(ExplainArgs {
            url: "https://example.com".to_string(),
            manifest_path: PathBuf::from("m.toml"),
            operation: None,
            sni: None,
            redirect_count: None,
            json: false,
        });
        let cloned = cmd.clone();
        match cloned {
            NetCommand::Explain(a) => {
                assert_eq!(a.url, "https://example.com");
            }
        }
    }

    #[test]
    fn net_args_debug() {
        let args = NetArgs {
            command: NetCommand::Explain(ExplainArgs {
                url: "https://example.com".to_string(),
                manifest_path: PathBuf::from("m.toml"),
                operation: None,
                sni: None,
                redirect_count: None,
                json: false,
            }),
        };
        let dbg = format!("{args:?}");
        assert!(dbg.contains("NetArgs"));
    }
}
