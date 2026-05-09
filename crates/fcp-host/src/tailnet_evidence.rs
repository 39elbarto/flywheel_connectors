//! Evidence contract for real tailnet invoke proof runs.
//!
//! The current `tailnet_invoke` Criterion benchmark is intentionally synthetic:
//! it measures the host-backed invoke path plus injected RTT. This module gives
//! the eventual real transport harness a typed, redaction-safe JSONL contract so
//! missing network prerequisites produce a structured skip instead of another
//! synthetic pass.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;

/// Stable schema tag for tailnet invoke evidence records.
pub const TAILNET_INVOKE_EVIDENCE_SCHEMA_VERSION: &str = "tailnet-invoke-evidence/v1";
/// Bead that owns replacing synthetic tailnet invoke proof.
pub const TAILNET_INVOKE_EVIDENCE_BEAD: &str = "flywheel_connectors-u1jce";

/// Source of the evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailnetInvokeEvidenceSource {
    /// Host-backed benchmark with injected RTT; useful only as a lower-bound fixture.
    SyntheticStub,
    /// Production mesh/tailscale transport path was exercised.
    RealTransport,
    /// Real transport could not run because explicit prerequisites were missing.
    StructuredSkip,
}

/// Route mode requested for the proof run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailnetInvokeRouteMode {
    /// Direct peer path inside the tailnet.
    DirectLan,
    /// DERP or equivalent relay/fallback path.
    DerpFallback,
}

impl TailnetInvokeRouteMode {
    /// Parse a command-line route label.
    ///
    /// # Errors
    ///
    /// Returns an error string when the label is not one of the supported
    /// route modes.
    pub fn parse_cli(value: &str) -> Result<Self, String> {
        match value {
            "direct-lan" | "direct_lan" | "lan" => Ok(Self::DirectLan),
            "derp-fallback" | "derp_fallback" | "derp" => Ok(Self::DerpFallback),
            other => Err(format!(
                "unsupported tailnet route mode '{other}', expected direct-lan or derp-fallback"
            )),
        }
    }
}

impl fmt::Display for TailnetInvokeRouteMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DirectLan => formatter.write_str("direct-lan"),
            Self::DerpFallback => formatter.write_str("derp-fallback"),
        }
    }
}

/// One prerequisite required for a real tailnet invoke run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailnetInvokePrerequisite {
    /// Stable prerequisite name.
    pub name: String,
    /// Whether the prerequisite was satisfied.
    pub satisfied: bool,
    /// Redaction-safe diagnostic detail.
    pub detail: String,
}

impl TailnetInvokePrerequisite {
    /// Build a prerequisite record.
    #[must_use]
    pub fn new(name: impl Into<String>, satisfied: bool, detail: impl Into<String>) -> Self {
        let detail = detail.into();
        Self {
            name: name.into(),
            satisfied,
            detail: redact_sensitive_text(&detail),
        }
    }
}

/// Nearest-rank latency summary for a tailnet invoke sample set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct TailnetInvokeLatencySummary {
    /// Number of samples included.
    pub sample_count: u64,
    /// Minimum sample.
    pub min_ns: u64,
    /// Maximum sample.
    pub max_ns: u64,
    /// Integer mean.
    pub mean_ns: u64,
    /// 50th percentile.
    pub p50_ns: u64,
    /// 95th percentile.
    pub p95_ns: u64,
    /// 99th percentile.
    pub p99_ns: u64,
    /// 99.9th percentile.
    pub p999_ns: u64,
}

impl TailnetInvokeLatencySummary {
    /// Compute nearest-rank latency percentiles from nanosecond samples.
    #[must_use]
    pub fn from_nanos<I>(samples: I) -> Option<Self>
    where
        I: IntoIterator<Item = u64>,
    {
        let mut sorted: Vec<u64> = samples.into_iter().collect();
        if sorted.is_empty() {
            return None;
        }
        sorted.sort_unstable();
        let sum = sorted
            .iter()
            .fold(0_u128, |acc, value| acc.saturating_add(u128::from(*value)));
        let mean = sum / sorted.len() as u128;
        let min_ns = sorted.first().copied()?;
        let max_ns = sorted.last().copied()?;
        Some(Self {
            sample_count: u64::try_from(sorted.len()).unwrap_or(u64::MAX),
            min_ns,
            max_ns,
            mean_ns: u64::try_from(mean).unwrap_or(u64::MAX),
            p50_ns: nearest_rank(&sorted, 500)?,
            p95_ns: nearest_rank(&sorted, 950)?,
            p99_ns: nearest_rank(&sorted, 990)?,
            p999_ns: nearest_rank(&sorted, 999)?,
        })
    }

    /// Compute percentiles from successful per-invoke attempt records.
    #[must_use]
    pub fn from_successful_attempts(attempts: &[TailnetInvokeAttemptEvidence]) -> Option<Self> {
        Self::from_nanos(attempts.iter().filter_map(|attempt| {
            (attempt.outcome == TailnetInvokeAttemptOutcome::Success)
                .then_some(attempt.latency_ns)
                .flatten()
        }))
    }
}

/// Per-invoke outcome classification for real transport evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TailnetInvokeAttemptOutcome {
    /// Invoke completed successfully.
    Success,
    /// Invoke returned a transport or application error.
    Error,
    /// Invoke exceeded its deadline or transport timeout.
    Timeout,
    /// Invoke was cancelled by the caller or host control plane.
    Cancelled,
}

/// One redaction-safe invoke attempt observed by a real transport harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailnetInvokeAttemptEvidence {
    /// Zero-based attempt index within the proof run.
    pub attempt_index: u64,
    /// Classified attempt outcome.
    pub outcome: TailnetInvokeAttemptOutcome,
    /// End-to-end latency in nanoseconds when measured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ns: Option<u64>,
    /// Stable error class for non-successful outcomes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_class: Option<String>,
    /// Redaction-safe diagnostic detail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl TailnetInvokeAttemptEvidence {
    /// Record a successful invoke attempt.
    #[must_use]
    pub const fn success(attempt_index: u64, latency_ns: u64) -> Self {
        Self {
            attempt_index,
            outcome: TailnetInvokeAttemptOutcome::Success,
            latency_ns: Some(latency_ns),
            error_class: None,
            detail: None,
        }
    }

    /// Record a failed, timed-out, or cancelled invoke attempt.
    #[must_use]
    pub fn non_success(
        attempt_index: u64,
        outcome: TailnetInvokeAttemptOutcome,
        latency_ns: Option<u64>,
        error_class: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        debug_assert!(outcome != TailnetInvokeAttemptOutcome::Success);
        let error_class = error_class.into();
        let detail = detail.into();
        Self {
            attempt_index,
            outcome,
            latency_ns,
            error_class: Some(redact_sensitive_text(&error_class)),
            detail: Some(redact_sensitive_text(&detail)),
        }
    }
}

/// Redacted node label for evidence output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailnetInvokeNodeEvidence {
    /// Role in the proof topology, such as `caller` or `responder`.
    pub role: String,
    /// Stable redacted node identifier.
    pub redacted_node_id: String,
}

impl TailnetInvokeNodeEvidence {
    /// Build a redacted node evidence record.
    #[must_use]
    pub fn new(role: impl Into<String>, raw_node_id: &str) -> Self {
        Self {
            role: role.into(),
            redacted_node_id: redact_node_id(raw_node_id),
        }
    }
}

/// Inputs for a real-transport tailnet invoke evidence record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailnetInvokeRealTransportInput {
    /// Requested route mode.
    pub route_mode: TailnetInvokeRouteMode,
    /// Redacted rerunnable command line.
    pub command_line: Vec<String>,
    /// Git revision under test.
    pub git_revision: String,
    /// Redacted topology label.
    pub topology: String,
    /// Redacted nodes involved in the run.
    pub nodes: Vec<TailnetInvokeNodeEvidence>,
    /// Authentication outcome label.
    pub auth_result: String,
    /// Number of transport retries observed.
    pub retries: u64,
    /// Latency summary for the real transport run.
    pub latency: TailnetInvokeLatencySummary,
    /// Per-invoke samples and error classifications.
    pub attempts: Vec<TailnetInvokeAttemptEvidence>,
}

/// Live prerequisite observations collected by the executable evidence runner.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct TailnetInvokeHarnessObservation {
    /// Whether a Tailscale `LocalAPI` endpoint was configured for the run.
    pub localapi_configured: bool,
    /// Whether `LocalAPI` reported the local node connected to the tailnet.
    pub tailscale_connected: bool,
    /// Count of online peers visible from `LocalAPI`.
    pub online_peer_count: usize,
    /// Whether the runner can prove the requested route mode from live telemetry.
    pub route_telemetry_available: bool,
    /// Redaction-safe detail explaining the route telemetry decision.
    pub route_telemetry_detail: String,
    /// Whether production invoke is wired through the mesh/tailscale boundary.
    pub production_mesh_invoke_transport_available: bool,
    /// Redaction-safe detail from the `LocalAPI` probe.
    pub localapi_detail: String,
}

impl TailnetInvokeHarnessObservation {
    /// Build a conservative observation for environments without `LocalAPI`.
    #[must_use]
    pub fn localapi_not_configured() -> Self {
        Self {
            localapi_configured: false,
            tailscale_connected: false,
            online_peer_count: 0,
            route_telemetry_available: false,
            route_telemetry_detail: "LocalAPI status unavailable".to_string(),
            production_mesh_invoke_transport_available: false,
            localapi_detail: "set --localapi-url or FCP_TAILSCALE_LOCALAPI_URL".to_string(),
        }
    }

    /// Convert observations into the prerequisite list emitted in skip records.
    #[must_use]
    pub fn prerequisites(
        &self,
        route_mode: TailnetInvokeRouteMode,
    ) -> Vec<TailnetInvokePrerequisite> {
        let route_name = match route_mode {
            TailnetInvokeRouteMode::DirectLan => "direct-lan-route-observed",
            TailnetInvokeRouteMode::DerpFallback => "derp-fallback-route-observed",
        };

        vec![
            TailnetInvokePrerequisite::new(
                "tailscale-localapi-url",
                self.localapi_configured,
                self.localapi_detail.clone(),
            ),
            TailnetInvokePrerequisite::new(
                "tailscale-connected",
                self.tailscale_connected,
                if self.tailscale_connected {
                    "backend_state=Running".to_string()
                } else {
                    "backend_state was not Running".to_string()
                },
            ),
            TailnetInvokePrerequisite::new(
                "two-tailnet-nodes",
                self.tailscale_connected && self.online_peer_count > 0,
                format!("online_peer_count={}", self.online_peer_count),
            ),
            TailnetInvokePrerequisite::new(
                route_name,
                self.route_telemetry_available,
                self.route_telemetry_detail.clone(),
            ),
            TailnetInvokePrerequisite::new(
                "production-mesh-invoke-transport",
                self.production_mesh_invoke_transport_available,
                "fcp-host invoke remains host-first; mesh/tailscale invoke routing is not wired",
            ),
        ]
    }

    /// Build the structured skip record for the observed environment.
    #[must_use]
    pub fn structured_skip_record(
        &self,
        route_mode: TailnetInvokeRouteMode,
        command_line: Vec<String>,
        git_revision: impl Into<String>,
        topology: impl Into<String>,
    ) -> TailnetInvokeEvidenceRecord {
        TailnetInvokeEvidenceRecord::structured_skip(
            route_mode,
            command_line,
            git_revision,
            topology,
            self.prerequisites(route_mode),
        )
    }
}

/// Machine-readable evidence or skip record for tailnet invoke proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailnetInvokeEvidenceRecord {
    /// Evidence schema version.
    pub schema_version: String,
    /// Owning bead id.
    pub bead_id: String,
    /// Source class for this evidence.
    pub source: TailnetInvokeEvidenceSource,
    /// Requested route mode.
    pub route_mode: TailnetInvokeRouteMode,
    /// Redacted rerunnable command line.
    pub command_line: Vec<String>,
    /// Git revision under test.
    pub git_revision: String,
    /// Redacted topology label.
    pub topology: String,
    /// Redacted nodes involved in the run.
    pub nodes: Vec<TailnetInvokeNodeEvidence>,
    /// Authentication outcome label.
    pub auth_result: String,
    /// Number of transport retries observed.
    pub retries: u64,
    /// Latency summary for real transport records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<TailnetInvokeLatencySummary>,
    /// Per-invoke samples for real transport records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attempts: Vec<TailnetInvokeAttemptEvidence>,
    /// Full prerequisite diagnostics for structured skip records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prerequisites: Vec<TailnetInvokePrerequisite>,
    /// Missing prerequisites for structured skip records.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_prerequisites: Vec<String>,
    /// Redaction-safe skip reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Record generation timestamp.
    pub generated_at: DateTime<Utc>,
}

impl TailnetInvokeEvidenceRecord {
    /// Build a real-transport evidence record.
    #[must_use]
    pub fn real_transport(input: TailnetInvokeRealTransportInput) -> Self {
        Self {
            schema_version: TAILNET_INVOKE_EVIDENCE_SCHEMA_VERSION.to_string(),
            bead_id: TAILNET_INVOKE_EVIDENCE_BEAD.to_string(),
            source: TailnetInvokeEvidenceSource::RealTransport,
            route_mode: input.route_mode,
            command_line: redact_command_line(input.command_line),
            git_revision: redact_sensitive_text(&input.git_revision),
            topology: redact_sensitive_text(&input.topology),
            nodes: input.nodes,
            auth_result: redact_sensitive_text(&input.auth_result),
            retries: input.retries,
            latency: Some(input.latency),
            attempts: input.attempts,
            prerequisites: Vec::new(),
            missing_prerequisites: Vec::new(),
            skip_reason: None,
            generated_at: Utc::now(),
        }
    }

    /// Build a structured skip record from missing prerequisites.
    #[must_use]
    pub fn structured_skip(
        route_mode: TailnetInvokeRouteMode,
        command_line: Vec<String>,
        git_revision: impl Into<String>,
        topology: impl Into<String>,
        prerequisites: Vec<TailnetInvokePrerequisite>,
    ) -> Self {
        let git_revision = git_revision.into();
        let topology = topology.into();
        let missing_prerequisites = prerequisites
            .iter()
            .filter(|prerequisite| !prerequisite.satisfied)
            .map(|prerequisite| prerequisite.name.clone())
            .collect::<Vec<_>>();
        let skip_reason = if missing_prerequisites.is_empty() {
            None
        } else {
            Some(format!(
                "missing_prerequisites:{}",
                missing_prerequisites.join(",")
            ))
        };
        Self {
            schema_version: TAILNET_INVOKE_EVIDENCE_SCHEMA_VERSION.to_string(),
            bead_id: TAILNET_INVOKE_EVIDENCE_BEAD.to_string(),
            source: TailnetInvokeEvidenceSource::StructuredSkip,
            route_mode,
            command_line: redact_command_line(command_line),
            git_revision: redact_sensitive_text(&git_revision),
            topology: redact_sensitive_text(&topology),
            nodes: Vec::new(),
            auth_result: "not_attempted".to_string(),
            retries: 0,
            latency: None,
            attempts: Vec::new(),
            prerequisites,
            missing_prerequisites,
            skip_reason,
            generated_at: Utc::now(),
        }
    }

    /// Render this record as a JSONL value.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the record cannot be converted to JSON.
    pub fn to_jsonl_value(&self) -> Result<Value, serde_json::Error> {
        Ok(json!({
            "record_type": "tailnet_invoke_evidence",
            "schema_version": self.schema_version,
            "bead_id": self.bead_id,
            "evidence": serde_json::to_value(self)?,
        }))
    }

    /// Render this record as one JSONL line.
    ///
    /// # Errors
    ///
    /// Returns a serde error if the record cannot be serialized.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.to_jsonl_value()?)
    }
}

fn nearest_rank(sorted: &[u64], per_mille: usize) -> Option<u64> {
    let len = sorted.len();
    if len == 0 {
        return None;
    }
    let rank = len.saturating_mul(per_mille).saturating_add(999) / 1_000;
    let index = rank.saturating_sub(1).min(len - 1);
    sorted.get(index).copied()
}

fn redact_command_line(command_line: Vec<String>) -> Vec<String> {
    command_line
        .into_iter()
        .map(|arg| redact_sensitive_text(&arg))
        .collect()
}

fn redact_sensitive_text(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let contains_secret = [
        "token",
        "secret",
        "password",
        "credential",
        "bearer",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
        "authorization",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let contains_endpoint = lower.contains("://");
    let contains_tailnet_hostname = lower.contains(".ts.net") || lower.contains(".tailnet.");
    let contains_private_path = lower.contains("/users/")
        || lower.contains("/home/")
        || lower.contains("\\users\\")
        || lower.contains(":\\");

    if contains_secret || contains_endpoint || contains_tailnet_hostname || contains_private_path {
        "[REDACTED]".to_string()
    } else {
        input.to_string()
    }
}

fn redact_node_id(raw_node_id: &str) -> String {
    let digest = blake3::hash(raw_node_id.as_bytes()).to_hex().to_string();
    format!("blake3:{}", &digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_summary_uses_nearest_rank_tail_math() {
        let summary = TailnetInvokeLatencySummary::from_nanos(1_u64..=1_000)
            .expect("non-empty samples have a summary");

        assert_eq!(summary.sample_count, 1_000);
        assert_eq!(summary.min_ns, 1);
        assert_eq!(summary.max_ns, 1_000);
        assert_eq!(summary.mean_ns, 500);
        assert_eq!(summary.p50_ns, 500);
        assert_eq!(summary.p95_ns, 950);
        assert_eq!(summary.p99_ns, 990);
        assert_eq!(summary.p999_ns, 999);
    }

    #[test]
    fn latency_summary_rejects_empty_samples() {
        assert!(TailnetInvokeLatencySummary::from_nanos([]).is_none());
    }

    #[test]
    fn latency_summary_uses_successful_attempt_samples_only() {
        let attempts = vec![
            TailnetInvokeAttemptEvidence::success(0, 100),
            TailnetInvokeAttemptEvidence::non_success(
                1,
                TailnetInvokeAttemptOutcome::Timeout,
                Some(500),
                "timeout",
                "request deadline elapsed",
            ),
            TailnetInvokeAttemptEvidence::non_success(
                2,
                TailnetInvokeAttemptOutcome::Cancelled,
                None,
                "cancelled",
                "caller cancelled operation",
            ),
            TailnetInvokeAttemptEvidence::success(3, 200),
        ];

        let summary = TailnetInvokeLatencySummary::from_successful_attempts(&attempts)
            .expect("successful attempts should produce latency summary");

        assert_eq!(summary.sample_count, 2);
        assert_eq!(summary.min_ns, 100);
        assert_eq!(summary.max_ns, 200);
        assert_eq!(summary.p50_ns, 100);
        assert_eq!(summary.p99_ns, 200);
    }

    #[test]
    fn route_mode_parses_cli_labels() {
        assert_eq!(
            TailnetInvokeRouteMode::parse_cli("direct-lan").expect("direct route"),
            TailnetInvokeRouteMode::DirectLan
        );
        assert_eq!(
            TailnetInvokeRouteMode::parse_cli("derp").expect("derp route"),
            TailnetInvokeRouteMode::DerpFallback
        );
        assert!(TailnetInvokeRouteMode::parse_cli("funnel").is_err());
        assert_eq!(TailnetInvokeRouteMode::DirectLan.to_string(), "direct-lan");
    }

    #[test]
    fn structured_skip_records_missing_prerequisites_and_rerun_command() {
        let credential_arg = format!("--{}=example-value", "token");
        let record = TailnetInvokeEvidenceRecord::structured_skip(
            TailnetInvokeRouteMode::DerpFallback,
            vec!["cargo".to_string(), "run".to_string(), credential_arg],
            "abcdef123456",
            "tailnet proof missing DERP route",
            vec![
                TailnetInvokePrerequisite::new("two-tailnet-nodes", true, "available"),
                TailnetInvokePrerequisite::new("derp-route", false, "no relay route observed"),
            ],
        );

        assert_eq!(record.source, TailnetInvokeEvidenceSource::StructuredSkip);
        assert_eq!(record.auth_result, "not_attempted");
        assert!(record.latency.is_none());
        assert!(record.attempts.is_empty());
        assert_eq!(record.prerequisites.len(), 2);
        assert_eq!(record.missing_prerequisites, vec!["derp-route"]);
        assert_eq!(
            record.skip_reason.as_deref(),
            Some("missing_prerequisites:derp-route")
        );
        assert_eq!(record.command_line[2], "[REDACTED]");

        let jsonl = record.to_jsonl_line().expect("serialize JSONL");
        let value: Value = serde_json::from_str(&jsonl).expect("parse JSONL");
        assert_eq!(value["record_type"], "tailnet_invoke_evidence");
        assert_eq!(value["bead_id"], TAILNET_INVOKE_EVIDENCE_BEAD);
        assert_eq!(
            value["evidence"]["prerequisites"][1]["detail"],
            "no relay route observed"
        );
        assert!(!jsonl.contains("example-value"));
    }

    #[test]
    fn harness_observation_builds_truthful_structured_skip() {
        let observation = TailnetInvokeHarnessObservation {
            localapi_configured: true,
            tailscale_connected: true,
            online_peer_count: 1,
            route_telemetry_available: false,
            route_telemetry_detail: "no active direct route".to_string(),
            production_mesh_invoke_transport_available: false,
            localapi_detail: "backend_state=Running".to_string(),
        };

        let record = observation.structured_skip_record(
            TailnetInvokeRouteMode::DirectLan,
            vec![
                "fcp-tailnet-invoke-evidence".to_string(),
                "--route=direct-lan".to_string(),
            ],
            "abc123",
            "two-node direct LAN proof",
        );

        assert_eq!(
            record.missing_prerequisites,
            vec![
                "direct-lan-route-observed",
                "production-mesh-invoke-transport"
            ]
        );
        assert!(
            record
                .prerequisites
                .iter()
                .any(|prerequisite| prerequisite.name == "two-tailnet-nodes"
                    && prerequisite.satisfied)
        );
        assert_eq!(
            record.skip_reason.as_deref(),
            Some(
                "missing_prerequisites:direct-lan-route-observed,production-mesh-invoke-transport"
            )
        );
    }

    #[test]
    fn evidence_redacts_urls_tailnet_hosts_and_private_paths_in_free_text() {
        let record = TailnetInvokeEvidenceRecord::structured_skip(
            TailnetInvokeRouteMode::DirectLan,
            vec![
                "fcp-tailnet-invoke-evidence".to_string(),
                "--localapi-url=http://127.0.0.1:41112".to_string(),
                "--topology=alice.tailnet.ts.net".to_string(),
                "--artifact=/Users/jemanuel/private/evidence.jsonl".to_string(),
            ],
            "abc123",
            "caller alice.tailnet.ts.net wrote /Users/jemanuel/private/evidence.jsonl",
            vec![TailnetInvokePrerequisite::new(
                "direct-lan-route-observed",
                false,
                "status came from https://example.invalid/localapi/v0/status",
            )],
        );

        assert_eq!(record.command_line[1], "[REDACTED]");
        assert_eq!(record.command_line[2], "[REDACTED]");
        assert_eq!(record.command_line[3], "[REDACTED]");
        assert_eq!(record.topology, "[REDACTED]");
        assert_eq!(record.prerequisites[0].detail, "[REDACTED]");

        let jsonl = record.to_jsonl_line().expect("serialize JSONL");
        assert!(!jsonl.contains("127.0.0.1"));
        assert!(!jsonl.contains("alice.tailnet.ts.net"));
        assert!(!jsonl.contains("/Users/jemanuel"));
        assert!(!jsonl.contains("example.invalid"));
    }

    #[test]
    fn real_transport_record_redacts_nodes_and_carries_percentiles() {
        let attempts = vec![
            TailnetInvokeAttemptEvidence::success(0, 10),
            TailnetInvokeAttemptEvidence::success(1, 20),
            TailnetInvokeAttemptEvidence::non_success(
                2,
                TailnetInvokeAttemptOutcome::Error,
                Some(25),
                "http_500",
                "upstream token leaked in detail",
            ),
            TailnetInvokeAttemptEvidence::non_success(
                3,
                TailnetInvokeAttemptOutcome::Timeout,
                Some(30),
                "timeout",
                "deadline elapsed",
            ),
            TailnetInvokeAttemptEvidence::non_success(
                4,
                TailnetInvokeAttemptOutcome::Cancelled,
                None,
                "cancelled",
                "caller cancelled",
            ),
            TailnetInvokeAttemptEvidence::success(5, 40),
            TailnetInvokeAttemptEvidence::success(6, 50),
        ];
        let latency = TailnetInvokeLatencySummary::from_successful_attempts(&attempts)
            .expect("latency summary");
        let record = TailnetInvokeEvidenceRecord::real_transport(TailnetInvokeRealTransportInput {
            route_mode: TailnetInvokeRouteMode::DirectLan,
            command_line: vec!["tailnet-proof".to_string(), "--route=direct".to_string()],
            git_revision: "017725e91".to_string(),
            topology: "direct LAN tailnet".to_string(),
            nodes: vec![
                TailnetInvokeNodeEvidence::new("caller", "alice.tailnet.ts.net"),
                TailnetInvokeNodeEvidence::new("responder", "bob.tailnet.ts.net"),
            ],
            auth_result: "capability_verified".to_string(),
            retries: 1,
            latency,
            attempts,
        });

        assert_eq!(record.source, TailnetInvokeEvidenceSource::RealTransport);
        assert_eq!(record.missing_prerequisites, Vec::<String>::new());
        assert_eq!(record.latency.expect("latency").p99_ns, 50);
        assert_eq!(record.attempts.len(), 7);
        assert!(
            record
                .nodes
                .iter()
                .all(|node| node.redacted_node_id.starts_with("blake3:"))
        );
        let jsonl = record.to_jsonl_line().expect("serialize JSONL");
        assert!(!jsonl.contains("alice.tailnet.ts.net"));
        assert!(!jsonl.contains("bob.tailnet.ts.net"));
        assert!(!jsonl.contains("leaked"));
        assert!(jsonl.contains("\"p99_ns\":50"));
        assert!(jsonl.contains("\"outcome\":\"timeout\""));
        assert!(jsonl.contains("\"outcome\":\"cancelled\""));
    }
}
