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
                "LocalAPI status does not prove direct-vs-DERP invoke route telemetry",
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
    fn real_transport_record_redacts_nodes_and_carries_percentiles() {
        let latency =
            TailnetInvokeLatencySummary::from_nanos([10, 20, 30, 40, 50]).expect("latency summary");
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
        });

        assert_eq!(record.source, TailnetInvokeEvidenceSource::RealTransport);
        assert_eq!(record.missing_prerequisites, Vec::<String>::new());
        assert_eq!(record.latency.expect("latency").p99_ns, 50);
        assert!(
            record
                .nodes
                .iter()
                .all(|node| node.redacted_node_id.starts_with("blake3:"))
        );
        let jsonl = record.to_jsonl_line().expect("serialize JSONL");
        assert!(!jsonl.contains("alice.tailnet.ts.net"));
        assert!(!jsonl.contains("bob.tailnet.ts.net"));
        assert!(jsonl.contains("\"p99_ns\":50"));
    }
}
