//! Connector/host readiness contract for `fwc`.
//!
//! Defines the minimum metadata and RPC surface that a connector and `fcp-host`
//! must expose for `fwc` to present discovery, configuration, lifecycle
//! management, and invocation workflows cleanly.
//!
//! A connector is **fwc-ready** when all mandatory fields are present and valid.
//! Gap categories identify what is missing so cohort remediation beads can
//! systematically bring connectors to full readiness.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fcp_core::{
    AgentHint, ApprovalMode, AuthDescriptor, CapabilityId, ConnectorDescriptor, DescriptorCheck,
    DescriptorStatus, IdempotencyClass, OperationId, OperationInfo, PrerequisiteCatalog,
    ReadinessDescriptor, RiskLevel, SafetyTier,
};
use fcp_manifest::{ConnectorManifest, ConnectorRuntimeFormat, ManifestApprovalMode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Metadata field truthfulness ─────────────────────────────────────────

/// Where a metadata value originated.
///
/// Provenance makes it mechanically impossible to confuse a manifest
/// declaration with a live runtime observation.  Downstream consumers
/// (MCP export, workflow engine, discovery UI) can use this to decide
/// how much weight to give a value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetadataProvenance {
    /// The connector's own manifest declared this value.
    DeclaredByConnector,
    /// The host observed or computed this value at runtime.
    ObservedByHost,
    /// Measured during actual execution (latency, throughput, etc.).
    MeasuredAtRuntime,
    /// Inferred from policy rules, zone settings, or configuration.
    InferredFromPolicy,
    /// Origin is not tracked (legacy code path or test fixture).
    Unattributed,
}

impl MetadataProvenance {
    /// Machine-readable tag for JSON output.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::DeclaredByConnector => "declared-by-connector",
            Self::ObservedByHost => "observed-by-host",
            Self::MeasuredAtRuntime => "measured-at-runtime",
            Self::InferredFromPolicy => "inferred-from-policy",
            Self::Unattributed => "unattributed",
        }
    }

    /// Human-readable explanation of this provenance source.
    pub const fn explanation(self) -> &'static str {
        match self {
            Self::DeclaredByConnector => "Value declared by the connector manifest.",
            Self::ObservedByHost => "Value observed or computed by the host at runtime.",
            Self::MeasuredAtRuntime => "Value measured during actual execution.",
            Self::InferredFromPolicy => "Value inferred from policy or configuration.",
            Self::Unattributed => "Origin is not tracked.",
        }
    }

    /// Whether this source is considered authoritative for live operations.
    pub const fn is_authoritative(self) -> bool {
        matches!(self, Self::ObservedByHost | Self::MeasuredAtRuntime)
    }
}

/// Explicit metadata-field wrapper that distinguishes between "we have a
/// value", "we have not queried yet", "the connector does not implement
/// this surface", and "the data should exist but is temporarily
/// unreachable."
///
/// Serialises as an object with `status` + optional `value` so consumers
/// never have to guess whether a missing JSON key means "unknown" or
/// "not applicable."
#[derive(Clone, Debug)]
pub enum MetadataField<T> {
    /// The field has a verified value.
    Known(T),
    /// No trustworthy signal is available yet (host still loading, first
    /// query has not returned, etc.).
    Unknown,
    /// The connector definitively does not implement this surface.
    Unsupported,
    /// The surface should exist but is temporarily unreachable (host
    /// down, timeout, transient error).
    Unavailable,
    /// The surface is not relevant for this connector archetype (e.g.
    /// streaming rate-limits on a request-response-only connector).
    NotApplicable,
}

impl<T> MetadataField<T> {
    /// Returns `true` when a verified value is present.
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }

    /// Borrow the inner value if `Known`.
    pub fn as_known(&self) -> Option<&T> {
        match self {
            Self::Known(value) => Some(value),
            _ => None,
        }
    }

    /// Map the inner value when `Known`, preserving the state otherwise.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> MetadataField<U> {
        match self {
            Self::Known(value) => MetadataField::Known(f(value)),
            Self::Unknown => MetadataField::Unknown,
            Self::Unsupported => MetadataField::Unsupported,
            Self::Unavailable => MetadataField::Unavailable,
            Self::NotApplicable => MetadataField::NotApplicable,
        }
    }

    /// Machine-readable status tag for this field.
    pub fn status_tag(&self) -> &'static str {
        match self {
            Self::Known(_) => "known",
            Self::Unknown => "unknown",
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
            Self::NotApplicable => "not-applicable",
        }
    }

    /// Upgrade a legacy `Option<T>` into a `MetadataField`.  `None` becomes
    /// `Unknown` because the old code path could not distinguish states.
    pub fn from_option(value: Option<T>) -> Self {
        match value {
            Some(value) => Self::Known(value),
            None => Self::Unknown,
        }
    }
}

impl<T: Serialize> Serialize for MetadataField<T> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("status", self.status_tag())?;
        if let Self::Known(value) = self {
            map.serialize_entry("value", value)?;
        }
        map.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for MetadataField<T> {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw<V> {
            status: String,
            value: Option<V>,
        }
        let raw = Raw::<T>::deserialize(deserializer)?;
        match raw.status.as_str() {
            "known" => raw.value.map(MetadataField::Known).ok_or_else(|| {
                serde::de::Error::custom("MetadataField status 'known' requires a value")
            }),
            "unknown" => Ok(MetadataField::Unknown),
            "unsupported" => Ok(MetadataField::Unsupported),
            "unavailable" => Ok(MetadataField::Unavailable),
            "not-applicable" => Ok(MetadataField::NotApplicable),
            other => Err(serde::de::Error::custom(format!(
                "unknown MetadataField status: {other}"
            ))),
        }
    }
}

// ── Provenance-tracking metadata field ──────────────────────────────────

/// A metadata field paired with its provenance — where the value
/// came from.  This is the full-fidelity wrapper that downstream
/// consumers (MCP export, workflow engine, discovery UI) should use
/// when the origin of a value matters for trust decisions.
///
/// Serialises as `{ "status": "...", "provenance": "...", "value": ... }`.
#[derive(Clone, Debug)]
pub struct ProvenanceMetadataField<T> {
    /// The metadata field state and optional value.
    pub field: MetadataField<T>,
    /// Where this metadata originated.
    pub provenance: MetadataProvenance,
}

impl<T> ProvenanceMetadataField<T> {
    /// Create a new provenance-tracked field.
    pub const fn new(field: MetadataField<T>, provenance: MetadataProvenance) -> Self {
        Self { field, provenance }
    }

    /// Convenience: create a `Known` field with provenance.
    pub const fn known(value: T, provenance: MetadataProvenance) -> Self {
        Self {
            field: MetadataField::Known(value),
            provenance,
        }
    }

    /// Convenience: create an `Unknown` field with provenance.
    pub const fn unknown(provenance: MetadataProvenance) -> Self {
        Self {
            field: MetadataField::Unknown,
            provenance,
        }
    }

    /// Convenience: create an `Unsupported` field with provenance.
    pub const fn unsupported(provenance: MetadataProvenance) -> Self {
        Self {
            field: MetadataField::Unsupported,
            provenance,
        }
    }

    /// Returns `true` when a verified value is present.
    pub fn is_known(&self) -> bool {
        self.field.is_known()
    }

    /// Borrow the inner value if `Known`.
    pub fn as_known(&self) -> Option<&T> {
        self.field.as_known()
    }

    /// Map the inner value when `Known`, preserving provenance and state.
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> ProvenanceMetadataField<U> {
        ProvenanceMetadataField {
            field: self.field.map(f),
            provenance: self.provenance,
        }
    }

    /// Whether the provenance source is considered authoritative.
    pub const fn is_authoritative(&self) -> bool {
        self.provenance.is_authoritative()
    }

    /// Strip provenance, returning just the field.
    pub fn into_field(self) -> MetadataField<T> {
        self.field
    }

    /// Upgrade a bare `MetadataField` with `Unattributed` provenance.
    pub const fn from_unattributed(field: MetadataField<T>) -> Self {
        Self {
            field,
            provenance: MetadataProvenance::Unattributed,
        }
    }
}

impl<T: Serialize> Serialize for ProvenanceMetadataField<T> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("status", self.field.status_tag())?;
        map.serialize_entry("provenance", self.provenance.tag())?;
        if let MetadataField::Known(value) = &self.field {
            map.serialize_entry("value", value)?;
        }
        map.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ProvenanceMetadataField<T> {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw<V> {
            status: String,
            provenance: Option<String>,
            value: Option<V>,
        }
        let raw = Raw::<T>::deserialize(deserializer)?;
        let field = match raw.status.as_str() {
            "known" => raw.value.map(MetadataField::Known).ok_or_else(|| {
                serde::de::Error::custom("ProvenanceMetadataField status 'known' requires a value")
            })?,
            "unknown" => MetadataField::Unknown,
            "unsupported" => MetadataField::Unsupported,
            "unavailable" => MetadataField::Unavailable,
            "not-applicable" => MetadataField::NotApplicable,
            other => {
                return Err(serde::de::Error::custom(format!(
                    "unknown ProvenanceMetadataField status: {other}"
                )));
            }
        };
        let provenance = match raw.provenance.as_deref() {
            Some("declared-by-connector") => MetadataProvenance::DeclaredByConnector,
            Some("observed-by-host") => MetadataProvenance::ObservedByHost,
            Some("measured-at-runtime") => MetadataProvenance::MeasuredAtRuntime,
            Some("inferred-from-policy") => MetadataProvenance::InferredFromPolicy,
            Some("unattributed") | None => MetadataProvenance::Unattributed,
            Some(other) => {
                return Err(serde::de::Error::custom(format!(
                    "unknown provenance: {other}"
                )));
            }
        };
        Ok(Self { field, provenance })
    }
}

// ── Metadata state representation ───────────────────────────────────────
// Defines how each `MetadataField` state is rendered across CLI output,
// JSON envelopes, log entries, and follow-up guidance.  This ensures every
// consumer speaks the same vocabulary and agents/users never confuse
// "unknown" with "unsupported" or "unavailable."

/// Presentation attributes for a single metadata state.
///
/// Downstream rendering (CLI, JSON, MCP export, TOON) should use these
/// values instead of hard-coding state-specific strings.  This makes the
/// vocabulary stable and testable.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MetadataStateRepr {
    /// Machine-readable status tag (matches `MetadataField::status_tag()`).
    pub status: &'static str,
    /// One-word CLI symbol suitable for table columns (e.g. "?" for unknown).
    pub cli_symbol: &'static str,
    /// Terminal label for human-readable output (e.g. "unknown").
    pub cli_label: &'static str,
    /// Suggested ANSI color name for CLI rendering.
    pub cli_color: &'static str,
    /// Short explanation shown in `--verbose` or `--json` output.
    pub explanation: &'static str,
    /// Whether agents should treat this state as actionable (i.e. the
    /// situation might change if the user takes some step).
    pub actionable: bool,
    /// Follow-up guidance lines.  Empty for terminal states like "known".
    pub guidance: &'static [&'static str],
}

/// Canonical representations for every `MetadataField` state.
///
/// Indexed by status tag, this table is the single source of truth for
/// how metadata states appear to users and agents.
#[allow(dead_code)]
pub const METADATA_STATE_REPRS: &[MetadataStateRepr] = &[
    MetadataStateRepr {
        status: "known",
        cli_symbol: "✓",
        cli_label: "known",
        cli_color: "green",
        explanation: "A verified value is available.",
        actionable: false,
        guidance: &[],
    },
    MetadataStateRepr {
        status: "unknown",
        cli_symbol: "?",
        cli_label: "unknown",
        cli_color: "yellow",
        explanation: "No trustworthy signal is available yet. The host may still be loading or the first query has not returned.",
        actionable: true,
        guidance: &[
            "Wait for the host to complete initial discovery.",
            "Use `fwc doctor` to check connectivity.",
            "Query the host directly with `--host <endpoint>`.",
        ],
    },
    MetadataStateRepr {
        status: "unsupported",
        cli_symbol: "✗",
        cli_label: "unsupported",
        cli_color: "red",
        explanation: "The connector definitively does not implement this surface.",
        actionable: false,
        guidance: &[
            "Check if a newer connector version adds this capability.",
            "Use `fwc ops <connector>` to see what is available.",
        ],
    },
    MetadataStateRepr {
        status: "unavailable",
        cli_symbol: "!",
        cli_label: "unavailable",
        cli_color: "red",
        explanation: "The surface should exist but is temporarily unreachable (host down, timeout, transient error).",
        actionable: true,
        guidance: &[
            "Check that `fcp-host` is running and reachable.",
            "Retry the command once the host is available.",
            "Use `--offline` to inspect local artifacts instead.",
        ],
    },
    MetadataStateRepr {
        status: "not-applicable",
        cli_symbol: "–",
        cli_label: "n/a",
        cli_color: "dim",
        explanation: "This surface is not relevant for this connector archetype.",
        actionable: false,
        guidance: &[],
    },
];

/// Look up the canonical representation for a status tag.
#[allow(dead_code)]
#[must_use]
pub fn metadata_state_repr(status_tag: &str) -> Option<&'static MetadataStateRepr> {
    METADATA_STATE_REPRS.iter().find(|r| r.status == status_tag)
}

/// Look up the representation for a `MetadataField` value.
#[allow(dead_code)]
#[must_use]
pub fn field_repr<T>(field: &MetadataField<T>) -> &'static MetadataStateRepr {
    metadata_state_repr(field.status_tag())
        .expect("every MetadataField variant has a representation")
}

/// Format a `MetadataField` for CLI display: "symbol label" (e.g. "? unknown").
#[allow(dead_code)]
#[must_use]
pub fn format_field_cli<T>(field: &MetadataField<T>) -> String {
    let repr = field_repr(field);
    format!("{} {}", repr.cli_symbol, repr.cli_label)
}

/// Format a `MetadataField` for log output: "status=unknown explanation=..."
#[allow(dead_code)]
#[must_use]
pub fn format_field_log<T>(field: &MetadataField<T>) -> String {
    let repr = field_repr(field);
    format!(
        "status={} explanation=\"{}\"",
        repr.status, repr.explanation
    )
}

/// Build a JSON representation of a `MetadataField`'s state metadata
/// (status, explanation, actionable, guidance) without the value itself.
#[allow(dead_code)]
#[must_use]
pub fn field_state_json<T>(field: &MetadataField<T>) -> serde_json::Value {
    let repr = field_repr(field);
    serde_json::json!({
        "status": repr.status,
        "explanation": repr.explanation,
        "actionable": repr.actionable,
        "guidance": repr.guidance,
        "cli_symbol": repr.cli_symbol,
        "cli_label": repr.cli_label,
    })
}

/// Format a `ProvenanceMetadataField` for CLI display, including provenance.
#[allow(dead_code)]
#[must_use]
pub fn format_provenance_field_cli<T>(field: &ProvenanceMetadataField<T>) -> String {
    let repr = field_repr(&field.field);
    format!(
        "{} {} ({})",
        repr.cli_symbol,
        repr.cli_label,
        field.provenance.tag()
    )
}

/// Format a `ProvenanceMetadataField` for log output with provenance.
#[allow(dead_code)]
#[must_use]
pub fn format_provenance_field_log<T>(field: &ProvenanceMetadataField<T>) -> String {
    let repr = field_repr(&field.field);
    format!(
        "status={} provenance={} explanation=\"{}\"",
        repr.status,
        field.provenance.tag(),
        repr.explanation
    )
}

// ── Command availability semantics ──────────────────────────────────────

/// Distinct semantic state for any command outcome that makes the source
/// of truth, authority boundary, and recoverability machine-readable.
///
/// Every `fwc` dispatch should tag its result with one of these so agents
/// and downstream tooling never have to guess whether a response came from
/// live runtime, offline artifacts, or something in between.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandAvailability {
    /// Result backed by a live, authenticated host/mesh connection.
    LiveRuntime,
    /// Result derived from offline artifacts (manifests, local catalog,
    /// static contracts) — not authoritative for runtime state.
    OfflineArtifact,
    /// The connector or host definitively does not implement this surface.
    /// This is a permanent condition until the connector is upgraded.
    Unsupported,
    /// The feature is planned but not yet implemented.  Output is a
    /// contract preview, not a real result.
    Planned,
    /// The surface should exist but is temporarily unreachable (host
    /// down, endpoint timeout, transient network error).
    Unavailable,
    /// The operation was blocked by policy, approval, auth, or zone
    /// restrictions.  The caller may be able to remediate.
    Denied,
    /// Cannot determine the availability state (host not queried, first
    /// connection pending, mixed signals).
    Unknown,
}

impl CommandAvailability {
    /// Machine-readable tag for JSON envelopes.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::LiveRuntime => "live-runtime",
            Self::OfflineArtifact => "offline-artifact",
            Self::Unsupported => "unsupported",
            Self::Planned => "planned",
            Self::Unavailable => "unavailable",
            Self::Denied => "denied",
            Self::Unknown => "unknown",
        }
    }

    /// Human-readable one-line explanation of what this state means.
    pub const fn explanation(&self) -> &'static str {
        match self {
            Self::LiveRuntime => "Result is backed by a live host connection.",
            Self::OfflineArtifact => {
                "Result is derived from offline artifacts and may not reflect live state."
            }
            Self::Unsupported => "This operation is not supported by the connector or host.",
            Self::Planned => {
                "This feature is planned but not yet implemented. Output is a contract preview."
            }
            Self::Unavailable => {
                "The operation should be available but the host or endpoint is temporarily unreachable."
            }
            Self::Denied => {
                "The operation was blocked by policy, approval requirements, or authorization."
            }
            Self::Unknown => {
                "Cannot determine availability. The host has not been queried or returned ambiguous state."
            }
        }
    }

    /// Whether an agent should consider retrying or remediating.
    pub const fn is_recoverable(&self) -> bool {
        match self {
            Self::LiveRuntime | Self::OfflineArtifact | Self::Unsupported | Self::Planned => false,
            Self::Unavailable | Self::Denied | Self::Unknown => true,
        }
    }

    /// Whether the result carries authoritative runtime data.
    pub const fn is_authoritative(&self) -> bool {
        matches!(self, Self::LiveRuntime)
    }

    /// Whether the result represents a successful data delivery
    /// (live or offline).
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::LiveRuntime | Self::OfflineArtifact)
    }

    /// Suggested next actions for the caller based on this state.
    pub fn next_actions(&self, command: &str) -> Vec<String> {
        match self {
            Self::LiveRuntime => vec![],
            Self::OfflineArtifact => vec![
                format!("Use `fwc {command} --host <endpoint>` for live host truth."),
                "Offline data may be stale; verify against the running system.".to_owned(),
            ],
            Self::Unsupported => vec![
                "Check if a newer connector version supports this operation.".to_owned(),
                format!("Use `fwc ops <connector>` to see available operations."),
            ],
            Self::Planned => vec![
                "This feature is under development and not yet available.".to_owned(),
                "The contract preview shows the expected interface shape.".to_owned(),
            ],
            Self::Unavailable => vec![
                "Check that `fcp-host` is running and reachable.".to_owned(),
                format!("Retry `fwc {command}` once the host is available."),
                format!("Use `fwc {command} --offline` to inspect local artifacts instead."),
            ],
            Self::Denied => vec![
                "Review the policy or approval requirements for this operation.".to_owned(),
                "Check zone restrictions and agent authorization.".to_owned(),
                "Use `fwc auth status` to inspect current credentials.".to_owned(),
            ],
            Self::Unknown => vec![
                format!("Use `fwc {command} --host <endpoint>` to query a specific host."),
                "Run `fwc doctor` to diagnose connectivity issues.".to_owned(),
            ],
        }
    }

    /// Standard exit-code category for dispatch outcomes.
    ///
    /// This maps availability states to the `CliExitCode` semantic
    /// buckets defined in `main.rs` without importing the enum itself.
    pub const fn exit_code_u8(&self) -> u8 {
        match self {
            Self::LiveRuntime | Self::OfflineArtifact | Self::Planned => 0, // success / preview
            Self::Unsupported => 5,                                         // validation
            Self::Unavailable | Self::Unknown => 8,                         // transport
            Self::Denied => 6,                                              // policy-denied
        }
    }

    /// Compact label for terminal and agent-facing output.
    ///
    /// Returns a short string like `"LIVE"`, `"OFFLINE"`, `"DENIED [remediate]"`
    /// that fits in a status column or agent summary line.  Bracket suffixes
    /// indicate whether the caller can act.
    pub const fn compact_label(&self) -> &'static str {
        match self {
            Self::LiveRuntime => "LIVE",
            Self::OfflineArtifact => "OFFLINE",
            Self::Unsupported => "UNSUPPORTED",
            Self::Planned => "PLANNED [preview]",
            Self::Unavailable => "UNAVAILABLE [retry]",
            Self::Denied => "DENIED [remediate]",
            Self::Unknown => "UNKNOWN [diagnose]",
        }
    }

    /// Short actionable help text for the given command, suitable for
    /// inline display in `--help`, error banners, and agent tool-call
    /// responses.  More detailed guidance lives in `next_actions()`.
    pub fn help_text(&self, command: &str) -> String {
        match self {
            Self::LiveRuntime => {
                format!("'{command}' returned live host-authoritative data.")
            }
            Self::OfflineArtifact => {
                format!("'{command}' used offline artifacts. Add --host <endpoint> for live data.")
            }
            Self::Unsupported => {
                format!(
                    "'{command}' is not supported by this connector. Check `fwc ops` for available operations."
                )
            }
            Self::Planned => {
                format!(
                    "'{command}' is planned but not yet implemented. Output is a contract preview only."
                )
            }
            Self::Unavailable => {
                format!(
                    "'{command}' failed: host unreachable. Retry later or use --offline for local artifacts."
                )
            }
            Self::Denied => {
                format!(
                    "'{command}' was denied by policy or authorization. Run `fwc auth status` to inspect."
                )
            }
            Self::Unknown => {
                format!(
                    "'{command}' availability unknown. Run `fwc doctor` or specify --host to query directly."
                )
            }
        }
    }

    /// CLI-friendly symbol for tabular rendering.
    pub const fn cli_symbol(&self) -> &'static str {
        match self {
            Self::LiveRuntime => "[+]",
            Self::OfflineArtifact => "[~]",
            Self::Unsupported => "[x]",
            Self::Planned => "[.]",
            Self::Unavailable => "[!]",
            Self::Denied => "[-]",
            Self::Unknown => "[?]",
        }
    }

    /// Severity category for sorting and filtering.
    pub const fn severity_rank(&self) -> u8 {
        match self {
            Self::LiveRuntime => 0,
            Self::OfflineArtifact => 1,
            Self::Planned => 2,
            Self::Unsupported => 3,
            Self::Unknown => 4,
            Self::Unavailable => 5,
            Self::Denied => 6,
        }
    }
}

impl std::fmt::Display for CommandAvailability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.compact_label())
    }
}

// ── Command family runtime-boundary classification ───────────────────

/// How a command family relates to the live/offline truth boundary.
///
/// Every `fwc` command must be classified into exactly one of these
/// categories so agents can mechanically determine whether a result
/// carries live runtime authority or explicit offline artifact data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommandTruthMode {
    /// The command always requires a live host connection and returns
    /// host-authoritative data.  Fails fast when no host is reachable.
    LiveOnly,
    /// The command always operates on local artifacts (manifests,
    /// catalog files, stored state) and never contacts a host.
    OfflineOnly,
    /// The command can operate in both modes.  The user chooses via
    /// `--host` (live) or `--offline` (artifact) flags.  The output
    /// always carries a clear provenance marker.
    Hybrid,
    /// The command passes through to a separate binary and the
    /// availability semantics are set at the binary boundary.
    Passthrough,
    /// The command is planned but not yet implemented.  Its structured
    /// dispatch returns a contract preview.
    PlannedOnly,
}

impl CommandTruthMode {
    /// Machine-readable tag.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::LiveOnly => "live-only",
            Self::OfflineOnly => "offline-only",
            Self::Hybrid => "hybrid",
            Self::Passthrough => "passthrough",
            Self::PlannedOnly => "planned-only",
        }
    }

    /// Human-readable description.
    pub const fn description(&self) -> &'static str {
        match self {
            Self::LiveOnly => "Requires a live host connection.",
            Self::OfflineOnly => "Operates on local artifacts only.",
            Self::Hybrid => {
                "Supports both live and offline modes with explicit provenance."
            }
            Self::Passthrough => {
                "Passes through to a separate binary at the process boundary."
            }
            Self::PlannedOnly => "Planned but not yet implemented.",
        }
    }

    /// Whether this mode can produce authoritative runtime data.
    pub const fn can_be_authoritative(&self) -> bool {
        matches!(self, Self::LiveOnly | Self::Hybrid)
    }
}

/// Static classification of an `fwc` command family with its truth-boundary mode.
#[derive(Clone, Debug, Serialize)]
pub struct CommandFamilyEntry {
    /// Command name as it appears in the CLI (e.g. `"list"`, `"batch-file"`).
    pub name: &'static str,
    /// Truth boundary classification.
    pub mode: CommandTruthMode,
}

/// Complete classification of all `fwc` command families.
///
/// This is the canonical source of truth for which commands are live-only,
/// offline-only, hybrid, passthrough, or planned.  Bead 29.9 requires that
/// this table is mechanically complete and that dispatch functions honor it.
pub const COMMAND_FAMILY_CLASSIFICATION: &[CommandFamilyEntry] = &[
    // ── Live-only commands (require host, fail fast without it) ──
    CommandFamilyEntry { name: "invoke", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "simulate", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "batch", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "batch-file", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "doctor", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "status", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "budget", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "pin", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "unpin", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "rollout", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "install", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "update", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "cancel", mode: CommandTruthMode::LiveOnly },
    CommandFamilyEntry { name: "map", mode: CommandTruthMode::LiveOnly },
    // ── Offline-only commands (operate on local state, never contact host) ──
    CommandFamilyEntry { name: "context", mode: CommandTruthMode::OfflineOnly },
    CommandFamilyEntry { name: "session", mode: CommandTruthMode::OfflineOnly },
    CommandFamilyEntry { name: "agent", mode: CommandTruthMode::OfflineOnly },
    CommandFamilyEntry { name: "task", mode: CommandTruthMode::OfflineOnly },
    CommandFamilyEntry { name: "history", mode: CommandTruthMode::OfflineOnly },
    CommandFamilyEntry { name: "pipe", mode: CommandTruthMode::OfflineOnly },
    CommandFamilyEntry { name: "plan", mode: CommandTruthMode::OfflineOnly },
    CommandFamilyEntry { name: "explain", mode: CommandTruthMode::OfflineOnly },
    CommandFamilyEntry { name: "do", mode: CommandTruthMode::OfflineOnly },
    CommandFamilyEntry { name: "guide", mode: CommandTruthMode::OfflineOnly },
    CommandFamilyEntry { name: "config", mode: CommandTruthMode::OfflineOnly },
    // ── Hybrid commands (live with --host, offline otherwise) ──
    CommandFamilyEntry { name: "list", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "show", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "ops", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "schema", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "examples", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "search", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "suggest", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "template", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "validate", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "export-tools", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "recipe", mode: CommandTruthMode::Hybrid },
    CommandFamilyEntry { name: "pipeline", mode: CommandTruthMode::Hybrid },
    // ── Passthrough commands (delegated to separate binaries) ──
    CommandFamilyEntry { name: "supply-chain", mode: CommandTruthMode::Passthrough },
    CommandFamilyEntry { name: "audit", mode: CommandTruthMode::Passthrough },
    CommandFamilyEntry { name: "manifest", mode: CommandTruthMode::Passthrough },
    CommandFamilyEntry { name: "net", mode: CommandTruthMode::Passthrough },
    CommandFamilyEntry { name: "trace", mode: CommandTruthMode::Passthrough },
    CommandFamilyEntry { name: "policy", mode: CommandTruthMode::Passthrough },
    CommandFamilyEntry { name: "package", mode: CommandTruthMode::Passthrough },
    // ── Planned commands (not yet implemented, contract preview only) ──
    CommandFamilyEntry { name: "serve-mcp", mode: CommandTruthMode::PlannedOnly },
];

/// Look up the truth-boundary classification for a command name.
pub fn classify_command(name: &str) -> Option<&'static CommandFamilyEntry> {
    COMMAND_FAMILY_CLASSIFICATION
        .iter()
        .find(|entry| entry.name == name)
}

/// Structured outcome envelope that pairs a JSON payload with its
/// availability semantics.  This is the standard shape emitted by
/// dispatch functions and consumed by the rendering pipeline.
#[derive(Clone, Debug, Serialize)]
pub struct CommandEnvelope {
    /// Machine-readable availability state.
    pub availability: CommandAvailability,
    /// The command that produced this envelope.
    pub command: String,
    /// Whether the result is authoritative runtime data.
    pub authoritative: bool,
    /// Human-readable explanation of the availability state.
    pub explanation: String,
    /// Whether the caller can remediate the situation.
    pub recoverable: bool,
    /// Suggested next actions.
    pub next_actions: Vec<String>,
}

impl CommandEnvelope {
    /// Build an envelope from an availability state and command name.
    pub fn new(availability: CommandAvailability, command: &str) -> Self {
        let authoritative = availability.is_authoritative();
        let explanation = availability.explanation().to_owned();
        let recoverable = availability.is_recoverable();
        let next_actions = availability.next_actions(command);
        Self {
            availability,
            command: command.to_owned(),
            authoritative,
            explanation,
            recoverable,
            next_actions,
        }
    }

    /// Merge this envelope into a JSON payload as a top-level
    /// `"availability"` object.
    pub fn inject_into(&self, payload: &mut Value) {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "availability".to_owned(),
                serde_json::to_value(self).unwrap_or(Value::Null),
            );
        }
    }

    /// Compact single-line rendering for terminal output and agent summaries.
    ///
    /// Format: `[symbol] LABEL: explanation`
    /// Example: `[!] UNAVAILABLE [retry]: The operation should be available but the host or endpoint is temporarily unreachable.`
    pub fn compact_line(&self) -> String {
        format!(
            "{} {}: {}",
            self.availability.cli_symbol(),
            self.availability.compact_label(),
            self.explanation
        )
    }

    /// Structured transcript entry for logging and replay.
    ///
    /// Returns a JSON value with a stable schema suitable for audit
    /// trails and transcript reconstruction.  Unlike `inject_into()`,
    /// this is self-contained and includes a timestamp placeholder.
    pub fn transcript_entry(&self) -> Value {
        serde_json::json!({
            "type": "availability_verdict",
            "command": self.command,
            "state": self.availability.tag(),
            "authoritative": self.authoritative,
            "recoverable": self.recoverable,
            "exit_code": self.availability.exit_code_u8(),
            "severity_rank": self.availability.severity_rank(),
            "explanation": self.explanation,
            "next_actions": self.next_actions,
            "compact": self.availability.compact_label(),
            "symbol": self.availability.cli_symbol(),
        })
    }

    /// Help-text suitable for inline display in error banners.
    pub fn help_banner(&self) -> String {
        self.availability.help_text(&self.command)
    }

    /// Exit code derived from availability semantics.
    pub const fn exit_code(&self) -> u8 {
        self.availability.exit_code_u8()
    }
}

impl std::fmt::Display for CommandEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} ({})",
            self.availability.cli_symbol(),
            self.command,
            self.availability.compact_label()
        )
    }
}

// ── Readiness verdict ───────────────────────────────────────────────────

/// Overall readiness assessment for a single connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadinessVerdict {
    /// Canonical connector id (e.g. `"github:fcp2:1.0"`).
    pub connector_id: String,
    /// Crate path relative to workspace root (e.g. `"connectors/github"`).
    pub crate_path: String,
    /// Connector category/cohort for grouping remediation work.
    pub cohort: ConnectorCohort,
    /// Overall readiness level.
    pub level: ReadinessLevel,
    /// Per-area checklist results.
    pub areas: ReadinessAreas,
    /// Specific gaps that prevent full readiness.
    pub gaps: Vec<ReadinessGap>,
}

/// Readiness level summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReadinessLevel {
    /// All mandatory fields present, all areas pass.
    Ready,
    /// Core functionality works but some metadata is missing.
    PartiallyReady,
    /// Major gaps prevent fwc from presenting this connector cleanly.
    NotReady,
}

/// Connector cohort for grouping remediation work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectorCohort {
    Messaging,
    Social,
    Workspace,
    Productivity,
    Ai,
    DevTools,
    Infra,
    Data,
    Storage,
    Analytics,
    Finance,
    Business,
    Browser,
    Knowledge,
    Automation,
    Community,
    Security,
    Media,
    Vectordb,
    Iot,
    Other,
}

impl ConnectorCohort {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Messaging => "messaging",
            Self::Social => "social",
            Self::Workspace => "workspace",
            Self::Productivity => "productivity",
            Self::Ai => "ai",
            Self::DevTools => "dev-tools",
            Self::Infra => "infra",
            Self::Data => "data",
            Self::Storage => "storage",
            Self::Analytics => "analytics",
            Self::Finance => "finance",
            Self::Business => "business",
            Self::Browser => "browser",
            Self::Knowledge => "knowledge",
            Self::Automation => "automation",
            Self::Community => "community",
            Self::Security => "security",
            Self::Media => "media",
            Self::Vectordb => "vectordb",
            Self::Iot => "iot",
            Self::Other => "other",
        }
    }
}

// ── Per-area checklists ─────────────────────────────────────────────────

/// Checklist results for each readiness area.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadinessAreas {
    pub summary: SummaryReadiness,
    pub operations: OperationsReadiness,
    pub config: ConfigReadiness,
    pub lifecycle: LifecycleReadiness,
}

/// Host-visible connector summary contract.
///
/// Mandatory fields that the host must expose for `fwc list` and `fwc show`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SummaryReadiness {
    /// Connector has a canonical id in `name:archetype:version` format.
    pub has_canonical_id: bool,
    /// Connector has a human-readable display name.
    pub has_display_name: bool,
    /// Connector declares at least one archetype (request-response, streaming, etc.).
    pub has_archetypes: bool,
    /// Version follows semver.
    pub has_semver_version: bool,
    /// Connector has a non-empty description.
    pub has_description: bool,
    /// Operation count is available from introspection.
    pub has_operation_count: bool,
    /// Capability/risk summary is derivable from operations.
    pub has_risk_summary: bool,
}

/// Operation metadata contract.
///
/// Every operation must declare these fields for `fwc ops`, `fwc schema`,
/// and `fwc invoke` to work correctly.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct OperationsReadiness {
    /// Total number of operations declared.
    pub operation_count: usize,
    /// All operations have a non-empty `id`.
    pub all_have_id: bool,
    /// All operations have a non-empty `summary`.
    pub all_have_summary: bool,
    /// All operations have an `input_schema` (JSON Schema).
    pub all_have_input_schema: bool,
    /// All operations have an `output_schema` (JSON Schema).
    pub all_have_output_schema: bool,
    /// All operations declare a `capability` requirement.
    pub all_have_capability: bool,
    /// All operations declare a `risk_level`.
    pub all_have_risk_level: bool,
    /// All operations declare a `safety_tier`.
    pub all_have_safety_tier: bool,
    /// All operations declare an `idempotency` class.
    pub all_have_idempotency: bool,
    /// All operations include `ai_hints` with `when_to_use`.
    pub all_have_ai_hints: bool,
    /// Operations that require approval declare `requires_approval`.
    pub approval_declared_where_needed: bool,
    /// Number of operations with complete examples in `ai_hints`.
    pub operations_with_examples: usize,
}

/// Config metadata contract.
///
/// Fields that `fwc config schema`, `fwc config doctor`, and `fwc config set`
/// need to present secure, redaction-aware configuration workflows.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ConfigReadiness {
    /// Connector accepts configuration via `configure()`.
    pub accepts_config: bool,
    /// Config schema is available (can be a JSON Schema or structured value).
    pub has_config_schema: bool,
    /// Secret fields are clearly marked for redaction.
    pub secrets_marked: bool,
    /// Default values are documented for non-secret fields.
    pub defaults_documented: bool,
    /// Self-check (`self_check()`) is implemented and returns actionable reports.
    pub has_self_check: bool,
}

/// Lifecycle and state metadata contract.
///
/// Fields for `fwc status`, `fwc enable/disable`, and `fwc start/stop`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct LifecycleReadiness {
    /// Health endpoint (`health()`) returns meaningful state.
    pub has_health: bool,
    /// Connector reports `configured` and `handshaken` state.
    pub reports_lifecycle_state: bool,
    /// Streaming/event support is declared when applicable.
    pub events_declared: bool,
    /// Rate limit declarations are present.
    pub has_rate_limits: bool,
    /// Metrics (`metrics()`) return populated data.
    pub has_metrics: bool,
    /// Shutdown is implemented for clean teardown.
    pub has_shutdown: bool,
}

// ── Gap categories ──────────────────────────────────────────────────────

/// A specific readiness gap with remediation guidance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadinessGap {
    /// Gap category for grouping.
    pub category: GapCategory,
    /// Human-readable description of what is missing.
    pub description: String,
    /// Severity: does this block fwc usage or just degrade it?
    pub severity: GapSeverity,
    /// Suggested remediation action.
    pub remediation: String,
}

/// Categories of readiness gaps.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GapCategory {
    /// Missing or malformed connector identity metadata.
    Identity,
    /// Missing operation metadata (schema, hints, safety).
    OperationMetadata,
    /// Missing or incomplete config schema.
    ConfigSchema,
    /// Missing health/lifecycle/metrics implementation.
    Lifecycle,
    /// Missing examples or agent hints.
    AgentHints,
    /// Missing event/stream declarations.
    EventSupport,
    /// Missing rate limit declarations.
    RateLimits,
    /// Missing approval mode declarations.
    ApprovalPolicy,
}

/// How severely a gap affects fwc usability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GapSeverity {
    /// fwc cannot present this connector at all.
    Blocking,
    /// fwc works but output is degraded or incomplete.
    Degraded,
    /// fwc works fully but polish/hints are missing.
    Cosmetic,
}

// ── Host RPC contract ───────────────────────────────────────────────────

/// Canonical payload shape for `fwc list` (discovery summary).
///
/// The host must be able to produce this for every registered connector.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorSummary {
    /// Canonical connector id.
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Semver version string.
    pub version: String,
    /// Short description.
    pub description: String,
    /// Connector archetypes with explicit metadata state.
    pub archetypes: MetadataField<Vec<String>>,
    /// Current lifecycle state.
    pub state: ConnectorState,
    /// Number of declared operations.
    pub operation_count: usize,
    /// Highest risk level across all operations.
    pub max_risk: String,
    /// Whether the connector supports events/streaming.
    pub has_events: bool,
}

/// Lifecycle state as reported by the host.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectorState {
    /// Host/runtime state has not been queried yet.
    Unknown,
    /// Not yet configured.
    Unconfigured,
    /// Configured but not handshaken.
    Configured,
    /// Fully operational.
    Ready,
    /// Running but with degraded functionality.
    Degraded,
    /// Explicitly disabled by operator.
    Disabled,
    /// Error state requiring intervention.
    Error,
}

/// Canonical payload shape for `fwc show <connector>`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectorDetail {
    /// Summary fields.
    pub summary: ConnectorSummary,
    /// Per-operation metadata.
    pub operations: Vec<OperationSummary>,
    /// Config schema (redacted: secrets replaced with `"***"`).
    pub config_schema: MetadataField<Value>,
    /// Current health snapshot.
    pub health: MetadataField<HealthSummary>,
    /// Rate limit declarations with explicit metadata state.
    pub rate_limits: MetadataField<Vec<RateLimitSummary>>,
}

/// Compact operation summary for `fwc ops`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationSummary {
    /// Operation id (e.g. `"issues.create"`).
    pub id: String,
    /// One-line summary.
    pub summary: String,
    /// Required capability.
    pub capability: String,
    /// Risk level: low, medium, high, critical.
    pub risk_level: String,
    /// Safety tier: safe, risky, dangerous, critical, forbidden.
    pub safety_tier: String,
    /// Idempotency class: none, best-effort, strict.
    pub idempotency: String,
    /// Whether approval is required.
    pub requires_approval: bool,
    /// Whether simulate is supported.
    pub supports_simulate: bool,
}

/// Health summary for display.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealthSummary {
    /// Current state: starting, ready, degraded, error, stopping.
    pub state: String,
    /// Uptime in human-readable form.
    pub uptime: String,
    /// Optional load factor (0.0 to 1.0).
    pub load: Option<f32>,
}

/// Rate limit summary for display.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitSummary {
    /// What this limit applies to (e.g. operation id or "global").
    pub scope: String,
    /// Requests per window.
    pub requests: u32,
    /// Window duration (e.g. "60s").
    pub window: String,
}

// ── Manifest-backed discovery catalog ──────────────────────────────────

#[derive(Clone, Debug)]
pub struct DiscoveryCatalog {
    connectors: Vec<DiscoveredConnector>,
}

impl DiscoveryCatalog {
    /// Load the current workspace connector catalog from `connectors/*/manifest.toml`.
    ///
    /// This stays honest about runtime state: discovery is manifest-backed until
    /// host-backed lifecycle/status surfaces land in later beads.
    pub fn load() -> Result<Self> {
        let connectors_dir = workspace_root().join("connectors");
        let mut connectors = Vec::new();

        for entry in fs::read_dir(&connectors_dir)
            .with_context(|| format!("failed to read {}", connectors_dir.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_dir() {
                continue;
            }

            let slug = entry.file_name().to_string_lossy().into_owned();
            let manifest_path = entry.path().join("manifest.toml");
            if !manifest_path.is_file() {
                continue;
            }

            if let Ok(connector) = DiscoveredConnector::from_manifest(&slug, &manifest_path) {
                connectors.push(connector);
            }
        }

        connectors.sort_by(|left, right| left.slug.cmp(&right.slug));
        Ok(Self { connectors })
    }

    #[must_use]
    pub fn connectors(&self) -> &[DiscoveredConnector] {
        &self.connectors
    }

    #[must_use]
    pub fn list(&self, zone: Option<&str>, category: Option<&str>) -> Vec<&DiscoveredConnector> {
        let zone = zone.map(normalize_zone_selector);
        let category = category.map(normalize_category_selector);

        self.connectors
            .iter()
            .filter(|connector| {
                zone.as_ref()
                    .is_none_or(|requested| connector.matches_zone(requested))
                    && category
                        .as_ref()
                        .is_none_or(|requested| connector.matches_category(requested))
            })
            .collect()
    }

    pub fn resolve_connector(&self, selector: &str) -> Result<&DiscoveredConnector, SelectorError> {
        let normalized = normalize_connector_selector(selector);
        let exact = self
            .connectors
            .iter()
            .filter(|connector| connector.matches_selector(&normalized))
            .collect::<Vec<_>>();

        if exact.len() == 1 {
            return Ok(exact[0]);
        }
        if exact.len() > 1 {
            return Err(SelectorError::ambiguous(
                selector,
                exact
                    .iter()
                    .map(|connector| connector.slug.clone())
                    .collect(),
            ));
        }

        let prefix = self
            .connectors
            .iter()
            .filter(|connector| connector.matches_prefix(&normalized))
            .collect::<Vec<_>>();

        match prefix.as_slice() {
            [connector] => Ok(*connector),
            [] => Err(SelectorError::not_found(
                selector,
                suggest_connector_slugs(&self.connectors, &normalized),
            )),
            _ => Err(SelectorError::ambiguous(
                selector,
                prefix
                    .iter()
                    .map(|connector| connector.slug.clone())
                    .take(5)
                    .collect(),
            )),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveredConnector {
    pub slug: String,
    pub manifest_path: String,
    pub cohort: String,
    pub runtime_format: String,
    pub state_model: MetadataField<String>,
    pub supported_zones: Vec<String>,
    pub detail: ConnectorDetail,
    pub zones: Value,
    pub capabilities: Value,
    pub connector_schema: Value,
    pub operations: Vec<DiscoveredOperation>,
}

impl DiscoveredConnector {
    #[allow(clippy::too_many_lines)]
    fn from_manifest(slug: &str, manifest_path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(manifest_path)
            .with_context(|| format!("failed to read {}", manifest_path.display()))?;
        // Discovery should tolerate stale interface hashes and a narrow set of
        // legacy manifest shapes so the CLI can still surface real connector
        // metadata instead of silently dropping connectors from offline catalog
        // views.
        let manifest = match parse_manifest_for_discovery(&raw, manifest_path) {
            Ok(manifest) => manifest,
            Err(parse_error) => {
                let document: toml::Value = toml::from_str(&raw).with_context(|| {
                    format!(
                        "failed to parse {} as TOML for discovery fallback",
                        manifest_path.display()
                    )
                })?;
                return discovered_connector_from_toml(
                    slug,
                    manifest_path,
                    &document,
                    &parse_error.to_string(),
                );
            }
        };

        let inventory_entry = CONNECTOR_INVENTORY.iter().find(|entry| entry.name == slug);
        let cohort = inventory_entry.map_or_else(
            || ConnectorCohort::Other.as_str().to_owned(),
            |entry| entry.cohort.as_str().to_owned(),
        );

        let namespace = manifest
            .connector
            .id
            .as_str()
            .strip_prefix("fcp.")
            .unwrap_or_else(|| manifest.connector.id.as_str())
            .to_owned();
        let runtime_format = runtime_format_label(manifest.connector.format).to_owned();
        let state_model = manifest
            .connector
            .state
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?
            .and_then(|json| {
                json.get("model")
                    .and_then(Value::as_str)
                    .map(std::borrow::ToOwned::to_owned)
            });
        let state_model_json = state_model.clone();

        let mut operations = manifest
            .provides
            .operations
            .iter()
            .map(|(operation_id, operation)| {
                DiscoveredOperation::from_manifest(
                    &namespace,
                    operation_id,
                    operation,
                    manifest.rate_limits.as_ref(),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        operations.sort_by(|left, right| left.preferred_selector.cmp(&right.preferred_selector));

        let max_risk = operations
            .iter()
            .map(|operation| operation.summary.risk_level.as_str())
            .max_by_key(|risk| risk_rank(risk))
            .unwrap_or("low")
            .to_owned();
        let has_events = manifest
            .event_caps
            .as_ref()
            .is_some_and(|caps| caps.streaming || caps.replay)
            || !manifest.provides.events.is_empty();
        let supported_zones = manifest
            .zones
            .allowed_sources
            .iter()
            .chain(manifest.zones.allowed_targets.iter())
            .chain(std::iter::once(&manifest.zones.home))
            .map(|zone| zone.as_str().to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let connector_rate_limits = manifest
            .rate_limits
            .as_ref()
            .map(|rate_limits| {
                rate_limits
                    .pools
                    .iter()
                    .map(|pool| RateLimitSummary {
                        scope: pool.id.clone(),
                        requests: pool.requests,
                        window: human_window_ms(pool.window_ms),
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let connector_id = manifest.connector.id.as_str().to_owned();
        let connector_name = manifest.connector.name.clone();
        let connector_version = manifest.connector.version.to_string();
        let connector_description = manifest.connector.description.clone();
        let archetypes = manifest
            .connector
            .archetypes
            .iter()
            .map(|archetype| archetype.as_str().to_owned())
            .collect::<Vec<_>>();
        let summary = ConnectorSummary {
            id: connector_id.clone(),
            name: connector_name.clone(),
            version: connector_version.clone(),
            description: connector_description.clone(),
            archetypes: MetadataField::Known(archetypes.clone()),
            state: ConnectorState::Unknown,
            operation_count: operations.len(),
            max_risk,
            has_events,
        };
        let operation_summaries = operations
            .iter()
            .map(|operation| operation.summary.clone())
            .collect();
        let zones = serde_json::to_value(&manifest.zones)?;
        let capabilities = serde_json::to_value(&manifest.capabilities)?;
        let event_caps = manifest
            .event_caps
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let sandbox = serde_json::to_value(&manifest.sandbox)?;
        let rate_limits = manifest
            .rate_limits
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let connector_schema = serde_json::json!({
            "connector": {
                "id": &connector_id,
                "name": &connector_name,
                "version": &connector_version,
                "description": &connector_description,
                "archetypes": archetypes,
                "format": &runtime_format,
                "state_model": state_model_json,
            },
            "zones": zones,
            "capabilities": capabilities,
            "events": {
                "event_caps": event_caps,
                "declared_topics": manifest.provides.events.keys().cloned().collect::<Vec<_>>(),
            },
            "sandbox": sandbox,
            "rate_limits": rate_limits,
            "operations": operations
                .iter()
                .map(|operation| serde_json::json!({
                    "selector": &operation.preferred_selector,
                    "canonical_id": &operation.actual_id,
                    "aliases": operation.aliases.clone(),
                }))
                .collect::<Vec<_>>(),
            "note": "This connector-level schema comes from the manifest. Config schema remains under `fwc config schema` once host-backed config introspection is wired.",
        });

        Ok(Self {
            slug: slug.to_owned(),
            manifest_path: relative_to_workspace(manifest_path),
            cohort,
            runtime_format,
            state_model: MetadataField::from_option(state_model),
            supported_zones,
            detail: ConnectorDetail {
                summary,
                operations: operation_summaries,
                config_schema: MetadataField::Unknown,
                health: MetadataField::Unknown,
                rate_limits: MetadataField::Known(connector_rate_limits),
            },
            zones,
            capabilities,
            connector_schema,
            operations,
        })
    }

    #[must_use]
    pub fn shared_descriptor(&self) -> ConnectorDescriptor {
        let auth = AuthDescriptor::unverifiable(
            "Auth capabilities are not surfaced by workspace-manifest discovery yet.",
        )
        .with_check(
            DescriptorCheck::new(
                "auth.discovery",
                DescriptorStatus::Unverifiable,
                "Use host-backed introspection to inspect active auth methods, profiles, and health.",
            )
            .with_remediation("Expose auth capabilities and active auth state through the host discovery contract."),
        )
        .with_check(DescriptorCheck::new(
            "auth.active_state",
            DescriptorStatus::NotYetMeasured,
            "The connector's active auth configuration has not been measured yet.",
        ));

        let prerequisites = PrerequisiteCatalog::unverifiable(
            "Provisioning prerequisites are not surfaced by workspace-manifest discovery yet.",
        );

        let readiness = ReadinessDescriptor::unverifiable(
            "Workspace-manifest discovery confirms static connector metadata, but runtime and setup state still require host-backed evidence.",
        )
        .with_check(DescriptorCheck::new(
            "manifest.metadata",
            DescriptorStatus::Ready,
            "Connector identity and operation catalog loaded from manifest metadata.",
        ))
        .with_check(DescriptorCheck::new(
            "runtime.state",
            DescriptorStatus::NotYetMeasured,
            "Runtime lifecycle and health have not been measured yet by the host.",
        ))
        .with_check(if self.detail.config_schema.is_known() {
            DescriptorCheck::new(
                "config.schema",
                DescriptorStatus::Ready,
                "Config schema is available for this connector.",
            )
        } else {
            DescriptorCheck::new(
                "config.schema",
                DescriptorStatus::Unverifiable,
                "Config schema is not available from manifest-backed discovery.",
            )
            .with_remediation(
                "Expose redaction-aware config schema through host-backed config introspection.",
            )
        })
        .with_check(DescriptorCheck::new(
            "setup.prerequisites",
            DescriptorStatus::NotYetMeasured,
            "Service-side onboarding and prerequisite drift have not been measured yet.",
        ));

        let mut descriptor = ConnectorDescriptor::new(self.detail.summary.id.clone());
        descriptor.display_name = Some(self.detail.summary.name.clone());
        descriptor.version = Some(self.detail.summary.version.clone());
        descriptor.description = Some(self.detail.summary.description.clone());
        descriptor.archetypes = self.detail.summary.archetypes.as_known().cloned();
        descriptor.supported_zones = Some(self.supported_zones.clone());
        descriptor.runtime_format = Some(self.runtime_format.clone());
        descriptor.state_model = self.state_model.as_known().cloned();
        descriptor.operations = self
            .operations
            .iter()
            .map(DiscoveredOperation::operation_info)
            .collect();
        descriptor.auth = Some(auth);
        descriptor.prerequisites = Some(prerequisites);
        descriptor.readiness = Some(readiness);
        descriptor
    }

    #[must_use]
    pub fn matches_zone(&self, zone: &str) -> bool {
        self.supported_zones
            .iter()
            .any(|candidate| candidate == zone)
    }

    #[must_use]
    pub fn matches_category(&self, category: &str) -> bool {
        self.cohort == category
            || self
                .detail
                .summary
                .archetypes
                .as_known()
                .into_iter()
                .flatten()
                .map(|archetype| normalize_category_selector(archetype))
                .any(|archetype| archetype == category)
    }

    pub fn resolve_operation(&self, selector: &str) -> Result<&DiscoveredOperation, SelectorError> {
        let normalized = normalize_operation_selector(selector);
        let exact = self
            .operations
            .iter()
            .filter(|operation| operation.matches_selector(&normalized))
            .collect::<Vec<_>>();

        if exact.len() == 1 {
            return Ok(exact[0]);
        }
        if exact.len() > 1 {
            return Err(SelectorError::ambiguous(
                selector,
                exact
                    .iter()
                    .map(|operation| operation.preferred_selector.clone())
                    .collect(),
            ));
        }

        let prefix = self
            .operations
            .iter()
            .filter(|operation| operation.matches_prefix(&normalized))
            .collect::<Vec<_>>();

        match prefix.as_slice() {
            [operation] => Ok(*operation),
            [] => Err(SelectorError::not_found(
                selector,
                suggest_operation_selectors(&self.operations, &normalized),
            )),
            _ => Err(SelectorError::ambiguous(
                selector,
                prefix
                    .iter()
                    .map(|operation| operation.preferred_selector.clone())
                    .take(5)
                    .collect(),
            )),
        }
    }

    fn matches_selector(&self, selector: &str) -> bool {
        self.selector_keys()
            .into_iter()
            .any(|candidate| candidate == selector)
    }

    fn matches_prefix(&self, selector: &str) -> bool {
        self.selector_keys()
            .into_iter()
            .any(|candidate| candidate.starts_with(selector))
    }

    fn selector_keys(&self) -> Vec<String> {
        let canonical = self.detail.summary.id.to_lowercase();
        let stripped = canonical
            .strip_prefix("fcp.")
            .unwrap_or(canonical.as_str())
            .to_owned();
        let normalized_name = normalize_connector_selector(&self.detail.summary.name);
        let compact_name = normalized_name.replace("-connector", "");

        [
            self.slug.to_lowercase(),
            canonical,
            stripped,
            normalized_name,
            compact_name,
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
    }
}

fn parse_manifest_for_discovery(raw: &str, manifest_path: &Path) -> Result<ConnectorManifest> {
    match ConnectorManifest::parse_str_unchecked(raw) {
        Ok(manifest) => Ok(manifest),
        Err(primary_error) => {
            let Some(normalized) = normalize_manifest_for_discovery(raw)? else {
                return Err(anyhow::Error::new(primary_error))
                    .with_context(|| format!("failed to parse {}", manifest_path.display()));
            };

            normalized.try_into().map_err(anyhow::Error::new).with_context(|| {
                format!(
                    "failed to parse {} after discovery compatibility normalization (original error: {primary_error})",
                    manifest_path.display()
                )
            })
        }
    }
}

fn normalize_manifest_for_discovery(raw: &str) -> Result<Option<toml::Value>> {
    let mut document: toml::Value =
        toml::from_str(raw).context("failed to parse manifest TOML for discovery normalization")?;
    let mut changed = false;

    if let Some(provides) = document
        .get_mut("provides")
        .and_then(toml::Value::as_table_mut)
        && provides.remove("streaming").is_some()
    {
        changed = true;
    }

    if let Some(operations) = document
        .get_mut("provides")
        .and_then(toml::Value::as_table_mut)
        .and_then(|provides| provides.get_mut("operations"))
        .and_then(toml::Value::as_table_mut)
    {
        for (_, operation) in operations.iter_mut() {
            if let Some(operation_table) = operation.as_table_mut() {
                if operation_table.remove("network").is_some() {
                    changed = true;
                }
            }
        }
    }

    if changed {
        Ok(Some(document))
    } else {
        Ok(None)
    }
}

#[derive(Clone, Debug)]
pub struct DiscoveredOperation {
    pub actual_id: String,
    pub local_id: String,
    pub preferred_selector: String,
    pub aliases: Vec<String>,
    pub description: String,
    pub summary: OperationSummary,
    pub input_schema: Value,
    pub output_schema: Value,
    pub approval_mode: String,
    pub when_to_use: String,
    pub common_mistakes: Vec<String>,
    pub examples: Vec<String>,
    pub related: Vec<String>,
    pub network_constraints: Option<Value>,
    pub rate_limits: Option<Vec<RateLimitSummary>>,
}

impl DiscoveredOperation {
    fn from_manifest(
        namespace: &str,
        operation_id: &str,
        operation: &fcp_manifest::OperationSection,
        rate_limits: Option<&fcp_manifest::RateLimitsSection>,
    ) -> Result<Self> {
        let local_id = operation_id
            .strip_prefix(&format!("{namespace}."))
            .unwrap_or(operation_id)
            .to_owned();
        let preferred_selector = preferred_operation_selector(&local_id);
        let aliases = operation_aliases(namespace, operation_id, &local_id);
        let rate_limits = summarize_operation_rate_limits(operation_id, operation, rate_limits);

        Ok(Self {
            actual_id: operation_id.to_owned(),
            local_id,
            preferred_selector,
            aliases,
            description: operation.description.clone(),
            summary: OperationSummary {
                id: operation_id.to_owned(),
                summary: operation.description.clone(),
                capability: operation.capability.as_str().to_owned(),
                risk_level: risk_level_label(operation.risk_level).to_owned(),
                safety_tier: safety_tier_label(operation.safety_tier).to_owned(),
                idempotency: idempotency_label(operation.idempotency).to_owned(),
                requires_approval: !matches!(
                    operation.requires_approval,
                    ManifestApprovalMode::None
                ),
                // Offline manifest metadata cannot prove host-backed simulate support.
                supports_simulate: false,
            },
            input_schema: operation.input_schema.clone(),
            output_schema: operation.output_schema.clone(),
            approval_mode: approval_mode_label(operation.requires_approval).to_owned(),
            when_to_use: operation.ai_hints.when_to_use.clone(),
            common_mistakes: operation.ai_hints.common_mistakes.clone(),
            examples: operation.ai_hints.examples.clone(),
            related: operation
                .ai_hints
                .related
                .iter()
                .map(|related| related.as_str().to_owned())
                .collect(),
            network_constraints: operation
                .network_constraints
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
            rate_limits: Some(rate_limits),
        })
    }

    fn matches_selector(&self, selector: &str) -> bool {
        self.selector_keys()
            .into_iter()
            .any(|candidate| candidate == selector)
    }

    fn matches_prefix(&self, selector: &str) -> bool {
        self.selector_keys()
            .into_iter()
            .any(|candidate| candidate.starts_with(selector))
    }

    #[must_use]
    pub fn operation_info(&self) -> OperationInfo {
        OperationInfo {
            id: OperationId::new(self.actual_id.clone())
                .expect("discovery catalog should only surface canonical operation ids"),
            summary: self.summary.summary.clone(),
            description: Some(self.description.clone())
                .filter(|description| !description.is_empty()),
            input_schema: self.input_schema.clone(),
            output_schema: self.output_schema.clone(),
            capability: CapabilityId::new(self.summary.capability.clone())
                .expect("discovery catalog should only surface canonical capability ids"),
            risk_level: parse_risk_level(&self.summary.risk_level),
            safety_tier: parse_safety_tier(&self.summary.safety_tier),
            idempotency: parse_idempotency(&self.summary.idempotency),
            ai_hints: AgentHint {
                when_to_use: self.when_to_use.clone(),
                common_mistakes: self.common_mistakes.clone(),
                examples: self.examples.clone(),
                related: self
                    .related
                    .iter()
                    .filter_map(|related| CapabilityId::new(related.clone()).ok())
                    .collect(),
            },
            // Discovery intentionally stores human-facing rate-limit summaries
            // rather than the raw declaration, so the canonical `OperationInfo`
            // path leaves this unset until host-backed introspection lands.
            rate_limit: None,
            requires_approval: parse_approval_mode(&self.approval_mode),
        }
    }

    fn selector_keys(&self) -> Vec<String> {
        self.aliases
            .iter()
            .map(|alias| normalize_operation_selector(alias))
            .chain([
                normalize_operation_selector(&self.actual_id),
                normalize_operation_selector(&self.local_id),
                normalize_operation_selector(&self.preferred_selector),
            ])
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

fn discovered_connector_from_toml(
    slug: &str,
    manifest_path: &Path,
    document: &toml::Value,
    parse_warning: &str,
) -> Result<DiscoveredConnector> {
    let inventory_entry = CONNECTOR_INVENTORY.iter().find(|entry| entry.name == slug);
    let cohort = inventory_entry.map_or_else(
        || ConnectorCohort::Other.as_str().to_owned(),
        |entry| entry.cohort.as_str().to_owned(),
    );

    let connector = document
        .get("connector")
        .and_then(toml::Value::as_table)
        .with_context(|| format!("{} is missing [connector]", manifest_path.display()))?;
    let connector_id = required_toml_str(connector, "id", manifest_path)?;
    let connector_name = required_toml_str(connector, "name", manifest_path)?;
    let connector_version = required_toml_str(connector, "version", manifest_path)?;
    let connector_description = required_toml_str(connector, "description", manifest_path)?;
    let runtime_format = connector
        .get("format")
        .and_then(toml::Value::as_str)
        .unwrap_or("wasi")
        .to_owned();
    let state_model = connector
        .get("state")
        .and_then(toml::Value::as_table)
        .and_then(|state| state.get("model"))
        .and_then(toml::Value::as_str)
        .map(std::borrow::ToOwned::to_owned);
    let archetypes = normalize_archetype_labels_from_toml(
        connector
            .get("archetypes")
            .and_then(toml::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    );

    let namespace = connector_id
        .strip_prefix("fcp.")
        .unwrap_or(connector_id.as_str())
        .to_owned();
    let operations_table = document
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .with_context(|| {
            format!(
                "{} is missing [provides.operations]",
                manifest_path.display()
            )
        })?;
    let mut operations = operations_table
        .iter()
        .map(|(operation_id, operation)| {
            discovered_operation_from_toml(&namespace, operation_id, operation, manifest_path)
        })
        .collect::<Result<Vec<_>>>()?;
    operations.sort_by(|left, right| left.preferred_selector.cmp(&right.preferred_selector));

    let max_risk = operations
        .iter()
        .map(|operation| operation.summary.risk_level.as_str())
        .max_by_key(|risk| risk_rank(risk))
        .unwrap_or("low")
        .to_owned();
    let declared_topics = document
        .get("provides")
        .and_then(|provides| provides.get("events"))
        .and_then(toml::Value::as_table)
        .map(|events| events.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    let has_events = !declared_topics.is_empty()
        || document
            .get("event_caps")
            .and_then(|caps| caps.get("streaming"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false)
        || document
            .get("event_caps")
            .and_then(|caps| caps.get("replay"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
    let supported_zones = extract_supported_zones_from_toml(document.get("zones"));

    let summary = ConnectorSummary {
        id: connector_id.clone(),
        name: connector_name.clone(),
        version: connector_version.clone(),
        description: connector_description.clone(),
        archetypes: MetadataField::Known(archetypes.clone()),
        state: ConnectorState::Unknown,
        operation_count: operations.len(),
        max_risk,
        has_events,
    };
    let operation_summaries = operations
        .iter()
        .map(|operation| operation.summary.clone())
        .collect::<Vec<_>>();
    let zones = document
        .get("zones")
        .map(toml_value_to_json)
        .transpose()?
        .unwrap_or(Value::Null);
    let capabilities = document
        .get("capabilities")
        .map(toml_value_to_json)
        .transpose()?
        .unwrap_or(Value::Null);
    let event_caps = document
        .get("event_caps")
        .map(toml_value_to_json)
        .transpose()?;
    let sandbox = document
        .get("sandbox")
        .map(toml_value_to_json)
        .transpose()?
        .unwrap_or(Value::Null);
    let rate_limits = document
        .get("rate_limits")
        .map(toml_value_to_json)
        .transpose()?;
    let state_model_json = state_model.clone();
    let connector_schema = serde_json::json!({
        "connector": {
            "id": &connector_id,
            "name": &connector_name,
            "version": &connector_version,
            "description": &connector_description,
            "archetypes": archetypes,
            "format": &runtime_format,
            "state_model": state_model_json,
        },
        "zones": zones,
        "capabilities": capabilities,
        "events": {
            "event_caps": event_caps,
            "declared_topics": declared_topics,
        },
        "sandbox": sandbox,
        "rate_limits": rate_limits,
        "operations": operations
            .iter()
            .map(|operation| serde_json::json!({
                "selector": &operation.preferred_selector,
                "canonical_id": &operation.actual_id,
                "aliases": operation.aliases.clone(),
            }))
            .collect::<Vec<_>>(),
        "note": "This connector-level schema comes from raw manifest TOML because strict `fcp-manifest` parsing could not validate the current file shape for discovery.",
        "manifest_parse_warning": parse_warning,
    });

    Ok(DiscoveredConnector {
        slug: slug.to_owned(),
        manifest_path: relative_to_workspace(manifest_path),
        cohort,
        runtime_format,
        state_model: MetadataField::from_option(state_model),
        supported_zones,
        detail: ConnectorDetail {
            summary,
            operations: operation_summaries,
            config_schema: MetadataField::Unknown,
            health: MetadataField::Unknown,
            // Raw TOML fallback cannot prove structured connector-level rate-limit declarations.
            rate_limits: MetadataField::Unknown,
        },
        zones,
        capabilities,
        connector_schema,
        operations,
    })
}

fn discovered_operation_from_toml(
    namespace: &str,
    operation_id: &str,
    operation: &toml::Value,
    manifest_path: &Path,
) -> Result<DiscoveredOperation> {
    let operation = operation.as_table().with_context(|| {
        format!(
            "{} has non-table operation definition for `{operation_id}`",
            manifest_path.display()
        )
    })?;
    let local_id = operation_id
        .strip_prefix(&format!("{namespace}."))
        .unwrap_or(operation_id)
        .to_owned();
    let preferred_selector = preferred_operation_selector(&local_id);
    let aliases = operation_aliases(namespace, operation_id, &local_id);
    let description = required_toml_str(operation, "description", manifest_path)?;
    let capability = required_toml_str(operation, "capability", manifest_path)?;
    let risk_level = operation
        .get("risk_level")
        .and_then(toml::Value::as_str)
        .unwrap_or("low")
        .to_owned();
    let safety_tier = operation
        .get("safety_tier")
        .and_then(toml::Value::as_str)
        .unwrap_or("safe")
        .to_owned();
    let approval_mode = operation
        .get("requires_approval")
        .and_then(toml::Value::as_str)
        .unwrap_or("none")
        .to_owned();
    let idempotency = operation
        .get("idempotency")
        .and_then(toml::Value::as_str)
        .unwrap_or("none")
        .to_owned();
    let input_schema = operation
        .get("input_schema")
        .map(toml_value_to_json)
        .transpose()?
        .unwrap_or_else(|| serde_json::json!({}));
    let output_schema = operation
        .get("output_schema")
        .map(toml_value_to_json)
        .transpose()?
        .unwrap_or_else(|| serde_json::json!({}));
    let ai_hints = operation.get("ai_hints").and_then(toml::Value::as_table);
    let when_to_use = ai_hints
        .and_then(|hints| hints.get("when_to_use"))
        .and_then(toml::Value::as_str)
        .unwrap_or("")
        .to_owned();
    let common_mistakes = ai_hints
        .and_then(|hints| hints.get("common_mistakes"))
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let examples = ai_hints
        .and_then(|hints| hints.get("examples"))
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let related = ai_hints
        .and_then(|hints| hints.get("related"))
        .and_then(toml::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let network_constraints = operation
        .get("network_constraints")
        .or_else(|| operation.get("network"))
        .map(toml_value_to_json)
        .transpose()?;

    Ok(DiscoveredOperation {
        actual_id: operation_id.to_owned(),
        local_id,
        preferred_selector,
        aliases,
        description: description.clone(),
        summary: OperationSummary {
            id: operation_id.to_owned(),
            summary: description,
            capability,
            risk_level,
            safety_tier,
            idempotency,
            requires_approval: !approval_mode.is_empty() && approval_mode != "none",
            // Raw manifest fallback must not invent simulate capability.
            supports_simulate: false,
        },
        input_schema,
        output_schema,
        approval_mode,
        when_to_use,
        common_mistakes,
        examples,
        related,
        network_constraints,
        // Raw TOML fallback cannot prove structured rate-limit declarations.
        rate_limits: None,
    })
}

fn required_toml_str(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
    manifest_path: &Path,
) -> Result<String> {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .with_context(|| format!("{} is missing `{key}`", manifest_path.display()))
}

fn toml_value_to_json(value: &toml::Value) -> Result<Value> {
    serde_json::to_value(value).context("failed to convert TOML value into JSON")
}

fn extract_supported_zones_from_toml(zones: Option<&toml::Value>) -> Vec<String> {
    let Some(zones) = zones.and_then(toml::Value::as_table) else {
        return Vec::new();
    };

    let home = zones
        .get("home")
        .and_then(toml::Value::as_str)
        .map(str::to_owned);
    let allowed_sources = zones
        .get("allowed_sources")
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let allowed_targets = zones
        .get("allowed_targets")
        .and_then(toml::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(toml::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    allowed_sources
        .into_iter()
        .chain(allowed_targets)
        .chain(home)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_archetype_labels_from_toml(labels: Vec<&str>) -> Vec<String> {
    let mut normalized = Vec::new();

    for label in labels {
        let label = label.trim();
        if label.is_empty() {
            continue;
        }
        if normalized.iter().any(|existing| existing == label) {
            continue;
        }
        normalized.push(label.to_owned());
    }

    normalized
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorErrorKind {
    NotFound,
    Ambiguous,
}

#[derive(Clone, Debug)]
pub struct SelectorError {
    pub kind: SelectorErrorKind,
    pub selector: String,
    pub suggestions: Vec<String>,
}

impl SelectorError {
    pub(crate) fn not_found(selector: &str, suggestions: Vec<String>) -> Self {
        Self {
            kind: SelectorErrorKind::NotFound,
            selector: selector.to_owned(),
            suggestions,
        }
    }

    pub(crate) fn ambiguous(selector: &str, suggestions: Vec<String>) -> Self {
        Self {
            kind: SelectorErrorKind::Ambiguous,
            selector: selector.to_owned(),
            suggestions,
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("fwc crate should live under crates/fwc")
        .to_path_buf()
}

fn relative_to_workspace(path: &Path) -> String {
    path.strip_prefix(workspace_root())
        .unwrap_or(path)
        .display()
        .to_string()
}

const fn runtime_format_label(format: ConnectorRuntimeFormat) -> &'static str {
    match format {
        ConnectorRuntimeFormat::Native => "native",
        ConnectorRuntimeFormat::Wasi => "wasi",
    }
}

fn parse_risk_level(label: &str) -> RiskLevel {
    match label {
        "low" => RiskLevel::Low,
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        other => panic!("unexpected risk level label from discovery catalog: {other}"),
    }
}

fn parse_safety_tier(label: &str) -> SafetyTier {
    match label {
        "safe" => SafetyTier::Safe,
        "risky" => SafetyTier::Risky,
        "dangerous" => SafetyTier::Dangerous,
        "critical" => SafetyTier::Critical,
        "forbidden" => SafetyTier::Forbidden,
        other => panic!("unexpected safety tier label from discovery catalog: {other}"),
    }
}

fn parse_idempotency(label: &str) -> IdempotencyClass {
    match label {
        "none" => IdempotencyClass::None,
        "best-effort" | "best_effort" => IdempotencyClass::BestEffort,
        "strict" => IdempotencyClass::Strict,
        other => panic!("unexpected idempotency label from discovery catalog: {other}"),
    }
}

fn parse_approval_mode(label: &str) -> Option<ApprovalMode> {
    match label {
        "none" => None,
        "policy" => Some(ApprovalMode::Policy),
        "interactive" => Some(ApprovalMode::Interactive),
        "elevation-token" | "elevation_token" => Some(ApprovalMode::ElevationToken),
        other => panic!("unexpected approval mode label from discovery catalog: {other}"),
    }
}

pub const fn risk_level_label(level: fcp_core::RiskLevel) -> &'static str {
    match level {
        fcp_core::RiskLevel::Low => "low",
        fcp_core::RiskLevel::Medium => "medium",
        fcp_core::RiskLevel::High => "high",
        fcp_core::RiskLevel::Critical => "critical",
    }
}

pub const fn safety_tier_label(tier: fcp_core::SafetyTier) -> &'static str {
    match tier {
        fcp_core::SafetyTier::Safe => "safe",
        fcp_core::SafetyTier::Risky => "risky",
        fcp_core::SafetyTier::Dangerous => "dangerous",
        fcp_core::SafetyTier::Critical => "critical",
        fcp_core::SafetyTier::Forbidden => "forbidden",
    }
}

pub const fn idempotency_label(idempotency: fcp_core::IdempotencyClass) -> &'static str {
    match idempotency {
        fcp_core::IdempotencyClass::None => "none",
        fcp_core::IdempotencyClass::BestEffort => "best-effort",
        fcp_core::IdempotencyClass::Strict => "strict",
    }
}

const fn approval_mode_label(mode: ManifestApprovalMode) -> &'static str {
    match mode {
        ManifestApprovalMode::None => "none",
        ManifestApprovalMode::Policy => "policy",
        ManifestApprovalMode::Interactive => "interactive",
        ManifestApprovalMode::ElevationToken => "elevation-token",
    }
}

fn summarize_operation_rate_limits(
    operation_id: &str,
    operation: &fcp_manifest::OperationSection,
    rate_limits: Option<&fcp_manifest::RateLimitsSection>,
) -> Vec<RateLimitSummary> {
    let mut summaries = Vec::new();

    if let Some(inline) = operation.rate_limit.as_ref() {
        summaries.push(RateLimitSummary {
            scope: "inline".to_owned(),
            requests: inline.as_inner().max,
            window: human_window_ms(inline.as_inner().per_ms),
        });
    }

    if let Some(rate_limits) = rate_limits {
        for pool_id in rate_limits
            .operation_pools
            .get(operation_id)
            .into_iter()
            .flatten()
        {
            if let Some(pool) = rate_limits.pools.iter().find(|pool| pool.id == *pool_id) {
                summaries.push(RateLimitSummary {
                    scope: pool.id.clone(),
                    requests: pool.requests,
                    window: human_window_ms(pool.window_ms),
                });
            }
        }
    }

    summaries
}

fn preferred_operation_selector(local_id: &str) -> String {
    if let Some((verb, object)) = local_id.split_once('_') {
        let plural = pluralize_object(object);
        return format!("{plural}.{verb}");
    }
    local_id.to_owned()
}

fn operation_aliases(namespace: &str, actual_id: &str, local_id: &str) -> Vec<String> {
    let mut aliases = BTreeSet::from([actual_id.to_owned(), local_id.to_owned()]);

    if let Some((verb, object)) = local_id.split_once('_') {
        let singular = object.to_owned();
        let plural = pluralize_object(object);
        for noun in [
            singular.clone(),
            plural.clone(),
            singular.replace('_', "-"),
            plural.replace('_', "-"),
        ] {
            aliases.insert(format!("{noun}.{verb}"));
        }
    }

    aliases.insert(format!("{namespace}.{local_id}"));
    aliases.into_iter().collect()
}

fn pluralize_object(object: &str) -> String {
    if object.ends_with('s') {
        object.to_owned()
    } else {
        format!("{object}s")
    }
}

pub fn normalize_connector_selector(selector: &str) -> String {
    selector
        .trim()
        .to_lowercase()
        .replace(" connector", "")
        .replace([' ', '_'], "-")
}

fn normalize_category_selector(selector: &str) -> String {
    selector.trim().to_lowercase().replace(' ', "-")
}

fn normalize_zone_selector(selector: &str) -> String {
    selector.trim().to_lowercase()
}

pub fn normalize_operation_selector(selector: &str) -> String {
    selector.trim().to_lowercase().replace('-', "_")
}

fn suggest_connector_slugs(connectors: &[DiscoveredConnector], selector: &str) -> Vec<String> {
    let mut candidates = connectors
        .iter()
        .map(|connector| {
            let distance = selector_distance(selector, &connector.slug);
            (connector.slug.clone(), distance)
        })
        .filter(|(slug, distance)| slug.starts_with(selector) || *distance <= 4)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    candidates
        .into_iter()
        .map(|(slug, _)| slug)
        .take(5)
        .collect()
}

fn suggest_operation_selectors(operations: &[DiscoveredOperation], selector: &str) -> Vec<String> {
    let mut candidates = operations
        .iter()
        .map(|operation| {
            let distance = selector_distance(selector, &operation.preferred_selector);
            (operation.preferred_selector.clone(), distance)
        })
        .filter(|(candidate, distance)| candidate.starts_with(selector) || *distance <= 5)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    candidates
        .into_iter()
        .map(|(candidate, _)| candidate)
        .take(5)
        .collect()
}

pub fn selector_distance(left: &str, right: &str) -> usize {
    let right_chars = right.chars().collect::<Vec<_>>();
    let mut costs = (0..=right_chars.len()).collect::<Vec<_>>();

    for (left_index, left_char) in left.chars().enumerate() {
        let mut previous = costs[0];
        costs[0] = left_index + 1;

        for (right_index, right_char) in right_chars.iter().enumerate() {
            let insertion = costs[right_index + 1] + 1;
            let deletion = costs[right_index] + 1;
            let substitution = previous + usize::from(left_char != *right_char);
            previous = costs[right_index + 1];
            costs[right_index + 1] = insertion.min(deletion).min(substitution);
        }
    }

    costs[right_chars.len()]
}

fn human_window_ms(window_ms: u64) -> String {
    match window_ms {
        1_000 => "1s".to_owned(),
        60_000 => "60s".to_owned(),
        3_600_000 => "1h".to_owned(),
        86_400_000 => "1d".to_owned(),
        _ if window_ms % 1_000 == 0 => format!("{}s", window_ms / 1_000),
        _ => format!("{window_ms}ms"),
    }
}

fn risk_rank(level: &str) -> u8 {
    match level {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

// ── Readiness evaluation ────────────────────────────────────────────────

/// Evaluate a connector's introspection output against the readiness contract.
///
/// Takes the raw introspection JSON (as returned by `FcpConnector::introspect()`)
/// and produces a verdict with specific gaps.
#[allow(clippy::too_many_lines)]
pub fn evaluate_introspection(
    connector_id: &str,
    crate_path: &str,
    cohort: ConnectorCohort,
    introspection: &Value,
) -> ReadinessVerdict {
    let ops = introspection["operations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let operation_count = ops.len();

    // Evaluate operation metadata completeness.
    let mut all_have_id = true;
    let mut all_have_summary = true;
    let mut all_have_input_schema = true;
    let mut all_have_output_schema = true;
    let mut all_have_capability = true;
    let mut all_have_risk_level = true;
    let mut all_have_safety_tier = true;
    let mut all_have_idempotency = true;
    let mut all_have_ai_hints = true;
    let mut approval_declared_where_needed = true;
    let mut operations_with_examples = 0usize;

    for op in &ops {
        if op["id"].as_str().unwrap_or_default().is_empty() {
            all_have_id = false;
        }
        if op["summary"].as_str().unwrap_or_default().is_empty() {
            all_have_summary = false;
        }
        if op["input_schema"].is_null() {
            all_have_input_schema = false;
        }
        if op["output_schema"].is_null() {
            all_have_output_schema = false;
        }
        if op["capability"].as_str().unwrap_or_default().is_empty() {
            all_have_capability = false;
        }
        if op["risk_level"].as_str().unwrap_or_default().is_empty() {
            all_have_risk_level = false;
        }
        if op["safety_tier"].as_str().unwrap_or_default().is_empty() {
            all_have_safety_tier = false;
        }
        if op["idempotency"].as_str().unwrap_or_default().is_empty() {
            all_have_idempotency = false;
        }
        let hints = &op["ai_hints"];
        if hints.is_null() || hints["when_to_use"].as_str().unwrap_or_default().is_empty() {
            all_have_ai_hints = false;
        }
        let declares_approval = op
            .get("requires_approval")
            .is_some_and(|value| value.is_boolean() || value.is_string())
            || op
                .get("approval_mode")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.is_empty());
        if !declares_approval {
            approval_declared_where_needed = false;
        }
        if hints["examples"].as_array().is_some_and(|a| !a.is_empty()) {
            operations_with_examples += 1;
        }
    }

    let operations = OperationsReadiness {
        operation_count,
        all_have_id,
        all_have_summary,
        all_have_input_schema,
        all_have_output_schema,
        all_have_capability,
        all_have_risk_level,
        all_have_safety_tier,
        all_have_idempotency,
        all_have_ai_hints,
        approval_declared_where_needed,
        operations_with_examples,
    };

    // Summary readiness: derived from connector_id format and introspection.
    let id_parts: Vec<&str> = connector_id.split(':').collect();
    let has_archetypes = introspection
        .get("archetypes")
        .and_then(Value::as_array)
        .is_some_and(|archetypes| !archetypes.is_empty())
        || introspection
            .get("archetype")
            .and_then(Value::as_str)
            .is_some_and(|archetype| !archetype.is_empty());
    let summary = SummaryReadiness {
        has_canonical_id: id_parts.len() >= 3,
        has_display_name: !connector_id.is_empty(),
        has_archetypes,
        has_semver_version: id_parts.len() >= 3,
        has_description: true, // from manifest
        has_operation_count: operation_count > 0,
        has_risk_summary: all_have_risk_level,
    };

    // Config and lifecycle from introspection are limited; mark as needing
    // host-level verification for a complete assessment.
    let has_auth_caps = !introspection["auth_caps"].is_null();
    let has_rate_limits = introspection
        .get("rate_limits")
        .is_some_and(|rate_limits| !rate_limits.is_null());

    let config = ConfigReadiness {
        accepts_config: true,             // all connectors accept config
        has_config_schema: has_auth_caps, // proxy: auth_caps implies config awareness
        secrets_marked: false,            // requires manifest inspection
        defaults_documented: false,       // requires manifest inspection
        has_self_check: true,             // trait requires it
    };

    let lifecycle = LifecycleReadiness {
        has_health: true,              // trait requires it
        reports_lifecycle_state: true, // BaseConnector provides it
        events_declared: true,         // event declaration is optional; all connectors pass
        has_rate_limits,
        has_metrics: true,  // trait requires metrics()
        has_shutdown: true, // trait requires shutdown()
    };

    let areas = ReadinessAreas {
        summary,
        operations,
        config,
        lifecycle,
    };

    // Collect gaps.
    let mut gaps = Vec::new();

    if operation_count == 0 {
        gaps.push(ReadinessGap {
            category: GapCategory::OperationMetadata,
            description: "No operations declared in introspection".to_owned(),
            severity: GapSeverity::Blocking,
            remediation: "Implement operations_info() returning at least one OperationInfo"
                .to_owned(),
        });
    }
    if !all_have_input_schema {
        gaps.push(ReadinessGap {
            category: GapCategory::OperationMetadata,
            description: "Some operations missing input_schema".to_owned(),
            severity: GapSeverity::Degraded,
            remediation: "Add JSON Schema for input to all operations".to_owned(),
        });
    }
    if !all_have_output_schema {
        gaps.push(ReadinessGap {
            category: GapCategory::OperationMetadata,
            description: "Some operations missing output_schema".to_owned(),
            severity: GapSeverity::Degraded,
            remediation: "Add JSON Schema for output to all operations".to_owned(),
        });
    }
    if !all_have_ai_hints {
        gaps.push(ReadinessGap {
            category: GapCategory::AgentHints,
            description: "Some operations missing ai_hints.when_to_use".to_owned(),
            severity: GapSeverity::Cosmetic,
            remediation: "Add AgentHint with when_to_use to all operations".to_owned(),
        });
    }
    if operations_with_examples < operation_count {
        gaps.push(ReadinessGap {
            category: GapCategory::AgentHints,
            description: format!(
                "Only {operations_with_examples}/{operation_count} operations have examples"
            ),
            severity: GapSeverity::Cosmetic,
            remediation: "Add examples to ai_hints for remaining operations".to_owned(),
        });
    }

    let level = if gaps.iter().any(|g| g.severity == GapSeverity::Blocking) {
        ReadinessLevel::NotReady
    } else if gaps.iter().any(|g| g.severity == GapSeverity::Degraded) {
        ReadinessLevel::PartiallyReady
    } else {
        ReadinessLevel::Ready
    };

    ReadinessVerdict {
        connector_id: connector_id.to_owned(),
        crate_path: crate_path.to_owned(),
        cohort,
        level,
        areas,
        gaps,
    }
}

/// Mandatory fields for the host discovery endpoint per connector.
///
/// These are the fields that `fwc list` absolutely requires.
pub const MANDATORY_SUMMARY_FIELDS: &[&str] = &[
    "id",
    "name",
    "version",
    "description",
    "operation_count",
    "state",
];

/// Mandatory fields per operation for `fwc ops` and `fwc invoke`.
pub const MANDATORY_OPERATION_FIELDS: &[&str] = &[
    "id",
    "summary",
    "capability",
    "risk_level",
    "safety_tier",
    "idempotency",
    "input_schema",
    "output_schema",
];

/// Fields that enhance agent UX but are not strictly required.
pub const RECOMMENDED_OPERATION_FIELDS: &[&str] = &[
    "description",
    "ai_hints",
    "requires_approval",
    "rate_limit",
    "examples",
];

// ── Connector inventory ─────────────────────────────────────────────

/// Metadata quality tier for a connector's operation declarations.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MetadataTier {
    /// Fully typed `OperationInfo` structs with `AgentHint`.
    Typed,
    /// Raw JSON in `operations_info()` without typed `AgentHint`.
    Json,
}

/// Static inventory entry for a single connector.
#[derive(Clone, Debug)]
pub struct ConnectorEntry {
    /// Directory name under `connectors/` (e.g. `"github"`).
    pub name: &'static str,
    /// Primary cohort classification.
    pub cohort: ConnectorCohort,
    /// Number of declared operations.
    pub operation_count: usize,
    /// Whether operations use typed `OperationInfo` with `AgentHint`.
    pub metadata_tier: MetadataTier,
    /// Whether `ai_hints` with `when_to_use` is populated.
    pub has_agent_hints: bool,
    /// Whether `manifest.toml` exists.
    pub has_manifest: bool,
}

/// Complete inventory of all connector crates in the workspace.
///
/// Sorted alphabetically by name. Each entry records the connector's cohort,
/// operation count, metadata quality tier, and manifest presence.
///
/// **Typed** connectors (82): Use `OperationInfo` structs with `AgentHint`
/// objects providing `when_to_use`, `common_mistakes`, `examples`, and
/// `related` fields. These are fully fwc-ready.
///
/// **JSON** connectors (0): All connectors have been migrated to typed metadata.
/// They have `input_schema`, `output_schema`, `risk_level`, `safety_tier`,
/// and `idempotency` but lack typed `AgentHint` metadata. These are
/// partially ready — they work but discovery UX is degraded.
pub static CONNECTOR_INVENTORY: &[ConnectorEntry] = &[
    ConnectorEntry {
        name: "1password",
        cohort: ConnectorCohort::Infra,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "airtable",
        cohort: ConnectorCohort::Workspace,
        operation_count: 16,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "algolia",
        cohort: ConnectorCohort::Data,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "amplitude",
        cohort: ConnectorCohort::Analytics,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "annas-archive",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "anthropic",
        cohort: ConnectorCohort::Ai,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "arxiv",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 13,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "asana",
        cohort: ConnectorCohort::Workspace,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "bigquery",
        cohort: ConnectorCohort::Data,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "bitbucket",
        cohort: ConnectorCohort::DevTools,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "bitwarden",
        cohort: ConnectorCohort::Infra,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "box",
        cohort: ConnectorCohort::Storage,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "browser",
        cohort: ConnectorCohort::Browser,
        operation_count: 16,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "clickup",
        cohort: ConnectorCohort::Workspace,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "cron",
        cohort: ConnectorCohort::Automation,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "datadog",
        cohort: ConnectorCohort::Infra,
        operation_count: 8,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "discord",
        cohort: ConnectorCohort::Messaging,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "docusign",
        cohort: ConnectorCohort::Finance,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "dropbox",
        cohort: ConnectorCohort::Storage,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "duckdb",
        cohort: ConnectorCohort::Data,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "elasticsearch",
        cohort: ConnectorCohort::Data,
        operation_count: 8,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "evernote",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "figma",
        cohort: ConnectorCohort::Workspace,
        operation_count: 17,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "github",
        cohort: ConnectorCohort::DevTools,
        operation_count: 13,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "gitlab",
        cohort: ConnectorCohort::DevTools,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "gmail",
        cohort: ConnectorCohort::Productivity,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "google-ai",
        cohort: ConnectorCohort::Ai,
        operation_count: 8,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "google-calendar",
        cohort: ConnectorCohort::Productivity,
        operation_count: 11,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "grafana",
        cohort: ConnectorCohort::Infra,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "homeassistant",
        cohort: ConnectorCohort::Automation,
        operation_count: 15,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "hubspot",
        cohort: ConnectorCohort::Social,
        operation_count: 11,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "intercom",
        cohort: ConnectorCohort::Social,
        operation_count: 6,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "jira",
        cohort: ConnectorCohort::Workspace,
        operation_count: 12,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "kubernetes",
        cohort: ConnectorCohort::Infra,
        operation_count: 14,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "linear",
        cohort: ConnectorCohort::Workspace,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "linkedin",
        cohort: ConnectorCohort::Social,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "llm-router",
        cohort: ConnectorCohort::Ai,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "logseq",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "mailchimp",
        cohort: ConnectorCohort::Social,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "make",
        cohort: ConnectorCohort::Automation,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "mcp-bridge",
        cohort: ConnectorCohort::Automation,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "metabase",
        cohort: ConnectorCohort::Analytics,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "microsoft365",
        cohort: ConnectorCohort::Productivity,
        operation_count: 30,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "mixpanel",
        cohort: ConnectorCohort::Analytics,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "monday",
        cohort: ConnectorCohort::Workspace,
        operation_count: 7,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "mongodb",
        cohort: ConnectorCohort::Data,
        operation_count: 6,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "n8n",
        cohort: ConnectorCohort::Automation,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "notion",
        cohort: ConnectorCohort::Workspace,
        operation_count: 16,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "openai",
        cohort: ConnectorCohort::Ai,
        operation_count: 23,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "pandadoc",
        cohort: ConnectorCohort::Finance,
        operation_count: 6,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "pinecone",
        cohort: ConnectorCohort::Storage,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "plaid",
        cohort: ConnectorCohort::Finance,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "postgresql",
        cohort: ConnectorCohort::Data,
        operation_count: 12,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: false,
    },
    ConnectorEntry {
        name: "posthog",
        cohort: ConnectorCohort::Analytics,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "pulumi",
        cohort: ConnectorCohort::DevTools,
        operation_count: 6,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "qdrant",
        cohort: ConnectorCohort::Storage,
        operation_count: 12,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "reddit",
        cohort: ConnectorCohort::Community,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "redis",
        cohort: ConnectorCohort::Data,
        operation_count: 14,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: false,
    },
    ConnectorEntry {
        name: "retool",
        cohort: ConnectorCohort::Automation,
        operation_count: 2,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "roam",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "s3",
        cohort: ConnectorCohort::Storage,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "salesforce",
        cohort: ConnectorCohort::Social,
        operation_count: 13,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "segment",
        cohort: ConnectorCohort::Analytics,
        operation_count: 3,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "semanticscholar",
        cohort: ConnectorCohort::Knowledge,
        operation_count: 7,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "sendgrid",
        cohort: ConnectorCohort::Messaging,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "sentry",
        cohort: ConnectorCohort::DevTools,
        operation_count: 16,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "slack",
        cohort: ConnectorCohort::Messaging,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "snowflake",
        cohort: ConnectorCohort::Data,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "spotify",
        cohort: ConnectorCohort::Social,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "stripe",
        cohort: ConnectorCohort::Finance,
        operation_count: 19,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "telegram",
        cohort: ConnectorCohort::Messaging,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "terraform",
        cohort: ConnectorCohort::DevTools,
        operation_count: 12,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "todoist",
        cohort: ConnectorCohort::Workspace,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "trello",
        cohort: ConnectorCohort::Workspace,
        operation_count: 5,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "twilio",
        cohort: ConnectorCohort::Messaging,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "twitter",
        cohort: ConnectorCohort::Social,
        operation_count: 12,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "vectordb",
        cohort: ConnectorCohort::Storage,
        operation_count: 9,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "webhook-receiver",
        cohort: ConnectorCohort::Automation,
        operation_count: 4,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "whisper",
        cohort: ConnectorCohort::Ai,
        operation_count: 8,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: false,
    },
    ConnectorEntry {
        name: "youtube",
        cohort: ConnectorCohort::Productivity,
        operation_count: 11,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "zapier",
        cohort: ConnectorCohort::Automation,
        operation_count: 2,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
    ConnectorEntry {
        name: "zendesk",
        cohort: ConnectorCohort::Social,
        operation_count: 10,
        metadata_tier: MetadataTier::Typed,
        has_agent_hints: true,
        has_manifest: true,
    },
];

/// Generate readiness verdicts for all connectors in the inventory.
///
/// Typed connectors are assessed as **Ready** (all metadata present).
/// JSON connectors are assessed as **Ready** (schemas present) but with
/// cosmetic `AgentHints` gaps since they lack typed `when_to_use` fields.
/// Connectors missing `manifest.toml` receive an additional `Identity` gap.
#[allow(clippy::too_many_lines)]
pub fn audit_all_connectors() -> Vec<ReadinessVerdict> {
    CONNECTOR_INVENTORY
        .iter()
        .map(|entry| {
            let mut gaps = Vec::new();

            // All connectors have schemas in their operations_info(), so they
            // pass the Degraded threshold. The only remaining gaps are Cosmetic.

            if !entry.has_agent_hints {
                gaps.push(ReadinessGap {
                    category: GapCategory::AgentHints,
                    description: "Operations use raw JSON without typed AgentHint (when_to_use, examples, related)".to_string(),
                    severity: GapSeverity::Cosmetic,
                    remediation: format!(
                        "Migrate {}/src/connector.rs operations_info() to typed OperationInfo with AgentHint",
                        entry.name
                    ),
                });
            }

            if !entry.has_manifest {
                gaps.push(ReadinessGap {
                    category: GapCategory::Identity,
                    description: "Missing manifest.toml — network constraints, categories, and archetype metadata unavailable".to_owned(),
                    severity: GapSeverity::Cosmetic,
                    remediation: format!(
                        "Create connectors/{}/manifest.toml with connector metadata",
                        entry.name
                    ),
                });
            }

            let level = if gaps.iter().any(|g| g.severity == GapSeverity::Blocking) {
                ReadinessLevel::NotReady
            } else if gaps.iter().any(|g| g.severity == GapSeverity::Degraded) {
                ReadinessLevel::PartiallyReady
            } else {
                ReadinessLevel::Ready
            };

            ReadinessVerdict {
                connector_id: entry.name.to_owned(),
                crate_path: format!("connectors/{}", entry.name),
                cohort: entry.cohort.clone(),
                level,
                areas: ReadinessAreas {
                    summary: SummaryReadiness {
                        has_canonical_id: true,
                        has_display_name: true,
                        has_archetypes: entry.has_manifest,
                        has_semver_version: true,
                        has_description: true,
                        has_operation_count: entry.operation_count > 0,
                        has_risk_summary: true,
                    },
                    operations: OperationsReadiness {
                        operation_count: entry.operation_count,
                        all_have_id: true,
                        all_have_summary: true,
                        all_have_input_schema: true,
                        all_have_output_schema: true,
                        all_have_capability: true,
                        all_have_risk_level: true,
                        all_have_safety_tier: true,
                        all_have_idempotency: true,
                        all_have_ai_hints: entry.has_agent_hints,
                        approval_declared_where_needed: false,
                        operations_with_examples: if entry.has_agent_hints {
                            entry.operation_count
                        } else {
                            0
                        },
                    },
                    config: ConfigReadiness {
                        accepts_config: true,
                        has_config_schema: true,
                        secrets_marked: entry.has_manifest,
                        defaults_documented: entry.has_manifest,
                        has_self_check: true,
                    },
                    lifecycle: LifecycleReadiness {
                        has_health: true,
                        reports_lifecycle_state: true,
                        events_declared: true,
                        has_rate_limits: false,
                        has_metrics: true,
                        has_shutdown: true,
                    },
                },
                gaps,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// All seven `CommandAvailability` variants for exhaustive testing.
    const ALL_AVAILABILITY: [CommandAvailability; 7] = [
        CommandAvailability::LiveRuntime,
        CommandAvailability::OfflineArtifact,
        CommandAvailability::Unsupported,
        CommandAvailability::Planned,
        CommandAvailability::Unavailable,
        CommandAvailability::Denied,
        CommandAvailability::Unknown,
    ];

    // ── MetadataField ──────────────────────────────────────────────────

    #[test]
    fn metadata_field_known_serializes_with_status_and_value() {
        let field = MetadataField::Known(vec!["request-response".to_owned()]);
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["status"], "known");
        assert_eq!(json["value"][0], "request-response");
    }

    #[test]
    fn metadata_field_unknown_serializes_status_only() {
        let field: MetadataField<String> = MetadataField::Unknown;
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["status"], "unknown");
        assert!(json.get("value").is_none());
    }

    #[test]
    fn metadata_field_unsupported_serializes_status_only() {
        let field: MetadataField<i32> = MetadataField::Unsupported;
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["status"], "unsupported");
        assert!(json.get("value").is_none());
    }

    #[test]
    fn metadata_field_unavailable_serializes_status_only() {
        let field: MetadataField<bool> = MetadataField::Unavailable;
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["status"], "unavailable");
    }

    #[test]
    fn metadata_field_not_applicable_serializes_status_only() {
        let field: MetadataField<String> = MetadataField::NotApplicable;
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["status"], "not-applicable");
    }

    #[test]
    fn metadata_field_known_round_trip() {
        let field = MetadataField::Known(42_u32);
        let json = serde_json::to_string(&field).unwrap();
        let back: MetadataField<u32> = serde_json::from_str(&json).unwrap();
        assert!(back.is_known());
        assert_eq!(*back.as_known().unwrap(), 42);
    }

    #[test]
    fn metadata_field_unknown_round_trip() {
        let field: MetadataField<String> = MetadataField::Unknown;
        let json = serde_json::to_string(&field).unwrap();
        let back: MetadataField<String> = serde_json::from_str(&json).unwrap();
        assert!(!back.is_known());
        assert_eq!(back.status_tag(), "unknown");
    }

    #[test]
    fn metadata_field_unsupported_round_trip() {
        let field: MetadataField<Vec<String>> = MetadataField::Unsupported;
        let json = serde_json::to_string(&field).unwrap();
        let back: MetadataField<Vec<String>> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status_tag(), "unsupported");
    }

    #[test]
    fn metadata_field_unavailable_round_trip() {
        let field: MetadataField<f64> = MetadataField::Unavailable;
        let json = serde_json::to_string(&field).unwrap();
        let back: MetadataField<f64> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status_tag(), "unavailable");
    }

    #[test]
    fn metadata_field_not_applicable_round_trip() {
        let field: MetadataField<bool> = MetadataField::NotApplicable;
        let json = serde_json::to_string(&field).unwrap();
        let back: MetadataField<bool> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status_tag(), "not-applicable");
    }

    #[test]
    fn metadata_field_from_option_some() {
        let field = MetadataField::from_option(Some("hello".to_owned()));
        assert!(field.is_known());
        assert_eq!(field.as_known().unwrap(), "hello");
    }

    #[test]
    fn metadata_field_from_option_none() {
        let field: MetadataField<String> = MetadataField::from_option(None);
        assert!(!field.is_known());
        assert_eq!(field.status_tag(), "unknown");
    }

    #[test]
    fn metadata_field_map_known() {
        let field = MetadataField::Known(42_i32);
        let mapped = field.map(|v| v.to_string());
        assert_eq!(mapped.as_known().unwrap(), "42");
    }

    #[test]
    fn metadata_field_map_unknown_preserves_state() {
        let field: MetadataField<i32> = MetadataField::Unknown;
        let mapped = field.map(|v| v.to_string());
        assert_eq!(mapped.status_tag(), "unknown");
    }

    #[test]
    fn metadata_field_map_unsupported_preserves_state() {
        let field: MetadataField<i32> = MetadataField::Unsupported;
        let mapped = field.map(|v| v.to_string());
        assert_eq!(mapped.status_tag(), "unsupported");
    }

    #[test]
    fn metadata_field_known_with_nested_json_value() {
        let schema = json!({"type": "object", "properties": {"key": {"type": "string"}}});
        let field = MetadataField::Known(schema);
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["status"], "known");
        assert_eq!(json["value"]["type"], "object");
    }

    #[test]
    fn metadata_field_rejects_known_without_value() {
        let bad_json = json!({"status": "known"});
        let result: std::result::Result<MetadataField<String>, _> =
            serde_json::from_value(bad_json);
        assert!(result.is_err());
    }

    #[test]
    fn metadata_field_rejects_unknown_status_string() {
        let bad_json = json!({"status": "banana"});
        let result: std::result::Result<MetadataField<String>, _> =
            serde_json::from_value(bad_json);
        assert!(result.is_err());
    }

    // ── MetadataProvenance ────────────────────────────────────────────

    #[test]
    fn provenance_tag_matches_serde_variant() {
        let cases = [
            (
                MetadataProvenance::DeclaredByConnector,
                "declared-by-connector",
            ),
            (MetadataProvenance::ObservedByHost, "observed-by-host"),
            (MetadataProvenance::MeasuredAtRuntime, "measured-at-runtime"),
            (
                MetadataProvenance::InferredFromPolicy,
                "inferred-from-policy",
            ),
            (MetadataProvenance::Unattributed, "unattributed"),
        ];
        for (variant, expected_tag) in &cases {
            assert_eq!(variant.tag(), *expected_tag, "tag mismatch for {variant:?}");
            let json = serde_json::to_value(variant).unwrap();
            assert_eq!(json.as_str().unwrap(), *expected_tag);
        }
    }

    #[test]
    fn provenance_round_trip_all_variants() {
        let variants = [
            MetadataProvenance::DeclaredByConnector,
            MetadataProvenance::ObservedByHost,
            MetadataProvenance::MeasuredAtRuntime,
            MetadataProvenance::InferredFromPolicy,
            MetadataProvenance::Unattributed,
        ];
        for variant in variants {
            let json = serde_json::to_string(&variant).unwrap();
            let back: MetadataProvenance = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn provenance_authoritative_only_for_host_and_runtime() {
        assert!(!MetadataProvenance::DeclaredByConnector.is_authoritative());
        assert!(MetadataProvenance::ObservedByHost.is_authoritative());
        assert!(MetadataProvenance::MeasuredAtRuntime.is_authoritative());
        assert!(!MetadataProvenance::InferredFromPolicy.is_authoritative());
        assert!(!MetadataProvenance::Unattributed.is_authoritative());
    }

    #[test]
    fn provenance_explanation_non_empty() {
        let variants = [
            MetadataProvenance::DeclaredByConnector,
            MetadataProvenance::ObservedByHost,
            MetadataProvenance::MeasuredAtRuntime,
            MetadataProvenance::InferredFromPolicy,
            MetadataProvenance::Unattributed,
        ];
        for variant in variants {
            assert!(
                !variant.explanation().is_empty(),
                "empty explanation for {variant:?}"
            );
        }
    }

    #[test]
    fn provenance_equality_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(MetadataProvenance::DeclaredByConnector);
        set.insert(MetadataProvenance::ObservedByHost);
        set.insert(MetadataProvenance::DeclaredByConnector); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn provenance_clone() {
        let p = MetadataProvenance::MeasuredAtRuntime;
        let cloned = p;
        assert_eq!(p, cloned);
    }

    // ── ProvenanceMetadataField ───────────────────────────────────────

    #[test]
    fn provenance_field_known_serializes_with_provenance() {
        let field = ProvenanceMetadataField::known(
            vec!["request-response".to_owned()],
            MetadataProvenance::DeclaredByConnector,
        );
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["status"], "known");
        assert_eq!(json["provenance"], "declared-by-connector");
        assert_eq!(json["value"][0], "request-response");
    }

    #[test]
    fn provenance_field_unknown_serializes_without_value() {
        let field: ProvenanceMetadataField<String> =
            ProvenanceMetadataField::unknown(MetadataProvenance::ObservedByHost);
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["status"], "unknown");
        assert_eq!(json["provenance"], "observed-by-host");
        assert!(json.get("value").is_none());
    }

    #[test]
    fn provenance_field_unsupported_with_provenance() {
        let field: ProvenanceMetadataField<i32> =
            ProvenanceMetadataField::unsupported(MetadataProvenance::DeclaredByConnector);
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["status"], "unsupported");
        assert_eq!(json["provenance"], "declared-by-connector");
    }

    #[test]
    fn provenance_field_known_round_trip() {
        let field = ProvenanceMetadataField::known(42_u32, MetadataProvenance::MeasuredAtRuntime);
        let json = serde_json::to_string(&field).unwrap();
        let back: ProvenanceMetadataField<u32> = serde_json::from_str(&json).unwrap();
        assert!(back.is_known());
        assert_eq!(*back.as_known().unwrap(), 42);
        assert_eq!(back.provenance, MetadataProvenance::MeasuredAtRuntime);
    }

    #[test]
    fn provenance_field_unknown_round_trip() {
        let field: ProvenanceMetadataField<String> =
            ProvenanceMetadataField::unknown(MetadataProvenance::InferredFromPolicy);
        let json = serde_json::to_string(&field).unwrap();
        let back: ProvenanceMetadataField<String> = serde_json::from_str(&json).unwrap();
        assert!(!back.is_known());
        assert_eq!(back.field.status_tag(), "unknown");
        assert_eq!(back.provenance, MetadataProvenance::InferredFromPolicy);
    }

    #[test]
    fn provenance_field_unavailable_round_trip() {
        let field = ProvenanceMetadataField::new(
            MetadataField::<f64>::Unavailable,
            MetadataProvenance::ObservedByHost,
        );
        let json = serde_json::to_string(&field).unwrap();
        let back: ProvenanceMetadataField<f64> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.field.status_tag(), "unavailable");
        assert_eq!(back.provenance, MetadataProvenance::ObservedByHost);
    }

    #[test]
    fn provenance_field_not_applicable_round_trip() {
        let field = ProvenanceMetadataField::new(
            MetadataField::<bool>::NotApplicable,
            MetadataProvenance::DeclaredByConnector,
        );
        let json = serde_json::to_string(&field).unwrap();
        let back: ProvenanceMetadataField<bool> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.field.status_tag(), "not-applicable");
        assert_eq!(back.provenance, MetadataProvenance::DeclaredByConnector);
    }

    #[test]
    fn provenance_field_map_preserves_provenance() {
        let field = ProvenanceMetadataField::known(42_i32, MetadataProvenance::MeasuredAtRuntime);
        let mapped = field.map(|v| v.to_string());
        assert_eq!(mapped.as_known().unwrap(), "42");
        assert_eq!(mapped.provenance, MetadataProvenance::MeasuredAtRuntime);
    }

    #[test]
    fn provenance_field_map_unknown_preserves_state_and_provenance() {
        let field: ProvenanceMetadataField<i32> =
            ProvenanceMetadataField::unknown(MetadataProvenance::ObservedByHost);
        let mapped = field.map(|v| v.to_string());
        assert_eq!(mapped.field.status_tag(), "unknown");
        assert_eq!(mapped.provenance, MetadataProvenance::ObservedByHost);
    }

    #[test]
    fn provenance_field_is_authoritative() {
        let host = ProvenanceMetadataField::known(1, MetadataProvenance::ObservedByHost);
        let manifest = ProvenanceMetadataField::known(1, MetadataProvenance::DeclaredByConnector);
        let runtime = ProvenanceMetadataField::known(1, MetadataProvenance::MeasuredAtRuntime);
        let policy = ProvenanceMetadataField::known(1, MetadataProvenance::InferredFromPolicy);
        let unattr = ProvenanceMetadataField::known(1, MetadataProvenance::Unattributed);

        assert!(host.is_authoritative());
        assert!(!manifest.is_authoritative());
        assert!(runtime.is_authoritative());
        assert!(!policy.is_authoritative());
        assert!(!unattr.is_authoritative());
    }

    #[test]
    fn provenance_field_into_field_strips_provenance() {
        let pf = ProvenanceMetadataField::known(99_u32, MetadataProvenance::ObservedByHost);
        let field = pf.into_field();
        assert!(field.is_known());
        assert_eq!(*field.as_known().unwrap(), 99);
    }

    #[test]
    fn provenance_field_from_unattributed() {
        let bare = MetadataField::Known("hello".to_owned());
        let pf = ProvenanceMetadataField::from_unattributed(bare);
        assert!(pf.is_known());
        assert_eq!(pf.provenance, MetadataProvenance::Unattributed);
    }

    #[test]
    fn provenance_field_missing_provenance_defaults_to_unattributed() {
        // Legacy JSON without provenance field
        let legacy = json!({"status": "known", "value": 42});
        let field: ProvenanceMetadataField<i32> = serde_json::from_value(legacy).unwrap();
        assert!(field.is_known());
        assert_eq!(*field.as_known().unwrap(), 42);
        assert_eq!(field.provenance, MetadataProvenance::Unattributed);
    }

    #[test]
    fn provenance_field_rejects_invalid_provenance() {
        let bad = json!({"status": "known", "provenance": "magic", "value": 1});
        let result: std::result::Result<ProvenanceMetadataField<i32>, _> =
            serde_json::from_value(bad);
        assert!(result.is_err());
    }

    #[test]
    fn provenance_field_rejects_known_without_value() {
        let bad = json!({"status": "known", "provenance": "observed-by-host"});
        let result: std::result::Result<ProvenanceMetadataField<String>, _> =
            serde_json::from_value(bad);
        assert!(result.is_err());
    }

    #[test]
    fn provenance_field_rejects_invalid_status() {
        let bad = json!({"status": "banana", "provenance": "unattributed"});
        let result: std::result::Result<ProvenanceMetadataField<String>, _> =
            serde_json::from_value(bad);
        assert!(result.is_err());
    }

    #[test]
    fn provenance_field_nested_json_value() {
        let schema = json!({"type": "object", "properties": {"key": {"type": "string"}}});
        let field = ProvenanceMetadataField::known(schema, MetadataProvenance::DeclaredByConnector);
        let json = serde_json::to_value(&field).unwrap();
        assert_eq!(json["status"], "known");
        assert_eq!(json["provenance"], "declared-by-connector");
        assert_eq!(json["value"]["type"], "object");

        let back: ProvenanceMetadataField<Value> = serde_json::from_value(json).unwrap();
        assert_eq!(back.as_known().unwrap()["type"], "object");
    }

    #[test]
    fn provenance_field_all_status_provenance_combinations() {
        let statuses: Vec<MetadataField<i32>> = vec![
            MetadataField::Known(1),
            MetadataField::Unknown,
            MetadataField::Unsupported,
            MetadataField::Unavailable,
            MetadataField::NotApplicable,
        ];
        let provenances = [
            MetadataProvenance::DeclaredByConnector,
            MetadataProvenance::ObservedByHost,
            MetadataProvenance::MeasuredAtRuntime,
            MetadataProvenance::InferredFromPolicy,
            MetadataProvenance::Unattributed,
        ];
        for status in &statuses {
            for prov in &provenances {
                let pf = ProvenanceMetadataField::new(status.clone(), *prov);
                let json = serde_json::to_string(&pf).unwrap();
                let back: ProvenanceMetadataField<i32> = serde_json::from_str(&json).unwrap();
                assert_eq!(back.field.status_tag(), pf.field.status_tag());
                assert_eq!(back.provenance, *prov);
            }
        }
    }

    // ── CommandAvailability ─────────────────────────────────────────────

    #[test]
    fn availability_tag_matches_serde_variant() {
        let cases = [
            (CommandAvailability::LiveRuntime, "live-runtime"),
            (CommandAvailability::OfflineArtifact, "offline-artifact"),
            (CommandAvailability::Unsupported, "unsupported"),
            (CommandAvailability::Planned, "planned"),
            (CommandAvailability::Unavailable, "unavailable"),
            (CommandAvailability::Denied, "denied"),
            (CommandAvailability::Unknown, "unknown"),
        ];
        for (variant, expected_tag) in &cases {
            assert_eq!(variant.tag(), *expected_tag, "tag mismatch for {variant:?}");
            // Serde round-trip must produce the same tag
            let json = serde_json::to_value(variant).unwrap();
            assert_eq!(json.as_str().unwrap(), *expected_tag);
        }
    }

    #[test]
    fn availability_serde_round_trip_all_variants() {
        let all = [
            CommandAvailability::LiveRuntime,
            CommandAvailability::OfflineArtifact,
            CommandAvailability::Unsupported,
            CommandAvailability::Planned,
            CommandAvailability::Unavailable,
            CommandAvailability::Denied,
            CommandAvailability::Unknown,
        ];
        for variant in &all {
            let json = serde_json::to_string(variant).unwrap();
            let back: CommandAvailability = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, back);
        }
    }

    #[test]
    fn availability_explanation_non_empty() {
        let all = [
            CommandAvailability::LiveRuntime,
            CommandAvailability::OfflineArtifact,
            CommandAvailability::Unsupported,
            CommandAvailability::Planned,
            CommandAvailability::Unavailable,
            CommandAvailability::Denied,
            CommandAvailability::Unknown,
        ];
        for variant in &all {
            assert!(
                !variant.explanation().is_empty(),
                "empty explanation for {variant:?}"
            );
        }
    }

    #[test]
    fn availability_is_recoverable_correct() {
        // Success states are not "recoverable" (they're not errors)
        assert!(!CommandAvailability::LiveRuntime.is_recoverable());
        assert!(!CommandAvailability::OfflineArtifact.is_recoverable());
        // Permanent conditions are not recoverable
        assert!(!CommandAvailability::Unsupported.is_recoverable());
        assert!(!CommandAvailability::Planned.is_recoverable());
        // Transient/actionable states are recoverable
        assert!(CommandAvailability::Unavailable.is_recoverable());
        assert!(CommandAvailability::Denied.is_recoverable());
        assert!(CommandAvailability::Unknown.is_recoverable());
    }

    #[test]
    fn availability_is_authoritative_only_live() {
        assert!(CommandAvailability::LiveRuntime.is_authoritative());
        assert!(!CommandAvailability::OfflineArtifact.is_authoritative());
        assert!(!CommandAvailability::Unsupported.is_authoritative());
        assert!(!CommandAvailability::Planned.is_authoritative());
        assert!(!CommandAvailability::Unavailable.is_authoritative());
        assert!(!CommandAvailability::Denied.is_authoritative());
        assert!(!CommandAvailability::Unknown.is_authoritative());
    }

    #[test]
    fn availability_is_success_live_and_offline() {
        assert!(CommandAvailability::LiveRuntime.is_success());
        assert!(CommandAvailability::OfflineArtifact.is_success());
        assert!(!CommandAvailability::Unsupported.is_success());
        assert!(!CommandAvailability::Planned.is_success());
        assert!(!CommandAvailability::Unavailable.is_success());
        assert!(!CommandAvailability::Denied.is_success());
        assert!(!CommandAvailability::Unknown.is_success());
    }

    #[test]
    fn availability_exit_codes_correct() {
        assert_eq!(CommandAvailability::LiveRuntime.exit_code_u8(), 0);
        assert_eq!(CommandAvailability::OfflineArtifact.exit_code_u8(), 0);
        assert_eq!(CommandAvailability::Unsupported.exit_code_u8(), 5);
        assert_eq!(CommandAvailability::Planned.exit_code_u8(), 0);
        assert_eq!(CommandAvailability::Unavailable.exit_code_u8(), 8);
        assert_eq!(CommandAvailability::Denied.exit_code_u8(), 6);
        assert_eq!(CommandAvailability::Unknown.exit_code_u8(), 8);
    }

    #[test]
    fn availability_next_actions_live_runtime_empty() {
        let actions = CommandAvailability::LiveRuntime.next_actions("show");
        assert!(actions.is_empty());
    }

    #[test]
    fn availability_next_actions_offline_suggests_host() {
        let actions = CommandAvailability::OfflineArtifact.next_actions("list");
        assert!(actions.iter().any(|a| a.contains("--host")));
    }

    #[test]
    fn availability_next_actions_unsupported_suggests_ops() {
        let actions = CommandAvailability::Unsupported.next_actions("invoke");
        assert!(actions.iter().any(|a| a.contains("ops")));
    }

    #[test]
    fn availability_next_actions_unavailable_suggests_retry() {
        let actions = CommandAvailability::Unavailable.next_actions("show");
        assert!(actions.iter().any(|a| a.contains("Retry")));
        assert!(actions.iter().any(|a| a.contains("--offline")));
    }

    #[test]
    fn availability_next_actions_denied_suggests_auth() {
        let actions = CommandAvailability::Denied.next_actions("invoke");
        assert!(actions.iter().any(|a| a.contains("auth")));
    }

    #[test]
    fn availability_next_actions_unknown_suggests_host_flag() {
        let actions = CommandAvailability::Unknown.next_actions("search");
        assert!(actions.iter().any(|a| a.contains("--host")));
    }

    #[test]
    fn availability_next_actions_planned_explains_preview() {
        let actions = CommandAvailability::Planned.next_actions("batch");
        assert!(
            actions
                .iter()
                .any(|a| a.contains("preview") || a.contains("development"))
        );
    }

    #[test]
    fn availability_next_actions_embed_command_name() {
        // Unavailable should embed the actual command name
        let actions = CommandAvailability::Unavailable.next_actions("my-custom-cmd");
        assert!(actions.iter().any(|a| a.contains("my-custom-cmd")));
    }

    // ── CommandEnvelope ────────────────────────────────────────────────

    #[test]
    fn envelope_new_live_runtime() {
        let env = CommandEnvelope::new(CommandAvailability::LiveRuntime, "show");
        assert_eq!(env.availability, CommandAvailability::LiveRuntime);
        assert_eq!(env.command, "show");
        assert!(env.authoritative);
        assert!(!env.recoverable);
        assert!(env.next_actions.is_empty());
    }

    #[test]
    fn envelope_new_offline_artifact() {
        let env = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "list");
        assert!(!env.authoritative);
        assert!(!env.recoverable);
        assert!(!env.next_actions.is_empty());
    }

    #[test]
    fn envelope_new_unavailable() {
        let env = CommandEnvelope::new(CommandAvailability::Unavailable, "invoke");
        assert!(!env.authoritative);
        assert!(env.recoverable);
        assert!(!env.next_actions.is_empty());
    }

    #[test]
    fn envelope_new_denied() {
        let env = CommandEnvelope::new(CommandAvailability::Denied, "simulate");
        assert!(!env.authoritative);
        assert!(env.recoverable);
        assert!(
            env.next_actions
                .iter()
                .any(|a| a.contains("auth") || a.contains("policy"))
        );
    }

    #[test]
    fn envelope_new_unsupported() {
        let env = CommandEnvelope::new(CommandAvailability::Unsupported, "stream");
        assert!(!env.authoritative);
        assert!(!env.recoverable);
        assert!(!env.explanation.is_empty());
    }

    #[test]
    fn envelope_new_planned() {
        let env = CommandEnvelope::new(CommandAvailability::Planned, "batch");
        assert!(!env.authoritative);
        assert!(!env.recoverable);
        assert!(env.explanation.contains("planned"));
    }

    #[test]
    fn envelope_inject_into_adds_availability_key() {
        let env = CommandEnvelope::new(CommandAvailability::LiveRuntime, "show");
        let mut payload = json!({"status": "ok", "data": {}});
        env.inject_into(&mut payload);
        assert!(payload["availability"].is_object());
        assert_eq!(payload["availability"]["availability"], "live-runtime");
        assert_eq!(payload["availability"]["command"], "show");
        assert_eq!(payload["availability"]["authoritative"], true);
    }

    #[test]
    fn envelope_inject_into_unavailable_has_next_actions() {
        let env = CommandEnvelope::new(CommandAvailability::Unavailable, "ops");
        let mut payload = json!({"status": "error"});
        env.inject_into(&mut payload);
        let avail = &payload["availability"];
        assert_eq!(avail["availability"], "unavailable");
        assert!(avail["recoverable"].as_bool().unwrap());
        assert!(avail["next_actions"].as_array().unwrap().len() > 0);
    }

    #[test]
    fn envelope_inject_preserves_existing_payload() {
        let env = CommandEnvelope::new(CommandAvailability::Denied, "invoke");
        let mut payload = json!({
            "status": "error",
            "command": "invoke",
            "error": {"type": "policy-denied", "message": "not allowed"}
        });
        env.inject_into(&mut payload);
        // Original keys preserved
        assert_eq!(payload["status"], "error");
        assert_eq!(payload["error"]["type"], "policy-denied");
        // Availability added
        assert_eq!(payload["availability"]["availability"], "denied");
    }

    #[test]
    fn envelope_inject_noop_on_non_object() {
        let env = CommandEnvelope::new(CommandAvailability::LiveRuntime, "show");
        let mut payload = json!("just a string");
        env.inject_into(&mut payload);
        // Should not panic, payload stays as-is
        assert_eq!(payload, json!("just a string"));
    }

    #[test]
    fn envelope_serializes_complete_json() {
        let env = CommandEnvelope::new(CommandAvailability::Unknown, "schema");
        let json = serde_json::to_value(&env).unwrap();
        assert!(json["availability"].is_string());
        assert!(json["command"].is_string());
        assert!(json["authoritative"].is_boolean());
        assert!(json["explanation"].is_string());
        assert!(json["recoverable"].is_boolean());
        assert!(json["next_actions"].is_array());
    }

    #[test]
    fn all_availability_variants_produce_valid_envelopes() {
        let all = [
            CommandAvailability::LiveRuntime,
            CommandAvailability::OfflineArtifact,
            CommandAvailability::Unsupported,
            CommandAvailability::Planned,
            CommandAvailability::Unavailable,
            CommandAvailability::Denied,
            CommandAvailability::Unknown,
        ];
        for variant in &all {
            let env = CommandEnvelope::new(variant.clone(), "test-cmd");
            let json = serde_json::to_value(&env).unwrap();
            // Every envelope must have these fields
            assert!(
                json["availability"].is_string(),
                "missing availability for {variant:?}"
            );
            assert!(
                json["command"].is_string(),
                "missing command for {variant:?}"
            );
            assert!(
                json["explanation"].is_string(),
                "missing explanation for {variant:?}"
            );
            assert!(
                json["recoverable"].is_boolean(),
                "missing recoverable for {variant:?}"
            );
            assert!(
                json["next_actions"].is_array(),
                "missing next_actions for {variant:?}"
            );
            // Inject should work
            let mut payload = json!({"status": "test"});
            env.inject_into(&mut payload);
            assert!(payload["availability"].is_object());
        }
    }

    #[test]
    fn availability_denied_exit_code_is_policy() {
        // PolicyDenied = 6 in CliExitCode
        assert_eq!(CommandAvailability::Denied.exit_code_u8(), 6);
    }

    #[test]
    fn availability_unavailable_exit_code_is_transport() {
        // Transport = 8 in CliExitCode
        assert_eq!(CommandAvailability::Unavailable.exit_code_u8(), 8);
    }

    #[test]
    fn availability_unsupported_exit_code_is_validation() {
        // Validation = 5 in CliExitCode
        assert_eq!(CommandAvailability::Unsupported.exit_code_u8(), 5);
    }

    #[test]
    fn envelope_command_name_propagates() {
        let commands = ["list", "show", "search", "invoke", "simulate", "batch"];
        for cmd in commands {
            let env = CommandEnvelope::new(CommandAvailability::LiveRuntime, cmd);
            assert_eq!(env.command, cmd);
        }
    }

    #[test]
    fn availability_deserialize_rejects_invalid() {
        let bad: Result<CommandAvailability, _> = serde_json::from_str("\"not-a-state\"");
        assert!(bad.is_err());
    }

    #[test]
    fn availability_deserialize_accepts_all_tags() {
        let tags = [
            "live-runtime",
            "offline-artifact",
            "unsupported",
            "planned",
            "unavailable",
            "denied",
            "unknown",
        ];
        for tag in tags {
            let json = format!("\"{tag}\"");
            let parsed: CommandAvailability = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.tag(), tag);
        }
    }

    // ── ReadinessLevel ──────────────────────────────────────────────────

    #[test]
    fn readiness_level_serde_round_trip() {
        for level in [
            ReadinessLevel::Ready,
            ReadinessLevel::PartiallyReady,
            ReadinessLevel::NotReady,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: ReadinessLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    #[test]
    fn readiness_level_kebab_case_serialization() {
        let json = serde_json::to_string(&ReadinessLevel::PartiallyReady).unwrap();
        assert_eq!(json, "\"partially-ready\"");
    }

    // ── ConnectorCohort ─────────────────────────────────────────────────

    #[test]
    fn cohort_serde_round_trip() {
        for cohort in [
            ConnectorCohort::Messaging,
            ConnectorCohort::Ai,
            ConnectorCohort::DevTools,
            ConnectorCohort::Finance,
        ] {
            let json = serde_json::to_string(&cohort).unwrap();
            let back: ConnectorCohort = serde_json::from_str(&json).unwrap();
            assert_eq!(cohort, back);
        }
    }

    // ── GapSeverity ordering ────────────────────────────────────────────

    #[test]
    fn gap_severity_ordering() {
        assert!(GapSeverity::Blocking < GapSeverity::Degraded);
        assert!(GapSeverity::Degraded < GapSeverity::Cosmetic);
    }

    // ── ConnectorState ──────────────────────────────────────────────────

    #[test]
    fn connector_state_serde() {
        let json = serde_json::to_string(&ConnectorState::Ready).unwrap();
        assert_eq!(json, "\"ready\"");
        let back: ConnectorState = serde_json::from_str("\"degraded\"").unwrap();
        assert_eq!(back, ConnectorState::Degraded);
    }

    // ── evaluate_introspection ──────────────────────────────────────────

    #[test]
    fn fully_ready_connector() {
        let introspection = json!({
            "operations": [
                {
                    "id": "issues.create",
                    "summary": "Create a new issue",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "github.write",
                    "risk_level": "medium",
                    "safety_tier": "risky",
                    "idempotency": "none",
                    "ai_hints": {
                        "when_to_use": "When the user wants to create a GitHub issue",
                        "common_mistakes": [],
                        "examples": ["Create issue titled 'Bug fix'"],
                        "related": []
                    }
                },
                {
                    "id": "issues.list",
                    "summary": "List issues",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "array"},
                    "capability": "github.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "When listing issues in a repository",
                        "common_mistakes": [],
                        "examples": ["List open issues"],
                        "related": []
                    }
                }
            ],
            "events": [],
            "resource_types": []
        });

        let verdict = evaluate_introspection(
            "github:fcp2:1.0",
            "connectors/github",
            ConnectorCohort::DevTools,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::Ready);
        assert!(verdict.gaps.is_empty());
        assert_eq!(verdict.areas.operations.operation_count, 2);
        assert!(verdict.areas.operations.all_have_id);
        assert!(verdict.areas.operations.all_have_summary);
        assert!(verdict.areas.operations.all_have_input_schema);
        assert!(verdict.areas.operations.all_have_capability);
        assert!(verdict.areas.operations.all_have_ai_hints);
        assert_eq!(verdict.areas.operations.operations_with_examples, 2);
    }

    #[test]
    fn connector_with_no_operations_is_not_ready() {
        let introspection = json!({
            "operations": [],
            "events": [],
            "resource_types": []
        });

        let verdict = evaluate_introspection(
            "empty:fcp2:0.1",
            "connectors/empty",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::NotReady);
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.category == GapCategory::OperationMetadata
                    && g.severity == GapSeverity::Blocking)
        );
    }

    #[test]
    fn connector_missing_schemas_is_partially_ready() {
        let introspection = json!({
            "operations": [
                {
                    "id": "send",
                    "summary": "Send a message",
                    "input_schema": null,
                    "output_schema": null,
                    "capability": "slack.write",
                    "risk_level": "medium",
                    "safety_tier": "risky",
                    "idempotency": "none",
                    "ai_hints": {
                        "when_to_use": "Send a Slack message",
                        "examples": ["Send hello to #general"]
                    }
                }
            ],
            "events": []
        });

        let verdict = evaluate_introspection(
            "slack:fcp2:1.0",
            "connectors/slack",
            ConnectorCohort::Messaging,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::PartiallyReady);
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.category == GapCategory::OperationMetadata
                    && g.description.contains("input_schema"))
        );
    }

    #[test]
    fn connector_missing_ai_hints_gets_cosmetic_gap() {
        let introspection = json!({
            "operations": [
                {
                    "id": "query",
                    "summary": "Run a SQL query",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "array"},
                    "capability": "pg.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": null
                }
            ],
            "events": []
        });

        let verdict = evaluate_introspection(
            "postgresql:fcp2:1.0",
            "connectors/postgresql",
            ConnectorCohort::Data,
            &introspection,
        );

        // Missing ai_hints is cosmetic, not blocking.
        assert_eq!(verdict.level, ReadinessLevel::Ready);
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.category == GapCategory::AgentHints
                    && g.severity == GapSeverity::Cosmetic)
        );
    }

    #[test]
    fn verdict_serialization_round_trip() {
        let verdict = ReadinessVerdict {
            connector_id: "test:fcp2:0.1".to_owned(),
            crate_path: "connectors/test".to_owned(),
            cohort: ConnectorCohort::Automation,
            level: ReadinessLevel::PartiallyReady,
            areas: ReadinessAreas {
                summary: SummaryReadiness {
                    has_canonical_id: true,
                    has_display_name: true,
                    has_archetypes: true,
                    has_semver_version: true,
                    has_description: true,
                    has_operation_count: true,
                    has_risk_summary: true,
                },
                operations: OperationsReadiness {
                    operation_count: 5,
                    all_have_id: true,
                    all_have_summary: true,
                    all_have_input_schema: false,
                    all_have_output_schema: true,
                    all_have_capability: true,
                    all_have_risk_level: true,
                    all_have_safety_tier: true,
                    all_have_idempotency: true,
                    all_have_ai_hints: false,
                    approval_declared_where_needed: true,
                    operations_with_examples: 3,
                },
                config: ConfigReadiness {
                    accepts_config: true,
                    has_config_schema: false,
                    secrets_marked: false,
                    defaults_documented: false,
                    has_self_check: true,
                },
                lifecycle: LifecycleReadiness {
                    has_health: true,
                    reports_lifecycle_state: true,
                    events_declared: true,
                    has_rate_limits: true,
                    has_metrics: true,
                    has_shutdown: true,
                },
            },
            gaps: vec![ReadinessGap {
                category: GapCategory::OperationMetadata,
                description: "Some operations missing input_schema".to_owned(),
                severity: GapSeverity::Degraded,
                remediation: "Add JSON Schema for input".to_owned(),
            }],
        };

        let json = serde_json::to_string_pretty(&verdict).unwrap();
        let back: ReadinessVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, "test:fcp2:0.1");
        assert_eq!(back.level, ReadinessLevel::PartiallyReady);
        assert_eq!(back.gaps.len(), 1);
    }

    // ── ConnectorSummary ────────────────────────────────────────────────

    #[test]
    fn connector_summary_serde() {
        let summary = ConnectorSummary {
            id: "github:fcp2:1.0".to_owned(),
            name: "GitHub".to_owned(),
            version: "1.0.0".to_owned(),
            description: "GitHub API connector".to_owned(),
            archetypes: MetadataField::Known(vec!["request-response".to_owned()]),
            state: ConnectorState::Ready,
            operation_count: 12,
            max_risk: "high".to_owned(),
            has_events: true,
        };

        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["id"], "github:fcp2:1.0");
        assert_eq!(json["state"], "ready");
        assert_eq!(json["operation_count"], 12);
        assert_eq!(json["archetypes"]["status"], "known");
        assert_eq!(json["archetypes"]["value"][0], "request-response");
    }

    // ── OperationSummary ────────────────────────────────────────────────

    #[test]
    fn operation_summary_serde() {
        let op = OperationSummary {
            id: "issues.create".to_owned(),
            summary: "Create a new issue".to_owned(),
            capability: "github.write".to_owned(),
            risk_level: "medium".to_owned(),
            safety_tier: "risky".to_owned(),
            idempotency: "none".to_owned(),
            requires_approval: false,
            supports_simulate: true,
        };

        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["id"], "issues.create");
        assert_eq!(json["risk_level"], "medium");
    }

    // ── Mandatory field constants ───────────────────────────────────────

    #[test]
    fn mandatory_summary_fields_are_non_empty() {
        assert!(!MANDATORY_SUMMARY_FIELDS.is_empty());
        assert!(MANDATORY_SUMMARY_FIELDS.contains(&"id"));
        assert!(MANDATORY_SUMMARY_FIELDS.contains(&"state"));
    }

    #[test]
    fn mandatory_operation_fields_cover_core_metadata() {
        assert!(MANDATORY_OPERATION_FIELDS.contains(&"id"));
        assert!(MANDATORY_OPERATION_FIELDS.contains(&"capability"));
        assert!(MANDATORY_OPERATION_FIELDS.contains(&"risk_level"));
        assert!(MANDATORY_OPERATION_FIELDS.contains(&"input_schema"));
    }

    #[test]
    fn recommended_fields_include_ai_hints() {
        assert!(RECOMMENDED_OPERATION_FIELDS.contains(&"ai_hints"));
        assert!(RECOMMENDED_OPERATION_FIELDS.contains(&"examples"));
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn evaluate_null_introspection() {
        let verdict = evaluate_introspection(
            "broken:fcp2:0.0",
            "connectors/broken",
            ConnectorCohort::Automation,
            &json!(null),
        );
        assert_eq!(verdict.level, ReadinessLevel::NotReady);
    }

    #[test]
    fn evaluate_empty_object_introspection() {
        let verdict = evaluate_introspection(
            "empty:fcp2:0.0",
            "connectors/empty",
            ConnectorCohort::Automation,
            &json!({}),
        );
        assert_eq!(verdict.level, ReadinessLevel::NotReady);
    }

    #[test]
    fn evaluate_operation_with_empty_strings() {
        let introspection = json!({
            "operations": [
                {
                    "id": "",
                    "summary": "",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "",
                    "risk_level": "",
                    "safety_tier": "",
                    "idempotency": "",
                    "ai_hints": null
                }
            ]
        });

        let verdict = evaluate_introspection(
            "bad:fcp2:0.1",
            "connectors/bad",
            ConnectorCohort::Automation,
            &introspection,
        );

        // Empty strings are treated as missing.
        assert!(!verdict.areas.operations.all_have_id);
        assert!(!verdict.areas.operations.all_have_summary);
        assert!(!verdict.areas.operations.all_have_capability);
    }

    #[test]
    fn gap_category_serde() {
        let json = serde_json::to_string(&GapCategory::ConfigSchema).unwrap();
        assert_eq!(json, "\"config-schema\"");
        let back: GapCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, GapCategory::ConfigSchema);
    }

    #[test]
    fn multiple_gaps_accumulate() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "Op one",
                    "input_schema": null,
                    "output_schema": null,
                    "capability": "cap.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": null
                }
            ]
        });

        let verdict = evaluate_introspection(
            "multi:fcp2:0.1",
            "connectors/multi",
            ConnectorCohort::Data,
            &introspection,
        );

        // Should have gaps for: input_schema, output_schema, ai_hints, examples.
        assert!(verdict.gaps.len() >= 3);
    }

    // ── HealthSummary ───────────────────────────────────────────────────

    #[test]
    fn health_summary_serde() {
        let h = HealthSummary {
            state: "ready".to_owned(),
            uptime: "2h 15m".to_owned(),
            load: Some(0.5),
        };
        let json = serde_json::to_value(&h).unwrap();
        assert_eq!(json["state"], "ready");
        assert_eq!(json["load"], 0.5);
    }

    // ── RateLimitSummary ────────────────────────────────────────────────

    #[test]
    fn rate_limit_summary_serde() {
        let rl = RateLimitSummary {
            scope: "global".to_owned(),
            requests: 100,
            window: "60s".to_owned(),
        };
        let json = serde_json::to_value(&rl).unwrap();
        assert_eq!(json["requests"], 100);
    }

    // ── ConnectorDetail ─────────────────────────────────────────────────

    #[test]
    fn connector_detail_serde() {
        let detail = ConnectorDetail {
            summary: ConnectorSummary {
                id: "test:fcp2:1.0".to_owned(),
                name: "Test".to_owned(),
                version: "1.0.0".to_owned(),
                description: "Test connector".to_owned(),
                archetypes: MetadataField::Known(vec!["request-response".to_owned()]),
                state: ConnectorState::Ready,
                operation_count: 1,
                max_risk: "low".to_owned(),
                has_events: false,
            },
            operations: vec![OperationSummary {
                id: "test.ping".to_owned(),
                summary: "Ping the service".to_owned(),
                capability: "test.read".to_owned(),
                risk_level: "low".to_owned(),
                safety_tier: "safe".to_owned(),
                idempotency: "strict".to_owned(),
                requires_approval: false,
                supports_simulate: true,
            }],
            config_schema: MetadataField::Known(json!({"type": "object", "properties": {}})),
            health: MetadataField::Known(HealthSummary {
                state: "ready".to_owned(),
                uptime: "5m".to_owned(),
                load: None,
            }),
            rate_limits: MetadataField::Known(vec![]),
        };

        let json = serde_json::to_string(&detail).unwrap();
        let back: ConnectorDetail = serde_json::from_str(&json).unwrap();
        assert_eq!(back.summary.id, "test:fcp2:1.0");
        assert_eq!(back.operations.len(), 1);
    }

    // ── All ConnectorCohort variants serde round-trip ──────────────────

    #[test]
    fn all_connector_cohort_variants_serde_round_trip() {
        let all = [
            ConnectorCohort::Messaging,
            ConnectorCohort::Social,
            ConnectorCohort::Workspace,
            ConnectorCohort::Productivity,
            ConnectorCohort::Ai,
            ConnectorCohort::DevTools,
            ConnectorCohort::Infra,
            ConnectorCohort::Data,
            ConnectorCohort::Storage,
            ConnectorCohort::Analytics,
            ConnectorCohort::Finance,
            ConnectorCohort::Browser,
            ConnectorCohort::Knowledge,
            ConnectorCohort::Automation,
            ConnectorCohort::Community,
        ];
        assert_eq!(all.len(), 15, "must cover all 15 variants");
        for cohort in all {
            let json = serde_json::to_string(&cohort).unwrap();
            let back: ConnectorCohort = serde_json::from_str(&json).unwrap();
            assert_eq!(cohort, back);
        }
    }

    #[test]
    fn connector_cohort_kebab_case_values() {
        assert_eq!(
            serde_json::to_string(&ConnectorCohort::DevTools).unwrap(),
            "\"dev-tools\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorCohort::Ai).unwrap(),
            "\"ai\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorCohort::Messaging).unwrap(),
            "\"messaging\""
        );
    }

    // ── All ConnectorState variants serde round-trip ───────────────────

    #[test]
    fn all_connector_state_variants_serde_round_trip() {
        let all = [
            ConnectorState::Unknown,
            ConnectorState::Unconfigured,
            ConnectorState::Configured,
            ConnectorState::Ready,
            ConnectorState::Degraded,
            ConnectorState::Disabled,
            ConnectorState::Error,
        ];
        assert_eq!(all.len(), 7, "must cover all 7 variants");
        for state in all {
            let json = serde_json::to_string(&state).unwrap();
            let back: ConnectorState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    #[test]
    fn connector_state_kebab_case_values() {
        assert_eq!(
            serde_json::to_string(&ConnectorState::Unknown).unwrap(),
            "\"unknown\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorState::Unconfigured).unwrap(),
            "\"unconfigured\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorState::Error).unwrap(),
            "\"error\""
        );
        assert_eq!(
            serde_json::to_string(&ConnectorState::Disabled).unwrap(),
            "\"disabled\""
        );
    }

    // ── All GapCategory variants serde round-trip ─────────────────────

    #[test]
    fn all_gap_category_variants_serde_round_trip() {
        let all = [
            GapCategory::Identity,
            GapCategory::OperationMetadata,
            GapCategory::ConfigSchema,
            GapCategory::Lifecycle,
            GapCategory::AgentHints,
            GapCategory::EventSupport,
            GapCategory::RateLimits,
            GapCategory::ApprovalPolicy,
        ];
        assert_eq!(all.len(), 8, "must cover all 8 variants");
        for cat in all {
            let json = serde_json::to_string(&cat).unwrap();
            let back: GapCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    #[test]
    fn gap_category_kebab_case_values() {
        assert_eq!(
            serde_json::to_string(&GapCategory::OperationMetadata).unwrap(),
            "\"operation-metadata\""
        );
        assert_eq!(
            serde_json::to_string(&GapCategory::ApprovalPolicy).unwrap(),
            "\"approval-policy\""
        );
        assert_eq!(
            serde_json::to_string(&GapCategory::RateLimits).unwrap(),
            "\"rate-limits\""
        );
    }

    // ── GapSeverity serde all 3 variants ──────────────────────────────

    #[test]
    fn all_gap_severity_variants_serde_round_trip() {
        let all = [
            GapSeverity::Blocking,
            GapSeverity::Degraded,
            GapSeverity::Cosmetic,
        ];
        for sev in all {
            let json = serde_json::to_string(&sev).unwrap();
            let back: GapSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn gap_severity_kebab_case_values() {
        assert_eq!(
            serde_json::to_string(&GapSeverity::Blocking).unwrap(),
            "\"blocking\""
        );
        assert_eq!(
            serde_json::to_string(&GapSeverity::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&GapSeverity::Cosmetic).unwrap(),
            "\"cosmetic\""
        );
    }

    // ── GapSeverity full ordering ─────────────────────────────────────

    #[test]
    fn gap_severity_ordering_full() {
        assert!(GapSeverity::Blocking < GapSeverity::Degraded);
        assert!(GapSeverity::Blocking < GapSeverity::Cosmetic);
        assert!(GapSeverity::Degraded < GapSeverity::Cosmetic);
        // Reflexivity
        assert!(GapSeverity::Blocking == GapSeverity::Blocking);
        assert!(GapSeverity::Degraded == GapSeverity::Degraded);
        assert!(GapSeverity::Cosmetic == GapSeverity::Cosmetic);
        // Sorting
        let mut v = vec![
            GapSeverity::Cosmetic,
            GapSeverity::Blocking,
            GapSeverity::Degraded,
        ];
        v.sort();
        assert_eq!(
            v,
            vec![
                GapSeverity::Blocking,
                GapSeverity::Degraded,
                GapSeverity::Cosmetic
            ]
        );
    }

    // ── ReadinessLevel equality checks ────────────────────────────────

    #[test]
    fn readiness_level_equality() {
        assert_eq!(ReadinessLevel::Ready, ReadinessLevel::Ready);
        assert_eq!(
            ReadinessLevel::PartiallyReady,
            ReadinessLevel::PartiallyReady
        );
        assert_eq!(ReadinessLevel::NotReady, ReadinessLevel::NotReady);
        assert_ne!(ReadinessLevel::Ready, ReadinessLevel::PartiallyReady);
        assert_ne!(ReadinessLevel::Ready, ReadinessLevel::NotReady);
        assert_ne!(ReadinessLevel::PartiallyReady, ReadinessLevel::NotReady);
    }

    #[test]
    fn readiness_level_all_kebab_values() {
        assert_eq!(
            serde_json::to_string(&ReadinessLevel::Ready).unwrap(),
            "\"ready\""
        );
        assert_eq!(
            serde_json::to_string(&ReadinessLevel::PartiallyReady).unwrap(),
            "\"partially-ready\""
        );
        assert_eq!(
            serde_json::to_string(&ReadinessLevel::NotReady).unwrap(),
            "\"not-ready\""
        );
    }

    // ── evaluate_introspection: complete but missing examples ─────────

    #[test]
    fn complete_fields_but_missing_examples_only_cosmetic_gap() {
        let introspection = json!({
            "operations": [
                {
                    "id": "do.something",
                    "summary": "Does something",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "test.write",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "When you need to do something",
                        "examples": []
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "test:fcp2:1.0",
            "connectors/test",
            ConnectorCohort::Automation,
            &introspection,
        );

        // All fields are complete except examples → only cosmetic gap
        assert_eq!(verdict.level, ReadinessLevel::Ready);
        assert!(
            verdict
                .gaps
                .iter()
                .all(|g| g.severity == GapSeverity::Cosmetic)
        );
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.description.contains("examples"))
        );
    }

    // ── evaluate_introspection: missing capability doesn't degrade ────

    #[test]
    fn missing_capability_does_not_degrade_level() {
        // "capability" missing still results in no Blocking/Degraded gap
        // (the function only adds gaps for schemas, ai_hints, examples, and zero ops)
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "Something",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "Use it",
                        "examples": ["ex"]
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "test:fcp2:1.0",
            "connectors/test",
            ConnectorCohort::DevTools,
            &introspection,
        );

        // Capability is tracked in areas but not in gaps
        assert!(!verdict.areas.operations.all_have_capability);
        assert_eq!(verdict.level, ReadinessLevel::Ready);
    }

    // ── evaluate_introspection: non-canonical id (no colons) ──────────

    #[test]
    fn non_canonical_id_still_evaluates() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "Op",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": {
                        "when_to_use": "use",
                        "examples": ["ex"]
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "noColonsHere",
            "connectors/test",
            ConnectorCohort::Browser,
            &introspection,
        );

        // Non-canonical id → has_canonical_id = false, has_semver_version = false
        assert!(!verdict.areas.summary.has_canonical_id);
        assert!(!verdict.areas.summary.has_semver_version);
        // But still evaluates the operations
        assert_eq!(verdict.areas.operations.operation_count, 1);
        assert_eq!(verdict.level, ReadinessLevel::Ready);
    }

    // ── evaluate_introspection: large operation set all complete ───────

    #[test]
    fn large_operation_set_all_complete_is_ready() {
        let ops: Vec<Value> = (0..15)
            .map(|i| {
                json!({
                    "id": format!("op.{i}"),
                    "summary": format!("Operation {i}"),
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": format!("cap.{i}"),
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": format!("When doing thing {i}"),
                        "examples": [format!("Example {i}")]
                    }
                })
            })
            .collect();

        let introspection = json!({ "operations": ops });

        let verdict = evaluate_introspection(
            "big:fcp2:2.0",
            "connectors/big",
            ConnectorCohort::Infra,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::Ready);
        assert!(verdict.gaps.is_empty());
        assert_eq!(verdict.areas.operations.operation_count, 15);
        assert_eq!(verdict.areas.operations.operations_with_examples, 15);
    }

    // ── evaluate_introspection: mixed ops → partially ready ──────────

    #[test]
    fn mixed_ops_some_missing_schemas_is_partially_ready() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op.good",
                    "summary": "Good operation",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "cap.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "Good operation",
                        "examples": ["ex"]
                    }
                },
                {
                    "id": "op.bad",
                    "summary": "Bad operation",
                    "input_schema": null,
                    "output_schema": {"type": "object"},
                    "capability": "cap.write",
                    "risk_level": "medium",
                    "safety_tier": "risky",
                    "idempotency": "none",
                    "ai_hints": {
                        "when_to_use": "Bad op",
                        "examples": ["ex"]
                    }
                },
                {
                    "id": "op.worse",
                    "summary": "Worse op",
                    "input_schema": {"type": "object"},
                    "output_schema": null,
                    "capability": "cap.admin",
                    "risk_level": "high",
                    "safety_tier": "dangerous",
                    "idempotency": "none",
                    "ai_hints": {
                        "when_to_use": "Worse op",
                        "examples": ["ex"]
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "mixed:fcp2:1.0",
            "connectors/mixed",
            ConnectorCohort::Data,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::PartiallyReady);
        assert!(!verdict.areas.operations.all_have_input_schema);
        assert!(!verdict.areas.operations.all_have_output_schema);
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.description.contains("input_schema"))
        );
        assert!(
            verdict
                .gaps
                .iter()
                .any(|g| g.description.contains("output_schema"))
        );
    }

    // ── evaluate_introspection: has_events detection ──────────────────

    #[test]
    fn connector_with_events_detected_via_introspection() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ],
            "events": [
                { "name": "issue.created", "description": "Fired when an issue is created" }
            ]
        });

        let verdict = evaluate_introspection(
            "evented:fcp2:1.0",
            "connectors/evented",
            ConnectorCohort::DevTools,
            &introspection,
        );

        // The lifecycle.events_declared is always true in current impl
        assert!(verdict.areas.lifecycle.events_declared);
        assert_eq!(verdict.areas.operations.operation_count, 1);
    }

    // ── evaluate_introspection: auth_caps → config awareness ─────────

    #[test]
    fn connector_with_auth_caps_has_config_schema() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ],
            "auth_caps": { "bearer": true }
        });

        let verdict = evaluate_introspection(
            "authed:fcp2:1.0",
            "connectors/authed",
            ConnectorCohort::Ai,
            &introspection,
        );

        assert!(verdict.areas.config.has_config_schema);
    }

    #[test]
    fn connector_without_auth_caps_no_config_schema() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "noauth:fcp2:1.0",
            "connectors/noauth",
            ConnectorCohort::Knowledge,
            &introspection,
        );

        assert!(!verdict.areas.config.has_config_schema);
    }

    #[test]
    fn connector_without_explicit_approval_metadata_keeps_approval_contract_false() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "approval:fcp2:1.0",
            "connectors/approval",
            ConnectorCohort::Ai,
            &introspection,
        );

        assert!(!verdict.areas.operations.approval_declared_where_needed);
    }

    #[test]
    fn connector_without_explicit_archetype_metadata_keeps_archetypes_false() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "archetype:fcp2:1.0",
            "connectors/archetype",
            ConnectorCohort::Knowledge,
            &introspection,
        );

        assert!(!verdict.areas.summary.has_archetypes);
    }

    #[test]
    fn connector_with_explicit_rate_limits_marks_rate_limit_readiness_true() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "requires_approval": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ],
            "rate_limits": []
        });

        let verdict = evaluate_introspection(
            "ratelimit:fcp2:1.0",
            "connectors/ratelimit",
            ConnectorCohort::Knowledge,
            &introspection,
        );

        assert!(verdict.areas.lifecycle.has_rate_limits);
    }

    // ── ConnectorSummary: all fields serialize correctly ──────────────

    #[test]
    fn connector_summary_all_fields_present_in_json() {
        let summary = ConnectorSummary {
            id: "slack:fcp2:2.0".to_owned(),
            name: "Slack".to_owned(),
            version: "2.0.0".to_owned(),
            description: "Slack messaging connector".to_owned(),
            archetypes: MetadataField::Known(vec![
                "request-response".to_owned(),
                "streaming".to_owned(),
            ]),
            state: ConnectorState::Degraded,
            operation_count: 42,
            max_risk: "critical".to_owned(),
            has_events: true,
        };

        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["id"], "slack:fcp2:2.0");
        assert_eq!(json["name"], "Slack");
        assert_eq!(json["version"], "2.0.0");
        assert_eq!(json["description"], "Slack messaging connector");
        assert_eq!(json["archetypes"]["status"], "known");
        assert_eq!(json["archetypes"]["value"].as_array().unwrap().len(), 2);
        assert_eq!(json["state"], "degraded");
        assert_eq!(json["operation_count"], 42);
        assert_eq!(json["max_risk"], "critical");
        assert_eq!(json["has_events"], true);
    }

    #[test]
    fn connector_summary_deserialization_from_json() {
        let json = json!({
            "id": "x:fcp2:1.0",
            "name": "X",
            "version": "1.0.0",
            "description": "desc",
            "archetypes": { "status": "known", "value": [] },
            "state": "unconfigured",
            "operation_count": 0,
            "max_risk": "low",
            "has_events": false
        });
        let summary: ConnectorSummary = serde_json::from_value(json).unwrap();
        assert_eq!(summary.state, ConnectorState::Unconfigured);
        assert!(summary.archetypes.is_known());
        assert!(!summary.has_events);
    }

    // ── ConnectorDetail: with None health and empty rate_limits ───────

    #[test]
    fn connector_detail_unknown_health_empty_rate_limits() {
        let detail = ConnectorDetail {
            summary: ConnectorSummary {
                id: "bare:fcp2:0.1".to_owned(),
                name: "Bare".to_owned(),
                version: "0.1.0".to_owned(),
                description: "Bare connector".to_owned(),
                archetypes: MetadataField::Known(vec![]),
                state: ConnectorState::Unconfigured,
                operation_count: 0,
                max_risk: "low".to_owned(),
                has_events: false,
            },
            operations: vec![],
            config_schema: MetadataField::Unknown,
            health: MetadataField::Unknown,
            rate_limits: MetadataField::Known(vec![]),
        };

        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(json["health"]["status"], "unknown");
        assert_eq!(json["config_schema"]["status"], "unknown");
        assert_eq!(json["rate_limits"]["status"], "known");
        assert_eq!(json["rate_limits"]["value"].as_array().unwrap().len(), 0);
        assert_eq!(json["operations"].as_array().unwrap().len(), 0);

        let back: ConnectorDetail = serde_json::from_value(json).unwrap();
        assert!(!back.health.is_known());
        assert!(!back.config_schema.is_known());
    }

    // ── ConnectorDetail: round-trip with all optionals populated ──────

    #[test]
    fn connector_detail_all_fields_known_round_trip() {
        let detail = ConnectorDetail {
            summary: ConnectorSummary {
                id: "full:fcp2:3.0".to_owned(),
                name: "Full".to_owned(),
                version: "3.0.0".to_owned(),
                description: "Full connector".to_owned(),
                archetypes: MetadataField::Known(vec!["request-response".to_owned()]),
                state: ConnectorState::Ready,
                operation_count: 2,
                max_risk: "high".to_owned(),
                has_events: true,
            },
            operations: vec![
                OperationSummary {
                    id: "a.create".to_owned(),
                    summary: "Create A".to_owned(),
                    capability: "a.write".to_owned(),
                    risk_level: "high".to_owned(),
                    safety_tier: "dangerous".to_owned(),
                    idempotency: "none".to_owned(),
                    requires_approval: true,
                    supports_simulate: false,
                },
                OperationSummary {
                    id: "a.list".to_owned(),
                    summary: "List A".to_owned(),
                    capability: "a.read".to_owned(),
                    risk_level: "low".to_owned(),
                    safety_tier: "safe".to_owned(),
                    idempotency: "strict".to_owned(),
                    requires_approval: false,
                    supports_simulate: true,
                },
            ],
            config_schema: MetadataField::Known(json!({
                "type": "object",
                "properties": {
                    "api_key": { "type": "string", "secret": true },
                    "base_url": { "type": "string", "default": "https://api.example.com" }
                }
            })),
            health: MetadataField::Known(HealthSummary {
                state: "ready".to_owned(),
                uptime: "12h 30m".to_owned(),
                load: Some(0.75),
            }),
            rate_limits: MetadataField::Known(vec![
                RateLimitSummary {
                    scope: "global".to_owned(),
                    requests: 1000,
                    window: "60s".to_owned(),
                },
                RateLimitSummary {
                    scope: "a.create".to_owned(),
                    requests: 50,
                    window: "60s".to_owned(),
                },
            ]),
        };

        let json_str = serde_json::to_string_pretty(&detail).unwrap();
        let back: ConnectorDetail = serde_json::from_str(&json_str).unwrap();

        assert_eq!(back.summary.id, "full:fcp2:3.0");
        assert_eq!(back.operations.len(), 2);
        assert!(back.operations[0].requires_approval);
        assert!(!back.operations[1].requires_approval);
        assert!(back.config_schema.is_known());
        assert!(back.health.is_known());
        let h = back.health.as_known().expect("health should be known");
        assert_eq!(h.load, Some(0.75));
        let rate_limits = back
            .rate_limits
            .as_known()
            .expect("rate limits should round-trip");
        assert_eq!(rate_limits.len(), 2);
        assert_eq!(rate_limits[1].requests, 50);
    }

    // ── OperationSummary: round-trip serde ────────────────────────────

    #[test]
    fn operation_summary_round_trip() {
        let op = OperationSummary {
            id: "repos.delete".to_owned(),
            summary: "Delete a repository".to_owned(),
            capability: "repos.admin".to_owned(),
            risk_level: "critical".to_owned(),
            safety_tier: "forbidden".to_owned(),
            idempotency: "none".to_owned(),
            requires_approval: true,
            supports_simulate: false,
        };

        let json_str = serde_json::to_string(&op).unwrap();
        let back: OperationSummary = serde_json::from_str(&json_str).unwrap();

        assert_eq!(back.id, "repos.delete");
        assert_eq!(back.safety_tier, "forbidden");
        assert!(back.requires_approval);
        assert!(!back.supports_simulate);
    }

    #[test]
    fn operation_summary_all_json_fields() {
        let op = OperationSummary {
            id: "x".to_owned(),
            summary: "s".to_owned(),
            capability: "c".to_owned(),
            risk_level: "low".to_owned(),
            safety_tier: "safe".to_owned(),
            idempotency: "best-effort".to_owned(),
            requires_approval: false,
            supports_simulate: true,
        };

        let v = serde_json::to_value(&op).unwrap();
        // Verify all expected keys exist
        let obj = v.as_object().unwrap();
        for key in [
            "id",
            "summary",
            "capability",
            "risk_level",
            "safety_tier",
            "idempotency",
            "requires_approval",
            "supports_simulate",
        ] {
            assert!(obj.contains_key(key), "missing key: {key}");
        }
    }

    // ── HealthSummary: load variants ──────────────────────────────────

    #[test]
    fn health_summary_load_none() {
        let h = HealthSummary {
            state: "starting".to_owned(),
            uptime: "0s".to_owned(),
            load: None,
        };
        let json = serde_json::to_value(&h).unwrap();
        assert!(json["load"].is_null());
        let back: HealthSummary = serde_json::from_value(json).unwrap();
        assert!(back.load.is_none());
    }

    #[test]
    fn health_summary_load_zero() {
        let h = HealthSummary {
            state: "ready".to_owned(),
            uptime: "1m".to_owned(),
            load: Some(0.0),
        };
        let json = serde_json::to_value(&h).unwrap();
        let load_val = json["load"].as_f64().unwrap();
        assert!((load_val).abs() < f64::EPSILON);
        let back: HealthSummary = serde_json::from_value(json).unwrap();
        assert_eq!(back.load, Some(0.0));
    }

    #[test]
    fn health_summary_load_max() {
        let h = HealthSummary {
            state: "degraded".to_owned(),
            uptime: "48h".to_owned(),
            load: Some(1.0),
        };
        let json = serde_json::to_value(&h).unwrap();
        let load_val = json["load"].as_f64().unwrap();
        assert!((load_val - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn health_summary_round_trip() {
        let h = HealthSummary {
            state: "error".to_owned(),
            uptime: "0s".to_owned(),
            load: Some(0.99),
        };
        let json_str = serde_json::to_string(&h).unwrap();
        let back: HealthSummary = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.state, "error");
        assert_eq!(back.uptime, "0s");
        assert!(back.load.is_some());
    }

    // ── RateLimitSummary: round-trip serde ────────────────────────────

    #[test]
    fn rate_limit_summary_round_trip() {
        let rl = RateLimitSummary {
            scope: "issues.create".to_owned(),
            requests: 500,
            window: "300s".to_owned(),
        };
        let json_str = serde_json::to_string(&rl).unwrap();
        let back: RateLimitSummary = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.scope, "issues.create");
        assert_eq!(back.requests, 500);
        assert_eq!(back.window, "300s");
    }

    #[test]
    fn rate_limit_summary_zero_requests() {
        let rl = RateLimitSummary {
            scope: "global".to_owned(),
            requests: 0,
            window: "1s".to_owned(),
        };
        let json = serde_json::to_value(&rl).unwrap();
        assert_eq!(json["requests"], 0);
    }

    // ── ReadinessGap: construction and serde ──────────────────────────

    #[test]
    fn readiness_gap_construction_and_serde() {
        let gap = ReadinessGap {
            category: GapCategory::EventSupport,
            description: "No events declared".to_owned(),
            severity: GapSeverity::Cosmetic,
            remediation: "Add subscribe() support".to_owned(),
        };

        let json = serde_json::to_value(&gap).unwrap();
        assert_eq!(json["category"], "event-support");
        assert_eq!(json["severity"], "cosmetic");
        assert_eq!(json["description"], "No events declared");
        assert_eq!(json["remediation"], "Add subscribe() support");

        let back: ReadinessGap = serde_json::from_value(json).unwrap();
        assert_eq!(back.category, GapCategory::EventSupport);
        assert_eq!(back.severity, GapSeverity::Cosmetic);
    }

    #[test]
    fn readiness_gap_all_category_severity_combos_serialize() {
        let categories = [
            GapCategory::Identity,
            GapCategory::OperationMetadata,
            GapCategory::ConfigSchema,
            GapCategory::Lifecycle,
        ];
        let severities = [
            GapSeverity::Blocking,
            GapSeverity::Degraded,
            GapSeverity::Cosmetic,
        ];
        for cat in categories {
            for sev in severities {
                let gap = ReadinessGap {
                    category: cat,
                    description: "test".to_owned(),
                    severity: sev,
                    remediation: "fix".to_owned(),
                };
                let json = serde_json::to_string(&gap).unwrap();
                let back: ReadinessGap = serde_json::from_str(&json).unwrap();
                assert_eq!(back.category, cat);
                assert_eq!(back.severity, sev);
            }
        }
    }

    // ── SummaryReadiness: all-true, all-false, mixed ──────────────────

    #[test]
    fn summary_readiness_all_true() {
        let s = SummaryReadiness {
            has_canonical_id: true,
            has_display_name: true,
            has_archetypes: true,
            has_semver_version: true,
            has_description: true,
            has_operation_count: true,
            has_risk_summary: true,
        };
        let json = serde_json::to_value(&s).unwrap();
        let obj = json.as_object().unwrap();
        for (key, val) in obj {
            assert!(val.as_bool().unwrap(), "expected true for {key}");
        }
    }

    #[test]
    fn summary_readiness_all_false() {
        let s = SummaryReadiness {
            has_canonical_id: false,
            has_display_name: false,
            has_archetypes: false,
            has_semver_version: false,
            has_description: false,
            has_operation_count: false,
            has_risk_summary: false,
        };
        let json = serde_json::to_value(&s).unwrap();
        let obj = json.as_object().unwrap();
        for (key, val) in obj {
            assert!(!val.as_bool().unwrap(), "expected false for {key}");
        }
    }

    #[test]
    fn summary_readiness_mixed_round_trip() {
        let s = SummaryReadiness {
            has_canonical_id: true,
            has_display_name: true,
            has_archetypes: false,
            has_semver_version: true,
            has_description: false,
            has_operation_count: true,
            has_risk_summary: false,
        };
        let json_str = serde_json::to_string(&s).unwrap();
        let back: SummaryReadiness = serde_json::from_str(&json_str).unwrap();
        assert!(back.has_canonical_id);
        assert!(back.has_display_name);
        assert!(!back.has_archetypes);
        assert!(back.has_semver_version);
        assert!(!back.has_description);
        assert!(back.has_operation_count);
        assert!(!back.has_risk_summary);
    }

    // ── OperationsReadiness: zero operations edge case ────────────────

    #[test]
    fn operations_readiness_zero_operations() {
        let ops = OperationsReadiness {
            operation_count: 0,
            all_have_id: true,
            all_have_summary: true,
            all_have_input_schema: true,
            all_have_output_schema: true,
            all_have_capability: true,
            all_have_risk_level: true,
            all_have_safety_tier: true,
            all_have_idempotency: true,
            all_have_ai_hints: true,
            approval_declared_where_needed: true,
            operations_with_examples: 0,
        };

        let json = serde_json::to_value(&ops).unwrap();
        assert_eq!(json["operation_count"], 0);
        assert_eq!(json["operations_with_examples"], 0);
        // All bools are vacuously true
        assert!(json["all_have_id"].as_bool().unwrap());

        let back: OperationsReadiness = serde_json::from_value(json).unwrap();
        assert_eq!(back.operation_count, 0);
    }

    #[test]
    fn operations_readiness_large_count() {
        let ops = OperationsReadiness {
            operation_count: 999,
            all_have_id: false,
            all_have_summary: false,
            all_have_input_schema: false,
            all_have_output_schema: false,
            all_have_capability: false,
            all_have_risk_level: false,
            all_have_safety_tier: false,
            all_have_idempotency: false,
            all_have_ai_hints: false,
            approval_declared_where_needed: false,
            operations_with_examples: 42,
        };

        let json_str = serde_json::to_string(&ops).unwrap();
        let back: OperationsReadiness = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.operation_count, 999);
        assert_eq!(back.operations_with_examples, 42);
        assert!(!back.all_have_id);
    }

    // ── ConfigReadiness: all-false serde ──────────────────────────────

    #[test]
    fn config_readiness_all_false_serde() {
        let c = ConfigReadiness {
            accepts_config: false,
            has_config_schema: false,
            secrets_marked: false,
            defaults_documented: false,
            has_self_check: false,
        };

        let json = serde_json::to_value(&c).unwrap();
        let obj = json.as_object().unwrap();
        for (key, val) in obj {
            assert!(!val.as_bool().unwrap(), "expected false for {key}");
        }

        let back: ConfigReadiness = serde_json::from_value(json).unwrap();
        assert!(!back.accepts_config);
        assert!(!back.has_config_schema);
        assert!(!back.secrets_marked);
        assert!(!back.defaults_documented);
        assert!(!back.has_self_check);
    }

    #[test]
    fn config_readiness_all_true_serde() {
        let c = ConfigReadiness {
            accepts_config: true,
            has_config_schema: true,
            secrets_marked: true,
            defaults_documented: true,
            has_self_check: true,
        };

        let json_str = serde_json::to_string(&c).unwrap();
        let back: ConfigReadiness = serde_json::from_str(&json_str).unwrap();
        assert!(back.accepts_config);
        assert!(back.has_config_schema);
        assert!(back.secrets_marked);
        assert!(back.defaults_documented);
        assert!(back.has_self_check);
    }

    // ── LifecycleReadiness: all-true serde ────────────────────────────

    #[test]
    fn lifecycle_readiness_all_true_serde() {
        let lc = LifecycleReadiness {
            has_health: true,
            reports_lifecycle_state: true,
            events_declared: true,
            has_rate_limits: true,
            has_metrics: true,
            has_shutdown: true,
        };

        let json = serde_json::to_value(&lc).unwrap();
        let obj = json.as_object().unwrap();
        for (key, val) in obj {
            assert!(val.as_bool().unwrap(), "expected true for {key}");
        }

        let back: LifecycleReadiness = serde_json::from_value(json).unwrap();
        assert!(back.has_health);
        assert!(back.has_shutdown);
    }

    #[test]
    fn lifecycle_readiness_all_false_serde() {
        let lc = LifecycleReadiness {
            has_health: false,
            reports_lifecycle_state: false,
            events_declared: false,
            has_rate_limits: false,
            has_metrics: false,
            has_shutdown: false,
        };

        let json_str = serde_json::to_string(&lc).unwrap();
        let back: LifecycleReadiness = serde_json::from_str(&json_str).unwrap();
        assert!(!back.has_health);
        assert!(!back.reports_lifecycle_state);
        assert!(!back.events_declared);
        assert!(!back.has_rate_limits);
        assert!(!back.has_metrics);
        assert!(!back.has_shutdown);
    }

    // ── MANDATORY_SUMMARY_FIELDS: no duplicates ──────────────────────

    #[test]
    fn mandatory_summary_fields_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for field in MANDATORY_SUMMARY_FIELDS {
            assert!(seen.insert(field), "duplicate field: {field}");
        }
    }

    #[test]
    fn mandatory_summary_fields_contains_required() {
        for required in &["id", "name", "version", "description", "state"] {
            assert!(
                MANDATORY_SUMMARY_FIELDS.contains(required),
                "missing required field: {required}"
            );
        }
    }

    // ── MANDATORY_OPERATION_FIELDS: no duplicates ────────────────────

    #[test]
    fn mandatory_operation_fields_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for field in MANDATORY_OPERATION_FIELDS {
            assert!(seen.insert(field), "duplicate field: {field}");
        }
    }

    #[test]
    fn mandatory_operation_fields_contains_required() {
        for required in &[
            "id",
            "summary",
            "capability",
            "risk_level",
            "safety_tier",
            "input_schema",
            "output_schema",
        ] {
            assert!(
                MANDATORY_OPERATION_FIELDS.contains(required),
                "missing required field: {required}"
            );
        }
    }

    // ── RECOMMENDED_OPERATION_FIELDS: no overlap with mandatory ──────

    #[test]
    fn recommended_fields_no_overlap_with_mandatory() {
        for rec in RECOMMENDED_OPERATION_FIELDS {
            assert!(
                !MANDATORY_OPERATION_FIELDS.contains(rec),
                "field {rec} appears in both mandatory and recommended"
            );
        }
    }

    #[test]
    fn recommended_operation_fields_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for field in RECOMMENDED_OPERATION_FIELDS {
            assert!(seen.insert(field), "duplicate field: {field}");
        }
    }

    // ── evaluate_introspection: non-array operations ─────────────────

    #[test]
    fn operations_as_string_treated_as_empty() {
        let introspection = json!({
            "operations": "not an array"
        });

        let verdict = evaluate_introspection(
            "weird:fcp2:0.1",
            "connectors/weird",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::NotReady);
        assert_eq!(verdict.areas.operations.operation_count, 0);
    }

    #[test]
    fn operations_as_number_treated_as_empty() {
        let introspection = json!({
            "operations": 42
        });

        let verdict = evaluate_introspection(
            "numops:fcp2:0.1",
            "connectors/numops",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::NotReady);
        assert_eq!(verdict.areas.operations.operation_count, 0);
    }

    #[test]
    fn operations_as_object_treated_as_empty() {
        let introspection = json!({
            "operations": { "op1": "data" }
        });

        let verdict = evaluate_introspection(
            "objops:fcp2:0.1",
            "connectors/objops",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::NotReady);
        assert_eq!(verdict.areas.operations.operation_count, 0);
    }

    #[test]
    fn operations_as_bool_treated_as_empty() {
        let introspection = json!({
            "operations": true
        });

        let verdict = evaluate_introspection(
            "boolops:fcp2:0.1",
            "connectors/boolops",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::NotReady);
        assert_eq!(verdict.areas.operations.operation_count, 0);
    }

    // ── evaluate_introspection: id format variations ─────────────────

    #[test]
    fn two_part_id_not_canonical() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "name:version",
            "connectors/test",
            ConnectorCohort::Community,
            &introspection,
        );

        assert!(!verdict.areas.summary.has_canonical_id);
        assert!(!verdict.areas.summary.has_semver_version);
    }

    #[test]
    fn empty_id_has_display_name_false() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "",
            "connectors/test",
            ConnectorCohort::Finance,
            &introspection,
        );

        assert!(!verdict.areas.summary.has_display_name);
        assert!(!verdict.areas.summary.has_canonical_id);
    }

    // ── ReadinessVerdict: verify cohort is preserved ──────────────────

    #[test]
    fn verdict_preserves_cohort() {
        let introspection = json!({ "operations": [] });
        for cohort in [
            ConnectorCohort::Social,
            ConnectorCohort::Storage,
            ConnectorCohort::Analytics,
        ] {
            let verdict = evaluate_introspection(
                "x:fcp2:1.0",
                "connectors/x",
                cohort.clone(),
                &introspection,
            );
            assert_eq!(verdict.cohort, cohort);
        }
    }

    #[test]
    fn verdict_preserves_crate_path() {
        let introspection = json!({ "operations": [] });
        let verdict = evaluate_introspection(
            "x:fcp2:1.0",
            "connectors/custom/path",
            ConnectorCohort::Productivity,
            &introspection,
        );
        assert_eq!(verdict.crate_path, "connectors/custom/path");
    }

    // ── ReadinessAreas serde round-trip ───────────────────────────────

    #[test]
    fn readiness_areas_full_round_trip() {
        let areas = ReadinessAreas {
            summary: SummaryReadiness {
                has_canonical_id: true,
                has_display_name: true,
                has_archetypes: false,
                has_semver_version: true,
                has_description: true,
                has_operation_count: true,
                has_risk_summary: false,
            },
            operations: OperationsReadiness {
                operation_count: 7,
                all_have_id: true,
                all_have_summary: false,
                all_have_input_schema: true,
                all_have_output_schema: true,
                all_have_capability: true,
                all_have_risk_level: true,
                all_have_safety_tier: false,
                all_have_idempotency: true,
                all_have_ai_hints: false,
                approval_declared_where_needed: true,
                operations_with_examples: 3,
            },
            config: ConfigReadiness {
                accepts_config: true,
                has_config_schema: true,
                secrets_marked: false,
                defaults_documented: true,
                has_self_check: true,
            },
            lifecycle: LifecycleReadiness {
                has_health: true,
                reports_lifecycle_state: false,
                events_declared: true,
                has_rate_limits: true,
                has_metrics: false,
                has_shutdown: true,
            },
        };

        let json_str = serde_json::to_string_pretty(&areas).unwrap();
        let back: ReadinessAreas = serde_json::from_str(&json_str).unwrap();

        assert_eq!(back.operations.operation_count, 7);
        assert_eq!(back.operations.operations_with_examples, 3);
        assert!(!back.summary.has_archetypes);
        assert!(!back.operations.all_have_summary);
        assert!(!back.lifecycle.reports_lifecycle_state);
        assert!(back.config.has_config_schema);
    }

    // ── evaluate_introspection: risk_summary derived from operations ──

    #[test]
    fn risk_summary_true_when_all_ops_have_risk_level() {
        let introspection = json!({
            "operations": [
                {
                    "id": "a",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "high",
                    "safety_tier": "dangerous",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                },
                {
                    "id": "b",
                    "summary": "s2",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c2",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": { "when_to_use": "w2", "examples": ["e2"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "r:fcp2:1.0",
            "connectors/r",
            ConnectorCohort::DevTools,
            &introspection,
        );

        assert!(verdict.areas.summary.has_risk_summary);
    }

    #[test]
    fn risk_summary_false_when_any_op_missing_risk_level() {
        let introspection = json!({
            "operations": [
                {
                    "id": "a",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "high",
                    "safety_tier": "dangerous",
                    "idempotency": "none",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                },
                {
                    "id": "b",
                    "summary": "s2",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c2",
                    "risk_level": "",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": { "when_to_use": "w2", "examples": ["e2"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "r:fcp2:1.0",
            "connectors/r",
            ConnectorCohort::DevTools,
            &introspection,
        );

        assert!(!verdict.areas.summary.has_risk_summary);
    }

    // ── evaluate_introspection: examples counting ─────────────────────

    #[test]
    fn examples_count_partial() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s1",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "w",
                        "examples": ["ex1"]
                    }
                },
                {
                    "id": "op2",
                    "summary": "s2",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "w",
                        "examples": []
                    }
                },
                {
                    "id": "op3",
                    "summary": "s3",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "w",
                        "examples": ["ex1", "ex2"]
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "ex:fcp2:1.0",
            "connectors/ex",
            ConnectorCohort::Automation,
            &introspection,
        );

        assert_eq!(verdict.areas.operations.operations_with_examples, 2);
        assert_eq!(verdict.areas.operations.operation_count, 3);
        // Gap for incomplete examples
        assert!(verdict.gaps.iter().any(|g| g.description.contains("2/3")));
    }

    // ── evaluate_introspection: operation missing only output_schema ──

    #[test]
    fn missing_only_output_schema_is_partially_ready() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {"type": "object"},
                    "output_schema": null,
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "out:fcp2:1.0",
            "connectors/out",
            ConnectorCohort::Data,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::PartiallyReady);
        assert!(verdict.areas.operations.all_have_input_schema);
        assert!(!verdict.areas.operations.all_have_output_schema);
    }

    // ── evaluate_introspection: single op all complete → ready ────────

    #[test]
    fn single_complete_operation_is_ready() {
        let introspection = json!({
            "operations": [
                {
                    "id": "ping",
                    "summary": "Ping the service",
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"},
                    "capability": "health.read",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": {
                        "when_to_use": "Check service health",
                        "examples": ["Ping the service"]
                    }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "simple:fcp2:1.0",
            "connectors/simple",
            ConnectorCohort::Infra,
            &introspection,
        );

        assert_eq!(verdict.level, ReadinessLevel::Ready);
        assert!(verdict.gaps.is_empty());
        assert_eq!(verdict.areas.operations.operation_count, 1);
        assert!(verdict.areas.operations.all_have_id);
        assert!(verdict.areas.operations.all_have_summary);
        assert!(verdict.areas.operations.all_have_input_schema);
        assert!(verdict.areas.operations.all_have_output_schema);
        assert!(verdict.areas.operations.all_have_capability);
        assert!(verdict.areas.operations.all_have_risk_level);
        assert!(verdict.areas.operations.all_have_safety_tier);
        assert!(verdict.areas.operations.all_have_idempotency);
        assert!(verdict.areas.operations.all_have_ai_hints);
        assert_eq!(verdict.areas.operations.operations_with_examples, 1);
    }

    // ── evaluate_introspection: connector_id stored correctly ─────────

    #[test]
    fn verdict_stores_connector_id() {
        let introspection = json!({ "operations": [] });
        let verdict = evaluate_introspection(
            "test-connector:fcp2:99.99",
            "connectors/test-connector",
            ConnectorCohort::Browser,
            &introspection,
        );
        assert_eq!(verdict.connector_id, "test-connector:fcp2:99.99");
    }

    // ── evaluate_introspection: all idempotency fields ───────────────

    #[test]
    fn idempotency_tracked_correctly() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "strict",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                },
                {
                    "id": "op2",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "safe",
                    "idempotency": "",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "idem:fcp2:1.0",
            "connectors/idem",
            ConnectorCohort::Workspace,
            &introspection,
        );

        assert!(!verdict.areas.operations.all_have_idempotency);
    }

    // ── evaluate_introspection: safety_tier tracking ─────────────────

    #[test]
    fn safety_tier_tracked_correctly() {
        let introspection = json!({
            "operations": [
                {
                    "id": "op1",
                    "summary": "s",
                    "input_schema": {},
                    "output_schema": {},
                    "capability": "c",
                    "risk_level": "low",
                    "safety_tier": "",
                    "idempotency": "strict",
                    "ai_hints": { "when_to_use": "w", "examples": ["e"] }
                }
            ]
        });

        let verdict = evaluate_introspection(
            "safe:fcp2:1.0",
            "connectors/safe",
            ConnectorCohort::Social,
            &introspection,
        );

        assert!(!verdict.areas.operations.all_have_safety_tier);
    }

    // ── Connector inventory audit ─────────────────────────────────────

    #[test]
    fn inventory_covers_all_connectors() {
        assert_eq!(CONNECTOR_INVENTORY.len(), 82);
    }

    #[test]
    fn inventory_entries_have_valid_cohorts() {
        for entry in CONNECTOR_INVENTORY {
            // Verify cohort round-trips through serde.
            let json = serde_json::to_string(&entry.cohort).unwrap();
            let _back: ConnectorCohort = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn inventory_entries_have_positive_operation_counts() {
        for entry in CONNECTOR_INVENTORY {
            assert!(
                entry.operation_count > 0,
                "{} has zero operations",
                entry.name
            );
        }
    }

    #[test]
    fn inventory_entries_sorted_by_name() {
        for window in CONNECTOR_INVENTORY.windows(2) {
            assert!(
                window[0].name <= window[1].name,
                "Inventory not sorted: {} > {}",
                window[0].name,
                window[1].name
            );
        }
    }

    #[test]
    fn typed_connectors_have_agent_hints() {
        let typed: Vec<_> = CONNECTOR_INVENTORY
            .iter()
            .filter(|e| e.metadata_tier == MetadataTier::Typed)
            .collect();

        assert!(!typed.is_empty());
        for entry in &typed {
            assert!(
                entry.has_agent_hints,
                "{} is typed but missing agent hints",
                entry.name
            );
        }
    }

    #[test]
    fn all_connectors_are_typed() {
        let json_style: Vec<_> = CONNECTOR_INVENTORY
            .iter()
            .filter(|e| e.metadata_tier == MetadataTier::Json)
            .collect();

        assert!(
            json_style.is_empty(),
            "expected 0 Json connectors, found {}: {:?}",
            json_style.len(),
            json_style.iter().map(|e| e.name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn missing_manifest_connectors_identified() {
        let missing: Vec<_> = CONNECTOR_INVENTORY
            .iter()
            .filter(|e| !e.has_manifest)
            .collect();

        assert_eq!(missing.len(), 3);
        let names: Vec<_> = missing.iter().map(|e| e.name).collect();
        assert!(names.contains(&"postgresql"));
        assert!(names.contains(&"redis"));
        assert!(names.contains(&"whisper"));
    }

    #[test]
    fn audit_all_returns_expected_count() {
        let results = audit_all_connectors();
        assert_eq!(results.len(), 82);
    }

    #[test]
    fn audit_typed_connectors_are_ready() {
        let results = audit_all_connectors();
        let typed_ready: Vec<_> = results
            .iter()
            .filter(|v| {
                CONNECTOR_INVENTORY
                    .iter()
                    .any(|e| e.name == v.connector_id && e.metadata_tier == MetadataTier::Typed)
            })
            .collect();

        for verdict in &typed_ready {
            assert_eq!(
                verdict.level,
                ReadinessLevel::Ready,
                "{} should be ready",
                verdict.connector_id
            );
        }
    }

    #[test]
    fn audit_json_connectors_are_partially_ready_or_ready() {
        let results = audit_all_connectors();
        for verdict in &results {
            let entry = CONNECTOR_INVENTORY
                .iter()
                .find(|e| e.name == verdict.connector_id);
            if let Some(e) = entry {
                if e.metadata_tier == MetadataTier::Json {
                    assert_ne!(
                        verdict.level,
                        ReadinessLevel::NotReady,
                        "{} should not be not-ready (has operations)",
                        verdict.connector_id
                    );
                }
            }
        }
    }

    #[test]
    fn audit_gap_categories_are_correct() {
        let results = audit_all_connectors();
        for verdict in &results {
            for gap in &verdict.gaps {
                // All gaps should have non-empty descriptions and remediations.
                assert!(!gap.description.is_empty());
                assert!(!gap.remediation.is_empty());
            }
        }
    }

    #[test]
    fn cohort_distribution_is_reasonable() {
        use std::collections::HashMap;
        let mut counts: HashMap<String, usize> = HashMap::new();
        for entry in CONNECTOR_INVENTORY {
            let key = serde_json::to_string(&entry.cohort).unwrap();
            *counts.entry(key).or_default() += 1;
        }
        // Every cohort that appears should have at least one connector.
        for (cohort, count) in &counts {
            assert!(*count > 0, "Cohort {cohort} is empty");
        }
    }

    #[test]
    fn audit_matrix_serializable() {
        let results = audit_all_connectors();
        let json = serde_json::to_string_pretty(&results).unwrap();
        assert!(json.len() > 1000, "Matrix too small");
        // Verify it round-trips.
        let back: Vec<ReadinessVerdict> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), results.len());
    }

    #[test]
    fn inventory_has_correct_typed_count() {
        let typed_count = CONNECTOR_INVENTORY
            .iter()
            .filter(|e| e.metadata_tier == MetadataTier::Typed)
            .count();
        assert_eq!(typed_count, 82);
    }

    #[test]
    fn inventory_has_correct_json_count() {
        let json_count = CONNECTOR_INVENTORY
            .iter()
            .filter(|e| e.metadata_tier == MetadataTier::Json)
            .count();
        assert_eq!(json_count, 0);
    }

    #[test]
    fn discovery_normalization_supports_legacy_manifest_shapes() {
        let raw = r#"
[manifest]
format = "fcp-connector-manifest"
schema_version = "2.1"
min_mesh_version = "2.0.0"
min_protocol = "fcp2-sym/2.0"
protocol_features = ["streaming"]
max_datagram_bytes = 65000
interface_hash = "blake3-256:fcp.interface.v2:0000000000000000000000000000000000000000000000000000000000000000"

[connector]
id = "fcp.legacy"
name = "Legacy Connector"
version = "0.1.0"
description = "Legacy manifest shape"
archetypes = ["messaging", "operational"]
format = "wasi"

[connector.state]
model = "cursor"
state_schema_version = "1"
migration_hint = "init"

[zones]
home = "z:work"
allowed_sources = ["z:work"]
allowed_targets = ["z:work"]
forbidden = []

[capabilities]
required = ["network.dns"]
optional = []
forbidden = []

[provides.operations.echo]
description = "Echo"
capability = "legacy.echo"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
input_schema = { type = "object" }
output_schema = { type = "object" }

[provides.operations.echo.network]
allowed_hosts = ["api.example.test"]
protocol = "https"

[provides.events.tick]
description = "Tick"
streaming = true
replay = false

[provides.streaming]
gateway_host = "gateway.example.test"
protocol = "wss"

[sandbox]
profile = "strict"
memory_mb = 64
cpu_percent = 20
wall_clock_timeout_ms = 1000
fs_readonly_paths = ["/usr"]
fs_writable_paths = ["$CONNECTOR_STATE"]
deny_exec = true
deny_ptrace = true

[rate_limits.pools."legacy.echo"]
description = "Legacy pool"
max_per_minute = 60
burst = 5
"#;

        let normalized =
            normalize_manifest_for_discovery(raw).expect("normalization should succeed");
        let normalized = normalized.expect("legacy manifest should need normalization");

        let archetypes = normalized
            .get("connector")
            .and_then(toml::Value::as_table)
            .and_then(|connector| connector.get("archetypes"))
            .and_then(toml::Value::as_array)
            .expect("normalized connector archetypes should exist")
            .iter()
            .filter_map(toml::Value::as_str)
            .collect::<Vec<_>>();
        assert_eq!(archetypes, vec!["messaging", "operational"]);
        assert_eq!(
            normalized
                .get("connector")
                .and_then(toml::Value::as_table)
                .and_then(|connector| connector.get("state"))
                .and_then(toml::Value::as_table)
                .and_then(|state| state.get("model"))
                .and_then(toml::Value::as_str),
            Some("cursor")
        );
        assert!(
            normalized
                .get("rate_limits")
                .and_then(toml::Value::as_table)
                .is_some(),
            "legacy rate limit metadata should remain visible for fallback discovery"
        );
        let echo = normalized
            .get("provides")
            .and_then(toml::Value::as_table)
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .and_then(|operations| operations.get("echo"))
            .and_then(toml::Value::as_table)
            .expect("echo operation should still exist");
        assert_eq!(
            echo.get("requires_approval").and_then(toml::Value::as_str),
            Some("none")
        );
        assert!(
            echo.get("network").is_none(),
            "legacy network aliases should still normalize away"
        );
    }

    #[test]
    fn discovered_operation_from_toml_does_not_claim_simulate_support() {
        let manifest: toml::Value = toml::from_str(
            r#"
[provides.operations.echo]
description = "Echo"
capability = "legacy.echo"
risk_level = "low"
safety_tier = "safe"
requires_approval = "none"
idempotency = "strict"
input_schema = { type = "object" }
output_schema = { type = "object" }
"#,
        )
        .expect("manifest snippet should parse");

        let operation = manifest
            .get("provides")
            .and_then(toml::Value::as_table)
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .and_then(|operations| operations.get("echo"))
            .expect("echo op should exist");

        let discovered = discovered_operation_from_toml(
            "legacy",
            "legacy.echo",
            operation,
            Path::new("legacy-manifest.toml"),
        )
        .expect("discovery fallback should parse operation");

        assert!(!discovered.summary.supports_simulate);
    }

    #[test]
    fn discovered_operation_from_toml_without_approval_metadata_keeps_requirement_false() {
        let manifest: toml::Value = toml::from_str(
            r#"
[provides.operations.echo]
description = "Echo"
capability = "legacy.echo"
risk_level = "low"
safety_tier = "safe"
idempotency = "strict"
input_schema = { type = "object" }
output_schema = { type = "object" }
"#,
        )
        .expect("manifest snippet should parse");

        let operation = manifest
            .get("provides")
            .and_then(toml::Value::as_table)
            .and_then(|provides| provides.get("operations"))
            .and_then(toml::Value::as_table)
            .and_then(|operations| operations.get("echo"))
            .expect("echo op should exist");

        let discovered = discovered_operation_from_toml(
            "legacy",
            "legacy.echo",
            operation,
            Path::new("legacy-manifest.toml"),
        )
        .expect("discovery fallback should parse operation");

        assert_eq!(discovered.approval_mode, "none");
        assert!(!discovered.summary.requires_approval);
        assert!(discovered.operation_info().requires_approval.is_none());
    }

    #[test]
    fn discovery_catalog_loads_discord_and_telegram() {
        let discord_manifest = workspace_root().join("connectors/discord/manifest.toml");
        let telegram_manifest = workspace_root().join("connectors/telegram/manifest.toml");

        DiscoveredConnector::from_manifest("discord", &discord_manifest)
            .expect("discord manifest should load for discovery");
        DiscoveredConnector::from_manifest("telegram", &telegram_manifest)
            .expect("telegram manifest should load for discovery");

        let catalog = DiscoveryCatalog::load().expect("catalog should load");
        let connector_ids = catalog
            .connectors()
            .iter()
            .map(|connector| connector.detail.summary.id.as_str())
            .collect::<Vec<_>>();

        assert!(connector_ids.contains(&"fcp.discord"));
        assert!(connector_ids.contains(&"fcp.telegram"));
    }

    #[test]
    fn shared_descriptor_uses_explicit_not_yet_measured_checks_for_runtime_gaps() {
        let catalog = DiscoveryCatalog::load().expect("catalog should load");
        let connector = catalog
            .resolve_connector("github")
            .expect("github connector should resolve");
        let descriptor = connector.shared_descriptor();

        let auth = descriptor.auth.expect("auth descriptor should exist");
        assert_eq!(auth.status, DescriptorStatus::Unverifiable);
        assert_eq!(
            auth.checks
                .iter()
                .find(|check| check.id == "auth.active_state")
                .map(|check| check.status),
            Some(DescriptorStatus::NotYetMeasured)
        );

        let readiness = descriptor
            .readiness
            .expect("readiness descriptor should exist");
        assert_eq!(readiness.status, DescriptorStatus::Unverifiable);
        assert_eq!(
            readiness
                .checks
                .iter()
                .find(|check| check.id == "runtime.state")
                .map(|check| check.status),
            Some(DescriptorStatus::NotYetMeasured)
        );
        assert_eq!(
            readiness
                .checks
                .iter()
                .find(|check| check.id == "setup.prerequisites")
                .map(|check| check.status),
            Some(DescriptorStatus::NotYetMeasured)
        );
    }

    // ── Truthfulness invariant tests (1g7z0.29.8.4) ─────────────────

    #[test]
    fn truthfulness_metadata_field_never_leaks_value_when_non_known() {
        // Invariant: non-Known variants must NEVER serialize a "value" key.
        let non_known: Vec<MetadataField<String>> = vec![
            MetadataField::Unknown,
            MetadataField::Unsupported,
            MetadataField::Unavailable,
            MetadataField::NotApplicable,
        ];
        for field in non_known {
            let json = serde_json::to_value(&field).unwrap();
            assert!(
                json.get("value").is_none(),
                "non-Known variant {:?} leaked a value key",
                field.status_tag()
            );
        }
    }

    #[test]
    fn truthfulness_metadata_field_known_always_has_value() {
        let field = MetadataField::Known("test".to_owned());
        let json = serde_json::to_value(&field).unwrap();
        assert!(json.get("value").is_some(), "Known variant missing value");
    }

    #[test]
    fn truthfulness_metadata_field_status_tags_are_stable_strings() {
        // Snapshot invariant: these exact strings must never change because
        // downstream consumers (MCP export, logs, agent output) depend on them.
        assert_eq!(MetadataField::Known(0).status_tag(), "known");
        assert_eq!(MetadataField::<()>::Unknown.status_tag(), "unknown");
        assert_eq!(MetadataField::<()>::Unsupported.status_tag(), "unsupported");
        assert_eq!(MetadataField::<()>::Unavailable.status_tag(), "unavailable");
        assert_eq!(
            MetadataField::<()>::NotApplicable.status_tag(),
            "not-applicable"
        );
    }

    #[test]
    fn truthfulness_provenance_tags_are_stable_strings() {
        // Snapshot invariant: provenance tags must never change.
        assert_eq!(
            MetadataProvenance::DeclaredByConnector.tag(),
            "declared-by-connector"
        );
        assert_eq!(MetadataProvenance::ObservedByHost.tag(), "observed-by-host");
        assert_eq!(
            MetadataProvenance::MeasuredAtRuntime.tag(),
            "measured-at-runtime"
        );
        assert_eq!(
            MetadataProvenance::InferredFromPolicy.tag(),
            "inferred-from-policy"
        );
        assert_eq!(MetadataProvenance::Unattributed.tag(), "unattributed");
    }

    #[test]
    fn truthfulness_availability_tags_are_stable_strings() {
        // Snapshot invariant: availability tags are part of the public contract.
        assert_eq!(CommandAvailability::LiveRuntime.tag(), "live-runtime");
        assert_eq!(
            CommandAvailability::OfflineArtifact.tag(),
            "offline-artifact"
        );
        assert_eq!(CommandAvailability::Unsupported.tag(), "unsupported");
        assert_eq!(CommandAvailability::Planned.tag(), "planned");
        assert_eq!(CommandAvailability::Unavailable.tag(), "unavailable");
        assert_eq!(CommandAvailability::Denied.tag(), "denied");
        assert_eq!(CommandAvailability::Unknown.tag(), "unknown");
    }

    #[test]
    fn truthfulness_only_live_runtime_is_authoritative() {
        // Invariant: no offline or degraded state may claim authority.
        let non_authoritative = [
            CommandAvailability::OfflineArtifact,
            CommandAvailability::Unsupported,
            CommandAvailability::Planned,
            CommandAvailability::Unavailable,
            CommandAvailability::Denied,
            CommandAvailability::Unknown,
        ];
        for avail in &non_authoritative {
            assert!(
                !avail.is_authoritative(),
                "{:?} should not be authoritative",
                avail
            );
        }
        assert!(CommandAvailability::LiveRuntime.is_authoritative());
    }

    #[test]
    fn truthfulness_envelope_offline_never_claims_authoritative() {
        let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "list");
        assert!(!envelope.authoritative);
        assert!(envelope.explanation.contains("offline"));
    }

    #[test]
    fn truthfulness_envelope_live_is_authoritative() {
        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "invoke");
        assert!(envelope.authoritative);
    }

    #[test]
    fn truthfulness_envelope_planned_is_not_authoritative() {
        let envelope = CommandEnvelope::new(CommandAvailability::Planned, "batch");
        assert!(!envelope.authoritative);
        assert!(
            envelope.explanation.contains("planned") || envelope.explanation.contains("not yet")
        );
    }

    #[test]
    fn truthfulness_envelope_unknown_is_not_authoritative_but_recoverable() {
        let envelope = CommandEnvelope::new(CommandAvailability::Unknown, "show");
        assert!(!envelope.authoritative);
        assert!(envelope.recoverable);
    }

    #[test]
    fn truthfulness_envelope_unsupported_is_not_recoverable() {
        let envelope = CommandEnvelope::new(CommandAvailability::Unsupported, "stream");
        assert!(!envelope.recoverable);
    }

    #[test]
    fn truthfulness_envelope_denied_is_recoverable() {
        let envelope = CommandEnvelope::new(CommandAvailability::Denied, "invoke");
        assert!(envelope.recoverable);
    }

    #[test]
    fn truthfulness_envelope_inject_into_payload() {
        let envelope = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "list");
        let mut payload = json!({"connectors": []});
        envelope.inject_into(&mut payload);

        let avail = &payload["availability"];
        assert_eq!(avail["availability"], "offline-artifact");
        assert_eq!(avail["authoritative"], false);
        assert_eq!(avail["command"], "list");
        assert!(avail["next_actions"].is_array());
    }

    #[test]
    fn truthfulness_envelope_next_actions_non_empty_for_degraded_states() {
        let degraded = [
            CommandAvailability::OfflineArtifact,
            CommandAvailability::Unsupported,
            CommandAvailability::Planned,
            CommandAvailability::Unavailable,
            CommandAvailability::Denied,
            CommandAvailability::Unknown,
        ];
        for avail in &degraded {
            let envelope = CommandEnvelope::new(avail.clone(), "test-cmd");
            assert!(
                !envelope.next_actions.is_empty(),
                "{:?} should suggest remediation actions",
                avail
            );
        }
    }

    #[test]
    fn truthfulness_envelope_live_runtime_has_no_next_actions() {
        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "invoke");
        assert!(envelope.next_actions.is_empty());
    }

    #[test]
    fn truthfulness_provenance_metadata_field_preserves_provenance_through_map() {
        let original = ProvenanceMetadataField::known(100_u32, MetadataProvenance::ObservedByHost);
        let mapped = original.map(|v| v * 2);
        assert_eq!(*mapped.as_known().unwrap(), 200);
        assert_eq!(mapped.provenance, MetadataProvenance::ObservedByHost);
    }

    #[test]
    fn truthfulness_provenance_metadata_field_from_unattributed_is_honest() {
        let bare = MetadataField::Known("data".to_owned());
        let pf = ProvenanceMetadataField::from_unattributed(bare);
        assert_eq!(pf.provenance, MetadataProvenance::Unattributed);
        assert!(!pf.is_authoritative());
    }

    #[test]
    fn truthfulness_metadata_field_from_option_none_is_unknown_not_fabricated() {
        // Invariant: converting None to MetadataField must produce Unknown,
        // never a fabricated default value.
        let field: MetadataField<Vec<String>> = MetadataField::from_option(None);
        assert_eq!(field.status_tag(), "unknown");
        assert!(field.as_known().is_none());
    }

    #[test]
    fn truthfulness_exit_codes_partition_correctly() {
        // Invariant: success states (0), validation (5), policy (6), transport (8)
        // must be consistent and non-overlapping in semantics.
        assert_eq!(CommandAvailability::LiveRuntime.exit_code_u8(), 0);
        assert_eq!(CommandAvailability::OfflineArtifact.exit_code_u8(), 0);
        assert_eq!(CommandAvailability::Planned.exit_code_u8(), 0);
        assert_eq!(CommandAvailability::Unsupported.exit_code_u8(), 5);
        assert_eq!(CommandAvailability::Denied.exit_code_u8(), 6);
        assert_eq!(CommandAvailability::Unavailable.exit_code_u8(), 8);
        assert_eq!(CommandAvailability::Unknown.exit_code_u8(), 8);
    }

    #[test]
    fn truthfulness_readiness_level_values_are_exhaustive() {
        // Snapshot: all readiness levels round-trip correctly.
        let levels = [
            ReadinessLevel::Ready,
            ReadinessLevel::PartiallyReady,
            ReadinessLevel::NotReady,
        ];
        for level in levels {
            let json = serde_json::to_value(level).unwrap();
            let back: ReadinessLevel = serde_json::from_value(json).unwrap();
            assert_eq!(back, level);
        }
    }

    #[test]
    fn truthfulness_gap_severity_ordering_is_consistent() {
        // Invariant: blocking > degraded > cosmetic in semantic weight.
        let blocking = json!("blocking");
        let degraded = json!("degraded");
        let cosmetic = json!("cosmetic");
        let b: GapSeverity = serde_json::from_value(blocking).unwrap();
        let d: GapSeverity = serde_json::from_value(degraded).unwrap();
        let c: GapSeverity = serde_json::from_value(cosmetic).unwrap();
        assert_eq!(b, GapSeverity::Blocking);
        assert_eq!(d, GapSeverity::Degraded);
        assert_eq!(c, GapSeverity::Cosmetic);
    }

    #[test]
    fn truthfulness_metadata_field_serialization_shape_is_stable() {
        // Snapshot: the JSON shape must be exactly {status, value?}
        let known = serde_json::to_value(MetadataField::Known(42)).unwrap();
        let obj = known.as_object().unwrap();
        assert!(obj.contains_key("status"));
        assert!(obj.contains_key("value"));
        assert_eq!(obj.len(), 2, "Known should have exactly 2 keys");

        let unknown = serde_json::to_value(MetadataField::<i32>::Unknown).unwrap();
        let obj = unknown.as_object().unwrap();
        assert!(obj.contains_key("status"));
        assert_eq!(obj.len(), 1, "Unknown should have exactly 1 key");
    }

    #[test]
    fn truthfulness_provenance_field_serialization_shape_is_stable() {
        // Snapshot: the JSON shape must be exactly {status, provenance, value?}
        let known = serde_json::to_value(ProvenanceMetadataField::known(
            42,
            MetadataProvenance::ObservedByHost,
        ))
        .unwrap();
        let obj = known.as_object().unwrap();
        assert!(obj.contains_key("status"));
        assert!(obj.contains_key("provenance"));
        assert!(obj.contains_key("value"));
        assert_eq!(
            obj.len(),
            3,
            "Known provenance field should have exactly 3 keys"
        );

        let unknown = serde_json::to_value(ProvenanceMetadataField::<i32>::unknown(
            MetadataProvenance::Unattributed,
        ))
        .unwrap();
        let obj = unknown.as_object().unwrap();
        assert!(obj.contains_key("status"));
        assert!(obj.contains_key("provenance"));
        assert_eq!(
            obj.len(),
            2,
            "Unknown provenance field should have exactly 2 keys"
        );
    }

    #[test]
    fn truthfulness_all_availability_variants_have_explanations() {
        let variants = [
            CommandAvailability::LiveRuntime,
            CommandAvailability::OfflineArtifact,
            CommandAvailability::Unsupported,
            CommandAvailability::Planned,
            CommandAvailability::Unavailable,
            CommandAvailability::Denied,
            CommandAvailability::Unknown,
        ];
        for variant in &variants {
            assert!(
                !variant.explanation().is_empty(),
                "{:?} has empty explanation",
                variant
            );
        }
    }

    #[test]
    fn truthfulness_envelope_serialization_includes_all_required_fields() {
        let envelope = CommandEnvelope::new(CommandAvailability::LiveRuntime, "invoke");
        let json = serde_json::to_value(&envelope).unwrap();
        let obj = json.as_object().unwrap();

        let required_keys = [
            "availability",
            "command",
            "authoritative",
            "explanation",
            "recoverable",
            "next_actions",
        ];
        for key in &required_keys {
            assert!(
                obj.contains_key(*key),
                "envelope missing required key: {key}"
            );
        }
    }

    #[test]
    fn truthfulness_connector_detail_metadata_fields_are_typed() {
        // Verify that ConnectorDetail uses MetadataField, not raw Option.
        let detail = ConnectorDetail {
            summary: ConnectorSummary {
                id: "test:fcp2:1.0".to_owned(),
                name: "Test".to_owned(),
                archetypes: MetadataField::Unknown,
                version: "1.0.0".to_owned(),
                description: "Test connector".to_owned(),
                state: ConnectorState::Unknown,
                operation_count: 0,
                max_risk: "low".to_owned(),
                has_events: false,
            },
            operations: vec![],
            config_schema: MetadataField::Unknown,
            health: MetadataField::NotApplicable,
            rate_limits: MetadataField::Unsupported,
        };

        // All metadata fields should serialize with explicit status tags
        let json = serde_json::to_value(&detail).unwrap();
        assert_eq!(json["config_schema"]["status"], "unknown");
        assert_eq!(json["health"]["status"], "not-applicable");
        assert_eq!(json["rate_limits"]["status"], "unsupported");
        assert_eq!(json["summary"]["archetypes"]["status"], "unknown");
    }

    #[test]
    fn truthfulness_connector_summary_archetypes_unknown_serialization() {
        let summary = ConnectorSummary {
            id: "test:fcp2:1.0".to_owned(),
            name: "Test".to_owned(),
            archetypes: MetadataField::Unknown,
            version: "1.0.0".to_owned(),
            description: "test".to_owned(),
            state: ConnectorState::Unknown,
            operation_count: 5,
            max_risk: "low".to_owned(),
            has_events: false,
        };
        let json = serde_json::to_value(&summary).unwrap();
        // The archetypes field must show "unknown", NOT an empty array
        assert_eq!(json["archetypes"]["status"], "unknown");
        assert!(json["archetypes"].get("value").is_none());
    }

    #[test]
    fn truthfulness_connector_summary_archetypes_known_serialization() {
        let summary = ConnectorSummary {
            id: "test:fcp2:1.0".to_owned(),
            name: "Test".to_owned(),
            archetypes: MetadataField::Known(vec!["request-response".to_owned()]),
            version: "1.0.0".to_owned(),
            description: "test".to_owned(),
            state: ConnectorState::Unknown,
            operation_count: 5,
            max_risk: "low".to_owned(),
            has_events: false,
        };
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["archetypes"]["status"], "known");
        assert_eq!(json["archetypes"]["value"][0], "request-response");
    }

    // ── Metadata state representation tests ──────────────────────────────

    #[test]
    fn repr_table_covers_all_metadata_field_variants() {
        // Every MetadataField variant must have a representation
        let fields: Vec<MetadataField<()>> = vec![
            MetadataField::Known(()),
            MetadataField::Unknown,
            MetadataField::Unsupported,
            MetadataField::Unavailable,
            MetadataField::NotApplicable,
        ];
        for field in &fields {
            let tag = field.status_tag();
            assert!(
                metadata_state_repr(tag).is_some(),
                "No representation for status tag '{tag}'"
            );
        }
    }

    #[test]
    fn repr_table_has_exactly_five_entries() {
        assert_eq!(METADATA_STATE_REPRS.len(), 5);
    }

    #[test]
    fn repr_status_tags_are_unique() {
        let tags: Vec<&str> = METADATA_STATE_REPRS.iter().map(|r| r.status).collect();
        let unique: std::collections::HashSet<&str> = tags.iter().copied().collect();
        assert_eq!(tags.len(), unique.len(), "Duplicate status tags");
    }

    #[test]
    fn repr_cli_symbols_are_nonempty() {
        for repr in METADATA_STATE_REPRS {
            assert!(
                !repr.cli_symbol.is_empty(),
                "Empty CLI symbol for '{}'",
                repr.status
            );
        }
    }

    #[test]
    fn repr_cli_labels_are_nonempty() {
        for repr in METADATA_STATE_REPRS {
            assert!(
                !repr.cli_label.is_empty(),
                "Empty CLI label for '{}'",
                repr.status
            );
        }
    }

    #[test]
    fn repr_cli_colors_are_nonempty() {
        for repr in METADATA_STATE_REPRS {
            assert!(
                !repr.cli_color.is_empty(),
                "Empty CLI color for '{}'",
                repr.status
            );
        }
    }

    #[test]
    fn repr_explanations_are_nonempty() {
        for repr in METADATA_STATE_REPRS {
            assert!(
                !repr.explanation.is_empty(),
                "Empty explanation for '{}'",
                repr.status
            );
        }
    }

    #[test]
    fn repr_known_is_not_actionable() {
        let repr = metadata_state_repr("known").unwrap();
        assert!(!repr.actionable);
        assert!(repr.guidance.is_empty());
    }

    #[test]
    fn repr_unknown_is_actionable_with_guidance() {
        let repr = metadata_state_repr("unknown").unwrap();
        assert!(repr.actionable);
        assert!(!repr.guidance.is_empty());
    }

    #[test]
    fn repr_unsupported_is_not_actionable() {
        let repr = metadata_state_repr("unsupported").unwrap();
        assert!(!repr.actionable);
    }

    #[test]
    fn repr_unavailable_is_actionable_with_guidance() {
        let repr = metadata_state_repr("unavailable").unwrap();
        assert!(repr.actionable);
        assert!(!repr.guidance.is_empty());
    }

    #[test]
    fn repr_not_applicable_is_not_actionable() {
        let repr = metadata_state_repr("not-applicable").unwrap();
        assert!(!repr.actionable);
        assert!(repr.guidance.is_empty());
    }

    #[test]
    fn repr_unknown_tag_returns_none() {
        assert!(metadata_state_repr("bogus").is_none());
    }

    // -- field_repr tests --

    #[test]
    fn field_repr_known() {
        let repr = field_repr(&MetadataField::Known(42));
        assert_eq!(repr.status, "known");
        assert_eq!(repr.cli_symbol, "✓");
    }

    #[test]
    fn field_repr_unknown() {
        let repr = field_repr::<i32>(&MetadataField::Unknown);
        assert_eq!(repr.status, "unknown");
        assert_eq!(repr.cli_symbol, "?");
    }

    #[test]
    fn field_repr_unsupported() {
        let repr = field_repr::<i32>(&MetadataField::Unsupported);
        assert_eq!(repr.status, "unsupported");
        assert_eq!(repr.cli_symbol, "✗");
    }

    #[test]
    fn field_repr_unavailable() {
        let repr = field_repr::<i32>(&MetadataField::Unavailable);
        assert_eq!(repr.status, "unavailable");
        assert_eq!(repr.cli_symbol, "!");
    }

    #[test]
    fn field_repr_not_applicable() {
        let repr = field_repr::<i32>(&MetadataField::NotApplicable);
        assert_eq!(repr.status, "not-applicable");
        assert_eq!(repr.cli_symbol, "–");
    }

    // -- format_field_cli tests --

    #[test]
    fn format_cli_known() {
        let s = format_field_cli(&MetadataField::Known("hello"));
        assert_eq!(s, "✓ known");
    }

    #[test]
    fn format_cli_unknown() {
        let s = format_field_cli::<i32>(&MetadataField::Unknown);
        assert_eq!(s, "? unknown");
    }

    #[test]
    fn format_cli_unsupported() {
        let s = format_field_cli::<i32>(&MetadataField::Unsupported);
        assert_eq!(s, "✗ unsupported");
    }

    #[test]
    fn format_cli_unavailable() {
        let s = format_field_cli::<i32>(&MetadataField::Unavailable);
        assert_eq!(s, "! unavailable");
    }

    #[test]
    fn format_cli_not_applicable() {
        let s = format_field_cli::<i32>(&MetadataField::NotApplicable);
        assert_eq!(s, "– n/a");
    }

    // -- format_field_log tests --

    #[test]
    fn format_log_known() {
        let s = format_field_log(&MetadataField::Known(42));
        assert!(s.starts_with("status=known"));
        assert!(s.contains("explanation="));
    }

    #[test]
    fn format_log_unknown() {
        let s = format_field_log::<i32>(&MetadataField::Unknown);
        assert!(s.starts_with("status=unknown"));
        assert!(s.contains("No trustworthy signal"));
    }

    #[test]
    fn format_log_unavailable() {
        let s = format_field_log::<i32>(&MetadataField::Unavailable);
        assert!(s.starts_with("status=unavailable"));
        assert!(s.contains("temporarily unreachable"));
    }

    // -- field_state_json tests --

    #[test]
    fn field_state_json_known() {
        let json = field_state_json(&MetadataField::Known(42));
        assert_eq!(json["status"], "known");
        assert_eq!(json["actionable"], false);
        assert_eq!(json["cli_symbol"], "✓");
        assert!(json["guidance"].as_array().unwrap().is_empty());
    }

    #[test]
    fn field_state_json_unknown() {
        let json = field_state_json::<i32>(&MetadataField::Unknown);
        assert_eq!(json["status"], "unknown");
        assert_eq!(json["actionable"], true);
        assert!(!json["guidance"].as_array().unwrap().is_empty());
    }

    #[test]
    fn field_state_json_unsupported() {
        let json = field_state_json::<i32>(&MetadataField::Unsupported);
        assert_eq!(json["status"], "unsupported");
        assert_eq!(json["actionable"], false);
    }

    #[test]
    fn field_state_json_unavailable() {
        let json = field_state_json::<i32>(&MetadataField::Unavailable);
        assert_eq!(json["status"], "unavailable");
        assert_eq!(json["actionable"], true);
    }

    #[test]
    fn field_state_json_not_applicable() {
        let json = field_state_json::<i32>(&MetadataField::NotApplicable);
        assert_eq!(json["status"], "not-applicable");
        assert_eq!(json["cli_label"], "n/a");
    }

    // -- Provenance formatting tests --

    #[test]
    fn format_provenance_cli_known_declared() {
        let f = ProvenanceMetadataField::known(42, MetadataProvenance::DeclaredByConnector);
        let s = format_provenance_field_cli(&f);
        assert_eq!(s, "✓ known (declared-by-connector)");
    }

    #[test]
    fn format_provenance_cli_unknown_unattributed() {
        let f = ProvenanceMetadataField::<i32>::unknown(MetadataProvenance::Unattributed);
        let s = format_provenance_field_cli(&f);
        assert_eq!(s, "? unknown (unattributed)");
    }

    #[test]
    fn format_provenance_log_known_observed() {
        let f = ProvenanceMetadataField::known(42, MetadataProvenance::ObservedByHost);
        let s = format_provenance_field_log(&f);
        assert!(s.contains("status=known"));
        assert!(s.contains("provenance=observed-by-host"));
    }

    #[test]
    fn format_provenance_log_unsupported() {
        let f =
            ProvenanceMetadataField::<i32>::unsupported(MetadataProvenance::DeclaredByConnector);
        let s = format_provenance_field_log(&f);
        assert!(s.contains("status=unsupported"));
        assert!(s.contains("provenance=declared-by-connector"));
    }

    // -- Cross-cutting representation invariants --

    #[test]
    fn repr_serializes_to_stable_json() {
        for repr in METADATA_STATE_REPRS {
            let json: serde_json::Value = serde_json::to_value(repr).unwrap();
            // Every repr must serialize with these keys
            assert_eq!(json["status"], repr.status);
            assert_eq!(json["cli_symbol"], repr.cli_symbol);
            assert_eq!(json["cli_label"], repr.cli_label);
            assert_eq!(json["cli_color"], repr.cli_color);
            assert_eq!(json["actionable"], repr.actionable);
            assert!(
                json["guidance"].is_array(),
                "guidance must be an array for '{}'",
                repr.status
            );
        }
    }

    #[test]
    fn repr_actionable_states_have_guidance() {
        for repr in METADATA_STATE_REPRS {
            if repr.actionable {
                assert!(
                    !repr.guidance.is_empty(),
                    "Actionable state '{}' must have guidance",
                    repr.status
                );
            }
        }
    }

    #[test]
    fn repr_non_actionable_terminal_states_no_guidance() {
        // "known" and "not-applicable" are terminal — no guidance needed
        for tag in ["known", "not-applicable"] {
            let repr = metadata_state_repr(tag).unwrap();
            assert!(!repr.actionable);
            assert!(
                repr.guidance.is_empty(),
                "Terminal state '{tag}' should have empty guidance"
            );
        }
    }

    #[test]
    fn repr_cli_symbols_are_distinct() {
        let symbols: Vec<&str> = METADATA_STATE_REPRS.iter().map(|r| r.cli_symbol).collect();
        let unique: std::collections::HashSet<&str> = symbols.iter().copied().collect();
        assert_eq!(symbols.len(), unique.len(), "Duplicate CLI symbols");
    }

    #[test]
    fn repr_all_states_have_stable_json_output() {
        // Verify the JSON shape is consistent across all states
        let fields: Vec<MetadataField<i32>> = vec![
            MetadataField::Known(42),
            MetadataField::Unknown,
            MetadataField::Unsupported,
            MetadataField::Unavailable,
            MetadataField::NotApplicable,
        ];
        for field in &fields {
            let json = field_state_json(field);
            // All must have these keys
            assert!(json.get("status").is_some(), "Missing 'status'");
            assert!(json.get("explanation").is_some(), "Missing 'explanation'");
            assert!(json.get("actionable").is_some(), "Missing 'actionable'");
            assert!(json.get("guidance").is_some(), "Missing 'guidance'");
            assert!(json.get("cli_symbol").is_some(), "Missing 'cli_symbol'");
            assert!(json.get("cli_label").is_some(), "Missing 'cli_label'");
        }
    }

    // ── Bead 29.7.3: Workflow truth output semantics ──────────────────────

    // ── compact_label ─────────────────────────────────────────────────────

    #[test]
    fn compact_label_all_seven_variants_are_distinct() {
        let labels: Vec<&str> = ALL_AVAILABILITY.iter().map(|a| a.compact_label()).collect();
        let unique: std::collections::HashSet<&str> = labels.iter().copied().collect();
        assert_eq!(labels.len(), unique.len(), "Duplicate compact labels");
    }

    #[test]
    fn compact_label_success_states_have_no_bracket_action() {
        assert_eq!(CommandAvailability::LiveRuntime.compact_label(), "LIVE");
        assert_eq!(
            CommandAvailability::OfflineArtifact.compact_label(),
            "OFFLINE"
        );
        // No bracket suffix for states that need no caller action
        assert!(
            !CommandAvailability::LiveRuntime
                .compact_label()
                .contains('[')
        );
    }

    #[test]
    fn compact_label_recoverable_states_have_bracket_action() {
        for avail in &ALL_AVAILABILITY {
            if avail.is_recoverable() {
                let label = avail.compact_label();
                assert!(
                    label.contains('['),
                    "{:?} is recoverable but compact_label '{}' has no bracket action",
                    avail,
                    label,
                );
            }
        }
    }

    #[test]
    fn compact_label_planned_has_preview_suffix() {
        assert!(
            CommandAvailability::Planned
                .compact_label()
                .contains("preview")
        );
    }

    #[test]
    fn compact_label_unavailable_has_retry_suffix() {
        assert!(
            CommandAvailability::Unavailable
                .compact_label()
                .contains("retry")
        );
    }

    #[test]
    fn compact_label_denied_has_remediate_suffix() {
        assert!(
            CommandAvailability::Denied
                .compact_label()
                .contains("remediate")
        );
    }

    #[test]
    fn compact_label_unknown_has_diagnose_suffix() {
        assert!(
            CommandAvailability::Unknown
                .compact_label()
                .contains("diagnose")
        );
    }

    // ── help_text ─────────────────────────────────────────────────────────

    #[test]
    fn help_text_embeds_command_name_in_all_variants() {
        for avail in &ALL_AVAILABILITY {
            let text = avail.help_text("my-test-cmd");
            assert!(
                text.contains("my-test-cmd"),
                "{:?} help_text does not embed command name: {}",
                avail,
                text,
            );
        }
    }

    #[test]
    fn help_text_all_variants_non_empty() {
        for avail in &ALL_AVAILABILITY {
            let text = avail.help_text("cmd");
            assert!(!text.is_empty(), "{:?} has empty help_text", avail);
        }
    }

    #[test]
    fn help_text_live_runtime_mentions_live() {
        let text = CommandAvailability::LiveRuntime.help_text("show");
        assert!(text.contains("live") || text.contains("Live"));
    }

    #[test]
    fn help_text_offline_mentions_host_flag() {
        let text = CommandAvailability::OfflineArtifact.help_text("list");
        assert!(text.contains("--host"));
    }

    #[test]
    fn help_text_unsupported_mentions_ops() {
        let text = CommandAvailability::Unsupported.help_text("invoke");
        assert!(text.contains("ops"));
    }

    #[test]
    fn help_text_planned_mentions_preview() {
        let text = CommandAvailability::Planned.help_text("batch");
        assert!(text.contains("preview"));
    }

    #[test]
    fn help_text_unavailable_mentions_offline_flag() {
        let text = CommandAvailability::Unavailable.help_text("show");
        assert!(text.contains("--offline"));
    }

    #[test]
    fn help_text_denied_mentions_auth() {
        let text = CommandAvailability::Denied.help_text("invoke");
        assert!(text.contains("auth"));
    }

    #[test]
    fn help_text_unknown_mentions_doctor() {
        let text = CommandAvailability::Unknown.help_text("show");
        assert!(text.contains("doctor"));
    }

    // ── cli_symbol ────────────────────────────────────────────────────────

    #[test]
    fn cli_symbol_all_seven_variants_are_distinct() {
        let symbols: Vec<&str> = ALL_AVAILABILITY.iter().map(|a| a.cli_symbol()).collect();
        let unique: std::collections::HashSet<&str> = symbols.iter().copied().collect();
        assert_eq!(symbols.len(), unique.len(), "Duplicate CLI symbols");
    }

    #[test]
    fn cli_symbol_all_are_bracketed() {
        for avail in &ALL_AVAILABILITY {
            let sym = avail.cli_symbol();
            assert!(
                sym.starts_with('[') && sym.ends_with(']'),
                "{:?} has unbracketed symbol: {}",
                avail,
                sym
            );
        }
    }

    #[test]
    fn cli_symbol_live_is_plus() {
        assert_eq!(CommandAvailability::LiveRuntime.cli_symbol(), "[+]");
    }

    #[test]
    fn cli_symbol_denied_is_minus() {
        assert_eq!(CommandAvailability::Denied.cli_symbol(), "[-]");
    }

    #[test]
    fn cli_symbol_unknown_is_question() {
        assert_eq!(CommandAvailability::Unknown.cli_symbol(), "[?]");
    }

    #[test]
    fn cli_symbol_unsupported_is_x() {
        assert_eq!(CommandAvailability::Unsupported.cli_symbol(), "[x]");
    }

    // ── severity_rank ─────────────────────────────────────────────────────

    #[test]
    fn severity_rank_all_variants_are_distinct() {
        let ranks: Vec<u8> = ALL_AVAILABILITY.iter().map(|a| a.severity_rank()).collect();
        let unique: std::collections::HashSet<u8> = ranks.iter().copied().collect();
        assert_eq!(ranks.len(), unique.len(), "Duplicate severity ranks");
    }

    #[test]
    fn severity_rank_live_runtime_is_lowest() {
        assert_eq!(CommandAvailability::LiveRuntime.severity_rank(), 0);
        for avail in &ALL_AVAILABILITY {
            assert!(avail.severity_rank() >= CommandAvailability::LiveRuntime.severity_rank());
        }
    }

    #[test]
    fn severity_rank_denied_is_highest() {
        assert_eq!(CommandAvailability::Denied.severity_rank(), 6);
        for avail in &ALL_AVAILABILITY {
            assert!(avail.severity_rank() <= CommandAvailability::Denied.severity_rank());
        }
    }

    #[test]
    fn severity_rank_ordering_success_before_degraded() {
        // Success states should rank lower (less severe) than degraded states
        assert!(
            CommandAvailability::LiveRuntime.severity_rank()
                < CommandAvailability::Unavailable.severity_rank()
        );
        assert!(
            CommandAvailability::OfflineArtifact.severity_rank()
                < CommandAvailability::Denied.severity_rank()
        );
    }

    // ── Display impls ─────────────────────────────────────────────────────

    #[test]
    fn availability_display_matches_compact_label() {
        for avail in &ALL_AVAILABILITY {
            assert_eq!(format!("{avail}"), avail.compact_label());
        }
    }

    #[test]
    fn envelope_display_contains_command_and_symbol() {
        let env = CommandEnvelope::new(CommandAvailability::Denied, "invoke");
        let display = format!("{env}");
        assert!(display.contains("invoke"));
        assert!(display.contains("[-]"));
        assert!(display.contains("DENIED"));
    }

    #[test]
    fn envelope_display_all_variants() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "test-cmd");
            let display = format!("{env}");
            assert!(display.contains("test-cmd"), "{:?}: {}", avail, display);
            assert!(
                display.contains(avail.cli_symbol()),
                "{:?}: {}",
                avail,
                display
            );
        }
    }

    // ── compact_line ──────────────────────────────────────────────────────

    #[test]
    fn envelope_compact_line_contains_symbol_label_explanation() {
        let env = CommandEnvelope::new(CommandAvailability::Unavailable, "show");
        let line = env.compact_line();
        assert!(line.contains("[!]"));
        assert!(line.contains("UNAVAILABLE [retry]"));
        assert!(line.contains("temporarily unreachable"));
    }

    #[test]
    fn envelope_compact_line_all_variants_non_empty() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "cmd");
            assert!(!env.compact_line().is_empty(), "{:?}", avail);
        }
    }

    #[test]
    fn envelope_compact_line_live_runtime_has_live_label() {
        let env = CommandEnvelope::new(CommandAvailability::LiveRuntime, "show");
        let line = env.compact_line();
        assert!(line.starts_with("[+]"));
        assert!(line.contains("LIVE"));
    }

    // ── transcript_entry ──────────────────────────────────────────────────

    #[test]
    fn transcript_entry_has_required_schema_keys() {
        let required_keys = [
            "type",
            "command",
            "state",
            "authoritative",
            "recoverable",
            "exit_code",
            "severity_rank",
            "explanation",
            "next_actions",
            "compact",
            "symbol",
        ];
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "test-cmd");
            let entry = env.transcript_entry();
            let obj = entry.as_object().unwrap();
            for key in &required_keys {
                assert!(
                    obj.contains_key(*key),
                    "{:?} transcript missing key: {}",
                    avail,
                    key
                );
            }
        }
    }

    #[test]
    fn transcript_entry_type_is_availability_verdict() {
        let env = CommandEnvelope::new(CommandAvailability::LiveRuntime, "show");
        let entry = env.transcript_entry();
        assert_eq!(entry["type"], "availability_verdict");
    }

    #[test]
    fn transcript_entry_state_matches_tag() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "cmd");
            let entry = env.transcript_entry();
            assert_eq!(entry["state"].as_str().unwrap(), avail.tag());
        }
    }

    #[test]
    fn transcript_entry_exit_code_matches_availability() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "cmd");
            let entry = env.transcript_entry();
            assert_eq!(
                entry["exit_code"].as_u64().unwrap(),
                u64::from(avail.exit_code_u8()),
            );
        }
    }

    #[test]
    fn transcript_entry_authoritative_only_for_live() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "cmd");
            let entry = env.transcript_entry();
            let auth = entry["authoritative"].as_bool().unwrap();
            assert_eq!(auth, avail.is_authoritative(), "{:?}", avail);
        }
    }

    #[test]
    fn transcript_entry_recoverable_matches_availability() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "cmd");
            let entry = env.transcript_entry();
            let rec = entry["recoverable"].as_bool().unwrap();
            assert_eq!(rec, avail.is_recoverable(), "{:?}", avail);
        }
    }

    #[test]
    fn transcript_entry_severity_rank_matches() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "cmd");
            let entry = env.transcript_entry();
            assert_eq!(
                entry["severity_rank"].as_u64().unwrap(),
                u64::from(avail.severity_rank()),
            );
        }
    }

    #[test]
    fn transcript_entry_compact_label_matches() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "cmd");
            let entry = env.transcript_entry();
            assert_eq!(entry["compact"].as_str().unwrap(), avail.compact_label());
        }
    }

    #[test]
    fn transcript_entry_symbol_matches() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "cmd");
            let entry = env.transcript_entry();
            assert_eq!(entry["symbol"].as_str().unwrap(), avail.cli_symbol());
        }
    }

    #[test]
    fn transcript_entry_next_actions_is_array() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "cmd");
            let entry = env.transcript_entry();
            assert!(entry["next_actions"].is_array(), "{:?}", avail);
        }
    }

    #[test]
    fn transcript_entry_command_preserved() {
        let env = CommandEnvelope::new(CommandAvailability::Denied, "my-special-cmd");
        let entry = env.transcript_entry();
        assert_eq!(entry["command"].as_str().unwrap(), "my-special-cmd");
    }

    // ── help_banner ───────────────────────────────────────────────────────

    #[test]
    fn envelope_help_banner_matches_availability_help_text() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "test-cmd");
            assert_eq!(env.help_banner(), avail.help_text("test-cmd"));
        }
    }

    #[test]
    fn envelope_help_banner_embeds_command() {
        let env = CommandEnvelope::new(CommandAvailability::Unavailable, "batch-run");
        assert!(env.help_banner().contains("batch-run"));
    }

    // ── exit_code ─────────────────────────────────────────────────────────

    #[test]
    fn envelope_exit_code_matches_availability() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "cmd");
            assert_eq!(env.exit_code(), avail.exit_code_u8());
        }
    }

    // ── Cross-cutting snapshot invariants for bead 29.7.3 ─────────────────

    #[test]
    fn snapshot_all_seven_states_have_distinct_output_tuple() {
        // Invariant: (tag, compact_label, cli_symbol, exit_code, severity_rank)
        // must be unique for every variant.
        let tuples: Vec<_> = ALL_AVAILABILITY
            .iter()
            .map(|a| {
                (
                    a.tag(),
                    a.compact_label(),
                    a.cli_symbol(),
                    a.exit_code_u8(),
                    a.severity_rank(),
                )
            })
            .collect();
        for (i, a) in tuples.iter().enumerate() {
            for (j, b) in tuples.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        a, b,
                        "Variants {} and {} have identical output tuples",
                        i, j
                    );
                }
            }
        }
    }

    #[test]
    fn snapshot_envelope_json_shape_is_stable_across_variants() {
        let required_keys = [
            "availability",
            "command",
            "authoritative",
            "explanation",
            "recoverable",
            "next_actions",
        ];
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "test");
            let json = serde_json::to_value(&env).unwrap();
            let obj = json.as_object().unwrap();
            for key in &required_keys {
                assert!(
                    obj.contains_key(*key),
                    "{:?} envelope JSON missing key: {}",
                    avail,
                    key
                );
            }
        }
    }

    #[test]
    fn snapshot_inject_then_extract_round_trip() {
        // Verify that inject_into produces data that can be deserialized
        // back into a CommandEnvelope-like structure.
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "round-trip");
            let mut payload = json!({"data": "test"});
            env.inject_into(&mut payload);

            let avail_obj = &payload["availability"];
            assert_eq!(avail_obj["command"].as_str().unwrap(), "round-trip");
            assert_eq!(avail_obj["availability"].as_str().unwrap(), avail.tag());
            assert_eq!(
                avail_obj["authoritative"].as_bool().unwrap(),
                avail.is_authoritative()
            );
            assert_eq!(
                avail_obj["recoverable"].as_bool().unwrap(),
                avail.is_recoverable()
            );
            // Original data preserved
            assert_eq!(payload["data"], "test");
        }
    }

    #[test]
    fn snapshot_denied_exit_code_is_distinct_from_unavailable() {
        // Critical invariant: Denied (policy) and Unavailable (transport)
        // must have different exit codes so agents can distinguish them.
        assert_ne!(
            CommandAvailability::Denied.exit_code_u8(),
            CommandAvailability::Unavailable.exit_code_u8(),
        );
    }

    #[test]
    fn snapshot_unsupported_exit_code_is_distinct_from_denied() {
        assert_ne!(
            CommandAvailability::Unsupported.exit_code_u8(),
            CommandAvailability::Denied.exit_code_u8(),
        );
    }

    #[test]
    fn snapshot_planned_exit_code_is_success() {
        // Planned is exit 0 because the output (contract preview) is valid data.
        assert_eq!(CommandAvailability::Planned.exit_code_u8(), 0);
    }

    #[test]
    fn snapshot_no_silent_fallback_test() {
        // Invariant: OfflineArtifact must never claim to be authoritative.
        // If this test fails, it means someone added a silent fallback where
        // offline data pretends to be live.
        let offline_env = CommandEnvelope::new(CommandAvailability::OfflineArtifact, "list");
        assert!(!offline_env.authoritative);
        assert!(offline_env.explanation.contains("offline"));
        assert!(!offline_env.next_actions.is_empty());
    }

    #[test]
    fn snapshot_transcript_entries_are_valid_json_for_all_variants() {
        for avail in &ALL_AVAILABILITY {
            let env = CommandEnvelope::new(avail.clone(), "test");
            let entry = env.transcript_entry();
            // Must be a valid JSON object (not null, not array)
            assert!(entry.is_object(), "{:?} transcript is not an object", avail);
            // Must round-trip through serialization
            let serialized = serde_json::to_string(&entry).unwrap();
            let parsed: Value = serde_json::from_str(&serialized).unwrap();
            assert_eq!(entry, parsed, "{:?} transcript round-trip failed", avail);
        }
    }

    #[test]
    fn snapshot_compact_labels_are_uppercase_prefix() {
        // Convention: compact labels start with an UPPERCASE word
        for avail in &ALL_AVAILABILITY {
            let label = avail.compact_label();
            let first_char = label.chars().next().unwrap();
            assert!(
                first_char.is_uppercase(),
                "{:?} compact_label '{}' doesn't start uppercase",
                avail,
                label,
            );
        }
    }

    #[test]
    fn snapshot_help_text_distinct_for_all_variants() {
        let texts: Vec<String> = ALL_AVAILABILITY
            .iter()
            .map(|a| a.help_text("cmd"))
            .collect();
        let unique: std::collections::HashSet<&str> = texts.iter().map(String::as_str).collect();
        assert_eq!(texts.len(), unique.len(), "Duplicate help_text outputs");
    }

    #[test]
    fn snapshot_severity_rank_is_monotonically_increasing_with_severity() {
        // Success states should be 0-1, planning 2, errors 3+
        assert!(CommandAvailability::LiveRuntime.severity_rank() < 2);
        assert!(CommandAvailability::OfflineArtifact.severity_rank() < 2);
        assert!(CommandAvailability::Planned.severity_rank() < 3);
        assert!(CommandAvailability::Unsupported.severity_rank() >= 3);
        assert!(CommandAvailability::Unknown.severity_rank() >= 3);
        assert!(CommandAvailability::Unavailable.severity_rank() >= 3);
        assert!(CommandAvailability::Denied.severity_rank() >= 3);
    }

    // ── CommandTruthMode ─────────────────────────────────────────────────

    const ALL_TRUTH_MODES: [CommandTruthMode; 5] = [
        CommandTruthMode::LiveOnly,
        CommandTruthMode::OfflineOnly,
        CommandTruthMode::Hybrid,
        CommandTruthMode::Passthrough,
        CommandTruthMode::PlannedOnly,
    ];

    #[test]
    fn truth_mode_tags_are_stable_kebab_case() {
        let expected = [
            "live-only",
            "offline-only",
            "hybrid",
            "passthrough",
            "planned-only",
        ];
        for (mode, tag) in ALL_TRUTH_MODES.iter().zip(expected.iter()) {
            assert_eq!(mode.tag(), *tag, "{:?}", mode);
        }
    }

    #[test]
    fn truth_mode_tags_are_all_unique() {
        let tags: Vec<&str> = ALL_TRUTH_MODES.iter().map(|m| m.tag()).collect();
        let unique: std::collections::HashSet<&str> = tags.iter().copied().collect();
        assert_eq!(tags.len(), unique.len());
    }

    #[test]
    fn truth_mode_descriptions_are_all_non_empty() {
        for mode in &ALL_TRUTH_MODES {
            assert!(!mode.description().is_empty(), "{:?}", mode);
        }
    }

    #[test]
    fn truth_mode_descriptions_are_all_unique() {
        let descs: Vec<&str> = ALL_TRUTH_MODES.iter().map(|m| m.description()).collect();
        let unique: std::collections::HashSet<&str> = descs.iter().copied().collect();
        assert_eq!(descs.len(), unique.len());
    }

    #[test]
    fn truth_mode_can_be_authoritative_only_live_and_hybrid() {
        assert!(CommandTruthMode::LiveOnly.can_be_authoritative());
        assert!(CommandTruthMode::Hybrid.can_be_authoritative());
        assert!(!CommandTruthMode::OfflineOnly.can_be_authoritative());
        assert!(!CommandTruthMode::Passthrough.can_be_authoritative());
        assert!(!CommandTruthMode::PlannedOnly.can_be_authoritative());
    }

    #[test]
    fn truth_mode_serde_round_trip() {
        for mode in &ALL_TRUTH_MODES {
            let json = serde_json::to_string(mode).unwrap();
            let back: CommandTruthMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, back, "round-trip failed for {:?}", mode);
        }
    }

    #[test]
    fn truth_mode_serde_uses_kebab_case() {
        let json = serde_json::to_string(&CommandTruthMode::LiveOnly).unwrap();
        assert_eq!(json, "\"live-only\"");
        let json = serde_json::to_string(&CommandTruthMode::PlannedOnly).unwrap();
        assert_eq!(json, "\"planned-only\"");
    }

    #[test]
    fn truth_mode_clone_and_eq() {
        for mode in &ALL_TRUTH_MODES {
            let cloned = mode.clone();
            assert_eq!(*mode, cloned);
        }
    }

    #[test]
    fn truth_mode_debug_contains_variant_name() {
        assert!(format!("{:?}", CommandTruthMode::LiveOnly).contains("LiveOnly"));
        assert!(format!("{:?}", CommandTruthMode::Passthrough).contains("Passthrough"));
    }

    // ── COMMAND_FAMILY_CLASSIFICATION ────────────────────────────────────

    #[test]
    fn family_classification_has_no_duplicates() {
        let names: Vec<&str> = COMMAND_FAMILY_CLASSIFICATION
            .iter()
            .map(|e| e.name)
            .collect();
        let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(
            names.len(),
            unique.len(),
            "Duplicate command names in COMMAND_FAMILY_CLASSIFICATION"
        );
    }

    #[test]
    fn family_classification_names_are_non_empty() {
        for entry in COMMAND_FAMILY_CLASSIFICATION {
            assert!(!entry.name.is_empty());
        }
    }

    #[test]
    fn family_classification_names_are_lowercase_kebab() {
        for entry in COMMAND_FAMILY_CLASSIFICATION {
            assert!(
                entry
                    .name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-'),
                "Command name '{}' is not lowercase-kebab",
                entry.name,
            );
        }
    }

    #[test]
    fn family_classification_covers_live_only_commands() {
        let live: Vec<&str> = COMMAND_FAMILY_CLASSIFICATION
            .iter()
            .filter(|e| e.mode == CommandTruthMode::LiveOnly)
            .map(|e| e.name)
            .collect();
        assert!(live.contains(&"invoke"));
        assert!(live.contains(&"batch"));
        assert!(live.contains(&"batch-file"));
        assert!(live.contains(&"doctor"));
        assert!(live.contains(&"status"));
        assert!(live.len() >= 10, "Expected at least 10 live-only commands");
    }

    #[test]
    fn family_classification_covers_offline_only_commands() {
        let offline: Vec<&str> = COMMAND_FAMILY_CLASSIFICATION
            .iter()
            .filter(|e| e.mode == CommandTruthMode::OfflineOnly)
            .map(|e| e.name)
            .collect();
        assert!(offline.contains(&"context"));
        assert!(offline.contains(&"session"));
        assert!(offline.contains(&"guide"));
        assert!(offline.contains(&"config"));
    }

    #[test]
    fn family_classification_covers_hybrid_commands() {
        let hybrid: Vec<&str> = COMMAND_FAMILY_CLASSIFICATION
            .iter()
            .filter(|e| e.mode == CommandTruthMode::Hybrid)
            .map(|e| e.name)
            .collect();
        assert!(hybrid.contains(&"list"));
        assert!(hybrid.contains(&"show"));
        assert!(hybrid.contains(&"ops"));
        assert!(hybrid.contains(&"export-tools"));
    }

    #[test]
    fn family_classification_covers_passthrough_commands() {
        let passthrough: Vec<&str> = COMMAND_FAMILY_CLASSIFICATION
            .iter()
            .filter(|e| e.mode == CommandTruthMode::Passthrough)
            .map(|e| e.name)
            .collect();
        assert!(passthrough.contains(&"supply-chain"));
        assert!(passthrough.contains(&"audit"));
        assert!(passthrough.contains(&"manifest"));
    }

    #[test]
    fn family_classification_serve_mcp_is_planned_only() {
        let entry = classify_command("serve-mcp").unwrap();
        assert_eq!(entry.mode, CommandTruthMode::PlannedOnly);
    }

    #[test]
    fn family_classification_all_five_modes_represented() {
        let modes: std::collections::HashSet<&str> = COMMAND_FAMILY_CLASSIFICATION
            .iter()
            .map(|e| e.mode.tag())
            .collect();
        assert!(modes.contains("live-only"));
        assert!(modes.contains("offline-only"));
        assert!(modes.contains("hybrid"));
        assert!(modes.contains("passthrough"));
        assert!(modes.contains("planned-only"));
    }

    #[test]
    fn family_classification_serializes_to_json_array() {
        let json = serde_json::to_value(COMMAND_FAMILY_CLASSIFICATION).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(arr.len(), COMMAND_FAMILY_CLASSIFICATION.len());
        let first = &arr[0];
        assert!(first.get("name").is_some());
        assert!(first.get("mode").is_some());
    }

    // ── classify_command ─────────────────────────────────────────────────

    #[test]
    fn classify_command_returns_correct_entry() {
        let entry = classify_command("invoke").unwrap();
        assert_eq!(entry.name, "invoke");
        assert_eq!(entry.mode, CommandTruthMode::LiveOnly);
    }

    #[test]
    fn classify_command_returns_none_for_unknown() {
        assert!(classify_command("nonexistent-command").is_none());
        assert!(classify_command("").is_none());
    }

    #[test]
    fn classify_command_is_case_sensitive() {
        assert!(classify_command("INVOKE").is_none());
        assert!(classify_command("Invoke").is_none());
    }

    #[test]
    fn classify_command_every_table_entry_round_trips() {
        for entry in COMMAND_FAMILY_CLASSIFICATION {
            let found = classify_command(entry.name).unwrap();
            assert_eq!(found.name, entry.name);
            assert_eq!(found.mode, entry.mode);
        }
    }

    #[test]
    fn classify_command_static_lifetime_borrow() {
        // Ensure the returned reference has 'static lifetime.
        let entry: &'static CommandFamilyEntry = classify_command("list").unwrap();
        assert_eq!(entry.name, "list");
    }

    // ── Cross-cutting truth-boundary invariants ──────────────────────────

    #[test]
    fn truth_mode_live_commands_cannot_be_offline_artifact() {
        // A live-only command should never produce OfflineArtifact availability.
        // This is a design contract — just verify the classification is consistent.
        for entry in COMMAND_FAMILY_CLASSIFICATION {
            if entry.mode == CommandTruthMode::LiveOnly {
                assert!(
                    entry.mode.can_be_authoritative(),
                    "Live-only command '{}' must be able to produce authoritative data",
                    entry.name,
                );
            }
        }
    }

    #[test]
    fn truth_mode_offline_commands_are_not_authoritative() {
        for entry in COMMAND_FAMILY_CLASSIFICATION {
            if entry.mode == CommandTruthMode::OfflineOnly {
                assert!(
                    !entry.mode.can_be_authoritative(),
                    "Offline-only command '{}' should not be authoritative",
                    entry.name,
                );
            }
        }
    }

    #[test]
    fn truth_mode_planned_commands_are_not_authoritative() {
        for entry in COMMAND_FAMILY_CLASSIFICATION {
            if entry.mode == CommandTruthMode::PlannedOnly {
                assert!(
                    !entry.mode.can_be_authoritative(),
                    "Planned-only command '{}' should not be authoritative",
                    entry.name,
                );
            }
        }
    }

    #[test]
    fn family_entry_debug_shows_name_and_mode() {
        let entry = classify_command("invoke").unwrap();
        let dbg = format!("{:?}", entry);
        assert!(dbg.contains("invoke"));
        assert!(dbg.contains("LiveOnly"));
    }

    #[test]
    fn family_classification_minimum_count() {
        // Ensure we haven't accidentally truncated the table.
        assert!(
            COMMAND_FAMILY_CLASSIFICATION.len() >= 40,
            "Expected at least 40 classified commands, got {}",
            COMMAND_FAMILY_CLASSIFICATION.len(),
        );
    }

    #[test]
    fn classify_command_batch_file_is_live_only() {
        let entry = classify_command("batch-file").unwrap();
        assert_eq!(entry.mode, CommandTruthMode::LiveOnly);
    }

    #[test]
    fn classify_command_template_is_hybrid() {
        let entry = classify_command("template").unwrap();
        assert_eq!(entry.mode, CommandTruthMode::Hybrid);
    }

    #[test]
    fn classify_command_audit_is_passthrough() {
        let entry = classify_command("audit").unwrap();
        assert_eq!(entry.mode, CommandTruthMode::Passthrough);
    }

    #[test]
    fn classify_command_session_is_offline_only() {
        let entry = classify_command("session").unwrap();
        assert_eq!(entry.mode, CommandTruthMode::OfflineOnly);
    }
}
