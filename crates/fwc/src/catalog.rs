use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ── Command source-of-truth classification ──────────────────────────────────
// Backbone types consumed by downstream beads (1g7z0.29.1.2+). The public API
// is intentionally broader than current callers.
#[allow(dead_code)]
/// Authoritative source of truth for a command's runtime data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandTruthSource {
    /// The command's output is authoritative only when backed by a live host.
    /// Without the host, the command must refuse or explicitly degrade.
    LiveHost,
    /// The command works entirely from local artifacts (manifests, files, history).
    /// No host connection is needed or attempted.
    OfflineArtifact,
    /// The command can operate in both modes with explicitly different behavior.
    /// When offline, output must be clearly labeled as potentially stale.
    Hybrid,
    /// The command is a passthrough to a separate subsystem with its own truth model.
    Passthrough,
}

#[allow(dead_code)]
/// Execution mode for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandExecutionMode {
    /// Read-only query (no side effects, no auth required).
    ReadOnly,
    /// Side-effecting mutation (requires auth, may need approval tokens).
    Mutating,
    /// Simulation or preflight (read-only but may reach connectors).
    Simulate,
    /// Interactive/streaming session (long-lived host connection).
    Interactive,
    /// Local-only computation (no network, no auth).
    LocalOnly,
}

#[allow(dead_code)]
/// What happens when the host is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostAbsentBehavior {
    /// The command fails immediately with a clear error.
    FailFast,
    /// The command falls back to offline data with a visible warning.
    DegradedWithWarning,
    /// The command works normally (doesn't need the host).
    Unaffected,
    /// Behavior depends on the subsystem.
    PassthroughDependent,
}

#[allow(dead_code)]
/// Full source-of-truth classification for a single command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandClassification {
    /// Command name as used on the CLI.
    pub command: &'static str,
    /// Where this command's authoritative data comes from.
    pub truth_source: CommandTruthSource,
    /// How the command executes.
    pub execution_mode: CommandExecutionMode,
    /// What happens when the host is absent.
    pub host_absent: HostAbsentBehavior,
    /// Whether the command requires a capability token.
    pub requires_capability_token: bool,
    /// Whether the command may need approval tokens.
    pub may_need_approval: bool,
    /// Brief explanation of the transport/truth model.
    pub transport_note: &'static str,
}

#[allow(dead_code)]
/// Static classification of every `fwc` command by source of truth.
///
/// This is the single authoritative matrix that determines how each command
/// behaves with respect to the host, offline mode, and auth requirements.
pub const COMMAND_CLASSIFICATIONS: &[CommandClassification] = &[
    // ── Offline-first commands (no host needed) ─────────────────────────
    CommandClassification {
        command: "guide",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Static contract documentation, fully local",
    },
    CommandClassification {
        command: "task",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local workflow capsule management",
    },
    CommandClassification {
        command: "plan",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Intent analysis from local manifest catalog",
    },
    CommandClassification {
        command: "explain",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Intent explanation from local catalog",
    },
    CommandClassification {
        command: "history",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local execution history file",
    },
    CommandClassification {
        command: "pipe",
        truth_source: CommandTruthSource::OfflineArtifact,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::Unaffected,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Local JQ-style data transformation, no connector calls",
    },
    // ── Dual-source commands (live by default, explicit offline opt-in) ─
    CommandClassification {
        command: "list",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host inventory by default; use --offline for explicit manifest-backed output",
    },
    CommandClassification {
        command: "search",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host search by default; use --offline for explicit manifest-backed search",
    },
    CommandClassification {
        command: "show",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host introspection by default; use --offline for explicit manifest detail",
    },
    CommandClassification {
        command: "ops",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host operation list by default; use --offline for explicit manifest data",
    },
    CommandClassification {
        command: "schema",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host schema by default; use --offline for explicit manifest schema",
    },
    CommandClassification {
        command: "examples",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host examples by default; use --offline for explicit manifest examples",
    },
    CommandClassification {
        command: "suggest",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host suggestions by default; use --offline for explicit local catalog suggestions",
    },
    CommandClassification {
        command: "template",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host schema templating by default; use --offline for explicit manifest templating",
    },
    CommandClassification {
        command: "validate",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host schema validation by default; use --offline for explicit manifest validation",
    },
    CommandClassification {
        command: "export-tools",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Live host tool export by default; use --offline for explicit manifest-backed export",
    },
    CommandClassification {
        command: "do",
        truth_source: CommandTruthSource::Hybrid,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::DegradedWithWarning,
        requires_capability_token: false,
        may_need_approval: true,
        transport_note: "Intent dispatch: invokes live host when available, plans offline otherwise",
    },
    // ── Live-host-required commands ─────────────────────────────────────
    CommandClassification {
        command: "invoke",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "POST /rpc/invoke — requires live host, capability token, may need approvals",
    },
    CommandClassification {
        command: "simulate",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Simulate,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: false,
        transport_note: "POST /rpc/simulate — requires live host, capability token",
    },
    CommandClassification {
        command: "cancel",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: false,
        transport_note: "POST /rpc/cancel — requires live host and active operation",
    },
    CommandClassification {
        command: "serve-mcp",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Interactive,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "Long-lived MCP session proxying to live host",
    },
    CommandClassification {
        command: "doctor",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "GET /health — live host health and connector diagnostics",
    },
    CommandClassification {
        command: "status",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "GET /rpc/admin/status — live host connector status",
    },
    CommandClassification {
        command: "budget",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "GET /rpc/budget — live host budget snapshot",
    },
    CommandClassification {
        command: "capabilities",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::ReadOnly,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/capabilities — live host capability report",
    },
    CommandClassification {
        command: "install",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/install — live host connector install",
    },
    CommandClassification {
        command: "update",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/update — live host connector update",
    },
    CommandClassification {
        command: "pin",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/pin — live host version pinning",
    },
    CommandClassification {
        command: "unpin",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/unpin — live host version unpinning",
    },
    CommandClassification {
        command: "rollout",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/rollout — live host rollout management",
    },
    CommandClassification {
        command: "config",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "POST /rpc/config — live host config management",
    },
    CommandClassification {
        command: "map",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "Parallel POST /rpc/invoke — batch invocation, requires live host",
    },
    CommandClassification {
        command: "batch-file",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "Sequential POST /rpc/invoke — file-driven batch, requires live host",
    },
    CommandClassification {
        command: "recipe",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "Multi-step recipe execution via live host",
    },
    CommandClassification {
        command: "pipeline",
        truth_source: CommandTruthSource::LiveHost,
        execution_mode: CommandExecutionMode::Mutating,
        host_absent: HostAbsentBehavior::FailFast,
        requires_capability_token: true,
        may_need_approval: true,
        transport_note: "Multi-step pipeline execution via live host",
    },
    // ── Passthrough commands ────────────────────────────────────────────
    CommandClassification {
        command: "supply-chain",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Supply chain verification subsystem",
    },
    CommandClassification {
        command: "audit",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Audit chain subsystem",
    },
    CommandClassification {
        command: "manifest",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Manifest validation subsystem",
    },
    CommandClassification {
        command: "net",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Network policy subsystem",
    },
    CommandClassification {
        command: "trace",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Trace replay subsystem",
    },
    CommandClassification {
        command: "policy",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Policy simulation subsystem",
    },
    CommandClassification {
        command: "package",
        truth_source: CommandTruthSource::Passthrough,
        execution_mode: CommandExecutionMode::LocalOnly,
        host_absent: HostAbsentBehavior::PassthroughDependent,
        requires_capability_token: false,
        may_need_approval: false,
        transport_note: "Connector packaging subsystem",
    },
];

#[allow(dead_code)]
/// Look up the classification for a command by name.
#[must_use]
pub fn classify_command(command: &str) -> Option<&'static CommandClassification> {
    COMMAND_CLASSIFICATIONS
        .iter()
        .find(|c| c.command == command)
}

#[allow(dead_code)]
/// Return all commands that require a live host.
#[must_use]
pub fn live_host_commands() -> Vec<&'static str> {
    COMMAND_CLASSIFICATIONS
        .iter()
        .filter(|c| c.truth_source == CommandTruthSource::LiveHost)
        .map(|c| c.command)
        .collect()
}

#[allow(dead_code)]
/// Return all commands that can work offline.
#[must_use]
pub fn offline_capable_commands() -> Vec<&'static str> {
    COMMAND_CLASSIFICATIONS
        .iter()
        .filter(|c| {
            matches!(
                c.truth_source,
                CommandTruthSource::OfflineArtifact | CommandTruthSource::Hybrid
            )
        })
        .map(|c| c.command)
        .collect()
}

#[allow(dead_code)]
/// Return all commands requiring a capability token.
#[must_use]
pub fn auth_required_commands() -> Vec<&'static str> {
    COMMAND_CLASSIFICATIONS
        .iter()
        .filter(|c| c.requires_capability_token)
        .map(|c| c.command)
        .collect()
}

// ── Host-absent fail-fast error types ────────────────────────────────────────

/// Why the host is not available.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostAbsentReason {
    /// No host endpoint configured (no --host, no FWC_HOST, no context).
    NotConfigured,
    /// Host endpoint configured but connection refused or timed out.
    Unreachable,
    /// Host responded but health check indicated degraded/unavailable.
    Unhealthy,
}

/// Structured error envelope returned when a command requires a live host
/// but the host is absent, unreachable, or unhealthy.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostAbsentError {
    /// The command that was attempted.
    pub command: String,
    /// Why the host is absent.
    pub reason: HostAbsentReason,
    /// Stable error type for agent/script branching.
    pub error_type: &'static str,
    /// Human-readable message explaining the failure.
    pub message: String,
    /// Whether the error is recoverable by the caller.
    pub recoverable: bool,
    /// Remediation hints ordered from most to least likely to help.
    pub next_actions: Vec<String>,
    /// The exit code the CLI should use.
    pub exit_code: u8,
}

/// Build a structured host-absent error from the command classification.
///
/// This is the single place that determines what error message, remediation
/// hints, and exit code a command gets when the host is unavailable. Downstream
/// consumers (dispatch functions, render pipeline) should use this rather than
/// hand-rolling their own error payloads.
#[allow(dead_code)]
#[must_use]
pub fn host_absent_error(command: &str, reason: HostAbsentReason) -> HostAbsentError {
    let classification = classify_command(command);

    let error_type = match reason {
        HostAbsentReason::NotConfigured => "missing-host-endpoint",
        HostAbsentReason::Unreachable => "host-unreachable",
        HostAbsentReason::Unhealthy => "host-unhealthy",
    };

    let message = match reason {
        HostAbsentReason::NotConfigured => format!(
            "`{command}` requires a live `fcp-host` endpoint. \
             `fwc` will not simulate runtime behavior or fabricate results."
        ),
        HostAbsentReason::Unreachable => format!(
            "`{command}` could not reach the configured `fcp-host` endpoint. \
             The host may be down, or the endpoint may be misconfigured."
        ),
        HostAbsentReason::Unhealthy => format!(
            "`{command}` reached the `fcp-host` endpoint but the host reports \
             unhealthy status. Operations may not be reliable."
        ),
    };

    let mut next_actions = Vec::new();

    // Remediation hints depend on the reason and classification
    match reason {
        HostAbsentReason::NotConfigured => {
            next_actions.push(format!(
                "Set a host endpoint: `fwc {command} --host <endpoint>`"
            ));
            next_actions.push("Set FWC_HOST or FCP_HOST_ENDPOINT environment variable".to_owned());
            next_actions.push("Create a context: `fwc context create --endpoint <url>`".to_owned());
        }
        HostAbsentReason::Unreachable => {
            next_actions
                .push("Check that fcp-host is running: `fwc doctor --host <endpoint>`".to_owned());
            next_actions.push("Verify the endpoint URL/socket is correct".to_owned());
            next_actions.push("Check network connectivity to the host".to_owned());
        }
        HostAbsentReason::Unhealthy => {
            next_actions
                .push("Check host health details: `fwc doctor --host <endpoint>`".to_owned());
            next_actions.push("Wait for the host to recover, then retry".to_owned());
        }
    }

    // If the command is Hybrid, suggest the offline alternative
    if let Some(cls) = classification {
        if cls.truth_source == CommandTruthSource::Hybrid {
            next_actions.push(format!(
                "Use `fwc {command} --offline` to inspect workspace manifests \
                 (results may be stale)."
            ));
        }
    }

    HostAbsentError {
        command: command.to_owned(),
        reason,
        error_type,
        message,
        recoverable: true,
        next_actions,
        exit_code: 8, // CliExitCode::Transport
    }
}

/// Convert a `HostAbsentError` into a JSON payload suitable for rendering.
#[allow(dead_code)]
#[must_use]
pub fn host_absent_error_payload(error: &HostAbsentError) -> Value {
    json!({
        "status": "error",
        "command": error.command,
        "error": {
            "type": error.error_type,
            "reason": error.reason,
            "message": error.message,
            "recoverable": error.recoverable,
        },
        "next_actions": error.next_actions,
    })
}

/// Check whether a command should fail fast when the host is absent.
///
/// Returns `true` if the command's classification says it must have a live
/// host (`FailFast` behavior). Returns `false` for offline, degraded, or
/// passthrough commands.
#[allow(dead_code)]
#[must_use]
pub fn command_requires_host(command: &str) -> bool {
    classify_command(command).is_some_and(|cls| cls.host_absent == HostAbsentBehavior::FailFast)
}

// ── Offline provenance contract ──────────────────────────────────────────────
// Defines how offline/artifact-backed output is labeled so agents and users
// never confuse it with live host truth.

/// Where offline data comes from.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OfflineSource {
    /// Data from workspace manifest files (TOML/JSON on disk).
    WorkspaceManifest,
    /// Data from a local discovery catalog cache.
    LocalCatalog,
    /// Data from local execution history.
    LocalHistory,
    /// Data from static embedded contract documentation.
    StaticContract,
    /// Data from a passthrough subsystem (audit, supply-chain, etc.).
    Subsystem,
}

/// Provenance envelope attached to any output that comes from offline sources.
///
/// Every response from an offline or hybrid-offline command must include this
/// marker so consumers know the data is not from a live host.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineProvenance {
    /// True when the output comes from offline/artifact sources.
    pub offline: bool,
    /// Where the data originated.
    pub source: OfflineSource,
    /// Human-readable caveat about the data's authority.
    pub caveat: &'static str,
    /// Suggested next step to get authoritative live data.
    pub live_alternative: Option<String>,
}

/// Standard provenance caveats for each offline source type.
#[allow(dead_code)]
const fn offline_caveat(source: OfflineSource) -> &'static str {
    match source {
        OfflineSource::WorkspaceManifest => {
            "This output is derived from workspace manifest files. \
             It may not reflect the current live host state."
        }
        OfflineSource::LocalCatalog => {
            "This output is from a local discovery catalog cache. \
             The live host may have different connectors or versions."
        }
        OfflineSource::LocalHistory => {
            "This output is from local execution history. \
             It records past operations, not current host state."
        }
        OfflineSource::StaticContract => {
            "This output is from static contract documentation. \
             It describes the intended behavior, not runtime state."
        }
        OfflineSource::Subsystem => {
            "This output is from a local subsystem. \
             It may depend on external state not verified here."
        }
    }
}

/// Build a provenance marker for a command operating in offline mode.
#[allow(dead_code)]
#[must_use]
pub fn offline_provenance(command: &str, source: OfflineSource) -> OfflineProvenance {
    let live_alternative = classify_command(command).and_then(|cls| {
        if cls.truth_source == CommandTruthSource::Hybrid {
            Some(format!(
                "For live host data: `fwc {command} --host <endpoint>` (omit --offline)"
            ))
        } else {
            None
        }
    });

    OfflineProvenance {
        offline: true,
        source,
        caveat: offline_caveat(source),
        live_alternative,
    }
}

/// Convert an `OfflineProvenance` into a JSON object suitable for embedding
/// in output payloads.
#[allow(dead_code)]
#[must_use]
pub fn offline_provenance_payload(prov: &OfflineProvenance) -> Value {
    let mut v = json!({
        "offline": prov.offline,
        "source": prov.source,
        "caveat": prov.caveat,
    });
    if let Some(alt) = &prov.live_alternative {
        v["live_alternative"] = json!(alt);
    }
    v
}

/// Determine the appropriate offline source for a command based on its
/// classification.
#[allow(dead_code)]
#[must_use]
pub fn default_offline_source(command: &str) -> OfflineSource {
    match classify_command(command).map(|c| c.truth_source) {
        Some(CommandTruthSource::OfflineArtifact) => {
            // Refine based on specific command
            match command {
                "guide" => OfflineSource::StaticContract,
                "history" => OfflineSource::LocalHistory,
                "pipe" => OfflineSource::LocalHistory,
                _ => OfflineSource::LocalCatalog,
            }
        }
        Some(CommandTruthSource::Hybrid) => OfflineSource::WorkspaceManifest,
        Some(CommandTruthSource::Passthrough) => OfflineSource::Subsystem,
        _ => OfflineSource::LocalCatalog,
    }
}

/// Help text contract for offline commands, describing what `--offline` means.
#[allow(dead_code)]
pub const OFFLINE_FLAG_HELP: &str = "\
Operate on workspace manifests and local artifacts instead of a live host. \
Output is labeled with provenance markers showing the data source.";

/// Help text contract for hybrid commands explaining the mode switch.
#[allow(dead_code)]
pub const HYBRID_MODE_HELP: &str = "\
By default, this command queries the live host. Pass `--offline` to explicitly \
use workspace manifests instead. Offline results include provenance markers \
and a caveat that the data may not reflect current host state.";

// ── Auth UX contract ─────────────────────────────────────────────────────────
// These types define how the CLI should guide users/agents through capability
// token acquisition, attachment, denial, and remediation on live auth-gated
// paths. No test-token placeholders, no empty approvals, no silent bypass.

/// What the CLI should do when a capability token is needed for a command.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthAcquisitionFlow {
    /// Token is required — prompt the user to issue or supply one.
    Required,
    /// Token is optional but recommended — warn if absent.
    Recommended,
    /// Token is not needed for this command.
    NotNeeded,
}

/// Structured auth UX guidance for a command, derived from its classification.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUxGuidance {
    /// The command name.
    pub command: String,
    /// Token acquisition flow.
    pub acquisition: AuthAcquisitionFlow,
    /// Whether approval tokens may also be needed.
    pub may_need_approval: bool,
    /// How the user should supply the token.
    pub supply_methods: Vec<String>,
    /// What to show when auth is missing.
    pub missing_guidance: String,
    /// What to show when auth is denied.
    pub denial_guidance: String,
}

/// Build auth UX guidance for a command based on its classification.
#[allow(dead_code)]
#[must_use]
pub fn auth_ux_guidance(command: &str) -> AuthUxGuidance {
    let cls = classify_command(command);

    let (acquisition, may_need_approval) =
        cls.map_or((AuthAcquisitionFlow::NotNeeded, false), |c| {
            if c.requires_capability_token {
                (AuthAcquisitionFlow::Required, c.may_need_approval)
            } else {
                (AuthAcquisitionFlow::NotNeeded, false)
            }
        });

    let supply_methods = if acquisition == AuthAcquisitionFlow::Required {
        vec![
            "--capability-token <base64>".to_owned(),
            "FWC_CAPABILITY_TOKEN environment variable".to_owned(),
            "fwc capabilities issue --connector <id> --operation <op>".to_owned(),
        ]
    } else {
        vec![]
    };

    let missing_guidance = if acquisition == AuthAcquisitionFlow::Required {
        format!(
            "`{command}` requires a capability token. Issue one with \
             `fwc capabilities issue` or pass via --capability-token."
        )
    } else {
        String::new()
    };

    let denial_guidance = if acquisition == AuthAcquisitionFlow::Required {
        format!(
            "Auth denied for `{command}`. Check that your token covers \
             the target connector and operation, and is not expired or revoked."
        )
    } else {
        String::new()
    };

    AuthUxGuidance {
        command: command.to_owned(),
        acquisition,
        may_need_approval,
        supply_methods,
        missing_guidance,
        denial_guidance,
    }
}

/// Verify that a command's auth requirements are met before dispatching.
///
/// Returns `None` if auth requirements are satisfied (or not needed).
/// Returns `Some(guidance)` if the command needs auth that hasn't been provided.
#[allow(dead_code)]
#[must_use]
pub fn check_auth_requirement(command: &str, has_token: bool) -> Option<AuthUxGuidance> {
    let guidance = auth_ux_guidance(command);
    if guidance.acquisition == AuthAcquisitionFlow::Required && !has_token {
        Some(guidance)
    } else {
        None
    }
}

// ── Workflow execution truth contract ────────────────────────────────────────
// Types for pipe, recipe, and pipeline to honestly report whether they're
// executing through real host primitives or merely planning/refusing.

/// The execution reality of a workflow step.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStepReality {
    /// Step executed through a real host-backed RPC with side effects.
    Executed,
    /// Step was planned/simulated but not executed.
    Planned,
    /// Step was refused because the host is unavailable.
    HostUnavailable,
    /// Step was refused because auth was denied.
    AuthDenied,
    /// Step was refused because the operation is unsupported.
    Unsupported,
    /// Step was skipped (upstream failure or conditional skip).
    Skipped,
}

/// How a workflow command should be classified for truthfulness.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowKind {
    /// Local data transformation (pipe). No side effects, no host needed.
    LocalTransform,
    /// Multi-step orchestrated execution (recipe, pipeline). Requires host.
    OrchestratedExecution,
}

/// Execution provenance for a workflow step, proving what actually happened.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowStepProvenance {
    /// Step identifier within the workflow.
    pub step_id: String,
    /// What actually happened.
    pub reality: WorkflowStepReality,
    /// The operation that was (or would have been) executed.
    pub operation: String,
    /// The connector targeted.
    pub connector: String,
    /// Receipt ID if the step was actually executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Reason for refusal, if refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
}

/// Determine the workflow kind for a command.
#[allow(dead_code)]
#[must_use]
pub fn workflow_kind(command: &str) -> Option<WorkflowKind> {
    match command {
        "pipe" => Some(WorkflowKind::LocalTransform),
        "recipe" | "pipeline" => Some(WorkflowKind::OrchestratedExecution),
        _ => None,
    }
}

/// Check whether a workflow command can proceed given the current context.
///
/// Returns `None` if the workflow can proceed.
/// Returns `Some(reality)` indicating why it cannot.
#[allow(dead_code)]
#[must_use]
pub fn workflow_can_proceed(
    command: &str,
    host_available: bool,
    has_token: bool,
) -> Option<WorkflowStepReality> {
    let kind = workflow_kind(command)?;

    match kind {
        WorkflowKind::LocalTransform => {
            // pipe never needs a host or token
            None
        }
        WorkflowKind::OrchestratedExecution => {
            if !host_available {
                Some(WorkflowStepReality::HostUnavailable)
            } else if !has_token {
                Some(WorkflowStepReality::AuthDenied)
            } else {
                None
            }
        }
    }
}

pub const COMMANDS: &[&str] = &[
    "guide",
    "task",
    "plan",
    "explain",
    "do",
    "list",
    "search",
    "show",
    "ops",
    "schema",
    "examples",
    "supply-chain",
    "audit",
    "manifest",
    "net",
    "trace",
    "policy",
    "package",
    "doctor",
    "status",
    "budget",
    "capabilities",
    "install",
    "update",
    "pin",
    "unpin",
    "rollout",
    "config",
    "invoke",
    "simulate",
    "cancel",
    "export-tools",
    "serve-mcp",
    "suggest",
    "template",
    "validate",
    "history",
    "pipe",
    "pipeline",
    "recipe",
    "map",
    "batch-file",
];

#[allow(clippy::too_many_lines)]
pub fn guide_payload(command: Option<&str>) -> Value {
    command.map_or_else(
        || {
            let commands = COMMANDS
                .iter()
                .filter_map(|command_name| command_contract(command_name))
                .collect::<Vec<_>>();

            json!({
                "status": "ok",
                "name": "fwc",
                "purpose": "Standalone Flywheel connector console for discovery, lifecycle management, configuration, and invocation across every connector.",
                "defaults": {
                    "format": "toon",
                    "reason": "TOON is the default because concise, agent-readable output is the baseline contract for this CLI.",
                    "json_opt_in": "--format json",
                    "workflow_bias": "intent-first progressive disclosure",
                },
                "exit_codes": {
                    "success": 0,
                    "parse_error": 2,
                    "unknown_command": 3,
                    "ambiguous_correction": 4,
                    "validation_error": 5,
                    "policy_denial": 6,
                    "connector_error": 7,
                    "transport_error": 8,
                    "internal_error": 1,
                },
                "recommended_workflow": [
                    "fwc task \"<intent>\"",
                    "fwc task resolve <task-id> --until ready",
                    "fwc task ask <task-id>",
                    "fwc task advance <task-id>",
                    "fwc task approve <task-id>",
                    "fwc task run <task-id>",
                    "fwc plan \"<intent>\"",
                    "fwc explain \"<intent>\"",
                    "fwc do \"<intent>\"",
                    "fwc do \"<intent>\" --approve",
                    "fwc list",
                    "fwc show <connector>",
                    "fwc ops <connector>",
                    "fwc schema <connector> <operation>",
                    "fwc config schema <connector>",
                    "fwc config doctor <connector>",
                    "fwc simulate <connector> <operation> --file payload.json",
                    "fwc invoke <connector> <operation> --file payload.json",
                ],
                "progressive_disclosure": [
                    {
                        "command": "task",
                        "contract": "Persist the whole workflow as a resumable capsule so agents can resolve draft bindings, answer one blocking question at a time, approve, and resume execution without restating the entire intent."
                    },
                    {
                        "command": "plan/explain/do",
                        "contract": "Start from intent, but compile down to explicit primitive commands, reasoning, and next actions instead of hiding the workflow."
                    },
                    {
                        "command": "list",
                        "contract": "Only show short, sortable connector summaries and health/lifecycle signals."
                    },
                    {
                        "command": "show",
                        "contract": "Expand one connector at a time into lifecycle, config, capability, and risk context."
                    },
                    {
                        "command": "ops",
                        "contract": "Stay operation-centric and avoid dumping schemas until the caller narrows scope."
                    },
                    {
                        "command": "schema",
                        "contract": "Reveal exactly one payload shape at a time so agents can build a valid request with minimal token waste."
                    },
                    {
                        "command": "simulate/invoke",
                        "contract": "Prefer explain/simulate before side effects, especially for risky or destructive operations."
                    }
                ],
                "families": [
                    {
                        "name": "workflow",
                        "commands": ["task"],
                    },
                    {
                        "name": "intent",
                        "commands": ["plan", "explain", "do"],
                    },
                    {
                        "name": "discovery",
                        "commands": ["list", "search", "show", "ops", "schema", "examples"],
                    },
                    {
                        "name": "evidence",
                        "commands": ["supply-chain", "audit", "manifest", "net", "trace", "policy", "package"],
                    },
                    {
                        "name": "lifecycle",
                        "commands": ["doctor", "status", "budget", "install", "update", "pin", "unpin", "rollout"],
                    },
                    {
                        "name": "capability-governance",
                        "commands": ["capabilities"],
                    },
                    {
                        "name": "config",
                        "commands": ["config"],
                    },
                    {
                        "name": "execution",
                        "commands": ["simulate", "invoke", "cancel", "export-tools", "serve-mcp", "suggest", "template", "validate", "history", "pipe", "pipeline", "recipe", "map", "batch-file"],
                    }
                ],
                "phase": {
                    "current_bead": "flywheel_connectors-1g7z0.2",
                    "current_scope": "Finalize the output contract so every `fwc` command emits deterministic TOON/JSON payloads, explicit exit semantics, and optional token-efficiency telemetry that agents can rely on.",
                    "follow_on_beads": [
                        "flywheel_connectors-1g7z0.2",
                        "flywheel_connectors-1g7z0.25",
                        "flywheel_connectors-1g7z0.18",
                        "flywheel_connectors-1g7z0.23",
                        "flywheel_connectors-1g7z0.6"
                    ],
                },
                "commands": commands,
            })
        },
        |command_name| {
            command_contract(command_name).map_or_else(
                || {
                    json!({
                        "status": "unknown-command",
                        "command": command_name,
                        "message": "No fwc command contract is registered under that name yet.",
                        "known_commands": COMMANDS,
                    })
                },
                |contract| {
                    json!({
                        "status": "ok",
                        "guide_scope": "command",
                        "command": command_name,
                        "contract": contract,
                    })
                },
            )
        },
    )
}

pub fn planned_payload(command: &str, captures: &Value) -> Value {
    command_contract(command).map_or_else(
        || {
            json!({
                "status": "unknown-command",
                "command": command,
                "captures": captures,
                "known_commands": COMMANDS,
            })
        },
        |contract| {
            json!({
                "status": "planned",
                "command": command,
                "phase": "ux-contract-preview",
                "message": "This is a structured contract preview for the command surface.",
                "captures": captures,
                "contract": contract,
            })
        },
    )
}

#[allow(clippy::too_many_lines)]
fn command_contract(command: &str) -> Option<Value> {
    match command {
        "guide" => Some(json!({
            "family": "meta",
            "summary": "Explain the fwc command taxonomy, defaults, and progressive-disclosure contract.",
            "intended_shape": "Structured guide that agents can read in TOON or JSON without scraping clap help.",
            "next_beads": ["flywheel_connectors-1g7z0.1", "flywheel_connectors-1g7z0.2"],
            "workflow_handoff": ["Use `fwc list` to begin discovery once host-backed data is wired in."],
        })),
        "task" => Some(workflow_contract(
            "Create and resume durable workflow capsules for connector jobs.",
            "A resumable capsule view over compiled intent, bindings, approvals, and execution receipts so agents can operate on a short task id instead of replaying the full workflow from scratch.",
        )),
        "plan" => Some(intent_contract(
            "Compile a natural-language goal into explicit primitive `fwc` steps.",
            "Transparent workflow plan with connector inference, operation hints, ambiguities, missing information, and exact next commands.",
        )),
        "explain" => Some(intent_contract(
            "Explain why the compiler chose a specific connector, template, and operation path.",
            "Reasoning-first output with connector evidence, action evidence, assumptions, and recovery hints.",
        )),
        "do" => Some(intent_contract(
            "Materialize the compiled workflow with safe-by-default simulation semantics.",
            "Executes only the safe prefix by default and stops before the first side-effecting primitive unless `--approve` is explicit.",
        )),
        "list" => Some(discovery_contract(
            "Show a low-token connector inventory with concise lifecycle and health state.",
            "Connector summaries grouped or filtered without expanding operation schemas.",
        )),
        "search" => Some(discovery_contract(
            "Search connectors and operations by ids, names, capabilities, or domains.",
            "Ranked search results with enough context to choose a single connector for `show` or `ops`.",
        )),
        "show" => Some(discovery_contract(
            "Expand one connector into lifecycle, config, capability, and risk context.",
            "One-connector detail view, still short enough to stay agent-readable by default.",
        )),
        "ops" => Some(discovery_contract(
            "List a connector's operations with risk, approvals, and brief input/output hints.",
            "Operation summaries that let the caller narrow to one operation before asking for schema.",
        )),
        "schema" => Some(discovery_contract(
            "Reveal exactly one connector contract or operation schema at a time.",
            "Single-schema output for a connector manifest contract or one connector operation.",
        )),
        "example" | "examples" => Some(discovery_contract(
            "Return a minimal example request or config snippet for one connector or operation.",
            "Copyable examples that stay small enough for agent reuse.",
        )),
        "supply-chain" => Some(json!({
            "family": "evidence",
            "summary": "Verify or summarize supply-chain evidence for a connector artifact.",
            "intended_shape": "Artifact-focused verification and reporting driven by real package metadata, attestations, and SBOM material.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc package` first if you need to generate fresh package metadata before verification."],
        })),
        "audit" => Some(json!({
            "family": "evidence",
            "summary": "Inspect audit-chain artifacts and reports.",
            "intended_shape": "Evidence-first audit workflows over retained chain material and host-backed reports.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc history` for operation-level receipts, or `fwc audit` when you need chain artifacts and verification detail."],
        })),
        "manifest" => Some(json!({
            "family": "evidence",
            "summary": "Validate, inspect, and repair connector manifests.",
            "intended_shape": "Manifest-centric verification and repair over real connector metadata.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc package` after manifest fixes so package metadata reflects the repaired manifest."],
        })),
        "net" => Some(json!({
            "family": "evidence",
            "summary": "Explain network egress allow and deny decisions for one manifest operation.",
            "intended_shape": "Focused policy explanation for connector network scope and operation-level egress requirements.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc manifest` or `fwc policy` when the network explanation reveals a policy mismatch."],
        })),
        "trace" => Some(json!({
            "family": "evidence",
            "summary": "Replay captured trace artifacts deterministically.",
            "intended_shape": "Trace-driven debugging and forensics over persisted capture bundles.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc history` or host-side capture tooling to gather the trace artifact you want to replay."],
        })),
        "policy" => Some(json!({
            "family": "evidence",
            "summary": "Diff, preview, and manage policy simulations and bundles.",
            "intended_shape": "Policy review and bundle management rooted in real policy evaluation logic rather than fabricated outcomes.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc simulate` or `fwc net` when you need operation-specific policy evidence before mutating state."],
        })),
        "package" => Some(json!({
            "family": "evidence",
            "summary": "Package a connector crate into a distributable artifact bundle.",
            "intended_shape": "Real build, manifest, SBOM, and metadata generation for connector artifacts.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": ["Use `fwc install` or `fwc update` with the generated package output directory once packaging completes."],
        })),
        "doctor" => Some(lifecycle_contract(
            "Diagnose live zone and connector health through `fcp-host`.",
            "Live host-backed report covering freshness, degraded mode, and optional connector self-checks.",
        )),
        "status" => Some(lifecycle_contract(
            "Report desired state, observed runtime state, and current health for one connector or the fleet.",
            "Desired-vs-observed lifecycle summary with audit-aware context.",
        )),
        "budget" => Some(lifecycle_contract(
            "Report current usage-budget state for configured zones through `fcp-host`.",
            "Live per-zone budget snapshots with exceeded-limit visibility and no fabricated usage data.",
        )),
        "capabilities" => Some(json!({
            "family": "capability-governance",
            "summary": "Report, recommend, and export capability usage using recorded execution history.",
            "intended_shape": "Least-privilege guidance rooted in real `fwc` history receipts and current connector metadata.",
            "next_beads": ["flywheel_connectors-1pjhh"],
            "workflow_handoff": [
                "Use `fwc history` to inspect the underlying receipts when a recommendation needs explanation.",
                "Use `fwc capabilities suggest` before tightening grants or policy bundles."
            ],
        })),
        "install" => Some(lifecycle_contract(
            "Install or verify a connector package into the persistent host inventory.",
            "Real package verification plus connector-inventory mutation without pretending the running host hot-reloaded.",
        )),
        "update" => Some(lifecycle_contract(
            "Update an installed connector entry from a replacement package source.",
            "Real package verification plus persistent inventory mutation with before/after visibility.",
        )),
        "pin" => Some(lifecycle_contract(
            "Pin a connector to a version or channel.",
            "State change that explains rollout/update consequences immediately.",
        )),
        "unpin" => Some(lifecycle_contract(
            "Remove a connector pin so managed updates can resume.",
            "Lifecycle state change with clear follow-on status reporting.",
        )),
        "rollout" => Some(lifecycle_contract(
            "Inspect or change connector rollout state.",
            "Managed rollout workflows with explicit status, canary, and rollback semantics.",
        )),
        "config" => Some(json!({
            "family": "config",
            "summary": "Manage config schema, values, import/export, and doctor checks through one nested command family.",
            "intended_shape": "Redaction-aware config workflows that keep secrets out of default output while preserving JSON fidelity when requested.",
            "next_beads": ["flywheel_connectors-1g7z0.9", "flywheel_connectors-1g7z0.4", "flywheel_connectors-1g7z0.5"],
            "workflow_handoff": [
                "Use `fwc config schema <connector>` before `get` or `set`.",
                "Use `fwc config doctor <connector>` immediately after mutating config."
            ],
        })),
        "invoke" => Some(execution_contract(
            "Execute a connector operation with explicit payload routing, risk context, and result rendering.",
            "Result view that stays concise by default while preserving full JSON fidelity.",
        )),
        "simulate" => Some(execution_contract(
            "Preflight or dry-run a connector operation before side effects.",
            "Explain-first execution path for risky or destructive operations.",
        )),
        "cancel" => Some(execution_contract(
            "Cancel an in-flight connector operation.",
            "Operation-control surface for result handles and long-running work.",
        )),
        "export-tools" => Some(execution_contract(
            "Export connector operations as tool definitions for agent runtimes.",
            "Machine-readable MCP, Claude, or OpenAI tool schemas synthesized from real connector introspection.",
        )),
        "serve-mcp" => Some(execution_contract(
            "Serve selected connectors as MCP tools over stdio JSON-RPC.",
            "Live MCP bridge rooted in real connector discovery and host-backed tool execution.",
        )),
        "suggest" => Some(execution_contract(
            "Suggest relevant connectors and operations from a goal or context description.",
            "Exploration surface for narrowing connector choice before planning or invocation.",
        )),
        "template" => Some(execution_contract(
            "Generate a fill-in-the-blanks JSON template for an operation.",
            "Schema-derived request template that helps assemble a valid payload quickly.",
        )),
        "validate" => Some(execution_contract(
            "Validate an input payload against an operation schema before invocation.",
            "Pre-execution validation with structured fix guidance.",
        )),
        "history" => Some(execution_contract(
            "Browse the append-only operation history.",
            "Receipt- and replay-oriented view over recorded operation outcomes.",
        )),
        "pipe" => Some(execution_contract(
            "Chain two operations by mapping output fields from one into the next.",
            "Two-step composition surface for cross-connector execution.",
        )),
        "pipeline" => Some(execution_contract(
            "Load reusable multi-step connector workflows from TOML and validate or plan them.",
            "Pipeline discovery and planning surface that binds parameters, validates dependencies, and produces deterministic execution plans.",
        )),
        "recipe" => Some(execution_contract(
            "Browse and plan bundled cross-connector pipeline recipes with starter defaults.",
            "Built-in recipe library for deterministic listing, inspection, estimate, dry-run, and export.",
        )),
        "map" => Some(execution_contract(
            "Apply one operation to many inputs in parallel.",
            "Batch-style execution for repeated operations over JSON arrays or JSONL inputs.",
        )),
        "batch-file" => Some(execution_contract(
            "Execute a JSONL file of heterogeneous operations with dependency ordering.",
            "File-driven multi-operation execution over real host-backed batch endpoints.",
        )),
        _ => None,
    }
}

fn intent_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "intent",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.22", "flywheel_connectors-1g7z0.23", "flywheel_connectors-1g7z0.24"],
        "workflow_handoff": [
            "Use `plan` first when the agent knows the goal but not the exact connector primitive.",
            "Use `explain` when you need the compiler's reasoning before trusting the plan.",
            "Use `do` for transparent materialization; it defaults to simulation and only advances to approval when explicitly requested."
        ],
    })
}

fn workflow_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "workflow",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.2", "flywheel_connectors-1g7z0.25", "flywheel_connectors-1g7z0.18", "flywheel_connectors-1g7z0.23"],
        "workflow_handoff": [
            "Use `fwc task \"<intent>\"` to create the capsule in one shot.",
            "Use `fwc task resolve <task-id> --until ready` to persist draft bindings, identifier candidates, and the smallest remaining question.",
            "Use `fwc task ask <task-id>` when you want the single best clarification prompt instead of the full capsule dump.",
            "Use `fwc task bind <task-id> key=value ...` to attach resolved values without rewriting the request, then `advance`, `approve`, and `run` when the workflow is ready."
        ],
    })
}

fn discovery_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "discovery",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.7", "flywheel_connectors-1g7z0.12", "flywheel_connectors-1g7z0.24"],
        "workflow_handoff": ["Move from discovery to `schema`, `examples`, or `config schema` once scope is narrowed."],
    })
}

fn lifecycle_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "lifecycle",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.8", "flywheel_connectors-1g7z0.4", "flywheel_connectors-1g7z0.5"],
        "workflow_handoff": ["Use `status` immediately before and after mutating lifecycle state."],
    })
}

fn execution_contract(summary: &str, intended_shape: &str) -> Value {
    json!({
        "family": "execution",
        "summary": summary,
        "intended_shape": intended_shape,
        "next_beads": ["flywheel_connectors-1g7z0.10", "flywheel_connectors-1g7z0.4"],
        "workflow_handoff": ["Use `schema` or `example` first, then `simulate`, then `invoke` if the action should proceed."],
    })
}

#[cfg(test)]
mod tests {
    use super::{
        AuthAcquisitionFlow, COMMAND_CLASSIFICATIONS, COMMANDS, CommandExecutionMode,
        CommandTruthSource, HYBRID_MODE_HELP, HostAbsentBehavior, HostAbsentReason,
        OFFLINE_FLAG_HELP, OfflineSource, WorkflowKind, WorkflowStepReality,
        auth_required_commands, auth_ux_guidance, check_auth_requirement, classify_command,
        command_requires_host, default_offline_source, guide_payload, host_absent_error,
        host_absent_error_payload, live_host_commands, offline_capable_commands,
        offline_provenance, offline_provenance_payload, planned_payload, workflow_can_proceed,
        workflow_kind,
    };
    use serde_json::json;

    // ── Existing tests ──────────────────────────────────────────────────

    #[test]
    fn guide_defaults_to_toon() {
        let guide = guide_payload(None);
        assert_eq!(guide["defaults"]["format"], "toon");
        assert_eq!(guide["exit_codes"]["unknown_command"], 3);
        assert_eq!(guide["status"], "ok");
    }

    #[test]
    fn list_payload_is_contract_preview_not_fake_runtime_state() {
        let captures = serde_json::json!({ "zone": "z:work" });
        let payload = planned_payload("list", &captures);
        assert_eq!(payload["status"], "planned");
        assert_eq!(payload["command"], "list");
        assert_eq!(payload["contract"]["family"], "discovery");
    }

    #[test]
    fn unknown_guide_command_returns_known_commands() {
        let payload = guide_payload(Some("does-not-exist"));
        assert_eq!(payload["status"], "unknown-command");
        assert!(payload["known_commands"].is_array());
    }

    // ── COMMANDS constant tests ─────────────────────────────────────────

    #[test]
    fn commands_is_non_empty() {
        assert!(!COMMANDS.is_empty());
    }

    #[test]
    fn commands_contains_guide() {
        assert!(COMMANDS.contains(&"guide"));
    }

    #[test]
    fn commands_contains_list() {
        assert!(COMMANDS.contains(&"list"));
    }

    #[test]
    fn commands_contains_show() {
        assert!(COMMANDS.contains(&"show"));
    }

    #[test]
    fn commands_contains_invoke() {
        assert!(COMMANDS.contains(&"invoke"));
    }

    #[test]
    fn commands_contains_task() {
        assert!(COMMANDS.contains(&"task"));
    }

    #[test]
    fn commands_contains_plan() {
        assert!(COMMANDS.contains(&"plan"));
    }

    #[test]
    fn commands_contains_simulate() {
        assert!(COMMANDS.contains(&"simulate"));
    }

    #[test]
    fn commands_contains_recipe() {
        assert!(COMMANDS.contains(&"recipe"));
    }

    #[test]
    fn commands_has_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for cmd in COMMANDS {
            assert!(seen.insert(cmd), "duplicate command: {cmd}");
        }
    }

    // ── guide_payload(None) full-guide tests ────────────────────────────

    #[test]
    fn full_guide_status_is_ok() {
        let g = guide_payload(None);
        assert_eq!(g["status"], "ok");
    }

    #[test]
    fn full_guide_name_is_fwc() {
        let g = guide_payload(None);
        assert_eq!(g["name"], "fwc");
    }

    #[test]
    fn full_guide_has_commands_array() {
        let g = guide_payload(None);
        assert!(g["commands"].is_array());
        assert!(!g["commands"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_has_exit_codes_object() {
        let g = guide_payload(None);
        assert!(g["exit_codes"].is_object());
    }

    #[test]
    fn full_guide_has_eight_families() {
        let g = guide_payload(None);
        let families = g["families"].as_array().expect("families should be array");
        assert_eq!(families.len(), 8);
    }

    #[test]
    fn full_guide_family_names() {
        let g = guide_payload(None);
        let families = g["families"].as_array().unwrap();
        let names: Vec<&str> = families
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"workflow"));
        assert!(names.contains(&"intent"));
        assert!(names.contains(&"discovery"));
        assert!(names.contains(&"evidence"));
        assert!(names.contains(&"lifecycle"));
        assert!(names.contains(&"capability-governance"));
        assert!(names.contains(&"config"));
        assert!(names.contains(&"execution"));
    }

    #[test]
    fn full_guide_has_progressive_disclosure() {
        let g = guide_payload(None);
        assert!(g["progressive_disclosure"].is_array());
        assert!(!g["progressive_disclosure"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_has_recommended_workflow() {
        let g = guide_payload(None);
        assert!(g["recommended_workflow"].is_array());
        assert!(!g["recommended_workflow"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_defaults_format_is_toon() {
        let g = guide_payload(None);
        assert_eq!(g["defaults"]["format"], "toon");
    }

    #[test]
    fn full_guide_has_purpose_string() {
        let g = guide_payload(None);
        assert!(g["purpose"].is_string());
    }

    // ── guide_payload(Some(cmd)) per-command tests ──────────────────────

    #[test]
    fn guide_for_guide_command() {
        let p = guide_payload(Some("guide"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["guide_scope"], "command");
        assert!(p["contract"]["family"].is_string());
        assert!(p["contract"]["summary"].is_string());
    }

    #[test]
    fn guide_for_list_command() {
        let p = guide_payload(Some("list"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["guide_scope"], "command");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_task_command() {
        let p = guide_payload(Some("task"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "workflow");
    }

    #[test]
    fn guide_for_invoke_command() {
        let p = guide_payload(Some("invoke"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "execution");
    }

    #[test]
    fn guide_for_config_command() {
        let p = guide_payload(Some("config"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "config");
    }

    #[test]
    fn guide_for_recipe_command() {
        let p = guide_payload(Some("recipe"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "execution");
    }

    #[test]
    fn guide_for_plan_command() {
        let p = guide_payload(Some("plan"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "intent");
    }

    #[test]
    fn guide_for_all_known_commands_returns_ok() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert_eq!(p["status"], "ok", "guide_payload for {cmd} should be ok");
        }
    }

    // ── guide_payload(Some("unknown")) ──────────────────────────────────

    #[test]
    fn guide_unknown_command_status() {
        let p = guide_payload(Some("nonexistent-xyzzy"));
        assert_eq!(p["status"], "unknown-command");
    }

    #[test]
    fn guide_unknown_command_has_known_commands_list() {
        let p = guide_payload(Some("nonexistent-xyzzy"));
        let known = p["known_commands"]
            .as_array()
            .expect("known_commands array");
        assert_eq!(known.len(), COMMANDS.len());
    }

    #[test]
    fn guide_unknown_command_echoes_command_name() {
        let p = guide_payload(Some("bogus"));
        assert_eq!(p["command"], "bogus");
    }

    // ── planned_payload for known commands ───────────────────────────────

    #[test]
    fn planned_payload_status_is_planned_for_known() {
        let cap = json!({});
        for cmd in COMMANDS {
            let p = planned_payload(cmd, &cap);
            assert_eq!(p["status"], "planned", "planned_payload for {cmd}");
        }
    }

    #[test]
    fn planned_payload_has_contract_for_known() {
        let cap = json!({"key": "val"});
        let p = planned_payload("show", &cap);
        assert!(p["contract"].is_object());
        assert!(p["contract"]["family"].is_string());
    }

    #[test]
    fn planned_payload_phase_is_ux_contract() {
        let cap = json!({});
        let p = planned_payload("ops", &cap);
        assert_eq!(p["phase"], "ux-contract-preview");
    }

    #[test]
    fn planned_payload_preserves_captures() {
        let cap = json!({"zone": "z:work", "limit": 10});
        let p = planned_payload("list", &cap);
        assert_eq!(p["captures"]["zone"], "z:work");
        assert_eq!(p["captures"]["limit"], 10);
    }

    // ── planned_payload for unknown command ─────────────────────────────

    #[test]
    fn planned_unknown_command_status() {
        let p = planned_payload("does-not-exist", &json!({}));
        assert_eq!(p["status"], "unknown-command");
    }

    #[test]
    fn planned_unknown_command_has_known_commands() {
        let p = planned_payload("does-not-exist", &json!({}));
        assert!(p["known_commands"].is_array());
        assert_eq!(
            p["known_commands"].as_array().unwrap().len(),
            COMMANDS.len()
        );
    }

    #[test]
    fn planned_unknown_command_echoes_command_and_captures() {
        let cap = json!({"a": 1});
        let p = planned_payload("nope", &cap);
        assert_eq!(p["command"], "nope");
        assert_eq!(p["captures"]["a"], 1);
    }

    // ── Family correctness ──────────────────────────────────────────────

    #[test]
    fn intent_commands_have_intent_family() {
        for cmd in &["plan", "explain", "do"] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "intent",
                "{cmd} should be intent family"
            );
        }
    }

    #[test]
    fn discovery_commands_have_discovery_family() {
        for cmd in &["list", "search", "show", "ops", "schema", "examples"] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "discovery",
                "{cmd} should be discovery family"
            );
        }
    }

    #[test]
    fn lifecycle_commands_have_lifecycle_family() {
        for cmd in &["status", "install", "update", "pin", "unpin", "rollout"] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "lifecycle",
                "{cmd} should be lifecycle family"
            );
        }
    }

    #[test]
    fn execution_commands_have_execution_family() {
        for cmd in &[
            "invoke",
            "simulate",
            "cancel",
            "export-tools",
            "serve-mcp",
            "suggest",
            "template",
            "validate",
            "history",
            "pipe",
            "pipeline",
            "recipe",
            "map",
            "batch-file",
        ] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "execution",
                "{cmd} should be execution family"
            );
        }
    }

    #[test]
    fn evidence_commands_have_evidence_family() {
        for cmd in &[
            "supply-chain",
            "audit",
            "manifest",
            "net",
            "trace",
            "policy",
            "package",
        ] {
            let p = guide_payload(Some(cmd));
            assert_eq!(
                p["contract"]["family"], "evidence",
                "{cmd} should be evidence family"
            );
        }
    }

    #[test]
    fn config_command_has_config_family() {
        let p = guide_payload(Some("config"));
        assert_eq!(p["contract"]["family"], "config");
    }

    #[test]
    fn guide_command_has_meta_family() {
        let p = guide_payload(Some("guide"));
        assert_eq!(p["contract"]["family"], "meta");
    }

    #[test]
    fn task_command_has_workflow_family() {
        let p = guide_payload(Some("task"));
        assert_eq!(p["contract"]["family"], "workflow");
    }

    // ── Contract shape tests ────────────────────────────────────────────

    #[test]
    fn all_contracts_have_summary() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["summary"].is_string(),
                "{cmd} contract missing summary"
            );
        }
    }

    #[test]
    fn all_contracts_have_intended_shape() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["intended_shape"].is_string(),
                "{cmd} contract missing intended_shape"
            );
        }
    }

    #[test]
    fn all_contracts_have_next_beads() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["next_beads"].is_array(),
                "{cmd} contract missing next_beads"
            );
        }
    }

    #[test]
    fn all_contracts_have_workflow_handoff() {
        for cmd in COMMANDS {
            let p = guide_payload(Some(cmd));
            assert!(
                p["contract"]["workflow_handoff"].is_array(),
                "{cmd} contract missing workflow_handoff"
            );
        }
    }

    // ── Exit codes tests ────────────────────────────────────────────────

    #[test]
    fn exit_codes_are_distinct() {
        let g = guide_payload(None);
        let codes_obj = g["exit_codes"].as_object().expect("exit_codes object");
        let values: Vec<i64> = codes_obj.values().map(|v| v.as_i64().unwrap()).collect();
        let unique: std::collections::HashSet<i64> = values.iter().copied().collect();
        assert_eq!(
            values.len(),
            unique.len(),
            "exit codes must be distinct: {values:?}"
        );
    }

    #[test]
    fn exit_codes_success_is_zero() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["success"], 0);
    }

    #[test]
    fn exit_codes_internal_error_is_one() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["internal_error"], 1);
    }

    // ── Families vs COMMANDS cross-check ────────────────────────────────

    #[test]
    fn family_commands_are_subset_of_commands_constant() {
        let g = guide_payload(None);
        let families = g["families"].as_array().unwrap();
        for family in families {
            let cmds = family["commands"].as_array().unwrap();
            for cmd in cmds {
                let name = cmd.as_str().unwrap();
                assert!(
                    COMMANDS.contains(&name),
                    "family command {name} not in COMMANDS"
                );
            }
        }
    }

    #[test]
    fn all_commands_appear_in_exactly_one_family() {
        let g = guide_payload(None);
        let families = g["families"].as_array().unwrap();
        let mut family_cmds: Vec<&str> = Vec::new();
        for family in families {
            for cmd in family["commands"].as_array().unwrap() {
                family_cmds.push(cmd.as_str().unwrap());
            }
        }
        // guide is in COMMANDS but only has a meta contract; it is NOT listed
        // in the families array. So we check that every family command is in
        // COMMANDS but we allow COMMANDS to have entries not in families.
        for fc in &family_cmds {
            assert!(
                COMMANDS.contains(fc),
                "family command {fc} not in COMMANDS constant"
            );
        }
        // No duplicates within families
        let unique: std::collections::HashSet<&str> = family_cmds.iter().copied().collect();
        assert_eq!(
            family_cmds.len(),
            unique.len(),
            "duplicate command across families"
        );
    }

    // ── Edge-case / misc tests ──────────────────────────────────────────

    #[test]
    fn planned_payload_with_empty_captures() {
        let p = planned_payload("invoke", &json!({}));
        assert_eq!(p["status"], "planned");
        assert!(p["captures"].is_object());
        assert_eq!(p["captures"].as_object().unwrap().len(), 0);
    }

    #[test]
    fn planned_payload_with_nested_captures() {
        let cap = json!({"filters": {"state": "active"}, "page": 1});
        let p = planned_payload("search", &cap);
        assert_eq!(p["captures"]["filters"]["state"], "active");
        assert_eq!(p["captures"]["page"], 1);
    }

    #[test]
    fn guide_full_commands_array_has_entries_with_family() {
        let g = guide_payload(None);
        let cmds = g["commands"].as_array().unwrap();
        for entry in cmds {
            assert!(
                entry["family"].is_string(),
                "command entry missing family field"
            );
            assert!(
                entry["summary"].is_string(),
                "command entry missing summary field"
            );
        }
    }

    #[test]
    fn example_alias_returns_same_family_as_examples() {
        // command_contract handles "example" | "examples" — but COMMANDS only
        // lists "examples". Verify via planned_payload which also uses command_contract.
        let p = planned_payload("example", &json!({}));
        assert_eq!(p["status"], "planned");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_scope_field_only_in_per_command_guide() {
        // Full guide should NOT have guide_scope
        let full = guide_payload(None);
        assert!(full.get("guide_scope").is_none());

        // Per-command guide SHOULD have guide_scope
        let per = guide_payload(Some("list"));
        assert_eq!(per["guide_scope"], "command");
    }

    #[test]
    fn all_exit_codes_are_non_negative() {
        let g = guide_payload(None);
        let codes_obj = g["exit_codes"].as_object().unwrap();
        for (name, val) in codes_obj {
            let v = val.as_i64().unwrap();
            assert!(v >= 0, "exit code {name} is negative: {v}");
        }
    }

    // ── Additional tests ──────────────────────────────────────────

    #[test]
    fn commands_contains_search() {
        assert!(COMMANDS.contains(&"search"));
    }

    #[test]
    fn commands_contains_ops() {
        assert!(COMMANDS.contains(&"ops"));
    }

    #[test]
    fn commands_contains_schema() {
        assert!(COMMANDS.contains(&"schema"));
    }

    #[test]
    fn commands_contains_status() {
        assert!(COMMANDS.contains(&"status"));
    }

    #[test]
    fn commands_contains_install() {
        assert!(COMMANDS.contains(&"install"));
    }

    #[test]
    fn commands_contains_pipeline() {
        assert!(COMMANDS.contains(&"pipeline"));
    }

    #[test]
    fn commands_contains_examples() {
        assert!(COMMANDS.contains(&"examples"));
    }

    #[test]
    fn commands_contains_do() {
        assert!(COMMANDS.contains(&"do"));
    }

    #[test]
    fn commands_contains_explain() {
        assert!(COMMANDS.contains(&"explain"));
    }

    #[test]
    fn commands_count() {
        assert!(COMMANDS.len() >= 20);
    }

    #[test]
    fn guide_for_explain_command() {
        let p = guide_payload(Some("explain"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "intent");
    }

    #[test]
    fn guide_for_do_command() {
        let p = guide_payload(Some("do"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "intent");
    }

    #[test]
    fn guide_for_search_command() {
        let p = guide_payload(Some("search"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_show_command() {
        let p = guide_payload(Some("show"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_ops_command() {
        let p = guide_payload(Some("ops"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_schema_command() {
        let p = guide_payload(Some("schema"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_for_simulate_command() {
        let p = guide_payload(Some("simulate"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "execution");
    }

    #[test]
    fn guide_for_pipeline_command() {
        let p = guide_payload(Some("pipeline"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "execution");
    }

    #[test]
    fn guide_for_status_command() {
        let p = guide_payload(Some("status"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "lifecycle");
    }

    #[test]
    fn guide_for_install_command() {
        let p = guide_payload(Some("install"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "lifecycle");
    }

    #[test]
    fn guide_for_update_command() {
        let p = guide_payload(Some("update"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "lifecycle");
    }

    #[test]
    fn guide_for_pin_command() {
        let p = guide_payload(Some("pin"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "lifecycle");
    }

    #[test]
    fn guide_for_unpin_command() {
        let p = guide_payload(Some("unpin"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "lifecycle");
    }

    #[test]
    fn planned_payload_echoes_command_name() {
        let p = planned_payload("schema", &json!({}));
        assert_eq!(p["command"], "schema");
    }

    #[test]
    fn planned_payload_has_message() {
        let p = planned_payload("list", &json!({}));
        assert!(p["message"].is_string());
        assert!(p["message"].as_str().unwrap().contains("contract preview"));
    }

    #[test]
    fn full_guide_has_phase_object() {
        let g = guide_payload(None);
        assert!(g["phase"].is_object());
        assert!(g["phase"]["current_bead"].is_string());
    }

    #[test]
    fn full_guide_phase_has_follow_on_beads() {
        let g = guide_payload(None);
        assert!(g["phase"]["follow_on_beads"].is_array());
        assert!(!g["phase"]["follow_on_beads"].as_array().unwrap().is_empty());
    }

    #[test]
    fn full_guide_defaults_has_json_opt_in() {
        let g = guide_payload(None);
        assert_eq!(g["defaults"]["json_opt_in"], "--format json");
    }

    #[test]
    fn full_guide_defaults_has_workflow_bias() {
        let g = guide_payload(None);
        assert!(g["defaults"]["workflow_bias"].is_string());
    }

    #[test]
    fn exit_code_parse_error_is_two() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["parse_error"], 2);
    }

    #[test]
    fn exit_code_ambiguous_correction_is_four() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["ambiguous_correction"], 4);
    }

    #[test]
    fn exit_code_validation_error_is_five() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["validation_error"], 5);
    }

    #[test]
    fn exit_code_policy_denial_is_six() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["policy_denial"], 6);
    }

    #[test]
    fn exit_code_connector_error_is_seven() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["connector_error"], 7);
    }

    #[test]
    fn exit_code_transport_error_is_eight() {
        let g = guide_payload(None);
        assert_eq!(g["exit_codes"]["transport_error"], 8);
    }

    #[test]
    fn planned_payload_for_all_families() {
        let families = [
            ("guide", "meta"),
            ("task", "workflow"),
            ("plan", "intent"),
            ("explain", "intent"),
            ("do", "intent"),
            ("list", "discovery"),
            ("search", "discovery"),
            ("invoke", "execution"),
            ("simulate", "execution"),
            ("config", "config"),
        ];
        for (cmd, family) in &families {
            let p = planned_payload(cmd, &json!({}));
            assert_eq!(
                p["contract"]["family"], *family,
                "planned_payload for {cmd} should have family {family}"
            );
        }
    }

    #[test]
    fn planned_payload_with_array_captures() {
        let cap = json!({"ids": [1, 2, 3]});
        let p = planned_payload("invoke", &cap);
        assert_eq!(p["captures"]["ids"], json!([1, 2, 3]));
    }

    #[test]
    fn guide_for_examples_command() {
        let p = guide_payload(Some("examples"));
        assert_eq!(p["status"], "ok");
        assert_eq!(p["contract"]["family"], "discovery");
    }

    #[test]
    fn guide_unknown_command_message() {
        let p = guide_payload(Some("does-not-exist"));
        assert!(p["message"].is_string());
        assert!(
            p["message"]
                .as_str()
                .unwrap()
                .contains("No fwc command contract")
        );
    }

    // ── Command classification tests ───────────────────────────────────

    #[test]
    fn every_command_has_classification() {
        for cmd in COMMANDS {
            assert!(
                classify_command(cmd).is_some(),
                "Command '{cmd}' is in COMMANDS but has no classification"
            );
        }
    }

    #[test]
    fn every_classification_is_in_commands() {
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                COMMANDS.contains(&cls.command),
                "Classification for '{}' exists but command is not in COMMANDS",
                cls.command
            );
        }
    }

    #[test]
    fn classification_count_matches_commands() {
        assert_eq!(
            COMMAND_CLASSIFICATIONS.len(),
            COMMANDS.len(),
            "Mismatch between COMMANDS ({}) and COMMAND_CLASSIFICATIONS ({})",
            COMMANDS.len(),
            COMMAND_CLASSIFICATIONS.len()
        );
    }

    #[test]
    fn invoke_requires_live_host_and_token() {
        let cls = classify_command("invoke").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::LiveHost);
        assert_eq!(cls.execution_mode, CommandExecutionMode::Mutating);
        assert_eq!(cls.host_absent, HostAbsentBehavior::FailFast);
        assert!(cls.requires_capability_token);
        assert!(cls.may_need_approval);
    }

    #[test]
    fn simulate_requires_live_host_and_token() {
        let cls = classify_command("simulate").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::LiveHost);
        assert_eq!(cls.execution_mode, CommandExecutionMode::Simulate);
        assert!(cls.requires_capability_token);
    }

    #[test]
    fn guide_is_offline_only() {
        let cls = classify_command("guide").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::OfflineArtifact);
        assert_eq!(cls.execution_mode, CommandExecutionMode::LocalOnly);
        assert_eq!(cls.host_absent, HostAbsentBehavior::Unaffected);
        assert!(!cls.requires_capability_token);
    }

    #[test]
    fn list_is_hybrid() {
        let cls = classify_command("list").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::Hybrid);
        assert_eq!(cls.host_absent, HostAbsentBehavior::FailFast);
    }

    #[test]
    fn search_is_hybrid() {
        let cls = classify_command("search").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::Hybrid);
        assert_eq!(cls.host_absent, HostAbsentBehavior::FailFast);
    }

    #[test]
    fn supply_chain_is_passthrough() {
        let cls = classify_command("supply-chain").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::Passthrough);
        assert_eq!(cls.host_absent, HostAbsentBehavior::PassthroughDependent);
    }

    #[test]
    fn serve_mcp_is_interactive_live() {
        let cls = classify_command("serve-mcp").unwrap();
        assert_eq!(cls.truth_source, CommandTruthSource::LiveHost);
        assert_eq!(cls.execution_mode, CommandExecutionMode::Interactive);
        assert!(cls.requires_capability_token);
    }

    #[test]
    fn live_host_commands_includes_invoke() {
        let live = live_host_commands();
        assert!(live.contains(&"invoke"));
        assert!(live.contains(&"simulate"));
        assert!(live.contains(&"serve-mcp"));
        assert!(!live.contains(&"guide"));
        assert!(!live.contains(&"list"));
    }

    #[test]
    fn offline_capable_includes_list_and_guide() {
        let offline = offline_capable_commands();
        assert!(offline.contains(&"guide"));
        assert!(offline.contains(&"list"));
        assert!(offline.contains(&"search"));
        assert!(!offline.contains(&"invoke"));
    }

    #[test]
    fn auth_required_includes_invoke_and_map() {
        let auth = auth_required_commands();
        assert!(auth.contains(&"invoke"));
        assert!(auth.contains(&"simulate"));
        assert!(auth.contains(&"map"));
        assert!(auth.contains(&"batch-file"));
        assert!(auth.contains(&"serve-mcp"));
        assert!(!auth.contains(&"list"));
        assert!(!auth.contains(&"guide"));
    }

    #[test]
    fn classification_serde_exposes_expected_fields() {
        let cls = classify_command("invoke").unwrap();
        let value = serde_json::to_value(cls).unwrap();
        assert_eq!(value["command"], "invoke");
        assert_eq!(value["truth_source"], "live_host");
        assert_eq!(value["execution_mode"], "mutating");
        assert_eq!(value["host_absent"], "fail_fast");
    }

    #[test]
    fn truth_source_serde() {
        for (src, expected) in [
            (CommandTruthSource::LiveHost, "\"live_host\""),
            (CommandTruthSource::OfflineArtifact, "\"offline_artifact\""),
            (CommandTruthSource::Hybrid, "\"hybrid\""),
            (CommandTruthSource::Passthrough, "\"passthrough\""),
        ] {
            let json = serde_json::to_string(&src).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn execution_mode_serde() {
        for (mode, expected) in [
            (CommandExecutionMode::ReadOnly, "\"read_only\""),
            (CommandExecutionMode::Mutating, "\"mutating\""),
            (CommandExecutionMode::Simulate, "\"simulate\""),
            (CommandExecutionMode::Interactive, "\"interactive\""),
            (CommandExecutionMode::LocalOnly, "\"local_only\""),
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn host_absent_behavior_serde() {
        for (behavior, expected) in [
            (HostAbsentBehavior::FailFast, "\"fail_fast\""),
            (
                HostAbsentBehavior::DegradedWithWarning,
                "\"degraded_with_warning\"",
            ),
            (HostAbsentBehavior::Unaffected, "\"unaffected\""),
            (
                HostAbsentBehavior::PassthroughDependent,
                "\"passthrough_dependent\"",
            ),
        ] {
            let json = serde_json::to_string(&behavior).unwrap();
            assert_eq!(json, expected);
        }
    }

    #[test]
    fn no_offline_command_requires_capability_token() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    !cls.requires_capability_token,
                    "Offline command '{}' should not require a capability token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn no_passthrough_command_requires_capability_token() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Passthrough {
                assert!(
                    !cls.requires_capability_token,
                    "Passthrough command '{}' should not require a capability token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_mutating_live_commands_with_auth_require_token_or_approval() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost
                && cls.execution_mode == CommandExecutionMode::Mutating
                && cls.command != "install"
                && cls.command != "update"
                && cls.command != "pin"
                && cls.command != "unpin"
                && cls.command != "rollout"
                && cls.command != "config"
            {
                assert!(
                    cls.requires_capability_token || cls.may_need_approval,
                    "Mutating live command '{}' should require auth",
                    cls.command
                );
            }
        }
    }

    // ── Host-absent fail-fast error tests ────────────────────────────────

    #[test]
    fn host_absent_error_not_configured_invoke() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert_eq!(err.command, "invoke");
        assert_eq!(err.error_type, "missing-host-endpoint");
        assert_eq!(err.exit_code, 8);
        assert!(err.recoverable);
        assert!(err.message.contains("requires a live"));
        assert!(err.next_actions.iter().any(|a| a.contains("--host")));
        assert!(err.next_actions.iter().any(|a| a.contains("FWC_HOST")));
    }

    #[test]
    fn host_absent_error_unreachable() {
        let err = host_absent_error("status", HostAbsentReason::Unreachable);
        assert_eq!(err.error_type, "host-unreachable");
        assert!(err.message.contains("could not reach"));
        assert!(err.next_actions.iter().any(|a| a.contains("doctor")));
    }

    #[test]
    fn host_absent_error_unhealthy() {
        let err = host_absent_error("budget", HostAbsentReason::Unhealthy);
        assert_eq!(err.error_type, "host-unhealthy");
        assert!(err.message.contains("unhealthy"));
        assert!(err.next_actions.iter().any(|a| a.contains("recover")));
    }

    #[test]
    fn host_absent_error_hybrid_command_suggests_offline() {
        let err = host_absent_error("list", HostAbsentReason::NotConfigured);
        assert!(
            err.next_actions.iter().any(|a| a.contains("--offline")),
            "Hybrid command 'list' should suggest --offline alternative"
        );
    }

    #[test]
    fn host_absent_error_live_command_no_offline_suggestion() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            !err.next_actions.iter().any(|a| a.contains("--offline")),
            "LiveHost command 'invoke' should NOT suggest --offline"
        );
    }

    #[test]
    fn host_absent_error_payload_has_required_fields() {
        let err = host_absent_error("simulate", HostAbsentReason::NotConfigured);
        let payload = host_absent_error_payload(&err);
        assert_eq!(payload["status"], "error");
        assert_eq!(payload["command"], "simulate");
        assert_eq!(payload["error"]["type"], "missing-host-endpoint");
        assert!(payload["error"]["recoverable"].as_bool().unwrap());
        assert!(payload["next_actions"].is_array());
    }

    #[test]
    fn host_absent_error_payload_includes_reason() {
        let err = host_absent_error("doctor", HostAbsentReason::Unreachable);
        let payload = host_absent_error_payload(&err);
        assert_eq!(payload["error"]["reason"], "unreachable");
    }

    #[test]
    fn command_requires_host_for_live_commands() {
        assert!(command_requires_host("invoke"));
        assert!(command_requires_host("simulate"));
        assert!(command_requires_host("cancel"));
        assert!(command_requires_host("doctor"));
        assert!(command_requires_host("status"));
        assert!(command_requires_host("budget"));
        assert!(command_requires_host("capabilities"));
        assert!(command_requires_host("serve-mcp"));
    }

    #[test]
    fn command_requires_host_for_hybrid_failfast_commands() {
        assert!(command_requires_host("list"));
        assert!(command_requires_host("search"));
        assert!(command_requires_host("show"));
        assert!(command_requires_host("ops"));
        assert!(command_requires_host("schema"));
        assert!(command_requires_host("examples"));
    }

    #[test]
    fn command_does_not_require_host_for_offline_commands() {
        assert!(!command_requires_host("guide"));
        assert!(!command_requires_host("task"));
        assert!(!command_requires_host("plan"));
        assert!(!command_requires_host("explain"));
        assert!(!command_requires_host("history"));
        assert!(!command_requires_host("pipe"));
    }

    #[test]
    fn command_does_not_require_host_for_degraded_commands() {
        assert!(!command_requires_host("do"));
    }

    #[test]
    fn command_does_not_require_host_for_passthrough_commands() {
        assert!(!command_requires_host("supply-chain"));
        assert!(!command_requires_host("audit"));
        assert!(!command_requires_host("manifest"));
    }

    #[test]
    fn command_requires_host_unknown_command_returns_false() {
        assert!(!command_requires_host("nonexistent-command"));
    }

    #[test]
    fn host_absent_reason_serde_roundtrip() {
        let reasons = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ];
        for reason in &reasons {
            let json_str = serde_json::to_string(reason).unwrap();
            let back: HostAbsentReason = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*reason, back);
        }
    }

    #[test]
    fn host_absent_reason_kebab_case_serialization() {
        assert_eq!(
            serde_json::to_value(HostAbsentReason::NotConfigured).unwrap(),
            json!("not-configured")
        );
        assert_eq!(
            serde_json::to_value(HostAbsentReason::Unreachable).unwrap(),
            json!("unreachable")
        );
        assert_eq!(
            serde_json::to_value(HostAbsentReason::Unhealthy).unwrap(),
            json!("unhealthy")
        );
    }

    #[test]
    fn host_absent_error_all_live_host_commands_get_valid_error() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                let err = host_absent_error(cls.command, HostAbsentReason::NotConfigured);
                assert_eq!(err.command, cls.command);
                assert_eq!(err.exit_code, 8);
                assert!(err.recoverable);
                assert!(!err.message.is_empty());
                assert!(!err.next_actions.is_empty());
                assert!(
                    !err.next_actions.iter().any(|a| a.contains("--offline")),
                    "LiveHost command '{}' should not suggest --offline",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn host_absent_error_all_hybrid_commands_suggest_offline() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid
                && cls.host_absent == HostAbsentBehavior::FailFast
            {
                let err = host_absent_error(cls.command, HostAbsentReason::NotConfigured);
                assert!(
                    err.next_actions.iter().any(|a| a.contains("--offline")),
                    "Hybrid FailFast command '{}' should suggest --offline",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn host_absent_error_exit_code_is_transport() {
        for reason in &[
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ] {
            let err = host_absent_error("invoke", *reason);
            assert_eq!(
                err.exit_code, 8,
                "Exit code should be Transport (8) for {reason:?}"
            );
        }
    }

    #[test]
    fn host_absent_error_each_reason_has_distinct_error_type() {
        let types: Vec<&str> = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ]
        .iter()
        .map(|r| host_absent_error("invoke", *r).error_type)
        .collect();
        let unique: std::collections::HashSet<_> = types.iter().collect();
        assert_eq!(unique.len(), types.len());
    }

    #[test]
    fn host_absent_error_each_reason_has_distinct_message() {
        let messages: Vec<String> = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ]
        .iter()
        .map(|r| host_absent_error("invoke", *r).message)
        .collect();
        let unique: std::collections::HashSet<_> = messages.iter().collect();
        assert_eq!(unique.len(), messages.len());
    }

    #[test]
    fn host_absent_payload_stable_across_toon_json() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        let payload = host_absent_error_payload(&err);

        // Required top-level keys
        assert!(payload.get("status").is_some());
        assert!(payload.get("command").is_some());
        assert!(payload.get("error").is_some());
        assert!(payload.get("next_actions").is_some());

        // Required error sub-keys
        let error = &payload["error"];
        assert!(error.get("type").is_some());
        assert!(error.get("reason").is_some());
        assert!(error.get("message").is_some());
        assert!(error.get("recoverable").is_some());
    }

    // ── Offline provenance contract tests ────────────────────────────────

    #[test]
    fn offline_source_serde_roundtrip() {
        let sources = [
            OfflineSource::WorkspaceManifest,
            OfflineSource::LocalCatalog,
            OfflineSource::LocalHistory,
            OfflineSource::StaticContract,
            OfflineSource::Subsystem,
        ];
        for source in &sources {
            let json_str = serde_json::to_string(source).unwrap();
            let back: OfflineSource = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*source, back);
        }
    }

    #[test]
    fn offline_source_kebab_case() {
        assert_eq!(
            serde_json::to_value(OfflineSource::WorkspaceManifest).unwrap(),
            json!("workspace-manifest")
        );
        assert_eq!(
            serde_json::to_value(OfflineSource::LocalCatalog).unwrap(),
            json!("local-catalog")
        );
        assert_eq!(
            serde_json::to_value(OfflineSource::LocalHistory).unwrap(),
            json!("local-history")
        );
        assert_eq!(
            serde_json::to_value(OfflineSource::StaticContract).unwrap(),
            json!("static-contract")
        );
        assert_eq!(
            serde_json::to_value(OfflineSource::Subsystem).unwrap(),
            json!("subsystem")
        );
    }

    #[test]
    fn offline_provenance_for_hybrid_command_has_live_alternative() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        assert!(prov.offline);
        assert_eq!(prov.source, OfflineSource::WorkspaceManifest);
        assert!(!prov.caveat.is_empty());
        assert!(
            prov.live_alternative.is_some(),
            "Hybrid command 'list' should have a live_alternative"
        );
        assert!(prov.live_alternative.unwrap().contains("--host"));
    }

    #[test]
    fn offline_provenance_for_offline_command_no_live_alternative() {
        let prov = offline_provenance("guide", OfflineSource::StaticContract);
        assert!(prov.offline);
        assert_eq!(prov.source, OfflineSource::StaticContract);
        assert!(
            prov.live_alternative.is_none(),
            "Offline-only command 'guide' should not have a live_alternative"
        );
    }

    #[test]
    fn offline_provenance_for_live_command_no_live_alternative() {
        // Live commands shouldn't normally be called in offline mode,
        // but the provenance builder should handle it gracefully
        let prov = offline_provenance("invoke", OfflineSource::LocalCatalog);
        assert!(prov.offline);
        assert!(prov.live_alternative.is_none());
    }

    #[test]
    fn offline_provenance_payload_has_required_fields() {
        let prov = offline_provenance("search", OfflineSource::WorkspaceManifest);
        let payload = offline_provenance_payload(&prov);
        assert_eq!(payload["offline"], true);
        assert_eq!(payload["source"], "workspace-manifest");
        assert!(payload["caveat"].as_str().unwrap().len() > 10);
        assert!(payload.get("live_alternative").is_some());
    }

    #[test]
    fn offline_provenance_payload_omits_live_alt_when_none() {
        let prov = offline_provenance("guide", OfflineSource::StaticContract);
        let payload = offline_provenance_payload(&prov);
        assert!(payload.get("live_alternative").is_none());
    }

    #[test]
    fn default_offline_source_guide_is_static_contract() {
        assert_eq!(
            default_offline_source("guide"),
            OfflineSource::StaticContract
        );
    }

    #[test]
    fn default_offline_source_history_is_local_history() {
        assert_eq!(
            default_offline_source("history"),
            OfflineSource::LocalHistory
        );
    }

    #[test]
    fn default_offline_source_pipe_is_local_history() {
        assert_eq!(default_offline_source("pipe"), OfflineSource::LocalHistory);
    }

    #[test]
    fn default_offline_source_task_is_local_catalog() {
        assert_eq!(default_offline_source("task"), OfflineSource::LocalCatalog);
    }

    #[test]
    fn default_offline_source_hybrid_is_workspace_manifest() {
        assert_eq!(
            default_offline_source("list"),
            OfflineSource::WorkspaceManifest
        );
        assert_eq!(
            default_offline_source("search"),
            OfflineSource::WorkspaceManifest
        );
        assert_eq!(
            default_offline_source("show"),
            OfflineSource::WorkspaceManifest
        );
        assert_eq!(
            default_offline_source("ops"),
            OfflineSource::WorkspaceManifest
        );
    }

    #[test]
    fn default_offline_source_passthrough_is_subsystem() {
        assert_eq!(
            default_offline_source("supply-chain"),
            OfflineSource::Subsystem
        );
        assert_eq!(default_offline_source("audit"), OfflineSource::Subsystem);
        assert_eq!(default_offline_source("manifest"), OfflineSource::Subsystem);
    }

    #[test]
    fn all_hybrid_commands_produce_provenance_with_live_alternative() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid {
                let source = default_offline_source(cls.command);
                let prov = offline_provenance(cls.command, source);
                assert!(
                    prov.live_alternative.is_some(),
                    "Hybrid command '{}' should have a live_alternative in provenance",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_offline_commands_produce_provenance_without_live_alternative() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                let source = default_offline_source(cls.command);
                let prov = offline_provenance(cls.command, source);
                assert!(
                    prov.live_alternative.is_none(),
                    "Offline command '{}' should not have a live_alternative in provenance",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn each_offline_source_has_non_empty_caveat() {
        let sources = [
            OfflineSource::WorkspaceManifest,
            OfflineSource::LocalCatalog,
            OfflineSource::LocalHistory,
            OfflineSource::StaticContract,
            OfflineSource::Subsystem,
        ];
        for source in &sources {
            let prov = offline_provenance("list", *source);
            assert!(
                !prov.caveat.is_empty(),
                "Source {source:?} should have a non-empty caveat"
            );
        }
    }

    #[test]
    fn each_offline_source_has_distinct_caveat() {
        let sources = [
            OfflineSource::WorkspaceManifest,
            OfflineSource::LocalCatalog,
            OfflineSource::LocalHistory,
            OfflineSource::StaticContract,
            OfflineSource::Subsystem,
        ];
        let caveats: Vec<&str> = sources
            .iter()
            .map(|s| offline_provenance("list", *s).caveat)
            .collect();
        let unique: std::collections::HashSet<_> = caveats.iter().collect();
        assert_eq!(
            unique.len(),
            caveats.len(),
            "Each source should have a distinct caveat"
        );
    }

    #[test]
    fn offline_flag_help_is_non_empty() {
        assert!(!OFFLINE_FLAG_HELP.is_empty());
        assert!(OFFLINE_FLAG_HELP.contains("manifest"));
    }

    #[test]
    fn hybrid_mode_help_is_non_empty() {
        assert!(!HYBRID_MODE_HELP.is_empty());
        assert!(HYBRID_MODE_HELP.contains("--offline"));
        assert!(HYBRID_MODE_HELP.contains("live host"));
    }

    #[test]
    fn offline_provenance_payload_serde_stable_shape() {
        let prov = offline_provenance("search", OfflineSource::WorkspaceManifest);
        let payload = offline_provenance_payload(&prov);
        // Shape must be stable for TOON/JSON rendering
        assert!(payload.is_object());
        let obj = payload.as_object().unwrap();
        assert!(obj.contains_key("offline"));
        assert!(obj.contains_key("source"));
        assert!(obj.contains_key("caveat"));
    }

    // ── Auth UX contract tests ───────────────────────────────────────────

    #[test]
    fn auth_acquisition_flow_serde_roundtrip() {
        let flows = [
            AuthAcquisitionFlow::Required,
            AuthAcquisitionFlow::Recommended,
            AuthAcquisitionFlow::NotNeeded,
        ];
        for flow in &flows {
            let json_str = serde_json::to_string(flow).unwrap();
            let back: AuthAcquisitionFlow = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*flow, back);
        }
    }

    #[test]
    fn auth_ux_invoke_requires_token() {
        let guidance = auth_ux_guidance("invoke");
        assert_eq!(guidance.acquisition, AuthAcquisitionFlow::Required);
        assert!(guidance.may_need_approval);
        assert!(!guidance.supply_methods.is_empty());
        assert!(!guidance.missing_guidance.is_empty());
        assert!(!guidance.denial_guidance.is_empty());
    }

    #[test]
    fn auth_ux_simulate_requires_token() {
        let guidance = auth_ux_guidance("simulate");
        assert_eq!(guidance.acquisition, AuthAcquisitionFlow::Required);
        assert!(!guidance.may_need_approval);
    }

    #[test]
    fn auth_ux_list_does_not_require_token() {
        let guidance = auth_ux_guidance("list");
        assert_eq!(guidance.acquisition, AuthAcquisitionFlow::NotNeeded);
        assert!(guidance.supply_methods.is_empty());
        assert!(guidance.missing_guidance.is_empty());
    }

    #[test]
    fn auth_ux_guide_does_not_require_token() {
        let guidance = auth_ux_guidance("guide");
        assert_eq!(guidance.acquisition, AuthAcquisitionFlow::NotNeeded);
    }

    #[test]
    fn auth_ux_all_token_commands_are_required() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.requires_capability_token {
                let guidance = auth_ux_guidance(cls.command);
                assert_eq!(
                    guidance.acquisition,
                    AuthAcquisitionFlow::Required,
                    "Command '{}' requires token but auth guidance says {:?}",
                    cls.command,
                    guidance.acquisition
                );
            }
        }
    }

    #[test]
    fn auth_ux_non_token_commands_are_not_needed() {
        for cls in COMMAND_CLASSIFICATIONS {
            if !cls.requires_capability_token {
                let guidance = auth_ux_guidance(cls.command);
                assert_eq!(
                    guidance.acquisition,
                    AuthAcquisitionFlow::NotNeeded,
                    "Command '{}' does not require token but auth guidance says {:?}",
                    cls.command,
                    guidance.acquisition
                );
            }
        }
    }

    #[test]
    fn check_auth_requirement_missing_token() {
        let result = check_auth_requirement("invoke", false);
        assert!(result.is_some());
        let guidance = result.unwrap();
        assert_eq!(guidance.acquisition, AuthAcquisitionFlow::Required);
    }

    #[test]
    fn check_auth_requirement_has_token() {
        let result = check_auth_requirement("invoke", true);
        assert!(result.is_none());
    }

    #[test]
    fn check_auth_requirement_not_needed() {
        let result = check_auth_requirement("guide", false);
        assert!(result.is_none());
    }

    #[test]
    fn auth_ux_guidance_supply_methods_for_required() {
        let guidance = auth_ux_guidance("invoke");
        assert!(
            guidance
                .supply_methods
                .iter()
                .any(|m| m.contains("--capability-token"))
        );
        assert!(
            guidance
                .supply_methods
                .iter()
                .any(|m| m.contains("FWC_CAPABILITY_TOKEN"))
        );
        assert!(
            guidance
                .supply_methods
                .iter()
                .any(|m| m.contains("fwc capabilities issue"))
        );
    }

    #[test]
    fn auth_ux_guidance_serde_roundtrip() {
        let guidance = auth_ux_guidance("invoke");
        let json_str = serde_json::to_string(&guidance).unwrap();
        let back: super::AuthUxGuidance = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.command, "invoke");
        assert_eq!(back.acquisition, AuthAcquisitionFlow::Required);
    }
}
