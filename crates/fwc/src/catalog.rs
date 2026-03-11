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

// ── Runtime truth boundary and offline-mode contract ────────────────────────
// Defines the resolved runtime mode for every command invocation. Each dispatch
// path must resolve a RuntimeMode BEFORE doing any work, so there is a single
// place that decides whether the invocation is live, offline, degraded, or
// refused. No command may silently switch modes.

/// The resolved runtime mode for one command invocation.
///
/// Dispatch code resolves this once at the top of every handler and threads it
/// through the rest of the call. The mode is immutable for the lifetime of the
/// invocation — no mid-flight fallback is permitted.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    /// The command is running against a live, reachable host.
    /// Output is authoritative and may cause side effects.
    Live,
    /// The command is explicitly running in offline mode (user passed --offline
    /// or the command is inherently offline). Output is from local artifacts.
    ExplicitOffline,
    /// The command would prefer a live host but none is configured or reachable.
    /// The classification says `DegradedWithWarning`, so we proceed with local
    /// data and attach visible provenance caveats.
    DegradedOffline,
    /// The command cannot proceed because it requires a host that is absent.
    /// Dispatch must produce a `HostAbsentError` and stop.
    Refused,
}

impl RuntimeMode {
    /// Whether this mode produces authoritative output.
    #[must_use]
    pub fn is_authoritative(self) -> bool {
        matches!(self, Self::Live)
    }

    /// Whether this mode uses local/artifact data.
    #[must_use]
    pub fn is_offline(self) -> bool {
        matches!(self, Self::ExplicitOffline | Self::DegradedOffline)
    }

    /// Whether this mode indicates the command should not execute.
    #[must_use]
    pub fn is_refused(self) -> bool {
        matches!(self, Self::Refused)
    }

    /// Whether the output needs an offline provenance marker.
    #[must_use]
    pub fn needs_provenance_marker(self) -> bool {
        matches!(self, Self::ExplicitOffline | Self::DegradedOffline)
    }

    /// Whether the output needs a degradation warning.
    #[must_use]
    pub fn needs_degradation_warning(self) -> bool {
        matches!(self, Self::DegradedOffline)
    }

    /// Machine-readable tag for embedding in output payloads.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::ExplicitOffline => "explicit-offline",
            Self::DegradedOffline => "degraded-offline",
            Self::Refused => "refused",
        }
    }
}

/// The inputs to runtime-mode resolution. Callers construct this from CLI args
/// and environment, then pass it to [`resolve_runtime_mode`].
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuntimeContext {
    /// The command being invoked.
    pub command: String,
    /// Whether the user passed `--offline`.
    pub offline_flag: bool,
    /// Whether a host endpoint was resolved (from args, env, or context file).
    pub host_resolved: bool,
    /// Whether the resolved host is actually reachable (only meaningful when
    /// `host_resolved` is true).
    pub host_reachable: bool,
}

/// Resolve the runtime mode for a command invocation.
///
/// This is the single decision point. Every dispatch handler must call this
/// before doing any work. The result is deterministic given the inputs.
#[allow(dead_code)]
#[must_use]
pub fn resolve_runtime_mode(ctx: &RuntimeContext) -> RuntimeMode {
    let cls = classify_command(&ctx.command);

    // Unknown commands default to Refused (let the parser handle the error).
    let cls = match cls {
        Some(c) => c,
        None => return RuntimeMode::Refused,
    };

    // If the user explicitly requested offline mode:
    if ctx.offline_flag {
        return match cls.truth_source {
            // Hybrid and OfflineArtifact commands support offline.
            CommandTruthSource::Hybrid | CommandTruthSource::OfflineArtifact => {
                RuntimeMode::ExplicitOffline
            }
            // LiveHost commands cannot go offline — refuse.
            CommandTruthSource::LiveHost => RuntimeMode::Refused,
            // Passthrough commands delegate to subsystem — treat as offline.
            CommandTruthSource::Passthrough => RuntimeMode::ExplicitOffline,
        };
    }

    // No offline flag — check host availability.
    match cls.host_absent {
        HostAbsentBehavior::Unaffected => {
            // Command doesn't need a host. If one is present, still use offline
            // semantics since the command is inherently local.
            RuntimeMode::ExplicitOffline
        }
        HostAbsentBehavior::FailFast => {
            // Command requires a live host.
            if ctx.host_resolved && ctx.host_reachable {
                RuntimeMode::Live
            } else {
                RuntimeMode::Refused
            }
        }
        HostAbsentBehavior::DegradedWithWarning => {
            // Command prefers live but can degrade.
            if ctx.host_resolved && ctx.host_reachable {
                RuntimeMode::Live
            } else {
                RuntimeMode::DegradedOffline
            }
        }
        HostAbsentBehavior::PassthroughDependent => {
            // Subsystem decides — if host is available use it, otherwise degrade.
            if ctx.host_resolved && ctx.host_reachable {
                RuntimeMode::Live
            } else {
                RuntimeMode::DegradedOffline
            }
        }
    }
}

/// Resolved boundary that a dispatch handler receives after mode resolution.
///
/// Bundles the mode with the pre-computed provenance and envelope metadata
/// the handler needs to build its response.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RuntimeBoundary {
    /// The resolved runtime mode.
    pub mode: RuntimeMode,
    /// The command being dispatched.
    pub command: String,
    /// If offline, the provenance marker to attach.
    pub offline_provenance: Option<OfflineProvenance>,
    /// If refused, the structured error.
    pub refusal: Option<HostAbsentError>,
}

/// Build a complete [`RuntimeBoundary`] from a [`RuntimeContext`].
///
/// This is the top-level entry point for dispatch handlers.
#[allow(dead_code)]
#[must_use]
pub fn resolve_boundary(ctx: &RuntimeContext) -> RuntimeBoundary {
    let mode = resolve_runtime_mode(ctx);

    let offline_prov = if mode.needs_provenance_marker() {
        let source = default_offline_source(&ctx.command);
        Some(offline_provenance(&ctx.command, source))
    } else {
        None
    };

    let refusal = if mode.is_refused() {
        let reason = if !ctx.host_resolved {
            HostAbsentReason::NotConfigured
        } else {
            HostAbsentReason::Unreachable
        };
        Some(host_absent_error(&ctx.command, reason))
    } else {
        None
    };

    RuntimeBoundary {
        mode,
        command: ctx.command.clone(),
        offline_provenance: offline_prov,
        refusal,
    }
}

/// Validate that a command's classification and resolved mode are consistent.
///
/// Returns `None` if consistent, or `Some(explanation)` if there is a mismatch.
/// This is a debug/test helper, not a runtime gate.
#[allow(dead_code)]
#[must_use]
pub fn validate_mode_consistency(command: &str, mode: RuntimeMode) -> Option<String> {
    let cls = classify_command(command)?;

    match (cls.truth_source, mode) {
        // LiveHost commands must be Live or Refused — never offline.
        (CommandTruthSource::LiveHost, RuntimeMode::ExplicitOffline)
        | (CommandTruthSource::LiveHost, RuntimeMode::DegradedOffline) => {
            Some(format!(
                "Command '{command}' is LiveHost but resolved to offline mode"
            ))
        }
        // OfflineArtifact commands should never be Live.
        (CommandTruthSource::OfflineArtifact, RuntimeMode::Live) => Some(format!(
            "Command '{command}' is OfflineArtifact but resolved to Live mode"
        )),
        _ => None,
    }
}

// ── Simulate truth contract ──────────────────────────────────────────────────
// Separates real connector simulation (dry-run with side-effect model) from
// host-level preflight (schema validation, policy check, budget estimation).
// The CLI must never present preflight as connector-level simulation.

/// What a connector actually supports for pre-execution analysis.
///
/// A connector may support full dry-run (real simulation), or only allow the
/// host to run a preflight check (validation + policy + budget). The CLI must
/// not conflate these — advertising "simulate" when only "preflight" is
/// available is dishonest.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulateCapability {
    /// The connector implements a real dry-run mode that models side effects
    /// without committing them. Output includes a meaningful side-effect
    /// prediction.
    FullDryRun,
    /// The host can validate schema, check policy, and estimate budget, but
    /// the connector itself has no dry-run mode. Output is limited to
    /// validation and policy results.
    PreflightOnly,
    /// The connector has not been audited for simulate support. The CLI must
    /// not assume either capability.
    Unknown,
    /// The connector explicitly does not support any form of pre-execution
    /// analysis. Simulation requests should be refused.
    Unsupported,
}

impl SimulateCapability {
    /// Machine-readable tag for embedding in output payloads.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::FullDryRun => "full-dry-run",
            Self::PreflightOnly => "preflight-only",
            Self::Unknown => "unknown",
            Self::Unsupported => "unsupported",
        }
    }

    /// Human-readable explanation of what "simulate" means for this capability.
    #[must_use]
    pub fn explanation(self) -> &'static str {
        match self {
            Self::FullDryRun => {
                "This connector supports full dry-run simulation. The output \
                 models predicted side effects without committing them."
            }
            Self::PreflightOnly => {
                "This connector only supports host-level preflight checks \
                 (schema validation, policy, budget). No connector-level \
                 dry-run is available."
            }
            Self::Unknown => {
                "This connector has not been audited for simulate support. \
                 Do not assume dry-run semantics are available."
            }
            Self::Unsupported => {
                "This connector does not support any form of pre-execution \
                 analysis. Simulation requests will be refused."
            }
        }
    }

    /// Whether the capability allows presenting output as "simulated".
    #[must_use]
    pub fn allows_simulate_label(self) -> bool {
        matches!(self, Self::FullDryRun)
    }

    /// Whether at least preflight checks are available.
    #[must_use]
    pub fn allows_preflight(self) -> bool {
        matches!(self, Self::FullDryRun | Self::PreflightOnly)
    }

    /// Whether the capability is definitively known (audited).
    #[must_use]
    pub fn is_audited(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// The result of a simulate or preflight request, with honest labeling.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulateResult {
    /// What level of simulation was actually performed.
    pub actual_capability: SimulateCapability,
    /// Whether the result represents a real connector dry-run or just
    /// host-level validation.
    pub is_connector_dry_run: bool,
    /// Caveat explaining the scope of the result.
    pub caveat: String,
    /// If only preflight was available but full dry-run was requested,
    /// this flag is true.
    pub downgraded: bool,
}

/// Build a simulate result with honest labeling based on what actually happened.
#[allow(dead_code)]
#[must_use]
pub fn simulate_result(
    requested_dry_run: bool,
    actual: SimulateCapability,
) -> SimulateResult {
    let downgraded = requested_dry_run && actual == SimulateCapability::PreflightOnly;
    let is_connector_dry_run = actual == SimulateCapability::FullDryRun;

    let caveat = if downgraded {
        "Full dry-run was requested but this connector only supports \
         preflight checks. The result shows validation and policy outcomes \
         only — not predicted side effects."
            .to_owned()
    } else if is_connector_dry_run {
        "This is a full connector dry-run. Predicted side effects are \
         modeled but not committed."
            .to_owned()
    } else {
        actual.explanation().to_owned()
    };

    SimulateResult {
        actual_capability: actual,
        is_connector_dry_run,
        caveat,
        downgraded,
    }
}

/// Convert a [`SimulateResult`] to a JSON payload for embedding in output.
#[allow(dead_code)]
#[must_use]
pub fn simulate_result_payload(result: &SimulateResult) -> Value {
    json!({
        "simulate_capability": result.actual_capability.tag(),
        "is_connector_dry_run": result.is_connector_dry_run,
        "caveat": result.caveat,
        "downgraded": result.downgraded,
    })
}

/// Determine if a simulate request should proceed, be downgraded, or be refused.
///
/// Returns `Ok(SimulateCapability)` with the actual capability to use, or
/// `Err(reason)` if the request should be refused.
#[allow(dead_code)]
pub fn evaluate_simulate_request(
    capability: SimulateCapability,
    allow_downgrade: bool,
) -> Result<SimulateCapability, &'static str> {
    match capability {
        SimulateCapability::FullDryRun => Ok(SimulateCapability::FullDryRun),
        SimulateCapability::PreflightOnly => {
            if allow_downgrade {
                Ok(SimulateCapability::PreflightOnly)
            } else {
                Err(
                    "This connector only supports preflight checks, not full dry-run. \
                     Pass --allow-preflight to proceed with validation-only output.",
                )
            }
        }
        SimulateCapability::Unknown => Err(
            "This connector has not been audited for simulate support. \
             Cannot proceed without a known capability.",
        ),
        SimulateCapability::Unsupported => Err(
            "This connector does not support simulation or preflight. \
             The request cannot proceed.",
        ),
    }
}

// ── Discovery truth contract ─────────────────────────────────────────────────
// Defines how discovery commands (list, search, show, ops, schema, examples,
// suggest) honestly label the source and freshness of their data.

/// Where discovery data actually came from.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryDataSource {
    /// Live host inventory via RPC (authoritative, fresh).
    LiveHostInventory,
    /// Live host introspection via RPC (authoritative, fresh).
    LiveHostIntrospection,
    /// Workspace manifest files on disk (stale, offline).
    WorkspaceManifest,
    /// Local discovery catalog cache (stale, offline).
    LocalCatalogCache,
    /// Static embedded schema (always available, never stale but never live).
    StaticSchema,
}

impl DiscoveryDataSource {
    /// Whether this source is authoritative (reflects current live state).
    #[must_use]
    pub fn is_authoritative(&self) -> bool {
        matches!(
            self,
            Self::LiveHostInventory | Self::LiveHostIntrospection
        )
    }

    /// Whether this source is from offline/local artifacts.
    #[must_use]
    pub fn is_offline(&self) -> bool {
        matches!(
            self,
            Self::WorkspaceManifest | Self::LocalCatalogCache | Self::StaticSchema
        )
    }

    /// Machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LiveHostInventory => "live-host-inventory",
            Self::LiveHostIntrospection => "live-host-introspection",
            Self::WorkspaceManifest => "workspace-manifest",
            Self::LocalCatalogCache => "local-catalog-cache",
            Self::StaticSchema => "static-schema",
        }
    }

    /// Freshness caveat for this source.
    #[must_use]
    pub fn freshness_caveat(&self) -> &'static str {
        match self {
            Self::LiveHostInventory => "Data reflects the current host inventory.",
            Self::LiveHostIntrospection => {
                "Data reflects the current connector introspection state."
            }
            Self::WorkspaceManifest => {
                "Data is from workspace manifests and may not reflect current host state."
            }
            Self::LocalCatalogCache => {
                "Data is from a local cache and may be stale."
            }
            Self::StaticSchema => {
                "Data is from embedded static schemas, not live connector state."
            }
        }
    }
}

/// Provenance envelope for discovery command output.
///
/// Every discovery response must include this so consumers know whether
/// they are looking at live host data or offline artifacts.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryProvenance {
    /// The command that produced this output.
    pub command: String,
    /// Where the data actually came from.
    pub source: DiscoveryDataSource,
    /// Whether the output is authoritative.
    pub authoritative: bool,
    /// Freshness caveat.
    pub caveat: String,
    /// When the data was fetched (for staleness tracking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetched_at: Option<String>,
}

/// Build a discovery provenance envelope for a command.
#[allow(dead_code)]
#[must_use]
pub fn discovery_provenance(command: &str, source: DiscoveryDataSource) -> DiscoveryProvenance {
    DiscoveryProvenance {
        command: command.to_owned(),
        authoritative: source.is_authoritative(),
        caveat: source.freshness_caveat().to_owned(),
        source,
        fetched_at: None,
    }
}

/// All discovery commands that should carry a `DiscoveryProvenance` envelope.
#[allow(dead_code)]
pub const DISCOVERY_COMMANDS: &[&str] = &[
    "list", "search", "show", "ops", "schema", "examples", "suggest",
];

/// Check if a command is a discovery command.
#[allow(dead_code)]
#[must_use]
pub fn is_discovery_command(command: &str) -> bool {
    DISCOVERY_COMMANDS.contains(&command)
}

/// Determine the expected discovery source for a command given the runtime mode.
#[allow(dead_code)]
#[must_use]
pub fn expected_discovery_source(
    command: &str,
    mode: RuntimeMode,
) -> Option<DiscoveryDataSource> {
    if !is_discovery_command(command) {
        return None;
    }

    Some(match mode {
        RuntimeMode::Live => {
            // show and ops use introspection; others use inventory
            match command {
                "show" | "ops" | "schema" | "examples" => {
                    DiscoveryDataSource::LiveHostIntrospection
                }
                _ => DiscoveryDataSource::LiveHostInventory,
            }
        }
        RuntimeMode::ExplicitOffline | RuntimeMode::DegradedOffline => {
            DiscoveryDataSource::WorkspaceManifest
        }
        RuntimeMode::Refused => return None,
    })
}

// ── Package artifact source validation ───────────────────────────────────────
// Defines the allowed sources for connector packages on install/update runtime
// paths. Demo, stub, and placeholder sources are explicitly rejected. Test
// code may use demo fixtures, but the canonical runtime paths refuse them.

/// Where a connector package artifact originates.
///
/// Install and update dispatch paths must validate the source before
/// proceeding. Only production-grade sources are accepted on runtime paths.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageArtifactSource {
    /// A real local directory containing a built package output.
    LocalDirectory(String),
    /// A real registry reference (URL or registry ID).
    Registry(String),
    /// A real mesh-distributed package bundle.
    MeshBundle(String),
    /// An offline-prepared package bundle (pre-verified, signed).
    OfflinePrepared(String),
    /// A demo/test fixture (REJECTED on runtime paths).
    DemoFixture(String),
    /// A stub/placeholder source (REJECTED on runtime paths).
    StubPlaceholder(String),
}

impl PackageArtifactSource {
    /// Whether this source is acceptable for runtime install/update paths.
    #[must_use]
    pub fn is_runtime_acceptable(&self) -> bool {
        !matches!(self, Self::DemoFixture(_) | Self::StubPlaceholder(_))
    }

    /// Whether this source is a demo or placeholder (test-only).
    #[must_use]
    pub fn is_demo_or_placeholder(&self) -> bool {
        matches!(self, Self::DemoFixture(_) | Self::StubPlaceholder(_))
    }

    /// Machine-readable tag for the source type.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::LocalDirectory(_) => "local-directory",
            Self::Registry(_) => "registry",
            Self::MeshBundle(_) => "mesh-bundle",
            Self::OfflinePrepared(_) => "offline-prepared",
            Self::DemoFixture(_) => "demo-fixture",
            Self::StubPlaceholder(_) => "stub-placeholder",
        }
    }

    /// The path or identifier for this source.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::LocalDirectory(p)
            | Self::Registry(p)
            | Self::MeshBundle(p)
            | Self::OfflinePrepared(p)
            | Self::DemoFixture(p)
            | Self::StubPlaceholder(p) => p,
        }
    }
}

/// Error returned when a demo/stub source is used on a runtime path.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoSourceRejection {
    /// What kind of source was rejected.
    pub source_tag: String,
    /// The path or identifier of the rejected source.
    pub source_path: String,
    /// Human-readable explanation.
    pub reason: String,
    /// Suggested remediation steps.
    pub next_actions: Vec<String>,
}

/// Validate a package source for use on a runtime install/update path.
///
/// Returns `Ok(())` if the source is acceptable, or `Err(DemoSourceRejection)`
/// if the source is a demo fixture or stub placeholder.
#[allow(dead_code)]
pub fn validate_package_source(
    source: &PackageArtifactSource,
    command: &str,
) -> Result<(), DemoSourceRejection> {
    if source.is_runtime_acceptable() {
        return Ok(());
    }

    Err(DemoSourceRejection {
        source_tag: source.tag().to_owned(),
        source_path: source.path().to_owned(),
        reason: format!(
            "The '{command}' command requires a real package source, not a {}. \
             Demo fixtures and stub placeholders are only valid in test environments.",
            source.tag()
        ),
        next_actions: vec![
            format!("Use `fwc package <connector>` to build a real package artifact"),
            format!("Or provide a real registry reference: `fwc {command} --source registry:<id>`"),
            format!("Or provide a real local directory: `fwc {command} --source <path>`"),
        ],
    })
}

/// Convert a [`DemoSourceRejection`] to a JSON payload.
#[allow(dead_code)]
#[must_use]
pub fn demo_source_rejection_payload(rejection: &DemoSourceRejection) -> Value {
    json!({
        "error": "demo_source_rejected",
        "source_tag": rejection.source_tag,
        "source_path": rejection.source_path,
        "reason": rejection.reason,
        "next_actions": rejection.next_actions,
    })
}

/// Known marker strings that indicate a demo or placeholder artifact.
///
/// Used to detect when a path or identifier is synthetic even if not explicitly
/// tagged as a `DemoFixture` or `StubPlaceholder`.
#[allow(dead_code)]
pub const DEMO_MARKERS: &[&str] = &[
    "fixture-connector",
    "placeholder",
    "PLACEHOLDER",
    "demo-package",
    "stub-connector",
    "deadbeef",
    "0000000000000000",
    "test-only",
    "fake-registry",
];

/// Check whether a string contains any known demo/placeholder markers.
#[allow(dead_code)]
#[must_use]
pub fn contains_demo_marker(s: &str) -> bool {
    DEMO_MARKERS.iter().any(|marker| s.contains(marker))
}

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

// ── Capability token source validation ───────────────────────────────────────
// Ensures that live execution paths only use capability tokens from real
// issuance flows. Test tokens and placeholder authority must be rejected.

/// Where a capability token originated.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityTokenSource {
    /// Issued by the host through the real capability issuance RPC.
    HostIssued {
        /// The host endpoint that issued the token.
        endpoint: String,
    },
    /// Supplied via environment variable (FWC_CAPABILITY_TOKEN).
    EnvironmentVariable,
    /// Supplied via CLI flag (--capability-token).
    CliFlag,
    /// Generated by a test helper (REJECTED on live paths).
    TestGenerated,
    /// Placeholder or empty token (REJECTED on live paths).
    Placeholder,
}

impl CapabilityTokenSource {
    /// Whether this source is acceptable for live execution paths.
    #[must_use]
    pub fn is_live_acceptable(&self) -> bool {
        !matches!(self, Self::TestGenerated | Self::Placeholder)
    }

    /// Whether this source is synthetic (test/placeholder).
    #[must_use]
    pub fn is_synthetic(&self) -> bool {
        matches!(self, Self::TestGenerated | Self::Placeholder)
    }

    /// Machine-readable tag.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::HostIssued { .. } => "host-issued",
            Self::EnvironmentVariable => "environment-variable",
            Self::CliFlag => "cli-flag",
            Self::TestGenerated => "test-generated",
            Self::Placeholder => "placeholder",
        }
    }
}

/// Error returned when a synthetic capability token is used on a live path.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyntheticTokenRejection {
    /// The command that requires a real token.
    pub command: String,
    /// What kind of token was rejected.
    pub source_tag: String,
    /// Human-readable explanation.
    pub reason: String,
    /// How to obtain a real token.
    pub next_actions: Vec<String>,
}

/// Validate a capability token source for a live execution path.
///
/// Returns `Ok(())` if the source is acceptable, or `Err(SyntheticTokenRejection)`
/// if the source is synthetic.
#[allow(dead_code)]
pub fn validate_capability_token_source(
    source: &CapabilityTokenSource,
    command: &str,
) -> Result<(), SyntheticTokenRejection> {
    if source.is_live_acceptable() {
        return Ok(());
    }

    Err(SyntheticTokenRejection {
        command: command.to_owned(),
        source_tag: source.tag().to_owned(),
        reason: format!(
            "The '{command}' command requires a real capability token, not a {}. \
             Test-generated and placeholder tokens are only valid in test environments.",
            source.tag()
        ),
        next_actions: vec![
            "Issue a real token: `fwc capabilities issue --connector <id> --operation <op>`"
                .to_owned(),
            format!("Or set FWC_CAPABILITY_TOKEN with a host-issued token"),
            format!("Or pass --capability-token <base64> from a real issuance flow"),
        ],
    })
}

/// Known marker strings in token values that indicate synthetic tokens.
#[allow(dead_code)]
pub const SYNTHETIC_TOKEN_MARKERS: &[&str] = &[
    "test-token",
    "test_token",
    "placeholder-token",
    "AAAAAAAAAA",
    "fake-capability",
    "demo-token",
];

/// Check whether a raw token string contains synthetic markers.
#[allow(dead_code)]
#[must_use]
pub fn contains_synthetic_token_marker(token: &str) -> bool {
    SYNTHETIC_TOKEN_MARKERS
        .iter()
        .any(|marker| token.contains(marker))
}

/// Classify a raw token string into a source based on content analysis.
///
/// This is a heuristic — it can't verify issuance, but it can catch obvious
/// test/placeholder tokens.
#[allow(dead_code)]
#[must_use]
pub fn classify_token_source(token: &str) -> CapabilityTokenSource {
    if token.is_empty() {
        return CapabilityTokenSource::Placeholder;
    }
    if contains_synthetic_token_marker(token) {
        return CapabilityTokenSource::TestGenerated;
    }
    // Cannot distinguish real sources without issuance metadata —
    // return CliFlag as the conservative default for non-empty, non-synthetic
    // tokens provided directly.
    CapabilityTokenSource::CliFlag
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
        AuthAcquisitionFlow, COMMAND_CLASSIFICATIONS, COMMANDS, CapabilityTokenSource,
        CommandExecutionMode, CommandTruthSource, DEMO_MARKERS, DISCOVERY_COMMANDS,
        DiscoveryDataSource, HYBRID_MODE_HELP, HostAbsentBehavior, HostAbsentReason,
        OFFLINE_FLAG_HELP, OfflineSource, PackageArtifactSource, RuntimeContext, RuntimeMode,
        SYNTHETIC_TOKEN_MARKERS, SimulateCapability, WorkflowKind, WorkflowStepReality,
        auth_required_commands, auth_ux_guidance, check_auth_requirement, classify_command,
        classify_token_source, command_requires_host, contains_demo_marker,
        contains_synthetic_token_marker, default_offline_source, demo_source_rejection_payload,
        discovery_provenance, evaluate_simulate_request, expected_discovery_source, guide_payload,
        host_absent_error, host_absent_error_payload, is_discovery_command, live_host_commands,
        offline_capable_commands, offline_provenance, offline_provenance_payload, planned_payload,
        resolve_boundary, resolve_runtime_mode, simulate_result, simulate_result_payload,
        validate_capability_token_source, validate_mode_consistency, validate_package_source,
        workflow_can_proceed, workflow_kind,
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

    // ── Truthfulness invariant suite (bead 1g7z0.29.8.4) ─────────────
    // Deterministic golden fixtures, source-of-truth classification,
    // live-vs-offline wording, refusal semantics, and envelope stability.

    // ── Source-of-truth classification golden fixtures ─────────────────

    #[test]
    fn truth_source_serde_roundtrip_all_variants() {
        let variants = [
            (CommandTruthSource::LiveHost, "\"live_host\""),
            (CommandTruthSource::OfflineArtifact, "\"offline_artifact\""),
            (CommandTruthSource::Hybrid, "\"hybrid\""),
            (CommandTruthSource::Passthrough, "\"passthrough\""),
        ];
        for (src, expected_json) in variants {
            let json = serde_json::to_string(&src).unwrap();
            assert_eq!(json, expected_json, "serde for {src:?}");
            let back: CommandTruthSource = serde_json::from_str(&json).unwrap();
            assert_eq!(back, src);
        }
    }

    #[test]
    fn execution_mode_serde_roundtrip_all_variants() {
        let variants = [
            (CommandExecutionMode::ReadOnly, "\"read_only\""),
            (CommandExecutionMode::Mutating, "\"mutating\""),
            (CommandExecutionMode::Simulate, "\"simulate\""),
            (CommandExecutionMode::Interactive, "\"interactive\""),
            (CommandExecutionMode::LocalOnly, "\"local_only\""),
        ];
        for (mode, expected_json) in variants {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, expected_json, "serde for {mode:?}");
            let back: CommandExecutionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn host_absent_behavior_serde_roundtrip_all_variants() {
        let variants = [
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
        ];
        for (beh, expected_json) in variants {
            let json = serde_json::to_string(&beh).unwrap();
            assert_eq!(json, expected_json, "serde for {beh:?}");
            let back: HostAbsentBehavior = serde_json::from_str(&json).unwrap();
            assert_eq!(back, beh);
        }
    }

    #[test]
    fn host_absent_reason_serde_roundtrip_all_variants() {
        let variants = [
            (HostAbsentReason::NotConfigured, "\"not-configured\""),
            (HostAbsentReason::Unreachable, "\"unreachable\""),
            (HostAbsentReason::Unhealthy, "\"unhealthy\""),
        ];
        for (reason, expected_json) in variants {
            let json = serde_json::to_string(&reason).unwrap();
            assert_eq!(json, expected_json, "serde for {reason:?}");
            let back: HostAbsentReason = serde_json::from_str(&json).unwrap();
            assert_eq!(back, reason);
        }
    }

    #[test]
    fn offline_source_serde_roundtrip_all_variants() {
        let variants = [
            (OfflineSource::WorkspaceManifest, "\"workspace-manifest\""),
            (OfflineSource::LocalCatalog, "\"local-catalog\""),
            (OfflineSource::LocalHistory, "\"local-history\""),
            (OfflineSource::StaticContract, "\"static-contract\""),
            (OfflineSource::Subsystem, "\"subsystem\""),
        ];
        for (src, expected_json) in variants {
            let json = serde_json::to_string(&src).unwrap();
            assert_eq!(json, expected_json, "serde for {src:?}");
            let back: OfflineSource = serde_json::from_str(&json).unwrap();
            assert_eq!(back, src);
        }
    }

    #[test]
    fn workflow_step_reality_serde_roundtrip_all_variants() {
        let variants = [
            (WorkflowStepReality::Executed, "\"executed\""),
            (WorkflowStepReality::Planned, "\"planned\""),
            (
                WorkflowStepReality::HostUnavailable,
                "\"host_unavailable\"",
            ),
            (WorkflowStepReality::AuthDenied, "\"auth_denied\""),
            (WorkflowStepReality::Unsupported, "\"unsupported\""),
            (WorkflowStepReality::Skipped, "\"skipped\""),
        ];
        for (reality, expected_json) in variants {
            let json = serde_json::to_string(&reality).unwrap();
            assert_eq!(json, expected_json, "serde for {reality:?}");
            let back: WorkflowStepReality = serde_json::from_str(&json).unwrap();
            assert_eq!(back, reality);
        }
    }

    #[test]
    fn workflow_kind_serde_roundtrip_all_variants() {
        let variants = [
            (WorkflowKind::LocalTransform, "\"local_transform\""),
            (
                WorkflowKind::OrchestratedExecution,
                "\"orchestrated_execution\"",
            ),
        ];
        for (kind, expected_json) in variants {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, expected_json, "serde for {kind:?}");
            let back: WorkflowKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    // ── Classification matrix golden invariants ────────────────────────

    #[test]
    fn every_classified_command_exists_in_commands_constant() {
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                COMMANDS.contains(&cls.command),
                "Classified command '{}' not in COMMANDS",
                cls.command
            );
        }
    }

    #[test]
    fn no_offline_artifact_command_requires_capability_token() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    !cls.requires_capability_token,
                    "Offline command '{}' should never require a capability token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn no_offline_artifact_command_needs_approval() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    !cls.may_need_approval,
                    "Offline command '{}' should never need approval",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_offline_artifact_commands_are_unaffected_by_host_absence() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::Unaffected,
                    "Offline command '{}' host_absent should be Unaffected",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_offline_artifact_commands_are_local_only() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert_eq!(
                    cls.execution_mode,
                    CommandExecutionMode::LocalOnly,
                    "Offline command '{}' should be LocalOnly",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_live_host_commands_fail_fast_when_host_absent() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::FailFast,
                    "Live host command '{}' should FailFast when host absent",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn execution_mutating_live_commands_require_token_or_approval() {
        // Execution-family mutating commands (invoke, map, batch-file, recipe,
        // pipeline) must require a capability token or approval. Lifecycle/admin
        // commands (install, update, config, etc.) are exempt — they're admin ops.
        let execution_mutating = [
            "invoke", "map", "batch-file", "recipe", "pipeline",
        ];
        for cmd in execution_mutating {
            let cls = classify_command(cmd).unwrap();
            assert!(
                cls.requires_capability_token || cls.may_need_approval,
                "Execution mutating command '{}' should require token or approval",
                cls.command
            );
        }
    }

    #[test]
    fn all_passthrough_commands_are_local_only() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Passthrough {
                assert_eq!(
                    cls.execution_mode,
                    CommandExecutionMode::LocalOnly,
                    "Passthrough command '{}' should be LocalOnly",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn all_passthrough_commands_are_passthrough_dependent() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Passthrough {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::PassthroughDependent,
                    "Passthrough command '{}' host_absent should be PassthroughDependent",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn no_passthrough_command_requires_token() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Passthrough {
                assert!(
                    !cls.requires_capability_token,
                    "Passthrough command '{}' should not require token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn hybrid_commands_are_read_only_or_mutating() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid {
                assert!(
                    cls.execution_mode == CommandExecutionMode::ReadOnly
                        || cls.execution_mode == CommandExecutionMode::Mutating,
                    "Hybrid command '{}' has unexpected mode {:?}",
                    cls.command,
                    cls.execution_mode
                );
            }
        }
    }

    #[test]
    fn every_classification_has_non_empty_transport_note() {
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                !cls.transport_note.is_empty(),
                "Command '{}' has empty transport_note",
                cls.command
            );
        }
    }

    #[test]
    fn classify_command_returns_none_for_unknown() {
        assert!(classify_command("nonexistent-xyz").is_none());
    }

    #[test]
    fn classify_command_returns_some_for_all_classified() {
        for cls in COMMAND_CLASSIFICATIONS {
            let found = classify_command(cls.command);
            assert!(found.is_some(), "classify_command({}) should find it", cls.command);
            assert_eq!(found.unwrap().command, cls.command);
        }
    }

    // ── Live vs offline wording invariants ─────────────────────────────

    #[test]
    fn host_absent_error_not_configured_mentions_fcp_host() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            err.message.contains("fcp-host"),
            "NotConfigured error should mention fcp-host: {}",
            err.message
        );
    }

    #[test]
    fn host_absent_error_not_configured_says_will_not_simulate() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            err.message.contains("will not simulate")
                || err.message.contains("will not fabricate"),
            "NotConfigured error should state refusal: {}",
            err.message
        );
    }

    #[test]
    fn host_absent_error_unreachable_mentions_connection() {
        let err = host_absent_error("status", HostAbsentReason::Unreachable);
        assert!(
            err.message.contains("reach") || err.message.contains("connection"),
            "Unreachable error should mention connection: {}",
            err.message
        );
    }

    #[test]
    fn host_absent_error_unhealthy_mentions_health() {
        let err = host_absent_error("doctor", HostAbsentReason::Unhealthy);
        assert!(
            err.message.contains("unhealthy") || err.message.contains("health"),
            "Unhealthy error should mention health: {}",
            err.message
        );
    }

    #[test]
    fn host_absent_error_for_all_reasons_has_next_actions() {
        let reasons = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ];
        for reason in reasons {
            let err = host_absent_error("invoke", reason);
            assert!(
                !err.next_actions.is_empty(),
                "host_absent_error({reason:?}) should have next_actions"
            );
        }
    }

    #[test]
    fn host_absent_error_not_configured_suggests_host_flag() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            err.next_actions.iter().any(|a| a.contains("--host")),
            "NotConfigured should suggest --host flag"
        );
    }

    #[test]
    fn host_absent_error_not_configured_suggests_env_var() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            err.next_actions
                .iter()
                .any(|a| a.contains("FWC_HOST") || a.contains("FCP_HOST")),
            "NotConfigured should suggest env var"
        );
    }

    #[test]
    fn host_absent_error_unreachable_suggests_doctor() {
        let err = host_absent_error("status", HostAbsentReason::Unreachable);
        assert!(
            err.next_actions.iter().any(|a| a.contains("doctor")),
            "Unreachable should suggest doctor check"
        );
    }

    #[test]
    fn host_absent_error_for_hybrid_command_suggests_offline() {
        let err = host_absent_error("list", HostAbsentReason::NotConfigured);
        assert!(
            err.next_actions.iter().any(|a| a.contains("--offline")),
            "Hybrid command 'list' should suggest --offline alternative"
        );
    }

    #[test]
    fn host_absent_error_for_live_command_does_not_suggest_offline() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert!(
            !err.next_actions.iter().any(|a| a.contains("--offline")),
            "Live command 'invoke' should NOT suggest --offline"
        );
    }

    #[test]
    fn host_absent_error_all_reasons_recoverable() {
        let reasons = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ];
        for reason in reasons {
            let err = host_absent_error("invoke", reason);
            assert!(err.recoverable, "host_absent_error should be recoverable");
        }
    }

    // ── Host-absent error payload envelope stability ──────────────────

    #[test]
    fn host_absent_error_payload_has_stable_envelope() {
        let err = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        let payload = host_absent_error_payload(&err);
        // Verify envelope keys are stable
        assert_eq!(payload["status"], "error");
        assert_eq!(payload["command"], "invoke");
        assert!(payload["error"].is_object());
        assert!(payload["error"]["type"].is_string());
        assert!(payload["error"]["reason"].is_string());
        assert!(payload["error"]["message"].is_string());
        assert!(payload["error"]["recoverable"].is_boolean());
        assert!(payload["next_actions"].is_array());
    }

    #[test]
    fn host_absent_error_payload_error_type_is_stable() {
        let not_configured = host_absent_error("invoke", HostAbsentReason::NotConfigured);
        assert_eq!(
            host_absent_error_payload(&not_configured)["error"]["type"],
            "missing-host-endpoint"
        );
        let unreachable = host_absent_error("invoke", HostAbsentReason::Unreachable);
        assert_eq!(
            host_absent_error_payload(&unreachable)["error"]["type"],
            "host-unreachable"
        );
        let unhealthy = host_absent_error("invoke", HostAbsentReason::Unhealthy);
        assert_eq!(
            host_absent_error_payload(&unhealthy)["error"]["type"],
            "host-unhealthy"
        );
    }

    #[test]
    fn host_absent_error_payload_serde_roundtrip() {
        let err = host_absent_error("simulate", HostAbsentReason::Unreachable);
        let val: serde_json::Value = serde_json::to_value(&err).unwrap();
        assert_eq!(val["command"], "simulate");
        assert_eq!(val["reason"], "unreachable");
        assert_eq!(val["exit_code"], 8);
        assert_eq!(val["error_type"], "host-unreachable");
    }

    // ── Offline provenance invariants ──────────────────────────────────

    #[test]
    fn offline_provenance_hybrid_commands_all_have_live_alternative() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid {
                let source = default_offline_source(cls.command);
                let prov = offline_provenance(cls.command, source);
                assert!(
                    prov.live_alternative.is_some(),
                    "Hybrid '{}' provenance missing live_alternative",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn offline_provenance_for_offline_artifact_has_no_live_alternative() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                let source = default_offline_source(cls.command);
                let prov = offline_provenance(cls.command, source);
                assert!(
                    prov.live_alternative.is_none(),
                    "Offline-only command '{}' should not have live_alternative",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn offline_provenance_live_alternative_mentions_host_flag() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        let alt = prov.live_alternative.as_deref().unwrap();
        assert!(
            alt.contains("--host"),
            "live_alternative should mention --host: {alt}"
        );
    }

    #[test]
    fn offline_provenance_live_alternative_mentions_omit_offline() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        let alt = prov.live_alternative.as_deref().unwrap();
        assert!(
            alt.contains("omit --offline"),
            "live_alternative should suggest omitting --offline: {alt}"
        );
    }

    #[test]
    fn offline_provenance_always_marked_offline() {
        for cls in COMMAND_CLASSIFICATIONS {
            let source = default_offline_source(cls.command);
            let prov = offline_provenance(cls.command, source);
            assert!(
                prov.offline,
                "offline_provenance for '{}' should be offline=true",
                cls.command
            );
        }
    }

    #[test]
    fn offline_provenance_has_non_empty_caveat() {
        for cls in COMMAND_CLASSIFICATIONS {
            let source = default_offline_source(cls.command);
            let prov = offline_provenance(cls.command, source);
            assert!(
                !prov.caveat.is_empty(),
                "offline_provenance for '{}' should have non-empty caveat",
                cls.command
            );
        }
    }

    #[test]
    fn offline_provenance_caveat_varies_by_source() {
        let manifest_prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        let catalog_prov = offline_provenance("list", OfflineSource::LocalCatalog);
        let history_prov = offline_provenance("history", OfflineSource::LocalHistory);
        let static_prov = offline_provenance("guide", OfflineSource::StaticContract);
        let subsystem_prov = offline_provenance("audit", OfflineSource::Subsystem);

        // All caveats should be distinct
        let caveats = [
            manifest_prov.caveat,
            catalog_prov.caveat,
            history_prov.caveat,
            static_prov.caveat,
            subsystem_prov.caveat,
        ];
        let unique: std::collections::HashSet<&str> = caveats.iter().copied().collect();
        assert_eq!(
            unique.len(),
            caveats.len(),
            "Each offline source should have a distinct caveat"
        );
    }

    // ── Offline provenance payload envelope stability ─────────────────

    #[test]
    fn offline_provenance_payload_has_stable_keys() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        let payload = offline_provenance_payload(&prov);
        assert!(payload["offline"].is_boolean());
        assert!(payload["source"].is_string());
        assert!(payload["caveat"].is_string());
        assert!(payload["live_alternative"].is_string());
    }

    #[test]
    fn offline_provenance_payload_omits_live_alternative_when_none() {
        let prov = offline_provenance("guide", OfflineSource::StaticContract);
        let payload = offline_provenance_payload(&prov);
        assert!(payload["offline"].as_bool().unwrap());
        assert!(payload.get("live_alternative").is_none() || payload["live_alternative"].is_null());
    }

    #[test]
    fn offline_provenance_serde_roundtrip() {
        let prov = offline_provenance("show", OfflineSource::WorkspaceManifest);
        let val: serde_json::Value = serde_json::to_value(&prov).unwrap();
        assert_eq!(val["offline"], true);
        assert_eq!(val["source"], "workspace-manifest");
        assert!(val["live_alternative"].is_string());
    }

    // ── Default offline source correctness ────────────────────────────

    #[test]
    fn default_offline_source_golden_guide_static_contract() {
        assert_eq!(
            default_offline_source("guide"),
            OfflineSource::StaticContract
        );
    }

    #[test]
    fn default_offline_source_golden_history_local_history() {
        assert_eq!(
            default_offline_source("history"),
            OfflineSource::LocalHistory
        );
    }

    #[test]
    fn default_offline_source_golden_pipe_local_history() {
        assert_eq!(
            default_offline_source("pipe"),
            OfflineSource::LocalHistory
        );
    }

    #[test]
    fn default_offline_source_hybrid_commands_are_workspace_manifest() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid {
                assert_eq!(
                    default_offline_source(cls.command),
                    OfflineSource::WorkspaceManifest,
                    "Hybrid command '{}' default source should be WorkspaceManifest",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn default_offline_source_passthrough_commands_are_subsystem() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Passthrough {
                assert_eq!(
                    default_offline_source(cls.command),
                    OfflineSource::Subsystem,
                    "Passthrough command '{}' default source should be Subsystem",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn default_offline_source_unknown_command_falls_back_to_local_catalog() {
        assert_eq!(
            default_offline_source("nonexistent-xyz"),
            OfflineSource::LocalCatalog
        );
    }

    // ── Refusal semantics ─────────────────────────────────────────────

    #[test]
    fn command_requires_host_true_for_all_live_commands() {
        for cmd in live_host_commands() {
            assert!(
                command_requires_host(cmd),
                "command_requires_host({cmd}) should be true"
            );
        }
    }

    #[test]
    fn command_requires_host_false_for_offline_commands() {
        for cmd in offline_capable_commands() {
            // Hybrid commands DO require host by default (fail fast)
            let cls = classify_command(cmd).unwrap();
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    !command_requires_host(cmd),
                    "OfflineArtifact command {cmd} should not require host"
                );
            }
        }
    }

    #[test]
    fn command_requires_host_false_for_unknown() {
        assert!(!command_requires_host("does-not-exist-xyzzy"));
    }

    #[test]
    fn hybrid_commands_fail_fast_by_default() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::Hybrid
                && cls.execution_mode == CommandExecutionMode::ReadOnly
            {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::FailFast,
                    "Read-only hybrid command '{}' should FailFast by default",
                    cls.command
                );
            }
        }
    }

    // ── Workflow truth contract ────────────────────────────────────────

    #[test]
    fn workflow_kind_pipe_is_local_transform() {
        assert_eq!(workflow_kind("pipe"), Some(WorkflowKind::LocalTransform));
    }

    #[test]
    fn workflow_kind_recipe_is_orchestrated() {
        assert_eq!(
            workflow_kind("recipe"),
            Some(WorkflowKind::OrchestratedExecution)
        );
    }

    #[test]
    fn workflow_kind_pipeline_is_orchestrated() {
        assert_eq!(
            workflow_kind("pipeline"),
            Some(WorkflowKind::OrchestratedExecution)
        );
    }

    #[test]
    fn workflow_kind_unknown_is_none() {
        assert_eq!(workflow_kind("invoke"), None);
        assert_eq!(workflow_kind("list"), None);
        assert_eq!(workflow_kind("nonexistent"), None);
    }

    #[test]
    fn workflow_can_proceed_pipe_always_proceeds() {
        // pipe is local-only, never needs host or token
        assert!(workflow_can_proceed("pipe", false, false).is_none());
        assert!(workflow_can_proceed("pipe", true, true).is_none());
        assert!(workflow_can_proceed("pipe", true, false).is_none());
        assert!(workflow_can_proceed("pipe", false, true).is_none());
    }

    #[test]
    fn workflow_can_proceed_recipe_needs_host() {
        let result = workflow_can_proceed("recipe", false, true);
        assert_eq!(result, Some(WorkflowStepReality::HostUnavailable));
    }

    #[test]
    fn workflow_can_proceed_recipe_needs_token() {
        let result = workflow_can_proceed("recipe", true, false);
        assert_eq!(result, Some(WorkflowStepReality::AuthDenied));
    }

    #[test]
    fn workflow_can_proceed_recipe_both_present_ok() {
        assert!(workflow_can_proceed("recipe", true, true).is_none());
    }

    #[test]
    fn workflow_can_proceed_pipeline_needs_host() {
        let result = workflow_can_proceed("pipeline", false, false);
        assert_eq!(result, Some(WorkflowStepReality::HostUnavailable));
    }

    #[test]
    fn workflow_can_proceed_non_workflow_is_none() {
        assert!(workflow_can_proceed("invoke", false, false).is_none());
    }

    // ── Preflight vs simulate labeling ────────────────────────────────

    #[test]
    fn simulate_command_is_classified_as_simulate_mode() {
        let cls = classify_command("simulate").unwrap();
        assert_eq!(cls.execution_mode, CommandExecutionMode::Simulate);
    }

    #[test]
    fn invoke_command_is_classified_as_mutating() {
        let cls = classify_command("invoke").unwrap();
        assert_eq!(cls.execution_mode, CommandExecutionMode::Mutating);
    }

    #[test]
    fn simulate_and_invoke_both_require_live_host() {
        let sim = classify_command("simulate").unwrap();
        let inv = classify_command("invoke").unwrap();
        assert_eq!(sim.truth_source, CommandTruthSource::LiveHost);
        assert_eq!(inv.truth_source, CommandTruthSource::LiveHost);
    }

    #[test]
    fn simulate_requires_token_but_no_approval() {
        let cls = classify_command("simulate").unwrap();
        assert!(cls.requires_capability_token);
        assert!(!cls.may_need_approval);
    }

    #[test]
    fn invoke_requires_token_and_approval() {
        let cls = classify_command("invoke").unwrap();
        assert!(cls.requires_capability_token);
        assert!(cls.may_need_approval);
    }

    // ── Auth acquisition flow golden fixtures ─────────────────────────

    #[test]
    fn auth_acquisition_flow_golden_json_strings() {
        let variants = [
            (AuthAcquisitionFlow::Required, "\"required\""),
            (AuthAcquisitionFlow::Recommended, "\"recommended\""),
            (AuthAcquisitionFlow::NotNeeded, "\"not_needed\""),
        ];
        for (flow, expected_json) in variants {
            let json = serde_json::to_string(&flow).unwrap();
            assert_eq!(json, expected_json, "golden JSON for {flow:?}");
        }
    }

    #[test]
    fn auth_ux_guidance_missing_text_mentions_capabilities_issue() {
        let guidance = auth_ux_guidance("invoke");
        assert!(
            guidance.missing_guidance.contains("capabilities issue"),
            "Missing guidance should mention `capabilities issue`: {}",
            guidance.missing_guidance
        );
    }

    #[test]
    fn auth_ux_guidance_denial_text_mentions_revoked() {
        let guidance = auth_ux_guidance("invoke");
        assert!(
            guidance.denial_guidance.contains("revoked")
                || guidance.denial_guidance.contains("expired"),
            "Denial guidance should mention token revocation/expiry: {}",
            guidance.denial_guidance
        );
    }

    #[test]
    fn auth_ux_guidance_for_non_token_command_has_empty_methods() {
        let guidance = auth_ux_guidance("guide");
        assert!(guidance.supply_methods.is_empty());
        assert!(guidance.missing_guidance.is_empty());
        assert!(guidance.denial_guidance.is_empty());
    }

    // ── Help text constants ───────────────────────────────────────────

    #[test]
    fn offline_flag_help_mentions_provenance() {
        assert!(
            OFFLINE_FLAG_HELP.contains("provenance"),
            "OFFLINE_FLAG_HELP should mention provenance"
        );
    }

    #[test]
    fn hybrid_mode_help_mentions_offline() {
        assert!(
            HYBRID_MODE_HELP.contains("--offline"),
            "HYBRID_MODE_HELP should mention --offline flag"
        );
    }

    #[test]
    fn hybrid_mode_help_mentions_live_host() {
        assert!(
            HYBRID_MODE_HELP.contains("live host"),
            "HYBRID_MODE_HELP should mention live host default"
        );
    }

    // ── Filter function golden results ────────────────────────────────

    #[test]
    fn live_host_commands_includes_invoke_simulate_cancel() {
        let cmds = live_host_commands();
        assert!(cmds.contains(&"invoke"));
        assert!(cmds.contains(&"simulate"));
        assert!(cmds.contains(&"cancel"));
        assert!(cmds.contains(&"serve-mcp"));
    }

    #[test]
    fn live_host_commands_excludes_offline_and_hybrid() {
        let cmds = live_host_commands();
        assert!(!cmds.contains(&"guide"));
        assert!(!cmds.contains(&"pipe"));
        assert!(!cmds.contains(&"list")); // hybrid, not live-only
    }

    #[test]
    fn offline_capable_commands_includes_hybrid_and_offline() {
        let cmds = offline_capable_commands();
        // Hybrid commands
        assert!(cmds.contains(&"list"));
        assert!(cmds.contains(&"search"));
        assert!(cmds.contains(&"show"));
        // Offline-artifact commands
        assert!(cmds.contains(&"guide"));
        assert!(cmds.contains(&"history"));
        assert!(cmds.contains(&"pipe"));
    }

    #[test]
    fn offline_capable_commands_excludes_live_only() {
        let cmds = offline_capable_commands();
        assert!(!cmds.contains(&"invoke"));
        assert!(!cmds.contains(&"simulate"));
        assert!(!cmds.contains(&"install"));
    }

    #[test]
    fn auth_required_commands_subset_of_live_host() {
        let auth = auth_required_commands();
        let live = live_host_commands();
        for cmd in &auth {
            assert!(
                live.contains(cmd),
                "Auth-required command {cmd} should be a live-host command"
            );
        }
    }

    // ── Workflow step provenance envelope stability ────────────────────

    #[test]
    fn workflow_step_provenance_serde_roundtrip_executed() {
        let prov = super::WorkflowStepProvenance {
            step_id: "step-1".to_owned(),
            reality: WorkflowStepReality::Executed,
            operation: "send_message".to_owned(),
            connector: "slack:messaging:1.0".to_owned(),
            receipt_id: Some("rcpt-abc123".to_owned()),
            refusal_reason: None,
        };
        let json_str = serde_json::to_string(&prov).unwrap();
        let back: super::WorkflowStepProvenance = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.step_id, "step-1");
        assert_eq!(back.reality, WorkflowStepReality::Executed);
        assert!(back.receipt_id.is_some());
        assert!(back.refusal_reason.is_none());
    }

    #[test]
    fn workflow_step_provenance_serde_roundtrip_refused() {
        let prov = super::WorkflowStepProvenance {
            step_id: "step-2".to_owned(),
            reality: WorkflowStepReality::AuthDenied,
            operation: "delete_channel".to_owned(),
            connector: "slack:messaging:1.0".to_owned(),
            receipt_id: None,
            refusal_reason: Some("Capability token expired".to_owned()),
        };
        let json_str = serde_json::to_string(&prov).unwrap();
        let back: super::WorkflowStepProvenance = serde_json::from_str(&json_str).unwrap();
        assert_eq!(back.reality, WorkflowStepReality::AuthDenied);
        assert!(back.receipt_id.is_none());
        assert!(back.refusal_reason.is_some());
    }

    #[test]
    fn workflow_step_provenance_executed_omits_refusal_reason_in_json() {
        let prov = super::WorkflowStepProvenance {
            step_id: "step-1".to_owned(),
            reality: WorkflowStepReality::Executed,
            operation: "send_message".to_owned(),
            connector: "slack:messaging:1.0".to_owned(),
            receipt_id: Some("rcpt-abc".to_owned()),
            refusal_reason: None,
        };
        let json_str = serde_json::to_string(&prov).unwrap();
        assert!(
            !json_str.contains("refusal_reason"),
            "Executed step should skip_serializing refusal_reason"
        );
    }

    #[test]
    fn workflow_step_provenance_refused_omits_receipt_in_json() {
        let prov = super::WorkflowStepProvenance {
            step_id: "step-2".to_owned(),
            reality: WorkflowStepReality::HostUnavailable,
            operation: "list_channels".to_owned(),
            connector: "slack:messaging:1.0".to_owned(),
            receipt_id: None,
            refusal_reason: Some("Host unreachable".to_owned()),
        };
        let json_str = serde_json::to_string(&prov).unwrap();
        assert!(
            !json_str.contains("receipt_id"),
            "Refused step should skip_serializing receipt_id"
        );
    }

    // ── Classification full-matrix serde roundtrip ────────────────────

    #[test]
    fn command_classification_serde_roundtrip_all() {
        for cls in COMMAND_CLASSIFICATIONS {
            let val: serde_json::Value = serde_json::to_value(cls).unwrap();
            assert_eq!(val["command"], cls.command);
            assert_eq!(
                val["requires_capability_token"],
                cls.requires_capability_token
            );
            assert_eq!(val["may_need_approval"], cls.may_need_approval);
            assert_eq!(val["transport_note"], cls.transport_note);
            // Verify the enum fields serialize to known strings
            assert!(val["truth_source"].is_string());
            assert!(val["execution_mode"].is_string());
            assert!(val["host_absent"].is_string());
        }
    }

    // ── Cross-invariant consistency checks ─────────────────────────────

    #[test]
    fn no_local_only_command_requires_token() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.execution_mode == CommandExecutionMode::LocalOnly {
                assert!(
                    !cls.requires_capability_token,
                    "LocalOnly command '{}' should not require token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn interactive_commands_require_live_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.execution_mode == CommandExecutionMode::Interactive {
                assert_eq!(
                    cls.truth_source,
                    CommandTruthSource::LiveHost,
                    "Interactive command '{}' must be LiveHost",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn simulate_commands_require_live_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.execution_mode == CommandExecutionMode::Simulate {
                assert_eq!(
                    cls.truth_source,
                    CommandTruthSource::LiveHost,
                    "Simulate command '{}' must be LiveHost",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn classification_count_matches_at_least_thirty() {
        // Guard against accidental removal of classifications
        assert!(
            COMMAND_CLASSIFICATIONS.len() >= 30,
            "Expected at least 30 classified commands, got {}",
            COMMAND_CLASSIFICATIONS.len()
        );
    }

    #[test]
    fn every_classified_command_is_unique() {
        let mut seen = std::collections::HashSet::new();
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                seen.insert(cls.command),
                "Duplicate classification for '{}'",
                cls.command
            );
        }
    }

    // ── Truthfulness invariant tests (1g7z0.29.8.4) ─────────────────

    #[test]
    fn truthfulness_live_host_commands_always_fail_fast_when_absent() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::FailFast,
                    "LiveHost command '{}' must FailFast when host absent",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_offline_commands_are_unaffected_by_host_absence() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert_eq!(
                    cls.host_absent,
                    HostAbsentBehavior::Unaffected,
                    "OfflineArtifact command '{}' must be Unaffected by host absence",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_offline_commands_never_require_capability_tokens() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    !cls.requires_capability_token,
                    "OfflineArtifact command '{}' should not require capability token",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_offline_commands_never_need_approval() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    !cls.may_need_approval,
                    "OfflineArtifact command '{}' should not need approval",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_offline_commands_are_local_only_or_readonly() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    matches!(
                        cls.execution_mode,
                        CommandExecutionMode::LocalOnly | CommandExecutionMode::ReadOnly
                    ),
                    "OfflineArtifact command '{}' should be LocalOnly or ReadOnly, got {:?}",
                    cls.command,
                    cls.execution_mode
                );
            }
        }
    }

    #[test]
    fn truthfulness_mutating_live_commands_have_non_empty_transport_notes() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost
                && matches!(cls.execution_mode, CommandExecutionMode::Mutating)
            {
                assert!(
                    !cls.transport_note.is_empty(),
                    "Mutating LiveHost command '{}' must have a transport note",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_commands_requiring_cap_token_are_always_live_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.requires_capability_token {
                assert_eq!(
                    cls.truth_source,
                    CommandTruthSource::LiveHost,
                    "Command '{}' requires cap token but is {:?} (must be LiveHost)",
                    cls.command,
                    cls.truth_source
                );
            }
        }
    }

    #[test]
    fn truthfulness_all_commands_have_transport_notes() {
        for cls in COMMAND_CLASSIFICATIONS {
            assert!(
                !cls.transport_note.is_empty(),
                "Command '{}' has empty transport note",
                cls.command
            );
        }
    }

    #[test]
    fn truthfulness_truth_source_serde_round_trip() {
        let sources = [
            CommandTruthSource::LiveHost,
            CommandTruthSource::OfflineArtifact,
            CommandTruthSource::Hybrid,
            CommandTruthSource::Passthrough,
        ];
        for src in sources {
            let json = serde_json::to_string(&src).unwrap();
            let back: CommandTruthSource = serde_json::from_str(&json).unwrap();
            assert_eq!(back, src);
        }
    }

    #[test]
    fn truthfulness_execution_mode_serde_round_trip() {
        let modes = [
            CommandExecutionMode::ReadOnly,
            CommandExecutionMode::Mutating,
            CommandExecutionMode::Simulate,
            CommandExecutionMode::Interactive,
            CommandExecutionMode::LocalOnly,
        ];
        for mode in modes {
            let json = serde_json::to_string(&mode).unwrap();
            let back: CommandExecutionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode);
        }
    }

    #[test]
    fn truthfulness_host_absent_behavior_serde_round_trip() {
        let behaviors = [
            HostAbsentBehavior::FailFast,
            HostAbsentBehavior::DegradedWithWarning,
            HostAbsentBehavior::Unaffected,
            HostAbsentBehavior::PassthroughDependent,
        ];
        for b in behaviors {
            let json = serde_json::to_string(&b).unwrap();
            let back: HostAbsentBehavior = serde_json::from_str(&json).unwrap();
            assert_eq!(back, b);
        }
    }

    #[test]
    fn truthfulness_classify_command_known_commands_match_matrix() {
        // Every command in the classification matrix must be resolvable.
        for cls in COMMAND_CLASSIFICATIONS {
            let found = classify_command(cls.command);
            assert!(
                found.is_some(),
                "classify_command('{}') returned None but is in COMMAND_CLASSIFICATIONS",
                cls.command
            );
            let found = found.unwrap();
            assert_eq!(found.truth_source, cls.truth_source);
            assert_eq!(found.execution_mode, cls.execution_mode);
        }
    }

    #[test]
    fn truthfulness_classify_command_unknown_returns_none() {
        assert!(classify_command("nonexistent-command-xyz").is_none());
    }

    #[test]
    fn truthfulness_command_requires_host_is_consistent_with_matrix() {
        for cls in COMMAND_CLASSIFICATIONS {
            let requires = command_requires_host(cls.command);
            match cls.truth_source {
                CommandTruthSource::LiveHost => {
                    assert!(
                        requires,
                        "LiveHost command '{}' should require host",
                        cls.command
                    );
                }
                CommandTruthSource::OfflineArtifact => {
                    assert!(
                        !requires,
                        "OfflineArtifact command '{}' should not require host",
                        cls.command
                    );
                }
                _ => {} // Hybrid/Passthrough can go either way
            }
        }
    }

    #[test]
    fn truthfulness_live_host_commands_list_matches_matrix() {
        let live = live_host_commands();
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                assert!(
                    live.contains(&cls.command),
                    "LiveHost command '{}' missing from live_host_commands()",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_offline_capable_commands_list_matches_matrix() {
        let offline = offline_capable_commands();
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::OfflineArtifact {
                assert!(
                    offline.contains(&cls.command),
                    "OfflineArtifact command '{}' missing from offline_capable_commands()",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn truthfulness_auth_required_commands_subset_of_live_host() {
        let auth = auth_required_commands();
        for cmd in &auth {
            let cls = classify_command(cmd);
            assert!(
                cls.is_some(),
                "auth_required command '{}' not in classification matrix",
                cmd
            );
            let cls = cls.unwrap();
            assert!(
                cls.requires_capability_token || cls.may_need_approval,
                "auth_required command '{}' has neither cap token nor approval requirement",
                cmd
            );
        }
    }

    #[test]
    fn truthfulness_host_absent_error_is_informative() {
        let reasons = [
            HostAbsentReason::NotConfigured,
            HostAbsentReason::Unreachable,
            HostAbsentReason::Unhealthy,
        ];
        for reason in reasons {
            let err = host_absent_error("test-cmd", reason);
            assert!(!err.message.is_empty(), "host_absent_error for {:?} has empty message", reason);
            assert!(!err.next_actions.is_empty(), "host_absent_error for {:?} has no next_actions", reason);
        }
    }

    #[test]
    fn truthfulness_host_absent_error_payload_is_structured() {
        let err = host_absent_error("invoke", HostAbsentReason::Unreachable);
        let payload = host_absent_error_payload(&err);
        assert!(payload["error"].is_object());
        assert!(payload["command"].is_string());
    }

    #[test]
    fn truthfulness_offline_provenance_includes_source() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        assert!(!prov.caveat.is_empty());
        assert!(prov.offline);
    }

    #[test]
    fn truthfulness_offline_provenance_payload_has_required_shape() {
        let prov = offline_provenance("list", OfflineSource::WorkspaceManifest);
        let payload = offline_provenance_payload(&prov);
        assert_eq!(payload["offline"], true);
        assert!(payload["source"].is_string());
        assert!(payload["caveat"].is_string());
    }

    // ── Runtime truth boundary tests ──────────────────────────────────────

    fn ctx(command: &str, offline: bool, resolved: bool, reachable: bool) -> RuntimeContext {
        RuntimeContext {
            command: command.to_owned(),
            offline_flag: offline,
            host_resolved: resolved,
            host_reachable: reachable,
        }
    }

    // -- RuntimeMode tag stability --

    #[test]
    fn runtime_mode_tags_are_stable() {
        assert_eq!(RuntimeMode::Live.tag(), "live");
        assert_eq!(RuntimeMode::ExplicitOffline.tag(), "explicit-offline");
        assert_eq!(RuntimeMode::DegradedOffline.tag(), "degraded-offline");
        assert_eq!(RuntimeMode::Refused.tag(), "refused");
    }

    #[test]
    fn runtime_mode_live_is_authoritative() {
        assert!(RuntimeMode::Live.is_authoritative());
    }

    #[test]
    fn runtime_mode_offline_is_not_authoritative() {
        assert!(!RuntimeMode::ExplicitOffline.is_authoritative());
        assert!(!RuntimeMode::DegradedOffline.is_authoritative());
    }

    #[test]
    fn runtime_mode_refused_is_not_authoritative() {
        assert!(!RuntimeMode::Refused.is_authoritative());
    }

    #[test]
    fn runtime_mode_offline_variants_are_offline() {
        assert!(RuntimeMode::ExplicitOffline.is_offline());
        assert!(RuntimeMode::DegradedOffline.is_offline());
    }

    #[test]
    fn runtime_mode_live_is_not_offline() {
        assert!(!RuntimeMode::Live.is_offline());
    }

    #[test]
    fn runtime_mode_refused_is_not_offline() {
        assert!(!RuntimeMode::Refused.is_offline());
    }

    #[test]
    fn runtime_mode_only_refused_is_refused() {
        assert!(RuntimeMode::Refused.is_refused());
        assert!(!RuntimeMode::Live.is_refused());
        assert!(!RuntimeMode::ExplicitOffline.is_refused());
        assert!(!RuntimeMode::DegradedOffline.is_refused());
    }

    #[test]
    fn runtime_mode_provenance_marker_needed_for_offline() {
        assert!(RuntimeMode::ExplicitOffline.needs_provenance_marker());
        assert!(RuntimeMode::DegradedOffline.needs_provenance_marker());
        assert!(!RuntimeMode::Live.needs_provenance_marker());
        assert!(!RuntimeMode::Refused.needs_provenance_marker());
    }

    #[test]
    fn runtime_mode_degradation_warning_only_for_degraded() {
        assert!(RuntimeMode::DegradedOffline.needs_degradation_warning());
        assert!(!RuntimeMode::ExplicitOffline.needs_degradation_warning());
        assert!(!RuntimeMode::Live.needs_degradation_warning());
        assert!(!RuntimeMode::Refused.needs_degradation_warning());
    }

    // -- RuntimeMode serde round-trip --

    #[test]
    fn runtime_mode_serde_roundtrip() {
        for mode in [
            RuntimeMode::Live,
            RuntimeMode::ExplicitOffline,
            RuntimeMode::DegradedOffline,
            RuntimeMode::Refused,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: RuntimeMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    // -- resolve_runtime_mode: offline-first commands --

    #[test]
    fn resolve_offline_command_without_host_is_explicit_offline() {
        // guide is OfflineArtifact, Unaffected
        let mode = resolve_runtime_mode(&ctx("guide", false, false, false));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    #[test]
    fn resolve_offline_command_with_host_is_still_explicit_offline() {
        // Even with host present, inherently-offline commands stay offline
        let mode = resolve_runtime_mode(&ctx("guide", false, true, true));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    #[test]
    fn resolve_offline_command_with_offline_flag_is_explicit_offline() {
        let mode = resolve_runtime_mode(&ctx("guide", true, false, false));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    // -- resolve_runtime_mode: live-host commands --

    #[test]
    fn resolve_live_command_with_host_is_live() {
        // invoke is LiveHost, FailFast
        let mode = resolve_runtime_mode(&ctx("invoke", false, true, true));
        assert_eq!(mode, RuntimeMode::Live);
    }

    #[test]
    fn resolve_live_command_without_host_is_refused() {
        let mode = resolve_runtime_mode(&ctx("invoke", false, false, false));
        assert_eq!(mode, RuntimeMode::Refused);
    }

    #[test]
    fn resolve_live_command_with_unreachable_host_is_refused() {
        let mode = resolve_runtime_mode(&ctx("invoke", false, true, false));
        assert_eq!(mode, RuntimeMode::Refused);
    }

    #[test]
    fn resolve_live_command_with_offline_flag_is_refused() {
        // Cannot force a LiveHost command offline
        let mode = resolve_runtime_mode(&ctx("invoke", true, false, false));
        assert_eq!(mode, RuntimeMode::Refused);
    }

    // -- resolve_runtime_mode: hybrid commands --

    #[test]
    fn resolve_hybrid_failfast_command_with_host_is_live() {
        // list is Hybrid + FailFast (requires host or explicit --offline)
        let mode = resolve_runtime_mode(&ctx("list", false, true, true));
        assert_eq!(mode, RuntimeMode::Live);
    }

    #[test]
    fn resolve_hybrid_failfast_command_without_host_is_refused() {
        // list is Hybrid + FailFast — no silent degradation
        let mode = resolve_runtime_mode(&ctx("list", false, false, false));
        assert_eq!(mode, RuntimeMode::Refused);
    }

    #[test]
    fn resolve_hybrid_failfast_command_with_offline_flag_is_explicit_offline() {
        let mode = resolve_runtime_mode(&ctx("list", true, false, false));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    #[test]
    fn resolve_hybrid_failfast_command_with_offline_flag_ignores_host() {
        // Even if host is available, --offline takes precedence
        let mode = resolve_runtime_mode(&ctx("list", true, true, true));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    #[test]
    fn resolve_hybrid_degraded_command_with_host_is_live() {
        // do is Hybrid + DegradedWithWarning
        let mode = resolve_runtime_mode(&ctx("do", false, true, true));
        assert_eq!(mode, RuntimeMode::Live);
    }

    #[test]
    fn resolve_hybrid_degraded_command_without_host_degrades() {
        let mode = resolve_runtime_mode(&ctx("do", false, false, false));
        assert_eq!(mode, RuntimeMode::DegradedOffline);
    }

    #[test]
    fn resolve_hybrid_degraded_command_with_offline_flag_is_explicit_offline() {
        let mode = resolve_runtime_mode(&ctx("do", true, false, false));
        assert_eq!(mode, RuntimeMode::ExplicitOffline);
    }

    // -- resolve_runtime_mode: unknown commands --

    #[test]
    fn resolve_unknown_command_is_refused() {
        let mode = resolve_runtime_mode(&ctx("nonexistent", false, true, true));
        assert_eq!(mode, RuntimeMode::Refused);
    }

    // -- resolve_runtime_mode: every classified command has a mode --

    #[test]
    fn every_classified_command_resolves_to_a_mode_with_live_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            let mode = resolve_runtime_mode(&ctx(cls.command, false, true, true));
            assert_ne!(
                mode,
                RuntimeMode::Refused,
                "Command '{}' should not be Refused when host is live",
                cls.command
            );
        }
    }

    #[test]
    fn offline_first_commands_resolve_offline_even_without_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.host_absent == HostAbsentBehavior::Unaffected {
                let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
                assert_eq!(
                    mode,
                    RuntimeMode::ExplicitOffline,
                    "Unaffected command '{}' should be ExplicitOffline without host",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn fail_fast_commands_refuse_without_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.host_absent == HostAbsentBehavior::FailFast {
                let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
                assert_eq!(
                    mode,
                    RuntimeMode::Refused,
                    "FailFast command '{}' should be Refused without host",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn degraded_commands_degrade_without_host() {
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.host_absent == HostAbsentBehavior::DegradedWithWarning {
                let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
                assert_eq!(
                    mode,
                    RuntimeMode::DegradedOffline,
                    "DegradedWithWarning command '{}' should degrade without host",
                    cls.command
                );
            }
        }
    }

    // -- resolve_boundary tests --

    #[test]
    fn boundary_live_has_no_provenance_or_refusal() {
        let b = resolve_boundary(&ctx("invoke", false, true, true));
        assert_eq!(b.mode, RuntimeMode::Live);
        assert!(b.offline_provenance.is_none());
        assert!(b.refusal.is_none());
    }

    #[test]
    fn boundary_offline_has_provenance_no_refusal() {
        let b = resolve_boundary(&ctx("list", true, false, false));
        assert_eq!(b.mode, RuntimeMode::ExplicitOffline);
        assert!(b.offline_provenance.is_some());
        assert!(b.refusal.is_none());
    }

    #[test]
    fn boundary_degraded_has_provenance_no_refusal() {
        // "do" is Hybrid + DegradedWithWarning
        let b = resolve_boundary(&ctx("do", false, false, false));
        assert_eq!(b.mode, RuntimeMode::DegradedOffline);
        assert!(b.offline_provenance.is_some());
        assert!(b.refusal.is_none());
    }

    #[test]
    fn boundary_refused_has_refusal_no_provenance() {
        let b = resolve_boundary(&ctx("invoke", false, false, false));
        assert_eq!(b.mode, RuntimeMode::Refused);
        assert!(b.offline_provenance.is_none());
        assert!(b.refusal.is_some());
    }

    #[test]
    fn boundary_hybrid_failfast_refused_without_host() {
        // list is Hybrid + FailFast — must refuse without host when no --offline
        let b = resolve_boundary(&ctx("list", false, false, false));
        assert_eq!(b.mode, RuntimeMode::Refused);
        assert!(b.refusal.is_some());
    }

    #[test]
    fn boundary_refusal_reason_not_configured_when_no_host() {
        let b = resolve_boundary(&ctx("invoke", false, false, false));
        let err = b.refusal.unwrap();
        assert_eq!(err.reason, HostAbsentReason::NotConfigured);
    }

    #[test]
    fn boundary_refusal_reason_unreachable_when_host_down() {
        let b = resolve_boundary(&ctx("invoke", false, true, false));
        let err = b.refusal.unwrap();
        assert_eq!(err.reason, HostAbsentReason::Unreachable);
    }

    #[test]
    fn boundary_offline_provenance_matches_default_source() {
        let b = resolve_boundary(&ctx("list", true, false, false));
        let prov = b.offline_provenance.unwrap();
        assert!(prov.offline);
        assert_eq!(prov.source, OfflineSource::WorkspaceManifest);
    }

    #[test]
    fn boundary_command_is_preserved() {
        let b = resolve_boundary(&ctx("show", false, true, true));
        assert_eq!(b.command, "show");
    }

    // -- validate_mode_consistency --

    #[test]
    fn consistency_live_host_command_in_offline_mode_is_inconsistent() {
        let err = validate_mode_consistency("invoke", RuntimeMode::ExplicitOffline);
        assert!(err.is_some());
    }

    #[test]
    fn consistency_live_host_command_in_live_mode_is_consistent() {
        let err = validate_mode_consistency("invoke", RuntimeMode::Live);
        assert!(err.is_none());
    }

    #[test]
    fn consistency_offline_command_in_live_mode_is_inconsistent() {
        let err = validate_mode_consistency("guide", RuntimeMode::Live);
        assert!(err.is_some());
    }

    #[test]
    fn consistency_offline_command_in_offline_mode_is_consistent() {
        let err = validate_mode_consistency("guide", RuntimeMode::ExplicitOffline);
        assert!(err.is_none());
    }

    #[test]
    fn consistency_hybrid_command_in_live_or_offline_is_consistent() {
        assert!(validate_mode_consistency("list", RuntimeMode::Live).is_none());
        assert!(validate_mode_consistency("list", RuntimeMode::ExplicitOffline).is_none());
        assert!(validate_mode_consistency("list", RuntimeMode::DegradedOffline).is_none());
    }

    #[test]
    fn consistency_unknown_command_returns_none() {
        // Unknown commands return None (no classification to validate against)
        assert!(validate_mode_consistency("nonexistent", RuntimeMode::Live).is_none());
    }

    // -- Cross-cutting: no silent mode switches --

    #[test]
    fn no_command_resolves_live_when_host_absent_and_offline_flag_not_set() {
        // Critical invariant: without a host, nothing should claim to be Live
        for cls in COMMAND_CLASSIFICATIONS {
            let mode = resolve_runtime_mode(&ctx(cls.command, false, false, false));
            assert_ne!(
                mode,
                RuntimeMode::Live,
                "Command '{}' resolved Live without a host — silent fallback!",
                cls.command
            );
        }
    }

    #[test]
    fn no_live_host_command_resolves_offline_even_with_flag() {
        // LiveHost commands must refuse --offline, not silently switch
        for cls in COMMAND_CLASSIFICATIONS {
            if cls.truth_source == CommandTruthSource::LiveHost {
                let mode = resolve_runtime_mode(&ctx(cls.command, true, false, false));
                assert_eq!(
                    mode,
                    RuntimeMode::Refused,
                    "LiveHost command '{}' accepted --offline flag instead of refusing",
                    cls.command
                );
            }
        }
    }

    #[test]
    fn resolved_mode_is_always_consistent_with_classification() {
        // For every command, every possible context, the resolved mode must be
        // consistent with the classification.
        for cls in COMMAND_CLASSIFICATIONS {
            for offline in [false, true] {
                for resolved in [false, true] {
                    for reachable in [false, true] {
                        let mode =
                            resolve_runtime_mode(&ctx(cls.command, offline, resolved, reachable));
                        let err = validate_mode_consistency(cls.command, mode);
                        assert!(
                            err.is_none(),
                            "Inconsistency for '{}' (offline={offline}, resolved={resolved}, \
                             reachable={reachable}): {mode:?} — {}",
                            cls.command,
                            err.unwrap()
                        );
                    }
                }
            }
        }
    }

    // ── Simulate truth contract tests ────────────────────────────────────

    // -- SimulateCapability tag stability --

    #[test]
    fn simulate_capability_tags_are_stable() {
        assert_eq!(SimulateCapability::FullDryRun.tag(), "full-dry-run");
        assert_eq!(SimulateCapability::PreflightOnly.tag(), "preflight-only");
        assert_eq!(SimulateCapability::Unknown.tag(), "unknown");
        assert_eq!(SimulateCapability::Unsupported.tag(), "unsupported");
    }

    #[test]
    fn simulate_capability_serde_roundtrip() {
        for cap in [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ] {
            let json = serde_json::to_string(&cap).unwrap();
            let back: SimulateCapability = serde_json::from_str(&json).unwrap();
            assert_eq!(cap, back);
        }
    }

    // -- SimulateCapability semantics --

    #[test]
    fn simulate_only_full_dry_run_allows_simulate_label() {
        assert!(SimulateCapability::FullDryRun.allows_simulate_label());
        assert!(!SimulateCapability::PreflightOnly.allows_simulate_label());
        assert!(!SimulateCapability::Unknown.allows_simulate_label());
        assert!(!SimulateCapability::Unsupported.allows_simulate_label());
    }

    #[test]
    fn simulate_preflight_allowed_for_dry_run_and_preflight() {
        assert!(SimulateCapability::FullDryRun.allows_preflight());
        assert!(SimulateCapability::PreflightOnly.allows_preflight());
        assert!(!SimulateCapability::Unknown.allows_preflight());
        assert!(!SimulateCapability::Unsupported.allows_preflight());
    }

    #[test]
    fn simulate_unknown_is_not_audited() {
        assert!(!SimulateCapability::Unknown.is_audited());
        assert!(SimulateCapability::FullDryRun.is_audited());
        assert!(SimulateCapability::PreflightOnly.is_audited());
        assert!(SimulateCapability::Unsupported.is_audited());
    }

    #[test]
    fn simulate_all_explanations_are_nonempty() {
        for cap in [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ] {
            assert!(!cap.explanation().is_empty(), "Empty explanation for {cap:?}");
        }
    }

    // -- evaluate_simulate_request --

    #[test]
    fn evaluate_full_dry_run_always_succeeds() {
        let result = evaluate_simulate_request(SimulateCapability::FullDryRun, false);
        assert_eq!(result, Ok(SimulateCapability::FullDryRun));
    }

    #[test]
    fn evaluate_preflight_with_downgrade_allowed_succeeds() {
        let result = evaluate_simulate_request(SimulateCapability::PreflightOnly, true);
        assert_eq!(result, Ok(SimulateCapability::PreflightOnly));
    }

    #[test]
    fn evaluate_preflight_without_downgrade_is_refused() {
        let result = evaluate_simulate_request(SimulateCapability::PreflightOnly, false);
        assert!(result.is_err());
    }

    #[test]
    fn evaluate_unknown_always_refused() {
        assert!(evaluate_simulate_request(SimulateCapability::Unknown, false).is_err());
        assert!(evaluate_simulate_request(SimulateCapability::Unknown, true).is_err());
    }

    #[test]
    fn evaluate_unsupported_always_refused() {
        assert!(evaluate_simulate_request(SimulateCapability::Unsupported, false).is_err());
        assert!(evaluate_simulate_request(SimulateCapability::Unsupported, true).is_err());
    }

    // -- simulate_result honesty --

    #[test]
    fn simulate_result_full_dry_run_is_honest() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        assert!(r.is_connector_dry_run);
        assert!(!r.downgraded);
        assert_eq!(r.actual_capability, SimulateCapability::FullDryRun);
    }

    #[test]
    fn simulate_result_preflight_only_is_not_dry_run() {
        let r = simulate_result(false, SimulateCapability::PreflightOnly);
        assert!(!r.is_connector_dry_run);
        assert!(!r.downgraded);
    }

    #[test]
    fn simulate_result_downgraded_when_dry_run_requested_but_preflight_only() {
        let r = simulate_result(true, SimulateCapability::PreflightOnly);
        assert!(r.downgraded);
        assert!(!r.is_connector_dry_run);
        assert!(r.caveat.contains("preflight"));
    }

    #[test]
    fn simulate_result_not_downgraded_when_preflight_requested_and_got_preflight() {
        let r = simulate_result(false, SimulateCapability::PreflightOnly);
        assert!(!r.downgraded);
    }

    #[test]
    fn simulate_result_not_downgraded_when_dry_run_available() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        assert!(!r.downgraded);
    }

    // -- simulate_result_payload shape --

    #[test]
    fn simulate_result_payload_has_required_fields() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        let payload = simulate_result_payload(&r);
        assert!(payload["simulate_capability"].is_string());
        assert!(payload["is_connector_dry_run"].is_boolean());
        assert!(payload["caveat"].is_string());
        assert!(payload["downgraded"].is_boolean());
    }

    #[test]
    fn simulate_result_payload_dry_run_tag_matches() {
        let r = simulate_result(true, SimulateCapability::FullDryRun);
        let payload = simulate_result_payload(&r);
        assert_eq!(payload["simulate_capability"], "full-dry-run");
        assert_eq!(payload["is_connector_dry_run"], true);
    }

    #[test]
    fn simulate_result_payload_preflight_tag_matches() {
        let r = simulate_result(false, SimulateCapability::PreflightOnly);
        let payload = simulate_result_payload(&r);
        assert_eq!(payload["simulate_capability"], "preflight-only");
        assert_eq!(payload["is_connector_dry_run"], false);
    }

    #[test]
    fn simulate_result_payload_downgraded_flag_correct() {
        let r = simulate_result(true, SimulateCapability::PreflightOnly);
        let payload = simulate_result_payload(&r);
        assert_eq!(payload["downgraded"], true);
    }

    // -- Cross-cutting simulate invariants --

    #[test]
    fn simulate_never_labels_preflight_as_dry_run() {
        // Critical invariant: PreflightOnly must never claim to be a dry run
        for requested in [false, true] {
            let r = simulate_result(requested, SimulateCapability::PreflightOnly);
            assert!(
                !r.is_connector_dry_run,
                "PreflightOnly claimed is_connector_dry_run=true (requested={requested})"
            );
        }
    }

    #[test]
    fn simulate_unknown_capability_never_produces_dry_run_result() {
        for requested in [false, true] {
            let r = simulate_result(requested, SimulateCapability::Unknown);
            assert!(!r.is_connector_dry_run);
        }
    }

    #[test]
    fn simulate_unsupported_never_produces_dry_run_result() {
        for requested in [false, true] {
            let r = simulate_result(requested, SimulateCapability::Unsupported);
            assert!(!r.is_connector_dry_run);
        }
    }

    #[test]
    fn simulate_downgrade_only_happens_when_dry_run_requested() {
        // If dry-run wasn't requested, there's nothing to downgrade
        for cap in [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ] {
            let r = simulate_result(false, cap);
            assert!(
                !r.downgraded,
                "Downgraded without dry-run request for {cap:?}"
            );
        }
    }

    #[test]
    fn simulate_all_results_have_nonempty_caveats() {
        for cap in [
            SimulateCapability::FullDryRun,
            SimulateCapability::PreflightOnly,
            SimulateCapability::Unknown,
            SimulateCapability::Unsupported,
        ] {
            for requested in [false, true] {
                let r = simulate_result(requested, cap);
                assert!(
                    !r.caveat.is_empty(),
                    "Empty caveat for {cap:?} (requested={requested})"
                );
            }
        }
    }

    // ── Package artifact source validation tests ─────────────────────────

    // -- PackageArtifactSource tag stability --

    #[test]
    fn package_source_tags_are_stable() {
        assert_eq!(
            PackageArtifactSource::LocalDirectory(String::new()).tag(),
            "local-directory"
        );
        assert_eq!(
            PackageArtifactSource::Registry(String::new()).tag(),
            "registry"
        );
        assert_eq!(
            PackageArtifactSource::MeshBundle(String::new()).tag(),
            "mesh-bundle"
        );
        assert_eq!(
            PackageArtifactSource::OfflinePrepared(String::new()).tag(),
            "offline-prepared"
        );
        assert_eq!(
            PackageArtifactSource::DemoFixture(String::new()).tag(),
            "demo-fixture"
        );
        assert_eq!(
            PackageArtifactSource::StubPlaceholder(String::new()).tag(),
            "stub-placeholder"
        );
    }

    #[test]
    fn package_source_serde_roundtrip() {
        let sources = [
            PackageArtifactSource::LocalDirectory("/tmp/pkg".into()),
            PackageArtifactSource::Registry("registry:fcp.slack:1.0.0".into()),
            PackageArtifactSource::MeshBundle("mesh://node-1/pkg-abc".into()),
            PackageArtifactSource::OfflinePrepared("/opt/bundles/slack-v1.tar".into()),
            PackageArtifactSource::DemoFixture("fixture-connector".into()),
            PackageArtifactSource::StubPlaceholder("stub://test".into()),
        ];
        for src in &sources {
            let json = serde_json::to_string(src).unwrap();
            let back: PackageArtifactSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, &back);
        }
    }

    // -- Runtime acceptability --

    #[test]
    fn package_source_real_sources_are_runtime_acceptable() {
        assert!(PackageArtifactSource::LocalDirectory("/tmp/pkg".into()).is_runtime_acceptable());
        assert!(PackageArtifactSource::Registry("r:1.0".into()).is_runtime_acceptable());
        assert!(PackageArtifactSource::MeshBundle("m:1".into()).is_runtime_acceptable());
        assert!(PackageArtifactSource::OfflinePrepared("/opt/b".into()).is_runtime_acceptable());
    }

    #[test]
    fn package_source_demo_fixture_is_not_runtime_acceptable() {
        assert!(!PackageArtifactSource::DemoFixture("demo".into()).is_runtime_acceptable());
    }

    #[test]
    fn package_source_stub_placeholder_is_not_runtime_acceptable() {
        assert!(!PackageArtifactSource::StubPlaceholder("stub".into()).is_runtime_acceptable());
    }

    #[test]
    fn package_source_demo_and_stub_are_demo_or_placeholder() {
        assert!(PackageArtifactSource::DemoFixture("d".into()).is_demo_or_placeholder());
        assert!(PackageArtifactSource::StubPlaceholder("s".into()).is_demo_or_placeholder());
    }

    #[test]
    fn package_source_real_sources_not_demo_or_placeholder() {
        assert!(!PackageArtifactSource::LocalDirectory("/x".into()).is_demo_or_placeholder());
        assert!(!PackageArtifactSource::Registry("r".into()).is_demo_or_placeholder());
        assert!(!PackageArtifactSource::MeshBundle("m".into()).is_demo_or_placeholder());
        assert!(!PackageArtifactSource::OfflinePrepared("o".into()).is_demo_or_placeholder());
    }

    // -- validate_package_source --

    #[test]
    fn validate_package_source_accepts_real_local_dir() {
        let src = PackageArtifactSource::LocalDirectory("/tmp/real-pkg".into());
        assert!(validate_package_source(&src, "install").is_ok());
    }

    #[test]
    fn validate_package_source_accepts_real_registry() {
        let src = PackageArtifactSource::Registry("registry:fcp.slack:2.1.0".into());
        assert!(validate_package_source(&src, "update").is_ok());
    }

    #[test]
    fn validate_package_source_accepts_mesh_bundle() {
        let src = PackageArtifactSource::MeshBundle("mesh://node/pkg".into());
        assert!(validate_package_source(&src, "install").is_ok());
    }

    #[test]
    fn validate_package_source_accepts_offline_prepared() {
        let src = PackageArtifactSource::OfflinePrepared("/opt/bundles/v1.tar".into());
        assert!(validate_package_source(&src, "install").is_ok());
    }

    #[test]
    fn validate_package_source_rejects_demo_fixture_on_install() {
        let src = PackageArtifactSource::DemoFixture("fixture-connector".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        assert!(err.reason.contains("install"));
        assert!(err.reason.contains("demo"));
        assert!(!err.next_actions.is_empty());
    }

    #[test]
    fn validate_package_source_rejects_demo_fixture_on_update() {
        let src = PackageArtifactSource::DemoFixture("fixture-connector".into());
        let err = validate_package_source(&src, "update").unwrap_err();
        assert!(err.reason.contains("update"));
    }

    #[test]
    fn validate_package_source_rejects_stub_placeholder_on_install() {
        let src = PackageArtifactSource::StubPlaceholder("stub://test".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        assert!(err.reason.contains("stub-placeholder"));
    }

    #[test]
    fn validate_rejection_has_informative_next_actions() {
        let src = PackageArtifactSource::DemoFixture("demo-pkg".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        assert!(err.next_actions.len() >= 2);
        assert!(err.next_actions.iter().any(|a| a.contains("package")));
        assert!(err.next_actions.iter().any(|a| a.contains("registry")));
    }

    #[test]
    fn validate_rejection_preserves_source_info() {
        let src = PackageArtifactSource::DemoFixture("my-demo-pkg".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        assert_eq!(err.source_tag, "demo-fixture");
        assert_eq!(err.source_path, "my-demo-pkg");
    }

    // -- demo_source_rejection_payload --

    #[test]
    fn demo_rejection_payload_has_required_fields() {
        let src = PackageArtifactSource::DemoFixture("demo".into());
        let err = validate_package_source(&src, "install").unwrap_err();
        let payload = demo_source_rejection_payload(&err);
        assert_eq!(payload["error"], "demo_source_rejected");
        assert!(payload["source_tag"].is_string());
        assert!(payload["source_path"].is_string());
        assert!(payload["reason"].is_string());
        assert!(payload["next_actions"].is_array());
    }

    // -- DEMO_MARKERS and contains_demo_marker --

    #[test]
    fn demo_markers_is_nonempty() {
        assert!(!DEMO_MARKERS.is_empty());
    }

    #[test]
    fn demo_markers_detects_fixture_connector() {
        assert!(contains_demo_marker("path/to/fixture-connector/v1"));
    }

    #[test]
    fn demo_markers_detects_placeholder() {
        assert!(contains_demo_marker("blake3-256:PLACEHOLDER:0000"));
    }

    #[test]
    fn demo_markers_detects_deadbeef() {
        assert!(contains_demo_marker("git_commit=deadbeef"));
    }

    #[test]
    fn demo_markers_detects_zero_hash() {
        assert!(contains_demo_marker("hash:0000000000000000abcd"));
    }

    #[test]
    fn demo_markers_does_not_match_real_paths() {
        assert!(!contains_demo_marker("/opt/packages/fcp.slack-2.1.0"));
        assert!(!contains_demo_marker("registry:fcp.github:3.0.1"));
        assert!(!contains_demo_marker("mesh://node-production/pkg-5a2f"));
    }

    // -- Cross-cutting: no demo source ever validates on runtime paths --

    #[test]
    fn no_demo_source_validates_for_any_install_update_command() {
        let demo_sources = [
            PackageArtifactSource::DemoFixture("fixture-connector".into()),
            PackageArtifactSource::DemoFixture("demo-package".into()),
            PackageArtifactSource::StubPlaceholder("stub://test".into()),
            PackageArtifactSource::StubPlaceholder("placeholder".into()),
        ];
        for src in &demo_sources {
            for cmd in ["install", "update"] {
                assert!(
                    validate_package_source(src, cmd).is_err(),
                    "Demo source {:?} should be rejected for '{cmd}'",
                    src
                );
            }
        }
    }

    #[test]
    fn all_real_sources_validate_for_install_and_update() {
        let real_sources = [
            PackageArtifactSource::LocalDirectory("/tmp/real".into()),
            PackageArtifactSource::Registry("r:1.0".into()),
            PackageArtifactSource::MeshBundle("m://node/pkg".into()),
            PackageArtifactSource::OfflinePrepared("/opt/bundles/v1".into()),
        ];
        for src in &real_sources {
            for cmd in ["install", "update"] {
                assert!(
                    validate_package_source(src, cmd).is_ok(),
                    "Real source {:?} should be accepted for '{cmd}'",
                    src
                );
            }
        }
    }

    #[test]
    fn package_source_path_accessor_returns_inner_value() {
        let src = PackageArtifactSource::LocalDirectory("/my/path".into());
        assert_eq!(src.path(), "/my/path");
        let src = PackageArtifactSource::DemoFixture("demo-id".into());
        assert_eq!(src.path(), "demo-id");
    }

    // ── Capability token source validation tests ─────────────────────────

    #[test]
    fn capability_token_source_tags_are_stable() {
        assert_eq!(
            CapabilityTokenSource::HostIssued {
                endpoint: String::new()
            }
            .tag(),
            "host-issued"
        );
        assert_eq!(CapabilityTokenSource::EnvironmentVariable.tag(), "environment-variable");
        assert_eq!(CapabilityTokenSource::CliFlag.tag(), "cli-flag");
        assert_eq!(CapabilityTokenSource::TestGenerated.tag(), "test-generated");
        assert_eq!(CapabilityTokenSource::Placeholder.tag(), "placeholder");
    }

    #[test]
    fn capability_token_source_serde_roundtrip() {
        let sources = [
            CapabilityTokenSource::HostIssued {
                endpoint: "http://localhost:8080".into(),
            },
            CapabilityTokenSource::EnvironmentVariable,
            CapabilityTokenSource::CliFlag,
            CapabilityTokenSource::TestGenerated,
            CapabilityTokenSource::Placeholder,
        ];
        for src in &sources {
            let json = serde_json::to_string(src).unwrap();
            let back: CapabilityTokenSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, &back);
        }
    }

    #[test]
    fn capability_real_sources_are_live_acceptable() {
        assert!(CapabilityTokenSource::HostIssued {
            endpoint: "h".into()
        }
        .is_live_acceptable());
        assert!(CapabilityTokenSource::EnvironmentVariable.is_live_acceptable());
        assert!(CapabilityTokenSource::CliFlag.is_live_acceptable());
    }

    #[test]
    fn capability_synthetic_sources_not_live_acceptable() {
        assert!(!CapabilityTokenSource::TestGenerated.is_live_acceptable());
        assert!(!CapabilityTokenSource::Placeholder.is_live_acceptable());
    }

    #[test]
    fn capability_synthetic_sources_are_synthetic() {
        assert!(CapabilityTokenSource::TestGenerated.is_synthetic());
        assert!(CapabilityTokenSource::Placeholder.is_synthetic());
    }

    #[test]
    fn capability_real_sources_are_not_synthetic() {
        assert!(!CapabilityTokenSource::HostIssued {
            endpoint: "h".into()
        }
        .is_synthetic());
        assert!(!CapabilityTokenSource::EnvironmentVariable.is_synthetic());
        assert!(!CapabilityTokenSource::CliFlag.is_synthetic());
    }

    // -- validate_capability_token_source --

    #[test]
    fn validate_token_source_accepts_host_issued() {
        let src = CapabilityTokenSource::HostIssued {
            endpoint: "http://host:8080".into(),
        };
        assert!(validate_capability_token_source(&src, "invoke").is_ok());
    }

    #[test]
    fn validate_token_source_accepts_env_var() {
        assert!(
            validate_capability_token_source(&CapabilityTokenSource::EnvironmentVariable, "invoke")
                .is_ok()
        );
    }

    #[test]
    fn validate_token_source_accepts_cli_flag() {
        assert!(
            validate_capability_token_source(&CapabilityTokenSource::CliFlag, "invoke").is_ok()
        );
    }

    #[test]
    fn validate_token_source_rejects_test_generated() {
        let err =
            validate_capability_token_source(&CapabilityTokenSource::TestGenerated, "invoke")
                .unwrap_err();
        assert!(err.reason.contains("invoke"));
        assert!(err.reason.contains("test-generated"));
        assert!(!err.next_actions.is_empty());
    }

    #[test]
    fn validate_token_source_rejects_placeholder() {
        let err =
            validate_capability_token_source(&CapabilityTokenSource::Placeholder, "batch-file")
                .unwrap_err();
        assert!(err.reason.contains("batch-file"));
        assert!(err.reason.contains("placeholder"));
    }

    #[test]
    fn validate_token_rejection_has_actionable_next_steps() {
        let err =
            validate_capability_token_source(&CapabilityTokenSource::TestGenerated, "invoke")
                .unwrap_err();
        assert!(err.next_actions.len() >= 2);
        assert!(err.next_actions.iter().any(|a| a.contains("capabilities issue")));
    }

    // -- SYNTHETIC_TOKEN_MARKERS and contains_synthetic_token_marker --

    #[test]
    fn synthetic_token_markers_is_nonempty() {
        assert!(!SYNTHETIC_TOKEN_MARKERS.is_empty());
    }

    #[test]
    fn synthetic_markers_detect_test_token() {
        assert!(contains_synthetic_token_marker("prefix-test-token-suffix"));
        assert!(contains_synthetic_token_marker("my_test_token_123"));
    }

    #[test]
    fn synthetic_markers_detect_placeholder() {
        assert!(contains_synthetic_token_marker("placeholder-token-abc"));
    }

    #[test]
    fn synthetic_markers_detect_repeated_a() {
        assert!(contains_synthetic_token_marker("cap_AAAAAAAAAA_xyz"));
    }

    #[test]
    fn synthetic_markers_do_not_match_real_tokens() {
        // A real base64-encoded token
        assert!(!contains_synthetic_token_marker(
            "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0"
        ));
        assert!(!contains_synthetic_token_marker("dGhpcyBpcyBhIHJlYWwgdG9rZW4"));
    }

    // -- classify_token_source --

    #[test]
    fn classify_empty_token_is_placeholder() {
        let src = classify_token_source("");
        assert_eq!(src, CapabilityTokenSource::Placeholder);
    }

    #[test]
    fn classify_test_token_is_test_generated() {
        let src = classify_token_source("my-test-token-abc123");
        assert_eq!(src, CapabilityTokenSource::TestGenerated);
    }

    #[test]
    fn classify_real_looking_token_is_cli_flag() {
        let src = classify_token_source("eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.payload.sig");
        assert_eq!(src, CapabilityTokenSource::CliFlag);
    }

    // -- Cross-cutting: no synthetic token validates for any token-requiring command --

    #[test]
    fn no_synthetic_token_validates_for_token_requiring_commands() {
        let synthetic_sources = [
            CapabilityTokenSource::TestGenerated,
            CapabilityTokenSource::Placeholder,
        ];
        let token_commands: Vec<&str> = COMMAND_CLASSIFICATIONS
            .iter()
            .filter(|c| c.requires_capability_token)
            .map(|c| c.command)
            .collect();
        assert!(!token_commands.is_empty());

        for src in &synthetic_sources {
            for cmd in &token_commands {
                assert!(
                    validate_capability_token_source(src, cmd).is_err(),
                    "Synthetic source {:?} should be rejected for '{cmd}'",
                    src
                );
            }
        }
    }

    #[test]
    fn all_real_token_sources_validate_for_all_commands() {
        let real_sources = [
            CapabilityTokenSource::HostIssued {
                endpoint: "http://host".into(),
            },
            CapabilityTokenSource::EnvironmentVariable,
            CapabilityTokenSource::CliFlag,
        ];
        for src in &real_sources {
            for cmd in COMMANDS {
                assert!(
                    validate_capability_token_source(src, cmd).is_ok(),
                    "Real source {:?} should be accepted for '{cmd}'",
                    src
                );
            }
        }
    }

    // ── Discovery truth contract tests ───────────────────────────────────

    #[test]
    fn discovery_data_source_tags_are_stable() {
        assert_eq!(DiscoveryDataSource::LiveHostInventory.tag(), "live-host-inventory");
        assert_eq!(
            DiscoveryDataSource::LiveHostIntrospection.tag(),
            "live-host-introspection"
        );
        assert_eq!(DiscoveryDataSource::WorkspaceManifest.tag(), "workspace-manifest");
        assert_eq!(DiscoveryDataSource::LocalCatalogCache.tag(), "local-catalog-cache");
        assert_eq!(DiscoveryDataSource::StaticSchema.tag(), "static-schema");
    }

    #[test]
    fn discovery_data_source_serde_roundtrip() {
        for src in [
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::LiveHostIntrospection,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::LocalCatalogCache,
            DiscoveryDataSource::StaticSchema,
        ] {
            let json = serde_json::to_string(&src).unwrap();
            let back: DiscoveryDataSource = serde_json::from_str(&json).unwrap();
            assert_eq!(src, back);
        }
    }

    #[test]
    fn discovery_live_sources_are_authoritative() {
        assert!(DiscoveryDataSource::LiveHostInventory.is_authoritative());
        assert!(DiscoveryDataSource::LiveHostIntrospection.is_authoritative());
    }

    #[test]
    fn discovery_offline_sources_are_not_authoritative() {
        assert!(!DiscoveryDataSource::WorkspaceManifest.is_authoritative());
        assert!(!DiscoveryDataSource::LocalCatalogCache.is_authoritative());
        assert!(!DiscoveryDataSource::StaticSchema.is_authoritative());
    }

    #[test]
    fn discovery_offline_sources_are_offline() {
        assert!(DiscoveryDataSource::WorkspaceManifest.is_offline());
        assert!(DiscoveryDataSource::LocalCatalogCache.is_offline());
        assert!(DiscoveryDataSource::StaticSchema.is_offline());
    }

    #[test]
    fn discovery_live_sources_are_not_offline() {
        assert!(!DiscoveryDataSource::LiveHostInventory.is_offline());
        assert!(!DiscoveryDataSource::LiveHostIntrospection.is_offline());
    }

    #[test]
    fn discovery_all_sources_have_freshness_caveat() {
        for src in [
            DiscoveryDataSource::LiveHostInventory,
            DiscoveryDataSource::LiveHostIntrospection,
            DiscoveryDataSource::WorkspaceManifest,
            DiscoveryDataSource::LocalCatalogCache,
            DiscoveryDataSource::StaticSchema,
        ] {
            assert!(!src.freshness_caveat().is_empty(), "Empty caveat for {src:?}");
        }
    }

    // -- discovery_provenance --

    #[test]
    fn discovery_provenance_live_is_authoritative() {
        let prov = discovery_provenance("list", DiscoveryDataSource::LiveHostInventory);
        assert!(prov.authoritative);
        assert_eq!(prov.command, "list");
    }

    #[test]
    fn discovery_provenance_offline_is_not_authoritative() {
        let prov = discovery_provenance("list", DiscoveryDataSource::WorkspaceManifest);
        assert!(!prov.authoritative);
    }

    #[test]
    fn discovery_provenance_has_caveat() {
        let prov = discovery_provenance("show", DiscoveryDataSource::LocalCatalogCache);
        assert!(!prov.caveat.is_empty());
    }

    // -- DISCOVERY_COMMANDS --

    #[test]
    fn discovery_commands_is_nonempty() {
        assert!(!DISCOVERY_COMMANDS.is_empty());
    }

    #[test]
    fn discovery_commands_contains_expected() {
        assert!(is_discovery_command("list"));
        assert!(is_discovery_command("search"));
        assert!(is_discovery_command("show"));
        assert!(is_discovery_command("ops"));
        assert!(is_discovery_command("schema"));
        assert!(is_discovery_command("examples"));
        assert!(is_discovery_command("suggest"));
    }

    #[test]
    fn discovery_commands_excludes_non_discovery() {
        assert!(!is_discovery_command("invoke"));
        assert!(!is_discovery_command("install"));
        assert!(!is_discovery_command("guide"));
    }

    // -- expected_discovery_source --

    #[test]
    fn expected_source_live_list_is_inventory() {
        let src = expected_discovery_source("list", RuntimeMode::Live);
        assert_eq!(src, Some(DiscoveryDataSource::LiveHostInventory));
    }

    #[test]
    fn expected_source_live_show_is_introspection() {
        let src = expected_discovery_source("show", RuntimeMode::Live);
        assert_eq!(src, Some(DiscoveryDataSource::LiveHostIntrospection));
    }

    #[test]
    fn expected_source_live_ops_is_introspection() {
        let src = expected_discovery_source("ops", RuntimeMode::Live);
        assert_eq!(src, Some(DiscoveryDataSource::LiveHostIntrospection));
    }

    #[test]
    fn expected_source_offline_is_workspace_manifest() {
        let src = expected_discovery_source("list", RuntimeMode::ExplicitOffline);
        assert_eq!(src, Some(DiscoveryDataSource::WorkspaceManifest));
    }

    #[test]
    fn expected_source_degraded_is_workspace_manifest() {
        let src = expected_discovery_source("search", RuntimeMode::DegradedOffline);
        assert_eq!(src, Some(DiscoveryDataSource::WorkspaceManifest));
    }

    #[test]
    fn expected_source_refused_is_none() {
        let src = expected_discovery_source("list", RuntimeMode::Refused);
        assert!(src.is_none());
    }

    #[test]
    fn expected_source_non_discovery_is_none() {
        let src = expected_discovery_source("invoke", RuntimeMode::Live);
        assert!(src.is_none());
    }

    // -- Cross-cutting discovery invariants --

    #[test]
    fn all_discovery_commands_are_in_commands_list() {
        for cmd in DISCOVERY_COMMANDS {
            assert!(COMMANDS.contains(cmd), "Discovery command '{cmd}' not in COMMANDS");
        }
    }

    #[test]
    fn all_discovery_commands_have_classifications() {
        for cmd in DISCOVERY_COMMANDS {
            assert!(
                classify_command(cmd).is_some(),
                "Discovery command '{cmd}' has no classification"
            );
        }
    }

    #[test]
    fn discovery_live_provenance_always_authoritative() {
        for cmd in DISCOVERY_COMMANDS {
            let src = expected_discovery_source(cmd, RuntimeMode::Live).unwrap();
            assert!(
                src.is_authoritative(),
                "Live discovery source for '{cmd}' is not authoritative: {src:?}"
            );
        }
    }

    #[test]
    fn discovery_offline_provenance_never_authoritative() {
        for cmd in DISCOVERY_COMMANDS {
            let src = expected_discovery_source(cmd, RuntimeMode::ExplicitOffline).unwrap();
            assert!(
                !src.is_authoritative(),
                "Offline discovery source for '{cmd}' claims authoritative: {src:?}"
            );
        }
    }
}
