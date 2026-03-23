//! Bridge and daemon connector test helpers.
//!
//! Provides utilities for testing connectors that bridge to external daemons
//! or local services (e.g., browser automation via CDP, home automation via
//! local API, desktop apps via IPC).
//!
//! # Example
//!
//! ```rust,ignore
//! use fcp_testkit::bridge_helpers::*;
//!
//! let mut tracker = BridgeConnectionTracker::new();
//! tracker.record_connect("ws://localhost:9222");
//! tracker.record_message_sent("Page.navigate");
//! tracker.record_message_received("Page.loadEventFired");
//! tracker.record_disconnect();
//!
//! assert_bridge_connected_once(&tracker);
//! assert_bridge_messages_exchanged(&tracker, 1, 1);
//! assert_bridge_clean_disconnect(&tracker);
//! ```

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

// ─────────────────────────────────────────────────────────────────────────────
// Bridge Connection Tracking
// ─────────────────────────────────────────────────────────────────────────────

/// State of a bridge connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeState {
    /// Not yet connected.
    Disconnected,
    /// Connected to the bridge target.
    Connected,
    /// Connection failed.
    Failed,
    /// Cleanly disconnected.
    Closed,
}

/// A recorded bridge event.
#[derive(Debug, Clone)]
pub struct BridgeEvent {
    /// Event kind.
    pub kind: BridgeEventKind,
    /// When the event occurred.
    pub timestamp: Instant,
    /// Optional payload.
    pub payload: Option<Value>,
}

/// Kind of bridge event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeEventKind {
    /// Connection initiated to an endpoint.
    Connect(String),
    /// Message sent to the bridge target.
    MessageSent(String),
    /// Message received from the bridge target.
    MessageReceived(String),
    /// Connection closed cleanly.
    Disconnect,
    /// Connection error.
    Error(String),
    /// Reconnection attempt.
    Reconnect(u32),
}

/// Tracks bridge connection lifecycle for test assertions.
#[derive(Debug)]
pub struct BridgeConnectionTracker {
    events: Vec<BridgeEvent>,
    state: BridgeState,
    connect_count: u32,
    disconnect_count: u32,
    messages_sent: u32,
    messages_received: u32,
    errors: Vec<String>,
}

impl BridgeConnectionTracker {
    /// Create a new tracker.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            events: Vec::new(),
            state: BridgeState::Disconnected,
            connect_count: 0,
            disconnect_count: 0,
            messages_sent: 0,
            messages_received: 0,
            errors: Vec::new(),
        }
    }

    /// Record a connection event.
    pub fn record_connect(&mut self, endpoint: &str) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::Connect(endpoint.to_string()),
            timestamp: Instant::now(),
            payload: None,
        });
        self.state = BridgeState::Connected;
        self.connect_count += 1;
    }

    /// Record a message sent to the bridge target.
    pub fn record_message_sent(&mut self, method: &str) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::MessageSent(method.to_string()),
            timestamp: Instant::now(),
            payload: None,
        });
        self.messages_sent += 1;
    }

    /// Record a message received from the bridge target.
    pub fn record_message_received(&mut self, method: &str) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::MessageReceived(method.to_string()),
            timestamp: Instant::now(),
            payload: None,
        });
        self.messages_received += 1;
    }

    /// Record a clean disconnect.
    pub fn record_disconnect(&mut self) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::Disconnect,
            timestamp: Instant::now(),
            payload: None,
        });
        self.state = BridgeState::Closed;
        self.disconnect_count += 1;
    }

    /// Record a connection error.
    pub fn record_error(&mut self, error: &str) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::Error(error.to_string()),
            timestamp: Instant::now(),
            payload: None,
        });
        self.state = BridgeState::Failed;
        self.errors.push(error.to_string());
    }

    /// Record a reconnection attempt.
    pub fn record_reconnect(&mut self, attempt: u32) {
        self.events.push(BridgeEvent {
            kind: BridgeEventKind::Reconnect(attempt),
            timestamp: Instant::now(),
            payload: None,
        });
    }

    /// Current connection state.
    #[must_use]
    pub const fn state(&self) -> BridgeState {
        self.state
    }

    /// Number of connection attempts.
    #[must_use]
    pub const fn connect_count(&self) -> u32 {
        self.connect_count
    }

    /// All recorded events.
    #[must_use]
    pub fn events(&self) -> &[BridgeEvent] {
        &self.events
    }

    /// Messages sent count.
    #[must_use]
    pub const fn messages_sent(&self) -> u32 {
        self.messages_sent
    }

    /// Messages received count.
    #[must_use]
    pub const fn messages_received(&self) -> u32 {
        self.messages_received
    }

    /// All recorded errors.
    #[must_use]
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

impl Default for BridgeConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock Bridge Responses
// ─────────────────────────────────────────────────────────────────────────────

/// Build a mock bridge discovery response (e.g., CDP target list).
#[must_use]
pub fn mock_bridge_discovery(targets: &[(&str, &str)]) -> Value {
    let items: Vec<Value> = targets
        .iter()
        .map(|(id, title)| {
            json!({
                "id": id,
                "title": title,
                "type": "page",
                "url": format!("about:blank#{id}"),
            })
        })
        .collect();
    json!(items)
}

/// Build a mock bridge command response.
#[must_use]
pub fn mock_bridge_command_response(id: u64, result: &Value) -> Value {
    json!({
        "id": id,
        "result": result,
    })
}

/// Build a mock bridge error response.
#[must_use]
pub fn mock_bridge_error_response(id: u64, code: i64, message: &str) -> Value {
    json!({
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    })
}

/// Build a mock bridge event (unsolicited server-sent message).
#[must_use]
pub fn mock_bridge_event(method: &str, params: &Value) -> Value {
    json!({
        "method": method,
        "params": params,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Prerequisites Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// A prerequisite check result for bridge/daemon connectors.
#[derive(Debug, Clone)]
pub struct PrerequisiteCheck {
    /// Name of the prerequisite (e.g., "chromium", "docker").
    pub name: String,
    /// Whether it is available.
    pub available: bool,
    /// Version string if available.
    pub version: Option<String>,
    /// Path to the binary if found.
    pub path: Option<String>,
    /// Error message if unavailable.
    pub error: Option<String>,
}

/// Builder for prerequisite checks.
pub struct PrerequisiteCheckBuilder {
    name: String,
    available: bool,
    version: Option<String>,
    path: Option<String>,
    error: Option<String>,
}

impl PrerequisiteCheckBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            available: false,
            version: None,
            path: None,
            error: None,
        }
    }

    /// Mark as available with version.
    #[must_use]
    pub fn available(mut self, version: &str, path: &str) -> Self {
        self.available = true;
        self.version = Some(version.to_string());
        self.path = Some(path.to_string());
        self
    }

    /// Mark as unavailable with error.
    #[must_use]
    pub fn unavailable(mut self, error: &str) -> Self {
        self.available = false;
        self.error = Some(error.to_string());
        self
    }

    /// Build the check.
    #[must_use]
    pub fn build(self) -> PrerequisiteCheck {
        PrerequisiteCheck {
            name: self.name,
            available: self.available,
            version: self.version,
            path: self.path,
            error: self.error,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Local Harness Contracts
// ─────────────────────────────────────────────────────────────────────────────

/// Canonical local harness family for queue, browser, subprocess, and bridge fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHarnessFamily {
    /// Queue or pub-sub fixture driven through a real local broker.
    Queue,
    /// Browser session fixture driven through a real local browser target.
    Browser,
    /// Local process or CLI fixture driven through a real child process.
    LocalProcess,
    /// Bridge or daemon-backed fixture driven through a real local socket or RPC boundary.
    Bridge,
}

/// Stable artifact kind for local harness evidence bundles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHarnessArtifactKind {
    /// Structured JSON payload.
    Json,
    /// JSON Lines event stream.
    Jsonl,
    /// Plain-text summary or stdout/stderr capture.
    Text,
    /// Replay script or equivalent command recipe.
    Replay,
    /// Directory or bundle root containing captured files.
    Directory,
}

/// Artifact descriptor for local harness runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHarnessArtifactDescriptor {
    /// Stable artifact label within the run report.
    pub label: String,
    /// Artifact kind (`json`, `jsonl`, `text`, `replay`, etc.).
    pub kind: LocalHarnessArtifactKind,
    /// Expected file name or bundle-relative path hint.
    pub path_hint: String,
    /// Operator-facing description of the artifact.
    pub description: String,
}

impl LocalHarnessArtifactDescriptor {
    /// Build a canonical artifact descriptor.
    #[must_use]
    pub fn new(
        label: &str,
        kind: LocalHarnessArtifactKind,
        path_hint: &str,
        description: &str,
    ) -> Self {
        Self {
            label: label.to_string(),
            kind,
            path_hint: path_hint.to_string(),
            description: description.to_string(),
        }
    }
}

/// Existing helper seam that downstream local harness work should promote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHarnessHelperReference {
    /// Module or crate path that already owns the behavior.
    pub symbol: String,
    /// Short explanation of why this helper should be reused.
    pub responsibility: String,
}

impl LocalHarnessHelperReference {
    /// Build a helper reference entry.
    #[must_use]
    pub fn new(symbol: &str, responsibility: &str) -> Self {
        Self {
            symbol: symbol.to_string(),
            responsibility: responsibility.to_string(),
        }
    }
}

/// Canonical scenario category for truthful local harness coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalHarnessScenarioKind {
    /// Publish and consume through a real local queue or broker.
    QueuePublishConsume,
    /// Negative-ack or retry/redelivery path through a real local broker.
    QueueRedelivery,
    /// Browser navigation or session bootstrap over a real local bridge.
    BrowserNavigate,
    /// Browser download or artifact capture over a real local bridge.
    BrowserDownloadCapture,
    /// Local JSONL process round-trip over stdin/stdout.
    LocalProcessJsonlRoundTrip,
    /// Non-zero exit, stderr capture, and replay metadata for local processes.
    LocalProcessExitFailure,
    /// Bridge or daemon connect and message exchange.
    BridgeConnectExchange,
    /// Bridge reconnect and recovery after an injected failure.
    BridgeReconnectRecovery,
}

impl LocalHarnessScenarioKind {
    /// All canonical local harness scenarios.
    pub const ALL: [Self; 8] = [
        Self::QueuePublishConsume,
        Self::QueueRedelivery,
        Self::BrowserNavigate,
        Self::BrowserDownloadCapture,
        Self::LocalProcessJsonlRoundTrip,
        Self::LocalProcessExitFailure,
        Self::BridgeConnectExchange,
        Self::BridgeReconnectRecovery,
    ];

    /// Stable scenario identifier.
    #[must_use]
    pub const fn scenario_id(self) -> &'static str {
        match self {
            Self::QueuePublishConsume => "queue.publish.consume",
            Self::QueueRedelivery => "queue.redelivery.after_nack",
            Self::BrowserNavigate => "browser.session.navigate",
            Self::BrowserDownloadCapture => "browser.download.capture",
            Self::LocalProcessJsonlRoundTrip => "local_process.jsonl.round_trip",
            Self::LocalProcessExitFailure => "local_process.exit_failure.capture",
            Self::BridgeConnectExchange => "bridge.connect.exchange",
            Self::BridgeReconnectRecovery => "bridge.reconnect.recovery",
        }
    }

    /// Harness family exercised by the scenario.
    #[must_use]
    pub const fn family(self) -> LocalHarnessFamily {
        match self {
            Self::QueuePublishConsume | Self::QueueRedelivery => LocalHarnessFamily::Queue,
            Self::BrowserNavigate | Self::BrowserDownloadCapture => LocalHarnessFamily::Browser,
            Self::LocalProcessJsonlRoundTrip | Self::LocalProcessExitFailure => {
                LocalHarnessFamily::LocalProcess
            }
            Self::BridgeConnectExchange | Self::BridgeReconnectRecovery => {
                LocalHarnessFamily::Bridge
            }
        }
    }

    /// Short operator-facing summary for the scenario.
    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            Self::QueuePublishConsume => {
                "verify publish and consume semantics over a real local queue or broker"
            }
            Self::QueueRedelivery => {
                "verify nack or retry paths produce deterministic local redelivery evidence"
            }
            Self::BrowserNavigate => {
                "verify browser session startup and navigation over a real local bridge"
            }
            Self::BrowserDownloadCapture => {
                "verify download and artifact capture through the real browser boundary"
            }
            Self::LocalProcessJsonlRoundTrip => {
                "verify stdin/stdout JSONL round-trips against a real child process"
            }
            Self::LocalProcessExitFailure => {
                "verify stderr, exit status, and replay metadata on local process failure"
            }
            Self::BridgeConnectExchange => {
                "verify bridge connect, message exchange, and clean disconnect"
            }
            Self::BridgeReconnectRecovery => {
                "verify reconnect and recovery after a real local bridge failure"
            }
        }
    }

    const fn assertions(self) -> &'static [&'static str] {
        match self {
            Self::QueuePublishConsume => &[
                "messages cross a real queue or broker boundary",
                "receipts and replay metadata name the consumed delivery",
            ],
            Self::QueueRedelivery => &[
                "negative acknowledgement or retry is visible in local broker state",
                "redelivery is captured without substituting a fake in-memory queue",
            ],
            Self::BrowserNavigate => &[
                "real browser or bridge session starts successfully",
                "navigation or equivalent session command reaches the live local target",
            ],
            Self::BrowserDownloadCapture => &[
                "downloads are written into a captured artifact directory",
                "stdout or stderr or bridge logs explain failures without redaction leaks",
            ],
            Self::LocalProcessJsonlRoundTrip => &[
                "real child process stdin and stdout are captured truthfully",
                "replay metadata is sufficient to rerun the subprocess boundary",
            ],
            Self::LocalProcessExitFailure => &[
                "non-zero exit status is captured as evidence rather than guessed",
                "stderr is preserved for triage and attached to the run report",
            ],
            Self::BridgeConnectExchange => &[
                "bridge connect and exchange events are observable in order",
                "receipts and message counts can be asserted without fake peers",
            ],
            Self::BridgeReconnectRecovery => &[
                "bridge reconnection attempts are visible in the evidence bundle",
                "recovery can be replayed with the captured command and prerequisites",
            ],
        }
    }
}

/// Serializable scenario manifest entry for local harness coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHarnessScenarioDefinition {
    /// Stable scenario identifier used by reports and playbooks.
    pub scenario_id: String,
    /// Canonical scenario kind.
    pub kind: LocalHarnessScenarioKind,
    /// Harness family exercised by the scenario.
    pub family: LocalHarnessFamily,
    /// Operator-facing summary of the behavior being covered.
    pub summary: String,
    /// Stable assertions this scenario must prove.
    pub assertions: Vec<String>,
}

impl From<LocalHarnessScenarioKind> for LocalHarnessScenarioDefinition {
    fn from(kind: LocalHarnessScenarioKind) -> Self {
        Self {
            scenario_id: kind.scenario_id().to_string(),
            kind,
            family: kind.family(),
            summary: kind.summary().to_string(),
            assertions: kind
                .assertions()
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        }
    }
}

/// Canonical contract for a truthful local harness family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalHarnessContract {
    /// Version marker for the contract itself.
    pub contract_version: String,
    /// Required suite class from the acceptance taxonomy.
    pub suite_class: String,
    /// Local harness family.
    pub family: LocalHarnessFamily,
    /// Transport truth being exercised.
    pub transport: String,
    /// Existing helpers that should be promoted rather than replaced.
    pub promoted_helpers: Vec<LocalHarnessHelperReference>,
    /// Run-level artifacts every compliant harness should emit.
    pub artifacts: Vec<LocalHarnessArtifactDescriptor>,
    /// Canonical required scenarios for this family.
    pub scenarios: Vec<LocalHarnessScenarioDefinition>,
}

/// Return the stable scenario inventory for a local harness family.
#[must_use]
pub fn canonical_local_harness_inventory(
    family: LocalHarnessFamily,
) -> Vec<LocalHarnessScenarioDefinition> {
    LocalHarnessScenarioKind::ALL
        .into_iter()
        .filter(|kind| kind.family() == family)
        .map(LocalHarnessScenarioDefinition::from)
        .collect()
}

/// Return the canonical queue harness contract.
#[must_use]
pub fn canonical_queue_harness_contract() -> LocalHarnessContract {
    LocalHarnessContract {
        contract_version: "local-harness-contract/v1".to_string(),
        suite_class: "local_non_mock".to_string(),
        family: LocalHarnessFamily::Queue,
        transport: "local_broker".to_string(),
        promoted_helpers: common_local_harness_helpers(),
        artifacts: vec![
            LocalHarnessArtifactDescriptor::new(
                "logs-jsonl",
                LocalHarnessArtifactKind::Jsonl,
                "logs.jsonl",
                "schema-valid event stream for queue or broker acceptance runs",
            ),
            LocalHarnessArtifactDescriptor::new(
                "report-json",
                LocalHarnessArtifactKind::Json,
                "report.json",
                "machine-readable run report with broker scenario metadata",
            ),
            LocalHarnessArtifactDescriptor::new(
                "broker-state-json",
                LocalHarnessArtifactKind::Json,
                "broker-state.json",
                "captured broker state, delivery ids, and subscription metadata",
            ),
            LocalHarnessArtifactDescriptor::new(
                "receipt-records",
                LocalHarnessArtifactKind::Json,
                "receipts.json",
                "delivery receipts, ack or nack evidence, and replay identifiers",
            ),
            LocalHarnessArtifactDescriptor::new(
                "replay-sh",
                LocalHarnessArtifactKind::Replay,
                "replay.sh",
                "deterministic replay command sequence for the queue boundary",
            ),
        ],
        scenarios: canonical_local_harness_inventory(LocalHarnessFamily::Queue),
    }
}

/// Return the canonical browser harness contract.
#[must_use]
pub fn canonical_browser_harness_contract() -> LocalHarnessContract {
    LocalHarnessContract {
        contract_version: "local-harness-contract/v1".to_string(),
        suite_class: "local_non_mock".to_string(),
        family: LocalHarnessFamily::Browser,
        transport: "local_browser_bridge".to_string(),
        promoted_helpers: common_local_harness_helpers(),
        artifacts: vec![
            LocalHarnessArtifactDescriptor::new(
                "logs-jsonl",
                LocalHarnessArtifactKind::Jsonl,
                "logs.jsonl",
                "schema-valid event stream for browser acceptance runs",
            ),
            LocalHarnessArtifactDescriptor::new(
                "report-json",
                LocalHarnessArtifactKind::Json,
                "report.json",
                "machine-readable run report with browser scenario metadata",
            ),
            LocalHarnessArtifactDescriptor::new(
                "bridge-events-jsonl",
                LocalHarnessArtifactKind::Jsonl,
                "bridge-events.jsonl",
                "ordered browser bridge events for reconnect and navigation triage",
            ),
            LocalHarnessArtifactDescriptor::new(
                "downloads",
                LocalHarnessArtifactKind::Directory,
                "downloads/",
                "captured browser downloads or generated artifacts",
            ),
            LocalHarnessArtifactDescriptor::new(
                "screenshots",
                LocalHarnessArtifactKind::Directory,
                "screenshots/",
                "optional screenshots or rendered evidence captured during the run",
            ),
            LocalHarnessArtifactDescriptor::new(
                "replay-sh",
                LocalHarnessArtifactKind::Replay,
                "replay.sh",
                "deterministic replay command sequence for the browser boundary",
            ),
        ],
        scenarios: canonical_local_harness_inventory(LocalHarnessFamily::Browser),
    }
}

/// Return the canonical local-process harness contract.
#[must_use]
pub fn canonical_local_process_harness_contract() -> LocalHarnessContract {
    LocalHarnessContract {
        contract_version: "local-harness-contract/v1".to_string(),
        suite_class: "local_non_mock".to_string(),
        family: LocalHarnessFamily::LocalProcess,
        transport: "child_process_stdio".to_string(),
        promoted_helpers: {
            let mut helpers = common_local_harness_helpers();
            helpers.push(LocalHarnessHelperReference::new(
                "fcp_e2e::ConnectorProcessRunner",
                "real child-process JSONL runner with stderr capture for connector binaries",
            ));
            helpers.push(LocalHarnessHelperReference::new(
                "fcp_e2e::SubprocessRunCapture",
                "serializable process artifact capture for stdout or stderr or exit metadata",
            ));
            helpers
        },
        artifacts: vec![
            LocalHarnessArtifactDescriptor::new(
                "logs-jsonl",
                LocalHarnessArtifactKind::Jsonl,
                "logs.jsonl",
                "schema-valid event stream for subprocess acceptance runs",
            ),
            LocalHarnessArtifactDescriptor::new(
                "report-json",
                LocalHarnessArtifactKind::Json,
                "report.json",
                "machine-readable run report with subprocess scenario metadata",
            ),
            LocalHarnessArtifactDescriptor::new(
                "stdout-txt",
                LocalHarnessArtifactKind::Text,
                "stdout.txt",
                "captured child-process stdout or primary output artifact",
            ),
            LocalHarnessArtifactDescriptor::new(
                "stderr-txt",
                LocalHarnessArtifactKind::Text,
                "stderr.txt",
                "captured child-process stderr for triage and replay",
            ),
            LocalHarnessArtifactDescriptor::new(
                "receipts-json",
                LocalHarnessArtifactKind::Json,
                "receipts.json",
                "captured receipt ids or subprocess evidence attached to the run",
            ),
            LocalHarnessArtifactDescriptor::new(
                "temp-dir",
                LocalHarnessArtifactKind::Directory,
                "tmp/",
                "ephemeral working directory preserved for reproducible failure analysis",
            ),
            LocalHarnessArtifactDescriptor::new(
                "replay-sh",
                LocalHarnessArtifactKind::Replay,
                "replay.sh",
                "deterministic replay command sequence for the subprocess boundary",
            ),
        ],
        scenarios: canonical_local_harness_inventory(LocalHarnessFamily::LocalProcess),
    }
}

/// Return the canonical bridge or daemon harness contract.
#[must_use]
pub fn canonical_bridge_harness_contract() -> LocalHarnessContract {
    LocalHarnessContract {
        contract_version: "local-harness-contract/v1".to_string(),
        suite_class: "local_non_mock".to_string(),
        family: LocalHarnessFamily::Bridge,
        transport: "daemon_socket_or_rpc".to_string(),
        promoted_helpers: {
            let mut helpers = common_local_harness_helpers();
            helpers.push(LocalHarnessHelperReference::new(
                "fcp_testkit::BridgeConnectionTracker",
                "ordered bridge or daemon event tracking for reconnect and exchange assertions",
            ));
            helpers.push(LocalHarnessHelperReference::new(
                "fcp_testkit::PrerequisiteCheck",
                "structured prerequisite reporting for local daemons, browsers, and bridges",
            ));
            helpers
        },
        artifacts: vec![
            LocalHarnessArtifactDescriptor::new(
                "logs-jsonl",
                LocalHarnessArtifactKind::Jsonl,
                "logs.jsonl",
                "schema-valid event stream for bridge or daemon acceptance runs",
            ),
            LocalHarnessArtifactDescriptor::new(
                "report-json",
                LocalHarnessArtifactKind::Json,
                "report.json",
                "machine-readable run report with bridge scenario metadata",
            ),
            LocalHarnessArtifactDescriptor::new(
                "bridge-events-jsonl",
                LocalHarnessArtifactKind::Jsonl,
                "bridge-events.jsonl",
                "ordered bridge lifecycle events including reconnect and exchange steps",
            ),
            LocalHarnessArtifactDescriptor::new(
                "daemon-stdout-txt",
                LocalHarnessArtifactKind::Text,
                "daemon-stdout.txt",
                "captured bridge or daemon stdout for reproducible replay",
            ),
            LocalHarnessArtifactDescriptor::new(
                "daemon-stderr-txt",
                LocalHarnessArtifactKind::Text,
                "daemon-stderr.txt",
                "captured bridge or daemon stderr for failure triage",
            ),
            LocalHarnessArtifactDescriptor::new(
                "receipts-json",
                LocalHarnessArtifactKind::Json,
                "receipts.json",
                "captured receipt ids, dedupe keys, or replay tokens for bridge flows",
            ),
            LocalHarnessArtifactDescriptor::new(
                "replay-sh",
                LocalHarnessArtifactKind::Replay,
                "replay.sh",
                "deterministic replay command sequence for the bridge boundary",
            ),
        ],
        scenarios: canonical_local_harness_inventory(LocalHarnessFamily::Bridge),
    }
}

fn common_local_harness_helpers() -> Vec<LocalHarnessHelperReference> {
    vec![
        LocalHarnessHelperReference::new(
            "fcp_testkit::EvidenceCollector",
            "shared evidence vocabulary for receipts, mutations, and cleanup verification",
        ),
        LocalHarnessHelperReference::new(
            "fcp_testkit::LogRedactionScanner",
            "artifact secret and PII scan for local harness evidence bundles",
        ),
        LocalHarnessHelperReference::new(
            "fcp_e2e::E2eRunReport",
            "machine-readable run envelope already used by shared E2E reporting",
        ),
        LocalHarnessHelperReference::new(
            "fcp_e2e::E2eArtifactRecord",
            "stable label or kind or description artifact vocabulary for report emission",
        ),
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Assertions
// ─────────────────────────────────────────────────────────────────────────────

/// Assert that the bridge connected exactly once.
///
/// # Panics
///
/// Panics if the connect count is not 1.
pub fn assert_bridge_connected_once(tracker: &BridgeConnectionTracker) {
    assert_eq!(
        tracker.connect_count(),
        1,
        "expected exactly one connection, got {}",
        tracker.connect_count()
    );
}

/// Assert the count of messages exchanged.
///
/// # Panics
///
/// Panics if sent or received counts don't match.
pub fn assert_bridge_messages_exchanged(
    tracker: &BridgeConnectionTracker,
    expected_sent: u32,
    expected_received: u32,
) {
    assert_eq!(
        tracker.messages_sent(),
        expected_sent,
        "expected {expected_sent} messages sent, got {}",
        tracker.messages_sent()
    );
    assert_eq!(
        tracker.messages_received(),
        expected_received,
        "expected {expected_received} messages received, got {}",
        tracker.messages_received()
    );
}

/// Assert that the bridge disconnected cleanly.
///
/// # Panics
///
/// Panics if the state is not `Closed` or there are recorded errors.
pub fn assert_bridge_clean_disconnect(tracker: &BridgeConnectionTracker) {
    assert_eq!(
        tracker.state(),
        BridgeState::Closed,
        "expected clean disconnect, state is {:?}",
        tracker.state()
    );
    assert!(
        tracker.errors().is_empty(),
        "expected no errors, got: {:?}",
        tracker.errors()
    );
}

/// Assert that a prerequisite check passed.
///
/// # Panics
///
/// Panics if the check is not available.
pub fn assert_prerequisite_available(check: &PrerequisiteCheck) {
    assert!(
        check.available,
        "prerequisite '{}' should be available but got error: {:?}",
        check.name, check.error
    );
}

/// Assert that a bridge had no errors during its lifecycle.
///
/// # Panics
///
/// Panics if any errors were recorded.
pub fn assert_bridge_no_errors(tracker: &BridgeConnectionTracker) {
    assert!(
        tracker.errors().is_empty(),
        "expected no bridge errors, got {} errors: {:?}",
        tracker.errors().len(),
        tracker.errors()
    );
}

/// Assert bridge connection happened within a timeout.
///
/// # Panics
///
/// Panics if there are no connect events, or the first occurred after the timeout.
pub fn assert_bridge_connected_within(tracker: &BridgeConnectionTracker, timeout: Duration) {
    let first_connect = tracker
        .events()
        .iter()
        .find(|e| matches!(e.kind, BridgeEventKind::Connect(_)));
    assert!(first_connect.is_some(), "no connect event found");
    let first = tracker.events().first().expect("events not empty");
    let connect = first_connect.expect("connect event");
    let elapsed = connect.timestamp.duration_since(first.timestamp);
    assert!(
        elapsed <= timeout,
        "connection took {elapsed:?}, expected within {timeout:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_lifecycle() {
        let mut tracker = BridgeConnectionTracker::new();
        assert_eq!(tracker.state(), BridgeState::Disconnected);
        assert_eq!(tracker.connect_count(), 0);

        tracker.record_connect("ws://localhost:9222");
        assert_eq!(tracker.state(), BridgeState::Connected);
        assert_eq!(tracker.connect_count(), 1);

        tracker.record_message_sent("Page.navigate");
        tracker.record_message_received("Page.loadEventFired");
        assert_eq!(tracker.messages_sent(), 1);
        assert_eq!(tracker.messages_received(), 1);

        tracker.record_disconnect();
        assert_eq!(tracker.state(), BridgeState::Closed);
    }

    #[test]
    fn tracker_error_recording() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_error("connection refused");
        assert_eq!(tracker.state(), BridgeState::Failed);
        assert_eq!(tracker.errors().len(), 1);
    }

    #[test]
    fn tracker_reconnect_counting() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_error("timeout");
        tracker.record_reconnect(1);
        tracker.record_connect("ws://localhost:9222");
        assert_eq!(tracker.connect_count(), 2);
    }

    #[test]
    fn mock_bridge_discovery_format() {
        let disco = mock_bridge_discovery(&[("t1", "Tab 1"), ("t2", "Tab 2")]);
        let arr = disco.as_array().expect("should be array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["id"], "t1");
        assert_eq!(arr[1]["title"], "Tab 2");
    }

    #[test]
    fn mock_bridge_command_response_format() {
        let resp = mock_bridge_command_response(42, &json!({"status": "ok"}));
        assert_eq!(resp["id"], 42);
        assert_eq!(resp["result"]["status"], "ok");
    }

    #[test]
    fn mock_bridge_error_response_format() {
        let resp = mock_bridge_error_response(7, -32_600, "Invalid Request");
        assert_eq!(resp["id"], 7);
        assert_eq!(resp["error"]["code"], -32_600);
    }

    #[test]
    fn mock_bridge_event_format() {
        let evt = mock_bridge_event("Page.loadEventFired", &json!({"timestamp": 123.0}));
        assert_eq!(evt["method"], "Page.loadEventFired");
    }

    #[test]
    fn prerequisite_check_available() {
        let check = PrerequisiteCheckBuilder::new("chromium")
            .available("120.0.1", "/usr/bin/chromium")
            .build();
        assert!(check.available);
        assert_eq!(check.version.as_deref(), Some("120.0.1"));
        assert_prerequisite_available(&check);
    }

    #[test]
    fn prerequisite_check_unavailable() {
        let check = PrerequisiteCheckBuilder::new("docker")
            .unavailable("not found in PATH")
            .build();
        assert!(!check.available);
        assert_eq!(check.error.as_deref(), Some("not found in PATH"));
    }

    #[test]
    fn assert_clean_disconnect_passes() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_disconnect();
        assert_bridge_clean_disconnect(&tracker);
    }

    #[test]
    #[should_panic(expected = "expected clean disconnect")]
    fn assert_clean_disconnect_fails_on_connected() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        assert_bridge_clean_disconnect(&tracker);
    }

    #[test]
    fn assert_messages_exchanged_passes() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_message_sent("cmd1");
        tracker.record_message_sent("cmd2");
        tracker.record_message_received("resp1");
        assert_bridge_messages_exchanged(&tracker, 2, 1);
    }

    #[test]
    fn default_tracker() {
        let tracker = BridgeConnectionTracker::default();
        assert_eq!(tracker.state(), BridgeState::Disconnected);
    }

    #[test]
    fn assert_no_errors_passes_when_clean() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_disconnect();
        assert_bridge_no_errors(&tracker);
    }

    #[test]
    #[should_panic(expected = "expected no bridge errors")]
    fn assert_no_errors_fails_with_errors() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_error("boom");
        assert_bridge_no_errors(&tracker);
    }

    #[test]
    fn events_preserved_in_order() {
        let mut tracker = BridgeConnectionTracker::new();
        tracker.record_connect("ws://localhost:9222");
        tracker.record_message_sent("a");
        tracker.record_message_received("b");
        tracker.record_disconnect();
        assert_eq!(tracker.events().len(), 4);
        assert!(matches!(
            tracker.events()[0].kind,
            BridgeEventKind::Connect(_)
        ));
        assert!(matches!(
            tracker.events()[3].kind,
            BridgeEventKind::Disconnect
        ));
    }

    #[test]
    fn local_process_contract_declares_stdio_artifacts() {
        let contract = canonical_local_process_harness_contract();

        assert_eq!(contract.suite_class, "local_non_mock");
        assert_eq!(contract.family, LocalHarnessFamily::LocalProcess);
        assert!(
            contract
                .artifacts
                .iter()
                .any(|artifact| artifact.label == "stdout-txt")
        );
        assert!(
            contract
                .artifacts
                .iter()
                .any(|artifact| artifact.label == "stderr-txt")
        );
        assert!(
            contract
                .promoted_helpers
                .iter()
                .any(|helper| helper.symbol == "fcp_e2e::ConnectorProcessRunner")
        );
    }

    #[test]
    fn bridge_contract_mentions_reconnect_artifacts() {
        let contract = canonical_bridge_harness_contract();

        assert_eq!(contract.family, LocalHarnessFamily::Bridge);
        assert!(
            contract
                .artifacts
                .iter()
                .any(|artifact| artifact.label == "bridge-events-jsonl")
        );
        assert!(
            contract
                .scenarios
                .iter()
                .any(|scenario| scenario.kind == LocalHarnessScenarioKind::BridgeReconnectRecovery)
        );
    }

    #[test]
    fn queue_inventory_filters_to_queue_scenarios() {
        let scenarios = canonical_local_harness_inventory(LocalHarnessFamily::Queue);
        assert_eq!(scenarios.len(), 2);
        assert!(
            scenarios
                .iter()
                .all(|scenario| scenario.family == LocalHarnessFamily::Queue)
        );
    }

    #[test]
    fn local_harness_artifact_kind_serializes_snake_case() {
        let value = serde_json::to_value(LocalHarnessArtifactKind::Replay)
            .expect("artifact kind should serialize");
        assert_eq!(value, json!("replay"));
    }
}
