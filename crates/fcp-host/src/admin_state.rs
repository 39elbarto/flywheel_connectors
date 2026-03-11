//! Durable host-side admin state for connector lifecycle and configuration.
//!
//! This module extracts the host binary's persisted lifecycle snapshot into a
//! reusable library component and widens it into a canonical admin-state model
//! for later `fwc` lifecycle/config work. The current focus is the storage
//! shape, monotonic journal semantics, and persistence invariants.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

use blake3::hash;
use chrono::{DateTime, Utc};
use fcp_async_core::sync::{Mutex, RwLock};
use fcp_core::{
    ConnectorId, CredentialId, LifecycleError, LifecycleManager, LifecycleRecord, LifecycleState,
    LifecycleStatus, TransitionReason,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{HostError, HostResult, discovery::ConnectorSummary};

const HOST_ADMIN_STATE_SNAPSHOT_VERSION: u32 = 1;
const REDACTED_CONFIG_VALUE: &str = "[REDACTED]";

/// Canonical connector inventory entry persisted and applied by the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedConnectorConfig {
    /// Canonical connector identifier.
    pub id: String,
    /// Executable path for the connector binary.
    pub binary: String,
    /// Optional display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Additional argv entries passed to the connector subprocess.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Connector-specific environment overrides.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Optional persisted config payload forwarded to `configure`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    /// Optional category labels surfaced by discovery.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// Optional explicit semantic version override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Live connector inventory mutation kind handled by the host admin plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorInventoryMutationKind {
    /// Add a new connector to the managed inventory.
    Install,
    /// Replace an existing connector entry in the managed inventory.
    Update,
}

/// Host admin API request for a live connector inventory mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorInventoryMutationRequest {
    /// Requested mutation kind.
    pub kind: ConnectorInventoryMutationKind,
    /// Preview the mutation against the live host inventory without persisting or applying it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Connector entry to persist and apply.
    pub connector: ManagedConnectorConfig,
}

/// Result of reconciling the live subprocess registry to a new inventory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorInventoryApplyReport {
    /// Connector identifiers newly added to the live registry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub added: Vec<String>,
    /// Connector identifiers whose subprocess/config was refreshed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub updated: Vec<String>,
    /// Connector identifiers removed from the live registry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<String>,
    /// Connector identifiers left unchanged.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unchanged: Vec<String>,
    /// New registry version visible to cache-aware clients.
    pub registry_version: u64,
}

/// Host admin API response after persisting and applying an inventory mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorInventoryMutationResponse {
    /// Requested mutation kind.
    pub kind: ConnectorInventoryMutationKind,
    /// Whether this response is a preview only.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Managed connectors file written by the host.
    pub connectors_file: String,
    /// Previous connector entry when this was an update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<ManagedConnectorConfig>,
    /// Current persisted connector entry.
    pub current: ManagedConnectorConfig,
    /// Total connector count after the mutation.
    pub inventory_size: usize,
    /// Live registry reconciliation summary.
    pub apply: ConnectorInventoryApplyReport,
    /// Admin-state reconciliation summary after the live registry changed.
    pub admin_state: StartupReconciliationReport,
}

// ── Lifecycle transition RPC types ──────────────────────────────────────────

/// Lifecycle transition action requested via the host admin API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleAction {
    /// Enable a connector (set desired state to `Enabled`).
    Enable,
    /// Disable a connector without uninstalling (set desired state to `Disabled`).
    Disable,
    /// Restart a running connector (disable then re-enable).
    Restart,
    /// Reload connector configuration without a full restart.
    Reload,
    /// Remove a connector from active use (set desired state to `Uninstalled`).
    Uninstall,
    /// Promote a canary deployment to production.
    Promote,
}

/// Host admin API request for a lifecycle state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTransitionRequest {
    /// Requested lifecycle action.
    pub action: LifecycleAction,
    /// Optional human-readable reason for the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Optional actor or subsystem requesting the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiated_by: Option<String>,
    /// Preview the transition without persisting it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
}

/// Host admin API response after a lifecycle state transition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTransitionResponse {
    /// Connector identifier.
    pub connector_id: String,
    /// Action that was performed.
    pub action: LifecycleAction,
    /// Whether this was a preview only.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    /// Desired state before the transition.
    pub previous_desired_state: DesiredRuntimeState,
    /// Desired state after the transition.
    pub current_desired_state: DesiredRuntimeState,
    /// Observed state at the time of the transition.
    pub observed_state: ObservedRuntimeState,
    /// Lifecycle record if available after the transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_status: Option<LifecycleStatus>,
    /// Journal sequence number for this transition.
    pub journal_sequence: u64,
    /// Timestamp of the transition.
    pub transitioned_at: DateTime<Utc>,
}

/// Host admin API request for querying the admin state journal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalQueryRequest {
    /// Optional connector ID filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    /// Only return entries after this sequence number.
    #[serde(default)]
    pub after_sequence: u64,
    /// Maximum number of entries to return.
    #[serde(default = "default_journal_limit")]
    pub limit: usize,
}

const fn default_journal_limit() -> usize {
    100
}

/// Host admin API response for a journal query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalQueryResponse {
    /// Journal entries matching the query.
    pub entries: Vec<AdminStateJournalEntry>,
    /// Total number of entries in the journal (before filtering).
    pub total_entries: usize,
    /// Highest sequence number in the response.
    pub latest_sequence: u64,
}

/// Desired connector runtime state persisted by the host admin plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DesiredRuntimeState {
    /// No desired runtime target has been recorded yet.
    #[default]
    Unspecified,
    /// Connector should be enabled and eligible for execution.
    Enabled,
    /// Connector should remain installed but disabled.
    Disabled,
    /// Connector should be removed from active use.
    Uninstalled,
}

impl DesiredRuntimeState {
    const fn from_lifecycle_state(state: LifecycleState) -> Self {
        match state {
            LifecycleState::Disabled => Self::Disabled,
            LifecycleState::Uninstalled => Self::Uninstalled,
            LifecycleState::Pending
            | LifecycleState::Installing
            | LifecycleState::Canary
            | LifecycleState::Production
            | LifecycleState::RolledBack => Self::Enabled,
        }
    }
}

/// Observed connector runtime state persisted by the host admin plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ObservedRuntimeState {
    /// The host has not yet observed a concrete runtime state.
    #[default]
    Unknown,
    /// Connector is starting or installing.
    Starting,
    /// Connector is running and currently receiving traffic.
    Running,
    /// Connector is available but degraded or recently rolled back.
    Degraded,
    /// Connector is stopped by policy or operator action.
    Stopped,
    /// Connector artifacts or runtime process are missing.
    Missing,
}

impl ObservedRuntimeState {
    const fn from_lifecycle_state(state: LifecycleState) -> Self {
        match state {
            LifecycleState::Pending | LifecycleState::Installing => Self::Starting,
            LifecycleState::Canary | LifecycleState::Production => Self::Running,
            LifecycleState::RolledBack => Self::Degraded,
            LifecycleState::Disabled => Self::Stopped,
            LifecycleState::Uninstalled => Self::Missing,
        }
    }
}

/// A single connector config revision recorded by the host admin plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigRevisionRecord {
    /// Monotonic revision identifier.
    pub revision_id: u64,
    /// Previous active revision for this connector, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_revision_id: Option<u64>,
    /// Revision creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Optional actor or subsystem that created the revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Optional summary or mutation reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_reason: Option<String>,
    /// Export-safe connector config payload with inline secrets redacted.
    pub payload: Value,
    /// Stable digest of the serialized payload.
    pub payload_digest: String,
    /// JSON pointer paths where inline secret material was redacted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
    /// Secretless credential references preserved in persisted config state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_references: Vec<CredentialReferenceRecord>,
    /// Whether the original payload contained inline secret material.
    #[serde(default, skip_serializing_if = "is_false")]
    pub contains_inline_secrets: bool,
}

impl ConfigRevisionRecord {
    fn new(
        revision_id: u64,
        previous_revision_id: Option<u64>,
        payload: Value,
        created_by: Option<String>,
        change_reason: Option<String>,
    ) -> Result<Self, LifecycleError> {
        let payload_digest = config_payload_digest(&payload)?;
        let sanitized_payload = sanitize_config_payload(payload);
        Ok(Self {
            revision_id,
            previous_revision_id,
            created_at: Utc::now(),
            created_by,
            change_reason,
            payload: sanitized_payload.payload,
            payload_digest,
            redacted_fields: sanitized_payload.redacted_fields,
            credential_references: sanitized_payload.credential_references,
            contains_inline_secrets: sanitized_payload.contains_inline_secrets,
        })
    }
}

/// Sanitized connector config payload safe for host responses and audit trails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedConnectorConfig {
    /// Export-safe config payload with inline secrets redacted.
    pub payload: Value,
    /// Stable digest of the raw serialized payload.
    pub payload_digest: String,
    /// JSON pointer paths where inline secret material was redacted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_fields: Vec<String>,
    /// Secretless credential references preserved in the payload.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_references: Vec<CredentialReferenceRecord>,
    /// Whether the original payload contained inline secret material.
    #[serde(default, skip_serializing_if = "is_false")]
    pub contains_inline_secrets: bool,
}

impl SanitizedConnectorConfig {
    /// Build a sanitized config view from a raw payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the payload cannot be serialized for digesting.
    pub fn from_payload(payload: Value) -> Result<Self, LifecycleError> {
        let payload_digest = config_payload_digest(&payload)?;
        let sanitized_payload = sanitize_config_payload(payload);
        Ok(Self {
            payload: sanitized_payload.payload,
            payload_digest,
            redacted_fields: sanitized_payload.redacted_fields,
            credential_references: sanitized_payload.credential_references,
            contains_inline_secrets: sanitized_payload.contains_inline_secrets,
        })
    }

    /// Whether this sanitized payload can be safely replayed back into the host.
    #[must_use]
    pub const fn is_replayable(&self) -> bool {
        !self.contains_inline_secrets
    }
}

impl From<&ConfigRevisionRecord> for SanitizedConnectorConfig {
    fn from(revision: &ConfigRevisionRecord) -> Self {
        Self {
            payload: revision.payload.clone(),
            payload_digest: revision.payload_digest.clone(),
            redacted_fields: revision.redacted_fields.clone(),
            credential_references: revision.credential_references.clone(),
            contains_inline_secrets: revision.contains_inline_secrets,
        }
    }
}

/// Source of the current host-visible config snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorConfigSnapshotSource {
    /// Current config is backed by the active admin-state revision.
    ActiveRevision,
    /// Current config comes from the managed inventory but has not yet been
    /// checkpointed into config revision history.
    ManagedInventory,
}

/// Host-visible current config snapshot for one connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigSnapshot {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Current sanitized config payload.
    pub current: SanitizedConnectorConfig,
    /// Where the current payload came from.
    pub source: ConnectorConfigSnapshotSource,
    /// Active config revision id, if one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_id: Option<u64>,
    /// Active revision metadata, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision: Option<ConfigRevisionRecord>,
    /// Total config revisions tracked for the connector.
    pub revision_count: usize,
    /// Latest journal sequence touching this connector.
    pub last_journal_sequence: u64,
}

/// Host-visible config revision history for one connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigRevisionsResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Currently active revision id, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_revision_id: Option<u64>,
    /// Total revisions in history.
    pub revision_count: usize,
    /// Latest journal sequence touching this connector.
    pub last_journal_sequence: u64,
    /// Recorded config revisions in creation order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revisions: Vec<ConfigRevisionRecord>,
}

/// Diff request comparing a candidate config payload against the current config
/// or a specific prior revision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigDiffRequest {
    /// Candidate raw config payload.
    pub payload: Value,
    /// Optional baseline revision id. Defaults to the current config snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<u64>,
}

/// Diff classification for one changed config path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigDiffKind {
    /// Path was added in the candidate payload.
    Added,
    /// Path was removed from the candidate payload.
    Removed,
    /// Path existed in both payloads but changed value.
    Changed,
}

/// One changed config path between two payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigDiffEntry {
    /// JSON pointer path (`/` for the root payload).
    pub path: String,
    /// Change classification.
    pub kind: ConfigDiffKind,
    /// Previous value when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<Value>,
    /// Candidate value when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<Value>,
}

/// Host-visible diff response for one config candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigDiffResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Baseline revision id when diffing against revision history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_revision_id: Option<u64>,
    /// Sanitized baseline payload.
    pub base: SanitizedConnectorConfig,
    /// Sanitized candidate payload.
    pub candidate: SanitizedConnectorConfig,
    /// Whether any paths changed.
    pub changed: bool,
    /// Detailed changed paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<ConfigDiffEntry>,
}

/// Validate a candidate config payload against the live host registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigValidateRequest {
    /// Candidate raw config payload.
    pub payload: Value,
    /// Optional optimistic concurrency guard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_active_revision_id: Option<u64>,
}

/// Validation result for a candidate config payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigValidateResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Whether the host accepted the candidate in preview mode.
    pub valid: bool,
    /// Current active revision id when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_active_revision_id: Option<u64>,
    /// Current sanitized config payload.
    pub current: SanitizedConnectorConfig,
    /// Candidate sanitized config payload.
    pub candidate: SanitizedConnectorConfig,
    /// Detailed changed paths between current and candidate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diff: Vec<ConfigDiffEntry>,
    /// Preview of the live registry reconciliation when validation succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<ConnectorInventoryApplyReport>,
    /// Validation failure when `valid=false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Apply a candidate config payload through the live host admin plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigApplyRequest {
    /// Candidate raw config payload.
    pub payload: Value,
    /// Optional optimistic concurrency guard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_active_revision_id: Option<u64>,
    /// Optional actor/subsystem label recorded in revision history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Optional change summary recorded in revision history.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_reason: Option<String>,
}

/// Apply response for a host-backed config mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigApplyResponse {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Whether the requested payload changed anything materially.
    #[serde(default, skip_serializing_if = "is_false")]
    pub changed: bool,
    /// Previous active revision id when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_active_revision_id: Option<u64>,
    /// Current active revision id when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_active_revision_id: Option<u64>,
    /// Previous sanitized config payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<SanitizedConnectorConfig>,
    /// Current sanitized config payload after the mutation.
    pub current: SanitizedConnectorConfig,
    /// Detailed changed paths between previous and current.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diff: Vec<ConfigDiffEntry>,
    /// Newly recorded active revision when a write occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<ConfigRevisionRecord>,
    /// Live registry reconciliation report.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apply: Option<ConnectorInventoryApplyReport>,
    /// Admin-state reconciliation summary after the live registry changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_state: Option<StartupReconciliationReport>,
}

/// Roll back to a previous config revision by re-applying its sanitized payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfigRollbackRequest {
    /// Revision to re-apply as the new active config.
    pub revision_id: u64,
    /// Optional optimistic concurrency guard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_active_revision_id: Option<u64>,
    /// Optional actor/subsystem label recorded in the new revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Optional change summary recorded in the new revision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_reason: Option<String>,
}

/// Compute a stable path-level diff between two config payloads.
#[must_use]
pub fn diff_config_values(before: &Value, after: &Value) -> Vec<ConfigDiffEntry> {
    let mut entries = Vec::new();
    diff_config_values_inner("", Some(before), Some(after), &mut entries);
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

fn diff_config_values_inner(
    path: &str,
    before: Option<&Value>,
    after: Option<&Value>,
    entries: &mut Vec<ConfigDiffEntry>,
) {
    match (before, after) {
        (Some(left), Some(right)) if left == right => {}
        (None, Some(right)) => entries.push(ConfigDiffEntry {
            path: config_diff_path(path),
            kind: ConfigDiffKind::Added,
            before: None,
            after: Some(right.clone()),
        }),
        (Some(left), None) => entries.push(ConfigDiffEntry {
            path: config_diff_path(path),
            kind: ConfigDiffKind::Removed,
            before: Some(left.clone()),
            after: None,
        }),
        (Some(Value::Object(left)), Some(Value::Object(right))) => {
            let keys = left
                .keys()
                .chain(right.keys())
                .cloned()
                .collect::<BTreeSet<_>>();
            for key in keys {
                let child_path = join_json_pointer(path, &key);
                diff_config_values_inner(&child_path, left.get(&key), right.get(&key), entries);
            }
        }
        (Some(Value::Array(left)), Some(Value::Array(right))) => {
            let max_len = left.len().max(right.len());
            for index in 0..max_len {
                let child_path = join_json_pointer(path, &index.to_string());
                diff_config_values_inner(&child_path, left.get(index), right.get(index), entries);
            }
        }
        (Some(left), Some(right)) => entries.push(ConfigDiffEntry {
            path: config_diff_path(path),
            kind: ConfigDiffKind::Changed,
            before: Some(left.clone()),
            after: Some(right.clone()),
        }),
        (None, None) => {}
    }
}

fn config_diff_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn join_json_pointer(path: &str, segment: &str) -> String {
    let escaped = segment.replace('~', "~0").replace('/', "~1");
    if path.is_empty() {
        format!("/{escaped}")
    } else {
        format!("{path}/{escaped}")
    }
}

/// Resolution state for a persisted secretless credential reference.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReferenceStatus {
    /// The host has not checked the reference since it was persisted.
    #[default]
    Unknown,
    /// The reference is currently resolvable.
    Available,
    /// The underlying secret material rotated since the last known-good check.
    Rotated,
    /// The referenced credential no longer exists.
    Missing,
    /// The reference exists but could not be accessed.
    Inaccessible,
}

/// Secretless credential reference metadata captured in config revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialReferenceRecord {
    /// JSON pointer path to the reference inside the config payload.
    pub path: String,
    /// Credential handle preserved instead of inline secret material.
    pub credential_id: CredentialId,
    /// Latest known resolution state for this reference.
    #[serde(default)]
    pub status: SecretReferenceStatus,
    /// Most recent resolution attempt timestamp, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_checked_at: Option<DateTime<Utc>>,
    /// Most recent resolution error, redacted and operator-safe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Mutation recorded in the host admin-state journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdminStateMutation {
    /// Lifecycle record was upserted.
    LifecycleRecordSaved {
        /// Version currently represented by the lifecycle record.
        version: Version,
        /// Current lifecycle state after the save.
        state: LifecycleState,
    },
    /// Desired runtime state changed.
    DesiredStateSet {
        /// New desired runtime target.
        desired_state: DesiredRuntimeState,
    },
    /// Observed runtime state changed.
    ObservedStateSet {
        /// New observed runtime state.
        observed_state: ObservedRuntimeState,
    },
    /// Connector pin state changed.
    PinSet {
        /// Version pinned for the connector.
        version: Version,
    },
    /// Connector pin state was cleared.
    PinCleared,
    /// Config revision was appended and made active.
    ConfigRevisionAppended {
        /// Newly assigned revision identifier.
        revision_id: u64,
        /// Stable payload digest for diff/audit linkage.
        payload_digest: String,
    },
}

/// A monotonic admin-state journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminStateJournalEntry {
    /// Monotonic sequence number for total ordering.
    pub sequence: u64,
    /// Connector affected by the mutation.
    pub connector_id: ConnectorId,
    /// Timestamp of the mutation.
    pub occurred_at: DateTime<Utc>,
    /// Mutation detail.
    pub mutation: AdminStateMutation,
    /// Optional initiating actor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiated_by: Option<String>,
}

/// Canonical persisted admin state for a single connector.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectorAdminState {
    /// Latest persisted lifecycle record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleRecord>,
    /// Desired runtime target.
    #[serde(default)]
    pub desired_state: DesiredRuntimeState,
    /// Latest host-observed runtime state.
    #[serde(default)]
    pub observed_state: ObservedRuntimeState,
    /// Optional pinned version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_version: Option<Version>,
    /// Recorded config revisions for this connector.
    #[serde(default)]
    pub config_revisions: Vec<ConfigRevisionRecord>,
    /// Currently active config revision id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_config_revision_id: Option<u64>,
    /// Last journal sequence that mutated this connector.
    #[serde(default)]
    pub last_journal_sequence: u64,
}

impl ConnectorAdminState {
    /// Return the active config revision, if any.
    #[must_use]
    pub fn active_config_revision(&self) -> Option<&ConfigRevisionRecord> {
        let revision_id = self.active_config_revision_id?;
        self.config_revisions
            .iter()
            .find(|revision| revision.revision_id == revision_id)
    }

    const fn apply_lifecycle_projection(&mut self, record: &LifecycleRecord) {
        self.desired_state = DesiredRuntimeState::from_lifecycle_state(record.state);
        self.observed_state = ObservedRuntimeState::from_lifecycle_state(record.state);
    }
}

const STARTUP_RECONCILIATION_ACTOR: &str = "host-startup-reconcile";
const STARTUP_RECONCILIATION_STUCK_SECS: i64 = 300;

/// Recommended next action when connector state has drifted from intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// Restart the connector runtime.
    RestartConnector,
    /// Repair configuration or health before retrying.
    RepairConnector,
    /// Reinstall or restore connector artifacts.
    ReinstallConnector,
    /// Finish an in-flight rollout decision.
    CompleteRollout,
    /// Disable or uninstall the connector to match policy.
    DisableConnector,
    /// Manual operator investigation is required.
    Investigate,
}

/// Drift category for desired-versus-observed connector state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorDriftKind {
    /// Connector should be enabled but is not running.
    EnabledButNotRunning,
    /// Connector should be enabled but the artifact/runtime is missing.
    EnabledButMissing,
    /// Connector is enabled but degraded.
    EnabledButDegraded,
    /// Connector is disabled but still active.
    DisabledButRunning,
    /// Connector should be absent but is still present.
    UninstalledButPresent,
    /// Installation appears to be stuck.
    InstallStuck,
    /// Canary rollout is overdue for promotion or rollback.
    CanaryStuck,
}

/// Human/audit-friendly drift detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorDriftStatus {
    /// Classified drift kind.
    pub kind: ConnectorDriftKind,
    /// Suggested recovery action for the operator or agent.
    pub recovery_action: RecoveryAction,
    /// Stable human-readable summary.
    pub message: String,
}

/// Host-visible connector status after reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorAdminStatus {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Desired runtime target.
    pub desired_state: DesiredRuntimeState,
    /// Latest observed runtime state.
    pub observed_state: ObservedRuntimeState,
    /// Lifecycle/rollout status when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<LifecycleStatus>,
    /// Optional pinned version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pinned_version: Option<Version>,
    /// Active config revision id, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_config_revision_id: Option<u64>,
    /// Total config revisions tracked for this connector.
    pub config_revision_count: usize,
    /// Latest journal sequence touching this connector.
    pub last_journal_sequence: u64,
    /// Drift/recovery diagnosis when desired and observed state diverge.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drift: Option<ConnectorDriftStatus>,
    /// Timestamp when this view was evaluated.
    pub evaluated_at: DateTime<Utc>,
}

/// Result row for one connector during startup reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupReconciliationEntry {
    /// Connector identifier.
    pub connector_id: ConnectorId,
    /// Whether the connector received a fresh admin-state row.
    pub created_admin_state: bool,
    /// Desired runtime state after reconciliation.
    pub desired_state: DesiredRuntimeState,
    /// Observed state before reconciliation.
    pub observed_state_before: ObservedRuntimeState,
    /// Observed state after reconciliation.
    pub observed_state_after: ObservedRuntimeState,
    /// Whether persistence state changed during reconciliation.
    pub updated: bool,
    /// Drift classification after reconciliation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drift: Option<ConnectorDriftStatus>,
}

/// Aggregate startup reconciliation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupReconciliationReport {
    /// Timestamp of the reconciliation pass.
    pub reconciled_at: DateTime<Utc>,
    /// Total tracked connectors after reconciliation.
    pub tracked_connectors: usize,
    /// Number of connector admin-state rows created.
    pub created_connectors: usize,
    /// Number of observed-state updates applied.
    pub observed_updates: usize,
    /// Number of connectors still in drift after reconciliation.
    pub drifted_connectors: usize,
    /// Per-connector outcomes.
    pub entries: Vec<StartupReconciliationEntry>,
}

const fn desired_state_from_summary(summary: &ConnectorSummary) -> DesiredRuntimeState {
    if summary.enabled {
        DesiredRuntimeState::Enabled
    } else {
        DesiredRuntimeState::Disabled
    }
}

const fn observed_state_from_summary(summary: &ConnectorSummary) -> ObservedRuntimeState {
    if !summary.enabled {
        return ObservedRuntimeState::Stopped;
    }

    match &summary.health {
        fcp_core::ConnectorHealth::Healthy => ObservedRuntimeState::Running,
        fcp_core::ConnectorHealth::Degraded { .. } => ObservedRuntimeState::Degraded,
        fcp_core::ConnectorHealth::Unavailable { .. } => ObservedRuntimeState::Stopped,
    }
}

fn install_stuck(record: &LifecycleRecord, now: DateTime<Utc>) -> bool {
    matches!(
        record.state,
        LifecycleState::Pending | LifecycleState::Installing
    ) && now
        .signed_duration_since(record.state_changed_at)
        .num_seconds()
        >= STARTUP_RECONCILIATION_STUCK_SECS
}

fn canary_stuck(record: &LifecycleRecord, now: DateTime<Utc>) -> bool {
    record.state == LifecycleState::Canary && record.canary_expires_in_secs_at(now) == Some(0)
}

fn connector_drift_status(
    state: &ConnectorAdminState,
    now: DateTime<Utc>,
) -> Option<ConnectorDriftStatus> {
    if let Some(record) = state.lifecycle.as_ref() {
        if install_stuck(record, now) {
            return Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::InstallStuck,
                recovery_action: RecoveryAction::Investigate,
                message: "connector install/startup has remained pending long enough to require operator investigation".to_string(),
            });
        }

        if canary_stuck(record, now) {
            return Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::CanaryStuck,
                recovery_action: RecoveryAction::CompleteRollout,
                message: "connector canary has exceeded its maximum duration and needs promotion or rollback".to_string(),
            });
        }
    }

    match state.desired_state {
        DesiredRuntimeState::Enabled => match state.observed_state {
            ObservedRuntimeState::Degraded => Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::EnabledButDegraded,
                recovery_action: RecoveryAction::RepairConnector,
                message: "connector should be enabled but health or self-check results are degraded".to_string(),
            }),
            ObservedRuntimeState::Stopped => Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::EnabledButNotRunning,
                recovery_action: RecoveryAction::RestartConnector,
                message: "connector should be enabled but is not currently running".to_string(),
            }),
            ObservedRuntimeState::Missing => Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::EnabledButMissing,
                recovery_action: RecoveryAction::ReinstallConnector,
                message: "connector should be enabled but no live runtime or artifact was found".to_string(),
            }),
            ObservedRuntimeState::Unknown | ObservedRuntimeState::Starting => Some(
                ConnectorDriftStatus {
                    kind: ConnectorDriftKind::EnabledButNotRunning,
                    recovery_action: RecoveryAction::Investigate,
                    message: "connector should be enabled but the host has not yet observed a stable running state".to_string(),
                },
            ),
            ObservedRuntimeState::Running => None,
        },
        DesiredRuntimeState::Disabled => match state.observed_state {
            ObservedRuntimeState::Running | ObservedRuntimeState::Degraded => {
                Some(ConnectorDriftStatus {
                    kind: ConnectorDriftKind::DisabledButRunning,
                    recovery_action: RecoveryAction::DisableConnector,
                    message: "connector should be disabled but still appears active".to_string(),
                })
            }
            _ => None,
        },
        DesiredRuntimeState::Uninstalled => match state.observed_state {
            ObservedRuntimeState::Running
            | ObservedRuntimeState::Degraded
            | ObservedRuntimeState::Stopped
            | ObservedRuntimeState::Starting => Some(ConnectorDriftStatus {
                kind: ConnectorDriftKind::UninstalledButPresent,
                recovery_action: RecoveryAction::DisableConnector,
                message: "connector should be uninstalled but host state still shows it present".to_string(),
            }),
            ObservedRuntimeState::Unknown | ObservedRuntimeState::Missing => None,
        },
        DesiredRuntimeState::Unspecified => None,
    }
}

fn connector_admin_status_from_state(
    connector_id: &ConnectorId,
    state: &ConnectorAdminState,
    now: DateTime<Utc>,
) -> ConnectorAdminStatus {
    ConnectorAdminStatus {
        connector_id: connector_id.clone(),
        desired_state: state.desired_state,
        observed_state: state.observed_state,
        lifecycle: state
            .lifecycle
            .as_ref()
            .map(|record| LifecycleStatus::from_record(record, now, false)),
        pinned_version: state.pinned_version.clone(),
        active_config_revision_id: state.active_config_revision_id,
        config_revision_count: state.config_revisions.len(),
        last_journal_sequence: state.last_journal_sequence,
        drift: connector_drift_status(state, now),
        evaluated_at: now,
    }
}

/// Entire persisted admin-state snapshot for the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostAdminStateSnapshot {
    #[serde(default = "host_admin_state_snapshot_version")]
    schema_version: u32,
    #[serde(default)]
    connectors: HashMap<ConnectorId, ConnectorAdminState>,
    #[serde(default)]
    journal: Vec<AdminStateJournalEntry>,
    #[serde(default = "initial_revision_id")]
    next_config_revision_id: u64,
    #[serde(default = "initial_journal_sequence")]
    next_journal_sequence: u64,
}

impl Default for HostAdminStateSnapshot {
    fn default() -> Self {
        Self {
            schema_version: HOST_ADMIN_STATE_SNAPSHOT_VERSION,
            connectors: HashMap::new(),
            journal: Vec::new(),
            next_config_revision_id: initial_revision_id(),
            next_journal_sequence: initial_journal_sequence(),
        }
    }
}

impl HostAdminStateSnapshot {
    fn connector_state_mut(&mut self, connector_id: &ConnectorId) -> &mut ConnectorAdminState {
        if !self.connectors.contains_key(connector_id) {
            self.connectors
                .insert(connector_id.clone(), ConnectorAdminState::default());
        }
        self.connectors.get_mut(connector_id).unwrap()
    }

    const fn next_config_revision_id(&mut self) -> u64 {
        let revision_id = self.next_config_revision_id;
        self.next_config_revision_id = self.next_config_revision_id.saturating_add(1);
        revision_id
    }

    fn append_journal(
        &mut self,
        connector_id: &ConnectorId,
        mutation: AdminStateMutation,
        initiated_by: Option<String>,
    ) -> u64 {
        let sequence = self.next_journal_sequence;
        self.next_journal_sequence = self.next_journal_sequence.saturating_add(1);
        self.journal.push(AdminStateJournalEntry {
            sequence,
            connector_id: connector_id.clone(),
            occurred_at: Utc::now(),
            mutation,
            initiated_by,
        });
        sequence
    }

    fn from_legacy(legacy: LegacyHostLifecycleSnapshot) -> Self {
        let mut snapshot = Self::default();
        for (connector_id, record) in legacy.records {
            let state = snapshot.connector_state_mut(&connector_id);
            state.apply_lifecycle_projection(&record);
            state.lifecycle = Some(record);
        }
        for (connector_id, pinned_version) in legacy.pinned_versions {
            snapshot.connector_state_mut(&connector_id).pinned_version = Some(pinned_version);
        }
        snapshot
    }
}

fn set_snapshot_desired_state(
    snapshot: &mut HostAdminStateSnapshot,
    connector_id: &ConnectorId,
    desired_state: DesiredRuntimeState,
    initiated_by: Option<&str>,
) -> bool {
    let current = snapshot
        .connectors
        .get(connector_id)
        .map_or(DesiredRuntimeState::Unspecified, |state| {
            state.desired_state
        });
    if current == desired_state {
        return false;
    }

    let sequence = snapshot.append_journal(
        connector_id,
        AdminStateMutation::DesiredStateSet { desired_state },
        initiated_by.map(ToOwned::to_owned),
    );
    let state = snapshot.connector_state_mut(connector_id);
    state.desired_state = desired_state;
    state.last_journal_sequence = sequence;
    true
}

fn set_snapshot_observed_state(
    snapshot: &mut HostAdminStateSnapshot,
    connector_id: &ConnectorId,
    observed_state: ObservedRuntimeState,
    initiated_by: Option<&str>,
) -> bool {
    let current = snapshot
        .connectors
        .get(connector_id)
        .map_or(ObservedRuntimeState::Unknown, |state| state.observed_state);
    if current == observed_state {
        return false;
    }

    let sequence = snapshot.append_journal(
        connector_id,
        AdminStateMutation::ObservedStateSet { observed_state },
        initiated_by.map(ToOwned::to_owned),
    );
    let state = snapshot.connector_state_mut(connector_id);
    state.observed_state = observed_state;
    state.last_journal_sequence = sequence;
    true
}

fn reconcile_registered_connector(
    snapshot: &mut HostAdminStateSnapshot,
    summary: &ConnectorSummary,
    now: DateTime<Utc>,
) -> (StartupReconciliationEntry, bool) {
    let connector_id = &summary.id;
    let created_admin_state = !snapshot.connectors.contains_key(connector_id);
    if created_admin_state {
        let _ = snapshot.connector_state_mut(connector_id);
    }

    let observed_state_before = snapshot
        .connectors
        .get(connector_id)
        .map_or(ObservedRuntimeState::Unknown, |state| state.observed_state);
    let mut updated = false;

    if created_admin_state
        || snapshot
            .connectors
            .get(connector_id)
            .is_some_and(|state| state.desired_state == DesiredRuntimeState::Unspecified)
    {
        updated |= set_snapshot_desired_state(
            snapshot,
            connector_id,
            desired_state_from_summary(summary),
            Some(STARTUP_RECONCILIATION_ACTOR),
        );
    }

    let observed_updated = set_snapshot_observed_state(
        snapshot,
        connector_id,
        observed_state_from_summary(summary),
        Some(STARTUP_RECONCILIATION_ACTOR),
    );
    updated |= observed_updated;

    let state = snapshot
        .connectors
        .get(connector_id)
        .expect("connector state must exist after reconciliation");
    (
        StartupReconciliationEntry {
            connector_id: connector_id.clone(),
            created_admin_state,
            desired_state: state.desired_state,
            observed_state_before,
            observed_state_after: state.observed_state,
            updated,
            drift: connector_drift_status(state, now),
        },
        observed_updated,
    )
}

fn reconcile_missing_connector(
    snapshot: &mut HostAdminStateSnapshot,
    connector_id: &ConnectorId,
    now: DateTime<Utc>,
) -> (StartupReconciliationEntry, bool) {
    let observed_state_before = snapshot
        .connectors
        .get(connector_id)
        .map_or(ObservedRuntimeState::Unknown, |state| state.observed_state);
    let observed_updated = set_snapshot_observed_state(
        snapshot,
        connector_id,
        ObservedRuntimeState::Missing,
        Some(STARTUP_RECONCILIATION_ACTOR),
    );
    let state = snapshot
        .connectors
        .get(connector_id)
        .expect("persisted connector state should still exist");
    (
        StartupReconciliationEntry {
            connector_id: connector_id.clone(),
            created_admin_state: false,
            desired_state: state.desired_state,
            observed_state_before,
            observed_state_after: state.observed_state,
            updated: observed_updated,
            drift: connector_drift_status(state, now),
        },
        observed_updated,
    )
}

const fn host_admin_state_snapshot_version() -> u32 {
    HOST_ADMIN_STATE_SNAPSHOT_VERSION
}

const fn initial_revision_id() -> u64 {
    1
}

const fn initial_journal_sequence() -> u64 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LegacyHostLifecycleSnapshot {
    #[serde(default = "host_admin_state_snapshot_version")]
    schema_version: u32,
    #[serde(default)]
    records: HashMap<ConnectorId, LifecycleRecord>,
    #[serde(default)]
    pinned_versions: HashMap<ConnectorId, Version>,
}

/// Durable host-side admin-state store.
pub struct HostAdminStateStore {
    state: RwLock<HostAdminStateSnapshot>,
    state_path: Option<PathBuf>,
    persist_lock: Mutex<()>,
}

impl Default for HostAdminStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HostAdminStateStore {
    /// Create an in-memory store without filesystem persistence.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: RwLock::new(HostAdminStateSnapshot::default()),
            state_path: None,
            persist_lock: Mutex::new(()),
        }
    }

    /// Create a store using the default admin-state path from the environment.
    ///
    /// The current implementation reuses the existing host lifecycle state file
    /// path so the extracted library store can consume previously persisted host
    /// snapshots.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured path is invalid or the persisted
    /// snapshot cannot be loaded.
    pub fn from_env() -> HostResult<Self> {
        let state_path = resolve_admin_state_path()?;
        Self::with_state_path_opt(state_path)
    }

    /// Create a store persisted at a specific path.
    ///
    /// # Errors
    ///
    /// Returns an error if the persisted snapshot cannot be loaded.
    pub fn with_state_path(state_path: PathBuf) -> HostResult<Self> {
        Self::with_state_path_opt(Some(state_path))
    }

    /// Create a store with an explicit optional persistence path.
    ///
    /// # Errors
    ///
    /// Returns an error if the persisted snapshot cannot be loaded.
    pub fn with_state_path_opt(state_path: Option<PathBuf>) -> HostResult<Self> {
        let state = match state_path.as_deref() {
            Some(path) => load_admin_state_snapshot(path)?,
            None => HostAdminStateSnapshot::default(),
        };
        Ok(Self {
            state: RwLock::new(state),
            state_path,
            persist_lock: Mutex::new(()),
        })
    }

    async fn apply_mutation<T, F>(&self, mutate: F) -> Result<T, LifecycleError>
    where
        F: FnOnce(&mut HostAdminStateSnapshot) -> Result<T, LifecycleError>,
    {
        let _persist_guard = self.persist_lock.lock().await;
        let mut snapshot = self.state.read().await.clone();
        let result = mutate(&mut snapshot)?;
        persist_admin_state_snapshot(self.state_path.as_deref(), &snapshot)?;
        *self.state.write().await = snapshot;
        Ok(result)
    }

    /// Return the persisted connector admin state, if present.
    pub async fn connector_state(&self, connector_id: &ConnectorId) -> Option<ConnectorAdminState> {
        self.state
            .read()
            .await
            .connectors
            .get(connector_id)
            .cloned()
    }

    /// Return the full admin-state journal or only the entries for one connector.
    pub async fn journal(&self, connector_id: Option<&ConnectorId>) -> Vec<AdminStateJournalEntry> {
        self.state
            .read()
            .await
            .journal
            .iter()
            .filter(|entry| connector_id.is_none_or(|id| &entry.connector_id == id))
            .cloned()
            .collect()
    }

    /// Export the current admin-state snapshot as JSON safe for CLI rendering,
    /// logs, fixtures, and diagnostics.
    ///
    /// Inline secret values are redacted before persistence, while
    /// credential-reference metadata remains available for safe inspection.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be serialized.
    pub async fn export_snapshot_json(&self) -> Result<Value, LifecycleError> {
        serde_json::to_value(self.state.read().await.clone()).map_err(|err| {
            LifecycleError::Persistence {
                reason: format!("could not serialize admin state export: {err}"),
            }
        })
    }

    /// Persist a desired runtime target for one connector.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be persisted.
    pub async fn set_desired_state(
        &self,
        connector_id: &ConnectorId,
        desired_state: DesiredRuntimeState,
        initiated_by: Option<String>,
    ) -> Result<(), LifecycleError> {
        self.apply_mutation(|snapshot| {
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::DesiredStateSet { desired_state },
                initiated_by,
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.desired_state = desired_state;
            state.last_journal_sequence = sequence;
            Ok(())
        })
        .await
    }

    /// Persist an observed runtime state for one connector.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be persisted.
    pub async fn set_observed_state(
        &self,
        connector_id: &ConnectorId,
        observed_state: ObservedRuntimeState,
        initiated_by: Option<String>,
    ) -> Result<(), LifecycleError> {
        self.apply_mutation(|snapshot| {
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::ObservedStateSet { observed_state },
                initiated_by,
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.observed_state = observed_state;
            state.last_journal_sequence = sequence;
            Ok(())
        })
        .await
    }

    /// Append and activate a config revision for one connector.
    ///
    /// # Errors
    ///
    /// Returns an error if the config payload cannot be serialized or the
    /// snapshot cannot be persisted.
    pub async fn append_config_revision(
        &self,
        connector_id: &ConnectorId,
        payload: Value,
        created_by: Option<String>,
        change_reason: Option<String>,
    ) -> Result<ConfigRevisionRecord, LifecycleError> {
        self.apply_mutation(|snapshot| {
            let previous_revision_id = snapshot
                .connectors
                .get(connector_id)
                .and_then(|state| state.active_config_revision_id);
            let revision_id = snapshot.next_config_revision_id();
            let revision = ConfigRevisionRecord::new(
                revision_id,
                previous_revision_id,
                payload,
                created_by.clone(),
                change_reason,
            )?;
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::ConfigRevisionAppended {
                    revision_id,
                    payload_digest: revision.payload_digest.clone(),
                },
                created_by,
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.config_revisions.push(revision.clone());
            state.active_config_revision_id = Some(revision_id);
            state.last_journal_sequence = sequence;
            Ok(revision)
        })
        .await
    }

    /// Pin a specific connector version.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be persisted.
    pub async fn pin(
        &self,
        connector_id: &ConnectorId,
        version: Version,
    ) -> Result<(), LifecycleError> {
        self.apply_mutation(|snapshot| {
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::PinSet {
                    version: version.clone(),
                },
                None,
            );
            let state = snapshot.connector_state_mut(connector_id);
            state.pinned_version = Some(version);
            state.last_journal_sequence = sequence;
            Ok(())
        })
        .await
    }

    /// Remove a connector version pin, returning the previous pin if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the snapshot cannot be persisted.
    pub async fn unpin(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<Option<Version>, LifecycleError> {
        self.apply_mutation(|snapshot| {
            let removed = snapshot
                .connectors
                .get(connector_id)
                .and_then(|state| state.pinned_version.clone());
            let sequence =
                snapshot.append_journal(connector_id, AdminStateMutation::PinCleared, None);
            let state = snapshot.connector_state_mut(connector_id);
            state.pinned_version = None;
            state.last_journal_sequence = sequence;
            Ok(removed)
        })
        .await
    }

    /// Return the current pinned version, if any.
    pub async fn pinned_version(&self, connector_id: &ConnectorId) -> Option<Version> {
        self.state
            .read()
            .await
            .connectors
            .get(connector_id)
            .and_then(|state| state.pinned_version.clone())
    }

    /// Return a host-facing desired-versus-observed status view for one
    /// connector.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleError::NotFound`] when the connector has no persisted
    /// admin state.
    pub async fn connector_status(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<ConnectorAdminStatus, LifecycleError> {
        self.connector_status_at(connector_id, Utc::now()).await
    }

    async fn connector_status_at(
        &self,
        connector_id: &ConnectorId,
        now: DateTime<Utc>,
    ) -> Result<ConnectorAdminStatus, LifecycleError> {
        let state = self.state.read().await;
        let connector_state =
            state
                .connectors
                .get(connector_id)
                .ok_or_else(|| LifecycleError::NotFound {
                    connector_id: connector_id.clone(),
                })?;
        Ok(connector_admin_status_from_state(
            connector_id,
            connector_state,
            now,
        ))
    }

    /// Execute a lifecycle transition and return the resulting state.
    ///
    /// The transition atomically updates desired state, journals the mutation,
    /// and optionally delegates to the [`LifecycleManager`] trait for promote
    /// operations. Dry-run mode returns the projected state without persisting.
    ///
    /// # Errors
    ///
    /// Returns an error if the connector is not tracked or if the transition
    /// is invalid for the current state.
    pub async fn execute_lifecycle_transition(
        &self,
        connector_id: &ConnectorId,
        request: &LifecycleTransitionRequest,
    ) -> Result<LifecycleTransitionResponse, LifecycleError> {
        let now = Utc::now();

        // Read current state first (for dry-run and validation).
        let (previous_desired, observed, current_lifecycle_status, current_seq) = {
            let state = self.state.read().await;
            let cs =
                state
                    .connectors
                    .get(connector_id)
                    .ok_or_else(|| LifecycleError::NotFound {
                        connector_id: connector_id.clone(),
                    })?;
            let lifecycle_status = cs.lifecycle.as_ref().map(|record| LifecycleStatus {
                connector_id: connector_id.clone(),
                state: record.state,
                version: record.version.clone(),
                health: record.health.clone(),
                auto_promote_pending: false,
                auto_rollback_pending: false,
                canary_expires_in_secs: None,
                crash_loop_detected: false,
                rollback_target_version: record.previous_version.clone(),
            });
            (
                cs.desired_state,
                cs.observed_state,
                lifecycle_status,
                cs.last_journal_sequence,
            )
        };

        let target_desired = match request.action {
            LifecycleAction::Enable | LifecycleAction::Restart | LifecycleAction::Reload => {
                DesiredRuntimeState::Enabled
            }
            LifecycleAction::Disable => DesiredRuntimeState::Disabled,
            LifecycleAction::Uninstall => DesiredRuntimeState::Uninstalled,
            LifecycleAction::Promote => DesiredRuntimeState::Enabled,
        };

        if request.dry_run {
            return Ok(LifecycleTransitionResponse {
                connector_id: connector_id.to_string(),
                action: request.action,
                dry_run: true,
                previous_desired_state: previous_desired,
                current_desired_state: target_desired,
                observed_state: observed,
                lifecycle_status: current_lifecycle_status,
                journal_sequence: current_seq,
                transitioned_at: now,
            });
        }

        // For promote, delegate to the LifecycleManager trait implementation.
        let lifecycle_status = if request.action == LifecycleAction::Promote {
            match self.promote(connector_id).await {
                Ok(record) => {
                    let status = LifecycleStatus {
                        connector_id: connector_id.clone(),
                        state: record.state,
                        version: record.version.clone(),
                        health: record.health.clone(),
                        auto_promote_pending: false,
                        auto_rollback_pending: false,
                        canary_expires_in_secs: None,
                        crash_loop_detected: false,
                        rollback_target_version: record.previous_version,
                    };
                    Some(status)
                }
                Err(e) => return Err(e),
            }
        } else {
            current_lifecycle_status
        };

        // Apply desired state mutation.
        self.set_desired_state(
            connector_id,
            target_desired,
            request
                .initiated_by
                .clone()
                .or_else(|| Some("admin-api".to_string())),
        )
        .await?;

        let new_seq = {
            let state = self.state.read().await;
            state
                .connectors
                .get(connector_id)
                .map_or(0, |cs| cs.last_journal_sequence)
        };

        Ok(LifecycleTransitionResponse {
            connector_id: connector_id.to_string(),
            action: request.action,
            dry_run: false,
            previous_desired_state: previous_desired,
            current_desired_state: target_desired,
            observed_state: observed,
            lifecycle_status,
            journal_sequence: new_seq,
            transitioned_at: now,
        })
    }

    /// Query the admin state journal with optional filtering.
    pub async fn query_journal(&self, request: &JournalQueryRequest) -> JournalQueryResponse {
        let state = self.state.read().await;
        let all_entries = &state.journal;
        let total_entries = all_entries.len();
        let latest_sequence = all_entries.last().map_or(0, |e| e.sequence);

        let filtered: Vec<AdminStateJournalEntry> = all_entries
            .iter()
            .filter(|e| e.sequence > request.after_sequence)
            .filter(|e| {
                request
                    .connector_id
                    .as_ref()
                    .is_none_or(|filter_id| e.connector_id.as_str() == filter_id.as_str())
            })
            .take(request.limit)
            .cloned()
            .collect();

        JournalQueryResponse {
            entries: filtered,
            total_entries,
            latest_sequence,
        }
    }

    /// Reconcile persisted admin state against the currently registered
    /// connector inventory.
    ///
    /// Existing desired state remains authoritative. Startup reconciliation only
    /// initializes intent for newly discovered connectors and refreshes observed
    /// runtime state so crashes, missing artifacts, and stuck rollouts surface as
    /// explicit drift instead of stale snapshots.
    ///
    /// # Errors
    ///
    /// Returns an error if the reconciled snapshot cannot be persisted.
    pub async fn reconcile_registered_connectors(
        &self,
        registered: &[ConnectorSummary],
    ) -> Result<StartupReconciliationReport, LifecycleError> {
        self.reconcile_registered_connectors_at(registered, Utc::now())
            .await
    }

    async fn reconcile_registered_connectors_at(
        &self,
        registered: &[ConnectorSummary],
        now: DateTime<Utc>,
    ) -> Result<StartupReconciliationReport, LifecycleError> {
        self.apply_mutation(|snapshot| {
            let registered_ids: HashSet<ConnectorId> = registered
                .iter()
                .map(|summary| summary.id.clone())
                .collect();
            let missing_connector_ids: Vec<ConnectorId> = snapshot
                .connectors
                .keys()
                .filter(|connector_id| !registered_ids.contains(*connector_id))
                .cloned()
                .collect();

            let mut created_connectors = 0;
            let mut observed_updates = 0;
            let mut entries = Vec::with_capacity(registered.len() + missing_connector_ids.len());

            for summary in registered {
                let (entry, observed_state_changed) =
                    reconcile_registered_connector(snapshot, summary, now);
                if entry.created_admin_state {
                    created_connectors += 1;
                }
                if observed_state_changed {
                    observed_updates += 1;
                }
                entries.push(entry);
            }

            for connector_id in missing_connector_ids {
                let (entry, observed_state_changed) =
                    reconcile_missing_connector(snapshot, &connector_id, now);
                if observed_state_changed {
                    observed_updates += 1;
                }
                entries.push(entry);
            }

            entries
                .sort_by(|left, right| left.connector_id.as_str().cmp(right.connector_id.as_str()));
            let drifted_connectors = entries.iter().filter(|entry| entry.drift.is_some()).count();

            Ok(StartupReconciliationReport {
                reconciled_at: now,
                tracked_connectors: snapshot.connectors.len(),
                created_connectors,
                observed_updates,
                drifted_connectors,
                entries,
            })
        })
        .await
    }
}

#[async_trait::async_trait]
impl LifecycleManager for HostAdminStateStore {
    async fn get(
        &self,
        connector_id: &ConnectorId,
    ) -> Result<Option<LifecycleRecord>, LifecycleError> {
        Ok(self
            .state
            .read()
            .await
            .connectors
            .get(connector_id)
            .and_then(|state| state.lifecycle.clone()))
    }

    async fn save(&self, record: &LifecycleRecord) -> Result<(), LifecycleError> {
        let initiated_by = record
            .transitions
            .last()
            .and_then(|transition| transition.initiated_by.clone());
        self.apply_mutation(|snapshot| {
            let sequence = snapshot.append_journal(
                &record.connector_id,
                AdminStateMutation::LifecycleRecordSaved {
                    version: record.version.clone(),
                    state: record.state,
                },
                initiated_by,
            );
            let state = snapshot.connector_state_mut(&record.connector_id);
            state.apply_lifecycle_projection(record);
            state.lifecycle = Some(record.clone());
            state.last_journal_sequence = sequence;
            Ok(())
        })
        .await
    }

    async fn promote(&self, connector_id: &ConnectorId) -> Result<LifecycleRecord, LifecycleError> {
        self.apply_mutation(|snapshot| {
            let updated_record = {
                let state = snapshot.connector_state_mut(connector_id);
                let record = state
                    .lifecycle
                    .as_mut()
                    .ok_or_else(|| LifecycleError::NotFound {
                        connector_id: connector_id.clone(),
                    })?;
                let health_score = record.health.success_rate.min(100);
                record.transition(
                    LifecycleState::Production,
                    TransitionReason::AutoPromotion { health_score },
                )?;
                let updated_record = record.clone();
                state.apply_lifecycle_projection(&updated_record);
                updated_record
            };
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::LifecycleRecordSaved {
                    version: updated_record.version.clone(),
                    state: updated_record.state,
                },
                None,
            );
            snapshot
                .connector_state_mut(connector_id)
                .last_journal_sequence = sequence;
            Ok(updated_record)
        })
        .await
    }

    async fn rollback(
        &self,
        connector_id: &ConnectorId,
        reason: Option<String>,
    ) -> Result<LifecycleRecord, LifecycleError> {
        self.apply_mutation(|snapshot| {
            let updated_record = {
                let state = snapshot.connector_state_mut(connector_id);
                let record = state
                    .lifecycle
                    .as_mut()
                    .ok_or_else(|| LifecycleError::NotFound {
                        connector_id: connector_id.clone(),
                    })?;
                if record.previous_version.is_none() {
                    return Err(LifecycleError::NoRollbackTarget);
                }
                let health_score = record.health.success_rate.min(100);
                let failure_reason = reason.unwrap_or_else(|| "rollback requested".to_string());
                record.transition(
                    LifecycleState::RolledBack,
                    TransitionReason::AutoRollback {
                        health_score,
                        failure_reason,
                    },
                )?;
                let updated_record = record.clone();
                state.apply_lifecycle_projection(&updated_record);
                updated_record
            };
            let sequence = snapshot.append_journal(
                connector_id,
                AdminStateMutation::LifecycleRecordSaved {
                    version: updated_record.version.clone(),
                    state: updated_record.state,
                },
                None,
            );
            snapshot
                .connector_state_mut(connector_id)
                .last_journal_sequence = sequence;
            Ok(updated_record)
        })
        .await
    }

    async fn status(&self, connector_id: &ConnectorId) -> Result<LifecycleStatus, LifecycleError> {
        let state = self.state.read().await;
        let record = state
            .connectors
            .get(connector_id)
            .and_then(|entry| entry.lifecycle.as_ref())
            .ok_or_else(|| LifecycleError::NotFound {
                connector_id: connector_id.clone(),
            })?;
        Ok(LifecycleStatus::from_record(record, Utc::now(), false))
    }
}

fn resolve_admin_state_path() -> HostResult<Option<PathBuf>> {
    match std::env::var("FCP_HOST_LIFECYCLE_STATE_FILE") {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(PathBuf::from(trimmed)))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(Some(default_admin_state_path())),
        Err(std::env::VarError::NotUnicode(_)) => Err(HostError::InvalidFilter(
            "FCP_HOST_LIFECYCLE_STATE_FILE must be valid unicode".to_string(),
        )),
    }
}

fn default_admin_state_path() -> PathBuf {
    PathBuf::from(".fcp-host").join("lifecycle-state.json")
}

fn load_admin_state_snapshot(path: &Path) -> HostResult<HostAdminStateSnapshot> {
    if !path.exists() {
        return Ok(HostAdminStateSnapshot::default());
    }

    let bytes = std::fs::read(path).map_err(|err| {
        HostError::Internal(format!(
            "failed to read admin state file '{}': {err}",
            path.display()
        ))
    })?;

    let raw: Value = serde_json::from_slice(&bytes).map_err(|err| {
        HostError::Internal(format!(
            "failed to parse admin state file '{}': {err}",
            path.display()
        ))
    })?;

    let raw_object = raw.as_object().ok_or_else(|| {
        HostError::Internal(format!(
            "admin state file '{}' must contain a JSON object",
            path.display()
        ))
    })?;

    let is_legacy_snapshot =
        raw_object.contains_key("records") || raw_object.contains_key("pinned_versions");

    if !is_legacy_snapshot {
        let snapshot: HostAdminStateSnapshot = serde_json::from_value(raw).map_err(|err| {
            HostError::Internal(format!(
                "failed to parse admin state file '{}': {err}",
                path.display()
            ))
        })?;
        if snapshot.schema_version != HOST_ADMIN_STATE_SNAPSHOT_VERSION {
            return Err(HostError::Internal(format!(
                "unsupported admin state schema version {} in '{}'",
                snapshot.schema_version,
                path.display()
            )));
        }
        return Ok(snapshot);
    }

    let legacy: LegacyHostLifecycleSnapshot = serde_json::from_value(raw).map_err(|err| {
        HostError::Internal(format!(
            "failed to parse admin state file '{}': {err}",
            path.display()
        ))
    })?;
    if legacy.schema_version != HOST_ADMIN_STATE_SNAPSHOT_VERSION {
        return Err(HostError::Internal(format!(
            "unsupported legacy admin state schema version {} in '{}'",
            legacy.schema_version,
            path.display()
        )));
    }
    Ok(HostAdminStateSnapshot::from_legacy(legacy))
}

fn persist_admin_state_snapshot(
    path: Option<&Path>,
    snapshot: &HostAdminStateSnapshot,
) -> Result<(), LifecycleError> {
    let Some(path) = path else {
        return Ok(());
    };

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| LifecycleError::Persistence {
            reason: format!(
                "could not create admin state directory '{}': {err}",
                parent.display()
            ),
        })?;
    }

    let payload =
        serde_json::to_vec_pretty(snapshot).map_err(|err| LifecycleError::Persistence {
            reason: format!(
                "could not serialize admin state for '{}': {err}",
                path.display()
            ),
        })?;
    let temp_path = temporary_admin_state_path(path);
    let write_result = (|| -> Result<(), LifecycleError> {
        let mut file =
            std::fs::File::create(&temp_path).map_err(|err| LifecycleError::Persistence {
                reason: format!(
                    "could not create temporary admin state file '{}': {err}",
                    temp_path.display()
                ),
            })?;
        file.write_all(&payload)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|err| LifecycleError::Persistence {
                reason: format!(
                    "could not write admin state file '{}': {err}",
                    temp_path.display()
                ),
            })?;
        replace_admin_state_file(&temp_path, path).map_err(|err| LifecycleError::Persistence {
            reason: format!(
                "could not replace admin state file '{}': {err}",
                path.display()
            ),
        })?;
        Ok(())
    })();

    if write_result.is_err() && temp_path.exists() {
        let _ = std::fs::remove_file(&temp_path);
    }

    write_result
}

fn temporary_admin_state_path(path: &Path) -> PathBuf {
    let mut temp = path.as_os_str().to_os_string();
    temp.push(".tmp");
    PathBuf::from(temp)
}

#[cfg(not(windows))]
fn replace_admin_state_file(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    std::fs::rename(temp_path, path)
}

#[cfg(windows)]
fn replace_admin_state_file(temp_path: &Path, path: &Path) -> std::io::Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    std::fs::rename(temp_path, path)
}

fn config_payload_digest(payload: &Value) -> Result<String, LifecycleError> {
    let bytes = serde_json::to_vec(payload).map_err(|err| LifecycleError::Persistence {
        reason: format!("could not serialize config revision payload: {err}"),
    })?;
    Ok(hash(&bytes).to_hex().to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SanitizedConfigPayload {
    payload: Value,
    redacted_fields: Vec<String>,
    credential_references: Vec<CredentialReferenceRecord>,
    contains_inline_secrets: bool,
}

fn sanitize_config_payload(payload: Value) -> SanitizedConfigPayload {
    let mut redacted_fields = Vec::new();
    let mut credential_references = Vec::new();
    let mut contains_inline_secrets = false;
    let payload = sanitize_config_value(
        payload,
        "",
        &mut redacted_fields,
        &mut credential_references,
        &mut contains_inline_secrets,
    );
    SanitizedConfigPayload {
        payload,
        redacted_fields,
        credential_references,
        contains_inline_secrets,
    }
}

fn sanitize_config_value(
    value: Value,
    path: &str,
    redacted_fields: &mut Vec<String>,
    credential_references: &mut Vec<CredentialReferenceRecord>,
    contains_inline_secrets: &mut bool,
) -> Value {
    match value {
        Value::Object(map) => {
            let mut sanitized = serde_json::Map::new();
            for (key, value) in map {
                let child_path = extend_json_pointer(path, &key);
                if is_credential_reference_key(&key) {
                    collect_credential_references(&child_path, &value, credential_references);
                    sanitized.insert(key, value);
                    continue;
                }

                if should_redact_config_key(&key) {
                    *contains_inline_secrets = true;
                    redacted_fields.push(child_path);
                    sanitized.insert(key, Value::String(REDACTED_CONFIG_VALUE.to_string()));
                    continue;
                }

                sanitized.insert(
                    key,
                    sanitize_config_value(
                        value,
                        &child_path,
                        redacted_fields,
                        credential_references,
                        contains_inline_secrets,
                    ),
                );
            }
            Value::Object(sanitized)
        }
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    sanitize_config_value(
                        value,
                        &extend_json_pointer(path, &index.to_string()),
                        redacted_fields,
                        credential_references,
                        contains_inline_secrets,
                    )
                })
                .collect(),
        ),
        other => other,
    }
}

fn collect_credential_references(
    path: &str,
    value: &Value,
    credential_references: &mut Vec<CredentialReferenceRecord>,
) {
    match value {
        Value::String(raw) => {
            if let Ok(credential_id) = CredentialId::parse(raw) {
                credential_references.push(CredentialReferenceRecord {
                    path: path.to_string(),
                    credential_id,
                    status: SecretReferenceStatus::Unknown,
                    last_checked_at: None,
                    last_error: None,
                });
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_credential_references(
                    &extend_json_pointer(path, &index.to_string()),
                    value,
                    credential_references,
                );
            }
        }
        _ => {}
    }
}

fn is_credential_reference_key(key: &str) -> bool {
    key.to_ascii_lowercase().contains("credential_id")
}

fn should_redact_config_key(key: &str) -> bool {
    let normalized = key.to_ascii_lowercase();
    if is_credential_reference_key(&normalized) {
        return false;
    }

    [
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "client_secret",
        "private_key",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn extend_json_pointer(prefix: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    if prefix.is_empty() {
        format!("/{escaped}")
    } else {
        format!("{prefix}/{escaped}")
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};
    use fcp_core::{CanaryPolicy, ConnectorHealth};

    fn connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.test.admin-state:utility:1.0.0")
    }

    fn secondary_connector_id() -> ConnectorId {
        ConnectorId::from_static("fcp.test.admin-state-secondary:utility:1.0.0")
    }

    fn connector_summary(
        connector_id: ConnectorId,
        enabled: bool,
        health: ConnectorHealth,
    ) -> ConnectorSummary {
        ConnectorSummary {
            id: connector_id,
            name: "Test Connector".to_string(),
            description: Some("Admin-state reconciliation test connector".to_string()),
            version: Version::new(1, 0, 0),
            categories: vec!["test".to_string()],
            tool_count: 1,
            max_safety_tier: fcp_core::SafetyTier::Safe,
            enabled,
            health,
            last_health_check: Some(Utc::now()),
        }
    }

    fn config_payload(name: &str) -> Value {
        serde_json::json!({
            "profile": name,
            "credential_id": format!("cred-{name}"),
        })
    }

    fn secretful_config_payload(credential_id: CredentialId) -> Value {
        serde_json::json!({
            "profile": "work",
            "credential_id": credential_id.to_string(),
            "access_token": "super-secret-access-token",
            "nested": {
                "client_secret": "ultra-secret-client-secret",
                "safe": "value"
            }
        })
    }

    #[fcp_async_core::runtime::test]
    async fn store_persists_connector_state_config_and_journal_across_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("state").join("admin-state.json");
        let connector_id = connector_id();
        let previous_version = Version::new(1, 4, 0);
        let current_version = Version::new(1, 5, 0);

        let store = HostAdminStateStore::with_state_path(state_path.clone()).expect("store");
        let mut record = LifecycleRecord::new(connector_id.clone(), current_version.clone())
            .with_previous_version(previous_version);
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .expect("pending -> installing");
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.4.0".to_string(),
                    to_version: "1.5.0".to_string(),
                },
            )
            .expect("installing -> canary");

        store.save(&record).await.expect("save");
        store
            .set_desired_state(
                &connector_id,
                DesiredRuntimeState::Enabled,
                Some("test-suite".to_string()),
            )
            .await
            .expect("desired");
        store
            .set_observed_state(
                &connector_id,
                ObservedRuntimeState::Running,
                Some("supervisor".to_string()),
            )
            .await
            .expect("observed");
        store
            .pin(&connector_id, current_version.clone())
            .await
            .expect("pin");
        let revision = store
            .append_config_revision(
                &connector_id,
                config_payload("work"),
                Some("test-suite".to_string()),
                Some("bootstrap".to_string()),
            )
            .await
            .expect("revision");

        let reloaded = HostAdminStateStore::with_state_path(state_path).expect("reloaded");
        let restored = reloaded
            .connector_state(&connector_id)
            .await
            .expect("connector state");

        assert_eq!(
            serde_json::to_value(restored.lifecycle.as_ref().expect("lifecycle"))
                .expect("serialize"),
            serde_json::to_value(&record).expect("serialize")
        );
        assert_eq!(restored.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(restored.observed_state, ObservedRuntimeState::Running);
        assert_eq!(restored.pinned_version, Some(current_version));
        assert_eq!(
            restored.active_config_revision_id,
            Some(revision.revision_id)
        );
        assert_eq!(
            restored
                .active_config_revision()
                .expect("active revision")
                .payload,
            config_payload("work")
        );
        assert_eq!(reloaded.journal(Some(&connector_id)).await.len(), 5);
    }

    #[fcp_async_core::runtime::test]
    async fn config_revisions_chain_monotonically_and_emit_monotonic_journal() {
        let store = HostAdminStateStore::new();
        let connector_id = connector_id();

        let first = store
            .append_config_revision(
                &connector_id,
                config_payload("one"),
                Some("operator-a".to_string()),
                Some("initial".to_string()),
            )
            .await
            .expect("first");
        let second = store
            .append_config_revision(
                &connector_id,
                config_payload("two"),
                Some("operator-b".to_string()),
                Some("update".to_string()),
            )
            .await
            .expect("second");

        assert!(second.revision_id > first.revision_id);
        assert_eq!(second.previous_revision_id, Some(first.revision_id));

        let journal = store.journal(Some(&connector_id)).await;
        assert_eq!(journal.len(), 2);
        assert_eq!(journal[0].sequence, 1);
        assert_eq!(journal[1].sequence, 2);
        assert!(matches!(
            journal[1].mutation,
            AdminStateMutation::ConfigRevisionAppended { revision_id, .. }
                if revision_id == second.revision_id
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn config_revision_redacts_inline_secrets_and_preserves_credential_refs() {
        let store = HostAdminStateStore::new();
        let connector_id = connector_id();
        let credential_id =
            CredentialId::parse("abababab-abab-abab-abab-abababababab").expect("credential id");

        let revision = store
            .append_config_revision(
                &connector_id,
                secretful_config_payload(credential_id),
                Some("operator".to_string()),
                Some("seed".to_string()),
            )
            .await
            .expect("append revision");

        assert_eq!(
            revision.payload["credential_id"],
            Value::String(credential_id.to_string())
        );
        assert_eq!(
            revision.payload["access_token"],
            Value::String(REDACTED_CONFIG_VALUE.to_string())
        );
        assert_eq!(
            revision.payload["nested"]["client_secret"],
            Value::String(REDACTED_CONFIG_VALUE.to_string())
        );
        assert_eq!(
            revision.payload["nested"]["safe"],
            Value::String("value".to_string())
        );
        assert!(revision.contains_inline_secrets);
        assert_eq!(
            revision.redacted_fields,
            vec![
                "/access_token".to_string(),
                "/nested/client_secret".to_string()
            ]
        );
        assert_eq!(revision.credential_references.len(), 1);
        assert_eq!(revision.credential_references[0].path, "/credential_id");
        assert_eq!(
            revision.credential_references[0].credential_id,
            credential_id
        );
        assert_eq!(
            revision.credential_references[0].status,
            SecretReferenceStatus::Unknown
        );
        assert!(!format!("{revision:?}").contains("super-secret-access-token"));
        assert!(!format!("{revision:?}").contains("ultra-secret-client-secret"));
    }

    #[fcp_async_core::runtime::test]
    async fn export_snapshot_json_is_safe_by_default_even_when_secret_digests_change() {
        let store = HostAdminStateStore::new();
        let connector_id = connector_id();
        let credential_id =
            CredentialId::parse("cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd").expect("credential id");

        let first = store
            .append_config_revision(
                &connector_id,
                secretful_config_payload(credential_id),
                Some("operator".to_string()),
                Some("initial".to_string()),
            )
            .await
            .expect("first revision");
        let second = store
            .append_config_revision(
                &connector_id,
                serde_json::json!({
                    "profile": "work",
                    "credential_id": credential_id.to_string(),
                    "access_token": "rotated-access-token"
                }),
                Some("operator".to_string()),
                Some("rotated".to_string()),
            )
            .await
            .expect("second revision");

        assert_ne!(
            first.payload_digest, second.payload_digest,
            "raw payload digest should still detect secret changes"
        );
        assert_eq!(
            first.payload["access_token"],
            second.payload["access_token"]
        );

        let export = store.export_snapshot_json().await.expect("export snapshot");
        let export_text = export.to_string();
        assert!(!export_text.contains("super-secret-access-token"));
        assert!(!export_text.contains("ultra-secret-client-secret"));
        assert!(!export_text.contains("rotated-access-token"));
        assert!(export_text.contains(REDACTED_CONFIG_VALUE));
        assert!(export_text.contains(&credential_id.to_string()));
    }

    #[fcp_async_core::runtime::test]
    async fn store_loads_legacy_lifecycle_snapshot_and_projects_runtime_state() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("legacy").join("lifecycle.json");
        let connector_id = connector_id();
        let version = Version::new(2, 0, 0);
        let mut record = LifecycleRecord::new(connector_id.clone(), version.clone());
        record
            .transition(
                LifecycleState::Installing,
                TransitionReason::InstallComplete,
            )
            .expect("pending -> installing");
        record
            .transition(
                LifecycleState::Production,
                TransitionReason::ManualPromotion,
            )
            .expect_err("installing -> production is invalid");
        record
            .transition(
                LifecycleState::Canary,
                TransitionReason::NewVersion {
                    from_version: "1.9.0".to_string(),
                    to_version: version.to_string(),
                },
            )
            .expect("installing -> canary");

        let mut records = serde_json::Map::new();
        records.insert(
            connector_id.to_string(),
            serde_json::to_value(record).expect("record value"),
        );
        let mut pinned_versions = serde_json::Map::new();
        pinned_versions.insert(
            connector_id.to_string(),
            serde_json::to_value(version.clone()).expect("version value"),
        );
        let legacy = Value::Object(serde_json::Map::from_iter([
            ("schema_version".to_string(), Value::from(1)),
            ("records".to_string(), Value::Object(records)),
            (
                "pinned_versions".to_string(),
                Value::Object(pinned_versions),
            ),
        ]));
        std::fs::create_dir_all(state_path.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &state_path,
            serde_json::to_vec_pretty(&legacy).expect("legacy json"),
        )
        .expect("write");

        let store = HostAdminStateStore::with_state_path(state_path).expect("load");
        let restored = store
            .connector_state(&connector_id)
            .await
            .expect("connector state");
        assert!(restored.lifecycle.is_some());
        assert_eq!(restored.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(restored.observed_state, ObservedRuntimeState::Running);
        assert_eq!(restored.pinned_version, Some(version));
        assert!(store.journal(Some(&connector_id)).await.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn startup_reconciliation_creates_rows_and_marks_missing_connectors() {
        let store = HostAdminStateStore::new();
        let live_connector_id = connector_id();
        let missing_connector_id = secondary_connector_id();

        store
            .set_desired_state(
                &missing_connector_id,
                DesiredRuntimeState::Enabled,
                Some("test-suite".to_string()),
            )
            .await
            .expect("desired state should persist");
        store
            .set_observed_state(
                &missing_connector_id,
                ObservedRuntimeState::Running,
                Some("test-suite".to_string()),
            )
            .await
            .expect("observed state should persist");

        let registered = vec![connector_summary(
            live_connector_id.clone(),
            true,
            ConnectorHealth::healthy(),
        )];
        let now = Utc.with_ymd_and_hms(2026, 3, 10, 23, 45, 0).unwrap();
        let report = store
            .reconcile_registered_connectors_at(&registered, now)
            .await
            .expect("startup reconciliation should persist");

        assert_eq!(report.tracked_connectors, 2);
        assert_eq!(report.created_connectors, 1);
        assert_eq!(report.observed_updates, 2);
        assert_eq!(report.drifted_connectors, 1);

        let live_entry = report
            .entries
            .iter()
            .find(|entry| entry.connector_id == live_connector_id)
            .expect("live connector entry");
        assert!(live_entry.created_admin_state);
        assert_eq!(live_entry.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(
            live_entry.observed_state_before,
            ObservedRuntimeState::Unknown
        );
        assert_eq!(
            live_entry.observed_state_after,
            ObservedRuntimeState::Running
        );
        assert!(live_entry.updated);
        assert!(live_entry.drift.is_none());

        let missing_entry = report
            .entries
            .iter()
            .find(|entry| entry.connector_id == missing_connector_id)
            .expect("missing connector entry");
        assert!(!missing_entry.created_admin_state);
        assert_eq!(missing_entry.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(
            missing_entry.observed_state_before,
            ObservedRuntimeState::Running
        );
        assert_eq!(
            missing_entry.observed_state_after,
            ObservedRuntimeState::Missing
        );
        assert!(missing_entry.updated);
        assert_eq!(
            missing_entry
                .drift
                .as_ref()
                .expect("missing connector should drift")
                .kind,
            ConnectorDriftKind::EnabledButMissing
        );

        let missing_status = store
            .connector_status_at(&missing_connector_id, now)
            .await
            .expect("status should exist after reconciliation");
        assert_eq!(missing_status.desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(missing_status.observed_state, ObservedRuntimeState::Missing);
        assert_eq!(
            missing_status
                .drift
                .as_ref()
                .expect("missing connector should drift")
                .recovery_action,
            RecoveryAction::ReinstallConnector
        );
    }

    #[test]
    fn connector_drift_status_identifies_stuck_install_and_canary() {
        let now = Utc.with_ymd_and_hms(2026, 3, 10, 23, 50, 0).unwrap();
        let install_record = LifecycleRecord {
            connector_id: connector_id(),
            version: Version::new(1, 0, 0),
            state: LifecycleState::Installing,
            deployed_at: now - Duration::minutes(15),
            state_changed_at: now - Duration::minutes(10),
            transitions: Vec::new(),
            health: fcp_core::HealthMetrics::default(),
            canary_policy: CanaryPolicy::default(),
            previous_version: None,
        };
        let install_state = ConnectorAdminState {
            lifecycle: Some(install_record),
            desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Starting,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
        };
        let install_drift =
            connector_drift_status(&install_state, now).expect("install should be stuck");
        assert_eq!(install_drift.kind, ConnectorDriftKind::InstallStuck);
        assert_eq!(install_drift.recovery_action, RecoveryAction::Investigate);

        let canary_record = LifecycleRecord {
            connector_id: secondary_connector_id(),
            version: Version::new(1, 1, 0),
            state: LifecycleState::Canary,
            deployed_at: now - Duration::minutes(30),
            state_changed_at: now - Duration::minutes(20),
            transitions: Vec::new(),
            health: fcp_core::HealthMetrics::default(),
            canary_policy: CanaryPolicy {
                max_canary_duration_secs: 60,
                ..CanaryPolicy::default()
            },
            previous_version: Some(Version::new(1, 0, 0)),
        };
        let canary_state = ConnectorAdminState {
            lifecycle: Some(canary_record),
            desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Running,
            pinned_version: None,
            config_revisions: Vec::new(),
            active_config_revision_id: None,
            last_journal_sequence: 0,
        };
        let canary_drift =
            connector_drift_status(&canary_state, now).expect("canary should be stuck");
        assert_eq!(canary_drift.kind, ConnectorDriftKind::CanaryStuck);
        assert_eq!(
            canary_drift.recovery_action,
            RecoveryAction::CompleteRollout
        );
    }

    // ── LifecycleAction serde ──

    #[test]
    fn lifecycle_action_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Enable).unwrap(),
            r#""enable""#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Disable).unwrap(),
            r#""disable""#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Restart).unwrap(),
            r#""restart""#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Reload).unwrap(),
            r#""reload""#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Uninstall).unwrap(),
            r#""uninstall""#
        );
        assert_eq!(
            serde_json::to_string(&LifecycleAction::Promote).unwrap(),
            r#""promote""#
        );
    }

    #[test]
    fn lifecycle_action_deserializes_all_variants() {
        let actions = [
            "enable", "disable", "restart", "reload", "uninstall", "promote",
        ];
        for action in actions {
            let json = format!("\"{action}\"");
            let parsed: LifecycleAction = serde_json::from_str(&json).unwrap();
            let reserialized = serde_json::to_string(&parsed).unwrap();
            assert_eq!(reserialized, json);
        }
    }

    // ── LifecycleTransitionRequest serde ──

    #[test]
    fn lifecycle_transition_request_minimal() {
        let json = r#"{"action":"enable"}"#;
        let req: LifecycleTransitionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.action, LifecycleAction::Enable);
        assert!(req.reason.is_none());
        assert!(req.initiated_by.is_none());
        assert!(!req.dry_run);
    }

    #[test]
    fn lifecycle_transition_request_full() {
        let json = r#"{
            "action": "disable",
            "reason": "maintenance window",
            "initiated_by": "operator",
            "dry_run": true
        }"#;
        let req: LifecycleTransitionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.action, LifecycleAction::Disable);
        assert_eq!(req.reason.as_deref(), Some("maintenance window"));
        assert_eq!(req.initiated_by.as_deref(), Some("operator"));
        assert!(req.dry_run);
    }

    #[test]
    fn lifecycle_transition_response_roundtrip() {
        let response = LifecycleTransitionResponse {
            connector_id: "fcp.test:echo:1.0.0".to_string(),
            action: LifecycleAction::Enable,
            dry_run: false,
            previous_desired_state: DesiredRuntimeState::Disabled,
            current_desired_state: DesiredRuntimeState::Enabled,
            observed_state: ObservedRuntimeState::Stopped,
            lifecycle_status: None,
            journal_sequence: 42,
            transitioned_at: Utc::now(),
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: LifecycleTransitionResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.connector_id, "fcp.test:echo:1.0.0");
        assert_eq!(parsed.action, LifecycleAction::Enable);
        assert_eq!(
            parsed.previous_desired_state,
            DesiredRuntimeState::Disabled
        );
        assert_eq!(parsed.current_desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(parsed.journal_sequence, 42);
    }

    // ── JournalQueryRequest serde ──

    #[test]
    fn journal_query_request_defaults() {
        let json = r#"{}"#;
        let req: JournalQueryRequest = serde_json::from_str(json).unwrap();
        assert!(req.connector_id.is_none());
        assert_eq!(req.after_sequence, 0);
        assert_eq!(req.limit, 100);
    }

    #[test]
    fn journal_query_request_with_filter() {
        let json = r#"{"connector_id":"fcp.test:echo:1.0.0","after_sequence":10,"limit":50}"#;
        let req: JournalQueryRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            req.connector_id.as_deref(),
            Some("fcp.test:echo:1.0.0")
        );
        assert_eq!(req.after_sequence, 10);
        assert_eq!(req.limit, 50);
    }

    #[test]
    fn journal_query_response_roundtrip() {
        let response = JournalQueryResponse {
            entries: Vec::new(),
            total_entries: 42,
            latest_sequence: 100,
        };
        let json = serde_json::to_string(&response).unwrap();
        let parsed: JournalQueryResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_entries, 42);
        assert_eq!(parsed.latest_sequence, 100);
        assert!(parsed.entries.is_empty());
    }

    // ── execute_lifecycle_transition integration ──

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_enable_dry_run() {
        let store = HostAdminStateStore::in_memory();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [ConnectorSummary {
            id: connector_id.clone(),
            name: Some("Echo".to_string()),
            description: None,
            version: semver::Version::new(1, 0, 0),
            health: ConnectorHealth::Unknown,
            categories: Vec::new(),
            tool_count: 0,
        }];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: None,
            dry_run: true,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await
            .unwrap();
        assert!(response.dry_run);
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
        assert_eq!(response.action, LifecycleAction::Enable);
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_enable_persists() {
        let store = HostAdminStateStore::in_memory();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [ConnectorSummary {
            id: connector_id.clone(),
            name: Some("Echo".to_string()),
            description: None,
            version: semver::Version::new(1, 0, 0),
            health: ConnectorHealth::Unknown,
            categories: Vec::new(),
            tool_count: 0,
        }];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: Some("go live".to_string()),
            initiated_by: Some("operator".to_string()),
            dry_run: false,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await
            .unwrap();
        assert!(!response.dry_run);
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
        assert!(response.journal_sequence > 0);

        let status = store.connector_status(&connector_id).await.unwrap();
        assert_eq!(status.desired_state, DesiredRuntimeState::Enabled);
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_disable() {
        let store = HostAdminStateStore::in_memory();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [ConnectorSummary {
            id: connector_id.clone(),
            name: Some("Echo".to_string()),
            description: None,
            version: semver::Version::new(1, 0, 0),
            health: ConnectorHealth::Unknown,
            categories: Vec::new(),
            tool_count: 0,
        }];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        // Enable first.
        let enable = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        store
            .execute_lifecycle_transition(&connector_id, &enable)
            .await
            .unwrap();

        // Then disable.
        let disable = LifecycleTransitionRequest {
            action: LifecycleAction::Disable,
            reason: Some("maintenance".to_string()),
            initiated_by: None,
            dry_run: false,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &disable)
            .await
            .unwrap();
        assert_eq!(
            response.previous_desired_state,
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            response.current_desired_state,
            DesiredRuntimeState::Disabled
        );
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_uninstall() {
        let store = HostAdminStateStore::in_memory();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [ConnectorSummary {
            id: connector_id.clone(),
            name: Some("Echo".to_string()),
            description: None,
            version: semver::Version::new(1, 0, 0),
            health: ConnectorHealth::Unknown,
            categories: Vec::new(),
            tool_count: 0,
        }];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Uninstall,
            reason: Some("no longer needed".to_string()),
            initiated_by: None,
            dry_run: false,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await
            .unwrap();
        assert_eq!(
            response.current_desired_state,
            DesiredRuntimeState::Uninstalled
        );
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_restart_sets_enabled() {
        let store = HostAdminStateStore::in_memory();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [ConnectorSummary {
            id: connector_id.clone(),
            name: Some("Echo".to_string()),
            description: None,
            version: semver::Version::new(1, 0, 0),
            health: ConnectorHealth::Unknown,
            categories: Vec::new(),
            tool_count: 0,
        }];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Restart,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await
            .unwrap();
        assert_eq!(response.action, LifecycleAction::Restart);
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_reload_sets_enabled() {
        let store = HostAdminStateStore::in_memory();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [ConnectorSummary {
            id: connector_id.clone(),
            name: Some("Echo".to_string()),
            description: None,
            version: semver::Version::new(1, 0, 0),
            health: ConnectorHealth::Unknown,
            categories: Vec::new(),
            tool_count: 0,
        }];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Reload,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        let response = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await
            .unwrap();
        assert_eq!(response.action, LifecycleAction::Reload);
        assert_eq!(response.current_desired_state, DesiredRuntimeState::Enabled);
    }

    #[fcp_async_core::runtime::test]
    async fn lifecycle_transition_not_found() {
        let store = HostAdminStateStore::in_memory();
        let connector_id = ConnectorId::from_static("fcp.test:ghost:1.0.0");
        let request = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        let result = store
            .execute_lifecycle_transition(&connector_id, &request)
            .await;
        assert!(result.is_err());
    }

    // ── query_journal integration ──

    #[fcp_async_core::runtime::test]
    async fn query_journal_empty() {
        let store = HostAdminStateStore::in_memory();
        let request = JournalQueryRequest {
            connector_id: None,
            after_sequence: 0,
            limit: 100,
        };
        let response = store.query_journal(&request).await;
        assert!(response.entries.is_empty());
        assert_eq!(response.total_entries, 0);
        assert_eq!(response.latest_sequence, 0);
    }

    #[fcp_async_core::runtime::test]
    async fn query_journal_after_transitions() {
        let store = HostAdminStateStore::in_memory();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [ConnectorSummary {
            id: connector_id.clone(),
            name: Some("Echo".to_string()),
            description: None,
            version: semver::Version::new(1, 0, 0),
            health: ConnectorHealth::Unknown,
            categories: Vec::new(),
            tool_count: 0,
        }];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        // Perform transitions.
        let enable = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: Some("test".to_string()),
            dry_run: false,
        };
        store
            .execute_lifecycle_transition(&connector_id, &enable)
            .await
            .unwrap();

        let disable = LifecycleTransitionRequest {
            action: LifecycleAction::Disable,
            reason: None,
            initiated_by: Some("test".to_string()),
            dry_run: false,
        };
        store
            .execute_lifecycle_transition(&connector_id, &disable)
            .await
            .unwrap();

        // Query all entries.
        let request = JournalQueryRequest {
            connector_id: None,
            after_sequence: 0,
            limit: 100,
        };
        let response = store.query_journal(&request).await;
        assert!(response.total_entries >= 2);
        assert!(response.latest_sequence > 0);
    }

    #[fcp_async_core::runtime::test]
    async fn query_journal_with_connector_filter() {
        let store = HostAdminStateStore::in_memory();
        let c1 = ConnectorId::from_static("fcp.test:alpha:1.0.0");
        let c2 = ConnectorId::from_static("fcp.test:beta:1.0.0");
        let summaries = [
            ConnectorSummary {
                id: c1.clone(),
                name: Some("Alpha".to_string()),
                description: None,
                version: semver::Version::new(1, 0, 0),
                health: ConnectorHealth::Unknown,
                categories: Vec::new(),
                tool_count: 0,
            },
            ConnectorSummary {
                id: c2.clone(),
                name: Some("Beta".to_string()),
                description: None,
                version: semver::Version::new(1, 0, 0),
                health: ConnectorHealth::Unknown,
                categories: Vec::new(),
                tool_count: 0,
            },
        ];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        let enable_c1 = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        store
            .execute_lifecycle_transition(&c1, &enable_c1)
            .await
            .unwrap();

        let enable_c2 = LifecycleTransitionRequest {
            action: LifecycleAction::Enable,
            reason: None,
            initiated_by: None,
            dry_run: false,
        };
        store
            .execute_lifecycle_transition(&c2, &enable_c2)
            .await
            .unwrap();

        // Filter to c1 only.
        let request = JournalQueryRequest {
            connector_id: Some("fcp.test:alpha:1.0.0".to_string()),
            after_sequence: 0,
            limit: 100,
        };
        let response = store.query_journal(&request).await;
        for entry in &response.entries {
            assert_eq!(entry.connector_id.as_str(), "fcp.test:alpha:1.0.0");
        }
    }

    #[fcp_async_core::runtime::test]
    async fn query_journal_respects_after_sequence() {
        let store = HostAdminStateStore::in_memory();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [ConnectorSummary {
            id: connector_id.clone(),
            name: Some("Echo".to_string()),
            description: None,
            version: semver::Version::new(1, 0, 0),
            health: ConnectorHealth::Unknown,
            categories: Vec::new(),
            tool_count: 0,
        }];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        // Two transitions.
        for action in [LifecycleAction::Enable, LifecycleAction::Disable] {
            let req = LifecycleTransitionRequest {
                action,
                reason: None,
                initiated_by: None,
                dry_run: false,
            };
            store
                .execute_lifecycle_transition(&connector_id, &req)
                .await
                .unwrap();
        }

        // Get all entries to find a midpoint.
        let all = store
            .query_journal(&JournalQueryRequest {
                connector_id: None,
                after_sequence: 0,
                limit: 1000,
            })
            .await;
        let total = all.entries.len();
        assert!(total >= 2);

        // Query after the first entry.
        let first_seq = all.entries[0].sequence;
        let after_first = store
            .query_journal(&JournalQueryRequest {
                connector_id: None,
                after_sequence: first_seq,
                limit: 1000,
            })
            .await;
        assert!(after_first.entries.len() < total);
        for entry in &after_first.entries {
            assert!(entry.sequence > first_seq);
        }
    }

    #[fcp_async_core::runtime::test]
    async fn query_journal_respects_limit() {
        let store = HostAdminStateStore::in_memory();
        let connector_id = ConnectorId::from_static("fcp.test:echo:1.0.0");
        let summaries = [ConnectorSummary {
            id: connector_id.clone(),
            name: Some("Echo".to_string()),
            description: None,
            version: semver::Version::new(1, 0, 0),
            health: ConnectorHealth::Unknown,
            categories: Vec::new(),
            tool_count: 0,
        }];
        store
            .reconcile_registered_connectors(&summaries)
            .await
            .unwrap();

        // Several transitions to create journal entries.
        for action in [
            LifecycleAction::Enable,
            LifecycleAction::Disable,
            LifecycleAction::Enable,
        ] {
            let req = LifecycleTransitionRequest {
                action,
                reason: None,
                initiated_by: None,
                dry_run: false,
            };
            store
                .execute_lifecycle_transition(&connector_id, &req)
                .await
                .unwrap();
        }

        let request = JournalQueryRequest {
            connector_id: None,
            after_sequence: 0,
            limit: 1,
        };
        let response = store.query_journal(&request).await;
        assert_eq!(response.entries.len(), 1);
    }

    // ── Lifecycle action target mapping ──

    #[test]
    fn lifecycle_action_target_desired_state() {
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Enable),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Disable),
            DesiredRuntimeState::Disabled
        );
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Restart),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Reload),
            DesiredRuntimeState::Enabled
        );
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Uninstall),
            DesiredRuntimeState::Uninstalled
        );
        assert_eq!(
            lifecycle_action_target(LifecycleAction::Promote),
            DesiredRuntimeState::Enabled
        );
    }
}

/// Helper for test assertions on lifecycle action → desired state mapping.
#[cfg(test)]
fn lifecycle_action_target(action: LifecycleAction) -> DesiredRuntimeState {
    match action {
        LifecycleAction::Enable | LifecycleAction::Restart | LifecycleAction::Reload => {
            DesiredRuntimeState::Enabled
        }
        LifecycleAction::Disable => DesiredRuntimeState::Disabled,
        LifecycleAction::Uninstall => DesiredRuntimeState::Uninstalled,
        LifecycleAction::Promote => DesiredRuntimeState::Enabled,
    }
}
