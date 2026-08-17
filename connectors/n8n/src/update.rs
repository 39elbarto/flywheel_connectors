//! Review-first update state machine for n8n-related components.
//!
//! Detection and diffing are pure and read-only. Applying an update requires an
//! exact, unexpired approval bound to the review digest. Component-specific
//! installers implement [`UpdateBackend`]; this module deliberately exposes no
//! generic command execution surface.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

const REVIEW_SCHEMA: &str = "fwc.n8n.update-review.v1";
const APPROVAL_SCHEMA: &str = "fwc.n8n.update-approval.v1";
const MAX_ATOM_BYTES: usize = 256;
const MAX_TOOLS: usize = 512;
const MAX_DEPENDENCIES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateComponent {
    LocalN8nMcp,
    OfficialN8nSkills,
    FwcN8nBundle,
    FcpHost,
    FcpN8n,
    FcpMcpBridge,
    EecN8nApi,
    EecOfficialMcp,
    HetznerN8nApi,
    HetznerOfficialMcp,
    CodexMcpProtocol,
}

impl UpdateComponent {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalN8nMcp => "local_n8n_mcp",
            Self::OfficialN8nSkills => "official_n8n_skills",
            Self::FwcN8nBundle => "fwc_n8n_bundle",
            Self::FcpHost => "fcp_host",
            Self::FcpN8n => "fcp_n8n",
            Self::FcpMcpBridge => "fcp_mcp_bridge",
            Self::EecN8nApi => "eec_n8n_api",
            Self::EecOfficialMcp => "eec_official_mcp",
            Self::HetznerN8nApi => "hetzner_n8n_api",
            Self::HetznerOfficialMcp => "hetzner_official_mcp",
            Self::CodexMcpProtocol => "codex_mcp_protocol",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolImpact {
    LocalKnowledge,
    Read,
    Write,
    Credential,
    Execution,
    Destructive,
    Unknown,
}

impl ToolImpact {
    const fn requires_owner_review(self) -> bool {
        matches!(
            self,
            Self::Write | Self::Credential | Self::Execution | Self::Destructive | Self::Unknown
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ToolSnapshot {
    pub name: String,
    pub schema_digest: String,
    pub description_digest: String,
    pub impact: ToolImpact,
    #[serde(default)]
    pub permissions: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProvenanceSnapshot {
    pub source_kind: String,
    pub artifact_digest: String,
    pub metadata_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_requirement: Option<String>,
    #[serde(default)]
    pub protocol_versions: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ComponentSnapshot {
    pub component: UpdateComponent,
    pub version: String,
    pub provenance: ProvenanceSnapshot,
    #[serde(default)]
    pub dependencies: BTreeMap<String, String>,
    #[serde(default)]
    pub tools: Vec<ToolSnapshot>,
}

impl ComponentSnapshot {
    fn normalize_and_validate(mut self) -> Result<Self, UpdateError> {
        validate_atom("version", &self.version)?;
        validate_atom("source_kind", &self.provenance.source_kind)?;
        validate_atom("artifact_digest", &self.provenance.artifact_digest)?;
        validate_atom("metadata_digest", &self.provenance.metadata_digest)?;
        if let Some(engine) = &self.provenance.engine_requirement {
            validate_atom("engine_requirement", engine)?;
        }
        for protocol in &self.provenance.protocol_versions {
            validate_atom("protocol_version", protocol)?;
        }
        if self.dependencies.len() > MAX_DEPENDENCIES {
            return Err(UpdateError::InvalidSnapshot("too_many_dependencies"));
        }
        for (name, version) in &self.dependencies {
            validate_atom("dependency_name", name)?;
            validate_atom("dependency_version", version)?;
        }
        if self.tools.len() > MAX_TOOLS {
            return Err(UpdateError::InvalidSnapshot("too_many_tools"));
        }
        for tool in &self.tools {
            validate_atom("tool_name", &tool.name)?;
            validate_atom("schema_digest", &tool.schema_digest)?;
            validate_atom("description_digest", &tool.description_digest)?;
            for permission in &tool.permissions {
                validate_atom("permission", permission)?;
            }
        }
        self.tools.sort_by(|left, right| left.name.cmp(&right.name));
        if self
            .tools
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(UpdateError::InvalidSnapshot("duplicate_tool"));
        }
        Ok(self)
    }

    fn digest(&self) -> Result<String, UpdateError> {
        canonical_digest(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ChangedTool {
    pub name: String,
    pub changes: BTreeSet<ToolChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolChange {
    Schema,
    Description,
    Impact,
    Permissions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DependencyChange {
    pub name: String,
    pub previous: Option<String>,
    pub candidate: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateDiff {
    pub added_tools: Vec<String>,
    pub removed_tools: Vec<String>,
    pub changed_tools: Vec<ChangedTool>,
    pub dependency_changes: Vec<DependencyChange>,
    pub flags: BTreeSet<UpdateFlag>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateFlag {
    ProvenanceChanged,
    EngineChanged,
    ProtocolChanged,
    NewSensitiveTool,
    RemovedTool,
    Breaking,
    DocsOrSkillsReviewRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UpdateReview {
    pub schema: String,
    pub component: UpdateComponent,
    pub current_version: String,
    pub candidate_version: String,
    pub current_snapshot_digest: String,
    pub candidate_snapshot_digest: String,
    pub candidate_artifact_digest: String,
    pub diff: UpdateDiff,
    pub review_digest: String,
    pub dedupe_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DetectionOutcome {
    NoChange {
        component: UpdateComponent,
        version: String,
        snapshot_digest: String,
    },
    ReviewRequired {
        review: Box<UpdateReview>,
        duplicate: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Approved,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ExactReviewDecision {
    pub schema: String,
    pub decision: ReviewDecision,
    pub component: UpdateComponent,
    pub current_version: String,
    pub candidate_version: String,
    pub candidate_artifact_digest: String,
    pub review_digest: String,
    pub approval_ref: String,
    pub expires_at_unix_ms: u64,
}

impl ExactReviewDecision {
    pub fn new(
        decision: ReviewDecision,
        review: &UpdateReview,
        approval_ref: impl Into<String>,
        expires_at_unix_ms: u64,
    ) -> Self {
        Self {
            schema: APPROVAL_SCHEMA.to_string(),
            decision,
            component: review.component,
            current_version: review.current_version.clone(),
            candidate_version: review.candidate_version.clone(),
            candidate_artifact_digest: review.candidate_artifact_digest.clone(),
            review_digest: review.review_digest.clone(),
            approval_ref: approval_ref.into(),
            expires_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorizedUpdate {
    component: UpdateComponent,
    current: ComponentSnapshot,
    candidate: ComponentSnapshot,
    review_digest: String,
    approval_ref: String,
    expires_at_unix_ms: u64,
}

impl AuthorizedUpdate {
    pub const fn component(&self) -> UpdateComponent {
        self.component
    }

    pub const fn current(&self) -> &ComponentSnapshot {
        &self.current
    }

    pub const fn candidate(&self) -> &ComponentSnapshot {
        &self.candidate
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SmokeReport {
    pub passed: bool,
    pub check_ids: Vec<String>,
    pub zero_idle_confirmed: bool,
    pub redaction_confirmed: bool,
}

impl SmokeReport {
    const fn valid_for_apply(&self) -> bool {
        self.passed && self.zero_idle_confirmed && self.redaction_confirmed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    ActiveReadFailed,
    ActivationFailed,
    SmokeFailed,
    RollbackFailed,
}

pub trait UpdateBackend {
    fn active_snapshot(
        &mut self,
        component: UpdateComponent,
    ) -> Result<ComponentSnapshot, BackendError>;

    fn activate_exact(&mut self, candidate: &ComponentSnapshot) -> Result<(), BackendError>;

    fn smoke_exact(&mut self, expected: &ComponentSnapshot) -> Result<SmokeReport, BackendError>;

    fn rollback_exact(&mut self, previous: &ComponentSnapshot) -> Result<(), BackendError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStatus {
    Applied,
    RolledBack,
    RollbackFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplyReceipt {
    pub status: ApplyStatus,
    pub component: UpdateComponent,
    pub previous_version: String,
    pub candidate_version: String,
    pub review_digest: String,
    pub approval_ref: String,
    pub candidate_smoke: Option<SmokeReport>,
    pub rollback_smoke: Option<SmokeReport>,
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateError {
    InvalidSnapshot(&'static str),
    ComponentMismatch,
    InvalidDecision(&'static str),
    ApprovalMismatch,
    ApprovalExpired,
    ApprovalNotApproved,
    ActivePreconditionMismatch,
    Encoding,
}

impl std::fmt::Display for UpdateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::InvalidSnapshot(code) | Self::InvalidDecision(code) => code,
            Self::ComponentMismatch => "component_mismatch",
            Self::ApprovalMismatch => "approval_mismatch",
            Self::ApprovalExpired => "approval_expired",
            Self::ApprovalNotApproved => "approval_not_approved",
            Self::ActivePreconditionMismatch => "active_precondition_mismatch",
            Self::Encoding => "encoding_failed",
        };
        write!(formatter, "n8n update review failed: {code}")
    }
}

impl std::error::Error for UpdateError {}

pub fn detect_update(
    current: ComponentSnapshot,
    candidate: ComponentSnapshot,
    known_dedupe_keys: &BTreeSet<String>,
) -> Result<DetectionOutcome, UpdateError> {
    let current = current.normalize_and_validate()?;
    let candidate = candidate.normalize_and_validate()?;
    if current.component != candidate.component {
        return Err(UpdateError::ComponentMismatch);
    }
    let current_snapshot_digest = current.digest()?;
    let candidate_snapshot_digest = candidate.digest()?;
    if current_snapshot_digest == candidate_snapshot_digest {
        return Ok(DetectionOutcome::NoChange {
            component: current.component,
            version: current.version,
            snapshot_digest: current_snapshot_digest,
        });
    }

    let diff = diff_snapshots(&current, &candidate);
    let mut review = UpdateReview {
        schema: REVIEW_SCHEMA.to_string(),
        component: current.component,
        current_version: current.version,
        candidate_version: candidate.version,
        current_snapshot_digest,
        candidate_snapshot_digest,
        candidate_artifact_digest: candidate.provenance.artifact_digest,
        diff,
        review_digest: String::new(),
        dedupe_key: String::new(),
    };
    review.review_digest = canonical_digest(&review)?;
    review.dedupe_key = canonical_digest(&(
        review.component,
        &review.current_snapshot_digest,
        &review.candidate_snapshot_digest,
        &review.review_digest,
    ))?;
    let duplicate = known_dedupe_keys.contains(&review.dedupe_key);
    Ok(DetectionOutcome::ReviewRequired {
        review: Box::new(review),
        duplicate,
    })
}

pub fn authorize_update(
    current: ComponentSnapshot,
    candidate: ComponentSnapshot,
    review: &UpdateReview,
    decision: &ExactReviewDecision,
    now_unix_ms: u64,
) -> Result<AuthorizedUpdate, UpdateError> {
    let current = current.normalize_and_validate()?;
    let candidate = candidate.normalize_and_validate()?;
    let DetectionOutcome::ReviewRequired {
        review: expected_review,
        ..
    } = detect_update(current.clone(), candidate.clone(), &BTreeSet::new())?
    else {
        return Err(UpdateError::ApprovalMismatch);
    };
    if expected_review.as_ref() != review {
        return Err(UpdateError::ApprovalMismatch);
    }
    validate_atom("approval_ref", &decision.approval_ref)
        .map_err(|_| UpdateError::InvalidDecision("invalid_approval_ref"))?;
    if decision.schema != APPROVAL_SCHEMA {
        return Err(UpdateError::InvalidDecision("invalid_approval_schema"));
    }
    if decision.decision != ReviewDecision::Approved {
        return Err(UpdateError::ApprovalNotApproved);
    }
    if decision.expires_at_unix_ms <= now_unix_ms {
        return Err(UpdateError::ApprovalExpired);
    }
    let expected = (
        review.component,
        review.current_version.as_str(),
        review.candidate_version.as_str(),
        review.candidate_artifact_digest.as_str(),
        review.review_digest.as_str(),
    );
    let supplied = (
        decision.component,
        decision.current_version.as_str(),
        decision.candidate_version.as_str(),
        decision.candidate_artifact_digest.as_str(),
        decision.review_digest.as_str(),
    );
    let current_version_matches = current.version == review.current_version;
    let candidate_version_matches = candidate.version == review.candidate_version;
    let current_matches_review = current.component == review.component
        && current_version_matches
        && current.digest()? == review.current_snapshot_digest;
    let candidate_matches_review = candidate.component == review.component
        && candidate_version_matches
        && candidate.provenance.artifact_digest == review.candidate_artifact_digest
        && candidate.digest()? == review.candidate_snapshot_digest;
    let snapshots_match_review = current_matches_review && candidate_matches_review;
    if expected != supplied || !snapshots_match_review {
        return Err(UpdateError::ApprovalMismatch);
    }
    Ok(AuthorizedUpdate {
        component: review.component,
        current,
        candidate,
        review_digest: review.review_digest.clone(),
        approval_ref: decision.approval_ref.clone(),
        expires_at_unix_ms: decision.expires_at_unix_ms,
    })
}

pub fn apply_authorized<B: UpdateBackend>(
    backend: &mut B,
    authorized: &AuthorizedUpdate,
    now_unix_ms: u64,
) -> Result<ApplyReceipt, UpdateError> {
    if authorized.expires_at_unix_ms <= now_unix_ms {
        return Err(UpdateError::ApprovalExpired);
    }
    let active = backend
        .active_snapshot(authorized.component)
        .map_err(|_| UpdateError::ActivePreconditionMismatch)?
        .normalize_and_validate()?;
    if active != authorized.current {
        return Err(UpdateError::ActivePreconditionMismatch);
    }

    let activation = backend.activate_exact(&authorized.candidate);
    if activation.is_err() {
        return Ok(rollback_receipt(
            backend,
            authorized,
            None,
            "activation_failed",
        ));
    }

    let candidate_smoke = backend.smoke_exact(&authorized.candidate).ok();
    let active_candidate = backend
        .active_snapshot(authorized.component)
        .ok()
        .and_then(|snapshot| snapshot.normalize_and_validate().ok());
    if candidate_smoke
        .as_ref()
        .is_some_and(SmokeReport::valid_for_apply)
        && active_candidate.as_ref() == Some(&authorized.candidate)
    {
        return Ok(ApplyReceipt {
            status: ApplyStatus::Applied,
            component: authorized.component,
            previous_version: authorized.current.version.clone(),
            candidate_version: authorized.candidate.version.clone(),
            review_digest: authorized.review_digest.clone(),
            approval_ref: authorized.approval_ref.clone(),
            candidate_smoke,
            rollback_smoke: None,
            failure_code: None,
        });
    }

    Ok(rollback_receipt(
        backend,
        authorized,
        candidate_smoke,
        "candidate_smoke_failed",
    ))
}

fn rollback_receipt<B: UpdateBackend>(
    backend: &mut B,
    authorized: &AuthorizedUpdate,
    candidate_smoke: Option<SmokeReport>,
    failure_code: &str,
) -> ApplyReceipt {
    let rollback_call_ok = backend.rollback_exact(&authorized.current).is_ok();
    let rollback_smoke = if rollback_call_ok {
        backend.smoke_exact(&authorized.current).ok()
    } else {
        None
    };
    let active_previous = backend
        .active_snapshot(authorized.component)
        .ok()
        .and_then(|snapshot| snapshot.normalize_and_validate().ok())
        .as_ref()
        == Some(&authorized.current);
    let rollback_verified = rollback_call_ok
        && active_previous
        && rollback_smoke
            .as_ref()
            .is_some_and(SmokeReport::valid_for_apply);
    ApplyReceipt {
        status: if rollback_verified {
            ApplyStatus::RolledBack
        } else {
            ApplyStatus::RollbackFailed
        },
        component: authorized.component,
        previous_version: authorized.current.version.clone(),
        candidate_version: authorized.candidate.version.clone(),
        review_digest: authorized.review_digest.clone(),
        approval_ref: authorized.approval_ref.clone(),
        candidate_smoke,
        rollback_smoke,
        failure_code: Some(failure_code.to_string()),
    }
}

fn diff_snapshots(current: &ComponentSnapshot, candidate: &ComponentSnapshot) -> UpdateDiff {
    let current_tools: BTreeMap<_, _> = current
        .tools
        .iter()
        .map(|tool| (tool.name.as_str(), tool))
        .collect();
    let candidate_tools: BTreeMap<_, _> = candidate
        .tools
        .iter()
        .map(|tool| (tool.name.as_str(), tool))
        .collect();
    let added_tools: Vec<_> = candidate_tools
        .keys()
        .filter(|name| !current_tools.contains_key(**name))
        .map(|name| (*name).to_string())
        .collect();
    let removed_tools: Vec<_> = current_tools
        .keys()
        .filter(|name| !candidate_tools.contains_key(**name))
        .map(|name| (*name).to_string())
        .collect();
    let changed_tools: Vec<_> = current_tools
        .iter()
        .filter_map(|(name, old)| {
            let new = candidate_tools.get(name)?;
            (old != new).then(|| ChangedTool {
                name: (*name).to_string(),
                changes: [
                    (old.schema_digest != new.schema_digest).then_some(ToolChange::Schema),
                    (old.description_digest != new.description_digest)
                        .then_some(ToolChange::Description),
                    (old.impact != new.impact).then_some(ToolChange::Impact),
                    (old.permissions != new.permissions).then_some(ToolChange::Permissions),
                ]
                .into_iter()
                .flatten()
                .collect(),
            })
        })
        .collect();
    let dependency_names: BTreeSet<_> = current
        .dependencies
        .keys()
        .chain(candidate.dependencies.keys())
        .collect();
    let dependency_changes: Vec<_> = dependency_names
        .into_iter()
        .filter_map(|name| {
            let previous = current.dependencies.get(name);
            let next = candidate.dependencies.get(name);
            (previous != next).then(|| DependencyChange {
                name: name.clone(),
                previous: previous.cloned(),
                candidate: next.cloned(),
            })
        })
        .collect();
    let has_new_sensitive_tool = added_tools.iter().any(|name| {
        candidate_tools
            .get(name.as_str())
            .is_some_and(|tool| tool.impact.requires_owner_review())
    });
    let changed_security_contract = changed_tools.iter().any(|tool| {
        tool.changes.contains(&ToolChange::Schema)
            || tool.changes.contains(&ToolChange::Impact)
            || tool.changes.contains(&ToolChange::Permissions)
    });
    let provenance_changed = current.provenance.source_kind != candidate.provenance.source_kind
        || current.provenance.artifact_digest != candidate.provenance.artifact_digest
        || current.provenance.metadata_digest != candidate.provenance.metadata_digest;
    let engine_changed =
        current.provenance.engine_requirement != candidate.provenance.engine_requirement;
    let protocol_changed =
        current.provenance.protocol_versions != candidate.provenance.protocol_versions;
    let has_removed_tool = !removed_tools.is_empty();
    let breaking = has_removed_tool
        || changed_security_contract
        || engine_changed
        || protocol_changed
        || has_new_sensitive_tool;
    let docs_or_skills_review_required = breaking
        || !added_tools.is_empty()
        || changed_tools
            .iter()
            .any(|tool| tool.changes.contains(&ToolChange::Description))
        || !dependency_changes.is_empty();
    let flags = [
        provenance_changed.then_some(UpdateFlag::ProvenanceChanged),
        engine_changed.then_some(UpdateFlag::EngineChanged),
        protocol_changed.then_some(UpdateFlag::ProtocolChanged),
        has_new_sensitive_tool.then_some(UpdateFlag::NewSensitiveTool),
        has_removed_tool.then_some(UpdateFlag::RemovedTool),
        breaking.then_some(UpdateFlag::Breaking),
        docs_or_skills_review_required.then_some(UpdateFlag::DocsOrSkillsReviewRequired),
    ]
    .into_iter()
    .flatten()
    .collect();
    UpdateDiff {
        added_tools,
        removed_tools,
        changed_tools,
        dependency_changes,
        flags,
    }
}

fn validate_atom(field: &'static str, value: &str) -> Result<(), UpdateError> {
    if value.is_empty()
        || value.len() > MAX_ATOM_BYTES
        || !value.is_ascii()
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return Err(UpdateError::InvalidSnapshot(field));
    }
    Ok(())
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, UpdateError> {
    let bytes = serde_json::to_vec(value).map_err(|_| UpdateError::Encoding)?;
    Ok(format!("blake3-256:{}", blake3::hash(&bytes).to_hex()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, impact: ToolImpact) -> ToolSnapshot {
        ToolSnapshot {
            name: name.to_string(),
            schema_digest: format!("schema-{name}"),
            description_digest: format!("description-{name}"),
            impact,
            permissions: BTreeSet::from([format!("permission-{name}")]),
        }
    }

    fn snapshot(version: &str, tools: Vec<ToolSnapshot>) -> ComponentSnapshot {
        ComponentSnapshot {
            component: UpdateComponent::LocalN8nMcp,
            version: version.to_string(),
            provenance: ProvenanceSnapshot {
                source_kind: "npm_registry".to_string(),
                artifact_digest: format!("sha512-{version}"),
                metadata_digest: format!("blake3-256-metadata-{version}"),
                engine_requirement: Some(">=20.0.0".to_string()),
                protocol_versions: BTreeSet::from(["2025-06-18".to_string()]),
            },
            dependencies: BTreeMap::from([("zod".to_string(), "3.25.0".to_string())]),
            tools,
        }
    }

    fn review_pair() -> (ComponentSnapshot, ComponentSnapshot, UpdateReview) {
        let current = snapshot("2.69.0", vec![tool("search_nodes", ToolImpact::Read)]);
        let candidate = snapshot(
            "2.70.0",
            vec![
                tool("search_nodes", ToolImpact::Read),
                tool("update_workflow", ToolImpact::Write),
            ],
        );
        let DetectionOutcome::ReviewRequired { review, .. } =
            detect_update(current.clone(), candidate.clone(), &BTreeSet::new()).unwrap()
        else {
            panic!("expected review");
        };
        (current, candidate, *review)
    }

    #[test]
    fn no_change_returns_stable_snapshot_digest() {
        let current = snapshot("2.69.0", vec![tool("search_nodes", ToolImpact::Read)]);
        let outcome =
            detect_update(current.clone(), current, &BTreeSet::new()).expect("detect no change");
        assert!(matches!(outcome, DetectionOutcome::NoChange { .. }));
    }

    #[test]
    fn candidate_available_flags_new_write_tool() {
        let (_, _, review) = review_pair();
        assert_eq!(review.diff.added_tools, ["update_workflow"]);
        assert!(review.diff.flags.contains(&UpdateFlag::NewSensitiveTool));
        assert!(review.diff.flags.contains(&UpdateFlag::Breaking));
        assert!(
            review
                .diff
                .flags
                .contains(&UpdateFlag::DocsOrSkillsReviewRequired)
        );
    }

    #[test]
    fn schema_change_is_breaking() {
        let current = snapshot("2.69.0", vec![tool("search_nodes", ToolImpact::Read)]);
        let mut changed = tool("search_nodes", ToolImpact::Read);
        changed.schema_digest = "schema-new".to_string();
        let candidate = snapshot("2.70.0", vec![changed]);
        let DetectionOutcome::ReviewRequired { review, .. } =
            detect_update(current, candidate, &BTreeSet::new()).unwrap()
        else {
            panic!("expected review");
        };
        assert!(
            review.diff.changed_tools[0]
                .changes
                .contains(&ToolChange::Schema)
        );
        assert!(review.diff.flags.contains(&UpdateFlag::Breaking));
    }

    #[test]
    fn removed_tool_is_breaking() {
        let current = snapshot(
            "2.69.0",
            vec![
                tool("search_nodes", ToolImpact::Read),
                tool("get_node", ToolImpact::Read),
            ],
        );
        let candidate = snapshot("2.70.0", vec![tool("search_nodes", ToolImpact::Read)]);
        let DetectionOutcome::ReviewRequired { review, .. } =
            detect_update(current, candidate, &BTreeSet::new()).unwrap()
        else {
            panic!("expected review");
        };
        assert_eq!(review.diff.removed_tools, ["get_node"]);
        assert!(review.diff.flags.contains(&UpdateFlag::RemovedTool));
        assert!(review.diff.flags.contains(&UpdateFlag::Breaking));
    }

    #[test]
    fn same_candidate_is_deduplicated() {
        let (current, candidate, review) = review_pair();
        let known = BTreeSet::from([review.dedupe_key]);
        let DetectionOutcome::ReviewRequired { duplicate, .. } =
            detect_update(current, candidate, &known).unwrap()
        else {
            panic!("expected review");
        };
        assert!(duplicate);
    }

    #[test]
    fn deferred_decision_cannot_authorize_apply() {
        let (current, candidate, review) = review_pair();
        let decision =
            ExactReviewDecision::new(ReviewDecision::Deferred, &review, "clickup-task-1", 2_000);
        assert_eq!(
            authorize_update(current, candidate, &review, &decision, 1_000),
            Err(UpdateError::ApprovalNotApproved)
        );
    }

    #[test]
    fn exact_unexpired_approval_authorizes_candidate() {
        let (current, candidate, review) = review_pair();
        let decision =
            ExactReviewDecision::new(ReviewDecision::Approved, &review, "clickup-task-1", 2_000);
        let authorized = authorize_update(current, candidate, &review, &decision, 1_000).unwrap();
        assert_eq!(authorized.component(), UpdateComponent::LocalN8nMcp);
        assert_eq!(authorized.candidate().version, "2.70.0");
    }

    #[test]
    fn approval_for_other_version_is_rejected() {
        let (current, candidate, review) = review_pair();
        let mut decision =
            ExactReviewDecision::new(ReviewDecision::Approved, &review, "clickup-task-1", 2_000);
        decision.candidate_version = "2.71.0".to_string();
        assert_eq!(
            authorize_update(current, candidate, &review, &decision, 1_000),
            Err(UpdateError::ApprovalMismatch)
        );
    }

    #[derive(Clone)]
    struct FakeBackend {
        active: ComponentSnapshot,
        candidate_smoke_passes: bool,
        rollback_fails: bool,
        activations: usize,
        rollbacks: usize,
    }

    impl UpdateBackend for FakeBackend {
        fn active_snapshot(
            &mut self,
            _component: UpdateComponent,
        ) -> Result<ComponentSnapshot, BackendError> {
            Ok(self.active.clone())
        }

        fn activate_exact(&mut self, candidate: &ComponentSnapshot) -> Result<(), BackendError> {
            self.activations += 1;
            self.active = candidate.clone();
            Ok(())
        }

        fn smoke_exact(
            &mut self,
            expected: &ComponentSnapshot,
        ) -> Result<SmokeReport, BackendError> {
            let candidate = expected.version == "2.70.0";
            let passed = !candidate || self.candidate_smoke_passes;
            Ok(SmokeReport {
                passed,
                check_ids: vec!["tools_list".to_string(), "zero_idle".to_string()],
                zero_idle_confirmed: passed,
                redaction_confirmed: passed,
            })
        }

        fn rollback_exact(&mut self, previous: &ComponentSnapshot) -> Result<(), BackendError> {
            self.rollbacks += 1;
            if self.rollback_fails {
                return Err(BackendError::RollbackFailed);
            }
            self.active = previous.clone();
            Ok(())
        }
    }

    fn authorized_pair() -> (ComponentSnapshot, AuthorizedUpdate) {
        let (current, candidate, review) = review_pair();
        let decision =
            ExactReviewDecision::new(ReviewDecision::Approved, &review, "clickup-task-1", 2_000);
        let authorized =
            authorize_update(current.clone(), candidate, &review, &decision, 1_000).unwrap();
        (current, authorized)
    }

    #[test]
    fn successful_smoke_keeps_exact_candidate_active() {
        let (current, authorized) = authorized_pair();
        let mut backend = FakeBackend {
            active: current,
            candidate_smoke_passes: true,
            rollback_fails: false,
            activations: 0,
            rollbacks: 0,
        };
        let receipt = apply_authorized(&mut backend, &authorized, 1_500).unwrap();
        assert_eq!(receipt.status, ApplyStatus::Applied);
        assert_eq!(backend.active.version, "2.70.0");
        assert_eq!(backend.activations, 1);
        assert_eq!(backend.rollbacks, 0);
    }

    #[test]
    fn smoke_failure_restores_previous_exact_version() {
        let (current, authorized) = authorized_pair();
        let mut backend = FakeBackend {
            active: current,
            candidate_smoke_passes: false,
            rollback_fails: false,
            activations: 0,
            rollbacks: 0,
        };
        let receipt = apply_authorized(&mut backend, &authorized, 1_500).unwrap();
        assert_eq!(receipt.status, ApplyStatus::RolledBack);
        assert_eq!(backend.active.version, "2.69.0");
        assert_eq!(backend.activations, 1);
        assert_eq!(backend.rollbacks, 1);
        assert!(receipt.rollback_smoke.unwrap().passed);
    }

    #[test]
    fn stale_active_precondition_prevents_switch() {
        let (_, authorized) = authorized_pair();
        let mut backend = FakeBackend {
            active: snapshot("2.68.0", vec![tool("search_nodes", ToolImpact::Read)]),
            candidate_smoke_passes: true,
            rollback_fails: false,
            activations: 0,
            rollbacks: 0,
        };
        assert_eq!(
            apply_authorized(&mut backend, &authorized, 1_500),
            Err(UpdateError::ActivePreconditionMismatch)
        );
        assert_eq!(backend.activations, 0);
    }

    #[test]
    fn authorization_is_rechecked_at_apply_time() {
        let (current, authorized) = authorized_pair();
        let mut backend = FakeBackend {
            active: current,
            candidate_smoke_passes: true,
            rollback_fails: false,
            activations: 0,
            rollbacks: 0,
        };
        assert_eq!(
            apply_authorized(&mut backend, &authorized, 2_000),
            Err(UpdateError::ApprovalExpired)
        );
        assert_eq!(backend.activations, 0);
    }

    #[test]
    fn manipulated_diff_cannot_be_authorized() {
        let (current, candidate, mut review) = review_pair();
        review.diff.flags.remove(&UpdateFlag::Breaking);
        let decision =
            ExactReviewDecision::new(ReviewDecision::Approved, &review, "clickup-task-1", 2_000);
        assert_eq!(
            authorize_update(current, candidate, &review, &decision, 1_000),
            Err(UpdateError::ApprovalMismatch)
        );
    }
}
