//! Deterministic target resolution and provider routing for `fwc-n8n`.
//!
//! This module deliberately carries only bounded identity and capability
//! metadata. Provider payloads, tool catalogs, and workflow content never
//! enter the resolver or router.

use std::{collections::BTreeSet, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const MAX_ID_BYTES: usize = 256;
const MAX_NAME_BYTES: usize = 256;
/// Maximum number of candidates exposed by a bounded name search.
pub const MAX_TARGET_CANDIDATES: usize = 8;

/// Registered n8n server identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerId {
    Eec,
    Hetzner,
    Legacy,
    Local,
}

impl ServerId {
    /// Parse only identities in the frozen server registry.
    pub fn parse(value: &str) -> Result<Self, TargetResolveError> {
        match value {
            "eec" => Ok(Self::Eec),
            "hetzner" => Ok(Self::Hetzner),
            "legacy" => Ok(Self::Legacy),
            "local" => Ok(Self::Local),
            _ => Err(TargetResolveError::new(TargetResolveCode::InvalidServer)),
        }
    }

    #[must_use]
    pub const fn is_legacy(self) -> bool {
        matches!(self, Self::Legacy)
    }

    #[must_use]
    pub const fn is_local(self) -> bool {
        matches!(self, Self::Local)
    }
}

impl fmt::Display for ServerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Eec => "eec",
            Self::Hetzner => "hetzner",
            Self::Legacy => "legacy",
            Self::Local => "local",
        })
    }
}

/// Resource kinds understood by canonical `fwc-n8n://` URIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Instance,
    Project,
    Folder,
    Workflow,
    WorkflowVersion,
    Execution,
    Credential,
    DataTable,
    Evaluation,
    LocalNode,
    LocalTemplate,
}

/// A validated canonical resource URI.
///
/// Debug output intentionally omits identifiers. The URI remains available
/// through [`Self::as_str`] for protocol serialization and approval binding.
#[derive(Clone, PartialEq, Eq)]
pub struct CanonicalResourceUri {
    raw: String,
    server: ServerId,
    kind: ResourceKind,
}

impl CanonicalResourceUri {
    /// Parse and canonicalize a resource URI from the frozen contract.
    pub fn parse(value: &str) -> Result<Self, TargetResolveError> {
        let remainder = value
            .strip_prefix("fwc-n8n://")
            .ok_or_else(|| TargetResolveError::new(TargetResolveCode::InvalidResourceUri))?;
        if remainder.is_empty() || remainder.contains('?') || remainder.contains('#') {
            return Err(TargetResolveError::new(
                TargetResolveCode::InvalidResourceUri,
            ));
        }

        let mut segments = remainder.split('/');
        let server = ServerId::parse(
            segments
                .next()
                .ok_or_else(|| TargetResolveError::new(TargetResolveCode::InvalidResourceUri))?,
        )?;
        let raw_segments: Vec<&str> = segments.collect();
        let decoded: Vec<String> = raw_segments
            .iter()
            .map(|segment| decode_segment(segment))
            .collect::<Result<_, _>>()?;
        let kind = match decoded.as_slice() {
            [] => ResourceKind::Instance,
            [collection, id]
                if collection == "projects"
                    || collection == "folders"
                    || collection == "credentials"
                    || collection == "data-tables" =>
            {
                match collection.as_str() {
                    "projects" => ResourceKind::Project,
                    "folders" => ResourceKind::Folder,
                    "credentials" => ResourceKind::Credential,
                    "data-tables" => ResourceKind::DataTable,
                    _ => unreachable!(),
                }
            }
            [collection, workflow_id, child, child_id]
                if collection == "workflows"
                    && (child == "versions" || child == "executions" || child == "evaluations") =>
            {
                let _ = (workflow_id, child_id);
                match child.as_str() {
                    "versions" => ResourceKind::WorkflowVersion,
                    "executions" => ResourceKind::Execution,
                    "evaluations" => ResourceKind::Evaluation,
                    _ => unreachable!(),
                }
            }
            [collection, id] if server.is_local() && collection == "nodes" => {
                let _ = id;
                ResourceKind::LocalNode
            }
            [collection, id] if server.is_local() && collection == "templates" => {
                let _ = id;
                ResourceKind::LocalTemplate
            }
            [collection, _] if collection == "workflows" => ResourceKind::Workflow,
            _ => {
                return Err(TargetResolveError::new(
                    TargetResolveCode::InvalidResourceUri,
                ));
            }
        };

        if !server.is_local()
            && matches!(kind, ResourceKind::LocalNode | ResourceKind::LocalTemplate)
        {
            return Err(TargetResolveError::new(
                TargetResolveCode::InvalidResourceUri,
            ));
        }
        if server.is_local()
            && !matches!(
                kind,
                ResourceKind::Instance | ResourceKind::LocalNode | ResourceKind::LocalTemplate
            )
        {
            return Err(TargetResolveError::new(
                TargetResolveCode::InvalidResourceUri,
            ));
        }

        let canonical = match decoded.as_slice() {
            [] => format!("fwc-n8n://{server}"),
            [collection, id] => {
                format!("fwc-n8n://{server}/{collection}/{}", encode_segment(id))
            }
            [collection, workflow_id, child, child_id] => format!(
                "fwc-n8n://{server}/{collection}/{}/{}/{}",
                encode_segment(workflow_id),
                child,
                encode_segment(child_id)
            ),
            _ => {
                return Err(TargetResolveError::new(
                    TargetResolveCode::InvalidResourceUri,
                ));
            }
        };
        Ok(Self {
            raw: canonical,
            server,
            kind,
        })
    }

    /// Construct an instance URI for a registered server.
    #[must_use]
    pub fn instance(server: ServerId) -> Self {
        Self {
            raw: format!("fwc-n8n://{server}"),
            server,
            kind: ResourceKind::Instance,
        }
    }

    /// Construct a project URI from a confirmed project identity.
    pub fn project(server: ServerId, project_id: &str) -> Result<Self, TargetResolveError> {
        Self::from_parts(server, ResourceKind::Project, &["projects", project_id])
    }

    /// Construct a workflow URI from a proven server and workflow ID.
    pub fn workflow(server: ServerId, workflow_id: &str) -> Result<Self, TargetResolveError> {
        Self::from_parts(server, ResourceKind::Workflow, &["workflows", workflow_id])
    }

    /// Construct an execution URI with both workflow and execution identity.
    pub fn execution(
        server: ServerId,
        workflow_id: &str,
        execution_id: &str,
    ) -> Result<Self, TargetResolveError> {
        Self::from_parts(
            server,
            ResourceKind::Execution,
            &["workflows", workflow_id, "executions", execution_id],
        )
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    #[must_use]
    pub const fn server(&self) -> ServerId {
        self.server
    }

    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    fn compatible_with(&self, other: &Self) -> bool {
        if self.server != other.server {
            return false;
        }
        if self.kind == ResourceKind::Instance || other.kind == ResourceKind::Instance {
            return true;
        }
        if self.kind == other.kind {
            return self.raw == other.raw;
        }
        if self.kind == ResourceKind::Project && other.is_workflow_resource()
            || other.kind == ResourceKind::Project && self.is_workflow_resource()
        {
            return true;
        }
        match (self.workflow_id_segment(), other.workflow_id_segment()) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
    }

    const fn is_workflow_resource(&self) -> bool {
        matches!(
            self.kind,
            ResourceKind::Workflow
                | ResourceKind::WorkflowVersion
                | ResourceKind::Execution
                | ResourceKind::Evaluation
        )
    }

    const fn specificity(&self) -> u8 {
        match self.kind {
            ResourceKind::Instance => 0,
            ResourceKind::Project => 1,
            ResourceKind::Workflow => 2,
            ResourceKind::WorkflowVersion | ResourceKind::Execution | ResourceKind::Evaluation => 3,
            ResourceKind::Folder
            | ResourceKind::Credential
            | ResourceKind::DataTable
            | ResourceKind::LocalNode
            | ResourceKind::LocalTemplate => 2,
        }
    }

    fn workflow_id_segment(&self) -> Option<&str> {
        let mut segments = self.raw.strip_prefix("fwc-n8n://")?.split('/');
        let _server = segments.next()?;
        if segments.next()? != "workflows" {
            return None;
        }
        segments.next()
    }

    fn from_parts(
        server: ServerId,
        kind: ResourceKind,
        parts: &[&str],
    ) -> Result<Self, TargetResolveError> {
        if server.is_local() {
            return Err(TargetResolveError::new(
                TargetResolveCode::InvalidResourceUri,
            ));
        }
        for part in parts.iter().skip(1) {
            validate_id(part)?;
        }
        let raw = format!(
            "fwc-n8n://{server}/{}",
            parts
                .iter()
                .map(|part| {
                    if *part == "projects" || *part == "workflows" || *part == "executions" {
                        (*part).to_string()
                    } else {
                        encode_segment(part)
                    }
                })
                .collect::<Vec<_>>()
                .join("/")
        );
        Ok(Self { raw, server, kind })
    }
}

impl fmt::Debug for CanonicalResourceUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalResourceUri")
            .field("server", &self.server)
            .field("kind", &self.kind)
            .finish()
    }
}

impl Serialize for CanonicalResourceUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for CanonicalResourceUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

/// A confirmed project-to-server mapping. It is intentionally distinct from
/// an unverified project name.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmedProjectMapping {
    pub server: ServerId,
    pub project_id: String,
}

impl fmt::Debug for ConfirmedProjectMapping {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedProjectMapping")
            .field("server", &self.server)
            .field("project_id", &"<redacted>")
            .finish()
    }
}

impl ConfirmedProjectMapping {
    pub fn new(
        server: ServerId,
        project_id: impl Into<String>,
    ) -> Result<Self, TargetResolveError> {
        let project_id = project_id.into();
        validate_id(&project_id)?;
        Ok(Self { server, project_id })
    }
}

/// Workflow ID provenance from a prior confirmed server read or bounded
/// search.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowIdProvenance {
    pub server: ServerId,
    pub workflow_id: String,
}

impl fmt::Debug for WorkflowIdProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkflowIdProvenance")
            .field("server", &self.server)
            .field("workflow_id", &"<redacted>")
            .finish()
    }
}

impl WorkflowIdProvenance {
    pub fn new(
        server: ServerId,
        workflow_id: impl Into<String>,
    ) -> Result<Self, TargetResolveError> {
        let workflow_id = workflow_id.into();
        validate_id(&workflow_id)?;
        Ok(Self {
            server,
            workflow_id,
        })
    }
}

/// Execution ID provenance. The containing workflow identity is mandatory so
/// an execution can never become an unscoped provider lookup.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionIdProvenance {
    pub server: ServerId,
    pub workflow_id: String,
    pub execution_id: String,
}

impl fmt::Debug for ExecutionIdProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionIdProvenance")
            .field("server", &self.server)
            .field("workflow_id", &"<redacted>")
            .field("execution_id", &"<redacted>")
            .finish()
    }
}

impl ExecutionIdProvenance {
    pub fn new(
        server: ServerId,
        workflow_id: impl Into<String>,
        execution_id: impl Into<String>,
    ) -> Result<Self, TargetResolveError> {
        let workflow_id = workflow_id.into();
        let execution_id = execution_id.into();
        validate_id(&workflow_id)?;
        validate_id(&execution_id)?;
        Ok(Self {
            server,
            workflow_id,
            execution_id,
        })
    }
}

/// Safe summary returned by a bounded workflow-name search.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetCandidate {
    pub server: ServerId,
    pub workflow_id: String,
    pub name: String,
}

impl TargetCandidate {
    pub fn new(
        server: ServerId,
        workflow_id: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<Self, TargetResolveError> {
        let workflow_id = workflow_id.into();
        let name = name.into();
        validate_id(&workflow_id)?;
        validate_name(&name)?;
        Ok(Self {
            server,
            workflow_id,
            name,
        })
    }
}

impl fmt::Debug for TargetCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TargetCandidate")
            .field("server", &self.server)
            .field("workflow_id", &"<redacted>")
            .field("name", &"<redacted>")
            .finish()
    }
}

/// Input to [`TargetResolver::resolve`]. Bare names and bare IDs are retained
/// only to return a deterministic denial; they never become identity proof.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetQuery {
    pub server: Option<ServerId>,
    pub project_mapping: Option<ConfirmedProjectMapping>,
    pub workflow_provenance: Option<WorkflowIdProvenance>,
    pub execution_provenance: Option<ExecutionIdProvenance>,
    pub resource_uri: Option<CanonicalResourceUri>,
    pub workflow_name: Option<String>,
    pub workflow_id: Option<String>,
    pub execution_id: Option<String>,
    /// Servers explicitly enumerated by a bounded read-only search. This is
    /// not target selection; a matching name still returns ambiguity.
    pub candidate_servers: Vec<ServerId>,
    pub candidates: Vec<TargetCandidate>,
    pub legacy_opt_in: bool,
}

impl fmt::Debug for TargetQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TargetQuery")
            .field("server", &self.server)
            .field("has_project_mapping", &self.project_mapping.is_some())
            .field(
                "has_workflow_provenance",
                &self.workflow_provenance.is_some(),
            )
            .field(
                "has_execution_provenance",
                &self.execution_provenance.is_some(),
            )
            .field("has_resource_uri", &self.resource_uri.is_some())
            .field("has_workflow_name", &self.workflow_name.is_some())
            .field("has_workflow_id", &self.workflow_id.is_some())
            .field("has_execution_id", &self.execution_id.is_some())
            .field("candidate_server_count", &self.candidate_servers.len())
            .field("candidate_count", &self.candidates.len())
            .field("legacy_opt_in", &self.legacy_opt_in)
            .finish()
    }
}

impl TargetQuery {
    #[must_use]
    pub fn explicit_server(server: ServerId) -> Self {
        Self {
            server: Some(server),
            ..Self::default()
        }
    }

    #[must_use]
    pub const fn with_legacy_opt_in(mut self) -> Self {
        self.legacy_opt_in = true;
        self
    }

    #[must_use]
    pub fn with_candidates(mut self, candidates: Vec<TargetCandidate>) -> Self {
        self.candidates = candidates;
        self
    }

    #[must_use]
    pub fn with_candidate_servers(mut self, servers: Vec<ServerId>) -> Self {
        self.candidate_servers = servers;
        self
    }
}

/// Resolved identity, containing no provider payload.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedTarget {
    pub resource_uri: CanonicalResourceUri,
    pub server: ServerId,
    pub kind: ResourceKind,
}

impl fmt::Debug for ResolvedTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedTarget")
            .field("server", &self.server)
            .field("kind", &self.kind)
            .finish()
    }
}

/// Outcome of target resolution. Ambiguity is data, not a guessed target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetResolution {
    Resolved(ResolvedTarget),
    Ambiguous {
        candidates: Vec<TargetCandidate>,
        truncated: bool,
    },
}

/// Stable, redaction-safe target resolver error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetResolveCode {
    InvalidServer,
    InvalidIdentifier,
    InvalidResourceUri,
    MissingTargetProof,
    NameOnlyTarget,
    NameNeedsSelection,
    TargetNotFound,
    CrossServerCollision,
    ConflictingEvidence,
    IdentifierProvenanceRequired,
    LegacyOptInRequired,
    CandidateLimitExceeded,
}

/// Resolver error without raw names, IDs, or provider text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetResolveError {
    code: TargetResolveCode,
}

impl TargetResolveError {
    const fn new(code: TargetResolveCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> TargetResolveCode {
        self.code
    }
}

impl fmt::Display for TargetResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            TargetResolveCode::InvalidServer => "invalid_server",
            TargetResolveCode::InvalidIdentifier => "invalid_identifier",
            TargetResolveCode::InvalidResourceUri => "invalid_resource_uri",
            TargetResolveCode::MissingTargetProof => "missing_target_proof",
            TargetResolveCode::NameOnlyTarget => "name_only_target",
            TargetResolveCode::NameNeedsSelection => "name_needs_selection",
            TargetResolveCode::TargetNotFound => "target_not_found",
            TargetResolveCode::CrossServerCollision => "cross_server_collision",
            TargetResolveCode::ConflictingEvidence => "conflicting_evidence",
            TargetResolveCode::IdentifierProvenanceRequired => "identifier_provenance_required",
            TargetResolveCode::LegacyOptInRequired => "legacy_opt_in_required",
            TargetResolveCode::CandidateLimitExceeded => "candidate_limit_exceeded",
        })
    }
}

impl std::error::Error for TargetResolveError {}

/// Pure target resolver. It performs no provider or filesystem I/O.
#[derive(Debug, Default, Clone, Copy)]
pub struct TargetResolver;

impl TargetResolver {
    /// Resolve only from explicit, confirmed, canonical, or bounded-search
    /// evidence. A name never selects a server on its own.
    pub fn resolve(query: &TargetQuery) -> Result<TargetResolution, TargetResolveError> {
        if query.candidates.len() > MAX_TARGET_CANDIDATES * 4 {
            return Err(TargetResolveError::new(
                TargetResolveCode::CandidateLimitExceeded,
            ));
        }
        if query.workflow_id.is_some() || query.execution_id.is_some() {
            return Err(TargetResolveError::new(
                TargetResolveCode::IdentifierProvenanceRequired,
            ));
        }
        let has_proof = query.server.is_some()
            || query.project_mapping.is_some()
            || query.workflow_provenance.is_some()
            || query.execution_provenance.is_some()
            || query.resource_uri.is_some();
        if !has_proof && query.candidate_servers.is_empty() && query.workflow_name.is_some() {
            return Err(TargetResolveError::new(TargetResolveCode::NameOnlyTarget));
        }
        if !has_proof && !query.candidate_servers.is_empty() {
            if query.candidate_servers.len() > 3 {
                return Err(TargetResolveError::new(
                    TargetResolveCode::CandidateLimitExceeded,
                ));
            }
            if query.candidate_servers.contains(&ServerId::Local) {
                return Err(TargetResolveError::new(TargetResolveCode::InvalidServer));
            }
            if query.candidate_servers.contains(&ServerId::Legacy) && !query.legacy_opt_in {
                return Err(TargetResolveError::new(
                    TargetResolveCode::LegacyOptInRequired,
                ));
            }
            let Some(name) = &query.workflow_name else {
                return Err(TargetResolveError::new(
                    TargetResolveCode::MissingTargetProof,
                ));
            };
            validate_name(name)?;
            let matches: Vec<TargetCandidate> = query
                .candidates
                .iter()
                .filter(|candidate| {
                    query.candidate_servers.contains(&candidate.server) && candidate.name == *name
                })
                .cloned()
                .collect();
            if matches.is_empty() {
                return Err(TargetResolveError::new(TargetResolveCode::TargetNotFound));
            }
            let servers: BTreeSet<ServerId> =
                matches.iter().map(|candidate| candidate.server).collect();
            if servers.len() > 1 {
                return Err(TargetResolveError::new(
                    TargetResolveCode::CrossServerCollision,
                ));
            }
            let (candidates, truncated) = bounded_candidates(matches);
            return Ok(TargetResolution::Ambiguous {
                candidates,
                truncated,
            });
        }
        let mut proven: Option<CanonicalResourceUri> = None;
        let mut add_proof = |uri: CanonicalResourceUri| -> Result<(), TargetResolveError> {
            if let Some(existing) = &proven {
                if !existing.compatible_with(&uri) {
                    return Err(TargetResolveError::new(
                        TargetResolveCode::ConflictingEvidence,
                    ));
                }
                if uri.specificity() > existing.specificity() {
                    proven = Some(uri);
                }
            } else {
                proven = Some(uri);
            }
            Ok(())
        };

        if let Some(server) = query.server {
            add_proof(CanonicalResourceUri::instance(server))?;
        }
        if let Some(mapping) = &query.project_mapping {
            add_proof(CanonicalResourceUri::project(
                mapping.server,
                &mapping.project_id,
            )?)?;
        }
        if let Some(workflow) = &query.workflow_provenance {
            add_proof(CanonicalResourceUri::workflow(
                workflow.server,
                &workflow.workflow_id,
            )?)?;
        }
        if let Some(execution) = &query.execution_provenance {
            add_proof(CanonicalResourceUri::execution(
                execution.server,
                &execution.workflow_id,
                &execution.execution_id,
            )?)?;
        }
        if let Some(uri) = &query.resource_uri {
            add_proof(uri.clone())?;
        }

        let Some(proof) = proven else {
            return Err(TargetResolveError::new(
                TargetResolveCode::MissingTargetProof,
            ));
        };
        if proof.server().is_legacy() && !query.legacy_opt_in {
            return Err(TargetResolveError::new(
                TargetResolveCode::LegacyOptInRequired,
            ));
        }

        let Some(name) = &query.workflow_name else {
            return Ok(TargetResolution::Resolved(ResolvedTarget {
                server: proof.server(),
                kind: proof.kind(),
                resource_uri: proof,
            }));
        };
        validate_name(name)?;

        if !matches!(proof.kind(), ResourceKind::Instance | ResourceKind::Project) {
            return Ok(TargetResolution::Resolved(ResolvedTarget {
                server: proof.server(),
                kind: proof.kind(),
                resource_uri: proof,
            }));
        }

        let matches: Vec<TargetCandidate> = query
            .candidates
            .iter()
            .filter(|candidate| candidate.server == proof.server() && candidate.name == *name)
            .cloned()
            .collect();
        if matches.is_empty() {
            return Err(TargetResolveError::new(
                TargetResolveCode::NameNeedsSelection,
            ));
        }
        let servers: BTreeSet<ServerId> =
            matches.iter().map(|candidate| candidate.server).collect();
        if servers.len() > 1 {
            return Err(TargetResolveError::new(
                TargetResolveCode::CrossServerCollision,
            ));
        }
        if matches.len() > 1 {
            let (candidates, truncated) = bounded_candidates(matches);
            return Ok(TargetResolution::Ambiguous {
                candidates,
                truncated,
            });
        }
        let candidate = &matches[0];
        let resource_uri =
            CanonicalResourceUri::workflow(candidate.server, &candidate.workflow_id)?;
        Ok(TargetResolution::Resolved(ResolvedTarget {
            server: candidate.server,
            kind: ResourceKind::Workflow,
            resource_uri,
        }))
    }
}

/// Provider selected by the typed public operation surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    TypedRest,
    LocalMcp,
    OfficialMcp,
}

/// Public operation intent used for deterministic route selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationIntent {
    CapabilitiesInspection,
    KnownIdRead,
    Search,
    NodeKnowledge,
    Validation,
    Comparison,
    WorkflowDraftWrite,
    Lifecycle,
    Execution,
    CredentialMetadata,
    DataTables,
    Audit,
    VersionHistory,
}

impl OperationIntent {
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            Self::WorkflowDraftWrite | Self::Lifecycle | Self::Execution | Self::DataTables
        )
    }

    const fn preferred_and_fallback(self) -> (Provider, Option<Provider>) {
        match self {
            Self::CapabilitiesInspection => (Provider::OfficialMcp, None),
            Self::KnownIdRead | Self::Search => (Provider::TypedRest, Some(Provider::OfficialMcp)),
            Self::NodeKnowledge | Self::Validation => {
                (Provider::LocalMcp, Some(Provider::OfficialMcp))
            }
            Self::Comparison | Self::WorkflowDraftWrite | Self::Execution | Self::DataTables => {
                (Provider::OfficialMcp, Some(Provider::TypedRest))
            }
            Self::Lifecycle | Self::VersionHistory => {
                (Provider::TypedRest, Some(Provider::OfficialMcp))
            }
            Self::CredentialMetadata => (Provider::OfficialMcp, Some(Provider::TypedRest)),
            Self::Audit => (Provider::TypedRest, Some(Provider::LocalMcp)),
        }
    }
}

/// Capability names are intentionally typed; arbitrary upstream tool names
/// cannot become routable write authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCapability {
    CapabilitiesInspection,
    KnownIdRead,
    Search,
    NodeKnowledge,
    Validation,
    Comparison,
    WorkflowDraftWrite,
    Lifecycle,
    Execution,
    CredentialMetadata,
    DataTables,
    Audit,
    VersionHistory,
}

impl From<OperationIntent> for ProviderCapability {
    fn from(intent: OperationIntent) -> Self {
        match intent {
            OperationIntent::CapabilitiesInspection => Self::CapabilitiesInspection,
            OperationIntent::KnownIdRead => Self::KnownIdRead,
            OperationIntent::Search => Self::Search,
            OperationIntent::NodeKnowledge => Self::NodeKnowledge,
            OperationIntent::Validation => Self::Validation,
            OperationIntent::Comparison => Self::Comparison,
            OperationIntent::WorkflowDraftWrite => Self::WorkflowDraftWrite,
            OperationIntent::Lifecycle => Self::Lifecycle,
            OperationIntent::Execution => Self::Execution,
            OperationIntent::CredentialMetadata => Self::CredentialMetadata,
            OperationIntent::DataTables => Self::DataTables,
            OperationIntent::Audit => Self::Audit,
            OperationIntent::VersionHistory => Self::VersionHistory,
        }
    }
}

/// Capability snapshot supplied by a trusted discovery layer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub typed_rest: BTreeSet<ProviderCapability>,
    pub local_mcp: BTreeSet<ProviderCapability>,
    pub official_mcp: BTreeSet<ProviderCapability>,
}

impl CapabilitySnapshot {
    #[must_use]
    pub fn with(mut self, provider: Provider, capability: ProviderCapability) -> Self {
        self.capabilities_mut(provider).insert(capability);
        self
    }

    #[must_use]
    pub fn supports(&self, provider: Provider, capability: ProviderCapability) -> bool {
        self.capabilities(provider).contains(&capability)
    }

    const fn capabilities(&self, provider: Provider) -> &BTreeSet<ProviderCapability> {
        match provider {
            Provider::TypedRest => &self.typed_rest,
            Provider::LocalMcp => &self.local_mcp,
            Provider::OfficialMcp => &self.official_mcp,
        }
    }

    const fn capabilities_mut(&mut self, provider: Provider) -> &mut BTreeSet<ProviderCapability> {
        match provider {
            Provider::TypedRest => &mut self.typed_rest,
            Provider::LocalMcp => &mut self.local_mcp,
            Provider::OfficialMcp => &mut self.official_mcp,
        }
    }
}

/// Explicit reason for selecting a fallback provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackReason {
    PreferredCapabilityUnavailable,
    CapabilityDrift,
}

/// Redaction-safe provider route/receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRoute {
    pub operation: OperationIntent,
    pub target_server: ServerId,
    pub preferred: Provider,
    pub selected: Provider,
    pub fallback: Option<FallbackReason>,
}

/// Stable provider routing error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteErrorCode {
    TargetRequired,
    TargetMustBeInstance,
    TargetMustBeExactResource,
    TargetMustBeWorkflow,
    LocalTargetRequired,
    ProviderUnavailable,
    CapabilityUnavailable,
    UnknownWriteCapability,
    FallbackNotEquivalent,
}

/// Router error carrying no provider payload or tool name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteError {
    code: RouteErrorCode,
}

impl RouteError {
    const fn new(code: RouteErrorCode) -> Self {
        Self { code }
    }

    #[must_use]
    pub const fn code(self) -> RouteErrorCode {
        self.code
    }
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.code {
            RouteErrorCode::TargetRequired => "target_required",
            RouteErrorCode::TargetMustBeInstance => "target_must_be_instance",
            RouteErrorCode::TargetMustBeExactResource => "target_must_be_exact_resource",
            RouteErrorCode::TargetMustBeWorkflow => "target_must_be_workflow",
            RouteErrorCode::LocalTargetRequired => "local_target_required",
            RouteErrorCode::ProviderUnavailable => "provider_unavailable",
            RouteErrorCode::CapabilityUnavailable => "capability_unavailable",
            RouteErrorCode::UnknownWriteCapability => "unknown_write_capability",
            RouteErrorCode::FallbackNotEquivalent => "fallback_not_equivalent",
        })
    }
}

impl std::error::Error for RouteError {}

/// Deterministic provider router. It only consumes typed capability snapshots.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProviderRouter;

impl ProviderRouter {
    /// Select the preferred provider or an explicitly reported equivalent
    /// fallback. Missing write capability always fails closed.
    pub fn route(
        operation: OperationIntent,
        target: Option<&ResolvedTarget>,
        capabilities: &CapabilitySnapshot,
    ) -> Result<ProviderRoute, RouteError> {
        let (preferred, fallback) = operation.preferred_and_fallback();
        let target = target.ok_or_else(|| RouteError::new(RouteErrorCode::TargetRequired))?;
        let target_server = target.server;
        Self::validate_target(operation, target)?;

        if preferred == Provider::LocalMcp && !target_server.is_local() {
            return Err(RouteError::new(RouteErrorCode::LocalTargetRequired));
        }
        if preferred != Provider::LocalMcp && target_server.is_local() {
            return Err(RouteError::new(RouteErrorCode::TargetMustBeInstance));
        }

        let capability = ProviderCapability::from(operation);
        if capabilities.supports(preferred, capability) {
            return Ok(ProviderRoute {
                operation,
                target_server,
                preferred,
                selected: preferred,
                fallback: None,
            });
        }

        let Some(fallback) = fallback else {
            return Err(if operation.is_write() {
                RouteError::new(RouteErrorCode::UnknownWriteCapability)
            } else {
                RouteError::new(RouteErrorCode::CapabilityUnavailable)
            });
        };
        if (fallback == Provider::LocalMcp) != target_server.is_local() {
            return Err(RouteError::new(RouteErrorCode::FallbackNotEquivalent));
        }
        if !capabilities.supports(fallback, capability) {
            return Err(if operation.is_write() {
                RouteError::new(RouteErrorCode::UnknownWriteCapability)
            } else {
                RouteError::new(RouteErrorCode::CapabilityUnavailable)
            });
        }
        Ok(ProviderRoute {
            operation,
            target_server,
            preferred,
            selected: fallback,
            fallback: Some(FallbackReason::PreferredCapabilityUnavailable),
        })
    }

    fn validate_target(
        operation: OperationIntent,
        target: &ResolvedTarget,
    ) -> Result<(), RouteError> {
        if matches!(
            operation,
            OperationIntent::WorkflowDraftWrite | OperationIntent::Lifecycle
        ) && target.kind != ResourceKind::Workflow
        {
            return Err(RouteError::new(RouteErrorCode::TargetMustBeWorkflow));
        }
        if operation == OperationIntent::KnownIdRead && target.kind == ResourceKind::Instance {
            return Err(RouteError::new(RouteErrorCode::TargetMustBeExactResource));
        }
        if matches!(
            operation,
            OperationIntent::NodeKnowledge | OperationIntent::Validation
        ) && target.kind != ResourceKind::LocalNode
            && target.kind != ResourceKind::LocalTemplate
            && target.server != ServerId::Local
        {
            return Err(RouteError::new(RouteErrorCode::LocalTargetRequired));
        }
        Ok(())
    }
}

fn validate_id(value: &str) -> Result<(), TargetResolveError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
        return Err(TargetResolveError::new(
            TargetResolveCode::InvalidIdentifier,
        ));
    }
    Ok(())
}

fn validate_name(value: &str) -> Result<(), TargetResolveError> {
    if value.is_empty() || value.len() > MAX_NAME_BYTES || value.chars().any(char::is_control) {
        return Err(TargetResolveError::new(
            TargetResolveCode::InvalidIdentifier,
        ));
    }
    Ok(())
}

fn encode_segment(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

fn decode_segment(value: &str) -> Result<String, TargetResolveError> {
    if value.is_empty() {
        return Err(TargetResolveError::new(
            TargetResolveCode::InvalidResourceUri,
        ));
    }
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%' {
            let valid_escape = index + 2 < bytes.len()
                && bytes[index + 1].is_ascii_hexdigit()
                && bytes[index + 2].is_ascii_hexdigit();
            if !valid_escape {
                return Err(TargetResolveError::new(
                    TargetResolveCode::InvalidResourceUri,
                ));
            }
        }
    }
    let decoded = percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| TargetResolveError::new(TargetResolveCode::InvalidResourceUri))?
        .into_owned();
    validate_id(&decoded)?;
    Ok(decoded)
}

fn bounded_candidates(candidates: Vec<TargetCandidate>) -> (Vec<TargetCandidate>, bool) {
    let truncated = candidates.len() > MAX_TARGET_CANDIDATES;
    (
        candidates.into_iter().take(MAX_TARGET_CANDIDATES).collect(),
        truncated,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workflow(server: ServerId, id: &str) -> WorkflowIdProvenance {
        WorkflowIdProvenance::new(server, id).expect("valid workflow provenance")
    }

    fn execution(server: ServerId, workflow_id: &str, execution_id: &str) -> ExecutionIdProvenance {
        ExecutionIdProvenance::new(server, workflow_id, execution_id)
            .expect("valid execution provenance")
    }

    fn target(query: TargetQuery) -> ResolvedTarget {
        match TargetResolver::resolve(&query).expect("target should resolve") {
            TargetResolution::Resolved(target) => target,
            TargetResolution::Ambiguous { .. } => panic!("target should not be ambiguous"),
        }
    }

    #[test]
    fn explicit_server_resolves_instance() {
        let resolved = target(TargetQuery::explicit_server(ServerId::Eec));
        assert_eq!(resolved.resource_uri.as_str(), "fwc-n8n://eec");
        assert_eq!(resolved.kind, ResourceKind::Instance);
    }

    #[test]
    fn confirmed_project_mapping_resolves_project() {
        let mapping = ConfirmedProjectMapping::new(ServerId::Hetzner, "project-7").unwrap();
        let resolved = target(TargetQuery {
            project_mapping: Some(mapping),
            ..TargetQuery::default()
        });
        assert_eq!(
            resolved.resource_uri.as_str(),
            "fwc-n8n://hetzner/projects/project%2D7"
        );
    }

    #[test]
    fn workflow_and_execution_provenance_resolve_exact_resources() {
        let workflow_target = target(TargetQuery {
            workflow_provenance: Some(workflow(ServerId::Eec, "wf-1")),
            ..TargetQuery::default()
        });
        assert_eq!(workflow_target.kind, ResourceKind::Workflow);

        let execution_target = target(TargetQuery {
            execution_provenance: Some(execution(ServerId::Eec, "wf-1", "run-2")),
            ..TargetQuery::default()
        });
        assert_eq!(execution_target.kind, ResourceKind::Execution);
        assert_eq!(execution_target.server, ServerId::Eec);

        let combined_target = target(TargetQuery {
            server: Some(ServerId::Eec),
            project_mapping: Some(
                ConfirmedProjectMapping::new(ServerId::Eec, "project-1").unwrap(),
            ),
            execution_provenance: Some(execution(ServerId::Eec, "wf-1", "run-2")),
            ..TargetQuery::default()
        });
        assert_eq!(combined_target.kind, ResourceKind::Execution);
        assert_eq!(
            combined_target.resource_uri.as_str(),
            "fwc-n8n://eec/workflows/wf%2D1/executions/run%2D2"
        );
    }

    #[test]
    fn name_only_never_resolves() {
        let error = TargetResolver::resolve(&TargetQuery {
            workflow_name: Some("daily".into()),
            candidates: vec![TargetCandidate::new(ServerId::Eec, "wf-1", "daily").unwrap()],
            ..TargetQuery::default()
        })
        .unwrap_err();
        assert_eq!(error.code(), TargetResolveCode::NameOnlyTarget);
    }

    #[test]
    fn ambiguous_name_returns_bounded_candidates() {
        let query = TargetQuery::explicit_server(ServerId::Eec).with_candidates(
            (0..10)
                .map(|index| {
                    TargetCandidate::new(ServerId::Eec, format!("wf-{index}"), "daily").unwrap()
                })
                .collect(),
        );
        let query = TargetQuery {
            workflow_name: Some("daily".into()),
            ..query
        };
        let result = TargetResolver::resolve(&query).unwrap();
        match result {
            TargetResolution::Ambiguous {
                candidates,
                truncated,
            } => {
                assert_eq!(candidates.len(), MAX_TARGET_CANDIDATES);
                assert!(truncated);
            }
            TargetResolution::Resolved(_) => panic!("ambiguous name must not resolve"),
        }
    }

    #[test]
    fn cross_server_name_collision_is_explicit() {
        let query = TargetQuery {
            workflow_name: Some("daily".into()),
            candidates: vec![
                TargetCandidate::new(ServerId::Eec, "wf-eec", "daily").unwrap(),
                TargetCandidate::new(ServerId::Hetzner, "wf-hetzner", "daily").unwrap(),
            ],
            server: Some(ServerId::Eec),
            ..TargetQuery::default()
        };
        // The explicit server narrows the search and is therefore safe.
        assert!(matches!(
            TargetResolver::resolve(&query),
            Ok(TargetResolution::Resolved(_))
        ));

        let query = TargetQuery {
            workflow_name: Some("daily".into()),
            candidates: vec![
                TargetCandidate::new(ServerId::Eec, "wf-eec", "daily").unwrap(),
                TargetCandidate::new(ServerId::Hetzner, "wf-hetzner", "daily").unwrap(),
            ],
            candidate_servers: vec![ServerId::Eec, ServerId::Hetzner],
            ..TargetQuery::default()
        };
        let error = TargetResolver::resolve(&query).unwrap_err();
        assert_eq!(error.code(), TargetResolveCode::CrossServerCollision);
    }

    #[test]
    fn legacy_requires_explicit_opt_in() {
        let query = TargetQuery::explicit_server(ServerId::Legacy);
        assert_eq!(
            TargetResolver::resolve(&query).unwrap_err().code(),
            TargetResolveCode::LegacyOptInRequired
        );
        let resolved = target(query.with_legacy_opt_in());
        assert_eq!(resolved.server, ServerId::Legacy);
    }

    #[test]
    fn bounded_search_preserves_legacy_opt_in_and_rejects_local_server() {
        let legacy_query = TargetQuery {
            workflow_name: Some("daily".into()),
            candidate_servers: vec![ServerId::Legacy],
            candidates: vec![TargetCandidate::new(ServerId::Legacy, "wf-1", "daily").unwrap()],
            ..TargetQuery::default()
        };
        assert_eq!(
            TargetResolver::resolve(&legacy_query).unwrap_err().code(),
            TargetResolveCode::LegacyOptInRequired
        );
        assert!(matches!(
            TargetResolver::resolve(&TargetQuery {
                legacy_opt_in: true,
                ..legacy_query
            }),
            Ok(TargetResolution::Ambiguous { .. })
        ));

        let local_query = TargetQuery {
            workflow_name: Some("daily".into()),
            candidate_servers: vec![ServerId::Local],
            candidates: vec![TargetCandidate::new(ServerId::Local, "wf-1", "daily").unwrap()],
            ..TargetQuery::default()
        };
        assert_eq!(
            TargetResolver::resolve(&local_query).unwrap_err().code(),
            TargetResolveCode::InvalidServer
        );
    }

    #[test]
    fn conflicting_server_evidence_fails_closed() {
        let query = TargetQuery {
            server: Some(ServerId::Eec),
            workflow_provenance: Some(workflow(ServerId::Hetzner, "wf-1")),
            ..TargetQuery::default()
        };
        assert_eq!(
            TargetResolver::resolve(&query).unwrap_err().code(),
            TargetResolveCode::ConflictingEvidence
        );

        let query = TargetQuery {
            workflow_provenance: Some(workflow(ServerId::Eec, "wf-1")),
            resource_uri: Some(CanonicalResourceUri::workflow(ServerId::Eec, "wf-2").unwrap()),
            ..TargetQuery::default()
        };
        assert_eq!(
            TargetResolver::resolve(&query).unwrap_err().code(),
            TargetResolveCode::ConflictingEvidence
        );
    }

    #[test]
    fn canonical_uri_is_validated_and_debug_redacts_identifier() {
        let uri = CanonicalResourceUri::parse("fwc-n8n://eec/workflows/wf%2D1").unwrap();
        assert_eq!(uri.as_str(), "fwc-n8n://eec/workflows/wf%2D1");
        let debug = format!("{uri:?}");
        assert!(!debug.contains("wf"));
        assert!(CanonicalResourceUri::parse("https://eec/workflows/wf-1").is_err());
        assert!(CanonicalResourceUri::parse("fwc-n8n://eec/workflows/wf%ZZ").is_err());
        assert!(CanonicalResourceUri::parse("fwc-n8n://local/credentials/cred%2D1").is_err());
        assert!(CanonicalResourceUri::parse("fwc-n8n://local/data-tables/table%2D1").is_err());
        assert!(CanonicalResourceUri::parse("fwc-n8n://local/nodes/n8n%2Dnodelang").is_ok());
    }

    #[test]
    fn typed_rest_is_preferred_for_known_id_reads() {
        let target = target(TargetQuery {
            workflow_provenance: Some(workflow(ServerId::Eec, "wf-1")),
            ..TargetQuery::default()
        });
        let capabilities = CapabilitySnapshot::default()
            .with(Provider::TypedRest, ProviderCapability::KnownIdRead);
        let route =
            ProviderRouter::route(OperationIntent::KnownIdRead, Some(&target), &capabilities)
                .unwrap();
        assert_eq!(route.selected, Provider::TypedRest);
        assert_eq!(route.fallback, None);
    }

    #[test]
    fn server_scoped_search_routes_without_guessing_a_resource() {
        let target = target(TargetQuery::explicit_server(ServerId::Hetzner));
        let capabilities =
            CapabilitySnapshot::default().with(Provider::TypedRest, ProviderCapability::Search);
        let route =
            ProviderRouter::route(OperationIntent::Search, Some(&target), &capabilities).unwrap();
        assert_eq!(route.target_server, ServerId::Hetzner);
        assert_eq!(route.selected, Provider::TypedRest);
    }

    #[test]
    fn fallback_is_reported_explicitly() {
        let target = target(TargetQuery {
            workflow_provenance: Some(workflow(ServerId::Eec, "wf-1")),
            ..TargetQuery::default()
        });
        let capabilities = CapabilitySnapshot::default()
            .with(Provider::OfficialMcp, ProviderCapability::KnownIdRead);
        let route =
            ProviderRouter::route(OperationIntent::KnownIdRead, Some(&target), &capabilities)
                .unwrap();
        assert_eq!(route.preferred, Provider::TypedRest);
        assert_eq!(route.selected, Provider::OfficialMcp);
        assert_eq!(
            route.fallback,
            Some(FallbackReason::PreferredCapabilityUnavailable)
        );
    }

    #[test]
    fn capability_drift_denies_unknown_write_tool() {
        let target = target(TargetQuery {
            workflow_provenance: Some(workflow(ServerId::Eec, "wf-1")),
            ..TargetQuery::default()
        });
        let error = ProviderRouter::route(
            OperationIntent::WorkflowDraftWrite,
            Some(&target),
            &CapabilitySnapshot::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), RouteErrorCode::UnknownWriteCapability);
    }

    #[test]
    fn local_knowledge_requires_local_target() {
        let target = target(TargetQuery::explicit_server(ServerId::Eec));
        let capabilities = CapabilitySnapshot::default()
            .with(Provider::LocalMcp, ProviderCapability::NodeKnowledge);
        let error =
            ProviderRouter::route(OperationIntent::NodeKnowledge, Some(&target), &capabilities)
                .unwrap_err();
        assert_eq!(error.code(), RouteErrorCode::LocalTargetRequired);
    }
}
