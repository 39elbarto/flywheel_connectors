//! n8n API types.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use serde_json::Value;

/// A required provider field that may explicitly contain JSON `null`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequiredNullable<T> {
    Null,
    Value(T),
}

impl<T> RequiredNullable<T> {
    #[must_use]
    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Null => None,
            Self::Value(value) => Some(value),
        }
    }
}

impl<'de, T> Deserialize<'de> for RequiredNullable<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.is_null() {
            Ok(Self::Null)
        } else {
            serde_json::from_value(value)
                .map(Self::Value)
                .map_err(serde::de::Error::custom)
        }
    }
}

/// Presence-aware provider value used for `activeVersionId`.
///
/// n8n can omit the field, return JSON `null`, or return a version ID. Those
/// states are kept distinct so the connector never infers draft or published
/// state from an absent provider field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ActiveVersionId {
    #[default]
    Missing,
    Null,
    Value(String),
}

impl ActiveVersionId {
    #[must_use]
    pub const fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }

    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::Missing | Self::Null)
    }
}

impl PartialEq<Option<String>> for ActiveVersionId {
    fn eq(&self, other: &Option<String>) -> bool {
        matches!((self, other), (Self::Null | Self::Missing, None))
            || matches!((self, other), (Self::Value(value), Some(expected)) if value == expected)
    }
}

impl<'de> Deserialize<'de> for ActiveVersionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(value) => Ok(Self::Value(value)),
            None => Ok(Self::Null),
        }
    }
}

impl Serialize for ActiveVersionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Missing => serializer.serialize_unit(),
            Self::Null => serializer.serialize_none(),
            Self::Value(value) => serializer.serialize_str(value),
        }
    }
}

/// Deserialize-only provider workflow DTO.
#[derive(Debug, Clone, Deserialize)]
pub struct Workflow {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default, rename = "versionId")]
    pub version_id: Option<String>,
    #[serde(default, rename = "activeVersionId")]
    pub active_version_id: ActiveVersionId,
    #[serde(default, rename = "isArchived")]
    pub is_archived: Option<bool>,
    #[serde(default, rename = "projectId")]
    pub project_id: Option<String>,
    #[serde(default, rename = "parentFolderId")]
    pub parent_folder_id: Option<String>,
    #[serde(default, rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(default, rename = "updatedAt")]
    pub updated_at: Option<String>,
    /// The list endpoint may include workflow settings.  Keep the raw value
    /// process-local so the MCP availability planner can inspect the one
    /// allow-listed flag without returning arbitrary provider settings.
    #[serde(default)]
    pub settings: Option<Value>,
    #[serde(default)]
    pub tags: Option<Vec<Tag>>,
}

/// Strict deserialize-only DTO for `GET /workflows/{id}`.
///
/// Unlike the compact list DTO, every provider state field needed to
/// distinguish the editable draft from the published graph is required.
/// Raw graph values never cross the connector output boundary.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowDetail {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    pub active: bool,
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "activeVersionId")]
    pub active_version_id: RequiredNullable<String>,
    #[serde(rename = "isArchived")]
    pub is_archived: bool,
    #[serde(default, rename = "projectId")]
    pub project_id: Option<String>,
    #[serde(default, rename = "parentFolderId")]
    pub parent_folder_id: Option<String>,
    #[serde(default, rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(default, rename = "updatedAt")]
    pub updated_at: Option<String>,
    pub nodes: Vec<Value>,
    pub connections: Value,
    #[serde(default)]
    pub settings: Option<Value>,
    #[serde(default, rename = "staticData")]
    pub static_data: Option<Value>,
    #[serde(default, rename = "pinData")]
    pub pin_data: Option<Value>,
    #[serde(rename = "activeVersion")]
    pub active_version: RequiredNullable<WorkflowVersion>,
    #[serde(default)]
    pub tags: Option<Vec<Tag>>,
}

/// Strict provider-published workflow version nested in a workflow detail.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowVersion {
    #[serde(rename = "versionId")]
    pub version_id: String,
    pub nodes: Vec<Value>,
    pub connections: Value,
}

/// Typed graph supplied to a guarded draft mutation.  Lifecycle fields are
/// deliberately absent: callers cannot request publish, activation, or
/// archival through this packet.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDraftGraph {
    pub nodes: Vec<Value>,
    pub connections: Value,
    #[serde(default)]
    pub settings: Option<Value>,
    #[serde(default, rename = "staticData")]
    pub static_data: Option<Value>,
    #[serde(default, rename = "pinData")]
    pub pin_data: Option<Value>,
}

/// Version/lifecycle precondition attached to a draft mutation approval.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftMutationPrecondition {
    #[serde(default, rename = "versionId")]
    pub version_id: Option<String>,
    #[serde(default, rename = "activeVersionId")]
    pub active_version_id: Option<RequiredNullable<String>>,
    #[serde(default)]
    pub active: Option<bool>,
    #[serde(default, rename = "isArchived")]
    pub is_archived: Option<bool>,
    #[serde(default, rename = "stateDigest")]
    pub state_digest: Option<String>,
}

/// One-use approval and idempotency binding for a draft mutation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftMutationGuard {
    #[serde(rename = "approvalRef")]
    pub approval_ref: String,
    #[serde(rename = "idempotencyKey")]
    pub idempotency_key: String,
    #[serde(default)]
    pub precondition: DraftMutationPrecondition,
}

/// Common typed input for `create_draft` and `update_draft`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDraftMutationInput {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "project_id")]
    pub project_id: Option<String>,
    #[serde(default, rename = "parent_folder_id")]
    pub parent_folder_id: Option<String>,
    pub graph: WorkflowDraftGraph,
    pub guard: DraftMutationGuard,
}

/// The only lifecycle actions admitted by the first typed lifecycle packet.
/// Archive/restore and activation remain separate, deferred operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowLifecycleAction {
    Publish,
    Unpublish,
}

impl WorkflowLifecycleAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Publish => "publish",
            Self::Unpublish => "unpublish",
        }
    }
}

/// Exact current state required before a lifecycle mutation may be attempted.
/// `activeVersionId` is intentionally presence-aware: explicit JSON `null` is
/// distinct from a missing provider field.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLifecyclePrecondition {
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "activeVersionId")]
    pub active_version_id: RequiredNullable<String>,
    pub active: bool,
    #[serde(rename = "isArchived")]
    pub is_archived: bool,
    #[serde(rename = "stateDigest")]
    pub state_digest: String,
}

/// Interactive approval and idempotency binding for a lifecycle mutation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLifecycleGuard {
    #[serde(rename = "approvalRef")]
    pub approval_ref: String,
    #[serde(rename = "idempotencyKey")]
    pub idempotency_key: String,
    pub precondition: WorkflowLifecyclePrecondition,
}

/// Typed input for `n8n.workflows.lifecycle`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowLifecycleInput {
    pub id: String,
    pub action: WorkflowLifecycleAction,
    /// Optional published version selected by `publish`.  When omitted, the
    /// provider chooses the current published version and the independent
    /// readback binds success to that returned version.
    #[serde(default, rename = "versionId")]
    pub version_id: Option<String>,
    pub guard: WorkflowLifecycleGuard,
}

/// Deserialize-only provider workflow tag DTO.
#[derive(Debug, Clone, Deserialize)]
pub struct Tag {
    pub id: Option<String>,
    pub name: Option<String>,
}

/// Deserialize-only provider execution DTO. Provider payload/data fields are
/// intentionally not represented here.
#[derive(Debug, Clone, Deserialize)]
pub struct Execution {
    pub id: String,
    #[serde(default)]
    pub finished: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default, rename = "startedAt")]
    pub started_at: Option<String>,
    #[serde(default, rename = "stoppedAt")]
    pub stopped_at: Option<String>,
    #[serde(default, rename = "workflowId")]
    pub workflow_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, rename = "retryOf")]
    pub retry_of: Option<String>,
    #[serde(default, rename = "retrySuccessId")]
    pub retry_success_id: Option<String>,
    #[serde(default, rename = "waitTill")]
    pub wait_till: Option<String>,
}

/// Deserialize-only provider project DTO. Unknown provider fields are
/// intentionally ignored before the runtime view is serialized.
#[derive(Debug, Clone, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    #[serde(default, rename = "type")]
    pub project_type: Option<String>,
}

/// Deserialize-only credential metadata returned by n8n's credentials list
/// endpoint. Secret/configuration fields are intentionally not represented.
#[derive(Debug, Clone, Deserialize)]
pub struct CredentialMetadata {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Deserialize-only provider parent-folder reference used by the list endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct FolderParent {
    pub id: String,
}

/// Deserialize-only compact folder DTO returned by the list endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct FolderListItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "parentFolder")]
    pub parent_folder: RequiredNullable<FolderParent>,
}

/// Deserialize-only detailed folder DTO returned by the get endpoint.
/// Every field is required by the provider contract; `parentFolderId` may be
/// explicitly null for a root folder.
#[derive(Debug, Clone, Deserialize)]
pub struct Folder {
    pub id: String,
    pub name: String,
    #[serde(rename = "parentFolderId")]
    pub parent_folder_id: RequiredNullable<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "totalSubFolders")]
    pub total_sub_folders: u64,
    #[serde(rename = "totalWorkflows")]
    pub total_workflows: u64,
}

/// n8n paginated list response wrapper.
#[derive(Debug, Clone, Deserialize)]
pub struct ListResponse<T> {
    pub data: Vec<T>,
    #[serde(default, rename = "nextCursor")]
    pub next_cursor: Option<String>,
}

/// Typed n8n workflow list response.
pub type WorkflowListResponse = ListResponse<Workflow>;

/// Typed n8n execution list response.
pub type ExecutionListResponse = ListResponse<Execution>;

/// Typed n8n project list response.
pub type ProjectListResponse = ListResponse<Project>;

/// Typed n8n tag list response.
pub type TagListResponse = ListResponse<TagRecord>;

/// Typed n8n credential metadata list response.
pub type CredentialListResponse = ListResponse<CredentialMetadata>;

/// Typed n8n folder list response wrapper.
#[derive(Debug, Clone, Deserialize)]
pub struct FolderListResponse {
    pub count: u64,
    pub data: Vec<FolderListItem>,
}

/// Serialize-only allowlisted page envelope returned by connector list operations.
#[derive(Debug, Clone, Serialize)]
pub struct ListView<T> {
    pub data: Vec<T>,
    #[serde(rename = "nextCursor", skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Serialize-only allowlisted workflow view returned by connector operations.
#[derive(Debug, Clone, Serialize)]
pub struct WorkflowView {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub active: Option<bool>,
    #[serde(rename = "versionId")]
    pub version_id: Option<String>,
    #[serde(
        rename = "activeVersionId",
        skip_serializing_if = "ActiveVersionId::is_missing"
    )]
    pub active_version_id: ActiveVersionId,
    #[serde(rename = "isArchived")]
    pub is_archived: Option<bool>,
    #[serde(rename = "projectId")]
    pub project_id: Option<String>,
    #[serde(rename = "parentFolderId")]
    pub parent_folder_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
    #[serde(rename = "availableInMCP", skip_serializing_if = "Option::is_none")]
    pub available_in_mcp: Option<bool>,
    pub tags: Option<Vec<TagView>>,
}

/// Serialize-only graph summary. Raw nodes, connections, Code source, and
/// credential references remain inside the connector process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkflowGraphSummary {
    #[serde(rename = "versionId")]
    pub version_id: String,
    #[serde(rename = "graphDigest")]
    pub graph_digest: String,
}

/// Serialize-only normalized state returned by `n8n.workflows.get`.
#[derive(Debug, Clone, Serialize)]
pub struct WorkflowStateView {
    pub id: String,
    pub name: Option<String>,
    #[serde(rename = "projectId")]
    pub project_id: Option<String>,
    #[serde(rename = "folderId")]
    pub folder_id: Option<String>,
    #[serde(rename = "versionId")]
    pub version_id: String,
    pub active: bool,
    #[serde(rename = "activeVersionId")]
    pub active_version_id: Option<String>,
    #[serde(rename = "isArchived")]
    pub is_archived: bool,
    pub draft: WorkflowGraphSummary,
    pub published: Option<WorkflowGraphSummary>,
    #[serde(rename = "stateDigest")]
    pub state_digest: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
}

/// Serialize-only allowlisted workflow tag view.
#[derive(Debug, Clone, Serialize)]
pub struct TagView {
    pub id: Option<String>,
    pub name: Option<String>,
}

/// Serialize-only allowlisted execution view. Execution payload data is not
/// part of this type.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionView {
    pub id: String,
    pub finished: Option<bool>,
    pub mode: Option<String>,
    #[serde(rename = "startedAt")]
    pub started_at: Option<String>,
    #[serde(rename = "stoppedAt")]
    pub stopped_at: Option<String>,
    #[serde(rename = "workflowId")]
    pub workflow_id: Option<String>,
    pub status: Option<String>,
    #[serde(rename = "retryOf")]
    pub retry_of: Option<String>,
    #[serde(rename = "retrySuccessId")]
    pub retry_success_id: Option<String>,
    #[serde(rename = "waitTill")]
    pub wait_till: Option<String>,
}

/// Serialize-only allowlisted project view returned by the connector.
#[derive(Debug, Clone, Serialize)]
pub struct ProjectView {
    pub id: String,
    pub name: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub project_type: Option<String>,
}

/// Serialize-only safe credential metadata view returned by the connector.
#[derive(Debug, Clone, Serialize)]
pub struct CredentialMetadataView {
    #[serde(rename = "resourceUri")]
    pub resource_uri: String,
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Deserialize-only provider tag DTO for the low-level tags endpoint.
/// Provider timestamps and unknown metadata are intentionally discarded.
#[derive(Debug, Clone, Deserialize)]
pub struct TagRecord {
    pub id: String,
    pub name: String,
}

/// Serialize-only compact tag view returned by `n8n.tags.list`.
#[derive(Debug, Clone, Serialize)]
pub struct TagRecordView {
    pub id: String,
    pub name: String,
}

/// Serialize-only folder item view returned by `n8n.folders.list`.
#[derive(Debug, Clone, Serialize)]
pub struct FolderListItemView {
    #[serde(rename = "resourceUri")]
    pub resource_uri: String,
    pub id: String,
    pub name: String,
    #[serde(rename = "parentFolderId")]
    pub parent_folder_id: Option<String>,
}

/// Serialize-only detailed folder view returned by `n8n.folders.get`.
#[derive(Debug, Clone, Serialize)]
pub struct FolderView {
    #[serde(rename = "resourceUri")]
    pub resource_uri: String,
    pub id: String,
    pub name: String,
    #[serde(rename = "parentFolderId")]
    pub parent_folder_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "totalSubFolders")]
    pub total_sub_folders: u64,
    #[serde(rename = "totalWorkflows")]
    pub total_workflows: u64,
}

/// Serialize-only folder list page returned by `n8n.folders.list`.
#[derive(Debug, Clone, Serialize)]
pub struct FolderListView {
    pub count: u64,
    pub data: Vec<FolderListItemView>,
}

impl Workflow {
    /// Return only the provider's explicit MCP availability flag.
    #[must_use]
    pub fn available_in_mcp(&self) -> Option<bool> {
        self.settings
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|settings| settings.get("availableInMCP"))
            .and_then(Value::as_bool)
    }

    #[must_use]
    pub fn into_view(self) -> WorkflowView {
        let available_in_mcp = self.available_in_mcp();
        WorkflowView {
            id: self.id,
            name: self.name,
            description: self.description,
            active: self.active,
            version_id: self.version_id,
            active_version_id: self.active_version_id,
            is_archived: self.is_archived,
            project_id: self.project_id,
            parent_folder_id: self.parent_folder_id,
            created_at: self.created_at,
            updated_at: self.updated_at,
            available_in_mcp,
            tags: self
                .tags
                .map(|tags| tags.into_iter().map(Tag::into_view).collect::<Vec<_>>()),
        }
    }
}

impl WorkflowDetail {
    /// Return only the provider's explicit MCP availability flag.
    #[must_use]
    pub fn available_in_mcp(&self) -> Option<bool> {
        self.settings
            .as_ref()
            .and_then(Value::as_object)
            .and_then(|settings| settings.get("availableInMCP"))
            .and_then(Value::as_bool)
    }
}

impl Tag {
    #[must_use]
    pub fn into_view(self) -> TagView {
        TagView {
            id: self.id,
            name: self.name,
        }
    }
}

impl Execution {
    #[must_use]
    pub fn into_view(self) -> ExecutionView {
        ExecutionView {
            id: self.id,
            finished: self.finished,
            mode: self.mode,
            started_at: self.started_at,
            stopped_at: self.stopped_at,
            workflow_id: self.workflow_id,
            status: self.status,
            retry_of: self.retry_of,
            retry_success_id: self.retry_success_id,
            wait_till: self.wait_till,
        }
    }
}

impl Project {
    #[must_use]
    pub fn into_view(self) -> ProjectView {
        ProjectView {
            id: self.id,
            name: self.name,
            project_type: self.project_type,
        }
    }
}

impl CredentialMetadata {
    #[must_use]
    pub fn into_view(self, resource_uri: String) -> CredentialMetadataView {
        CredentialMetadataView {
            resource_uri,
            id: self.id,
            name: self.name,
            credential_type: self.credential_type,
        }
    }
}

impl TagRecord {
    #[must_use]
    pub fn into_view(self) -> TagRecordView {
        TagRecordView {
            id: self.id,
            name: self.name,
        }
    }
}

impl FolderListItem {
    #[must_use]
    pub fn into_view(self, resource_uri: String) -> FolderListItemView {
        FolderListItemView {
            resource_uri,
            id: self.id,
            name: self.name,
            parent_folder_id: self.parent_folder.into_option().map(|parent| parent.id),
        }
    }
}

impl Folder {
    #[must_use]
    pub fn into_view(self, resource_uri: String) -> FolderView {
        FolderView {
            resource_uri,
            id: self.id,
            name: self.name,
            parent_folder_id: self.parent_folder_id.into_option(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            total_sub_folders: self.total_sub_folders,
            total_workflows: self.total_workflows,
        }
    }
}

/// n8n API error response body.
///
/// n8n returns `{"message": "error description"}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message from n8n.
    pub message: Option<String>,
    /// Optional error code.
    pub code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn workflow_full_roundtrip() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "1001",
            "name": "Daily Report",
            "description": "A daily report",
            "active": true,
            "versionId": "version-1001",
            "activeVersionId": "version-1001",
            "isArchived": false,
            "projectId": "project-1",
            "parentFolderId": "folder-1",
            "createdAt": "2025-01-15T10:00:00.000Z",
            "updatedAt": "2025-02-20T14:30:00.000Z",
            "tags": [
                {"id": "t1", "name": "production"},
                {"id": "t2", "name": "reporting"},
            ]
        }))
        .unwrap();
        assert_eq!(w.id, "1001");
        assert_eq!(w.name, Some("Daily Report".into()));
        assert_eq!(w.description, Some("A daily report".into()));
        assert_eq!(w.active, Some(true));
        assert_eq!(w.version_id, Some("version-1001".into()));
        assert_eq!(w.active_version_id, Some("version-1001".into()));
        assert_eq!(w.is_archived, Some(false));
        assert_eq!(w.project_id, Some("project-1".into()));
        assert_eq!(w.parent_folder_id, Some("folder-1".into()));
        assert_eq!(w.created_at, Some("2025-01-15T10:00:00.000Z".into()));
        assert_eq!(w.updated_at, Some("2025-02-20T14:30:00.000Z".into()));
        let tags = w.tags.as_ref().unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].name, Some("production".into()));
        let re = serde_json::to_value(w.into_view()).unwrap();
        assert_eq!(re["name"], "Daily Report");
    }

    #[test]
    fn workflow_minimal() {
        let w: Workflow = serde_json::from_value(json!({"id": "42"})).unwrap();
        assert_eq!(w.id, "42");
        assert!(w.name.is_none());
        assert!(w.description.is_none());
        assert!(w.active.is_none());
        assert!(w.version_id.is_none());
        assert!(w.active_version_id.is_none());
        assert!(w.is_archived.is_none());
        assert!(w.project_id.is_none());
        assert!(w.parent_folder_id.is_none());
        assert!(w.created_at.is_none());
        assert!(w.updated_at.is_none());
        assert!(w.tags.is_none());
    }

    #[test]
    fn workflow_inactive() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "99",
            "name": "Disabled Workflow",
            "active": false,
        }))
        .unwrap();
        assert_eq!(w.active, Some(false));
    }

    #[test]
    fn workflow_extra_fields_ignored() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "1",
            "name": "Test",
            "unknown_field": "should be ignored",
            "nodes": [{"type": "n8n-nodes-base.start"}],
            "connections": {"Start": {"main": []}},
            "credentials": {"api": {"id": "secret-id"}},
            "code": "return secret",
            "pinData": {"Start": []},
        }))
        .unwrap();
        assert_eq!(w.id, "1");
        assert_eq!(w.name, Some("Test".into()));
        let serialized = serde_json::to_value(w.into_view()).unwrap();
        for field in ["nodes", "connections", "credentials", "code", "pinData"] {
            assert!(
                serialized.get(field).is_none(),
                "sensitive field leaked: {field}"
            );
        }
    }

    #[test]
    fn workflow_metadata_preserves_provider_state_without_inference() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "ambiguous-state",
            "active": false,
            "versionId": "draft-v3",
            "activeVersionId": "published-v2",
            "isArchived": true,
        }))
        .unwrap();
        assert_eq!(w.active, Some(false));
        assert_eq!(w.version_id, Some("draft-v3".into()));
        assert_eq!(w.active_version_id, Some("published-v2".into()));
        assert_eq!(w.is_archived, Some(true));
    }

    #[test]
    fn workflow_serialize_roundtrip() {
        let w = Workflow {
            id: "w1".into(),
            name: Some("My Workflow".into()),
            description: None,
            active: Some(true),
            version_id: None,
            active_version_id: ActiveVersionId::Missing,
            is_archived: None,
            project_id: None,
            parent_folder_id: None,
            created_at: None,
            updated_at: None,
            settings: Some(json!({"availableInMCP": true, "private": "discard"})),
            tags: Some(vec![Tag {
                id: Some("t1".into()),
                name: Some("dev".into()),
            }]),
        };
        let v = serde_json::to_value(w.into_view()).unwrap();
        assert_eq!(v["id"], "w1");
        assert_eq!(v["name"], "My Workflow");
        assert_eq!(v["active"], true);
        assert_eq!(v["availableInMCP"], true);
        assert!(v.get("private").is_none());
        assert_eq!(v["tags"][0]["name"], "dev");
    }

    #[test]
    fn tag_roundtrip() {
        let t: Tag = serde_json::from_value(json!({"id": "t1", "name": "production"})).unwrap();
        assert_eq!(t.id, Some("t1".into()));
        assert_eq!(t.name, Some("production".into()));
    }

    #[test]
    fn credential_metadata_projection_discards_provider_secrets() {
        let page: CredentialListResponse = serde_json::from_value(json!({
            "data": [{
                "id": "cred-1",
                "name": "GitHub",
                "type": "githubApi",
                "data": {"token": "marker.secret"},
                "authHeader": "marker.header",
                "config": {"password": "marker.config"},
                "shared": [{"role": "credential:owner", "id": "project-1"}]
            }],
            "nextCursor": null
        }))
        .unwrap();
        let output = serde_json::to_value(
            page.data[0]
                .clone()
                .into_view("fwc-n8n://eec/credentials/cred-1".into()),
        )
        .unwrap();
        assert_eq!(
            output,
            json!({
                "resourceUri": "fwc-n8n://eec/credentials/cred-1",
                "id": "cred-1",
                "name": "GitHub",
                "type": "githubApi"
            })
        );
        let serialized = serde_json::to_string(&output).unwrap();
        for marker in ["marker.secret", "marker.header", "marker.config", "shared"] {
            assert!(!serialized.contains(marker));
        }
    }

    #[test]
    fn tag_minimal() {
        let t: Tag = serde_json::from_value(json!({})).unwrap();
        assert!(t.id.is_none());
        assert!(t.name.is_none());
    }

    #[test]
    fn execution_full_roundtrip() {
        let e: Execution = serde_json::from_value(json!({
            "id": "50001",
            "finished": true,
            "mode": "trigger",
            "startedAt": "2025-03-01T08:00:00.000Z",
            "stoppedAt": "2025-03-01T08:00:05.000Z",
            "workflowId": "1001",
            "status": "success",
            "retryOf": null,
            "retrySuccessId": null,
            "waitTill": "2025-03-01T08:01:00.000Z",
        }))
        .unwrap();
        assert_eq!(e.id, "50001");
        assert_eq!(e.finished, Some(true));
        assert_eq!(e.mode, Some("trigger".into()));
        assert_eq!(e.started_at, Some("2025-03-01T08:00:00.000Z".into()));
        assert_eq!(e.stopped_at, Some("2025-03-01T08:00:05.000Z".into()));
        assert_eq!(e.workflow_id, Some("1001".into()));
        assert_eq!(e.status, Some("success".into()));
        assert_eq!(e.wait_till, Some("2025-03-01T08:01:00.000Z".into()));
        assert!(e.retry_of.is_none());
        assert!(e.retry_success_id.is_none());
    }

    #[test]
    fn execution_minimal() {
        let e: Execution = serde_json::from_value(json!({"id": "1"})).unwrap();
        assert_eq!(e.id, "1");
        assert!(e.finished.is_none());
        assert!(e.mode.is_none());
        assert!(e.started_at.is_none());
        assert!(e.workflow_id.is_none());
        assert!(e.status.is_none());
        assert!(e.wait_till.is_none());
    }

    #[test]
    fn execution_failed() {
        let e: Execution = serde_json::from_value(json!({
            "id": "50002",
            "finished": true,
            "mode": "manual",
            "status": "error",
            "workflowId": "1002",
        }))
        .unwrap();
        assert_eq!(e.status, Some("error".into()));
        assert_eq!(e.finished, Some(true));
    }

    #[test]
    fn execution_running() {
        let e: Execution = serde_json::from_value(json!({
            "id": "50003",
            "finished": false,
            "mode": "webhook",
            "status": "running",
        }))
        .unwrap();
        assert_eq!(e.finished, Some(false));
        assert_eq!(e.status, Some("running".into()));
    }

    #[test]
    fn execution_with_retry() {
        let e: Execution = serde_json::from_value(json!({
            "id": "50004",
            "finished": true,
            "retryOf": "50003",
            "retrySuccessId": "50004",
            "status": "success",
        }))
        .unwrap();
        assert_eq!(e.retry_of, Some("50003".into()));
        assert_eq!(e.retry_success_id, Some("50004".into()));
    }

    #[test]
    fn execution_extra_fields_ignored() {
        let e: Execution = serde_json::from_value(json!({
            "id": "1",
            "finished": true,
            "data": {"resultData": {}},
            "credentials": {"secret": "never-return"},
            "pinData": {"node": []},
            "unknown": 42,
        }))
        .unwrap();
        assert_eq!(e.id, "1");
        assert_eq!(e.finished, Some(true));
        let serialized = serde_json::to_value(e.into_view()).unwrap();
        assert!(serialized.get("data").is_none());
        assert!(serialized.get("credentials").is_none());
        assert!(serialized.get("pinData").is_none());
    }

    #[test]
    fn project_projection_allowlists_safe_fields() {
        let project: Project = serde_json::from_value(json!({
            "id": "project-1",
            "name": "Operations",
            "type": "team",
            "users": [{"id": "user-secret"}],
            "roles": ["owner"],
            "memberships": [{"credential": "secret"}],
            "credentials": {"api": "never-return"},
            "workflow": {"nodes": ["never-return"]},
            "unknownField": "marker.unknown",
        }))
        .unwrap();
        let serialized = serde_json::to_value(project.into_view()).unwrap();
        assert_eq!(serialized["id"], "project-1");
        assert_eq!(serialized["name"], "Operations");
        assert_eq!(serialized["type"], "team");
        for field in [
            "users",
            "roles",
            "memberships",
            "credentials",
            "workflow",
            "unknownField",
        ] {
            assert!(serialized.get(field).is_none(), "field leaked: {field}");
        }
        assert!(!serialized.to_string().contains("user-secret"));
        assert!(!serialized.to_string().contains("marker.unknown"));
    }

    #[test]
    fn project_type_is_omitted_when_provider_omits_it() {
        let project: Project = serde_json::from_value(json!({
            "id": "project-1",
            "name": "Personal",
        }))
        .unwrap();
        let serialized = serde_json::to_value(project.into_view()).unwrap();
        assert!(serialized.get("type").is_none());
    }

    #[test]
    fn tag_record_projection_discards_provider_metadata() {
        let tag: TagRecord = serde_json::from_value(json!({
            "id": "tag-1",
            "name": "production",
            "createdAt": "2025-01-01T00:00:00Z",
            "updatedAt": "2025-01-02T00:00:00Z",
            "users": [{"id": "marker.tag.users"}],
            "unknownField": "marker.tag.unknown",
        }))
        .unwrap();
        let serialized = serde_json::to_value(tag.into_view()).unwrap();
        assert_eq!(serialized["id"], "tag-1");
        assert_eq!(serialized["name"], "production");
        for field in ["createdAt", "updatedAt", "users", "unknownField"] {
            assert!(serialized.get(field).is_none(), "field leaked: {field}");
        }
        assert!(!serialized.to_string().contains("marker.tag"));
    }

    #[test]
    fn execution_serialize_roundtrip() {
        let e = Execution {
            id: "e1".into(),
            finished: Some(true),
            mode: Some("trigger".into()),
            started_at: Some("2025-01-01T00:00:00Z".into()),
            stopped_at: Some("2025-01-01T00:00:01Z".into()),
            workflow_id: Some("w1".into()),
            status: Some("success".into()),
            retry_of: None,
            retry_success_id: None,
            wait_till: None,
        };
        let v = serde_json::to_value(e.into_view()).unwrap();
        assert_eq!(v["id"], "e1");
        assert_eq!(v["finished"], true);
        assert_eq!(v["mode"], "trigger");
        assert_eq!(v["workflowId"], "w1");
    }

    #[test]
    fn list_response_workflows() {
        let lr: ListResponse<Workflow> = serde_json::from_value(json!({
            "data": [
                {"id": "1", "name": "WF1"},
                {"id": "2", "name": "WF2"},
            ],
            "nextCursor": "abc123",
        }))
        .unwrap();
        assert_eq!(lr.data.len(), 2);
        assert_eq!(lr.next_cursor, Some("abc123".into()));
    }

    #[test]
    fn list_response_empty() {
        let lr: ListResponse<Workflow> = serde_json::from_value(json!({
            "data": [],
        }))
        .unwrap();
        assert!(lr.data.is_empty());
        assert!(lr.next_cursor.is_none());
    }

    #[test]
    fn list_response_executions() {
        let lr: ListResponse<Execution> = serde_json::from_value(json!({
            "data": [
                {"id": "100", "finished": true},
            ],
        }))
        .unwrap();
        assert_eq!(lr.data.len(), 1);
        assert_eq!(lr.data[0].id, "100");
    }

    #[test]
    fn list_response_projects_preserves_cursor() {
        let lr: ProjectListResponse = serde_json::from_value(json!({
            "data": [{"id": "project-1", "name": "Operations", "type": "team"}],
            "nextCursor": "opaque-project-cursor",
        }))
        .unwrap();
        assert_eq!(lr.data.len(), 1);
        assert_eq!(lr.data[0].id, "project-1");
        assert_eq!(lr.data[0].project_type, Some("team".into()));
        assert_eq!(lr.next_cursor, Some("opaque-project-cursor".into()));
    }

    #[test]
    fn list_response_tags_requires_id_and_name() {
        let lr: TagListResponse = serde_json::from_value(json!({
            "data": [{
                "id": "tag-1",
                "name": "production",
                "createdAt": "ignored",
                "updatedAt": "ignored"
            }],
            "nextCursor": "opaque-tag-cursor",
        }))
        .unwrap();
        assert_eq!(lr.data[0].id, "tag-1");
        assert_eq!(lr.data[0].name, "production");
        assert_eq!(lr.next_cursor, Some("opaque-tag-cursor".into()));
        assert!(serde_json::from_value::<TagRecord>(json!({"id": "tag-1"})).is_err());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Workflow not found",
            "code": "NOT_FOUND",
        }))
        .unwrap();
        assert_eq!(e.message, Some("Workflow not found".into()));
        assert_eq!(e.code, Some("NOT_FOUND".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.code.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Rate limit exceeded",
        }))
        .unwrap();
        assert_eq!(e.message, Some("Rate limit exceeded".into()));
        assert!(e.code.is_none());
    }

    #[test]
    fn workflow_empty_tags() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "1",
            "tags": [],
        }))
        .unwrap();
        assert!(w.tags.unwrap().is_empty());
    }

    #[test]
    fn tag_extra_fields_ignored() {
        let t: Tag = serde_json::from_value(json!({
            "id": "t1",
            "name": "test",
            "createdAt": "2025-01-01",
        }))
        .unwrap();
        assert_eq!(t.id, Some("t1".into()));
    }

    #[test]
    fn workflow_clone() {
        let w = Workflow {
            id: "w1".into(),
            name: Some("Test".into()),
            description: None,
            active: Some(true),
            version_id: None,
            active_version_id: ActiveVersionId::Missing,
            is_archived: None,
            project_id: None,
            parent_folder_id: None,
            created_at: None,
            updated_at: None,
            settings: None,
            tags: Some(vec![Tag {
                id: Some("t1".into()),
                name: Some("dev".into()),
            }]),
        };
        let cloned = Workflow::clone(&w);
        assert_eq!(cloned.id, "w1");
        assert_eq!(cloned.name, Some("Test".into()));
        assert_eq!(cloned.tags.unwrap().len(), 1);
    }

    #[test]
    fn workflow_debug() {
        let w = Workflow {
            id: "w1".into(),
            name: Some("Debug Test".into()),
            description: None,
            active: None,
            version_id: None,
            active_version_id: ActiveVersionId::Missing,
            is_archived: None,
            project_id: None,
            parent_folder_id: None,
            created_at: None,
            updated_at: None,
            settings: None,
            tags: None,
        };
        let dbg = format!("{w:?}");
        assert!(dbg.contains("w1"));
        assert!(dbg.contains("Debug Test"));
    }

    #[test]
    fn tag_clone() {
        let t = Tag {
            id: Some("t1".into()),
            name: Some("prod".into()),
        };
        let cloned = Tag::clone(&t);
        assert_eq!(cloned.id, Some("t1".into()));
        assert_eq!(cloned.name, Some("prod".into()));
    }

    #[test]
    fn tag_debug() {
        let t = Tag {
            id: Some("t1".into()),
            name: Some("dev".into()),
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("t1"));
        assert!(dbg.contains("dev"));
    }

    #[test]
    fn execution_clone() {
        let e = Execution {
            id: "e1".into(),
            finished: Some(true),
            mode: Some("trigger".into()),
            started_at: None,
            stopped_at: None,
            workflow_id: Some("w1".into()),
            status: Some("success".into()),
            retry_of: None,
            retry_success_id: None,
            wait_till: None,
        };
        let cloned = Execution::clone(&e);
        assert_eq!(cloned.id, "e1");
        assert_eq!(cloned.status, Some("success".into()));
    }

    #[test]
    fn execution_debug() {
        let e = Execution {
            id: "e99".into(),
            finished: None,
            mode: None,
            started_at: None,
            stopped_at: None,
            workflow_id: None,
            status: None,
            retry_of: None,
            retry_success_id: None,
            wait_till: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("e99"));
    }

    #[test]
    fn list_response_clone() {
        let lr = ListResponse::<Workflow> {
            data: vec![Workflow {
                id: "w1".into(),
                name: None,
                description: None,
                active: None,
                version_id: None,
                active_version_id: ActiveVersionId::Missing,
                is_archived: None,
                project_id: None,
                parent_folder_id: None,
                created_at: None,
                updated_at: None,
                settings: None,
                tags: None,
            }],
            next_cursor: Some("cursor1".into()),
        };
        let cloned = ListResponse::clone(&lr);
        assert_eq!(cloned.data.len(), 1);
        assert_eq!(cloned.next_cursor, Some("cursor1".into()));
    }

    #[test]
    fn list_response_debug() {
        let lr = ListResponse::<Workflow> {
            data: vec![],
            next_cursor: None,
        };
        let dbg = format!("{lr:?}");
        assert!(dbg.contains("ListResponse"));
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            message: Some("err".into()),
            code: Some("E001".into()),
        };
        let cloned = ApiErrorResponse::clone(&e);
        assert_eq!(cloned.message, Some("err".into()));
        assert_eq!(cloned.code, Some("E001".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse {
            message: Some("test error".into()),
            code: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("test error"));
    }

    #[test]
    fn workflow_null_fields_become_none() {
        let w: Workflow = serde_json::from_value(json!({
            "id": "1",
            "name": null,
            "description": null,
            "active": null,
            "versionId": null,
            "activeVersionId": null,
            "isArchived": null,
            "projectId": null,
            "parentFolderId": null,
            "createdAt": null,
            "updatedAt": null,
            "tags": null,
        }))
        .unwrap();
        assert!(w.name.is_none());
        assert!(w.description.is_none());
        assert!(w.active.is_none());
        assert!(w.version_id.is_none());
        assert!(matches!(w.active_version_id, ActiveVersionId::Null));
        assert!(w.is_archived.is_none());
        assert!(w.project_id.is_none());
        assert!(w.parent_folder_id.is_none());
        assert!(w.created_at.is_none());
        assert!(w.updated_at.is_none());
        assert!(w.tags.is_none());
    }

    #[test]
    fn workflow_detail_requires_exact_state_fields_and_explicit_nulls() {
        let detail: WorkflowDetail = serde_json::from_value(json!({
            "id": "w1",
            "name": null,
            "active": false,
            "versionId": "draft-v1",
            "activeVersionId": null,
            "isArchived": false,
            "nodes": [],
            "connections": {},
            "activeVersion": null
        }))
        .unwrap();
        assert!(matches!(detail.active_version_id, RequiredNullable::Null));
        assert!(matches!(detail.active_version, RequiredNullable::Null));

        for missing in [
            "active",
            "versionId",
            "activeVersionId",
            "isArchived",
            "nodes",
            "connections",
            "activeVersion",
        ] {
            let mut value = json!({
                "id": "w1",
                "active": false,
                "versionId": "draft-v1",
                "activeVersionId": null,
                "isArchived": false,
                "nodes": [],
                "connections": {},
                "activeVersion": null
            });
            value.as_object_mut().unwrap().remove(missing);
            assert!(
                serde_json::from_value::<WorkflowDetail>(value).is_err(),
                "missing {missing} must fail closed"
            );
        }
    }

    #[test]
    fn list_response_decodes_cursor_without_runtime_output() {
        let lr: ListResponse<Workflow> = serde_json::from_value(json!({
            "data": [],
            "nextCursor": "xyz",
        }))
        .unwrap();
        assert_eq!(lr.next_cursor, Some("xyz".into()));
        assert!(lr.data.is_empty());
    }

    #[test]
    fn list_view_serializes_cursor_only_when_present() {
        let with_cursor = serde_json::to_value(ListView {
            data: vec![WorkflowView {
                id: "w1".into(),
                name: Some("safe".into()),
                description: None,
                active: None,
                version_id: None,
                active_version_id: ActiveVersionId::Missing,
                is_archived: None,
                project_id: None,
                parent_folder_id: None,
                created_at: None,
                updated_at: None,
                available_in_mcp: None,
                tags: None,
            }],
            next_cursor: Some("opaque-cursor".into()),
        })
        .unwrap();
        assert_eq!(with_cursor["nextCursor"], "opaque-cursor");

        let without_cursor = serde_json::to_value(ListView::<WorkflowView> {
            data: Vec::new(),
            next_cursor: None,
        })
        .unwrap();
        assert!(without_cursor.get("nextCursor").is_none());
    }

    #[test]
    fn folder_list_item_projects_parent_and_discards_unknown_fields() {
        let item: FolderListItem = serde_json::from_value(json!({
            "id": "folder-1",
            "name": "Root",
            "parentFolder": {"id": "parent-1", "secret": "discarded"},
            "unknownField": "discarded"
        }))
        .unwrap();
        let output =
            serde_json::to_value(item.into_view("fwc-n8n://eec/folders/folder-1".into())).unwrap();
        assert_eq!(output["parentFolderId"], "parent-1");
        assert!(output.get("parentFolder").is_none());
        assert!(output.get("unknownField").is_none());
    }

    #[test]
    fn folder_list_item_requires_parent_field_but_accepts_null() {
        let root: FolderListItem = serde_json::from_value(json!({
            "id": "folder-1",
            "name": "Root",
            "parentFolder": null
        }))
        .unwrap();
        assert!(matches!(root.parent_folder, RequiredNullable::Null));

        let missing_parent: Result<FolderListItem, _> = serde_json::from_value(json!({
            "id": "folder-1",
            "name": "Root"
        }));
        assert!(missing_parent.is_err());
    }

    #[test]
    fn folder_root_parent_is_null_and_detail_requires_all_fields() {
        let folder: Folder = serde_json::from_value(json!({
            "id": "folder-1",
            "name": "Root",
            "parentFolderId": null,
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-02T00:00:00Z",
            "totalSubFolders": 0,
            "totalWorkflows": 2
        }))
        .unwrap();
        assert!(matches!(folder.parent_folder_id, RequiredNullable::Null));
        let output =
            serde_json::to_value(folder.into_view("fwc-n8n://eec/folders/folder-1".into()))
                .unwrap();
        assert_eq!(output["parentFolderId"], Value::Null);

        let missing_parent: Result<Folder, _> = serde_json::from_value(json!({
            "id": "folder-1",
            "name": "Root",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-02T00:00:00Z",
            "totalSubFolders": 0,
            "totalWorkflows": 2
        }));
        assert!(missing_parent.is_err());
    }
}
