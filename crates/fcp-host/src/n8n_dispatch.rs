//! Host-owned typed dispatch for the fixed local n8n MCP catalog.
//!
//! The request types in this module are deliberately narrower than
//! [`LocalMcpRequest`].  A host caller can select only the two local
//! operation families and their operation-specific inputs; process policy,
//! executable paths, environment, and MCP tool names are all host-owned.

use std::fmt;
use std::sync::{Arc, atomic::AtomicBool};

use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{LocalMcpCall, LocalMcpError, LocalMcpProvider, LocalMcpRequest, LocalMcpResult};

/// Maximum serialized size of one host-internal local n8n dispatch request.
pub const DEFAULT_LOCAL_N8N_INPUT_MAX_BYTES: usize = 16 * 1024;

const MAX_CORRELATION_ID_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 1_024;
const MAX_LIST_ITEMS: usize = 20;

/// One of the host-internal local n8n operation families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nOperationKind {
    KnowledgeQuery,
    ValidationRun,
}

/// The fixed local catalog tool selected by a typed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nTool {
    ToolsDocumentation,
    SearchNodes,
    GetNode,
    SearchTemplates,
    GetTemplate,
    ValidateNode,
    ValidateWorkflow,
}

impl LocalN8nTool {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ToolsDocumentation => "tools_documentation",
            Self::SearchNodes => "search_nodes",
            Self::GetNode => "get_node",
            Self::SearchTemplates => "search_templates",
            Self::GetTemplate => "get_template",
            Self::ValidateNode => "validate_node",
            Self::ValidateWorkflow => "validate_workflow",
        }
    }
}

/// Host-internal typed input for the local knowledge operation. The eventual
/// public contract/router may fan out into these catalog-specific forms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalN8nKnowledgeQuery {
    pub correlation_id: String,
    pub action: LocalN8nKnowledgeAction,
}

/// Knowledge actions that have a corresponding fixed local catalog tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalN8nKnowledgeAction {
    #[serde(rename = "tool_documentation")]
    ToolDocumentation(LocalN8nToolDocumentationInput),
    #[serde(rename = "search_nodes")]
    SearchNodes(LocalN8nSearchNodesInput),
    #[serde(rename = "get_node")]
    GetNode(LocalN8nGetNodeInput),
    #[serde(rename = "search_templates")]
    SearchTemplates(LocalN8nSearchTemplatesInput),
    #[serde(rename = "get_template")]
    GetTemplate(LocalN8nGetTemplateInput),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalN8nToolDocumentationInput {
    pub topic: Option<String>,
    #[serde(default)]
    pub depth: LocalN8nDocumentationDepth,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalN8nDocumentationDepth {
    #[default]
    #[serde(rename = "essentials")]
    Essentials,
    #[serde(rename = "full")]
    Full,
}

impl LocalN8nDocumentationDepth {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Essentials => "essentials",
            Self::Full => "full",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalN8nSearchNodesInput {
    pub query: String,
    #[serde(default)]
    pub limit: Option<u16>,
    #[serde(default)]
    pub mode: Option<LocalN8nSearchMode>,
    #[serde(rename = "includeExamples", default)]
    pub include_examples: bool,
    #[serde(rename = "includeOperations", default)]
    pub include_operations: bool,
    #[serde(default)]
    pub source: Option<LocalN8nNodeSource>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalN8nSearchMode {
    #[serde(rename = "OR")]
    Or,
    #[serde(rename = "AND")]
    And,
    #[serde(rename = "FUZZY")]
    Fuzzy,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LocalN8nNodeSource {
    All,
    Core,
    Community,
    Verified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalN8nGetNodeInput {
    #[serde(rename = "nodeType")]
    pub node_type: String,
    #[serde(default)]
    pub detail: LocalN8nDetail,
    #[serde(default)]
    pub mode: LocalN8nNodeMode,
    #[serde(rename = "includeTypeInfo", default)]
    pub include_type_info: bool,
    #[serde(rename = "includeExamples", default)]
    pub include_examples: bool,
    #[serde(rename = "fromVersion", default)]
    pub from_version: Option<String>,
    #[serde(rename = "toVersion", default)]
    pub to_version: Option<String>,
    #[serde(rename = "propertyQuery", default)]
    pub property_query: Option<String>,
    #[serde(rename = "maxPropertyResults", default)]
    pub max_property_results: Option<u16>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nNodeMode {
    #[default]
    Info,
    Docs,
    SearchProperties,
    Versions,
    Compare,
    Breaking,
    Migrations,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nDetail {
    Minimal,
    #[default]
    Standard,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalN8nSearchTemplatesInput {
    #[serde(rename = "searchMode", default)]
    pub search_mode: LocalN8nTemplateSearchMode,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub fields: Option<Vec<LocalN8nTemplateField>>,
    #[serde(rename = "nodeTypes", default)]
    pub node_types: Option<Vec<String>>,
    #[serde(default)]
    pub task: Option<LocalN8nTemplateTask>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub complexity: Option<LocalN8nTemplateComplexity>,
    #[serde(rename = "maxSetupMinutes", default)]
    pub max_setup_minutes: Option<u16>,
    #[serde(rename = "minSetupMinutes", default)]
    pub min_setup_minutes: Option<u16>,
    #[serde(rename = "requiredService", default)]
    pub required_service: Option<String>,
    #[serde(rename = "targetAudience", default)]
    pub target_audience: Option<String>,
    #[serde(default = "default_template_limit")]
    pub limit: u16,
    #[serde(default)]
    pub offset: u32,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nTemplateSearchMode {
    #[default]
    Keyword,
    ByNodes,
    ByTask,
    ByMetadata,
    Patterns,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nTemplateField {
    Id,
    Name,
    Description,
    Author,
    Nodes,
    Views,
    Created,
    Url,
    Metadata,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nTemplateTask {
    AiAutomation,
    DataSync,
    WebhookProcessing,
    EmailAutomation,
    SlackIntegration,
    DataTransformation,
    FileProcessing,
    Scheduling,
    ApiIntegration,
    DatabaseOperations,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nTemplateComplexity {
    Simple,
    Medium,
    Complex,
}

const fn default_template_limit() -> u16 {
    20
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalN8nGetTemplateInput {
    #[serde(rename = "templateId")]
    pub template_id: u64,
    #[serde(default)]
    pub mode: LocalN8nTemplateMode,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nTemplateMode {
    NodesOnly,
    Structure,
    #[default]
    Full,
}

/// Host-internal typed input for the local validation operation. This is not
/// the final public wire contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalN8nValidationRun {
    pub correlation_id: String,
    pub subject: LocalN8nValidationSubject,
}

/// Validation subjects that map to the fixed local node/workflow tools.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalN8nValidationSubject {
    #[serde(rename = "node")]
    Node(LocalN8nNodeValidationInput),
    #[serde(rename = "workflow")]
    Workflow(LocalN8nWorkflowValidationInput),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalN8nNodeValidationInput {
    #[serde(rename = "nodeType")]
    pub node_type: String,
    pub config: Value,
    #[serde(default)]
    pub mode: LocalN8nValidationMode,
    #[serde(default = "default_node_profile")]
    pub profile: LocalN8nValidationProfile,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nValidationMode {
    #[default]
    Full,
    Minimal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalN8nWorkflowValidationInput {
    pub workflow: Value,
    #[serde(default)]
    pub options: Option<LocalN8nWorkflowValidationOptions>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalN8nWorkflowValidationOptions {
    #[serde(rename = "validateNodes", default = "default_true")]
    pub validate_nodes: bool,
    #[serde(rename = "validateConnections", default = "default_true")]
    pub validate_connections: bool,
    #[serde(rename = "validateExpressions", default = "default_true")]
    pub validate_expressions: bool,
    #[serde(default)]
    pub profile: Option<LocalN8nValidationProfile>,
}

const fn default_true() -> bool {
    true
}

const fn default_node_profile() -> LocalN8nValidationProfile {
    LocalN8nValidationProfile::AiFriendly
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocalN8nValidationProfile {
    #[default]
    Minimal,
    Runtime,
    AiFriendly,
    Strict,
}

impl LocalN8nValidationProfile {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Runtime => "runtime",
            Self::AiFriendly => "ai-friendly",
            Self::Strict => "strict",
        }
    }
}

/// Host-internal local dispatch request.
///
/// Its custom deserializer keeps the adapter shape compact while ensuring
/// unknown top-level fields fail closed. The public contract/router is
/// expected to normalize or fan out into it later.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "operation", content = "input")]
pub enum LocalN8nDispatchRequest {
    #[serde(rename = "n8n.knowledge.query")]
    KnowledgeQuery(LocalN8nKnowledgeQuery),
    #[serde(rename = "n8n.validation.run")]
    ValidationRun(LocalN8nValidationRun),
}

impl<'de> Deserialize<'de> for LocalN8nDispatchRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawRequest {
            operation: String,
            input: Value,
        }

        let raw = RawRequest::deserialize(deserializer)?;
        let invalid = || D::Error::custom("invalid local n8n dispatch request");
        match raw.operation.as_str() {
            "n8n.knowledge.query" => serde_json::from_value(raw.input)
                .map(Self::KnowledgeQuery)
                .map_err(|_| invalid()),
            "n8n.validation.run" => serde_json::from_value(raw.input)
                .map(Self::ValidationRun)
                .map_err(|_| invalid()),
            _ => Err(invalid()),
        }
    }
}

impl LocalN8nDispatchRequest {
    /// Return the public operation kind without exposing a provider detail.
    #[must_use]
    pub const fn operation_kind(&self) -> LocalN8nOperationKind {
        match self {
            Self::KnowledgeQuery(_) => LocalN8nOperationKind::KnowledgeQuery,
            Self::ValidationRun(_) => LocalN8nOperationKind::ValidationRun,
        }
    }

    /// Return the fixed catalog tool selected by this request.
    #[must_use]
    pub const fn internal_tool(&self) -> LocalN8nTool {
        match self {
            Self::KnowledgeQuery(input) => match &input.action {
                LocalN8nKnowledgeAction::ToolDocumentation(_) => LocalN8nTool::ToolsDocumentation,
                LocalN8nKnowledgeAction::SearchNodes(_) => LocalN8nTool::SearchNodes,
                LocalN8nKnowledgeAction::GetNode(_) => LocalN8nTool::GetNode,
                LocalN8nKnowledgeAction::SearchTemplates(_) => LocalN8nTool::SearchTemplates,
                LocalN8nKnowledgeAction::GetTemplate(_) => LocalN8nTool::GetTemplate,
            },
            Self::ValidationRun(input) => match &input.subject {
                LocalN8nValidationSubject::Node(_) => LocalN8nTool::ValidateNode,
                LocalN8nValidationSubject::Workflow(_) => LocalN8nTool::ValidateWorkflow,
            },
        }
    }

    fn into_provider_request(self) -> Result<LocalMcpRequest, LocalN8nDispatchError> {
        match self {
            Self::KnowledgeQuery(input) => {
                validate_correlation_id(&input.correlation_id)?;
                let (tool, arguments) = input.action.into_call()?;
                Ok(LocalMcpRequest {
                    correlation_id: input.correlation_id,
                    calls: vec![LocalMcpCall {
                        tool: tool.as_str().to_string(),
                        arguments,
                    }],
                })
            }
            Self::ValidationRun(input) => {
                validate_correlation_id(&input.correlation_id)?;
                let correlation_id = input.correlation_id.clone();
                let (tool, arguments) = input.into_call()?;
                Ok(LocalMcpRequest {
                    correlation_id,
                    calls: vec![LocalMcpCall {
                        tool: tool.as_str().to_string(),
                        arguments,
                    }],
                })
            }
        }
    }
}

impl LocalN8nKnowledgeAction {
    // Keeping the complete closed-catalog mapping together makes review
    // against the installed n8n-mcp schema mechanical and auditable.
    #[allow(clippy::too_many_lines)]
    fn into_call(self) -> Result<(LocalN8nTool, Value), LocalN8nDispatchError> {
        match self {
            Self::ToolDocumentation(input) => {
                if let Some(topic) = &input.topic {
                    validate_text(topic, MAX_TEXT_BYTES)?;
                }
                let mut arguments = json!({ "depth": input.depth.as_str() });
                if let Some(topic) = input.topic {
                    arguments["topic"] = Value::String(topic);
                }
                Ok((LocalN8nTool::ToolsDocumentation, arguments))
            }
            Self::SearchNodes(input) => {
                validate_text(&input.query, MAX_TEXT_BYTES)?;
                validate_limit(input.limit)?;
                let mut arguments = optional_limit(json!({ "query": input.query }), input.limit);
                arguments["mode"] = json!(input.mode.unwrap_or(LocalN8nSearchMode::Or));
                arguments["includeExamples"] = json!(input.include_examples);
                arguments["includeOperations"] = json!(input.include_operations);
                if let Some(source) = input.source {
                    arguments["source"] = json!(source);
                }
                Ok((LocalN8nTool::SearchNodes, arguments))
            }
            Self::GetNode(input) => {
                validate_text(&input.node_type, MAX_TEXT_BYTES)?;
                if let Some(value) = &input.from_version {
                    validate_text(value, MAX_TEXT_BYTES)?;
                }
                if let Some(value) = &input.to_version {
                    validate_text(value, MAX_TEXT_BYTES)?;
                }
                if let Some(value) = &input.property_query {
                    validate_text(value, MAX_TEXT_BYTES)?;
                }
                if input
                    .max_property_results
                    .is_some_and(|value| value == 0 || value > 100)
                {
                    return Err(invalid_request());
                }
                let mode_fields_valid = match input.mode {
                    LocalN8nNodeMode::SearchProperties => input.property_query.is_some(),
                    LocalN8nNodeMode::Compare | LocalN8nNodeMode::Breaking => {
                        input.from_version.is_some()
                    }
                    LocalN8nNodeMode::Migrations => {
                        input.from_version.is_some() && input.to_version.is_some()
                    }
                    LocalN8nNodeMode::Info
                    | LocalN8nNodeMode::Docs
                    | LocalN8nNodeMode::Versions => true,
                };
                if !mode_fields_valid {
                    return Err(invalid_request());
                }
                let mut arguments = json!({
                    "nodeType": input.node_type,
                    "mode": input.mode,
                    "detail": input.detail,
                    "includeTypeInfo": input.include_type_info,
                    "includeExamples": input.include_examples,
                });
                if let Some(value) = input.from_version {
                    arguments["fromVersion"] = Value::String(value);
                }
                if let Some(value) = input.to_version {
                    arguments["toVersion"] = Value::String(value);
                }
                if let Some(value) = input.property_query {
                    arguments["propertyQuery"] = Value::String(value);
                }
                if let Some(value) = input.max_property_results {
                    arguments["maxPropertyResults"] = json!(value);
                }
                Ok((LocalN8nTool::GetNode, arguments))
            }
            Self::SearchTemplates(input) => {
                if let Some(query) = &input.query {
                    validate_text(query, MAX_TEXT_BYTES)?;
                }
                if let Some(node_types) = &input.node_types {
                    if node_types.is_empty() || node_types.len() > MAX_LIST_ITEMS {
                        return Err(LocalN8nDispatchError::new(
                            LocalN8nDispatchErrorCode::InvalidRequest,
                        ));
                    }
                    for node_type in node_types {
                        validate_text(node_type, MAX_TEXT_BYTES)?;
                    }
                }
                if input
                    .fields
                    .as_ref()
                    .is_some_and(|fields| fields.is_empty() || fields.len() > 9)
                    || input.limit == 0
                    || input.limit > 100
                    || input.offset > 1_000_000
                    || input
                        .max_setup_minutes
                        .is_some_and(|value| !(5..=480).contains(&value))
                    || input
                        .min_setup_minutes
                        .is_some_and(|value| !(5..=480).contains(&value))
                {
                    return Err(invalid_request());
                }
                for value in [
                    input.category.as_ref(),
                    input.required_service.as_ref(),
                    input.target_audience.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    validate_text(value, MAX_TEXT_BYTES)?;
                }
                let mode_fields_valid = match input.search_mode {
                    LocalN8nTemplateSearchMode::Keyword => input.query.is_some(),
                    LocalN8nTemplateSearchMode::ByNodes => input.node_types.is_some(),
                    LocalN8nTemplateSearchMode::ByTask => input.task.is_some(),
                    LocalN8nTemplateSearchMode::ByMetadata => {
                        input.category.is_some()
                            || input.complexity.is_some()
                            || input.max_setup_minutes.is_some()
                            || input.min_setup_minutes.is_some()
                            || input.required_service.is_some()
                            || input.target_audience.is_some()
                    }
                    LocalN8nTemplateSearchMode::Patterns => true,
                };
                if !mode_fields_valid {
                    return Err(invalid_request());
                }
                let mut arguments = serde_json::Map::new();
                arguments.insert("searchMode".into(), json!(input.search_mode));
                if let Some(query) = input.query {
                    arguments.insert("query".into(), Value::String(query));
                }
                if let Some(fields) = input.fields {
                    arguments.insert("fields".into(), json!(fields));
                }
                if let Some(node_types) = input.node_types {
                    arguments.insert("nodeTypes".into(), json!(node_types));
                }
                if let Some(task) = input.task {
                    arguments.insert("task".into(), json!(task));
                }
                if let Some(category) = input.category {
                    arguments.insert("category".into(), Value::String(category));
                }
                if let Some(complexity) = input.complexity {
                    arguments.insert("complexity".into(), json!(complexity));
                }
                if let Some(value) = input.max_setup_minutes {
                    arguments.insert("maxSetupMinutes".into(), json!(value));
                }
                if let Some(value) = input.min_setup_minutes {
                    arguments.insert("minSetupMinutes".into(), json!(value));
                }
                if let Some(value) = input.required_service {
                    arguments.insert("requiredService".into(), Value::String(value));
                }
                if let Some(value) = input.target_audience {
                    arguments.insert("targetAudience".into(), Value::String(value));
                }
                arguments.insert("limit".into(), json!(input.limit));
                arguments.insert("offset".into(), json!(input.offset));
                Ok((LocalN8nTool::SearchTemplates, Value::Object(arguments)))
            }
            Self::GetTemplate(input) => {
                if input.template_id == 0 {
                    return Err(invalid_request());
                }
                Ok((
                    LocalN8nTool::GetTemplate,
                    json!({ "templateId": input.template_id, "mode": input.mode }),
                ))
            }
        }
    }
}

impl LocalN8nValidationRun {
    fn into_call(self) -> Result<(LocalN8nTool, Value), LocalN8nDispatchError> {
        match self.subject {
            LocalN8nValidationSubject::Node(input) => {
                validate_text(&input.node_type, MAX_TEXT_BYTES)?;
                if !input.config.is_object() {
                    return Err(LocalN8nDispatchError::new(
                        LocalN8nDispatchErrorCode::InvalidRequest,
                    ));
                }
                Ok((
                    LocalN8nTool::ValidateNode,
                    json!({
                        "nodeType": input.node_type,
                        "config": input.config,
                        "mode": input.mode,
                        "profile": input.profile.as_str(),
                    }),
                ))
            }
            LocalN8nValidationSubject::Workflow(input) => {
                if !input.workflow.is_object() {
                    return Err(LocalN8nDispatchError::new(
                        LocalN8nDispatchErrorCode::InvalidRequest,
                    ));
                }
                let mut arguments = json!({ "workflow": input.workflow });
                if let Some(options) = input.options {
                    arguments["options"] = json!({
                        "validateNodes": options.validate_nodes,
                        "validateConnections": options.validate_connections,
                        "validateExpressions": options.validate_expressions,
                        "profile": options.profile.unwrap_or(LocalN8nValidationProfile::Runtime).as_str(),
                    });
                }
                Ok((LocalN8nTool::ValidateWorkflow, arguments))
            }
        }
    }
}

fn optional_limit(mut arguments: Value, limit: Option<u16>) -> Value {
    if let Some(limit) = limit {
        arguments["limit"] = json!(limit);
    }
    arguments
}

fn validate_correlation_id(value: &str) -> Result<(), LocalN8nDispatchError> {
    if value.is_empty()
        || value.len() > MAX_CORRELATION_ID_BYTES
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(LocalN8nDispatchError::new(
            LocalN8nDispatchErrorCode::InvalidRequest,
        ));
    }
    Ok(())
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), LocalN8nDispatchError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(LocalN8nDispatchError::new(
            LocalN8nDispatchErrorCode::InvalidRequest,
        ));
    }
    Ok(())
}

fn validate_limit(limit: Option<u16>) -> Result<(), LocalN8nDispatchError> {
    if limit.is_some_and(|value| value == 0 || usize::from(value) > MAX_LIST_ITEMS) {
        return Err(LocalN8nDispatchError::new(
            LocalN8nDispatchErrorCode::InvalidRequest,
        ));
    }
    Ok(())
}

const fn invalid_request() -> LocalN8nDispatchError {
    LocalN8nDispatchError::new(LocalN8nDispatchErrorCode::InvalidRequest)
}

/// Stable, redaction-safe adapter error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalN8nDispatchErrorCode {
    InvalidRequest,
    InputTooLarge,
    UnsupportedPlatform,
    Cancelled,
    ProviderError,
}

impl LocalN8nDispatchErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InputTooLarge => "input_too_large",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Cancelled => "cancelled",
            Self::ProviderError => "provider_error",
        }
    }
}

/// Adapter failure that never includes provider, path, policy, or payload text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalN8nDispatchError {
    code: LocalN8nDispatchErrorCode,
}

impl LocalN8nDispatchError {
    const fn new(code: LocalN8nDispatchErrorCode) -> Self {
        Self { code }
    }

    /// Return the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> LocalN8nDispatchErrorCode {
        self.code
    }
}

impl fmt::Display for LocalN8nDispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code.as_str())
    }
}

impl std::error::Error for LocalN8nDispatchError {}

/// Result envelope preserving the complete provider lifecycle receipt.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalN8nDispatchResponse {
    pub operation: LocalN8nOperationKind,
    pub result: LocalMcpResult,
}

impl fmt::Debug for LocalN8nDispatchResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalN8nDispatchResponse")
            .field("operation", &self.operation)
            .field("status", &self.result.status)
            .field("result_code", &self.result.result_code)
            .field("shutdown", &self.result.shutdown)
            .finish_non_exhaustive()
    }
}

/// Host-owned dispatcher. The provider and its validated policy are supplied
/// by the host; the request cannot select or alter either one.
pub struct LocalN8nDispatcher {
    provider: LocalMcpProvider,
    max_input_bytes: usize,
}

impl LocalN8nDispatcher {
    /// Construct a dispatcher with the default compact input bound.
    #[must_use]
    pub const fn new(provider: LocalMcpProvider) -> Self {
        Self {
            provider,
            max_input_bytes: DEFAULT_LOCAL_N8N_INPUT_MAX_BYTES,
        }
    }

    /// Construct a dispatcher with a tighter host-selected bound.
    #[must_use]
    pub const fn with_max_input_bytes(provider: LocalMcpProvider, max_input_bytes: usize) -> Self {
        Self {
            provider,
            max_input_bytes,
        }
    }

    /// Dispatch one typed local operation through the existing provider.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe adapter error when the typed input is invalid
    /// or oversized, cancellation is requested, the platform is unsupported,
    /// or the supervised provider fails.
    pub fn dispatch(
        &self,
        request: LocalN8nDispatchRequest,
        cancelled: Arc<AtomicBool>,
    ) -> Result<LocalN8nDispatchResponse, LocalN8nDispatchError> {
        let serialized = serde_json::to_vec(&request)
            .map_err(|_| LocalN8nDispatchError::new(LocalN8nDispatchErrorCode::InvalidRequest))?;
        if serialized.len() > self.max_input_bytes {
            return Err(LocalN8nDispatchError::new(
                LocalN8nDispatchErrorCode::InputTooLarge,
            ));
        }

        let operation = request.operation_kind();
        let provider_request = request.into_provider_request()?;
        let result = self
            .provider
            .run_once_with_cancel(provider_request, cancelled)
            .map_err(|error| map_provider_error(&error))?;
        Ok(LocalN8nDispatchResponse { operation, result })
    }
}

const fn map_provider_error(error: &LocalMcpError) -> LocalN8nDispatchError {
    let code = match error {
        LocalMcpError::UnsupportedPlatform => LocalN8nDispatchErrorCode::UnsupportedPlatform,
        LocalMcpError::Cancelled => LocalN8nDispatchErrorCode::Cancelled,
        _ => LocalN8nDispatchErrorCode::ProviderError,
    };
    LocalN8nDispatchError::new(code)
}
