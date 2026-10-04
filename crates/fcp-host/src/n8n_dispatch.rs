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

/// Closed official SDK reads. These arguments never select authoring tools.
///
/// # Errors
/// Rejects unknown fields, unsupported sections and oversized SDK source.
pub fn official_n8n_sdk_arguments(
    operation: &str,
    input: &Value,
) -> Result<(&'static str, Value), &'static str> {
    match operation {
        "n8n.knowledge.query" => official_knowledge_arguments(input),
        "n8n.validation.run" => official_validation_arguments(input),
        _ => Err("invalid_operation_input"),
    }
}

fn official_knowledge_arguments(input: &Value) -> Result<(&'static str, Value), &'static str> {
    let object = input.as_object().ok_or("invalid_operation_input")?;
    match input["action"].as_str() {
        Some("sdk_reference") => {
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "action" | "section"))
            {
                return Err("invalid_operation_input");
            }
            let section = input["section"].as_str().ok_or("invalid_operation_input")?;
            if !matches!(
                section,
                "patterns"
                    | "patterns_detailed"
                    | "expressions"
                    | "functions"
                    | "rules"
                    | "import"
                    | "guidelines"
                    | "design"
                    | "all"
            ) {
                return Err("invalid_operation_input");
            }
            Ok(("get_workflow_sdk_reference", json!({"section":section})))
        }
        Some("workflow_best_practices") => {
            if object
                .keys()
                .any(|key| !matches!(key.as_str(), "action" | "technique"))
            {
                return Err("invalid_operation_input");
            }
            let technique = input["technique"]
                .as_str()
                .ok_or("invalid_operation_input")?;
            if !matches!(
                technique,
                "list"
                    | "scheduling"
                    | "chatbot"
                    | "form_input"
                    | "scraping_and_research"
                    | "monitoring"
                    | "enrichment"
                    | "triage"
                    | "content_generation"
                    | "document_processing"
                    | "data_extraction"
                    | "data_analysis"
                    | "data_transformation"
                    | "data_persistence"
                    | "notification"
                    | "knowledge_base"
                    | "human_in_the_loop"
                    | "web_app"
            ) {
                return Err("invalid_operation_input");
            }
            Ok((
                "get_workflow_best_practices",
                json!({"technique":technique}),
            ))
        }
        _ => Err("invalid_operation_input"),
    }
}

fn official_validation_arguments(input: &Value) -> Result<(&'static str, Value), &'static str> {
    let object = input.as_object().ok_or("invalid_operation_input")?;
    if input["subject"] == "nodes" {
        return official_node_validation_arguments(input);
    }
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "subject" | "code" | "profile"))
        || input["subject"] != "workflow_code"
    {
        return Err("invalid_operation_input");
    }
    if object.contains_key("profile") {
        return Err("sdk_validation_profile_unsupported");
    }
    let code = input["code"]
        .as_str()
        .filter(|code| !code.is_empty() && code.len() <= 300_000)
        .ok_or("invalid_operation_input")?;
    Ok(("validate_workflow", json!({"code":code})))
}

fn official_node_validation_arguments(
    input: &Value,
) -> Result<(&'static str, Value), &'static str> {
    let object = input.as_object().ok_or("invalid_operation_input")?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "subject" | "nodes" | "profile"))
    {
        return Err("invalid_operation_input");
    }
    if object.contains_key("profile") {
        return Err("sdk_validation_profile_unsupported");
    }
    let nodes = input["nodes"]
        .as_array()
        .filter(|nodes| !nodes.is_empty() && nodes.len() <= 50)
        .ok_or("invalid_operation_input")?;
    for node in nodes {
        let node = node.as_object().ok_or("invalid_operation_input")?;
        if node.keys().any(|key| {
            !matches!(
                key.as_str(),
                "name" | "type" | "typeVersion" | "parameters" | "subnodes" | "isToolNode"
            )
        }) || node
            .get("type")
            .and_then(Value::as_str)
            .is_none_or(|value| {
                value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
            })
            || node.get("name").is_some_and(|value| {
                value
                    .as_str()
                    .is_none_or(|value| value.len() > 256 || value.chars().any(char::is_control))
            })
            || node.get("typeVersion").is_some_and(|value| {
                value
                    .as_f64()
                    .is_none_or(|value| !value.is_finite() || value <= 0.0 || value > 1000.0)
            })
            || node
                .get("parameters")
                .is_some_and(|value| !value.is_object())
            || node
                .get("isToolNode")
                .is_some_and(|value| !value.is_boolean())
        {
            return Err("invalid_operation_input");
        }
        if let Some(subnodes) = node.get("subnodes") {
            validate_sdk_subnodes(subnodes)?;
        }
    }
    if serde_json::to_vec(nodes)
        .map_err(|_| "invalid_operation_input")?
        .len()
        > 128 * 1024
    {
        return Err("invalid_operation_input");
    }
    Ok(("validate_node_config", json!({"nodes":nodes})))
}

fn validate_sdk_subnodes(subnodes: &Value) -> Result<(), &'static str> {
    let subnodes = subnodes.as_object().ok_or("invalid_operation_input")?;
    if subnodes
        .keys()
        .any(|key| !matches!(key.as_str(), "model" | "memory" | "tools"))
    {
        return Err("invalid_operation_input");
    }
    let mut references = Vec::new();
    for key in ["model", "memory"] {
        if let Some(value) = subnodes.get(key) {
            references.push(value);
        }
    }
    if let Some(tools) = subnodes.get("tools") {
        let tools = tools
            .as_array()
            .filter(|tools| tools.len() <= 20)
            .ok_or("invalid_operation_input")?;
        references.extend(tools);
    }
    for reference in references {
        let reference = reference.as_object().ok_or("invalid_operation_input")?;
        if reference
            .keys()
            .any(|key| !matches!(key.as_str(), "type" | "version"))
            || reference
                .get("type")
                .and_then(Value::as_str)
                .is_none_or(|value| {
                    value.is_empty() || value.len() > 256 || value.chars().any(char::is_control)
                })
            || reference.get("version").is_some_and(|value| {
                value
                    .as_f64()
                    .is_none_or(|value| !value.is_finite() || value <= 0.0 || value > 1000.0)
            })
        {
            return Err("invalid_operation_input");
        }
    }
    Ok(())
}

/// Exact installed source/schema observations; matching is not admission.
#[must_use]
pub fn official_n8n_sdk_schema_pins(tool: &str) -> Option<(&'static str, &'static str)> {
    match tool {
        "get_workflow_sdk_reference" => Some((
            "sha256:c0c69d975afd16845bee57cbd37e0cf0a50b7d5741810625963dedf60279fda2",
            "sha256:555b1d6f84918d5b03adfd55c3f652d2b0ac0457f80e9e811963fbbbc61426dc",
        )),
        "get_workflow_best_practices" => Some((
            "sha256:d95120da8063c53d7dc379b938043cfdc81da869c40a33ce608fe76ddda31423",
            "sha256:9530d1f518b2640320f8ffbfd971d662b3f00558be8b3ff9418fe0d916a1728c",
        )),
        "validate_workflow" => Some((
            "sha256:34160cafc3bf8971e214a3b35195b12d5e33a22f3738d49d68c1e2aeb736e9f0",
            "sha256:a56a4e3038b4b2732ab9fffbfcf038b4d4824c48481123ede01f3a444358fae9",
        )),
        "validate_node_config" => Some((
            "sha256:37231a38664a9375573c84d8484fc30cef2e99efbca5f6172f1a4cd308c34f8d",
            "sha256:11fa90ee8936aa8946e5a1556d3c03ad3640dc837731c0302f4b0dc40e5920a0",
        )),
        "search_projects" => Some((
            "sha256:d37453c28e110141c606ef901d7651367544f8d272f183bd181978e086712200",
            "sha256:28c5f100b2daae7bff8225376c4bed8000f67b785f174a6ae1636ff90fc5126e",
        )),
        "search_folders" => Some((
            "sha256:20a822576c3a6e883e942dfc695ccc7114ffc18e2e3a7bf555af8b07da314269",
            "sha256:d0af92b84b63148c231ee85778e7af9b765cf6edc4e8d638eec067220b496487",
        )),
        "list_workflow_tags" => Some((
            "sha256:c0602bd0434d0c2aeafb763bc12512b63443448c9331dc0cb1ebf02973603e8e",
            "sha256:5481cbd6dedd4134020f44bdcc900e40eb9802e70d5ccedf8dda6252d55b720b",
        )),
        "search_workflows" => Some((
            "sha256:179069c19267545edc43d943befdcff9743bbf4557e6a10efe7fa0cb7b91e714",
            "sha256:1b9737c076b6f72be4f1521911b589fce8f9954bdc7487ea12933f2bd0586206",
        )),
        _ => None,
    }
}

/// Map the public structure query to fixed native arguments. Parent filtering
/// and pagination require a complete bounded native result, never page-local
/// claims about a truncated result.
///
/// # Errors
/// Rejects unknown fields, unrelated selectors and malformed public bounds.
pub fn official_n8n_structure_arguments(
    input: &Value,
) -> Result<(&'static str, Value), &'static str> {
    let invalid = "invalid_structure_search";
    let object = input.as_object().ok_or(invalid)?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "kind" | "query" | "projectId" | "parentFolderId" | "page"
        )
    }) {
        return Err(invalid);
    }
    let kind = input["kind"].as_str().ok_or(invalid)?;
    let (tool, limit) = match kind {
        "projects" => ("search_projects", 100),
        "folders" => ("search_folders", 100),
        "tags" => ("list_workflow_tags", 500),
        _ => return Err(invalid),
    };
    let mut arguments = json!({"limit":limit});
    for key in ["query", "projectId", "parentFolderId"] {
        if let Some(value) = object.get(key) {
            let value = value
                .as_str()
                .filter(|text| {
                    !text.is_empty() && text.len() <= 256 && !text.chars().any(char::is_control)
                })
                .ok_or(invalid)?;
            if key != "query" && kind != "folders" {
                return Err(invalid);
            }
            if key == "projectId" || key == "query" && kind != "tags" {
                arguments[key] = json!(value);
            }
        }
    }
    if kind == "folders" && arguments.get("projectId").is_none() {
        return Err(invalid);
    }
    if let Some(page) = object.get("page") {
        let page = page.as_object().ok_or(invalid)?;
        if page
            .keys()
            .any(|key| !matches!(key.as_str(), "limit" | "cursor"))
        {
            return Err(invalid);
        }
        if page.get("limit").is_some_and(|limit| {
            limit
                .as_u64()
                .is_none_or(|limit| !(1..=200).contains(&limit))
        }) {
            return Err(invalid);
        }
        if page.get("cursor").is_some_and(|cursor| {
            cursor.as_str().is_none_or(|cursor| {
                cursor.is_empty()
                    || cursor.len() > 8192
                    || !cursor.is_ascii()
                    || cursor.chars().any(char::is_control)
            })
        }) {
            return Err(invalid);
        }
    }
    Ok((tool, arguments))
}

/// Source-bound official workflow search. Native search excludes archives and
/// has no cursor; public paging/filtering requires a complete bounded result.
///
/// # Errors
/// Rejects unsupported archives and fields or malformed filter bounds.
pub fn official_n8n_workflow_search_arguments(input: &Value) -> Result<Value, &'static str> {
    let invalid = "invalid_workflow_search";
    let object = input.as_object().ok_or(invalid)?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "query" | "projectId" | "folderId" | "tags" | "active" | "isArchived" | "page" | "sort"
        )
    }) {
        return Err(invalid);
    }
    if input
        .get("isArchived")
        .is_some_and(|value| value.as_bool() != Some(false))
    {
        return Err("official_archived_workflow_search_unsupported");
    }
    if input.get("active").is_some_and(|value| !value.is_boolean()) {
        return Err(invalid);
    }
    let mut arguments = json!({"limit":200});
    for key in ["query", "projectId", "folderId", "sort"] {
        if let Some(value) = input.get(key) {
            let value = value
                .as_str()
                .filter(|text| {
                    !text.is_empty() && text.len() <= 256 && !text.chars().any(char::is_control)
                })
                .ok_or(invalid)?;
            if key == "sort"
                && !matches!(
                    value,
                    "name:asc"
                        | "name:desc"
                        | "createdAt:asc"
                        | "createdAt:desc"
                        | "updatedAt:asc"
                        | "updatedAt:desc"
                )
            {
                return Err(invalid);
            }
            if key == "folderId"
                && !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(invalid);
            }
            arguments[if key == "sort" { "sortBy" } else { key }] = json!(value);
        }
    }
    if let Some(tags) = input.get("tags") {
        let tags = tags
            .as_array()
            .filter(|tags| !tags.is_empty() && tags.len() <= 10)
            .ok_or(invalid)?;
        let mut seen = std::collections::BTreeSet::new();
        for tag in tags {
            let tag = tag
                .as_str()
                .filter(|tag| {
                    !tag.is_empty() && tag.len() <= 256 && !tag.chars().any(char::is_control)
                })
                .ok_or(invalid)?;
            if !seen.insert(tag) {
                return Err(invalid);
            }
        }
        arguments["tags"] = json!(tags);
    }
    if let Some(page) = input.get("page") {
        let page = page.as_object().ok_or(invalid)?;
        if page
            .keys()
            .any(|key| !matches!(key.as_str(), "limit" | "cursor"))
            || page.get("limit").is_some_and(|limit| {
                limit
                    .as_u64()
                    .is_none_or(|limit| !(1..=200).contains(&limit))
            })
            || page.get("cursor").is_some_and(|cursor| {
                cursor.as_str().is_none_or(|cursor| {
                    cursor.is_empty()
                        || cursor.len() > 8192
                        || !cursor.is_ascii()
                        || cursor.chars().any(char::is_control)
                })
            })
        {
            return Err(invalid);
        }
    }
    Ok(arguments)
}

/// Digest the current graph's semantics and layout without emitting graph
/// fields. The same implementation binds connector projection and host capture.
///
/// # Errors
/// Rejects malformed or oversized native graphs.
pub fn n8n_comparison_graph_digests(
    nodes: &[Value],
    connections: &Value,
) -> Result<(String, String), LocalN8nDispatchError> {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut entries = object.iter().collect::<Vec<_>>();
                entries.sort_unstable_by_key(|(key, _)| *key);
                Value::Object(
                    entries
                        .into_iter()
                        .map(|(key, value)| (key.clone(), canonical(value)))
                        .collect(),
                )
            }
            Value::Array(array) => Value::Array(array.iter().map(canonical).collect()),
            scalar => scalar.clone(),
        }
    }
    let malformed = || LocalN8nDispatchError::new(LocalN8nDispatchErrorCode::ProviderError);
    let digest = |domain: &[u8], value: Value| {
        let bytes = serde_json::to_vec(&canonical(&value)).map_err(|_| malformed())?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&[0]);
        hasher.update(&bytes);
        Ok::<_, LocalN8nDispatchError>(format!("blake3-256:{}", hasher.finalize().to_hex()))
    };
    if nodes.len() > 1000 || !connections.is_object() {
        return Err(malformed());
    }
    let mut semantic = Vec::with_capacity(nodes.len());
    let mut layout = Vec::with_capacity(nodes.len());
    for node in nodes {
        let mut object = node.as_object().ok_or_else(malformed)?.clone();
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(malformed)?;
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return Err(malformed());
        }
        layout.push(json!({"id":id,"position":object.get("position")}));
        object.remove("position");
        semantic.push(Value::Object(object));
    }
    Ok((
        digest(
            b"FCP/n8n/compare-semantic/v1\0",
            json!({"nodes":semantic,"connections":connections}),
        )?,
        digest(b"FCP/n8n/compare-layout/v1\0", json!(layout))?,
    ))
}

/// Project one native local validator result without native messages, node
/// names, suggestions, or provider transport fields.
///
/// # Errors
/// Rejects malformed envelopes and contradictory validation outcomes.
pub fn project_local_n8n_validation_call(native: &Value) -> Result<Value, LocalN8nDispatchError> {
    let malformed = || LocalN8nDispatchError::new(LocalN8nDispatchErrorCode::ProviderError);
    let is_error = match native.get("isError") {
        None => false,
        Some(Value::Bool(value)) => *value,
        _ => return Err(malformed()),
    };
    let content = native["content"].as_array().ok_or_else(malformed)?;
    if content.len() != 1 || content[0]["type"] != "text" {
        return Err(malformed());
    }
    let text = content[0]["text"].as_str().ok_or_else(malformed)?;
    if text.len() > 256 * 1024 {
        return Err(malformed());
    }
    let typed: Value = serde_json::from_str(text).map_err(|_| malformed())?;
    if native
        .get("structuredContent")
        .is_some_and(|structured| structured != &typed)
    {
        return Err(malformed());
    }
    let valid = typed["valid"].as_bool().ok_or_else(malformed)?;
    let errors = typed["errors"].as_array().ok_or_else(malformed)?;
    let warnings = typed["warnings"].as_array().ok_or_else(malformed)?;
    if errors.len() > 256
        || warnings.len() > 256
        || valid && (!errors.is_empty() || is_error)
        || !valid && errors.is_empty()
        || errors.iter().chain(warnings).any(|item| {
            !item.is_object()
                || item["message"]
                    .as_str()
                    .is_none_or(|message| message.len() > 8192)
        })
    {
        return Err(malformed());
    }
    let project = |items: &[Value], code, message| {
        items
            .iter()
            .map(|_| json!({"path":"graph","code":code,"message":message}))
            .collect::<Vec<_>>()
    };
    Ok(json!({"valid":valid,
        "errors":project(errors,"validation_error","Native validator reported an error"),
        "warnings":project(warnings,"validation_warning","Native validator reported a warning")}))
}

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
    #[serde(rename = "search_nodes_batch")]
    SearchNodesBatch(Vec<LocalN8nSearchNodesInput>),
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
    #[serde(rename = "nodes")]
    Nodes(Vec<LocalN8nNodeValidationInput>),
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
                LocalN8nKnowledgeAction::SearchNodes(_)
                | LocalN8nKnowledgeAction::SearchNodesBatch(_) => LocalN8nTool::SearchNodes,
                LocalN8nKnowledgeAction::GetNode(_) => LocalN8nTool::GetNode,
                LocalN8nKnowledgeAction::SearchTemplates(_) => LocalN8nTool::SearchTemplates,
                LocalN8nKnowledgeAction::GetTemplate(_) => LocalN8nTool::GetTemplate,
            },
            Self::ValidationRun(input) => match &input.subject {
                LocalN8nValidationSubject::Node(_) | LocalN8nValidationSubject::Nodes(_) => {
                    LocalN8nTool::ValidateNode
                }
                LocalN8nValidationSubject::Workflow(_) => LocalN8nTool::ValidateWorkflow,
            },
        }
    }

    fn into_provider_request(self) -> Result<LocalMcpRequest, LocalN8nDispatchError> {
        match self {
            Self::KnowledgeQuery(input) => {
                validate_correlation_id(&input.correlation_id)?;
                if let LocalN8nKnowledgeAction::SearchNodesBatch(queries) = input.action {
                    if !(1..=20).contains(&queries.len()) {
                        return Err(invalid_request());
                    }
                    let mut calls = Vec::with_capacity(queries.len());
                    for query in queries {
                        let (tool, arguments) =
                            LocalN8nKnowledgeAction::SearchNodes(query).into_call()?;
                        calls.push(LocalMcpCall {
                            tool: tool.as_str().to_owned(),
                            arguments,
                        });
                    }
                    return Ok(LocalMcpRequest {
                        correlation_id: input.correlation_id,
                        calls,
                    });
                }
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
                if let LocalN8nValidationSubject::Nodes(nodes) = input.subject {
                    if !(1..=50).contains(&nodes.len()) {
                        return Err(invalid_request());
                    }
                    let mut calls = Vec::with_capacity(nodes.len());
                    for node in nodes {
                        let (tool, arguments) = LocalN8nValidationRun {
                            correlation_id: correlation_id.clone(),
                            subject: LocalN8nValidationSubject::Node(node),
                        }
                        .into_call()?;
                        calls.push(LocalMcpCall {
                            tool: tool.as_str().to_string(),
                            arguments,
                        });
                    }
                    return Ok(LocalMcpRequest {
                        correlation_id,
                        calls,
                    });
                }
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
            Self::SearchNodesBatch(_) => Err(invalid_request()),
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
            LocalN8nValidationSubject::Nodes(_) => Err(invalid_request()),
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
    /// Validate one invocation-captured current graph with a shared deadline.
    /// This does not introduce an unverified provider or a public raw graph route.
    ///
    /// # Errors
    /// Rejects oversized graphs, cancellation, and native provider failure.
    pub fn validate_current_graph(
        &self,
        correlation_id: String,
        graph: Value,
        profile: LocalN8nValidationProfile,
        cancelled: &Arc<AtomicBool>,
        deadline: std::time::Instant,
    ) -> Result<LocalN8nDispatchResponse, LocalN8nDispatchError> {
        validate_correlation_id(&correlation_id)?;
        let (_, arguments) = LocalN8nValidationRun {
            correlation_id: correlation_id.clone(),
            subject: LocalN8nValidationSubject::Workflow(LocalN8nWorkflowValidationInput {
                workflow: graph,
                options: Some(LocalN8nWorkflowValidationOptions {
                    validate_nodes: true,
                    validate_connections: true,
                    validate_expressions: true,
                    profile: Some(profile),
                }),
            }),
        }
        .into_call()?;
        let request = LocalMcpRequest {
            correlation_id,
            calls: vec![LocalMcpCall {
                tool: "validate_workflow".into(),
                arguments,
            }],
        };
        if serde_json::to_vec(&request)
            .map_err(|_| invalid_request())?
            .len()
            > self.max_input_bytes
        {
            return Err(LocalN8nDispatchError::new(
                LocalN8nDispatchErrorCode::InputTooLarge,
            ));
        }
        let result = self
            .provider
            .run_once_until(request, cancelled, Some(deadline))
            .map_err(|error| map_provider_error(&error))?;
        Ok(LocalN8nDispatchResponse {
            operation: LocalN8nOperationKind::ValidationRun,
            result,
        })
    }

    /// Validate exactly the two current graphs captured by one admitted host
    /// invocation. This is not a new model-facing dispatch operation.
    ///
    /// # Errors
    /// Rejects oversized graphs, cancellation, and native provider failure.
    pub fn validate_current_pair(
        &self,
        correlation_id: String,
        graphs: [Value; 2],
        cancelled: &Arc<AtomicBool>,
        deadline: std::time::Instant,
    ) -> Result<LocalN8nDispatchResponse, LocalN8nDispatchError> {
        validate_correlation_id(&correlation_id)?;
        let mut calls = Vec::with_capacity(2);
        for workflow in graphs {
            let (_, arguments) = LocalN8nValidationRun {
                correlation_id: correlation_id.clone(),
                subject: LocalN8nValidationSubject::Workflow(LocalN8nWorkflowValidationInput {
                    workflow,
                    options: Some(LocalN8nWorkflowValidationOptions {
                        validate_nodes: true,
                        validate_connections: true,
                        validate_expressions: true,
                        profile: Some(LocalN8nValidationProfile::Runtime),
                    }),
                }),
            }
            .into_call()?;
            calls.push(LocalMcpCall {
                tool: "validate_workflow".to_owned(),
                arguments,
            });
        }
        let request = LocalMcpRequest {
            correlation_id,
            calls,
        };
        if serde_json::to_vec(&request)
            .map_err(|_| invalid_request())?
            .len()
            > self.max_input_bytes
        {
            return Err(LocalN8nDispatchError::new(
                LocalN8nDispatchErrorCode::InputTooLarge,
            ));
        }
        let result = self
            .provider
            .run_once_until(request, cancelled, Some(deadline))
            .map_err(|error| map_provider_error(&error))?;
        Ok(LocalN8nDispatchResponse {
            operation: LocalN8nOperationKind::ValidationRun,
            result,
        })
    }

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
            .run_once_with_cancel(provider_request, &cancelled)
            .map_err(|error| map_provider_error(&error))?;
        let response = LocalN8nDispatchResponse { operation, result };
        // Retain the dispatch-owned cancellation flag through response construction,
        // matching its original end-of-dispatch lifetime.
        drop(cancelled);
        Ok(response)
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

#[cfg(test)]
mod typed_batch_tests {
    use super::*;

    #[test]
    #[ignore = "requires the existing fixed network-disabled local catalog; explicit synthetic current-graph process check"]
    fn installed_local_current_graph_profiles_deadline_cancel_and_teardown() {
        let policy: fcp_manifest::LocalMcpPolicy = serde_json::from_slice(
            &std::fs::read("/usr/local/lib/fwc-n8n/current/policy/local-mcp.json")
                .expect("public installed policy"),
        )
        .unwrap();
        assert!(policy.network_disabled);
        let bound = policy.max_request_bytes as usize;
        // This public-policy test factory is not candidate signed-current admission.
        let dispatcher =
            LocalN8nDispatcher::with_max_input_bytes(LocalMcpProvider::new(policy).unwrap(), bound);
        for profile in [
            LocalN8nValidationProfile::Minimal,
            LocalN8nValidationProfile::Runtime,
            LocalN8nValidationProfile::AiFriendly,
            LocalN8nValidationProfile::Strict,
        ] {
            let result = dispatcher
                .validate_current_graph(
                    "synthetic-remote-current".into(),
                    json!({"nodes":[],"connections":{}}),
                    profile,
                    &Arc::new(AtomicBool::new(false)),
                    std::time::Instant::now() + std::time::Duration::from_secs(10),
                )
                .unwrap();
            assert_eq!(result.result.status, crate::LocalMcpResultStatus::Completed);
            assert!(result.result.startup.network_disabled);
            assert!(
                result.result.shutdown.completion.reaped
                    && result.result.shutdown.completion.group_absent
            );
            assert!(result.result.teardown_error_code.is_none());
            assert_eq!(result.result.responses.len(), 1);
            let safe = project_local_n8n_validation_call(&result.result.responses[0]).unwrap();
            assert_eq!(safe["valid"], true);
        }
        for (cancelled, deadline) in [
            (
                true,
                std::time::Instant::now() + std::time::Duration::from_secs(10),
            ),
            (false, std::time::Instant::now()),
        ] {
            let result = dispatcher.validate_current_graph(
                "synthetic-remote-refusal".into(),
                json!({"nodes":[],"connections":{}}),
                LocalN8nValidationProfile::Runtime,
                &Arc::new(AtomicBool::new(cancelled)),
                deadline,
            );
            assert!(
                result.is_err()
                    || result.is_ok_and(
                        |result| result.result.status != crate::LocalMcpResultStatus::Completed
                    )
            );
        }
    }

    #[test]
    #[ignore = "requires the existing installed fixed network-disabled local catalog; run explicitly"]
    fn installed_local_current_pair_native_validation_and_teardown() {
        let bytes = std::fs::read("/usr/local/lib/fwc-n8n/current/policy/local-mcp.json")
            .expect("existing public installed policy");
        let policy: fcp_manifest::LocalMcpPolicy =
            serde_json::from_slice(&bytes).expect("closed installed policy");
        assert!(policy.network_disabled);
        assert!(policy.max_sequential_calls >= 2);
        let bound = policy.max_request_bytes as usize;
        // Test-only policy injection exercises the actual local process and
        // dispatcher, not candidate installed trust or production broker admission.
        let provider = LocalMcpProvider::new(policy).expect("native fixed policy");
        let dispatcher = LocalN8nDispatcher::with_max_input_bytes(provider, bound);
        let result = dispatcher
            .validate_current_pair(
                "synthetic-current-pair".to_owned(),
                [
                    json!({"nodes":[],"connections":{}}),
                    json!({"nodes":[],"connections":{}}),
                ],
                &Arc::new(AtomicBool::new(false)),
                std::time::Instant::now() + std::time::Duration::from_secs(10),
            )
            .expect("native local pair");
        assert_eq!(result.result.status, crate::LocalMcpResultStatus::Completed);
        assert!(result.result.startup.network_disabled);
        assert!(
            result.result.shutdown.completion.reaped
                && result.result.shutdown.completion.group_absent
        );
        assert!(result.result.teardown_error_code.is_none());
        assert_eq!(result.result.responses.len(), 2);
        for native in &result.result.responses {
            let safe =
                project_local_n8n_validation_call(native).expect("native serialized validation");
            assert_eq!(safe["valid"], true);
            assert_eq!(safe["errors"], json!([]));
            assert!(!safe["warnings"].as_array().unwrap().is_empty());
        }
        println!("native_calls=2 network_disabled=true owned_reaped=true group_absent=true");
    }

    #[test]
    fn nodes_batch_serialization_preserves_profiles_and_denies_bounds_before_provider() {
        for profile in ["minimal", "runtime", "ai-friendly", "strict"] {
            let request: LocalN8nDispatchRequest = serde_json::from_value(json!({
                "operation":"n8n.validation.run","input":{"correlation_id":"batch-one",
                    "subject":{"nodes":[{"nodeType":"nodes-base.noOp","config":{},"profile":profile},
                        {"nodeType":"nodes-base.set","config":{"mode":"manual"},"profile":profile}]}}})).unwrap();
            let provider = request.into_provider_request().unwrap();
            assert_eq!(provider.calls.len(), 2);
            assert!(
                provider.calls.iter().all(
                    |call| call.tool == "validate_node" && call.arguments["profile"] == profile
                )
            );
        }
        for count in [0, 51] {
            let request: LocalN8nDispatchRequest = serde_json::from_value(json!({"operation":"n8n.validation.run",
                "input":{"correlation_id":"batch-one","subject":{"nodes":vec![json!({"nodeType":"nodes-base.noOp","config":{}});count]}}})).unwrap();
            assert!(request.into_provider_request().is_err());
        }
        let request: LocalN8nDispatchRequest = serde_json::from_value(json!({"operation":"n8n.validation.run",
            "input":{"correlation_id":"batch-one","subject":{"nodes":[{"nodeType":"nodes-base.noOp","config":"PRIVATE_CANARY"}]}}})).unwrap();
        assert!(request.into_provider_request().is_err());
        assert!(serde_json::from_value::<LocalN8nDispatchRequest>(json!({"operation":"n8n.validation.run",
            "input":{"correlation_id":"batch-one","subject":{"nodes":[{"nodeType":"nodes-base.noOp","config":{},"executable":"PRIVATE_CANARY"}]}}})).is_err());
    }
}
