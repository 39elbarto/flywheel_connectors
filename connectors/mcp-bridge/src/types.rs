//! MCP protocol types for the bridge connector.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Closed native read actions. Neither a caller-selected MCP name nor an
/// arbitrary argument object can enter this lane.
#[derive(Clone, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum TypedN8nRead {
    SdkReference {
        section: String,
    },
    WorkflowBestPractices {
        technique: String,
    },
    Nodes {
        nodes: Vec<TypedN8nNode>,
    },
    Projects {
        query: Option<String>,
        limit: u16,
    },
    Folders {
        #[serde(rename = "projectId")]
        project_id: String,
        query: Option<String>,
        limit: u16,
    },
    Tags {
        limit: u16,
    },
    Workflows {
        query: Option<String>,
        #[serde(rename = "projectId")]
        project_id: Option<String>,
        tags: Option<Vec<String>>,
        #[serde(rename = "sortBy")]
        sort_by: Option<String>,
        #[serde(rename = "folderId")]
        folder_id: Option<String>,
        #[serde(rename = "includeSubfolders")]
        include_subfolders: Option<bool>,
        limit: u16,
    },
    Credentials {
        query: Option<String>,
        #[serde(rename = "type")]
        credential_type: Option<String>,
        #[serde(rename = "projectId")]
        project_id: Option<String>,
        #[serde(rename = "onlySharedWithMe")]
        only_shared_with_me: Option<bool>,
        limit: u16,
    },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TypedN8nNode {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "type")]
    node_type: String,
    #[serde(rename = "typeVersion", skip_serializing_if = "Option::is_none")]
    type_version: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parameters: Option<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subnodes: Option<TypedN8nSubnodes>,
    #[serde(rename = "isToolNode", skip_serializing_if = "Option::is_none")]
    is_tool_node: Option<bool>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TypedN8nSubnodes {
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<TypedN8nNodeRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory: Option<TypedN8nNodeRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<TypedN8nNodeRef>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TypedN8nNodeRef {
    #[serde(rename = "type")]
    node_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<f64>,
}

fn bounded_read_text(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

impl TypedN8nRead {
    pub(crate) const fn action(&self) -> &'static str {
        match self {
            Self::SdkReference { .. } => "sdk_reference",
            Self::WorkflowBestPractices { .. } => "workflow_best_practices",
            Self::Nodes { .. } => "nodes",
            Self::Projects { .. } => "projects",
            Self::Folders { .. } => "folders",
            Self::Tags { .. } => "tags",
            Self::Workflows { .. } => "workflows",
            Self::Credentials { .. } => "credentials",
        }
    }

    pub(crate) const fn tool(&self) -> &'static str {
        match self {
            Self::SdkReference { .. } => "get_workflow_sdk_reference",
            Self::WorkflowBestPractices { .. } => "get_workflow_best_practices",
            Self::Nodes { .. } => "validate_node_config",
            Self::Projects { .. } => "search_projects",
            Self::Folders { .. } => "search_folders",
            Self::Tags { .. } => "list_workflow_tags",
            Self::Workflows { .. } => "search_workflows",
            Self::Credentials { .. } => "list_credentials",
        }
    }

    pub(crate) const fn schema_pins(&self) -> (&'static str, &'static str) {
        match self {
            Self::SdkReference { .. } => (
                "sha256:c0c69d975afd16845bee57cbd37e0cf0a50b7d5741810625963dedf60279fda2",
                "sha256:555b1d6f84918d5b03adfd55c3f652d2b0ac0457f80e9e811963fbbbc61426dc",
            ),
            Self::WorkflowBestPractices { .. } => (
                "sha256:d95120da8063c53d7dc379b938043cfdc81da869c40a33ce608fe76ddda31423",
                "sha256:9530d1f518b2640320f8ffbfd971d662b3f00558be8b3ff9418fe0d916a1728c",
            ),
            Self::Nodes { .. } => (
                "sha256:37231a38664a9375573c84d8484fc30cef2e99efbca5f6172f1a4cd308c34f8d",
                "sha256:11fa90ee8936aa8946e5a1556d3c03ad3640dc837731c0302f4b0dc40e5920a0",
            ),
            Self::Projects { .. } => (
                "sha256:d37453c28e110141c606ef901d7651367544f8d272f183bd181978e086712200",
                "sha256:28c5f100b2daae7bff8225376c4bed8000f67b785f174a6ae1636ff90fc5126e",
            ),
            Self::Folders { .. } => (
                "sha256:20a822576c3a6e883e942dfc695ccc7114ffc18e2e3a7bf555af8b07da314269",
                "sha256:d0af92b84b63148c231ee85778e7af9b765cf6edc4e8d638eec067220b496487",
            ),
            Self::Tags { .. } => (
                "sha256:c0602bd0434d0c2aeafb763bc12512b63443448c9331dc0cb1ebf02973603e8e",
                "sha256:5481cbd6dedd4134020f44bdcc900e40eb9802e70d5ccedf8dda6252d55b720b",
            ),
            Self::Workflows { .. } => (
                "sha256:179069c19267545edc43d943befdcff9743bbf4557e6a10efe7fa0cb7b91e714",
                "sha256:1b9737c076b6f72be4f1521911b589fce8f9954bdc7487ea12933f2bd0586206",
            ),
            Self::Credentials { .. } => (
                "sha256:a29acfec48d5f9919cb4fb65ce44c7fe544624a4ea537638d148b5c93ee3a821",
                "sha256:305aeecb628786f249e9f71a2be18fc26a212b8dd4f090ff073c701a8b4563ac",
            ),
        }
    }

    pub(crate) fn arguments(&self) -> Result<Value, &'static str> {
        let invalid = "typed_n8n_read_input_invalid";
        match self {
            Self::Projects { query, limit } | Self::Folders { query, limit, .. } => {
                if !(1..=100).contains(limit)
                    || query
                        .as_ref()
                        .is_some_and(|query| !bounded_read_text(query, 256))
                {
                    return Err(invalid);
                }
                let mut arguments = json!({"limit":limit});
                if let Some(query) = query {
                    arguments["query"] = json!(query);
                }
                if let Self::Folders { project_id, .. } = self {
                    if !bounded_read_text(project_id, 256) {
                        return Err(invalid);
                    }
                    arguments["projectId"] = json!(project_id);
                }
                Ok(arguments)
            }
            Self::Tags { limit } => {
                if !(1..=500).contains(limit) {
                    return Err(invalid);
                }
                Ok(json!({"limit":limit}))
            }
            Self::Workflows {
                query,
                project_id,
                tags,
                sort_by,
                folder_id,
                include_subfolders,
                limit,
            } => {
                if !(1..=200).contains(limit)
                    || query
                        .iter()
                        .chain(project_id.iter())
                        .any(|text| !bounded_read_text(text, 256))
                    || tags.as_ref().is_some_and(|tags| {
                        tags.is_empty()
                            || tags.len() > 10
                            || tags.iter().any(|tag| !bounded_read_text(tag, 256))
                    })
                    || sort_by.as_ref().is_some_and(|sort| {
                        !matches!(
                            sort.as_str(),
                            "name:asc"
                                | "name:desc"
                                | "createdAt:asc"
                                | "createdAt:desc"
                                | "updatedAt:asc"
                                | "updatedAt:desc"
                        )
                    })
                    || folder_id.as_ref().is_some_and(|id| {
                        !bounded_read_text(id, 256)
                            || !id
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    })
                    || include_subfolders.is_some() && folder_id.is_none()
                {
                    return Err(invalid);
                }
                let mut arguments = json!({"limit":limit});
                for (key, value) in [
                    ("query", query),
                    ("projectId", project_id),
                    ("sortBy", sort_by),
                    ("folderId", folder_id),
                ] {
                    if let Some(value) = value {
                        arguments[key] = json!(value);
                    }
                }
                if let Some(tags) = tags {
                    arguments["tags"] = json!(tags);
                }
                if let Some(value) = include_subfolders {
                    arguments["includeSubfolders"] = json!(value);
                }
                Ok(arguments)
            }
            Self::SdkReference { section } => {
                if !matches!(
                    section.as_str(),
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
                    return Err(invalid);
                }
                Ok(json!({"section":section}))
            }
            Self::WorkflowBestPractices { technique } => {
                if !matches!(
                    technique.as_str(),
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
                    return Err(invalid);
                }
                Ok(json!({"technique":technique}))
            }
            Self::Nodes { nodes } => {
                if nodes.is_empty() || nodes.len() > 50 {
                    return Err(invalid);
                }
                for node in nodes {
                    if !bounded_read_text(&node.node_type, 256)
                        || node
                            .name
                            .as_ref()
                            .is_some_and(|value| !bounded_read_text(value, 256))
                        || node.type_version.is_some_and(|version| {
                            !version.is_finite() || version <= 0.0 || version > 1000.0
                        })
                    {
                        return Err(invalid);
                    }
                    if let Some(subnodes) = &node.subnodes {
                        if subnodes
                            .tools
                            .as_ref()
                            .is_some_and(|tools| tools.len() > 20)
                        {
                            return Err(invalid);
                        }
                        for reference in subnodes
                            .model
                            .iter()
                            .chain(subnodes.memory.iter())
                            .chain(subnodes.tools.iter().flatten())
                        {
                            if !bounded_read_text(&reference.node_type, 256)
                                || reference.version.is_some_and(|version| {
                                    !version.is_finite() || version <= 0.0 || version > 1000.0
                                })
                            {
                                return Err(invalid);
                            }
                        }
                    }
                }
                let arguments = json!({"nodes":nodes});
                if serde_json::to_vec(&arguments).map_err(|_| invalid)?.len() > 128 * 1024 {
                    return Err(invalid);
                }
                Ok(arguments)
            }
            Self::Credentials {
                query,
                credential_type,
                project_id,
                only_shared_with_me,
                limit,
            } => {
                if !(1..=200).contains(limit)
                    || query
                        .iter()
                        .chain(credential_type.iter())
                        .chain(project_id.iter())
                        .any(|text| !bounded_read_text(text, 256))
                {
                    return Err(invalid);
                }
                let mut arguments = serde_json::Map::new();
                for (key, value) in [
                    ("query", query),
                    ("type", credential_type),
                    ("projectId", project_id),
                ] {
                    if let Some(value) = value {
                        arguments.insert(key.into(), json!(value));
                    }
                }
                if let Some(value) = only_shared_with_me {
                    arguments.insert("onlySharedWithMe".into(), json!(value));
                }
                arguments.insert("limit".into(), json!(limit));
                Ok(Value::Object(arguments))
            }
        }
    }

    /// Project only the closed public result; raw native messages and unknown
    /// credential fields remain process-local.
    pub(crate) fn project(&self, server: &str, result: &Value) -> Result<Value, &'static str> {
        let invalid = "typed_n8n_read_response_invalid";
        if !matches!(server, "eec" | "hetzner")
            || serde_json::to_vec(result).map_err(|_| invalid)?.len() > 512 * 1024
        {
            return Err(invalid);
        }
        let content = result["content"]
            .as_array()
            .filter(|content| content.len() == 1)
            .ok_or(invalid)?;
        if content[0]["type"] != "text" {
            return Err(invalid);
        }
        let text = content[0]["text"]
            .as_str()
            .filter(|text| text.len() <= 256 * 1024)
            .ok_or(invalid)?;
        let native = result
            .get("structuredContent")
            .filter(|value| value.is_object())
            .ok_or(invalid)?;
        let is_error = match result.get("isError") {
            None => false,
            Some(Value::Bool(value)) => *value,
            _ => return Err(invalid),
        };
        if !matches!(
            self,
            Self::SdkReference { .. } | Self::WorkflowBestPractices { .. }
        ) {
            let decoded: Value = serde_json::from_str(text).map_err(|_| invalid)?;
            if &decoded != native {
                return Err(invalid);
            }
        }
        let data = match self {
            Self::Projects { limit, .. }
            | Self::Folders { limit, .. }
            | Self::Tags { limit }
            | Self::Workflows { limit, .. } => {
                if is_error || native.get("error").is_some() {
                    return Err(invalid);
                }
                let rows = native["data"]
                    .as_array()
                    .filter(|rows| rows.len() <= usize::from(*limit))
                    .ok_or(invalid)?;
                let count = native["count"].as_u64().ok_or(invalid)?;
                let total = if matches!(self, Self::Tags { .. }) {
                    if count != rows.len() as u64 {
                        return Err(invalid);
                    }
                    native["totalCount"].as_u64().ok_or(invalid)?
                } else {
                    count
                };
                if total < rows.len() as u64 {
                    return Err(invalid);
                }
                let field = |value: &Value| {
                    value
                        .as_str()
                        .filter(|text| bounded_read_text(text, 256))
                        .map(str::to_owned)
                        .ok_or(invalid)
                };
                let mut ids = std::collections::BTreeSet::new();
                let mut items = Vec::new();
                for row in rows {
                    let id = field(&row["id"])?;
                    if !ids.insert(id.clone()) {
                        return Err(invalid);
                    }
                    let name = field(&row["name"])?;
                    let collection = self.action();
                    let encoded = percent_encoding::utf8_percent_encode(
                        &id,
                        percent_encoding::NON_ALPHANUMERIC,
                    );
                    let mut item = json!({"id":id,"name":name,"resourceUri":format!("fwc-n8n://{server}/{collection}/{encoded}")});
                    match self {
                        Self::Projects { .. } => {
                            let kind = row["type"]
                                .as_str()
                                .filter(|kind| matches!(*kind, "personal" | "team"))
                                .ok_or(invalid)?;
                            item["type"] = json!(kind);
                        }
                        Self::Folders { project_id, .. } => {
                            item["type"] = json!("folder");
                            item["projectId"] = json!(project_id);
                            item["parentFolderId"] = match row.get("parentFolderId") {
                                Some(Value::Null) => Value::Null,
                                Some(value) => json!(field(value)?),
                                None => return Err(invalid),
                            };
                            let path = row["path"]
                                .as_array()
                                .filter(|path| !path.is_empty() && path.len() <= 64)
                                .ok_or(invalid)?;
                            item["path"] =
                                json!(path.iter().map(&field).collect::<Result<Vec<_>, _>>()?);
                        }
                        Self::Tags { .. } => {
                            item["type"] = json!("tag");
                            item["usageCount"] = json!(row["usageCount"].as_u64().ok_or(invalid)?);
                        }
                        Self::Workflows { .. } => {
                            item["active"] = json!(row["active"].as_bool().ok_or(invalid)?);
                            item["availableInMCP"] =
                                json!(row["availableInMCP"].as_bool().ok_or(invalid)?);
                            for key in ["createdAt", "updatedAt"] {
                                item[key] = json!(field(&row[key])?);
                            }
                            item["parentFolderId"] = match row.get("parentFolderId") {
                                Some(Value::Null) => Value::Null,
                                Some(value) => json!(field(value)?),
                                None => return Err(invalid),
                            };
                            let tags = row["tags"]
                                .as_array()
                                .filter(|tags| tags.len() <= 100)
                                .ok_or(invalid)?;
                            item["tags"] = json!(
                                tags.iter()
                                    .map(|tag| Ok(
                                        json!({"id":field(&tag["id"])?,"name":field(&tag["name"])?})
                                    ))
                                    .collect::<Result<Vec<_>, &str>>()?
                            );
                        }
                        _ => return Err(invalid),
                    }
                    items.push(item);
                }
                // A native workflow count can describe only the returned rows.
                // Reaching the requested limit therefore cannot establish EOF,
                // even when count equals length. Never admit that cutoff as a
                // complete globally sorted/filterable snapshot.
                let complete = total == rows.len() as u64
                    && (!matches!(self, Self::Workflows { .. })
                        || rows.len() < usize::from(*limit));
                json!({"items":items,"page":{"returnedCount":rows.len(),"total":total,"limit":limit,"continuation":"unavailable","completeness":if complete {"complete"} else {"partial"}}})
            }
            Self::SdkReference { section } => {
                if is_error
                    || native["reference"].as_str() != Some(text)
                    || text.is_empty()
                    || text
                        .chars()
                        .any(|value| value.is_control() && !matches!(value, '\n' | '\r' | '\t'))
                {
                    return Err(invalid);
                }
                json!({"section":section,"reference":text,"digest":read_document_digest(text)})
            }
            Self::WorkflowBestPractices { technique } => {
                if is_error
                    || native["technique"] != *technique
                    || !native["message"].is_string()
                    || text.is_empty()
                    || text
                        .chars()
                        .any(|value| value.is_control() && !matches!(value, '\n' | '\r' | '\t'))
                {
                    return Err(invalid);
                }
                if let Some(documentation) = native.get("documentation") {
                    if documentation.as_str() != Some(text) {
                        return Err(invalid);
                    }
                } else if technique != "list" && native["message"].as_str() != Some(text) {
                    return Err(invalid);
                }
                json!({"technique":technique,"guidance":text,"digest":read_document_digest(text)})
            }
            Self::Nodes { nodes } => {
                if is_error || native.get("error").is_some() {
                    return Err(invalid);
                }
                let results = native["results"]
                    .as_array()
                    .filter(|results| results.len() == nodes.len())
                    .ok_or(invalid)?;
                let mut errors = Vec::new();
                let mut valid = true;
                for (index, (node, result)) in nodes.iter().zip(results).enumerate() {
                    if result["index"].as_u64() != Some(index as u64)
                        || result["type"] != node.node_type
                        || result.get("name").and_then(Value::as_str) != node.name.as_deref()
                    {
                        return Err(invalid);
                    }
                    let node_valid = result["valid"].as_bool().ok_or(invalid)?;
                    let native_errors = match result.get("errors") {
                        None if node_valid => &[][..],
                        Some(Value::Array(errors)) => errors.as_slice(),
                        _ => return Err(invalid),
                    };
                    if native_errors.len() > 256
                        || node_valid && !native_errors.is_empty()
                        || !node_valid && native_errors.is_empty()
                    {
                        return Err(invalid);
                    }
                    for error in native_errors {
                        if errors.len() >= 256
                            || !error.is_object()
                            || error["path"].as_str().is_none_or(|text| text.len() > 1024)
                            || error["message"]
                                .as_str()
                                .is_none_or(|text| text.len() > 8192)
                        {
                            return Err(invalid);
                        }
                        errors.push(json!({"path":format!("nodes[{index}]"),"code":"sdk_node_validation_error","message":"Native node validator reported an error"}));
                    }
                    valid &= node_valid;
                }
                if native["valid"].as_bool() != Some(valid) {
                    return Err(invalid);
                }
                json!({"valid":valid,"errors":errors,"warnings":[]})
            }
            Self::Credentials { limit, .. } => {
                if is_error || native.get("error").is_some() {
                    return Err(invalid);
                }
                let rows = native["data"]
                    .as_array()
                    .filter(|rows| rows.len() <= usize::from(*limit))
                    .ok_or(invalid)?;
                if native["count"].as_u64() != Some(rows.len() as u64) {
                    return Err(invalid);
                }
                let field = |value: &Value| {
                    value
                        .as_str()
                        .filter(|text| bounded_read_text(text, 256))
                        .map(str::to_owned)
                        .ok_or(invalid)
                };
                let mut ids = std::collections::BTreeSet::new();
                let mut credentials = Vec::new();
                for row in rows {
                    let id = field(&row["id"])?;
                    if !ids.insert(id.clone()) {
                        return Err(invalid);
                    }
                    let scopes = row["scopes"]
                        .as_array()
                        .filter(|scopes| scopes.len() <= 64)
                        .ok_or(invalid)?
                        .iter()
                        .map(&field)
                        .collect::<Result<Vec<_>, _>>()?;
                    let home = match row.get("homeProject") {
                        Some(Value::Null) => Value::Null,
                        Some(home) if home.is_object() => {
                            json!({"id":field(&home["id"])?,"name":field(&home["name"])?,"type":field(&home["type"])?})
                        }
                        _ => return Err(invalid),
                    };
                    let encoded = percent_encoding::utf8_percent_encode(
                        &id,
                        percent_encoding::NON_ALPHANUMERIC,
                    );
                    credentials.push(json!({"resourceUri":format!("fwc-n8n://{server}/credentials/{encoded}"),"id":id,"name":field(&row["name"])?,"type":field(&row["type"])?,"scopes":scopes,
                        "isManaged":row["isManaged"].as_bool().ok_or(invalid)?,"isGlobal":row["isGlobal"].as_bool().ok_or(invalid)?,"homeProject":home}));
                }
                let mut output = json!({"credentials":credentials,"page":{"returnedCount":rows.len(),"limit":limit,"continuation":"unavailable","completeness":"not_established"}});
                if rows.len() == usize::from(*limit) {
                    output["page"]["hint"] = json!(
                        "Result may be limited; narrow query, type, projectId or sharing filters."
                    );
                }
                output
            }
        };
        Ok(json!({"serverId":server,"action":self.action(),"data":data}))
    }
}

fn read_document_digest(text: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"FCP/n8n/knowledge-public/v1\0");
    hasher.update(text.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// An MCP tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    /// The name of the tool.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema for the tool's input.
    #[serde(rename = "inputSchema", skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<serde_json::Value>,
}

/// An MCP resource definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResource {
    /// The URI of the resource.
    pub uri: String,
    /// Human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type hint.
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Content returned by a resource read or tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceContent {
    /// The URI of the content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    /// MIME type.
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Text content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Base64-encoded blob content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
}

/// Content item from a tool call result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolContent {
    /// Content type: "text", "image", or "resource".
    #[serde(rename = "type")]
    pub content_type: String,
    /// Text content (for type="text").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Extra fields.
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// An MCP prompt definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPrompt {
    /// The name of the prompt.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Arguments the prompt accepts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<PromptArgument>>,
}

/// An argument definition for an MCP prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    /// Argument name.
    pub name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Whether the argument is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcResponse {
    #[allow(dead_code)]
    pub jsonrpc: Option<String>,
    #[allow(dead_code)]
    pub id: Option<serde_json::Value>,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// MCP API error response body (HTTP-level error).
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<String>,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn workflow_search_limit_saturation_never_proves_complete_snapshot() {
        let read: super::TypedN8nRead = serde_json::from_value(json!({
            "action":"workflows","limit":2
        }))
        .unwrap();
        let row = |id: &str| {
            json!({"id":id,"name":"Synthetic","active":false,
            "availableInMCP":false,"createdAt":"2026-10-04T00:00:00Z",
            "updatedAt":"2026-10-04T00:00:00Z","parentFolderId":null,"tags":[]})
        };
        for (rows, count, expected) in [
            (vec![row("one")], 1, "complete"),
            (vec![row("one"), row("two")], 2, "partial"),
            (vec![row("one")], 3, "partial"),
        ] {
            let data = json!({"data":rows,"count":count});
            let response = json!({"structuredContent":data,
                "content":[{"type":"text","text":data.to_string()}]});
            let projected = read.project("eec", &response).unwrap();
            assert_eq!(projected["data"]["page"]["completeness"], expected);
        }
    }

    #[test]
    fn retired_workflow_code_is_not_a_typed_action() {
        assert!(
            serde_json::from_value::<super::TypedN8nRead>(
                serde_json::json!({"action":"workflow_code","code":"HOSTILE_SDK_CANARY"}),
            )
            .is_err()
        );
        let reference: super::TypedN8nRead = serde_json::from_value(
            serde_json::json!({"action":"sdk_reference","section":"patterns"}),
        )
        .unwrap();
        assert_eq!(reference.tool(), "get_workflow_sdk_reference");
    }

    #[test]
    fn typed_n8n_structure_native_shapes_keep_counts_and_refuse_invented_filters() {
        for (input, tool, row, total) in [
            (
                json!({"action":"projects","query":"fixture","limit":100}),
                "search_projects",
                json!({"id":"p","name":"fixture","type":"team","hint":"PRIVATE_CANARY"}),
                2,
            ),
            (
                json!({"action":"folders","projectId":"p","limit":100}),
                "search_folders",
                json!({"id":"f","name":"fixture","parentFolderId":null,"path":["fixture"]}),
                1,
            ),
            (
                json!({"action":"tags","limit":500}),
                "list_workflow_tags",
                json!({"id":"t","name":"fixture","usageCount":3,"createdAt":"2026-10-04","updatedAt":"2026-10-04"}),
                1,
            ),
        ] {
            let read: super::TypedN8nRead = serde_json::from_value(input).unwrap();
            assert_eq!(read.tool(), tool);
            read.arguments().unwrap();
            let mut output = json!({"data":[row],"count":total});
            if tool == "list_workflow_tags" {
                output["totalCount"] = json!(total);
            }
            let native = json!({"structuredContent":output,"content":[{"type":"text","text":output.to_string()}]});
            let projected = read.project("eec", &native).unwrap();
            assert_eq!(projected["data"]["page"]["total"], total);
            assert_eq!(
                projected["data"]["page"]["completeness"],
                if total == 1 { "complete" } else { "partial" }
            );
            assert!(!projected.to_string().contains("PRIVATE_CANARY"));
            let mut failed = native;
            failed["isError"] = json!(true);
            assert!(read.project("eec", &failed).is_err());
        }
        for input in [
            json!({"action":"projects","limit":100,"cursor":"invented"}),
            json!({"action":"folders","projectId":"p","parentFolderId":"f","limit":100}),
            json!({"action":"workflows","limit":200,"active":true}),
            json!({"action":"workflows","limit":200,"isArchived":true}),
        ] {
            assert!(serde_json::from_value::<super::TypedN8nRead>(input).is_err());
        }
        let input = json!({"action":"workflows","query":"description match","folderId":"folder-1","includeSubfolders":true,"sortBy":"updatedAt:desc","tags":["fixture"],"limit":200});
        let read: super::TypedN8nRead = serde_json::from_value(input).unwrap();
        let arguments = read.arguments().unwrap();
        assert_eq!(arguments["query"], "description match");
        assert_eq!(arguments["folderId"], "folder-1");
        assert!(arguments.get("action").is_none());
    }
    #[test]
    fn typed_n8n_read_rejects_generic_calls_and_preserves_invalid_validation() {
        for input in [
            json!({"action":"publish_workflow","workflowId":"synthetic"}),
            json!({"action":"workflow_code","code":"synthetic","name":"execute_workflow"}),
            json!({"action":"credentials","limit":1,"url":"https://example.invalid"}),
            json!({"action":"nodes","nodes":[{"type":"synthetic","unknown":true}]}),
        ] {
            assert!(serde_json::from_value::<super::TypedN8nRead>(input).is_err());
        }
    }

    #[test]
    fn typed_n8n_credentials_projects_required_native_metadata_only() {
        let read: super::TypedN8nRead = serde_json::from_value(json!({
            "action":"credentials","projectId":"synthetic-project","onlySharedWithMe":true,"limit":1
        }))
        .unwrap();
        assert_eq!(
            read.arguments().unwrap(),
            json!({"projectId":"synthetic-project","onlySharedWithMe":true,"limit":1})
        );
        let structured = json!({"count":1,"data":[{"id":"synthetic","name":"fixture","type":"fixture","scopes":[],"isManaged":false,"isGlobal":false,"homeProject":null,"password":"PRIVATE_CANARY"}]});
        let mut native = json!({"content":[{"type":"text","text":structured.to_string()}],"structuredContent":structured});
        let projected = read.project("hetzner", &native).unwrap();
        assert_eq!(
            projected["data"]["credentials"][0]["homeProject"],
            Value::Null
        );
        assert_eq!(projected["data"]["page"]["completeness"], "not_established");
        assert!(!projected.to_string().contains("PRIVATE_CANARY"));
        native["structuredContent"]["count"] = json!(2);
        native["content"][0]["text"] = json!(native["structuredContent"].to_string());
        assert!(read.project("hetzner", &native).is_err());
    }
    use super::*;
    use serde_json::json;

    #[test]
    fn mcp_tool_roundtrip() {
        let t: McpTool = serde_json::from_value(json!({
            "name": "read_file",
            "description": "Read a file from disk",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }
        }))
        .unwrap();
        assert_eq!(t.name, "read_file");
        assert_eq!(t.description, Some("Read a file from disk".into()));
        assert!(t.input_schema.is_some());
        let re = serde_json::to_value(&t).unwrap();
        assert_eq!(re["name"], "read_file");
    }

    #[test]
    fn mcp_tool_minimal() {
        let t: McpTool = serde_json::from_value(json!({"name": "ping"})).unwrap();
        assert_eq!(t.name, "ping");
        assert!(t.description.is_none());
        assert!(t.input_schema.is_none());
    }

    #[test]
    fn mcp_resource_roundtrip() {
        let r: McpResource = serde_json::from_value(json!({
            "uri": "file:///tmp/data.txt",
            "name": "data.txt",
            "description": "Test data file",
            "mimeType": "text/plain"
        }))
        .unwrap();
        assert_eq!(r.uri, "file:///tmp/data.txt");
        assert_eq!(r.name, Some("data.txt".into()));
        assert_eq!(r.mime_type, Some("text/plain".into()));
        let re = serde_json::to_value(&r).unwrap();
        assert_eq!(re["uri"], "file:///tmp/data.txt");
    }

    #[test]
    fn mcp_resource_minimal() {
        let r: McpResource = serde_json::from_value(json!({"uri": "res://x"})).unwrap();
        assert_eq!(r.uri, "res://x");
        assert!(r.name.is_none());
        assert!(r.description.is_none());
        assert!(r.mime_type.is_none());
    }

    #[test]
    fn resource_content_roundtrip() {
        let c: ResourceContent = serde_json::from_value(json!({
            "uri": "file:///tmp/data.txt",
            "mimeType": "text/plain",
            "text": "Hello, world!"
        }))
        .unwrap();
        assert_eq!(c.uri, Some("file:///tmp/data.txt".into()));
        assert_eq!(c.text, Some("Hello, world!".into()));
        assert!(c.blob.is_none());
    }

    #[test]
    fn resource_content_blob() {
        let c: ResourceContent = serde_json::from_value(json!({
            "mimeType": "image/png",
            "blob": "iVBORw0KGgo="
        }))
        .unwrap();
        assert_eq!(c.blob, Some("iVBORw0KGgo=".into()));
        assert!(c.text.is_none());
    }

    #[test]
    fn resource_content_empty() {
        let c: ResourceContent = serde_json::from_value(json!({})).unwrap();
        assert!(c.uri.is_none());
        assert!(c.text.is_none());
        assert!(c.blob.is_none());
    }

    #[test]
    fn tool_content_roundtrip() {
        let c: ToolContent = serde_json::from_value(json!({
            "type": "text",
            "text": "result data"
        }))
        .unwrap();
        assert_eq!(c.content_type, "text");
        assert_eq!(c.text, Some("result data".into()));
    }

    #[test]
    fn tool_content_image() {
        let c: ToolContent = serde_json::from_value(json!({
            "type": "image",
            "data": "base64data",
            "mimeType": "image/png"
        }))
        .unwrap();
        assert_eq!(c.content_type, "image");
        assert!(c.text.is_none());
    }

    #[test]
    fn mcp_prompt_roundtrip() {
        let p: McpPrompt = serde_json::from_value(json!({
            "name": "summarize",
            "description": "Summarize text",
            "arguments": [
                {"name": "text", "description": "Text to summarize", "required": true}
            ]
        }))
        .unwrap();
        assert_eq!(p.name, "summarize");
        assert_eq!(p.description, Some("Summarize text".into()));
        let args = p.arguments.unwrap();
        assert_eq!(args.len(), 1);
        assert_eq!(args[0].name, "text");
        assert_eq!(args[0].required, Some(true));
    }

    #[test]
    fn mcp_prompt_minimal() {
        let p: McpPrompt = serde_json::from_value(json!({"name": "greeting"})).unwrap();
        assert_eq!(p.name, "greeting");
        assert!(p.description.is_none());
        assert!(p.arguments.is_none());
    }

    #[test]
    fn prompt_argument_roundtrip() {
        let a: PromptArgument = serde_json::from_value(json!({
            "name": "language",
            "description": "Target language",
            "required": false
        }))
        .unwrap();
        assert_eq!(a.name, "language");
        assert_eq!(a.required, Some(false));
    }

    #[test]
    fn prompt_argument_minimal() {
        let a: PromptArgument = serde_json::from_value(json!({"name": "input"})).unwrap();
        assert_eq!(a.name, "input");
        assert!(a.description.is_none());
        assert!(a.required.is_none());
    }

    #[test]
    fn jsonrpc_request_serializes() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "tools/list".into(),
            params: json!({}),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["method"], "tools/list");
    }

    #[test]
    fn jsonrpc_response_with_result() {
        let r: JsonRpcResponse = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": []}
        }))
        .unwrap();
        assert!(r.result.is_some());
        assert!(r.error.is_none());
    }

    #[test]
    fn jsonrpc_response_with_error() {
        let r: JsonRpcResponse = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        }))
        .unwrap();
        assert!(r.result.is_none());
        let err = r.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "Method not found");
    }

    #[test]
    fn jsonrpc_error_with_data() {
        let e: JsonRpcError = serde_json::from_value(json!({
            "code": -32600,
            "message": "Invalid Request",
            "data": {"detail": "missing method"}
        }))
        .unwrap();
        assert_eq!(e.code, -32600);
        assert!(e.data.is_some());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Not found",
            "error": "404"
        }))
        .unwrap();
        assert_eq!(e.message, Some("Not found".into()));
        assert_eq!(e.error, Some("404".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.error.is_none());
    }

    #[test]
    fn mcp_tool_serialize_skips_none() {
        let t = McpTool {
            name: "ping".into(),
            description: None,
            input_schema: None,
        };
        let v = serde_json::to_value(&t).unwrap();
        assert!(!v.as_object().unwrap().contains_key("description"));
        assert!(!v.as_object().unwrap().contains_key("inputSchema"));
    }

    #[test]
    fn mcp_resource_serialize_skips_none() {
        let r = McpResource {
            uri: "res://x".into(),
            name: None,
            description: None,
            mime_type: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(!v.as_object().unwrap().contains_key("name"));
        assert!(!v.as_object().unwrap().contains_key("mimeType"));
    }

    #[test]
    fn mcp_prompt_with_empty_arguments() {
        let p: McpPrompt = serde_json::from_value(json!({
            "name": "test",
            "arguments": []
        }))
        .unwrap();
        assert!(p.arguments.unwrap().is_empty());
    }

    #[test]
    fn mcp_prompt_with_multiple_arguments() {
        let p: McpPrompt = serde_json::from_value(json!({
            "name": "translate",
            "arguments": [
                {"name": "text", "required": true},
                {"name": "target_language", "required": true},
                {"name": "tone", "required": false}
            ]
        }))
        .unwrap();
        assert_eq!(p.arguments.unwrap().len(), 3);
    }

    #[test]
    fn resource_content_serialize_skips_none() {
        let c = ResourceContent {
            uri: Some("res://x".into()),
            mime_type: None,
            text: Some("hello".into()),
            blob: None,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert!(!v.as_object().unwrap().contains_key("mimeType"));
        assert!(!v.as_object().unwrap().contains_key("blob"));
        assert_eq!(v["text"], "hello");
    }

    #[test]
    fn mcp_tool_clone() {
        let t = McpTool {
            name: "read_file".into(),
            description: Some("Read a file".into()),
            input_schema: Some(json!({"type": "object"})),
        };
        let cloned = McpTool::clone(&t);
        assert_eq!(cloned.name, "read_file");
        assert_eq!(cloned.description, Some("Read a file".into()));
    }

    #[test]
    fn mcp_tool_debug() {
        let t = McpTool {
            name: "ping".into(),
            description: None,
            input_schema: None,
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("ping"));
    }

    #[test]
    fn mcp_resource_clone() {
        let r = McpResource {
            uri: "res://x".into(),
            name: Some("data".into()),
            description: None,
            mime_type: Some("text/plain".into()),
        };
        let cloned = McpResource::clone(&r);
        assert_eq!(cloned.uri, "res://x");
        assert_eq!(cloned.name, Some("data".into()));
    }

    #[test]
    fn mcp_resource_debug() {
        let r = McpResource {
            uri: "res://test".into(),
            name: None,
            description: None,
            mime_type: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("res://test"));
    }

    #[test]
    fn resource_content_clone() {
        let c = ResourceContent {
            uri: Some("res://x".into()),
            mime_type: None,
            text: Some("data".into()),
            blob: None,
        };
        let cloned = ResourceContent::clone(&c);
        assert_eq!(cloned.text, Some("data".into()));
    }

    #[test]
    fn tool_content_clone() {
        let c = ToolContent {
            content_type: "text".into(),
            text: Some("result".into()),
            extra: json!({}),
        };
        let cloned = ToolContent::clone(&c);
        assert_eq!(cloned.content_type, "text");
        assert_eq!(cloned.text, Some("result".into()));
    }

    #[test]
    fn mcp_prompt_clone() {
        let p = McpPrompt {
            name: "summarize".into(),
            description: Some("Summarize text".into()),
            arguments: Some(vec![PromptArgument {
                name: "text".into(),
                description: None,
                required: Some(true),
            }]),
        };
        let cloned = McpPrompt::clone(&p);
        assert_eq!(cloned.name, "summarize");
        assert_eq!(cloned.arguments.unwrap().len(), 1);
    }

    #[test]
    fn prompt_argument_clone() {
        let a = PromptArgument {
            name: "lang".into(),
            description: Some("Language".into()),
            required: Some(false),
        };
        let cloned = PromptArgument::clone(&a);
        assert_eq!(cloned.name, "lang");
        assert_eq!(cloned.required, Some(false));
    }

    #[test]
    fn jsonrpc_request_clone() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 42,
            method: "test".into(),
            params: json!({}),
        };
        let cloned = JsonRpcRequest::clone(&req);
        assert_eq!(cloned.id, 42);
        assert_eq!(cloned.method, "test");
    }

    #[test]
    fn jsonrpc_response_clone() {
        let r: JsonRpcResponse = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"ok": true}
        }))
        .unwrap();
        let cloned = JsonRpcResponse::clone(&r);
        assert!(cloned.result.is_some());
        assert!(cloned.error.is_none());
    }

    #[test]
    fn jsonrpc_error_clone() {
        let e: JsonRpcError = serde_json::from_value(json!({
            "code": -32600,
            "message": "Invalid"
        }))
        .unwrap();
        let cloned = JsonRpcError::clone(&e);
        assert_eq!(cloned.code, -32600);
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            message: Some("err".into()),
            error: Some("404".into()),
        };
        let cloned = ApiErrorResponse::clone(&e);
        assert_eq!(cloned.message, Some("err".into()));
        assert_eq!(cloned.error, Some("404".into()));
    }

    #[test]
    fn mcp_prompt_serialize_skips_none() {
        let p = McpPrompt {
            name: "test".into(),
            description: None,
            arguments: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert!(!v.as_object().unwrap().contains_key("description"));
        assert!(!v.as_object().unwrap().contains_key("arguments"));
    }

    #[test]
    fn prompt_argument_serialize_skips_none() {
        let a = PromptArgument {
            name: "input".into(),
            description: None,
            required: None,
        };
        let v = serde_json::to_value(&a).unwrap();
        assert!(!v.as_object().unwrap().contains_key("description"));
        assert!(!v.as_object().unwrap().contains_key("required"));
    }

    #[test]
    fn jsonrpc_request_with_params() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 5,
            method: "tools/call".into(),
            params: json!({"name": "test", "arguments": {}}),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["params"]["name"], "test");
    }

    #[test]
    fn jsonrpc_response_null_result() {
        let r: JsonRpcResponse = serde_json::from_value(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        }))
        .unwrap();
        // null result deserializes as None
        assert!(r.result.is_none());
    }

    #[test]
    fn tool_content_debug() {
        let c = ToolContent {
            content_type: "text".into(),
            text: Some("result".into()),
            extra: json!({}),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("text"));
    }

    #[test]
    fn resource_content_debug() {
        let c = ResourceContent {
            uri: Some("res://x".into()),
            mime_type: None,
            text: None,
            blob: None,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("res://x"));
    }
}
