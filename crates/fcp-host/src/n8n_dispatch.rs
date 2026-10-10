//! Host-owned typed dispatch for the fixed local n8n MCP catalog.
//!
//! The request types in this module are deliberately narrower than
//! [`LocalMcpRequest`].  A host caller can select only the two local
//! operation families and their operation-specific inputs; process policy,
//! executable paths, environment, and MCP tool names are all host-owned.

use std::fmt;
use std::fmt::Write as _;
use std::sync::{Arc, atomic::AtomicBool};

use serde::de::Error as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    LocalMcpCall, LocalMcpError, LocalMcpProvider, LocalMcpRequest, LocalMcpResult,
    credential_metadata_unique_json,
};

/// Maximum serialized size of one host-internal local n8n dispatch request.
pub const DEFAULT_LOCAL_N8N_INPUT_MAX_BYTES: usize = 16 * 1024;

const MAX_CORRELATION_ID_BYTES: usize = 128;
const MAX_TEXT_BYTES: usize = 1_024;
const MAX_LIST_ITEMS: usize = 20;

/// Immutable current-version selector for a separately authorized sensitive read.
///
/// Parsing this data is not authority; the exact resource must be verified with
/// the original bound `n8n.workflows.code.read` token before any HTTP request.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowCodeReadInput {
    pub id: String,
    pub version: String,
    pub pins: std::collections::BTreeMap<String, WorkflowCodeReadPin>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkflowCodeReadPin {
    pub version_id: String,
    pub graph_digest: String,
}

impl WorkflowCodeReadInput {
    /// # Errors
    /// Refuses unknown fields, ambiguous selectors and incomplete/invalid pins.
    pub fn parse(value: &Value) -> Result<Self, &'static str> {
        let input: Self =
            serde_json::from_value(value.clone()).map_err(|_| "invalid_code_read_input")?;
        let safe_id = |id: &str| {
            !id.is_empty()
                && id.len() <= 256
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        };
        let labels: &[&str] = match input.version.as_str() {
            "draft" => &["draft"],
            "published" => &["published"],
            "both" => &["draft", "published"],
            _ => return Err("invalid_code_read_input"),
        };
        if !safe_id(&input.id)
            || input.pins.len() != labels.len()
            || labels.iter().any(|label| {
                input.pins.get(*label).is_none_or(|pin| {
                    !safe_id(&pin.version_id)
                        || pin.graph_digest.len() != 75
                        || !pin.graph_digest.starts_with("blake3-256:")
                        || !pin.graph_digest[11..]
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            })
        {
            return Err("invalid_code_read_input");
        }
        Ok(input)
    }

    /// # Errors
    /// Only explicit current EEC/Hetzner targets are supported.
    pub fn resource_uri(&self, server: &str) -> Result<String, &'static str> {
        if !matches!(server, "eec" | "hetzner") {
            return Err("invalid_code_read_target");
        }
        let mut resource = format!(
            "fwc-n8n://{server}/workflows/{}?codeVersion={}",
            self.id, self.version
        );
        for (label, pin) in &self.pins {
            write!(
                resource,
                "&{label}VersionId={}&{label}GraphDigest={}",
                pin.version_id, pin.graph_digest
            )
            .map_err(|_| "invalid_code_read_target")?;
        }
        Ok(resource)
    }
}

#[must_use]
pub fn workflow_code_read_input_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["id","version","pins"],"properties":{
        "id":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9_-]+$"},
        "version":{"type":"string","enum":["draft","published","both"]},
        "pins":{"type":"object","additionalProperties":false,"minProperties":1,"maxProperties":2,
            "properties":{"draft":workflow_code_read_pin_schema(),"published":workflow_code_read_pin_schema()}}}})
}

fn workflow_code_read_pin_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["versionId","graphDigest"],"properties":{
        "versionId":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9_-]+$"},
        "graphDigest":{"type":"string","pattern":"^blake3-256:[0-9a-f]{64}$"}}})
}

#[must_use]
pub fn workflow_code_read_output_schema() -> Value {
    json!({"type":"object","additionalProperties":false,"required":["id","versions"],"properties":{
        "id":{"type":"string"},"versions":{"type":"array","minItems":1,"maxItems":2,"items":{
            "type":"object","additionalProperties":false,"required":["version","versionId","graphDigest","codeNodes"],"properties":{
                "version":{"type":"string","enum":["draft","published"]},"versionId":{"type":"string"},
                "graphDigest":{"type":"string","pattern":"^blake3-256:[0-9a-f]{64}$"},
                "codeNodes":{"type":"array","maxItems":100,"items":{"type":"object","additionalProperties":false,
                    "required":["nodeId","language","source","digest"],"properties":{
                        "nodeId":{"type":"string","maxLength":256},"language":{"type":"string","enum":["javascript","python"]},
                        "source":{"type":"string","maxLength":300_000},"digest":{"type":"string","pattern":"^blake3-256:[0-9a-f]{64}$"}}}}}}}}})
}

/// Data supplied only by managed configuration.
///
/// Deserialization is not an authority proof; the owned host must intersect the original bound token,
/// accepted child session, network policy and leased credential purpose.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialMetadataReadMapping {
    credential_id: String,
    purpose: String,
    tool: String,
    class: String,
    input_schema_digest: String,
    output_schema_digest: String,
}

impl CredentialMetadataReadMapping {
    /// # Errors
    /// Refuses every mapping except the exact observed metadata read contract.
    pub fn validate(&self) -> Result<(), &'static str> {
        fcp_core::CredentialId::parse(&self.credential_id)
            .map_err(|_| "credential_metadata_mapping_denied")?;
        if self.purpose != "n8n.credentials.metadata.read"
            || self.tool != "list_credentials"
            || self.class != "read"
            || self.input_schema_digest
                != "sha256:a29acfec48d5f9919cb4fb65ce44c7fe544624a4ea537638d148b5c93ee3a821"
            || self.output_schema_digest
                != "sha256:305aeecb628786f249e9f71a2be18fc26a212b8dd4f090ff073c701a8b4563ac"
        {
            return Err("credential_metadata_mapping_denied");
        }
        Ok(())
    }

    #[must_use]
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    /// Fixed server endpoints; neither caller input nor the mapping selects URL.
    /// # Errors
    /// Rejects local, legacy and unknown servers.
    pub fn endpoint(server: &str) -> Result<&'static str, &'static str> {
        match server {
            "eec" => Ok("https://n8n.europeaneyecenter.com/mcp-server/http"),
            "hetzner" => Ok("https://n8nhet.levilaser.com:8443/mcp-server/http"),
            _ => Err("credential_metadata_mapping_denied"),
        }
    }

    /// The admitted server's existing REST origin, used only for consistency.
    /// Native MCP ports remain subject to the original egress constraints.
    /// # Errors
    /// Rejects unknown servers without selecting an alternate transport.
    pub fn api_origin(server: &str) -> Result<&'static str, &'static str> {
        match server {
            "eec" => Ok("https://n8n.europeaneyecenter.com"),
            "hetzner" => Ok("https://n8nhet.levilaser.com"),
            _ => Err("credential_metadata_mapping_denied"),
        }
    }
}

/// Closed four-request native protocol, shared by connector construction and
/// the invocation-private host gate.
///
/// It cannot select tools or arbitrary args.
/// No raw provider body or schema is retained in the final public projection.
pub struct CredentialMetadataReadProtocol {
    mapping: CredentialMetadataReadMapping,
    server: String,
    request_id: String,
    arguments: Value,
    phase: u8,
    in_flight: bool,
    session: Option<String>,
    protocol_version: &'static str,
    projected: Option<Value>,
}

impl CredentialMetadataReadProtocol {
    /// Synthetic schemas for owned transport tests only. This creates no
    /// capability, session, credential lease or installed-provider proof.
    /// Production builds do not include this fixture constructor.
    /// # Errors
    /// Retains all normal argument and mapping checks before fixture rebinding.
    #[cfg(any(test, feature = "n8n-test-support"))]
    pub fn synthetic_schema_fixture(
        mapping: CredentialMetadataReadMapping,
        server: &str,
        request_id: &str,
        arguments: Value,
        input: &Value,
        output: &Value,
    ) -> Result<Self, &'static str> {
        let mut protocol = Self::new(mapping, server, request_id, arguments)?;
        protocol.mapping.input_schema_digest = credential_metadata_schema_digest(input)?;
        protocol.mapping.output_schema_digest = credential_metadata_schema_digest(output)?;
        Ok(protocol)
    }

    /// # Errors
    /// Rejects unsupported server, mapping, request identity or native filters.
    pub fn new(
        mapping: CredentialMetadataReadMapping,
        server: &str,
        request_id: &str,
        arguments: Value,
    ) -> Result<Self, &'static str> {
        mapping.validate()?;
        CredentialMetadataReadMapping::endpoint(server)?;
        if request_id.is_empty()
            || request_id.len() > 128
            || request_id.chars().any(char::is_control)
        {
            return Err("credential_metadata_request_denied");
        }
        let object = arguments
            .as_object()
            .ok_or("credential_metadata_request_denied")?;
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "query" | "type" | "projectId" | "onlySharedWithMe" | "limit"
            )
        }) || arguments["limit"]
            .as_u64()
            .is_none_or(|n| !(1..=200).contains(&n))
        {
            return Err("credential_metadata_request_denied");
        }
        for key in ["query", "type", "projectId"] {
            if object.get(key).is_some_and(|v| {
                v.as_str().is_none_or(|s| {
                    s.is_empty() || s.len() > 256 || s.chars().any(char::is_control)
                })
            }) {
                return Err("credential_metadata_request_denied");
            }
        }
        if object
            .get("onlySharedWithMe")
            .is_some_and(|v| !v.is_boolean())
        {
            return Err("credential_metadata_request_denied");
        }
        Ok(Self {
            mapping,
            server: server.into(),
            request_id: request_id.into(),
            arguments,
            phase: 0,
            in_flight: false,
            session: None,
            protocol_version: "2025-11-25",
            projected: None,
        })
    }

    /// # Errors
    /// A completed, failed or currently outstanding protocol cannot be replayed.
    pub fn request(&self) -> Result<Value, &'static str> {
        if self.phase > 3 || self.in_flight {
            return Err("credential_metadata_replay_denied");
        }
        self.phase_request()
    }

    fn phase_request(&self) -> Result<Value, &'static str> {
        let id = format!("{}:metadata:{}", self.request_id, self.phase);
        Ok(match self.phase {
            0 => {
                json!({"jsonrpc":"2.0","id":id,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"fwc-n8n-credentials-read","version":"1"}}})
            }
            1 => json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
            2 => json!({"jsonrpc":"2.0","id":id,"method":"tools/list","params":{}}),
            3 => {
                json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"list_credentials","arguments":self.arguments}})
            }
            _ => return Err("credential_metadata_replay_denied"),
        })
    }

    /// # Errors
    /// Refuses native body substitution, generic batches, duplicate attempts.
    pub fn admit_request(&mut self, body: &Value) -> Result<(), &'static str> {
        if *body != self.request()? {
            return Err("credential_metadata_request_denied");
        }
        self.in_flight = true;
        Ok(())
    }

    /// # Errors
    /// Refuses a non-outstanding or substituted native attempt after an await.
    pub fn verify_in_flight_bytes(&self, bytes: &[u8]) -> Result<(), &'static str> {
        if !self.in_flight || self.phase > 3 {
            return Err("credential_metadata_request_denied");
        }
        let expected = serde_json::to_vec(&self.phase_request()?)
            .map_err(|_| "credential_metadata_request_denied")?;
        if bytes != expected {
            return Err("credential_metadata_request_denied");
        }
        Ok(())
    }

    #[must_use]
    pub fn session(&self) -> Option<&str> {
        self.session.as_deref()
    }

    #[must_use]
    pub const fn protocol_version(&self) -> &'static str {
        self.protocol_version
    }

    #[must_use]
    pub const fn completed(&self) -> bool {
        self.phase == 4 && !self.in_flight
    }

    /// # Errors
    /// Refuses malformed/error responses, changed native schemas and metadata.
    /// A refusal leaves the attempted phase outstanding: no automatic retry.
    pub fn accept_response(
        &mut self,
        status: u16,
        session: Option<&str>,
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        let denied = || "credential_metadata_response_denied";
        if !self.in_flight || bytes.len() > 2 * 1024 * 1024 {
            return Err(denied());
        }
        if self.phase == 1 {
            if !matches!(status, 200 | 202 | 204)
                || !bytes.is_empty()
                || session.is_some_and(|s| Some(s) != self.session())
            {
                return Err(denied());
            }
        } else {
            if status != 200 {
                return Err(denied());
            }
            let response = credential_metadata_rpc_json(bytes)?;
            let object = response.as_object().ok_or_else(denied)?;
            if object.len() != 3
                || response["jsonrpc"] != "2.0"
                || response["id"] != format!("{}:metadata:{}", self.request_id, self.phase)
                || !object.contains_key("result")
            {
                return Err(denied());
            }
            let result = &response["result"];
            match self.phase {
                0 => {
                    self.protocol_version = match result["protocolVersion"].as_str() {
                        Some("2025-11-25") => "2025-11-25",
                        Some("2025-06-18") => "2025-06-18",
                        _ => return Err(denied()),
                    };
                    if !result["capabilities"]["tools"].is_object() {
                        return Err(denied());
                    }
                    if let Some(s) = session {
                        if s.is_empty() || s.len() > 256 || !s.bytes().all(|b| b.is_ascii_graphic())
                        {
                            return Err(denied());
                        }
                        self.session = Some(s.into());
                    }
                }
                2 => {
                    let tools = result["tools"]
                        .as_array()
                        .filter(|v| v.len() <= 200)
                        .ok_or_else(denied)?;
                    if result.get("nextCursor").is_some() {
                        return Err(denied());
                    }
                    credential_metadata_catalog_structure(tools)?;
                    let selected = tools
                        .iter()
                        .filter(|t| t["name"] == "list_credentials")
                        .collect::<Vec<_>>();
                    if selected.len() != 1 {
                        return Err(denied());
                    }
                    let tool = selected[0];
                    if tool["annotations"]["readOnlyHint"] != true
                        || !tool["inputSchema"].is_object()
                        || !tool["outputSchema"].is_object()
                        || credential_metadata_schema_digest(&tool["inputSchema"])?
                            != self.mapping.input_schema_digest
                        || credential_metadata_schema_digest(&tool["outputSchema"])?
                            != self.mapping.output_schema_digest
                    {
                        return Err(denied());
                    }
                }
                3 => {
                    let native = credential_metadata_call_value(result)?;
                    let limit =
                        usize::try_from(self.arguments["limit"].as_u64().ok_or_else(denied)?)
                            .map_err(|_| denied())?;
                    self.projected = Some(project_official_n8n_credentials(
                        &native,
                        &self.server,
                        limit,
                    )?);
                }
                _ => return Err(denied()),
            }
            if self.phase != 0 && session.is_some_and(|s| Some(s) != self.session()) {
                return Err(denied());
            }
        }
        self.in_flight = false;
        self.phase += 1;
        Ok(())
    }

    /// # Errors
    /// No success projection exists until the one admitted native read completes.
    pub fn projection(&self) -> Result<Value, &'static str> {
        if !self.completed() {
            return Err("credential_metadata_incomplete");
        }
        self.projected
            .clone()
            .ok_or("credential_metadata_incomplete")
    }
}

fn credential_metadata_catalog_structure(tools: &[Value]) -> Result<(), &'static str> {
    let denied = || "credential_metadata_response_denied";
    let mut names = std::collections::BTreeSet::new();
    for entry in tools {
        let entry = entry.as_object().ok_or_else(denied)?;
        let name = entry
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty() && name.len() <= 256)
            .ok_or_else(denied)?;
        if !names.insert(name)
            || !entry
                .get("inputSchema")
                .is_some_and(|schema| schema.is_object() && schema["type"] == "object")
            || entry
                .get("outputSchema")
                .is_some_and(|schema| !schema.is_object() || schema["type"] != "object")
            || entry
                .get("annotations")
                .is_some_and(|value| !value.is_object())
        {
            return Err(denied());
        }
    }
    Ok(())
}

fn credential_metadata_call_value(result: &Value) -> Result<Value, &'static str> {
    let denied = || "credential_metadata_response_denied";
    if result.get("isError").is_some_and(|value| value != false) {
        return Err(denied());
    }
    let text = result
        .get("content")
        .map(|content| {
            let content = content
                .as_array()
                .filter(|values| values.len() == 1)
                .ok_or_else(denied)?;
            if content[0]["type"] != "text" {
                return Err(denied());
            }
            credential_metadata_unique_json(
                content[0]["text"].as_str().ok_or_else(denied)?.as_bytes(),
            )
        })
        .transpose()?;
    if let Some(structured) = result.get("structuredContent") {
        if text.as_ref().is_some_and(|text| text != structured) {
            return Err(denied());
        }
        Ok(structured.clone())
    } else {
        text.ok_or_else(denied)
    }
}

fn credential_metadata_rpc_json(bytes: &[u8]) -> Result<Value, &'static str> {
    if let Ok(value) = credential_metadata_unique_json(bytes) {
        return Ok(value);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "credential_metadata_response_denied")?;
    let mut data = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("data:") {
            if data.is_some() {
                return Err("credential_metadata_response_denied");
            }
            data = Some(value.trim_start());
        } else if !line.is_empty() && line != "event: message" {
            return Err("credential_metadata_response_denied");
        }
    }
    credential_metadata_unique_json(
        data.ok_or("credential_metadata_response_denied")?
            .as_bytes(),
    )
}

fn credential_metadata_schema_digest(value: &Value) -> Result<String, &'static str> {
    use sha2::{Digest, Sha256};
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(values) => Value::Object(
                values
                    .iter()
                    .map(|(k, v)| (k.clone(), ordered(v)))
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_iter()
                    .collect(),
            ),
            Value::Array(values) => Value::Array(values.iter().map(ordered).collect()),
            other => other.clone(),
        }
    }
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(
            serde_json::to_vec(&ordered(value))
                .map_err(|_| "credential_metadata_response_denied")?
        ))
    ))
}

/// Shared public credential-metadata projection for the wrapper and original
/// host-owned invocation. Credential bodies and undeclared fields are discarded.
///
/// # Errors
/// Rejects malformed metadata, duplicate identities and exceeded bounds.
pub fn project_official_n8n_credentials(
    input: &Value,
    server: &str,
    limit: usize,
) -> Result<Value, &'static str> {
    if !matches!(server, "eec" | "hetzner") || !(1..=200).contains(&limit) {
        return Err("official_credential_response_invalid");
    }
    let object = input
        .as_object()
        .ok_or("official_credential_response_invalid")?;
    if object.contains_key("error") {
        return Err("official_credential_provider_failed");
    }
    let rows = object
        .get("data")
        .and_then(Value::as_array)
        .ok_or("official_credential_response_invalid")?;
    if rows.len() > limit || object.get("count").and_then(Value::as_u64) != Some(rows.len() as u64)
    {
        return Err("official_credential_response_invalid");
    }
    let text = |value: &Value| -> Result<String, &'static str> {
        value
            .as_str()
            .filter(|value| {
                !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
            })
            .map(str::to_owned)
            .ok_or("official_credential_response_invalid")
    };
    let mut ids = std::collections::BTreeSet::new();
    let mut projected = Vec::with_capacity(rows.len());
    for row in rows {
        let id = text(&row["id"])?;
        if !ids.insert(id.clone()) {
            return Err("official_credential_response_invalid");
        }
        let scopes = row["scopes"]
            .as_array()
            .filter(|items| items.len() <= 64)
            .ok_or("official_credential_response_invalid")?
            .iter()
            .map(&text)
            .collect::<Result<Vec<_>, _>>()?;
        let home = match row.get("homeProject") {
            Some(Value::Null) => Value::Null,
            Some(home) if home.is_object() => {
                json!({"id":text(&home["id"])? ,"name":text(&home["name"])? ,"type":text(&home["type"])?})
            }
            _ => return Err("official_credential_response_invalid"),
        };
        let mut encoded_id = String::new();
        for byte in id.bytes() {
            if byte.is_ascii_alphanumeric() {
                encoded_id.push(char::from(byte));
            } else {
                use std::fmt::Write as _;
                write!(encoded_id, "%{byte:02X}")
                    .map_err(|_| "official_credential_response_invalid")?;
            }
        }
        projected.push(json!({"resourceUri":format!("fwc-n8n://{server}/credentials/{encoded_id}"),
            "id":id,"name":text(&row["name"])? ,"type":text(&row["type"])? ,"scopes":scopes,
            "isManaged":row["isManaged"].as_bool().ok_or("official_credential_response_invalid")?,
            "isGlobal":row["isGlobal"].as_bool().ok_or("official_credential_response_invalid")?,"homeProject":home}));
    }
    Ok(
        json!({"credentials":projected,"page":{"returnedCount":rows.len(),"limit":limit,"continuation":"unavailable","completeness":"not_established"}}),
    )
}

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

fn unknown_validation_finding(
    context: Option<&LocalN8nDiagnosticContext>,
    item: &Value,
    warning: bool,
) -> Value {
    let (source, stage, version) = match context {
        Some(ctx) if ctx.versioned_source.is_some() => (
            "verified_derived_native",
            "native_origin_projection",
            json!("2.91.0"),
        ),
        Some(_) => (
            "pinned_legacy_native",
            "legacy_text_projection",
            json!("2.91.0"),
        ),
        None => ("unbound_native", "context_binding", Value::Null),
    };
    let reason = match context {
        None => "missing_context",
        Some(_) if item["node"] == "workflow" => "reserved_workflow_scope",
        Some(ctx) if ctx.versioned_source.is_some() => {
            let origin = if warning {
                "fwcWarning"
            } else {
                "fwcDiagnostic"
            };
            if item.get(origin).is_some() {
                "unsupported_native_rule"
            } else {
                "missing_origin"
            }
        }
        Some(ctx) => {
            let matches = item["node"].as_str().map_or(0, |name| {
                ctx.nodes
                    .iter()
                    .filter(|node| node["name"].as_str() == Some(name))
                    .count()
            });
            match matches {
                0 => "node_binding_unavailable",
                1 => "unrecognized_native_form",
                _ => "ambiguous_node_binding",
            }
        }
    };
    let binding = context.map_or(Value::Null, |ctx| {
        let metadata = ctx.versioned_source.as_ref().map_or_else(
            || json!(LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST),
            |source| source["packageMetadataDigest"].clone(),
        );
        json!({"graphDigest":ctx.graph_digest,"layoutDigest":ctx.layout_digest,
            "profile":ctx.profile.as_str(),"packageMetadataDigest":metadata})
    });
    json!({"path":"graph","code":"unclassified","classification":"unclassified",
        "unknownReason":reason,"diagnosticStage":stage,"diagnosticSource":source,
        "sourceVersion":version,"binding":binding,
        "nextDiagnostic":"authorized_graph_bound_native_diagnostic_required",
        "message":"Native validator finding could not be safely classified"})
}

/// Project one native local validator result without native messages, node
/// names, suggestions, or provider transport fields.
///
/// # Errors
/// Rejects malformed envelopes and contradictory validation outcomes.
pub fn project_local_n8n_validation_call(native: &Value) -> Result<Value, LocalN8nDispatchError> {
    project_local_n8n_validation_with_context(native, None)
}

/// Invocation-private metadata derived from the exact graph sent to the
/// validator. It is neither caller-deserializable nor printable with Debug.
pub struct LocalN8nDiagnosticContext {
    nodes: Vec<Value>,
    connections: Value,
    graph_digest: String,
    layout_digest: String,
    profile: LocalN8nValidationProfile,
    versioned_source: Option<Value>,
}

/// Existing admitted 2.91.0 package metadata fingerprint for these exact rules.
pub const LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST: &str =
    "0428c7d49767df9eec57c26d27997021812a1b6faf55e0faef9c14498376e723";

impl LocalN8nDiagnosticContext {
    /// Enable structured native origin only with a sealed, verified derived
    /// package proof. Caller/native JSON and a version string are insufficient.
    #[must_use]
    pub fn from_verified_versioned_source(
        graph: &Value,
        profile: LocalN8nValidationProfile,
        source: &crate::VerifiedVersionedValidationSource,
    ) -> Option<Self> {
        let mut context = Self::from_graph(
            graph,
            profile,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )?;
        context.versioned_source = Some(json!({
            "contract":"fwc.n8n.versioned-validation.v1",
            "packageMetadataDigest":source.metadata_digest(),
            "patchSha256":source.patch_digest(),
            "packageTreeSha256":source.package_tree_digest(),
            "schemaAuthority":"pinned_native_database_not_deployed_descriptor"
        }));
        Some(context)
    }

    /// Construct only from the retained invocation input and verified package
    /// version. Unsupported packages or incomplete graphs remain unclassified.
    #[must_use]
    pub fn from_graph(
        graph: &Value,
        profile: LocalN8nValidationProfile,
        package_version: &str,
        package_metadata_digest: &str,
    ) -> Option<Self> {
        if package_version != "2.91.0"
            || package_metadata_digest != LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST
        {
            return None;
        }
        let nodes = graph.get("nodes")?.as_array()?;
        let (graph_digest, layout_digest) =
            n8n_comparison_graph_digests(nodes, graph.get("connections")?).ok()?;
        Some(Self {
            nodes: nodes
                .iter()
                .map(|node| {
                    let code_field = match node["parameters"]["language"].as_str() {
                        None if node["parameters"]["language"].is_null() => Some("jsCode"),
                        Some("javascript") => Some("jsCode"),
                        Some("python" | "pythonNative") => Some("pythonCode"),
                        _ => None,
                    };
                    let code_empty = code_field.is_some_and(|field| {
                        let code = &node["parameters"][field];
                        code.is_null() || code.as_str().is_some_and(|s| s.trim().is_empty())
                    });
                    json!({"name":node["name"],"type":node["type"],
                "typeVersion":node["typeVersion"],"position":node["position"],
                "disabled":node["disabled"],"continueOnFail":node["continueOnFail"],
                "codeField":code_field,"codeEmpty":code_empty})
                })
                .collect(),
            connections: graph["connections"].clone(),
            graph_digest,
            layout_digest,
            profile,
            versioned_source: None,
        })
    }

    fn finding(&self, item: &Value, warning: bool) -> Option<Value> {
        if self.versioned_source.is_some()
            && ((!warning && item.get("fwcDiagnostic").is_some())
                || (warning && item.get("fwcWarning").is_some()))
        {
            return self.derived_finding(item, warning);
        }
        self.legacy_finding(item, warning)
    }

    fn derived_finding(&self, item: &Value, warning: bool) -> Option<Value> {
        // Scope validation has already checked the actual emitted slot,
        // captured graph, version and closed shape. Duplicate names cannot
        // erase this stronger binding. Legacy text never acquires it.
        if !warning {
            let index = usize::try_from(item["fwcDiagnostic"]["nodeIndex"].as_u64()?).ok()?;
            let node = self.nodes.get(index)?;
            if item["node"] == "workflow" {
                return None;
            }
            return Self::versioned_finding(item, index, node);
        }
        let origin = &item["fwcWarning"];
        if origin["code"] == "connection_disabled_target" {
            return Some(json!({"path":"graph","scope":"graph","field":"connections",
                "code":"graph_connection_disabled_target","classification":"validator_observation",
                "message":"Native validator reports a connection to a disabled node"}));
        }
        if item["node"] == "workflow" {
            return None;
        }
        let index = usize::try_from(origin["nodeIndex"].as_u64()?).ok()?;
        let node = self.nodes.get(index)?;
        let (code, field, message) = match origin["code"].as_str()? {
            "node_unreachable" if node["disabled"] != true => (
                "node_unreachable",
                "connections",
                "Native validator reports no trigger path to this node",
            ),
            "node_legacy_continue_on_fail" if node["continueOnFail"] == true => (
                "node_legacy_continue_on_fail",
                "continueOnFail",
                "Native validator reports legacy error handling",
            ),
            _ => return None,
        };
        Some(
            json!({"path":"graph","nodeIndex":index,"code":code,"field":field,
            "classification":"validator_observation","message":message}),
        )
    }

    fn legacy_finding(&self, item: &Value, warning: bool) -> Option<Value> {
        let name = item.get("node")?.as_str()?;
        if name == "workflow"
            || name.is_empty()
            || name.len() > 256
            || name.chars().any(char::is_control)
        {
            return None;
        }
        let mut matches = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node["name"].as_str() == Some(name));
        let (index, node) = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let message = item
            .get("message")?
            .as_str()
            .filter(|text| !text.chars().any(char::is_control))?;
        // Exact forms from pinned 2.91 workflow-validator.js. Native text is
        // never reflected; dynamic parts must match this captured node.
        let rule = Self::empty_code_rule(node, message, warning).or_else(|| {
            if warning
                && message == "Node is not connected to any other nodes"
                && matches!(
                    node["type"].as_str(),
                    Some("n8n-nodes-base.noOp" | "nodes-base.noOp")
                )
                && node["disabled"] != true
                && !self.node_has_connection(name)
            {
                Some((
                    "node_disconnected",
                    "connections",
                    "validator_observation",
                    "Node has no graph connections",
                ))
            } else if !warning
                && message == "Node position must be an array with exactly 2 numbers [x, y]"
                && node
                    .get("position")
                    .and_then(Value::as_array)
                    .is_none_or(|p| p.len() != 2)
            {
                Some((
                    "node_position_shape",
                    "position",
                    "input_shape",
                    "Node position has an invalid shape",
                ))
            } else if !warning
                && message == "Node position values must be finite numbers"
                && node["position"].as_array().is_some_and(|p| {
                    p.len() == 2 && p.iter().any(|v| v.as_f64().is_none_or(|n| !n.is_finite()))
                })
            {
                Some((
                    "node_position_values",
                    "position",
                    "input_shape",
                    "Node position values are invalid",
                ))
            } else if !warning
                && node.get("typeVersion").is_none_or(Value::is_null)
                && message
                    .strip_prefix("Missing required property 'typeVersion'. Add typeVersion: ")
                    .is_some_and(native_version_number)
            {
                Some((
                    "node_type_version_missing",
                    "typeVersion",
                    "input_shape",
                    "Node type version is missing",
                ))
            } else {
                Self::support_rule(node, message, warning)
            }
        })?;
        Some(json!({"path":"graph","code":rule.0,"field":rule.1,
            "classification":rule.2,"message":rule.3,"nodeIndex":index}))
    }

    fn versioned_finding(item: &Value, index: usize, node: &Value) -> Option<Value> {
        let diagnostic = item.get("fwcDiagnostic")?;
        if diagnostic["nodeIndex"].as_u64()? != index as u64
            || diagnostic["typeVersion"] != node["typeVersion"]
        {
            return None;
        }
        let (code, message, classification) = match diagnostic["code"].as_str()? {
            "required_absent" => (
                "configuration_required_absent",
                "Required parameter is absent",
                "validator_observation",
            ),
            "required_null" => (
                "configuration_required_null",
                "Required parameter is null",
                "validator_observation",
            ),
            "required_trim_empty" => (
                "configuration_required_empty",
                "Required parameter is empty after native defaults",
                "validator_observation",
            ),
            "special_type_mismatch" => (
                "configuration_special_type_mismatch",
                "Parameter does not match the native schema type",
                "validator_observation",
            ),
            "special_null_required" => (
                "configuration_special_null_required",
                "Native structured parameter requires a value",
                "validator_observation",
            ),
            "schema_version_unavailable" => (
                "validator_node_version_schema_unavailable",
                "Exact node-version schema is unavailable",
                "validator_support_limit",
            ),
            _ => return None,
        };
        Some(
            json!({"path":"graph","code":code,"field":"parameters","classification":classification,
            "message":message,"nodeIndex":index,"nativePropertyOrdinal":diagnostic["propertyOrdinal"],
            "schemaPropertyOrdinal":diagnostic["originalOrdinal"],"defaultApplied":diagnostic["defaultApplied"],
            "apiVersion":diagnostic["apiVersion"],"nodeTypeVersion":node["typeVersion"],
            "expectedType":diagnostic["expectedType"],"actualType":diagnostic["actualType"],
            "structureKind":diagnostic["structureKind"]}),
        )
    }

    fn versioned_scope(&self, typed: &Value) -> Result<Option<Value>, LocalN8nDispatchError> {
        let malformed = || LocalN8nDispatchError::new(LocalN8nDispatchErrorCode::ProviderError);
        let Some(source) = &self.versioned_source else {
            return if typed.get("fwcValidation").is_some() {
                Err(malformed())
            } else {
                Ok(None)
            };
        };
        let scope = typed.get("fwcValidation").ok_or_else(malformed)?;
        let keys = [
            "schema",
            "profile",
            "graphNodes",
            "schemas",
            "errorCount",
            "warningCount",
            "schemaCoverageComplete",
        ];
        if scope
            .as_object()
            .is_none_or(|o| o.len() != keys.len() || o.keys().any(|k| !keys.contains(&k.as_str())))
            || scope["schema"] != "fwc.n8n.versioned-validation.v1"
            || scope["profile"] != self.profile.as_str()
            || scope["graphNodes"].as_u64() != Some(self.nodes.len() as u64)
            || scope["errorCount"].as_u64() != typed["errors"].as_array().map(|a| a.len() as u64)
            || scope["warningCount"].as_u64()
                != typed["warnings"].as_array().map(|a| a.len() as u64)
        {
            return Err(malformed());
        }
        let schemas = scope["schemas"]
            .as_array()
            .filter(|a| a.len() == self.nodes.len())
            .ok_or_else(malformed)?;
        let complete = self.validate_versioned_schemas(schemas)?;
        if scope["schemaCoverageComplete"].as_bool() != Some(complete) {
            return Err(malformed());
        }
        self.validate_versioned_findings(typed, schemas)?;
        let warning_origins = self.versioned_warning_origins(typed)?;
        Ok(Some(
            json!({"schemaCoverageComplete":complete,"graphNodes":self.nodes.len(),
            "schemas":schemas,"nativeSource":source,"warningOrigins":warning_origins}),
        ))
    }

    fn validate_versioned_schemas(&self, schemas: &[Value]) -> Result<bool, LocalN8nDispatchError> {
        let malformed = || LocalN8nDispatchError::new(LocalN8nDispatchErrorCode::ProviderError);
        let schema_keys = [
            "index",
            "typeVersion",
            "status",
            "schemaVersion",
            "schemaSha256",
            "propertyCount",
        ];
        let mut complete = true;
        for (index, selection) in schemas.iter().enumerate() {
            let version = self.nodes[index]["typeVersion"]
                .as_f64()
                .filter(|v| v.is_finite() && *v >= 0.0);
            if selection.as_object().is_none_or(|o| {
                o.len() != schema_keys.len() || o.keys().any(|k| !schema_keys.contains(&k.as_str()))
            }) || selection["index"].as_u64() != Some(index as u64)
                || selection["typeVersion"].as_f64() != version
                || (version.is_none() && !selection["typeVersion"].is_null())
            {
                return Err(malformed());
            }
            match selection["status"].as_str() {
                Some("validated")
                    if version.is_some()
                        && selection["schemaVersion"].as_f64() == version
                        && selection["schemaSha256"].as_str().is_some_and(sha256_hex)
                        && selection["propertyCount"]
                            .as_u64()
                            .is_some_and(|n| n <= 4096) => {}
                Some("disabled") if self.nodes[index]["disabled"] == true => {}
                Some("non_executable")
                    if matches!(
                        self.nodes[index]["type"].as_str(),
                        Some("n8n-nodes-base.stickyNote" | "nodes-base.stickyNote")
                    ) => {}
                Some("unsupported_version" | "not_collected") => complete = false,
                _ => return Err(malformed()),
            }
            if selection["status"] != "validated"
                && (!selection["schemaVersion"].is_null()
                    || !selection["schemaSha256"].is_null()
                    || !selection["propertyCount"].is_null())
            {
                return Err(malformed());
            }
        }
        Ok(complete)
    }

    fn validate_versioned_findings(
        &self,
        typed: &Value,
        schemas: &[Value],
    ) -> Result<(), LocalN8nDispatchError> {
        let malformed = || LocalN8nDispatchError::new(LocalN8nDispatchErrorCode::ProviderError);
        let fields = [
            "code",
            "nodeIndex",
            "typeVersion",
            "propertyOrdinal",
            "originalOrdinal",
            "defaultApplied",
            "apiVersion",
            "expectedType",
            "actualType",
            "structureKind",
        ];
        for item in typed["errors"]
            .as_array()
            .ok_or_else(malformed)?
            .iter()
            .chain(typed["warnings"].as_array().ok_or_else(malformed)?)
        {
            let Some(diagnostic) = item.get("fwcDiagnostic") else {
                continue;
            };
            let index = diagnostic["nodeIndex"]
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| *n < self.nodes.len())
                .ok_or_else(malformed)?;
            if diagnostic.as_object().is_none_or(|o| {
                o.len() != fields.len() || o.keys().any(|k| !fields.contains(&k.as_str()))
            }) || diagnostic["code"]
                .as_str()
                .is_none_or(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
                || diagnostic["typeVersion"] != schemas[index]["typeVersion"]
                || item["node"] != self.nodes[index]["name"]
                || ["propertyOrdinal", "originalOrdinal"].iter().any(|k| {
                    !diagnostic[*k].is_null()
                        && diagnostic[*k].as_u64().is_none_or(|n| {
                            n >= 4096
                                || schemas[index]["propertyCount"]
                                    .as_u64()
                                    .is_none_or(|count| n >= count)
                        })
                })
                || !(diagnostic["defaultApplied"].is_null()
                    || diagnostic["defaultApplied"].is_boolean())
                || !(diagnostic["apiVersion"].is_null()
                    || matches!(diagnostic["apiVersion"].as_u64(), Some(1..=3)))
                || (diagnostic["code"] == "schema_version_unavailable")
                    != (schemas[index]["status"] == "unsupported_version")
            {
                return Err(malformed());
            }
            Self::validate_versioned_type_predicates(diagnostic)?;
            if diagnostic["code"] != "schema_version_unavailable"
                && schemas[index]["status"] != "validated"
            {
                return Err(malformed());
            }
            if matches!(
                diagnostic["code"].as_str(),
                Some("required_absent" | "required_null" | "required_trim_empty")
            ) && (diagnostic["propertyOrdinal"].is_null()
                || diagnostic["originalOrdinal"].is_null()
                || !diagnostic["defaultApplied"].is_boolean())
            {
                return Err(malformed());
            }
        }
        Ok(())
    }

    fn validate_versioned_type_predicates(diagnostic: &Value) -> Result<(), LocalN8nDispatchError> {
        let malformed = || LocalN8nDispatchError::new(LocalN8nDispatchErrorCode::ProviderError);
        let special = matches!(
            diagnostic["code"].as_str(),
            Some("special_type_mismatch" | "special_null_required")
        );
        if special {
            if !matches!(
                diagnostic["expectedType"].as_str(),
                Some("object" | "string" | "number" | "boolean" | "array" | "any")
            ) || !matches!(
                diagnostic["actualType"].as_str(),
                Some("object" | "string" | "number" | "boolean" | "array" | "null" | "undefined")
            ) || !matches!(
                diagnostic["structureKind"].as_str(),
                Some(
                    "string"
                        | "number"
                        | "boolean"
                        | "dateTime"
                        | "color"
                        | "json"
                        | "options"
                        | "multiOptions"
                        | "collection"
                        | "fixedCollection"
                        | "resourceLocator"
                        | "resourceMapper"
                        | "filter"
                        | "assignmentCollection"
                        | "credentials"
                        | "credentialsSelect"
                        | "hidden"
                        | "button"
                        | "callout"
                        | "notice"
                        | "workflowSelector"
                        | "agentSelector"
                        | "curlImport"
                        | "icon"
                )
            ) || diagnostic["propertyOrdinal"].is_null()
                || diagnostic["code"] == "special_type_mismatch"
                    && diagnostic["expectedType"] == diagnostic["actualType"]
                || diagnostic["code"] == "special_null_required"
                    && !matches!(
                        diagnostic["actualType"].as_str(),
                        Some("null" | "undefined")
                    )
            {
                return Err(malformed());
            }
        } else if !diagnostic["expectedType"].is_null()
            || !diagnostic["actualType"].is_null()
            || !diagnostic["structureKind"].is_null()
        {
            return Err(malformed());
        }
        Ok(())
    }

    fn versioned_warning_origins(
        &self,
        typed: &Value,
    ) -> Result<Vec<Value>, LocalN8nDispatchError> {
        let malformed = || LocalN8nDispatchError::new(LocalN8nDispatchErrorCode::ProviderError);
        let mut warning_origins = Vec::new();
        for (finding_index, warning) in typed["warnings"]
            .as_array()
            .ok_or_else(malformed)?
            .iter()
            .enumerate()
        {
            let Some(origin) = warning.get("fwcWarning") else {
                continue;
            };
            if origin.as_object().is_none_or(|o| {
                o.len() != 2
                    || o.keys()
                        .any(|k| !matches!(k.as_str(), "code" | "nodeIndex"))
            }) {
                return Err(malformed());
            }
            let code = origin["code"].as_str().ok_or_else(malformed)?;
            if code == "connection_disabled_target" {
                if !origin["nodeIndex"].is_null()
                    || warning["node"] != "workflow"
                    || !self.nodes.iter().any(|node| {
                        node["disabled"] == true
                            && node["name"]
                                .as_str()
                                .is_some_and(|name| self.node_has_connection(name))
                    })
                {
                    return Err(malformed());
                }
                // Reserved native workflow scope NEVER invents a node index.
                warning_origins.push(json!({"findingIndex":finding_index,"code":code,"scope":"graph","nodeIndex":null}));
            } else if matches!(code, "node_unreachable" | "node_legacy_continue_on_fail") {
                let index = origin["nodeIndex"]
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .filter(|n| *n < self.nodes.len())
                    .ok_or_else(malformed)?;
                if warning["node"] != self.nodes[index]["name"]
                    || code == "node_legacy_continue_on_fail"
                        && self.nodes[index]["continueOnFail"] != true
                {
                    return Err(malformed());
                }
                warning_origins.push(json!({"findingIndex":finding_index,"code":code,"scope":"node",
                    "nodeIndex":if warning["node"] == "workflow" { Value::Null } else { json!(index) }}));
            } else {
                return Err(malformed());
            }
        }
        Ok(warning_origins)
    }

    fn empty_code_rule(
        node: &Value,
        message: &str,
        warning: bool,
    ) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
        if warning
            || message != "Code cannot be empty"
            || node["codeEmpty"] != true
            || !matches!(
                node["type"].as_str(),
                Some("n8n-nodes-base.code" | "nodes-base.code")
            )
        {
            return None;
        }
        let field = match node["codeField"].as_str()? {
            "jsCode" => "parameters.jsCode",
            "pythonCode" => "parameters.pythonCode",
            _ => return None,
        };
        Some((
            "node_code_empty",
            field,
            "input_shape",
            "Selected code parameter is empty",
        ))
    }

    fn node_has_connection(&self, name: &str) -> bool {
        self.connections.as_object().is_none_or(|sources| {
            sources.iter().any(|(source, outputs)| {
                outputs.as_object().is_none_or(|outputs| {
                    outputs.values().any(|groups| {
                        groups.as_array().is_none_or(|groups| {
                            groups.iter().any(|group| {
                                group.as_array().is_none_or(|edges| {
                                    edges.iter().any(|edge| {
                                        !edge.is_null() && (source == name || edge["node"] == name)
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    }

    fn support_rule(
        node: &Value,
        message: &str,
        warning: bool,
    ) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
        let node_type = node.get("type")?.as_str()?;
        if node_type.is_empty() || node_type.len() > 256 || node_type.chars().any(char::is_control)
        {
            return None;
        }
        let core = node_type.starts_with("n8n-nodes-base.")
            || node_type.starts_with("nodes-base.")
            || node_type.starts_with("@n8n/n8n-nodes-langchain.")
            || node_type.starts_with("nodes-langchain.")
            || node_type.starts_with("n8n-nodes-langchain.");
        let suffix = if warning && !core && node_type.contains('.') {
            " This looks like a community node that is not in this server's node database — the workflow can still run on an n8n instance where the package is installed."
        } else if !warning && core {
            " No similar nodes found. Node types must include the package prefix (e.g., \"n8n-nodes-base.webhook\")."
        } else {
            return None;
        };
        if message == format!("Unknown node type: \"{node_type}\".{suffix}") {
            return Some((
                "validator_node_type_unavailable",
                "type",
                "validator_support_limit",
                "Node type is unavailable in the validator database",
            ));
        }
        let version = node.get("typeVersion")?.as_f64()?;
        if !version.is_finite() || version < 0.0 {
            return None;
        }
        let prefix = format!("typeVersion {version} exceeds maximum supported version ");
        let maximum = message.strip_prefix(&prefix)?;
        let maximum = if warning && !core {
            maximum.strip_suffix(" known to this server. The community package may be newer than this server's data — verify the version exists in your installed package.")?
        } else if !warning && core {
            maximum
        } else {
            return None;
        };
        if native_version_number(maximum) && maximum.parse::<f64>().ok()? < version {
            return Some((
                "validator_type_version_limit",
                "typeVersion",
                "validator_support_limit",
                "Node type version exceeds the validator database limit",
            ));
        }
        None
    }
}

fn native_version_number(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 32
        && text.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        && text
            .parse::<f64>()
            .is_ok_and(|n| n.is_finite() && n >= 0.0 && n.to_string() == text)
}

fn sha256_hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Preserve native counts while projecting only closed diagnostics bound to
/// the exact input graph. Missing/ambiguous context is explicitly unclassified.
///
/// # Errors
/// Rejects the same malformed/oversized/contradictory envelopes as the unbound projector.
pub fn project_local_n8n_validation_with_context(
    native: &Value,
    context: Option<&LocalN8nDiagnosticContext>,
) -> Result<Value, LocalN8nDispatchError> {
    let malformed = || LocalN8nDispatchError::new(LocalN8nDispatchErrorCode::ProviderError);
    let is_error = match native.get("isError") {
        None => false,
        Some(Value::Bool(value)) => *value,
        _ => return Err(malformed()),
    };
    let blocks = native["content"].as_array().ok_or_else(malformed)?;
    if blocks.len() != 1 || blocks[0]["type"] != "text" {
        return Err(malformed());
    }
    let text = blocks[0]["text"].as_str().ok_or_else(malformed)?;
    if text.len() > 256 * 1024 {
        return Err(malformed());
    }
    let typed = credential_metadata_unique_json(text.as_bytes()).map_err(|_| malformed())?;
    if native
        .get("structuredContent")
        .is_some_and(|structured| structured != &typed)
    {
        return Err(malformed());
    }
    let valid = typed["valid"].as_bool().ok_or_else(malformed)?;
    let errors = typed["errors"].as_array().ok_or_else(malformed)?;
    let warnings = typed["warnings"].as_array().ok_or_else(malformed)?;
    let versioned_scope = match context {
        Some(context) => context.versioned_scope(&typed)?,
        None if typed.get("fwcValidation").is_some() => return Err(malformed()),
        None => None,
    };
    if errors.len() > 256
        || warnings.len() > 256
        || valid && (!errors.is_empty() || is_error)
        || !valid
            && errors.is_empty()
            && versioned_scope
                .as_ref()
                .is_none_or(|s| s["schemaCoverageComplete"] != false)
        || errors.iter().chain(warnings).any(|item| {
            !item.is_object()
                || item["message"]
                    .as_str()
                    .is_none_or(|message| message.len() > 8192)
        })
    {
        return Err(malformed());
    }
    let project = |items: &[Value], warning| {
        items
            .iter()
            .map(|item| {
                context
                    .and_then(|ctx| ctx.finding(item, warning))
                    .unwrap_or_else(|| unknown_validation_finding(context, item, warning))
            })
            .collect::<Vec<_>>()
    };
    let mut projected = json!({"valid":valid,"nativeValid":valid,"overallStatus":"incomplete",
            "errors":project(errors,false),"warnings":project(warnings,true)});
    if let Some(context) = context {
        projected["diagnosticBinding"] = json!({"graphDigest":context.graph_digest,
            "layoutDigest":context.layout_digest,"profile":context.profile.as_str(),"packageVersion":"2.91.0"});
        projected["diagnosticBinding"]["packageMetadataDigest"] =
            context.versioned_source.as_ref().map_or_else(
                || json!(LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST),
                |source| source["packageMetadataDigest"].clone(),
            );
    }
    if let Some(mut scope) = versioned_scope {
        let unclassified_errors = projected["errors"]
            .as_array()
            .ok_or_else(malformed)?
            .iter()
            .filter(|item| item["classification"] == "unclassified")
            .count();
        let unclassified_warnings = projected["warnings"]
            .as_array()
            .ok_or_else(malformed)?
            .iter()
            .filter(|item| item["classification"] == "unclassified")
            .count();
        scope["unclassifiedErrors"] = json!(unclassified_errors);
        scope["unclassifiedWarnings"] = json!(unclassified_warnings);
        scope["assessmentComplete"] = json!(
            scope["schemaCoverageComplete"] == true
                && unclassified_errors == 0
                && unclassified_warnings == 0
        );
        if scope["assessmentComplete"] == true {
            projected["overallStatus"] = json!("complete");
        }
        projected["validationCoverage"] = scope;
    }
    Ok(projected)
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
    #[serde(rename = "search_templates_batch")]
    SearchTemplatesBatch(Vec<LocalN8nSearchTemplatesInput>),
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
                LocalN8nKnowledgeAction::SearchTemplates(_)
                | LocalN8nKnowledgeAction::SearchTemplatesBatch(_) => LocalN8nTool::SearchTemplates,
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
                if let LocalN8nKnowledgeAction::SearchTemplatesBatch(queries) = input.action {
                    if !(2..=4).contains(&queries.len()) {
                        return Err(invalid_request());
                    }
                    let mut calls = Vec::with_capacity(queries.len());
                    for query in queries {
                        let (tool, arguments) =
                            LocalN8nKnowledgeAction::SearchTemplates(query).into_call()?;
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
            Self::SearchNodesBatch(_) | Self::SearchTemplatesBatch(_) => Err(invalid_request()),
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

    fn diagnostic_graph() -> Value {
        json!({"nodes":[{"id":"one","name":"PRIVATE_NODE_CANARY","type":"n8n-nodes-base.noOp",
            "typeVersion":9,"parameters":{"token":"PARAMETER_CANARY"},"position":[0,0]}],"connections":{}})
    }

    fn diagnostic_native(errors: Value, warnings: Value) -> Value {
        let mut typed = json!({"valid":errors.as_array().unwrap().is_empty()});
        typed["errors"] = errors;
        typed["warnings"] = warnings;
        json!({"content":[{"type":"text","text":serde_json::to_string(&typed).unwrap()}],"structuredContent":typed})
    }

    fn versioned_native(errors: Value, warnings: Value) -> Value {
        let scope = json!({"schema":"fwc.n8n.versioned-validation.v1","profile":"runtime","graphNodes":1,
            "schemas":[{"index":0,"typeVersion":9,"status":"validated","schemaVersion":9,
                "schemaSha256":"2".repeat(64),"propertyCount":30}],
            "errorCount":errors.as_array().unwrap().len(),"warningCount":warnings.as_array().unwrap().len(),
            "schemaCoverageComplete":true});
        let mut typed =
            json!({"valid":errors.as_array().unwrap().is_empty(),"fwcValidation":scope});
        typed["errors"] = errors;
        typed["warnings"] = warnings;
        json!({"content":[{"type":"text","text":typed.to_string()}],"structuredContent":typed})
    }

    fn versioned_required() -> Value {
        json!({"node":"PRIVATE_NODE_CANARY","message":"MESSAGE_CANARY\nCONTROL","details":"DETAIL_CANARY",
            "fwcDiagnostic":{"code":"required_trim_empty","nodeIndex":0,"typeVersion":9,
                "propertyOrdinal":7,"originalOrdinal":21,"defaultApplied":true,"apiVersion":3,
                "expectedType":null,"actualType":null,"structureKind":null}})
    }

    fn versioned_context(graph: &Value) -> LocalN8nDiagnosticContext {
        LocalN8nDiagnosticContext::from_verified_versioned_source(
            graph,
            LocalN8nValidationProfile::Runtime,
            &crate::local_mcp::VerifiedVersionedValidationSource::synthetic_fixture(),
        )
        .unwrap()
    }

    fn repack_versioned(typed: Value) -> Value {
        let mut envelope = json!({"content":[{"type":"text","text":typed.to_string()}]});
        envelope["structuredContent"] = typed;
        envelope
    }

    #[test]
    fn versioned_validation_default_and_type_predicates_are_safe_and_counted() {
        let context = versioned_context(&diagnostic_graph());
        let mut special = versioned_required();
        special["fwcDiagnostic"]["code"] = json!("special_type_mismatch");
        special["fwcDiagnostic"]["originalOrdinal"] = Value::Null;
        special["fwcDiagnostic"]["defaultApplied"] = Value::Null;
        special["fwcDiagnostic"]["expectedType"] = json!("object");
        special["fwcDiagnostic"]["actualType"] = json!("string");
        special["fwcDiagnostic"]["structureKind"] = json!("resourceLocator");
        let native = versioned_native(
            json!([versioned_required(), special]),
            json!([{"node":"workflow","message":"UNKNOWN_WARNING_CANARY"}]),
        );
        let result = project_local_n8n_validation_with_context(&native, Some(&context)).unwrap();
        assert_eq!(result["errors"].as_array().unwrap().len(), 2);
        assert_eq!(result["errors"][0]["defaultApplied"], true);
        assert_eq!(result["errors"][0]["apiVersion"], 3);
        assert_eq!(result["errors"][0]["schemaPropertyOrdinal"], 21);
        assert_eq!(result["errors"][1]["expectedType"], "object");
        assert_eq!(result["errors"][1]["actualType"], "string");
        assert_eq!(result["validationCoverage"]["unclassifiedWarnings"], 1);
        assert_eq!(result["validationCoverage"]["assessmentComplete"], false);
        assert!(!result.to_string().contains("CANARY"));
        assert_eq!(
            result["diagnosticBinding"]["packageMetadataDigest"],
            "0".repeat(64)
        );
        assert!(project_local_n8n_validation_with_context(&native, None).is_err());
        let old = LocalN8nDiagnosticContext::from_graph(
            &diagnostic_graph(),
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        assert!(project_local_n8n_validation_with_context(&native, Some(&old)).is_err());
    }

    #[test]
    fn versioned_validation_substitution_shape_bounds_and_counts_fail_closed() {
        let context = versioned_context(&diagnostic_graph());
        let base =
            versioned_native(json!([versioned_required()]), json!([]))["structuredContent"].clone();
        let substitutions = [
            ("/fwcValidation/profile", json!("strict")),
            ("/fwcValidation/graphNodes", json!(2)),
            ("/fwcValidation/errorCount", json!(0)),
            ("/fwcValidation/schemaCoverageComplete", json!(false)),
            ("/fwcValidation/schemas/0/index", json!(1)),
            ("/fwcValidation/schemas/0/typeVersion", json!(8)),
            ("/fwcValidation/schemas/0/schemaVersion", json!(8)),
            (
                "/fwcValidation/schemas/0/schemaSha256",
                json!("HASH_CANARY"),
            ),
            ("/errors/0/node", json!("WRONG_NODE_CANARY")),
            ("/errors/0/fwcDiagnostic/nodeIndex", json!(1)),
            ("/errors/0/fwcDiagnostic/typeVersion", json!(8)),
            ("/errors/0/fwcDiagnostic/propertyOrdinal", json!(4096)),
            ("/errors/0/fwcDiagnostic/originalOrdinal", json!(30)),
            ("/errors/0/fwcDiagnostic/apiVersion", json!(4)),
            (
                "/errors/0/fwcDiagnostic/defaultApplied",
                json!("FLAG_CANARY"),
            ),
            ("/errors/0/fwcDiagnostic/expectedType", json!("TYPE_CANARY")),
            ("/errors/0/message", json!("x".repeat(8193))),
            ("/valid", json!(true)),
        ];
        for (path, value) in substitutions {
            let mut changed = base.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(
                project_local_n8n_validation_with_context(
                    &repack_versioned(changed),
                    Some(&context)
                )
                .is_err()
            );
        }
        let mut extra = base;
        extra["errors"][0]["fwcDiagnostic"]["RAW_CANARY"] = json!("secret");
        assert!(
            project_local_n8n_validation_with_context(&repack_versioned(extra), Some(&context))
                .is_err()
        );
    }

    #[test]
    fn versioned_validation_unknown_rule_reserved_name_and_incomplete_are_honest() {
        let mut error = versioned_required();
        error["fwcDiagnostic"]["code"] = json!("UNKNOWN_RULE_CANARY");
        let context = versioned_context(&diagnostic_graph());
        let result = project_local_n8n_validation_with_context(
            &versioned_native(json!([error]), json!([])),
            Some(&context),
        )
        .unwrap();
        assert_eq!(
            result["errors"][0]["unknownReason"],
            "unsupported_native_rule"
        );
        assert_eq!(result["validationCoverage"]["unclassifiedErrors"], 1);
        assert!(!result.to_string().contains("CANARY"));
        let mut graph = diagnostic_graph();
        graph["nodes"][0]["name"] = json!("workflow");
        let mut reserved = versioned_required();
        reserved["node"] = json!("workflow");
        let result = project_local_n8n_validation_with_context(
            &versioned_native(json!([reserved]), json!([])),
            Some(&versioned_context(&graph)),
        )
        .unwrap();
        assert_eq!(result["errors"][0]["code"], "unclassified");
        assert_eq!(
            result["errors"][0]["unknownReason"],
            "reserved_workflow_scope"
        );
        assert!(result["errors"][0].get("nodeIndex").is_none());
        let mut missing = versioned_native(json!([]), json!([]))["structuredContent"].clone();
        missing["valid"] = json!(false);
        missing["fwcValidation"]["schemaCoverageComplete"] = json!(false);
        missing["fwcValidation"]["schemas"][0] = json!({"index":0,"typeVersion":9,"status":"unsupported_version",
            "schemaVersion":null,"schemaSha256":null,"propertyCount":null});
        let result =
            project_local_n8n_validation_with_context(&repack_versioned(missing), Some(&context))
                .unwrap();
        assert_eq!(result["valid"], false);
        assert_eq!(
            result["validationCoverage"]["schemaCoverageComplete"],
            false
        );
        assert_eq!(result["validationCoverage"]["assessmentComplete"], false);
    }

    #[test]
    fn versioned_warning_origins_bind_nodes_and_preserve_safe_graph_scope() {
        let mut graph = diagnostic_graph();
        graph["nodes"][0]["continueOnFail"] = json!(true);
        let warning = json!({"node":"PRIVATE_NODE_CANARY","message":"WARNING_CANARY",
            "fwcWarning":{"code":"node_legacy_continue_on_fail","nodeIndex":0}});
        let native = versioned_native(
            json!([]),
            json!([warning,
            {"node":"workflow","message":"UNKNOWN_CANARY"}]),
        );
        let result =
            project_local_n8n_validation_with_context(&native, Some(&versioned_context(&graph)))
                .unwrap();
        assert_eq!(result["warnings"].as_array().unwrap().len(), 2);
        assert_eq!(result["warnings"][0]["nodeIndex"], 0);
        assert_eq!(result["warnings"][0]["field"], "continueOnFail");
        assert_eq!(result["validationCoverage"]["unclassifiedWarnings"], 1);
        assert!(!result.to_string().contains("CANARY"));
        for index in [json!(1), Value::Null] {
            let mut changed = warning.clone();
            changed["fwcWarning"]["nodeIndex"] = index;
            assert!(
                project_local_n8n_validation_with_context(
                    &versioned_native(json!([]), json!([changed])),
                    Some(&versioned_context(&graph))
                )
                .is_err()
            );
        }
        graph["nodes"][0]["continueOnFail"] = json!(false);
        assert!(
            project_local_n8n_validation_with_context(&native, Some(&versioned_context(&graph)))
                .is_err()
        );
        graph["nodes"][0]["disabled"] = json!(true);
        graph["connections"] = json!({"PRIVATE_NODE_CANARY":{"main":[[{"node":"PRIVATE_NODE_CANARY","type":"main","index":0}]]}});
        let mut scoped = versioned_native(
            json!([]),
            json!([{"node":"workflow","message":"GRAPH_CANARY",
            "fwcWarning":{"code":"connection_disabled_target","nodeIndex":null}}]),
        )["structuredContent"]
            .clone();
        scoped["fwcValidation"]["schemas"][0] = json!({"index":0,"typeVersion":9,"status":"disabled",
            "schemaVersion":null,"schemaSha256":null,"propertyCount":null});
        let result = project_local_n8n_validation_with_context(
            &repack_versioned(scoped),
            Some(&versioned_context(&graph)),
        )
        .unwrap();
        assert_eq!(
            result["warnings"][0]["code"],
            "graph_connection_disabled_target"
        );
        assert_eq!(result["warnings"][0]["scope"], "graph");
        assert_eq!(result["warnings"][0]["field"], "connections");
        assert_eq!(result["warnings"].as_array().unwrap().len(), 1);
        assert!(!result.to_string().contains("CANARY"));
        assert!(result["warnings"][0].get("nodeIndex").is_none());
        assert!(result["validationCoverage"]["warningOrigins"][0]["nodeIndex"].is_null());
        assert_eq!(
            result["validationCoverage"]["warningOrigins"][0]["scope"],
            "graph"
        );
    }

    #[test]
    fn versioned_duplicate_names_use_verified_slots_not_legacy_name_identity() {
        let mut graph = diagnostic_graph();
        let mut second = graph["nodes"][0].clone();
        second["id"] = json!("two");
        second["typeVersion"] = json!(10);
        graph["nodes"].as_array_mut().unwrap().push(second);
        let context = versioned_context(&graph);
        let mut second_error = versioned_required();
        second_error["fwcDiagnostic"]["nodeIndex"] = json!(1);
        second_error["fwcDiagnostic"]["typeVersion"] = json!(10);
        let mut typed = versioned_native(json!([versioned_required(), second_error]), json!([]))["structuredContent"].clone();
        typed["fwcValidation"]["graphNodes"] = json!(2);
        let mut schema = typed["fwcValidation"]["schemas"][0].clone();
        schema["index"] = json!(1);
        schema["typeVersion"] = json!(10);
        schema["schemaVersion"] = json!(10);
        typed["fwcValidation"]["schemas"]
            .as_array_mut()
            .unwrap()
            .push(schema);
        let result = project_local_n8n_validation_with_context(
            &repack_versioned(typed.clone()),
            Some(&context),
        )
        .unwrap();
        assert_eq!(result["errors"].as_array().unwrap().len(), 2);
        for index in 0..2 {
            assert_eq!(result["errors"][index]["nodeIndex"], index);
            assert_ne!(result["errors"][index]["code"], "unclassified");
        }
        assert!(!result.to_string().contains("CANARY"));
        for (index, version) in [(1, 9), (0, 10), (2, 9)] {
            let mut substituted = typed.clone();
            substituted["errors"][0]["fwcDiagnostic"]["nodeIndex"] = json!(index);
            substituted["errors"][0]["fwcDiagnostic"]["typeVersion"] = json!(version);
            assert!(
                project_local_n8n_validation_with_context(
                    &repack_versioned(substituted),
                    Some(&context)
                )
                .is_err()
            );
        }
        let legacy = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        let native = diagnostic_native(
            json!([{"node":"PRIVATE_NODE_CANARY","message":"UNKNOWN_CANARY"}]),
            json!([]),
        );
        let result = project_local_n8n_validation_with_context(&native, Some(&legacy)).unwrap();
        assert_eq!(
            result["errors"][0]["unknownReason"],
            "ambiguous_node_binding"
        );
        assert!(result["errors"][0].get("nodeIndex").is_none());
    }

    #[test]
    fn validation_unknown_fallback_and_zero_error_incomplete_have_closed_status() {
        let context = versioned_context(&diagnostic_graph());
        let native = versioned_native(
            json!([{"node":"PRIVATE_NODE_CANARY","message":"UNKNOWN_CANARY"}]),
            json!([]),
        );
        let result = project_local_n8n_validation_with_context(&native, Some(&context)).unwrap();
        let finding = &result["errors"][0];
        assert_eq!(finding["unknownReason"], "missing_origin");
        assert_eq!(finding["diagnosticStage"], "native_origin_projection");
        assert_eq!(finding["diagnosticSource"], "verified_derived_native");
        assert_eq!(finding["sourceVersion"], "2.91.0");
        assert_eq!(finding["binding"]["profile"], "runtime");
        assert!(finding["binding"]["graphDigest"].is_string());
        assert_eq!(
            finding["nextDiagnostic"],
            "authorized_graph_bound_native_diagnostic_required"
        );
        assert!(!result.to_string().contains("CANARY"));
        let unbound = project_local_n8n_validation_call(&diagnostic_native(
            json!([{"message":"UNKNOWN_CANARY"}]),
            json!([]),
        ))
        .unwrap();
        assert_eq!(unbound["errors"][0]["unknownReason"], "missing_context");
        assert!(unbound["errors"][0]["binding"].is_null());
        assert!(unbound["errors"][0]["sourceVersion"].is_null());
        let mut typed = versioned_native(json!([]), json!([]))["structuredContent"].clone();
        typed["fwcValidation"]["schemaCoverageComplete"] = json!(false);
        typed["fwcValidation"]["schemas"][0] = json!({"index":0,"typeVersion":9,"status":"unsupported_version",
            "schemaVersion":null,"schemaSha256":null,"propertyCount":null});
        let result =
            project_local_n8n_validation_with_context(&repack_versioned(typed), Some(&context))
                .unwrap();
        assert_eq!(result["valid"], true);
        assert_eq!(result["nativeValid"], true);
        assert_eq!(result["overallStatus"], "incomplete");
        assert_eq!(result["validationCoverage"]["assessmentComplete"], false);
        assert!(result["errors"].as_array().unwrap().is_empty());
        assert!(result["warnings"].as_array().unwrap().is_empty());
        let complete = project_local_n8n_validation_with_context(
            &versioned_native(json!([]), json!([])),
            Some(&context),
        )
        .unwrap();
        assert_eq!(complete["overallStatus"], "complete");
    }

    #[test]
    fn validation_diagnostics_classify_exact_version_support_and_preserve_counts() {
        let graph = diagnostic_graph();
        let context = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        let native = diagnostic_native(
            json!([{"node":"PRIVATE_NODE_CANARY",
            "message":"typeVersion 9 exceeds maximum supported version 2","details":"DETAIL_CANARY"}]),
            json!([{"node":"PRIVATE_NODE_CANARY","message":"UNKNOWN_WARNING_CANARY"}]),
        );
        let result = project_local_n8n_validation_with_context(&native, Some(&context)).unwrap();
        assert_eq!(result["valid"], false);
        assert_eq!(result["errors"].as_array().unwrap().len(), 1);
        assert_eq!(result["warnings"].as_array().unwrap().len(), 1);
        assert_eq!(result["errors"][0]["code"], "validator_type_version_limit");
        assert_eq!(
            result["errors"][0]["classification"],
            "validator_support_limit"
        );
        assert_eq!(result["errors"][0]["nodeIndex"], 0);
        assert_eq!(result["errors"][0]["field"], "typeVersion");
        assert_eq!(result["warnings"][0]["code"], "unclassified");
        assert!(!result.to_string().contains("CANARY"));
        assert_eq!(result["diagnosticBinding"]["packageVersion"], "2.91.0");
        let valid = project_local_n8n_validation_with_context(
            &diagnostic_native(json!([]), json!([])),
            Some(&context),
        )
        .unwrap();
        assert_eq!(valid["valid"], true);
        assert!(valid["errors"].as_array().unwrap().is_empty());
    }

    #[test]
    fn validation_diagnostics_unknown_ambiguous_and_hostile_are_unclassified() {
        let graph = diagnostic_graph();
        let context = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        for item in [
            json!({"node":"PRIVATE_NODE_CANARY","message":"typeVersion 9 exceeds maximum supported version 2 EXTRA_CANARY"}),
            json!({"node":"PRIVATE_NODE_CANARY","message":"typeVersion 9 exceeds maximum supported version 2\n"}),
            json!({"node":"PRIVATE_NODE_CANARY","message":"typeVersion 9 exceeds maximum supported version 20"}),
            json!({"node":"PRIVATE_NODE_CANARY","message":"typeVersion 8 exceeds maximum supported version 2"}),
            json!({"node":"OTHER_CANARY","message":"typeVersion 9 exceeds maximum supported version 2"}),
            json!({"node":"PRIVATE_NODE_CANARY\n","message":"typeVersion 9 exceeds maximum supported version 2"}),
            json!({"node":null,"message":"typeVersion 9 exceeds maximum supported version 2"}),
            json!({"message":"typeVersion 9 exceeds maximum supported version 2"}),
        ] {
            let result = project_local_n8n_validation_with_context(
                &diagnostic_native(json!([item]), json!([])),
                Some(&context),
            )
            .unwrap();
            assert_eq!(result["errors"][0]["code"], "unclassified");
            assert!(result["errors"][0].get("nodeIndex").is_none());
            assert!(!result.to_string().contains("CANARY"));
        }
        let native = diagnostic_native(
            json!([{"node":"PRIVATE_NODE_CANARY","message":"typeVersion 9 exceeds maximum supported version 2"}]),
            json!([]),
        );
        let mut duplicate = graph.clone();
        duplicate["nodes"]
            .as_array_mut()
            .unwrap()
            .push(graph["nodes"][0].clone());
        let duplicate_context = LocalN8nDiagnosticContext::from_graph(
            &duplicate,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        for context in [None, Some(&duplicate_context)] {
            let result = project_local_n8n_validation_with_context(&native, context).unwrap();
            assert_eq!(result["errors"][0]["code"], "unclassified");
        }
        assert!(
            LocalN8nDiagnosticContext::from_graph(
                &graph,
                LocalN8nValidationProfile::Runtime,
                "2.90.0",
                LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
            )
            .is_none()
        );
        assert!(
            LocalN8nDiagnosticContext::from_graph(
                &json!({}),
                LocalN8nValidationProfile::Runtime,
                "2.91.0",
                LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
            )
            .is_none()
        );
    }

    #[test]
    fn validation_diagnostics_missing_version_position_and_community_forms() {
        let mut graph = diagnostic_graph();
        graph["nodes"][0]
            .as_object_mut()
            .unwrap()
            .remove("typeVersion");
        graph["nodes"][0]["position"] = json!([]);
        let context = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        let native = diagnostic_native(
            json!([
                {"node":"PRIVATE_NODE_CANARY","message":"Missing required property 'typeVersion'. Add typeVersion: 2"},
                {"node":"PRIVATE_NODE_CANARY","message":"Node position must be an array with exactly 2 numbers [x, y]"}
            ]),
            json!([]),
        );
        let result = project_local_n8n_validation_with_context(&native, Some(&context)).unwrap();
        assert_eq!(result["errors"][0]["code"], "node_type_version_missing");
        assert_eq!(result["errors"][1]["code"], "node_position_shape");
        graph["nodes"][0]["type"] = json!("community.synthetic");
        let context = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        let native = diagnostic_native(
            json!([]),
            json!([{"node":"PRIVATE_NODE_CANARY",
            "message":"Unknown node type: \"community.synthetic\". This looks like a community node that is not in this server's node database — the workflow can still run on an n8n instance where the package is installed."}]),
        );
        let result = project_local_n8n_validation_with_context(&native, Some(&context)).unwrap();
        assert_eq!(
            result["warnings"][0]["code"],
            "validator_node_type_unavailable"
        );
        assert_eq!(result["valid"], true);
    }

    #[test]
    fn validation_diagnostics_reserved_workflow_fingerprint_and_parameter_rules() {
        let mut graph = diagnostic_graph();
        graph["nodes"][0]["name"] = json!("workflow");
        let context = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        let native = diagnostic_native(
            json!([{"node":"workflow","message":"typeVersion 9 exceeds maximum supported version 2"}]),
            json!([]),
        );
        let safe = project_local_n8n_validation_with_context(&native, Some(&context)).unwrap();
        assert_eq!(safe["errors"][0]["code"], "unclassified");
        assert!(safe["errors"][0].get("nodeIndex").is_none());
        assert!(
            LocalN8nDiagnosticContext::from_graph(
                &graph,
                LocalN8nValidationProfile::Runtime,
                "2.91.0",
                "altered"
            )
            .is_none()
        );
        graph["nodes"][0]["name"] = json!("PRIVATE_NODE_CANARY");
        graph["nodes"][0]["type"] = json!("n8n-nodes-base.code");
        graph["nodes"][0]["parameters"] =
            json!({"language":"pythonNative","pythonCode":" ","jsCode":"INACTIVE_CODE_CANARY"});
        let context = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        let native = diagnostic_native(
            json!([{"node":"PRIVATE_NODE_CANARY","message":"Code cannot be empty"}]),
            json!([]),
        );
        let safe = project_local_n8n_validation_with_context(&native, Some(&context)).unwrap();
        assert_eq!(safe["errors"][0]["field"], "parameters.pythonCode");
        assert!(!safe.to_string().contains("CANARY"));
        graph["nodes"][0]["parameters"]["pythonCode"] = json!("NONEMPTY_CODE_CANARY");
        let context = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        assert_eq!(
            project_local_n8n_validation_with_context(&native, Some(&context)).unwrap()["errors"]
                [0]["code"],
            "unclassified"
        );
        graph["nodes"][0]["type"] = json!("n8n-nodes-base.noOp");
        let context = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        let native = diagnostic_native(
            json!([]),
            json!([{"node":"PRIVATE_NODE_CANARY","message":"Node is not connected to any other nodes"}]),
        );
        assert_eq!(
            project_local_n8n_validation_with_context(&native, Some(&context)).unwrap()["warnings"]
                [0]["code"],
            "node_disconnected"
        );
        graph["connections"] =
            json!({"PRIVATE_NODE_CANARY":{"main":[[{"node":"other","type":"main","index":0}]]}});
        let context = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        assert_eq!(
            project_local_n8n_validation_with_context(&native, Some(&context)).unwrap()["warnings"]
                [0]["code"],
            "unclassified"
        );
    }

    #[test]
    fn validation_diagnostics_indexes_are_graph_local_and_digest_bound() {
        let mut graph = diagnostic_graph();
        graph["nodes"].as_array_mut().unwrap().insert(
            0,
            json!({"id":"two","name":"OTHER_PRIVATE_CANARY",
            "type":"n8n-nodes-base.noOp","typeVersion":1,"position":[1,0],"parameters":{}}),
        );
        let native = diagnostic_native(
            json!([{"node":"PRIVATE_NODE_CANARY","message":"typeVersion 9 exceeds maximum supported version 2"}]),
            json!([]),
        );
        let first = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        let first = project_local_n8n_validation_with_context(&native, Some(&first)).unwrap();
        assert_eq!(first["errors"][0]["nodeIndex"], 1);
        graph["nodes"].as_array_mut().unwrap().swap(0, 1);
        graph["nodes"][0]["parameters"] = json!({"changed":"PRIVATE_PARAMETER_CANARY"});
        let second = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Strict,
            "2.91.0",
            LOCAL_N8N_DIAGNOSTIC_PACKAGE_METADATA_DIGEST,
        )
        .unwrap();
        let second = project_local_n8n_validation_with_context(&native, Some(&second)).unwrap();
        assert_eq!(second["errors"][0]["nodeIndex"], 0);
        assert_ne!(
            first["diagnosticBinding"]["graphDigest"],
            second["diagnosticBinding"]["graphDigest"]
        );
        assert_eq!(second["diagnosticBinding"]["profile"], "strict");
        assert!(!second.to_string().contains("CANARY"));
    }

    #[test]
    fn validation_diagnostics_keep_envelope_bounds_and_contradiction_guards() {
        for text in [
            r#"{"valid":true,"valid":false,"errors":[],"warnings":[]}"#,
            r#"{"valid":false,"errors":[{"node":"one","node":"two","message":"x"}],"warnings":[]}"#,
        ] {
            assert!(
                project_local_n8n_validation_with_context(
                    &json!({"content":[{"type":"text","text":text}]}),
                    None
                )
                .is_err()
            );
        }
        let mut native = diagnostic_native(json!([{"message":"x"}]), json!([]));
        native["structuredContent"]["valid"] = json!(true);
        assert!(project_local_n8n_validation_call(&native).is_err());
        let native = diagnostic_native(json!([{"message":"x".repeat(8193)}]), json!([]));
        assert!(project_local_n8n_validation_call(&native).is_err());
        let native = diagnostic_native(json!(vec![json!({"message":"x"}); 257]), json!([]));
        assert!(project_local_n8n_validation_call(&native).is_err());
        let native = json!({"content":[{"type":"text","text":"x".repeat(256*1024+1)}]});
        assert!(project_local_n8n_validation_call(&native).is_err());
    }

    #[test]
    fn credential_metadata_protocol_native_shapes_and_redaction() {
        let mapping: CredentialMetadataReadMapping = serde_json::from_value(json!({
            "credential_id":fcp_core::CredentialId::new().to_string(),
            "purpose":"n8n.credentials.metadata.read","tool":"list_credentials","class":"read",
            "input_schema_digest":"sha256:a29acfec48d5f9919cb4fb65ce44c7fe544624a4ea537638d148b5c93ee3a821",
            "output_schema_digest":"sha256:305aeecb628786f249e9f71a2be18fc26a212b8dd4f090ff073c701a8b4563ac"
        })).unwrap();
        let mut protocol = CredentialMetadataReadProtocol::new(
            mapping,
            "eec",
            "original-request",
            json!({"limit":10,"projectId":"p"}),
        )
        .unwrap();
        // Synthetic schema admission belongs only to this in-module fixture;
        // production construction retains the two fixed installed raw pins.
        let input = json!({"type":"object","properties":{"limit":{"type":"integer"}}});
        let output = json!({"type":"object","properties":{"data":{"type":"array"}}});
        protocol.mapping.input_schema_digest = credential_metadata_schema_digest(&input).unwrap();
        protocol.mapping.output_schema_digest = credential_metadata_schema_digest(&output).unwrap();
        let native = json!({"data":[{"id":"c/1","name":"synthetic","type":"test","scopes":["credential:read"],"isManaged":false,"isGlobal":false,"homeProject":null,"data":{"secret":"SECRET_CANARY"}}],"count":1});
        let results = [
            json!({"protocolVersion":"2025-11-25","capabilities":{"tools":{}}}),
            Value::Null,
            json!({"tools":[{"name":"list_credentials","annotations":{"readOnlyHint":true},"inputSchema":input,"outputSchema":output}]}),
            json!({"structuredContent":native,"isError":false}),
        ];
        for (phase, result) in results.into_iter().enumerate() {
            let request = protocol.request().unwrap();
            if phase == 3 {
                assert_eq!(
                    request["params"]["arguments"],
                    json!({"limit":10,"projectId":"p"})
                );
            }
            assert!(
                protocol
                    .verify_in_flight_bytes(&serde_json::to_vec(&request).unwrap())
                    .is_err()
            );
            protocol.admit_request(&request).unwrap();
            assert!(protocol.request().is_err());
            assert!(
                protocol
                    .verify_in_flight_bytes(&serde_json::to_vec(&request).unwrap())
                    .is_ok()
            );
            assert!(protocol.verify_in_flight_bytes(b"[]").is_err());
            let bytes = if phase == 1 {
                Vec::new()
            } else {
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
                    .unwrap()
            };
            protocol
                .accept_response(
                    if phase == 1 { 202 } else { 200 },
                    Some("native-session"),
                    &bytes,
                )
                .unwrap();
        }
        let projected = protocol.projection().unwrap();
        assert_eq!(
            projected["credentials"][0]["resourceUri"],
            "fwc-n8n://eec/credentials/c%2F1"
        );
        assert!(!projected.to_string().contains("SECRET_CANARY"));
        assert!(protocol.request().is_err());
        assert!(
            protocol
                .admit_request(&json!({"method":"tools/call"}))
                .is_err()
        );
    }

    #[test]
    fn credential_metadata_duplicate_keys_and_batches_denied() {
        for bytes in [
            br#"{"result":{},"result":{"secret":"SECRET_CANARY"}}"#.as_slice(),
            br#"{"result":{"data":[],"data":["SECRET_CANARY"]}}"#.as_slice(),
        ] {
            assert_eq!(
                credential_metadata_unique_json(bytes).unwrap_err(),
                "credential_metadata_response_denied"
            );
            assert!(credential_metadata_rpc_json(bytes).is_err());
        }
        assert!(credential_metadata_unique_json(br#"{"ok":[true,null,1,"x"]}"#).is_ok());
        assert!(credential_metadata_rpc_json(b"data: {}\ndata: {}\n").is_err());
    }

    #[test]
    fn credential_metadata_schema_presence_drift_and_partial_response_denied() {
        let mapping: CredentialMetadataReadMapping=serde_json::from_value(json!({
            "credential_id":fcp_core::CredentialId::new().to_string(),"purpose":"n8n.credentials.metadata.read","tool":"list_credentials","class":"read",
            "input_schema_digest":"sha256:a29acfec48d5f9919cb4fb65ce44c7fe544624a4ea537638d148b5c93ee3a821",
            "output_schema_digest":"sha256:305aeecb628786f249e9f71a2be18fc26a212b8dd4f090ff073c701a8b4563ac"})).unwrap();
        let schema = json!({"type":"object"});
        assert_credential_catalog_defects(&mapping, &schema);
        assert!(
            credential_metadata_call_value(
                &json!({"isError":true,"content":[{"type":"text","text":"SECRET_CANARY"}]})
            )
            .is_err()
        );
        assert!(credential_metadata_call_value(&json!({"structuredContent":{"data":[],"count":0},"content":[{"type":"text","text":"{}"}]})).is_err());
        assert!(CredentialMetadataReadMapping::endpoint("legacy").is_err());
        assert_eq!(
            CredentialMetadataReadMapping::api_origin("hetzner").unwrap(),
            "https://n8nhet.levilaser.com"
        );
        assert_eq!(
            CredentialMetadataReadMapping::endpoint("hetzner").unwrap(),
            "https://n8nhet.levilaser.com:8443/mcp-server/http"
        );
    }

    fn assert_credential_catalog_defects(mapping: &CredentialMetadataReadMapping, schema: &Value) {
        for defect in [
            "input_drift",
            "missing_output",
            "write_annotation",
            "duplicate",
            "wrong_id",
            "partial_eof",
            "oversize",
            "session",
            "unrelated_null",
            "unrelated_missing_input",
            "unrelated_null_output",
            "unrelated_array_schema",
            "unrelated_duplicate",
            "unrelated_valid_addition",
            "unrelated_valid_drift",
        ] {
            let mut protocol = CredentialMetadataReadProtocol::synthetic_schema_fixture(
                mapping.clone(),
                "hetzner",
                "negative",
                json!({"limit":3}),
                schema,
                schema,
            )
            .unwrap();
            let initialize = protocol.request().unwrap();
            protocol.admit_request(&initialize).unwrap();
            protocol.accept_response(200,None,&serde_json::to_vec(&json!({"jsonrpc":"2.0","id":initialize["id"],"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}}}})).unwrap()).unwrap();
            assert_eq!(protocol.protocol_version(), "2025-06-18");
            let initialized = protocol.request().unwrap();
            protocol.admit_request(&initialized).unwrap();
            protocol.accept_response(202, None, &[]).unwrap();
            let list = protocol.request().unwrap();
            protocol.admit_request(&list).unwrap();
            let mut tool = json!({"name":"list_credentials","annotations":{"readOnlyHint":true},"inputSchema":schema,"outputSchema":schema});
            match defect {
                "input_drift" => tool["inputSchema"] = json!({"type":"array"}),
                "missing_output" => {
                    tool.as_object_mut().unwrap().remove("outputSchema");
                }
                "write_annotation" => tool["annotations"]["readOnlyHint"] = json!(false),
                _ => {}
            }
            let mut tools = if defect == "duplicate" {
                json!([tool.clone(), tool])
            } else {
                json!([tool])
            };
            let unrelated = json!({"name":"unrelated_write","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":false}});
            match defect {
                "unrelated_null" => tools.as_array_mut().unwrap().push(Value::Null),
                "unrelated_missing_input" => tools.as_array_mut().unwrap().push(json!({"name":"other"})),
                "unrelated_null_output" => tools.as_array_mut().unwrap().push(json!({"name":"other","inputSchema":{"type":"object"},"outputSchema":null})),
                "unrelated_array_schema" => tools.as_array_mut().unwrap().push(json!({"name":"other","inputSchema":{"type":"array"}})),
                "unrelated_duplicate" => tools.as_array_mut().unwrap().extend([unrelated.clone(), unrelated]),
                "unrelated_valid_addition" => tools.as_array_mut().unwrap().push(unrelated),
                "unrelated_valid_drift" => tools.as_array_mut().unwrap().push(json!({"name":"unrelated_write","inputSchema":{"type":"object","properties":{"changed":{"type":"string"}}},"outputSchema":{"type":"object","additionalProperties":true}})),
                _ => {}
            }
            let mut response = json!({"jsonrpc":"2.0","id":list["id"],"result":{"tools":tools}});
            if defect == "wrong_id" {
                response["id"] = json!("different");
            }
            let bytes = match defect {
                "partial_eof" => br#"{"jsonrpc":"2.0","result":"#.to_vec(),
                "oversize" => vec![b' '; 2 * 1024 * 1024 + 1],
                _ => serde_json::to_vec(&response).unwrap(),
            };
            if matches!(defect, "unrelated_valid_addition" | "unrelated_valid_drift") {
                protocol.accept_response(200, None, &bytes).unwrap();
                let application = protocol.request().unwrap();
                assert_eq!(application["params"]["name"], "list_credentials");
                continue;
            }
            assert!(
                protocol
                    .accept_response(
                        200,
                        if defect == "session" {
                            Some("unexpected")
                        } else {
                            None
                        },
                        &bytes
                    )
                    .is_err()
            );
            assert!(protocol.request().is_err());
            assert!(protocol.projection().is_err());
        }
    }

    #[test]
    fn credential_metadata_protocol_real_loopback_transport() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let mapping: CredentialMetadataReadMapping=serde_json::from_value(json!({
            "credential_id":fcp_core::CredentialId::new().to_string(),"purpose":"n8n.credentials.metadata.read",
            "tool":"list_credentials","class":"read",
            "input_schema_digest":"sha256:a29acfec48d5f9919cb4fb65ce44c7fe544624a4ea537638d148b5c93ee3a821",
            "output_schema_digest":"sha256:305aeecb628786f249e9f71a2be18fc26a212b8dd4f090ff073c701a8b4563ac"
        })).unwrap();
        let mut protocol = CredentialMetadataReadProtocol::new(
            mapping,
            "hetzner",
            "transport-test",
            json!({"limit":2,"type":"test"}),
        )
        .unwrap();
        let input = json!({"type":"object"});
        let output = json!({"type":"object","required":["data","count"]});
        protocol.mapping.input_schema_digest = credential_metadata_schema_digest(&input).unwrap();
        protocol.mapping.output_schema_digest = credential_metadata_schema_digest(&output).unwrap();
        let server = std::thread::spawn(move || {
            let methods = [
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call",
            ];
            for (phase, method) in methods.into_iter().enumerate() {
                let mut stream = accept_credential_loopback_stream(&listener);
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut received = Vec::new();
                let mut byte = [0u8; 1];
                while !received.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    received.push(byte[0]);
                    assert!(received.len() < 4096);
                }
                let header = std::str::from_utf8(&received).unwrap();
                assert!(header.starts_with("POST /mcp-server/http HTTP/1.1\r\n"));
                let length: usize = header
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!(length < 4096);
                let mut body = vec![0; length];
                stream.read_exact(&mut body).unwrap();
                let request = credential_metadata_unique_json(&body).unwrap();
                assert_eq!(request["method"], method);
                if phase == 3 {
                    assert_eq!(
                        request["params"],
                        json!({"name":"list_credentials","arguments":{"limit":2,"type":"test"}})
                    );
                }
                let result = match phase {
                    0 => json!({"protocolVersion":"2025-11-25","capabilities":{"tools":{}}}),
                    2 => {
                        json!({"tools":[{"name":"list_credentials","annotations":{"readOnlyHint":true},"inputSchema":input,"outputSchema":output}]})
                    }
                    _ => json!({"structuredContent":{"data":[],"count":0},"isError":false}),
                };
                let response = if phase == 1 {
                    Vec::new()
                } else {
                    serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
                        .unwrap()
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        // This is a native HTTP/protocol fixture, not the production TLS,
        // credential injection, capability or installed-admission proof.
        drive_credential_loopback_requests(&mut protocol, address);
        server.join().unwrap();
        assert!(protocol.completed());
        assert_eq!(protocol.projection().unwrap()["credentials"], json!([]));
    }

    fn accept_credential_loopback_stream(listener: &std::net::TcpListener) -> std::net::TcpStream {
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(3);
        let (stream, _) = loop {
            match listener.accept() {
                Ok(stream) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!(
                    "bounded synthetic transport accept failed: {:?}",
                    error.kind()
                ),
            }
        };
        stream
    }

    fn drive_credential_loopback_requests(
        protocol: &mut CredentialMetadataReadProtocol,
        address: std::net::SocketAddr,
    ) {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;
        for _ in 0..4 {
            let request = protocol.request().unwrap();
            let body = serde_json::to_vec(&request).unwrap();
            protocol.admit_request(&request).unwrap();
            let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            write!(stream,"POST /mcp-server/http HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
            stream.write_all(&body).unwrap();
            let mut response = Vec::new();
            stream.take(8192).read_to_end(&mut response).unwrap();
            let start = response
                .windows(4)
                .position(|bytes| bytes == b"\r\n\r\n")
                .unwrap()
                + 4;
            protocol
                .accept_response(200, None, &response[start..])
                .unwrap();
        }
    }

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
    fn installed_local_diagnostics_native_position_and_teardown() {
        let bytes = std::fs::read("/usr/local/lib/fwc-n8n/current/policy/local-mcp.json")
            .expect("existing public installed policy");
        let policy: fcp_manifest::LocalMcpPolicy = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(policy.package_version.to_string(), "2.91.0");
        assert!(policy.network_disabled);
        let graph = json!({"nodes":[{"id":"synthetic","name":"PRIVATE_NODE_CANARY",
            "type":"n8n-nodes-base.noOp","typeVersion":1,"parameters":{},"position":[]}],"connections":{}});
        let context = LocalN8nDiagnosticContext::from_graph(
            &graph,
            LocalN8nValidationProfile::Runtime,
            &policy.package_version.to_string(),
            &policy.package_metadata_digest,
        )
        .unwrap();
        let bound = policy.max_request_bytes as usize;
        let dispatcher =
            LocalN8nDispatcher::with_max_input_bytes(LocalMcpProvider::new(policy).unwrap(), bound);
        let result = dispatcher
            .validate_current_graph(
                "synthetic-safe-diagnostics".into(),
                graph,
                LocalN8nValidationProfile::Runtime,
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
        let safe =
            project_local_n8n_validation_with_context(&result.result.responses[0], Some(&context))
                .unwrap();
        assert_eq!(safe["valid"], false);
        assert!(
            safe["errors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|item| item["code"] == "node_position_shape" && item["nodeIndex"] == 0)
        );
        assert!(!safe.to_string().contains("CANARY"));
        println!(
            "synthetic_native_diagnostics=true network_disabled=true owned_reaped=true group_absent=true"
        );
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
    fn combined_template_batch_is_fixed_bounded_and_uses_normal_native_inputs() {
        let request: LocalN8nDispatchRequest = serde_json::from_value(json!({
        "operation":"n8n.knowledge.query","input":{"correlation_id":"templates-one",
            "action":{"search_templates_batch":[
                {"searchMode":"keyword","query":"synthetic","limit":100,"offset":0},
                {"searchMode":"by_nodes","nodeTypes":["nodes-base.noOp"],"limit":100,"offset":0}
            ]}}}))
        .unwrap();
        assert_eq!(request.internal_tool(), LocalN8nTool::SearchTemplates);
        let provider = request.into_provider_request().unwrap();
        assert_eq!(provider.calls.len(), 2);
        assert!(
            provider
                .calls
                .iter()
                .all(|call| call.tool == "search_templates")
        );
        assert_eq!(provider.calls[0].arguments["query"], "synthetic");
        assert_eq!(
            provider.calls[1].arguments["nodeTypes"],
            json!(["nodes-base.noOp"])
        );
        for queries in [
            json!([]),
            json!([{"query":"synthetic"}]),
            json!(vec![json!({"query":"synthetic"}); 5]),
        ] {
            let request: LocalN8nDispatchRequest = serde_json::from_value(json!({"operation":"n8n.knowledge.query","input":{"correlation_id":"templates-one","action":{"search_templates_batch":queries}}})).unwrap();
            assert!(request.into_provider_request().is_err());
        }
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
