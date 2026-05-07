use std::collections::BTreeMap;

use fcp_prelude::{FcpError, FcpResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitWorkflowInput {
    #[serde(alias = "prompt")]
    pub workflow: Value,
    pub client_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptIdInput {
    pub prompt_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelInput {
    pub prompt_id: String,
    #[serde(default)]
    pub interrupt_running: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitInput {
    pub prompt_id: String,
    pub timeout_ms: Option<u64>,
    pub poll_interval_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PromptSubmitResponse {
    pub prompt_id: Option<String>,
    pub number: Option<u64>,
    #[serde(default)]
    pub node_errors: Value,
    #[serde(default)]
    pub error: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistoryEntry {
    #[serde(default)]
    pub outputs: BTreeMap<String, OutputNode>,
    #[serde(default)]
    pub status: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutputNode {
    #[serde(default)]
    pub images: Vec<ComfyImage>,
    #[serde(default)]
    pub gifs: Vec<ComfyImage>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ComfyImage {
    pub filename: String,
    #[serde(default)]
    pub subfolder: String,
    #[serde(rename = "type", default = "default_output_type")]
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ViewArtifact {
    pub node_id: String,
    pub filename: String,
    pub subfolder: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub url: String,
    pub url_host_class: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorkflowStatus {
    pub prompt_id: String,
    pub complete: bool,
    pub output_count: usize,
    pub node_count: usize,
    pub status: Value,
}

pub type HistoryResponse = BTreeMap<String, HistoryEntry>;

impl SubmitWorkflowInput {
    pub fn parse(value: Value, default_client_id: &str) -> FcpResult<Self> {
        let mut input: Self =
            serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid ComfyUI submit input: {err}"),
            })?;
        validate_workflow_json(&input.workflow)?;
        input.client_id = Some(validate_client_id(
            input.client_id.as_deref().unwrap_or(default_client_id),
        )?);
        Ok(input)
    }

    pub fn request_body(&self) -> Value {
        json!({
            "prompt": self.workflow,
            "client_id": self.client_id.as_deref().unwrap_or_default(),
        })
    }
}

impl PromptIdInput {
    pub fn parse(value: Value) -> FcpResult<Self> {
        let input: Self =
            serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid ComfyUI prompt_id input: {err}"),
            })?;
        validate_prompt_id(&input.prompt_id)?;
        Ok(input)
    }
}

impl CancelInput {
    pub fn parse(value: Value) -> FcpResult<Self> {
        let input: Self =
            serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid ComfyUI cancel input: {err}"),
            })?;
        validate_prompt_id(&input.prompt_id)?;
        Ok(input)
    }
}

impl WaitInput {
    pub fn parse(value: Value) -> FcpResult<Self> {
        let input: Self =
            serde_json::from_value(value).map_err(|err| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid ComfyUI wait input: {err}"),
            })?;
        validate_prompt_id(&input.prompt_id)?;
        if input.timeout_ms.is_some_and(|timeout| timeout == 0) {
            return invalid("timeout_ms must be greater than 0");
        }
        if input
            .poll_interval_ms
            .is_some_and(|interval| interval == 0 || interval > 60_000)
        {
            return invalid("poll_interval_ms must be between 1 and 60000");
        }
        Ok(input)
    }
}

pub fn validate_workflow_json(workflow: &Value) -> FcpResult<()> {
    if !workflow.is_object() {
        return invalid("workflow must be a JSON object");
    }
    let bytes = serde_json::to_vec(workflow).map_err(|err| FcpError::InvalidRequest {
        code: 1003,
        message: format!("workflow JSON did not serialize: {err}"),
    })?;
    if bytes.is_empty() || bytes.len() > 16 * 1024 * 1024 {
        return invalid("workflow JSON must be between 1 byte and 16 MiB");
    }
    Ok(())
}

pub fn validate_prompt_id(prompt_id: &str) -> FcpResult<String> {
    validate_token_like("prompt_id", prompt_id, 256)
}

pub fn validate_client_id(client_id: &str) -> FcpResult<String> {
    validate_token_like("client_id", client_id, 256)
}

pub fn status_from_history(prompt_id: &str, history: &HistoryResponse) -> WorkflowStatus {
    let entry = history.get(prompt_id);
    let output_count = entry.map_or(0, output_count);
    WorkflowStatus {
        prompt_id: prompt_id.into(),
        complete: entry.is_some(),
        output_count,
        node_count: entry.map_or(0, |entry| entry.outputs.len()),
        status: entry.map_or_else(|| json!({"state": "pending"}), |entry| entry.status.clone()),
    }
}

pub fn artifacts_from_history(
    base_url: &str,
    prompt_id: &str,
    history: &HistoryResponse,
) -> FcpResult<Vec<ViewArtifact>> {
    let Some(entry) = history.get(prompt_id) else {
        return Ok(Vec::new());
    };
    let mut artifacts = Vec::new();
    for (node_id, node) in &entry.outputs {
        for image in node.images.iter().chain(node.gifs.iter()) {
            artifacts.push(ViewArtifact {
                node_id: node_id.clone(),
                filename: image.filename.clone(),
                subfolder: image.subfolder.clone(),
                kind: image.kind.clone(),
                url: view_url(base_url, image)?,
                url_host_class: view_url_host_class(base_url),
            });
        }
    }
    Ok(artifacts)
}

pub fn view_url(base_url: &str, image: &ComfyImage) -> FcpResult<String> {
    validate_image_component("filename", &image.filename)?;
    validate_image_component("subfolder", &image.subfolder)?;
    validate_image_component("type", &image.kind)?;
    let mut url = Url::parse(base_url).map_err(|err| FcpError::InvalidRequest {
        code: 1003,
        message: format!("Invalid ComfyUI base_url: {err}"),
    })?;
    url.set_path("/view");
    url.set_query(None);
    url.query_pairs_mut()
        .append_pair("filename", &image.filename)
        .append_pair("subfolder", &image.subfolder)
        .append_pair("type", &image.kind);
    Ok(url.to_string())
}

pub fn output_count(entry: &HistoryEntry) -> usize {
    entry
        .outputs
        .values()
        .map(|node| node.images.len() + node.gifs.len())
        .sum()
}

fn validate_token_like(field: &str, value: &str, max_len: usize) -> FcpResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return invalid(&format!("{field} must not be empty"));
    }
    if trimmed.len() > max_len {
        return invalid(&format!("{field} must be at most {max_len} bytes"));
    }
    if trimmed.bytes().any(|byte| {
        matches!(
            byte,
            b'\r' | b'\n' | b'\0' | b'/' | b'\\' | b'?' | b'#' | b'&' | b'='
        )
    }) {
        return invalid(&format!("{field} contains characters invalid in paths"));
    }
    Ok(trimmed.to_string())
}

fn validate_image_component(field: &str, value: &str) -> FcpResult<()> {
    if value.len() > 1024 {
        return invalid(&format!("{field} must be at most 1024 bytes"));
    }
    if value
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | b'\0'))
    {
        return invalid(&format!("{field} contains invalid characters"));
    }
    Ok(())
}

fn view_url_host_class(base_url: &str) -> &'static str {
    Url::parse(base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_owned))
        .map_or("invalid", |host| {
            if matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1") {
                "loopback"
            } else if host.ends_with(".ts.net") {
                "tailnet_dns"
            } else {
                "operator_allowed_host"
            }
        })
}

fn default_output_type() -> String {
    "output".into()
}

fn invalid<T>(message: &str) -> FcpResult<T> {
    Err(FcpError::InvalidRequest {
        code: 1003,
        message: message.into(),
    })
}
