//! FCP Google Docs Connector implementation.

use std::sync::Arc;

use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::DocsClient;
use crate::error::DocsError;
use crate::types::{Request, TextStyle};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_REQUESTS: usize = 100;
const MAX_BATCH_BYTES: usize = 512 * 1024;
const MAX_TEXT_BYTES: usize = 100 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_DOCUMENT_INDEX: u32 = 10_000_000;
const MAX_READ_TEXT_BYTES: usize = 48_000;

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn host_is_docs_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("docs.googleapis.com")
}

/// Validate a google-docs `base_url` override.
///
/// The Docs client concatenates this string into downstream request URLs, so
/// only the Docs API host is accepted outside local test listeners.
fn validate_docs_base_url(raw: &str) -> FcpResult<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not be empty".into(),
        });
    }
    let parsed = Url::parse(trimmed).map_err(|error| FcpError::InvalidRequest {
        code: 1003,
        message: format!("base_url could not be parsed: {error}"),
    })?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use http or https".into(),
        });
    }
    let host = parsed.host_str().ok_or(FcpError::InvalidRequest {
        code: 1003,
        message: "base_url must include a host".into(),
    })?;
    let local = is_local_test_host(host);
    if parsed.scheme() == "http" && !local {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must use https unless targeting localhost/127.0.0.1/::1 for tests"
                .into(),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include userinfo".into(),
        });
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: "base_url must not include a query string or fragment".into(),
        });
    }
    if !local && !host_is_docs_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url host must target docs.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn docs_document_resource_uri(document_id: &str) -> String {
    format!("google-docs:document:{document_id}")
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    match operation {
        "docs.get" | "docs.batch_update" => {
            let document_id = require_str(input, "document_id")?;
            Ok(vec![docs_document_resource_uri(document_id)])
        }
        "docs.create" => Ok(vec!["google-docs:documents".to_string()]),
        _ => Ok(Vec::new()),
    }
}

fn docs_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        "docs.get" => Ok(CapabilityId::from_static("docs.read")),
        "docs.create" | "docs.batch_update" => Ok(CapabilityId::from_static("docs.write")),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn validate_docs_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    let allowed_fields: &[&str] = match operation {
        "docs.get" => &["document_id", "text_offset", "text_limit"],
        "docs.create" => &["title"],
        "docs.batch_update" => &[
            "document_id",
            "requests",
            "required_revision_id",
            "confirm_destructive",
            "confirmation_sha256",
        ],
        _ => &[],
    };
    let object = input
        .as_object()
        .ok_or_else(|| invalid("operation input must be an object"))?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed_fields.contains(&field.as_str()))
    {
        return Err(invalid(format!("unsupported input field '{field}'")));
    }
    match operation {
        "docs.get" => {
            validate_identifier(require_str(input, "document_id")?, "document_id")?;
            optional_bounded_usize(input, "text_offset", 0, MAX_DOCUMENT_INDEX as usize)?;
            optional_bounded_usize(input, "text_limit", 1, MAX_READ_TEXT_BYTES)?;
        }
        "docs.create" => {
            validate_title(require_str(input, "title")?)?;
        }
        "docs.batch_update" => {
            validate_identifier(require_str(input, "document_id")?, "document_id")?;
            validated_requests(input)?;
            if let Some(revision) = input.get("required_revision_id") {
                validate_identifier(
                    revision
                        .as_str()
                        .ok_or_else(|| invalid("'required_revision_id' must be a string"))?,
                    "required_revision_id",
                )?;
            }
            if let Some(hash) = input.get("confirmation_sha256") {
                let hash = hash
                    .as_str()
                    .ok_or_else(|| invalid("'confirmation_sha256' must be a string"))?;
                if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(invalid(
                        "'confirmation_sha256' must be 64 hexadecimal characters",
                    ));
                }
            }
            if input.get("confirm_destructive").is_some()
                && input
                    .get("confirm_destructive")
                    .and_then(serde_json::Value::as_bool)
                    .is_none()
            {
                return Err(invalid("'confirm_destructive' must be a boolean"));
            }
        }
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1001,
        message: message.into(),
    }
}

fn validate_title(value: &str) -> FcpResult<&str> {
    let value = value.trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(invalid(
            "title must be 1..=256 bytes without control characters",
        ));
    }
    Ok(value)
}

fn validate_identifier<'a>(value: &'a str, field: &str) -> FcpResult<&'a str> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "'{field}' must be 1..={MAX_IDENTIFIER_BYTES} bytes without control characters"
        )));
    }
    Ok(value)
}

fn optional_bounded_usize(
    input: &serde_json::Value,
    field: &str,
    minimum: usize,
    maximum: usize,
) -> FcpResult<Option<usize>> {
    input
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .filter(|value| (*value >= minimum) && (*value <= maximum))
                .ok_or_else(|| invalid(format!("'{field}' must be {minimum}..={maximum}")))
        })
        .transpose()
}

fn validate_location(location: &crate::types::Location) -> FcpResult<()> {
    if location.index == 0 || location.index > MAX_DOCUMENT_INDEX {
        return Err(invalid(format!(
            "location.index must be 1..={MAX_DOCUMENT_INDEX}"
        )));
    }
    if let Some(segment_id) = &location.segment_id {
        validate_identifier(segment_id, "segmentId")?;
    }
    if let Some(tab_id) = &location.tab_id {
        validate_identifier(tab_id, "tabId")?;
    }
    Ok(())
}

fn validate_range(range: &crate::types::Range) -> FcpResult<()> {
    if range.start_index == 0
        || range.start_index >= range.end_index
        || range.end_index > MAX_DOCUMENT_INDEX
    {
        return Err(invalid(format!(
            "range must satisfy 1 <= startIndex < endIndex <= {MAX_DOCUMENT_INDEX}"
        )));
    }
    if let Some(segment_id) = &range.segment_id {
        validate_identifier(segment_id, "segmentId")?;
    }
    if let Some(tab_id) = &range.tab_id {
        validate_identifier(tab_id, "tabId")?;
    }
    Ok(())
}

fn validate_text(value: &str, field: &str, allow_empty: bool) -> FcpResult<()> {
    if (!allow_empty && value.is_empty()) || value.len() > MAX_TEXT_BYTES {
        return Err(invalid(format!(
            "'{field}' must be {}..={MAX_TEXT_BYTES} bytes",
            usize::from(!allow_empty)
        )));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(invalid(format!(
            "'{field}' contains unsupported control characters"
        )));
    }
    Ok(())
}

fn validate_text_style(style: &TextStyle, fields: &str) -> FcpResult<()> {
    let mut provided = Vec::new();
    if style.bold.is_some() {
        provided.push("bold");
    }
    if style.italic.is_some() {
        provided.push("italic");
    }
    if style.underline.is_some() {
        provided.push("underline");
    }
    if style.font_size.is_some() {
        provided.push("fontSize");
    }
    if style.foreground_color.is_some() {
        provided.push("foregroundColor");
    }
    let requested = fields.split(',').map(str::trim).collect::<Vec<_>>();
    if requested.is_empty()
        || requested.iter().any(|field| field.is_empty())
        || requested != provided
    {
        return Err(invalid(
            "updateTextStyle fields must list exactly the provided allowlisted style fields in canonical order",
        ));
    }
    if let Some(font_size) = &style.font_size {
        if font_size.unit != "PT" || !(1.0..=400.0).contains(&font_size.magnitude) {
            return Err(invalid("fontSize must use PT with magnitude 1..=400"));
        }
    }
    if let Some(color) = &style.foreground_color {
        let color = color
            .color
            .as_ref()
            .ok_or_else(|| invalid("foregroundColor.color is required"))?;
        if ![color.red, color.green, color.blue]
            .into_iter()
            .all(|component| (0.0..=1.0).contains(&component))
        {
            return Err(invalid("foregroundColor components must be 0..=1"));
        }
    }
    Ok(())
}

fn validated_requests(input: &serde_json::Value) -> FcpResult<Vec<Request>> {
    let value = input
        .get("requests")
        .ok_or_else(|| invalid("Missing 'requests'"))?;
    let serialized = serde_json::to_vec(value)
        .map_err(|error| invalid(format!("invalid requests JSON: {error}")))?;
    if serialized.len() > MAX_BATCH_BYTES {
        return Err(invalid(format!(
            "'requests' exceeds the {MAX_BATCH_BYTES}-byte batch limit"
        )));
    }
    let requests: Vec<Request> = serde_json::from_value(value.clone()).map_err(|_| {
        invalid("'requests' must contain only supported typed Google Docs requests")
    })?;
    if requests.is_empty() || requests.len() > MAX_REQUESTS {
        return Err(invalid(format!(
            "'requests' must contain 1..={MAX_REQUESTS} entries"
        )));
    }
    for request in &requests {
        match request {
            Request::InsertText(request) => {
                validate_location(&request.location)?;
                validate_text(&request.text, "insertText.text", false)?;
            }
            Request::UpdateTextStyle(request) => {
                validate_range(&request.range)?;
                validate_text_style(&request.text_style, &request.fields)?;
            }
            Request::UpdateParagraphStyle(request) => {
                validate_range(&request.range)?;
                if request.fields != "namedStyleType"
                    || !matches!(
                        request.paragraph_style.named_style_type.as_str(),
                        "NORMAL_TEXT"
                            | "TITLE"
                            | "SUBTITLE"
                            | "HEADING_1"
                            | "HEADING_2"
                            | "HEADING_3"
                            | "HEADING_4"
                            | "HEADING_5"
                            | "HEADING_6"
                    )
                {
                    return Err(invalid(
                        "updateParagraphStyle supports only a provided namedStyleType",
                    ));
                }
            }
            Request::CreateParagraphBullets(request) => {
                validate_range(&request.range)?;
                if !matches!(
                    request.bullet_preset.as_str(),
                    "BULLET_DISC_CIRCLE_SQUARE"
                        | "BULLET_DIAMONDX_ARROW3D_SQUARE"
                        | "BULLET_CHECKBOX"
                        | "NUMBERED_DECIMAL_ALPHA_ROMAN"
                        | "NUMBERED_DECIMAL_ALPHA_ROMAN_PARENS"
                        | "NUMBERED_DECIMAL_NESTED"
                ) {
                    return Err(invalid("unsupported bulletPreset"));
                }
            }
            Request::DeleteParagraphBullets(request) => validate_range(&request.range)?,
            Request::InsertTable(request) => {
                validate_location(&request.location)?;
                if !(1..=20).contains(&request.rows) || !(1..=20).contains(&request.columns) {
                    return Err(invalid("insertTable rows and columns must each be 1..=20"));
                }
            }
            Request::CreateNamedRange(request) => {
                validate_identifier(&request.name, "createNamedRange.name")?;
                validate_range(&request.range)?;
            }
            Request::DeleteContentRange(request) => validate_range(&request.range)?,
            Request::ReplaceAllText(request) => {
                validate_text(&request.contains_text.text, "containsText.text", false)?;
                validate_text(&request.replace_text, "replaceText", true)?;
                validate_tabs_criteria(request.tabs_criteria.as_ref())?;
            }
            Request::ReplaceNamedRangeContent(request) => {
                validate_exactly_one_identifier(
                    request.named_range_id.as_deref(),
                    request.named_range_name.as_deref(),
                    "namedRangeId",
                    "namedRangeName",
                )?;
                validate_text(&request.text, "replaceNamedRangeContent.text", true)?;
                validate_tabs_criteria(request.tabs_criteria.as_ref())?;
            }
            Request::DeleteNamedRange(request) => {
                validate_exactly_one_identifier(
                    request.named_range_id.as_deref(),
                    request.name.as_deref(),
                    "namedRangeId",
                    "name",
                )?;
                validate_tabs_criteria(request.tabs_criteria.as_ref())?;
            }
            Request::ReplaceImage(request) => {
                validate_identifier(&request.image_object_id, "imageObjectId")?;
                let uri = Url::parse(&request.uri)
                    .map_err(|_| invalid("replaceImage.uri must be a valid HTTPS URL"))?;
                if uri.scheme() != "https" || request.uri.len() > 2048 {
                    return Err(invalid(
                        "replaceImage.uri must be an HTTPS URL up to 2048 bytes",
                    ));
                }
                if request.image_replace_method != "CENTER_CROP" {
                    return Err(invalid("imageReplaceMethod must be CENTER_CROP"));
                }
                if let Some(tab_id) = request.tab_id.as_deref() {
                    validate_identifier(tab_id, "tabId")?;
                }
            }
        }
    }
    Ok(requests)
}

fn validate_tabs_criteria(criteria: Option<&crate::types::TabsCriteria>) -> FcpResult<()> {
    let Some(criteria) = criteria else {
        return Ok(());
    };
    if criteria.tab_ids.is_empty() || criteria.tab_ids.len() > 100 {
        return Err(invalid("tabsCriteria.tabIds must contain 1..=100 entries"));
    }
    for tab_id in &criteria.tab_ids {
        validate_identifier(tab_id, "tabId")?;
    }
    Ok(())
}

fn validate_exactly_one_identifier(
    first: Option<&str>,
    second: Option<&str>,
    first_name: &str,
    second_name: &str,
) -> FcpResult<()> {
    match (first, second) {
        (Some(value), None) => {
            validate_identifier(value, first_name)?;
            Ok(())
        }
        (None, Some(value)) => {
            validate_identifier(value, second_name)?;
            Ok(())
        }
        _ => Err(invalid(format!(
            "exactly one of '{first_name}' or '{second_name}' is required"
        ))),
    }
}

fn document_revision(document: &serde_json::Value) -> FcpResult<&str> {
    document
        .get("revisionId")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("document revision is unavailable; edit access is required"))
}

fn document_receipt(document: &serde_json::Value) -> serde_json::Value {
    json!({
        "document_id": document.get("documentId").and_then(serde_json::Value::as_str),
        "title": document.get("title").and_then(serde_json::Value::as_str),
        "revision_id": document.get("revisionId").and_then(serde_json::Value::as_str),
        "tab_count": document.get("tabs").and_then(serde_json::Value::as_array).map_or(0, Vec::len),
    })
}

fn collect_document_text(value: &serde_json::Value, output: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(content) = map
                .get("textRun")
                .and_then(|run| run.get("content"))
                .and_then(serde_json::Value::as_str)
            {
                output.push_str(content);
            }
            for (key, nested) in map {
                if key != "textRun" {
                    collect_document_text(nested, output);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values {
                collect_document_text(nested, output);
            }
        }
        _ => {}
    }
}

fn bounded_text_slice(value: &str, offset: usize, limit: usize) -> (&str, usize, usize) {
    let start = value
        .char_indices()
        .map(|(index, _)| index)
        .find(|index| *index >= offset)
        .unwrap_or(value.len());
    let candidate_end = start.saturating_add(limit).min(value.len());
    let end = if candidate_end == value.len() {
        value.len()
    } else {
        value
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= candidate_end)
            .last()
            .unwrap_or(start)
    };
    (&value[start..end], start, end)
}

fn compact_document(
    document: &serde_json::Value,
    offset: usize,
    limit: usize,
) -> serde_json::Value {
    let mut text = String::new();
    collect_document_text(document, &mut text);
    let (page, actual_offset, next_offset) = bounded_text_slice(&text, offset, limit);
    json!({
        "metadata": document_receipt(document),
        "text": page,
        "text_offset": actual_offset,
        "text_next_offset": next_offset,
        "text_complete": next_offset >= text.len(),
        "text_total_bytes": text.len(),
    })
}

fn request_impact(request: &Request) -> serde_json::Value {
    let kind = request.kind();
    match request {
        Request::DeleteContentRange(request) => json!({
            "kind": kind,
            "start_index": request.range.start_index,
            "end_index": request.range.end_index,
            "utf16_units": request.range.end_index.saturating_sub(request.range.start_index),
            "segment_id_sha256": request.range.segment_id.as_ref().map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
            "tab_id_sha256": request.range.tab_id.as_ref().map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
        }),
        Request::ReplaceAllText(request) => json!({
            "kind": kind,
            "match_case": request.contains_text.match_case,
            "search_sha256": hex::encode(Sha256::digest(request.contains_text.text.as_bytes())),
            "search_bytes": request.contains_text.text.len(),
            "replacement_bytes": request.replace_text.len(),
            "tab_count": request.tabs_criteria.as_ref().map_or(0, |criteria| criteria.tab_ids.len()),
            "tabs_sha256": request.tabs_criteria.as_ref().map(|criteria| hash_serializable(&criteria.tab_ids)),
        }),
        Request::ReplaceNamedRangeContent(request) => json!({
            "kind": kind,
            "named_range_id_sha256": request.named_range_id.as_ref().map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
            "named_range_name_sha256": request.named_range_name.as_ref().map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
            "replacement_bytes": request.text.len(),
            "tab_count": request.tabs_criteria.as_ref().map_or(0, |criteria| criteria.tab_ids.len()),
            "tabs_sha256": request.tabs_criteria.as_ref().map(|criteria| hash_serializable(&criteria.tab_ids)),
        }),
        Request::DeleteNamedRange(request) => json!({
            "kind": kind,
            "named_range_id_sha256": request.named_range_id.as_ref().map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
            "name_sha256": request.name.as_ref().map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
            "tab_count": request.tabs_criteria.as_ref().map_or(0, |criteria| criteria.tab_ids.len()),
            "tabs_sha256": request.tabs_criteria.as_ref().map(|criteria| hash_serializable(&criteria.tab_ids)),
        }),
        Request::ReplaceImage(request) => json!({
            "kind": kind,
            "image_object_id_sha256": hex::encode(Sha256::digest(request.image_object_id.as_bytes())),
            "uri_sha256": hex::encode(Sha256::digest(request.uri.as_bytes())),
            "tab_id_sha256": request.tab_id.as_ref().map(|value| hex::encode(Sha256::digest(value.as_bytes()))),
        }),
        _ => json!({ "kind": kind, "destructive": false }),
    }
}

fn hash_serializable(value: &impl serde::Serialize) -> String {
    let encoded = serde_json::to_vec(value).unwrap_or_default();
    hex::encode(Sha256::digest(encoded))
}

fn confirmation_sha256(
    document_id: &str,
    revision_id: &str,
    requests: &[Request],
) -> FcpResult<String> {
    let encoded = serde_json::to_vec(&(document_id, revision_id, requests))
        .map_err(|error| invalid(format!("could not bind confirmation payload: {error}")))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

/// FCP Google Docs Connector.
pub struct DocsConnector {
    base: Arc<BaseConnector>,
    client: Option<DocsClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
}

impl DocsConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("google-docs"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    #[must_use]
    fn manifest_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
    }

    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let auth_params = params
            .get("auth")
            .cloned()
            .unwrap_or_else(|| params.clone());

        let selection =
            GoogleAuthSelection::from_connector_config(&auth_params).map_err(|error| {
                FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Invalid Google auth config: {error}"),
                }
            })?;

        let materialized =
            selection
                .materialize()
                .await
                .map_err(|error| FcpError::InvalidRequest {
                    code: 1003,
                    message: format!("Failed to materialize Google auth: {error}"),
                })?;

        let status = match &materialized {
            GoogleMaterializedAuth::CredentialReference { .. } => {
                "configured_pending_token_materialization"
            }
            GoogleMaterializedAuth::BearerToken { .. } => "configured",
        };

        let mut client =
            DocsClient::new_with_auth(materialized).map_err(|e| FcpError::Internal {
                message: format!("Failed to create Docs client: {e}"),
            })?;
        if let Some(value) = params.get("base_url") {
            let base_url = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "`base_url` must be a string".into(),
            })?;
            client = client.with_base_url(validate_docs_base_url(base_url)?);
        }

        let auth_label = client.auth_redacted_label();
        self.client = Some(client);
        self.base.set_configured(true);
        info!(auth = %auth_label, status, "Google Docs connector configured");

        Ok(json!({ "status": status }))
    }

    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        if let Some(requested_instance_id) = req.requested_instance_id {
            let base = Arc::get_mut(&mut self.base).ok_or_else(|| FcpError::Internal {
                message: "Cannot assign requested instance ID after connector state is shared"
                    .into(),
            })?;
            base.instance_id = requested_instance_id;
        }

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = fcp_core::SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);

        let capabilities_granted: Vec<CapabilityGrant> = req
            .capabilities_requested
            .into_iter()
            .map(|cap| CapabilityGrant {
                capability: cap,
                operation: None,
            })
            .collect();

        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted,
            session_id,
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };

        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let status = if self.client.is_some() {
            "healthy"
        } else {
            "not_configured"
        };
        let metrics = self.base.metrics();
        Ok(json!({
            "status": status,
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let checks = vec![
            json!({
                "name": "configuration",
                "passed": configured,
                "message": if configured { "Connector is configured" } else { "Not configured - run configure first" },
                "critical": true,
            }),
            json!({
                "name": "client_initialized",
                "passed": configured,
                "message": if configured { "HTTP client is ready" } else { "HTTP client is not initialized" },
                "critical": true,
            }),
        ];
        let status = if checks
            .iter()
            .all(|c| c["passed"].as_bool().unwrap_or(false))
        {
            "healthy"
        } else {
            "unhealthy"
        };
        Ok(json!({ "status": status, "checks": checks }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<serde_json::Value> {
        if self.client.is_none() {
            return Ok(json!({
                "status": "fail",
                "check": "not_configured",
                "message": "Connector is not configured yet"
            }));
        }
        Ok(json!({
            "status": "pass",
            "check": "configured",
            "message": "Connector is operational"
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
            operations: vec![
                op_info(
                    "docs.get",
                    "Get a document by ID",
                    json!({
                        "type": "object",
                        "required": ["document_id"],
                        "properties": {
                            "document_id": { "type": "string", "minLength": 1, "maxLength": 512 },
                            "text_offset": { "type": "integer", "minimum": 0, "maximum": 10000000 },
                            "text_limit": { "type": "integer", "minimum": 1, "maximum": 48000 }
                        },
                        "additionalProperties": false
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "status": { "type": "string" },
                            "document": { "type": "object" },
                            "readback": { "type": "object" },
                            "retry_safe": { "type": "boolean" }
                        }
                    }),
                    "docs.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use:
                            "Retrieve a Google Docs document including title, body content, and structure."
                                .into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"document_id": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"}"#
                                .into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("docs.create"),
                            CapabilityId::from_static("docs.batch_update"),
                        ],
                    },
                ),
                op_info(
                    "docs.create",
                    "Create a new document",
                    json!({
                        "type": "object",
                        "required": ["title"],
                        "properties": {
                            "title": { "type": "string", "minLength": 1, "maxLength": 256 }
                        },
                        "additionalProperties": false
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "document": { "type": "object" }
                        }
                    }),
                    "docs.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a brand new Google Docs document with a given title."
                            .into(),
                        common_mistakes: vec![
                            "Each call creates a new document — do not call repeatedly for the same title"
                                .into(),
                        ],
                        examples: vec![r#"{"title": "Meeting Notes 2026-03-14"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("docs.get"),
                            CapabilityId::from_static("docs.batch_update"),
                        ],
                    },
                ),
                op_info(
                    "docs.batch_update",
                    "Apply batch updates to a document",
                    json!({
                        "type": "object",
                        "required": ["document_id", "requests"],
                        "properties": {
                            "document_id": { "type": "string", "minLength": 1, "maxLength": 512 },
                            "requests": { "type": "array", "minItems": 1, "maxItems": 100 },
                            "required_revision_id": { "type": "string", "minLength": 1, "maxLength": 512 },
                            "confirm_destructive": { "type": "boolean" },
                            "confirmation_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
                        },
                        "additionalProperties": false
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "status": { "type": "string" },
                            "document_id": { "type": "string" },
                            "preflight": { "type": "object" },
                            "readback": { "type": "object" }
                        }
                    }),
                    "docs.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use:
                            "Apply a bounded typed batch guarded by a current document revision. Destructive requests first return a confirmation receipt."
                                .into(),
                        common_mistakes: vec![
                            "Requests are applied in order — indices shift after inserts/deletes"
                                .into(),
                            "Apply changes in reverse index order to avoid index drift".into(),
                            "Never retry an uncertain write before reading the document again".into(),
                        ],
                        examples: vec![
                            r#"{"document_id": "abc123", "requests": [{"insertText": {"location": {"index": 1}, "text": "Hello"}}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("docs.get")],
                    },
                ),
            ],
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    pub async fn handle_invoke(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1001,
                message: "Missing 'operation' field".into(),
            })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));
        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1002,
            message: format!("Invalid operation ID: {operation}"),
        })?;
        let cap_id = docs_capability_for_operation(operation)?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotConfigured)?;
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1001,
                message: "Missing 'capability_token' field".into(),
            })?;
        let capability =
            serde_json::from_value::<CapabilityToken>(token_value.clone()).map_err(|e| {
                FcpError::InvalidRequest {
                    code: 1001,
                    message: format!("Invalid capability_token format: {e}"),
                }
            })?;
        validate_docs_input(operation, &input)?;
        let resource_uris = resource_uris_for_operation(operation, &input)?;
        verifier.verify_bound(capability, &cap_id, &op_id, &resource_uris)?;

        match operation {
            "docs.get" => {
                let document_id = require_str(&input, "document_id")?;
                let doc = client
                    .get_document(document_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let offset =
                    optional_bounded_usize(&input, "text_offset", 0, MAX_DOCUMENT_INDEX as usize)?
                        .unwrap_or(0);
                let limit = optional_bounded_usize(&input, "text_limit", 1, MAX_READ_TEXT_BYTES)?
                    .unwrap_or(MAX_READ_TEXT_BYTES);
                Ok(json!({ "document": compact_document(&doc, offset, limit) }))
            }
            "docs.create" => {
                let title = validate_title(require_str(&input, "title")?)?;
                let created = match client.create_document(title).await {
                    Ok(created) => created,
                    Err(error) if error.is_retryable() => {
                        return Ok(json!({
                            "status": "outcome_uncertain",
                            "retry_safe": false,
                            "readback": { "available": false },
                        }));
                    }
                    Err(error) => return Err(error.to_fcp_error()),
                };
                let Some(document_id) = created
                    .get("documentId")
                    .and_then(serde_json::Value::as_str)
                else {
                    return Ok(json!({
                        "status": "outcome_uncertain",
                        "retry_safe": false,
                        "readback": { "available": false },
                    }));
                };
                match client.get_document(document_id).await {
                    Ok(readback) => Ok(json!({
                        "status": "created_and_verified",
                        "document": document_receipt(&created),
                        "readback": document_receipt(&readback),
                        "retry_safe": false,
                    })),
                    Err(_) => Ok(json!({
                        "status": "created_unverified",
                        "document": document_receipt(&created),
                        "readback": { "available": false },
                        "retry_safe": false,
                    })),
                }
            }
            "docs.batch_update" => {
                let document_id = require_str(&input, "document_id")?;
                let requests = validated_requests(&input)?;
                let preflight_document = client
                    .get_document(document_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let revision_before = document_revision(&preflight_document)?.to_string();
                let destructive = requests.iter().any(Request::is_destructive);
                let impacts = requests.iter().map(request_impact).collect::<Vec<_>>();
                let expected_confirmation =
                    confirmation_sha256(document_id, &revision_before, &requests)?;

                if destructive
                    && input
                        .get("confirm_destructive")
                        .and_then(serde_json::Value::as_bool)
                        != Some(true)
                {
                    return Ok(json!({
                        "status": "confirmation_required",
                        "document_id": document_id,
                        "destructive": true,
                        "preflight": document_receipt(&preflight_document),
                        "impact": impacts,
                        "confirmation_sha256": expected_confirmation,
                        "next_call_requires": [
                            "required_revision_id",
                            "confirm_destructive=true",
                            "confirmation_sha256"
                        ],
                    }));
                }

                let Some(required_revision_id) = input
                    .get("required_revision_id")
                    .and_then(serde_json::Value::as_str)
                else {
                    return Ok(json!({
                        "status": "revision_required",
                        "document_id": document_id,
                        "destructive": destructive,
                        "preflight": document_receipt(&preflight_document),
                        "impact": impacts,
                        "required_revision_id": revision_before,
                        "confirmation_sha256": destructive.then_some(expected_confirmation),
                    }));
                };
                if required_revision_id != revision_before {
                    return Err(invalid(
                        "required_revision_id does not match the current document revision",
                    ));
                }
                if destructive {
                    let supplied_confirmation = input
                        .get("confirmation_sha256")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| {
                            invalid("confirmation_sha256 is required for destructive requests")
                        })?;
                    if supplied_confirmation != expected_confirmation {
                        return Err(invalid(
                            "confirmation_sha256 does not match the document revision and exact request batch",
                        ));
                    }
                }

                let batch_result = match client
                    .batch_update(document_id, &requests, required_revision_id)
                    .await
                {
                    Ok(result) => result,
                    Err(DocsError::Api {
                        status_code: 400, ..
                    }) => {
                        let readback = client.get_document(document_id).await.ok();
                        return Ok(json!({
                            "status": "revision_conflict_or_provider_rejected",
                            "document_id": document_id,
                            "destructive": destructive,
                            "revision_before": revision_before,
                            "readback": readback.as_ref().map_or_else(|| json!({ "available": false }), document_receipt),
                            "retry_safe": false,
                        }));
                    }
                    Err(DocsError::Json(_)) => {
                        let readback = client.get_document(document_id).await.ok();
                        return Ok(json!({
                            "status": "outcome_uncertain",
                            "document_id": document_id,
                            "destructive": destructive,
                            "revision_before": revision_before,
                            "readback": readback.as_ref().map_or_else(|| json!({ "available": false }), document_receipt),
                            "retry_safe": false,
                        }));
                    }
                    Err(error) if error.is_retryable() => {
                        let readback = client.get_document(document_id).await.ok();
                        return Ok(json!({
                            "status": "outcome_uncertain",
                            "document_id": document_id,
                            "destructive": destructive,
                            "revision_before": revision_before,
                            "readback": readback.as_ref().map_or_else(|| json!({ "available": false }), document_receipt),
                            "retry_safe": false,
                        }));
                    }
                    Err(error) => return Err(error.to_fcp_error()),
                };
                let readback_document = client.get_document(document_id).await.ok();
                Ok(json!({
                    "status": if readback_document.is_some() { "applied_and_verified" } else { "applied_unverified" },
                    "document_id": batch_result.document_id,
                    "destructive": destructive,
                    "request_count": requests.len(),
                    "request_kinds": requests.iter().map(Request::kind).collect::<Vec<_>>(),
                    "reply_count": batch_result.replies.len(),
                    "preflight": document_receipt(&preflight_document),
                    "readback": readback_document.as_ref().map_or_else(|| json!({ "available": false }), document_receipt),
                    "retry_safe": false,
                }))
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid simulate request: {e}"),
            })?;
        let operation = req.operation.as_str();
        let response = match docs_capability_for_operation(operation) {
            Ok(capability) => {
                if let Err(error) = validate_docs_input(operation, &req.input) {
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code())
                } else if self.client.is_none() {
                    SimulateResponse::denied(
                        req.id,
                        "Connector is not configured",
                        FcpError::NotConfigured.error_code(),
                    )
                } else if let Some(verifier) = &self.verifier {
                    let resource_uris = resource_uris_for_operation(operation, &req.input)?;
                    match verifier.verify_bound(
                        req.capability_token,
                        &capability,
                        &req.operation,
                        &resource_uris,
                    ) {
                        Ok(_) => SimulateResponse::allowed(req.id),
                        Err(error) => {
                            let is_grant_mismatch = matches!(
                                error,
                                FcpError::CapabilityDenied { .. }
                                    | FcpError::OperationNotGranted { .. }
                            );
                            let mut response = SimulateResponse::denied(
                                req.id,
                                error.to_string(),
                                error.error_code(),
                            );
                            if is_grant_mismatch {
                                response = response
                                    .with_missing_capabilities(vec![capability.to_string()]);
                            }
                            response
                        }
                    }
                } else {
                    SimulateResponse::denied(
                        req.id,
                        "Connector handshake not completed",
                        FcpError::NotHandshaken.error_code(),
                    )
                }
            }
            Err(error) => SimulateResponse::denied(req.id, error.to_string(), error.error_code()),
        };
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize simulate response: {e}"),
        })
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        info!("Google Docs connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for DocsConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| FcpError::InvalidRequest {
            code: 1001,
            message: format!("Missing '{field}'"),
        })
}

fn op_info(
    id: &'static str,
    summary: &str,
    input_schema: serde_json::Value,
    output_schema: serde_json::Value,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
    ai_hints: AgentHint,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(id),
        summary: summary.to_string(),
        description: None,
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints,
        rate_limit: None,
        requires_approval: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_prelude::CapabilityConstraints;
    use std::future::Future;

    fn run_async_test<F>(future: F) -> F::Output
    where
        F: Future,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    fn bearer_config(value: &str) -> serde_json::Value {
        let mut params = serde_json::Map::new();
        params.insert(["access", "token"].join("_"), json!(value));
        serde_json::Value::Object(params)
    }

    fn bearer_config_with_base_url(
        value: &str,
        base_url: impl Into<serde_json::Value>,
    ) -> serde_json::Value {
        let mut params = serde_json::Map::new();
        params.insert(["access", "token"].join("_"), json!(value));
        params.insert("base_url".to_string(), base_url.into());
        serde_json::Value::Object(params)
    }

    fn build_capability(
        signing_key: &Ed25519SigningKey,
        operation: &str,
        instance_id: &fcp_core::InstanceId,
    ) -> CapabilityToken {
        let capability = match operation {
            "docs.get" => "docs.read",
            "docs.create" | "docs.batch_update" => "docs.write",
            _ => "docs.read",
        };
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor)
            .expect("serialize token constraints");
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .audience("*")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .expect("attach token constraints")
            .target_instance(instance_id.as_str())
            .sign(signing_key)
            .expect("sign capability token");
        CapabilityToken::from_raw(cose)
    }

    fn simulate_request(
        signing_key: &Ed25519SigningKey,
        operation: &'static str,
        input: serde_json::Value,
        instance_id: &fcp_core::InstanceId,
    ) -> serde_json::Value {
        let capability = build_capability(signing_key, operation, instance_id);
        serde_json::to_value(SimulateRequest::new(
            ConnectorId::from_static("google-docs"),
            OperationId::from_static(operation),
            fcp_core::ZoneId::work(),
            input,
            capability,
        ))
        .expect("serialize simulate request")
    }

    fn parse_simulate_response(value: serde_json::Value) -> SimulateResponse {
        serde_json::from_value(value).expect("simulate response")
    }

    async fn configure_and_handshake(
        connector: &mut DocsConnector,
        signing_key: &Ed25519SigningKey,
    ) -> fcp_core::InstanceId {
        let instance_id = fcp_core::InstanceId::new();
        connector
            .handle_configure(bearer_config("test"))
            .await
            .unwrap();
        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": signing_key.verifying_key().to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["docs.read", "docs.write"],
                "requested_instance_id": instance_id
            }))
            .await
            .unwrap();
        connector.base.instance_id.clone()
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(hasher.finalize()));

        assert_eq!(DocsConnector::manifest_hash(), expected);
        assert_ne!(
            DocsConnector::manifest_hash(),
            "sha256:google-docs-connector-v1"
        );
    }

    #[test]
    fn health_unconfigured() {
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_health()).unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[test]
    fn health_configured() {
        run_async_test(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_configure(bearer_config("test-token"))
                .await
                .unwrap();
            let result = connector.handle_health().await.unwrap();
            assert_eq!(result["status"], "healthy");
        });
    }

    #[test]
    fn configure_no_auth_fails() {
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            connector.handle_configure(json!({})).await
        });
        assert!(result.is_err());
    }

    #[test]
    fn configure_rejects_invalid_base_url_override() {
        run_async_test(async {
            let mut connector = DocsConnector::new();
            let err = connector
                .handle_configure(bearer_config_with_base_url("test-token", json!(123)))
                .await
                .unwrap_err();
            assert!(
                matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("base_url")),
                "expected base_url validation error, got {err:?}"
            );

            let mut connector = DocsConnector::new();
            let err = connector
                .handle_configure(bearer_config_with_base_url("test-token", json!("")))
                .await
                .unwrap_err();
            assert!(
                matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("empty")),
                "expected empty base_url validation error, got {err:?}"
            );
        });
    }

    #[test]
    fn configure_with_bearer_auth() {
        run_async_test(async {
            let mut connector = DocsConnector::new();
            let result = connector
                .handle_configure(bearer_config("test-token"))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured");
        });
    }

    #[test]
    fn configure_with_credential_id() {
        run_async_test(async {
            let mut connector = DocsConnector::new();
            let cred_id = fcp_core::CredentialId::new();
            let result = connector
                .handle_configure(json!({ "credential_id": cred_id.to_string() }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured_pending_token_materialization");
        });
    }

    #[test]
    fn validate_docs_base_url_accepts_googleapis() {
        let out = validate_docs_base_url("https://docs.googleapis.com/v1/").unwrap();
        assert_eq!(out, "https://docs.googleapis.com/v1");
    }

    #[test]
    fn validate_docs_base_url_allows_localhost_http() {
        validate_docs_base_url("http://localhost:9999/v1").unwrap();
        validate_docs_base_url("http://127.0.0.1/docs").unwrap();
        validate_docs_base_url("http://[::1]:9999/v1").unwrap();
    }

    #[test]
    fn validate_docs_base_url_rejects_foreign_host() {
        let err = validate_docs_base_url("https://evil.example.com/v1").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("docs.googleapis.com")),
            "expected InvalidRequest mentioning googleapis.com, got {err:?}"
        );
    }

    #[test]
    fn validate_docs_base_url_rejects_substring_smuggle() {
        let err = validate_docs_base_url("https://evil.com/docs.googleapis.com/v1").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_docs_base_url_rejects_query_fragment_userinfo() {
        assert!(matches!(
            validate_docs_base_url("https://docs.googleapis.com/v1?leak=x").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_docs_base_url("https://docs.googleapis.com/v1#frag").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        let err = validate_docs_base_url("https://attacker:pw@docs.googleapis.com/v1").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("userinfo")),
            "expected InvalidRequest mentioning userinfo, got {err:?}"
        );
    }

    #[test]
    fn validate_docs_base_url_rejects_plain_http_on_public_host() {
        let err = validate_docs_base_url("http://docs.googleapis.com/v1").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_docs_base_url_rejects_empty_and_malformed() {
        assert!(matches!(
            validate_docs_base_url("   ").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_docs_base_url("not a url").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn host_is_docs_googleapis_rejects_wrong_hosts_and_lookalikes() {
        assert!(host_is_docs_googleapis("docs.googleapis.com"));
        assert!(!host_is_docs_googleapis("googleapis.com"));
        assert!(!host_is_docs_googleapis("www.googleapis.com"));
        assert!(!host_is_docs_googleapis("googleapis.com.evil.com"));
        assert!(!host_is_docs_googleapis("evil-googleapis.com"));
    }

    #[test]
    fn resource_uris_bind_docs_targets() {
        let get =
            resource_uris_for_operation("docs.get", &json!({ "document_id": "doc_123" })).unwrap();
        assert_eq!(get, vec!["google-docs:document:doc_123"]);

        let create = resource_uris_for_operation("docs.create", &json!({})).unwrap();
        assert_eq!(create, vec!["google-docs:documents"]);
    }

    #[test]
    fn introspect_has_all_operations() {
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 3);

        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(op_ids.contains(&"docs.get"));
        assert!(op_ids.contains(&"docs.create"));
        assert!(op_ids.contains(&"docs.batch_update"));
    }

    #[test]
    fn introspect_operations_have_schemas() {
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        for op in ops {
            assert!(
                op.get("input_schema").is_some(),
                "missing input_schema for {}",
                op["id"]
            );
            assert!(
                op.get("output_schema").is_some(),
                "missing output_schema for {}",
                op["id"]
            );
            assert!(
                op.get("risk_level").is_some(),
                "missing risk_level for {}",
                op["id"]
            );
            assert!(
                op.get("safety_tier").is_some(),
                "missing safety_tier for {}",
                op["id"]
            );
        }
    }

    #[test]
    fn introspect_docs_get_is_safe() {
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        let docs_get = ops.iter().find(|o| o["id"] == "docs.get").unwrap();
        assert_eq!(docs_get["safety_tier"], "safe");
        assert_eq!(docs_get["risk_level"], "low");
    }

    #[test]
    fn shutdown_succeeds() {
        run_async_test(async {
            let mut connector = DocsConnector::new();
            let result = connector.handle_shutdown(json!({})).await.unwrap();
            assert_eq!(result["status"], "shutdown");
        });
    }

    #[test]
    fn invoke_without_configure_returns_not_configured() {
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "docs.get",
                    "input": { "document_id": "abc" }
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[test]
    fn invoke_unknown_operation_is_denied_before_token_validation() {
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "docs.nonexistent",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
    }

    #[test]
    fn invoke_missing_operation_field() {
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_configure(bearer_config("test"))
                .await
                .unwrap();
            connector.handle_invoke(json!({ "input": {} })).await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn default_creates_new() {
        let connector = DocsConnector::default();
        assert!(connector.client.is_none());
    }

    #[test]
    fn simulate_denies_before_configure() {
        let signing_key = Ed25519SigningKey::generate();
        let instance_id = fcp_core::InstanceId::new();
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_simulate(simulate_request(
            &signing_key,
            "docs.get",
            json!({ "document_id": "doc_123" }),
            &instance_id,
        )))
        .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(FcpError::NotConfigured.error_code())
        );
    }

    #[test]
    fn simulate_denies_missing_required_input() {
        run_async_test(async {
            let signing_key = Ed25519SigningKey::generate();
            let mut connector = DocsConnector::new();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let result = connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "docs.get",
                    json!({}),
                    &instance_id,
                ))
                .await
                .unwrap();
            let response = parse_simulate_response(result);
            assert!(!response.would_succeed);
            assert_eq!(
                response.denial_code,
                Some(
                    FcpError::InvalidRequest {
                        code: 1001,
                        message: String::new()
                    }
                    .error_code()
                )
            );
            assert!(
                response
                    .failure_reason
                    .as_deref()
                    .is_some_and(|reason| reason.contains("document_id"))
            );
        });
    }

    #[test]
    fn simulate_allows_valid_authorized_request() {
        run_async_test(async {
            let signing_key = Ed25519SigningKey::generate();
            let mut connector = DocsConnector::new();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let result = connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "docs.get",
                    json!({ "document_id": "doc_123" }),
                    &instance_id,
                ))
                .await
                .unwrap();
            let response = parse_simulate_response(result);
            assert!(response.would_succeed);
            assert!(response.denial_code.is_none());
        });
    }

    #[test]
    fn simulate_unknown_operation_is_denied() {
        let signing_key = Ed25519SigningKey::generate();
        let instance_id = fcp_core::InstanceId::new();
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_simulate(simulate_request(
            &signing_key,
            "docs.unknown",
            json!({}),
            &instance_id,
        )))
        .unwrap();
        let response = parse_simulate_response(result);
        assert!(!response.would_succeed);
        assert_eq!(
            response.denial_code,
            Some(
                FcpError::OperationNotGranted {
                    operation: String::new()
                }
                .error_code()
            )
        );
    }

    #[test]
    fn lifecycle_configure_then_shutdown() {
        run_async_test(async {
            let mut connector = DocsConnector::new();

            // Initially not configured
            let health = connector.handle_health().await.unwrap();
            assert_eq!(health["status"], "not_configured");

            // Configure
            connector
                .handle_configure(bearer_config("test-token"))
                .await
                .unwrap();

            // Now healthy
            let health = connector.handle_health().await.unwrap();
            assert_eq!(health["status"], "healthy");

            // Shutdown
            let result = connector.handle_shutdown(json!({})).await.unwrap();
            assert_eq!(result["status"], "shutdown");

            // After shutdown, not configured again
            let health = connector.handle_health().await.unwrap();
            assert_eq!(health["status"], "not_configured");
        });
    }

    #[test]
    fn configured_connector_introspects_docs_operations() {
        run_async_test(async {
            let mut connector = DocsConnector::new();
            connector
                .handle_configure(bearer_config("test-token"))
                .await
                .unwrap();

            // Verify introspect works since we can confirm the connector is functional
            let introspect = connector.handle_introspect().await.unwrap();
            assert_eq!(introspect["operations"].as_array().unwrap().len(), 3);
        });
    }

    #[test]
    fn invoke_docs_get_missing_document_id() {
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let capability = build_capability(&signing_key, "docs.get", &instance_id);
            connector
                .handle_invoke(json!({
                    "operation": "docs.get",
                    "input": {},
                    "capability_token": capability
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_docs_create_missing_title() {
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let capability = build_capability(&signing_key, "docs.create", &instance_id);
            connector
                .handle_invoke(json!({
                    "operation": "docs.create",
                    "input": {},
                    "capability_token": capability
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_docs_batch_update_missing_requests() {
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let capability = build_capability(&signing_key, "docs.batch_update", &instance_id);
            connector
                .handle_invoke(json!({
                    "operation": "docs.batch_update",
                    "input": { "document_id": "abc" },
                    "capability_token": capability
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn invoke_docs_batch_update_missing_document_id() {
        let result = run_async_test(async {
            let mut connector = DocsConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let capability = build_capability(&signing_key, "docs.batch_update", &instance_id);
            connector
                .handle_invoke(json!({
                    "operation": "docs.batch_update",
                    "input": { "requests": [] },
                    "capability_token": capability
                }))
                .await
        });
        assert!(matches!(
            result,
            Err(FcpError::InvalidRequest { code: 1001, .. })
        ));
    }

    #[test]
    fn health_metrics_initially_zero() {
        let connector = DocsConnector::new();
        let result = run_async_test(connector.handle_health()).unwrap();
        assert_eq!(result["metrics"]["requests_total"], 0);
        assert_eq!(result["metrics"]["requests_error"], 0);
    }

    #[test]
    fn typed_request_allowlist_rejects_raw_escape_and_unknown_nested_fields() {
        let raw_escape = json!({
            "requests": [{ "deleteTab": { "tabId": "tab-1" } }]
        });
        assert!(validated_requests(&raw_escape).is_err());

        let unknown_nested = json!({
            "requests": [{
                "insertText": {
                    "location": { "index": 1, "unexpected": true },
                    "text": "hello"
                }
            }]
        });
        assert!(validated_requests(&unknown_nested).is_err());
    }

    #[test]
    fn typed_request_allowlist_classifies_and_bounds_requests() {
        let input = json!({
            "requests": [
                { "insertText": { "location": { "index": 1 }, "text": "hello" } },
                { "deleteContentRange": { "range": { "startIndex": 2, "endIndex": 5 } } }
            ]
        });
        let requests = validated_requests(&input).unwrap();
        assert_eq!(requests.len(), 2);
        assert!(!requests[0].is_destructive());
        assert!(requests[1].is_destructive());

        let too_many = json!({
            "requests": (0..=MAX_REQUESTS)
                .map(|_| json!({ "insertText": { "location": { "index": 1 }, "text": "x" } }))
                .collect::<Vec<_>>()
        });
        assert!(validated_requests(&too_many).is_err());
    }

    #[test]
    fn destructive_confirmation_is_bound_to_revision_and_exact_payload() {
        let first = validated_requests(&json!({
            "requests": [{
                "replaceAllText": {
                    "containsText": { "text": "old", "matchCase": true },
                    "replaceText": "new"
                }
            }]
        }))
        .unwrap();
        let second = validated_requests(&json!({
            "requests": [{
                "replaceAllText": {
                    "containsText": { "text": "old", "matchCase": true },
                    "replaceText": "different"
                }
            }]
        }))
        .unwrap();
        let hash = confirmation_sha256("doc", "rev-1", &first).unwrap();
        assert_ne!(hash, confirmation_sha256("doc", "rev-2", &first).unwrap());
        assert_ne!(hash, confirmation_sha256("doc", "rev-1", &second).unwrap());
    }

    #[test]
    fn compact_document_pages_utf8_without_splitting_codepoints() {
        let document = json!({
            "documentId": "doc",
            "title": "test",
            "revisionId": "rev",
            "body": { "content": [{ "paragraph": { "elements": [
                { "textRun": { "content": "a😀b" } }
            ] } }] }
        });
        let compact = compact_document(&document, 1, 4);
        assert_eq!(compact["text"], "😀");
        assert_eq!(compact["text_next_offset"], 5);
        assert_eq!(compact["text_complete"], false);
    }

    #[test]
    fn compact_document_result_stays_below_manifest_budget() {
        let document = json!({
            "documentId": "doc",
            "title": "bounded",
            "revisionId": "rev",
            "body": { "content": [{ "paragraph": { "elements": [
                { "textRun": { "content": "x".repeat(200_000) } }
            ] } }] }
        });
        let compact = compact_document(&document, 0, MAX_READ_TEXT_BYTES);
        assert!(serde_json::to_vec(&compact).unwrap().len() < 60_000);
        assert_eq!(compact["text_complete"], false);
    }

    #[test]
    fn operation_input_rejects_unknown_top_level_fields() {
        let error = validate_docs_input(
            "docs.get",
            &json!({ "document_id": "doc", "provider_escape": {} }),
        )
        .unwrap_err();
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
}
