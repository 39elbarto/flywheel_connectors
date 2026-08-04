//! FCP Google Forms connector.

use std::sync::Arc;

use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use fcp_prelude::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SimulateRequest, SimulateResponse,
};
use reqwest::Url;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::FormsClient;
use crate::error::FormsError;
use crate::types::{PublishSettings, PublishState, Request};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_REQUESTS: usize = 100;
const MAX_BATCH_BYTES: usize = 512 * 1024;
const MAX_ITEMS_PER_READ: usize = 100;
const MAX_RESPONSES_PER_PAGE: u32 = 100;
const MAX_CALLER_PAYLOAD_BYTES: usize = 60_000;

fn invalid(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1001,
        message: message.into(),
    }
}

fn require_str<'a>(value: &'a Value, field: &str) -> FcpResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("missing or invalid '{field}'")))
}

fn validate_identifier<'a>(value: &'a str, field: &str) -> FcpResult<&'a str> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.contains(['/', '\\', '?', '#', '%'])
        || value.contains("..")
    {
        return Err(invalid(format!(
            "'{field}' must be a safe 1..={MAX_IDENTIFIER_BYTES} byte identifier"
        )));
    }
    Ok(value)
}

fn validate_opaque_token<'a>(value: &'a str, field: &str) -> FcpResult<&'a str> {
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "'{field}' must be a non-empty opaque token of at most 2048 bytes"
        )));
    }
    Ok(value)
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

fn validate_object_fields(value: &Value, allowed: &[&str], context: &str) -> FcpResult<()> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(format!("{context} must be an object")))?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(format!("unsupported {context} field '{field}'")));
    }
    Ok(())
}

fn validate_field_mask(mask: &str, allowed: &[&str], context: &str) -> FcpResult<()> {
    if mask.is_empty() || mask == "*" {
        return Err(invalid(format!("{context} field mask must be explicit")));
    }
    for field in mask.split(',').map(str::trim) {
        if !allowed.contains(&field) {
            return Err(invalid(format!(
                "unsupported {context} field mask path '{field}'"
            )));
        }
    }
    Ok(())
}

fn validate_https_media_uri(uri: &str) -> FcpResult<()> {
    let url = Url::parse(uri).map_err(|_| invalid("media sourceUri must be an absolute URL"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "media sourceUri must use HTTPS without userinfo or a fragment",
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| invalid("media sourceUri must include a host"))?;
    let host_lower = host.to_ascii_lowercase();
    let host_labels = host_lower.split('.').collect::<Vec<_>>();
    let private_suffix = host_labels
        .last()
        .is_some_and(|label| matches!(*label, "local" | "internal"))
        || host_labels
            .windows(2)
            .last()
            .is_some_and(|labels| labels == ["ts", "net"]);
    let blocked_name = matches!(
        host_lower.as_str(),
        "localhost" | "metadata.google.internal"
    ) || private_suffix;
    if blocked_name || host.parse::<std::net::IpAddr>().is_ok() {
        return Err(invalid(
            "media sourceUri may not target local, private-name, tailnet, or literal-IP hosts",
        ));
    }
    Ok(())
}

fn validate_grading(value: &Value) -> FcpResult<()> {
    validate_object_fields(
        value,
        &[
            "pointValue",
            "correctAnswers",
            "whenRight",
            "whenWrong",
            "generalFeedback",
        ],
        "grading",
    )?;
    let points = value
        .get("pointValue")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("grading.pointValue must be a non-negative integer"))?;
    if points > 10_000 {
        return Err(invalid("grading.pointValue must be <= 10000"));
    }
    if let Some(correct) = value.get("correctAnswers") {
        validate_object_fields(correct, &["answers"], "correctAnswers")?;
        let answers = correct
            .get("answers")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("correctAnswers.answers must be an array"))?;
        if answers.is_empty() || answers.len() > 100 {
            return Err(invalid(
                "correctAnswers.answers must contain 1..=100 values",
            ));
        }
        for answer in answers {
            validate_object_fields(answer, &["value"], "correctAnswer")?;
            let value = answer
                .get("value")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("correctAnswer.value must be a string"))?;
            if value.len() > 10_000 {
                return Err(invalid("correctAnswer.value is too large"));
            }
        }
    }
    Ok(())
}

fn validate_question(value: &Value, allow_row: bool) -> FcpResult<()> {
    validate_object_fields(
        value,
        &[
            "questionId",
            "required",
            "grading",
            "choiceQuestion",
            "textQuestion",
            "scaleQuestion",
            "dateQuestion",
            "timeQuestion",
            "rowQuestion",
            "ratingQuestion",
            "fileUploadQuestion",
        ],
        "question",
    )?;
    let kinds = [
        "choiceQuestion",
        "textQuestion",
        "scaleQuestion",
        "dateQuestion",
        "timeQuestion",
        "rowQuestion",
        "ratingQuestion",
        "fileUploadQuestion",
    ];
    let present = kinds
        .iter()
        .filter(|kind| value.get(**kind).is_some())
        .copied()
        .collect::<Vec<_>>();
    if present.len() != 1 {
        return Err(invalid("question must contain exactly one supported kind"));
    }
    if present[0] == "fileUploadQuestion" {
        return Err(invalid(
            "Forms API does not support creating or rewriting file-upload questions",
        ));
    }
    if present[0] == "rowQuestion" && !allow_row {
        return Err(invalid(
            "rowQuestion is valid only inside questionGroupItem",
        ));
    }
    if let Some(grading) = value.get("grading") {
        validate_grading(grading)?;
    }
    match present[0] {
        "choiceQuestion" => {
            let question = &value["choiceQuestion"];
            validate_object_fields(question, &["type", "options", "shuffle"], "choiceQuestion")?;
            let kind = question
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("choiceQuestion.type is required"))?;
            if !matches!(kind, "RADIO" | "CHECKBOX" | "DROP_DOWN") {
                return Err(invalid("unsupported choiceQuestion.type"));
            }
            let options = question
                .get("options")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("choiceQuestion.options must be an array"))?;
            if options.is_empty() || options.len() > 200 {
                return Err(invalid(
                    "choiceQuestion.options must contain 1..=200 entries",
                ));
            }
            for option in options {
                validate_object_fields(
                    option,
                    &["value", "image", "isOther", "goToAction", "goToSectionId"],
                    "choice option",
                )?;
                if let Some(image) = option.get("image") {
                    validate_image(image)?;
                }
            }
        }
        "textQuestion" => {
            validate_object_fields(&value["textQuestion"], &["paragraph"], "textQuestion")?;
        }
        "scaleQuestion" => validate_object_fields(
            &value["scaleQuestion"],
            &["low", "high", "lowLabel", "highLabel"],
            "scaleQuestion",
        )?,
        "dateQuestion" => validate_object_fields(
            &value["dateQuestion"],
            &["includeTime", "includeYear"],
            "dateQuestion",
        )?,
        "timeQuestion" => {
            validate_object_fields(&value["timeQuestion"], &["duration"], "timeQuestion")?;
        }
        "rowQuestion" => {
            validate_object_fields(&value["rowQuestion"], &["title"], "rowQuestion")?;
        }
        "ratingQuestion" => validate_object_fields(
            &value["ratingQuestion"],
            &["ratingScaleLevel", "iconType"],
            "ratingQuestion",
        )?,
        _ => unreachable!(),
    }
    Ok(())
}

fn validate_image(value: &Value) -> FcpResult<()> {
    validate_object_fields(value, &["sourceUri", "altText", "properties"], "image")?;
    let uri = value
        .get("sourceUri")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("image.sourceUri is required for writes"))?;
    validate_https_media_uri(uri)?;
    if let Some(properties) = value.get("properties") {
        validate_object_fields(properties, &["alignment", "width"], "media properties")?;
    }
    Ok(())
}

fn validate_item(value: &Value) -> FcpResult<()> {
    validate_object_fields(
        value,
        &[
            "itemId",
            "title",
            "description",
            "questionItem",
            "questionGroupItem",
            "pageBreakItem",
            "textItem",
            "imageItem",
            "videoItem",
        ],
        "item",
    )?;
    let kinds = [
        "questionItem",
        "questionGroupItem",
        "pageBreakItem",
        "textItem",
        "imageItem",
        "videoItem",
    ];
    let present = kinds
        .iter()
        .filter(|kind| value.get(**kind).is_some())
        .copied()
        .collect::<Vec<_>>();
    if present.len() != 1 {
        return Err(invalid("item must contain exactly one supported kind"));
    }
    match present[0] {
        "questionItem" => {
            let item = &value["questionItem"];
            validate_object_fields(item, &["question", "image"], "questionItem")?;
            validate_question(
                item.get("question")
                    .ok_or_else(|| invalid("questionItem.question is required"))?,
                false,
            )?;
            if let Some(image) = item.get("image") {
                validate_image(image)?;
            }
        }
        "questionGroupItem" => {
            let group = &value["questionGroupItem"];
            validate_object_fields(group, &["questions", "grid", "image"], "questionGroupItem")?;
            let questions = group
                .get("questions")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("questionGroupItem.questions must be an array"))?;
            if questions.is_empty() || questions.len() > 100 {
                return Err(invalid(
                    "questionGroupItem.questions must contain 1..=100 rows",
                ));
            }
            for question in questions {
                validate_question(question, true)?;
            }
            let grid = group
                .get("grid")
                .ok_or_else(|| invalid("questionGroupItem.grid is required"))?;
            validate_object_fields(grid, &["columns", "shuffleQuestions"], "grid")?;
            let columns = grid
                .get("columns")
                .and_then(Value::as_object)
                .ok_or_else(|| invalid("grid.columns must be a choiceQuestion object"))?;
            validate_object_fields(
                &Value::Object(columns.clone()),
                &["type", "options", "shuffle"],
                "grid.columns",
            )?;
        }
        "imageItem" => validate_image(
            value["imageItem"]
                .get("image")
                .ok_or_else(|| invalid("imageItem.image is required"))?,
        )?,
        "videoItem" => {
            let video_item = &value["videoItem"];
            validate_object_fields(video_item, &["video", "caption"], "videoItem")?;
            let video = video_item
                .get("video")
                .ok_or_else(|| invalid("videoItem.video is required"))?;
            validate_object_fields(video, &["youtubeUri", "properties"], "video")?;
            validate_https_media_uri(
                video
                    .get("youtubeUri")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("video.youtubeUri is required"))?,
            )?;
        }
        "pageBreakItem" | "textItem" => {
            validate_object_fields(&value[present[0]], &[], present[0])?;
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn validated_requests(input: &Value) -> FcpResult<Vec<Request>> {
    let raw = input
        .get("requests")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("'requests' must be an array"))?;
    if raw.is_empty() || raw.len() > MAX_REQUESTS {
        return Err(invalid("requests must contain 1..=100 entries"));
    }
    let encoded = serde_json::to_vec(raw)
        .map_err(|error| invalid(format!("could not encode requests: {error}")))?;
    if encoded.len() > MAX_BATCH_BYTES {
        return Err(invalid("serialized request batch exceeds 512 KiB"));
    }
    let requests = raw
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<Result<Vec<Request>, _>>()
        .map_err(|error| invalid(format!("unsupported Forms request: {error}")))?;
    for request in &requests {
        match request {
            Request::UpdateFormInfo(request) => {
                validate_field_mask(&request.update_mask, &["title", "description"], "form info")?;
            }
            Request::UpdateSettings(request) => {
                validate_field_mask(
                    &request.update_mask,
                    &["quizSettings.isQuiz", "emailCollectionType"],
                    "settings",
                )?;
                if let Some(value) = &request.settings.email_collection_type {
                    if !matches!(
                        value.as_str(),
                        "DO_NOT_COLLECT" | "VERIFIED" | "RESPONDER_INPUT"
                    ) {
                        return Err(invalid("unsupported emailCollectionType"));
                    }
                }
            }
            Request::CreateItem(request) => validate_item(&request.item)?,
            Request::UpdateItem(request) => {
                validate_item(&request.item)?;
                validate_field_mask(
                    &request.update_mask,
                    &[
                        "title",
                        "description",
                        "questionItem",
                        "questionItem.question",
                        "questionItem.question.required",
                        "questionItem.question.grading",
                        "questionGroupItem",
                        "questionGroupItem.questions",
                        "questionGroupItem.questions.grading",
                        "imageItem",
                        "videoItem",
                    ],
                    "item",
                )?;
            }
            Request::MoveItem(_) | Request::DeleteItem(_) => {}
        }
    }
    Ok(requests)
}

fn form_revision(form: &Value) -> FcpResult<&str> {
    form.get("revisionId")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Forms response did not include revisionId"))
}

fn form_receipt(form: &Value) -> Value {
    json!({
        "form_id": form.get("formId").and_then(Value::as_str),
        "revision_id": form.get("revisionId").and_then(Value::as_str),
        "title": form.pointer("/info/title").and_then(Value::as_str),
        "item_count": form.get("items").and_then(Value::as_array).map_or(0, Vec::len),
        "responder_uri_present": form.get("responderUri").is_some(),
        "linked_sheet_id_present": form.get("linkedSheetId").is_some(),
        "publish_settings": form.get("publishSettings"),
    })
}

fn compact_form(form: &Value, offset: usize, limit: usize) -> Value {
    let items = form
        .get("items")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let end = offset.saturating_add(limit).min(items.len());
    let page = if offset < items.len() {
        items[offset..end].to_vec()
    } else {
        Vec::new()
    };
    json!({
        "metadata": form_receipt(form),
        "info": form.get("info"),
        "settings": form.get("settings"),
        "publish_settings": form.get("publishSettings"),
        "items": page,
        "item_offset": offset,
        "item_next_offset": end,
        "items_complete": end >= items.len(),
    })
}

fn hash_serializable(value: &impl serde::Serialize) -> String {
    let encoded = serde_json::to_vec(value).unwrap_or_default();
    hex::encode(Sha256::digest(encoded))
}

fn batch_confirmation(form_id: &str, revision: &str, requests: &[Request]) -> String {
    hash_serializable(&(form_id, revision, requests))
}

fn publish_confirmation(
    form_id: &str,
    revision: &str,
    current: &Value,
    desired: &PublishSettings,
) -> String {
    hash_serializable(&(form_id, revision, current, desired))
}

fn cursor_binding(form_id: &str, filter: Option<&str>, page_token: &str) -> String {
    hash_serializable(&(form_id, filter.unwrap_or(""), page_token))
}

fn validate_timestamp_filter(filter: &str) -> FcpResult<()> {
    let timestamp = filter
        .strip_prefix("timestamp >= ")
        .or_else(|| filter.strip_prefix("timestamp > "))
        .ok_or_else(|| {
            invalid("filter must be 'timestamp > RFC3339Z' or 'timestamp >= RFC3339Z'")
        })?;
    if !timestamp.ends_with('Z')
        || chrono::DateTime::parse_from_rfc3339(timestamp).is_err()
        || timestamp.len() > 64
    {
        return Err(invalid(
            "response timestamp filter must use RFC3339 UTC Z format",
        ));
    }
    Ok(())
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn validate_forms_base_url(raw: &str) -> FcpResult<String> {
    let parsed = Url::parse(raw.trim())
        .map_err(|error| invalid(format!("base_url could not be parsed: {error}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid("base_url must include a host"))?;
    let local = is_local_test_host(host);
    if !matches!(parsed.scheme(), "https" | "http")
        || (parsed.scheme() == "http" && !local)
        || (!local && !host.eq_ignore_ascii_case("forms.googleapis.com"))
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid(
            "base_url must target https://forms.googleapis.com (loopback HTTP allowed for tests)",
        ));
    }
    Ok(raw.trim().trim_end_matches('/').to_string())
}

fn capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        "forms.get" => Ok(CapabilityId::from_static("forms.read")),
        "forms.create" | "forms.batch_update" => {
            Ok(CapabilityId::from_static("form.structure.write"))
        }
        "forms.responses.get" | "forms.responses.list" => {
            Ok(CapabilityId::from_static("forms.responses.read"))
        }
        "forms.set_publish_settings" => Ok(CapabilityId::from_static("form.publish.write")),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn resource_uris(operation: &str, input: &Value) -> FcpResult<Vec<String>> {
    match operation {
        "forms.create" => Ok(vec!["google-forms:forms".into()]),
        "forms.get" | "forms.batch_update" | "forms.set_publish_settings" => {
            let form_id = require_str(input, "form_id")?;
            Ok(vec![format!("google-forms:form:{form_id}")])
        }
        "forms.responses.get" => {
            let form_id = require_str(input, "form_id")?;
            let response_id = require_str(input, "response_id")?;
            Ok(vec![
                format!("google-forms:form:{form_id}"),
                format!("google-forms:response:{form_id}:{response_id}"),
            ])
        }
        "forms.responses.list" => {
            let form_id = require_str(input, "form_id")?;
            Ok(vec![format!("google-forms:responses:{form_id}")])
        }
        _ => Ok(Vec::new()),
    }
}

fn validate_input(operation: &str, input: &Value) -> FcpResult<()> {
    let allowed: &[&str] = match operation {
        "forms.get" => &["form_id", "item_offset", "item_limit"],
        "forms.create" => &["title"],
        "forms.batch_update" => &[
            "form_id",
            "requests",
            "required_revision_id",
            "confirm_destructive",
            "confirmation_sha256",
        ],
        "forms.responses.get" => &["form_id", "response_id"],
        "forms.responses.list" => &[
            "form_id",
            "filter",
            "page_size",
            "page_token",
            "cursor_binding_sha256",
        ],
        "forms.set_publish_settings" => &[
            "form_id",
            "is_published",
            "is_accepting_responses",
            "required_revision_id",
            "required_state_sha256",
            "confirm",
            "confirmation_sha256",
        ],
        _ => {
            return Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            });
        }
    };
    validate_object_fields(input, allowed, "operation input")?;
    match operation {
        "forms.create" => {
            validate_title(require_str(input, "title")?)?;
        }
        _ => {
            validate_identifier(require_str(input, "form_id")?, "form_id")?;
        }
    }
    match operation {
        "forms.get" => {
            if input
                .get("item_offset")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                > 1_000_000
            {
                return Err(invalid("item_offset must be <= 1000000"));
            }
            if input
                .get("item_limit")
                .and_then(Value::as_u64)
                .unwrap_or(50)
                > MAX_ITEMS_PER_READ as u64
            {
                return Err(invalid("item_limit must be <= 100"));
            }
        }
        "forms.batch_update" => {
            validated_requests(input)?;
        }
        "forms.responses.get" => {
            validate_identifier(require_str(input, "response_id")?, "response_id")?;
        }
        "forms.responses.list" => {
            if let Some(filter) = input.get("filter").and_then(Value::as_str) {
                validate_timestamp_filter(filter)?;
            } else if input.get("filter").is_some() {
                return Err(invalid("filter must be a string"));
            }
            let page_size = input.get("page_size").and_then(Value::as_u64).unwrap_or(50);
            if page_size == 0 || page_size > u64::from(MAX_RESPONSES_PER_PAGE) {
                return Err(invalid("page_size must be 1..=100"));
            }
            if let Some(token) = input.get("page_token").and_then(Value::as_str) {
                validate_opaque_token(token, "page_token")?;
                let supplied = require_str(input, "cursor_binding_sha256")?;
                if supplied
                    != cursor_binding(
                        require_str(input, "form_id")?,
                        input.get("filter").and_then(Value::as_str),
                        token,
                    )
                {
                    return Err(invalid(
                        "cursor binding does not match form, filter, and page token",
                    ));
                }
            }
        }
        "forms.set_publish_settings" => {
            for field in ["is_published", "is_accepting_responses"] {
                if input.get(field).and_then(Value::as_bool).is_none() {
                    return Err(invalid(format!("'{field}' must be a boolean")));
                }
            }
        }
        "forms.create" => {}
        _ => {}
    }
    Ok(())
}

/// FCP Google Forms connector.
pub struct FormsConnector {
    base: Arc<BaseConnector>,
    client: Option<FormsClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
}

impl FormsConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("google-forms"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    #[must_use]
    fn manifest_hash() -> String {
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(MANIFEST_TOML.as_bytes()))
        )
    }

    pub async fn handle_configure(&mut self, params: Value) -> FcpResult<Value> {
        let auth_params = params
            .get("auth")
            .cloned()
            .unwrap_or_else(|| params.clone());
        let selection = GoogleAuthSelection::from_connector_config(&auth_params)
            .map_err(|error| invalid(format!("invalid Google auth config: {error}")))?;
        let materialized = selection
            .materialize()
            .await
            .map_err(|error| invalid(format!("failed to materialize Google auth: {error}")))?;
        let status = if matches!(
            materialized,
            GoogleMaterializedAuth::CredentialReference { .. }
        ) {
            "configured_pending_token_materialization"
        } else {
            "configured"
        };
        let mut client =
            FormsClient::new_with_auth(materialized).map_err(|error| FcpError::Internal {
                message: format!("failed to create Forms client: {error}"),
            })?;
        if let Some(value) = params.get("base_url") {
            client = client.with_base_url(validate_forms_base_url(
                value
                    .as_str()
                    .ok_or_else(|| invalid("base_url must be a string"))?,
            )?);
        }
        info!(auth = %client.auth_redacted_label(), status, "Google Forms connector configured");
        self.client = Some(client);
        self.base.set_configured(true);
        Ok(json!({"status": status}))
    }

    pub async fn handle_handshake(&mut self, params: Value) -> FcpResult<Value> {
        let request: HandshakeRequest = serde_json::from_value(params)
            .map_err(|error| invalid(format!("invalid handshake request: {error}")))?;
        if let Some(instance_id) = request.requested_instance_id {
            Arc::get_mut(&mut self.base)
                .ok_or_else(|| FcpError::Internal {
                    message: "cannot assign requested instance ID after sharing state".into(),
                })?
                .instance_id = instance_id;
        }
        self.verifier = Some(CapabilityVerifier::new(
            request.host_public_key,
            request.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let session_id = fcp_core::SessionId::new();
        self.session_id = Some(session_id.clone());
        self.base.set_handshaken(true);
        let response = HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: request
                .capabilities_requested
                .into_iter()
                .map(|capability| CapabilityGrant {
                    capability,
                    operation: None,
                })
                .collect(),
            session_id,
            manifest_hash: Self::manifest_hash(),
            nonce: request.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 100,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        };
        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: error.to_string(),
        })
    }

    pub async fn handle_health(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.client.is_some() { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": self.base.metrics().requests_total,
                "requests_error": self.base.metrics().requests_error,
            }
        }))
    }

    pub async fn handle_doctor(&self) -> FcpResult<Value> {
        let configured = self.client.is_some();
        Ok(json!({
            "status": if configured { "healthy" } else { "unhealthy" },
            "checks": [{
                "name": "configuration",
                "passed": configured,
                "critical": true,
                "message": if configured { "Connector is configured" } else { "Not configured" }
            }]
        }))
    }

    pub async fn handle_self_check(&self) -> FcpResult<Value> {
        Ok(json!({
            "status": if self.client.is_some() { "pass" } else { "fail" },
            "check": "configured"
        }))
    }

    pub async fn handle_introspect(&self) -> FcpResult<Value> {
        let operations = vec![
            op_info(
                "forms.get",
                "Read a bounded form structure",
                "forms.read",
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
            ),
            op_info(
                "forms.create",
                "Create a new form",
                "form.structure.write",
                RiskLevel::Medium,
                SafetyTier::Risky,
                IdempotencyClass::None,
            ),
            op_info(
                "forms.batch_update",
                "Apply a typed revision-guarded form batch",
                "form.structure.write",
                RiskLevel::High,
                SafetyTier::Dangerous,
                IdempotencyClass::None,
            ),
            op_info(
                "forms.responses.get",
                "Read one form response",
                "forms.responses.read",
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
            ),
            op_info(
                "forms.responses.list",
                "List a bounded response page",
                "forms.responses.read",
                RiskLevel::Low,
                SafetyTier::Safe,
                IdempotencyClass::Strict,
            ),
            op_info(
                "forms.set_publish_settings",
                "Publish/unpublish and accept/stop responses",
                "form.publish.write",
                RiskLevel::High,
                SafetyTier::Dangerous,
                IdempotencyClass::None,
            ),
        ];
        serde_json::to_value(Introspection {
            operations,
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        })
        .map_err(|error| FcpError::Internal {
            message: error.to_string(),
        })
    }

    pub async fn handle_invoke(&mut self, params: Value) -> FcpResult<Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(&self, params: Value) -> FcpResult<Value> {
        let operation = require_str(&params, "operation")?;
        let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
        let operation_id: OperationId = operation
            .parse()
            .map_err(|_| invalid(format!("invalid operation ID: {operation}")))?;
        let capability_id = capability_for_operation(operation)?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotConfigured)?;
        let token: CapabilityToken = serde_json::from_value(
            params
                .get("capability_token")
                .cloned()
                .ok_or_else(|| invalid("missing capability_token"))?,
        )
        .map_err(|error| invalid(format!("invalid capability_token: {error}")))?;
        validate_input(operation, &input)?;
        verifier.verify_bound(
            token,
            &capability_id,
            &operation_id,
            &resource_uris(operation, &input)?,
        )?;

        match operation {
            "forms.get" => {
                let form = client
                    .get_form(require_str(&input, "form_id")?)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let offset = input
                    .get("item_offset")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                let limit = input
                    .get("item_limit")
                    .and_then(Value::as_u64)
                    .unwrap_or(50) as usize;
                Ok(json!({"form": compact_form(&form, offset, limit)}))
            }
            "forms.create" => {
                let created = match client
                    .create_form(validate_title(require_str(&input, "title")?)?)
                    .await
                {
                    Ok(value) => value,
                    Err(error) if error.is_retryable() => {
                        return Ok(json!({
                            "status": "outcome_uncertain", "retry_safe": false
                        }));
                    }
                    Err(error) => return Err(error.to_fcp_error()),
                };
                let Some(form_id) = created.get("formId").and_then(Value::as_str) else {
                    return Ok(json!({"status": "outcome_uncertain", "retry_safe": false}));
                };
                let readback = client.get_form(form_id).await.ok();
                Ok(json!({
                    "status": if readback.is_some() { "created_and_verified" } else { "created_unverified" },
                    "form": form_receipt(&created),
                    "readback": readback.as_ref().map_or_else(|| json!({"available": false}), form_receipt),
                    "retry_safe": false,
                }))
            }
            "forms.batch_update" => {
                let form_id = require_str(&input, "form_id")?;
                let requests = validated_requests(&input)?;
                let before = client
                    .get_form(form_id)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let revision = form_revision(&before)?;
                let destructive = requests.iter().any(Request::is_destructive);
                let confirmation = batch_confirmation(form_id, revision, &requests);
                let request_kinds = requests.iter().map(Request::kind).collect::<Vec<_>>();
                if destructive
                    && input.get("confirm_destructive").and_then(Value::as_bool) != Some(true)
                {
                    return Ok(json!({
                        "status": "confirmation_required",
                        "destructive": true,
                        "preflight": form_receipt(&before),
                        "request_kinds": request_kinds,
                        "confirmation_sha256": confirmation,
                    }));
                }
                let required_revision =
                    input
                        .get("required_revision_id")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid("required_revision_id is required"))?;
                if required_revision != revision {
                    return Err(invalid(
                        "required_revision_id does not match current form revision",
                    ));
                }
                if destructive
                    && input.get("confirmation_sha256").and_then(Value::as_str)
                        != Some(confirmation.as_str())
                {
                    return Err(invalid(
                        "confirmation_sha256 does not bind the exact current batch",
                    ));
                }
                let result = match client.batch_update(form_id, &requests, revision).await {
                    Ok(value) => value,
                    Err(FormsError::Api {
                        status_code: 400, ..
                    }) => {
                        return Ok(json!({
                            "status": "revision_conflict_or_provider_rejected", "retry_safe": false
                        }));
                    }
                    Err(error) if error.is_retryable() => {
                        return Ok(json!({
                            "status": "outcome_uncertain", "retry_safe": false
                        }));
                    }
                    Err(error) => return Err(error.to_fcp_error()),
                };
                let readback = client.get_form(form_id).await.ok();
                Ok(json!({
                    "status": if readback.is_some() { "applied_and_verified" } else { "applied_unverified" },
                    "destructive": destructive,
                    "request_count": requests.len(),
                    "request_kinds": request_kinds,
                    "reply_count": result.replies.len(),
                    "preflight": form_receipt(&before),
                    "readback": readback.as_ref().map_or_else(|| json!({"available": false}), form_receipt),
                    "retry_safe": false,
                }))
            }
            "forms.responses.get" => {
                let response = client
                    .get_response(
                        require_str(&input, "form_id")?,
                        require_str(&input, "response_id")?,
                    )
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                if serde_json::to_vec(&response).map_or(usize::MAX, |bytes| bytes.len())
                    > MAX_CALLER_PAYLOAD_BYTES
                {
                    return Err(invalid("response exceeds the FCP payload budget"));
                }
                Ok(json!({"response": response}))
            }
            "forms.responses.list" => {
                let form_id = require_str(&input, "form_id")?;
                let filter = input.get("filter").and_then(Value::as_str);
                let page_size = input.get("page_size").and_then(Value::as_u64).unwrap_or(50) as u32;
                let page_token = input.get("page_token").and_then(Value::as_str);
                let mut page = client
                    .list_responses(form_id, filter, page_size, page_token)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                if serde_json::to_vec(&page).map_or(usize::MAX, |bytes| bytes.len())
                    > MAX_CALLER_PAYLOAD_BYTES
                {
                    return Err(invalid(
                        "response page exceeds the FCP payload budget; retry with a smaller page_size",
                    ));
                }
                let next_token = page
                    .get("nextPageToken")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if let Some(object) = page.as_object_mut() {
                    object.remove("nextPageToken");
                }
                Ok(json!({
                    "responses": page.get("responses").cloned().unwrap_or_else(|| json!([])),
                    "next_cursor": next_token.as_deref().map(|token| json!({
                        "page_token": token,
                        "cursor_binding_sha256": cursor_binding(form_id, filter, token)
                    })),
                }))
            }
            "forms.set_publish_settings" => {
                let form_id = require_str(&input, "form_id")?;
                let desired = PublishSettings {
                    publish_state: PublishState {
                        is_published: input["is_published"].as_bool().unwrap_or(false),
                        is_accepting_responses: input["is_accepting_responses"]
                            .as_bool()
                            .unwrap_or(false),
                    },
                };
                let before = client
                    .get_form(form_id)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let revision = form_revision(&before)?;
                let current = before
                    .get("publishSettings")
                    .cloned()
                    .unwrap_or(Value::Null);
                if current.is_null() {
                    return Err(invalid("legacy form does not support publishSettings"));
                }
                let state_hash = hash_serializable(&current);
                let confirmation = publish_confirmation(form_id, revision, &current, &desired);
                let confirmed = input.get("confirm").and_then(Value::as_bool) == Some(true)
                    && input.get("required_revision_id").and_then(Value::as_str) == Some(revision)
                    && input.get("required_state_sha256").and_then(Value::as_str)
                        == Some(state_hash.as_str())
                    && input.get("confirmation_sha256").and_then(Value::as_str)
                        == Some(confirmation.as_str());
                if !confirmed {
                    return Ok(json!({
                        "status": "confirmation_required",
                        "preflight": form_receipt(&before),
                        "desired_publish_state": desired.publish_state,
                        "required_revision_id": revision,
                        "required_state_sha256": state_hash,
                        "confirmation_sha256": confirmation,
                    }));
                }
                let result = match client.set_publish_settings(form_id, &desired).await {
                    Ok(value) => value,
                    Err(error) if error.is_retryable() => {
                        return Ok(json!({
                            "status": "outcome_uncertain", "retry_safe": false
                        }));
                    }
                    Err(error) => return Err(error.to_fcp_error()),
                };
                let readback = client.get_form(form_id).await.ok();
                Ok(json!({
                    "status": if readback.is_some() { "applied_and_verified" } else { "applied_unverified" },
                    "publish_settings": result.get("publishSettings"),
                    "readback": readback.as_ref().map_or_else(|| json!({"available": false}), form_receipt),
                    "retry_safe": false,
                }))
            }
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    pub async fn handle_simulate(&self, params: Value) -> FcpResult<Value> {
        let request: SimulateRequest = serde_json::from_value(params)
            .map_err(|error| invalid(format!("invalid simulate request: {error}")))?;
        let operation = request.operation.as_str();
        let response = match capability_for_operation(operation) {
            Ok(capability) => {
                if let Err(error) = validate_input(operation, &request.input) {
                    SimulateResponse::denied(request.id, error.to_string(), error.error_code())
                } else if self.client.is_none() {
                    SimulateResponse::denied(
                        request.id,
                        "Connector is not configured",
                        FcpError::NotConfigured.error_code(),
                    )
                } else if let Some(verifier) = &self.verifier {
                    match verifier.verify_bound(
                        request.capability_token,
                        &capability,
                        &request.operation,
                        &resource_uris(operation, &request.input)?,
                    ) {
                        Ok(_) => SimulateResponse::allowed(request.id),
                        Err(error) => {
                            let grant_mismatch = matches!(
                                error,
                                FcpError::CapabilityDenied { .. }
                                    | FcpError::OperationNotGranted { .. }
                            );
                            let response = SimulateResponse::denied(
                                request.id,
                                error.to_string(),
                                error.error_code(),
                            );
                            if grant_mismatch {
                                response.with_missing_capabilities(vec![capability.to_string()])
                            } else {
                                response
                            }
                        }
                    }
                } else {
                    SimulateResponse::denied(
                        request.id,
                        "Connector handshake not completed",
                        FcpError::NotHandshaken.error_code(),
                    )
                }
            }
            Err(error) => {
                SimulateResponse::denied(request.id, error.to_string(), error.error_code())
            }
        };
        serde_json::to_value(response).map_err(|error| FcpError::Internal {
            message: error.to_string(),
        })
    }

    pub async fn handle_shutdown(&mut self, _params: Value) -> FcpResult<Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        self.verifier = None;
        self.session_id = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(json!({"status": "shutdown"}))
    }
}

impl Default for FormsConnector {
    fn default() -> Self {
        Self::new()
    }
}

fn op_info(
    operation: &'static str,
    description: &str,
    capability: &'static str,
    risk_level: RiskLevel,
    safety_tier: SafetyTier,
    idempotency: IdempotencyClass,
) -> OperationInfo {
    OperationInfo {
        id: OperationId::from_static(operation),
        summary: description.into(),
        description: None,
        input_schema: json!({"type": "object"}),
        output_schema: json!({"type": "object"}),
        capability: CapabilityId::from_static(capability),
        risk_level,
        safety_tier,
        idempotency,
        ai_hints: AgentHint {
            when_to_use: description.into(),
            common_mistakes: vec![],
            examples: vec![],
            related: vec![],
        },
        rate_limit: None,
        requires_approval: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_filter_is_strict_and_utc() {
        assert!(validate_timestamp_filter("timestamp >= 2026-08-04T10:00:00Z").is_ok());
        assert!(validate_timestamp_filter("timestamp = 2026-08-04T10:00:00Z").is_err());
        assert!(validate_timestamp_filter("timestamp > 2026-08-04T10:00:00+07:00").is_err());
    }

    #[test]
    fn raw_and_file_upload_item_writes_are_rejected() {
        let raw = json!({"raw": {"anything": true}});
        assert!(validate_item(&raw).is_err());
        let upload = json!({
            "title": "Upload",
            "questionItem": {"question": {"fileUploadQuestion": {}}}
        });
        assert!(validate_item(&upload).is_err());
    }

    #[test]
    fn safe_text_question_is_accepted() {
        let item = json!({
            "title": "Name",
            "questionItem": {
                "question": {
                    "required": true,
                    "textQuestion": {"paragraph": false}
                }
            }
        });
        assert!(validate_item(&item).is_ok());
    }

    #[test]
    fn cursor_is_bound_to_form_filter_and_token() {
        let a = cursor_binding("form-a", Some("timestamp > 2026-08-04T00:00:00Z"), "token");
        let b = cursor_binding("form-b", Some("timestamp > 2026-08-04T00:00:00Z"), "token");
        assert_ne!(a, b);
    }
}
