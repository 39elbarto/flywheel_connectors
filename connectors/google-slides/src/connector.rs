//! FCP Google Slides Connector implementation.

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

use crate::client::SlidesClient;
use crate::error::SlidesError;
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

fn host_is_slides_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("slides.googleapis.com")
}

/// Validate a google-slides `base_url` override.
///
/// The Slides client concatenates this string into downstream request URLs, so
/// only the Slides API host is accepted outside local test listeners.
fn validate_slides_base_url(raw: &str) -> FcpResult<String> {
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
    if !local && !host_is_slides_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url host must target slides.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn slides_presentation_resource_uri(presentation_id: &str) -> String {
    format!("google-slides:presentation:{presentation_id}")
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    match operation {
        "slides.get" | "slides.batch_update" => {
            let presentation_id = require_str(input, "presentation_id")?;
            Ok(vec![slides_presentation_resource_uri(presentation_id)])
        }
        "slides.pages.get" | "slides.pages.get_thumbnail" => {
            let presentation_id = require_str(input, "presentation_id")?;
            let page_object_id = require_str(input, "page_object_id")?;
            Ok(vec![
                slides_presentation_resource_uri(presentation_id),
                format!("google-slides:page:{presentation_id}:{page_object_id}"),
            ])
        }
        "slides.create" => Ok(vec!["google-slides:presentations".to_string()]),
        _ => Ok(Vec::new()),
    }
}

fn slides_capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
    match operation {
        "slides.get" | "slides.pages.get" | "slides.pages.get_thumbnail" => {
            Ok(CapabilityId::from_static("slides.read"))
        }
        "slides.create" | "slides.batch_update" => Ok(CapabilityId::from_static("slides.write")),
        _ => Err(FcpError::OperationNotGranted {
            operation: operation.into(),
        }),
    }
}

fn validate_slides_input(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
    let allowed_fields: &[&str] = match operation {
        "slides.get" => &["presentation_id", "text_offset", "text_limit"],
        "slides.pages.get" => &["presentation_id", "page_object_id"],
        "slides.pages.get_thumbnail" => &["presentation_id", "page_object_id", "size"],
        "slides.create" => &["title"],
        "slides.batch_update" => &[
            "presentation_id",
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
        "slides.get" => {
            validate_identifier(require_str(input, "presentation_id")?, "presentation_id")?;
            optional_bounded_usize(input, "text_offset", 0, MAX_DOCUMENT_INDEX as usize)?;
            optional_bounded_usize(input, "text_limit", 1, MAX_READ_TEXT_BYTES)?;
        }
        "slides.pages.get" => {
            validate_identifier(require_str(input, "presentation_id")?, "presentation_id")?;
            validate_object_id(require_str(input, "page_object_id")?, "page_object_id")?;
        }
        "slides.pages.get_thumbnail" => {
            validate_identifier(require_str(input, "presentation_id")?, "presentation_id")?;
            validate_object_id(require_str(input, "page_object_id")?, "page_object_id")?;
            if let Some(size) = input.get("size") {
                let size = size
                    .as_str()
                    .ok_or_else(|| invalid("'size' must be a string"))?;
                if !matches!(size, "SMALL" | "MEDIUM" | "LARGE") {
                    return Err(invalid("'size' must be SMALL, MEDIUM, or LARGE"));
                }
            }
        }
        "slides.create" => {
            validate_title(require_str(input, "title")?)?;
        }
        "slides.batch_update" => {
            validate_identifier(require_str(input, "presentation_id")?, "presentation_id")?;
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

fn validate_object_id(value: &str, field: &str) -> FcpResult<()> {
    let valid = (5..=50).contains(&value.len())
        && value.chars().enumerate().all(|(index, character)| {
            character.is_ascii_alphanumeric()
                || character == '_'
                || (index > 0 && matches!(character, '-' | ':'))
        });
    if !valid {
        return Err(invalid(format!(
            "'{field}' must be a 5..=50 character Slides object ID"
        )));
    }
    Ok(())
}

fn validate_cell(location: Option<&crate::types::TableCellLocation>) -> FcpResult<()> {
    if let Some(location) = location {
        if location.row_index > 1_000 || location.column_index > 1_000 {
            return Err(invalid("table cell indexes must be 0..=1000"));
        }
    }
    Ok(())
}

fn validate_text_range(range: &crate::types::TextRange) -> FcpResult<()> {
    match range.range_type.as_str() {
        "ALL" => {
            if range.start_index.is_some() || range.end_index.is_some() {
                return Err(invalid("ALL textRange must not include indexes"));
            }
        }
        "FROM_START_INDEX" => {
            if range.start_index.is_none() || range.end_index.is_some() {
                return Err(invalid(
                    "FROM_START_INDEX requires startIndex and forbids endIndex",
                ));
            }
        }
        "FIXED_RANGE" => match (range.start_index, range.end_index) {
            (Some(start), Some(end)) if start < end && end <= MAX_DOCUMENT_INDEX => {}
            _ => {
                return Err(invalid(
                    "FIXED_RANGE requires 0 <= startIndex < endIndex <= 10000000",
                ));
            }
        },
        _ => return Err(invalid("unsupported textRange.type")),
    }
    Ok(())
}

fn validate_dimension(value: &crate::types::Dimension, field: &str) -> FcpResult<()> {
    if !value.magnitude.is_finite()
        || !(0.0..=10_000_000.0).contains(&value.magnitude)
        || !matches!(value.unit.as_str(), "PT" | "EMU")
    {
        return Err(invalid(format!(
            "'{field}' must be finite, non-negative, and use PT or EMU"
        )));
    }
    Ok(())
}

fn validate_transform(value: &crate::types::AffineTransform) -> FcpResult<()> {
    let numbers = [
        value.scale_x,
        value.scale_y,
        value.shear_x,
        value.shear_y,
        value.translate_x,
        value.translate_y,
    ];
    if numbers
        .iter()
        .any(|number| !number.is_finite() || number.abs() > 10_000_000.0)
        || !matches!(value.unit.as_str(), "PT" | "EMU")
    {
        return Err(invalid(
            "transform values must be finite/bounded and use PT or EMU",
        ));
    }
    Ok(())
}

fn validate_element_properties(value: &crate::types::PageElementProperties) -> FcpResult<()> {
    validate_object_id(&value.page_object_id, "pageObjectId")?;
    if let Some(size) = &value.size {
        validate_dimension(&size.width, "size.width")?;
        validate_dimension(&size.height, "size.height")?;
        if size.width.magnitude == 0.0 || size.height.magnitude == 0.0 {
            return Err(invalid("element size must be positive"));
        }
    }
    if let Some(transform) = &value.transform {
        validate_transform(transform)?;
    }
    Ok(())
}

fn validate_fields(fields: &str, allowed: &[&str]) -> FcpResult<()> {
    let parts = fields.split(',').map(str::trim).collect::<Vec<_>>();
    if parts.is_empty()
        || parts
            .iter()
            .any(|field| field.is_empty() || *field == "*" || !allowed.contains(field))
    {
        return Err(invalid("field mask contains an unsupported or broad field"));
    }
    Ok(())
}

fn validate_text_style(style: &TextStyle, fields: &str) -> FcpResult<()> {
    validate_fields(
        fields,
        &[
            "bold",
            "italic",
            "underline",
            "fontFamily",
            "fontSize",
            "foregroundColor",
        ],
    )?;
    if let Some(font_family) = &style.font_family {
        validate_text(font_family, "fontFamily", false)?;
    }
    if let Some(font_size) = &style.font_size {
        validate_dimension(font_size, "fontSize")?;
        if !(1.0..=400.0).contains(&font_size.magnitude) || font_size.unit != "PT" {
            return Err(invalid("fontSize must use PT with magnitude 1..=400"));
        }
    }
    if let Some(color) = &style.foreground_color {
        if let Some(rgb) = &color.opaque_color.rgb_color {
            if ![rgb.red, rgb.green, rgb.blue]
                .into_iter()
                .all(|component| (0.0..=1.0).contains(&component))
            {
                return Err(invalid("RGB components must be 0..=1"));
            }
        } else if color.opaque_color.theme_color.is_none() {
            return Err(invalid(
                "foregroundColor must provide rgbColor or themeColor",
            ));
        }
    }
    Ok(())
}

fn validate_external_media_url(raw: &str, field: &str) -> FcpResult<()> {
    if raw.len() > 2048 {
        return Err(invalid(format!("'{field}' exceeds 2048 bytes")));
    }
    let url = Url::parse(raw).map_err(|_| invalid(format!("'{field}' must be a valid URL")))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(format!(
            "'{field}' must be HTTPS without userinfo or fragment"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| invalid(format!("'{field}' must include a host")))?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.rsplit('.').next() == Some("local")
        || host.ends_with(".internal")
        || host.ends_with(".ts.net")
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(invalid(format!(
            "'{field}' may not target localhost, private-name, tailnet, or IP-literal hosts"
        )));
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
        invalid("'requests' must contain only supported typed Google Slides requests")
    })?;
    if requests.is_empty() || requests.len() > MAX_REQUESTS {
        return Err(invalid(format!(
            "'requests' must contain 1..={MAX_REQUESTS} entries"
        )));
    }

    let mut created_ids = std::collections::BTreeSet::new();
    for request in &requests {
        match request {
            Request::CreateSlide(request) => {
                if let Some(id) = &request.object_id {
                    validate_object_id(id, "createSlide.objectId")?;
                    if !created_ids.insert(id.clone()) {
                        return Err(invalid("duplicate created objectId in batch"));
                    }
                }
                if request.insertion_index.unwrap_or(0) > 10_000 {
                    return Err(invalid("createSlide.insertionIndex must be <= 10000"));
                }
                if let Some(layout) = &request.slide_layout_reference {
                    match (&layout.predefined_layout, &layout.layout_id) {
                        (Some(value), None)
                            if matches!(
                                value.as_str(),
                                "BLANK"
                                    | "CAPTION_ONLY"
                                    | "TITLE"
                                    | "TITLE_AND_BODY"
                                    | "TITLE_AND_TWO_COLUMNS"
                                    | "TITLE_ONLY"
                                    | "SECTION_HEADER"
                                    | "SECTION_TITLE_AND_DESCRIPTION"
                                    | "ONE_COLUMN_TEXT"
                                    | "MAIN_POINT"
                                    | "BIG_NUMBER"
                            ) => {}
                        (None, Some(id)) => validate_object_id(id, "layoutId")?,
                        _ => return Err(invalid("layout reference must select exactly one kind")),
                    }
                }
            }
            Request::CreateShape(request) => {
                validate_object_id(&request.object_id, "createShape.objectId")?;
                if !created_ids.insert(request.object_id.clone()) {
                    return Err(invalid("duplicate created objectId in batch"));
                }
                if !matches!(
                    request.shape_type.as_str(),
                    "TEXT_BOX" | "RECTANGLE" | "ROUND_RECTANGLE" | "ELLIPSE" | "LINE" | "ARROW"
                ) {
                    return Err(invalid("unsupported createShape.shapeType"));
                }
                validate_element_properties(&request.element_properties)?;
            }
            Request::CreateTable(request) => {
                validate_object_id(&request.object_id, "createTable.objectId")?;
                if !created_ids.insert(request.object_id.clone()) {
                    return Err(invalid("duplicate created objectId in batch"));
                }
                if !(1..=20).contains(&request.rows) || !(1..=20).contains(&request.columns) {
                    return Err(invalid("createTable rows and columns must be 1..=20"));
                }
                validate_element_properties(&request.element_properties)?;
            }
            Request::InsertText(request) => {
                validate_object_id(&request.object_id, "insertText.objectId")?;
                validate_text(&request.text, "insertText.text", false)?;
                if request.insertion_index.unwrap_or(0) > MAX_DOCUMENT_INDEX {
                    return Err(invalid("insertText.insertionIndex is too large"));
                }
                validate_cell(request.cell_location.as_ref())?;
            }
            Request::DeleteText(request) => {
                validate_object_id(&request.object_id, "deleteText.objectId")?;
                validate_text_range(&request.text_range)?;
                validate_cell(request.cell_location.as_ref())?;
            }
            Request::UpdateTextStyle(request) => {
                validate_object_id(&request.object_id, "updateTextStyle.objectId")?;
                validate_text_range(&request.text_range)?;
                validate_text_style(&request.style, &request.fields)?;
                validate_cell(request.cell_location.as_ref())?;
            }
            Request::UpdateParagraphStyle(request) => {
                validate_object_id(&request.object_id, "updateParagraphStyle.objectId")?;
                validate_text_range(&request.text_range)?;
                validate_fields(&request.fields, &["alignment", "lineSpacing", "direction"])?;
                if let Some(spacing) = request.style.line_spacing {
                    if !spacing.is_finite() || !(1.0..=500.0).contains(&spacing) {
                        return Err(invalid("lineSpacing must be 1..=500"));
                    }
                }
                validate_cell(request.cell_location.as_ref())?;
            }
            Request::CreateImage(request) => {
                validate_object_id(&request.object_id, "createImage.objectId")?;
                if !created_ids.insert(request.object_id.clone()) {
                    return Err(invalid("duplicate created objectId in batch"));
                }
                validate_external_media_url(&request.url, "createImage.url")?;
                validate_element_properties(&request.element_properties)?;
            }
            Request::CreateSheetsChart(request) => {
                validate_object_id(&request.object_id, "createSheetsChart.objectId")?;
                validate_identifier(&request.spreadsheet_id, "spreadsheetId")?;
                if !created_ids.insert(request.object_id.clone()) {
                    return Err(invalid("duplicate created objectId in batch"));
                }
                if !matches!(request.linking_mode.as_str(), "LINKED" | "NOT_LINKED_IMAGE") {
                    return Err(invalid("unsupported createSheetsChart.linkingMode"));
                }
                validate_element_properties(&request.element_properties)?;
            }
            Request::RefreshSheetsChart(request) => {
                validate_object_id(&request.object_id, "refreshSheetsChart.objectId")?;
            }
            Request::DeleteObject(request) => {
                validate_object_id(&request.object_id, "deleteObject.objectId")?;
            }
            Request::ReplaceAllText(request) => {
                validate_text(&request.contains_text.text, "containsText.text", false)?;
                validate_text(&request.replace_text, "replaceText", true)?;
                if request.contains_text.search_by_regex {
                    return Err(invalid("regex replaceAllText is not exposed"));
                }
                if request.page_object_ids.len() > 100 {
                    return Err(invalid("pageObjectIds must contain at most 100 entries"));
                }
                for id in &request.page_object_ids {
                    validate_object_id(id, "pageObjectId")?;
                }
            }
            Request::UpdateSlidesPosition(request) => {
                if request.slide_object_ids.is_empty() || request.slide_object_ids.len() > 100 {
                    return Err(invalid("slideObjectIds must contain 1..=100 entries"));
                }
                let mut ids = std::collections::BTreeSet::new();
                for id in &request.slide_object_ids {
                    validate_object_id(id, "slideObjectId")?;
                    if !ids.insert(id) {
                        return Err(invalid("slideObjectIds must not contain duplicates"));
                    }
                }
                if request.insertion_index > 10_000 {
                    return Err(invalid("insertionIndex must be <= 10000"));
                }
            }
            Request::DuplicateObject(request) => {
                validate_object_id(&request.object_id, "duplicateObject.objectId")?;
                if request.object_ids.len() > 100 {
                    return Err(invalid("duplicateObject.objectIds exceeds 100 mappings"));
                }
                for (source, target) in &request.object_ids {
                    validate_object_id(source, "duplicateObject source ID")?;
                    validate_object_id(target, "duplicateObject target ID")?;
                    if !created_ids.insert(target.clone()) {
                        return Err(invalid("duplicate created objectId in batch"));
                    }
                }
            }
            Request::ReplaceImage(request) => {
                validate_object_id(&request.image_object_id, "replaceImage.imageObjectId")?;
                validate_external_media_url(&request.url, "replaceImage.url")?;
                if !matches!(
                    request.image_replace_method.as_str(),
                    "CENTER_CROP" | "CENTER_INSIDE"
                ) {
                    return Err(invalid("unsupported imageReplaceMethod"));
                }
            }
            Request::UpdatePageElementTransform(request) => {
                validate_object_id(&request.object_id, "updatePageElementTransform.objectId")?;
                validate_transform(&request.transform)?;
                if !matches!(request.apply_mode.as_str(), "RELATIVE" | "ABSOLUTE") {
                    return Err(invalid("unsupported transform applyMode"));
                }
            }
            Request::UpdateShapeProperties(request) => {
                validate_object_id(&request.object_id, "updateShapeProperties.objectId")?;
                validate_fields(&request.fields, &["contentAlignment", "autofit"])?;
                if let Some(autofit) = &request.shape_properties.autofit {
                    if !matches!(
                        autofit.autofit_type.as_str(),
                        "NONE" | "TEXT_AUTOFIT" | "SHAPE_AUTOFIT"
                    ) {
                        return Err(invalid("unsupported autofitType"));
                    }
                }
            }
            Request::UpdatePageProperties(request) => {
                validate_object_id(&request.object_id, "updatePageProperties.objectId")?;
                validate_fields(&request.fields, &["pageBackgroundFill"])?;
                if let Some(fill) = &request.page_properties.page_background_fill {
                    if let Some(alpha) = fill.solid_fill.alpha {
                        if !(0.0..=1.0).contains(&alpha) {
                            return Err(invalid("solidFill.alpha must be 0..=1"));
                        }
                    }
                }
            }
            Request::UpdateTableCellProperties(request) => {
                validate_object_id(&request.object_id, "updateTableCellProperties.objectId")?;
                validate_cell(Some(&request.table_range.location))?;
                if request.table_range.row_span == 0
                    || request.table_range.row_span > 20
                    || request.table_range.column_span == 0
                    || request.table_range.column_span > 20
                {
                    return Err(invalid("tableRange spans must be 1..=20"));
                }
                validate_fields(&request.fields, &["contentAlignment"])?;
            }
        }
    }
    Ok(requests)
}

fn presentation_revision(presentation: &serde_json::Value) -> FcpResult<&str> {
    presentation
        .get("revisionId")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("presentation revision is unavailable; edit access is required"))
}

fn presentation_receipt(presentation: &serde_json::Value) -> serde_json::Value {
    json!({
        "presentation_id": presentation.get("presentationId").and_then(serde_json::Value::as_str),
        "title": presentation.get("title").and_then(serde_json::Value::as_str),
        "revision_id": presentation.get("revisionId").and_then(serde_json::Value::as_str),
        "slide_count": presentation.get("slides").and_then(serde_json::Value::as_array).map_or(0, Vec::len),
    })
}

fn collect_presentation_text(value: &serde_json::Value, output: &mut String) {
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
                    collect_presentation_text(nested, output);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values {
                collect_presentation_text(nested, output);
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

fn compact_presentation(
    presentation: &serde_json::Value,
    offset: usize,
    limit: usize,
) -> serde_json::Value {
    let mut text = String::new();
    collect_presentation_text(presentation, &mut text);
    let (page, actual_offset, next_offset) = bounded_text_slice(&text, offset, limit);
    json!({
        "metadata": presentation_receipt(presentation),
        "text": page,
        "text_offset": actual_offset,
        "text_next_offset": next_offset,
        "text_complete": next_offset >= text.len(),
        "text_total_bytes": text.len(),
    })
}

fn request_impact(request: &Request) -> serde_json::Value {
    let kind = request.kind();
    let hash = |value: &str| hex::encode(Sha256::digest(value.as_bytes()));
    match request {
        Request::DeleteText(request) => json!({
            "kind": kind,
            "object_id_sha256": hash(&request.object_id),
            "range_type": request.text_range.range_type,
            "start_index": request.text_range.start_index,
            "end_index": request.text_range.end_index,
        }),
        Request::DeleteObject(request) => json!({
            "kind": kind,
            "object_id_sha256": hash(&request.object_id),
        }),
        Request::ReplaceAllText(request) => json!({
            "kind": kind,
            "match_case": request.contains_text.match_case,
            "search_sha256": hash(&request.contains_text.text),
            "search_bytes": request.contains_text.text.len(),
            "replacement_bytes": request.replace_text.len(),
            "page_count": request.page_object_ids.len(),
            "pages_sha256": hash_serializable(&request.page_object_ids),
        }),
        Request::UpdateSlidesPosition(request) => json!({
            "kind": kind,
            "slide_count": request.slide_object_ids.len(),
            "slides_sha256": hash_serializable(&request.slide_object_ids),
            "insertion_index": request.insertion_index,
        }),
        Request::ReplaceImage(request) => json!({
            "kind": kind,
            "image_object_id_sha256": hash(&request.image_object_id),
            "url_sha256": hash(&request.url),
        }),
        Request::RefreshSheetsChart(request) => json!({
            "kind": kind,
            "object_id_sha256": hash(&request.object_id),
        }),
        _ => json!({ "kind": kind, "destructive": false }),
    }
}

fn hash_serializable(value: &impl serde::Serialize) -> String {
    let encoded = serde_json::to_vec(value).unwrap_or_default();
    hex::encode(Sha256::digest(encoded))
}

fn confirmation_sha256(
    presentation_id: &str,
    revision_id: &str,
    requests: &[Request],
) -> FcpResult<String> {
    let encoded = serde_json::to_vec(&(presentation_id, revision_id, requests))
        .map_err(|error| invalid(format!("could not bind confirmation payload: {error}")))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

/// FCP Google Slides Connector.
pub struct SlidesConnector {
    base: Arc<BaseConnector>,
    client: Option<SlidesClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
}

impl SlidesConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "google-slides",
            ))),
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
            SlidesClient::new_with_auth(materialized).map_err(|e| FcpError::Internal {
                message: format!("Failed to create Slides client: {e}"),
            })?;
        if let Some(value) = params.get("base_url") {
            let base_url = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "`base_url` must be a string".into(),
            })?;
            client = client.with_base_url(validate_slides_base_url(base_url)?);
        }

        let auth_label = client.auth_redacted_label();
        self.client = Some(client);
        self.base.set_configured(true);
        info!(auth = %auth_label, status, "Google Slides connector configured");

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
                    "slides.get",
                    "Get a presentation by ID",
                    json!({
                        "type": "object",
                        "required": ["presentation_id"],
                        "properties": {
                            "presentation_id": { "type": "string", "minLength": 1, "maxLength": 512 },
                            "text_offset": { "type": "integer", "minimum": 0, "maximum": 10000000 },
                            "text_limit": { "type": "integer", "minimum": 1, "maximum": 48000 }
                        },
                        "additionalProperties": false
                    }),
                    json!({
                        "type": "object",
                        "properties": {
                            "status": { "type": "string" },
                            "presentation": { "type": "object" },
                            "readback": { "type": "object" },
                            "retry_safe": { "type": "boolean" }
                        }
                    }),
                    "slides.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use:
                            "Retrieve a Google Slides presentation including title, body content, and structure."
                                .into(),
                        common_mistakes: vec![],
                        examples: vec![
                            r#"{"presentation_id": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"}"#
                                .into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("slides.create"),
                            CapabilityId::from_static("slides.batch_update"),
                        ],
                    },
                ),
                op_info(
                    "slides.pages.get",
                    "Get one slide, notes page, master, or layout",
                    json!({
                        "type": "object",
                        "required": ["presentation_id", "page_object_id"],
                        "properties": {
                            "presentation_id": { "type": "string", "minLength": 1, "maxLength": 512 },
                            "page_object_id": { "type": "string", "minLength": 5, "maxLength": 50 }
                        },
                        "additionalProperties": false
                    }),
                    json!({ "type": "object", "properties": { "page": { "type": "object" } } }),
                    "slides.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Read one bounded page, including speaker notes text when the page ID targets a notes page.".into(),
                        common_mistakes: vec![],
                        examples: vec![r#"{"presentation_id":"presentation123","page_object_id":"slide_001"}"#.into()],
                        related: vec![CapabilityId::from_static("slides.get")],
                    },
                ),
                op_info(
                    "slides.pages.get_thumbnail",
                    "Generate bounded PNG thumbnail metadata for a page",
                    json!({
                        "type": "object",
                        "required": ["presentation_id", "page_object_id"],
                        "properties": {
                            "presentation_id": { "type": "string", "minLength": 1, "maxLength": 512 },
                            "page_object_id": { "type": "string", "minLength": 5, "maxLength": 50 },
                            "size": { "type": "string", "enum": ["SMALL", "MEDIUM", "LARGE"] }
                        },
                        "additionalProperties": false
                    }),
                    json!({ "type": "object", "properties": { "thumbnail": { "type": "object" } } }),
                    "slides.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Request a short-lived Google-authenticated PNG thumbnail URL; do not persist or log the URL.".into(),
                        common_mistakes: vec!["Treating the temporary content URL as public or durable".into()],
                        examples: vec![r#"{"presentation_id":"presentation123","page_object_id":"slide_001","size":"MEDIUM"}"#.into()],
                        related: vec![CapabilityId::from_static("slides.pages.get")],
                    },
                ),
                op_info(
                    "slides.create",
                    "Create a new presentation",
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
                            "presentation": { "type": "object" }
                        }
                    }),
                    "slides.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create a brand new Google Slides presentation with a given title."
                            .into(),
                        common_mistakes: vec![
                            "Each call creates a new presentation — do not call repeatedly for the same title"
                                .into(),
                        ],
                        examples: vec![r#"{"title": "Meeting Notes 2026-03-14"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("slides.get"),
                            CapabilityId::from_static("slides.batch_update"),
                        ],
                    },
                ),
                op_info(
                    "slides.batch_update",
                    "Apply batch updates to a presentation",
                    json!({
                        "type": "object",
                        "required": ["presentation_id", "requests"],
                        "properties": {
                            "presentation_id": { "type": "string", "minLength": 1, "maxLength": 512 },
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
                            "presentation_id": { "type": "string" },
                            "preflight": { "type": "object" },
                            "readback": { "type": "object" }
                        }
                    }),
                    "slides.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use:
                            "Apply a bounded typed batch guarded by a current presentation revision. Destructive requests first return a confirmation receipt."
                                .into(),
                        common_mistakes: vec![
                            "Requests are applied in order — indices shift after inserts/deletes"
                                .into(),
                            "Apply changes in reverse index order to avoid index drift".into(),
                            "Never retry an uncertain write before reading the presentation again".into(),
                        ],
                        examples: vec![
                            r#"{"presentation_id": "abc123", "requests": [{"insertText": {"location": {"index": 1}, "text": "Hello"}}]}"#.into(),
                        ],
                        related: vec![CapabilityId::from_static("slides.get")],
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
        let cap_id = slides_capability_for_operation(operation)?;
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
        validate_slides_input(operation, &input)?;
        let resource_uris = resource_uris_for_operation(operation, &input)?;
        verifier.verify_bound(capability, &cap_id, &op_id, &resource_uris)?;

        match operation {
            "slides.get" => {
                let presentation_id = require_str(&input, "presentation_id")?;
                let doc = client
                    .get_presentation(presentation_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let offset =
                    optional_bounded_usize(&input, "text_offset", 0, MAX_DOCUMENT_INDEX as usize)?
                        .unwrap_or(0);
                let limit = optional_bounded_usize(&input, "text_limit", 1, MAX_READ_TEXT_BYTES)?
                    .unwrap_or(MAX_READ_TEXT_BYTES);
                Ok(json!({ "presentation": compact_presentation(&doc, offset, limit) }))
            }
            "slides.pages.get" => {
                let presentation_id = require_str(&input, "presentation_id")?;
                let page_object_id = require_str(&input, "page_object_id")?;
                let page = client
                    .get_page(presentation_id, page_object_id)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let mut text = String::new();
                collect_presentation_text(&page, &mut text);
                let (text, _, _) = bounded_text_slice(&text, 0, MAX_READ_TEXT_BYTES);
                Ok(json!({
                    "page": {
                        "object_id": page.get("objectId").and_then(serde_json::Value::as_str),
                        "page_type": page.get("pageType").and_then(serde_json::Value::as_str),
                        "element_count": page.get("pageElements").and_then(serde_json::Value::as_array).map_or(0, Vec::len),
                        "text": text,
                        "text_complete": text.len() < MAX_READ_TEXT_BYTES,
                    }
                }))
            }
            "slides.pages.get_thumbnail" => {
                let presentation_id = require_str(&input, "presentation_id")?;
                let page_object_id = require_str(&input, "page_object_id")?;
                let size = input
                    .get("size")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("MEDIUM");
                let thumbnail = client
                    .get_thumbnail(presentation_id, page_object_id, size)
                    .await
                    .map_err(|error| error.to_fcp_error())?;
                let content_url = thumbnail
                    .get("contentUrl")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| invalid("thumbnail response did not include contentUrl"))?;
                validate_external_media_url(content_url, "thumbnail.contentUrl")?;
                Ok(json!({
                    "thumbnail": {
                        "width": thumbnail.get("width").and_then(serde_json::Value::as_u64),
                        "height": thumbnail.get("height").and_then(serde_json::Value::as_u64),
                        "content_url": content_url,
                        "mime_type": "image/png",
                        "size": size,
                        "expires_approximately_seconds": 1800,
                    }
                }))
            }
            "slides.create" => {
                let title = validate_title(require_str(&input, "title")?)?;
                let created = match client.create_presentation(title).await {
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
                let Some(presentation_id) = created
                    .get("presentationId")
                    .and_then(serde_json::Value::as_str)
                else {
                    return Ok(json!({
                        "status": "outcome_uncertain",
                        "retry_safe": false,
                        "readback": { "available": false },
                    }));
                };
                match client.get_presentation(presentation_id).await {
                    Ok(readback) => Ok(json!({
                        "status": "created_and_verified",
                        "presentation": presentation_receipt(&created),
                        "readback": presentation_receipt(&readback),
                        "retry_safe": false,
                    })),
                    Err(_) => Ok(json!({
                        "status": "created_unverified",
                        "presentation": presentation_receipt(&created),
                        "readback": { "available": false },
                        "retry_safe": false,
                    })),
                }
            }
            "slides.batch_update" => {
                let presentation_id = require_str(&input, "presentation_id")?;
                let requests = validated_requests(&input)?;
                let preflight_presentation = client
                    .get_presentation(presentation_id)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let revision_before = presentation_revision(&preflight_presentation)?.to_string();
                let destructive = requests.iter().any(Request::is_destructive);
                let impacts = requests.iter().map(request_impact).collect::<Vec<_>>();
                let expected_confirmation =
                    confirmation_sha256(presentation_id, &revision_before, &requests)?;

                if destructive
                    && input
                        .get("confirm_destructive")
                        .and_then(serde_json::Value::as_bool)
                        != Some(true)
                {
                    return Ok(json!({
                        "status": "confirmation_required",
                        "presentation_id": presentation_id,
                        "destructive": true,
                        "preflight": presentation_receipt(&preflight_presentation),
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
                        "presentation_id": presentation_id,
                        "destructive": destructive,
                        "preflight": presentation_receipt(&preflight_presentation),
                        "impact": impacts,
                        "required_revision_id": revision_before,
                        "confirmation_sha256": destructive.then_some(expected_confirmation),
                    }));
                };
                if required_revision_id != revision_before {
                    return Err(invalid(
                        "required_revision_id does not match the current presentation revision",
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
                            "confirmation_sha256 does not match the presentation revision and exact request batch",
                        ));
                    }
                }

                let batch_result = match client
                    .batch_update(presentation_id, &requests, required_revision_id)
                    .await
                {
                    Ok(result) => result,
                    Err(SlidesError::Api {
                        status_code: 400, ..
                    }) => {
                        let readback = client.get_presentation(presentation_id).await.ok();
                        return Ok(json!({
                            "status": "revision_conflict_or_provider_rejected",
                            "presentation_id": presentation_id,
                            "destructive": destructive,
                            "revision_before": revision_before,
                            "readback": readback.as_ref().map_or_else(|| json!({ "available": false }), presentation_receipt),
                            "retry_safe": false,
                        }));
                    }
                    Err(SlidesError::Json(_)) => {
                        let readback = client.get_presentation(presentation_id).await.ok();
                        return Ok(json!({
                            "status": "outcome_uncertain",
                            "presentation_id": presentation_id,
                            "destructive": destructive,
                            "revision_before": revision_before,
                            "readback": readback.as_ref().map_or_else(|| json!({ "available": false }), presentation_receipt),
                            "retry_safe": false,
                        }));
                    }
                    Err(error) if error.is_retryable() => {
                        let readback = client.get_presentation(presentation_id).await.ok();
                        return Ok(json!({
                            "status": "outcome_uncertain",
                            "presentation_id": presentation_id,
                            "destructive": destructive,
                            "revision_before": revision_before,
                            "readback": readback.as_ref().map_or_else(|| json!({ "available": false }), presentation_receipt),
                            "retry_safe": false,
                        }));
                    }
                    Err(error) => return Err(error.to_fcp_error()),
                };
                let readback_presentation = client.get_presentation(presentation_id).await.ok();
                Ok(json!({
                    "status": if readback_presentation.is_some() { "applied_and_verified" } else { "applied_unverified" },
                    "presentation_id": batch_result.presentation_id,
                    "destructive": destructive,
                    "request_count": requests.len(),
                    "request_kinds": requests.iter().map(Request::kind).collect::<Vec<_>>(),
                    "reply_count": batch_result.replies.len(),
                    "preflight": presentation_receipt(&preflight_presentation),
                    "readback": readback_presentation.as_ref().map_or_else(|| json!({ "available": false }), presentation_receipt),
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
        let response = match slides_capability_for_operation(operation) {
            Ok(capability) => {
                if let Err(error) = validate_slides_input(operation, &req.input) {
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
        info!("Google Slides connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for SlidesConnector {
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
            "slides.get" => "slides.read",
            "slides.create" | "slides.batch_update" => "slides.write",
            _ => "slides.read",
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
            ConnectorId::from_static("google-slides"),
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
        connector: &mut SlidesConnector,
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
                "capabilities_requested": ["slides.read", "slides.write"],
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

        assert_eq!(SlidesConnector::manifest_hash(), expected);
        assert_ne!(
            SlidesConnector::manifest_hash(),
            "sha256:google-slides-connector-v1"
        );
    }

    #[test]
    fn health_unconfigured() {
        let connector = SlidesConnector::new();
        let result = run_async_test(connector.handle_health()).unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[test]
    fn health_configured() {
        run_async_test(async {
            let mut connector = SlidesConnector::new();
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
            let mut connector = SlidesConnector::new();
            connector.handle_configure(json!({})).await
        });
        assert!(result.is_err());
    }

    #[test]
    fn configure_rejects_invalid_base_url_override() {
        run_async_test(async {
            let mut connector = SlidesConnector::new();
            let err = connector
                .handle_configure(bearer_config_with_base_url("test-token", json!(123)))
                .await
                .unwrap_err();
            assert!(
                matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("base_url")),
                "expected base_url validation error, got {err:?}"
            );

            let mut connector = SlidesConnector::new();
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
            let mut connector = SlidesConnector::new();
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
            let mut connector = SlidesConnector::new();
            let cred_id = fcp_core::CredentialId::new();
            let result = connector
                .handle_configure(json!({ "credential_id": cred_id.to_string() }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured_pending_token_materialization");
        });
    }

    #[test]
    fn validate_slides_base_url_accepts_googleapis() {
        let out = validate_slides_base_url("https://slides.googleapis.com/v1/").unwrap();
        assert_eq!(out, "https://slides.googleapis.com/v1");
    }

    #[test]
    fn validate_slides_base_url_allows_localhost_http() {
        validate_slides_base_url("http://localhost:9999/v1").unwrap();
        validate_slides_base_url("http://127.0.0.1/slides").unwrap();
        validate_slides_base_url("http://[::1]:9999/v1").unwrap();
    }

    #[test]
    fn validate_slides_base_url_rejects_foreign_host() {
        let err = validate_slides_base_url("https://evil.example.com/v1").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("slides.googleapis.com")),
            "expected InvalidRequest mentioning googleapis.com, got {err:?}"
        );
    }

    #[test]
    fn validate_slides_base_url_rejects_substring_smuggle() {
        let err =
            validate_slides_base_url("https://evil.com/slides.googleapis.com/v1").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_slides_base_url_rejects_query_fragment_userinfo() {
        assert!(matches!(
            validate_slides_base_url("https://slides.googleapis.com/v1?leak=x").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_slides_base_url("https://slides.googleapis.com/v1#frag").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        let err =
            validate_slides_base_url("https://attacker:pw@slides.googleapis.com/v1").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("userinfo")),
            "expected InvalidRequest mentioning userinfo, got {err:?}"
        );
    }

    #[test]
    fn validate_slides_base_url_rejects_plain_http_on_public_host() {
        let err = validate_slides_base_url("http://slides.googleapis.com/v1").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_slides_base_url_rejects_empty_and_malformed() {
        assert!(matches!(
            validate_slides_base_url("   ").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_slides_base_url("not a url").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn host_is_slides_googleapis_rejects_wrong_hosts_and_lookalikes() {
        assert!(host_is_slides_googleapis("slides.googleapis.com"));
        assert!(!host_is_slides_googleapis("googleapis.com"));
        assert!(!host_is_slides_googleapis("www.googleapis.com"));
        assert!(!host_is_slides_googleapis("googleapis.com.evil.com"));
        assert!(!host_is_slides_googleapis("evil-googleapis.com"));
    }

    #[test]
    fn resource_uris_bind_slides_targets() {
        let get =
            resource_uris_for_operation("slides.get", &json!({ "presentation_id": "doc_123" }))
                .unwrap();
        assert_eq!(get, vec!["google-slides:presentation:doc_123"]);

        let create = resource_uris_for_operation("slides.create", &json!({})).unwrap();
        assert_eq!(create, vec!["google-slides:presentations"]);
    }

    #[test]
    fn introspect_has_all_operations() {
        let connector = SlidesConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 5);

        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(op_ids.contains(&"slides.get"));
        assert!(op_ids.contains(&"slides.pages.get"));
        assert!(op_ids.contains(&"slides.pages.get_thumbnail"));
        assert!(op_ids.contains(&"slides.create"));
        assert!(op_ids.contains(&"slides.batch_update"));
    }

    #[test]
    fn introspect_operations_have_schemas() {
        let connector = SlidesConnector::new();
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
    fn introspect_slides_get_is_safe() {
        let connector = SlidesConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        let slides_get = ops.iter().find(|o| o["id"] == "slides.get").unwrap();
        assert_eq!(slides_get["safety_tier"], "safe");
        assert_eq!(slides_get["risk_level"], "low");
    }

    #[test]
    fn shutdown_succeeds() {
        run_async_test(async {
            let mut connector = SlidesConnector::new();
            let result = connector.handle_shutdown(json!({})).await.unwrap();
            assert_eq!(result["status"], "shutdown");
        });
    }

    #[test]
    fn invoke_without_configure_returns_not_configured() {
        let result = run_async_test(async {
            let mut connector = SlidesConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "slides.get",
                    "input": { "presentation_id": "abc" }
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[test]
    fn invoke_unknown_operation_is_denied_before_token_validation() {
        let result = run_async_test(async {
            let mut connector = SlidesConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "slides.nonexistent",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
    }

    #[test]
    fn invoke_missing_operation_field() {
        let result = run_async_test(async {
            let mut connector = SlidesConnector::new();
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
        let connector = SlidesConnector::default();
        assert!(connector.client.is_none());
    }

    #[test]
    fn simulate_denies_before_configure() {
        let signing_key = Ed25519SigningKey::generate();
        let instance_id = fcp_core::InstanceId::new();
        let connector = SlidesConnector::new();
        let result = run_async_test(connector.handle_simulate(simulate_request(
            &signing_key,
            "slides.get",
            json!({ "presentation_id": "doc_123" }),
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
            let mut connector = SlidesConnector::new();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let result = connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "slides.get",
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
                    .is_some_and(|reason| reason.contains("presentation_id"))
            );
        });
    }

    #[test]
    fn simulate_allows_valid_authorized_request() {
        run_async_test(async {
            let signing_key = Ed25519SigningKey::generate();
            let mut connector = SlidesConnector::new();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let result = connector
                .handle_simulate(simulate_request(
                    &signing_key,
                    "slides.get",
                    json!({ "presentation_id": "doc_123" }),
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
        let connector = SlidesConnector::new();
        let result = run_async_test(connector.handle_simulate(simulate_request(
            &signing_key,
            "slides.unknown",
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
            let mut connector = SlidesConnector::new();

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
    fn configured_connector_introspects_slides_operations() {
        run_async_test(async {
            let mut connector = SlidesConnector::new();
            connector
                .handle_configure(bearer_config("test-token"))
                .await
                .unwrap();

            // Verify introspect works since we can confirm the connector is functional
            let introspect = connector.handle_introspect().await.unwrap();
            assert_eq!(introspect["operations"].as_array().unwrap().len(), 5);
        });
    }

    #[test]
    fn invoke_slides_get_missing_presentation_id() {
        let result = run_async_test(async {
            let mut connector = SlidesConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let capability = build_capability(&signing_key, "slides.get", &instance_id);
            connector
                .handle_invoke(json!({
                    "operation": "slides.get",
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
    fn invoke_slides_create_missing_title() {
        let result = run_async_test(async {
            let mut connector = SlidesConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let capability = build_capability(&signing_key, "slides.create", &instance_id);
            connector
                .handle_invoke(json!({
                    "operation": "slides.create",
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
    fn invoke_slides_batch_update_missing_requests() {
        let result = run_async_test(async {
            let mut connector = SlidesConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let capability = build_capability(&signing_key, "slides.batch_update", &instance_id);
            connector
                .handle_invoke(json!({
                    "operation": "slides.batch_update",
                    "input": { "presentation_id": "abc" },
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
    fn invoke_slides_batch_update_missing_presentation_id() {
        let result = run_async_test(async {
            let mut connector = SlidesConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            let instance_id = configure_and_handshake(&mut connector, &signing_key).await;
            let capability = build_capability(&signing_key, "slides.batch_update", &instance_id);
            connector
                .handle_invoke(json!({
                    "operation": "slides.batch_update",
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
        let connector = SlidesConnector::new();
        let result = run_async_test(connector.handle_health()).unwrap();
        assert_eq!(result["metrics"]["requests_total"], 0);
        assert_eq!(result["metrics"]["requests_error"], 0);
    }

    #[test]
    fn typed_request_allowlist_rejects_raw_escape_and_unknown_nested_fields() {
        let raw_escape = json!({
            "requests": [{ "deleteFile": { "fileId": "file-1" } }]
        });
        assert!(validated_requests(&raw_escape).is_err());

        let unknown_nested = json!({
            "requests": [{
                "insertText": {
                    "objectId": "shape_001",
                    "insertionIndex": 0,
                    "unexpected": true,
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
                { "insertText": { "objectId": "shape_001", "insertionIndex": 0, "text": "hello" } },
                { "deleteText": { "objectId": "shape_001", "textRange": { "type": "FIXED_RANGE", "startIndex": 2, "endIndex": 5 } } }
            ]
        });
        let requests = validated_requests(&input).unwrap();
        assert_eq!(requests.len(), 2);
        assert!(!requests[0].is_destructive());
        assert!(requests[1].is_destructive());

        let too_many = json!({
            "requests": (0..=MAX_REQUESTS)
                .map(|_| json!({ "insertText": { "objectId": "shape_001", "insertionIndex": 0, "text": "x" } }))
                .collect::<Vec<_>>()
        });
        assert!(validated_requests(&too_many).is_err());
    }

    #[test]
    fn media_urls_and_duplicate_created_ids_fail_before_provider_io() {
        for url in [
            "http://example.com/image.png",
            "https://127.0.0.1/image.png",
            "https://host.ts.net/image.png",
            "https://localhost/image.png",
        ] {
            let input = json!({
                "requests": [{
                    "createImage": {
                        "objectId": "image_001",
                        "url": url,
                        "elementProperties": { "pageObjectId": "slide_001" }
                    }
                }]
            });
            assert!(validated_requests(&input).is_err(), "accepted {url}");
        }

        let duplicate = json!({
            "requests": [
                { "createSlide": { "objectId": "slide_001" } },
                { "createShape": {
                    "objectId": "slide_001",
                    "shapeType": "TEXT_BOX",
                    "elementProperties": { "pageObjectId": "slide_002" }
                } }
            ]
        });
        assert!(validated_requests(&duplicate).is_err());
    }

    #[test]
    fn broad_field_masks_and_regex_replace_are_rejected() {
        let broad_mask = json!({
            "requests": [{
                "updateShapeProperties": {
                    "objectId": "shape_001",
                    "shapeProperties": { "contentAlignment": "MIDDLE" },
                    "fields": "*"
                }
            }]
        });
        assert!(validated_requests(&broad_mask).is_err());

        let regex = json!({
            "requests": [{
                "replaceAllText": {
                    "containsText": { "text": ".*", "searchByRegex": true },
                    "replaceText": "redacted"
                }
            }]
        });
        assert!(validated_requests(&regex).is_err());
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
    fn compact_presentation_pages_utf8_without_splitting_codepoints() {
        let presentation = json!({
            "presentationId": "doc",
            "title": "test",
            "revisionId": "rev",
            "body": { "content": [{ "paragraph": { "elements": [
                { "textRun": { "content": "a😀b" } }
            ] } }] }
        });
        let compact = compact_presentation(&presentation, 1, 4);
        assert_eq!(compact["text"], "😀");
        assert_eq!(compact["text_next_offset"], 5);
        assert_eq!(compact["text_complete"], false);
    }

    #[test]
    fn compact_presentation_result_stays_below_manifest_budget() {
        let presentation = json!({
            "presentationId": "doc",
            "title": "bounded",
            "revisionId": "rev",
            "body": { "content": [{ "paragraph": { "elements": [
                { "textRun": { "content": "x".repeat(200_000) } }
            ] } }] }
        });
        let compact = compact_presentation(&presentation, 0, MAX_READ_TEXT_BYTES);
        assert!(serde_json::to_vec(&compact).unwrap().len() < 60_000);
        assert_eq!(compact["text_complete"], false);
    }

    #[test]
    fn operation_input_rejects_unknown_top_level_fields() {
        let error = validate_slides_input(
            "slides.get",
            &json!({ "presentation_id": "doc", "provider_escape": {} }),
        )
        .unwrap_err();
        assert!(matches!(error, FcpError::InvalidRequest { .. }));
    }
}
