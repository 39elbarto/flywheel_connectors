//! Generic Google REST executor substrate.
//!
//! This module centralizes request validation and HTTP mechanics so individual
//! connectors can focus on service semantics instead of rebuilding transport,
//! URL-template expansion, pagination extraction, upload/download routing, and
//! Google error parsing.

#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::{Method, StatusCode};

use crate::auth::GoogleMaterializedAuth;
use crate::{DiscoveryMethod, DiscoverySchema};

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

const MAX_SCHEMA_VALIDATION_DEPTH: usize = 64;

/// Upload mode for methods that expose Discovery `mediaUpload` metadata.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GoogleUploadMode {
    /// `uploadType=media` (bytes-only payload).
    Simple,
    /// `uploadType=multipart` (metadata + media payload in multipart/form-data).
    Multipart,
    /// `uploadType=resumable` (session-init metadata request).
    Resumable,
}

impl GoogleUploadMode {
    #[must_use]
    const fn upload_type(self) -> &'static str {
        match self {
            Self::Simple => "media",
            Self::Multipart => "multipart",
            Self::Resumable => "resumable",
        }
    }
}

/// Upload payload details.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoogleUploadPayload {
    /// Upload mode.
    pub mode: GoogleUploadMode,
    /// MIME type for media bytes.
    pub content_type: String,
    /// Media bytes.
    pub bytes: Vec<u8>,
    /// Optional metadata JSON payload.
    pub metadata: Option<serde_json::Value>,
}

impl GoogleUploadPayload {
    /// Construct a simple media upload payload.
    #[must_use]
    pub fn simple(content_type: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            mode: GoogleUploadMode::Simple,
            content_type: content_type.into(),
            bytes,
            metadata: None,
        }
    }

    /// Construct a multipart upload payload.
    #[must_use]
    pub fn multipart(
        content_type: impl Into<String>,
        bytes: Vec<u8>,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            mode: GoogleUploadMode::Multipart,
            content_type: content_type.into(),
            bytes,
            metadata: Some(metadata),
        }
    }

    /// Construct a resumable upload init payload.
    #[must_use]
    pub fn resumable(
        content_type: impl Into<String>,
        bytes: Vec<u8>,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            mode: GoogleUploadMode::Resumable,
            content_type: content_type.into(),
            bytes,
            metadata: Some(metadata),
        }
    }
}

/// Preferred response decoding mode.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GoogleResponseMode {
    /// Auto-detect from content type and payload shape.
    Auto,
    /// Decode strictly as JSON.
    Json,
    /// Return binary bytes.
    Binary,
}

/// Response body variant.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum GoogleResponseBody {
    /// Empty response body.
    Empty,
    /// JSON response payload.
    Json(serde_json::Value),
    /// Binary response payload.
    Binary(Vec<u8>),
}

impl GoogleResponseBody {
    /// JSON view when payload is JSON.
    #[must_use]
    pub const fn as_json(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Json(value) => Some(value),
            Self::Empty | Self::Binary(_) => None,
        }
    }

    /// Byte-slice view when payload is binary.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Binary(bytes) => Some(bytes.as_slice()),
            Self::Empty | Self::Json(_) => None,
        }
    }
}

/// Normalized Google API error payload.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoogleApiError {
    /// HTTP status code.
    pub status_code: u16,
    /// Top-level message.
    pub message: String,
    /// Optional canonical Google status (`PERMISSION_DENIED`, etc).
    pub status: Option<String>,
    /// Optional reason from the first detailed error.
    pub reason: Option<String>,
    /// Optional domain from the first detailed error.
    pub domain: Option<String>,
    /// Whether the error indicates API not enabled/configured.
    pub access_not_configured_hint: bool,
}

/// Request parameters for one generic Google REST invocation.
#[derive(Debug)]
pub struct GoogleExecuteRequest<'a> {
    /// Normalized method metadata from Discovery.
    pub method: &'a DiscoveryMethod,
    /// Snapshot schema map for request body validation.
    pub schemas: &'a BTreeMap<String, DiscoverySchema>,
    /// Base API URL (for example `https://gmail.googleapis.com/`).
    pub base_url: &'a str,
    /// Parameter map (path/query values by parameter name).
    pub parameters: BTreeMap<String, Vec<String>>,
    /// Optional JSON request body.
    pub body: Option<serde_json::Value>,
    /// Optional upload payload for media-capable methods.
    pub upload: Option<GoogleUploadPayload>,
    /// Response decoding mode.
    pub response_mode: GoogleResponseMode,
    /// Optional materialized auth payload.
    pub auth: Option<&'a GoogleMaterializedAuth>,
    /// Additional headers to add after auth headers.
    pub extra_headers: Vec<(String, String)>,
}

impl<'a> GoogleExecuteRequest<'a> {
    /// Construct a minimal execution request.
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn new(
        method: &'a DiscoveryMethod,
        schemas: &'a BTreeMap<String, DiscoverySchema>,
        base_url: &'a str,
    ) -> Self {
        Self {
            method,
            schemas,
            base_url,
            parameters: BTreeMap::new(),
            body: None,
            upload: None,
            response_mode: GoogleResponseMode::Auto,
            auth: None,
            extra_headers: Vec::new(),
        }
    }
}

/// Execution response with pagination metadata.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoogleExecuteResponse {
    /// HTTP status code.
    pub status_code: u16,
    /// Response headers in lowercase-preserving insertion order.
    pub headers: Vec<(String, String)>,
    /// Decoded response body.
    pub body: GoogleResponseBody,
    /// Extracted pagination token when present (`nextPageToken`).
    pub next_page_token: Option<String>,
}

/// Shared REST execution errors.
#[derive(Debug, thiserror::Error)]
pub enum GoogleRestError {
    /// Unsupported HTTP method in discovery metadata.
    #[error("unsupported http method `{method}`")]
    UnsupportedHttpMethod {
        /// Method string from discovery metadata.
        method: String,
    },

    /// Required parameter missing.
    #[error("missing required parameter `{name}`{location_suffix}")]
    MissingRequiredParameter {
        /// Parameter name.
        name: String,
        /// Optional discovery location (`path`, `query`, ...).
        location: Option<String>,
        /// Cached display suffix.
        location_suffix: String,
    },

    /// Parameter provided with no values.
    #[error("parameter `{name}` must include at least one value")]
    EmptyParameterValue {
        /// Parameter name.
        name: String,
    },

    /// Parameter repeated where discovery metadata marks it non-repeated.
    #[error("parameter `{name}` is not repeatable")]
    InvalidParameterMultiplicity {
        /// Parameter name.
        name: String,
    },

    /// Parameter not declared in discovery metadata.
    #[error("unknown parameter `{name}` for method `{method_key}`")]
    UnknownParameter {
        /// Method key.
        method_key: String,
        /// Parameter name.
        name: String,
    },

    /// Malformed path template.
    #[error("invalid path template `{template}`: {message}")]
    InvalidPathTemplate {
        /// Template string.
        template: String,
        /// Validation failure details.
        message: String,
    },

    /// Missing value for a template path parameter.
    #[error("missing path parameter `{name}` for template `{template}`")]
    MissingPathParameter {
        /// Parameter name.
        name: String,
        /// Template string.
        template: String,
    },

    /// Path traversal guard rejected a segment.
    #[error("path parameter `{name}` contains disallowed segment `{segment}`")]
    PathTraversalRejected {
        /// Parameter name.
        name: String,
        /// Rejected segment value.
        segment: String,
    },

    /// Base URL parse failed.
    #[error("invalid base url `{base_url}`: {message}")]
    InvalidBaseUrl {
        /// Base URL string.
        base_url: String,
        /// Parser error details.
        message: String,
    },

    /// URL join failed.
    #[error("failed to join path `{path}` against base `{base_url}`: {message}")]
    UrlJoin {
        /// Base URL string.
        base_url: String,
        /// Path string.
        path: String,
        /// Parser error details.
        message: String,
    },

    /// Request body is required by schema-aware validation.
    #[error("request body required for schema `{schema}`")]
    MissingRequestBody {
        /// Discovery schema reference.
        schema: String,
    },

    /// Request body provided where the method does not permit one.
    #[error("request body is not allowed for `{http_method}` without upload")]
    BodyNotAllowed {
        /// HTTP method name.
        http_method: String,
    },

    /// Request body failed schema validation.
    #[error("request body validation failed for `{schema}` at `{path}`: {message}")]
    RequestBodyValidation {
        /// Root schema reference.
        schema: String,
        /// JSON path in the payload.
        path: String,
        /// Validation details.
        message: String,
    },

    /// Unknown schema reference.
    #[error("unknown schema reference `{schema}`")]
    UnknownSchemaReference {
        /// Missing schema name.
        schema: String,
    },

    /// Upload mode/path mismatch.
    #[error("invalid upload configuration: {message}")]
    InvalidUploadConfiguration {
        /// Error detail.
        message: String,
    },

    /// Upload content type is invalid.
    #[error("invalid upload content type `{content_type}`: {message}")]
    InvalidUploadContentType {
        /// Content type string.
        content_type: String,
        /// Error detail.
        message: String,
    },

    /// HTTP transport failure.
    #[error("google rest transport failed: {source}")]
    Http {
        /// Upstream reqwest error.
        source: reqwest::Error,
    },

    /// JSON decode failure.
    #[error("failed to decode response json: {source}")]
    JsonDecode {
        /// Upstream serde error.
        source: serde_json::Error,
    },

    /// Non-success Google API response.
    #[error("google api error {status_code}: {message}")]
    Api {
        /// Parsed API error payload.
        error: GoogleApiError,
        /// Cached status code.
        status_code: u16,
        /// Cached message.
        message: String,
    },
}

/// Shared Google REST executor.
#[derive(Debug, Clone)]
pub struct GoogleRestExecutor {
    client: reqwest::Client,
}

impl Default for GoogleRestExecutor {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl GoogleRestExecutor {
    /// Construct an executor with a default HTTP client.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an executor with a caller-provided client.
    #[must_use]
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    /// Execute a normalized Google API method request.
    ///
    /// # Errors
    ///
    /// Returns [`GoogleRestError`] when validation fails, transport fails, or
    /// the response is a non-success Google API error.
    pub async fn execute(
        &self,
        request: &GoogleExecuteRequest<'_>,
    ) -> Result<GoogleExecuteResponse, GoogleRestError> {
        validate_parameters(request.method, &request.parameters)?;
        let method = parse_http_method(&request.method.http_method)?;
        let path_template = resolve_path_template(request.method, request.upload.as_ref())?;
        let rendered_path = render_path_template(path_template, &request.parameters)?;
        let mut url = build_url(request.base_url, &rendered_path)?;
        append_query_parameters(&mut url, request)?;

        let validation_body = body_for_validation(request);
        validate_request_body(
            request.method,
            request.schemas,
            validation_body.as_ref(),
            request.upload.as_ref(),
        )?;

        let mut builder = self.client.request(method.clone(), url);

        if let Some(auth) = request.auth {
            let mut headers = Vec::new();
            auth.apply_headers(&mut headers);
            for (name, value) in headers {
                builder = builder.header(name, value);
            }
        }
        for (name, value) in &request.extra_headers {
            builder = builder.header(name, value);
        }

        builder = apply_payload(builder, &method, request, validation_body.as_ref())?;

        let response = builder
            .send()
            .await
            .map_err(|source| GoogleRestError::Http { source })?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_ascii_lowercase);
        let headers = collect_headers(response.headers());
        let bytes = response
            .bytes()
            .await
            .map_err(|source| GoogleRestError::Http { source })?;

        if !status.is_success() {
            let error = parse_google_api_error(status, &bytes);
            return Err(GoogleRestError::Api {
                status_code: error.status_code,
                message: error.message.clone(),
                error,
            });
        }

        let body = decode_response_body(&bytes, content_type.as_deref(), request.response_mode)?;
        let next_page_token = body
            .as_json()
            .and_then(extract_next_page_token)
            .map(ToString::to_string);

        Ok(GoogleExecuteResponse {
            status_code: status.as_u16(),
            headers,
            body,
            next_page_token,
        })
    }
}

fn parse_http_method(http_method: &str) -> Result<Method, GoogleRestError> {
    match http_method.trim().to_ascii_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "POST" => Ok(Method::POST),
        "PUT" => Ok(Method::PUT),
        "PATCH" => Ok(Method::PATCH),
        "DELETE" => Ok(Method::DELETE),
        other => Err(GoogleRestError::UnsupportedHttpMethod {
            method: other.to_string(),
        }),
    }
}

fn validate_parameters(
    method: &DiscoveryMethod,
    parameters: &BTreeMap<String, Vec<String>>,
) -> Result<(), GoogleRestError> {
    for (name, values) in parameters {
        let Some(param_meta) = method.parameters.get(name) else {
            return Err(GoogleRestError::UnknownParameter {
                method_key: method.key.clone(),
                name: name.clone(),
            });
        };

        if values.is_empty() {
            return Err(GoogleRestError::EmptyParameterValue { name: name.clone() });
        }
        if !param_meta.repeated && values.len() > 1 {
            return Err(GoogleRestError::InvalidParameterMultiplicity { name: name.clone() });
        }
    }

    for (name, param_meta) in &method.parameters {
        if !param_meta.required {
            continue;
        }

        let Some(values) = parameters.get(name) else {
            return Err(GoogleRestError::MissingRequiredParameter {
                name: name.clone(),
                location: param_meta.location.clone(),
                location_suffix: location_suffix(param_meta.location.as_deref()),
            });
        };

        if values.iter().all(|value| value.trim().is_empty()) {
            return Err(GoogleRestError::MissingRequiredParameter {
                name: name.clone(),
                location: param_meta.location.clone(),
                location_suffix: location_suffix(param_meta.location.as_deref()),
            });
        }
    }

    Ok(())
}

fn location_suffix(location: Option<&str>) -> String {
    location.map_or_else(String::new, |value| format!(" in `{value}`"))
}

fn resolve_path_template<'a>(
    method: &'a DiscoveryMethod,
    upload: Option<&GoogleUploadPayload>,
) -> Result<&'a str, GoogleRestError> {
    if let Some(upload) = upload {
        let Some(media_upload) = method.media_upload.as_ref() else {
            return Err(GoogleRestError::InvalidUploadConfiguration {
                message: "method does not expose mediaUpload metadata".to_string(),
            });
        };

        let selected = match upload.mode {
            GoogleUploadMode::Simple | GoogleUploadMode::Multipart => {
                media_upload.simple_path.as_deref()
            }
            GoogleUploadMode::Resumable => media_upload.resumable_path.as_deref(),
        };

        return selected.ok_or_else(|| GoogleRestError::InvalidUploadConfiguration {
            message: format!(
                "upload mode `{}` not supported by method",
                upload.mode.upload_type()
            ),
        });
    }

    Ok(method.canonical_path.as_str())
}

fn render_path_template(
    template: &str,
    parameters: &BTreeMap<String, Vec<String>>,
) -> Result<String, GoogleRestError> {
    if template.trim().is_empty() {
        return Err(GoogleRestError::InvalidPathTemplate {
            template: template.to_string(),
            message: "template must not be empty".to_string(),
        });
    }

    let mut rendered = String::with_capacity(template.len());
    let mut remainder = template;

    while let Some(open_idx) = remainder.find('{') {
        let prefix = &remainder[..open_idx];
        if prefix.contains('}') {
            return Err(GoogleRestError::InvalidPathTemplate {
                template: template.to_string(),
                message: "unmatched `}` in template".to_string(),
            });
        }
        rendered.push_str(prefix);

        let token_start = open_idx + 1;
        let Some(close_rel) = remainder[token_start..].find('}') else {
            return Err(GoogleRestError::InvalidPathTemplate {
                template: template.to_string(),
                message: "missing closing `}`".to_string(),
            });
        };
        let token_end = token_start + close_rel;
        let token = &remainder[token_start..token_end];
        if token.is_empty() {
            return Err(GoogleRestError::InvalidPathTemplate {
                template: template.to_string(),
                message: "empty placeholder token".to_string(),
            });
        }

        let (reserved, name) = token
            .strip_prefix('+')
            .map_or((false, token), |name| (true, name));
        if name.is_empty() {
            return Err(GoogleRestError::InvalidPathTemplate {
                template: template.to_string(),
                message: "empty placeholder name".to_string(),
            });
        }

        let value = first_parameter_value(name, template, parameters)?;
        reject_path_traversal(name, value, reserved)?;
        let encoded = encode_path_value(value, reserved);
        rendered.push_str(&encoded);

        let next = token_end + 1;
        remainder = &remainder[next..];
    }

    if remainder.contains('}') {
        return Err(GoogleRestError::InvalidPathTemplate {
            template: template.to_string(),
            message: "unmatched `}` in template".to_string(),
        });
    }
    rendered.push_str(remainder);

    Ok(rendered)
}

fn first_parameter_value<'a>(
    name: &str,
    template: &str,
    parameters: &'a BTreeMap<String, Vec<String>>,
) -> Result<&'a str, GoogleRestError> {
    let Some(values) = parameters.get(name) else {
        return Err(GoogleRestError::MissingPathParameter {
            name: name.to_string(),
            template: template.to_string(),
        });
    };

    let Some(value) = values.first() else {
        return Err(GoogleRestError::MissingPathParameter {
            name: name.to_string(),
            template: template.to_string(),
        });
    };

    if value.trim().is_empty() {
        return Err(GoogleRestError::MissingPathParameter {
            name: name.to_string(),
            template: template.to_string(),
        });
    }

    Ok(value)
}

fn reject_path_traversal(
    name: &str,
    value: &str,
    reserved_expansion: bool,
) -> Result<(), GoogleRestError> {
    let invalid = if reserved_expansion {
        value
            .split('/')
            .find(|segment| matches!(*segment, "." | ".."))
    } else if matches!(value, "." | "..") {
        Some(value)
    } else {
        None
    };

    if let Some(segment) = invalid {
        return Err(GoogleRestError::PathTraversalRejected {
            name: name.to_string(),
            segment: segment.to_string(),
        });
    }

    Ok(())
}

fn encode_path_value(value: &str, reserved_expansion: bool) -> String {
    if reserved_expansion {
        value
            .split('/')
            .map(encode_path_segment)
            .collect::<Vec<_>>()
            .join("/")
    } else {
        encode_path_segment(value)
    }
}

fn encode_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn build_url(base_url: &str, rendered_path: &str) -> Result<reqwest::Url, GoogleRestError> {
    let base = reqwest::Url::parse(base_url).map_err(|error| GoogleRestError::InvalidBaseUrl {
        base_url: base_url.to_string(),
        message: error.to_string(),
    })?;

    let joined = base
        .join(rendered_path.trim_start_matches('/'))
        .map_err(|error| GoogleRestError::UrlJoin {
            base_url: base_url.to_string(),
            path: rendered_path.to_string(),
            message: error.to_string(),
        })?;

    Ok(joined)
}

fn append_query_parameters(
    url: &mut reqwest::Url,
    request: &GoogleExecuteRequest<'_>,
) -> Result<(), GoogleRestError> {
    let mut pairs = url.query_pairs_mut();

    for (name, values) in &request.parameters {
        let Some(meta) = request.method.parameters.get(name) else {
            return Err(GoogleRestError::UnknownParameter {
                method_key: request.method.key.clone(),
                name: name.clone(),
            });
        };

        let is_path = meta.location.as_deref() == Some("path");
        if is_path {
            continue;
        }

        for value in values {
            pairs.append_pair(name, value);
        }
    }

    if let Some(upload) = request.upload.as_ref() {
        pairs.append_pair("uploadType", upload.mode.upload_type());
    }

    let should_force_media_alt = matches!(request.response_mode, GoogleResponseMode::Binary)
        && request.method.supports_media_download
        && !request.parameters.contains_key("alt");
    if should_force_media_alt {
        pairs.append_pair("alt", "media");
    }

    drop(pairs);
    Ok(())
}

fn body_for_validation(request: &GoogleExecuteRequest<'_>) -> Option<serde_json::Value> {
    request
        .upload
        .as_ref()
        .and_then(|upload| upload.metadata.clone())
        .or_else(|| request.body.clone())
}

fn validate_request_body(
    method: &DiscoveryMethod,
    schemas: &BTreeMap<String, DiscoverySchema>,
    body: Option<&serde_json::Value>,
    upload: Option<&GoogleUploadPayload>,
) -> Result<(), GoogleRestError> {
    let Some(schema_ref) = method.request_ref.as_deref() else {
        return Ok(());
    };

    let requires_body = matches!(method.http_method.as_str(), "POST" | "PUT" | "PATCH")
        || matches!(
            upload.map(|payload| payload.mode),
            Some(GoogleUploadMode::Multipart | GoogleUploadMode::Resumable)
        );

    if body.is_none() && requires_body {
        return Err(GoogleRestError::MissingRequestBody {
            schema: schema_ref.to_string(),
        });
    }

    let Some(value) = body else {
        return Ok(());
    };

    let Some(schema) = schemas.get(schema_ref) else {
        return Err(GoogleRestError::UnknownSchemaReference {
            schema: schema_ref.to_string(),
        });
    };

    validate_schema_value(schema_ref, schema, value, schemas, "$", 0)
}

#[allow(clippy::too_many_lines)]
fn validate_schema_value(
    root_schema_ref: &str,
    schema: &DiscoverySchema,
    value: &serde_json::Value,
    schemas: &BTreeMap<String, DiscoverySchema>,
    path: &str,
    depth: usize,
) -> Result<(), GoogleRestError> {
    if depth > MAX_SCHEMA_VALIDATION_DEPTH {
        return Err(GoogleRestError::RequestBodyValidation {
            schema: root_schema_ref.to_string(),
            path: path.to_string(),
            message: "schema validation depth limit exceeded".to_string(),
        });
    }

    if let Some(ref_name) = schema.ref_name.as_deref() {
        let Some(next_schema) = schemas.get(ref_name) else {
            return Err(GoogleRestError::UnknownSchemaReference {
                schema: ref_name.to_string(),
            });
        };
        return validate_schema_value(
            root_schema_ref,
            next_schema,
            value,
            schemas,
            path,
            depth + 1,
        );
    }

    let treats_as_object = schema.type_name.as_deref() == Some("object")
        || (schema.type_name.is_none()
            && (!schema.properties.is_empty() || !schema.required.is_empty()));

    if treats_as_object {
        let Some(object) = value.as_object() else {
            return Err(GoogleRestError::RequestBodyValidation {
                schema: root_schema_ref.to_string(),
                path: path.to_string(),
                message: "expected object".to_string(),
            });
        };

        for required in &schema.required {
            if !object.contains_key(required) {
                return Err(GoogleRestError::RequestBodyValidation {
                    schema: root_schema_ref.to_string(),
                    path: format!("{path}.{required}"),
                    message: "missing required field".to_string(),
                });
            }
        }

        for (field_name, field_value) in object {
            if let Some(field_schema) = schema.properties.get(field_name) {
                validate_schema_value(
                    root_schema_ref,
                    field_schema,
                    field_value,
                    schemas,
                    &format!("{path}.{field_name}"),
                    depth + 1,
                )?;
                continue;
            }

            if let Some(additional_schema) = schema.additional_properties.as_deref() {
                validate_schema_value(
                    root_schema_ref,
                    additional_schema,
                    field_value,
                    schemas,
                    &format!("{path}.{field_name}"),
                    depth + 1,
                )?;
            }
        }

        return Ok(());
    }

    match schema.type_name.as_deref() {
        Some("array") => {
            let Some(items) = value.as_array() else {
                return Err(GoogleRestError::RequestBodyValidation {
                    schema: root_schema_ref.to_string(),
                    path: path.to_string(),
                    message: "expected array".to_string(),
                });
            };

            if let Some(item_schema) = schema.items.as_deref() {
                for (index, item) in items.iter().enumerate() {
                    validate_schema_value(
                        root_schema_ref,
                        item_schema,
                        item,
                        schemas,
                        &format!("{path}[{index}]"),
                        depth + 1,
                    )?;
                }
            }
            Ok(())
        }
        Some("string") if !value.is_string() => Err(GoogleRestError::RequestBodyValidation {
            schema: root_schema_ref.to_string(),
            path: path.to_string(),
            message: "expected string".to_string(),
        }),
        Some("integer") if !(value.is_i64() || value.is_u64()) => {
            Err(GoogleRestError::RequestBodyValidation {
                schema: root_schema_ref.to_string(),
                path: path.to_string(),
                message: "expected integer".to_string(),
            })
        }
        Some("number") if !value.is_number() => Err(GoogleRestError::RequestBodyValidation {
            schema: root_schema_ref.to_string(),
            path: path.to_string(),
            message: "expected number".to_string(),
        }),
        Some("boolean") if !value.is_boolean() => Err(GoogleRestError::RequestBodyValidation {
            schema: root_schema_ref.to_string(),
            path: path.to_string(),
            message: "expected boolean".to_string(),
        }),
        _ => Ok(()),
    }
}

fn apply_payload(
    mut builder: reqwest::RequestBuilder,
    method: &Method,
    request: &GoogleExecuteRequest<'_>,
    validation_body: Option<&serde_json::Value>,
) -> Result<reqwest::RequestBuilder, GoogleRestError> {
    if let Some(upload) = request.upload.as_ref() {
        match upload.mode {
            GoogleUploadMode::Simple => {
                builder = builder
                    .header(reqwest::header::CONTENT_TYPE, upload.content_type.as_str())
                    .body(upload.bytes.clone());
            }
            GoogleUploadMode::Multipart => {
                let metadata = validation_body
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));

                let metadata_part = reqwest::multipart::Part::text(metadata.to_string())
                    .mime_str("application/json; charset=UTF-8")
                    .map_err(|error| GoogleRestError::InvalidUploadContentType {
                        content_type: "application/json; charset=UTF-8".to_string(),
                        message: error.to_string(),
                    })?;
                let media_part = reqwest::multipart::Part::bytes(upload.bytes.clone())
                    .mime_str(&upload.content_type)
                    .map_err(|error| GoogleRestError::InvalidUploadContentType {
                        content_type: upload.content_type.clone(),
                        message: error.to_string(),
                    })?;

                let form = reqwest::multipart::Form::new()
                    .part("metadata", metadata_part)
                    .part("media", media_part);
                builder = builder.multipart(form);
            }
            GoogleUploadMode::Resumable => {
                let metadata = validation_body
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));
                builder = builder
                    .header("X-Upload-Content-Type", upload.content_type.as_str())
                    .header("X-Upload-Content-Length", upload.bytes.len())
                    .json(&metadata);
            }
        }

        return Ok(builder);
    }

    if let Some(body) = validation_body {
        if matches!(*method, Method::GET | Method::DELETE) {
            return Err(GoogleRestError::BodyNotAllowed {
                http_method: method.as_str().to_string(),
            });
        }
        builder = builder.json(body);
    }

    Ok(builder)
}

fn collect_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = String::from_utf8_lossy(value.as_bytes()).to_string();
            (name.as_str().to_string(), value)
        })
        .collect()
}

fn decode_response_body(
    bytes: &[u8],
    content_type: Option<&str>,
    response_mode: GoogleResponseMode,
) -> Result<GoogleResponseBody, GoogleRestError> {
    if bytes.is_empty() {
        return Ok(GoogleResponseBody::Empty);
    }

    match response_mode {
        GoogleResponseMode::Binary => Ok(GoogleResponseBody::Binary(bytes.to_vec())),
        GoogleResponseMode::Json => serde_json::from_slice(bytes)
            .map(GoogleResponseBody::Json)
            .map_err(|source| GoogleRestError::JsonDecode { source }),
        GoogleResponseMode::Auto => {
            let looks_like_json = content_type.is_some_and(|value| value.contains("json"))
                || matches!(bytes.first(), Some(b'{' | b'['));
            if looks_like_json {
                serde_json::from_slice(bytes).map_or_else(
                    |_| Ok(GoogleResponseBody::Binary(bytes.to_vec())),
                    |value| Ok(GoogleResponseBody::Json(value)),
                )
            } else {
                Ok(GoogleResponseBody::Binary(bytes.to_vec()))
            }
        }
    }
}

fn extract_next_page_token(body: &serde_json::Value) -> Option<&str> {
    body.get("nextPageToken")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            body.get("next_page_token")
                .and_then(serde_json::Value::as_str)
        })
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GoogleErrorEnvelope {
    #[serde(default)]
    error: Option<GoogleErrorBody>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GoogleErrorBody {
    #[serde(default)]
    code: Option<u16>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    errors: Vec<GoogleErrorDetail>,
}

#[derive(Debug, Clone, serde::Deserialize)]
struct GoogleErrorDetail {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    domain: Option<String>,
}

fn parse_google_api_error(status: StatusCode, body: &[u8]) -> GoogleApiError {
    let fallback_message = String::from_utf8_lossy(body).trim().to_string();

    if let Ok(envelope) = serde_json::from_slice::<GoogleErrorEnvelope>(body)
        && let Some(error) = envelope.error
    {
        let message = error
            .message
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()));
        let reason = error
            .errors
            .first()
            .and_then(|detail| detail.reason.clone());
        let domain = error
            .errors
            .first()
            .and_then(|detail| detail.domain.clone());
        let access_not_configured_hint = reason.as_deref() == Some("accessNotConfigured")
            || message.contains("accessNotConfigured")
            || message.contains("has not been used in project");

        return GoogleApiError {
            status_code: error.code.unwrap_or_else(|| status.as_u16()),
            message,
            status: error.status,
            reason,
            domain,
            access_not_configured_hint,
        };
    }

    GoogleApiError {
        status_code: status.as_u16(),
        message: if fallback_message.is_empty() {
            format!("HTTP {}", status.as_u16())
        } else {
            format!("HTTP {}: {fallback_message}", status.as_u16())
        },
        status: None,
        reason: None,
        domain: None,
        access_not_configured_hint: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method_fixture(
        http_method: &str,
        canonical_path: &str,
        parameters: BTreeMap<String, crate::DiscoveryParameter>,
    ) -> DiscoveryMethod {
        DiscoveryMethod {
            key: "users.messages.list".to_string(),
            id: "gmail.users.messages.list".to_string(),
            http_method: http_method.to_string(),
            path: canonical_path.to_string(),
            flat_path: None,
            canonical_path: canonical_path.to_string(),
            resource_path: vec!["users".to_string(), "messages".to_string()],
            description: None,
            scopes: Vec::new(),
            request_ref: None,
            response_ref: None,
            parameters,
            supports_media_download: false,
            supports_media_upload: false,
            media_upload: None,
        }
    }

    fn path_param(required: bool) -> crate::DiscoveryParameter {
        crate::DiscoveryParameter {
            location: Some("path".to_string()),
            required,
            repeated: false,
            type_name: Some("string".to_string()),
            format: None,
            description: None,
        }
    }

    fn query_parameter_meta(required: bool, repeated: bool) -> crate::DiscoveryParameter {
        crate::DiscoveryParameter {
            location: Some("query".to_string()),
            required,
            repeated,
            type_name: Some("string".to_string()),
            format: None,
            description: None,
        }
    }

    fn schema_object(required: Vec<&str>) -> DiscoverySchema {
        DiscoverySchema {
            type_name: Some("object".to_string()),
            format: None,
            description: None,
            required: required.into_iter().map(str::to_string).collect(),
            enum_values: Vec::new(),
            properties: BTreeMap::new(),
            items: None,
            ref_name: None,
            additional_properties: None,
        }
    }

    #[test]
    fn render_path_template_encodes_and_preserves_reserved_slashes() {
        let params = BTreeMap::from([
            ("userId".to_string(), vec!["me@example.com".to_string()]),
            (
                "name".to_string(),
                vec!["projects/demo/topics/a/b".to_string()],
            ),
        ]);

        let rendered = render_path_template("gmail/v1/users/{userId}/{+name}", &params)
            .expect("rendered path");

        assert_eq!(
            rendered,
            "gmail/v1/users/me%40example.com/projects/demo/topics/a/b"
        );
    }

    #[test]
    fn render_path_template_rejects_traversal_segments() {
        let params = BTreeMap::from([("resource".to_string(), vec!["../etc".to_string()])]);

        let error = render_path_template("gmail/v1/{+resource}", &params)
            .expect_err("traversal should be rejected");

        assert!(matches!(
            error,
            GoogleRestError::PathTraversalRejected { .. }
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn execute_rejects_missing_required_parameter() {
        let mut params = BTreeMap::new();
        params.insert("userId".to_string(), path_param(true));

        let method = method_fixture("GET", "gmail/v1/users/{userId}/messages", params);
        let schemas = BTreeMap::new();
        let executor = GoogleRestExecutor::new();

        let request = GoogleExecuteRequest::new(&method, &schemas, "https://gmail.googleapis.com/");
        let error = executor
            .execute(&request)
            .await
            .expect_err("required parameter should fail");

        assert!(matches!(
            error,
            GoogleRestError::MissingRequiredParameter {
                name,
                location,
                ..
            } if name == "userId" && location.as_deref() == Some("path")
        ));
    }

    #[test]
    fn append_query_parameters_adds_upload_type_and_alt_media() {
        let mut method_params = BTreeMap::new();
        method_params.insert("userId".to_string(), path_param(true));
        method_params.insert("maxResults".to_string(), query_parameter_meta(false, false));
        let mut method = method_fixture("GET", "gmail/v1/users/{userId}/messages", method_params);
        method.supports_media_download = true;
        let schemas = BTreeMap::new();

        let mut request =
            GoogleExecuteRequest::new(&method, &schemas, "https://gmail.googleapis.com/");
        request
            .parameters
            .insert("userId".to_string(), vec!["me".to_string()]);
        request
            .parameters
            .insert("maxResults".to_string(), vec!["10".to_string()]);

        request.upload = Some(GoogleUploadPayload::simple(
            "application/octet-stream",
            b"bytes".to_vec(),
        ));
        request.response_mode = GoogleResponseMode::Binary;

        let rendered_path =
            render_path_template(&request.method.canonical_path, &request.parameters)
                .expect("path");
        let mut url = build_url(request.base_url, &rendered_path).expect("url");
        append_query_parameters(&mut url, &request).expect("query append");
        let query = url.query().unwrap_or_default().to_string();

        assert!(query.contains("maxResults=10"));
        assert!(query.contains("uploadType=media"));
        assert!(query.contains("alt=media"));
    }

    #[test]
    fn resolve_upload_path_uses_media_upload_metadata() {
        let mut method = method_fixture("POST", "drive/v3/files", BTreeMap::new());
        method.request_ref = Some("FileMetadata".to_string());
        method.supports_media_upload = true;
        method.media_upload = Some(crate::DiscoveryMediaUpload {
            accept: vec!["*/*".to_string()],
            max_size: None,
            simple_path: Some("upload/drive/v3/files".to_string()),
            resumable_path: Some("upload/drive/v3/files/resumable".to_string()),
        });

        let simple = resolve_path_template(
            &method,
            Some(&GoogleUploadPayload::simple(
                "application/octet-stream",
                vec![1, 2, 3],
            )),
        )
        .expect("simple path");
        let resumable = resolve_path_template(
            &method,
            Some(&GoogleUploadPayload::resumable(
                "application/octet-stream",
                vec![1, 2, 3],
                serde_json::json!({"name": "demo"}),
            )),
        )
        .expect("resumable path");

        assert_eq!(simple, "upload/drive/v3/files");
        assert_eq!(resumable, "upload/drive/v3/files/resumable");
    }

    #[test]
    fn decode_response_body_auto_extracts_json_and_binary_modes() {
        let json_body = serde_json::json!({"nextPageToken":"page-2","items":[]});
        let json_bytes = serde_json::to_vec(&json_body).expect("serialize json");
        let decoded_json = decode_response_body(
            &json_bytes,
            Some("application/json; charset=utf-8"),
            GoogleResponseMode::Auto,
        )
        .expect("decode json");
        assert!(matches!(decoded_json, GoogleResponseBody::Json(_)));
        assert_eq!(
            extract_next_page_token(decoded_json.as_json().expect("json")),
            Some("page-2")
        );

        let decoded_binary = decode_response_body(
            b"raw-bytes",
            Some("application/octet-stream"),
            GoogleResponseMode::Binary,
        )
        .expect("decode binary");
        assert_eq!(decoded_binary.as_bytes(), Some(&b"raw-bytes"[..]));
    }

    #[fcp_async_core::runtime::test]
    async fn execute_validates_body_required_fields() {
        let mut method = method_fixture("POST", "gmail/v1/users/me/messages/send", BTreeMap::new());
        method.request_ref = Some("SendRequest".to_string());

        let schemas = BTreeMap::from([("SendRequest".to_string(), schema_object(vec!["raw"]))]);

        let mut request =
            GoogleExecuteRequest::new(&method, &schemas, "https://gmail.googleapis.com/");
        request.body = Some(serde_json::json!({}));

        let error = GoogleRestExecutor::new()
            .execute(&request)
            .await
            .expect_err("missing required schema field should fail");

        assert!(matches!(
            error,
            GoogleRestError::RequestBodyValidation {
                schema,
                path,
                message,
            } if schema == "SendRequest" && path == "$.raw" && message == "missing required field"
        ));
    }

    #[test]
    fn parse_google_error_extracts_access_not_configured_hint() {
        let body = serde_json::json!({
            "error": {
                "code": 403,
                "message": "Access Not Configured. Gmail API has not been used in project 123 before or it is disabled.",
                "status": "PERMISSION_DENIED",
                "errors": [{
                    "reason": "accessNotConfigured",
                    "domain": "usageLimits"
                }]
            }
        });
        let bytes = serde_json::to_vec(&body).expect("serialize");
        let parsed = parse_google_api_error(StatusCode::FORBIDDEN, &bytes);

        assert_eq!(parsed.status_code, 403);
        assert_eq!(parsed.reason.as_deref(), Some("accessNotConfigured"));
        assert_eq!(parsed.domain.as_deref(), Some("usageLimits"));
        assert_eq!(parsed.status.as_deref(), Some("PERMISSION_DENIED"));
        assert!(parsed.access_not_configured_hint);
    }
}
