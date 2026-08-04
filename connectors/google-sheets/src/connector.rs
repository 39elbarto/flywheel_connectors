//! FCP Google Sheets Connector implementation.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use fcp_google_discovery::auth::{GoogleAuthSelection, GoogleMaterializedAuth};
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken,
    CapabilityVerifier, ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest,
    HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection, OperationId, OperationInfo,
    RiskLevel, SafetyTier,
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::SheetsClient;
use crate::types::{BatchUpdateValuesRequest, Spreadsheet, ValueRange};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const MAX_RANGES: usize = 100;
const MAX_BATCH_REQUESTS: usize = 100;
const MAX_CELLS: usize = 50_000;
/// Provider-bound JSON bodies must fit below the shared transport frame after
/// the invoke and capability envelopes are added.
const MAX_PAYLOAD_BYTES: usize = 48 * 1024;
const MAX_RANGE_QUERY_BYTES: usize = 16_384;
/// Leaves headroom for the JSON-RPC and InvokeResponse envelopes inside the
/// shared 65,536-byte native host frame.
const MAX_OPERATION_RESULT_BYTES: usize = 48 * 1024;
const DEFAULT_PAGE_ROWS: u32 = 64;
const MAX_PAGE_ROWS: u32 = 1_000;
const DEFAULT_CHUNK_RANGES: usize = 10;
const MAX_CHUNK_RANGES: usize = 25;
const METADATA_FIELDS: &str = "spreadsheetId,properties,sheets(properties),namedRanges(namedRangeId,name,range),spreadsheetUrl,developerMetadata(metadataId,location,visibility)";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ValuesPageCursor {
    version: u8,
    target_hash: String,
    next_row: u32,
    end_row: u32,
    page_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ValuesChunkCursor {
    version: u8,
    target_hash: String,
    next_chunk: usize,
    total_chunks: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExplicitRowRange {
    sheet_prefix: String,
    start_column: String,
    start_row: u32,
    end_column: String,
    end_row: u32,
}

impl ExplicitRowRange {
    fn page_range(&self, start_row: u32, row_count: u32) -> FcpResult<String> {
        let end_row = start_row
            .checked_add(row_count.saturating_sub(1))
            .ok_or_else(|| invalid("paged row boundary overflow"))?
            .min(self.end_row);
        Ok(format!(
            "{}{}{}:{}{}",
            self.sheet_prefix, self.start_column, start_row, self.end_column, end_row
        ))
    }
}

#[derive(Clone)]
struct AppendReceipt {
    payload_hash: String,
    output: serde_json::Value,
}

fn is_local_test_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

fn host_is_sheets_googleapis(host: &str) -> bool {
    host.eq_ignore_ascii_case("sheets.googleapis.com")
}

/// Validate a google-sheets `base_url` override.
///
/// The Sheets client concatenates this string into downstream request URLs, so
/// only the Sheets API host is accepted outside local test listeners.
fn validate_sheets_base_url(raw: &str) -> FcpResult<String> {
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
    if !local && !host_is_sheets_googleapis(host) {
        return Err(FcpError::InvalidRequest {
            code: 1003,
            message: format!(
                "base_url host must target sheets.googleapis.com (localhost/127.0.0.1/::1 allowed for tests): {host}"
            ),
        });
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn sheets_spreadsheet_resource_uri(spreadsheet_id: &str) -> String {
    format!("google-sheets:spreadsheet:{spreadsheet_id}")
}

fn resource_uris_for_operation(
    operation: &str,
    input: &serde_json::Value,
) -> FcpResult<Vec<String>> {
    match operation {
        "sheets.get_spreadsheet"
        | "sheets.get_values"
        | "sheets.get_values_page"
        | "sheets.batch_get_values"
        | "sheets.update_values"
        | "sheets.batch_update_values"
        | "sheets.batch_update_values_chunked"
        | "sheets.append_values"
        | "sheets.clear_values"
        | "sheets.batch_update_spreadsheet" => {
            let spreadsheet_id = require_str(input, "spreadsheet_id")?;
            Ok(vec![sheets_spreadsheet_resource_uri(spreadsheet_id)])
        }
        "sheets.copy_sheet" => {
            let spreadsheet_id = require_str(input, "spreadsheet_id")?;
            let destination = require_str(input, "destination_spreadsheet_id")?;
            Ok(vec![
                sheets_spreadsheet_resource_uri(spreadsheet_id),
                sheets_spreadsheet_resource_uri(destination),
            ])
        }
        _ => Ok(Vec::new()),
    }
}

/// FCP Google Sheets Connector.
pub struct SheetsConnector {
    base: Arc<BaseConnector>,
    client: Option<SheetsClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<fcp_core::SessionId>,
    append_receipts: Mutex<HashMap<String, AppendReceipt>>,
    page_count: AtomicU64,
    chunk_count: AtomicU64,
}

impl SheetsConnector {
    /// Content-free cumulative provider counters for invocation telemetry.
    #[must_use]
    pub fn provider_telemetry(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
        self.client
            .as_ref()
            .map_or((0, 0, 0, 0, 0, 0, 0, 0), |client| {
                (
                    client.total_requests(),
                    client.provider_total_us(),
                    0,
                    client.rate_limit_count(),
                    client.provider_request_bytes(),
                    client.provider_response_bytes(),
                    self.page_count.load(Ordering::Relaxed),
                    self.chunk_count.load(Ordering::Relaxed),
                )
            })
    }

    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static(
                "google-sheets",
            ))),
            client: None,
            verifier: None,
            session_id: None,
            append_receipts: Mutex::new(HashMap::new()),
            page_count: AtomicU64::new(0),
            chunk_count: AtomicU64::new(0),
        }
    }

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
            SheetsClient::new_with_auth(materialized).map_err(|e| FcpError::Internal {
                message: format!("Failed to create Sheets client: {e}"),
            })?;
        if let Some(value) = params.get("base_url") {
            let base_url = value.as_str().ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "`base_url` must be a string".into(),
            })?;
            client = client.with_base_url(validate_sheets_base_url(base_url)?);
        }

        let auth_label = client.auth_redacted_label();
        self.client = Some(client);
        self.base.set_configured(true);
        info!(auth = %auth_label, status, "Google Sheets connector configured");

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
        let mut snapshot = if self.client.is_some() {
            HealthSnapshot::ready()
        } else {
            HealthSnapshot::degraded("not_configured")
        };
        let metrics = self.base.metrics();
        snapshot.details = Some(json!({
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }));
        serde_json::to_value(snapshot).map_err(|error| FcpError::Internal {
            message: format!("Failed to serialize health response: {error}"),
        })
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
                    "sheets.get_spreadsheet",
                    "Get bounded spreadsheet metadata, tabs, ranges, filters, charts, and developer metadata",
                    object_schema(&["spreadsheet_id"]),
                    object_schema(&["spreadsheet"]),
                    "sheets.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    hint("Inspect spreadsheet structure before reading or changing it."),
                ),
                op_info(
                    "sheets.get_values",
                    "Read one range with explicit render choices",
                    object_schema(&["spreadsheet_id", "range"]),
                    object_schema(&["values"]),
                    "sheets.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    hint(
                        "Read a bounded A1 range; choose formatted values, raw values, or formulas.",
                    ),
                ),
                op_info(
                    "sheets.get_values_page",
                    "Read one explicit row-bounded A1 range through deterministic bounded pages",
                    object_schema(&["spreadsheet_id", "range"]),
                    object_schema(&["values", "page"]),
                    "sheets.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    hint(
                        "Use for ranges that may not fit one FCP frame; pass the returned page_token unchanged.",
                    ),
                ),
                op_info(
                    "sheets.batch_get_values",
                    "Read up to 100 ranges with explicit render choices",
                    object_schema(&["spreadsheet_id", "ranges"]),
                    object_schema(&["value_ranges"]),
                    "sheets.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    hint("Read several bounded A1 ranges efficiently."),
                ),
                op_info(
                    "sheets.update_values",
                    "Write cell values to a range",
                    object_schema(&["spreadsheet_id", "range", "values"]),
                    object_schema(&["updated_cells"]),
                    "sheets.values.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    hint("Write a bounded two-dimensional value array."),
                ),
                op_info(
                    "sheets.batch_update_values",
                    "Atomically update up to 100 value ranges",
                    object_schema(&["spreadsheet_id", "data"]),
                    object_schema(&["total_updated_cells"]),
                    "sheets.values.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    hint("Apply related value and formula changes atomically."),
                ),
                op_info(
                    "sheets.batch_update_values_chunked",
                    "Update independent value ranges in explicit verified chunks with partial-progress receipts",
                    object_schema(&["spreadsheet_id", "data", "confirm_independent_chunks"]),
                    object_schema(&["status", "completed_chunks", "readback"]),
                    "sheets.values.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    hint(
                        "Use only when each range is independently applicable and partial progress is acceptable.",
                    ),
                ),
                op_info(
                    "sheets.append_values",
                    "Append rows once per connector-session idempotency key",
                    object_schema(&["spreadsheet_id", "range", "values", "idempotency_key"]),
                    object_schema(&["table_range"]),
                    "sheets.values.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::BestEffort,
                    hint("Append new rows and reuse the same idempotency key when retrying."),
                ),
                op_info(
                    "sheets.clear_values",
                    "Preflight, confirm, clear, and read back one bounded range",
                    object_schema(&["spreadsheet_id", "range", "confirm_clear"]),
                    json!({ "type": "object" }),
                    "sheets.values.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    hint("Clear values only after reviewing the returned preflight values."),
                ),
                op_info(
                    "sheets.create_spreadsheet",
                    "Create a spreadsheet with bounded initial tabs",
                    object_schema(&["title"]),
                    object_schema(&["spreadsheet"]),
                    "sheets.structure.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    hint("Create a new spreadsheet and optional initial tabs."),
                ),
                op_info(
                    "sheets.copy_sheet",
                    "Copy one tab to another spreadsheet",
                    object_schema(&["spreadsheet_id", "sheet_id", "destination_spreadsheet_id"]),
                    object_schema(&["sheet"]),
                    "sheets.structure.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    hint("Copy a tab when both source and destination spreadsheet IDs are known."),
                ),
                op_info(
                    "sheets.batch_update_spreadsheet",
                    "Apply an allowlisted, validated structural batch atomically",
                    object_schema(&["spreadsheet_id", "requests"]),
                    object_schema(&["preflight", "response", "readback"]),
                    "sheets.structure.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::BestEffort,
                    hint(
                        "Apply formatting, tab, dimension, filter, protection, chart, pivot, or metadata changes.",
                    ),
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
        let intro = self.handle_introspect().await?;
        let cap_str = intro
            .get("operations")
            .and_then(|ops| ops.as_array())
            .and_then(|ops| {
                ops.iter()
                    .find(|op| op.get("id").and_then(|id| id.as_str()) == Some(operation))
            })
            .and_then(|op| op.get("capability"))
            .and_then(|cap| cap.as_str())
            .ok_or_else(|| FcpError::OperationNotGranted {
                operation: operation.into(),
            })?;
        let cap_id: CapabilityId = cap_str.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1002,
            message: format!("Invalid capability ID for operation {operation}"),
        })?;
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let verifier = self.verifier.as_ref().ok_or(FcpError::NotConfigured)?;
        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1001,
                message: "Missing 'capability_token' field".into(),
            })?;
        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid capability_token format: {e}"),
            })?;
        let resource_uris = resource_uris_for_operation(operation, &input)?;
        verifier.verify_bound(token, &cap_id, &op_id, &resource_uris)?;

        match operation {
            "sheets.get_spreadsheet" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let ranges = optional_ranges(&input, "ranges")?;
                let include_grid_data = input
                    .get("include_grid_data")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                if include_grid_data {
                    return Err(invalid(
                        "metadata reads never include grid data; use sheets.get_values_page with an explicit row-bounded A1 range",
                    ));
                }
                let ss = client
                    .get_spreadsheet_with_options(
                        spreadsheet_id,
                        &ranges,
                        include_grid_data,
                        Some(METADATA_FIELDS),
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                bounded_result(
                    json!({ "spreadsheet": ss }),
                    "metadata result is too large; request fewer metadata ranges or fields",
                )
            }
            "sheets.get_values" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let range = validate_range(require_str(&input, "range")?)?;
                let (major, render, date_time) = read_options(&input)?;
                let vr = client
                    .get_values_with_options(spreadsheet_id, range, major, render, date_time)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                bounded_result(
                    json!({ "range": vr.range, "values": vr.values }),
                    "value result is too large; use sheets.get_values_page",
                )
            }
            "sheets.get_values_page" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let requested_range = validate_range(require_str(&input, "range")?)?;
                let parsed_range = parse_explicit_row_range(requested_range)?;
                let (major, render, date_time) = read_options(&input)?;
                let requested_page_rows = input
                    .get("page_size_rows")
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|value| u32::try_from(value).ok())
                            .filter(|value| (1..=MAX_PAGE_ROWS).contains(value))
                            .ok_or_else(|| {
                                invalid(format!("'page_size_rows' must be 1..={MAX_PAGE_ROWS}"))
                            })
                    })
                    .transpose()?
                    .unwrap_or(DEFAULT_PAGE_ROWS);
                let target_hash = values_page_target_hash(
                    spreadsheet_id,
                    requested_range,
                    major,
                    render,
                    date_time,
                    requested_page_rows,
                );
                let cursor = input
                    .get("page_token")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| invalid("'page_token' must be a string"))
                            .and_then(decode_values_page_cursor)
                    })
                    .transpose()?;
                let (start_row, page_index) = if let Some(cursor) = cursor {
                    if cursor.version != 1
                        || cursor.target_hash != target_hash
                        || cursor.end_row != parsed_range.end_row
                        || cursor.next_row < parsed_range.start_row
                        || cursor.next_row > parsed_range.end_row
                    {
                        return Err(invalid(
                            "page_token does not match the requested spreadsheet, range, or render options",
                        ));
                    }
                    (cursor.next_row, cursor.page_index)
                } else {
                    (parsed_range.start_row, 0)
                };
                let remaining_rows = parsed_range
                    .end_row
                    .saturating_sub(start_row)
                    .saturating_add(1);
                let mut page_rows = requested_page_rows.min(remaining_rows);
                let (output, consumed_rows) = loop {
                    let provider_range = parsed_range.page_range(start_row, page_rows)?;
                    let vr = match client
                        .get_values_with_options(
                            spreadsheet_id,
                            &provider_range,
                            major,
                            render,
                            date_time,
                        )
                        .await
                    {
                        Ok(value) => value,
                        Err(crate::error::SheetsError::Api {
                            status_code: 413, ..
                        }) if page_rows > 1 => {
                            page_rows = (page_rows / 2).max(1);
                            continue;
                        }
                        Err(error) => return Err(error.to_fcp_error()),
                    };
                    let next_row = start_row.saturating_add(page_rows);
                    let next_page_token = if next_row <= parsed_range.end_row {
                        Some(encode_values_page_cursor(&ValuesPageCursor {
                            version: 1,
                            target_hash: target_hash.clone(),
                            next_row,
                            end_row: parsed_range.end_row,
                            page_index: page_index.saturating_add(1),
                        })?)
                    } else {
                        None
                    };
                    let candidate = json!({
                        "requested_range": requested_range,
                        "range": vr.range,
                        "major_dimension": major,
                        "values": vr.values,
                        "page": {
                            "page_index": page_index,
                            "start_row": start_row,
                            "end_row": start_row.saturating_add(page_rows).saturating_sub(1),
                            "row_span": page_rows,
                            "complete": next_page_token.is_none(),
                            "page_token": next_page_token,
                        }
                    });
                    if serialized_len(&candidate)? <= MAX_OPERATION_RESULT_BYTES {
                        break (candidate, page_rows);
                    }
                    if page_rows == 1 {
                        return Err(invalid(format!(
                            "one requested row exceeds the {MAX_OPERATION_RESULT_BYTES}-byte connector result budget"
                        )));
                    }
                    page_rows = (page_rows / 2).max(1);
                };
                debug_assert_eq!(consumed_rows, page_rows);
                self.page_count.fetch_add(1, Ordering::Relaxed);
                Ok(output)
            }
            "sheets.batch_get_values" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let ranges = required_ranges(&input, "ranges")?;
                let (major, render, date_time) = read_options(&input)?;
                let response = client
                    .batch_get_values(spreadsheet_id, &ranges, major, render, date_time)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                bounded_result(
                    json!({
                        "spreadsheet_id": response.get("spreadsheetId").cloned().unwrap_or(json!(spreadsheet_id)),
                        "value_ranges": response.get("valueRanges").cloned().unwrap_or_else(|| json!([])),
                    }),
                    "batch value result is too large; use sheets.get_values_page for each explicit range",
                )
            }
            "sheets.update_values" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let range = validate_range(require_str(&input, "range")?)?;
                let values = validated_values(&input, "values")?;
                let ur = client
                    .update_values(spreadsheet_id, range, values)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({
                    "updated_range": ur.updated_range,
                    "updated_cells": ur.updated_cells,
                    "updated_rows": ur.updated_rows,
                }))
            }
            "sheets.batch_update_values" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let data = validated_value_ranges(&input)?;
                let request = BatchUpdateValuesRequest {
                    value_input_option: value_input_option(&input)?.to_string(),
                    data,
                    include_values_in_response: input
                        .get("include_values_in_response")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                    response_value_render_option: optional_enum(
                        &input,
                        "response_value_render_option",
                        &["FORMATTED_VALUE", "UNFORMATTED_VALUE", "FORMULA"],
                    )?
                    .map(str::to_string),
                    response_date_time_render_option: optional_enum(
                        &input,
                        "response_date_time_render_option",
                        &["SERIAL_NUMBER", "FORMATTED_STRING"],
                    )?
                    .map(str::to_string),
                };
                let response = client
                    .batch_update_values(spreadsheet_id, &request)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({
                    "spreadsheet_id": response.spreadsheet_id,
                    "total_updated_rows": response.total_updated_rows,
                    "total_updated_columns": response.total_updated_columns,
                    "total_updated_cells": response.total_updated_cells,
                    "total_updated_sheets": response.total_updated_sheets,
                }))
            }
            "sheets.batch_update_values_chunked" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                require_confirmation(&input, "confirm_independent_chunks")?;
                let data = validated_value_ranges(&input)?;
                if data.iter().any(|range| range.major_dimension != "ROWS") {
                    return Err(invalid(
                        "chunked value writes require major_dimension=ROWS for deterministic batch readback",
                    ));
                }
                let chunk_size = input
                    .get("chunk_size_ranges")
                    .map(|value| {
                        value
                            .as_u64()
                            .and_then(|value| usize::try_from(value).ok())
                            .filter(|value| (1..=MAX_CHUNK_RANGES).contains(value))
                            .ok_or_else(|| {
                                invalid(format!(
                                    "'chunk_size_ranges' must be 1..={MAX_CHUNK_RANGES}"
                                ))
                            })
                    })
                    .transpose()?
                    .unwrap_or(DEFAULT_CHUNK_RANGES);
                let value_input_option = value_input_option(&input)?.to_string();
                let target_hash = values_chunk_target_hash(
                    spreadsheet_id,
                    &data,
                    &value_input_option,
                    chunk_size,
                )?;
                let total_chunks = data.len().div_ceil(chunk_size);
                let cursor = input
                    .get("resume_token")
                    .map(|value| {
                        value
                            .as_str()
                            .ok_or_else(|| invalid("'resume_token' must be a string"))
                            .and_then(decode_values_chunk_cursor)
                    })
                    .transpose()?;
                let start_chunk = if let Some(cursor) = cursor {
                    if cursor.version != 1
                        || cursor.target_hash != target_hash
                        || cursor.total_chunks != total_chunks
                        || cursor.next_chunk >= total_chunks
                    {
                        return Err(invalid(
                            "resume_token does not match the spreadsheet, data, options, or chunk plan",
                        ));
                    }
                    cursor.next_chunk
                } else {
                    0
                };
                let mut completed_chunks = Vec::new();
                let mut completed_range_count = 0_usize;
                let mut total_updated_cells = 0_u64;
                for chunk_index in start_chunk..total_chunks {
                    let start = chunk_index.saturating_mul(chunk_size);
                    let end = start.saturating_add(chunk_size).min(data.len());
                    let chunk = data[start..end].to_vec();
                    self.chunk_count.fetch_add(1, Ordering::Relaxed);
                    let request = BatchUpdateValuesRequest {
                        value_input_option: value_input_option.clone(),
                        data: chunk.clone(),
                        include_values_in_response: false,
                        response_value_render_option: None,
                        response_date_time_render_option: None,
                    };
                    let response = match client.batch_update_values(spreadsheet_id, &request).await
                    {
                        Ok(response) => response,
                        Err(error) => {
                            let uncertain = error.is_retryable();
                            let resume_token = if uncertain {
                                None
                            } else {
                                Some(encode_values_chunk_cursor(&ValuesChunkCursor {
                                    version: 1,
                                    target_hash: target_hash.clone(),
                                    next_chunk: chunk_index,
                                    total_chunks,
                                })?)
                            };
                            return Ok(json!({
                                "status": if uncertain { "outcome_uncertain" } else { "provider_rejected" },
                                "completed_chunks": completed_chunks,
                                "completed_range_count": completed_range_count,
                                "failed_chunk": chunk_index,
                                "failed_range_indexes": (start..end).collect::<Vec<_>>(),
                                "readback": {
                                    "required": uncertain,
                                    "range_indexes": (start..end).collect::<Vec<_>>(),
                                },
                                "resume_safe": !uncertain,
                                "resume_token": resume_token,
                                "provider_error_class": if uncertain { "transport_or_retryable" } else { "rejected" },
                            }));
                        }
                    };
                    total_updated_cells =
                        total_updated_cells.saturating_add(u64::from(response.total_updated_cells));
                    let ranges = chunk
                        .iter()
                        .map(|entry| entry.range.clone())
                        .collect::<Vec<_>>();
                    let Ok(readback) = client
                        .batch_get_values(
                            spreadsheet_id,
                            &ranges,
                            "ROWS",
                            "FORMULA",
                            "SERIAL_NUMBER",
                        )
                        .await
                    else {
                        return Ok(json!({
                            "status": "applied_unverified",
                            "completed_chunks": completed_chunks,
                            "completed_range_count": completed_range_count,
                            "unverified_chunk": chunk_index,
                            "readback": {
                                "required": true,
                                "range_indexes": (start..end).collect::<Vec<_>>(),
                            },
                            "resume_safe": false,
                            "resume_token": null,
                        }));
                    };
                    let verified_range_count = verify_chunk_readback(&chunk, &readback);
                    if verified_range_count != chunk.len() {
                        return Ok(json!({
                            "status": "applied_unverified",
                            "completed_chunks": completed_chunks,
                            "completed_range_count": completed_range_count,
                            "unverified_chunk": chunk_index,
                            "readback": {
                                "required": true,
                                "verified_range_count": verified_range_count,
                                "range_count": chunk.len(),
                                "range_indexes": (start..end).collect::<Vec<_>>(),
                            },
                            "resume_safe": false,
                            "resume_token": null,
                        }));
                    }
                    completed_chunks.push(chunk_index);
                    completed_range_count = completed_range_count.saturating_add(chunk.len());
                }
                let output = json!({
                    "status": "applied_and_verified",
                    "completed_chunks": completed_chunks,
                    "completed_range_count": completed_range_count,
                    "total_updated_cells": total_updated_cells,
                    "readback": {
                        "required": false,
                        "verified_range_count": completed_range_count,
                    },
                    "resume_safe": false,
                    "resume_token": null,
                });
                if serialized_len(&output)? > MAX_OPERATION_RESULT_BYTES {
                    return Err(invalid("chunk receipt exceeds connector result budget"));
                }
                Ok(output)
            }
            "sheets.append_values" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let range = validate_range(require_str(&input, "range")?)?;
                let values = validated_values(&input, "values")?;
                let idempotency_key =
                    validate_idempotency_key(require_str(&input, "idempotency_key")?)?;
                let payload_hash = append_payload_hash(spreadsheet_id, range, &values)?;
                {
                    let receipts = self
                        .append_receipts
                        .lock()
                        .map_err(|_| FcpError::Internal {
                            message: "append idempotency cache lock poisoned".into(),
                        })?;
                    if let Some(receipt) = receipts.get(idempotency_key).cloned() {
                        if receipt.payload_hash != payload_hash {
                            return Err(invalid(
                                "idempotency_key was already used for a different append payload",
                            ));
                        }
                        let mut output = receipt.output;
                        output["replayed"] = json!(true);
                        return Ok(output);
                    }
                    if receipts.len() >= 10_000 {
                        return Err(invalid(
                            "append idempotency receipt limit reached; restart the connector before using new keys",
                        ));
                    }
                }
                let ar = client
                    .append_values(spreadsheet_id, range, values)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let output = json!({
                    "table_range": ar.table_range,
                    "updates": ar.updates,
                    "idempotency_key": idempotency_key,
                    "replayed": false,
                });
                self.append_receipts
                    .lock()
                    .map_err(|_| FcpError::Internal {
                        message: "append idempotency cache lock poisoned".into(),
                    })?
                    .insert(
                        idempotency_key.to_string(),
                        AppendReceipt {
                            payload_hash,
                            output: output.clone(),
                        },
                    );
                Ok(output)
            }
            "sheets.clear_values" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let range = validate_range(require_str(&input, "range")?)?;
                require_confirmation(&input, "confirm_clear")?;
                let before = client
                    .get_values(spreadsheet_id, range)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                if serialized_len(&json!({ "preflight": &before }))? > MAX_OPERATION_RESULT_BYTES {
                    return Err(invalid(
                        "clear preflight is too large; narrow the range before clearing",
                    ));
                }
                let clear_result = client
                    .clear_values(spreadsheet_id, range)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let after = client
                    .get_values(spreadsheet_id, range)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({
                    "preflight": before,
                    "clear_response": clear_result,
                    "readback": after,
                }))
            }
            "sheets.create_spreadsheet" => {
                let title = validate_title(require_str(&input, "title")?)?;
                let sheet_titles = optional_titles(&input, "sheet_titles")?;
                let sheets: Vec<_> = sheet_titles
                    .into_iter()
                    .map(|sheet_title| json!({ "properties": { "title": sheet_title } }))
                    .collect();
                let mut properties = serde_json::Map::new();
                properties.insert("title".into(), json!(title));
                if let Some(locale) = optional_short_string(&input, "locale")? {
                    properties.insert("locale".into(), json!(locale));
                }
                if let Some(time_zone) = optional_short_string(&input, "time_zone")? {
                    properties.insert("timeZone".into(), json!(time_zone));
                }
                let body = json!({
                    "properties": properties,
                    "sheets": sheets,
                });
                let spreadsheet = client
                    .create_spreadsheet(&body)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "spreadsheet": spreadsheet }))
            }
            "sheets.copy_sheet" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let destination = require_str(&input, "destination_spreadsheet_id")?;
                let sheet_id = require_u32(&input, "sheet_id")?;
                let sheet = client
                    .copy_sheet(spreadsheet_id, sheet_id, destination)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                Ok(json!({ "sheet": sheet }))
            }
            "sheets.batch_update_spreadsheet" => {
                let spreadsheet_id = require_str(&input, "spreadsheet_id")?;
                let (requests, destructive) = validated_structural_requests(&input)?;
                if destructive {
                    require_confirmation(&input, "confirm_destructive")?;
                }
                let preflight = client
                    .get_spreadsheet_with_options(spreadsheet_id, &[], false, Some(METADATA_FIELDS))
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let preflight = spreadsheet_receipt(&preflight);
                let response = client
                    .batch_update_spreadsheet(
                        spreadsheet_id,
                        &json!({
                            "requests": requests,
                            "includeSpreadsheetInResponse": false,
                        }),
                    )
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let readback = client
                    .get_spreadsheet_with_options(spreadsheet_id, &[], false, Some(METADATA_FIELDS))
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                let readback = spreadsheet_receipt(&readback);
                bounded_result(
                    json!({
                        "destructive": destructive,
                        "preflight": preflight,
                        "response": response,
                        "readback": readback,
                    }),
                    "structural write receipt exceeds the connector result budget",
                )
            }
            _ => Err(FcpError::InvalidRequest {
                code: 1002,
                message: format!("Unknown operation: {operation}"),
            }),
        }
    }

    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let operation = params
            .get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        Ok(json!({
            "operation": operation,
            "would_execute": true,
            "dry_run": true
        }))
    }

    pub async fn handle_shutdown(
        &mut self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        if let Some(client) = &self.client {
            client.shutdown();
        }
        self.client = None;
        info!("Google Sheets connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for SheetsConnector {
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

fn invalid(message: impl Into<String>) -> FcpError {
    FcpError::InvalidRequest {
        code: 1001,
        message: message.into(),
    }
}

fn require_u32(input: &serde_json::Value, field: &str) -> FcpResult<u32> {
    let value = input
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid(format!("Missing or invalid '{field}'")))?;
    u32::try_from(value).map_err(|_| invalid(format!("'{field}' exceeds u32")))
}

fn validate_range(range: &str) -> FcpResult<&str> {
    let trimmed = range.trim();
    if trimmed.is_empty() || trimmed.len() > 1024 || trimmed.chars().any(char::is_control) {
        return Err(invalid(
            "range must be 1..=1024 characters without control characters",
        ));
    }
    Ok(trimmed)
}

fn parse_explicit_row_range(range: &str) -> FcpResult<ExplicitRowRange> {
    let (sheet_prefix, cells) = range.rfind('!').map_or_else(
        || (String::new(), range),
        |index| (range[..=index].to_string(), &range[index + 1..]),
    );
    let (start, end) = cells.split_once(':').ok_or_else(|| {
        invalid("paged range must be an explicit A1 interval such as 'Sheet1!A1:D500'")
    })?;
    let (start_column, start_row) = parse_explicit_cell_reference(start)?;
    let (end_column, end_row) = parse_explicit_cell_reference(end)?;
    if start_row > end_row {
        return Err(invalid("paged range start row must not exceed end row"));
    }
    Ok(ExplicitRowRange {
        sheet_prefix,
        start_column,
        start_row,
        end_column,
        end_row,
    })
}

fn parse_explicit_cell_reference(value: &str) -> FcpResult<(String, u32)> {
    let value = value.trim();
    let column_end = value
        .char_indices()
        .take_while(|(_, character)| character.is_ascii_alphabetic() || *character == '$')
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0);
    let column = value[..column_end].replace('$', "");
    let row = value[column_end..].trim_start_matches('$');
    if column.is_empty()
        || column.len() > 4
        || !column
            .chars()
            .all(|character| character.is_ascii_alphabetic())
        || row.is_empty()
        || !row.chars().all(|character| character.is_ascii_digit())
    {
        return Err(invalid(
            "paged range endpoints must contain explicit columns and positive row numbers",
        ));
    }
    let row = row
        .parse::<u32>()
        .ok()
        .filter(|row| *row > 0)
        .ok_or_else(|| invalid("paged range row numbers must fit u32 and be positive"))?;
    Ok((column.to_ascii_uppercase(), row))
}

fn values_page_target_hash(
    spreadsheet_id: &str,
    range: &str,
    major_dimension: &str,
    value_render_option: &str,
    date_time_render_option: &str,
    page_size_rows: u32,
) -> String {
    let mut hasher = Sha256::new();
    for value in [
        spreadsheet_id,
        range,
        major_dimension,
        value_render_option,
        date_time_render_option,
    ] {
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hasher.update(page_size_rows.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn encode_values_page_cursor(cursor: &ValuesPageCursor) -> FcpResult<String> {
    let payload = serde_json::to_vec(cursor)
        .map_err(|error| invalid(format!("failed to encode page token: {error}")))?;
    let checksum = hex::encode(Sha256::digest(&payload));
    Ok(format!("{}.{}", hex::encode(payload), checksum))
}

fn decode_values_page_cursor(token: &str) -> FcpResult<ValuesPageCursor> {
    if token.len() > 4_096 {
        return Err(invalid("page_token exceeds 4096 characters"));
    }
    let (payload_hex, supplied_checksum) = token
        .split_once('.')
        .ok_or_else(|| invalid("page_token is malformed"))?;
    let payload = hex::decode(payload_hex).map_err(|_| invalid("page_token is malformed"))?;
    let expected_checksum = hex::encode(Sha256::digest(&payload));
    if supplied_checksum.len() != expected_checksum.len() || supplied_checksum != expected_checksum
    {
        return Err(invalid("page_token checksum is invalid"));
    }
    serde_json::from_slice(&payload).map_err(|_| invalid("page_token payload is invalid"))
}

fn values_chunk_target_hash(
    spreadsheet_id: &str,
    data: &[ValueRange],
    value_input_option: &str,
    chunk_size: usize,
) -> FcpResult<String> {
    let payload = serde_json::to_vec(&(spreadsheet_id, data, value_input_option, chunk_size))
        .map_err(|error| invalid(format!("failed to bind chunk plan: {error}")))?;
    Ok(hex::encode(Sha256::digest(payload)))
}

fn encode_values_chunk_cursor(cursor: &ValuesChunkCursor) -> FcpResult<String> {
    let payload = serde_json::to_vec(cursor)
        .map_err(|error| invalid(format!("failed to encode resume token: {error}")))?;
    let checksum = hex::encode(Sha256::digest(&payload));
    Ok(format!("{}.{}", hex::encode(payload), checksum))
}

fn decode_values_chunk_cursor(token: &str) -> FcpResult<ValuesChunkCursor> {
    if token.len() > 4_096 {
        return Err(invalid("resume_token exceeds 4096 characters"));
    }
    let (payload_hex, supplied_checksum) = token
        .split_once('.')
        .ok_or_else(|| invalid("resume_token is malformed"))?;
    let payload = hex::decode(payload_hex).map_err(|_| invalid("resume_token is malformed"))?;
    let expected_checksum = hex::encode(Sha256::digest(&payload));
    if supplied_checksum.len() != expected_checksum.len() || supplied_checksum != expected_checksum
    {
        return Err(invalid("resume_token checksum is invalid"));
    }
    serde_json::from_slice(&payload).map_err(|_| invalid("resume_token payload is invalid"))
}

fn verify_chunk_readback(chunk: &[ValueRange], response: &serde_json::Value) -> usize {
    let Some(readbacks) = response
        .get("valueRanges")
        .and_then(serde_json::Value::as_array)
    else {
        return 0;
    };
    chunk
        .iter()
        .zip(readbacks)
        .filter(|(expected, actual)| {
            let actual_values = actual
                .get("values")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            normalized_values(expected.values.clone()) == normalized_values_json(actual_values)
        })
        .count()
}

fn normalized_values(mut rows: Vec<Vec<serde_json::Value>>) -> Vec<Vec<serde_json::Value>> {
    for row in &mut rows {
        while row.last().is_some_and(serde_json::Value::is_null) {
            row.pop();
        }
    }
    while rows.last().is_some_and(Vec::is_empty) {
        rows.pop();
    }
    rows
}

fn normalized_values_json(rows: Vec<serde_json::Value>) -> Vec<Vec<serde_json::Value>> {
    normalized_values(
        rows.into_iter()
            .map(|row| row.as_array().cloned().unwrap_or_default())
            .collect(),
    )
}

fn serialized_len(value: &serde_json::Value) -> FcpResult<usize> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .map_err(|error| invalid(format!("failed to measure connector result: {error}")))
}

fn bounded_result(
    value: serde_json::Value,
    oversized_message: &'static str,
) -> FcpResult<serde_json::Value> {
    if serialized_len(&value)? > MAX_OPERATION_RESULT_BYTES {
        return Err(invalid(oversized_message));
    }
    Ok(value)
}

fn spreadsheet_receipt(spreadsheet: &Spreadsheet) -> serde_json::Value {
    json!({
        "spreadsheet_id": spreadsheet.spreadsheet_id,
        "title": spreadsheet.properties.title,
        "sheet_count": spreadsheet.sheets.len(),
        "sheets": spreadsheet.sheets.iter().map(|sheet| json!({
            "sheet_id": sheet.properties.sheet_id,
            "title": sheet.properties.title,
            "index": sheet.properties.index,
            "sheet_type": sheet.properties.sheet_type,
        })).collect::<Vec<_>>(),
        "named_range_count": spreadsheet.named_ranges.len(),
        "developer_metadata_count": spreadsheet.developer_metadata.len(),
    })
}

fn optional_ranges(input: &serde_json::Value, field: &str) -> FcpResult<Vec<String>> {
    let Some(value) = input.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid(format!("'{field}' must be an array")))?;
    if values.len() > MAX_RANGES {
        return Err(invalid(format!("'{field}' exceeds {MAX_RANGES} entries")));
    }
    let ranges: Vec<String> = values
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| invalid(format!("'{field}' entries must be strings")))?;
            Ok(validate_range(value)?.to_string())
        })
        .collect::<FcpResult<_>>()?;
    if ranges.iter().map(String::len).sum::<usize>() > MAX_RANGE_QUERY_BYTES {
        return Err(invalid(format!(
            "'{field}' exceeds {MAX_RANGE_QUERY_BYTES} total range characters"
        )));
    }
    Ok(ranges)
}

fn required_ranges(input: &serde_json::Value, field: &str) -> FcpResult<Vec<String>> {
    let values = optional_ranges(input, field)?;
    if values.is_empty() {
        return Err(invalid(format!(
            "'{field}' must contain at least one range"
        )));
    }
    Ok(values)
}

fn optional_enum<'a>(
    input: &'a serde_json::Value,
    field: &str,
    allowed: &[&str],
) -> FcpResult<Option<&'a str>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| invalid(format!("'{field}' must be a string")))?;
    if !allowed.contains(&value) {
        return Err(invalid(format!(
            "'{field}' must be one of {}",
            allowed.join(", ")
        )));
    }
    Ok(Some(value))
}

fn read_options(input: &serde_json::Value) -> FcpResult<(&str, &str, &str)> {
    Ok((
        optional_enum(input, "major_dimension", &["ROWS", "COLUMNS"])?.unwrap_or("ROWS"),
        optional_enum(
            input,
            "value_render_option",
            &["FORMATTED_VALUE", "UNFORMATTED_VALUE", "FORMULA"],
        )?
        .unwrap_or("FORMATTED_VALUE"),
        optional_enum(
            input,
            "date_time_render_option",
            &["SERIAL_NUMBER", "FORMATTED_STRING"],
        )?
        .unwrap_or("SERIAL_NUMBER"),
    ))
}

fn value_input_option(input: &serde_json::Value) -> FcpResult<&str> {
    Ok(
        optional_enum(input, "value_input_option", &["RAW", "USER_ENTERED"])?
            .unwrap_or("USER_ENTERED"),
    )
}

fn validated_values(
    input: &serde_json::Value,
    field: &str,
) -> FcpResult<Vec<Vec<serde_json::Value>>> {
    let values = input
        .get(field)
        .ok_or_else(|| invalid(format!("Missing '{field}'")))?;
    let rows = values
        .as_array()
        .ok_or_else(|| invalid(format!("'{field}' must be a two-dimensional array")))?;
    if rows.is_empty() {
        return Err(invalid(format!("'{field}' must not be empty")));
    }
    let mut cell_count = 0_usize;
    let mut output = Vec::with_capacity(rows.len());
    for row in rows {
        let row = row
            .as_array()
            .ok_or_else(|| invalid(format!("'{field}' must be a two-dimensional array")))?;
        cell_count = cell_count.saturating_add(row.len());
        if cell_count > MAX_CELLS {
            return Err(invalid(format!("'{field}' exceeds {MAX_CELLS} cells")));
        }
        for cell in row {
            if !(cell.is_null() || cell.is_boolean() || cell.is_number() || cell.is_string()) {
                return Err(invalid(
                    "cell values must be null, boolean, number, or string",
                ));
            }
            if cell.as_str().is_some_and(|value| value.len() > 50_000) {
                return Err(invalid("cell string exceeds 50000 bytes"));
            }
        }
        output.push(row.clone());
    }
    if serde_json::to_vec(values)
        .map_err(|error| invalid(format!("invalid values payload: {error}")))?
        .len()
        > MAX_PAYLOAD_BYTES
    {
        return Err(invalid(format!(
            "values payload exceeds the {MAX_PAYLOAD_BYTES}-byte connector request budget"
        )));
    }
    Ok(output)
}

fn validated_value_ranges(input: &serde_json::Value) -> FcpResult<Vec<ValueRange>> {
    let data = input
        .get("data")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid("Missing or invalid 'data'"))?;
    if data.is_empty() || data.len() > MAX_RANGES {
        return Err(invalid(format!(
            "'data' must contain 1..={MAX_RANGES} ranges"
        )));
    }
    if serde_json::to_vec(data)
        .map_err(|error| invalid(format!("invalid batch values payload: {error}")))?
        .len()
        > MAX_PAYLOAD_BYTES
    {
        return Err(invalid(format!(
            "batch values payload exceeds the {MAX_PAYLOAD_BYTES}-byte connector request budget"
        )));
    }
    let mut total_cells = 0_usize;
    data.iter()
        .map(|entry| {
            let range = validate_range(require_str(entry, "range")?)?.to_string();
            let values = validated_values(entry, "values")?;
            total_cells = total_cells.saturating_add(values.iter().map(Vec::len).sum::<usize>());
            if total_cells > MAX_CELLS {
                return Err(invalid(format!("batch exceeds {MAX_CELLS} cells")));
            }
            Ok(ValueRange {
                range,
                major_dimension: optional_enum(entry, "major_dimension", &["ROWS", "COLUMNS"])?
                    .unwrap_or("ROWS")
                    .to_string(),
                values,
            })
        })
        .collect()
}

fn validate_idempotency_key(value: &str) -> FcpResult<&str> {
    if value.len() < 8
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_:".contains(character))
    {
        return Err(invalid(
            "idempotency_key must be 8..=128 ASCII letters, digits, '-', '_', or ':'",
        ));
    }
    Ok(value)
}

fn append_payload_hash(
    spreadsheet_id: &str,
    range: &str,
    values: &[Vec<serde_json::Value>],
) -> FcpResult<String> {
    let bytes = serde_json::to_vec(&(spreadsheet_id, range, values))
        .map_err(|error| invalid(format!("invalid append payload: {error}")))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn require_confirmation(input: &serde_json::Value, field: &str) -> FcpResult<()> {
    if input.get(field).and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(invalid(format!(
            "'{field}' must be true after reviewing the preflight scope"
        )));
    }
    Ok(())
}

fn validate_title(value: &str) -> FcpResult<&str> {
    let value = value.trim();
    if value.is_empty() || value.len() > 200 || value.chars().any(char::is_control) {
        return Err(invalid(
            "title must be 1..=200 characters without control characters",
        ));
    }
    Ok(value)
}

fn optional_titles(input: &serde_json::Value, field: &str) -> FcpResult<Vec<String>> {
    let Some(value) = input.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid(format!("'{field}' must be an array")))?;
    if values.len() > 100 {
        return Err(invalid(format!("'{field}' exceeds 100 entries")));
    }
    values
        .iter()
        .map(|value| {
            let value = value
                .as_str()
                .ok_or_else(|| invalid(format!("'{field}' entries must be strings")))?;
            Ok(validate_title(value)?.to_string())
        })
        .collect()
}

fn optional_short_string(input: &serde_json::Value, field: &str) -> FcpResult<Option<String>> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    let value = value
        .as_str()
        .ok_or_else(|| invalid(format!("'{field}' must be a string")))?;
    if value.is_empty() || value.len() > 100 || value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "'{field}' is not a bounded printable string"
        )));
    }
    Ok(Some(value.to_string()))
}

const STRUCTURAL_REQUESTS: &[&str] = &[
    "updateSpreadsheetProperties",
    "updateSheetProperties",
    "updateDimensionProperties",
    "repeatCell",
    "updateCells",
    "appendCells",
    "addSheet",
    "duplicateSheet",
    "insertDimension",
    "appendDimension",
    "addNamedRange",
    "updateNamedRange",
    "setBasicFilter",
    "clearBasicFilter",
    "addFilterView",
    "updateFilterView",
    "setDataValidation",
    "addProtectedRange",
    "updateProtectedRange",
    "addChart",
    "updateChartSpec",
    "addConditionalFormatRule",
    "updateConditionalFormatRule",
    "createDeveloperMetadata",
    "updateDeveloperMetadata",
    "deleteSheet",
    "deleteDimension",
    "deleteNamedRange",
    "deleteFilterView",
    "deleteProtectedRange",
    "deleteEmbeddedObject",
    "deleteConditionalFormatRule",
    "deleteDeveloperMetadata",
];

const DESTRUCTIVE_REQUESTS: &[&str] = &[
    "deleteSheet",
    "deleteDimension",
    "deleteNamedRange",
    "deleteFilterView",
    "deleteProtectedRange",
    "deleteEmbeddedObject",
    "deleteConditionalFormatRule",
    "deleteDeveloperMetadata",
    "clearBasicFilter",
];

const FIELD_MASK_REQUESTS: &[&str] = &[
    "updateSpreadsheetProperties",
    "updateSheetProperties",
    "updateDimensionProperties",
    "repeatCell",
    "updateCells",
    "updateNamedRange",
    "updateFilterView",
    "updateProtectedRange",
    "updateChartSpec",
    "updateConditionalFormatRule",
    "updateDeveloperMetadata",
];

fn validated_structural_requests(
    input: &serde_json::Value,
) -> FcpResult<(Vec<serde_json::Value>, bool)> {
    let requests = input
        .get("requests")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid("Missing or invalid 'requests'"))?;
    if requests.is_empty() || requests.len() > MAX_BATCH_REQUESTS {
        return Err(invalid(format!(
            "'requests' must contain 1..={MAX_BATCH_REQUESTS} entries"
        )));
    }
    if serde_json::to_vec(requests)
        .map_err(|error| invalid(format!("invalid batch payload: {error}")))?
        .len()
        > MAX_PAYLOAD_BYTES
    {
        return Err(invalid(format!(
            "structural batch payload exceeds the {MAX_PAYLOAD_BYTES}-byte atomic request budget; atomic batches are never split"
        )));
    }
    let mut destructive = false;
    for request in requests {
        let object = request
            .as_object()
            .ok_or_else(|| invalid("each batch request must be an object"))?;
        if object.len() != 1 {
            return Err(invalid(
                "each batch request must contain exactly one request type",
            ));
        }
        let (kind, body) = object.iter().next().expect("one request key");
        if !STRUCTURAL_REQUESTS.contains(&kind.as_str()) {
            return Err(invalid(format!(
                "unsupported structural request type '{kind}'"
            )));
        }
        if !body.is_object() {
            return Err(invalid(format!("'{kind}' body must be an object")));
        }
        if FIELD_MASK_REQUESTS.contains(&kind.as_str()) && body.get("fields").is_none() {
            return Err(invalid(format!("'{kind}' requires an explicit field mask")));
        }
        validate_nested_payload(body, 0)?;
        destructive |= DESTRUCTIVE_REQUESTS.contains(&kind.as_str());
    }
    Ok((requests.clone(), destructive))
}

fn validate_nested_payload(value: &serde_json::Value, depth: usize) -> FcpResult<()> {
    if depth > 20 {
        return Err(invalid("batch request nesting exceeds 20 levels"));
    }
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                if key == "fields" {
                    let fields = value
                        .as_str()
                        .ok_or_else(|| invalid("field masks must be strings"))?;
                    if fields.is_empty()
                        || fields == "*"
                        || fields.len() > 512
                        || !fields.chars().all(|character| {
                            character.is_ascii_alphanumeric() || "_.,()".contains(character)
                        })
                    {
                        return Err(invalid(
                            "field mask is empty, wildcard, oversized, or malformed",
                        ));
                    }
                }
                if (key.ends_with("Id") || key.ends_with("Index"))
                    && value.as_i64().is_some_and(|number| number < 0)
                {
                    return Err(invalid(format!("'{key}' must not be negative")));
                }
                validate_nested_payload(value, depth + 1)?;
            }
        }
        serde_json::Value::Array(values) => {
            if values.len() > MAX_CELLS {
                return Err(invalid("nested array exceeds bounded item count"));
            }
            for value in values {
                validate_nested_payload(value, depth + 1)?;
            }
        }
        serde_json::Value::String(value) if value.len() > 50_000 => {
            return Err(invalid("nested string exceeds 50000 bytes"));
        }
        _ => {}
    }
    Ok(())
}

fn object_schema(required: &[&str]) -> serde_json::Value {
    json!({
        "type": "object",
        "required": required,
        "additionalProperties": true,
    })
}

fn hint(when_to_use: &str) -> AgentHint {
    AgentHint {
        when_to_use: when_to_use.to_string(),
        common_mistakes: Vec::new(),
        examples: Vec::new(),
        related: Vec::new(),
    }
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
    let requires_approval = Some(match safety_tier {
        SafetyTier::Safe => ApprovalMode::None,
        SafetyTier::Risky => ApprovalMode::Policy,
        SafetyTier::Dangerous => ApprovalMode::Interactive,
        SafetyTier::Critical | SafetyTier::Forbidden => ApprovalMode::ElevationToken,
    });
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
        requires_approval,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    fn run_async_test<F>(future: F) -> F::Output
    where
        F: Future,
    {
        fcp_async_core::runtime::block_on_sync(future).expect("test runtime")
    }

    #[test]
    fn health_unconfigured() {
        let connector = SheetsConnector::new();
        let result = run_async_test(connector.handle_health()).unwrap();
        assert_eq!(result["status"]["state"], "degraded");
        assert_eq!(result["status"]["reason"], "not_configured");
    }

    #[test]
    fn health_configured() {
        run_async_test(async {
            let mut connector = SheetsConnector::new();
            connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();
            let result = connector.handle_health().await.unwrap();
            assert_eq!(result["status"]["state"], "ready");
        });
    }

    #[test]
    fn configure_no_auth_fails() {
        let result = run_async_test(async {
            let mut connector = SheetsConnector::new();
            connector.handle_configure(json!({})).await
        });
        assert!(result.is_err());
    }

    #[test]
    fn configure_rejects_invalid_base_url_override() {
        run_async_test(async {
            let mut connector = SheetsConnector::new();
            let err = connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": 123
                }))
                .await
                .unwrap_err();
            assert!(
                matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("base_url")),
                "expected base_url validation error, got {err:?}"
            );

            let mut connector = SheetsConnector::new();
            let err = connector
                .handle_configure(json!({
                    "access_token": "test-token",
                    "base_url": ""
                }))
                .await
                .unwrap_err();
            assert!(
                matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("empty")),
                "expected empty base_url validation error, got {err:?}"
            );
        });
    }

    #[test]
    fn configure_with_access_token() {
        run_async_test(async {
            let mut connector = SheetsConnector::new();
            let result = connector
                .handle_configure(json!({ "access_token": "test-token" }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured");
        });
    }

    #[test]
    fn configure_with_credential_id() {
        run_async_test(async {
            let mut connector = SheetsConnector::new();
            let cred_id = fcp_core::CredentialId::new();
            let result = connector
                .handle_configure(json!({ "credential_id": cred_id.to_string() }))
                .await
                .unwrap();
            assert_eq!(result["status"], "configured_pending_token_materialization");
        });
    }

    #[test]
    fn validate_sheets_base_url_accepts_googleapis() {
        let out = validate_sheets_base_url("https://sheets.googleapis.com/v4/").unwrap();
        assert_eq!(out, "https://sheets.googleapis.com/v4");
    }

    #[test]
    fn validate_sheets_base_url_allows_localhost_http() {
        validate_sheets_base_url("http://localhost:9999/v4").unwrap();
        validate_sheets_base_url("http://127.0.0.1/sheets").unwrap();
        validate_sheets_base_url("http://[::1]:9999/v4").unwrap();
    }

    #[test]
    fn validate_sheets_base_url_rejects_foreign_host() {
        let err = validate_sheets_base_url("https://evil.example.com/v4").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("sheets.googleapis.com")),
            "expected InvalidRequest mentioning googleapis.com, got {err:?}"
        );
    }

    #[test]
    fn validate_sheets_base_url_rejects_substring_smuggle() {
        let err =
            validate_sheets_base_url("https://evil.com/sheets.googleapis.com/v4").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_sheets_base_url_rejects_query_fragment_userinfo() {
        assert!(matches!(
            validate_sheets_base_url("https://sheets.googleapis.com/v4?leak=x").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_sheets_base_url("https://sheets.googleapis.com/v4#frag").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        let err =
            validate_sheets_base_url("https://attacker:pw@sheets.googleapis.com/v4").unwrap_err();
        assert!(
            matches!(&err, FcpError::InvalidRequest { message, .. } if message.contains("userinfo")),
            "expected InvalidRequest mentioning userinfo, got {err:?}"
        );
    }

    #[test]
    fn validate_sheets_base_url_rejects_plain_http_on_public_host() {
        let err = validate_sheets_base_url("http://sheets.googleapis.com/v4").unwrap_err();
        assert!(matches!(err, FcpError::InvalidRequest { .. }));
    }

    #[test]
    fn validate_sheets_base_url_rejects_empty_and_malformed() {
        assert!(matches!(
            validate_sheets_base_url("   ").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
        assert!(matches!(
            validate_sheets_base_url("not a url").unwrap_err(),
            FcpError::InvalidRequest { .. }
        ));
    }

    #[test]
    fn host_is_sheets_googleapis_rejects_wrong_hosts_and_lookalikes() {
        assert!(host_is_sheets_googleapis("sheets.googleapis.com"));
        assert!(!host_is_sheets_googleapis("googleapis.com"));
        assert!(!host_is_sheets_googleapis("www.googleapis.com"));
        assert!(!host_is_sheets_googleapis("googleapis.com.evil.com"));
        assert!(!host_is_sheets_googleapis("evil-googleapis.com"));
    }

    #[test]
    fn resource_uris_bind_sheets_targets() {
        let get = resource_uris_for_operation(
            "sheets.get_spreadsheet",
            &json!({ "spreadsheet_id": "sheet_123" }),
        )
        .unwrap();
        assert_eq!(get, vec!["google-sheets:spreadsheet:sheet_123"]);

        let update = resource_uris_for_operation(
            "sheets.update_values",
            &json!({ "spreadsheet_id": "sheet_123", "range": "Sheet1!A1:B2" }),
        )
        .unwrap();
        assert_eq!(update, vec!["google-sheets:spreadsheet:sheet_123"]);
    }

    #[test]
    fn introspect_has_all_operations() {
        let connector = SheetsConnector::new();
        let result = run_async_test(connector.handle_introspect()).unwrap();
        let ops = result["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 12);

        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert!(op_ids.contains(&"sheets.get_spreadsheet"));
        assert!(op_ids.contains(&"sheets.get_values"));
        assert!(op_ids.contains(&"sheets.get_values_page"));
        assert!(op_ids.contains(&"sheets.batch_get_values"));
        assert!(op_ids.contains(&"sheets.update_values"));
        assert!(op_ids.contains(&"sheets.batch_update_values"));
        assert!(op_ids.contains(&"sheets.batch_update_values_chunked"));
        assert!(op_ids.contains(&"sheets.append_values"));
        assert!(op_ids.contains(&"sheets.clear_values"));
        assert!(op_ids.contains(&"sheets.create_spreadsheet"));
        assert!(op_ids.contains(&"sheets.copy_sheet"));
        assert!(op_ids.contains(&"sheets.batch_update_spreadsheet"));
    }

    #[test]
    fn manifest_and_introspection_operation_contracts_agree() {
        let connector = SheetsConnector::new();
        let introspection = run_async_test(connector.handle_introspect()).unwrap();
        let manifest = fcp_manifest::ConnectorManifest::parse_str_unchecked(MANIFEST_TOML).unwrap();
        let manifest_operations = &manifest.provides.operations;
        let introspection_operations = introspection["operations"].as_array().unwrap();
        assert_eq!(manifest_operations.len(), introspection_operations.len());
        for operation in introspection_operations {
            let id = operation["id"].as_str().unwrap();
            let manifest_operation = manifest_operations.get(id).unwrap();
            assert_eq!(
                manifest_operation.capability.as_str(),
                operation["capability"].as_str().unwrap(),
                "capability mismatch for {id}"
            );
            assert_eq!(
                serde_json::to_value(manifest_operation.risk_level).unwrap(),
                operation["risk_level"],
                "risk mismatch for {id}"
            );
            assert_eq!(
                serde_json::to_value(manifest_operation.safety_tier).unwrap(),
                operation["safety_tier"],
                "safety mismatch for {id}"
            );
            assert_eq!(
                serde_json::to_value(manifest_operation.idempotency).unwrap(),
                operation["idempotency"],
                "idempotency mismatch for {id}"
            );
            assert_eq!(
                serde_json::to_value(ApprovalMode::from(manifest_operation.requires_approval))
                    .unwrap(),
                operation["requires_approval"],
                "approval mismatch for {id}"
            );
            assert_eq!(
                manifest_operation.input_schema.get("required"),
                operation["input_schema"].get("required"),
                "input required fields mismatch for {id}"
            );
            assert_eq!(
                manifest_operation.output_schema.get("required"),
                operation["output_schema"].get("required"),
                "output required fields mismatch for {id}"
            );
        }
    }

    #[test]
    fn bundled_manifest_validates_with_current_interface_hash() {
        fcp_manifest::ConnectorManifest::parse_str(MANIFEST_TOML).unwrap();
    }

    #[test]
    fn structural_batch_is_typed_and_fail_closed() {
        let (requests, destructive) = validated_structural_requests(&json!({
            "requests": [
                {"repeatCell": {"range": {"sheetId": 0}, "cell": {"userEnteredFormat": {"textFormat": {"bold": true}}}, "fields": "userEnteredFormat.textFormat.bold"}},
                {"updateCells": {"rows": [{"values": [{"userEnteredValue": {"formulaValue": "=SUM(A1:A3)"}}]}], "fields": "userEnteredValue.formulaValue", "start": {"sheetId": 0}}},
                {"addSheet": {"properties": {"title": "Summary"}}}
            ]
        }))
        .unwrap();
        assert_eq!(requests.len(), 3);
        assert!(!destructive);

        assert!(
            validated_structural_requests(&json!({
                "requests": [{"rawRequest": {"uri": "https://example.invalid"}}]
            }))
            .is_err()
        );
        assert!(
            validated_structural_requests(&json!({
                "requests": [{"repeatCell": {"fields": "*"}}]
            }))
            .is_err()
        );
        assert!(
            validated_structural_requests(&json!({
                "requests": [{"deleteSheet": {"sheetId": 7}}]
            }))
            .unwrap()
            .1
        );
    }

    #[test]
    fn value_batches_reject_malformed_and_oversized_inputs() {
        assert!(validated_values(&json!({"values": ["not-a-row"]}), "values").is_err());
        let rows = vec![vec![json!(1); MAX_CELLS + 1]];
        assert!(validated_values(&json!({"values": rows}), "values").is_err());
        let too_many_ranges = vec!["A1"; MAX_RANGES + 1];
        assert!(required_ranges(&json!({"ranges": too_many_ranges}), "ranges").is_err());
    }

    #[test]
    fn metadata_fields_exclude_grid_data() {
        assert!(!METADATA_FIELDS.contains("charts,data"));
        assert!(!METADATA_FIELDS.contains("sheets(data"));
        assert!(METADATA_FIELDS.contains("sheets(properties)"));
    }

    #[test]
    fn chunk_readback_normalization_and_target_hashes_are_deterministic() {
        let chunk = vec![ValueRange {
            range: "Sheet1!A1:B2".into(),
            major_dimension: "ROWS".into(),
            values: vec![vec![json!(1), json!(null)], vec![json!(null)]],
        }];
        let response = json!({
            "valueRanges": [{"range": "Sheet1!A1:B2", "values": [[1]]}]
        });
        assert_eq!(verify_chunk_readback(&chunk, &response), 1);
        let first = values_chunk_target_hash("sheet123", &chunk, "USER_ENTERED", 10).unwrap();
        let second = values_chunk_target_hash("sheet123", &chunk, "USER_ENTERED", 10).unwrap();
        assert_eq!(first, second);
        assert_ne!(
            first,
            values_chunk_target_hash("sheet123", &chunk, "RAW", 10).unwrap()
        );
    }

    #[test]
    fn explicit_row_ranges_and_page_tokens_are_bounded_and_target_bound() {
        let parsed = parse_explicit_row_range("'Revenue ! 2026'!$A$7:D120").unwrap();
        assert_eq!(parsed.sheet_prefix, "'Revenue ! 2026'!");
        assert_eq!(parsed.start_column, "A");
        assert_eq!(parsed.start_row, 7);
        assert_eq!(parsed.end_column, "D");
        assert_eq!(parsed.end_row, 120);
        assert_eq!(parsed.page_range(7, 10).unwrap(), "'Revenue ! 2026'!A7:D16");
        assert!(parse_explicit_row_range("Sheet1!A:D").is_err());
        assert!(parse_explicit_row_range("named_range").is_err());

        let cursor = ValuesPageCursor {
            version: 1,
            target_hash: values_page_target_hash(
                "sheet123",
                "Sheet1!A1:D120",
                "ROWS",
                "FORMATTED_VALUE",
                "SERIAL_NUMBER",
                64,
            ),
            next_row: 65,
            end_row: 120,
            page_index: 1,
        };
        let token = encode_values_page_cursor(&cursor).unwrap();
        assert!(token.len() < 4_096);
        assert_eq!(decode_values_page_cursor(&token).unwrap(), cursor);
        let mut tampered = token.into_bytes();
        tampered[0] = if tampered[0] == b'a' { b'b' } else { b'a' };
        assert!(decode_values_page_cursor(std::str::from_utf8(&tampered).unwrap()).is_err());
    }

    #[test]
    fn append_keys_and_confirmations_are_explicit() {
        assert!(validate_idempotency_key("retry-key-001").is_ok());
        assert!(validate_idempotency_key("short").is_err());
        assert!(require_confirmation(&json!({"confirm_clear": true}), "confirm_clear").is_ok());
        assert!(require_confirmation(&json!({}), "confirm_clear").is_err());
    }

    #[test]
    fn shutdown_succeeds() {
        run_async_test(async {
            let mut connector = SheetsConnector::new();
            let result = connector.handle_shutdown(json!({})).await.unwrap();
            assert_eq!(result["status"], "shutdown");
        });
    }

    #[test]
    fn invoke_without_configure_returns_not_configured() {
        let result = run_async_test(async {
            let mut connector = SheetsConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "sheets.get_spreadsheet",
                    "input": { "spreadsheet_id": "abc" }
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::NotConfigured)));
    }

    #[test]
    fn invoke_unknown_operation_is_denied_before_token_validation() {
        let result = run_async_test(async {
            let mut connector = SheetsConnector::new();
            connector
                .handle_invoke(json!({
                    "operation": "sheets.nonexistent",
                    "input": {}
                }))
                .await
        });
        assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
    }

    #[test]
    fn default_creates_new() {
        let connector = SheetsConnector::default();
        assert!(connector.client.is_none());
    }

    #[test]
    fn handshake_manifest_hash_tracks_bundled_manifest() {
        let mut expected = Sha256::new();
        expected.update(MANIFEST_TOML.as_bytes());
        let expected = format!("sha256:{}", hex::encode(expected.finalize()));

        assert_eq!(SheetsConnector::manifest_hash(), expected);
        assert_ne!(
            SheetsConnector::manifest_hash(),
            "sha256:google-sheets-connector-v1"
        );
    }
}
