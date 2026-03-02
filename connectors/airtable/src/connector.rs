//! FCP Airtable Connector implementation.

use std::sync::Arc;

use fcp_core::{
    AgentHint, BaseConnector, CapabilityGrant, CapabilityId, CapabilityToken, CapabilityVerifier,
    ConnectorId, EventCaps, FcpError, FcpResult, HandshakeRequest, HandshakeResponse,
    IdempotencyClass, Introspection, OperationId, OperationInfo, RiskLevel, SafetyTier, SessionId,
    SimulateRequest, SimulateResponse,
};
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    client::AirtableClient,
    error::AirtableError,
    types::SortSpec,
};

/// FCP Airtable Connector.
pub struct AirtableConnector {
    base: Arc<BaseConnector>,
    client: Option<AirtableClient>,
    verifier: Option<CapabilityVerifier>,
    session_id: Option<SessionId>,
}

impl AirtableConnector {
    /// Create a new Airtable connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: Arc::new(BaseConnector::new(ConnectorId::from_static("airtable"))),
            client: None,
            verifier: None,
            session_id: None,
        }
    }

    /// Handle configure method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the configuration is invalid or client creation fails.
    #[instrument(skip(self, params))]
    pub async fn handle_configure(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let token =
            params
                .get("token")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing token in configuration".into(),
                })?;

        let base_url = params.get("base_url").and_then(|v| v.as_str());

        let mut client = AirtableClient::new(token).map_err(|e| FcpError::Internal {
            message: format!("Failed to create HTTP client: {e}"),
        })?;

        if let Some(url) = base_url {
            client = client.with_base_url(url);
        }

        self.client = Some(client);
        self.base.set_configured(true);
        info!("Airtable connector configured");

        Ok(json!({ "status": "configured" }))
    }

    /// Handle handshake method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_handshake(
        &mut self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let req: HandshakeRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid handshake request: {e}"),
            })?;

        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));

        let session_id = SessionId::new();
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
            manifest_hash: "sha256:airtable-connector-v1".into(),
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

    /// Handle health check.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the health status cannot be determined.
    pub async fn handle_health(&self) -> FcpResult<serde_json::Value> {
        let configured = self.client.is_some();
        let metrics = self.base.metrics();
        Ok(json!({
            "status": if configured { "healthy" } else { "not_configured" },
            "metrics": {
                "requests_total": metrics.requests_total,
                "requests_error": metrics.requests_error,
            }
        }))
    }

    /// Handle introspect method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if serialization of the introspection data fails.
    pub async fn handle_introspect(&self) -> FcpResult<serde_json::Value> {
        let introspection = Introspection {
            operations: vec![
                op_info(
                    "airtable.list_bases",
                    "List all accessible Airtable bases",
                    json!({
                        "type": "object",
                        "properties": {
                            "offset": { "type": "string", "description": "Pagination cursor from previous response" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["bases"],
                        "properties": {
                            "bases": { "type": "array" },
                            "offset": { "type": "string" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Discover available Airtable bases the user has access to.".into(),
                        common_mistakes: vec![],
                        examples: vec![r"{}".into()],
                        related: vec![CapabilityId::from_static("airtable.get_base_schema")],
                    },
                ),
                op_info(
                    "airtable.get_base_schema",
                    "Get the schema of an Airtable base including all tables and fields",
                    json!({
                        "type": "object",
                        "required": ["base_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID (starts with 'app')" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["tables"],
                        "properties": {
                            "tables": { "type": "array" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Discover table structure and field types before querying records.".into(),
                        common_mistakes: vec!["Using table name instead of base_id to get schema.".into()],
                        examples: vec![r#"{"base_id": "appXXXXXXXXXXXXXX"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.list_bases"),
                            CapabilityId::from_static("airtable.list_records"),
                        ],
                    },
                ),
                op_info(
                    "airtable.list_records",
                    "List records from an Airtable table with filtering and sorting",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "fields": { "type": "array", "items": { "type": "string" }, "description": "Only return specified field names" },
                            "filter_by_formula": { "type": "string", "description": "Airtable formula to filter records" },
                            "max_records": { "type": "integer", "description": "Maximum records to return (max 100)" },
                            "page_size": { "type": "integer", "description": "Records per page (max 100)" },
                            "sort": { "type": "array", "items": { "type": "object" }, "description": "Fields to sort by" },
                            "view": { "type": "string", "description": "View name or ID" },
                            "offset": { "type": "string", "description": "Pagination cursor" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["records"],
                        "properties": {
                            "records": { "type": "array" },
                            "offset": { "type": "string" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Query records from an Airtable table. Use filter_by_formula for filtering.".into(),
                        common_mistakes: vec![
                            "Using SQL syntax instead of Airtable formula syntax.".into(),
                            "Not handling pagination for large datasets.".into(),
                        ],
                        examples: vec![
                            r#"{"base_id": "appXXX", "table_id": "Tasks", "filter_by_formula": "{Status} = \"Active\""}"#.into(),
                        ],
                        related: vec![
                            CapabilityId::from_static("airtable.get_record"),
                            CapabilityId::from_static("airtable.get_base_schema"),
                        ],
                    },
                ),
                op_info(
                    "airtable.get_record",
                    "Get a single record by ID from an Airtable table",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "record_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "record_id": { "type": "string", "description": "Record ID (starts with 'rec')" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "fields"],
                        "properties": {
                            "id": { "type": "string" },
                            "fields": { "type": "object" },
                            "createdTime": { "type": "string" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Retrieve a specific record when you know its ID.".into(),
                        common_mistakes: vec!["Using row number instead of record ID.".into()],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "record_id": "recYYY"}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.list_records"),
                            CapabilityId::from_static("airtable.update_record"),
                        ],
                    },
                ),
                op_info(
                    "airtable.create_record",
                    "Create a new record in an Airtable table",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "fields"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "fields": { "type": "object", "description": "Field values for the new record" },
                            "typecast": { "type": "boolean", "description": "If true, try to convert string values to appropriate types" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "fields"],
                        "properties": {
                            "id": { "type": "string" },
                            "fields": { "type": "object" },
                            "createdTime": { "type": "string" }
                        }
                    }),
                    "airtable.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Add a new record to an Airtable table.".into(),
                        common_mistakes: vec![
                            "Using field IDs instead of field names.".into(),
                            "Not matching field types.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "fields": {"Name": "New Task", "Status": "Todo"}}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.get_base_schema"),
                            CapabilityId::from_static("airtable.update_record"),
                        ],
                    },
                ),
                op_info(
                    "airtable.create_records",
                    "Create multiple records in an Airtable table (batch, max 10)",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "records"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "records": { "type": "array", "description": "Array of records to create (max 10)", "maxItems": 10 },
                            "typecast": { "type": "boolean", "description": "If true, try to convert string values" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["records"],
                        "properties": {
                            "records": { "type": "array" }
                        }
                    }),
                    "airtable.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::None,
                    AgentHint {
                        when_to_use: "Create multiple records efficiently. Limited to 10 records per call.".into(),
                        common_mistakes: vec!["Exceeding 10 record limit per batch.".into()],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "records": [{"fields": {"Name": "Task 1"}}, {"fields": {"Name": "Task 2"}}]}"#.into()],
                        related: vec![CapabilityId::from_static("airtable.create_record")],
                    },
                ),
                op_info(
                    "airtable.update_record",
                    "Update an existing record in an Airtable table (PATCH)",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "record_id", "fields"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "record_id": { "type": "string", "description": "Record ID to update" },
                            "fields": { "type": "object", "description": "Field values to update (partial)" },
                            "typecast": { "type": "boolean", "description": "If true, try to convert string values" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "fields"],
                        "properties": {
                            "id": { "type": "string" },
                            "fields": { "type": "object" }
                        }
                    }),
                    "airtable.write",
                    RiskLevel::Medium,
                    SafetyTier::Risky,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Modify specific fields of an existing record. Only specified fields are updated.".into(),
                        common_mistakes: vec![
                            "Trying to update the record ID field.".into(),
                            "Not quoting linked record IDs correctly.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "record_id": "recYYY", "fields": {"Status": "Done"}}"#.into()],
                        related: vec![
                            CapabilityId::from_static("airtable.get_record"),
                            CapabilityId::from_static("airtable.replace_record"),
                        ],
                    },
                ),
                op_info(
                    "airtable.replace_record",
                    "Replace all fields of a record (PUT - destructive update)",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "record_id", "fields"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "record_id": { "type": "string", "description": "Record ID to replace" },
                            "fields": { "type": "object", "description": "Complete field values (replaces all existing)" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "fields"],
                        "properties": {
                            "id": { "type": "string" },
                            "fields": { "type": "object" }
                        }
                    }),
                    "airtable.write",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Replace all fields of a record. Fields not included will be cleared. Prefer update_record for partial updates.".into(),
                        common_mistakes: vec![
                            "Using replace when update_record would suffice.".into(),
                            "Accidentally clearing fields by not including them.".into(),
                        ],
                        examples: vec![],
                        related: vec![CapabilityId::from_static("airtable.update_record")],
                    },
                ),
                op_info(
                    "airtable.delete_record",
                    "Delete a record from an Airtable table (irreversible)",
                    json!({
                        "type": "object",
                        "required": ["base_id", "table_id", "record_id"],
                        "properties": {
                            "base_id": { "type": "string", "description": "Airtable base ID" },
                            "table_id": { "type": "string", "description": "Table name or ID" },
                            "record_id": { "type": "string", "description": "Record ID to delete" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["id", "deleted"],
                        "properties": {
                            "id": { "type": "string" },
                            "deleted": { "type": "boolean" }
                        }
                    }),
                    "airtable.delete",
                    RiskLevel::High,
                    SafetyTier::Dangerous,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Permanently delete a record. This cannot be undone.".into(),
                        common_mistakes: vec![
                            "Deleting without confirmation.".into(),
                            "Deleting records linked from other tables.".into(),
                        ],
                        examples: vec![r#"{"base_id": "appXXX", "table_id": "Tasks", "record_id": "recYYY"}"#.into()],
                        related: vec![CapabilityId::from_static("airtable.get_record")],
                    },
                ),
                op_info(
                    "airtable.download_attachment",
                    "Download an attachment file from an Airtable record",
                    json!({
                        "type": "object",
                        "required": ["url"],
                        "properties": {
                            "url": { "type": "string", "description": "Attachment URL from a record's attachment field" }
                        }
                    }),
                    json!({
                        "type": "object",
                        "required": ["data", "content_type"],
                        "properties": {
                            "data": { "type": "string", "description": "Base64-encoded file data" },
                            "content_type": { "type": "string", "description": "MIME type" },
                            "filename": { "type": "string", "description": "Original filename" }
                        }
                    }),
                    "airtable.read",
                    RiskLevel::Low,
                    SafetyTier::Safe,
                    IdempotencyClass::Strict,
                    AgentHint {
                        when_to_use: "Download attachment files (images, documents) from Airtable records.".into(),
                        common_mistakes: vec![
                            "Using the thumbnail URL instead of the full URL.".into(),
                            "Not handling large files appropriately.".into(),
                        ],
                        examples: vec![r#"{"url": "https://dl.airtable.com/.attachments/..."}"#.into()],
                        related: vec![CapabilityId::from_static("airtable.get_record")],
                    },
                ),
            ],
            events: vec![],
            resource_types: vec![],
            auth_caps: None,
            event_caps: None,
        };

        serde_json::to_value(introspection).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize introspection: {e}"),
        })
    }

    /// Handle simulate method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the request is invalid or serialization fails.
    pub async fn handle_simulate(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let req: SimulateRequest =
            serde_json::from_value(params).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid simulate request: {e}"),
            })?;

        let response = SimulateResponse::allowed(req.id);
        serde_json::to_value(response).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize response: {e}"),
        })
    }

    /// Handle invoke method.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the operation fails or capability verification fails.
    pub async fn handle_invoke(&self, params: serde_json::Value) -> FcpResult<serde_json::Value> {
        let result = self.handle_invoke_internal(params).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn handle_invoke_internal(
        &self,
        params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let operation =
            params
                .get("operation")
                .and_then(|v| v.as_str())
                .ok_or(FcpError::InvalidRequest {
                    code: 1003,
                    message: "Missing operation".into(),
                })?;

        let input = params.get("input").cloned().unwrap_or(json!({}));

        let token_value = params
            .get("capability_token")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing capability_token".into(),
            })?;

        let token: CapabilityToken =
            serde_json::from_value(token_value.clone()).map_err(|e| FcpError::InvalidRequest {
                code: 1003,
                message: format!("Invalid capability_token format: {e}"),
            })?;

        let op_id: OperationId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid operation ID format".into(),
        })?;
        let cap_id: CapabilityId = operation.parse().map_err(|_| FcpError::InvalidRequest {
            code: 1003,
            message: "Invalid capability ID format".into(),
        })?;

        if let Some(verifier) = &self.verifier {
            verifier.verify(&token, &cap_id, &op_id, &[])?;
        } else {
            return Err(FcpError::NotConfigured);
        }

        match operation {
            "airtable.list_bases" => self.invoke_list_bases(input).await,
            "airtable.get_base_schema" => self.invoke_get_base_schema(input).await,
            "airtable.list_records" => self.invoke_list_records(input).await,
            "airtable.get_record" => self.invoke_get_record(input).await,
            "airtable.create_record" => self.invoke_create_record(input).await,
            "airtable.create_records" => self.invoke_create_records(input).await,
            "airtable.update_record" => self.invoke_update_record(input).await,
            "airtable.replace_record" => self.invoke_replace_record(input).await,
            "airtable.delete_record" => self.invoke_delete_record(input).await,
            "airtable.download_attachment" => self.invoke_download_attachment(input).await,
            _ => Err(FcpError::OperationNotGranted {
                operation: operation.into(),
            }),
        }
    }

    // ── Operation implementations ─────────────────────────────────

    async fn invoke_list_bases(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let offset = input.get("offset").and_then(|v| v.as_str());

        let result = client
            .list_bases(offset)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        let mut resp = json!({ "bases": result.bases });
        if let Some(offset) = result.offset {
            resp["offset"] = json!(offset);
        }
        Ok(resp)
    }

    async fn invoke_get_base_schema(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_str(&input, "base_id")?;

        let result = client
            .get_base_schema(base_id)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        Ok(json!({ "tables": result.tables }))
    }

    async fn invoke_list_records(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_str(&input, "base_id")?;
        let table_id = require_str(&input, "table_id")?;

        let fields: Option<Vec<String>> = input.get("fields").and_then(|v| {
            v.as_array().map(|arr| {
                arr.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
        });

        let filter_by_formula = input.get("filter_by_formula").and_then(|v| v.as_str());
        let max_records = input
            .get("max_records")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let page_size = input
            .get("page_size")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let sort: Option<Vec<SortSpec>> = input.get("sort").and_then(|v| {
            serde_json::from_value(v.clone()).ok()
        });

        let view = input.get("view").and_then(|v| v.as_str());
        let offset = input.get("offset").and_then(|v| v.as_str());

        let result = client
            .list_records(
                base_id,
                table_id,
                fields.as_deref(),
                filter_by_formula,
                max_records,
                page_size,
                sort.as_deref(),
                view,
                offset,
            )
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        let mut resp = json!({ "records": result.records });
        if let Some(offset) = result.offset {
            resp["offset"] = json!(offset);
        }
        Ok(resp)
    }

    async fn invoke_get_record(&self, input: serde_json::Value) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_str(&input, "base_id")?;
        let table_id = require_str(&input, "table_id")?;
        let record_id = require_str(&input, "record_id")?;

        let record = client
            .get_record(base_id, table_id, record_id)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(record).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize record: {e}"),
        })
    }

    async fn invoke_create_record(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_str(&input, "base_id")?;
        let table_id = require_str(&input, "table_id")?;
        let fields = input
            .get("fields")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: fields".into(),
            })?;
        let typecast = input.get("typecast").and_then(|v| v.as_bool());

        let record = client
            .create_record(base_id, table_id, fields, typecast)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(record).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize record: {e}"),
        })
    }

    async fn invoke_create_records(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_str(&input, "base_id")?;
        let table_id = require_str(&input, "table_id")?;
        let records = input
            .get("records")
            .and_then(|v| v.as_array())
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: records (must be an array)".into(),
            })?;
        let typecast = input.get("typecast").and_then(|v| v.as_bool());

        let result = client
            .create_records(base_id, table_id, records, typecast)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        Ok(json!({ "records": result.records }))
    }

    async fn invoke_update_record(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_str(&input, "base_id")?;
        let table_id = require_str(&input, "table_id")?;
        let record_id = require_str(&input, "record_id")?;
        let fields = input
            .get("fields")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: fields".into(),
            })?;
        let typecast = input.get("typecast").and_then(|v| v.as_bool());

        let record = client
            .update_record(base_id, table_id, record_id, fields, typecast)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(record).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize record: {e}"),
        })
    }

    async fn invoke_replace_record(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_str(&input, "base_id")?;
        let table_id = require_str(&input, "table_id")?;
        let record_id = require_str(&input, "record_id")?;
        let fields = input
            .get("fields")
            .ok_or(FcpError::InvalidRequest {
                code: 1003,
                message: "Missing required field: fields".into(),
            })?;

        let record = client
            .replace_record(base_id, table_id, record_id, fields)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(record).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize record: {e}"),
        })
    }

    async fn invoke_delete_record(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let base_id = require_str(&input, "base_id")?;
        let table_id = require_str(&input, "table_id")?;
        let record_id = require_str(&input, "record_id")?;

        let result = client
            .delete_record(base_id, table_id, record_id)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize result: {e}"),
        })
    }

    async fn invoke_download_attachment(
        &self,
        input: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        let client = self.client.as_ref().ok_or(FcpError::NotConfigured)?;
        let url = require_str(&input, "url")?;

        let result = client
            .download_attachment(url)
            .await
            .map_err(|e: AirtableError| e.to_fcp_error())?;

        serde_json::to_value(result).map_err(|e| FcpError::Internal {
            message: format!("Failed to serialize result: {e}"),
        })
    }

    /// Handle shutdown.
    ///
    /// # Errors
    /// Returns [`FcpError`] if the shutdown process fails.
    pub async fn handle_shutdown(
        &self,
        _params: serde_json::Value,
    ) -> FcpResult<serde_json::Value> {
        info!("Airtable connector shutting down");
        Ok(json!({ "status": "shutdown" }))
    }
}

impl Default for AirtableConnector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helper functions ──────────────────────────────────────────────

fn require_str<'a>(input: &'a serde_json::Value, field: &str) -> FcpResult<&'a str> {
    input
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or(FcpError::InvalidRequest {
            code: 1003,
            message: format!("Missing required field: {field}"),
        })
}

#[allow(clippy::fn_params_excessive_bools)]
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
        summary: summary.into(),
        input_schema,
        output_schema,
        capability: CapabilityId::from_static(capability),
        risk_level,
        description: None,
        rate_limit: None,
        requires_approval: None,
        safety_tier,
        idempotency,
        ai_hints,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

    fn generate_valid_token(signing_key: &Ed25519SigningKey, cap: &str) -> CapabilityToken {
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(cap)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[cap])
            .issuer("node:test")
            .validity(now, now + Duration::hours(1))
            .sign(signing_key)
            .unwrap();
        CapabilityToken { raw: cose }
    }

    #[fcp_async_core::runtime::test]
    async fn test_handshake() {
        let mut connector = AirtableConnector::new();
        let result = connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": vec![0u8; 32],
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["airtable.read"]
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "accepted");
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_not_configured() {
        let connector = AirtableConnector::new();
        let result = connector.handle_health().await.unwrap();
        assert_eq!(result["status"], "not_configured");
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_without_config() {
        let mut connector = AirtableConnector::new();

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["airtable.list_bases"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "airtable.list_bases");

        let result = connector
            .handle_invoke(json!({
                "operation": "airtable.list_bases",
                "input": {},
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FcpError::NotConfigured));
    }

    #[fcp_async_core::runtime::test]
    async fn test_invoke_missing_field() {
        let mut connector = AirtableConnector::new();
        connector.client = Some(
            AirtableClient::new("fake_key")
                .unwrap()
                .with_base_url("http://localhost:9999"),
        );

        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        connector
            .handle_handshake(json!({
                "protocol_version": "1.0.0",
                "zone": "z:work",
                "host_public_key": verifying_key.to_bytes(),
                "nonce": vec![0u8; 32],
                "capabilities_requested": ["airtable.get_record"]
            }))
            .await
            .unwrap();

        let token = generate_valid_token(&signing_key, "airtable.get_record");

        let result = connector
            .handle_invoke(json!({
                "operation": "airtable.get_record",
                "input": { "base_id": "appXXX" },
                "capability_token": token
            }))
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("table_id"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_introspect_has_all_operations() {
        let connector = AirtableConnector::new();
        let result = connector.handle_introspect().await.unwrap();

        let ops = result["operations"].as_array().unwrap();
        let op_ids: Vec<&str> = ops.iter().map(|o| o["id"].as_str().unwrap()).collect();

        assert!(op_ids.contains(&"airtable.list_bases"));
        assert!(op_ids.contains(&"airtable.get_base_schema"));
        assert!(op_ids.contains(&"airtable.list_records"));
        assert!(op_ids.contains(&"airtable.get_record"));
        assert!(op_ids.contains(&"airtable.create_record"));
        assert!(op_ids.contains(&"airtable.create_records"));
        assert!(op_ids.contains(&"airtable.update_record"));
        assert!(op_ids.contains(&"airtable.replace_record"));
        assert!(op_ids.contains(&"airtable.delete_record"));
        assert!(op_ids.contains(&"airtable.download_attachment"));
        assert_eq!(ops.len(), 10);
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure() {
        let mut connector = AirtableConnector::new();
        let result = connector
            .handle_configure(json!({
                "token": "pat_test_token_123"
            }))
            .await
            .unwrap();

        assert_eq!(result["status"], "configured");
        assert!(connector.client.is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn test_configure_missing_token() {
        let mut connector = AirtableConnector::new();
        let result = connector.handle_configure(json!({})).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            FcpError::InvalidRequest { message, .. } => {
                assert!(message.contains("token"));
            }
            e => panic!("Expected InvalidRequest, got: {e:?}"),
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_shutdown() {
        let connector = AirtableConnector::new();
        let result = connector.handle_shutdown(json!({})).await.unwrap();
        assert_eq!(result["status"], "shutdown");
    }
}
