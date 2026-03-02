//! Airtable API types.

use serde::{Deserialize, Serialize};

// ── Base types ─────────────────────────────────────────────────────

/// An Airtable base (workspace/database).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Base {
    pub id: String,
    pub name: String,
    #[serde(default, rename = "permissionLevel")]
    pub permission_level: Option<String>,
}

/// Response for listing bases.
#[derive(Debug, Clone, Deserialize)]
pub struct ListBasesResponse {
    #[serde(default)]
    pub bases: Vec<Base>,
    #[serde(default)]
    pub offset: Option<String>,
}

// ── Schema types ───────────────────────────────────────────────────

/// A table in an Airtable base schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableSchema {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub fields: Vec<FieldSchema>,
    #[serde(default)]
    pub views: Vec<ViewSchema>,
    #[serde(default, rename = "primaryFieldId")]
    pub primary_field_id: Option<String>,
}

/// A field definition in a table schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSchema {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub options: Option<serde_json::Value>,
}

/// A view in a table schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewSchema {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub view_type: String,
}

/// Response for getting base schema.
#[derive(Debug, Clone, Deserialize)]
pub struct BaseSchemaResponse {
    pub tables: Vec<TableSchema>,
}

// ── Record types ───────────────────────────────────────────────────

/// An Airtable record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub fields: serde_json::Value,
    #[serde(default, rename = "createdTime")]
    pub created_time: Option<String>,
}

/// Response for listing records.
#[derive(Debug, Clone, Deserialize)]
pub struct ListRecordsResponse {
    pub records: Vec<Record>,
    #[serde(default)]
    pub offset: Option<String>,
}

/// Response for creating multiple records.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateRecordsResponse {
    pub records: Vec<Record>,
}

/// Response for deleting a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRecordResponse {
    pub id: String,
    pub deleted: bool,
}

// ── Sort types ─────────────────────────────────────────────────────

/// Sort specification for listing records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SortSpec {
    pub field: String,
    #[serde(default = "default_sort_direction")]
    pub direction: String,
}

fn default_sort_direction() -> String {
    "asc".into()
}

// ── Attachment types ───────────────────────────────────────────────

/// Downloaded attachment data.
#[derive(Debug, Clone, Serialize)]
pub struct AttachmentDownload {
    pub data: String,
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

// ── API Error response ─────────────────────────────────────────────

/// Airtable API error response body.
#[derive(Debug, Clone, Deserialize)]
pub struct AirtableApiError {
    #[serde(default)]
    pub error: Option<AirtableErrorDetail>,
}

/// Detail inside an Airtable error response.
#[derive(Debug, Clone, Deserialize)]
pub struct AirtableErrorDetail {
    #[serde(default, rename = "type")]
    pub error_type: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}
