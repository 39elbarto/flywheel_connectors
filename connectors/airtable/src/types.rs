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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn base_serde() {
        let json = json!({"id": "app123", "name": "My Base", "permissionLevel": "create"});
        let base: Base = serde_json::from_value(json).unwrap();
        assert_eq!(base.id, "app123");
        assert_eq!(base.permission_level.as_deref(), Some("create"));
    }

    #[test]
    fn list_bases_response() {
        let json = json!({"bases": [{"id": "app1", "name": "B1"}], "offset": "abc"});
        let resp: ListBasesResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.bases.len(), 1);
        assert_eq!(resp.offset.as_deref(), Some("abc"));
    }

    #[test]
    fn table_schema_serde() {
        let json = json!({
            "id": "tbl1",
            "name": "Tasks",
            "fields": [{"id": "fld1", "name": "Name", "type": "singleLineText"}],
            "views": [{"id": "viw1", "name": "Grid", "type": "grid"}],
            "primaryFieldId": "fld1"
        });
        let schema: TableSchema = serde_json::from_value(json).unwrap();
        assert_eq!(schema.fields.len(), 1);
        assert_eq!(schema.fields[0].field_type, "singleLineText");
    }

    #[test]
    fn record_serde() {
        let json = json!({"id": "rec1", "fields": {"Name": "Task 1"}, "createdTime": "2026-03-01"});
        let rec: Record = serde_json::from_value(json).unwrap();
        assert_eq!(rec.id, "rec1");
        assert!(rec.created_time.is_some());
    }

    #[test]
    fn list_records_response() {
        let json = json!({"records": [], "offset": "next"});
        let resp: ListRecordsResponse = serde_json::from_value(json).unwrap();
        assert!(resp.records.is_empty());
        assert_eq!(resp.offset.as_deref(), Some("next"));
    }

    #[test]
    fn delete_record_response() {
        let resp = DeleteRecordResponse {
            id: "rec1".to_string(),
            deleted: true,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: DeleteRecordResponse = serde_json::from_str(&json).unwrap();
        assert!(back.deleted);
    }

    #[test]
    fn sort_spec_default_direction() {
        let json = r#"{"field":"Name"}"#;
        let sort: SortSpec = serde_json::from_str(json).unwrap();
        assert_eq!(sort.direction, "asc");
    }

    #[test]
    fn attachment_download_serialize() {
        let dl = AttachmentDownload {
            data: "base64data".to_string(),
            content_type: "image/png".to_string(),
            filename: None,
        };
        let json = serde_json::to_string(&dl).unwrap();
        assert!(!json.contains("filename"));
    }

    #[test]
    fn airtable_api_error() {
        let json = json!({"error": {"type": "INVALID_REQUEST", "message": "Bad field"}});
        let err: AirtableApiError = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert_eq!(detail.error_type.as_deref(), Some("INVALID_REQUEST"));
    }
}
