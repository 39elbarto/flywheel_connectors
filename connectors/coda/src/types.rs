//! Coda API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Common pagination
// ─────────────────────────────────────────────────────────────────────────────

/// Paginated list response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "nextPageToken")]
    pub next_page_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "nextPageLink")]
    pub next_page_link: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Document types
// ─────────────────────────────────────────────────────────────────────────────

/// A Coda document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Doc {
    pub id: String,
    #[serde(rename = "type")]
    pub doc_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "browserLink")]
    pub browser_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "folderId")]
    pub folder_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<DocIcon>,
}

/// Document icon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocIcon {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub icon_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "browserLink")]
    pub browser_link: Option<String>,
}

/// Document creation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDocRequest {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "sourceDoc")]
    pub source_doc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "folderId")]
    pub folder_id: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Page types
// ─────────────────────────────────────────────────────────────────────────────

/// A Coda page (section).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub id: String,
    #[serde(rename = "type")]
    pub page_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "browserLink")]
    pub browser_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtitle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    #[serde(default)]
    pub children: Vec<PageRef>,
}

/// Page reference (in children list).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageRef {
    pub id: String,
    #[serde(rename = "type")]
    pub page_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Table types
// ─────────────────────────────────────────────────────────────────────────────

/// A Coda table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Table {
    pub id: String,
    #[serde(rename = "type")]
    pub table_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "browserLink")]
    pub browser_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "tableType")]
    pub table_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "rowCount")]
    pub row_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<PageRef>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Row types
// ─────────────────────────────────────────────────────────────────────────────

/// A Coda row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub id: String,
    #[serde(rename = "type")]
    pub row_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "browserLink")]
    pub browser_link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
    #[serde(default)]
    pub values: serde_json::Map<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
}

/// Row upsert request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertRowsRequest {
    pub rows: Vec<RowValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "keyColumns")]
    pub key_columns: Option<Vec<String>>,
}

/// A single row's cell values for upsert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RowValue {
    pub cells: Vec<CellValue>,
}

/// A single cell value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellValue {
    pub column: String,
    pub value: serde_json::Value,
}

/// Row upsert response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertRowsResponse {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(default)]
    #[serde(rename = "addedRowIds")]
    pub added_row_ids: Vec<String>,
}

/// Row delete request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRowsRequest {
    #[serde(rename = "rowIds")]
    pub row_ids: Vec<String>,
}

/// Row delete response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRowsResponse {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(default)]
    pub row_ids: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Formula types
// ─────────────────────────────────────────────────────────────────────────────

/// A Coda formula.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Formula {
    pub id: String,
    #[serde(rename = "type")]
    pub formula_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<PageRef>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error response
// ─────────────────────────────────────────────────────────────────────────────

/// Coda API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(rename = "statusCode")]
    pub status_code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "statusMessage")]
    pub status_message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doc_deserialization() {
        let json = serde_json::json!({
            "id": "doc123",
            "type": "doc",
            "name": "My Doc",
            "href": "https://coda.io/apis/v1/docs/doc123",
            "browserLink": "https://coda.io/d/doc123",
            "owner": "user@example.com",
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-03-21T00:00:00Z"
        });
        let doc: Doc = serde_json::from_value(json).unwrap();
        assert_eq!(doc.id, "doc123");
        assert_eq!(doc.name, "My Doc");
        assert_eq!(doc.owner, Some("user@example.com".into()));
    }

    #[test]
    fn doc_list_deserialization() {
        let json = serde_json::json!({
            "items": [
                { "id": "doc1", "type": "doc", "name": "Doc 1" },
                { "id": "doc2", "type": "doc", "name": "Doc 2" }
            ],
            "nextPageToken": "tok_abc",
            "nextPageLink": "https://coda.io/apis/v1/docs?pageToken=tok_abc"
        });
        let resp: PaginatedResponse<Doc> = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 2);
        assert!(resp.next_page_token.is_some());
    }

    #[test]
    fn page_deserialization() {
        let json = serde_json::json!({
            "id": "page1",
            "type": "page",
            "name": "Main Page",
            "subtitle": "A subtitle",
            "children": [
                { "id": "page2", "type": "page", "name": "Sub Page" }
            ]
        });
        let page: Page = serde_json::from_value(json).unwrap();
        assert_eq!(page.children.len(), 1);
        assert_eq!(page.subtitle, Some("A subtitle".into()));
    }

    #[test]
    fn table_deserialization() {
        let json = serde_json::json!({
            "id": "tbl1",
            "type": "table",
            "name": "Tasks",
            "tableType": "table",
            "rowCount": 42,
            "parent": {
                "id": "page1",
                "type": "page",
                "name": "Main Page"
            }
        });
        let table: Table = serde_json::from_value(json).unwrap();
        assert_eq!(table.row_count, Some(42));
        assert!(table.parent.is_some());
    }

    #[test]
    fn row_deserialization() {
        let json = serde_json::json!({
            "id": "row1",
            "type": "row",
            "name": "Row 1",
            "index": 0,
            "values": {
                "c-col1": "value1",
                "c-col2": 42
            },
            "createdAt": "2026-01-01T00:00:00Z"
        });
        let row: Row = serde_json::from_value(json).unwrap();
        assert_eq!(row.values.len(), 2);
        assert_eq!(row.index, Some(0));
    }

    #[test]
    fn upsert_request_serialization() {
        let req = UpsertRowsRequest {
            rows: vec![RowValue {
                cells: vec![
                    CellValue {
                        column: "Name".into(),
                        value: serde_json::json!("Test"),
                    },
                    CellValue {
                        column: "Count".into(),
                        value: serde_json::json!(10),
                    },
                ],
            }],
            key_columns: Some(vec!["Name".into()]),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["rows"][0]["cells"].as_array().unwrap().len(), 2);
        assert!(json["keyColumns"].is_array());
    }

    #[test]
    fn upsert_response_deserialization() {
        let json = serde_json::json!({
            "requestId": "req-abc",
            "addedRowIds": ["row1", "row2"]
        });
        let resp: UpsertRowsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.request_id, "req-abc");
        assert_eq!(resp.added_row_ids.len(), 2);
    }

    #[test]
    fn delete_request_serialization() {
        let req = DeleteRowsRequest {
            row_ids: vec!["row1".into(), "row2".into()],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["rowIds"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn formula_deserialization() {
        let json = serde_json::json!({
            "id": "f-formula1",
            "type": "formula",
            "name": "Total",
            "value": 123.45
        });
        let formula: Formula = serde_json::from_value(json).unwrap();
        assert_eq!(formula.name, "Total");
        assert!(formula.value.is_some());
    }

    #[test]
    fn api_error_deserialization() {
        let json = serde_json::json!({
            "statusCode": 404,
            "message": "Doc not found",
            "statusMessage": "Not Found"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.status_code, 404);
        assert_eq!(err.message, Some("Doc not found".into()));
    }

    #[test]
    fn doc_with_icon() {
        let json = serde_json::json!({
            "id": "doc1",
            "type": "doc",
            "name": "Fancy Doc",
            "icon": {
                "name": "rocket",
                "type": "emoji"
            }
        });
        let doc: Doc = serde_json::from_value(json).unwrap();
        assert!(doc.icon.is_some());
        assert_eq!(doc.icon.unwrap().name, Some("rocket".into()));
    }

    #[test]
    fn create_doc_request_serialization() {
        let req = CreateDocRequest {
            title: "New Doc".into(),
            source_doc: None,
            folder_id: Some("folder123".into()),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["title"], "New Doc");
        assert_eq!(json["folderId"], "folder123");
        assert!(json.get("sourceDoc").is_none());
    }

    #[test]
    fn row_empty_values() {
        let json = serde_json::json!({
            "id": "row1",
            "type": "row",
            "name": "Empty Row"
        });
        let row: Row = serde_json::from_value(json).unwrap();
        assert!(row.values.is_empty());
    }

    #[test]
    fn paginated_response_no_next() {
        let json = serde_json::json!({
            "items": [
                { "id": "doc1", "type": "doc", "name": "Only Doc" }
            ]
        });
        let resp: PaginatedResponse<Doc> = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 1);
        assert!(resp.next_page_token.is_none());
    }

    #[test]
    fn delete_response_deserialization() {
        let json = serde_json::json!({
            "requestId": "req-del",
            "row_ids": ["r1", "r2"]
        });
        let resp: DeleteRowsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.request_id, "req-del");
        assert_eq!(resp.row_ids.len(), 2);
    }
}
