use serde::{Deserialize, Serialize};

fn default_select() -> String {
    "*".to_string()
}

fn default_true() -> bool {
    true
}

/// Return payload verbosity for write operations.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReturningMode {
    /// Ask PostgREST to return no row body.
    Minimal,
    /// Ask PostgREST to return the mutated rows.
    #[default]
    Representation,
}

impl ReturningMode {
    #[must_use]
    pub const fn as_prefer_token(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Representation => "representation",
        }
    }
}

/// Structured PostgREST filter clause.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFilter {
    /// Column name to filter on.
    pub column: String,
    /// PostgREST operator (`eq`, `lt`, `ilike`, `in`, `is`, ...).
    pub operator: String,
    /// Right-hand-side filter value.
    pub value: serde_json::Value,
}

/// Structured ordering clause.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryOrder {
    /// Column to order by.
    pub column: String,
    /// Sort direction. Defaults to ascending.
    #[serde(default = "default_true")]
    pub ascending: bool,
    /// Optional null ordering preference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nulls_first: Option<bool>,
}

/// Read request against a PostgREST table/view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableQueryRequest {
    /// Table or view name.
    pub table: String,
    /// PostgREST select projection.
    #[serde(default = "default_select")]
    pub select: String,
    /// Optional filter list.
    #[serde(default)]
    pub filters: Vec<QueryFilter>,
    /// Optional ordering clauses.
    #[serde(default)]
    pub order: Vec<QueryOrder>,
    /// Optional page size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    /// Optional offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Optional explicit schema. Falls back to connector config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Request exactly one object back.
    #[serde(default)]
    pub single: bool,
}

/// Insert rows into a table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertRequest {
    /// Target table.
    pub table: String,
    /// Rows to insert.
    #[serde(default)]
    pub rows: Vec<serde_json::Value>,
    /// Optional explicit schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// PostgREST return preference.
    #[serde(default)]
    pub returning: ReturningMode,
}

/// Update rows matching filters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRequest {
    /// Target table.
    pub table: String,
    /// Patch object.
    pub values: serde_json::Value,
    /// Required filters.
    #[serde(default)]
    pub filters: Vec<QueryFilter>,
    /// Optional explicit schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// PostgREST return preference.
    #[serde(default)]
    pub returning: ReturningMode,
}

/// Upsert rows with conflict handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertRequest {
    /// Target table.
    pub table: String,
    /// Rows to merge.
    #[serde(default)]
    pub rows: Vec<serde_json::Value>,
    /// Conflict columns.
    #[serde(default)]
    pub on_conflict: Vec<String>,
    /// Use ignore-duplicates instead of merge-duplicates.
    #[serde(default)]
    pub ignore_duplicates: bool,
    /// Optional explicit schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// PostgREST return preference.
    #[serde(default)]
    pub returning: ReturningMode,
}

/// Delete rows matching filters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    /// Target table.
    pub table: String,
    /// Required filters.
    #[serde(default)]
    pub filters: Vec<QueryFilter>,
    /// Optional explicit schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// PostgREST return preference.
    #[serde(default)]
    pub returning: ReturningMode,
}

/// RPC invocation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    /// Database function name.
    pub function: String,
    /// JSON arguments payload.
    #[serde(default = "default_rpc_args")]
    pub args: serde_json::Value,
    /// Optional explicit schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
}

fn default_rpc_args() -> serde_json::Value {
    serde_json::json!({})
}

/// Schema introspection request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchemaTablesRequest {
    /// Optional schema label echoed in the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
}

/// Upload a file into Storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageUploadRequest {
    /// Bucket name.
    pub bucket: String,
    /// Object path inside the bucket.
    pub path: String,
    /// Base64-encoded content bytes.
    pub content_base64: String,
    /// Optional content type override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Overwrite an existing object.
    #[serde(default)]
    pub upsert: bool,
}

/// Download a file from Storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDownloadRequest {
    /// Bucket name.
    pub bucket: String,
    /// Object path inside the bucket.
    pub path: String,
    /// Read via the public URL path instead of the authenticated path.
    #[serde(default)]
    pub public: bool,
    /// Optional custom download filename.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_filename: Option<String>,
}

/// Delete a file from Storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDeleteRequest {
    /// Bucket name.
    pub bucket: String,
    /// Object path inside the bucket.
    pub path: String,
}

/// Normalized JSON response wrapper from PostgREST/Storage calls.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonHttpResponse {
    /// Response payload.
    pub data: serde_json::Value,
    /// HTTP status code.
    pub status_code: u16,
    /// Optional content-range header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_range: Option<String>,
    /// Optional content-type header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Normalized binary download response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryHttpResponse {
    /// Base64-encoded response bytes.
    pub content_base64: String,
    /// HTTP status code.
    pub status_code: u16,
    /// Optional content-type header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Optional content-length header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    /// Optional entity tag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Optional cache-control header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<String>,
}

/// Entry extracted from the PostgREST OpenAPI root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableCatalogEntry {
    /// Resource name (path tail).
    pub name: String,
    /// OpenAPI resource path.
    pub path: String,
    /// Supported HTTP verbs on the resource.
    pub methods: Vec<String>,
}

/// Parsed OpenAPI-derived table list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaTablesResponse {
    /// Echoed schema label.
    pub schema: String,
    /// Exposed table/view resources.
    pub tables: Vec<TableCatalogEntry>,
}

/// Minimal OpenAPI document root used for schema introspection.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenApiDocument {
    /// OpenAPI metadata.
    pub info: Option<OpenApiInfo>,
    /// Path map.
    #[serde(default)]
    pub paths: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Minimal OpenAPI info block.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenApiInfo {
    /// API title.
    pub title: Option<String>,
    /// API version.
    pub version: Option<String>,
}

/// Common error response body from Supabase services.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// Human-readable message.
    pub message: Option<String>,
    /// Alternate error text field.
    pub error: Option<String>,
    /// Provider-specific code.
    pub code: Option<String>,
    /// Additional details.
    pub details: Option<String>,
    /// Optional hint text.
    pub hint: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn returning_mode_defaults_to_representation() {
        let mode = ReturningMode::default();
        assert_eq!(mode.as_prefer_token(), "representation");
    }

    #[test]
    fn returning_mode_minimal_token() {
        assert_eq!(ReturningMode::Minimal.as_prefer_token(), "minimal");
    }

    #[test]
    fn deserialize_table_query_minimal() {
        let json = json!({"table": "todos"});
        let req: TableQueryRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.table, "todos");
        assert_eq!(req.select, "*");
        assert!(req.filters.is_empty());
        assert!(req.limit.is_none());
        assert!(!req.single);
    }

    #[test]
    fn deserialize_table_query_full() {
        let json = json!({
            "table": "todos",
            "select": "id,title",
            "filters": [{"column": "status", "operator": "eq", "value": "open"}],
            "order": [{"column": "id", "ascending": false, "nulls_first": true}],
            "limit": 25,
            "offset": 10,
            "schema": "public",
            "single": true
        });
        let req: TableQueryRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.table, "todos");
        assert_eq!(req.select, "id,title");
        assert_eq!(req.filters.len(), 1);
        assert_eq!(req.order.len(), 1);
        assert!(!req.order[0].ascending);
        assert_eq!(req.order[0].nulls_first, Some(true));
        assert_eq!(req.limit, Some(25));
        assert_eq!(req.offset, Some(10));
        assert!(req.single);
    }

    #[test]
    fn deserialize_insert_request() {
        let json = json!({
            "table": "todos",
            "rows": [{"title": "Ship it"}]
        });
        let req: InsertRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.table, "todos");
        assert_eq!(req.rows.len(), 1);
        assert_eq!(req.returning.as_prefer_token(), "representation");
    }

    #[test]
    fn deserialize_update_request() {
        let json = json!({
            "table": "todos",
            "values": {"status": "done"},
            "filters": [{"column": "id", "operator": "eq", "value": 42}]
        });
        let req: UpdateRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.table, "todos");
        assert!(req.values.is_object());
        assert_eq!(req.filters.len(), 1);
    }

    #[test]
    fn deserialize_upsert_request() {
        let json = json!({
            "table": "profiles",
            "rows": [{"id": "u1", "name": "Test"}],
            "on_conflict": ["id"],
            "ignore_duplicates": true
        });
        let req: UpsertRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.on_conflict, vec!["id"]);
        assert!(req.ignore_duplicates);
    }

    #[test]
    fn deserialize_delete_request() {
        let json = json!({
            "table": "todos",
            "filters": [{"column": "id", "operator": "eq", "value": 1}]
        });
        let req: DeleteRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.table, "todos");
        assert_eq!(req.filters.len(), 1);
    }

    #[test]
    fn deserialize_rpc_request() {
        let json = json!({"function": "search_todos", "args": {"q": "test"}});
        let req: RpcRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.function, "search_todos");
        assert_eq!(req.args["q"], "test");
    }

    #[test]
    fn rpc_request_default_args() {
        let json = json!({"function": "ping"});
        let req: RpcRequest = serde_json::from_value(json).unwrap();
        assert!(req.args.is_object());
    }

    #[test]
    fn deserialize_schema_tables_request() {
        let req: SchemaTablesRequest = serde_json::from_value(json!({})).unwrap();
        assert!(req.schema.is_none());

        let req2: SchemaTablesRequest =
            serde_json::from_value(json!({"schema": "public"})).unwrap();
        assert_eq!(req2.schema.unwrap(), "public");
    }

    #[test]
    fn deserialize_storage_upload() {
        let json = json!({
            "bucket": "artifacts",
            "path": "reports/out.txt",
            "content_base64": "SGVsbG8=",
            "content_type": "text/plain",
            "upsert": true
        });
        let req: StorageUploadRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.bucket, "artifacts");
        assert_eq!(req.path, "reports/out.txt");
        assert!(req.upsert);
        assert_eq!(req.content_type.unwrap(), "text/plain");
    }

    #[test]
    fn deserialize_storage_download() {
        let json = json!({"bucket": "artifacts", "path": "reports/out.txt", "public": true});
        let req: StorageDownloadRequest = serde_json::from_value(json).unwrap();
        assert!(req.public);
        assert!(req.download_filename.is_none());
    }

    #[test]
    fn deserialize_storage_delete() {
        let json = json!({"bucket": "artifacts", "path": "reports/out.txt"});
        let req: StorageDeleteRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.bucket, "artifacts");
    }

    #[test]
    fn deserialize_api_error_response() {
        let json = json!({
            "message": "relation does not exist",
            "code": "42P01",
            "details": "Missing from clause",
            "hint": "Check table name"
        });
        let resp: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.message.unwrap(), "relation does not exist");
        assert_eq!(resp.code.unwrap(), "42P01");
        assert_eq!(resp.hint.unwrap(), "Check table name");
    }

    #[test]
    fn deserialize_openapi_document() {
        let json = json!({
            "info": {"title": "PostgREST API", "version": "12.0.0"},
            "paths": {
                "/todos": {"get": {}, "post": {}},
                "/rpc/my_func": {"post": {}}
            }
        });
        let doc: OpenApiDocument = serde_json::from_value(json).unwrap();
        assert_eq!(
            doc.info.as_ref().unwrap().title.as_deref(),
            Some("PostgREST API")
        );
        assert_eq!(doc.paths.len(), 2);
    }

    #[test]
    fn query_order_defaults_ascending() {
        let json = json!({"column": "id"});
        let order: QueryOrder = serde_json::from_value(json).unwrap();
        assert!(order.ascending);
        assert!(order.nulls_first.is_none());
    }

    #[test]
    fn json_http_response_roundtrip() {
        let resp = JsonHttpResponse {
            data: json!({"id": 1}),
            status_code: 200,
            content_range: Some("0-9/100".into()),
            content_type: Some("application/json".into()),
        };
        let serialized = serde_json::to_value(&resp).unwrap();
        assert_eq!(serialized["status_code"], 200);
        assert_eq!(serialized["content_range"], "0-9/100");
    }

    #[test]
    fn binary_http_response_roundtrip() {
        let resp = BinaryHttpResponse {
            content_base64: "SGVsbG8=".into(),
            status_code: 200,
            content_type: Some("text/plain".into()),
            content_length: Some(5),
            etag: None,
            cache_control: None,
        };
        let serialized = serde_json::to_value(&resp).unwrap();
        assert_eq!(serialized["content_base64"], "SGVsbG8=");
        assert!(serialized.get("etag").is_none());
    }

    #[test]
    fn schema_tables_response_roundtrip() {
        let resp = SchemaTablesResponse {
            schema: "public".into(),
            tables: vec![TableCatalogEntry {
                name: "todos".into(),
                path: "/todos".into(),
                methods: vec!["get".into(), "post".into()],
            }],
        };
        let serialized = serde_json::to_value(&resp).unwrap();
        assert_eq!(serialized["tables"][0]["name"], "todos");
    }
}
