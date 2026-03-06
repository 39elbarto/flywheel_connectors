//! `Metabase` API types.

use serde::{Deserialize, Serialize};

/// A `Metabase` dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub id: i64,
    pub name: Option<String>,
    pub description: Option<String>,
    pub collection_id: Option<i64>,
    pub archived: Option<bool>,
}

/// A `Metabase` card (saved question).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Card {
    pub id: i64,
    pub name: Option<String>,
    pub description: Option<String>,
    pub display: Option<String>,
    pub collection_id: Option<i64>,
    pub archived: Option<bool>,
}

/// Query result returned when running a saved question.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub data: Option<QueryData>,
    pub status: Option<String>,
}

/// The data payload within a query result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryData {
    pub rows: Option<Vec<Vec<serde_json::Value>>>,
    pub cols: Option<Vec<Column>>,
}

/// A column descriptor in query results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Column {
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub base_type: Option<String>,
}

/// `Metabase` API error response body.
///
/// `Metabase` returns `{"message": "..."}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message from `Metabase`.
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dashboard_roundtrip() {
        let d: Dashboard = serde_json::from_value(json!({
            "id": 42,
            "name": "Sales Overview",
            "description": "Sales metrics dashboard",
            "collection_id": 5,
            "archived": false,
        }))
        .unwrap();
        assert_eq!(d.id, 42);
        assert_eq!(d.name, Some("Sales Overview".into()));
        assert_eq!(d.description, Some("Sales metrics dashboard".into()));
        assert_eq!(d.collection_id, Some(5));
        assert_eq!(d.archived, Some(false));
        let re = serde_json::to_value(&d).unwrap();
        assert_eq!(re["name"], "Sales Overview");
    }

    #[test]
    fn dashboard_minimal() {
        let d: Dashboard = serde_json::from_value(json!({"id": 1})).unwrap();
        assert_eq!(d.id, 1);
        assert!(d.name.is_none());
        assert!(d.description.is_none());
        assert!(d.collection_id.is_none());
        assert!(d.archived.is_none());
    }

    #[test]
    fn dashboard_serialize_roundtrip() {
        let d = Dashboard {
            id: 7,
            name: Some("Revenue".into()),
            description: None,
            collection_id: Some(3),
            archived: Some(false),
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["id"], 7);
        assert_eq!(v["name"], "Revenue");
        assert_eq!(v["collection_id"], 3);
    }

    #[test]
    fn card_roundtrip() {
        let c: Card = serde_json::from_value(json!({
            "id": 99,
            "name": "Monthly Revenue",
            "description": "Total revenue by month",
            "display": "line",
            "collection_id": 10,
            "archived": false,
        }))
        .unwrap();
        assert_eq!(c.id, 99);
        assert_eq!(c.name, Some("Monthly Revenue".into()));
        assert_eq!(c.description, Some("Total revenue by month".into()));
        assert_eq!(c.display, Some("line".into()));
        assert_eq!(c.collection_id, Some(10));
        assert_eq!(c.archived, Some(false));
        let re = serde_json::to_value(&c).unwrap();
        assert_eq!(re["display"], "line");
    }

    #[test]
    fn card_minimal() {
        let c: Card = serde_json::from_value(json!({"id": 1})).unwrap();
        assert_eq!(c.id, 1);
        assert!(c.name.is_none());
        assert!(c.description.is_none());
        assert!(c.display.is_none());
        assert!(c.collection_id.is_none());
        assert!(c.archived.is_none());
    }

    #[test]
    fn card_serialize_roundtrip() {
        let c = Card {
            id: 33,
            name: Some("Active Users".into()),
            description: None,
            display: Some("table".into()),
            collection_id: None,
            archived: None,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["id"], 33);
        assert_eq!(v["name"], "Active Users");
        assert_eq!(v["display"], "table");
    }

    #[test]
    fn query_result_roundtrip() {
        let qr: QueryResult = serde_json::from_value(json!({
            "data": {
                "rows": [[1, "Alice"], [2, "Bob"]],
                "cols": [
                    {"name": "id", "display_name": "ID", "base_type": "type/Integer"},
                    {"name": "name", "display_name": "Name", "base_type": "type/Text"},
                ]
            },
            "status": "completed",
        }))
        .unwrap();
        assert_eq!(qr.status, Some("completed".into()));
        let data = qr.data.unwrap();
        assert_eq!(data.rows.as_ref().unwrap().len(), 2);
        assert_eq!(data.cols.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn query_result_minimal() {
        let qr: QueryResult = serde_json::from_value(json!({})).unwrap();
        assert!(qr.data.is_none());
        assert!(qr.status.is_none());
    }

    #[test]
    fn query_data_empty_rows() {
        let qd: QueryData = serde_json::from_value(json!({
            "rows": [],
            "cols": []
        }))
        .unwrap();
        assert!(qd.rows.as_ref().unwrap().is_empty());
        assert!(qd.cols.as_ref().unwrap().is_empty());
    }

    #[test]
    fn column_roundtrip() {
        let col: Column = serde_json::from_value(json!({
            "name": "user_id",
            "display_name": "User ID",
            "base_type": "type/Integer",
        }))
        .unwrap();
        assert_eq!(col.name, Some("user_id".into()));
        assert_eq!(col.display_name, Some("User ID".into()));
        assert_eq!(col.base_type, Some("type/Integer".into()));
    }

    #[test]
    fn column_minimal() {
        let col: Column = serde_json::from_value(json!({})).unwrap();
        assert!(col.name.is_none());
        assert!(col.display_name.is_none());
        assert!(col.base_type.is_none());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "You don't have permissions to do that.",
        }))
        .unwrap();
        assert_eq!(e.message, Some("You don't have permissions to do that.".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
    }

    #[test]
    fn dashboard_extra_fields_ignored() {
        let d: Dashboard = serde_json::from_value(json!({
            "id": 1,
            "name": "Test",
            "creator": {"id": 1, "email": "admin@example.com"},
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(d.id, 1);
        assert_eq!(d.name, Some("Test".into()));
    }

    #[test]
    fn card_extra_fields_ignored() {
        let c: Card = serde_json::from_value(json!({
            "id": 1,
            "name": "Test",
            "database_id": 1,
            "query_type": "native",
        }))
        .unwrap();
        assert_eq!(c.id, 1);
        assert_eq!(c.name, Some("Test".into()));
    }

    #[test]
    fn query_result_with_error_status() {
        let qr: QueryResult = serde_json::from_value(json!({
            "status": "failed",
            "data": null,
        }))
        .unwrap();
        assert_eq!(qr.status, Some("failed".into()));
        assert!(qr.data.is_none());
    }

    #[test]
    fn query_data_with_mixed_types_in_rows() {
        let qd: QueryData = serde_json::from_value(json!({
            "rows": [[1, "text", true, null, 9.99]],
            "cols": [
                {"name": "int_col"},
                {"name": "str_col"},
                {"name": "bool_col"},
                {"name": "null_col"},
                {"name": "float_col"},
            ]
        }))
        .unwrap();
        let rows = qd.rows.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].len(), 5);
        assert_eq!(rows[0][0], json!(1));
        assert_eq!(rows[0][1], json!("text"));
        assert_eq!(rows[0][2], json!(true));
        assert!(rows[0][3].is_null());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn dashboard_clone() {
        let d = Dashboard {
            id: 1,
            name: Some("Revenue".into()),
            description: Some("desc".into()),
            collection_id: Some(10),
            archived: Some(false),
        };
        let cloned = d.clone();
        assert_eq!(cloned.id, 1);
        assert_eq!(cloned.name, Some("Revenue".into()));
        assert_eq!(cloned.description, Some("desc".into()));
        assert_eq!(cloned.collection_id, Some(10));
        assert_eq!(cloned.archived, Some(false));
    }

    #[test]
    fn dashboard_debug() {
        let d = Dashboard { id: 42, name: None, description: None, collection_id: None, archived: None };
        let dbg = format!("{d:?}");
        assert!(dbg.contains("Dashboard"));
        assert!(dbg.contains("42"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn card_clone() {
        let c = Card {
            id: 7,
            name: Some("Active Users".into()),
            description: None,
            display: Some("bar".into()),
            collection_id: Some(2),
            archived: Some(true),
        };
        let cloned = c.clone();
        assert_eq!(cloned.id, 7);
        assert_eq!(cloned.display, Some("bar".into()));
        assert_eq!(cloned.archived, Some(true));
    }

    #[test]
    fn card_debug() {
        let c = Card { id: 99, name: Some("Q".into()), description: None, display: None, collection_id: None, archived: None };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Card"));
        assert!(dbg.contains("99"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn query_result_clone() {
        let qr = QueryResult {
            data: Some(QueryData { rows: Some(vec![]), cols: Some(vec![]) }),
            status: Some("completed".into()),
        };
        let cloned = qr.clone();
        assert_eq!(cloned.status, Some("completed".into()));
        assert!(cloned.data.is_some());
    }

    #[test]
    fn query_result_debug() {
        let qr = QueryResult { data: None, status: None };
        let dbg = format!("{qr:?}");
        assert!(dbg.contains("QueryResult"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn query_data_clone() {
        let qd = QueryData { rows: Some(vec![vec![json!(1)]]), cols: None };
        let cloned = qd.clone();
        assert_eq!(cloned.rows.unwrap().len(), 1);
        assert!(cloned.cols.is_none());
    }

    #[test]
    fn query_data_debug() {
        let qd = QueryData { rows: None, cols: None };
        let dbg = format!("{qd:?}");
        assert!(dbg.contains("QueryData"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn column_clone() {
        let col = Column {
            name: Some("id".into()),
            display_name: Some("ID".into()),
            base_type: Some("type/Integer".into()),
        };
        let cloned = col.clone();
        assert_eq!(cloned.name, Some("id".into()));
        assert_eq!(cloned.display_name, Some("ID".into()));
    }

    #[test]
    fn column_debug() {
        let col = Column { name: Some("x".into()), display_name: None, base_type: None };
        let dbg = format!("{col:?}");
        assert!(dbg.contains("Column"));
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse { message: Some("err".into()) };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn api_error_response_clone() {
        let e = ApiErrorResponse { message: Some("test error".into()) };
        let cloned = e.clone();
        assert_eq!(cloned.message, Some("test error".into()));
    }

    #[test]
    fn dashboard_with_archived_true() {
        let d: Dashboard = serde_json::from_value(json!({
            "id": 5,
            "archived": true,
        }))
        .unwrap();
        assert_eq!(d.archived, Some(true));
    }

    #[test]
    fn dashboard_json_string_roundtrip() {
        let d = Dashboard {
            id: 100,
            name: Some("Big Dashboard".into()),
            description: Some("Very detailed".into()),
            collection_id: Some(20),
            archived: Some(false),
        };
        let json_str = serde_json::to_string(&d).unwrap();
        let d2: Dashboard = serde_json::from_str(&json_str).unwrap();
        assert_eq!(d2.id, 100);
        assert_eq!(d2.name, Some("Big Dashboard".into()));
    }

    #[test]
    fn card_all_display_types() {
        for display in &["table", "line", "bar", "pie", "scalar", "map", "pivot"] {
            let c: Card = serde_json::from_value(json!({
                "id": 1,
                "display": display,
            }))
            .unwrap();
            assert_eq!(c.display.as_deref(), Some(*display));
        }
    }

    #[test]
    fn card_json_string_roundtrip() {
        let c = Card {
            id: 55,
            name: Some("Revenue Q4".into()),
            description: Some("Quarterly revenue".into()),
            display: Some("line".into()),
            collection_id: Some(3),
            archived: Some(false),
        };
        let s = serde_json::to_string(&c).unwrap();
        let c2: Card = serde_json::from_str(&s).unwrap();
        assert_eq!(c2.id, 55);
        assert_eq!(c2.display, Some("line".into()));
    }

    #[test]
    fn query_result_serialize_roundtrip() {
        let qr = QueryResult {
            data: Some(QueryData {
                rows: Some(vec![vec![json!(1), json!("a")]]),
                cols: Some(vec![
                    Column { name: Some("id".into()), display_name: Some("ID".into()), base_type: Some("type/Integer".into()) },
                    Column { name: Some("name".into()), display_name: Some("Name".into()), base_type: Some("type/Text".into()) },
                ]),
            }),
            status: Some("completed".into()),
        };
        let s = serde_json::to_string(&qr).unwrap();
        let qr2: QueryResult = serde_json::from_str(&s).unwrap();
        assert_eq!(qr2.status, Some("completed".into()));
        let data = qr2.data.unwrap();
        assert_eq!(data.rows.unwrap().len(), 1);
        assert_eq!(data.cols.unwrap().len(), 2);
    }

    #[test]
    fn column_serialize_roundtrip() {
        let col = Column {
            name: Some("price".into()),
            display_name: Some("Price".into()),
            base_type: Some("type/Float".into()),
        };
        let s = serde_json::to_string(&col).unwrap();
        let col2: Column = serde_json::from_str(&s).unwrap();
        assert_eq!(col2.name, Some("price".into()));
        assert_eq!(col2.base_type, Some("type/Float".into()));
    }

    #[test]
    fn query_data_multiple_rows() {
        let qd: QueryData = serde_json::from_value(json!({
            "rows": [[1, "a"], [2, "b"], [3, "c"]],
            "cols": [{"name": "id"}, {"name": "val"}]
        }))
        .unwrap();
        assert_eq!(qd.rows.unwrap().len(), 3);
        assert_eq!(qd.cols.unwrap().len(), 2);
    }

    #[test]
    fn api_error_response_with_extra_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "bad request",
            "errors": {"name": "required"},
            "status": 400,
        }))
        .unwrap();
        assert_eq!(e.message, Some("bad request".into()));
    }

    #[test]
    fn dashboard_null_fields_are_none() {
        let d: Dashboard = serde_json::from_value(json!({
            "id": 1,
            "name": null,
            "description": null,
            "collection_id": null,
            "archived": null,
        }))
        .unwrap();
        assert!(d.name.is_none());
        assert!(d.description.is_none());
        assert!(d.collection_id.is_none());
        assert!(d.archived.is_none());
    }

    #[test]
    fn card_null_fields_are_none() {
        let c: Card = serde_json::from_value(json!({
            "id": 1,
            "name": null,
            "display": null,
        }))
        .unwrap();
        assert!(c.name.is_none());
        assert!(c.display.is_none());
    }
}
