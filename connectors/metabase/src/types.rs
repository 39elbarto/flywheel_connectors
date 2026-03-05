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
}
