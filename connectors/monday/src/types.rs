//! Monday.com API types.

use serde::{Deserialize, Serialize};

/// A Monday.com board.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Board {
    pub id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub state: Option<String>,
    pub board_kind: Option<String>,
}

/// A Monday.com item (row on a board).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub name: Option<String>,
    pub state: Option<String>,
    #[serde(default)]
    pub column_values: Vec<ColumnValue>,
}

/// A column value on a Monday.com item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnValue {
    pub id: Option<String>,
    pub text: Option<String>,
    pub value: Option<String>,
}

/// An update (comment) on a Monday.com item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Update {
    pub id: Option<String>,
    pub text_body: Option<String>,
    pub creator: Option<UpdateCreator>,
    pub created_at: Option<String>,
}

/// Creator information for an update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCreator {
    pub name: Option<String>,
}

/// Monday.com GraphQL response wrapper.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphQLResponse {
    pub data: Option<serde_json::Value>,
    pub errors: Option<Vec<GraphQLError>>,
}

/// A GraphQL error entry.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphQLError {
    pub message: String,
}

/// Monday.com API error response body (non-GraphQL errors).
///
/// Monday.com returns `{"error_message": "...", "status_code": N}` on HTTP errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message.
    pub error_message: Option<String>,
    /// Optional error code.
    pub error_code: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn board_roundtrip() {
        let b: Board = serde_json::from_value(json!({
            "id": "board_123",
            "name": "Sprint Board",
            "description": "Main sprint board",
            "state": "active",
            "board_kind": "public",
        }))
        .unwrap();
        assert_eq!(b.id, "board_123");
        assert_eq!(b.name, Some("Sprint Board".into()));
        assert_eq!(b.description, Some("Main sprint board".into()));
        assert_eq!(b.state, Some("active".into()));
        assert_eq!(b.board_kind, Some("public".into()));
        let re = serde_json::to_value(&b).unwrap();
        assert_eq!(re["name"], "Sprint Board");
    }

    #[test]
    fn board_minimal() {
        let b: Board = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(b.id, "x");
        assert!(b.name.is_none());
        assert!(b.description.is_none());
        assert!(b.state.is_none());
        assert!(b.board_kind.is_none());
    }

    #[test]
    fn item_roundtrip() {
        let i: Item = serde_json::from_value(json!({
            "id": "item_456",
            "name": "Fix login bug",
            "state": "active",
            "column_values": [
                {"id": "status", "text": "Working on it", "value": "{\"index\":1}"},
                {"id": "person", "text": "Alice", "value": null},
            ]
        }))
        .unwrap();
        assert_eq!(i.id, "item_456");
        assert_eq!(i.name, Some("Fix login bug".into()));
        assert_eq!(i.state, Some("active".into()));
        assert_eq!(i.column_values.len(), 2);
        assert_eq!(i.column_values[0].id, Some("status".into()));
        assert_eq!(i.column_values[0].text, Some("Working on it".into()));
        let re = serde_json::to_value(&i).unwrap();
        assert_eq!(re["name"], "Fix login bug");
    }

    #[test]
    fn item_minimal() {
        let i: Item = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(i.id, "x");
        assert!(i.name.is_none());
        assert!(i.state.is_none());
        assert!(i.column_values.is_empty());
    }

    #[test]
    fn item_empty_column_values() {
        let i: Item = serde_json::from_value(json!({
            "id": "item_1",
            "name": "Test",
            "column_values": []
        }))
        .unwrap();
        assert!(i.column_values.is_empty());
    }

    #[test]
    fn column_value_roundtrip() {
        let cv: ColumnValue = serde_json::from_value(json!({
            "id": "status",
            "text": "Done",
            "value": "{\"index\":2}",
        }))
        .unwrap();
        assert_eq!(cv.id, Some("status".into()));
        assert_eq!(cv.text, Some("Done".into()));
        assert_eq!(cv.value, Some("{\"index\":2}".into()));
    }

    #[test]
    fn column_value_minimal() {
        let cv: ColumnValue = serde_json::from_value(json!({})).unwrap();
        assert!(cv.id.is_none());
        assert!(cv.text.is_none());
        assert!(cv.value.is_none());
    }

    #[test]
    fn update_roundtrip() {
        let u: Update = serde_json::from_value(json!({
            "id": "upd_789",
            "text_body": "Looks good!",
            "creator": {"name": "Alice"},
            "created_at": "2026-03-01T12:00:00Z",
        }))
        .unwrap();
        assert_eq!(u.id, Some("upd_789".into()));
        assert_eq!(u.text_body, Some("Looks good!".into()));
        assert!(u.creator.is_some());
        assert_eq!(u.creator.unwrap().name, Some("Alice".into()));
        assert_eq!(u.created_at, Some("2026-03-01T12:00:00Z".into()));
    }

    #[test]
    fn update_minimal() {
        let u: Update = serde_json::from_value(json!({})).unwrap();
        assert!(u.id.is_none());
        assert!(u.text_body.is_none());
        assert!(u.creator.is_none());
        assert!(u.created_at.is_none());
    }

    #[test]
    fn update_creator_roundtrip() {
        let c: UpdateCreator = serde_json::from_value(json!({"name": "Bob"})).unwrap();
        assert_eq!(c.name, Some("Bob".into()));
    }

    #[test]
    fn graphql_response_with_data() {
        let r: GraphQLResponse = serde_json::from_value(json!({
            "data": {"boards": [{"id": "1", "name": "Board"}]},
        }))
        .unwrap();
        assert!(r.data.is_some());
        assert!(r.errors.is_none());
    }

    #[test]
    fn graphql_response_with_errors() {
        let r: GraphQLResponse = serde_json::from_value(json!({
            "errors": [{"message": "Something went wrong"}],
        }))
        .unwrap();
        assert!(r.data.is_none());
        assert!(r.errors.is_some());
        let errors = r.errors.unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].message, "Something went wrong");
    }

    #[test]
    fn graphql_response_empty() {
        let r: GraphQLResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.data.is_none());
        assert!(r.errors.is_none());
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error_message": "Not Authenticated",
            "error_code": "NOT_AUTHENTICATED",
        }))
        .unwrap();
        assert_eq!(e.error_message, Some("Not Authenticated".into()));
        assert_eq!(e.error_code, Some("NOT_AUTHENTICATED".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error_message.is_none());
        assert!(e.error_code.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error_message": "Rate limit exceeded",
        }))
        .unwrap();
        assert_eq!(e.error_message, Some("Rate limit exceeded".into()));
        assert!(e.error_code.is_none());
    }

    #[test]
    fn board_extra_fields_ignored() {
        let b: Board = serde_json::from_value(json!({
            "id": "b1",
            "name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(b.id, "b1");
        assert_eq!(b.name, Some("Test".into()));
    }

    #[test]
    fn item_extra_fields_ignored() {
        let i: Item = serde_json::from_value(json!({
            "id": "i1",
            "name": "Test",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(i.id, "i1");
        assert_eq!(i.name, Some("Test".into()));
    }

    #[test]
    fn update_extra_fields_ignored() {
        let u: Update = serde_json::from_value(json!({
            "id": "u1",
            "text_body": "Test",
            "unknown_field": true,
        }))
        .unwrap();
        assert_eq!(u.id, Some("u1".into()));
        assert_eq!(u.text_body, Some("Test".into()));
    }

    #[test]
    fn board_serialize_roundtrip() {
        let b = Board {
            id: "b1".into(),
            name: Some("My Board".into()),
            description: None,
            state: Some("active".into()),
            board_kind: Some("public".into()),
        };
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["id"], "b1");
        assert_eq!(v["name"], "My Board");
        assert_eq!(v["state"], "active");
    }

    #[test]
    fn item_serialize_roundtrip() {
        let i = Item {
            id: "i1".into(),
            name: Some("Do thing".into()),
            state: None,
            column_values: vec![ColumnValue {
                id: Some("col1".into()),
                text: Some("text".into()),
                value: None,
            }],
        };
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["id"], "i1");
        assert_eq!(v["name"], "Do thing");
        assert_eq!(v["column_values"][0]["id"], "col1");
    }

    #[test]
    fn board_clone() {
        let b = Board {
            id: "b1".into(),
            name: Some("Board".into()),
            description: Some("Desc".into()),
            state: Some("active".into()),
            board_kind: Some("public".into()),
        };
        let b2 = b.clone();
        assert_eq!(b.id, b2.id);
        assert_eq!(b.name, b2.name);
        assert_eq!(b.description, b2.description);
    }

    #[test]
    fn board_debug() {
        let b = Board {
            id: "b1".into(),
            name: None,
            description: None,
            state: None,
            board_kind: None,
        };
        let dbg = format!("{b:?}");
        assert!(dbg.contains("Board"));
        assert!(dbg.contains("b1"));
    }

    #[test]
    fn board_null_fields_serialize() {
        let b = Board {
            id: "b1".into(),
            name: None,
            description: None,
            state: None,
            board_kind: None,
        };
        let v = serde_json::to_value(&b).unwrap();
        assert!(v["name"].is_null());
        assert!(v["description"].is_null());
    }

    #[test]
    fn board_json_string_roundtrip() {
        let b = Board {
            id: "b1".into(),
            name: Some("Test".into()),
            description: None,
            state: Some("active".into()),
            board_kind: None,
        };
        let s = serde_json::to_string(&b).unwrap();
        let b2: Board = serde_json::from_str(&s).unwrap();
        assert_eq!(b2.id, "b1");
        assert_eq!(b2.name, Some("Test".into()));
    }

    #[test]
    fn item_clone() {
        let i = Item {
            id: "i1".into(),
            name: Some("Item".into()),
            state: None,
            column_values: vec![],
        };
        let i2 = i.clone();
        assert_eq!(i.id, i2.id);
        assert_eq!(i.column_values.len(), i2.column_values.len());
    }

    #[test]
    fn item_debug() {
        let i = Item {
            id: "i1".into(),
            name: None,
            state: None,
            column_values: vec![],
        };
        let dbg = format!("{i:?}");
        assert!(dbg.contains("Item"));
    }

    #[test]
    fn item_json_string_roundtrip() {
        let i = Item {
            id: "i1".into(),
            name: Some("Test".into()),
            state: Some("active".into()),
            column_values: vec![ColumnValue {
                id: Some("c1".into()),
                text: Some("t".into()),
                value: None,
            }],
        };
        let s = serde_json::to_string(&i).unwrap();
        let i2: Item = serde_json::from_str(&s).unwrap();
        assert_eq!(i2.column_values.len(), 1);
    }

    #[test]
    fn column_value_clone() {
        let cv = ColumnValue {
            id: Some("c1".into()),
            text: Some("t".into()),
            value: Some("v".into()),
        };
        let cv2 = cv.clone();
        assert_eq!(cv.id, cv2.id);
    }

    #[test]
    fn column_value_debug() {
        let cv = ColumnValue {
            id: None,
            text: None,
            value: None,
        };
        let dbg = format!("{cv:?}");
        assert!(dbg.contains("ColumnValue"));
    }

    #[test]
    fn column_value_json_string_roundtrip() {
        let cv = ColumnValue {
            id: Some("status".into()),
            text: Some("Done".into()),
            value: Some("{\"index\":2}".into()),
        };
        let s = serde_json::to_string(&cv).unwrap();
        let cv2: ColumnValue = serde_json::from_str(&s).unwrap();
        assert_eq!(cv2.text, Some("Done".into()));
    }

    #[test]
    fn update_clone() {
        let u = Update {
            id: Some("u1".into()),
            text_body: Some("body".into()),
            creator: Some(UpdateCreator {
                name: Some("Alice".into()),
            }),
            created_at: Some("2026-01-01".into()),
        };
        let u2 = u.clone();
        assert_eq!(u.id, u2.id);
        assert_eq!(
            u.creator.as_ref().unwrap().name,
            u2.creator.as_ref().unwrap().name
        );
    }

    #[test]
    fn update_debug() {
        let u = Update {
            id: None,
            text_body: None,
            creator: None,
            created_at: None,
        };
        let dbg = format!("{u:?}");
        assert!(dbg.contains("Update"));
    }

    #[test]
    fn update_json_string_roundtrip() {
        let u = Update {
            id: Some("u1".into()),
            text_body: Some("body".into()),
            creator: None,
            created_at: None,
        };
        let s = serde_json::to_string(&u).unwrap();
        let u2: Update = serde_json::from_str(&s).unwrap();
        assert_eq!(u2.id, Some("u1".into()));
    }

    #[test]
    fn update_creator_clone() {
        let c = UpdateCreator {
            name: Some("Bob".into()),
        };
        let c2 = c.clone();
        assert_eq!(c.name, c2.name);
    }

    #[test]
    fn update_creator_debug() {
        let c = UpdateCreator { name: None };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("UpdateCreator"));
    }

    #[test]
    fn update_creator_minimal() {
        let c: UpdateCreator = serde_json::from_value(json!({})).unwrap();
        assert!(c.name.is_none());
    }

    #[test]
    fn graphql_response_clone() {
        let r = GraphQLResponse {
            data: Some(json!({})),
            errors: None,
        };
        let r2 = r.clone();
        assert_eq!(r.data, r2.data);
    }

    #[test]
    fn graphql_response_debug() {
        let r = GraphQLResponse {
            data: None,
            errors: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("GraphQLResponse"));
    }

    #[test]
    fn graphql_response_with_both_data_and_errors() {
        let r: GraphQLResponse = serde_json::from_value(json!({
            "data": {"boards": []},
            "errors": [{"message": "partial error"}],
        }))
        .unwrap();
        assert!(r.data.is_some());
        assert!(r.errors.is_some());
        assert_eq!(r.errors.unwrap()[0].message, "partial error");
    }

    #[test]
    fn graphql_error_clone() {
        let e = GraphQLError {
            message: "err".into(),
        };
        let e2 = e.clone();
        assert_eq!(e.message, e2.message);
    }

    #[test]
    fn graphql_error_debug() {
        let e = GraphQLError {
            message: "err".into(),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("GraphQLError"));
    }

    #[test]
    fn graphql_response_multiple_errors() {
        let r: GraphQLResponse = serde_json::from_value(json!({
            "errors": [
                {"message": "first error"},
                {"message": "second error"},
            ],
        }))
        .unwrap();
        let errors = r.errors.unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[1].message, "second error");
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            error_message: Some("msg".into()),
            error_code: Some("code".into()),
        };
        let e2 = e.clone();
        assert_eq!(e.error_message, e2.error_message);
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse {
            error_message: None,
            error_code: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_response_extra_fields_ignored() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error_message": "Bad",
            "extra_field": "ignored",
        }))
        .unwrap();
        assert_eq!(e.error_message, Some("Bad".into()));
    }

    #[test]
    fn item_multiple_column_values() {
        let i: Item = serde_json::from_value(json!({
            "id": "item_1",
            "column_values": [
                {"id": "c1", "text": "A"},
                {"id": "c2", "text": "B"},
                {"id": "c3", "text": "C"},
            ]
        }))
        .unwrap();
        assert_eq!(i.column_values.len(), 3);
        assert_eq!(i.column_values[2].id, Some("c3".into()));
    }

    #[test]
    fn column_value_extra_fields_ignored() {
        let cv: ColumnValue = serde_json::from_value(json!({
            "id": "c1",
            "text": "t",
            "extra": true,
        }))
        .unwrap();
        assert_eq!(cv.id, Some("c1".into()));
    }
}
