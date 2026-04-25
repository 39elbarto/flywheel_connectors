//! Operation types and typed GraphQL traits.

use serde::{Deserialize, Serialize};

use crate::error::GraphqlError;

/// GraphQL query wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GraphqlQuery {
    query: String,
}

impl GraphqlQuery {
    /// Create a new query from a string.
    #[must_use]
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: query.into(),
        }
    }

    /// Create a new query from a static string.
    #[must_use]
    pub fn from_static(query: &'static str) -> Self {
        Self::new(query)
    }

    /// Return the query text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.query
    }
}

/// Typed GraphQL operation definition.
///
/// Implement this trait for each query/mutation/subscription.
pub trait GraphqlOperation {
    /// Variables type.
    type Variables: Serialize + Send + Sync;
    /// Response data type.
    type ResponseData: Serialize + for<'de> Deserialize<'de> + Send + Sync;

    /// GraphQL query text.
    const QUERY: &'static str;
    /// Operation name (used for observability and routing).
    const OPERATION_NAME: &'static str;

    /// Optional JSON Schema for variables.
    fn variables_schema() -> Option<&'static str> {
        None
    }

    /// Optional JSON Schema for response data.
    fn response_schema() -> Option<&'static str> {
        None
    }

    /// Whether this operation is safe to retry on transport errors.
    fn is_idempotent() -> bool {
        true
    }
}

/// GraphQL request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlRequest<V> {
    /// Query text.
    pub query: GraphqlQuery,
    /// Variables.
    pub variables: V,
    /// Optional operation name.
    #[serde(rename = "operationName", skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
}

impl<V> GraphqlRequest<V> {
    /// Create a new request.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(query: GraphqlQuery, variables: V) -> Self {
        Self {
            query,
            variables,
            operation_name: None,
        }
    }

    /// Attach an operation name.
    #[must_use]
    pub fn with_operation_name(mut self, name: impl Into<String>) -> Self {
        self.operation_name = Some(name.into());
        self
    }
}

/// GraphQL batch item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphqlBatchItem<V> {
    /// Query text.
    pub query: GraphqlQuery,
    /// Variables payload.
    pub variables: V,
    /// Optional operation name.
    #[serde(rename = "operationName", skip_serializing_if = "Option::is_none")]
    pub operation_name: Option<String>,
}

impl<V> GraphqlBatchItem<V> {
    /// Create a batch item.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(query: GraphqlQuery, variables: V) -> Self {
        Self {
            query,
            variables,
            operation_name: None,
        }
    }

    /// Attach an operation name.
    #[must_use]
    pub fn with_operation_name(mut self, name: impl Into<String>) -> Self {
        self.operation_name = Some(name.into());
        self
    }
}

/// GraphQL response container.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
pub struct GraphqlResponse<T> {
    /// Response data.
    #[serde(default)]
    pub data: Option<T>,
    /// GraphQL errors.
    #[serde(default)]
    pub errors: Vec<GraphqlError>,
    /// Extensions payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl<T> GraphqlResponse<T> {
    /// Returns `true` if no GraphQL errors were returned.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- GraphqlQuery ----

    #[test]
    fn query_new_and_as_str() {
        let q = GraphqlQuery::new("{ users { id } }");
        assert_eq!(q.as_str(), "{ users { id } }");
    }

    #[test]
    fn query_from_static() {
        let q = GraphqlQuery::from_static("query Foo { bar }");
        assert_eq!(q.as_str(), "query Foo { bar }");
    }

    #[test]
    fn query_serde_roundtrip() {
        let q = GraphqlQuery::new("{ ping }");
        let json = serde_json::to_string(&q).unwrap();
        assert_eq!(json, "\"{ ping }\"");
        let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn query_clone_eq() {
        let q = GraphqlQuery::new("{ x }");
        let q2 = q.clone();
        assert_eq!(q, q2);
    }

    // ---- GraphqlRequest ----

    #[test]
    fn request_new_no_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        assert!(req.operation_name.is_none());
    }

    #[test]
    fn request_with_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("GetUsers");
        assert_eq!(req.operation_name.as_deref(), Some("GetUsers"));
    }

    #[test]
    fn request_serde_roundtrip() {
        let req = GraphqlRequest::new(
            GraphqlQuery::new("query Q($id: ID!) { user(id: $id) { name } }"),
            serde_json::json!({"id": "123"}),
        )
        .with_operation_name("Q");
        let json = serde_json::to_string(&req).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "query": "query Q($id: ID!) { user(id: $id) { name } }",
                "variables": {"id": "123"},
                "operationName": "Q"
            })
        );
        let back: GraphqlRequest<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.operation_name.as_deref(), Some("Q"));
        assert_eq!(back.variables["id"], "123");
    }

    #[test]
    fn request_serde_skips_none_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("operation_name"));
        assert!(!json.contains("operationName"));
    }

    // ---- GraphqlBatchItem ----

    #[test]
    fn batch_item_new() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        assert!(item.operation_name.is_none());
    }

    #[test]
    fn batch_item_with_operation_name() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("Op");
        assert_eq!(item.operation_name.as_deref(), Some("Op"));
    }

    // ---- GraphqlResponse ----

    #[test]
    fn response_is_ok_when_no_errors() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: Some(serde_json::json!({"user": "alice"})),
            errors: vec![],
            extensions: None,
        };
        assert!(resp.is_ok());
    }

    #[test]
    fn response_is_not_ok_when_errors() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: None,
            errors: vec![GraphqlError {
                message: "not found".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            }],
            extensions: None,
        };
        assert!(!resp.is_ok());
    }

    #[test]
    fn response_serde_roundtrip() {
        let resp = GraphqlResponse {
            data: Some(serde_json::json!({"count": 42})),
            errors: vec![],
            extensions: Some(serde_json::json!({"trace_id": "abc"})),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: GraphqlResponse<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.data.unwrap()["count"], 42);
        assert!(back.errors.is_empty());
        assert!(back.extensions.is_some());
    }

    #[test]
    fn response_minimal_json() {
        let json = "{}";
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_none());
        assert!(resp.errors.is_empty());
        assert!(resp.extensions.is_none());
        assert!(resp.is_ok());
    }

    #[test]
    fn response_with_partial_data_and_errors() {
        let json = r#"{"data":{"user":null},"errors":[{"message":"Not authorized"}]}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_some());
        assert!(!resp.is_ok());
        assert_eq!(resp.errors.len(), 1);
    }

    #[test]
    fn request_and_response_shape_snapshot() {
        let request = GraphqlRequest::new(
            GraphqlQuery::new(
                "query ViewerById($id: ID!, $includeTeams: Boolean!) {\n  viewer(id: $id) {\n    id\n    teams @include(if: $includeTeams) {\n      id\n      slug\n    }\n  }\n}",
            ),
            serde_json::json!({
                "id": "[id]",
                "includeTeams": true,
            }),
        )
        .with_operation_name("ViewerById");
        let response = GraphqlResponse::<serde_json::Value> {
            data: Some(serde_json::json!({
                "viewer": {
                    "id": "[id]",
                    "teams": [
                        {
                            "id": "[id]",
                            "slug": "platform"
                        }
                    ]
                }
            })),
            errors: vec![GraphqlError {
                message: "viewer team edge is stale".into(),
                locations: vec![crate::error::GraphqlErrorLocation { line: 4, column: 7 }],
                path: vec![
                    crate::error::GraphqlPathSegment::Key("viewer".into()),
                    crate::error::GraphqlPathSegment::Key("teams".into()),
                    crate::error::GraphqlPathSegment::Index(0),
                ],
                extensions: Some(serde_json::json!({
                    "code": "STALE_EDGE",
                    "trace_id": "[trace-id]",
                })),
            }],
            extensions: Some(serde_json::json!({
                "cost": 7,
                "request_id": "[request-id]",
            })),
        };

        insta::assert_json_snapshot!(
            "request_and_response_shape_snapshot",
            serde_json::json!({
                "request": serde_json::to_value(&request).unwrap(),
                "response": serde_json::to_value(&response).unwrap(),
            })
        );
    }

    // ---- GraphqlQuery additional tests ----

    #[test]
    fn query_debug() {
        let q = GraphqlQuery::new("{ users { id } }");
        let dbg = format!("{q:?}");
        assert!(dbg.contains("GraphqlQuery"));
        assert!(dbg.contains("users"));
    }

    #[test]
    fn query_empty_string() {
        let q = GraphqlQuery::new("");
        assert_eq!(q.as_str(), "");
    }

    #[test]
    fn query_unicode_content() {
        let q = GraphqlQuery::new("{ benutzer { name } }");
        assert_eq!(q.as_str(), "{ benutzer { name } }");
    }

    #[test]
    fn query_multiline() {
        let q = GraphqlQuery::new("{\n  users {\n    id\n    name\n  }\n}");
        assert!(q.as_str().contains('\n'));
        let json = serde_json::to_string(&q).unwrap();
        let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn query_with_variables_placeholder() {
        let q = GraphqlQuery::new("query GetUser($id: ID!) { user(id: $id) { name } }");
        assert!(q.as_str().contains("$id"));
    }

    #[test]
    fn query_inequality() {
        let a = GraphqlQuery::new("{ a }");
        let b = GraphqlQuery::new("{ b }");
        assert_ne!(a, b);
    }

    // ---- GraphqlRequest additional tests ----

    #[test]
    fn request_debug() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        let dbg = format!("{req:?}");
        assert!(dbg.contains("GraphqlRequest"));
    }

    #[test]
    fn request_clone() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({"a": 1}))
            .with_operation_name("Op");
        let cloned = req.clone();
        assert_eq!(req.query, cloned.query);
        assert_eq!(req.operation_name, cloned.operation_name);
    }

    #[test]
    fn request_with_complex_variables() {
        let vars = serde_json::json!({
            "input": {
                "name": "Alice",
                "tags": ["admin", "user"],
                "nested": {"deep": true}
            }
        });
        let req = GraphqlRequest::new(
            GraphqlQuery::new("mutation Create($input: Input!) { create(input: $input) { id } }"),
            vars,
        );
        let json = serde_json::to_string(&req).unwrap();
        let back: GraphqlRequest<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.variables["input"]["name"], "Alice");
        assert!(back.variables["input"]["tags"].is_array());
    }

    #[test]
    fn request_with_null_variables() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ ping }"), serde_json::Value::Null);
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("null"));
    }

    // ---- GraphqlBatchItem additional tests ----

    #[test]
    fn batch_item_debug() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        let dbg = format!("{item:?}");
        assert!(dbg.contains("GraphqlBatchItem"));
    }

    #[test]
    fn batch_item_clone() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({"k": "v"}))
            .with_operation_name("BatchOp");
        let cloned = item.clone();
        assert_eq!(item.operation_name, cloned.operation_name);
        assert_eq!(item.query, cloned.query);
    }

    #[test]
    fn batch_item_serde_roundtrip() {
        let item = GraphqlBatchItem::new(
            GraphqlQuery::new("{ users { id } }"),
            serde_json::json!({"limit": 10}),
        )
        .with_operation_name("GetUsers");
        let json = serde_json::to_string(&item).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "query": "{ users { id } }",
                "variables": {"limit": 10},
                "operationName": "GetUsers"
            })
        );
        let back: GraphqlBatchItem<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.operation_name.as_deref(), Some("GetUsers"));
        assert_eq!(back.variables["limit"], 10);
    }

    #[test]
    fn batch_item_skips_none_operation_name() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        let json = serde_json::to_string(&item).unwrap();
        assert!(!json.contains("operation_name"));
        assert!(!json.contains("operationName"));
    }

    // ---- GraphqlResponse additional tests ----

    #[test]
    fn response_debug() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: Some(serde_json::json!({})),
            errors: vec![],
            extensions: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("GraphqlResponse"));
    }

    #[test]
    fn response_clone() {
        let resp = GraphqlResponse {
            data: Some(serde_json::json!({"x": 1})),
            errors: vec![],
            extensions: Some(serde_json::json!({"trace": "abc"})),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.data.unwrap()["x"], 1);
        assert!(resp.data.is_some());
    }

    #[test]
    fn response_with_multiple_errors() {
        let json = r#"{"errors":[{"message":"a"},{"message":"b"},{"message":"c"}]}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert_eq!(resp.errors.len(), 3);
        assert!(!resp.is_ok());
        assert!(resp.data.is_none());
    }

    #[test]
    fn response_extensions_only() {
        let json = r#"{"extensions":{"requestId":"xyz-123"}}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_none());
        assert!(resp.is_ok());
        assert_eq!(resp.extensions.unwrap()["requestId"], "xyz-123");
    }

    #[test]
    fn response_skips_none_extensions_in_serialization() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: Some(serde_json::json!({})),
            errors: vec![],
            extensions: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("extensions"));
    }

    // ---- GraphqlQuery from String (not &str) ----

    #[test]
    fn query_from_owned_string() {
        let owned = String::from("mutation { createUser { id } }");
        let q = GraphqlQuery::new(owned);
        assert!(q.as_str().contains("createUser"));
    }

    #[test]
    fn query_from_static_long_query() {
        let q = GraphqlQuery::from_static(
            "query GetUsersWithFilters($filter: FilterInput!, $limit: Int, $offset: Int) { users(filter: $filter, limit: $limit, offset: $offset) { id name email } }",
        );
        assert!(q.as_str().contains("FilterInput"));
        assert!(q.as_str().contains("$limit"));
    }

    #[test]
    fn query_with_fragment() {
        let q = GraphqlQuery::new(
            "fragment UserFields on User { id name } query { users { ...UserFields } }",
        );
        assert!(q.as_str().contains("fragment"));
        assert!(q.as_str().contains("UserFields"));
    }

    #[test]
    fn query_eq_same_content_different_construction() {
        let a = GraphqlQuery::new("{ x }");
        let b = GraphqlQuery::from_static("{ x }");
        assert_eq!(a, b);
    }

    #[test]
    fn query_serde_preserves_whitespace() {
        let q = GraphqlQuery::new("{\n  users  {\n    id\n  }\n}");
        let json = serde_json::to_string(&q).unwrap();
        let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
        assert!(back.as_str().contains('\n'));
        assert_eq!(q, back);
    }

    // ---- GraphqlRequest edge cases ----

    #[test]
    fn request_with_empty_variables() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ ping }"), serde_json::json!({}));
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("{}"));
    }

    #[test]
    fn request_with_array_variables() {
        let vars = serde_json::json!({"ids": [1, 2, 3]});
        let req = GraphqlRequest::new(
            GraphqlQuery::new("query($ids: [Int!]!) { byIds(ids: $ids) { id } }"),
            vars,
        );
        let json = serde_json::to_string(&req).unwrap();
        let back: GraphqlRequest<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert!(back.variables["ids"].is_array());
        assert_eq!(back.variables["ids"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn request_operation_name_overwrite() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("First")
            .with_operation_name("Second");
        assert_eq!(req.operation_name.as_deref(), Some("Second"));
    }

    #[test]
    fn request_serde_includes_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("MyOp");
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("MyOp"));
        assert!(json.contains("operationName"));
        assert!(!json.contains("operation_name"));
    }

    // ---- GraphqlBatchItem edge cases ----

    #[test]
    fn batch_item_serde_with_complex_vars() {
        let vars = serde_json::json!({
            "input": {"name": "test", "tags": ["a", "b"]},
            "limit": 50
        });
        let item = GraphqlBatchItem::new(GraphqlQuery::new("mutation M { m }"), vars)
            .with_operation_name("M");
        let json = serde_json::to_string(&item).unwrap();
        let back: GraphqlBatchItem<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.variables["limit"], 50);
        assert_eq!(back.operation_name.as_deref(), Some("M"));
    }

    #[test]
    fn batch_item_operation_name_overwrite() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("A")
            .with_operation_name("B");
        assert_eq!(item.operation_name.as_deref(), Some("B"));
    }

    #[test]
    fn batch_item_with_null_variables() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::Value::Null);
        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("null"));
    }

    // ---- GraphqlResponse edge cases ----

    #[test]
    fn response_data_none_no_errors_is_ok() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: None,
            errors: vec![],
            extensions: None,
        };
        assert!(resp.is_ok());
    }

    #[test]
    fn response_data_some_with_errors_is_not_ok() {
        let resp = GraphqlResponse {
            data: Some(serde_json::json!({"partial": true})),
            errors: vec![GraphqlError {
                message: "partial error".into(),
                locations: vec![],
                path: vec![],
                extensions: None,
            }],
            extensions: None,
        };
        assert!(!resp.is_ok());
    }

    #[test]
    fn response_serde_with_typed_data() {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
        struct User {
            id: String,
            name: String,
        }
        let resp = GraphqlResponse {
            data: Some(User {
                id: "1".into(),
                name: "Alice".into(),
            }),
            errors: vec![],
            extensions: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: GraphqlResponse<User> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.data.unwrap().name, "Alice");
    }

    #[test]
    fn response_deserialized_from_server_format() {
        let json = r#"{
            "data": {"viewer": {"login": "test-user"}},
            "errors": [],
            "extensions": {"cost": {"requestedQueryCost": 1}}
        }"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.is_ok());
        assert_eq!(resp.data.unwrap()["viewer"]["login"], "test-user");
        assert!(resp.extensions.is_some());
    }

    #[test]
    fn response_data_null_deserialized_as_none() {
        let json = r#"{"data": null}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_none());
        assert!(resp.is_ok());
    }

    #[test]
    fn response_with_only_errors() {
        let json = r#"{"errors":[{"message":"forbidden"}]}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.data.is_none());
        assert!(!resp.is_ok());
        assert_eq!(resp.errors[0].message, "forbidden");
    }

    #[test]
    fn response_clone_preserves_errors() {
        let resp = GraphqlResponse::<serde_json::Value> {
            data: None,
            errors: vec![
                GraphqlError {
                    message: "err1".into(),
                    locations: vec![],
                    path: vec![],
                    extensions: None,
                },
                GraphqlError {
                    message: "err2".into(),
                    locations: vec![],
                    path: vec![],
                    extensions: None,
                },
            ],
            extensions: None,
        };
        let cloned = resp.clone();
        assert_eq!(resp.errors.len(), cloned.errors.len());
        assert_eq!(resp.errors.len(), 2);
    }

    // ---- GraphqlOperation trait tests ----

    #[derive(Debug)]
    struct TestOp;

    #[derive(Debug, Serialize, Deserialize)]
    struct TestVars {
        id: String,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        name: String,
    }

    impl GraphqlOperation for TestOp {
        type Variables = TestVars;
        type ResponseData = TestData;

        const QUERY: &'static str = "query GetUser($id: ID!) { user(id: $id) { name } }";
        const OPERATION_NAME: &'static str = "GetUser";
    }

    #[test]
    fn trait_defaults_variables_schema_none() {
        assert!(TestOp::variables_schema().is_none());
    }

    #[test]
    fn trait_defaults_response_schema_none() {
        assert!(TestOp::response_schema().is_none());
    }

    #[test]
    fn trait_defaults_is_idempotent_true() {
        assert!(TestOp::is_idempotent());
    }

    #[test]
    fn trait_query_constant() {
        assert!(TestOp::QUERY.contains("GetUser"));
        assert!(TestOp::QUERY.contains("$id"));
    }

    #[test]
    fn trait_operation_name_constant() {
        assert_eq!(TestOp::OPERATION_NAME, "GetUser");
    }

    // ---- Non-idempotent operation test ----

    struct MutationOp;

    impl GraphqlOperation for MutationOp {
        type Variables = serde_json::Value;
        type ResponseData = serde_json::Value;

        const QUERY: &'static str = "mutation CreateUser { createUser { id } }";
        const OPERATION_NAME: &'static str = "CreateUser";

        fn is_idempotent() -> bool {
            false
        }

        fn variables_schema() -> Option<&'static str> {
            Some(r#"{"type":"object"}"#)
        }

        fn response_schema() -> Option<&'static str> {
            Some(r#"{"type":"object"}"#)
        }
    }

    #[test]
    fn mutation_op_not_idempotent() {
        assert!(!MutationOp::is_idempotent());
    }

    #[test]
    fn mutation_op_has_schemas() {
        assert!(MutationOp::variables_schema().is_some());
        assert!(MutationOp::response_schema().is_some());
    }

    // ---- GraphqlQuery edge cases ----

    #[test]
    fn query_very_long_string() {
        let long = "a".repeat(10_000);
        let q = GraphqlQuery::new(long);
        assert_eq!(q.as_str().len(), 10_000);
        let json = serde_json::to_string(&q).unwrap();
        let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn query_with_special_json_chars() {
        let q = GraphqlQuery::new(r#"{ user(name: "test\"escaped") { id } }"#);
        let json = serde_json::to_string(&q).unwrap();
        let back: GraphqlQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(q, back);
    }

    #[test]
    fn query_with_tab_and_carriage_return() {
        let q = GraphqlQuery::new("{\t\r\n  users { id }\r\n}");
        assert!(q.as_str().contains('\t'));
        assert!(q.as_str().contains('\r'));
    }

    // ---- GraphqlRequest edge cases ----

    #[test]
    fn request_with_deeply_nested_variables() {
        let vars = serde_json::json!({
            "l1": {"l2": {"l3": {"l4": {"l5": "deep"}}}}
        });
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), vars);
        let json = serde_json::to_string(&req).unwrap();
        let back: GraphqlRequest<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.variables["l1"]["l2"]["l3"]["l4"]["l5"], "deep");
    }

    #[test]
    fn request_with_unicode_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("BenutzerAbfrage");
        assert_eq!(req.operation_name.as_deref(), Some("BenutzerAbfrage"));
    }

    #[test]
    fn request_with_empty_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("");
        assert_eq!(req.operation_name.as_deref(), Some(""));
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("operationName"));
        assert!(!json.contains("operation_name"));
    }

    // ---- GraphqlBatchItem edge cases ----

    #[test]
    fn batch_item_with_empty_operation_name() {
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), serde_json::json!({}))
            .with_operation_name("");
        assert_eq!(item.operation_name.as_deref(), Some(""));
    }

    #[test]
    fn batch_item_with_deeply_nested_variables() {
        let vars = serde_json::json!({"a": {"b": {"c": 42}}});
        let item = GraphqlBatchItem::new(GraphqlQuery::new("{ x }"), vars);
        let json = serde_json::to_string(&item).unwrap();
        let back: GraphqlBatchItem<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.variables["a"]["b"]["c"], 42);
    }

    // ---- GraphqlResponse edge cases ----

    #[test]
    fn response_serde_with_nested_errors_and_extensions() {
        let json = r#"{
            "data": {"count": 5},
            "errors": [
                {
                    "message": "partial",
                    "locations": [{"line": 2, "column": 3}],
                    "path": ["users", 0],
                    "extensions": {"code": "PARTIAL_RESULT"}
                }
            ],
            "extensions": {"requestId": "req-123", "cost": 7}
        }"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(!resp.is_ok());
        assert_eq!(resp.data.unwrap()["count"], 5);
        assert_eq!(resp.errors.len(), 1);
        assert_eq!(resp.errors[0].locations[0].line, 2);
        assert_eq!(resp.extensions.unwrap()["cost"], 7);
    }

    #[test]
    fn response_with_empty_data_object() {
        let json = r#"{"data":{}}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.is_ok());
        assert!(resp.data.is_some());
        assert!(resp.data.unwrap().is_object());
    }

    #[test]
    fn response_with_empty_errors_array() {
        let json = r#"{"data":null,"errors":[]}"#;
        let resp: GraphqlResponse<serde_json::Value> = serde_json::from_str(json).unwrap();
        assert!(resp.is_ok());
        assert!(resp.data.is_none());
    }

    #[test]
    fn response_clone_with_extensions() {
        let resp = GraphqlResponse {
            data: Some(serde_json::json!({"key": "val"})),
            errors: vec![],
            extensions: Some(serde_json::json!({"trace_id": "abc", "cost": 42})),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.extensions.unwrap()["trace_id"], "abc");
        assert!(resp.extensions.is_some());
    }

    #[test]
    fn response_debug_contains_struct_name() {
        let resp = GraphqlResponse::<String> {
            data: Some("hello".to_string()),
            errors: vec![],
            extensions: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("GraphqlResponse"));
        assert!(dbg.contains("hello"));
    }
}
