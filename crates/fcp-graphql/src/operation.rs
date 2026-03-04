//! Operation types and typed GraphQL traits.

use serde::{Deserialize, Serialize};

use crate::error::GraphqlError;

/// GraphQL query wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(skip_serializing_if = "Option::is_none")]
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
        let back: GraphqlRequest<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.operation_name.as_deref(), Some("Q"));
        assert_eq!(back.variables["id"], "123");
    }

    #[test]
    fn request_serde_skips_none_operation_name() {
        let req = GraphqlRequest::new(GraphqlQuery::new("{ x }"), serde_json::json!({}));
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("operation_name"));
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
}
