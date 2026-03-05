//! `MongoDB` Atlas Data API types.

use serde::{Deserialize, Serialize};

/// Response from `findOne` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindResult {
    /// The matched document, or `None` if no match.
    pub document: Option<serde_json::Value>,
}

/// Response from `find` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindManyResult {
    /// The matched documents.
    pub documents: Option<Vec<serde_json::Value>>,
}

/// Response from `insertOne` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InsertResult {
    /// The inserted document's `_id`.
    pub inserted_id: Option<String>,
}

/// Response from `insertMany` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InsertManyResult {
    /// The inserted documents' `_id` values.
    pub inserted_ids: Option<Vec<String>>,
}

/// Response from `updateOne` / `updateMany` actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResult {
    /// Number of documents matched by the filter.
    pub matched_count: Option<u64>,
    /// Number of documents actually modified.
    pub modified_count: Option<u64>,
}

/// Response from `deleteOne` / `deleteMany` actions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResult {
    /// Number of documents deleted.
    pub deleted_count: Option<u64>,
}

/// Response from `aggregate` action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateResult {
    /// The aggregation pipeline result documents.
    pub documents: Option<Vec<serde_json::Value>>,
}

/// `MongoDB` Atlas Data API error response body.
///
/// Atlas returns `{"error": "message", "error_code": "CODE", "link": "URL"}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message from Atlas.
    pub error: Option<String>,
    /// The error code (e.g., `"InvalidSession"`).
    pub error_code: Option<String>,
    /// Link to documentation about the error.
    pub link: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- FindResult --

    #[test]
    fn find_result_with_document() {
        let r: FindResult = serde_json::from_value(json!({
            "document": {"_id": "abc123", "name": "Alice", "age": 30}
        }))
        .unwrap();
        assert!(r.document.is_some());
        let doc = r.document.unwrap();
        assert_eq!(doc["name"], "Alice");
        assert_eq!(doc["age"], 30);
    }

    #[test]
    fn find_result_null_document() {
        let r: FindResult = serde_json::from_value(json!({ "document": null })).unwrap();
        assert!(r.document.is_none());
    }

    #[test]
    fn find_result_missing_document() {
        let r: FindResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.document.is_none());
    }

    #[test]
    fn find_result_roundtrip() {
        let r = FindResult {
            document: Some(json!({"_id": "x", "val": 42})),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["document"]["val"], 42);
        let r2: FindResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.document.unwrap()["_id"], "x");
    }

    // -- FindManyResult --

    #[test]
    fn find_many_result_with_documents() {
        let r: FindManyResult = serde_json::from_value(json!({
            "documents": [
                {"_id": "1", "name": "Alice"},
                {"_id": "2", "name": "Bob"},
            ]
        }))
        .unwrap();
        let docs = r.documents.unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0]["name"], "Alice");
        assert_eq!(docs[1]["name"], "Bob");
    }

    #[test]
    fn find_many_result_empty() {
        let r: FindManyResult = serde_json::from_value(json!({ "documents": [] })).unwrap();
        assert!(r.documents.unwrap().is_empty());
    }

    #[test]
    fn find_many_result_missing() {
        let r: FindManyResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.documents.is_none());
    }

    #[test]
    fn find_many_result_roundtrip() {
        let r = FindManyResult {
            documents: Some(vec![json!({"a": 1}), json!({"b": 2})]),
        };
        let v = serde_json::to_value(&r).unwrap();
        let r2: FindManyResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.documents.unwrap().len(), 2);
    }

    // -- InsertResult --

    #[test]
    fn insert_result_with_id() {
        let r: InsertResult =
            serde_json::from_value(json!({ "insertedId": "64c0...abc" })).unwrap();
        assert_eq!(r.inserted_id, Some("64c0...abc".into()));
    }

    #[test]
    fn insert_result_missing_id() {
        let r: InsertResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.inserted_id.is_none());
    }

    #[test]
    fn insert_result_roundtrip() {
        let r = InsertResult {
            inserted_id: Some("new_id".into()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["insertedId"], "new_id");
        let r2: InsertResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.inserted_id.unwrap(), "new_id");
    }

    // -- InsertManyResult --

    #[test]
    fn insert_many_result_with_ids() {
        let r: InsertManyResult =
            serde_json::from_value(json!({ "insertedIds": ["id1", "id2", "id3"] })).unwrap();
        let ids = r.inserted_ids.unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0], "id1");
    }

    #[test]
    fn insert_many_result_empty() {
        let r: InsertManyResult = serde_json::from_value(json!({ "insertedIds": [] })).unwrap();
        assert!(r.inserted_ids.unwrap().is_empty());
    }

    #[test]
    fn insert_many_result_missing() {
        let r: InsertManyResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.inserted_ids.is_none());
    }

    #[test]
    fn insert_many_result_roundtrip() {
        let r = InsertManyResult {
            inserted_ids: Some(vec!["a".into(), "b".into()]),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["insertedIds"][0], "a");
        let r2: InsertManyResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.inserted_ids.unwrap().len(), 2);
    }

    // -- UpdateResult --

    #[test]
    fn update_result_with_counts() {
        let r: UpdateResult =
            serde_json::from_value(json!({ "matchedCount": 5, "modifiedCount": 3 })).unwrap();
        assert_eq!(r.matched_count, Some(5));
        assert_eq!(r.modified_count, Some(3));
    }

    #[test]
    fn update_result_missing_counts() {
        let r: UpdateResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.matched_count.is_none());
        assert!(r.modified_count.is_none());
    }

    #[test]
    fn update_result_roundtrip() {
        let r = UpdateResult {
            matched_count: Some(10),
            modified_count: Some(7),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["matchedCount"], 10);
        assert_eq!(v["modifiedCount"], 7);
        let r2: UpdateResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.matched_count, Some(10));
        assert_eq!(r2.modified_count, Some(7));
    }

    // -- DeleteResult --

    #[test]
    fn delete_result_with_count() {
        let r: DeleteResult = serde_json::from_value(json!({ "deletedCount": 42 })).unwrap();
        assert_eq!(r.deleted_count, Some(42));
    }

    #[test]
    fn delete_result_missing_count() {
        let r: DeleteResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.deleted_count.is_none());
    }

    #[test]
    fn delete_result_roundtrip() {
        let r = DeleteResult {
            deleted_count: Some(3),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["deletedCount"], 3);
        let r2: DeleteResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.deleted_count, Some(3));
    }

    // -- AggregateResult --

    #[test]
    fn aggregate_result_with_documents() {
        let r: AggregateResult = serde_json::from_value(json!({
            "documents": [
                {"_id": "product_a", "total": 1500},
                {"_id": "product_b", "total": 2300},
            ]
        }))
        .unwrap();
        let docs = r.documents.unwrap();
        assert_eq!(docs.len(), 2);
        assert_eq!(docs[0]["total"], 1500);
    }

    #[test]
    fn aggregate_result_empty() {
        let r: AggregateResult = serde_json::from_value(json!({ "documents": [] })).unwrap();
        assert!(r.documents.unwrap().is_empty());
    }

    #[test]
    fn aggregate_result_missing() {
        let r: AggregateResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.documents.is_none());
    }

    #[test]
    fn aggregate_result_roundtrip() {
        let r = AggregateResult {
            documents: Some(vec![json!({"count": 99})]),
        };
        let v = serde_json::to_value(&r).unwrap();
        let r2: AggregateResult = serde_json::from_value(v).unwrap();
        assert_eq!(r2.documents.unwrap()[0]["count"], 99);
    }

    // -- ApiErrorResponse --

    #[test]
    fn api_error_response_with_all_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "no matching documents found",
            "error_code": "InvalidSession",
            "link": "https://docs.atlas.mongodb.com/error/InvalidSession",
        }))
        .unwrap();
        assert_eq!(e.error, Some("no matching documents found".into()));
        assert_eq!(e.error_code, Some("InvalidSession".into()));
        assert!(e.link.unwrap().contains("atlas.mongodb.com"));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error.is_none());
        assert!(e.error_code.is_none());
        assert!(e.link.is_none());
    }

    #[test]
    fn api_error_response_error_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "Rate limit exceeded",
        }))
        .unwrap();
        assert_eq!(e.error, Some("Rate limit exceeded".into()));
        assert!(e.error_code.is_none());
        assert!(e.link.is_none());
    }

    #[test]
    fn api_error_response_extra_fields_ignored() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "oops",
            "error_code": "ERR",
            "link": "https://example.com",
            "extra_field": 42,
        }))
        .unwrap();
        assert_eq!(e.error, Some("oops".into()));
    }

    #[test]
    fn find_result_complex_document() {
        let r: FindResult = serde_json::from_value(json!({
            "document": {
                "_id": "abc",
                "nested": {"key": "value"},
                "arr": [1, 2, 3],
                "flag": true,
            }
        }))
        .unwrap();
        let doc = r.document.unwrap();
        assert_eq!(doc["nested"]["key"], "value");
        assert_eq!(doc["arr"][1], 2);
        assert_eq!(doc["flag"], true);
    }

    #[test]
    fn update_result_zero_counts() {
        let r: UpdateResult =
            serde_json::from_value(json!({ "matchedCount": 0, "modifiedCount": 0 })).unwrap();
        assert_eq!(r.matched_count, Some(0));
        assert_eq!(r.modified_count, Some(0));
    }

    #[test]
    fn delete_result_zero_count() {
        let r: DeleteResult = serde_json::from_value(json!({ "deletedCount": 0 })).unwrap();
        assert_eq!(r.deleted_count, Some(0));
    }
}
