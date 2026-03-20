//! Firebase connector request, response, and wire types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

/// Request to fetch a single Firestore document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirestoreGetRequest {
    /// Relative document path such as `users/alice`.
    pub document_path: String,
    /// Optional field mask.
    #[serde(default)]
    pub mask: Vec<String>,
}

/// Request to list documents in a collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirestoreListRequest {
    /// Relative collection path such as `users` or `rooms/alpha/messages`.
    pub collection_path: String,
    /// Optional page size.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    /// Optional pagination token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    /// Optional order-by clause.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_by: Option<String>,
    /// Include missing documents in collection group lookups.
    #[serde(default)]
    pub show_missing: bool,
    /// Optional field mask.
    #[serde(default)]
    pub mask: Vec<String>,
}

/// Request to create a Firestore document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirestoreCreateRequest {
    /// Relative collection path.
    pub collection_path: String,
    /// Optional client-assigned document id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    /// Plain JSON document fields.
    pub document: Value,
    /// Optional return mask.
    #[serde(default)]
    pub mask: Vec<String>,
}

/// Request to update a Firestore document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirestoreUpdateRequest {
    /// Relative document path.
    pub document_path: String,
    /// Plain JSON document fields.
    pub document: Value,
    /// Field paths to patch.
    #[serde(default)]
    pub update_mask: Vec<String>,
    /// Optional return mask.
    #[serde(default)]
    pub mask: Vec<String>,
    /// Optional current document exists precondition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_exists: Option<bool>,
    /// Optional update time precondition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_update_time: Option<String>,
}

/// Request to delete a Firestore document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirestoreDeleteRequest {
    /// Relative document path.
    pub document_path: String,
    /// Optional current document exists precondition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_exists: Option<bool>,
    /// Optional update time precondition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_update_time: Option<String>,
}

/// Request to run a structured Firestore query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirestoreQueryRequest {
    /// Optional relative parent document path. Empty or omitted targets the root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_path: Option<String>,
    /// Raw `structuredQuery` payload.
    pub structured_query: Value,
}

/// Request to execute a Firestore batch write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirestoreBatchWriteRequest {
    /// Raw Firestore write operations.
    #[serde(default)]
    pub writes: Vec<Value>,
    /// Optional labels echoed to Firestore.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Request to read from Realtime Database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RealtimeGetRequest {
    /// Relative JSON path. Empty targets the root.
    #[serde(default)]
    pub path: String,
    /// Optional `orderBy` expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_by: Option<String>,
    /// Optional `startAt` cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_at: Option<Value>,
    /// Optional `endAt` cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_at: Option<Value>,
    /// Optional `equalTo` cursor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub equal_to: Option<Value>,
    /// Optional `limitToFirst`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_to_first: Option<u32>,
    /// Optional `limitToLast`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_to_last: Option<u32>,
    /// Optional shallow read.
    #[serde(default)]
    pub shallow: bool,
}

/// Request to write a value into Realtime Database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeSetRequest {
    /// Relative JSON path.
    pub path: String,
    /// Raw JSON value to write.
    pub value: Value,
    /// Suppress response body.
    #[serde(default)]
    pub silent: bool,
}

/// Request to delete a value from Realtime Database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeDeleteRequest {
    /// Relative JSON path.
    pub path: String,
    /// Suppress response body.
    #[serde(default)]
    pub silent: bool,
}

/// Simplified Firestore document output returned to callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirestoreDocumentView {
    /// Fully-qualified Firestore resource name.
    pub name: String,
    /// Plain JSON field payload.
    pub fields: Value,
    /// Optional create timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
    /// Optional update timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_time: Option<String>,
}

/// List response returned from Firestore list operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirestoreListResponse {
    /// Documents in the page.
    pub documents: Vec<FirestoreDocumentView>,
    /// Pagination token, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

/// Query response returned from Firestore `runQuery`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirestoreQueryResponse {
    /// Query result documents.
    pub documents: Vec<FirestoreDocumentView>,
    /// Number of skipped results accumulated across responses.
    pub skipped_results: u64,
    /// Final read time seen in the result stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_time: Option<String>,
    /// Final transaction token, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<String>,
}

/// Firestore wire-format document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirestoreDocumentWire {
    /// Document resource name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Firestore-typed field map.
    #[serde(default)]
    pub fields: BTreeMap<String, FirestoreValue>,
    /// Create timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
    /// Update timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_time: Option<String>,
}

/// Firestore wire-format value object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirestoreValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub null_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boolean_value: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integer_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub double_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub string_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo_point_value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub array_value: Option<FirestoreArrayValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub map_value: Option<FirestoreMapValue>,
}

/// Firestore array wrapper.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirestoreArrayValue {
    /// Encoded array values.
    #[serde(default)]
    pub values: Vec<FirestoreValue>,
}

/// Firestore map wrapper.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirestoreMapValue {
    /// Encoded map fields.
    #[serde(default)]
    pub fields: BTreeMap<String, FirestoreValue>,
}

/// Firestore query result wire item.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirestoreRunQueryResultWire {
    /// Query result document.
    #[serde(default)]
    pub document: Option<FirestoreDocumentWire>,
    /// Count of skipped results in this response frame.
    #[serde(default)]
    pub skipped_results: Option<u64>,
    /// Read time for this frame.
    #[serde(default)]
    pub read_time: Option<String>,
    /// Transaction token.
    #[serde(default)]
    pub transaction: Option<String>,
}

/// Convert plain JSON into a Firestore wire document.
pub fn json_to_firestore_document(document: &Value) -> Result<FirestoreDocumentWire, String> {
    let object = document
        .as_object()
        .ok_or_else(|| "Firestore document payload must be a JSON object".to_string())?;

    let mut fields = BTreeMap::new();
    for (key, value) in object {
        fields.insert(key.clone(), json_to_firestore_value(value)?);
    }

    Ok(FirestoreDocumentWire {
        name: None,
        fields,
        create_time: None,
        update_time: None,
    })
}

/// Convert plain JSON into a Firestore value.
pub fn json_to_firestore_value(value: &Value) -> Result<FirestoreValue, String> {
    match value {
        Value::Null => Ok(FirestoreValue {
            null_value: Some("NULL_VALUE".into()),
            ..FirestoreValue::default()
        }),
        Value::Bool(boolean_value) => Ok(FirestoreValue {
            boolean_value: Some(*boolean_value),
            ..FirestoreValue::default()
        }),
        Value::Number(number) => {
            if let Some(integer_value) = number.as_i64() {
                Ok(FirestoreValue {
                    integer_value: Some(integer_value.to_string()),
                    ..FirestoreValue::default()
                })
            } else if let Some(integer_value) = number.as_u64() {
                Ok(FirestoreValue {
                    integer_value: Some(integer_value.to_string()),
                    ..FirestoreValue::default()
                })
            } else if let Some(double_value) = number.as_f64() {
                Ok(FirestoreValue {
                    double_value: Some(double_value),
                    ..FirestoreValue::default()
                })
            } else {
                Err("Unsupported JSON number for Firestore".into())
            }
        }
        Value::String(string_value) => Ok(FirestoreValue {
            string_value: Some(string_value.clone()),
            ..FirestoreValue::default()
        }),
        Value::Array(values) => {
            let values = values
                .iter()
                .map(json_to_firestore_value)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(FirestoreValue {
                array_value: Some(FirestoreArrayValue { values }),
                ..FirestoreValue::default()
            })
        }
        Value::Object(object) => {
            let mut fields = BTreeMap::new();
            for (key, value) in object {
                fields.insert(key.clone(), json_to_firestore_value(value)?);
            }
            Ok(FirestoreValue {
                map_value: Some(FirestoreMapValue { fields }),
                ..FirestoreValue::default()
            })
        }
    }
}

/// Convert a Firestore wire document into the simplified output view.
#[must_use]
pub fn firestore_document_to_view(document: FirestoreDocumentWire) -> FirestoreDocumentView {
    FirestoreDocumentView {
        name: document.name.unwrap_or_default(),
        fields: firestore_fields_to_json(&document.fields),
        create_time: document.create_time,
        update_time: document.update_time,
    }
}

/// Convert a Firestore field map into plain JSON.
#[must_use]
pub fn firestore_fields_to_json(fields: &BTreeMap<String, FirestoreValue>) -> Value {
    let mut object = Map::new();
    for (key, value) in fields {
        object.insert(key.clone(), firestore_value_to_json(value));
    }
    Value::Object(object)
}

/// Convert a Firestore wire value into plain JSON.
#[must_use]
pub fn firestore_value_to_json(value: &FirestoreValue) -> Value {
    if value.null_value.is_some() {
        Value::Null
    } else if let Some(boolean_value) = value.boolean_value {
        Value::Bool(boolean_value)
    } else if let Some(integer_value) = &value.integer_value {
        integer_value.parse::<i64>().map_or_else(
            |_| Value::String(integer_value.clone()),
            |n| Value::Number(Number::from(n)),
        )
    } else if let Some(double_value) = value.double_value {
        Number::from_f64(double_value).map_or(Value::Null, Value::Number)
    } else if let Some(string_value) = &value.string_value {
        Value::String(string_value.clone())
    } else if let Some(timestamp_value) = &value.timestamp_value {
        serde_json::json!({ "__firebase_timestamp": timestamp_value })
    } else if let Some(bytes_value) = &value.bytes_value {
        serde_json::json!({ "__firebase_bytes_base64": bytes_value })
    } else if let Some(reference_value) = &value.reference_value {
        serde_json::json!({ "__firebase_reference": reference_value })
    } else if let Some(geo_point_value) = &value.geo_point_value {
        serde_json::json!({ "__firebase_geo_point": geo_point_value })
    } else if let Some(array_value) = &value.array_value {
        Value::Array(
            array_value
                .values
                .iter()
                .map(firestore_value_to_json)
                .collect(),
        )
    } else if let Some(map_value) = &value.map_value {
        firestore_fields_to_json(&map_value.fields)
    } else {
        Value::Null
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firestore_json_roundtrip_handles_nested_objects() {
        let input = serde_json::json!({
            "name": "Ada",
            "active": true,
            "score": 42,
            "roles": ["admin", "owner"],
            "profile": {
                "city": "London",
                "verified": false
            }
        });

        let wire = json_to_firestore_document(&input).unwrap();
        let roundtrip = firestore_document_to_view(wire);
        assert_eq!(roundtrip.fields, input);
    }

    #[test]
    fn firestore_value_to_json_preserves_special_wrappers() {
        let value = FirestoreValue {
            timestamp_value: Some("2026-01-01T00:00:00Z".into()),
            ..FirestoreValue::default()
        };
        assert_eq!(
            firestore_value_to_json(&value),
            serde_json::json!({ "__firebase_timestamp": "2026-01-01T00:00:00Z" })
        );
    }

    #[test]
    fn json_to_firestore_document_rejects_non_object() {
        let error = json_to_firestore_document(&serde_json::json!(["bad"])).unwrap_err();
        assert!(error.contains("JSON object"));
    }
}
