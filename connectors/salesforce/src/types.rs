//! `Salesforce` API types.

use serde::{Deserialize, Serialize};

/// `Salesforce` SOQL query response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoqlResponse {
    pub total_size: Option<i64>,
    pub done: Option<bool>,
    #[serde(default)]
    pub records: Vec<serde_json::Value>,
    pub next_records_url: Option<String>,
}

/// A generic `Salesforce` sObject wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SObject {
    #[serde(flatten)]
    pub fields: serde_json::Value,
}

/// `Salesforce` API error response (array of error objects).
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(default)]
    pub errors: Vec<ApiErrorItem>,
    /// Single-message variant returned by some endpoints.
    pub message: Option<String>,
}

/// A single error item from the `Salesforce` error array.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorItem {
    pub message: Option<String>,
    #[serde(rename = "errorCode")]
    pub error_code: Option<String>,
    #[serde(default)]
    pub fields: Vec<String>,
}

/// `Salesforce` report result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportResult {
    pub report_metadata: Option<serde_json::Value>,
    pub fact_map: Option<serde_json::Value>,
    pub has_detailed_data: Option<bool>,
}

/// `Salesforce` create/update response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationResponse {
    pub id: Option<String>,
    pub success: Option<bool>,
    #[serde(default)]
    pub errors: Vec<serde_json::Value>,
}

/// Lead conversion response from the actions endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LeadConvertResult {
    pub account_id: Option<String>,
    pub contact_id: Option<String>,
    pub opportunity_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn soql_response_roundtrip() {
        let s: SoqlResponse = serde_json::from_value(json!({
            "totalSize": 2,
            "done": true,
            "records": [
                {"Id": "001xx1", "Name": "Acme"},
                {"Id": "001xx2", "Name": "Globex"}
            ]
        })).unwrap();
        assert_eq!(s.total_size, Some(2));
        assert!(s.done.unwrap());
        assert_eq!(s.records.len(), 2);
        assert!(s.next_records_url.is_none());
    }

    #[test]
    fn soql_response_with_next_url() {
        let s: SoqlResponse = serde_json::from_value(json!({
            "totalSize": 500,
            "done": false,
            "records": [],
            "nextRecordsUrl": "/services/data/v59.0/query/01g..."
        })).unwrap();
        assert!(!s.done.unwrap());
        assert!(s.next_records_url.is_some());
    }

    #[test]
    fn soql_response_minimal() {
        let s: SoqlResponse = serde_json::from_value(json!({"records": []})).unwrap();
        assert!(s.total_size.is_none());
        assert!(s.records.is_empty());
    }

    #[test]
    fn sobject_roundtrip() {
        let obj: SObject = serde_json::from_value(json!({
            "Id": "001xx1", "Name": "Test", "Industry": "Tech"
        })).unwrap();
        assert_eq!(obj.fields["Id"], "001xx1");
    }

    #[test]
    fn api_error_response_array() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "errors": [{"message": "Invalid field", "errorCode": "INVALID_FIELD", "fields": ["BadField"]}]
        })).unwrap();
        assert_eq!(e.errors.len(), 1);
        assert_eq!(e.errors[0].error_code.as_deref(), Some("INVALID_FIELD"));
    }

    #[test]
    fn api_error_response_single_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Session expired or invalid"
        })).unwrap();
        assert_eq!(e.message.as_deref(), Some("Session expired or invalid"));
        assert!(e.errors.is_empty());
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.errors.is_empty());
    }

    #[test]
    fn mutation_response_success() {
        let m: MutationResponse = serde_json::from_value(json!({
            "id": "003xx000004TmiQ", "success": true, "errors": []
        })).unwrap();
        assert_eq!(m.id.as_deref(), Some("003xx000004TmiQ"));
        assert!(m.success.unwrap());
    }

    #[test]
    fn mutation_response_failure() {
        let m: MutationResponse = serde_json::from_value(json!({
            "id": null, "success": false, "errors": [{"message": "required"}]
        })).unwrap();
        assert!(m.id.is_none());
        assert!(!m.success.unwrap());
    }

    #[test]
    fn lead_convert_result() {
        let r: LeadConvertResult = serde_json::from_value(json!({
            "accountId": "001xx1", "contactId": "003xx1", "opportunityId": "006xx1"
        })).unwrap();
        assert_eq!(r.account_id.as_deref(), Some("001xx1"));
        assert_eq!(r.contact_id.as_deref(), Some("003xx1"));
        assert_eq!(r.opportunity_id.as_deref(), Some("006xx1"));
    }

    #[test]
    fn report_result_roundtrip() {
        let r: ReportResult = serde_json::from_value(json!({
            "reportMetadata": {"id": "00Oxx1"},
            "factMap": {"T!T": {"rows": []}},
            "hasDetailedData": true
        })).unwrap();
        assert!(r.report_metadata.is_some());
        assert!(r.fact_map.is_some());
        assert!(r.has_detailed_data.unwrap());
    }
}
