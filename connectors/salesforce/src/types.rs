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
        }))
        .unwrap();
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
            "nextRecordsUrl": "/services/data/v66.0/query/01g..."
        }))
        .unwrap();
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
        }))
        .unwrap();
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
        }))
        .unwrap();
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
        }))
        .unwrap();
        assert_eq!(m.id.as_deref(), Some("003xx000004TmiQ"));
        assert!(m.success.unwrap());
    }

    #[test]
    fn mutation_response_failure() {
        let m: MutationResponse = serde_json::from_value(json!({
            "id": null, "success": false, "errors": [{"message": "required"}]
        }))
        .unwrap();
        assert!(m.id.is_none());
        assert!(!m.success.unwrap());
    }

    #[test]
    fn lead_convert_result() {
        let r: LeadConvertResult = serde_json::from_value(json!({
            "accountId": "001xx1", "contactId": "003xx1", "opportunityId": "006xx1"
        }))
        .unwrap();
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
        }))
        .unwrap();
        assert!(r.report_metadata.is_some());
        assert!(r.fact_map.is_some());
        assert!(r.has_detailed_data.unwrap());
    }

    // -- Additional types tests --

    #[test]
    fn soql_response_clone() {
        let s: SoqlResponse = serde_json::from_value(json!({
            "totalSize": 1,
            "done": true,
            "records": [{"Id": "001"}]
        }))
        .unwrap();
        let cloned = s.clone();
        assert_eq!(s.total_size, Some(1));
        assert_eq!(cloned.records.len(), 1);
    }

    #[test]
    fn soql_response_debug() {
        let s: SoqlResponse = serde_json::from_value(json!({"records": []})).unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SoqlResponse"));
    }

    #[test]
    fn soql_response_serialize_roundtrip() {
        let s = SoqlResponse {
            total_size: Some(10),
            done: Some(false),
            records: vec![json!({"Id": "x"})],
            next_records_url: Some("/query/01g...".into()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["totalSize"], 10);
        assert_eq!(v["done"], false);
        assert_eq!(v["records"][0]["Id"], "x");
        assert_eq!(v["nextRecordsUrl"], "/query/01g...");
    }

    #[test]
    fn soql_response_records_default_empty() {
        let s: SoqlResponse = serde_json::from_value(json!({"totalSize": 0})).unwrap();
        assert!(s.records.is_empty());
    }

    #[test]
    fn sobject_debug() {
        let obj: SObject = serde_json::from_value(json!({"Id": "x"})).unwrap();
        let dbg = format!("{obj:?}");
        assert!(dbg.contains("SObject"));
    }

    #[test]
    fn sobject_clone() {
        let obj: SObject = serde_json::from_value(json!({"Id": "x", "Name": "Test"})).unwrap();
        let cloned = obj.clone();
        assert_eq!(obj.fields["Id"], "x");
        assert_eq!(cloned.fields["Name"], "Test");
    }

    #[test]
    fn sobject_flatten_roundtrip() {
        let obj = SObject {
            fields: json!({"Id": "001", "Type": "Account"}),
        };
        let v = serde_json::to_value(&obj).unwrap();
        assert_eq!(v["Id"], "001");
        assert_eq!(v["Type"], "Account");
    }

    #[test]
    fn sobject_empty() {
        let obj: SObject = serde_json::from_value(json!({})).unwrap();
        assert!(obj.fields.is_object());
        assert_eq!(obj.fields.as_object().unwrap().len(), 0);
    }

    #[test]
    fn api_error_item_debug() {
        let item: ApiErrorItem = serde_json::from_value(json!({
            "message": "test",
            "errorCode": "INVALID",
            "fields": ["a"]
        }))
        .unwrap();
        let dbg = format!("{item:?}");
        assert!(dbg.contains("ApiErrorItem"));
    }

    #[test]
    fn api_error_item_clone() {
        let item: ApiErrorItem = serde_json::from_value(json!({
            "message": "err",
            "errorCode": "CODE"
        }))
        .unwrap();
        let cloned = item.clone();
        assert_eq!(item.message.as_deref(), Some("err"));
        assert_eq!(cloned.error_code.as_deref(), Some("CODE"));
    }

    #[test]
    fn api_error_item_minimal() {
        let item: ApiErrorItem = serde_json::from_value(json!({})).unwrap();
        assert!(item.message.is_none());
        assert!(item.error_code.is_none());
        assert!(item.fields.is_empty());
    }

    #[test]
    fn api_error_item_fields_default() {
        let item: ApiErrorItem = serde_json::from_value(json!({"message": "x"})).unwrap();
        assert!(item.fields.is_empty());
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"message": "test"})).unwrap();
        let cloned = e.clone();
        assert!(e.errors.is_empty());
        assert_eq!(cloned.message.as_deref(), Some("test"));
    }

    #[test]
    fn mutation_response_debug() {
        let m: MutationResponse = serde_json::from_value(json!({"id": "x"})).unwrap();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("MutationResponse"));
    }

    #[test]
    fn mutation_response_clone() {
        let m: MutationResponse = serde_json::from_value(json!({
            "id": "003xx1",
            "success": true,
            "errors": []
        }))
        .unwrap();
        let cloned = m.clone();
        assert_eq!(m.id.as_deref(), Some("003xx1"));
        assert!(cloned.success.unwrap());
    }

    #[test]
    fn mutation_response_errors_default() {
        let m: MutationResponse = serde_json::from_value(json!({})).unwrap();
        assert!(m.errors.is_empty());
        assert!(m.id.is_none());
        assert!(m.success.is_none());
    }

    #[test]
    fn mutation_response_serialize() {
        let m = MutationResponse {
            id: Some("003".into()),
            success: Some(true),
            errors: vec![],
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["id"], "003");
        assert_eq!(v["success"], true);
        assert_eq!(v["errors"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn lead_convert_result_minimal() {
        let r: LeadConvertResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.account_id.is_none());
        assert!(r.contact_id.is_none());
        assert!(r.opportunity_id.is_none());
    }

    #[test]
    fn lead_convert_result_clone() {
        let r: LeadConvertResult = serde_json::from_value(json!({
            "accountId": "001",
            "contactId": "003",
            "opportunityId": "006"
        }))
        .unwrap();
        let cloned = r.clone();
        assert_eq!(r.account_id.as_deref(), Some("001"));
        assert_eq!(cloned.contact_id.as_deref(), Some("003"));
    }

    #[test]
    fn lead_convert_result_debug() {
        let r: LeadConvertResult = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("LeadConvertResult"));
    }

    #[test]
    fn lead_convert_result_serialize() {
        let r = LeadConvertResult {
            account_id: Some("acc".into()),
            contact_id: None,
            opportunity_id: Some("opp".into()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["accountId"], "acc");
        assert!(v["contactId"].is_null());
        assert_eq!(v["opportunityId"], "opp");
    }

    #[test]
    fn report_result_minimal() {
        let r: ReportResult = serde_json::from_value(json!({})).unwrap();
        assert!(r.report_metadata.is_none());
        assert!(r.fact_map.is_none());
        assert!(r.has_detailed_data.is_none());
    }

    #[test]
    fn report_result_clone() {
        let r: ReportResult = serde_json::from_value(json!({
            "hasDetailedData": false
        }))
        .unwrap();
        let cloned = r.clone();
        assert!(r.report_metadata.is_none());
        assert_eq!(cloned.has_detailed_data, Some(false));
    }

    #[test]
    fn report_result_debug() {
        let r: ReportResult = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("ReportResult"));
    }

    #[test]
    fn report_result_serialize() {
        let r = ReportResult {
            report_metadata: Some(json!({"id": "rpt"})),
            fact_map: None,
            has_detailed_data: Some(true),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["reportMetadata"]["id"], "rpt");
        assert!(v["factMap"].is_null());
        assert_eq!(v["hasDetailedData"], true);
    }
}
