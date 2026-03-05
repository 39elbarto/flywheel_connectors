//! `HubSpot` API types.

use serde::{Deserialize, Serialize};

/// A `HubSpot` CRM object (contact, company, deal).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrmObject {
    pub id: Option<String>,
    pub properties: Option<serde_json::Value>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
    pub archived: Option<bool>,
}

/// Paginated list response from `HubSpot` CRM API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrmListResponse {
    #[serde(default)]
    pub results: Vec<CrmObject>,
    pub paging: Option<Paging>,
}

/// Pagination info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paging {
    pub next: Option<PagingNext>,
}

/// Next page cursor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagingNext {
    pub after: Option<String>,
    pub link: Option<String>,
}

/// Pipeline object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pipeline {
    pub id: Option<String>,
    pub label: Option<String>,
    #[serde(rename = "displayOrder")]
    pub display_order: Option<i64>,
    #[serde(default)]
    pub stages: Vec<PipelineStage>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<String>,
    pub archived: Option<bool>,
}

/// Pipeline stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStage {
    pub id: Option<String>,
    pub label: Option<String>,
    #[serde(rename = "displayOrder")]
    pub display_order: Option<i64>,
    pub metadata: Option<serde_json::Value>,
}

/// Pipeline list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineListResponse {
    #[serde(default)]
    pub results: Vec<Pipeline>,
}

/// `HubSpot` webhook event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    #[serde(rename = "eventId")]
    pub event_id: Option<i64>,
    #[serde(rename = "subscriptionId")]
    pub subscription_id: Option<i64>,
    #[serde(rename = "portalId")]
    pub portal_id: Option<i64>,
    #[serde(rename = "occurredAt")]
    pub occurred_at: Option<i64>,
    #[serde(rename = "subscriptionType")]
    pub subscription_type: Option<String>,
    #[serde(rename = "objectId")]
    pub object_id: Option<i64>,
    #[serde(rename = "propertyName")]
    pub property_name: Option<String>,
    #[serde(rename = "propertyValue")]
    pub property_value: Option<String>,
    #[serde(rename = "changeSource")]
    pub change_source: Option<String>,
}

/// `HubSpot` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<String>,
    pub status: Option<String>,
    pub category: Option<String>,
    #[serde(rename = "correlationId")]
    pub correlation_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn crm_object_roundtrip() {
        let o: CrmObject = serde_json::from_value(json!({
            "id": "123",
            "properties": {"email": "alice@example.com", "firstname": "Alice"},
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-03-01T00:00:00Z",
            "archived": false
        }))
        .unwrap();
        assert_eq!(o.id.as_deref(), Some("123"));
        assert!(!o.archived.unwrap());
    }

    #[test]
    fn crm_object_minimal() {
        let o: CrmObject = serde_json::from_value(json!({})).unwrap();
        assert!(o.id.is_none());
        assert!(o.properties.is_none());
    }

    #[test]
    fn crm_list_response_with_paging() {
        let r: CrmListResponse = serde_json::from_value(json!({
            "results": [{"id": "1", "properties": {"email": "a@b.com"}}],
            "paging": {"next": {"after": "cursor123", "link": "https://api.hubapi.com/..."}}
        }))
        .unwrap();
        assert_eq!(r.results.len(), 1);
        assert_eq!(
            r.paging.unwrap().next.unwrap().after.as_deref(),
            Some("cursor123")
        );
    }

    #[test]
    fn crm_list_response_empty() {
        let r: CrmListResponse = serde_json::from_value(json!({"results": []})).unwrap();
        assert!(r.results.is_empty());
        assert!(r.paging.is_none());
    }

    #[test]
    fn pipeline_roundtrip() {
        let p: Pipeline = serde_json::from_value(json!({
            "id": "default",
            "label": "Sales Pipeline",
            "displayOrder": 0,
            "stages": [
                {"id": "1", "label": "Qualification", "displayOrder": 0},
                {"id": "2", "label": "Closed Won", "displayOrder": 1}
            ],
            "createdAt": "2026-01-01T00:00:00Z",
            "archived": false
        }))
        .unwrap();
        assert_eq!(p.label.as_deref(), Some("Sales Pipeline"));
        assert_eq!(p.stages.len(), 2);
    }

    #[test]
    fn pipeline_minimal() {
        let p: Pipeline = serde_json::from_value(json!({})).unwrap();
        assert!(p.id.is_none());
        assert!(p.stages.is_empty());
    }

    #[test]
    fn pipeline_list_response() {
        let r: PipelineListResponse = serde_json::from_value(json!({
            "results": [{"id": "default", "label": "Sales"}]
        }))
        .unwrap();
        assert_eq!(r.results.len(), 1);
    }

    #[test]
    fn webhook_event_roundtrip() {
        let e: WebhookEvent = serde_json::from_value(json!({
            "eventId": 1,
            "subscriptionId": 100,
            "portalId": 12345,
            "occurredAt": 1709251200000_i64,
            "subscriptionType": "contact.propertyChange",
            "objectId": 999,
            "propertyName": "email",
            "propertyValue": "new@example.com",
            "changeSource": "CRM"
        }))
        .unwrap();
        assert_eq!(e.event_id, Some(1));
        assert_eq!(
            e.subscription_type.as_deref(),
            Some("contact.propertyChange")
        );
    }

    #[test]
    fn webhook_event_minimal() {
        let e: WebhookEvent = serde_json::from_value(json!({})).unwrap();
        assert!(e.event_id.is_none());
    }

    #[test]
    fn api_error_response() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Contact not found",
            "status": "error",
            "category": "OBJECT_NOT_FOUND",
            "correlationId": "abc-123"
        }))
        .unwrap();
        assert_eq!(e.message.as_deref(), Some("Contact not found"));
        assert_eq!(e.category.as_deref(), Some("OBJECT_NOT_FOUND"));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
    }
}
