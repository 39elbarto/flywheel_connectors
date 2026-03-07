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

    // ── CrmObject additional tests ──────────────────────────────────

    #[test]
    fn crm_object_serialize_roundtrip() {
        let o = CrmObject {
            id: Some("456".into()),
            properties: Some(json!({"name": "Acme"})),
            created_at: Some("2026-01-01T00:00:00Z".into()),
            updated_at: None,
            archived: Some(false),
        };
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v["id"], "456");
        assert_eq!(v["properties"]["name"], "Acme");
        let o2: CrmObject = serde_json::from_value(v).unwrap();
        assert_eq!(o2.id, Some("456".into()));
    }

    #[test]
    fn crm_object_clone() {
        let o: CrmObject = serde_json::from_value(json!({"id": "c1"})).unwrap();
        #[allow(clippy::redundant_clone)]
        let o2 = o.clone();
        assert_eq!(o2.id, Some("c1".into()));
    }

    #[test]
    fn crm_object_debug() {
        let o: CrmObject = serde_json::from_value(json!({"id": "dbg"})).unwrap();
        let dbg = format!("{o:?}");
        assert!(dbg.contains("dbg"));
    }

    #[test]
    fn crm_object_archived_true() {
        let o: CrmObject = serde_json::from_value(json!({"archived": true})).unwrap();
        assert_eq!(o.archived, Some(true));
    }

    // ── CrmListResponse additional tests ────────────────────────────

    #[test]
    fn crm_list_response_no_paging() {
        let r: CrmListResponse = serde_json::from_value(json!({"results": [{"id": "1"}]})).unwrap();
        assert_eq!(r.results.len(), 1);
        assert!(r.paging.is_none());
    }

    #[test]
    fn crm_list_response_clone() {
        let r: CrmListResponse = serde_json::from_value(json!({"results": []})).unwrap();
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert!(r2.results.is_empty());
    }

    #[test]
    fn crm_list_response_debug() {
        let r: CrmListResponse = serde_json::from_value(json!({"results": []})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("CrmListResponse"));
    }

    #[test]
    fn crm_list_response_default_results() {
        // results uses #[serde(default)] so omitting works
        let r: CrmListResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.results.is_empty());
    }

    // ── Paging tests ────────────────────────────────────────────────

    #[test]
    fn paging_roundtrip() {
        let p: Paging = serde_json::from_value(json!({
            "next": {"after": "abc", "link": "https://api.hubapi.com/next"}
        }))
        .unwrap();
        assert_eq!(p.next.as_ref().unwrap().after.as_deref(), Some("abc"));
    }

    #[test]
    fn paging_empty() {
        let p: Paging = serde_json::from_value(json!({})).unwrap();
        assert!(p.next.is_none());
    }

    #[test]
    fn paging_clone() {
        let p: Paging = serde_json::from_value(json!({"next": {"after": "x"}})).unwrap();
        #[allow(clippy::redundant_clone)]
        let p2 = p.clone();
        assert_eq!(p2.next.unwrap().after, Some("x".into()));
    }

    // ── PagingNext tests ────────────────────────────────────────────

    #[test]
    fn paging_next_minimal() {
        let pn: PagingNext = serde_json::from_value(json!({})).unwrap();
        assert!(pn.after.is_none());
        assert!(pn.link.is_none());
    }

    #[test]
    fn paging_next_serialize_roundtrip() {
        let pn = PagingNext {
            after: Some("cur".into()),
            link: Some("http://link".into()),
        };
        let v = serde_json::to_value(&pn).unwrap();
        assert_eq!(v["after"], "cur");
        let pn2: PagingNext = serde_json::from_value(v).unwrap();
        assert_eq!(pn2.after, Some("cur".into()));
    }

    // ── Pipeline additional tests ───────────────────────────────────

    #[test]
    fn pipeline_clone() {
        let p: Pipeline = serde_json::from_value(json!({"id": "p1", "label": "Sales"})).unwrap();
        #[allow(clippy::redundant_clone)]
        let p2 = p.clone();
        assert_eq!(p2.id, Some("p1".into()));
    }

    #[test]
    fn pipeline_debug() {
        let p: Pipeline = serde_json::from_value(json!({"id": "dbg_pipe"})).unwrap();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("dbg_pipe"));
    }

    #[test]
    fn pipeline_serialize_roundtrip() {
        let p = Pipeline {
            id: Some("default".into()),
            label: Some("Sales".into()),
            display_order: Some(0),
            stages: vec![PipelineStage {
                id: Some("s1".into()),
                label: Some("New".into()),
                display_order: Some(0),
                metadata: None,
            }],
            created_at: None,
            updated_at: None,
            archived: Some(false),
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["displayOrder"], 0);
        assert_eq!(v["stages"][0]["label"], "New");
    }

    // ── PipelineStage additional tests ──────────────────────────────

    #[test]
    fn pipeline_stage_minimal() {
        let s: PipelineStage = serde_json::from_value(json!({})).unwrap();
        assert!(s.id.is_none());
        assert!(s.metadata.is_none());
    }

    #[test]
    fn pipeline_stage_with_metadata() {
        let s: PipelineStage = serde_json::from_value(json!({
            "id": "s1", "metadata": {"probability": 0.5}
        }))
        .unwrap();
        assert_eq!(s.metadata.unwrap()["probability"], 0.5);
    }

    // ── PipelineListResponse additional ─────────────────────────────

    #[test]
    fn pipeline_list_response_empty() {
        let r: PipelineListResponse = serde_json::from_value(json!({"results": []})).unwrap();
        assert!(r.results.is_empty());
    }

    #[test]
    fn pipeline_list_response_clone() {
        let r: PipelineListResponse = serde_json::from_value(json!({"results": []})).unwrap();
        #[allow(clippy::redundant_clone)]
        let r2 = r.clone();
        assert!(r2.results.is_empty());
    }

    // ── WebhookEvent additional tests ───────────────────────────────

    #[test]
    fn webhook_event_clone() {
        let e: WebhookEvent = serde_json::from_value(json!({"eventId": 42})).unwrap();
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2.event_id, Some(42));
    }

    #[test]
    fn webhook_event_debug() {
        let e: WebhookEvent = serde_json::from_value(json!({"eventId": 99})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("99"));
    }

    #[test]
    fn webhook_event_serialize_roundtrip() {
        let e = WebhookEvent {
            event_id: Some(1),
            subscription_id: Some(100),
            portal_id: Some(12345),
            occurred_at: Some(1700000000),
            subscription_type: Some("contact.creation".into()),
            object_id: Some(999),
            property_name: None,
            property_value: None,
            change_source: Some("CRM".into()),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["eventId"], 1);
        assert_eq!(v["subscriptionType"], "contact.creation");
        let e2: WebhookEvent = serde_json::from_value(v).unwrap();
        assert_eq!(e2.event_id, Some(1));
    }

    // ── ApiErrorResponse additional tests ───────────────────────────

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"message": "err"})).unwrap();
        #[allow(clippy::redundant_clone)]
        let e2 = e.clone();
        assert_eq!(e2.message, Some("err".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"message": "debug"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("debug"));
    }

    #[test]
    fn api_error_response_all_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "err",
            "status": "error",
            "category": "VALIDATION_ERROR",
            "correlationId": "corr-123"
        }))
        .unwrap();
        assert_eq!(e.status.as_deref(), Some("error"));
        assert_eq!(e.category.as_deref(), Some("VALIDATION_ERROR"));
        assert_eq!(e.correlation_id.as_deref(), Some("corr-123"));
    }

    // ── Additional type coverage tests ────────────────────────────

    #[test]
    fn crm_object_created_at_and_updated_at() {
        let o: CrmObject = serde_json::from_value(json!({
            "createdAt": "2026-01-15T10:30:00Z",
            "updatedAt": "2026-03-01T14:00:00Z"
        }))
        .unwrap();
        assert_eq!(o.created_at.as_deref(), Some("2026-01-15T10:30:00Z"));
        assert_eq!(o.updated_at.as_deref(), Some("2026-03-01T14:00:00Z"));
    }

    #[test]
    fn crm_object_properties_complex() {
        let o: CrmObject = serde_json::from_value(json!({
            "properties": {"email": "test@example.com", "score": 42, "tags": ["vip"]}
        }))
        .unwrap();
        let props = o.properties.unwrap();
        assert_eq!(props["email"], "test@example.com");
        assert_eq!(props["score"], 42);
        assert!(props["tags"].is_array());
    }

    #[test]
    fn pipeline_stages_empty_vec() {
        let p: Pipeline = serde_json::from_value(json!({"stages": []})).unwrap();
        assert!(p.stages.is_empty());
    }

    #[test]
    fn pipeline_stage_clone() {
        let s: PipelineStage =
            serde_json::from_value(json!({"id": "s1", "label": "New"})).unwrap();
        let cloned = s.clone();
        assert_eq!(cloned.id, s.id);
        assert_eq!(cloned.label, s.label);
    }

    #[test]
    fn webhook_event_all_none_fields() {
        let e: WebhookEvent = serde_json::from_value(json!({})).unwrap();
        assert!(e.subscription_id.is_none());
        assert!(e.portal_id.is_none());
        assert!(e.occurred_at.is_none());
        assert!(e.object_id.is_none());
        assert!(e.property_name.is_none());
        assert!(e.property_value.is_none());
        assert!(e.change_source.is_none());
    }

    #[test]
    fn pipeline_display_order_negative() {
        let p: Pipeline = serde_json::from_value(json!({"displayOrder": -1})).unwrap();
        assert_eq!(p.display_order, Some(-1));
    }
}
