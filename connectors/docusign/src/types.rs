//! `DocuSign` API types.

use serde::{Deserialize, Serialize};

/// An envelope summary (from list response).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeSummary {
    pub envelope_id: String,
    pub status: Option<String>,
    pub email_subject: Option<String>,
    pub sent_date_time: Option<String>,
    pub created_date_time: Option<String>,
    pub completed_date_time: Option<String>,
    pub status_changed_date_time: Option<String>,
    pub envelope_uri: Option<String>,
}

/// Full envelope detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Envelope {
    pub envelope_id: String,
    pub status: Option<String>,
    pub email_subject: Option<String>,
    pub email_blurb: Option<String>,
    pub sent_date_time: Option<String>,
    pub created_date_time: Option<String>,
    pub completed_date_time: Option<String>,
    pub voided_date_time: Option<String>,
    pub voided_reason: Option<String>,
    pub status_changed_date_time: Option<String>,
    pub envelope_uri: Option<String>,
    pub recipients: Option<serde_json::Value>,
    pub documents: Option<serde_json::Value>,
}

/// Envelope creation response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeCreateResponse {
    pub envelope_id: String,
    pub status: Option<String>,
    pub uri: Option<String>,
    pub status_date_time: Option<String>,
}

/// Envelope list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeListResponse {
    pub envelopes: Option<Vec<serde_json::Value>>,
    pub result_set_size: Option<String>,
    pub total_set_size: Option<String>,
    pub start_position: Option<String>,
    pub end_position: Option<String>,
    pub next_uri: Option<String>,
}

/// A recipient (signer, carbon copy, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recipient {
    pub recipient_id: Option<String>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub status: Option<String>,
    pub routing_order: Option<String>,
    pub recipient_type: Option<String>,
}

/// Recipients response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientsResponse {
    pub signers: Option<Vec<serde_json::Value>>,
    pub carbon_copies: Option<Vec<serde_json::Value>>,
    pub certified_deliveries: Option<Vec<serde_json::Value>>,
    pub recipient_count: Option<String>,
}

/// Template summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Template {
    pub template_id: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub created: Option<String>,
    pub last_modified: Option<String>,
    pub uri: Option<String>,
    pub shared: Option<String>,
    pub folder_name: Option<String>,
}

/// Template list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateListResponse {
    pub envelope_templates: Option<Vec<serde_json::Value>>,
    pub result_set_size: Option<String>,
    pub total_set_size: Option<String>,
    pub start_position: Option<String>,
    pub end_position: Option<String>,
}

/// Connect event from webhook.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectEvent {
    pub envelope_id: Option<String>,
    pub status: Option<String>,
    pub event_timestamp: Option<String>,
    pub envelope_status: Option<serde_json::Value>,
    pub recipient_statuses: Option<Vec<serde_json::Value>>,
}

/// `DocuSign` API error response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiErrorResponse {
    pub error_code: Option<String>,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelope_summary_roundtrip() {
        let e: EnvelopeSummary = serde_json::from_value(json!({
            "envelopeId": "env-001",
            "status": "completed",
            "emailSubject": "Please sign this document",
            "sentDateTime": "2026-01-15T10:00:00.000Z",
            "createdDateTime": "2026-01-15T09:00:00.000Z",
            "completedDateTime": "2026-01-15T12:00:00.000Z",
        }))
        .unwrap();
        assert_eq!(e.envelope_id, "env-001");
        assert_eq!(e.status, Some("completed".into()));
        assert_eq!(e.email_subject, Some("Please sign this document".into()));
        let re = serde_json::to_value(&e).unwrap();
        assert_eq!(re["envelopeId"], "env-001");
    }

    #[test]
    fn envelope_summary_minimal() {
        let e: EnvelopeSummary = serde_json::from_value(json!({"envelopeId": "x"})).unwrap();
        assert_eq!(e.envelope_id, "x");
        assert!(e.status.is_none());
        assert!(e.email_subject.is_none());
    }

    #[test]
    fn envelope_detail_roundtrip() {
        let e: Envelope = serde_json::from_value(json!({
            "envelopeId": "env-002",
            "status": "sent",
            "emailSubject": "Contract review",
            "emailBlurb": "Please review and sign",
            "sentDateTime": "2026-02-01T08:00:00.000Z",
            "createdDateTime": "2026-02-01T07:30:00.000Z",
            "recipients": {"signers": [{"name": "Alice", "email": "alice@example.com"}]},
        }))
        .unwrap();
        assert_eq!(e.envelope_id, "env-002");
        assert_eq!(e.status, Some("sent".into()));
        assert!(e.recipients.is_some());
        assert!(e.voided_reason.is_none());
    }

    #[test]
    fn envelope_detail_minimal() {
        let e: Envelope = serde_json::from_value(json!({"envelopeId": "y"})).unwrap();
        assert_eq!(e.envelope_id, "y");
        assert!(e.status.is_none());
        assert!(e.recipients.is_none());
        assert!(e.documents.is_none());
    }

    #[test]
    fn envelope_create_response_roundtrip() {
        let r: EnvelopeCreateResponse = serde_json::from_value(json!({
            "envelopeId": "env-new",
            "status": "created",
            "uri": "/envelopes/env-new",
            "statusDateTime": "2026-02-01T10:00:00.000Z",
        }))
        .unwrap();
        assert_eq!(r.envelope_id, "env-new");
        assert_eq!(r.status, Some("created".into()));
        assert_eq!(r.uri, Some("/envelopes/env-new".into()));
    }

    #[test]
    fn envelope_list_response_roundtrip() {
        let l: EnvelopeListResponse = serde_json::from_value(json!({
            "envelopes": [
                {"envelopeId": "e1", "status": "sent"},
                {"envelopeId": "e2", "status": "completed"},
            ],
            "resultSetSize": "2",
            "totalSetSize": "50",
            "startPosition": "0",
            "endPosition": "1",
            "nextUri": "/envelopes?start_position=2",
        }))
        .unwrap();
        assert_eq!(l.envelopes.as_ref().unwrap().len(), 2);
        assert_eq!(l.total_set_size, Some("50".into()));
    }

    #[test]
    fn envelope_list_response_empty() {
        let l: EnvelopeListResponse = serde_json::from_value(json!({})).unwrap();
        assert!(l.envelopes.is_none());
        assert!(l.result_set_size.is_none());
    }

    #[test]
    fn recipient_roundtrip() {
        let r: Recipient = serde_json::from_value(json!({
            "recipientId": "1",
            "email": "signer@example.com",
            "name": "Bob",
            "status": "completed",
            "routingOrder": "1",
            "recipientType": "signer",
        }))
        .unwrap();
        assert_eq!(r.email, Some("signer@example.com".into()));
        assert_eq!(r.name, Some("Bob".into()));
        assert_eq!(r.status, Some("completed".into()));
    }

    #[test]
    fn recipient_minimal() {
        let r: Recipient = serde_json::from_value(json!({})).unwrap();
        assert!(r.recipient_id.is_none());
        assert!(r.email.is_none());
    }

    #[test]
    fn recipients_response_roundtrip() {
        let r: RecipientsResponse = serde_json::from_value(json!({
            "signers": [{"name": "Alice", "email": "alice@example.com"}],
            "carbonCopies": [{"name": "Manager", "email": "mgr@example.com"}],
            "recipientCount": "2",
        }))
        .unwrap();
        assert_eq!(r.signers.as_ref().unwrap().len(), 1);
        assert_eq!(r.carbon_copies.as_ref().unwrap().len(), 1);
        assert_eq!(r.recipient_count, Some("2".into()));
    }

    #[test]
    fn template_roundtrip() {
        let t: Template = serde_json::from_value(json!({
            "templateId": "tmpl-001",
            "name": "NDA Template",
            "description": "Standard NDA",
            "created": "2026-01-01T00:00:00.000Z",
            "lastModified": "2026-02-01T00:00:00.000Z",
            "uri": "/templates/tmpl-001",
            "shared": "true",
            "folderName": "Templates",
        }))
        .unwrap();
        assert_eq!(t.template_id, "tmpl-001");
        assert_eq!(t.name, Some("NDA Template".into()));
        let re = serde_json::to_value(&t).unwrap();
        assert_eq!(re["templateId"], "tmpl-001");
    }

    #[test]
    fn template_minimal() {
        let t: Template = serde_json::from_value(json!({"templateId": "x"})).unwrap();
        assert_eq!(t.template_id, "x");
        assert!(t.name.is_none());
    }

    #[test]
    fn template_list_response_roundtrip() {
        let tl: TemplateListResponse = serde_json::from_value(json!({
            "envelopeTemplates": [
                {"templateId": "t1", "name": "Template 1"},
                {"templateId": "t2", "name": "Template 2"},
            ],
            "resultSetSize": "2",
            "totalSetSize": "10",
        }))
        .unwrap();
        assert_eq!(tl.envelope_templates.as_ref().unwrap().len(), 2);
        assert_eq!(tl.total_set_size, Some("10".into()));
    }

    #[test]
    fn template_list_response_empty() {
        let tl: TemplateListResponse = serde_json::from_value(json!({})).unwrap();
        assert!(tl.envelope_templates.is_none());
    }

    #[test]
    fn connect_event_roundtrip() {
        let ce: ConnectEvent = serde_json::from_value(json!({
            "envelopeId": "env-100",
            "status": "sent",
            "eventTimestamp": "2026-03-01T12:00:00.000Z",
            "envelopeStatus": {"status": "sent"},
            "recipientStatuses": [{"name": "Alice", "status": "sent"}],
        }))
        .unwrap();
        assert_eq!(ce.envelope_id, Some("env-100".into()));
        assert_eq!(ce.status, Some("sent".into()));
        assert_eq!(ce.recipient_statuses.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn connect_event_minimal() {
        let ce: ConnectEvent = serde_json::from_value(json!({})).unwrap();
        assert!(ce.envelope_id.is_none());
        assert!(ce.status.is_none());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "errorCode": "ENVELOPE_NOT_IN_CORRECT_STATE",
            "message": "The envelope is not in a valid state for this operation.",
        }))
        .unwrap();
        assert_eq!(e.error_code, Some("ENVELOPE_NOT_IN_CORRECT_STATE".into()));
        assert!(e.message.unwrap().contains("not in a valid state"));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error_code.is_none());
        assert!(e.message.is_none());
    }

    // -- Clone trait tests --

    #[test]
    fn envelope_summary_clone() {
        let e = EnvelopeSummary {
            envelope_id: "env-1".into(),
            status: Some("sent".into()),
            email_subject: None,
            sent_date_time: None,
            created_date_time: None,
            completed_date_time: None,
            status_changed_date_time: None,
            envelope_uri: None,
        };
        let cloned = e.clone();
        drop(e);
        assert_eq!(cloned.envelope_id, "env-1");
        assert_eq!(cloned.status, Some("sent".into()));
    }

    #[test]
    fn envelope_clone() {
        let e = Envelope {
            envelope_id: "env-2".into(),
            status: Some("completed".into()),
            email_subject: Some("Test".into()),
            email_blurb: None,
            sent_date_time: None,
            created_date_time: None,
            completed_date_time: None,
            voided_date_time: None,
            voided_reason: None,
            status_changed_date_time: None,
            envelope_uri: None,
            recipients: None,
            documents: None,
        };
        let cloned = e.clone();
        drop(e);
        assert_eq!(cloned.envelope_id, "env-2");
    }

    #[test]
    fn envelope_create_response_clone() {
        let r = EnvelopeCreateResponse {
            envelope_id: "env-new".into(),
            status: Some("created".into()),
            uri: None,
            status_date_time: None,
        };
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.envelope_id, "env-new");
    }

    #[test]
    fn recipient_clone() {
        let r = Recipient {
            recipient_id: Some("1".into()),
            email: Some("a@b.com".into()),
            name: Some("Alice".into()),
            status: None,
            routing_order: None,
            recipient_type: None,
        };
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.email, Some("a@b.com".into()));
    }

    #[test]
    fn template_clone() {
        let t = Template {
            template_id: "tmpl-1".into(),
            name: Some("NDA".into()),
            description: None,
            created: None,
            last_modified: None,
            uri: None,
            shared: None,
            folder_name: None,
        };
        let cloned = t.clone();
        drop(t);
        assert_eq!(cloned.template_id, "tmpl-1");
    }

    #[test]
    fn connect_event_clone() {
        let ce = ConnectEvent {
            envelope_id: Some("env-100".into()),
            status: Some("sent".into()),
            event_timestamp: None,
            envelope_status: None,
            recipient_statuses: None,
        };
        let cloned = ce.clone();
        drop(ce);
        assert_eq!(cloned.envelope_id, Some("env-100".into()));
    }

    // -- Debug trait tests --

    #[test]
    fn envelope_summary_debug() {
        let e: EnvelopeSummary = serde_json::from_value(json!({"envelopeId": "dbg"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("EnvelopeSummary"));
    }

    #[test]
    fn envelope_debug() {
        let e: Envelope = serde_json::from_value(json!({"envelopeId": "dbg"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Envelope"));
    }

    #[test]
    fn template_debug() {
        let t: Template = serde_json::from_value(json!({"templateId": "dbg"})).unwrap();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("Template"));
    }

    #[test]
    fn recipient_debug() {
        let r: Recipient = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Recipient"));
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse {
            error_code: Some("ERR".into()),
            message: Some("msg".into()),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    // -- Serialization edge cases --

    #[test]
    fn envelope_voided_fields() {
        let e: Envelope = serde_json::from_value(json!({
            "envelopeId": "env-voided",
            "status": "voided",
            "voidedDateTime": "2026-02-01T00:00:00Z",
            "voidedReason": "Cancelled by sender",
        }))
        .unwrap();
        assert_eq!(e.status, Some("voided".into()));
        assert_eq!(e.voided_reason, Some("Cancelled by sender".into()));
    }

    #[test]
    fn envelope_with_documents() {
        let e: Envelope = serde_json::from_value(json!({
            "envelopeId": "env-docs",
            "documents": [{"documentId": "1", "name": "contract.pdf"}]
        }))
        .unwrap();
        assert!(e.documents.is_some());
    }

    #[test]
    fn recipients_response_empty() {
        let r: RecipientsResponse = serde_json::from_value(json!({})).unwrap();
        assert!(r.signers.is_none());
        assert!(r.carbon_copies.is_none());
        assert!(r.recipient_count.is_none());
    }

    #[test]
    fn envelope_list_response_with_next_uri() {
        let l: EnvelopeListResponse = serde_json::from_value(json!({
            "envelopes": [],
            "nextUri": "/envelopes?start_position=10"
        }))
        .unwrap();
        assert_eq!(l.next_uri, Some("/envelopes?start_position=10".into()));
    }

    #[test]
    fn envelope_create_response_minimal() {
        let r: EnvelopeCreateResponse = serde_json::from_value(json!({"envelopeId": "x"})).unwrap();
        assert_eq!(r.envelope_id, "x");
        assert!(r.status.is_none());
        assert!(r.uri.is_none());
    }
}
