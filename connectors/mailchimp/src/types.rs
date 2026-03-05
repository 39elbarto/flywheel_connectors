//! Mailchimp API types.

#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};

/// A Mailchimp audience (list).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Audience {
    pub id: String,
    pub name: Option<String>,
    pub member_count: Option<u64>,
    pub web_id: Option<u64>,
}

/// A Mailchimp audience member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: Option<String>,
    pub email_address: Option<String>,
    pub status: Option<String>,
    pub list_id: Option<String>,
    pub full_name: Option<String>,
}

/// A Mailchimp campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub id: String,
    #[serde(rename = "type")]
    pub campaign_type: Option<String>,
    pub status: Option<String>,
    pub send_time: Option<String>,
    pub settings: Option<CampaignSettings>,
}

/// Campaign settings returned by the Mailchimp API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignSettings {
    pub subject_line: Option<String>,
    pub from_name: Option<String>,
    pub reply_to: Option<String>,
    pub title: Option<String>,
}

/// Mailchimp API error response body.
///
/// Mailchimp returns `{"type": "...", "title": "...", "status": N, "detail": "...", "instance": "..."}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error type URI.
    #[serde(rename = "type")]
    pub error_type: Option<String>,
    /// Short error title.
    pub title: Option<String>,
    /// HTTP status code in the body.
    pub status: Option<u16>,
    /// Detailed error message.
    pub detail: Option<String>,
    /// Instance identifier.
    pub instance: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audience_roundtrip() {
        let a: Audience = serde_json::from_value(json!({
            "id": "abc123",
            "name": "Newsletter Subscribers",
            "member_count": 1500,
            "web_id": 42,
        }))
        .unwrap();
        assert_eq!(a.id, "abc123");
        assert_eq!(a.name, Some("Newsletter Subscribers".into()));
        assert_eq!(a.member_count, Some(1500));
        assert_eq!(a.web_id, Some(42));
        let re = serde_json::to_value(&a).unwrap();
        assert_eq!(re["name"], "Newsletter Subscribers");
    }

    #[test]
    fn audience_minimal() {
        let a: Audience = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(a.id, "x");
        assert!(a.name.is_none());
        assert!(a.member_count.is_none());
        assert!(a.web_id.is_none());
    }

    #[test]
    fn member_roundtrip() {
        let m: Member = serde_json::from_value(json!({
            "id": "mem_abc",
            "email_address": "user@example.com",
            "status": "subscribed",
            "list_id": "list_123",
            "full_name": "Jane Doe",
        }))
        .unwrap();
        assert_eq!(m.id, Some("mem_abc".into()));
        assert_eq!(m.email_address, Some("user@example.com".into()));
        assert_eq!(m.status, Some("subscribed".into()));
        assert_eq!(m.list_id, Some("list_123".into()));
        assert_eq!(m.full_name, Some("Jane Doe".into()));
        let re = serde_json::to_value(&m).unwrap();
        assert_eq!(re["email_address"], "user@example.com");
    }

    #[test]
    fn member_minimal() {
        let m: Member = serde_json::from_value(json!({})).unwrap();
        assert!(m.id.is_none());
        assert!(m.email_address.is_none());
        assert!(m.status.is_none());
    }

    #[test]
    fn campaign_roundtrip() {
        let c: Campaign = serde_json::from_value(json!({
            "id": "camp_abc",
            "type": "regular",
            "status": "sent",
            "send_time": "2026-03-01T12:00:00+00:00",
            "settings": {
                "subject_line": "March Newsletter",
                "from_name": "Acme Corp",
                "reply_to": "hello@acme.com",
                "title": "March 2026",
            },
        }))
        .unwrap();
        assert_eq!(c.id, "camp_abc");
        assert_eq!(c.campaign_type, Some("regular".into()));
        assert_eq!(c.status, Some("sent".into()));
        assert_eq!(c.send_time, Some("2026-03-01T12:00:00+00:00".into()));
        assert!(c.settings.is_some());
        let settings = c.settings.unwrap();
        assert_eq!(settings.subject_line, Some("March Newsletter".into()));
        assert_eq!(settings.from_name, Some("Acme Corp".into()));
        assert_eq!(settings.reply_to, Some("hello@acme.com".into()));
        assert_eq!(settings.title, Some("March 2026".into()));
    }

    #[test]
    fn campaign_minimal() {
        let c: Campaign = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(c.id, "x");
        assert!(c.campaign_type.is_none());
        assert!(c.status.is_none());
        assert!(c.send_time.is_none());
        assert!(c.settings.is_none());
    }

    #[test]
    fn campaign_serialize_roundtrip() {
        let c = Campaign {
            id: "c1".into(),
            campaign_type: Some("regular".into()),
            status: Some("draft".into()),
            send_time: None,
            settings: Some(CampaignSettings {
                subject_line: Some("Hello".into()),
                from_name: None,
                reply_to: None,
                title: None,
            }),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["id"], "c1");
        assert_eq!(v["type"], "regular");
        assert_eq!(v["settings"]["subject_line"], "Hello");
    }

    #[test]
    fn campaign_settings_roundtrip() {
        let s: CampaignSettings = serde_json::from_value(json!({
            "subject_line": "Test",
            "from_name": "Team",
            "reply_to": "team@example.com",
            "title": "Campaign Title",
        }))
        .unwrap();
        assert_eq!(s.subject_line, Some("Test".into()));
        assert_eq!(s.from_name, Some("Team".into()));
        assert_eq!(s.reply_to, Some("team@example.com".into()));
        assert_eq!(s.title, Some("Campaign Title".into()));
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "type": "https://mailchimp.com/developer/marketing/docs/errors/",
            "title": "Resource Not Found",
            "status": 404,
            "detail": "The requested resource could not be found.",
            "instance": "abc-123",
        }))
        .unwrap();
        assert_eq!(
            e.error_type,
            Some("https://mailchimp.com/developer/marketing/docs/errors/".into())
        );
        assert_eq!(e.title, Some("Resource Not Found".into()));
        assert_eq!(e.status, Some(404));
        assert_eq!(
            e.detail,
            Some("The requested resource could not be found.".into())
        );
        assert_eq!(e.instance, Some("abc-123".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error_type.is_none());
        assert!(e.title.is_none());
        assert!(e.status.is_none());
        assert!(e.detail.is_none());
        assert!(e.instance.is_none());
    }

    #[test]
    fn api_error_response_detail_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "detail": "Something went wrong",
        }))
        .unwrap();
        assert_eq!(e.detail, Some("Something went wrong".into()));
        assert!(e.title.is_none());
    }

    #[test]
    fn audience_extra_fields_ignored() {
        let a: Audience = serde_json::from_value(json!({
            "id": "a1",
            "name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(a.id, "a1");
        assert_eq!(a.name, Some("Test".into()));
    }

    #[test]
    fn member_extra_fields_ignored() {
        let m: Member = serde_json::from_value(json!({
            "id": "m1",
            "email_address": "a@b.com",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(m.id, Some("m1".into()));
        assert_eq!(m.email_address, Some("a@b.com".into()));
    }

    #[test]
    fn campaign_extra_fields_ignored() {
        let c: Campaign = serde_json::from_value(json!({
            "id": "c1",
            "unknown_field": true,
        }))
        .unwrap();
        assert_eq!(c.id, "c1");
    }
}
