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

    // -- Additional types tests --

    #[test]
    fn audience_clone() {
        let a: Audience = serde_json::from_value(json!({
            "id": "a1",
            "name": "List",
            "member_count": 100
        }))
        .unwrap();
        let cloned = a.clone();
        assert_eq!(a.id, "a1");
        assert_eq!(cloned.name, Some("List".into()));
    }

    #[test]
    fn audience_debug() {
        let a: Audience = serde_json::from_value(json!({"id": "x"})).unwrap();
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Audience"));
    }

    #[test]
    fn audience_serialize() {
        let a = Audience {
            id: "a1".into(),
            name: Some("My List".into()),
            member_count: Some(50),
            web_id: None,
        };
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["id"], "a1");
        assert_eq!(v["name"], "My List");
        assert_eq!(v["member_count"], 50);
        assert!(v["web_id"].is_null());
    }

    #[test]
    fn audience_zero_members() {
        let a: Audience = serde_json::from_value(json!({
            "id": "a1",
            "member_count": 0
        }))
        .unwrap();
        assert_eq!(a.member_count, Some(0));
    }

    #[test]
    fn member_clone() {
        let m: Member = serde_json::from_value(json!({
            "id": "m1",
            "email_address": "a@b.com"
        }))
        .unwrap();
        let cloned = m.clone();
        assert_eq!(m.id, Some("m1".into()));
        assert_eq!(cloned.email_address, Some("a@b.com".into()));
    }

    #[test]
    fn member_debug() {
        let m: Member = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{m:?}");
        assert!(dbg.contains("Member"));
    }

    #[test]
    fn member_serialize() {
        let m = Member {
            id: Some("m1".into()),
            email_address: Some("user@example.com".into()),
            status: Some("subscribed".into()),
            list_id: None,
            full_name: None,
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["id"], "m1");
        assert_eq!(v["status"], "subscribed");
        assert!(v["list_id"].is_null());
    }

    #[test]
    fn member_all_statuses() {
        for status in &[
            "subscribed",
            "unsubscribed",
            "cleaned",
            "pending",
            "transactional",
        ] {
            let m: Member = serde_json::from_value(json!({"status": status})).unwrap();
            assert_eq!(m.status.as_deref(), Some(*status));
        }
    }

    #[test]
    fn campaign_clone() {
        let c: Campaign = serde_json::from_value(json!({
            "id": "c1",
            "type": "regular"
        }))
        .unwrap();
        let cloned = c.clone();
        assert_eq!(c.id, "c1");
        assert_eq!(cloned.campaign_type, Some("regular".into()));
    }

    #[test]
    fn campaign_debug() {
        let c: Campaign = serde_json::from_value(json!({"id": "x"})).unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Campaign"));
    }

    #[test]
    fn campaign_types() {
        for ctype in &["regular", "plaintext", "rss", "variate", "absplit"] {
            let c: Campaign = serde_json::from_value(json!({"id": "x", "type": ctype})).unwrap();
            assert_eq!(c.campaign_type.as_deref(), Some(*ctype));
        }
    }

    #[test]
    fn campaign_settings_minimal() {
        let s: CampaignSettings = serde_json::from_value(json!({})).unwrap();
        assert!(s.subject_line.is_none());
        assert!(s.from_name.is_none());
        assert!(s.reply_to.is_none());
        assert!(s.title.is_none());
    }

    #[test]
    fn campaign_settings_clone() {
        let s: CampaignSettings = serde_json::from_value(json!({
            "subject_line": "Hello"
        }))
        .unwrap();
        let cloned = s.clone();
        assert_eq!(s.subject_line, Some("Hello".into()));
        assert_eq!(cloned.subject_line, Some("Hello".into()));
    }

    #[test]
    fn campaign_settings_debug() {
        let s: CampaignSettings = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("CampaignSettings"));
    }

    #[test]
    fn campaign_settings_serialize() {
        let s = CampaignSettings {
            subject_line: Some("Subject".into()),
            from_name: Some("Sender".into()),
            reply_to: Some("reply@test.com".into()),
            title: Some("Title".into()),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["subject_line"], "Subject");
        assert_eq!(v["from_name"], "Sender");
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "detail": "err",
            "title": "Error"
        }))
        .unwrap();
        let cloned = e.clone();
        assert_eq!(e.detail, Some("err".into()));
        assert_eq!(cloned.title, Some("Error".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn api_error_response_with_instance() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "instance": "abc-123-instance"
        }))
        .unwrap();
        assert_eq!(e.instance, Some("abc-123-instance".into()));
    }

    #[test]
    fn api_error_response_status_numeric() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "status": 429
        }))
        .unwrap();
        assert_eq!(e.status, Some(429));
    }

    #[test]
    fn audience_large_member_count() {
        let a: Audience = serde_json::from_value(json!({
            "id": "big",
            "member_count": 999_999
        }))
        .unwrap();
        assert_eq!(a.member_count, Some(999_999));
    }
}
