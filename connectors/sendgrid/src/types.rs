//! `SendGrid` API types.

use serde::{Deserialize, Serialize};

/// A `SendGrid` marketing contact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}

/// A `SendGrid` marketing contact list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactList {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_count: Option<u64>,
}

/// A `SendGrid` email template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
}

/// Personalization block for email sending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailPersonalization {
    pub to: Vec<EmailAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

/// An email address with optional display name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAddress {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// An individual error item from the `SendGrid` API.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorItem {
    pub message: Option<String>,
    pub field: Option<String>,
    pub help: Option<String>,
}

/// `SendGrid` API error response body.
///
/// `SendGrid` returns `{"errors": [{"message": "...", "field": "...", "help": "..."}]}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub errors: Option<Vec<ApiErrorItem>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn contact_roundtrip() {
        let c: Contact = serde_json::from_value(json!({
            "id": "contact_abc123",
            "email": "alice@example.com",
            "first_name": "Alice",
            "last_name": "Smith",
        }))
        .unwrap();
        assert_eq!(c.id, Some("contact_abc123".into()));
        assert_eq!(c.email, Some("alice@example.com".into()));
        assert_eq!(c.first_name, Some("Alice".into()));
        assert_eq!(c.last_name, Some("Smith".into()));
        let re = serde_json::to_value(&c).unwrap();
        assert_eq!(re["email"], "alice@example.com");
    }

    #[test]
    fn contact_minimal() {
        let c: Contact = serde_json::from_value(json!({})).unwrap();
        assert!(c.id.is_none());
        assert!(c.email.is_none());
        assert!(c.first_name.is_none());
        assert!(c.last_name.is_none());
    }

    #[test]
    fn contact_serialize_skips_none() {
        let c = Contact {
            id: Some("c1".into()),
            email: None,
            first_name: None,
            last_name: None,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["id"], "c1");
        assert!(v.get("email").is_none());
        assert!(v.get("first_name").is_none());
    }

    #[test]
    fn contact_list_roundtrip() {
        let l: ContactList = serde_json::from_value(json!({
            "id": "list_abc123",
            "name": "Newsletter Subscribers",
            "contact_count": 1500,
        }))
        .unwrap();
        assert_eq!(l.id, Some("list_abc123".into()));
        assert_eq!(l.name, Some("Newsletter Subscribers".into()));
        assert_eq!(l.contact_count, Some(1500));
        let re = serde_json::to_value(&l).unwrap();
        assert_eq!(re["name"], "Newsletter Subscribers");
    }

    #[test]
    fn contact_list_minimal() {
        let l: ContactList = serde_json::from_value(json!({})).unwrap();
        assert!(l.id.is_none());
        assert!(l.name.is_none());
        assert!(l.contact_count.is_none());
    }

    #[test]
    fn template_roundtrip() {
        let t: Template = serde_json::from_value(json!({
            "id": "d-abc123",
            "name": "Welcome Email",
            "generation": "dynamic",
        }))
        .unwrap();
        assert_eq!(t.id, Some("d-abc123".into()));
        assert_eq!(t.name, Some("Welcome Email".into()));
        assert_eq!(t.generation, Some("dynamic".into()));
        let re = serde_json::to_value(&t).unwrap();
        assert_eq!(re["name"], "Welcome Email");
    }

    #[test]
    fn template_minimal() {
        let t: Template = serde_json::from_value(json!({})).unwrap();
        assert!(t.id.is_none());
        assert!(t.name.is_none());
        assert!(t.generation.is_none());
    }

    #[test]
    fn email_personalization_roundtrip() {
        let p: EmailPersonalization = serde_json::from_value(json!({
            "to": [{"email": "bob@example.com", "name": "Bob"}],
            "subject": "Hello Bob",
        }))
        .unwrap();
        assert_eq!(p.to.len(), 1);
        assert_eq!(p.to[0].email, "bob@example.com");
        assert_eq!(p.to[0].name, Some("Bob".into()));
        assert_eq!(p.subject, Some("Hello Bob".into()));
        let re = serde_json::to_value(&p).unwrap();
        assert_eq!(re["to"][0]["email"], "bob@example.com");
    }

    #[test]
    fn email_personalization_multiple_recipients() {
        let p: EmailPersonalization = serde_json::from_value(json!({
            "to": [
                {"email": "a@example.com"},
                {"email": "b@example.com", "name": "B"},
            ],
        }))
        .unwrap();
        assert_eq!(p.to.len(), 2);
        assert!(p.subject.is_none());
    }

    #[test]
    fn email_address_roundtrip() {
        let a: EmailAddress = serde_json::from_value(json!({
            "email": "alice@example.com",
            "name": "Alice",
        }))
        .unwrap();
        assert_eq!(a.email, "alice@example.com");
        assert_eq!(a.name, Some("Alice".into()));
        let re = serde_json::to_value(&a).unwrap();
        assert_eq!(re["email"], "alice@example.com");
        assert_eq!(re["name"], "Alice");
    }

    #[test]
    fn email_address_no_name() {
        let a: EmailAddress = serde_json::from_value(json!({
            "email": "noreply@example.com",
        }))
        .unwrap();
        assert_eq!(a.email, "noreply@example.com");
        assert!(a.name.is_none());
    }

    #[test]
    fn email_address_serialize_skips_none_name() {
        let a = EmailAddress {
            email: "test@example.com".into(),
            name: None,
        };
        let v = serde_json::to_value(&a).unwrap();
        assert!(v.get("name").is_none());
    }

    #[test]
    fn api_error_item_full() {
        let e: ApiErrorItem = serde_json::from_value(json!({
            "message": "The from email does not contain a valid address.",
            "field": "from.email",
            "help": "http://sendgrid.com/docs/API_Reference/Web_API_v3/Mail/errors.html#message.from",
        }))
        .unwrap();
        assert_eq!(
            e.message,
            Some("The from email does not contain a valid address.".into())
        );
        assert_eq!(e.field, Some("from.email".into()));
        assert!(e.help.is_some());
    }

    #[test]
    fn api_error_item_minimal() {
        let e: ApiErrorItem = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.field.is_none());
        assert!(e.help.is_none());
    }

    #[test]
    fn api_error_response_with_errors() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "errors": [
                {"message": "Bad request", "field": "to", "help": null},
                {"message": "Missing field"},
            ]
        }))
        .unwrap();
        let errors = e.errors.unwrap();
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0].message, Some("Bad request".into()));
        assert_eq!(errors[0].field, Some("to".into()));
        assert_eq!(errors[1].message, Some("Missing field".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.errors.is_none());
    }

    #[test]
    fn api_error_response_empty_array() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"errors": []})).unwrap();
        assert!(e.errors.unwrap().is_empty());
    }

    #[test]
    fn contact_extra_fields_ignored() {
        let c: Contact = serde_json::from_value(json!({
            "id": "c1",
            "email": "test@example.com",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(c.id, Some("c1".into()));
        assert_eq!(c.email, Some("test@example.com".into()));
    }

    #[test]
    fn contact_list_extra_fields_ignored() {
        let l: ContactList = serde_json::from_value(json!({
            "id": "l1",
            "name": "Test",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(l.id, Some("l1".into()));
        assert_eq!(l.name, Some("Test".into()));
    }

    #[test]
    fn template_extra_fields_ignored() {
        let t: Template = serde_json::from_value(json!({
            "id": "t1",
            "name": "Test",
            "unknown_field": true,
        }))
        .unwrap();
        assert_eq!(t.id, Some("t1".into()));
        assert_eq!(t.name, Some("Test".into()));
    }

    #[test]
    fn contact_list_serialize_roundtrip() {
        let l = ContactList {
            id: Some("list1".into()),
            name: Some("VIP".into()),
            contact_count: Some(42),
        };
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["id"], "list1");
        assert_eq!(v["name"], "VIP");
        assert_eq!(v["contact_count"], 42);
    }

    #[test]
    fn template_serialize_roundtrip() {
        let t = Template {
            id: Some("d-template1".into()),
            name: Some("Invoice".into()),
            generation: Some("dynamic".into()),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["id"], "d-template1");
        assert_eq!(v["generation"], "dynamic");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn contact_clone() {
        let c = Contact {
            id: Some("c1".into()),
            email: Some("test@example.com".into()),
            first_name: Some("Test".into()),
            last_name: None,
        };
        let cl = c.clone();
        assert_eq!(cl.id, Some("c1".into()));
        assert_eq!(cl.email, Some("test@example.com".into()));
    }

    #[test]
    fn contact_debug() {
        let c = Contact {
            id: None,
            email: None,
            first_name: None,
            last_name: None,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Contact"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn contact_list_clone() {
        let l = ContactList {
            id: Some("l1".into()),
            name: Some("VIP".into()),
            contact_count: Some(100),
        };
        let cl = l.clone();
        assert_eq!(cl.contact_count, Some(100));
    }

    #[test]
    fn contact_list_debug() {
        let l = ContactList {
            id: None,
            name: None,
            contact_count: None,
        };
        let dbg = format!("{l:?}");
        assert!(dbg.contains("ContactList"));
    }

    #[test]
    fn contact_list_serialize_skips_none() {
        let l = ContactList {
            id: Some("l1".into()),
            name: None,
            contact_count: None,
        };
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["id"], "l1");
        assert!(v.get("name").is_none());
        assert!(v.get("contact_count").is_none());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn template_clone() {
        let t = Template {
            id: Some("t1".into()),
            name: Some("Welcome".into()),
            generation: Some("dynamic".into()),
        };
        let cl = t.clone();
        assert_eq!(cl.name, Some("Welcome".into()));
    }

    #[test]
    fn template_debug() {
        let t = Template {
            id: None,
            name: None,
            generation: None,
        };
        let dbg = format!("{t:?}");
        assert!(dbg.contains("Template"));
    }

    #[test]
    fn template_serialize_skips_none() {
        let t = Template {
            id: None,
            name: Some("Test".into()),
            generation: None,
        };
        let v = serde_json::to_value(&t).unwrap();
        assert!(v.get("id").is_none());
        assert_eq!(v["name"], "Test");
        assert!(v.get("generation").is_none());
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn email_personalization_clone() {
        let p = EmailPersonalization {
            to: vec![EmailAddress {
                email: "a@b.com".into(),
                name: None,
            }],
            subject: Some("Hello".into()),
        };
        let cl = p.clone();
        assert_eq!(cl.to.len(), 1);
        assert_eq!(cl.subject, Some("Hello".into()));
    }

    #[test]
    fn email_personalization_debug() {
        let p = EmailPersonalization {
            to: vec![],
            subject: None,
        };
        let dbg = format!("{p:?}");
        assert!(dbg.contains("EmailPersonalization"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn email_address_clone() {
        let a = EmailAddress {
            email: "test@example.com".into(),
            name: Some("Test".into()),
        };
        let cl = a.clone();
        assert_eq!(cl.email, "test@example.com");
    }

    #[test]
    fn email_address_debug() {
        let a = EmailAddress {
            email: "a@b.com".into(),
            name: None,
        };
        let dbg = format!("{a:?}");
        assert!(dbg.contains("EmailAddress"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn api_error_item_clone() {
        let e = ApiErrorItem {
            message: Some("err".into()),
            field: Some("to".into()),
            help: None,
        };
        let cl = e.clone();
        assert_eq!(cl.message, Some("err".into()));
    }

    #[test]
    fn api_error_item_debug() {
        let e = ApiErrorItem {
            message: None,
            field: None,
            help: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorItem"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            errors: Some(vec![ApiErrorItem {
                message: Some("bad".into()),
                field: None,
                help: None,
            }]),
        };
        let cl = e.clone();
        assert_eq!(cl.errors.unwrap().len(), 1);
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse { errors: None };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn email_personalization_serialize_skips_none_subject() {
        let p = EmailPersonalization {
            to: vec![EmailAddress {
                email: "a@b.com".into(),
                name: None,
            }],
            subject: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("subject").is_none());
    }
}
