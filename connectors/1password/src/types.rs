//! `1Password` API types.

use serde::{Deserialize, Serialize};

/// A `1Password` vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub vault_type: Option<String>,
    pub description: Option<String>,
    pub attribute_version: Option<i64>,
    pub content_version: Option<i64>,
    pub items: Option<i64>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// A `1Password` item (summary, without field values).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub title: Option<String>,
    pub category: Option<String>,
    pub vault: Option<VaultRef>,
    pub tags: Option<Vec<String>>,
    pub version: Option<i64>,
    pub state: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub last_edited_by: Option<String>,
    #[serde(default)]
    pub urls: Vec<ItemUrl>,
    #[serde(default)]
    pub fields: Vec<ItemField>,
    #[serde(default)]
    pub sections: Vec<ItemSection>,
}

/// Reference to a vault within an item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRef {
    pub id: String,
    pub name: Option<String>,
}

/// A URL associated with an item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemUrl {
    pub label: Option<String>,
    pub primary: Option<bool>,
    pub href: String,
}

/// A field on a `1Password` item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemField {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub field_type: Option<String>,
    pub purpose: Option<String>,
    pub label: Option<String>,
    pub value: Option<String>,
    pub section: Option<SectionRef>,
    pub generate: Option<bool>,
    pub entropy: Option<f64>,
}

/// Reference to a section within a field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionRef {
    pub id: String,
}

/// A section within an item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemSection {
    pub id: String,
    pub label: Option<String>,
}

/// Body for creating a new item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateItemRequest {
    pub vault: VaultRef,
    pub category: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub fields: Vec<ItemField>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sections: Vec<ItemSection>,
}

/// `1Password` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub status: Option<u16>,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn vault_roundtrip() {
        let v: Vault = serde_json::from_value(json!({
            "id": "vault-123",
            "name": "My Vault",
            "type": "USER_CREATED",
            "description": "A test vault",
            "attribute_version": 1,
            "content_version": 5,
            "items": 42,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-06-15T12:30:00Z",
        }))
        .unwrap();
        assert_eq!(v.id, "vault-123");
        assert_eq!(v.name, "My Vault");
        assert_eq!(v.vault_type, Some("USER_CREATED".into()));
        assert_eq!(v.items, Some(42));
        let re = serde_json::to_value(&v).unwrap();
        assert_eq!(re["name"], "My Vault");
    }

    #[test]
    fn vault_minimal() {
        let v: Vault = serde_json::from_value(json!({"id": "v1", "name": "V"})).unwrap();
        assert_eq!(v.id, "v1");
        assert!(v.vault_type.is_none());
        assert!(v.description.is_none());
        assert!(v.items.is_none());
    }

    #[test]
    fn item_roundtrip() {
        let i: Item = serde_json::from_value(json!({
            "id": "item-456",
            "title": "My Login",
            "category": "LOGIN",
            "vault": {"id": "vault-123", "name": "My Vault"},
            "tags": ["production", "aws"],
            "version": 3,
            "state": "ACTIVE",
            "created_at": "2024-01-15T08:00:00Z",
            "updated_at": "2024-06-15T12:30:00Z",
            "fields": [
                {"id": "username", "type": "STRING", "label": "username", "value": "admin"},
                {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "label": "password", "value": "s3cret"}
            ],
            "urls": [{"href": "https://example.com", "primary": true}],
            "sections": [{"id": "sec1", "label": "Additional"}],
        }))
        .unwrap();
        assert_eq!(i.id, "item-456");
        assert_eq!(i.title, Some("My Login".into()));
        assert_eq!(i.category, Some("LOGIN".into()));
        assert_eq!(i.fields.len(), 2);
        assert_eq!(i.urls.len(), 1);
        assert_eq!(i.sections.len(), 1);
        assert_eq!(i.tags, Some(vec!["production".into(), "aws".into()]));
    }

    #[test]
    fn item_minimal() {
        let i: Item = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(i.id, "x");
        assert!(i.title.is_none());
        assert!(i.category.is_none());
        assert!(i.vault.is_none());
        assert!(i.fields.is_empty());
        assert!(i.urls.is_empty());
        assert!(i.sections.is_empty());
    }

    #[test]
    fn vault_ref_roundtrip() {
        let vr: VaultRef =
            serde_json::from_value(json!({"id": "v1", "name": "Production"})).unwrap();
        assert_eq!(vr.id, "v1");
        assert_eq!(vr.name, Some("Production".into()));
    }

    #[test]
    fn vault_ref_minimal() {
        let vr: VaultRef = serde_json::from_value(json!({"id": "v1"})).unwrap();
        assert_eq!(vr.id, "v1");
        assert!(vr.name.is_none());
    }

    #[test]
    fn item_url_roundtrip() {
        let u: ItemUrl = serde_json::from_value(json!({
            "label": "website",
            "primary": true,
            "href": "https://example.com"
        }))
        .unwrap();
        assert_eq!(u.href, "https://example.com");
        assert_eq!(u.primary, Some(true));
    }

    #[test]
    fn item_field_roundtrip() {
        let f: ItemField = serde_json::from_value(json!({
            "id": "f1",
            "type": "CONCEALED",
            "purpose": "PASSWORD",
            "label": "password",
            "value": "s3cret",
            "section": {"id": "sec1"},
            "generate": false,
            "entropy": 72.5,
        }))
        .unwrap();
        assert_eq!(f.id, Some("f1".into()));
        assert_eq!(f.field_type, Some("CONCEALED".into()));
        assert_eq!(f.purpose, Some("PASSWORD".into()));
        assert_eq!(f.value, Some("s3cret".into()));
        assert_eq!(f.entropy, Some(72.5));
    }

    #[test]
    fn item_field_minimal() {
        let f: ItemField = serde_json::from_value(json!({})).unwrap();
        assert!(f.id.is_none());
        assert!(f.field_type.is_none());
        assert!(f.value.is_none());
    }

    #[test]
    fn section_ref_roundtrip() {
        let s: SectionRef = serde_json::from_value(json!({"id": "sec1"})).unwrap();
        assert_eq!(s.id, "sec1");
    }

    #[test]
    fn item_section_roundtrip() {
        let s: ItemSection =
            serde_json::from_value(json!({"id": "sec1", "label": "Additional Info"})).unwrap();
        assert_eq!(s.id, "sec1");
        assert_eq!(s.label, Some("Additional Info".into()));
    }

    #[test]
    fn item_section_minimal() {
        let s: ItemSection = serde_json::from_value(json!({"id": "sec1"})).unwrap();
        assert_eq!(s.id, "sec1");
        assert!(s.label.is_none());
    }

    #[test]
    fn create_item_request_roundtrip() {
        let req = CreateItemRequest {
            vault: VaultRef {
                id: "vault-123".into(),
                name: None,
            },
            category: "API_CREDENTIAL".into(),
            title: "Stripe Key".into(),
            tags: Some(vec!["production".into()]),
            fields: vec![ItemField {
                id: None,
                field_type: Some("CONCEALED".into()),
                purpose: None,
                label: Some("api_key".into()),
                value: Some("sk_live_abc".into()),
                section: None,
                generate: None,
                entropy: None,
            }],
            sections: vec![],
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["vault"]["id"], "vault-123");
        assert_eq!(v["category"], "API_CREDENTIAL");
        assert_eq!(v["title"], "Stripe Key");
        assert_eq!(v["fields"][0]["label"], "api_key");
        // sections should not be serialized when empty
        assert!(v.get("sections").is_none());
    }

    #[test]
    fn create_item_request_minimal() {
        let req = CreateItemRequest {
            vault: VaultRef {
                id: "v1".into(),
                name: None,
            },
            category: "LOGIN".into(),
            title: "Test".into(),
            tags: None,
            fields: vec![],
            sections: vec![],
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["category"], "LOGIN");
        assert!(v.get("tags").is_none());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "status": 400,
            "message": "Invalid vault ID format"
        }))
        .unwrap();
        assert_eq!(e.status, Some(400));
        assert_eq!(e.message, Some("Invalid vault ID format".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.status.is_none());
        assert!(e.message.is_none());
    }

    #[test]
    fn item_with_multiple_urls() {
        let i: Item = serde_json::from_value(json!({
            "id": "item-1",
            "urls": [
                {"href": "https://a.com", "primary": true},
                {"href": "https://b.com", "primary": false, "label": "backup"}
            ]
        }))
        .unwrap();
        assert_eq!(i.urls.len(), 2);
        assert_eq!(i.urls[0].primary, Some(true));
        assert_eq!(i.urls[1].label, Some("backup".into()));
    }

    #[test]
    fn item_field_with_generate() {
        let f: ItemField = serde_json::from_value(json!({
            "id": "pwd",
            "type": "CONCEALED",
            "generate": true
        }))
        .unwrap();
        assert_eq!(f.generate, Some(true));
    }

    #[test]
    fn vault_with_versions() {
        let v: Vault = serde_json::from_value(json!({
            "id": "v1",
            "name": "V",
            "attribute_version": 3,
            "content_version": 12
        }))
        .unwrap();
        assert_eq!(v.attribute_version, Some(3));
        assert_eq!(v.content_version, Some(12));
    }

    #[test]
    fn item_with_last_edited_by() {
        let i: Item = serde_json::from_value(json!({
            "id": "item-1",
            "last_edited_by": "DWZX6FOBBGSQPDYMM3Q4CWQVGE"
        }))
        .unwrap();
        assert_eq!(
            i.last_edited_by,
            Some("DWZX6FOBBGSQPDYMM3Q4CWQVGE".into())
        );
    }

    #[test]
    fn vault_clone() {
        let v: Vault = serde_json::from_value(json!({"id": "v1", "name": "V"})).unwrap();
        let v2 = v.clone();
        assert_eq!(v.id, v2.id);
        assert_eq!(v.name, v2.name);
    }

    #[test]
    fn vault_debug() {
        let v: Vault = serde_json::from_value(json!({"id": "v1", "name": "V"})).unwrap();
        let dbg = format!("{v:?}");
        assert!(dbg.contains("Vault"));
    }

    #[test]
    fn item_clone() {
        let i: Item = serde_json::from_value(json!({"id": "i1"})).unwrap();
        let i2 = i.clone();
        assert_eq!(i.id, i2.id);
    }

    #[test]
    fn item_debug() {
        let i: Item = serde_json::from_value(json!({"id": "i1"})).unwrap();
        let dbg = format!("{i:?}");
        assert!(dbg.contains("Item"));
    }

    #[test]
    fn vault_ref_clone() {
        let vr: VaultRef = serde_json::from_value(json!({"id": "v1"})).unwrap();
        let vr2 = vr.clone();
        assert_eq!(vr.id, vr2.id);
    }

    #[test]
    fn item_url_clone() {
        let u: ItemUrl = serde_json::from_value(json!({"href": "https://a.com"})).unwrap();
        let u2 = u.clone();
        assert_eq!(u.href, u2.href);
    }

    #[test]
    fn item_url_minimal() {
        let u: ItemUrl =
            serde_json::from_value(json!({"href": "https://example.com"})).unwrap();
        assert!(u.label.is_none());
        assert!(u.primary.is_none());
    }

    #[test]
    fn item_field_clone() {
        let f: ItemField = serde_json::from_value(json!({"id": "f1"})).unwrap();
        let f2 = f.clone();
        assert_eq!(f.id, f2.id);
    }

    #[test]
    fn section_ref_clone() {
        let s: SectionRef = serde_json::from_value(json!({"id": "sec1"})).unwrap();
        let s2 = s.clone();
        assert_eq!(s.id, s2.id);
    }

    #[test]
    fn section_ref_debug() {
        let s: SectionRef = serde_json::from_value(json!({"id": "sec1"})).unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SectionRef"));
    }

    #[test]
    fn item_section_clone() {
        let s: ItemSection = serde_json::from_value(json!({"id": "sec1"})).unwrap();
        let s2 = s.clone();
        assert_eq!(s.id, s2.id);
    }

    #[test]
    fn create_item_request_clone() {
        let req = CreateItemRequest {
            vault: VaultRef {
                id: "v1".into(),
                name: None,
            },
            category: "LOGIN".into(),
            title: "Test".into(),
            tags: None,
            fields: vec![],
            sections: vec![],
        };
        let req2 = req.clone();
        assert_eq!(req.title, req2.title);
        assert_eq!(req.category, req2.category);
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "status": 400,
            "message": "err"
        }))
        .unwrap();
        let e2 = e.clone();
        assert_eq!(e.status, e2.status);
        assert_eq!(e.message, e2.message);
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"message": "err"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn vault_serialize_preserves_type_rename() {
        let v = Vault {
            id: "v1".into(),
            name: "V".into(),
            vault_type: Some("USER_CREATED".into()),
            description: None,
            attribute_version: None,
            content_version: None,
            items: None,
            created_at: None,
            updated_at: None,
        };
        let val = serde_json::to_value(&v).unwrap();
        assert_eq!(val["type"], "USER_CREATED");
    }

    #[test]
    fn item_with_state_archived() {
        let i: Item = serde_json::from_value(json!({
            "id": "item-1",
            "state": "ARCHIVED",
        }))
        .unwrap();
        assert_eq!(i.state, Some("ARCHIVED".into()));
    }

    #[test]
    fn item_with_version() {
        let i: Item = serde_json::from_value(json!({
            "id": "item-1",
            "version": 7,
        }))
        .unwrap();
        assert_eq!(i.version, Some(7));
    }

    #[test]
    fn item_field_with_section_ref() {
        let f: ItemField = serde_json::from_value(json!({
            "id": "f1",
            "section": {"id": "sec1"},
        }))
        .unwrap();
        assert_eq!(f.section.as_ref().unwrap().id, "sec1");
    }

    #[test]
    fn create_item_request_with_sections() {
        let req = CreateItemRequest {
            vault: VaultRef {
                id: "v1".into(),
                name: None,
            },
            category: "LOGIN".into(),
            title: "Test".into(),
            tags: Some(vec!["tag1".into()]),
            fields: vec![],
            sections: vec![ItemSection {
                id: "sec1".into(),
                label: Some("Custom".into()),
            }],
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["sections"][0]["id"], "sec1");
        assert_eq!(v["sections"][0]["label"], "Custom");
    }
}
