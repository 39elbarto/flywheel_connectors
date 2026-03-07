//! `Bitwarden` API types.

use serde::{Deserialize, Serialize};

/// A `Bitwarden` collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub id: String,
    pub name: String,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
}

/// A `Bitwarden` vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    pub id: String,
    pub name: String,
    /// Item type: 1=Login, 2=SecureNote, 3=Card, 4=Identity
    #[serde(rename = "type")]
    pub item_type: Option<i64>,
    #[serde(rename = "folderId")]
    pub folder_id: Option<String>,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    #[serde(rename = "collectionIds")]
    pub collection_ids: Option<Vec<String>>,
    pub notes: Option<String>,
    pub favorite: Option<bool>,
    pub login: Option<Login>,
    pub card: Option<Card>,
    pub identity: Option<Identity>,
    #[serde(rename = "secureNote")]
    pub secure_note: Option<SecureNote>,
    pub fields: Option<Vec<ItemField>>,
    #[serde(rename = "revisionDate")]
    pub revision_date: Option<String>,
    #[serde(rename = "creationDate")]
    pub creation_date: Option<String>,
    #[serde(rename = "deletedDate")]
    pub deleted_date: Option<String>,
    pub reprompt: Option<i64>,
}

/// Login data for a vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Login {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<LoginUri>>,
}

/// A URI associated with a login item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginUri {
    pub uri: Option<String>,
    #[serde(rename = "match")]
    pub match_type: Option<i64>,
}

/// Card data for a vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Card {
    #[serde(rename = "cardholderName")]
    pub cardholder_name: Option<String>,
    pub brand: Option<String>,
    pub number: Option<String>,
    #[serde(rename = "expMonth")]
    pub exp_month: Option<String>,
    #[serde(rename = "expYear")]
    pub exp_year: Option<String>,
    pub code: Option<String>,
}

/// Identity data for a vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub title: Option<String>,
    #[serde(rename = "firstName")]
    pub first_name: Option<String>,
    #[serde(rename = "lastName")]
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub company: Option<String>,
}

/// Secure note data for a vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureNote {
    /// Secure note type (0 = generic)
    #[serde(rename = "type")]
    pub note_type: Option<i64>,
}

/// A custom field on a vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemField {
    pub name: Option<String>,
    pub value: Option<String>,
    /// Field type: 0=Text, 1=Hidden, 2=Boolean, 3=Linked
    #[serde(rename = "type")]
    pub field_type: Option<i64>,
}

/// List response from `Bitwarden` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub object: Option<String>,
    pub data: Vec<serde_json::Value>,
}

/// `Bitwarden` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    #[serde(rename = "validationErrors")]
    pub validation_errors: Option<serde_json::Value>,
}

/// Create-item request body.
#[derive(Debug, Clone, Serialize)]
pub struct CreateItemRequest {
    /// Item type: 1=Login, 2=SecureNote, 3=Card, 4=Identity
    #[serde(rename = "type")]
    pub item_type: i64,
    pub name: String,
    #[serde(rename = "organizationId", skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(rename = "folderId", skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
    #[serde(rename = "collectionIds", skip_serializing_if = "Option::is_none")]
    pub collection_ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub favorite: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login: Option<Login>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<ItemField>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reprompt: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn collection_roundtrip() {
        let c: Collection = serde_json::from_value(json!({
            "id": "col-1",
            "name": "Engineering",
            "organizationId": "org-1",
            "externalId": "ext-1",
        }))
        .unwrap();
        assert_eq!(c.id, "col-1");
        assert_eq!(c.name, "Engineering");
        assert_eq!(c.organization_id, Some("org-1".into()));
        let re = serde_json::to_value(&c).unwrap();
        assert_eq!(re["name"], "Engineering");
    }

    #[test]
    fn collection_minimal() {
        let c: Collection = serde_json::from_value(json!({
            "id": "c1",
            "name": "Default",
        }))
        .unwrap();
        assert_eq!(c.id, "c1");
        assert!(c.organization_id.is_none());
    }

    #[test]
    fn item_roundtrip() {
        let i: Item = serde_json::from_value(json!({
            "id": "item-1",
            "name": "GitHub Token",
            "type": 1,
            "folderId": "folder-1",
            "favorite": true,
            "login": {
                "username": "admin",
                "password": "secret123",
                "totp": "JBSWY3DPEHPK3PXP",
                "uris": [{"uri": "https://github.com", "match": 0}]
            },
            "revisionDate": "2026-01-15T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(i.id, "item-1");
        assert_eq!(i.item_type, Some(1));
        assert_eq!(i.favorite, Some(true));
        let login = i.login.as_ref().unwrap();
        assert_eq!(login.username, Some("admin".into()));
        assert_eq!(login.uris.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn item_minimal() {
        let i: Item = serde_json::from_value(json!({
            "id": "i1",
            "name": "Note",
        }))
        .unwrap();
        assert_eq!(i.id, "i1");
        assert!(i.login.is_none());
        assert!(i.card.is_none());
        assert!(i.identity.is_none());
    }

    #[test]
    fn item_type_secure_note() {
        let i: Item = serde_json::from_value(json!({
            "id": "i2",
            "name": "My Note",
            "type": 2,
            "secureNote": {"type": 0},
        }))
        .unwrap();
        assert_eq!(i.item_type, Some(2));
        assert_eq!(i.secure_note.as_ref().unwrap().note_type, Some(0));
    }

    #[test]
    fn item_type_card() {
        let i: Item = serde_json::from_value(json!({
            "id": "i3",
            "name": "Visa",
            "type": 3,
            "card": {
                "cardholderName": "Alice",
                "brand": "Visa",
                "number": "4111111111111111",
                "expMonth": "12",
                "expYear": "2028",
                "code": "123",
            }
        }))
        .unwrap();
        assert_eq!(i.item_type, Some(3));
        let card = i.card.as_ref().unwrap();
        assert_eq!(card.brand, Some("Visa".into()));
        assert_eq!(card.number, Some("4111111111111111".into()));
    }

    #[test]
    fn item_type_identity() {
        let i: Item = serde_json::from_value(json!({
            "id": "i4",
            "name": "Personal ID",
            "type": 4,
            "identity": {
                "title": "Mr",
                "firstName": "Bob",
                "lastName": "Smith",
                "email": "bob@example.com",
                "phone": "+1234567890",
                "company": "Acme",
            }
        }))
        .unwrap();
        assert_eq!(i.item_type, Some(4));
        let ident = i.identity.as_ref().unwrap();
        assert_eq!(ident.first_name, Some("Bob".into()));
        assert_eq!(ident.company, Some("Acme".into()));
    }

    #[test]
    fn login_roundtrip() {
        let l: Login = serde_json::from_value(json!({
            "username": "user",
            "password": "pass",
            "totp": null,
            "uris": [],
        }))
        .unwrap();
        assert_eq!(l.username, Some("user".into()));
        assert_eq!(l.password, Some("pass".into()));
        assert!(l.totp.is_none());
        let re = serde_json::to_value(&l).unwrap();
        assert_eq!(re["username"], "user");
    }

    #[test]
    fn login_minimal() {
        let l: Login = serde_json::from_value(json!({})).unwrap();
        assert!(l.username.is_none());
        assert!(l.password.is_none());
    }

    #[test]
    fn login_uri_roundtrip() {
        let u: LoginUri = serde_json::from_value(json!({
            "uri": "https://example.com",
            "match": 1,
        }))
        .unwrap();
        assert_eq!(u.uri, Some("https://example.com".into()));
        assert_eq!(u.match_type, Some(1));
    }

    #[test]
    fn card_roundtrip() {
        let c: Card = serde_json::from_value(json!({
            "cardholderName": "Alice",
            "brand": "Mastercard",
            "number": "5555555555554444",
            "expMonth": "06",
            "expYear": "2029",
            "code": "456",
        }))
        .unwrap();
        assert_eq!(c.cardholder_name, Some("Alice".into()));
        assert_eq!(c.exp_year, Some("2029".into()));
    }

    #[test]
    fn identity_roundtrip() {
        let i: Identity = serde_json::from_value(json!({
            "title": "Dr",
            "firstName": "Jane",
            "lastName": "Doe",
            "email": "jane@example.com",
        }))
        .unwrap();
        assert_eq!(i.first_name, Some("Jane".into()));
        assert_eq!(i.last_name, Some("Doe".into()));
    }

    #[test]
    fn secure_note_roundtrip() {
        let s: SecureNote = serde_json::from_value(json!({"type": 0})).unwrap();
        assert_eq!(s.note_type, Some(0));
    }

    #[test]
    fn item_field_roundtrip() {
        let f: ItemField = serde_json::from_value(json!({
            "name": "API Key",
            "value": "sk-12345",
            "type": 1,
        }))
        .unwrap();
        assert_eq!(f.name, Some("API Key".into()));
        assert_eq!(f.field_type, Some(1));
    }

    #[test]
    fn item_field_text_type() {
        let f: ItemField = serde_json::from_value(json!({
            "name": "Note",
            "value": "hello",
            "type": 0,
        }))
        .unwrap();
        assert_eq!(f.field_type, Some(0));
    }

    #[test]
    fn list_response_roundtrip() {
        let lr: ListResponse = serde_json::from_value(json!({
            "object": "list",
            "data": [
                {"id": "c1", "name": "Default"},
                {"id": "c2", "name": "Shared"},
            ]
        }))
        .unwrap();
        assert_eq!(lr.object, Some("list".into()));
        assert_eq!(lr.data.len(), 2);
    }

    #[test]
    fn list_response_empty() {
        let lr: ListResponse = serde_json::from_value(json!({
            "object": "list",
            "data": []
        }))
        .unwrap();
        assert!(lr.data.is_empty());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Item not found",
            "validationErrors": {"name": ["Required"]}
        }))
        .unwrap();
        assert_eq!(e.message, Some("Item not found".into()));
        assert!(e.validation_errors.is_some());
    }

    #[test]
    fn api_error_response_with_error_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "error": "invalid_grant",
            "error_description": "Invalid credentials",
        }))
        .unwrap();
        assert_eq!(e.error, Some("invalid_grant".into()));
        assert_eq!(e.error_description, Some("Invalid credentials".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.error.is_none());
        assert!(e.validation_errors.is_none());
    }

    #[test]
    fn create_item_request_serializes() {
        let req = CreateItemRequest {
            item_type: 1,
            name: "Test Login".into(),
            organization_id: None,
            folder_id: Some("f1".into()),
            collection_ids: None,
            notes: None,
            favorite: Some(false),
            login: Some(Login {
                username: Some("admin".into()),
                password: Some("pass123".into()),
                totp: None,
                uris: None,
            }),
            fields: None,
            reprompt: None,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["type"], 1);
        assert_eq!(v["name"], "Test Login");
        assert_eq!(v["folderId"], "f1");
        assert_eq!(v["login"]["username"], "admin");
        // Optional None fields should be omitted
        assert!(v.get("organizationId").is_none());
        assert!(v.get("collectionIds").is_none());
        assert!(v.get("notes").is_none());
    }

    #[test]
    fn create_item_request_with_collections() {
        let req = CreateItemRequest {
            item_type: 2,
            name: "Shared Note".into(),
            organization_id: Some("org-1".into()),
            folder_id: None,
            collection_ids: Some(vec!["col-1".into(), "col-2".into()]),
            notes: Some("Important note".into()),
            favorite: None,
            login: None,
            fields: Some(vec![ItemField {
                name: Some("key".into()),
                value: Some("val".into()),
                field_type: Some(0),
            }]),
            reprompt: Some(1),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["type"], 2);
        assert_eq!(v["collectionIds"].as_array().unwrap().len(), 2);
        assert_eq!(v["fields"].as_array().unwrap().len(), 1);
        assert_eq!(v["reprompt"], 1);
    }

    #[test]
    fn item_with_fields() {
        let i: Item = serde_json::from_value(json!({
            "id": "i5",
            "name": "API Creds",
            "type": 1,
            "fields": [
                {"name": "env", "value": "production", "type": 0},
                {"name": "secret", "value": "hidden", "type": 1},
            ]
        }))
        .unwrap();
        assert_eq!(i.fields.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn item_with_deleted_date() {
        let i: Item = serde_json::from_value(json!({
            "id": "i6",
            "name": "Trashed",
            "deletedDate": "2026-01-01T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(i.deleted_date, Some("2026-01-01T00:00:00Z".into()));
    }

    #[test]
    fn login_with_multiple_uris() {
        let l: Login = serde_json::from_value(json!({
            "username": "user",
            "password": "pass",
            "uris": [
                {"uri": "https://app.example.com", "match": 0},
                {"uri": "https://login.example.com", "match": 1},
            ]
        }))
        .unwrap();
        assert_eq!(l.uris.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn collection_clone() {
        let c: Collection = serde_json::from_value(json!({
            "id": "c1",
            "name": "Test",
        }))
        .unwrap();
        let c2 = c.clone();
        assert_eq!(c.id, c2.id);
        assert_eq!(c.name, c2.name);
    }

    #[test]
    fn collection_debug() {
        let c: Collection = serde_json::from_value(json!({
            "id": "c1",
            "name": "Test",
        }))
        .unwrap();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Collection"));
        assert!(dbg.contains("c1"));
    }

    #[test]
    fn item_clone() {
        let i: Item = serde_json::from_value(json!({
            "id": "i1",
            "name": "Test",
        }))
        .unwrap();
        let i2 = i.clone();
        assert_eq!(i.id, i2.id);
    }

    #[test]
    fn item_debug() {
        let i: Item = serde_json::from_value(json!({
            "id": "i1",
            "name": "Test",
        }))
        .unwrap();
        let dbg = format!("{i:?}");
        assert!(dbg.contains("Item"));
    }

    #[test]
    fn login_clone() {
        let l: Login = serde_json::from_value(json!({
            "username": "u",
            "password": "p",
        }))
        .unwrap();
        let l2 = l.clone();
        assert_eq!(l.username, l2.username);
    }

    #[test]
    fn card_minimal() {
        let c: Card = serde_json::from_value(json!({})).unwrap();
        assert!(c.cardholder_name.is_none());
        assert!(c.brand.is_none());
        assert!(c.number.is_none());
    }

    #[test]
    fn card_clone() {
        let c: Card = serde_json::from_value(json!({"brand": "Visa"})).unwrap();
        let c2 = c.clone();
        assert_eq!(c.brand, c2.brand);
    }

    #[test]
    fn identity_minimal() {
        let i: Identity = serde_json::from_value(json!({})).unwrap();
        assert!(i.title.is_none());
        assert!(i.first_name.is_none());
        assert!(i.email.is_none());
    }

    #[test]
    fn identity_clone() {
        let i: Identity = serde_json::from_value(json!({"email": "a@b.com"})).unwrap();
        let i2 = i.clone();
        assert_eq!(i.email, i2.email);
    }

    #[test]
    fn secure_note_minimal() {
        let s: SecureNote = serde_json::from_value(json!({})).unwrap();
        assert!(s.note_type.is_none());
    }

    #[test]
    fn item_field_minimal() {
        let f: ItemField = serde_json::from_value(json!({})).unwrap();
        assert!(f.name.is_none());
        assert!(f.value.is_none());
        assert!(f.field_type.is_none());
    }

    #[test]
    fn login_uri_minimal() {
        let u: LoginUri = serde_json::from_value(json!({})).unwrap();
        assert!(u.uri.is_none());
        assert!(u.match_type.is_none());
    }

    #[test]
    fn list_response_clone() {
        let lr: ListResponse = serde_json::from_value(json!({
            "object": "list",
            "data": [{"id": "1"}]
        }))
        .unwrap();
        let lr2 = lr.clone();
        assert_eq!(lr.data.len(), lr2.data.len());
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Test error"
        }))
        .unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn collection_serialize_preserves_rename() {
        let c = Collection {
            id: "c1".into(),
            name: "Test".into(),
            organization_id: Some("org-1".into()),
            external_id: Some("ext-1".into()),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["organizationId"], "org-1");
        assert_eq!(v["externalId"], "ext-1");
    }

    #[test]
    fn item_serialize_preserves_renames() {
        let i: Item = serde_json::from_value(json!({
            "id": "i1",
            "name": "N",
            "type": 1,
            "folderId": "f1",
            "organizationId": "o1",
            "collectionIds": ["c1"],
            "revisionDate": "2026-01-01T00:00:00Z",
            "creationDate": "2025-01-01T00:00:00Z",
        }))
        .unwrap();
        let v = serde_json::to_value(&i).unwrap();
        assert_eq!(v["type"], 1);
        assert_eq!(v["folderId"], "f1");
        assert_eq!(v["organizationId"], "o1");
        assert_eq!(v["revisionDate"], "2026-01-01T00:00:00Z");
        assert_eq!(v["creationDate"], "2025-01-01T00:00:00Z");
    }

    #[test]
    fn item_with_reprompt() {
        let i: Item = serde_json::from_value(json!({
            "id": "i7",
            "name": "Reprompt Item",
            "reprompt": 1,
        }))
        .unwrap();
        assert_eq!(i.reprompt, Some(1));
    }
}
