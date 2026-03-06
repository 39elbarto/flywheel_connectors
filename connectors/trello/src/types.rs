//! Trello API types.

use serde::{Deserialize, Serialize};

/// A Trello board.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Board {
    pub id: String,
    pub name: Option<String>,
    pub desc: Option<String>,
    pub closed: Option<bool>,
    pub url: Option<String>,
}

/// A Trello list (column on a board).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrelloList {
    pub id: String,
    pub name: Option<String>,
    pub closed: Option<bool>,
    pub pos: Option<f64>,
}

/// A Trello card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Card {
    pub id: String,
    pub name: Option<String>,
    pub desc: Option<String>,
    pub closed: Option<bool>,
    pub due: Option<String>,
    pub labels: Option<Vec<Label>>,
    pub url: Option<String>,
    #[serde(rename = "idList")]
    pub id_list: Option<String>,
}

/// A Trello label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Label {
    pub id: String,
    pub name: Option<String>,
    pub color: Option<String>,
}

/// A Trello board member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    pub username: Option<String>,
    #[serde(rename = "fullName")]
    pub full_name: Option<String>,
}

/// Trello API error response body.
///
/// Trello returns `{"message": "...", "error": "..."}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message from Trello.
    pub message: Option<String>,
    /// The error type/code.
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn board_roundtrip() {
        let b: Board = serde_json::from_value(json!({
            "id": "board_abc123",
            "name": "Engineering Kanban",
            "desc": "Main engineering board",
            "closed": false,
            "url": "https://trello.com/b/abc123/engineering-kanban",
        }))
        .unwrap();
        assert_eq!(b.id, "board_abc123");
        assert_eq!(b.name, Some("Engineering Kanban".into()));
        assert_eq!(b.desc, Some("Main engineering board".into()));
        assert_eq!(b.closed, Some(false));
        assert_eq!(
            b.url,
            Some("https://trello.com/b/abc123/engineering-kanban".into())
        );
        let re = serde_json::to_value(&b).unwrap();
        assert_eq!(re["name"], "Engineering Kanban");
    }

    #[test]
    fn board_minimal() {
        let b: Board = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(b.id, "x");
        assert!(b.name.is_none());
        assert!(b.desc.is_none());
        assert!(b.closed.is_none());
        assert!(b.url.is_none());
    }

    #[test]
    fn trello_list_roundtrip() {
        let l: TrelloList = serde_json::from_value(json!({
            "id": "list_abc123",
            "name": "To Do",
            "closed": false,
            "pos": 65535.5,
        }))
        .unwrap();
        assert_eq!(l.id, "list_abc123");
        assert_eq!(l.name, Some("To Do".into()));
        assert_eq!(l.closed, Some(false));
        assert_eq!(l.pos, Some(65535.5));
        let re = serde_json::to_value(&l).unwrap();
        assert_eq!(re["name"], "To Do");
    }

    #[test]
    fn trello_list_minimal() {
        let l: TrelloList = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(l.id, "x");
        assert!(l.name.is_none());
        assert!(l.closed.is_none());
        assert!(l.pos.is_none());
    }

    #[test]
    fn card_roundtrip() {
        let c: Card = serde_json::from_value(json!({
            "id": "card_abc123",
            "name": "Fix login bug",
            "desc": "Users report intermittent 500 errors",
            "closed": false,
            "due": "2026-04-01T12:00:00.000Z",
            "labels": [
                {"id": "lbl1", "name": "Bug", "color": "red"},
            ],
            "url": "https://trello.com/c/abc123/fix-login-bug",
            "idList": "list_xyz",
        }))
        .unwrap();
        assert_eq!(c.id, "card_abc123");
        assert_eq!(c.name, Some("Fix login bug".into()));
        assert_eq!(c.desc, Some("Users report intermittent 500 errors".into()));
        assert_eq!(c.closed, Some(false));
        assert_eq!(c.due, Some("2026-04-01T12:00:00.000Z".into()));
        assert_eq!(c.labels.as_ref().unwrap().len(), 1);
        assert_eq!(c.labels.as_ref().unwrap()[0].name, Some("Bug".into()));
        assert_eq!(
            c.url,
            Some("https://trello.com/c/abc123/fix-login-bug".into())
        );
        assert_eq!(c.id_list, Some("list_xyz".into()));
    }

    #[test]
    fn card_minimal() {
        let c: Card = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(c.id, "x");
        assert!(c.name.is_none());
        assert!(c.desc.is_none());
        assert!(c.closed.is_none());
        assert!(c.due.is_none());
        assert!(c.labels.is_none());
        assert!(c.url.is_none());
        assert!(c.id_list.is_none());
    }

    #[test]
    fn card_serialize_roundtrip() {
        let c = Card {
            id: "c1".into(),
            name: Some("Do thing".into()),
            desc: None,
            closed: None,
            due: None,
            labels: Some(vec![Label {
                id: "lbl1".into(),
                name: Some("Feature".into()),
                color: Some("green".into()),
            }]),
            url: None,
            id_list: Some("list_a".into()),
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["id"], "c1");
        assert_eq!(v["name"], "Do thing");
        assert_eq!(v["labels"][0]["name"], "Feature");
        assert_eq!(v["idList"], "list_a");
    }

    #[test]
    fn label_roundtrip() {
        let l: Label = serde_json::from_value(json!({
            "id": "lbl_abc123",
            "name": "Priority",
            "color": "orange",
        }))
        .unwrap();
        assert_eq!(l.id, "lbl_abc123");
        assert_eq!(l.name, Some("Priority".into()));
        assert_eq!(l.color, Some("orange".into()));
    }

    #[test]
    fn label_minimal() {
        let l: Label = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(l.id, "x");
        assert!(l.name.is_none());
        assert!(l.color.is_none());
    }

    #[test]
    fn member_roundtrip() {
        let m: Member = serde_json::from_value(json!({
            "id": "mem_abc123",
            "username": "johndoe",
            "fullName": "John Doe",
        }))
        .unwrap();
        assert_eq!(m.id, "mem_abc123");
        assert_eq!(m.username, Some("johndoe".into()));
        assert_eq!(m.full_name, Some("John Doe".into()));
    }

    #[test]
    fn member_minimal() {
        let m: Member = serde_json::from_value(json!({"id": "x"})).unwrap();
        assert_eq!(m.id, "x");
        assert!(m.username.is_none());
        assert!(m.full_name.is_none());
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "invalid token",
            "error": "UNAUTHORIZED",
        }))
        .unwrap();
        assert_eq!(e.message, Some("invalid token".into()));
        assert_eq!(e.error, Some("UNAUTHORIZED".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.error.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Rate limit exceeded",
        }))
        .unwrap();
        assert_eq!(e.message, Some("Rate limit exceeded".into()));
        assert!(e.error.is_none());
    }

    #[test]
    fn board_extra_fields_ignored() {
        let b: Board = serde_json::from_value(json!({
            "id": "b1",
            "name": "Test",
            "unknown_field": "should be ignored",
        }))
        .unwrap();
        assert_eq!(b.id, "b1");
        assert_eq!(b.name, Some("Test".into()));
    }

    #[test]
    fn trello_list_extra_fields_ignored() {
        let l: TrelloList = serde_json::from_value(json!({
            "id": "l1",
            "name": "Test",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(l.id, "l1");
        assert_eq!(l.name, Some("Test".into()));
    }

    #[test]
    fn card_extra_fields_ignored() {
        let c: Card = serde_json::from_value(json!({
            "id": "c1",
            "name": "Test",
            "unknown_field": true,
        }))
        .unwrap();
        assert_eq!(c.id, "c1");
        assert_eq!(c.name, Some("Test".into()));
    }

    #[test]
    fn card_with_empty_labels() {
        let c: Card = serde_json::from_value(json!({
            "id": "c1",
            "labels": [],
        }))
        .unwrap();
        assert!(c.labels.as_ref().unwrap().is_empty());
    }

    #[test]
    fn card_with_multiple_labels() {
        let c: Card = serde_json::from_value(json!({
            "id": "c1",
            "labels": [
                {"id": "l1", "name": "Bug", "color": "red"},
                {"id": "l2", "name": "Feature", "color": "green"},
                {"id": "l3", "name": "Urgent", "color": "orange"},
            ],
        }))
        .unwrap();
        assert_eq!(c.labels.as_ref().unwrap().len(), 3);
        assert_eq!(c.labels.as_ref().unwrap()[1].color, Some("green".into()));
    }

    #[test]
    fn member_extra_fields_ignored() {
        let m: Member = serde_json::from_value(json!({
            "id": "m1",
            "username": "alice",
            "avatarHash": "abc123",
        }))
        .unwrap();
        assert_eq!(m.id, "m1");
        assert_eq!(m.username, Some("alice".into()));
    }

    #[test]
    fn board_closed_true() {
        let b: Board = serde_json::from_value(json!({
            "id": "b1",
            "closed": true,
        }))
        .unwrap();
        assert_eq!(b.closed, Some(true));
    }

    #[test]
    fn trello_list_pos_integer() {
        let l: TrelloList = serde_json::from_value(json!({
            "id": "l1",
            "pos": 16384,
        }))
        .unwrap();
        assert_eq!(l.pos, Some(16384.0));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn board_clone() {
        let b = Board {
            id: "b1".into(),
            name: Some("Test".into()),
            desc: None,
            closed: Some(false),
            url: None,
        };
        let c = b.clone();
        assert_eq!(c.id, "b1");
        assert_eq!(c.name, Some("Test".into()));
    }

    #[test]
    fn board_debug() {
        let b = Board {
            id: "b1".into(),
            name: None,
            desc: None,
            closed: None,
            url: None,
        };
        let dbg = format!("{b:?}");
        assert!(dbg.contains("Board"));
    }

    #[test]
    fn board_serialize_roundtrip() {
        let b = Board {
            id: "b1".into(),
            name: Some("Engineering".into()),
            desc: Some("Main board".into()),
            closed: Some(false),
            url: Some("https://trello.com/b/abc".into()),
        };
        let v = serde_json::to_value(&b).unwrap();
        assert_eq!(v["id"], "b1");
        assert_eq!(v["name"], "Engineering");
        assert_eq!(v["desc"], "Main board");
        assert_eq!(v["closed"], false);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn trello_list_clone() {
        let l = TrelloList {
            id: "l1".into(),
            name: Some("To Do".into()),
            closed: None,
            pos: Some(1.0),
        };
        let c = l.clone();
        assert_eq!(c.id, "l1");
        assert_eq!(c.pos, Some(1.0));
    }

    #[test]
    fn trello_list_debug() {
        let l = TrelloList {
            id: "l1".into(),
            name: None,
            closed: None,
            pos: None,
        };
        let dbg = format!("{l:?}");
        assert!(dbg.contains("TrelloList"));
    }

    #[test]
    fn trello_list_serialize() {
        let l = TrelloList {
            id: "l1".into(),
            name: Some("Done".into()),
            closed: Some(true),
            pos: Some(32768.0),
        };
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["id"], "l1");
        assert_eq!(v["closed"], true);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn card_clone() {
        let c = Card {
            id: "c1".into(),
            name: Some("Task".into()),
            desc: None,
            closed: None,
            due: None,
            labels: None,
            url: None,
            id_list: None,
        };
        let cl = c.clone();
        assert_eq!(cl.id, "c1");
    }

    #[test]
    fn card_debug() {
        let c = Card {
            id: "c1".into(),
            name: None,
            desc: None,
            closed: None,
            due: None,
            labels: None,
            url: None,
            id_list: None,
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Card"));
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn label_clone() {
        let l = Label {
            id: "lbl1".into(),
            name: Some("Bug".into()),
            color: Some("red".into()),
        };
        let c = l.clone();
        assert_eq!(c.id, "lbl1");
    }

    #[test]
    fn label_debug() {
        let l = Label {
            id: "lbl1".into(),
            name: None,
            color: None,
        };
        let dbg = format!("{l:?}");
        assert!(dbg.contains("Label"));
    }

    #[test]
    fn label_serialize() {
        let l = Label {
            id: "lbl1".into(),
            name: Some("Feature".into()),
            color: Some("green".into()),
        };
        let v = serde_json::to_value(&l).unwrap();
        assert_eq!(v["id"], "lbl1");
        assert_eq!(v["name"], "Feature");
        assert_eq!(v["color"], "green");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn member_clone() {
        let m = Member {
            id: "m1".into(),
            username: Some("alice".into()),
            full_name: Some("Alice Smith".into()),
        };
        let c = m.clone();
        assert_eq!(c.id, "m1");
        assert_eq!(c.username, Some("alice".into()));
    }

    #[test]
    fn member_debug() {
        let m = Member {
            id: "m1".into(),
            username: None,
            full_name: None,
        };
        let dbg = format!("{m:?}");
        assert!(dbg.contains("Member"));
    }

    #[test]
    fn member_serialize() {
        let m = Member {
            id: "m1".into(),
            username: Some("bob".into()),
            full_name: Some("Bob Jones".into()),
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["id"], "m1");
        assert_eq!(v["username"], "bob");
        assert_eq!(v["fullName"], "Bob Jones");
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            message: Some("error".into()),
            error: Some("UNAUTHORIZED".into()),
        };
        let c = e.clone();
        assert_eq!(c.message, Some("error".into()));
        assert_eq!(c.error, Some("UNAUTHORIZED".into()));
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse {
            message: None,
            error: None,
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    #[test]
    fn card_null_fields_serialize() {
        let c = Card {
            id: "c1".into(),
            name: None,
            desc: None,
            closed: None,
            due: None,
            labels: None,
            url: None,
            id_list: None,
        };
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["id"], "c1");
        assert!(v["name"].is_null());
    }
}
