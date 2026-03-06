//! `Evernote` API types.

use serde::{Deserialize, Serialize};

/// An `Evernote` notebook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notebook {
    pub id: String,
    pub name: String,
    pub created: Option<i64>,
    pub updated: Option<i64>,
    #[serde(rename = "defaultNotebook")]
    pub default_notebook: Option<bool>,
    pub stack: Option<String>,
}

/// List of notebooks response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotebookList {
    pub notebooks: Vec<serde_json::Value>,
}

/// An `Evernote` note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    #[serde(rename = "noteId")]
    pub note_id: String,
    pub title: String,
    pub content: Option<String>,
    #[serde(rename = "notebookId")]
    pub notebook_id: Option<String>,
    pub created: Option<i64>,
    pub updated: Option<i64>,
    pub active: Option<bool>,
    pub tags: Option<Vec<String>>,
}

/// List of notes response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteList {
    pub notes: Vec<serde_json::Value>,
    pub total_count: Option<i64>,
}

/// Create note response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateNoteResponse {
    #[serde(rename = "noteId")]
    pub note_id: String,
    pub title: Option<String>,
    #[serde(rename = "notebookId")]
    pub notebook_id: Option<String>,
}

/// `Evernote` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(rename = "errorCode")]
    pub error_code: Option<i64>,
    pub message: Option<String>,
}

/// Pagination parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    pub offset: Option<i64>,
    pub limit: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn notebook_roundtrip() {
        let n: Notebook = serde_json::from_value(json!({
            "id": "nb-abc123",
            "name": "Work Notes",
            "created": 1_709_251_200,
            "updated": 1_709_337_600,
            "defaultNotebook": true,
        }))
        .unwrap();
        assert_eq!(n.id, "nb-abc123");
        assert_eq!(n.name, "Work Notes");
        assert_eq!(n.default_notebook, Some(true));
        let re = serde_json::to_value(&n).unwrap();
        assert_eq!(re["name"], "Work Notes");
    }

    #[test]
    fn notebook_minimal() {
        let n: Notebook = serde_json::from_value(json!({"id": "x", "name": "N"})).unwrap();
        assert_eq!(n.id, "x");
        assert_eq!(n.name, "N");
        assert!(n.created.is_none());
        assert!(n.default_notebook.is_none());
        assert!(n.stack.is_none());
    }

    #[test]
    fn notebook_with_stack() {
        let n: Notebook = serde_json::from_value(json!({
            "id": "nb1",
            "name": "Team",
            "stack": "Projects"
        }))
        .unwrap();
        assert_eq!(n.stack, Some("Projects".into()));
    }

    #[test]
    fn notebook_list_roundtrip() {
        let nl: NotebookList = serde_json::from_value(json!({
            "notebooks": [
                {"id": "nb1", "name": "Work"},
                {"id": "nb2", "name": "Personal"},
            ]
        }))
        .unwrap();
        assert_eq!(nl.notebooks.len(), 2);
    }

    #[test]
    fn notebook_list_empty() {
        let nl: NotebookList = serde_json::from_value(json!({ "notebooks": [] })).unwrap();
        assert!(nl.notebooks.is_empty());
    }

    #[test]
    fn note_roundtrip() {
        let n: Note = serde_json::from_value(json!({
            "noteId": "note-abc123",
            "title": "Meeting Notes",
            "content": "Discussed the roadmap.",
            "notebookId": "nb-abc123",
            "created": 1_709_251_200,
            "updated": 1_709_337_600,
            "active": true,
            "tags": ["important", "work"],
        }))
        .unwrap();
        assert_eq!(n.note_id, "note-abc123");
        assert_eq!(n.title, "Meeting Notes");
        assert_eq!(n.content, Some("Discussed the roadmap.".into()));
        assert_eq!(n.notebook_id, Some("nb-abc123".into()));
        assert_eq!(n.tags.as_ref().unwrap().len(), 2);
        let re = serde_json::to_value(&n).unwrap();
        assert_eq!(re["title"], "Meeting Notes");
    }

    #[test]
    fn note_minimal() {
        let n: Note = serde_json::from_value(json!({
            "noteId": "note-1",
            "title": "Quick Note",
        }))
        .unwrap();
        assert_eq!(n.note_id, "note-1");
        assert_eq!(n.title, "Quick Note");
        assert!(n.content.is_none());
        assert!(n.notebook_id.is_none());
        assert!(n.tags.is_none());
        assert!(n.active.is_none());
    }

    #[test]
    fn note_with_empty_content() {
        let n: Note = serde_json::from_value(json!({
            "noteId": "note-2",
            "title": "Empty",
            "content": "",
        }))
        .unwrap();
        assert_eq!(n.content, Some(String::new()));
    }

    #[test]
    fn note_list_roundtrip() {
        let nl: NoteList = serde_json::from_value(json!({
            "notes": [
                {"noteId": "n1", "title": "Note 1"},
                {"noteId": "n2", "title": "Note 2"},
            ],
            "total_count": 2,
        }))
        .unwrap();
        assert_eq!(nl.notes.len(), 2);
        assert_eq!(nl.total_count, Some(2));
    }

    #[test]
    fn note_list_empty() {
        let nl: NoteList =
            serde_json::from_value(json!({ "notes": [], "total_count": 0 })).unwrap();
        assert!(nl.notes.is_empty());
        assert_eq!(nl.total_count, Some(0));
    }

    #[test]
    fn note_list_no_total_count() {
        let nl: NoteList = serde_json::from_value(json!({ "notes": [] })).unwrap();
        assert!(nl.total_count.is_none());
    }

    #[test]
    fn create_note_response_roundtrip() {
        let r: CreateNoteResponse = serde_json::from_value(json!({
            "noteId": "note-new",
            "title": "New Note",
            "notebookId": "nb-1",
        }))
        .unwrap();
        assert_eq!(r.note_id, "note-new");
        assert_eq!(r.title, Some("New Note".into()));
        assert_eq!(r.notebook_id, Some("nb-1".into()));
    }

    #[test]
    fn create_note_response_minimal() {
        let r: CreateNoteResponse = serde_json::from_value(json!({
            "noteId": "note-x",
        }))
        .unwrap();
        assert_eq!(r.note_id, "note-x");
        assert!(r.title.is_none());
        assert!(r.notebook_id.is_none());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "errorCode": 2,
            "message": "Not found",
        }))
        .unwrap();
        assert_eq!(e.error_code, Some(2));
        assert_eq!(e.message, Some("Not found".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.error_code.is_none());
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_response_code_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"errorCode": 10})).unwrap();
        assert_eq!(e.error_code, Some(10));
        assert!(e.message.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse =
            serde_json::from_value(json!({"message": "auth failed"})).unwrap();
        assert!(e.error_code.is_none());
        assert_eq!(e.message, Some("auth failed".into()));
    }

    #[test]
    fn pagination_params_roundtrip() {
        let p: PaginationParams = serde_json::from_value(json!({
            "offset": 10,
            "limit": 25,
        }))
        .unwrap();
        assert_eq!(p.offset, Some(10));
        assert_eq!(p.limit, Some(25));
    }

    #[test]
    fn pagination_params_empty() {
        let p: PaginationParams = serde_json::from_value(json!({})).unwrap();
        assert!(p.offset.is_none());
        assert!(p.limit.is_none());
    }

    #[test]
    fn notebook_serialization_preserves_camel_case() {
        let n = Notebook {
            id: "nb1".into(),
            name: "Test".into(),
            created: None,
            updated: None,
            default_notebook: Some(false),
            stack: None,
        };
        let v = serde_json::to_value(&n).unwrap();
        assert!(v.get("defaultNotebook").is_some());
        assert!(v.get("default_notebook").is_none());
    }

    #[test]
    fn note_serialization_preserves_camel_case() {
        let n = Note {
            note_id: "n1".into(),
            title: "T".into(),
            content: None,
            notebook_id: Some("nb1".into()),
            created: None,
            updated: None,
            active: None,
            tags: None,
        };
        let v = serde_json::to_value(&n).unwrap();
        assert!(v.get("noteId").is_some());
        assert!(v.get("notebookId").is_some());
        assert!(v.get("note_id").is_none());
    }

    #[test]
    fn note_with_empty_tags() {
        let n: Note = serde_json::from_value(json!({
            "noteId": "n1",
            "title": "T",
            "tags": [],
        }))
        .unwrap();
        assert!(n.tags.unwrap().is_empty());
    }

    #[test]
    fn notebook_clone() {
        let n = Notebook {
            id: "nb1".into(),
            name: "Work".into(),
            created: Some(1000),
            updated: Some(2000),
            default_notebook: Some(true),
            stack: Some("Projects".into()),
        };
        let cloned = Notebook::clone(&n);
        assert_eq!(cloned.id, "nb1");
        assert_eq!(cloned.stack, Some("Projects".into()));
    }

    #[test]
    fn notebook_debug() {
        let n = Notebook {
            id: "nb99".into(),
            name: "Debug".into(),
            created: None,
            updated: None,
            default_notebook: None,
            stack: None,
        };
        let dbg = format!("{n:?}");
        assert!(dbg.contains("nb99"));
    }

    #[test]
    fn note_clone() {
        let n = Note {
            note_id: "n1".into(),
            title: "Test".into(),
            content: Some("body".into()),
            notebook_id: Some("nb1".into()),
            created: None,
            updated: None,
            active: Some(true),
            tags: Some(vec!["tag1".into()]),
        };
        let cloned = Note::clone(&n);
        assert_eq!(cloned.note_id, "n1");
        assert_eq!(cloned.tags.unwrap().len(), 1);
    }

    #[test]
    fn note_debug() {
        let n = Note {
            note_id: "n99".into(),
            title: "Dbg".into(),
            content: None,
            notebook_id: None,
            created: None,
            updated: None,
            active: None,
            tags: None,
        };
        let dbg = format!("{n:?}");
        assert!(dbg.contains("n99"));
    }

    #[test]
    fn notebook_list_clone() {
        let nl = NotebookList { notebooks: vec![json!({"id": "nb1"})] };
        let cloned = NotebookList::clone(&nl);
        assert_eq!(cloned.notebooks.len(), 1);
    }

    #[test]
    fn note_list_clone() {
        let nl = NoteList { notes: vec![], total_count: Some(5) };
        let cloned = NoteList::clone(&nl);
        assert_eq!(cloned.total_count, Some(5));
    }

    #[test]
    fn create_note_response_clone() {
        let r = CreateNoteResponse {
            note_id: "n1".into(),
            title: Some("Title".into()),
            notebook_id: Some("nb1".into()),
        };
        let cloned = CreateNoteResponse::clone(&r);
        assert_eq!(cloned.note_id, "n1");
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            error_code: Some(5),
            message: Some("err".into()),
        };
        let cloned = ApiErrorResponse::clone(&e);
        assert_eq!(cloned.error_code, Some(5));
    }

    #[test]
    fn pagination_params_clone() {
        let p = PaginationParams { offset: Some(10), limit: Some(25) };
        let cloned = PaginationParams::clone(&p);
        assert_eq!(cloned.offset, Some(10));
        assert_eq!(cloned.limit, Some(25));
    }

    #[test]
    fn notebook_serialize_roundtrip() {
        let n = Notebook {
            id: "nb1".into(),
            name: "Test".into(),
            created: Some(1000),
            updated: None,
            default_notebook: None,
            stack: None,
        };
        let v = serde_json::to_value(&n).unwrap();
        let back: Notebook = serde_json::from_value(v).unwrap();
        assert_eq!(back.id, "nb1");
        assert_eq!(back.created, Some(1000));
    }

    #[test]
    fn note_null_fields_become_none() {
        let n: Note = serde_json::from_value(json!({
            "noteId": "n1",
            "title": "T",
            "content": null,
            "notebookId": null,
            "created": null,
            "updated": null,
            "active": null,
            "tags": null,
        }))
        .unwrap();
        assert!(n.content.is_none());
        assert!(n.notebook_id.is_none());
        assert!(n.active.is_none());
        assert!(n.tags.is_none());
    }

    #[test]
    fn create_note_response_serialize_roundtrip() {
        let r = CreateNoteResponse {
            note_id: "n1".into(),
            title: Some("T".into()),
            notebook_id: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["noteId"], "n1");
        assert_eq!(v["title"], "T");
    }
}
