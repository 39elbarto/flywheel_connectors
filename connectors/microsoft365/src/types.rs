//! Microsoft Graph API types.

use serde::{Deserialize, Serialize};

/// An Outlook email message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: Option<String>,
    pub subject: Option<String>,
    #[serde(rename = "bodyPreview")]
    pub body_preview: Option<String>,
    pub body: Option<ItemBody>,
    #[serde(rename = "from")]
    pub from: Option<Recipient>,
    #[serde(rename = "toRecipients")]
    pub to_recipients: Option<Vec<Recipient>>,
    #[serde(rename = "receivedDateTime")]
    pub received_date_time: Option<String>,
    #[serde(rename = "isRead")]
    pub is_read: Option<bool>,
}

/// Email body content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemBody {
    #[serde(rename = "contentType")]
    pub content_type: Option<String>,
    pub content: Option<String>,
}

/// Email recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    #[serde(rename = "emailAddress")]
    pub email_address: Option<EmailAddress>,
}

/// Email address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub address: Option<String>,
}

/// A OneDrive file or folder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveItem {
    pub id: Option<String>,
    pub name: Option<String>,
    pub size: Option<i64>,
    #[serde(rename = "webUrl")]
    pub web_url: Option<String>,
    pub folder: Option<FolderFacet>,
    pub file: Option<FileFacet>,
    #[serde(rename = "createdDateTime")]
    pub created_date_time: Option<String>,
    #[serde(rename = "lastModifiedDateTime")]
    pub last_modified_date_time: Option<String>,
}

/// Folder facet indicating an item is a folder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderFacet {
    #[serde(rename = "childCount")]
    pub child_count: Option<i32>,
}

/// File facet indicating an item is a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileFacet {
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,
}

/// A calendar event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Option<String>,
    pub subject: Option<String>,
    pub body: Option<ItemBody>,
    pub start: Option<DateTimeTimeZone>,
    pub end: Option<DateTimeTimeZone>,
    pub location: Option<Location>,
    pub attendees: Option<Vec<Attendee>>,
    #[serde(rename = "organizer")]
    pub organizer: Option<Recipient>,
    #[serde(rename = "isAllDay")]
    pub is_all_day: Option<bool>,
}

/// DateTime with time zone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateTimeTimeZone {
    #[serde(rename = "dateTime")]
    pub date_time: Option<String>,
    #[serde(rename = "timeZone")]
    pub time_zone: Option<String>,
}

/// Event location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
}

/// Event attendee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attendee {
    #[serde(rename = "emailAddress")]
    pub email_address: Option<EmailAddress>,
    #[serde(rename = "type")]
    pub attendee_type: Option<String>,
}

/// A Microsoft To Do task list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoTaskList {
    pub id: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "isOwner")]
    pub is_owner: Option<bool>,
}

/// A Microsoft To Do task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TodoTask {
    pub id: Option<String>,
    pub title: Option<String>,
    pub status: Option<String>,
    pub body: Option<ItemBody>,
    #[serde(rename = "dueDateTime")]
    pub due_date_time: Option<DateTimeTimeZone>,
    #[serde(rename = "createdDateTime")]
    pub created_date_time: Option<String>,
    #[serde(rename = "completedDateTime")]
    pub completed_date_time: Option<DateTimeTimeZone>,
}

/// A Graph API webhook subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: Option<String>,
    pub resource: Option<String>,
    #[serde(rename = "changeType")]
    pub change_type: Option<String>,
    #[serde(rename = "notificationUrl")]
    pub notification_url: Option<String>,
    #[serde(rename = "expirationDateTime")]
    pub expiration_date_time: Option<String>,
}

/// Generic OData list response from Microsoft Graph.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphListResponse {
    pub value: Vec<serde_json::Value>,
    #[serde(rename = "@odata.nextLink")]
    pub next_link: Option<String>,
    #[serde(rename = "@odata.deltaLink")]
    pub delta_link: Option<String>,
}

/// Graph API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphErrorResponse {
    pub error: Option<GraphErrorDetail>,
}

/// Graph API error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphErrorDetail {
    pub code: Option<String>,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Message serde roundtrip ----

    #[test]
    fn message_serde_roundtrip() {
        let msg = Message {
            id: Some("msg-1".into()),
            subject: Some("Test subject".into()),
            body_preview: Some("Preview text".into()),
            body: Some(ItemBody {
                content_type: Some("text".into()),
                content: Some("Hello world".into()),
            }),
            from: Some(Recipient {
                email_address: Some(EmailAddress {
                    name: Some("Alice".into()),
                    address: Some("alice@example.com".into()),
                }),
            }),
            to_recipients: Some(vec![Recipient {
                email_address: Some(EmailAddress {
                    name: Some("Bob".into()),
                    address: Some("bob@example.com".into()),
                }),
            }]),
            received_date_time: Some("2026-03-01T10:00:00Z".into()),
            is_read: Some(false),
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["id"], "msg-1");
        assert_eq!(json["subject"], "Test subject");
        assert_eq!(json["bodyPreview"], "Preview text");
        assert_eq!(json["isRead"], false);

        let back: Message = serde_json::from_value(json).unwrap();
        assert_eq!(back.id.as_deref(), Some("msg-1"));
        assert_eq!(back.is_read, Some(false));
    }

    #[test]
    fn message_with_all_nulls_deserializes() {
        let json = serde_json::json!({});
        let msg: Message = serde_json::from_value(json).unwrap();
        assert!(msg.id.is_none());
        assert!(msg.subject.is_none());
        assert!(msg.body.is_none());
        assert!(msg.from.is_none());
        assert!(msg.to_recipients.is_none());
        assert!(msg.is_read.is_none());
    }

    // ---- DriveItem serde ----

    #[test]
    fn drive_item_folder_vs_file() {
        let folder = DriveItem {
            id: Some("folder-1".into()),
            name: Some("Documents".into()),
            size: Some(0),
            web_url: Some("https://example.com/docs".into()),
            folder: Some(FolderFacet {
                child_count: Some(5),
            }),
            file: None,
            created_date_time: None,
            last_modified_date_time: None,
        };
        let json = serde_json::to_value(&folder).unwrap();
        assert!(json.get("folder").is_some());
        assert!(json.get("file").is_none() || json["file"].is_null());

        let file = DriveItem {
            id: Some("file-1".into()),
            name: Some("report.pdf".into()),
            size: Some(12345),
            web_url: None,
            folder: None,
            file: Some(FileFacet {
                mime_type: Some("application/pdf".into()),
            }),
            created_date_time: Some("2026-01-01T00:00:00Z".into()),
            last_modified_date_time: Some("2026-03-01T00:00:00Z".into()),
        };
        let json = serde_json::to_value(&file).unwrap();
        assert_eq!(json["name"], "report.pdf");
        assert_eq!(json["size"], 12345);
    }

    // ---- Event serde ----

    #[test]
    fn event_with_attendees_roundtrip() {
        let event = Event {
            id: Some("evt-1".into()),
            subject: Some("Team Meeting".into()),
            body: None,
            start: Some(DateTimeTimeZone {
                date_time: Some("2026-03-15T10:00:00".into()),
                time_zone: Some("UTC".into()),
            }),
            end: Some(DateTimeTimeZone {
                date_time: Some("2026-03-15T11:00:00".into()),
                time_zone: Some("UTC".into()),
            }),
            location: Some(Location {
                display_name: Some("Room 101".into()),
            }),
            attendees: Some(vec![Attendee {
                email_address: Some(EmailAddress {
                    name: Some("Charlie".into()),
                    address: Some("charlie@example.com".into()),
                }),
                attendee_type: Some("required".into()),
            }]),
            organizer: None,
            is_all_day: Some(false),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["subject"], "Team Meeting");
        assert_eq!(json["isAllDay"], false);
        assert_eq!(json["location"]["displayName"], "Room 101");
        let attendees = json["attendees"].as_array().unwrap();
        assert_eq!(attendees.len(), 1);
    }

    // ---- TodoTask serde ----

    #[test]
    fn todo_task_roundtrip() {
        let task = TodoTask {
            id: Some("task-1".into()),
            title: Some("Buy groceries".into()),
            status: Some("notStarted".into()),
            body: None,
            due_date_time: Some(DateTimeTimeZone {
                date_time: Some("2026-03-20T00:00:00".into()),
                time_zone: Some("UTC".into()),
            }),
            created_date_time: Some("2026-03-01T00:00:00Z".into()),
            completed_date_time: None,
        };
        let json = serde_json::to_value(&task).unwrap();
        assert_eq!(json["title"], "Buy groceries");
        assert_eq!(json["status"], "notStarted");
        let back: TodoTask = serde_json::from_value(json).unwrap();
        assert_eq!(back.title.as_deref(), Some("Buy groceries"));
    }

    // ---- TodoTaskList serde ----

    #[test]
    fn todo_task_list_serde() {
        let list = TodoTaskList {
            id: Some("list-1".into()),
            display_name: Some("Work Tasks".into()),
            is_owner: Some(true),
        };
        let json = serde_json::to_value(&list).unwrap();
        assert_eq!(json["displayName"], "Work Tasks");
        assert_eq!(json["isOwner"], true);
    }

    // ---- Subscription serde ----

    #[test]
    fn subscription_roundtrip() {
        let sub = Subscription {
            id: Some("sub-1".into()),
            resource: Some("/me/messages".into()),
            change_type: Some("created".into()),
            notification_url: Some("https://hook.example.com/notify".into()),
            expiration_date_time: Some("2026-04-01T00:00:00Z".into()),
        };
        let json = serde_json::to_value(&sub).unwrap();
        assert_eq!(json["changeType"], "created");
        assert_eq!(json["notificationUrl"], "https://hook.example.com/notify");
    }

    // ---- GraphListResponse ----

    #[test]
    fn graph_list_response_with_pagination() {
        let json = serde_json::json!({
            "value": [{"id": "1"}, {"id": "2"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skip=2"
        });
        let resp: GraphListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.value.len(), 2);
        assert!(resp.next_link.is_some());
        assert!(resp.delta_link.is_none());
    }

    #[test]
    fn graph_list_response_with_delta_link() {
        let json = serde_json::json!({
            "value": [],
            "@odata.deltaLink": "https://graph.microsoft.com/v1.0/me/messages/delta?$deltatoken=abc"
        });
        let resp: GraphListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.value.len(), 0);
        assert!(resp.delta_link.is_some());
        assert!(resp.delta_link.unwrap().contains("deltatoken"));
    }

    // ---- GraphErrorResponse ----

    #[test]
    fn graph_error_response_deserializes() {
        let json = serde_json::json!({
            "error": {
                "code": "InvalidAuthenticationToken",
                "message": "Access token has expired."
            }
        });
        let err: GraphErrorResponse = serde_json::from_value(json).unwrap();
        let detail = err.error.unwrap();
        assert_eq!(detail.code.as_deref(), Some("InvalidAuthenticationToken"));
        assert!(detail.message.unwrap().contains("expired"));
    }

    #[test]
    fn graph_error_response_null_error() {
        let json = serde_json::json!({ "error": null });
        let err: GraphErrorResponse = serde_json::from_value(json).unwrap();
        assert!(err.error.is_none());
    }
}
