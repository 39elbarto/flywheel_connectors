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

    // ---- Message: Clone, Debug, camelCase deserialization ----

    #[test]
    fn message_clone() {
        let msg = Message {
            id: Some("m-1".into()),
            subject: Some("Hello".into()),
            body_preview: None,
            body: None,
            from: None,
            to_recipients: None,
            received_date_time: None,
            is_read: Some(true),
        };
        let cloned = msg.clone();
        assert_eq!(cloned.id, msg.id);
        assert_eq!(cloned.subject, msg.subject);
        assert_eq!(cloned.is_read, msg.is_read);
    }

    #[test]
    fn message_debug() {
        let msg = Message {
            id: Some("dbg-1".into()),
            subject: None,
            body_preview: None,
            body: None,
            from: None,
            to_recipients: None,
            received_date_time: None,
            is_read: None,
        };
        let debug = format!("{msg:?}");
        assert!(debug.contains("Message"), "got: {debug}");
        assert!(debug.contains("dbg-1"), "got: {debug}");
    }

    #[test]
    fn message_deserialize_from_camelcase_json() {
        let json = serde_json::json!({
            "id": "camel-1",
            "subject": "Re: Meeting",
            "bodyPreview": "Thanks for the update",
            "body": {
                "contentType": "html",
                "content": "<p>Thanks</p>"
            },
            "from": {
                "emailAddress": {
                    "name": "Alice",
                    "address": "alice@contoso.com"
                }
            },
            "toRecipients": [
                {
                    "emailAddress": {
                        "name": "Bob",
                        "address": "bob@contoso.com"
                    }
                }
            ],
            "receivedDateTime": "2026-03-05T14:30:00Z",
            "isRead": true
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.id.as_deref(), Some("camel-1"));
        assert_eq!(msg.body_preview.as_deref(), Some("Thanks for the update"));
        assert_eq!(
            msg.received_date_time.as_deref(),
            Some("2026-03-05T14:30:00Z")
        );
        assert_eq!(msg.is_read, Some(true));
        let body = msg.body.unwrap();
        assert_eq!(body.content_type.as_deref(), Some("html"));
        let from = msg.from.unwrap();
        assert_eq!(
            from.email_address.unwrap().address.as_deref(),
            Some("alice@contoso.com")
        );
        let recipients = msg.to_recipients.unwrap();
        assert_eq!(recipients.len(), 1);
    }

    // ---- ItemBody ----

    #[test]
    fn item_body_roundtrip() {
        let body = ItemBody {
            content_type: Some("text".into()),
            content: Some("Hello world".into()),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["contentType"], "text");
        assert_eq!(json["content"], "Hello world");
        let back: ItemBody = serde_json::from_value(json).unwrap();
        assert_eq!(back.content_type.as_deref(), Some("text"));
    }

    #[test]
    fn item_body_all_none() {
        let json = serde_json::json!({});
        let body: ItemBody = serde_json::from_value(json).unwrap();
        assert!(body.content_type.is_none());
        assert!(body.content.is_none());
    }

    #[test]
    fn item_body_debug() {
        let body = ItemBody {
            content_type: Some("html".into()),
            content: None,
        };
        let debug = format!("{body:?}");
        assert!(debug.contains("ItemBody"), "got: {debug}");
        assert!(debug.contains("html"), "got: {debug}");
    }

    #[test]
    fn item_body_clone() {
        let body = ItemBody {
            content_type: Some("text".into()),
            content: Some("content".into()),
        };
        let cloned = body.clone();
        assert_eq!(cloned.content_type, body.content_type);
        assert_eq!(cloned.content, body.content);
    }

    // ---- Recipient ----

    #[test]
    fn recipient_roundtrip() {
        let r = Recipient {
            email_address: Some(EmailAddress {
                name: Some("Test".into()),
                address: Some("test@example.com".into()),
            }),
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["emailAddress"]["name"], "Test");
        let back: Recipient = serde_json::from_value(json).unwrap();
        assert!(back.email_address.is_some());
    }

    #[test]
    fn recipient_none_email() {
        let json = serde_json::json!({});
        let r: Recipient = serde_json::from_value(json).unwrap();
        assert!(r.email_address.is_none());
    }

    #[test]
    fn recipient_debug() {
        let r = Recipient {
            email_address: None,
        };
        let debug = format!("{r:?}");
        assert!(debug.contains("Recipient"), "got: {debug}");
    }

    // ---- EmailAddress ----

    #[test]
    fn email_address_roundtrip() {
        let ea = EmailAddress {
            name: Some("John Doe".into()),
            address: Some("john@example.com".into()),
        };
        let json = serde_json::to_value(&ea).unwrap();
        assert_eq!(json["name"], "John Doe");
        assert_eq!(json["address"], "john@example.com");
        let back: EmailAddress = serde_json::from_value(json).unwrap();
        assert_eq!(back.name.as_deref(), Some("John Doe"));
    }

    #[test]
    fn email_address_empty_strings() {
        let ea = EmailAddress {
            name: Some(String::new()),
            address: Some(String::new()),
        };
        let json = serde_json::to_value(&ea).unwrap();
        assert_eq!(json["name"], "");
        assert_eq!(json["address"], "");
    }

    #[test]
    fn email_address_debug() {
        let ea = EmailAddress {
            name: Some("Test".into()),
            address: None,
        };
        let debug = format!("{ea:?}");
        assert!(debug.contains("EmailAddress"), "got: {debug}");
        assert!(debug.contains("Test"), "got: {debug}");
    }

    // ---- DriveItem ----

    #[test]
    fn drive_item_all_none() {
        let json = serde_json::json!({});
        let item: DriveItem = serde_json::from_value(json).unwrap();
        assert!(item.id.is_none());
        assert!(item.name.is_none());
        assert!(item.size.is_none());
        assert!(item.web_url.is_none());
        assert!(item.folder.is_none());
        assert!(item.file.is_none());
        assert!(item.created_date_time.is_none());
        assert!(item.last_modified_date_time.is_none());
    }

    #[test]
    fn drive_item_clone() {
        let item = DriveItem {
            id: Some("clone-1".into()),
            name: Some("test.txt".into()),
            size: Some(100),
            web_url: None,
            folder: None,
            file: None,
            created_date_time: None,
            last_modified_date_time: None,
        };
        let cloned = item.clone();
        assert_eq!(cloned.id, item.id);
        assert_eq!(cloned.size, item.size);
    }

    #[test]
    fn drive_item_debug() {
        let item = DriveItem {
            id: Some("dbg-1".into()),
            name: None,
            size: None,
            web_url: None,
            folder: None,
            file: None,
            created_date_time: None,
            last_modified_date_time: None,
        };
        let debug = format!("{item:?}");
        assert!(debug.contains("DriveItem"), "got: {debug}");
    }

    #[test]
    fn drive_item_both_folder_and_file_none() {
        let item = DriveItem {
            id: Some("neither".into()),
            name: Some("weird".into()),
            size: Some(0),
            web_url: None,
            folder: None,
            file: None,
            created_date_time: None,
            last_modified_date_time: None,
        };
        let json = serde_json::to_value(&item).unwrap();
        assert!(
            json.get("folder").is_none() || json["folder"].is_null(),
            "folder should be absent or null"
        );
        assert!(
            json.get("file").is_none() || json["file"].is_null(),
            "file should be absent or null"
        );
    }

    // ---- FolderFacet ----

    #[test]
    fn folder_facet_roundtrip() {
        let f = FolderFacet {
            child_count: Some(10),
        };
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["childCount"], 10);
        let back: FolderFacet = serde_json::from_value(json).unwrap();
        assert_eq!(back.child_count, Some(10));
    }

    #[test]
    fn folder_facet_none_child_count() {
        let json = serde_json::json!({});
        let f: FolderFacet = serde_json::from_value(json).unwrap();
        assert!(f.child_count.is_none());
    }

    #[test]
    fn folder_facet_debug() {
        let f = FolderFacet {
            child_count: Some(3),
        };
        let debug = format!("{f:?}");
        assert!(debug.contains("FolderFacet"), "got: {debug}");
    }

    // ---- FileFacet ----

    #[test]
    fn file_facet_roundtrip() {
        let f = FileFacet {
            mime_type: Some("application/pdf".into()),
        };
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["mimeType"], "application/pdf");
        let back: FileFacet = serde_json::from_value(json).unwrap();
        assert_eq!(back.mime_type.as_deref(), Some("application/pdf"));
    }

    #[test]
    fn file_facet_none_mime_type() {
        let json = serde_json::json!({});
        let f: FileFacet = serde_json::from_value(json).unwrap();
        assert!(f.mime_type.is_none());
    }

    #[test]
    fn file_facet_debug() {
        let f = FileFacet {
            mime_type: Some("text/plain".into()),
        };
        let debug = format!("{f:?}");
        assert!(debug.contains("FileFacet"), "got: {debug}");
    }

    // ---- Event ----

    #[test]
    fn event_all_none() {
        let json = serde_json::json!({});
        let event: Event = serde_json::from_value(json).unwrap();
        assert!(event.id.is_none());
        assert!(event.subject.is_none());
        assert!(event.body.is_none());
        assert!(event.start.is_none());
        assert!(event.end.is_none());
        assert!(event.location.is_none());
        assert!(event.attendees.is_none());
        assert!(event.organizer.is_none());
        assert!(event.is_all_day.is_none());
    }

    #[test]
    fn event_clone() {
        let event = Event {
            id: Some("evt-clone".into()),
            subject: Some("Cloned".into()),
            body: None,
            start: None,
            end: None,
            location: None,
            attendees: None,
            organizer: None,
            is_all_day: Some(false),
        };
        let cloned = event.clone();
        assert_eq!(cloned.id, event.id);
        assert_eq!(cloned.is_all_day, event.is_all_day);
    }

    #[test]
    fn event_debug() {
        let event = Event {
            id: Some("evt-dbg".into()),
            subject: None,
            body: None,
            start: None,
            end: None,
            location: None,
            attendees: None,
            organizer: None,
            is_all_day: None,
        };
        let debug = format!("{event:?}");
        assert!(debug.contains("Event"), "got: {debug}");
    }

    #[test]
    fn event_all_day_true() {
        let json = serde_json::json!({
            "id": "allday-1",
            "subject": "Holiday",
            "isAllDay": true,
            "start": { "dateTime": "2026-12-25", "timeZone": "UTC" },
            "end": { "dateTime": "2026-12-26", "timeZone": "UTC" }
        });
        let event: Event = serde_json::from_value(json).unwrap();
        assert_eq!(event.is_all_day, Some(true));
        assert_eq!(event.subject.as_deref(), Some("Holiday"));
    }

    #[test]
    fn event_with_organizer() {
        let json = serde_json::json!({
            "id": "org-1",
            "subject": "Organized Event",
            "organizer": {
                "emailAddress": {
                    "name": "Organizer Person",
                    "address": "organizer@contoso.com"
                }
            }
        });
        let event: Event = serde_json::from_value(json).unwrap();
        let organizer = event.organizer.unwrap();
        let ea = organizer.email_address.unwrap();
        assert_eq!(ea.name.as_deref(), Some("Organizer Person"));
        assert_eq!(ea.address.as_deref(), Some("organizer@contoso.com"));
    }

    // ---- DateTimeTimeZone ----

    #[test]
    fn datetimetimezone_roundtrip() {
        let dt = DateTimeTimeZone {
            date_time: Some("2026-03-05T10:00:00".into()),
            time_zone: Some("Pacific Standard Time".into()),
        };
        let json = serde_json::to_value(&dt).unwrap();
        assert_eq!(json["dateTime"], "2026-03-05T10:00:00");
        assert_eq!(json["timeZone"], "Pacific Standard Time");
        let back: DateTimeTimeZone = serde_json::from_value(json).unwrap();
        assert_eq!(back.date_time.as_deref(), Some("2026-03-05T10:00:00"));
    }

    #[test]
    fn datetimetimezone_both_none() {
        let json = serde_json::json!({});
        let dt: DateTimeTimeZone = serde_json::from_value(json).unwrap();
        assert!(dt.date_time.is_none());
        assert!(dt.time_zone.is_none());
    }

    #[test]
    fn datetimetimezone_clone() {
        let dt = DateTimeTimeZone {
            date_time: Some("2026-01-01".into()),
            time_zone: Some("UTC".into()),
        };
        let cloned = dt.clone();
        assert_eq!(cloned.date_time, dt.date_time);
        assert_eq!(cloned.time_zone, dt.time_zone);
    }

    #[test]
    fn datetimetimezone_debug() {
        let dt = DateTimeTimeZone {
            date_time: Some("2026-06-15T09:00:00".into()),
            time_zone: None,
        };
        let debug = format!("{dt:?}");
        assert!(debug.contains("DateTimeTimeZone"), "got: {debug}");
    }

    // ---- Location ----

    #[test]
    fn location_roundtrip() {
        let loc = Location {
            display_name: Some("Conference Room A".into()),
        };
        let json = serde_json::to_value(&loc).unwrap();
        assert_eq!(json["displayName"], "Conference Room A");
        let back: Location = serde_json::from_value(json).unwrap();
        assert_eq!(back.display_name.as_deref(), Some("Conference Room A"));
    }

    #[test]
    fn location_none_display_name() {
        let json = serde_json::json!({});
        let loc: Location = serde_json::from_value(json).unwrap();
        assert!(loc.display_name.is_none());
    }

    #[test]
    fn location_debug() {
        let loc = Location {
            display_name: Some("Room 42".into()),
        };
        let debug = format!("{loc:?}");
        assert!(debug.contains("Location"), "got: {debug}");
    }

    // ---- Attendee ----

    #[test]
    fn attendee_roundtrip() {
        let att = Attendee {
            email_address: Some(EmailAddress {
                name: Some("Jane".into()),
                address: Some("jane@example.com".into()),
            }),
            attendee_type: Some("optional".into()),
        };
        let json = serde_json::to_value(&att).unwrap();
        assert_eq!(json["type"], "optional");
        assert_eq!(json["emailAddress"]["name"], "Jane");
        let back: Attendee = serde_json::from_value(json).unwrap();
        assert_eq!(back.attendee_type.as_deref(), Some("optional"));
    }

    #[test]
    fn attendee_clone() {
        let att = Attendee {
            email_address: Some(EmailAddress {
                name: Some("Clone".into()),
                address: None,
            }),
            attendee_type: Some("required".into()),
        };
        let cloned = att.clone();
        assert_eq!(cloned.attendee_type, att.attendee_type);
    }

    #[test]
    fn attendee_debug() {
        let att = Attendee {
            email_address: None,
            attendee_type: None,
        };
        let debug = format!("{att:?}");
        assert!(debug.contains("Attendee"), "got: {debug}");
    }

    // ---- TodoTaskList ----

    #[test]
    fn todo_task_list_all_none() {
        let json = serde_json::json!({});
        let list: TodoTaskList = serde_json::from_value(json).unwrap();
        assert!(list.id.is_none());
        assert!(list.display_name.is_none());
        assert!(list.is_owner.is_none());
    }

    #[test]
    fn todo_task_list_debug() {
        let list = TodoTaskList {
            id: Some("list-dbg".into()),
            display_name: Some("Debug List".into()),
            is_owner: Some(true),
        };
        let debug = format!("{list:?}");
        assert!(debug.contains("TodoTaskList"), "got: {debug}");
    }

    #[test]
    fn todo_task_list_is_owner_false() {
        let json = serde_json::json!({
            "id": "shared-1",
            "displayName": "Shared Tasks",
            "isOwner": false
        });
        let list: TodoTaskList = serde_json::from_value(json).unwrap();
        assert_eq!(list.is_owner, Some(false));
        assert_eq!(list.display_name.as_deref(), Some("Shared Tasks"));
    }

    // ---- TodoTask ----

    #[test]
    fn todo_task_all_none() {
        let json = serde_json::json!({});
        let task: TodoTask = serde_json::from_value(json).unwrap();
        assert!(task.id.is_none());
        assert!(task.title.is_none());
        assert!(task.status.is_none());
        assert!(task.body.is_none());
        assert!(task.due_date_time.is_none());
        assert!(task.created_date_time.is_none());
        assert!(task.completed_date_time.is_none());
    }

    #[test]
    fn todo_task_completed_with_completed_date_time() {
        let json = serde_json::json!({
            "id": "task-done",
            "title": "Finish report",
            "status": "completed",
            "completedDateTime": {
                "dateTime": "2026-03-04T16:00:00",
                "timeZone": "UTC"
            },
            "createdDateTime": "2026-03-01T09:00:00Z"
        });
        let task: TodoTask = serde_json::from_value(json).unwrap();
        assert_eq!(task.status.as_deref(), Some("completed"));
        let completed = task.completed_date_time.unwrap();
        assert_eq!(completed.date_time.as_deref(), Some("2026-03-04T16:00:00"));
        assert_eq!(completed.time_zone.as_deref(), Some("UTC"));
    }

    #[test]
    fn todo_task_debug() {
        let task = TodoTask {
            id: Some("task-dbg".into()),
            title: Some("Debug task".into()),
            status: None,
            body: None,
            due_date_time: None,
            created_date_time: None,
            completed_date_time: None,
        };
        let debug = format!("{task:?}");
        assert!(debug.contains("TodoTask"), "got: {debug}");
    }

    // ---- Subscription ----

    #[test]
    fn subscription_all_none() {
        let json = serde_json::json!({});
        let sub: Subscription = serde_json::from_value(json).unwrap();
        assert!(sub.id.is_none());
        assert!(sub.resource.is_none());
        assert!(sub.change_type.is_none());
        assert!(sub.notification_url.is_none());
        assert!(sub.expiration_date_time.is_none());
    }

    #[test]
    fn subscription_debug() {
        let sub = Subscription {
            id: Some("sub-dbg".into()),
            resource: Some("/me/messages".into()),
            change_type: None,
            notification_url: None,
            expiration_date_time: None,
        };
        let debug = format!("{sub:?}");
        assert!(debug.contains("Subscription"), "got: {debug}");
    }

    #[test]
    fn subscription_clone() {
        let sub = Subscription {
            id: Some("sub-clone".into()),
            resource: Some("/me/events".into()),
            change_type: Some("updated".into()),
            notification_url: Some("https://example.com/hook".into()),
            expiration_date_time: Some("2026-04-01T00:00:00Z".into()),
        };
        let cloned = sub.clone();
        assert_eq!(cloned.id, sub.id);
        assert_eq!(cloned.resource, sub.resource);
        assert_eq!(cloned.change_type, sub.change_type);
        assert_eq!(cloned.notification_url, sub.notification_url);
        assert_eq!(cloned.expiration_date_time, sub.expiration_date_time);
    }

    // ---- GraphListResponse ----

    #[test]
    fn graph_list_response_empty_value_array() {
        let json = serde_json::json!({ "value": [] });
        let resp: GraphListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.value.is_empty());
        assert!(resp.next_link.is_none());
        assert!(resp.delta_link.is_none());
    }

    #[test]
    fn graph_list_response_both_links_none() {
        let json = serde_json::json!({
            "value": [{"id": "1"}]
        });
        let resp: GraphListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.value.len(), 1);
        assert!(resp.next_link.is_none());
        assert!(resp.delta_link.is_none());
    }

    #[test]
    fn graph_list_response_clone() {
        let json = serde_json::json!({
            "value": [{"id": "a"}, {"id": "b"}],
            "@odata.nextLink": "https://graph.microsoft.com/next"
        });
        let resp: GraphListResponse = serde_json::from_value(json).unwrap();
        let cloned = resp.clone();
        assert_eq!(cloned.value.len(), 2);
        assert_eq!(cloned.next_link, resp.next_link);
    }

    #[test]
    fn graph_list_response_debug() {
        let json = serde_json::json!({ "value": [] });
        let resp: GraphListResponse = serde_json::from_value(json).unwrap();
        let debug = format!("{resp:?}");
        assert!(debug.contains("GraphListResponse"), "got: {debug}");
    }

    // ---- GraphErrorResponse ----

    #[test]
    fn graph_error_response_missing_error_key() {
        let json = serde_json::json!({});
        let resp: GraphErrorResponse = serde_json::from_value(json).unwrap();
        assert!(resp.error.is_none());
    }

    #[test]
    fn graph_error_response_debug() {
        let json = serde_json::json!({
            "error": { "code": "BadRequest", "message": "Invalid filter" }
        });
        let resp: GraphErrorResponse = serde_json::from_value(json).unwrap();
        let debug = format!("{resp:?}");
        assert!(debug.contains("GraphErrorResponse"), "got: {debug}");
        assert!(debug.contains("BadRequest"), "got: {debug}");
    }

    // ---- GraphErrorDetail ----

    #[test]
    fn graph_error_detail_all_none() {
        let json = serde_json::json!({});
        let detail: GraphErrorDetail = serde_json::from_value(json).unwrap();
        assert!(detail.code.is_none());
        assert!(detail.message.is_none());
    }

    #[test]
    fn graph_error_detail_debug() {
        let detail = GraphErrorDetail {
            code: Some("NotFound".into()),
            message: Some("Resource not found".into()),
        };
        let debug = format!("{detail:?}");
        assert!(debug.contains("GraphErrorDetail"), "got: {debug}");
        assert!(debug.contains("NotFound"), "got: {debug}");
    }
}
