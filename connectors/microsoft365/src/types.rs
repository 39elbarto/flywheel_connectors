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
