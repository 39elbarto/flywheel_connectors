//! Google Calendar API types.

use serde::{Deserialize, Serialize};

/// A calendar entry from the calendar list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarEntry {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub time_zone: Option<String>,
    #[serde(default)]
    pub primary: bool,
}

/// A calendar event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub start: Option<EventDateTime>,
    #[serde(default)]
    pub end: Option<EventDateTime>,
    #[serde(default)]
    pub creator: Option<EventPerson>,
    #[serde(default)]
    pub organizer: Option<EventPerson>,
    #[serde(default)]
    pub attendees: Vec<Attendee>,
    #[serde(default)]
    pub html_link: Option<String>,
    #[serde(default)]
    pub hangout_link: Option<String>,
    #[serde(default)]
    pub recurrence: Vec<String>,
}

/// Date/time for an event (either date-time or all-day date).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventDateTime {
    #[serde(default)]
    pub date_time: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub time_zone: Option<String>,
}

/// A person associated with an event (creator or organizer).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventPerson {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(rename = "self", default)]
    pub self_: bool,
}

/// An event attendee.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attendee {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub response_status: Option<String>,
    #[serde(default)]
    pub optional: bool,
}

/// Response from the calendar list endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarListResponse {
    #[serde(default)]
    pub items: Vec<CalendarEntry>,
}

/// Response from the events list endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventsListResponse {
    #[serde(default)]
    pub items: Vec<Event>,
    #[serde(default)]
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}
