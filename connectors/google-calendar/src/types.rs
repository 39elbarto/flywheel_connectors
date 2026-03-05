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
    pub next_sync_token: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

/// A calendar item in a freebusy request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeBusyRequestItem {
    pub id: String,
}

/// Request body for the freebusy query.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreeBusyRequest {
    pub time_min: String,
    pub time_max: String,
    pub items: Vec<FreeBusyRequestItem>,
}

/// A busy time range within a calendar's freebusy response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusyTime {
    pub start: String,
    pub end: String,
}

/// Per-calendar freebusy information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarFreeBusy {
    #[serde(default)]
    pub busy: Vec<BusyTime>,
}

/// Response from the freebusy endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FreeBusyResponse {
    #[serde(default)]
    pub calendars: std::collections::HashMap<String, CalendarFreeBusy>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn calendar_entry_serde() {
        let json = json!({
            "id": "primary",
            "summary": "My Calendar",
            "timeZone": "America/New_York",
            "primary": true
        });
        let cal: CalendarEntry = serde_json::from_value(json).unwrap();
        assert_eq!(cal.id, "primary");
        assert!(cal.primary);
    }

    #[test]
    fn calendar_entry_defaults() {
        let json = json!({"id": "test"});
        let cal: CalendarEntry = serde_json::from_value(json).unwrap();
        assert!(!cal.primary);
        assert!(cal.summary.is_none());
    }

    #[test]
    fn event_serde() {
        let json = json!({
            "id": "evt1",
            "status": "confirmed",
            "summary": "Meeting",
            "start": {"dateTime": "2026-03-03T10:00:00-05:00", "timeZone": "America/New_York"},
            "end": {"dateTime": "2026-03-03T11:00:00-05:00"},
            "attendees": [{"email": "alice@example.com", "responseStatus": "accepted"}]
        });
        let event: Event = serde_json::from_value(json).unwrap();
        assert_eq!(event.summary.as_deref(), Some("Meeting"));
        assert!(event.start.is_some());
        assert_eq!(event.attendees.len(), 1);
    }

    #[test]
    fn event_minimal() {
        let json = json!({});
        let event: Event = serde_json::from_value(json).unwrap();
        assert!(event.id.is_none());
        assert!(event.attendees.is_empty());
        assert!(event.recurrence.is_empty());
    }

    #[test]
    fn event_date_time_all_day() {
        let json = json!({"date": "2026-03-03"});
        let dt: EventDateTime = serde_json::from_value(json).unwrap();
        assert_eq!(dt.date.as_deref(), Some("2026-03-03"));
        assert!(dt.date_time.is_none());
    }

    #[test]
    fn event_person_self_rename() {
        let json = json!({"email": "me@example.com", "self": true});
        let person: EventPerson = serde_json::from_value(json).unwrap();
        assert!(person.self_);
    }

    #[test]
    fn events_list_response() {
        let json = json!({
            "items": [],
            "nextPageToken": "token123",
            "summary": "My Calendar"
        });
        let resp: EventsListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.items.is_empty());
        assert_eq!(resp.next_page_token.as_deref(), Some("token123"));
    }

    #[test]
    fn free_busy_request_serialize() {
        let req = FreeBusyRequest {
            time_min: "2026-03-03T00:00:00Z".to_string(),
            time_max: "2026-03-04T00:00:00Z".to_string(),
            items: vec![FreeBusyRequestItem {
                id: "primary".to_string(),
            }],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("timeMin"));
        assert!(json.contains("timeMax"));
    }

    #[test]
    fn free_busy_response_serde() {
        let json = json!({
            "calendars": {
                "primary": {"busy": [{"start": "2026-03-03T10:00:00Z", "end": "2026-03-03T11:00:00Z"}]}
            }
        });
        let resp: FreeBusyResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.calendars.len(), 1);
        assert_eq!(resp.calendars["primary"].busy.len(), 1);
    }
}
