//! Google Admin Reports API types.

use serde::{Deserialize, Serialize};

/// An activity record from the Admin Activities report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub kind: Option<String>,
    pub id: Option<ActivityId>,
    pub actor: Option<Actor>,
    pub events: Option<Vec<ActivityEvent>>,
    #[serde(rename = "ipAddress")]
    pub ip_address: Option<String>,
}

/// Activity identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityId {
    pub time: Option<String>,
    pub unique_qualifier: Option<String>,
    pub application_name: Option<String>,
    pub customer_id: Option<String>,
}

/// Actor who performed the activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Actor {
    pub email: Option<String>,
    pub profile_id: Option<String>,
    pub caller_type: Option<String>,
    pub key: Option<String>,
}

/// An event within an activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityEvent {
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub name: Option<String>,
    pub parameters: Option<Vec<EventParameter>>,
}

/// A parameter on an activity event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventParameter {
    pub name: Option<String>,
    pub value: Option<String>,
    pub bool_value: Option<bool>,
    pub int_value: Option<String>,
    pub multi_value: Option<Vec<String>>,
}

/// Activities list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivitiesListResponse {
    pub kind: Option<String>,
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub items: Vec<Activity>,
}

/// Usage report entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageReport {
    pub kind: Option<String>,
    pub date: Option<String>,
    pub entity: Option<serde_json::Value>,
    pub parameters: Option<Vec<UsageParameter>>,
}

/// A parameter in a usage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageParameter {
    pub name: Option<String>,
    pub string_value: Option<String>,
    pub int_value: Option<String>,
    pub bool_value: Option<bool>,
    pub datetime_value: Option<String>,
}

/// Usage reports list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageReportsListResponse {
    pub kind: Option<String>,
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub usage_reports: Vec<UsageReport>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn activity_serde_roundtrip() {
        let json_val = json!({
            "kind": "admin#reports#activity",
            "id": {
                "time": "2026-03-14T00:00:00Z",
                "applicationName": "login"
            },
            "actor": {
                "email": "admin@example.com"
            },
            "events": [{
                "type": "login",
                "name": "login_success"
            }]
        });
        let activity: Activity = serde_json::from_value(json_val).unwrap();
        assert_eq!(activity.actor.unwrap().email.unwrap(), "admin@example.com");
    }

    #[test]
    fn activities_list_response_empty() {
        let json_val = json!({ "kind": "admin#reports#activities", "items": [] });
        let resp: ActivitiesListResponse = serde_json::from_value(json_val).unwrap();
        assert!(resp.items.is_empty());
    }

    #[test]
    fn usage_report_serde() {
        let json_val = json!({
            "kind": "admin#reports#usageReport",
            "date": "2026-03-13",
            "parameters": [{
                "name": "accounts:num_users",
                "intValue": "150"
            }]
        });
        let report: UsageReport = serde_json::from_value(json_val).unwrap();
        assert_eq!(report.date.unwrap(), "2026-03-13");
    }
}
