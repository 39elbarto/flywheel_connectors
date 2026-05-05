//! `Home Assistant` API types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

const DEFAULT_SUBSCRIBE_TIMEOUT_MS: u64 = 30_000;
const MAX_SUBSCRIBE_TIMEOUT_MS: u64 = 600_000;
const DEFAULT_MAX_SUBSCRIBE_EVENTS: usize = 1;
const MAX_SUBSCRIBE_EVENTS: usize = 100;
const DEFAULT_RECONNECT_ATTEMPTS: u32 = 1;
const MAX_RECONNECT_ATTEMPTS: u32 = 5;

const fn default_timeout_ms() -> u64 {
    DEFAULT_SUBSCRIBE_TIMEOUT_MS
}

const fn default_max_events() -> usize {
    DEFAULT_MAX_SUBSCRIBE_EVENTS
}

const fn default_reconnect_attempts() -> u32 {
    DEFAULT_RECONNECT_ATTEMPTS
}

fn normalize_string_list(values: &mut Vec<String>, field: &str) -> Result<(), String> {
    for value in values.iter_mut() {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(format!("{field} cannot contain empty strings"));
        }
        if trimmed != value {
            *value = trimmed.to_string();
        }
    }
    values.sort();
    values.dedup();
    Ok(())
}

/// Request body for `homeassistant.subscribe_events`.
///
/// The operation is intentionally filter-first. A caller must opt into all
/// events with `watch_all` or specify entities/domains to keep busy Home
/// Assistant installs from flooding the host by accident.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HomeAssistantEventSubscriptionRequest {
    /// Event type passed to the Home Assistant WebSocket `subscribe_events`
    /// command. The default mirrors Hermes and subscribes to state changes.
    /// Set this to null to ask Home Assistant for all event types.
    pub event_type: Option<String>,
    /// Entity domains to forward, for example `light` or `sensor`.
    pub watch_domains: Vec<String>,
    /// Fully qualified entity IDs to forward.
    pub watch_entities: Vec<String>,
    /// Fully qualified entity IDs to suppress before other filters run.
    pub ignore_entities: Vec<String>,
    /// Forward every event that is not ignored.
    pub watch_all: bool,
    /// Minimum delay between emitted events for the same entity.
    pub cooldown_ms: u64,
    /// Maximum events to collect before this invoke returns.
    pub max_events: usize,
    /// Per-connection receive timeout.
    pub timeout_ms: u64,
    /// Reconnects attempted if the WebSocket closes before enough events arrive.
    pub max_reconnect_attempts: u32,
}

impl Default for HomeAssistantEventSubscriptionRequest {
    fn default() -> Self {
        Self {
            event_type: Some("state_changed".to_string()),
            watch_domains: Vec::new(),
            watch_entities: Vec::new(),
            ignore_entities: Vec::new(),
            watch_all: false,
            cooldown_ms: 0,
            max_events: default_max_events(),
            timeout_ms: default_timeout_ms(),
            max_reconnect_attempts: default_reconnect_attempts(),
        }
    }
}

impl HomeAssistantEventSubscriptionRequest {
    /// Validate and normalize caller input.
    pub fn validate(&mut self) -> Result<(), String> {
        if let Some(event_type) = &mut self.event_type {
            let trimmed = event_type.trim();
            if trimmed.is_empty() {
                return Err("event_type cannot be empty; use null for all events".into());
            }
            if trimmed != event_type {
                *event_type = trimmed.to_string();
            }
        }

        normalize_string_list(&mut self.watch_domains, "watch_domains")?;
        normalize_string_list(&mut self.watch_entities, "watch_entities")?;
        normalize_string_list(&mut self.ignore_entities, "ignore_entities")?;

        if !self.watch_all && self.watch_domains.is_empty() && self.watch_entities.is_empty() {
            return Err(
                "subscribe_events requires watch_all=true or at least one watch_domains/watch_entities filter"
                    .into(),
            );
        }
        if self.max_events == 0 || self.max_events > MAX_SUBSCRIBE_EVENTS {
            return Err(format!(
                "max_events must be between 1 and {MAX_SUBSCRIBE_EVENTS}"
            ));
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_SUBSCRIBE_TIMEOUT_MS {
            return Err(format!(
                "timeout_ms must be between 1 and {MAX_SUBSCRIBE_TIMEOUT_MS}"
            ));
        }
        if self.max_reconnect_attempts > MAX_RECONNECT_ATTEMPTS {
            return Err(format!(
                "max_reconnect_attempts must be at most {MAX_RECONNECT_ATTEMPTS}"
            ));
        }
        Ok(())
    }
}

/// Parsed, redacted event emitted by a Home Assistant WebSocket subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeAssistantEvent {
    pub event_type: String,
    pub entity_id: Option<String>,
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_state: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_state: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_fired: Option<String>,
    #[serde(default)]
    pub data: Value,
    pub raw: Value,
}

/// Drop counters for a bounded Home Assistant event subscription invoke.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HomeAssistantSubscriptionStats {
    pub received: u64,
    pub emitted: u64,
    pub dropped_ignored: u64,
    pub dropped_filter: u64,
    pub dropped_cooldown: u64,
    pub malformed: u64,
    pub reconnects: u64,
}

/// Return value for `homeassistant.subscribe_events`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeAssistantEventSubscription {
    pub subscription_id: u64,
    pub event_type: Option<String>,
    pub event: HomeAssistantEvent,
    pub events: Vec<HomeAssistantEvent>,
    pub stats: HomeAssistantSubscriptionStats,
    pub replay_supported: bool,
    pub persistent: bool,
}

/// An entity state from `Home Assistant`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityState {
    pub entity_id: String,
    pub state: String,
    #[serde(default)]
    pub attributes: serde_json::Value,
    pub last_changed: Option<String>,
    pub last_updated: Option<String>,
    pub last_reported: Option<String>,
    pub context: Option<StateContext>,
}

/// State context for tracking state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateContext {
    pub id: Option<String>,
    pub parent_id: Option<String>,
    pub user_id: Option<String>,
}

/// A service domain from `Home Assistant`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDomain {
    pub domain: String,
    pub services: serde_json::Value,
}

/// An area (room/zone) in `Home Assistant`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Area {
    pub area_id: String,
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub picture: Option<String>,
}

/// A device in the `Home Assistant` device registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub entity_id: String,
    pub state: String,
    #[serde(default)]
    pub attributes: serde_json::Value,
    pub domain: Option<String>,
}

/// An automation entity from `Home Assistant`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Automation {
    pub entity_id: String,
    pub state: String,
    #[serde(default)]
    pub attributes: serde_json::Value,
    pub last_triggered: Option<String>,
    pub friendly_name: Option<String>,
}

/// A scene entity from `Home Assistant`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scene {
    pub entity_id: String,
    pub state: String,
    #[serde(default)]
    pub attributes: serde_json::Value,
    pub friendly_name: Option<String>,
}

/// A history entry for an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub entity_id: String,
    pub state: String,
    #[serde(default)]
    pub attributes: serde_json::Value,
    pub last_changed: Option<String>,
    pub last_updated: Option<String>,
}

/// Statistics record from `Home Assistant` long-term statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatisticsRecord {
    pub statistic_id: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub mean: Option<f64>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub sum: Option<f64>,
    pub state: Option<f64>,
}

/// Service call request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCallRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<serde_json::Value>,
}

/// Set state request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetStateRequest {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<serde_json::Value>,
}

/// `Home Assistant` API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entity_state_roundtrip() {
        let s: EntityState = serde_json::from_value(json!({
            "entity_id": "light.living_room",
            "state": "on",
            "attributes": {"brightness": 255, "friendly_name": "Living Room Light"},
            "last_changed": "2026-03-01T10:00:00Z",
            "last_updated": "2026-03-01T10:00:00Z",
            "context": {"id": "ctx1", "parent_id": null, "user_id": "u1"}
        }))
        .unwrap();
        assert_eq!(s.entity_id, "light.living_room");
        assert_eq!(s.state, "on");
        assert_eq!(s.attributes["brightness"], 255);
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["state"], "on");
    }

    #[test]
    fn entity_state_minimal() {
        let s: EntityState = serde_json::from_value(json!({
            "entity_id": "sensor.temp",
            "state": "22.5"
        }))
        .unwrap();
        assert_eq!(s.entity_id, "sensor.temp");
        assert_eq!(s.state, "22.5");
        assert!(s.last_changed.is_none());
        assert!(s.context.is_none());
    }

    #[test]
    fn state_context_roundtrip() {
        let c: StateContext = serde_json::from_value(json!({
            "id": "ctx1",
            "parent_id": "parent1",
            "user_id": "user1"
        }))
        .unwrap();
        assert_eq!(c.id, Some("ctx1".into()));
        assert_eq!(c.parent_id, Some("parent1".into()));
    }

    #[test]
    fn state_context_empty() {
        let c: StateContext = serde_json::from_value(json!({})).unwrap();
        assert!(c.id.is_none());
        assert!(c.parent_id.is_none());
        assert!(c.user_id.is_none());
    }

    #[test]
    fn service_domain_roundtrip() {
        let sd: ServiceDomain = serde_json::from_value(json!({
            "domain": "light",
            "services": {"turn_on": {"description": "Turn on light"}}
        }))
        .unwrap();
        assert_eq!(sd.domain, "light");
        assert!(sd.services["turn_on"].is_object());
    }

    #[test]
    fn area_roundtrip() {
        let a: Area = serde_json::from_value(json!({
            "area_id": "living_room",
            "name": "Living Room",
            "aliases": ["lounge"],
            "picture": "/local/living_room.jpg"
        }))
        .unwrap();
        assert_eq!(a.area_id, "living_room");
        assert_eq!(a.name, "Living Room");
        assert_eq!(a.aliases, vec!["lounge"]);
    }

    #[test]
    fn area_minimal() {
        let a: Area = serde_json::from_value(json!({
            "area_id": "kitchen",
            "name": "Kitchen"
        }))
        .unwrap();
        assert_eq!(a.area_id, "kitchen");
        assert!(a.aliases.is_empty());
        assert!(a.picture.is_none());
    }

    #[test]
    fn device_roundtrip() {
        let d: Device = serde_json::from_value(json!({
            "entity_id": "light.desk_lamp",
            "state": "on",
            "attributes": {"brightness": 128},
            "domain": "light"
        }))
        .unwrap();
        assert_eq!(d.entity_id, "light.desk_lamp");
        assert_eq!(d.state, "on");
        assert_eq!(d.domain, Some("light".into()));
    }

    #[test]
    fn automation_roundtrip() {
        let a: Automation = serde_json::from_value(json!({
            "entity_id": "automation.night_mode",
            "state": "on",
            "attributes": {"last_triggered": "2026-03-01T22:00:00Z"},
            "last_triggered": "2026-03-01T22:00:00Z",
            "friendly_name": "Night Mode"
        }))
        .unwrap();
        assert_eq!(a.entity_id, "automation.night_mode");
        assert_eq!(a.state, "on");
        assert_eq!(a.friendly_name, Some("Night Mode".into()));
    }

    #[test]
    fn automation_minimal() {
        let a: Automation = serde_json::from_value(json!({
            "entity_id": "automation.test",
            "state": "off"
        }))
        .unwrap();
        assert_eq!(a.entity_id, "automation.test");
        assert!(a.friendly_name.is_none());
    }

    #[test]
    fn scene_roundtrip() {
        let s: Scene = serde_json::from_value(json!({
            "entity_id": "scene.movie_night",
            "state": "scening",
            "attributes": {"entity_id": ["light.tv", "light.ceiling"]},
            "friendly_name": "Movie Night"
        }))
        .unwrap();
        assert_eq!(s.entity_id, "scene.movie_night");
        assert_eq!(s.friendly_name, Some("Movie Night".into()));
    }

    #[test]
    fn scene_minimal() {
        let s: Scene = serde_json::from_value(json!({
            "entity_id": "scene.test",
            "state": "scening"
        }))
        .unwrap();
        assert_eq!(s.entity_id, "scene.test");
        assert!(s.friendly_name.is_none());
    }

    #[test]
    fn history_entry_roundtrip() {
        let h: HistoryEntry = serde_json::from_value(json!({
            "entity_id": "sensor.temp",
            "state": "22.5",
            "attributes": {"unit_of_measurement": "C"},
            "last_changed": "2026-03-01T10:00:00Z",
            "last_updated": "2026-03-01T10:00:00Z"
        }))
        .unwrap();
        assert_eq!(h.entity_id, "sensor.temp");
        assert_eq!(h.state, "22.5");
        assert_eq!(h.attributes["unit_of_measurement"], "C");
    }

    #[test]
    fn history_entry_minimal() {
        let h: HistoryEntry = serde_json::from_value(json!({
            "entity_id": "light.test",
            "state": "off"
        }))
        .unwrap();
        assert_eq!(h.state, "off");
        assert!(h.last_changed.is_none());
    }

    #[test]
    fn statistics_record_roundtrip() {
        let s: StatisticsRecord = serde_json::from_value(json!({
            "statistic_id": "sensor:energy",
            "start": "2026-03-01T00:00:00Z",
            "end": "2026-03-01T01:00:00Z",
            "mean": 1.5,
            "min": 0.5,
            "max": 2.5,
            "sum": 36.0,
            "state": 1.5
        }))
        .unwrap();
        assert_eq!(s.statistic_id, Some("sensor:energy".into()));
        assert_eq!(s.mean, Some(1.5));
        assert_eq!(s.min, Some(0.5));
        assert_eq!(s.max, Some(2.5));
    }

    #[test]
    fn statistics_record_minimal() {
        let s: StatisticsRecord = serde_json::from_value(json!({})).unwrap();
        assert!(s.statistic_id.is_none());
        assert!(s.mean.is_none());
    }

    #[test]
    fn service_call_request_roundtrip() {
        let r: ServiceCallRequest = serde_json::from_value(json!({
            "entity_id": "light.living_room",
            "service_data": {"brightness_pct": 75},
            "target": {"entity_id": "light.living_room"}
        }))
        .unwrap();
        assert_eq!(r.entity_id, Some("light.living_room".into()));
        assert!(r.service_data.is_some());
        assert!(r.target.is_some());
    }

    #[test]
    fn service_call_request_minimal() {
        let r: ServiceCallRequest = serde_json::from_value(json!({})).unwrap();
        assert!(r.entity_id.is_none());
        assert!(r.service_data.is_none());
        assert!(r.target.is_none());
    }

    #[test]
    fn service_call_request_skip_none_fields() {
        let r = ServiceCallRequest {
            entity_id: None,
            service_data: None,
            target: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v, json!({}));
    }

    #[test]
    fn set_state_request_roundtrip() {
        let r: SetStateRequest = serde_json::from_value(json!({
            "state": "on",
            "attributes": {"brightness": 255}
        }))
        .unwrap();
        assert_eq!(r.state, "on");
        assert!(r.attributes.is_some());
    }

    #[test]
    fn set_state_request_minimal() {
        let r: SetStateRequest = serde_json::from_value(json!({"state": "off"})).unwrap();
        assert_eq!(r.state, "off");
        assert!(r.attributes.is_none());
    }

    #[test]
    fn set_state_request_skip_none_attributes() {
        let r = SetStateRequest {
            state: "on".into(),
            attributes: None,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("attributes").is_none());
    }

    #[test]
    fn api_error_response_with_message() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Entity not found"
        }))
        .unwrap();
        assert_eq!(e.message, Some("Entity not found".into()));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
    }

    #[test]
    fn entity_state_with_last_reported() {
        let s: EntityState = serde_json::from_value(json!({
            "entity_id": "sensor.temp",
            "state": "22",
            "last_reported": "2026-03-01T10:30:00Z"
        }))
        .unwrap();
        assert_eq!(s.last_reported, Some("2026-03-01T10:30:00Z".into()));
    }

    #[test]
    fn device_minimal() {
        let d: Device = serde_json::from_value(json!({
            "entity_id": "sensor.test",
            "state": "unknown"
        }))
        .unwrap();
        assert!(d.domain.is_none());
    }

    // -- Clone trait tests --

    #[test]
    fn entity_state_clone() {
        let s = EntityState {
            entity_id: "light.test".into(),
            state: "on".into(),
            attributes: json!({"brightness": 255}),
            last_changed: None,
            last_updated: None,
            last_reported: None,
            context: None,
        };
        let cloned = s.clone();
        drop(s);
        assert_eq!(cloned.entity_id, "light.test");
        assert_eq!(cloned.state, "on");
    }

    #[test]
    fn state_context_clone() {
        let c = StateContext {
            id: Some("ctx1".into()),
            parent_id: None,
            user_id: Some("u1".into()),
        };
        let cloned = c.clone();
        drop(c);
        assert_eq!(cloned.id, Some("ctx1".into()));
    }

    #[test]
    fn area_clone() {
        let a = Area {
            area_id: "kitchen".into(),
            name: "Kitchen".into(),
            aliases: vec!["cooking".into()],
            picture: None,
        };
        let cloned = a.clone();
        drop(a);
        assert_eq!(cloned.area_id, "kitchen");
        assert_eq!(cloned.aliases.len(), 1);
    }

    #[test]
    fn device_clone() {
        let d = Device {
            entity_id: "light.desk".into(),
            state: "on".into(),
            attributes: json!({}),
            domain: Some("light".into()),
        };
        let cloned = d.clone();
        drop(d);
        assert_eq!(cloned.domain, Some("light".into()));
    }

    #[test]
    fn automation_clone() {
        let a = Automation {
            entity_id: "automation.test".into(),
            state: "on".into(),
            attributes: json!({}),
            last_triggered: None,
            friendly_name: Some("Test".into()),
        };
        let cloned = a.clone();
        drop(a);
        assert_eq!(cloned.friendly_name, Some("Test".into()));
    }

    #[test]
    fn scene_clone() {
        let s = Scene {
            entity_id: "scene.test".into(),
            state: "scening".into(),
            attributes: json!({}),
            friendly_name: Some("Movie".into()),
        };
        let cloned = s.clone();
        drop(s);
        assert_eq!(cloned.friendly_name, Some("Movie".into()));
    }

    #[test]
    fn history_entry_clone() {
        let h = HistoryEntry {
            entity_id: "sensor.temp".into(),
            state: "22.5".into(),
            attributes: json!({}),
            last_changed: None,
            last_updated: None,
        };
        let cloned = h.clone();
        drop(h);
        assert_eq!(cloned.state, "22.5");
    }

    #[test]
    fn statistics_record_clone() {
        let s = StatisticsRecord {
            statistic_id: Some("sensor:energy".into()),
            start: None,
            end: None,
            mean: Some(1.5),
            min: None,
            max: None,
            sum: None,
            state: None,
        };
        let cloned = s.clone();
        drop(s);
        assert_eq!(cloned.mean, Some(1.5));
    }

    // -- Debug trait tests --

    #[test]
    fn entity_state_debug() {
        let s: EntityState = serde_json::from_value(json!({
            "entity_id": "light.dbg",
            "state": "on"
        }))
        .unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("EntityState"));
        assert!(dbg.contains("light.dbg"));
    }

    #[test]
    fn area_debug() {
        let a: Area = serde_json::from_value(json!({
            "area_id": "living",
            "name": "Living Room"
        }))
        .unwrap();
        let dbg = format!("{a:?}");
        assert!(dbg.contains("Area"));
    }

    #[test]
    fn service_domain_debug() {
        let sd: ServiceDomain = serde_json::from_value(json!({
            "domain": "light",
            "services": {}
        }))
        .unwrap();
        let dbg = format!("{sd:?}");
        assert!(dbg.contains("ServiceDomain"));
    }

    #[test]
    fn api_error_response_debug() {
        let e = ApiErrorResponse {
            message: Some("test".into()),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    // -- Serialization edge cases --

    #[test]
    fn entity_state_empty_attributes_default() {
        let s: EntityState = serde_json::from_value(json!({
            "entity_id": "sensor.x",
            "state": "0"
        }))
        .unwrap();
        // attributes should default to null/empty via #[serde(default)]
        assert!(s.attributes.is_null() || s.attributes.is_object());
    }

    #[test]
    fn area_empty_aliases_default() {
        let a: Area = serde_json::from_value(json!({
            "area_id": "office",
            "name": "Office"
        }))
        .unwrap();
        assert!(a.aliases.is_empty());
    }

    #[test]
    fn service_call_request_clone() {
        let r = ServiceCallRequest {
            entity_id: Some("light.test".into()),
            service_data: Some(json!({"brightness_pct": 50})),
            target: None,
        };
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.entity_id, Some("light.test".into()));
    }

    #[test]
    fn set_state_request_clone() {
        let r = SetStateRequest {
            state: "on".into(),
            attributes: Some(json!({"brightness": 128})),
        };
        let cloned = r.clone();
        drop(r);
        assert_eq!(cloned.state, "on");
    }

    #[test]
    fn api_error_response_clone() {
        let e = ApiErrorResponse {
            message: Some("test".into()),
        };
        let cloned = e.clone();
        drop(e);
        assert_eq!(cloned.message, Some("test".into()));
    }

    #[test]
    fn statistics_record_all_fields() {
        let s: StatisticsRecord = serde_json::from_value(json!({
            "statistic_id": "sensor:energy",
            "start": "2026-03-01T00:00:00Z",
            "end": "2026-03-01T01:00:00Z",
            "mean": 1.5,
            "min": 0.5,
            "max": 2.5,
            "sum": 36.0,
            "state": 1.5
        }))
        .unwrap();
        assert_eq!(s.sum, Some(36.0));
        assert_eq!(s.state, Some(1.5));
    }

    #[test]
    fn service_domain_clone() {
        let sd = ServiceDomain {
            domain: "light".into(),
            services: json!({"turn_on": {}}),
        };
        let cloned = sd.clone();
        drop(sd);
        assert_eq!(cloned.domain, "light");
    }
}
