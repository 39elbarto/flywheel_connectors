//! Home Assistant integration aggregation layer.
//!
//! Provides a unified, typed abstraction over Home Assistant's entity/service
//! model, covering 2000+ device types through domain-based capability mapping,
//! normalized device control operations, and strict safety policies for
//! security-adjacent domains (locks, alarms, cameras).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// CapabilityFamily
// ---------------------------------------------------------------------------

/// Capability family for a Home Assistant entity domain.
///
/// Determines the level of access and control permitted for entities in a
/// given domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityFamily {
    /// Read-only sensors and informational entities.
    ReadOnly,
    /// Controllable actuators (lights, switches, fans, covers, etc.).
    Controllable,
    /// Security-adjacent domains requiring approval (locks, alarms, cameras).
    SecurityAdjacent,
    /// Automation and scripting entities.
    Automation,
}

impl std::fmt::Display for CapabilityFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReadOnly => write!(f, "read_only"),
            Self::Controllable => write!(f, "controllable"),
            Self::SecurityAdjacent => write!(f, "security_adjacent"),
            Self::Automation => write!(f, "automation"),
        }
    }
}

// ---------------------------------------------------------------------------
// EntityDomain
// ---------------------------------------------------------------------------

/// Known Home Assistant entity domains.
///
/// Covers the most common integration domains. Unknown domains are captured
/// in the `Other` variant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityDomain {
    Light,
    Switch,
    Sensor,
    BinarySensor,
    Climate,
    Cover,
    Lock,
    Alarm,
    Camera,
    MediaPlayer,
    Fan,
    Vacuum,
    Automation,
    Script,
    Scene,
    InputBoolean,
    InputNumber,
    InputSelect,
    InputText,
    Weather,
    Person,
    Zone,
    Other(String),
}

impl EntityDomain {
    /// Parse a domain string into an `EntityDomain`.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "light" => Self::Light,
            "switch" => Self::Switch,
            "sensor" => Self::Sensor,
            "binary_sensor" => Self::BinarySensor,
            "climate" => Self::Climate,
            "cover" => Self::Cover,
            "lock" => Self::Lock,
            "alarm_control_panel" => Self::Alarm,
            "camera" => Self::Camera,
            "media_player" => Self::MediaPlayer,
            "fan" => Self::Fan,
            "vacuum" => Self::Vacuum,
            "automation" => Self::Automation,
            "script" => Self::Script,
            "scene" => Self::Scene,
            "input_boolean" => Self::InputBoolean,
            "input_number" => Self::InputNumber,
            "input_select" => Self::InputSelect,
            "input_text" => Self::InputText,
            "weather" => Self::Weather,
            "person" => Self::Person,
            "zone" => Self::Zone,
            other => Self::Other(other.to_string()),
        }
    }

    /// Return the string representation of this domain.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Light => "light",
            Self::Switch => "switch",
            Self::Sensor => "sensor",
            Self::BinarySensor => "binary_sensor",
            Self::Climate => "climate",
            Self::Cover => "cover",
            Self::Lock => "lock",
            Self::Alarm => "alarm_control_panel",
            Self::Camera => "camera",
            Self::MediaPlayer => "media_player",
            Self::Fan => "fan",
            Self::Vacuum => "vacuum",
            Self::Automation => "automation",
            Self::Script => "script",
            Self::Scene => "scene",
            Self::InputBoolean => "input_boolean",
            Self::InputNumber => "input_number",
            Self::InputSelect => "input_select",
            Self::InputText => "input_text",
            Self::Weather => "weather",
            Self::Person => "person",
            Self::Zone => "zone",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Map this domain to a capability family.
    #[must_use]
    pub const fn capability_family(&self) -> CapabilityFamily {
        match self {
            Self::Sensor | Self::BinarySensor | Self::Weather | Self::Person | Self::Zone => {
                CapabilityFamily::ReadOnly
            }

            Self::Light
            | Self::Switch
            | Self::Climate
            | Self::Cover
            | Self::MediaPlayer
            | Self::Fan
            | Self::Vacuum
            | Self::InputBoolean
            | Self::InputNumber
            | Self::InputSelect
            | Self::InputText => CapabilityFamily::Controllable,

            Self::Lock | Self::Alarm | Self::Camera => CapabilityFamily::SecurityAdjacent,

            Self::Automation | Self::Script | Self::Scene => CapabilityFamily::Automation,

            Self::Other(_) => CapabilityFamily::ReadOnly,
        }
    }
}

impl Serialize for EntityDomain {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EntityDomain {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::parse(&s))
    }
}

impl std::fmt::Display for EntityDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Entity
// ---------------------------------------------------------------------------

/// A discovered Home Assistant entity with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    /// Fully qualified entity ID (e.g. `light.living_room`).
    pub entity_id: String,
    /// Domain extracted from the entity ID.
    pub domain: EntityDomain,
    /// Friendly name of the entity.
    pub name: String,
    /// Area / room this entity belongs to.
    pub area: Option<String>,
    /// Device ID in the device registry.
    pub device_id: Option<String>,
    /// Current state string (e.g. "on", "off", "22.5").
    pub state: String,
    /// Arbitrary attributes bag.
    #[serde(default)]
    pub attributes: Value,
    /// ISO-8601 timestamp of last update.
    pub last_updated: Option<String>,
}

impl Entity {
    /// Whether the entity is considered available (not "unavailable" or "unknown").
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.state != "unavailable" && self.state != "unknown"
    }

    /// Whether this entity belongs to a security-adjacent domain.
    #[must_use]
    pub fn is_security_adjacent(&self) -> bool {
        self.domain.capability_family() == CapabilityFamily::SecurityAdjacent
    }
}

// ---------------------------------------------------------------------------
// EntityRegistry
// ---------------------------------------------------------------------------

/// Registry of all discovered entities, indexed by ID, domain, and area.
#[derive(Debug, Clone, Default)]
pub struct EntityRegistry {
    entities: HashMap<String, Entity>,
    by_domain: HashMap<String, Vec<String>>,
    by_area: HashMap<String, Vec<String>>,
}

impl EntityRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an entity. Replaces any existing entity with the same ID.
    pub fn register(&mut self, entity: Entity) {
        let id = entity.entity_id.clone();
        let domain_key = entity.domain.as_str().to_string();

        // Remove old entry if present (clean up indices).
        self.remove(&id);

        // Index by domain.
        self.by_domain
            .entry(domain_key)
            .or_default()
            .push(id.clone());

        // Index by area.
        if let Some(ref area) = entity.area {
            self.by_area
                .entry(area.clone())
                .or_default()
                .push(id.clone());
        }

        self.entities.insert(id, entity);
    }

    /// Remove an entity by ID. Returns the entity if it existed.
    pub fn remove(&mut self, entity_id: &str) -> Option<Entity> {
        if let Some(entity) = self.entities.remove(entity_id) {
            // Clean domain index.
            let domain_key = entity.domain.as_str().to_string();
            if let Some(ids) = self.by_domain.get_mut(&domain_key) {
                ids.retain(|id| id != entity_id);
                if ids.is_empty() {
                    self.by_domain.remove(&domain_key);
                }
            }

            // Clean area index.
            if let Some(ref area) = entity.area {
                if let Some(ids) = self.by_area.get_mut(area) {
                    ids.retain(|id| id != entity_id);
                    if ids.is_empty() {
                        self.by_area.remove(area);
                    }
                }
            }

            Some(entity)
        } else {
            None
        }
    }

    /// Look up an entity by ID.
    #[must_use]
    pub fn get(&self, entity_id: &str) -> Option<&Entity> {
        self.entities.get(entity_id)
    }

    /// List entity IDs belonging to a domain.
    #[must_use]
    pub fn list_by_domain(&self, domain: &EntityDomain) -> Vec<&str> {
        self.by_domain
            .get(domain.as_str())
            .map(|ids| ids.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// List entity IDs belonging to an area.
    #[must_use]
    pub fn list_by_area(&self, area: &str) -> Vec<&str> {
        self.by_area
            .get(area)
            .map(|ids| ids.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Total entity count.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entities.len()
    }

    /// Set of unique domain strings currently in the registry.
    #[must_use]
    pub fn domains(&self) -> Vec<String> {
        let mut domains: Vec<String> = self.by_domain.keys().cloned().collect();
        domains.sort();
        domains
    }
}

// ---------------------------------------------------------------------------
// ServiceCall
// ---------------------------------------------------------------------------

/// A normalized Home Assistant service call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCall {
    /// Domain of the service (e.g. "light").
    pub domain: String,
    /// Service name (e.g. `turn_on`).
    pub service: String,
    /// Target entity ID.
    pub entity_id: Option<String>,
    /// Additional service data.
    #[serde(default)]
    pub data: Value,
}

impl ServiceCall {
    /// Create a new service call.
    #[must_use]
    pub fn new(domain: impl Into<String>, service: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            service: service.into(),
            entity_id: None,
            data: Value::Null,
        }
    }

    /// Set the target entity.
    #[must_use]
    pub fn with_entity(mut self, entity_id: impl Into<String>) -> Self {
        self.entity_id = Some(entity_id.into());
        self
    }

    /// Set additional service data.
    #[must_use]
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }
}

// ---------------------------------------------------------------------------
// DeviceControl
// ---------------------------------------------------------------------------

/// Normalized device-control operations covering most Home Assistant integrations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceControl {
    TurnOn,
    TurnOff,
    Toggle,
    SetBrightness(u8),
    SetTemperature(f64),
    SetPosition(u8),
    Lock,
    Unlock,
    ArmHome,
    ArmAway,
    Disarm,
    Custom { service: String, data: Value },
}

impl DeviceControl {
    /// Convert this control to a `ServiceCall` for a given entity domain.
    #[must_use]
    pub fn to_service_call(&self, domain: &str) -> ServiceCall {
        match self {
            Self::TurnOn => ServiceCall::new(domain, "turn_on"),
            Self::TurnOff => ServiceCall::new(domain, "turn_off"),
            Self::Toggle => ServiceCall::new(domain, "toggle"),
            Self::SetBrightness(b) => {
                ServiceCall::new(domain, "turn_on").with_data(serde_json::json!({"brightness": b}))
            }
            Self::SetTemperature(t) => ServiceCall::new(domain, "set_temperature")
                .with_data(serde_json::json!({"temperature": t})),
            Self::SetPosition(p) => ServiceCall::new(domain, "set_cover_position")
                .with_data(serde_json::json!({"position": p})),
            Self::Lock => ServiceCall::new(domain, "lock"),
            Self::Unlock => ServiceCall::new(domain, "unlock"),
            Self::ArmHome => ServiceCall::new(domain, "alarm_arm_home"),
            Self::ArmAway => ServiceCall::new(domain, "alarm_arm_away"),
            Self::Disarm => ServiceCall::new(domain, "alarm_disarm"),
            Self::Custom { service, data } => {
                ServiceCall::new(domain, service.as_str()).with_data(data.clone())
            }
        }
    }

    /// Whether this control requires policy approval (security-adjacent ops).
    #[must_use]
    pub const fn requires_approval(&self) -> bool {
        matches!(
            self,
            Self::Lock | Self::Unlock | Self::ArmHome | Self::ArmAway | Self::Disarm
        )
    }
}

// ---------------------------------------------------------------------------
// ControlPolicy / ControlDecision
// ---------------------------------------------------------------------------

/// Policy decision for a device control operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlDecision {
    /// Operation is allowed.
    Allow,
    /// Operation is denied.
    Deny { reason: String },
    /// Operation requires explicit approval.
    RequireApproval { reason: String },
}

/// Policy governing which device controls are permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct ControlPolicy {
    /// Allow reading entity states.
    pub allow_read: bool,
    /// Allow controlling non-security entities.
    pub allow_control: bool,
    /// Allow controlling security-adjacent entities.
    pub allow_security: bool,
    /// Require explicit approval for security-adjacent controls.
    pub require_approval_for_security: bool,
    /// Domains that are entirely blocked.
    pub blocked_domains: HashSet<String>,
    /// Individual entity IDs that are blocked.
    pub blocked_entities: HashSet<String>,
}

impl ControlPolicy {
    /// Create a permissive policy (allow everything).
    #[must_use]
    pub fn new_permissive() -> Self {
        Self {
            allow_read: true,
            allow_control: true,
            allow_security: true,
            require_approval_for_security: false,
            blocked_domains: HashSet::new(),
            blocked_entities: HashSet::new(),
        }
    }

    /// Create a read-only policy (deny all control).
    #[must_use]
    pub fn new_readonly() -> Self {
        Self {
            allow_read: true,
            allow_control: false,
            allow_security: false,
            require_approval_for_security: false,
            blocked_domains: HashSet::new(),
            blocked_entities: HashSet::new(),
        }
    }

    /// Create a safe policy (allow control, require approval for security).
    #[must_use]
    pub fn new_safe() -> Self {
        Self {
            allow_read: true,
            allow_control: true,
            allow_security: true,
            require_approval_for_security: true,
            blocked_domains: HashSet::new(),
            blocked_entities: HashSet::new(),
        }
    }

    /// Check whether a device control is allowed for a given entity.
    #[must_use]
    pub fn check_control(&self, entity: &Entity, control: &DeviceControl) -> ControlDecision {
        // Check entity-level block.
        if self.blocked_entities.contains(&entity.entity_id) {
            return ControlDecision::Deny {
                reason: format!("entity '{}' is blocked by policy", entity.entity_id),
            };
        }

        // Check domain-level block.
        let domain_str = entity.domain.as_str().to_string();
        if self.blocked_domains.contains(&domain_str) {
            return ControlDecision::Deny {
                reason: format!("domain '{}' is blocked by policy", entity.domain),
            };
        }

        let family = entity.domain.capability_family();

        // Security-adjacent check.
        if family == CapabilityFamily::SecurityAdjacent || control.requires_approval() {
            if !self.allow_security {
                return ControlDecision::Deny {
                    reason: "security-adjacent controls are not allowed".to_string(),
                };
            }
            if self.require_approval_for_security {
                return ControlDecision::RequireApproval {
                    reason: format!(
                        "security-adjacent control on '{}' requires approval",
                        entity.entity_id,
                    ),
                };
            }
        }

        // General control check.
        if family == CapabilityFamily::ReadOnly {
            return ControlDecision::Deny {
                reason: format!(
                    "domain '{}' is read-only and cannot be controlled",
                    entity.domain,
                ),
            };
        }

        if !self.allow_control
            && (family == CapabilityFamily::Controllable || family == CapabilityFamily::Automation)
        {
            return ControlDecision::Deny {
                reason: "controls are not allowed by policy".to_string(),
            };
        }

        ControlDecision::Allow
    }
}

// ---------------------------------------------------------------------------
// IntegrationAuditEvent
// ---------------------------------------------------------------------------

/// Audit log entry for integration operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationAuditEvent {
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// Human-readable action description.
    pub action: String,
    /// Target entity ID.
    pub entity_id: String,
    /// The service call that was (or would have been) issued.
    pub service_call: Option<ServiceCall>,
    /// Policy decision.
    pub decision: ControlDecision,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ===== EntityDomain from_str / as_str round-trips =====

    #[test]
    fn domain_light_roundtrip() {
        let d = EntityDomain::parse("light");
        assert_eq!(d.as_str(), "light");
        assert_eq!(d, EntityDomain::Light);
    }

    #[test]
    fn domain_switch_roundtrip() {
        let d = EntityDomain::parse("switch");
        assert_eq!(d.as_str(), "switch");
    }

    #[test]
    fn domain_sensor_roundtrip() {
        let d = EntityDomain::parse("sensor");
        assert_eq!(d.as_str(), "sensor");
    }

    #[test]
    fn domain_binary_sensor_roundtrip() {
        let d = EntityDomain::parse("binary_sensor");
        assert_eq!(d.as_str(), "binary_sensor");
    }

    #[test]
    fn domain_climate_roundtrip() {
        let d = EntityDomain::parse("climate");
        assert_eq!(d.as_str(), "climate");
    }

    #[test]
    fn domain_cover_roundtrip() {
        let d = EntityDomain::parse("cover");
        assert_eq!(d.as_str(), "cover");
    }

    #[test]
    fn domain_lock_roundtrip() {
        let d = EntityDomain::parse("lock");
        assert_eq!(d.as_str(), "lock");
    }

    #[test]
    fn domain_alarm_roundtrip() {
        let d = EntityDomain::parse("alarm_control_panel");
        assert_eq!(d.as_str(), "alarm_control_panel");
        assert_eq!(d, EntityDomain::Alarm);
    }

    #[test]
    fn domain_camera_roundtrip() {
        let d = EntityDomain::parse("camera");
        assert_eq!(d.as_str(), "camera");
    }

    #[test]
    fn domain_media_player_roundtrip() {
        let d = EntityDomain::parse("media_player");
        assert_eq!(d.as_str(), "media_player");
    }

    #[test]
    fn domain_fan_roundtrip() {
        let d = EntityDomain::parse("fan");
        assert_eq!(d.as_str(), "fan");
    }

    #[test]
    fn domain_vacuum_roundtrip() {
        let d = EntityDomain::parse("vacuum");
        assert_eq!(d.as_str(), "vacuum");
    }

    #[test]
    fn domain_automation_roundtrip() {
        let d = EntityDomain::parse("automation");
        assert_eq!(d.as_str(), "automation");
    }

    #[test]
    fn domain_script_roundtrip() {
        let d = EntityDomain::parse("script");
        assert_eq!(d.as_str(), "script");
    }

    #[test]
    fn domain_scene_roundtrip() {
        let d = EntityDomain::parse("scene");
        assert_eq!(d.as_str(), "scene");
    }

    #[test]
    fn domain_input_boolean_roundtrip() {
        let d = EntityDomain::parse("input_boolean");
        assert_eq!(d.as_str(), "input_boolean");
    }

    #[test]
    fn domain_input_number_roundtrip() {
        let d = EntityDomain::parse("input_number");
        assert_eq!(d.as_str(), "input_number");
    }

    #[test]
    fn domain_input_select_roundtrip() {
        let d = EntityDomain::parse("input_select");
        assert_eq!(d.as_str(), "input_select");
    }

    #[test]
    fn domain_input_text_roundtrip() {
        let d = EntityDomain::parse("input_text");
        assert_eq!(d.as_str(), "input_text");
    }

    #[test]
    fn domain_weather_roundtrip() {
        let d = EntityDomain::parse("weather");
        assert_eq!(d.as_str(), "weather");
    }

    #[test]
    fn domain_person_roundtrip() {
        let d = EntityDomain::parse("person");
        assert_eq!(d.as_str(), "person");
    }

    #[test]
    fn domain_zone_roundtrip() {
        let d = EntityDomain::parse("zone");
        assert_eq!(d.as_str(), "zone");
    }

    #[test]
    fn domain_other_roundtrip() {
        let d = EntityDomain::parse("custom_domain");
        assert_eq!(d.as_str(), "custom_domain");
        assert!(matches!(d, EntityDomain::Other(ref s) if s == "custom_domain"));
    }

    // ===== Capability family mapping =====

    #[test]
    fn capability_sensor_readonly() {
        assert_eq!(
            EntityDomain::Sensor.capability_family(),
            CapabilityFamily::ReadOnly
        );
    }

    #[test]
    fn capability_binary_sensor_readonly() {
        assert_eq!(
            EntityDomain::BinarySensor.capability_family(),
            CapabilityFamily::ReadOnly
        );
    }

    #[test]
    fn capability_weather_readonly() {
        assert_eq!(
            EntityDomain::Weather.capability_family(),
            CapabilityFamily::ReadOnly
        );
    }

    #[test]
    fn capability_person_readonly() {
        assert_eq!(
            EntityDomain::Person.capability_family(),
            CapabilityFamily::ReadOnly
        );
    }

    #[test]
    fn capability_zone_readonly() {
        assert_eq!(
            EntityDomain::Zone.capability_family(),
            CapabilityFamily::ReadOnly
        );
    }

    #[test]
    fn capability_light_controllable() {
        assert_eq!(
            EntityDomain::Light.capability_family(),
            CapabilityFamily::Controllable
        );
    }

    #[test]
    fn capability_switch_controllable() {
        assert_eq!(
            EntityDomain::Switch.capability_family(),
            CapabilityFamily::Controllable
        );
    }

    #[test]
    fn capability_climate_controllable() {
        assert_eq!(
            EntityDomain::Climate.capability_family(),
            CapabilityFamily::Controllable
        );
    }

    #[test]
    fn capability_cover_controllable() {
        assert_eq!(
            EntityDomain::Cover.capability_family(),
            CapabilityFamily::Controllable
        );
    }

    #[test]
    fn capability_media_player_controllable() {
        assert_eq!(
            EntityDomain::MediaPlayer.capability_family(),
            CapabilityFamily::Controllable,
        );
    }

    #[test]
    fn capability_fan_controllable() {
        assert_eq!(
            EntityDomain::Fan.capability_family(),
            CapabilityFamily::Controllable
        );
    }

    #[test]
    fn capability_vacuum_controllable() {
        assert_eq!(
            EntityDomain::Vacuum.capability_family(),
            CapabilityFamily::Controllable
        );
    }

    #[test]
    fn capability_input_boolean_controllable() {
        assert_eq!(
            EntityDomain::InputBoolean.capability_family(),
            CapabilityFamily::Controllable,
        );
    }

    #[test]
    fn capability_input_number_controllable() {
        assert_eq!(
            EntityDomain::InputNumber.capability_family(),
            CapabilityFamily::Controllable,
        );
    }

    #[test]
    fn capability_input_select_controllable() {
        assert_eq!(
            EntityDomain::InputSelect.capability_family(),
            CapabilityFamily::Controllable,
        );
    }

    #[test]
    fn capability_input_text_controllable() {
        assert_eq!(
            EntityDomain::InputText.capability_family(),
            CapabilityFamily::Controllable,
        );
    }

    #[test]
    fn capability_lock_security() {
        assert_eq!(
            EntityDomain::Lock.capability_family(),
            CapabilityFamily::SecurityAdjacent,
        );
    }

    #[test]
    fn capability_alarm_security() {
        assert_eq!(
            EntityDomain::Alarm.capability_family(),
            CapabilityFamily::SecurityAdjacent,
        );
    }

    #[test]
    fn capability_camera_security() {
        assert_eq!(
            EntityDomain::Camera.capability_family(),
            CapabilityFamily::SecurityAdjacent,
        );
    }

    #[test]
    fn capability_automation_family() {
        assert_eq!(
            EntityDomain::Automation.capability_family(),
            CapabilityFamily::Automation
        );
    }

    #[test]
    fn capability_script_family() {
        assert_eq!(
            EntityDomain::Script.capability_family(),
            CapabilityFamily::Automation
        );
    }

    #[test]
    fn capability_scene_family() {
        assert_eq!(
            EntityDomain::Scene.capability_family(),
            CapabilityFamily::Automation
        );
    }

    #[test]
    fn capability_other_defaults_readonly() {
        assert_eq!(
            EntityDomain::Other("custom".into()).capability_family(),
            CapabilityFamily::ReadOnly,
        );
    }

    // ===== EntityDomain serde =====

    #[test]
    fn domain_serde_known() {
        let d = EntityDomain::Light;
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, "\"light\"");
        let parsed: EntityDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EntityDomain::Light);
    }

    #[test]
    fn domain_serde_other() {
        let d = EntityDomain::Other("plant".into());
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, "\"plant\"");
        let parsed: EntityDomain = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, EntityDomain::Other("plant".into()));
    }

    #[test]
    fn domain_display() {
        assert_eq!(EntityDomain::Light.to_string(), "light");
        assert_eq!(EntityDomain::Alarm.to_string(), "alarm_control_panel");
        assert_eq!(EntityDomain::Other("zwave".into()).to_string(), "zwave");
    }

    // ===== CapabilityFamily display =====

    #[test]
    fn capability_family_display() {
        assert_eq!(CapabilityFamily::ReadOnly.to_string(), "read_only");
        assert_eq!(CapabilityFamily::Controllable.to_string(), "controllable");
        assert_eq!(
            CapabilityFamily::SecurityAdjacent.to_string(),
            "security_adjacent"
        );
        assert_eq!(CapabilityFamily::Automation.to_string(), "automation");
    }

    #[test]
    fn capability_family_serde_roundtrip() {
        let cf = CapabilityFamily::SecurityAdjacent;
        let json = serde_json::to_string(&cf).unwrap();
        let parsed: CapabilityFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cf);
    }

    // ===== Entity =====

    fn make_entity(domain: &str, entity_id: &str, state: &str) -> Entity {
        Entity {
            entity_id: entity_id.to_string(),
            domain: EntityDomain::parse(domain),
            name: entity_id.to_string(),
            area: None,
            device_id: None,
            state: state.to_string(),
            attributes: Value::Null,
            last_updated: None,
        }
    }

    #[test]
    fn entity_available_on() {
        let e = make_entity("light", "light.living_room", "on");
        assert!(e.is_available());
    }

    #[test]
    fn entity_available_off() {
        let e = make_entity("switch", "switch.outlet", "off");
        assert!(e.is_available());
    }

    #[test]
    fn entity_unavailable() {
        let e = make_entity("sensor", "sensor.temp", "unavailable");
        assert!(!e.is_available());
    }

    #[test]
    fn entity_unknown() {
        let e = make_entity("sensor", "sensor.temp", "unknown");
        assert!(!e.is_available());
    }

    #[test]
    fn entity_security_adjacent_lock() {
        let e = make_entity("lock", "lock.front_door", "locked");
        assert!(e.is_security_adjacent());
    }

    #[test]
    fn entity_security_adjacent_alarm() {
        let e = make_entity(
            "alarm_control_panel",
            "alarm_control_panel.home",
            "armed_home",
        );
        assert!(e.is_security_adjacent());
    }

    #[test]
    fn entity_security_adjacent_camera() {
        let e = make_entity("camera", "camera.front_porch", "idle");
        assert!(e.is_security_adjacent());
    }

    #[test]
    fn entity_not_security_light() {
        let e = make_entity("light", "light.lamp", "on");
        assert!(!e.is_security_adjacent());
    }

    #[test]
    fn entity_not_security_sensor() {
        let e = make_entity("sensor", "sensor.humidity", "55");
        assert!(!e.is_security_adjacent());
    }

    #[test]
    fn entity_serde_roundtrip() {
        let e = Entity {
            entity_id: "light.desk".into(),
            domain: EntityDomain::Light,
            name: "Desk Light".into(),
            area: Some("Office".into()),
            device_id: Some("dev_123".into()),
            state: "on".into(),
            attributes: json!({"brightness": 200}),
            last_updated: Some("2026-03-09T12:00:00Z".into()),
        };
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["entity_id"], "light.desk");
        assert_eq!(json["domain"], "light");
        assert_eq!(json["area"], "Office");
        let parsed: Entity = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.entity_id, "light.desk");
        assert_eq!(parsed.domain, EntityDomain::Light);
    }

    #[test]
    fn entity_clone() {
        let e = make_entity("fan", "fan.bedroom", "on");
        let cloned = e.clone();
        drop(e);
        assert_eq!(cloned.entity_id, "fan.bedroom");
    }

    #[test]
    fn entity_debug() {
        let e = make_entity("light", "light.debug_test", "on");
        let dbg = format!("{e:?}");
        assert!(dbg.contains("Entity"));
        assert!(dbg.contains("light.debug_test"));
    }

    // ===== EntityRegistry =====

    #[test]
    fn registry_new_empty() {
        let reg = EntityRegistry::new();
        assert_eq!(reg.count(), 0);
        assert!(reg.domains().is_empty());
    }

    #[test]
    fn registry_register_and_get() {
        let mut reg = EntityRegistry::new();
        reg.register(make_entity("light", "light.kitchen", "on"));
        assert_eq!(reg.count(), 1);
        assert!(reg.get("light.kitchen").is_some());
        assert_eq!(reg.get("light.kitchen").unwrap().state, "on");
    }

    #[test]
    fn registry_register_replaces() {
        let mut reg = EntityRegistry::new();
        reg.register(make_entity("light", "light.kitchen", "off"));
        reg.register(make_entity("light", "light.kitchen", "on"));
        assert_eq!(reg.count(), 1);
        assert_eq!(reg.get("light.kitchen").unwrap().state, "on");
    }

    #[test]
    fn registry_remove() {
        let mut reg = EntityRegistry::new();
        reg.register(make_entity("light", "light.a", "on"));
        let removed = reg.remove("light.a");
        assert!(removed.is_some());
        assert_eq!(reg.count(), 0);
        assert!(reg.get("light.a").is_none());
    }

    #[test]
    fn registry_remove_nonexistent() {
        let mut reg = EntityRegistry::new();
        assert!(reg.remove("light.ghost").is_none());
    }

    #[test]
    fn registry_list_by_domain() {
        let mut reg = EntityRegistry::new();
        reg.register(make_entity("light", "light.a", "on"));
        reg.register(make_entity("light", "light.b", "off"));
        reg.register(make_entity("switch", "switch.c", "on"));
        let lights = reg.list_by_domain(&EntityDomain::Light);
        assert_eq!(lights.len(), 2);
        assert!(lights.contains(&"light.a"));
        assert!(lights.contains(&"light.b"));
    }

    #[test]
    fn registry_list_by_domain_empty() {
        let reg = EntityRegistry::new();
        assert!(reg.list_by_domain(&EntityDomain::Lock).is_empty());
    }

    #[test]
    fn registry_list_by_area() {
        let mut reg = EntityRegistry::new();
        let mut e1 = make_entity("light", "light.a", "on");
        e1.area = Some("Kitchen".into());
        let mut e2 = make_entity("sensor", "sensor.b", "22");
        e2.area = Some("Kitchen".into());
        reg.register(e1);
        reg.register(e2);
        let kitchen = reg.list_by_area("Kitchen");
        assert_eq!(kitchen.len(), 2);
    }

    #[test]
    fn registry_list_by_area_empty() {
        let reg = EntityRegistry::new();
        assert!(reg.list_by_area("Garage").is_empty());
    }

    #[test]
    fn registry_domains() {
        let mut reg = EntityRegistry::new();
        reg.register(make_entity("light", "light.a", "on"));
        reg.register(make_entity("sensor", "sensor.b", "22"));
        reg.register(make_entity("light", "light.c", "off"));
        let domains = reg.domains();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&"light".to_string()));
        assert!(domains.contains(&"sensor".to_string()));
    }

    #[test]
    fn registry_remove_cleans_domain_index() {
        let mut reg = EntityRegistry::new();
        reg.register(make_entity("light", "light.only", "on"));
        reg.remove("light.only");
        assert!(reg.list_by_domain(&EntityDomain::Light).is_empty());
        assert!(reg.domains().is_empty());
    }

    #[test]
    fn registry_remove_cleans_area_index() {
        let mut reg = EntityRegistry::new();
        let mut e = make_entity("light", "light.a", "on");
        e.area = Some("Office".into());
        reg.register(e);
        reg.remove("light.a");
        assert!(reg.list_by_area("Office").is_empty());
    }

    #[test]
    fn registry_count_after_multiple_ops() {
        let mut reg = EntityRegistry::new();
        reg.register(make_entity("light", "light.a", "on"));
        reg.register(make_entity("light", "light.b", "off"));
        reg.register(make_entity("sensor", "sensor.c", "22"));
        assert_eq!(reg.count(), 3);
        reg.remove("light.a");
        assert_eq!(reg.count(), 2);
    }

    #[test]
    fn registry_clone() {
        let mut reg = EntityRegistry::new();
        reg.register(make_entity("light", "light.a", "on"));
        let cloned = reg.clone();
        drop(reg);
        assert_eq!(cloned.count(), 1);
    }

    // ===== ServiceCall =====

    #[test]
    fn service_call_new() {
        let sc = ServiceCall::new("light", "turn_on");
        assert_eq!(sc.domain, "light");
        assert_eq!(sc.service, "turn_on");
        assert!(sc.entity_id.is_none());
        assert!(sc.data.is_null());
    }

    #[test]
    fn service_call_with_entity() {
        let sc = ServiceCall::new("light", "turn_on").with_entity("light.desk");
        assert_eq!(sc.entity_id, Some("light.desk".into()));
    }

    #[test]
    fn service_call_with_data() {
        let sc = ServiceCall::new("light", "turn_on").with_data(json!({"brightness": 128}));
        assert_eq!(sc.data["brightness"], 128);
    }

    #[test]
    fn service_call_builder_chain() {
        let sc = ServiceCall::new("climate", "set_temperature")
            .with_entity("climate.living_room")
            .with_data(json!({"temperature": 21.5}));
        assert_eq!(sc.domain, "climate");
        assert_eq!(sc.service, "set_temperature");
        assert_eq!(sc.entity_id, Some("climate.living_room".into()));
        assert_eq!(sc.data["temperature"], 21.5);
    }

    #[test]
    fn service_call_serde_roundtrip() {
        let sc = ServiceCall::new("fan", "set_speed")
            .with_entity("fan.bedroom")
            .with_data(json!({"speed": "medium"}));
        let json = serde_json::to_value(&sc).unwrap();
        let parsed: ServiceCall = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.domain, "fan");
        assert_eq!(parsed.entity_id, Some("fan.bedroom".into()));
    }

    #[test]
    fn service_call_clone() {
        let sc = ServiceCall::new("light", "toggle");
        let cloned = sc.clone();
        drop(sc);
        assert_eq!(cloned.service, "toggle");
    }

    #[test]
    fn service_call_debug() {
        let sc = ServiceCall::new("switch", "turn_off");
        let dbg = format!("{sc:?}");
        assert!(dbg.contains("ServiceCall"));
    }

    // ===== DeviceControl =====

    #[test]
    fn device_control_turn_on_service_call() {
        let sc = DeviceControl::TurnOn.to_service_call("light");
        assert_eq!(sc.domain, "light");
        assert_eq!(sc.service, "turn_on");
    }

    #[test]
    fn device_control_turn_off_service_call() {
        let sc = DeviceControl::TurnOff.to_service_call("switch");
        assert_eq!(sc.service, "turn_off");
    }

    #[test]
    fn device_control_toggle_service_call() {
        let sc = DeviceControl::Toggle.to_service_call("light");
        assert_eq!(sc.service, "toggle");
    }

    #[test]
    fn device_control_set_brightness_service_call() {
        let sc = DeviceControl::SetBrightness(200).to_service_call("light");
        assert_eq!(sc.service, "turn_on");
        assert_eq!(sc.data["brightness"], 200);
    }

    #[test]
    fn device_control_set_temperature_service_call() {
        let sc = DeviceControl::SetTemperature(22.5).to_service_call("climate");
        assert_eq!(sc.service, "set_temperature");
        assert_eq!(sc.data["temperature"], 22.5);
    }

    #[test]
    fn device_control_set_position_service_call() {
        let sc = DeviceControl::SetPosition(50).to_service_call("cover");
        assert_eq!(sc.service, "set_cover_position");
        assert_eq!(sc.data["position"], 50);
    }

    #[test]
    fn device_control_lock_service_call() {
        let sc = DeviceControl::Lock.to_service_call("lock");
        assert_eq!(sc.service, "lock");
    }

    #[test]
    fn device_control_unlock_service_call() {
        let sc = DeviceControl::Unlock.to_service_call("lock");
        assert_eq!(sc.service, "unlock");
    }

    #[test]
    fn device_control_arm_home_service_call() {
        let sc = DeviceControl::ArmHome.to_service_call("alarm_control_panel");
        assert_eq!(sc.service, "alarm_arm_home");
    }

    #[test]
    fn device_control_arm_away_service_call() {
        let sc = DeviceControl::ArmAway.to_service_call("alarm_control_panel");
        assert_eq!(sc.service, "alarm_arm_away");
    }

    #[test]
    fn device_control_disarm_service_call() {
        let sc = DeviceControl::Disarm.to_service_call("alarm_control_panel");
        assert_eq!(sc.service, "alarm_disarm");
    }

    #[test]
    fn device_control_custom_service_call() {
        let ctrl = DeviceControl::Custom {
            service: "start_cleaning".into(),
            data: json!({"mode": "turbo"}),
        };
        let sc = ctrl.to_service_call("vacuum");
        assert_eq!(sc.domain, "vacuum");
        assert_eq!(sc.service, "start_cleaning");
        assert_eq!(sc.data["mode"], "turbo");
    }

    #[test]
    fn device_control_requires_approval_lock() {
        assert!(DeviceControl::Lock.requires_approval());
    }

    #[test]
    fn device_control_requires_approval_unlock() {
        assert!(DeviceControl::Unlock.requires_approval());
    }

    #[test]
    fn device_control_requires_approval_arm_home() {
        assert!(DeviceControl::ArmHome.requires_approval());
    }

    #[test]
    fn device_control_requires_approval_arm_away() {
        assert!(DeviceControl::ArmAway.requires_approval());
    }

    #[test]
    fn device_control_requires_approval_disarm() {
        assert!(DeviceControl::Disarm.requires_approval());
    }

    #[test]
    fn device_control_no_approval_turn_on() {
        assert!(!DeviceControl::TurnOn.requires_approval());
    }

    #[test]
    fn device_control_no_approval_turn_off() {
        assert!(!DeviceControl::TurnOff.requires_approval());
    }

    #[test]
    fn device_control_no_approval_toggle() {
        assert!(!DeviceControl::Toggle.requires_approval());
    }

    #[test]
    fn device_control_no_approval_brightness() {
        assert!(!DeviceControl::SetBrightness(128).requires_approval());
    }

    #[test]
    fn device_control_no_approval_temperature() {
        assert!(!DeviceControl::SetTemperature(21.0).requires_approval());
    }

    #[test]
    fn device_control_no_approval_position() {
        assert!(!DeviceControl::SetPosition(75).requires_approval());
    }

    #[test]
    fn device_control_no_approval_custom() {
        let ctrl = DeviceControl::Custom {
            service: "test".into(),
            data: Value::Null,
        };
        assert!(!ctrl.requires_approval());
    }

    #[test]
    fn device_control_serde_turn_on() {
        let ctrl = DeviceControl::TurnOn;
        let json = serde_json::to_string(&ctrl).unwrap();
        let parsed: DeviceControl = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, DeviceControl::TurnOn));
    }

    #[test]
    fn device_control_serde_custom() {
        let ctrl = DeviceControl::Custom {
            service: "clean".into(),
            data: json!({"zones": [1, 2]}),
        };
        let json = serde_json::to_value(&ctrl).unwrap();
        let parsed: DeviceControl = serde_json::from_value(json).unwrap();
        if let DeviceControl::Custom { service, data } = parsed {
            assert_eq!(service, "clean");
            assert_eq!(data["zones"][0], 1);
        } else {
            panic!("expected Custom variant");
        }
    }

    #[test]
    fn device_control_clone() {
        let ctrl = DeviceControl::SetBrightness(100);
        let cloned = ctrl.clone();
        drop(ctrl);
        assert!(matches!(cloned, DeviceControl::SetBrightness(100)));
    }

    #[test]
    fn device_control_debug() {
        let ctrl = DeviceControl::ArmAway;
        let dbg = format!("{ctrl:?}");
        assert!(dbg.contains("ArmAway"));
    }

    // ===== ControlPolicy =====

    #[test]
    fn policy_permissive_allows_everything() {
        let policy = ControlPolicy::new_permissive();
        assert!(policy.allow_read);
        assert!(policy.allow_control);
        assert!(policy.allow_security);
        assert!(!policy.require_approval_for_security);
    }

    #[test]
    fn policy_readonly_denies_control() {
        let policy = ControlPolicy::new_readonly();
        assert!(policy.allow_read);
        assert!(!policy.allow_control);
        assert!(!policy.allow_security);
    }

    #[test]
    fn policy_safe_requires_approval() {
        let policy = ControlPolicy::new_safe();
        assert!(policy.allow_read);
        assert!(policy.allow_control);
        assert!(policy.allow_security);
        assert!(policy.require_approval_for_security);
    }

    // ----- check_control tests -----

    #[test]
    fn policy_permissive_allows_light_control() {
        let policy = ControlPolicy::new_permissive();
        let entity = make_entity("light", "light.desk", "on");
        assert_eq!(
            policy.check_control(&entity, &DeviceControl::TurnOff),
            ControlDecision::Allow,
        );
    }

    #[test]
    fn policy_permissive_allows_lock_control() {
        let policy = ControlPolicy::new_permissive();
        let entity = make_entity("lock", "lock.front", "locked");
        assert_eq!(
            policy.check_control(&entity, &DeviceControl::Unlock),
            ControlDecision::Allow,
        );
    }

    #[test]
    fn policy_readonly_denies_light_control() {
        let policy = ControlPolicy::new_readonly();
        let entity = make_entity("light", "light.desk", "on");
        let decision = policy.check_control(&entity, &DeviceControl::TurnOff);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
    }

    #[test]
    fn policy_readonly_denies_lock_control() {
        let policy = ControlPolicy::new_readonly();
        let entity = make_entity("lock", "lock.front", "locked");
        let decision = policy.check_control(&entity, &DeviceControl::Unlock);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
    }

    #[test]
    fn policy_safe_allows_light() {
        let policy = ControlPolicy::new_safe();
        let entity = make_entity("light", "light.lamp", "on");
        assert_eq!(
            policy.check_control(&entity, &DeviceControl::Toggle),
            ControlDecision::Allow,
        );
    }

    #[test]
    fn policy_safe_requires_approval_for_lock() {
        let policy = ControlPolicy::new_safe();
        let entity = make_entity("lock", "lock.back_door", "locked");
        let decision = policy.check_control(&entity, &DeviceControl::Unlock);
        assert!(matches!(decision, ControlDecision::RequireApproval { .. }));
    }

    #[test]
    fn policy_safe_requires_approval_for_alarm() {
        let policy = ControlPolicy::new_safe();
        let entity = make_entity(
            "alarm_control_panel",
            "alarm_control_panel.home",
            "armed_home",
        );
        let decision = policy.check_control(&entity, &DeviceControl::Disarm);
        assert!(matches!(decision, ControlDecision::RequireApproval { .. }));
    }

    #[test]
    fn policy_safe_requires_approval_for_camera() {
        let policy = ControlPolicy::new_safe();
        let entity = make_entity("camera", "camera.porch", "idle");
        let decision = policy.check_control(&entity, &DeviceControl::TurnOff);
        assert!(matches!(decision, ControlDecision::RequireApproval { .. }));
    }

    #[test]
    fn policy_blocked_entity() {
        let mut policy = ControlPolicy::new_permissive();
        policy.blocked_entities.insert("light.forbidden".into());
        let entity = make_entity("light", "light.forbidden", "on");
        let decision = policy.check_control(&entity, &DeviceControl::TurnOn);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
        if let ControlDecision::Deny { reason } = decision {
            assert!(reason.contains("light.forbidden"));
        }
    }

    #[test]
    fn policy_blocked_domain() {
        let mut policy = ControlPolicy::new_permissive();
        policy.blocked_domains.insert("vacuum".into());
        let entity = make_entity("vacuum", "vacuum.roomba", "docked");
        let decision = policy.check_control(&entity, &DeviceControl::TurnOn);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
        if let ControlDecision::Deny { reason } = decision {
            assert!(reason.contains("vacuum"));
        }
    }

    #[test]
    fn policy_blocked_entity_takes_precedence() {
        let mut policy = ControlPolicy::new_permissive();
        policy.blocked_entities.insert("light.special".into());
        let entity = make_entity("light", "light.special", "on");
        let decision = policy.check_control(&entity, &DeviceControl::TurnOff);
        if let ControlDecision::Deny { reason } = decision {
            assert!(reason.contains("light.special"));
            assert!(reason.contains("entity"));
        } else {
            panic!("expected Deny");
        }
    }

    #[test]
    fn policy_deny_sensor_control() {
        let policy = ControlPolicy::new_permissive();
        let entity = make_entity("sensor", "sensor.temp", "22.5");
        let decision = policy.check_control(&entity, &DeviceControl::TurnOn);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
        if let ControlDecision::Deny { reason } = decision {
            assert!(reason.contains("read-only"));
        }
    }

    #[test]
    fn policy_deny_binary_sensor_control() {
        let policy = ControlPolicy::new_permissive();
        let entity = make_entity("binary_sensor", "binary_sensor.door", "off");
        let decision = policy.check_control(&entity, &DeviceControl::Toggle);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
    }

    #[test]
    fn policy_deny_weather_control() {
        let policy = ControlPolicy::new_permissive();
        let entity = make_entity("weather", "weather.home", "sunny");
        let decision = policy.check_control(&entity, &DeviceControl::TurnOff);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
    }

    #[test]
    fn policy_allow_automation_control() {
        let policy = ControlPolicy::new_permissive();
        let entity = make_entity("automation", "automation.night_mode", "on");
        assert_eq!(
            policy.check_control(&entity, &DeviceControl::TurnOff),
            ControlDecision::Allow,
        );
    }

    #[test]
    fn policy_readonly_denies_automation() {
        let policy = ControlPolicy::new_readonly();
        let entity = make_entity("automation", "automation.test", "on");
        let decision = policy.check_control(&entity, &DeviceControl::TurnOff);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
    }

    #[test]
    fn policy_safe_lock_operation_on_nonlock_entity() {
        // A Lock DeviceControl on a light still triggers approval because the
        // control itself requires_approval.
        let policy = ControlPolicy::new_safe();
        let entity = make_entity("light", "light.test", "on");
        let decision = policy.check_control(&entity, &DeviceControl::Lock);
        assert!(matches!(decision, ControlDecision::RequireApproval { .. }));
    }

    #[test]
    fn policy_serde_roundtrip() {
        let policy = ControlPolicy::new_safe();
        let json = serde_json::to_value(&policy).unwrap();
        let parsed: ControlPolicy = serde_json::from_value(json).unwrap();
        assert!(parsed.require_approval_for_security);
        assert!(parsed.allow_control);
    }

    #[test]
    fn policy_clone() {
        let policy = ControlPolicy::new_safe();
        let cloned = policy.clone();
        drop(policy);
        assert!(cloned.require_approval_for_security);
    }

    #[test]
    fn policy_debug() {
        let policy = ControlPolicy::new_permissive();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("ControlPolicy"));
    }

    // ===== ControlDecision =====

    #[test]
    fn decision_allow_eq() {
        assert_eq!(ControlDecision::Allow, ControlDecision::Allow);
    }

    #[test]
    fn decision_deny_eq() {
        let a = ControlDecision::Deny {
            reason: "test".into(),
        };
        let b = ControlDecision::Deny {
            reason: "test".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn decision_deny_ne() {
        let a = ControlDecision::Deny { reason: "a".into() };
        let b = ControlDecision::Deny { reason: "b".into() };
        assert_ne!(a, b);
    }

    #[test]
    fn decision_require_approval_eq() {
        let a = ControlDecision::RequireApproval {
            reason: "security".into(),
        };
        let b = ControlDecision::RequireApproval {
            reason: "security".into(),
        };
        assert_eq!(a, b);
    }

    #[test]
    fn decision_serde_roundtrip() {
        let decisions = vec![
            ControlDecision::Allow,
            ControlDecision::Deny {
                reason: "blocked".into(),
            },
            ControlDecision::RequireApproval {
                reason: "security".into(),
            },
        ];
        for d in decisions {
            let json = serde_json::to_value(&d).unwrap();
            let parsed: ControlDecision = serde_json::from_value(json).unwrap();
            assert_eq!(parsed, d);
        }
    }

    #[test]
    fn decision_clone() {
        let d = ControlDecision::RequireApproval {
            reason: "lock".into(),
        };
        let cloned = d.clone();
        drop(d);
        assert!(matches!(cloned, ControlDecision::RequireApproval { .. }));
    }

    // ===== IntegrationAuditEvent =====

    #[test]
    fn audit_event_serde_roundtrip() {
        let event = IntegrationAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            action: "turn_on".into(),
            entity_id: "light.desk".into(),
            service_call: Some(ServiceCall::new("light", "turn_on").with_entity("light.desk")),
            decision: ControlDecision::Allow,
        };
        let json = serde_json::to_value(&event).unwrap();
        let parsed: IntegrationAuditEvent = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.entity_id, "light.desk");
        assert_eq!(parsed.decision, ControlDecision::Allow);
    }

    #[test]
    fn audit_event_denied() {
        let event = IntegrationAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            action: "unlock".into(),
            entity_id: "lock.front".into(),
            service_call: None,
            decision: ControlDecision::Deny {
                reason: "security blocked".into(),
            },
        };
        let json = serde_json::to_value(&event).unwrap();
        assert!(
            json["decision"]["Deny"]["reason"]
                .as_str()
                .unwrap()
                .contains("security")
        );
    }

    #[test]
    fn audit_event_clone() {
        let event = IntegrationAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            action: "toggle".into(),
            entity_id: "switch.test".into(),
            service_call: None,
            decision: ControlDecision::Allow,
        };
        let cloned = event.clone();
        drop(event);
        assert_eq!(cloned.action, "toggle");
    }

    #[test]
    fn audit_event_debug() {
        let event = IntegrationAuditEvent {
            timestamp: "2026-03-09T12:00:00Z".into(),
            action: "test".into(),
            entity_id: "light.test".into(),
            service_call: None,
            decision: ControlDecision::Allow,
        };
        let dbg = format!("{event:?}");
        assert!(dbg.contains("IntegrationAuditEvent"));
    }

    // ===== Integration scenario tests =====

    #[test]
    fn scenario_full_registry_lifecycle() {
        let mut reg = EntityRegistry::new();

        // Populate a small home.
        let mut light = make_entity("light", "light.living_room", "on");
        light.area = Some("Living Room".into());
        let mut sensor = make_entity("sensor", "sensor.temp_living", "22.5");
        sensor.area = Some("Living Room".into());
        let lock = make_entity("lock", "lock.front_door", "locked");

        reg.register(light);
        reg.register(sensor);
        reg.register(lock);
        assert_eq!(reg.count(), 3);

        // Query by domain.
        assert_eq!(reg.list_by_domain(&EntityDomain::Light).len(), 1);
        assert_eq!(reg.list_by_domain(&EntityDomain::Sensor).len(), 1);
        assert_eq!(reg.list_by_domain(&EntityDomain::Lock).len(), 1);

        // Query by area.
        assert_eq!(reg.list_by_area("Living Room").len(), 2);

        // Remove and verify cleanup.
        reg.remove("sensor.temp_living");
        assert_eq!(reg.count(), 2);
        assert_eq!(reg.list_by_area("Living Room").len(), 1);
        assert!(reg.list_by_domain(&EntityDomain::Sensor).is_empty());
    }

    #[test]
    fn scenario_safe_policy_mixed_controls() {
        let policy = ControlPolicy::new_safe();

        // Light: allowed.
        let light = make_entity("light", "light.bedroom", "on");
        assert_eq!(
            policy.check_control(&light, &DeviceControl::SetBrightness(128)),
            ControlDecision::Allow,
        );

        // Lock: requires approval.
        let lock = make_entity("lock", "lock.garage", "unlocked");
        let decision = policy.check_control(&lock, &DeviceControl::Lock);
        assert!(matches!(decision, ControlDecision::RequireApproval { .. }));

        // Sensor: deny (read-only).
        let sensor = make_entity("sensor", "sensor.humidity", "65");
        let decision = policy.check_control(&sensor, &DeviceControl::TurnOn);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
    }

    #[test]
    fn scenario_custom_policy_blocks() {
        let mut policy = ControlPolicy::new_permissive();
        policy.blocked_domains.insert("vacuum".into());
        policy.blocked_entities.insert("light.kids_room".into());

        let vacuum = make_entity("vacuum", "vacuum.roomba", "docked");
        assert!(matches!(
            policy.check_control(&vacuum, &DeviceControl::TurnOn),
            ControlDecision::Deny { .. },
        ));

        let kids_light = make_entity("light", "light.kids_room", "on");
        assert!(matches!(
            policy.check_control(&kids_light, &DeviceControl::TurnOff),
            ControlDecision::Deny { .. },
        ));

        // Other lights are fine.
        let other_light = make_entity("light", "light.hallway", "off");
        assert_eq!(
            policy.check_control(&other_light, &DeviceControl::TurnOn),
            ControlDecision::Allow,
        );
    }

    #[test]
    fn scenario_security_control_on_permissive() {
        let policy = ControlPolicy::new_permissive();
        let lock = make_entity("lock", "lock.office", "locked");
        assert_eq!(
            policy.check_control(&lock, &DeviceControl::Unlock),
            ControlDecision::Allow,
        );
    }

    #[test]
    fn scenario_no_security_policy() {
        // Disallow security entirely.
        let mut policy = ControlPolicy::new_permissive();
        policy.allow_security = false;
        let lock = make_entity("lock", "lock.test", "locked");
        let decision = policy.check_control(&lock, &DeviceControl::Unlock);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
        if let ControlDecision::Deny { reason } = decision {
            assert!(reason.contains("security"));
        }
    }

    #[test]
    fn scenario_device_control_brightness_zero() {
        let sc = DeviceControl::SetBrightness(0).to_service_call("light");
        assert_eq!(sc.data["brightness"], 0);
    }

    #[test]
    fn scenario_device_control_brightness_max() {
        let sc = DeviceControl::SetBrightness(255).to_service_call("light");
        assert_eq!(sc.data["brightness"], 255);
    }

    #[test]
    fn scenario_device_control_temperature_negative() {
        let sc = DeviceControl::SetTemperature(-5.0).to_service_call("climate");
        assert_eq!(sc.data["temperature"], -5.0);
    }

    #[test]
    fn scenario_device_control_position_zero() {
        let sc = DeviceControl::SetPosition(0).to_service_call("cover");
        assert_eq!(sc.data["position"], 0);
    }

    #[test]
    fn scenario_device_control_position_max() {
        let sc = DeviceControl::SetPosition(100).to_service_call("cover");
        assert_eq!(sc.data["position"], 100);
    }

    #[test]
    fn policy_no_security_blocks_approval_controls() {
        // Lock DeviceControl on a light with security disabled.
        let mut policy = ControlPolicy::new_permissive();
        policy.allow_security = false;
        let entity = make_entity("light", "light.test", "on");
        let decision = policy.check_control(&entity, &DeviceControl::Lock);
        assert!(matches!(decision, ControlDecision::Deny { .. }));
    }

    #[test]
    fn registry_domains_sorted() {
        let mut reg = EntityRegistry::new();
        reg.register(make_entity("vacuum", "vacuum.a", "on"));
        reg.register(make_entity("light", "light.b", "off"));
        reg.register(make_entity(
            "alarm_control_panel",
            "alarm_control_panel.c",
            "armed",
        ));
        let domains = reg.domains();
        assert_eq!(domains[0], "alarm_control_panel");
        assert_eq!(domains[1], "light");
        assert_eq!(domains[2], "vacuum");
    }

    #[test]
    fn entity_with_all_fields() {
        let e = Entity {
            entity_id: "climate.thermostat".into(),
            domain: EntityDomain::Climate,
            name: "Main Thermostat".into(),
            area: Some("Hallway".into()),
            device_id: Some("dev_abc".into()),
            state: "heating".into(),
            attributes: json!({"current_temperature": 19.5, "target_temperature": 22.0}),
            last_updated: Some("2026-03-09T10:00:00Z".into()),
        };
        assert!(e.is_available());
        assert!(!e.is_security_adjacent());
        assert_eq!(e.attributes["current_temperature"], 19.5);
    }

    #[test]
    fn registry_re_register_changes_area() {
        let mut reg = EntityRegistry::new();
        let mut e = make_entity("light", "light.portable", "on");
        e.area = Some("Kitchen".into());
        reg.register(e);

        assert_eq!(reg.list_by_area("Kitchen").len(), 1);

        let mut e2 = make_entity("light", "light.portable", "on");
        e2.area = Some("Bedroom".into());
        reg.register(e2);

        assert_eq!(reg.count(), 1);
        assert!(reg.list_by_area("Kitchen").is_empty());
        assert_eq!(reg.list_by_area("Bedroom").len(), 1);
    }

    #[test]
    fn domain_hash_eq() {
        let mut set = HashSet::new();
        set.insert(EntityDomain::Light);
        set.insert(EntityDomain::Light);
        assert_eq!(set.len(), 1);

        set.insert(EntityDomain::Other("custom".into()));
        set.insert(EntityDomain::Other("custom".into()));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn capability_family_copy() {
        let cf = CapabilityFamily::ReadOnly;
        let cf2 = cf;
        assert_eq!(cf, cf2);
    }

    #[test]
    fn capability_family_hash() {
        let mut set = HashSet::new();
        set.insert(CapabilityFamily::ReadOnly);
        set.insert(CapabilityFamily::Controllable);
        set.insert(CapabilityFamily::SecurityAdjacent);
        set.insert(CapabilityFamily::Automation);
        assert_eq!(set.len(), 4);
        set.insert(CapabilityFamily::ReadOnly);
        assert_eq!(set.len(), 4);
    }
}
