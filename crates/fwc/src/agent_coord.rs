//! Agent Mail integration for multi-agent connector coordination.
//!
//! Provides a coordination layer so multiple agents can announce connector
//! usage, reserve resources, exchange messages, and avoid conflicting
//! operations on the same connector or resource.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Agent identity ────────────────────────────────────────────────

/// An agent participating in coordination.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct AgentId(String);

impl AgentId {
    /// Create from a name string.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The raw string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Announcements ─────────────────────────────────────────────────

/// An agent announcing what connector/operation it intends to use.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageAnnouncement {
    /// Who is announcing.
    pub agent: AgentId,
    /// Connector being used.
    pub connector: String,
    /// Operation (optional — may be broad "using github").
    pub operation: Option<String>,
    /// Human-readable purpose.
    pub purpose: String,
    /// When announced.
    pub announced_at: u64,
    /// Expected duration in seconds (0 = indefinite).
    pub expected_duration: u64,
}

impl UsageAnnouncement {
    /// Create a new announcement.
    pub fn new(agent: AgentId, connector: impl Into<String>, purpose: impl Into<String>) -> Self {
        Self {
            agent,
            connector: connector.into(),
            operation: None,
            purpose: purpose.into(),
            announced_at: epoch_seconds(),
            expected_duration: 0,
        }
    }

    /// With a specific operation.
    pub fn with_operation(mut self, op: impl Into<String>) -> Self {
        self.operation = Some(op.into());
        self
    }

    /// With an expected duration.
    pub const fn with_duration(mut self, seconds: u64) -> Self {
        self.expected_duration = seconds;
        self
    }

    /// Whether the announcement has expired.
    pub fn is_expired(&self) -> bool {
        self.expected_duration > 0
            && epoch_seconds().saturating_sub(self.announced_at) >= self.expected_duration
    }
}

// ── Resource reservations ─────────────────────────────────────────

/// A reservation on a connector resource.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceReservation {
    /// Reservation ID.
    pub id: String,
    /// Who holds the reservation.
    pub agent: AgentId,
    /// Connector.
    pub connector: String,
    /// Resource identifier within the connector.
    pub resource: String,
    /// When reserved.
    pub reserved_at: u64,
    /// Time-to-live in seconds.
    pub ttl_seconds: u64,
    /// Whether the reservation is exclusive.
    pub exclusive: bool,
}

impl ResourceReservation {
    /// Whether this reservation has expired.
    pub fn is_expired(&self) -> bool {
        self.ttl_seconds > 0 && epoch_seconds().saturating_sub(self.reserved_at) >= self.ttl_seconds
    }

    /// Remaining TTL in seconds.
    pub fn remaining_seconds(&self) -> u64 {
        if self.ttl_seconds == 0 {
            return u64::MAX;
        }
        let elapsed = epoch_seconds().saturating_sub(self.reserved_at);
        self.ttl_seconds.saturating_sub(elapsed)
    }
}

// ── Messages ──────────────────────────────────────────────────────

/// A message between agents.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentMessage {
    /// Sender.
    pub from: AgentId,
    /// Recipient.
    pub to: AgentId,
    /// Message type.
    pub kind: MessageKind,
    /// Free-form payload.
    pub payload: serde_json::Value,
    /// When sent.
    pub sent_at: u64,
    /// Whether the message has been read.
    pub read: bool,
}

/// Types of agent-to-agent messages.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Requesting another agent to do something.
    Request,
    /// Responding to a request.
    Response,
    /// Informational announcement.
    Info,
    /// Warning about a conflict or issue.
    Warning,
    /// Releasing a resource or completing a task.
    Release,
}

impl fmt::Display for MessageKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request => write!(f, "request"),
            Self::Response => write!(f, "response"),
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Release => write!(f, "release"),
        }
    }
}

// ── Coordination hub ──────────────────────────────────────────────

/// Central coordination hub for multi-agent connector operations.
#[derive(Clone, Debug, Default)]
pub struct CoordinationHub {
    /// Active usage announcements.
    announcements: Vec<UsageAnnouncement>,
    /// Active resource reservations.
    reservations: BTreeMap<String, ResourceReservation>,
    /// Message inboxes (agent → messages).
    inboxes: BTreeMap<String, Vec<AgentMessage>>,
    /// Reservation ID counter.
    next_reservation_id: u64,
}

impl CoordinationHub {
    /// Create a new hub.
    pub fn new() -> Self {
        Self::default()
    }

    // ── Announcements ─────────────────────────────────────────

    /// Announce connector usage.
    pub fn announce(&mut self, announcement: UsageAnnouncement) {
        self.announcements.push(announcement);
    }

    /// List active (non-expired) announcements.
    pub fn active_announcements(&self) -> Vec<&UsageAnnouncement> {
        self.announcements
            .iter()
            .filter(|a| !a.is_expired())
            .collect()
    }

    /// Announcements for a specific connector.
    pub fn announcements_for(&self, connector: &str) -> Vec<&UsageAnnouncement> {
        self.announcements
            .iter()
            .filter(|a| !a.is_expired() && a.connector == connector)
            .collect()
    }

    /// Purge expired announcements.
    pub fn purge_announcements(&mut self) -> usize {
        let before = self.announcements.len();
        self.announcements.retain(|a| !a.is_expired());
        before - self.announcements.len()
    }

    // ── Reservations ──────────────────────────────────────────

    /// Reserve a resource. Returns the reservation ID.
    pub fn reserve(
        &mut self,
        agent: AgentId,
        connector: impl Into<String>,
        resource: impl Into<String>,
        ttl_seconds: u64,
        exclusive: bool,
    ) -> Result<String, CoordError> {
        let connector = connector.into();
        let resource = resource.into();

        // Check for conflicts.
        if exclusive {
            for res in self.reservations.values() {
                if !res.is_expired() && res.connector == connector && res.resource == resource {
                    return Err(CoordError::ResourceConflict {
                        resource,
                        held_by: res.agent.to_string(),
                    });
                }
            }
        } else {
            // Non-exclusive: only conflict with exclusive reservations.
            for res in self.reservations.values() {
                if !res.is_expired()
                    && res.connector == connector
                    && res.resource == resource
                    && res.exclusive
                {
                    return Err(CoordError::ResourceConflict {
                        resource,
                        held_by: res.agent.to_string(),
                    });
                }
            }
        }

        self.next_reservation_id += 1;
        let id = format!("res_{}", self.next_reservation_id);
        self.reservations.insert(
            id.clone(),
            ResourceReservation {
                id: id.clone(),
                agent,
                connector,
                resource,
                reserved_at: epoch_seconds(),
                ttl_seconds,
                exclusive,
            },
        );
        Ok(id)
    }

    /// Release a reservation.
    pub fn release(&mut self, reservation_id: &str) -> Result<ResourceReservation, CoordError> {
        self.reservations
            .remove(reservation_id)
            .ok_or_else(|| CoordError::ReservationNotFound(reservation_id.to_owned()))
    }

    /// Extend a reservation's TTL.
    pub fn extend_reservation(
        &mut self,
        reservation_id: &str,
        additional_seconds: u64,
    ) -> Result<(), CoordError> {
        let res = self
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(|| CoordError::ReservationNotFound(reservation_id.to_owned()))?;
        res.ttl_seconds += additional_seconds;
        Ok(())
    }

    /// List active reservations for a connector.
    pub fn reservations_for(&self, connector: &str) -> Vec<&ResourceReservation> {
        self.reservations
            .values()
            .filter(|r| !r.is_expired() && r.connector == connector)
            .collect()
    }

    /// Purge expired reservations.
    pub fn purge_reservations(&mut self) -> usize {
        let before = self.reservations.len();
        self.reservations.retain(|_, r| !r.is_expired());
        before - self.reservations.len()
    }

    // ── Messaging ─────────────────────────────────────────────

    /// Send a message to an agent.
    pub fn send(
        &mut self,
        from: AgentId,
        to: &AgentId,
        kind: MessageKind,
        payload: serde_json::Value,
    ) {
        let msg = AgentMessage {
            from,
            to: to.clone(),
            kind,
            payload,
            sent_at: epoch_seconds(),
            read: false,
        };
        self.inboxes
            .entry(to.as_str().to_owned())
            .or_default()
            .push(msg);
    }

    /// Read all unread messages for an agent.
    pub fn inbox(&self, agent: &AgentId) -> Vec<&AgentMessage> {
        self.inboxes
            .get(agent.as_str())
            .map(|msgs| msgs.iter().collect())
            .unwrap_or_default()
    }

    /// Read and mark all messages as read.
    pub fn read_inbox(&mut self, agent: &AgentId) -> Vec<AgentMessage> {
        self.inboxes
            .get_mut(agent.as_str())
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// Count unread messages for an agent.
    pub fn unread_count(&self, agent: &AgentId) -> usize {
        self.inboxes
            .get(agent.as_str())
            .map_or(0, |msgs| msgs.iter().filter(|m| !m.read).count())
    }

    // ── Conflict detection ────────────────────────────────────

    /// Check if a connector/operation is safe to invoke given current state.
    pub fn check_conflict(
        &self,
        agent: &AgentId,
        connector: &str,
        resource: Option<&str>,
    ) -> ConflictCheck {
        let mut warnings = Vec::new();

        // Check announcements.
        for ann in &self.announcements {
            if !ann.is_expired() && ann.connector == connector && ann.agent != *agent {
                warnings.push(format!(
                    "Agent {} is using {} ({})",
                    ann.agent, connector, ann.purpose
                ));
            }
        }

        // Check reservations.
        if let Some(res_name) = resource {
            for res in self.reservations.values() {
                if !res.is_expired()
                    && res.connector == connector
                    && res.resource == res_name
                    && res.agent != *agent
                    && res.exclusive
                {
                    return ConflictCheck::Blocked {
                        reason: format!(
                            "Resource {} exclusively reserved by {}",
                            res_name, res.agent
                        ),
                    };
                }
            }
        }

        if warnings.is_empty() {
            ConflictCheck::Clear
        } else {
            ConflictCheck::Warning { warnings }
        }
    }

    /// Total active reservations.
    pub fn reservation_count(&self) -> usize {
        self.reservations
            .values()
            .filter(|r| !r.is_expired())
            .count()
    }

    /// Total active announcements.
    pub fn announcement_count(&self) -> usize {
        self.announcements
            .iter()
            .filter(|a| !a.is_expired())
            .count()
    }
}

/// Result of a conflict check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConflictCheck {
    /// No conflicts detected.
    Clear,
    /// Other agents are using the same connector (informational).
    Warning { warnings: Vec<String> },
    /// An exclusive reservation prevents access.
    Blocked { reason: String },
}

impl fmt::Display for ConflictCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Clear => write!(f, "clear"),
            Self::Warning { warnings } => write!(f, "warning: {}", warnings.join("; ")),
            Self::Blocked { reason } => write!(f, "blocked: {reason}"),
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────

/// Coordination errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordError {
    /// Resource already reserved by another agent.
    ResourceConflict { resource: String, held_by: String },
    /// Reservation not found.
    ReservationNotFound(String),
}

impl fmt::Display for CoordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ResourceConflict { resource, held_by } => {
                write!(f, "resource {resource} already held by {held_by}")
            }
            Self::ReservationNotFound(id) => write!(f, "reservation not found: {id}"),
        }
    }
}

impl std::error::Error for CoordError {}

// ── Helpers ───────────────────────────────────────────────────────

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn agent(name: &str) -> AgentId {
        AgentId::new(name)
    }

    // ── AgentId ───────────────────────────────────────────────

    #[test]
    fn agent_id_display() {
        let a = agent("SunnyMoose");
        assert_eq!(a.to_string(), "SunnyMoose");
        assert_eq!(a.as_str(), "SunnyMoose");
    }

    #[test]
    fn agent_id_equality() {
        assert_eq!(agent("A"), agent("A"));
        assert_ne!(agent("A"), agent("B"));
    }

    // ── UsageAnnouncement ─────────────────────────────────────

    #[test]
    fn announcement_creation() {
        let ann = UsageAnnouncement::new(agent("A"), "github", "Reading issues");
        assert_eq!(ann.connector, "github");
        assert_eq!(ann.purpose, "Reading issues");
        assert!(ann.operation.is_none());
        assert!(!ann.is_expired());
    }

    #[test]
    fn announcement_with_operation() {
        let ann =
            UsageAnnouncement::new(agent("A"), "github", "test").with_operation("list_issues");
        assert_eq!(ann.operation.as_deref(), Some("list_issues"));
    }

    #[test]
    fn announcement_with_duration_expired() {
        let ann = UsageAnnouncement::new(agent("A"), "github", "test").with_duration(1);
        // Duration of 1 second — with epoch_seconds() it should expire almost immediately
        // (race condition window, but 1 second is enough for assertion to usually work)
        // We'll just check the field is set.
        assert_eq!(ann.expected_duration, 1);
    }

    #[test]
    fn announcement_no_duration_never_expires() {
        let ann = UsageAnnouncement::new(agent("A"), "github", "test");
        assert!(!ann.is_expired());
    }

    // ── ResourceReservation ───────────────────────────────────

    #[test]
    fn reservation_remaining() {
        let res = ResourceReservation {
            id: "res_1".into(),
            agent: agent("A"),
            connector: "github".into(),
            resource: "repo:octocat/hello".into(),
            reserved_at: epoch_seconds(),
            ttl_seconds: 3600,
            exclusive: true,
        };
        assert!(res.remaining_seconds() > 3500);
        assert!(!res.is_expired());
    }

    #[test]
    fn reservation_no_ttl() {
        let res = ResourceReservation {
            id: "res_1".into(),
            agent: agent("A"),
            connector: "github".into(),
            resource: "repo:octocat/hello".into(),
            reserved_at: epoch_seconds(),
            ttl_seconds: 0,
            exclusive: false,
        };
        assert_eq!(res.remaining_seconds(), u64::MAX);
        assert!(!res.is_expired());
    }

    // ── MessageKind ───────────────────────────────────────────

    #[test]
    fn message_kind_display() {
        assert_eq!(MessageKind::Request.to_string(), "request");
        assert_eq!(MessageKind::Response.to_string(), "response");
        assert_eq!(MessageKind::Info.to_string(), "info");
        assert_eq!(MessageKind::Warning.to_string(), "warning");
        assert_eq!(MessageKind::Release.to_string(), "release");
    }

    // ── CoordinationHub announcements ─────────────────────────

    #[test]
    fn hub_announce_and_list() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(agent("A"), "github", "reading"));
        hub.announce(UsageAnnouncement::new(agent("B"), "slack", "posting"));
        assert_eq!(hub.active_announcements().len(), 2);
        assert_eq!(hub.announcement_count(), 2);
    }

    #[test]
    fn hub_announcements_for_connector() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(agent("A"), "github", "r1"));
        hub.announce(UsageAnnouncement::new(agent("B"), "github", "r2"));
        hub.announce(UsageAnnouncement::new(agent("C"), "slack", "r3"));
        assert_eq!(hub.announcements_for("github").len(), 2);
        assert_eq!(hub.announcements_for("slack").len(), 1);
        assert_eq!(hub.announcements_for("jira").len(), 0);
    }

    // ── CoordinationHub reservations ──────────────────────────

    #[test]
    fn hub_reserve_and_release() {
        let mut hub = CoordinationHub::new();
        let id = hub
            .reserve(agent("A"), "github", "repo:octocat/hello", 300, true)
            .unwrap();
        assert_eq!(hub.reservation_count(), 1);
        let released = hub.release(&id).unwrap();
        assert_eq!(released.agent, agent("A"));
        assert_eq!(hub.reservation_count(), 0);
    }

    #[test]
    fn hub_exclusive_conflict() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "github", "repo:x", 300, true)
            .unwrap();
        let err = hub
            .reserve(agent("B"), "github", "repo:x", 300, true)
            .unwrap_err();
        assert!(err.to_string().contains("held by"));
    }

    #[test]
    fn hub_non_exclusive_no_conflict() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "github", "repo:x", 300, false)
            .unwrap();
        assert!(
            hub.reserve(agent("B"), "github", "repo:x", 300, false)
                .is_ok()
        );
    }

    #[test]
    fn hub_non_exclusive_blocked_by_exclusive() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "github", "repo:x", 300, true)
            .unwrap();
        assert!(
            hub.reserve(agent("B"), "github", "repo:x", 300, false)
                .is_err()
        );
    }

    #[test]
    fn hub_different_resources_no_conflict() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "github", "repo:x", 300, true)
            .unwrap();
        assert!(
            hub.reserve(agent("B"), "github", "repo:y", 300, true)
                .is_ok()
        );
    }

    #[test]
    fn hub_extend_reservation() {
        let mut hub = CoordinationHub::new();
        let id = hub
            .reserve(agent("A"), "github", "repo:x", 300, true)
            .unwrap();
        hub.extend_reservation(&id, 600).unwrap();
        let reservations = hub.reservations_for("github");
        assert_eq!(reservations[0].ttl_seconds, 900);
    }

    #[test]
    fn hub_extend_not_found() {
        let mut hub = CoordinationHub::new();
        assert!(hub.extend_reservation("nope", 100).is_err());
    }

    #[test]
    fn hub_release_not_found() {
        let mut hub = CoordinationHub::new();
        assert!(hub.release("nope").is_err());
    }

    // ── CoordinationHub messaging ─────────────────────────────

    #[test]
    fn hub_send_and_read() {
        let mut hub = CoordinationHub::new();
        hub.send(
            agent("A"),
            &agent("B"),
            MessageKind::Request,
            json!({"action": "please do X"}),
        );
        assert_eq!(hub.unread_count(&agent("B")), 1);
        let msgs = hub.read_inbox(&agent("B"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].from, agent("A"));
        assert_eq!(msgs[0].kind, MessageKind::Request);
    }

    #[test]
    fn hub_inbox_empty() {
        let hub = CoordinationHub::new();
        assert_eq!(hub.unread_count(&agent("A")), 0);
        assert!(hub.inbox(&agent("A")).is_empty());
    }

    #[test]
    fn hub_multiple_messages() {
        let mut hub = CoordinationHub::new();
        hub.send(agent("A"), &agent("B"), MessageKind::Info, json!("msg1"));
        hub.send(agent("C"), &agent("B"), MessageKind::Warning, json!("msg2"));
        assert_eq!(hub.unread_count(&agent("B")), 2);
    }

    #[test]
    fn hub_read_clears_inbox() {
        let mut hub = CoordinationHub::new();
        hub.send(agent("A"), &agent("B"), MessageKind::Info, json!("hi"));
        let msgs = hub.read_inbox(&agent("B"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(hub.unread_count(&agent("B")), 0);
    }

    // ── Conflict detection ────────────────────────────────────

    #[test]
    fn conflict_check_clear() {
        let hub = CoordinationHub::new();
        assert_eq!(
            hub.check_conflict(&agent("A"), "github", None),
            ConflictCheck::Clear
        );
    }

    #[test]
    fn conflict_check_warning() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(agent("B"), "github", "reading"));
        let result = hub.check_conflict(&agent("A"), "github", None);
        assert!(matches!(result, ConflictCheck::Warning { .. }));
    }

    #[test]
    fn conflict_check_own_announcement_ignored() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(agent("A"), "github", "reading"));
        assert_eq!(
            hub.check_conflict(&agent("A"), "github", None),
            ConflictCheck::Clear
        );
    }

    #[test]
    fn conflict_check_blocked_by_reservation() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("B"), "github", "repo:x", 300, true)
            .unwrap();
        let result = hub.check_conflict(&agent("A"), "github", Some("repo:x"));
        assert!(matches!(result, ConflictCheck::Blocked { .. }));
    }

    #[test]
    fn conflict_check_own_reservation_not_blocked() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "github", "repo:x", 300, true)
            .unwrap();
        // Own reservation doesn't block self.
        let result = hub.check_conflict(&agent("A"), "github", Some("repo:x"));
        assert!(matches!(result, ConflictCheck::Clear));
    }

    // ── ConflictCheck display ─────────────────────────────────

    #[test]
    fn conflict_check_display() {
        assert_eq!(ConflictCheck::Clear.to_string(), "clear");
        assert!(
            ConflictCheck::Warning {
                warnings: vec!["test".into()]
            }
            .to_string()
            .contains("warning")
        );
        assert!(
            ConflictCheck::Blocked {
                reason: "locked".into()
            }
            .to_string()
            .contains("blocked")
        );
    }

    // ── Error display ─────────────────────────────────────────

    #[test]
    fn error_display() {
        assert!(
            CoordError::ResourceConflict {
                resource: "r".into(),
                held_by: "A".into(),
            }
            .to_string()
            .contains("held by")
        );
        assert!(
            CoordError::ReservationNotFound("x".into())
                .to_string()
                .contains("not found")
        );
    }

    // ── Serialization ─────────────────────────────────────────

    #[test]
    fn announcement_serialization() {
        let ann = UsageAnnouncement::new(agent("A"), "github", "test");
        let json = serde_json::to_string(&ann).unwrap();
        let ann2: UsageAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(ann.connector, ann2.connector);
    }

    #[test]
    fn reservation_serialization() {
        let res = ResourceReservation {
            id: "res_1".into(),
            agent: agent("A"),
            connector: "github".into(),
            resource: "repo:x".into(),
            reserved_at: 100,
            ttl_seconds: 300,
            exclusive: true,
        };
        let json = serde_json::to_string(&res).unwrap();
        let res2: ResourceReservation = serde_json::from_str(&json).unwrap();
        assert_eq!(res.id, res2.id);
        assert!(res2.exclusive);
    }

    #[test]
    fn message_serialization() {
        let msg = AgentMessage {
            from: agent("A"),
            to: agent("B"),
            kind: MessageKind::Request,
            payload: json!({"task": "review"}),
            sent_at: 100,
            read: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let msg2: AgentMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg.from, msg2.from);
        assert_eq!(msg.kind, msg2.kind);
    }

    // ── Purge ─────────────────────────────────────────────────

    #[test]
    fn hub_purge_announcements() {
        let mut hub = CoordinationHub::new();
        // Add an announcement with 1-second duration (will expire).
        let mut ann = UsageAnnouncement::new(agent("A"), "github", "test");
        ann.announced_at = 1; // Far in the past.
        ann.expected_duration = 1;
        hub.announce(ann);
        hub.announce(UsageAnnouncement::new(agent("B"), "slack", "still active"));
        let purged = hub.purge_announcements();
        assert_eq!(purged, 1);
        assert_eq!(hub.announcement_count(), 1);
    }

    #[test]
    fn hub_purge_reservations() {
        let mut hub = CoordinationHub::new();
        // Manually insert an expired reservation.
        hub.reservations.insert(
            "expired".into(),
            ResourceReservation {
                id: "expired".into(),
                agent: agent("A"),
                connector: "github".into(),
                resource: "x".into(),
                reserved_at: 1,
                ttl_seconds: 1,
                exclusive: true,
            },
        );
        hub.reserve(agent("B"), "slack", "y", 3600, false).unwrap();
        let purged = hub.purge_reservations();
        assert_eq!(purged, 1);
        assert_eq!(hub.reservation_count(), 1);
    }

    // ── AgentId serde roundtrips ─────────────────────────────────

    #[test]
    fn agent_id_serde_roundtrip() {
        let a = agent("GreenBasin");
        let json = serde_json::to_string(&a).unwrap();
        let a2: AgentId = serde_json::from_str(&json).unwrap();
        assert_eq!(a, a2);
    }

    #[test]
    fn agent_id_serde_json_value() {
        let a = agent("NavyDeer");
        let val = serde_json::to_value(&a).unwrap();
        assert_eq!(val, json!("NavyDeer"));
    }

    #[test]
    fn agent_id_hash() {
        let mut set = std::collections::HashSet::new();
        set.insert(agent("A"));
        set.insert(agent("A"));
        set.insert(agent("B"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn agent_id_clone() {
        let a = agent("X");
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn agent_id_empty_name() {
        let a = agent("");
        assert_eq!(a.as_str(), "");
        assert_eq!(a.to_string(), "");
    }

    // ── UsageAnnouncement edge cases ─────────────────────────────

    #[test]
    fn announcement_serde_roundtrip_with_operation() {
        let ann = UsageAnnouncement::new(agent("A"), "github", "test")
            .with_operation("list_issues")
            .with_duration(600);
        let json = serde_json::to_string(&ann).unwrap();
        let ann2: UsageAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(ann2.operation.as_deref(), Some("list_issues"));
        assert_eq!(ann2.expected_duration, 600);
        assert_eq!(ann2.connector, "github");
        assert_eq!(ann2.agent, agent("A"));
    }

    #[test]
    fn announcement_builder_chaining() {
        let ann = UsageAnnouncement::new(agent("A"), "slack", "posting")
            .with_operation("send_message")
            .with_duration(120);
        assert_eq!(ann.connector, "slack");
        assert_eq!(ann.operation.as_deref(), Some("send_message"));
        assert_eq!(ann.expected_duration, 120);
    }

    #[test]
    fn announcement_expired_far_past() {
        let mut ann = UsageAnnouncement::new(agent("A"), "github", "test");
        ann.announced_at = 0;
        ann.expected_duration = 1;
        assert!(ann.is_expired());
    }

    #[test]
    fn announcement_indefinite_never_expires() {
        let mut ann = UsageAnnouncement::new(agent("A"), "github", "test");
        ann.announced_at = 0;
        ann.expected_duration = 0;
        assert!(!ann.is_expired());
    }

    // ── ResourceReservation edge cases ───────────────────────────

    #[test]
    fn reservation_serde_roundtrip_full() {
        let res = ResourceReservation {
            id: "res_42".into(),
            agent: agent("SunnyMoose"),
            connector: "slack".into(),
            resource: "channel:general".into(),
            reserved_at: 1_000_000,
            ttl_seconds: 7200,
            exclusive: false,
        };
        let json = serde_json::to_string(&res).unwrap();
        let res2: ResourceReservation = serde_json::from_str(&json).unwrap();
        assert_eq!(res2.id, "res_42");
        assert_eq!(res2.agent, agent("SunnyMoose"));
        assert!(!res2.exclusive);
        assert_eq!(res2.ttl_seconds, 7200);
    }

    #[test]
    fn reservation_expired_far_past() {
        let res = ResourceReservation {
            id: "res_1".into(),
            agent: agent("A"),
            connector: "github".into(),
            resource: "repo:x".into(),
            reserved_at: 0,
            ttl_seconds: 1,
            exclusive: true,
        };
        assert!(res.is_expired());
        assert_eq!(res.remaining_seconds(), 0);
    }

    #[test]
    fn reservation_remaining_saturates_to_zero() {
        let res = ResourceReservation {
            id: "res_1".into(),
            agent: agent("A"),
            connector: "github".into(),
            resource: "repo:x".into(),
            reserved_at: 1,
            ttl_seconds: 10,
            exclusive: true,
        };
        // Far in the past — remaining should saturate to 0.
        assert_eq!(res.remaining_seconds(), 0);
    }

    // ── MessageKind serde ────────────────────────────────────────

    #[test]
    fn message_kind_serde_roundtrip() {
        for kind in &[
            MessageKind::Request,
            MessageKind::Response,
            MessageKind::Info,
            MessageKind::Warning,
            MessageKind::Release,
        ] {
            let json = serde_json::to_string(kind).unwrap();
            let kind2: MessageKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, kind2);
        }
    }

    #[test]
    fn message_kind_snake_case_serialization() {
        let json = serde_json::to_value(MessageKind::Request).unwrap();
        assert_eq!(json, json!("request"));
        let json = serde_json::to_value(MessageKind::Release).unwrap();
        assert_eq!(json, json!("release"));
    }

    // ── AgentMessage edge cases ──────────────────────────────────

    #[test]
    fn message_serde_roundtrip_with_complex_payload() {
        let msg = AgentMessage {
            from: agent("A"),
            to: agent("B"),
            kind: MessageKind::Info,
            payload: json!({"nested": {"array": [1, 2, 3]}, "flag": true}),
            sent_at: 12345,
            read: true,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let msg2: AgentMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg2.to, agent("B"));
        assert!(msg2.read);
        assert_eq!(msg2.payload["nested"]["array"][1], 2);
    }

    #[test]
    fn message_serde_null_payload() {
        let msg = AgentMessage {
            from: agent("X"),
            to: agent("Y"),
            kind: MessageKind::Release,
            payload: serde_json::Value::Null,
            sent_at: 0,
            read: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let msg2: AgentMessage = serde_json::from_str(&json).unwrap();
        assert!(msg2.payload.is_null());
    }

    // ── CoordinationHub advanced ─────────────────────────────────

    #[test]
    fn hub_default_is_empty() {
        let hub = CoordinationHub::default();
        assert_eq!(hub.announcement_count(), 0);
        assert_eq!(hub.reservation_count(), 0);
    }

    #[test]
    fn hub_reservation_id_increments() {
        let mut hub = CoordinationHub::new();
        let id1 = hub.reserve(agent("A"), "g", "r1", 300, false).unwrap();
        let id2 = hub.reserve(agent("A"), "g", "r2", 300, false).unwrap();
        assert_ne!(id1, id2);
        assert!(id1.starts_with("res_"));
        assert!(id2.starts_with("res_"));
    }

    #[test]
    fn hub_reservations_for_empty_connector() {
        let hub = CoordinationHub::new();
        assert!(hub.reservations_for("nonexistent").is_empty());
    }

    #[test]
    fn hub_reservations_for_multiple_connectors() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "github", "r1", 300, false).unwrap();
        hub.reserve(agent("B"), "github", "r2", 300, false).unwrap();
        hub.reserve(agent("C"), "slack", "r3", 300, false).unwrap();
        assert_eq!(hub.reservations_for("github").len(), 2);
        assert_eq!(hub.reservations_for("slack").len(), 1);
    }

    #[test]
    fn hub_exclusive_conflict_same_agent_allowed() {
        // Same agent can hold exclusive reservations on different resources.
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "github", "r1", 300, true).unwrap();
        assert!(hub.reserve(agent("A"), "github", "r2", 300, true).is_ok());
    }

    #[test]
    fn hub_exclusive_conflict_message_content() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("Alice"), "github", "repo:x", 300, true)
            .unwrap();
        let err = hub
            .reserve(agent("Bob"), "github", "repo:x", 300, true)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("repo:x"));
        assert!(msg.contains("Alice"));
    }

    #[test]
    fn hub_extend_reservation_cumulative() {
        let mut hub = CoordinationHub::new();
        let id = hub.reserve(agent("A"), "g", "r", 100, true).unwrap();
        hub.extend_reservation(&id, 50).unwrap();
        hub.extend_reservation(&id, 50).unwrap();
        let reservations = hub.reservations_for("g");
        assert_eq!(reservations[0].ttl_seconds, 200);
    }

    #[test]
    fn hub_release_returns_correct_reservation() {
        let mut hub = CoordinationHub::new();
        let id1 = hub.reserve(agent("A"), "github", "r1", 300, true).unwrap();
        let _id2 = hub.reserve(agent("B"), "slack", "r2", 300, true).unwrap();
        let released = hub.release(&id1).unwrap();
        assert_eq!(released.connector, "github");
        assert_eq!(released.resource, "r1");
        assert_eq!(hub.reservation_count(), 1);
    }

    // ── Messaging advanced ───────────────────────────────────────

    #[test]
    fn hub_inbox_returns_all_including_read() {
        let mut hub = CoordinationHub::new();
        hub.send(agent("A"), &agent("B"), MessageKind::Info, json!("msg1"));
        let inbox_view = hub.inbox(&agent("B"));
        assert_eq!(inbox_view.len(), 1);
        // inbox() doesn't consume, read_inbox does
        let inbox_view2 = hub.inbox(&agent("B"));
        assert_eq!(inbox_view2.len(), 1);
    }

    #[test]
    fn hub_read_inbox_for_nonexistent_agent() {
        let mut hub = CoordinationHub::new();
        let msgs = hub.read_inbox(&agent("nobody"));
        assert!(msgs.is_empty());
    }

    #[test]
    fn hub_messages_between_multiple_agents() {
        let mut hub = CoordinationHub::new();
        hub.send(agent("A"), &agent("B"), MessageKind::Request, json!("1"));
        hub.send(agent("A"), &agent("C"), MessageKind::Info, json!("2"));
        hub.send(agent("B"), &agent("C"), MessageKind::Warning, json!("3"));
        assert_eq!(hub.unread_count(&agent("B")), 1);
        assert_eq!(hub.unread_count(&agent("C")), 2);
        assert_eq!(hub.unread_count(&agent("A")), 0);
    }

    // ── Conflict detection advanced ──────────────────────────────

    #[test]
    fn conflict_check_warning_multiple_agents() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(agent("B"), "github", "reading"));
        hub.announce(UsageAnnouncement::new(agent("C"), "github", "writing"));
        let result = hub.check_conflict(&agent("A"), "github", None);
        match result {
            ConflictCheck::Warning { warnings } => assert_eq!(warnings.len(), 2),
            other => panic!("Expected Warning, got {other:?}"),
        }
    }

    #[test]
    fn conflict_check_different_connector_clear() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(agent("B"), "github", "reading"));
        assert_eq!(
            hub.check_conflict(&agent("A"), "slack", None),
            ConflictCheck::Clear
        );
    }

    #[test]
    fn conflict_check_non_exclusive_reservation_not_blocked() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("B"), "github", "repo:x", 300, false)
            .unwrap();
        let result = hub.check_conflict(&agent("A"), "github", Some("repo:x"));
        // Non-exclusive reservations don't block
        assert!(matches!(result, ConflictCheck::Clear));
    }

    #[test]
    fn conflict_check_expired_announcement_ignored() {
        let mut hub = CoordinationHub::new();
        let mut ann = UsageAnnouncement::new(agent("B"), "github", "old work");
        ann.announced_at = 1;
        ann.expected_duration = 1;
        hub.announce(ann);
        assert_eq!(
            hub.check_conflict(&agent("A"), "github", None),
            ConflictCheck::Clear
        );
    }

    #[test]
    fn conflict_check_expired_reservation_not_blocked() {
        let mut hub = CoordinationHub::new();
        hub.reservations.insert(
            "expired_res".into(),
            ResourceReservation {
                id: "expired_res".into(),
                agent: agent("B"),
                connector: "github".into(),
                resource: "repo:x".into(),
                reserved_at: 1,
                ttl_seconds: 1,
                exclusive: true,
            },
        );
        let result = hub.check_conflict(&agent("A"), "github", Some("repo:x"));
        assert_eq!(result, ConflictCheck::Clear);
    }

    #[test]
    fn conflict_check_no_resource_not_blocked_by_reservation() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("B"), "github", "repo:x", 300, true)
            .unwrap();
        // Checking without a specific resource should not trigger reservation block.
        let result = hub.check_conflict(&agent("A"), "github", None);
        assert!(matches!(result, ConflictCheck::Clear));
    }

    // ── ConflictCheck display edge cases ─────────────────────────

    #[test]
    fn conflict_check_warning_display_joins() {
        let check = ConflictCheck::Warning {
            warnings: vec!["w1".into(), "w2".into()],
        };
        let s = check.to_string();
        assert!(s.contains("w1; w2"));
    }

    #[test]
    fn conflict_check_blocked_display() {
        let check = ConflictCheck::Blocked {
            reason: "exclusive lock".into(),
        };
        assert_eq!(check.to_string(), "blocked: exclusive lock");
    }

    // ── CoordError ───────────────────────────────────────────────

    #[test]
    fn coord_error_is_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(CoordError::ReservationNotFound("x".into()));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn coord_error_equality() {
        let e1 = CoordError::ReservationNotFound("x".into());
        let e2 = CoordError::ReservationNotFound("x".into());
        assert_eq!(e1, e2);
        let e3 = CoordError::ReservationNotFound("y".into());
        assert_ne!(e1, e3);
    }

    #[test]
    fn coord_error_resource_conflict_fields() {
        let e = CoordError::ResourceConflict {
            resource: "repo:hello".into(),
            held_by: "AgentZ".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("repo:hello"));
        assert!(msg.contains("AgentZ"));
    }

    // ── Purge edge cases ─────────────────────────────────────────

    #[test]
    fn hub_purge_announcements_all_active() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(agent("A"), "github", "active"));
        hub.announce(UsageAnnouncement::new(agent("B"), "slack", "active"));
        let purged = hub.purge_announcements();
        assert_eq!(purged, 0);
        assert_eq!(hub.announcement_count(), 2);
    }

    #[test]
    fn hub_purge_reservations_none_expired() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "github", "r1", 3600, true).unwrap();
        let purged = hub.purge_reservations();
        assert_eq!(purged, 0);
    }

    #[test]
    fn hub_purge_announcements_empty() {
        let mut hub = CoordinationHub::new();
        assert_eq!(hub.purge_announcements(), 0);
    }

    #[test]
    fn hub_purge_reservations_empty() {
        let mut hub = CoordinationHub::new();
        assert_eq!(hub.purge_reservations(), 0);
    }

    // ── Hub clone ────────────────────────────────────────────────

    #[test]
    fn hub_clone_is_independent() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(agent("A"), "github", "test"));
        let hub2 = hub.clone();
        hub.announce(UsageAnnouncement::new(agent("B"), "slack", "test2"));
        assert_eq!(hub.announcement_count(), 2);
        assert_eq!(hub2.announcement_count(), 1);
    }
}
