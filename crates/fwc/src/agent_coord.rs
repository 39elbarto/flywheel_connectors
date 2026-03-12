//! Agent Mail integration for multi-agent connector coordination.
//!
//! Provides a coordination layer so multiple agents can announce connector
//! usage, reserve resources, exchange messages, and avoid conflicting
//! operations on the same connector or resource.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

    /// List all active reservations across connectors.
    pub fn active_reservations(&self) -> Vec<&ResourceReservation> {
        self.reservations
            .values()
            .filter(|r| !r.is_expired())
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

    /// Peek at all messages in an agent's inbox (non-consuming).
    pub fn inbox(&self, agent: &AgentId) -> Vec<&AgentMessage> {
        self.inboxes
            .get(agent.as_str())
            .map(|msgs| msgs.iter().collect())
            .unwrap_or_default()
    }

    /// Drain all messages from an agent's inbox, returning them.
    pub fn read_inbox(&mut self, agent: &AgentId) -> Vec<AgentMessage> {
        self.inboxes
            .get_mut(agent.as_str())
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// Count messages in an agent's inbox.
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

    /// Purge all expired coordination state and return the number removed.
    pub fn cleanup_expired(&mut self) -> usize {
        self.purge_announcements() + self.purge_reservations()
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

// ── Persistence ──────────────────────────────────────────────────

/// File-backed coordination state stored under `~/.fwc/agent_mail/`.
pub struct CoordinationStore {
    path: PathBuf,
}

impl CoordinationStore {
    /// Create a store at the default location.
    #[must_use]
    pub fn default_path() -> Self {
        if let Ok(path) = std::env::var("FWC_AGENT_COORD_PATH")
            && !path.trim().is_empty()
        {
            return Self {
                path: PathBuf::from(path),
            };
        }

        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_or_else(|_| PathBuf::from("."), PathBuf::from);
        Self {
            path: home
                .join(".fwc")
                .join("agent_mail")
                .join("coordination.json"),
        }
    }

    /// Create a store at a custom path (primarily for testing).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Return the underlying file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the coordination hub from disk, returning an empty hub if no file exists yet.
    pub fn load(&self) -> anyhow::Result<CoordinationHub> {
        if !self.path.exists() {
            return Ok(CoordinationHub::new());
        }

        let raw = std::fs::read_to_string(&self.path).with_context(|| {
            format!(
                "failed to read coordination store `{}`",
                self.path.display()
            )
        })?;
        serde_json::from_str(&raw).with_context(|| {
            format!(
                "failed to parse coordination store `{}`",
                self.path.display()
            )
        })
    }

    /// Persist the coordination hub atomically.
    pub fn save(&self, hub: &CoordinationHub) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create the parent directory for `{}`",
                    self.path.display()
                )
            })?;
        }

        let tmp_path = coordination_tmp_path(&self.path);
        let raw =
            serde_json::to_string_pretty(hub).context("failed to serialize coordination state")?;
        std::fs::write(&tmp_path, raw)
            .with_context(|| format!("failed to write `{}`", tmp_path.display()))?;
        if self.path.exists() {
            std::fs::remove_file(&self.path).with_context(|| {
                format!(
                    "failed to replace the existing coordination store `{}`",
                    self.path.display()
                )
            })?;
        }
        std::fs::rename(&tmp_path, &self.path).with_context(|| {
            format!(
                "failed to persist coordination state from `{}` to `{}`",
                tmp_path.display(),
                self.path.display()
            )
        })?;
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn coordination_tmp_path(path: &Path) -> PathBuf {
    path.with_extension("tmp")
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

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

    #[test]
    fn coordination_store_load_missing_returns_empty_hub() {
        let dir = TempDir::new().unwrap();
        let store = CoordinationStore::new(dir.path().join("coordination.json"));
        let hub = store.load().unwrap();
        assert_eq!(hub.announcement_count(), 0);
        assert_eq!(hub.reservation_count(), 0);
    }

    #[test]
    fn coordination_store_round_trips_announcements_reservations_and_mail() {
        let dir = TempDir::new().unwrap();
        let store = CoordinationStore::new(dir.path().join("coordination.json"));

        let mut hub = CoordinationHub::new();
        hub.announce(
            UsageAnnouncement::new(agent("BronzeValley"), "github", "triage")
                .with_operation("issues.create")
                .with_duration(300),
        );
        let reservation_id = hub
            .reserve(
                agent("BronzeValley"),
                "github",
                "repo:octocat/hello-world",
                120,
                true,
            )
            .unwrap();
        hub.send(
            agent("BronzeValley"),
            &agent("GoldenWolf"),
            MessageKind::Info,
            json!({"task":"flywheel_connectors-qnchs.13.3"}),
        );

        store.save(&hub).unwrap();
        let loaded = store.load().unwrap();

        assert_eq!(loaded.announcement_count(), 1);
        assert_eq!(loaded.reservation_count(), 1);
        assert_eq!(loaded.active_reservations()[0].id, reservation_id);
        assert_eq!(loaded.inbox(&agent("GoldenWolf")).len(), 1);
    }

    // ── AgentId additional ──────────────────────────────────────

    #[test]
    fn agent_id_debug_format() {
        let a = agent("TestAgent");
        let dbg = format!("{a:?}");
        assert!(dbg.contains("TestAgent"));
    }

    #[test]
    fn agent_id_from_string_owned() {
        let name = String::from("OwnedName");
        let a = AgentId::new(name);
        assert_eq!(a.as_str(), "OwnedName");
    }

    #[test]
    fn agent_id_unicode_name() {
        let a = agent("Agente\u{00e9}");
        assert_eq!(a.as_str(), "Agente\u{00e9}");
        assert_eq!(a.to_string(), "Agente\u{00e9}");
    }

    #[test]
    fn agent_id_whitespace_name() {
        let a = agent("  spaced  ");
        assert_eq!(a.as_str(), "  spaced  ");
    }

    #[test]
    fn agent_id_long_name() {
        let name = "A".repeat(1000);
        let a = AgentId::new(name.clone());
        assert_eq!(a.as_str(), name);
    }

    #[test]
    fn agent_id_clone_independence() {
        let a = agent("Original");
        let b = a.clone();
        assert_eq!(a.as_str(), b.as_str());
        // Both are independent values.
        assert_eq!(a, b);
    }

    #[test]
    fn agent_id_ne_case_sensitive() {
        assert_ne!(agent("abc"), agent("ABC"));
    }

    // ── UsageAnnouncement additional ────────────────────────────

    #[test]
    fn announcement_clone_independence() {
        let ann = UsageAnnouncement::new(agent("A"), "github", "test")
            .with_operation("op1")
            .with_duration(100);
        let ann2 = ann.clone();
        assert_eq!(ann.connector, ann2.connector);
        assert_eq!(ann.operation, ann2.operation);
        assert_eq!(ann.expected_duration, ann2.expected_duration);
        assert_eq!(ann.agent, ann2.agent);
    }

    #[test]
    fn announcement_debug_format() {
        let ann = UsageAnnouncement::new(agent("A"), "github", "test");
        let dbg = format!("{ann:?}");
        assert!(dbg.contains("github"));
        assert!(dbg.contains("UsageAnnouncement"));
    }

    #[test]
    fn announcement_empty_connector() {
        let ann = UsageAnnouncement::new(agent("A"), "", "test");
        assert_eq!(ann.connector, "");
    }

    #[test]
    fn announcement_empty_purpose() {
        let ann = UsageAnnouncement::new(agent("A"), "github", "");
        assert_eq!(ann.purpose, "");
    }

    #[test]
    fn announcement_max_duration() {
        let ann = UsageAnnouncement::new(agent("A"), "g", "t").with_duration(u64::MAX);
        assert_eq!(ann.expected_duration, u64::MAX);
        // With announced_at being epoch_seconds(), this will never expire via subtraction.
        assert!(!ann.is_expired());
    }

    #[test]
    fn announcement_with_operation_replaces_none() {
        let ann = UsageAnnouncement::new(agent("A"), "g", "t");
        assert!(ann.operation.is_none());
        let ann = ann.with_operation("op");
        assert_eq!(ann.operation.as_deref(), Some("op"));
    }

    #[test]
    fn announcement_chained_with_operation_overwrites() {
        let ann = UsageAnnouncement::new(agent("A"), "g", "t")
            .with_operation("first")
            .with_operation("second");
        assert_eq!(ann.operation.as_deref(), Some("second"));
    }

    #[test]
    fn announcement_chained_with_duration_overwrites() {
        let ann = UsageAnnouncement::new(agent("A"), "g", "t")
            .with_duration(100)
            .with_duration(200);
        assert_eq!(ann.expected_duration, 200);
    }

    #[test]
    fn announcement_serde_preserves_null_operation() {
        let ann = UsageAnnouncement::new(agent("A"), "github", "test");
        let json = serde_json::to_string(&ann).unwrap();
        let ann2: UsageAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(ann2.operation.is_none());
    }

    #[test]
    fn announcement_announced_at_is_recent() {
        let before = epoch_seconds();
        let ann = UsageAnnouncement::new(agent("A"), "g", "t");
        let after = epoch_seconds();
        assert!(ann.announced_at >= before);
        assert!(ann.announced_at <= after);
    }

    // ── ResourceReservation additional ──────────────────────────

    #[test]
    fn reservation_debug_format() {
        let res = ResourceReservation {
            id: "res_99".into(),
            agent: agent("Z"),
            connector: "jira".into(),
            resource: "issue:123".into(),
            reserved_at: 500,
            ttl_seconds: 100,
            exclusive: false,
        };
        let dbg = format!("{res:?}");
        assert!(dbg.contains("res_99"));
        assert!(dbg.contains("jira"));
    }

    #[test]
    fn reservation_clone_independence() {
        let res = ResourceReservation {
            id: "res_1".into(),
            agent: agent("A"),
            connector: "github".into(),
            resource: "r".into(),
            reserved_at: epoch_seconds(),
            ttl_seconds: 300,
            exclusive: true,
        };
        let res2 = res.clone();
        assert_eq!(res.id, res2.id);
        assert_eq!(res.agent, res2.agent);
        assert_eq!(res.exclusive, res2.exclusive);
    }

    #[test]
    fn reservation_zero_reserved_at_with_zero_ttl() {
        let res = ResourceReservation {
            id: "r".into(),
            agent: agent("A"),
            connector: "c".into(),
            resource: "x".into(),
            reserved_at: 0,
            ttl_seconds: 0,
            exclusive: false,
        };
        assert!(!res.is_expired());
        assert_eq!(res.remaining_seconds(), u64::MAX);
    }

    #[test]
    fn reservation_max_ttl_not_expired() {
        let res = ResourceReservation {
            id: "r".into(),
            agent: agent("A"),
            connector: "c".into(),
            resource: "x".into(),
            reserved_at: epoch_seconds(),
            ttl_seconds: u64::MAX,
            exclusive: true,
        };
        assert!(!res.is_expired());
    }

    #[test]
    fn reservation_remaining_for_active_reservation() {
        let now = epoch_seconds();
        let res = ResourceReservation {
            id: "r".into(),
            agent: agent("A"),
            connector: "c".into(),
            resource: "x".into(),
            reserved_at: now,
            ttl_seconds: 600,
            exclusive: false,
        };
        let remaining = res.remaining_seconds();
        assert!(remaining > 590);
        assert!(remaining <= 600);
    }

    // ── AgentMessage additional ─────────────────────────────────

    #[test]
    fn message_clone_independence() {
        let msg = AgentMessage {
            from: agent("A"),
            to: agent("B"),
            kind: MessageKind::Info,
            payload: json!({"key": "value"}),
            sent_at: 100,
            read: false,
        };
        let msg2 = msg.clone();
        assert_eq!(msg.from, msg2.from);
        assert_eq!(msg.to, msg2.to);
        assert_eq!(msg.kind, msg2.kind);
        assert_eq!(msg.payload, msg2.payload);
        assert_eq!(msg.sent_at, msg2.sent_at);
        assert_eq!(msg.read, msg2.read);
    }

    #[test]
    fn message_debug_format() {
        let msg = AgentMessage {
            from: agent("Sender"),
            to: agent("Receiver"),
            kind: MessageKind::Warning,
            payload: json!("alert"),
            sent_at: 999,
            read: true,
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Sender"));
        assert!(dbg.contains("Receiver"));
        assert!(dbg.contains("Warning"));
    }

    #[test]
    fn message_serde_with_string_payload() {
        let msg = AgentMessage {
            from: agent("A"),
            to: agent("B"),
            kind: MessageKind::Response,
            payload: json!("just a string"),
            sent_at: 42,
            read: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let msg2: AgentMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg2.payload, json!("just a string"));
    }

    #[test]
    fn message_serde_with_array_payload() {
        let msg = AgentMessage {
            from: agent("A"),
            to: agent("B"),
            kind: MessageKind::Info,
            payload: json!([1, "two", null, true]),
            sent_at: 0,
            read: true,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let msg2: AgentMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg2.payload[2], serde_json::Value::Null);
        assert_eq!(msg2.payload[1], "two");
    }

    #[test]
    fn message_serde_with_numeric_payload() {
        let msg = AgentMessage {
            from: agent("A"),
            to: agent("B"),
            kind: MessageKind::Request,
            payload: json!(42),
            sent_at: 0,
            read: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let msg2: AgentMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg2.payload, json!(42));
    }

    #[test]
    fn message_serde_with_bool_payload() {
        let msg = AgentMessage {
            from: agent("A"),
            to: agent("B"),
            kind: MessageKind::Release,
            payload: json!(false),
            sent_at: 0,
            read: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let msg2: AgentMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg2.payload, json!(false));
    }

    // ── MessageKind additional ──────────────────────────────────

    #[test]
    fn message_kind_clone() {
        let k = MessageKind::Warning;
        let k2 = k.clone();
        assert_eq!(k, k2);
    }

    #[test]
    fn message_kind_debug_format() {
        let dbg = format!("{:?}", MessageKind::Request);
        assert_eq!(dbg, "Request");
        let dbg = format!("{:?}", MessageKind::Release);
        assert_eq!(dbg, "Release");
    }

    #[test]
    fn message_kind_ne() {
        assert_ne!(MessageKind::Request, MessageKind::Response);
        assert_ne!(MessageKind::Info, MessageKind::Warning);
        assert_ne!(MessageKind::Warning, MessageKind::Release);
    }

    #[test]
    fn message_kind_deserialize_invalid() {
        let result = serde_json::from_str::<MessageKind>("\"invalid_kind\"");
        assert!(result.is_err());
    }

    // ── CoordinationHub advanced reservation scenarios ───────────

    #[test]
    fn hub_reserve_many_resources_same_connector() {
        let mut hub = CoordinationHub::new();
        for i in 0..10 {
            hub.reserve(agent("A"), "github", format!("r{i}"), 300, true)
                .unwrap();
        }
        assert_eq!(hub.reservation_count(), 10);
        assert_eq!(hub.reservations_for("github").len(), 10);
    }

    #[test]
    fn hub_reserve_same_resource_different_connectors() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "github", "repo:x", 300, true)
            .unwrap();
        hub.reserve(agent("A"), "slack", "repo:x", 300, true)
            .unwrap();
        assert_eq!(hub.reservation_count(), 2);
    }

    #[test]
    fn hub_active_reservations_filters_expired() {
        let mut hub = CoordinationHub::new();
        hub.reservations.insert(
            "expired".into(),
            ResourceReservation {
                id: "expired".into(),
                agent: agent("A"),
                connector: "g".into(),
                resource: "r".into(),
                reserved_at: 1,
                ttl_seconds: 1,
                exclusive: true,
            },
        );
        hub.reserve(agent("B"), "g", "r2", 3600, false).unwrap();
        let active = hub.active_reservations();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].agent, agent("B"));
    }

    #[test]
    fn hub_reservation_id_format() {
        let mut hub = CoordinationHub::new();
        let id = hub.reserve(agent("A"), "g", "r", 300, false).unwrap();
        assert!(id.starts_with("res_"));
        let num: u64 = id.strip_prefix("res_").unwrap().parse().unwrap();
        assert!(num > 0);
    }

    #[test]
    fn hub_exclusive_same_agent_same_resource_conflicts() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "g", "r", 300, true).unwrap();
        // Even the same agent can't double-reserve exclusively.
        let err = hub.reserve(agent("A"), "g", "r", 300, true).unwrap_err();
        assert!(matches!(err, CoordError::ResourceConflict { .. }));
    }

    #[test]
    fn hub_non_exclusive_multiple_agents_same_resource() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("A"), "g", "r", 300, false).unwrap();
        hub.reserve(agent("B"), "g", "r", 300, false).unwrap();
        hub.reserve(agent("C"), "g", "r", 300, false).unwrap();
        assert_eq!(hub.reservation_count(), 3);
    }

    #[test]
    fn hub_release_then_re_reserve() {
        let mut hub = CoordinationHub::new();
        let id = hub.reserve(agent("A"), "g", "r", 300, true).unwrap();
        hub.release(&id).unwrap();
        // After release, another agent can exclusively reserve.
        let id2 = hub.reserve(agent("B"), "g", "r", 300, true).unwrap();
        assert_ne!(id, id2);
        assert_eq!(hub.reservation_count(), 1);
    }

    #[test]
    fn hub_extend_reservation_zero_seconds() {
        let mut hub = CoordinationHub::new();
        let id = hub.reserve(agent("A"), "g", "r", 100, true).unwrap();
        hub.extend_reservation(&id, 0).unwrap();
        let reservations = hub.reservations_for("g");
        assert_eq!(reservations[0].ttl_seconds, 100);
    }

    #[test]
    fn hub_release_double_fails() {
        let mut hub = CoordinationHub::new();
        let id = hub.reserve(agent("A"), "g", "r", 300, true).unwrap();
        hub.release(&id).unwrap();
        let err = hub.release(&id).unwrap_err();
        assert!(matches!(err, CoordError::ReservationNotFound(_)));
    }

    // ── CoordinationHub announcements advanced ──────────────────

    #[test]
    fn hub_many_announcements_same_connector() {
        let mut hub = CoordinationHub::new();
        for i in 0..20 {
            hub.announce(UsageAnnouncement::new(
                agent(&format!("Agent{i}")),
                "github",
                format!("purpose {i}"),
            ));
        }
        assert_eq!(hub.announcement_count(), 20);
        assert_eq!(hub.announcements_for("github").len(), 20);
    }

    #[test]
    fn hub_active_announcements_filters_expired() {
        let mut hub = CoordinationHub::new();
        let mut expired = UsageAnnouncement::new(agent("A"), "github", "old");
        expired.announced_at = 1;
        expired.expected_duration = 1;
        hub.announce(expired);
        hub.announce(UsageAnnouncement::new(agent("B"), "github", "fresh"));
        let active = hub.active_announcements();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].agent, agent("B"));
    }

    #[test]
    fn hub_announcements_for_filters_expired() {
        let mut hub = CoordinationHub::new();
        let mut expired = UsageAnnouncement::new(agent("A"), "github", "old");
        expired.announced_at = 1;
        expired.expected_duration = 1;
        hub.announce(expired);
        hub.announce(UsageAnnouncement::new(agent("B"), "github", "fresh"));
        assert_eq!(hub.announcements_for("github").len(), 1);
    }

    // ── CoordinationHub messaging advanced ──────────────────────

    #[test]
    fn hub_send_message_to_self() {
        let mut hub = CoordinationHub::new();
        hub.send(
            agent("A"),
            &agent("A"),
            MessageKind::Info,
            json!("self-note"),
        );
        assert_eq!(hub.unread_count(&agent("A")), 1);
        let msgs = hub.inbox(&agent("A"));
        assert_eq!(msgs[0].from, agent("A"));
        assert_eq!(msgs[0].to, agent("A"));
    }

    #[test]
    fn hub_read_inbox_then_new_messages() {
        let mut hub = CoordinationHub::new();
        hub.send(agent("A"), &agent("B"), MessageKind::Info, json!("first"));
        let msgs = hub.read_inbox(&agent("B"));
        assert_eq!(msgs.len(), 1);
        // Inbox is now empty.
        assert_eq!(hub.unread_count(&agent("B")), 0);
        // New message arrives.
        hub.send(agent("C"), &agent("B"), MessageKind::Warning, json!("second"));
        assert_eq!(hub.unread_count(&agent("B")), 1);
        let msgs2 = hub.read_inbox(&agent("B"));
        assert_eq!(msgs2.len(), 1);
        assert_eq!(msgs2[0].from, agent("C"));
    }

    #[test]
    fn hub_unread_count_empty_inbox_no_panic() {
        let hub = CoordinationHub::new();
        // Agent never received any messages.
        assert_eq!(hub.unread_count(&agent("ghost")), 0);
    }

    #[test]
    fn hub_send_many_messages_ordering() {
        let mut hub = CoordinationHub::new();
        for i in 0..5 {
            hub.send(
                agent("Sender"),
                &agent("Receiver"),
                MessageKind::Info,
                json!(i),
            );
        }
        let msgs = hub.inbox(&agent("Receiver"));
        assert_eq!(msgs.len(), 5);
        // Messages should be in insertion order.
        for (i, msg) in msgs.iter().enumerate() {
            assert_eq!(msg.payload, json!(i));
        }
    }

    #[test]
    fn hub_inbox_peek_does_not_consume() {
        let mut hub = CoordinationHub::new();
        hub.send(agent("A"), &agent("B"), MessageKind::Info, json!("msg"));
        let first = hub.inbox(&agent("B"));
        let second = hub.inbox(&agent("B"));
        assert_eq!(first.len(), second.len());
        assert_eq!(hub.unread_count(&agent("B")), 1);
    }

    #[test]
    fn hub_messages_from_different_senders() {
        let mut hub = CoordinationHub::new();
        hub.send(agent("A"), &agent("D"), MessageKind::Request, json!("a"));
        hub.send(agent("B"), &agent("D"), MessageKind::Response, json!("b"));
        hub.send(agent("C"), &agent("D"), MessageKind::Release, json!("c"));
        let inbox = hub.inbox(&agent("D"));
        assert_eq!(inbox.len(), 3);
        assert_eq!(inbox[0].from, agent("A"));
        assert_eq!(inbox[1].from, agent("B"));
        assert_eq!(inbox[2].from, agent("C"));
    }

    // ── Conflict detection additional ───────────────────────────

    #[test]
    fn conflict_check_warning_and_blocked_prefers_blocked() {
        let mut hub = CoordinationHub::new();
        // Add announcement from B (would cause warning).
        hub.announce(UsageAnnouncement::new(agent("B"), "github", "reading"));
        // Add exclusive reservation from C (would cause blocked).
        hub.reserve(agent("C"), "github", "repo:x", 300, true)
            .unwrap();
        let result = hub.check_conflict(&agent("A"), "github", Some("repo:x"));
        // Blocked takes priority.
        assert!(matches!(result, ConflictCheck::Blocked { .. }));
    }

    #[test]
    fn conflict_check_warning_content() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(
            agent("Bob"),
            "github",
            "code review",
        ));
        let result = hub.check_conflict(&agent("Alice"), "github", None);
        match result {
            ConflictCheck::Warning { warnings } => {
                assert_eq!(warnings.len(), 1);
                assert!(warnings[0].contains("Bob"));
                assert!(warnings[0].contains("github"));
                assert!(warnings[0].contains("code review"));
            }
            other => panic!("Expected Warning, got {other:?}"),
        }
    }

    #[test]
    fn conflict_check_blocked_content() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("Carol"), "github", "repo:main", 300, true)
            .unwrap();
        let result = hub.check_conflict(&agent("Dave"), "github", Some("repo:main"));
        match result {
            ConflictCheck::Blocked { reason } => {
                assert!(reason.contains("repo:main"));
                assert!(reason.contains("Carol"));
            }
            other => panic!("Expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn conflict_check_different_resource_not_blocked() {
        let mut hub = CoordinationHub::new();
        hub.reserve(agent("B"), "github", "repo:x", 300, true)
            .unwrap();
        let result = hub.check_conflict(&agent("A"), "github", Some("repo:y"));
        assert!(matches!(result, ConflictCheck::Clear));
    }

    // ── ConflictCheck additional ────────────────────────────────

    #[test]
    fn conflict_check_clone() {
        let c1 = ConflictCheck::Warning {
            warnings: vec!["w1".into()],
        };
        let c2 = c1.clone();
        assert_eq!(c1, c2);
    }

    #[test]
    fn conflict_check_debug() {
        let c = ConflictCheck::Clear;
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Clear"));
    }

    #[test]
    fn conflict_check_blocked_debug() {
        let c = ConflictCheck::Blocked {
            reason: "locked".into(),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Blocked"));
        assert!(dbg.contains("locked"));
    }

    #[test]
    fn conflict_check_warning_empty_vec_display() {
        let c = ConflictCheck::Warning {
            warnings: vec![],
        };
        assert_eq!(c.to_string(), "warning: ");
    }

    #[test]
    fn conflict_check_equality_variants() {
        assert_eq!(ConflictCheck::Clear, ConflictCheck::Clear);
        assert_ne!(ConflictCheck::Clear, ConflictCheck::Blocked { reason: "x".into() });
        assert_ne!(
            ConflictCheck::Warning { warnings: vec!["a".into()] },
            ConflictCheck::Warning { warnings: vec!["b".into()] }
        );
    }

    // ── CoordError additional ───────────────────────────────────

    #[test]
    fn coord_error_clone() {
        let e = CoordError::ResourceConflict {
            resource: "r".into(),
            held_by: "A".into(),
        };
        let e2 = e.clone();
        assert_eq!(e, e2);
    }

    #[test]
    fn coord_error_debug_format() {
        let e = CoordError::ReservationNotFound("xyz".into());
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ReservationNotFound"));
        assert!(dbg.contains("xyz"));
    }

    #[test]
    fn coord_error_resource_conflict_debug() {
        let e = CoordError::ResourceConflict {
            resource: "repo:hello".into(),
            held_by: "AgentZ".into(),
        };
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ResourceConflict"));
        assert!(dbg.contains("repo:hello"));
    }

    #[test]
    fn coord_error_source_is_none() {
        let e = CoordError::ReservationNotFound("x".into());
        let err: &dyn std::error::Error = &e;
        assert!(err.source().is_none());
    }

    #[test]
    fn coord_error_resource_conflict_ne_different_resource() {
        let e1 = CoordError::ResourceConflict {
            resource: "r1".into(),
            held_by: "A".into(),
        };
        let e2 = CoordError::ResourceConflict {
            resource: "r2".into(),
            held_by: "A".into(),
        };
        assert_ne!(e1, e2);
    }

    #[test]
    fn coord_error_resource_conflict_ne_different_holder() {
        let e1 = CoordError::ResourceConflict {
            resource: "r".into(),
            held_by: "A".into(),
        };
        let e2 = CoordError::ResourceConflict {
            resource: "r".into(),
            held_by: "B".into(),
        };
        assert_ne!(e1, e2);
    }

    #[test]
    fn coord_error_different_variants_ne() {
        let e1 = CoordError::ReservationNotFound("r".into());
        let e2 = CoordError::ResourceConflict {
            resource: "r".into(),
            held_by: "A".into(),
        };
        assert_ne!(e1, e2);
    }

    // ── cleanup_expired ─────────────────────────────────────────

    #[test]
    fn hub_cleanup_expired_both_types() {
        let mut hub = CoordinationHub::new();
        // Add expired announcement.
        let mut ann = UsageAnnouncement::new(agent("A"), "github", "old");
        ann.announced_at = 1;
        ann.expected_duration = 1;
        hub.announce(ann);
        // Add expired reservation.
        hub.reservations.insert(
            "expired_r".into(),
            ResourceReservation {
                id: "expired_r".into(),
                agent: agent("B"),
                connector: "slack".into(),
                resource: "ch".into(),
                reserved_at: 1,
                ttl_seconds: 1,
                exclusive: false,
            },
        );
        // Add active entries.
        hub.announce(UsageAnnouncement::new(agent("C"), "jira", "active"));
        hub.reserve(agent("D"), "jira", "issue:1", 3600, true).unwrap();
        let removed = hub.cleanup_expired();
        assert_eq!(removed, 2);
        assert_eq!(hub.announcement_count(), 1);
        assert_eq!(hub.reservation_count(), 1);
    }

    #[test]
    fn hub_cleanup_expired_nothing_to_remove() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(agent("A"), "g", "active"));
        hub.reserve(agent("B"), "g", "r", 3600, false).unwrap();
        assert_eq!(hub.cleanup_expired(), 0);
    }

    #[test]
    fn hub_cleanup_expired_empty_hub() {
        let mut hub = CoordinationHub::new();
        assert_eq!(hub.cleanup_expired(), 0);
    }

    // ── CoordinationHub serialization ───────────────────────────

    #[test]
    fn hub_serde_roundtrip_full_state() {
        let mut hub = CoordinationHub::new();
        hub.announce(UsageAnnouncement::new(agent("A"), "github", "triage"));
        hub.announce(
            UsageAnnouncement::new(agent("B"), "slack", "posting")
                .with_operation("send")
                .with_duration(120),
        );
        hub.reserve(agent("A"), "github", "repo:x", 3600, true).unwrap();
        hub.reserve(agent("B"), "slack", "channel:gen", 600, false).unwrap();
        hub.send(agent("A"), &agent("B"), MessageKind::Request, json!({"action": "review"}));
        hub.send(agent("B"), &agent("A"), MessageKind::Response, json!("ok"));

        let json = serde_json::to_string(&hub).unwrap();
        let hub2: CoordinationHub = serde_json::from_str(&json).unwrap();

        assert_eq!(hub2.announcement_count(), 2);
        assert_eq!(hub2.reservation_count(), 2);
        assert_eq!(hub2.inbox(&agent("B")).len(), 1);
        assert_eq!(hub2.inbox(&agent("A")).len(), 1);
    }

    #[test]
    fn hub_serde_empty() {
        let hub = CoordinationHub::new();
        let json = serde_json::to_string(&hub).unwrap();
        let hub2: CoordinationHub = serde_json::from_str(&json).unwrap();
        assert_eq!(hub2.announcement_count(), 0);
        assert_eq!(hub2.reservation_count(), 0);
    }

    #[test]
    fn hub_debug_format() {
        let hub = CoordinationHub::new();
        let dbg = format!("{hub:?}");
        assert!(dbg.contains("CoordinationHub"));
    }

    // ── CoordinationStore additional ────────────────────────────

    #[test]
    fn store_path_returns_configured_path() {
        let store = CoordinationStore::new("/tmp/test/coord.json");
        assert_eq!(store.path(), Path::new("/tmp/test/coord.json"));
    }

    #[test]
    fn store_save_creates_parent_dirs() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("deep").join("nested").join("coord.json");
        let store = CoordinationStore::new(&nested);
        let hub = CoordinationHub::new();
        store.save(&hub).unwrap();
        assert!(nested.exists());
    }

    #[test]
    fn store_save_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("coord.json");
        let store = CoordinationStore::new(&path);

        let mut hub1 = CoordinationHub::new();
        hub1.announce(UsageAnnouncement::new(agent("A"), "g", "first"));
        store.save(&hub1).unwrap();

        let mut hub2 = CoordinationHub::new();
        hub2.announce(UsageAnnouncement::new(agent("B"), "s", "second"));
        hub2.announce(UsageAnnouncement::new(agent("C"), "j", "third"));
        store.save(&hub2).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.announcement_count(), 2);
    }

    #[test]
    fn store_load_corrupt_data_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("coord.json");
        std::fs::write(&path, "not valid json!!!").unwrap();
        let store = CoordinationStore::new(&path);
        assert!(store.load().is_err());
    }

    #[test]
    fn store_load_empty_json_object() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("coord.json");
        // CoordinationHub has defaults, so an object with just the required shape should work.
        std::fs::write(&path, r#"{"announcements":[],"reservations":{},"inboxes":{},"next_reservation_id":0}"#).unwrap();
        let store = CoordinationStore::new(&path);
        let hub = store.load().unwrap();
        assert_eq!(hub.announcement_count(), 0);
    }

    #[test]
    fn store_save_and_load_preserves_messages() {
        let dir = TempDir::new().unwrap();
        let store = CoordinationStore::new(dir.path().join("coord.json"));
        let mut hub = CoordinationHub::new();
        hub.send(agent("X"), &agent("Y"), MessageKind::Warning, json!({"level": 5}));
        hub.send(agent("Y"), &agent("X"), MessageKind::Release, json!(null));
        store.save(&hub).unwrap();

        let loaded = store.load().unwrap();
        assert_eq!(loaded.unread_count(&agent("Y")), 1);
        assert_eq!(loaded.unread_count(&agent("X")), 1);
    }

    #[test]
    fn store_save_and_load_preserves_reservation_ids() {
        let dir = TempDir::new().unwrap();
        let store = CoordinationStore::new(dir.path().join("coord.json"));
        let mut hub = CoordinationHub::new();
        let id1 = hub.reserve(agent("A"), "g", "r1", 3600, true).unwrap();
        let id2 = hub.reserve(agent("B"), "g", "r2", 3600, false).unwrap();
        store.save(&hub).unwrap();

        let loaded = store.load().unwrap();
        let active = loaded.active_reservations();
        let ids: Vec<&str> = active.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&id1.as_str()));
        assert!(ids.contains(&id2.as_str()));
    }

    // ── coordination_tmp_path ───────────────────────────────────

    #[test]
    fn tmp_path_replaces_extension() {
        let p = coordination_tmp_path(Path::new("/foo/bar/coord.json"));
        assert_eq!(p, PathBuf::from("/foo/bar/coord.tmp"));
    }

    #[test]
    fn tmp_path_no_extension() {
        let p = coordination_tmp_path(Path::new("/foo/bar/coord"));
        assert_eq!(p, PathBuf::from("/foo/bar/coord.tmp"));
    }

    #[test]
    fn tmp_path_double_extension() {
        let p = coordination_tmp_path(Path::new("/foo/bar/coord.json.bak"));
        assert_eq!(p, PathBuf::from("/foo/bar/coord.json.tmp"));
    }
}
