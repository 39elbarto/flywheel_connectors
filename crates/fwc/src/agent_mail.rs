//! Agent Mail integration for multi-agent connector coordination.
//!
//! Provides typed messaging, resource reservation, and workflow coordination
//! between autonomous agents operating on connectors in the FCP mesh.
//!
//! # Design principles
//!
//! - Every agent has a unique `AgentId` in `PascalCase` two-word format.
//! - Messages are typed via `MessageBody` variants, not free-form strings.
//! - Resource reservations prevent conflicting concurrent operations.
//! - Workflow coordination enables sequential multi-agent pipelines.
//! - All state is persisted to `~/.fwc/agent_mail/` as JSONL files.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Agent identity ───────────────────────────────────────────────────────

/// Unique agent identifier in `PascalCase` two-word format (e.g. `"SunnyMoose"`).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct AgentId(String);

impl AgentId {
    /// Parse a string into an `AgentId`, validating the `PascalCase` two-word format.
    ///
    /// A valid agent name consists of exactly two `PascalCase` words concatenated,
    /// each starting with an uppercase ASCII letter followed by one or more
    /// lowercase ASCII letters.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let words = split_pascal_words(s)?;
        if words.len() == 2 {
            Some(Self(s.to_owned()))
        } else {
            None
        }
    }

    /// Return the inner string as a slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Split a `PascalCase` string into its constituent words.
///
/// Returns `None` if the string is empty, starts with a lowercase letter, or
/// contains non-ASCII-alpha characters.
fn split_pascal_words(s: &str) -> Option<Vec<String>> {
    if s.is_empty() {
        return None;
    }
    let chars: Vec<char> = s.chars().collect();
    if !chars[0].is_ascii_uppercase() {
        return None;
    }
    let mut words = Vec::new();
    let mut current = String::new();
    for &ch in &chars {
        if !ch.is_ascii_alphabetic() {
            return None;
        }
        if ch.is_ascii_uppercase() {
            if !current.is_empty() {
                words.push(current);
                current = String::new();
            }
        } else if current.is_empty() {
            return None;
        }
        current.push(ch);
    }
    if !current.is_empty() {
        words.push(current);
    }
    // Each word must have at least 2 chars (1 uppercase + 1 lowercase)
    if words.iter().all(|w| w.len() >= 2) {
        Some(words)
    } else {
        None
    }
}

/// Agent profile with model metadata and capabilities.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentProfile {
    /// Unique agent identifier.
    pub id: AgentId,
    /// Model name (e.g. `"claude-opus-4-6"`).
    pub model: String,
    /// Provider (e.g. `"anthropic"`).
    pub provider: String,
    /// Declared capabilities (e.g. `["code", "search", "connectors"]`).
    pub capabilities: Vec<String>,
    /// Optional session identifier for tracking across context windows.
    pub session_id: Option<String>,
}

// ── Message types ────────────────────────────────────────────────────────

/// A mail message between agents.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MailMessage {
    /// Unique message identifier (UUID v4).
    pub id: String,
    /// Sender agent.
    pub from: AgentId,
    /// Recipient agent.
    pub to: AgentId,
    /// Human-readable subject line.
    pub subject: String,
    /// Typed message body.
    pub body: MessageBody,
    /// Timestamp when the message was created.
    pub timestamp: DateTime<Utc>,
    /// Optional thread identifier for grouping related messages.
    pub thread_id: Option<String>,
    /// Message priority.
    pub priority: Priority,
}

impl MailMessage {
    /// Create a new message with the given fields and auto-generated ID/timestamp.
    #[must_use]
    pub fn new(from: AgentId, to: AgentId, subject: impl Into<String>, body: MessageBody) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            from,
            to,
            subject: subject.into(),
            body,
            timestamp: Utc::now(),
            thread_id: None,
            priority: Priority::Normal,
        }
    }

    /// Set the thread ID for this message.
    #[must_use]
    pub fn with_thread(mut self, thread_id: impl Into<String>) -> Self {
        self.thread_id = Some(thread_id.into());
        self
    }

    /// Set the priority for this message.
    #[must_use]
    pub const fn with_priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }
}

/// Typed message body variants for structured inter-agent communication.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum MessageBody {
    /// Free-form text message.
    Text(TextPayload),
    /// Announce connector usage in a zone.
    ConnectorAnnounce {
        connector_id: String,
        operations: Vec<String>,
        zone: String,
    },
    /// Request exclusive access to a connector operation.
    ResourceReserve {
        connector_id: String,
        operation: String,
        duration_secs: u64,
        reason: String,
    },
    /// Release a previously acquired reservation.
    ResourceRelease {
        connector_id: String,
        operation: String,
        reservation_id: String,
    },
    /// Hand off a workflow step to the next agent.
    WorkflowHandoff {
        workflow_id: String,
        step_completed: String,
        next_step: String,
        context: serde_json::Value,
    },
    /// Broadcast a status update.
    StatusUpdate {
        task_id: String,
        status: String,
        detail: String,
    },
}

/// Text payload wrapper (needed for internally-tagged enum serialization).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TextPayload {
    pub text: String,
}

/// Message priority levels.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Low,
    Normal,
    High,
    Urgent,
}

impl Priority {
    /// All priority levels from lowest to highest.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[Self::Low, Self::Normal, Self::High, Self::Urgent]
    }
}

// ── Mailbox ──────────────────────────────────────────────────────────────

/// Summary of a message thread.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreadSummary {
    /// Thread identifier.
    pub thread_id: String,
    /// Subject of the first message in the thread.
    pub subject: String,
    /// Number of distinct participants.
    pub participant_count: usize,
    /// Total number of messages in the thread.
    pub message_count: usize,
    /// Timestamp of the last message in the thread.
    pub last_activity: DateTime<Utc>,
}

/// In-memory mailbox for an agent, with inbox/outbox separation.
pub struct Mailbox {
    /// Identity of the agent owning this mailbox.
    agent_id: AgentId,
    /// All messages where `to == agent_id`.
    inbox: Vec<MailMessage>,
    /// All messages sent by this agent.
    outbox: Vec<MailMessage>,
    /// Set of message IDs that have been read.
    read_ids: std::collections::BTreeSet<String>,
}

impl Mailbox {
    /// Create a new empty mailbox for the given agent.
    #[must_use]
    pub const fn new(agent_id: AgentId) -> Self {
        Self {
            agent_id,
            inbox: Vec::new(),
            outbox: Vec::new(),
            read_ids: std::collections::BTreeSet::new(),
        }
    }

    /// Return the agent identity for this mailbox.
    #[must_use]
    pub const fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Send a message. The message is appended to the outbox and returns its ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the sender does not match this mailbox's agent ID.
    pub fn send(&mut self, msg: MailMessage) -> Result<String> {
        if msg.from != self.agent_id {
            bail!(
                "sender mismatch: mailbox belongs to {}, message from {}",
                self.agent_id,
                msg.from,
            );
        }
        let id = msg.id.clone();
        self.outbox.push(msg);
        Ok(id)
    }

    /// Deliver a message to this mailbox's inbox.
    ///
    /// # Errors
    ///
    /// Returns an error if the recipient does not match this mailbox's agent ID.
    pub fn deliver(&mut self, msg: MailMessage) -> Result<()> {
        if msg.to != self.agent_id {
            bail!(
                "recipient mismatch: mailbox belongs to {}, message to {}",
                self.agent_id,
                msg.to,
            );
        }
        self.inbox.push(msg);
        Ok(())
    }

    /// Return all messages in the inbox.
    #[must_use]
    pub fn receive(&self) -> &[MailMessage] {
        &self.inbox
    }

    /// Return inbox messages matching the given filter.
    #[must_use]
    pub fn receive_filtered(&self, filter: &MailFilter) -> Vec<&MailMessage> {
        self.inbox.iter().filter(|m| filter.matches(m)).collect()
    }

    /// Mark a message as read by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if no message with the given ID exists in the inbox.
    pub fn mark_read(&mut self, msg_id: &str) -> Result<()> {
        if !self.inbox.iter().any(|m| m.id == msg_id) {
            bail!("message not found in inbox: {msg_id}");
        }
        self.read_ids.insert(msg_id.to_owned());
        Ok(())
    }

    /// Check if a message has been read.
    #[must_use]
    pub fn is_read(&self, msg_id: &str) -> bool {
        self.read_ids.contains(msg_id)
    }

    /// Return the number of unread messages.
    #[must_use]
    pub fn unread_count(&self) -> usize {
        self.inbox
            .iter()
            .filter(|m| !self.read_ids.contains(&m.id))
            .count()
    }

    /// Build thread summaries from all messages (inbox + outbox).
    #[must_use]
    pub fn list_threads(&self) -> Vec<ThreadSummary> {
        let mut threads: BTreeMap<String, ThreadData> = BTreeMap::new();
        let all_messages = self.inbox.iter().chain(self.outbox.iter());
        for msg in all_messages {
            let tid = msg.thread_id.clone().unwrap_or_else(|| msg.id.clone());
            let entry = threads.entry(tid.clone()).or_insert_with(|| ThreadData {
                thread_id: tid,
                subject: msg.subject.clone(),
                participants: std::collections::BTreeSet::new(),
                message_count: 0,
                last_activity: msg.timestamp,
            });
            entry.participants.insert(msg.from.as_str().to_owned());
            entry.participants.insert(msg.to.as_str().to_owned());
            entry.message_count += 1;
            if msg.timestamp > entry.last_activity {
                entry.last_activity = msg.timestamp;
            }
        }
        threads
            .into_values()
            .map(|td| ThreadSummary {
                thread_id: td.thread_id,
                subject: td.subject,
                participant_count: td.participants.len(),
                message_count: td.message_count,
                last_activity: td.last_activity,
            })
            .collect()
    }
}

/// Internal accumulator for thread summary computation.
struct ThreadData {
    thread_id: String,
    subject: String,
    participants: std::collections::BTreeSet<String>,
    message_count: usize,
    last_activity: DateTime<Utc>,
}

// ── Mail filter ──────────────────────────────────────────────────────────

/// Filter for selecting messages from a mailbox.
#[derive(Clone, Debug, Default)]
pub struct MailFilter {
    /// Match only messages from this agent.
    pub from: Option<AgentId>,
    /// Match messages whose subject contains this substring.
    pub subject_contains: Option<String>,
    /// Match messages created at or after this timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Match messages with priority >= this level.
    pub priority_min: Option<Priority>,
    /// Match messages whose body is of this type.
    pub body_type: Option<BodyType>,
}

/// Discriminant for message body type filtering.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyType {
    Text,
    ConnectorAnnounce,
    ResourceReserve,
    ResourceRelease,
    WorkflowHandoff,
    StatusUpdate,
}

impl MailFilter {
    /// Create a new empty filter that matches all messages.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Only match messages from the named agent.
    #[must_use]
    pub fn with_sender(mut self, agent: &str) -> Self {
        self.from = AgentId::parse(agent);
        self
    }

    /// Only match messages whose subject contains the given substring.
    #[must_use]
    pub fn subject_contains(mut self, needle: impl Into<String>) -> Self {
        self.subject_contains = Some(needle.into());
        self
    }

    /// Only match messages since the given timestamp.
    #[must_use]
    pub const fn since(mut self, since: DateTime<Utc>) -> Self {
        self.since = Some(since);
        self
    }

    /// Only match messages with priority at or above the given level.
    #[must_use]
    pub const fn priority_min(mut self, priority: Priority) -> Self {
        self.priority_min = Some(priority);
        self
    }

    /// Only match messages whose body is of the given type.
    #[must_use]
    pub const fn body_type(mut self, body_type: BodyType) -> Self {
        self.body_type = Some(body_type);
        self
    }

    /// Check whether a message matches this filter.
    #[must_use]
    pub fn matches(&self, msg: &MailMessage) -> bool {
        if let Some(ref from) = self.from {
            if &msg.from != from {
                return false;
            }
        }
        if let Some(ref needle) = self.subject_contains {
            if !msg.subject.contains(needle.as_str()) {
                return false;
            }
        }
        if let Some(since) = self.since {
            if msg.timestamp < since {
                return false;
            }
        }
        if let Some(min_priority) = self.priority_min {
            if msg.priority < min_priority {
                return false;
            }
        }
        if let Some(body_type) = self.body_type {
            if message_body_type(&msg.body) != body_type {
                return false;
            }
        }
        true
    }
}

/// Extract the `BodyType` discriminant from a `MessageBody`.
#[must_use]
const fn message_body_type(body: &MessageBody) -> BodyType {
    match body {
        MessageBody::Text(_) => BodyType::Text,
        MessageBody::ConnectorAnnounce { .. } => BodyType::ConnectorAnnounce,
        MessageBody::ResourceReserve { .. } => BodyType::ResourceReserve,
        MessageBody::ResourceRelease { .. } => BodyType::ResourceRelease,
        MessageBody::WorkflowHandoff { .. } => BodyType::WorkflowHandoff,
        MessageBody::StatusUpdate { .. } => BodyType::StatusUpdate,
    }
}

// ── Resource reservation ─────────────────────────────────────────────────

/// A resource reservation granting exclusive access to a connector operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reservation {
    /// Unique reservation identifier.
    pub id: String,
    /// Connector being reserved.
    pub connector_id: String,
    /// Operation being reserved.
    pub operation: String,
    /// Agent holding the reservation.
    pub holder: AgentId,
    /// When the reservation was acquired.
    pub acquired_at: DateTime<Utc>,
    /// When the reservation expires.
    pub expires_at: DateTime<Utc>,
    /// Reason for the reservation.
    pub reason: String,
}

/// Request to acquire a resource reservation.
pub struct ReservationRequest {
    /// Connector to reserve.
    pub connector_id: String,
    /// Operation to reserve.
    pub operation: String,
    /// Agent requesting the reservation.
    pub requester: AgentId,
    /// How long the reservation should last in seconds.
    pub duration_secs: u64,
    /// Reason for the reservation.
    pub reason: String,
}

/// Result of a reservation request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ReservationResult {
    /// Reservation was granted.
    Granted { reservation: Reservation },
    /// Reservation was denied because the resource is already held.
    Denied {
        held_by: AgentId,
        expires_at: DateTime<Utc>,
    },
    /// Request was queued because the resource is held but expiring soon.
    Queued { position: usize },
}

/// Store for managing active resource reservations.
pub struct ReservationStore {
    /// Active reservations keyed by `"connector_id:operation"`.
    reservations: BTreeMap<String, Reservation>,
    /// Queue of pending reservation requests per resource key.
    queue: BTreeMap<String, Vec<ReservationRequest>>,
}

impl ReservationStore {
    /// Create a new empty reservation store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            reservations: BTreeMap::new(),
            queue: BTreeMap::new(),
        }
    }

    /// Request a resource reservation.
    pub fn request_reservation(&mut self, req: ReservationRequest) -> ReservationResult {
        let key = reservation_key(&req.connector_id, &req.operation);
        let now = Utc::now();

        // Check for an existing active reservation.
        if let Some(existing) = self.reservations.get(&key) {
            if existing.expires_at > now {
                // Resource is held — check queue size to decide if we queue or deny.
                let queue_entry = self.queue.entry(key).or_default();
                let position = queue_entry.len() + 1;
                // Only queue if 3 or fewer already waiting.
                if position <= 3 {
                    queue_entry.push(req);
                    return ReservationResult::Queued { position };
                }
                return ReservationResult::Denied {
                    held_by: existing.holder.clone(),
                    expires_at: existing.expires_at,
                };
            }
            // Existing reservation has expired — remove it.
            self.reservations.remove(&key);
        }

        // Grant the reservation.
        let duration =
            chrono::Duration::seconds(i64::try_from(req.duration_secs).unwrap_or(i64::MAX));
        let reservation = Reservation {
            id: Uuid::new_v4().to_string(),
            connector_id: req.connector_id,
            operation: req.operation,
            holder: req.requester,
            acquired_at: now,
            expires_at: now + duration,
            reason: req.reason,
        };
        self.reservations.insert(
            reservation_key(&reservation.connector_id, &reservation.operation),
            reservation.clone(),
        );
        ReservationResult::Granted { reservation }
    }

    /// Release a reservation by ID.
    ///
    /// # Errors
    ///
    /// Returns an error if no reservation with the given ID exists.
    pub fn release_reservation(&mut self, id: &str) -> Result<()> {
        let key = self
            .reservations
            .iter()
            .find(|(_, r)| r.id == id)
            .map(|(k, _)| k.clone());
        match key {
            Some(k) => {
                self.reservations.remove(&k);
                Ok(())
            }
            None => bail!("reservation not found: {id}"),
        }
    }

    /// Return all active (non-expired) reservations.
    #[must_use]
    pub fn active_reservations(&self) -> Vec<&Reservation> {
        let now = Utc::now();
        self.reservations
            .values()
            .filter(|r| r.expires_at > now)
            .collect()
    }

    /// Check whether a specific connector/operation is currently reserved.
    #[must_use]
    pub fn check_reservation(&self, connector_id: &str, operation: &str) -> Option<&Reservation> {
        let key = reservation_key(connector_id, operation);
        let now = Utc::now();
        self.reservations.get(&key).filter(|r| r.expires_at > now)
    }

    /// Remove all expired reservations and return the number removed.
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Utc::now();
        let expired_keys: Vec<String> = self
            .reservations
            .iter()
            .filter(|(_, r)| r.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        let count = expired_keys.len();
        for key in expired_keys {
            self.reservations.remove(&key);
            self.queue.remove(&key);
        }
        count
    }

    /// Return the total number of reservations (including expired).
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.reservations.len()
    }
}

/// Build the `BTreeMap` key for a connector/operation pair.
#[must_use]
fn reservation_key(connector_id: &str, operation: &str) -> String {
    format!("{connector_id}:{operation}")
}

// ── Workflow coordination ────────────────────────────────────────────────

/// A multi-agent sequential workflow.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Workflow {
    /// Unique workflow identifier.
    pub id: String,
    /// Human-readable workflow name.
    pub name: String,
    /// Ordered list of workflow steps.
    pub steps: Vec<WorkflowStep>,
    /// Index of the current step (0-based).
    pub current_step: usize,
    /// Overall workflow status.
    pub status: WorkflowStatus,
    /// When the workflow was created.
    pub created_at: DateTime<Utc>,
    /// When the workflow was last updated.
    pub updated_at: DateTime<Utc>,
}

/// A single step in a workflow.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkflowStep {
    /// Step identifier (unique within the workflow).
    pub id: String,
    /// Agent assigned to execute this step.
    pub assigned_to: AgentId,
    /// Operation or task to perform.
    pub operation: String,
    /// Current status of this step.
    pub status: StepStatus,
    /// Result data from step execution, if completed.
    pub result: Option<serde_json::Value>,
}

/// Overall workflow status.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Cancelled,
}

/// Status of a single workflow step.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Skipped,
}

/// Input for creating a new workflow step (before IDs are assigned).
pub struct NewWorkflowStep {
    /// Agent assigned to execute this step.
    pub assigned_to: AgentId,
    /// Operation or task to perform.
    pub operation: String,
}

/// Coordinator for multi-agent sequential workflows.
pub struct WorkflowCoordinator {
    workflows: BTreeMap<String, Workflow>,
}

impl WorkflowCoordinator {
    /// Create a new empty workflow coordinator.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            workflows: BTreeMap::new(),
        }
    }

    /// Create a new workflow with the given name and steps.
    ///
    /// Returns the workflow ID.
    pub fn create_workflow(
        &mut self,
        name: impl Into<String>,
        steps: Vec<NewWorkflowStep>,
    ) -> String {
        let now = Utc::now();
        let id = Uuid::new_v4().to_string();
        let workflow = Workflow {
            id: id.clone(),
            name: name.into(),
            steps: steps
                .into_iter()
                .enumerate()
                .map(|(i, s)| WorkflowStep {
                    id: format!("step-{i}"),
                    assigned_to: s.assigned_to,
                    operation: s.operation,
                    status: StepStatus::Pending,
                    result: None,
                })
                .collect(),
            current_step: 0,
            status: WorkflowStatus::Pending,
            created_at: now,
            updated_at: now,
        };
        self.workflows.insert(id.clone(), workflow);
        id
    }

    /// Advance a workflow by completing the current step with a result.
    ///
    /// Returns the next step if there is one, or `None` if the workflow is complete.
    ///
    /// # Errors
    ///
    /// Returns an error if the workflow is not found or is not in a state that
    /// can be advanced (already completed, failed, or cancelled).
    pub fn advance_workflow(
        &mut self,
        workflow_id: &str,
        step_result: serde_json::Value,
    ) -> Result<Option<WorkflowStep>> {
        let wf = self
            .workflows
            .get_mut(workflow_id)
            .ok_or_else(|| anyhow::anyhow!("workflow not found: {workflow_id}"))?;

        match wf.status {
            WorkflowStatus::Completed | WorkflowStatus::Failed | WorkflowStatus::Cancelled => {
                bail!("workflow {} is already {:?}", workflow_id, wf.status);
            }
            _ => {}
        }

        let now = Utc::now();

        // Mark current step completed.
        if wf.current_step < wf.steps.len() {
            wf.steps[wf.current_step].status = StepStatus::Completed;
            wf.steps[wf.current_step].result = Some(step_result);
        }

        // Move to next step.
        wf.current_step += 1;
        wf.updated_at = now;

        if wf.current_step < wf.steps.len() {
            // There is a next step.
            wf.status = WorkflowStatus::InProgress;
            wf.steps[wf.current_step].status = StepStatus::InProgress;
            Ok(Some(wf.steps[wf.current_step].clone()))
        } else {
            // Workflow is complete.
            wf.status = WorkflowStatus::Completed;
            Ok(None)
        }
    }

    /// Fail the current step and the entire workflow.
    ///
    /// # Errors
    ///
    /// Returns an error if the workflow is not found or is already terminal.
    pub fn fail_workflow(&mut self, workflow_id: &str, reason: serde_json::Value) -> Result<()> {
        let wf = self
            .workflows
            .get_mut(workflow_id)
            .ok_or_else(|| anyhow::anyhow!("workflow not found: {workflow_id}"))?;

        match wf.status {
            WorkflowStatus::Completed | WorkflowStatus::Failed | WorkflowStatus::Cancelled => {
                bail!("workflow {} is already {:?}", workflow_id, wf.status);
            }
            _ => {}
        }

        if wf.current_step < wf.steps.len() {
            wf.steps[wf.current_step].status = StepStatus::Failed;
            wf.steps[wf.current_step].result = Some(reason);
        }

        // Skip remaining steps.
        for step in wf.steps.iter_mut().skip(wf.current_step + 1) {
            step.status = StepStatus::Skipped;
        }

        wf.status = WorkflowStatus::Failed;
        wf.updated_at = Utc::now();
        Ok(())
    }

    /// Cancel a workflow.
    ///
    /// # Errors
    ///
    /// Returns an error if the workflow is not found or is already terminal.
    pub fn cancel_workflow(&mut self, workflow_id: &str) -> Result<()> {
        let wf = self
            .workflows
            .get_mut(workflow_id)
            .ok_or_else(|| anyhow::anyhow!("workflow not found: {workflow_id}"))?;

        match wf.status {
            WorkflowStatus::Completed | WorkflowStatus::Failed | WorkflowStatus::Cancelled => {
                bail!("workflow {} is already {:?}", workflow_id, wf.status);
            }
            _ => {}
        }

        for step in &mut wf.steps {
            if step.status == StepStatus::Pending || step.status == StepStatus::InProgress {
                step.status = StepStatus::Skipped;
            }
        }

        wf.status = WorkflowStatus::Cancelled;
        wf.updated_at = Utc::now();
        Ok(())
    }

    /// Retrieve the current state of a workflow.
    #[must_use]
    pub fn workflow_status(&self, workflow_id: &str) -> Option<&Workflow> {
        self.workflows.get(workflow_id)
    }

    /// Return the number of active (non-terminal) workflows.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.workflows
            .values()
            .filter(|wf| {
                matches!(
                    wf.status,
                    WorkflowStatus::Pending | WorkflowStatus::InProgress
                )
            })
            .count()
    }

    /// Return all workflow IDs.
    #[must_use]
    pub fn workflow_ids(&self) -> Vec<&str> {
        self.workflows.keys().map(String::as_str).collect()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Helper constructors ──────────────────────────────────────────

    fn sunny() -> AgentId {
        AgentId::parse("SunnyMoose").unwrap()
    }

    fn gold() -> AgentId {
        AgentId::parse("GoldOx").unwrap()
    }

    fn green() -> AgentId {
        AgentId::parse("GreenBasin").unwrap()
    }

    fn text_body(s: &str) -> MessageBody {
        MessageBody::Text(TextPayload { text: s.to_owned() })
    }

    fn make_msg(from: AgentId, to: AgentId, subject: &str, body: MessageBody) -> MailMessage {
        MailMessage::new(from, to, subject, body)
    }

    // ── AgentId parsing ──────────────────────────────────────────────

    #[test]
    fn agent_id_valid_two_words() {
        assert!(AgentId::parse("SunnyMoose").is_some());
        assert!(AgentId::parse("GoldOx").is_some());
        assert!(AgentId::parse("GreenBasin").is_some());
        assert!(AgentId::parse("DarkStone").is_some());
    }

    #[test]
    fn agent_id_single_word_rejected() {
        assert!(AgentId::parse("Sunny").is_none());
        assert!(AgentId::parse("Gold").is_none());
    }

    #[test]
    fn agent_id_three_words_rejected() {
        assert!(AgentId::parse("SunnyBigMoose").is_none());
        assert!(AgentId::parse("VeryGoldOx").is_none());
    }

    #[test]
    fn agent_id_lowercase_rejected() {
        assert!(AgentId::parse("sunnyMoose").is_none());
        assert!(AgentId::parse("sunnymoose").is_none());
    }

    #[test]
    fn agent_id_empty_rejected() {
        assert!(AgentId::parse("").is_none());
    }

    #[test]
    fn agent_id_numbers_rejected() {
        assert!(AgentId::parse("Sunny123").is_none());
        assert!(AgentId::parse("Agent42").is_none());
    }

    #[test]
    fn agent_id_underscore_rejected() {
        assert!(AgentId::parse("Sunny_Moose").is_none());
    }

    #[test]
    fn agent_id_spaces_rejected() {
        assert!(AgentId::parse("Sunny Moose").is_none());
    }

    #[test]
    fn agent_id_hyphen_rejected() {
        assert!(AgentId::parse("Sunny-Moose").is_none());
    }

    #[test]
    fn agent_id_all_uppercase_rejected() {
        assert!(AgentId::parse("SM").is_none());
        assert!(AgentId::parse("AB").is_none());
    }

    #[test]
    fn agent_id_single_char_words_rejected() {
        // Each word must be at least 2 chars (1 upper + 1 lower)
        assert!(AgentId::parse("AB").is_none());
    }

    #[test]
    fn agent_id_display() {
        let id = sunny();
        assert_eq!(id.to_string(), "SunnyMoose");
    }

    #[test]
    fn agent_id_as_str() {
        let id = sunny();
        assert_eq!(id.as_str(), "SunnyMoose");
    }

    #[test]
    fn agent_id_equality() {
        let a = AgentId::parse("SunnyMoose").unwrap();
        let b = AgentId::parse("SunnyMoose").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn agent_id_inequality() {
        assert_ne!(sunny(), gold());
    }

    #[test]
    fn agent_id_ordering() {
        assert!(gold() < green());
        assert!(green() < sunny());
    }

    #[test]
    fn agent_id_clone() {
        let original = sunny();
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    // ── AgentId serde ────────────────────────────────────────────────

    #[test]
    fn agent_id_serde_roundtrip() {
        let id = sunny();
        let json = serde_json::to_string(&id).unwrap();
        let back: AgentId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // ── AgentProfile ─────────────────────────────────────────────────

    #[test]
    fn agent_profile_serde_roundtrip() {
        let profile = AgentProfile {
            id: sunny(),
            model: "claude-opus-4-6".to_owned(),
            provider: "anthropic".to_owned(),
            capabilities: vec!["code".to_owned(), "connectors".to_owned()],
            session_id: Some("sess-001".to_owned()),
        };
        let json = serde_json::to_value(&profile).unwrap();
        let back: AgentProfile = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, profile.id);
        assert_eq!(back.model, "claude-opus-4-6");
        assert_eq!(back.capabilities.len(), 2);
    }

    #[test]
    fn agent_profile_no_session() {
        let profile = AgentProfile {
            id: gold(),
            model: "claude-sonnet".to_owned(),
            provider: "anthropic".to_owned(),
            capabilities: Vec::new(),
            session_id: None,
        };
        let json = serde_json::to_value(&profile).unwrap();
        let back: AgentProfile = serde_json::from_value(json).unwrap();
        assert!(back.session_id.is_none());
        assert!(back.capabilities.is_empty());
    }

    // ── MailMessage construction ─────────────────────────────────────

    #[test]
    fn mail_message_new_has_uuid() {
        let msg = MailMessage::new(sunny(), gold(), "test", text_body("hello"));
        assert!(!msg.id.is_empty());
        // UUID v4 format: 8-4-4-4-12
        assert_eq!(msg.id.len(), 36);
        assert_eq!(msg.id.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn mail_message_default_priority() {
        let msg = MailMessage::new(sunny(), gold(), "test", text_body("hello"));
        assert_eq!(msg.priority, Priority::Normal);
    }

    #[test]
    fn mail_message_default_thread_id() {
        let msg = MailMessage::new(sunny(), gold(), "test", text_body("hello"));
        assert!(msg.thread_id.is_none());
    }

    #[test]
    fn mail_message_with_thread() {
        let msg =
            MailMessage::new(sunny(), gold(), "test", text_body("hello")).with_thread("thread-001");
        assert_eq!(msg.thread_id.as_deref(), Some("thread-001"));
    }

    #[test]
    fn mail_message_with_priority() {
        let msg = MailMessage::new(sunny(), gold(), "test", text_body("hello"))
            .with_priority(Priority::Urgent);
        assert_eq!(msg.priority, Priority::Urgent);
    }

    #[test]
    fn mail_message_chained_builders() {
        let msg = MailMessage::new(sunny(), gold(), "test", text_body("hello"))
            .with_thread("t-1")
            .with_priority(Priority::High);
        assert_eq!(msg.thread_id.as_deref(), Some("t-1"));
        assert_eq!(msg.priority, Priority::High);
    }

    #[test]
    fn mail_message_serde_roundtrip() {
        let msg = MailMessage::new(sunny(), gold(), "test subject", text_body("body content"))
            .with_thread("t-42");
        let json = serde_json::to_value(&msg).unwrap();
        let back: MailMessage = serde_json::from_value(json).unwrap();
        assert_eq!(back.from, sunny());
        assert_eq!(back.to, gold());
        assert_eq!(back.subject, "test subject");
        assert_eq!(back.thread_id.as_deref(), Some("t-42"));
    }

    // ── MessageBody serde roundtrips ─────────────────────────────────

    #[test]
    fn body_text_serde() {
        let body = text_body("hello world");
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["type"], "text");
        let back: MessageBody = serde_json::from_value(json).unwrap();
        if let MessageBody::Text(p) = back {
            assert_eq!(p.text, "hello world");
        } else {
            panic!("expected Text variant");
        }
    }

    #[test]
    fn body_connector_announce_serde() {
        let body = MessageBody::ConnectorAnnounce {
            connector_id: "github".to_owned(),
            operations: vec!["issues.create".to_owned(), "issues.list".to_owned()],
            zone: "z:work".to_owned(),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["type"], "connector_announce");
        assert_eq!(json["connector_id"], "github");
        let back: MessageBody = serde_json::from_value(json).unwrap();
        if let MessageBody::ConnectorAnnounce {
            connector_id,
            operations,
            zone,
        } = back
        {
            assert_eq!(connector_id, "github");
            assert_eq!(operations.len(), 2);
            assert_eq!(zone, "z:work");
        } else {
            panic!("expected ConnectorAnnounce variant");
        }
    }

    #[test]
    fn body_resource_reserve_serde() {
        let body = MessageBody::ResourceReserve {
            connector_id: "slack".to_owned(),
            operation: "messages.send".to_owned(),
            duration_secs: 300,
            reason: "sending batch notifications".to_owned(),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["type"], "resource_reserve");
        assert_eq!(json["duration_secs"], 300);
        let back: MessageBody = serde_json::from_value(json).unwrap();
        if let MessageBody::ResourceReserve {
            connector_id,
            operation,
            duration_secs,
            reason,
        } = back
        {
            assert_eq!(connector_id, "slack");
            assert_eq!(operation, "messages.send");
            assert_eq!(duration_secs, 300);
            assert!(reason.contains("batch"));
        } else {
            panic!("expected ResourceReserve variant");
        }
    }

    #[test]
    fn body_resource_release_serde() {
        let body = MessageBody::ResourceRelease {
            connector_id: "slack".to_owned(),
            operation: "messages.send".to_owned(),
            reservation_id: "res-001".to_owned(),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["type"], "resource_release");
        let back: MessageBody = serde_json::from_value(json).unwrap();
        if let MessageBody::ResourceRelease {
            connector_id,
            operation,
            reservation_id,
        } = back
        {
            assert_eq!(connector_id, "slack");
            assert_eq!(operation, "messages.send");
            assert_eq!(reservation_id, "res-001");
        } else {
            panic!("expected ResourceRelease variant");
        }
    }

    #[test]
    fn body_workflow_handoff_serde() {
        let body = MessageBody::WorkflowHandoff {
            workflow_id: "wf-001".to_owned(),
            step_completed: "step-0".to_owned(),
            next_step: "step-1".to_owned(),
            context: json!({"key": "value"}),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["type"], "workflow_handoff");
        let back: MessageBody = serde_json::from_value(json).unwrap();
        if let MessageBody::WorkflowHandoff {
            workflow_id,
            step_completed,
            next_step,
            context,
        } = back
        {
            assert_eq!(workflow_id, "wf-001");
            assert_eq!(step_completed, "step-0");
            assert_eq!(next_step, "step-1");
            assert_eq!(context["key"], "value");
        } else {
            panic!("expected WorkflowHandoff variant");
        }
    }

    #[test]
    fn body_status_update_serde() {
        let body = MessageBody::StatusUpdate {
            task_id: "task-42".to_owned(),
            status: "in_progress".to_owned(),
            detail: "50% complete".to_owned(),
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["type"], "status_update");
        let back: MessageBody = serde_json::from_value(json).unwrap();
        if let MessageBody::StatusUpdate {
            task_id,
            status,
            detail,
        } = back
        {
            assert_eq!(task_id, "task-42");
            assert_eq!(status, "in_progress");
            assert_eq!(detail, "50% complete");
        } else {
            panic!("expected StatusUpdate variant");
        }
    }

    // ── Priority ─────────────────────────────────────────────────────

    #[test]
    fn priority_ordering() {
        assert!(Priority::Low < Priority::Normal);
        assert!(Priority::Normal < Priority::High);
        assert!(Priority::High < Priority::Urgent);
    }

    #[test]
    fn priority_equality() {
        assert_eq!(Priority::Low, Priority::Low);
        assert_ne!(Priority::Low, Priority::High);
    }

    #[test]
    fn priority_all_has_four_variants() {
        assert_eq!(Priority::all().len(), 4);
        assert_eq!(Priority::all()[0], Priority::Low);
        assert_eq!(Priority::all()[3], Priority::Urgent);
    }

    #[test]
    fn priority_serde_roundtrip() {
        for &p in Priority::all() {
            let json = serde_json::to_string(&p).unwrap();
            let back: Priority = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn priority_serde_snake_case() {
        let json = serde_json::to_string(&Priority::Low).unwrap();
        assert_eq!(json, "\"low\"");
        let json = serde_json::to_string(&Priority::Urgent).unwrap();
        assert_eq!(json, "\"urgent\"");
    }

    // ── Mailbox ──────────────────────────────────────────────────────

    #[test]
    fn mailbox_new_is_empty() {
        let mb = Mailbox::new(sunny());
        assert_eq!(mb.agent_id(), &sunny());
        assert!(mb.receive().is_empty());
        assert_eq!(mb.unread_count(), 0);
    }

    #[test]
    fn mailbox_send_and_outbox() {
        let mut mb = Mailbox::new(sunny());
        let msg = make_msg(sunny(), gold(), "hi", text_body("hello"));
        let id = mb.send(msg).unwrap();
        assert!(!id.is_empty());
        assert_eq!(mb.outbox.len(), 1);
    }

    #[test]
    fn mailbox_send_wrong_sender() {
        let mut mb = Mailbox::new(sunny());
        let msg = make_msg(gold(), sunny(), "hi", text_body("hello"));
        let result = mb.send(msg);
        assert!(result.is_err());
    }

    #[test]
    fn mailbox_deliver_and_receive() {
        let mut mb = Mailbox::new(sunny());
        let msg = make_msg(gold(), sunny(), "hi", text_body("hello"));
        mb.deliver(msg).unwrap();
        assert_eq!(mb.receive().len(), 1);
        assert_eq!(mb.receive()[0].subject, "hi");
    }

    #[test]
    fn mailbox_deliver_wrong_recipient() {
        let mut mb = Mailbox::new(sunny());
        let msg = make_msg(sunny(), gold(), "hi", text_body("hello"));
        let result = mb.deliver(msg);
        assert!(result.is_err());
    }

    #[test]
    fn mailbox_mark_read() {
        let mut mb = Mailbox::new(sunny());
        let msg = make_msg(gold(), sunny(), "hi", text_body("hello"));
        let id = msg.id.clone();
        mb.deliver(msg).unwrap();
        assert!(!mb.is_read(&id));
        assert_eq!(mb.unread_count(), 1);
        mb.mark_read(&id).unwrap();
        assert!(mb.is_read(&id));
        assert_eq!(mb.unread_count(), 0);
    }

    #[test]
    fn mailbox_mark_read_nonexistent() {
        let mut mb = Mailbox::new(sunny());
        assert!(mb.mark_read("nonexistent").is_err());
    }

    #[test]
    fn mailbox_empty_inbox_receive() {
        let mb = Mailbox::new(sunny());
        assert!(mb.receive().is_empty());
        assert_eq!(mb.unread_count(), 0);
    }

    #[test]
    fn mailbox_multiple_messages() {
        let mut mb = Mailbox::new(sunny());
        for i in 0..5 {
            let msg = make_msg(gold(), sunny(), &format!("msg-{i}"), text_body("body"));
            mb.deliver(msg).unwrap();
        }
        assert_eq!(mb.receive().len(), 5);
        assert_eq!(mb.unread_count(), 5);
    }

    #[test]
    fn mailbox_unread_count_after_partial_read() {
        let mut mb = Mailbox::new(sunny());
        let msg1 = make_msg(gold(), sunny(), "a", text_body("1"));
        let id1 = msg1.id.clone();
        let msg2 = make_msg(gold(), sunny(), "b", text_body("2"));
        mb.deliver(msg1).unwrap();
        mb.deliver(msg2).unwrap();
        mb.mark_read(&id1).unwrap();
        assert_eq!(mb.unread_count(), 1);
    }

    // ── MailFilter ───────────────────────────────────────────────────

    #[test]
    fn filter_empty_matches_all() {
        let filter = MailFilter::new();
        let msg = make_msg(sunny(), gold(), "hi", text_body("hello"));
        assert!(filter.matches(&msg));
    }

    #[test]
    fn filter_by_from() {
        let filter = MailFilter::new().with_sender("SunnyMoose");
        let msg1 = make_msg(sunny(), gold(), "hi", text_body("hello"));
        let msg2 = make_msg(gold(), sunny(), "hi", text_body("hello"));
        assert!(filter.matches(&msg1));
        assert!(!filter.matches(&msg2));
    }

    #[test]
    fn filter_by_subject() {
        let filter = MailFilter::new().subject_contains("urgent");
        let msg1 = make_msg(sunny(), gold(), "urgent task", text_body("body"));
        let msg2 = make_msg(sunny(), gold(), "normal task", text_body("body"));
        assert!(filter.matches(&msg1));
        assert!(!filter.matches(&msg2));
    }

    #[test]
    fn filter_by_date() {
        let cutoff = Utc::now();
        let filter = MailFilter::new().since(cutoff);
        let msg = make_msg(sunny(), gold(), "hi", text_body("hello"));
        // Message created at or after cutoff should match.
        assert!(filter.matches(&msg));
    }

    #[test]
    fn filter_by_priority() {
        let filter = MailFilter::new().priority_min(Priority::High);
        let msg_low =
            MailMessage::new(sunny(), gold(), "low", text_body("x")).with_priority(Priority::Low);
        let msg_high =
            MailMessage::new(sunny(), gold(), "high", text_body("x")).with_priority(Priority::High);
        let msg_urgent = MailMessage::new(sunny(), gold(), "urgent", text_body("x"))
            .with_priority(Priority::Urgent);
        assert!(!filter.matches(&msg_low));
        assert!(filter.matches(&msg_high));
        assert!(filter.matches(&msg_urgent));
    }

    #[test]
    fn filter_by_body_type() {
        let filter = MailFilter::new().body_type(BodyType::ConnectorAnnounce);
        let msg_text = make_msg(sunny(), gold(), "hi", text_body("hello"));
        let msg_announce = make_msg(
            sunny(),
            gold(),
            "announce",
            MessageBody::ConnectorAnnounce {
                connector_id: "github".to_owned(),
                operations: vec!["issues.list".to_owned()],
                zone: "z:work".to_owned(),
            },
        );
        assert!(!filter.matches(&msg_text));
        assert!(filter.matches(&msg_announce));
    }

    #[test]
    fn filter_combined() {
        let filter = MailFilter::new()
            .with_sender("SunnyMoose")
            .priority_min(Priority::High);
        let msg1 = MailMessage::new(sunny(), gold(), "hi", text_body("hello"))
            .with_priority(Priority::Urgent);
        let msg2 = MailMessage::new(sunny(), gold(), "hi", text_body("hello"))
            .with_priority(Priority::Low);
        let msg3 = MailMessage::new(gold(), sunny(), "hi", text_body("hello"))
            .with_priority(Priority::Urgent);
        assert!(filter.matches(&msg1)); // correct sender + high priority
        assert!(!filter.matches(&msg2)); // correct sender, low priority
        assert!(!filter.matches(&msg3)); // wrong sender
    }

    #[test]
    fn filter_no_match() {
        let filter = MailFilter::new()
            .with_sender("SunnyMoose")
            .subject_contains("nonexistent");
        let msg = make_msg(sunny(), gold(), "hello", text_body("body"));
        assert!(!filter.matches(&msg));
    }

    #[test]
    fn filter_body_type_resource_reserve() {
        let filter = MailFilter::new().body_type(BodyType::ResourceReserve);
        let msg = make_msg(
            sunny(),
            gold(),
            "reserve",
            MessageBody::ResourceReserve {
                connector_id: "slack".to_owned(),
                operation: "send".to_owned(),
                duration_secs: 60,
                reason: "batch".to_owned(),
            },
        );
        assert!(filter.matches(&msg));
    }

    #[test]
    fn filter_body_type_status_update() {
        let filter = MailFilter::new().body_type(BodyType::StatusUpdate);
        let msg = make_msg(
            sunny(),
            gold(),
            "update",
            MessageBody::StatusUpdate {
                task_id: "t-1".to_owned(),
                status: "done".to_owned(),
                detail: "finished".to_owned(),
            },
        );
        assert!(filter.matches(&msg));
    }

    #[test]
    fn filter_body_type_workflow_handoff() {
        let filter = MailFilter::new().body_type(BodyType::WorkflowHandoff);
        let msg = make_msg(
            sunny(),
            gold(),
            "handoff",
            MessageBody::WorkflowHandoff {
                workflow_id: "wf-1".to_owned(),
                step_completed: "step-0".to_owned(),
                next_step: "step-1".to_owned(),
                context: json!({}),
            },
        );
        assert!(filter.matches(&msg));
    }

    #[test]
    fn filter_body_type_resource_release() {
        let filter = MailFilter::new().body_type(BodyType::ResourceRelease);
        let msg = make_msg(
            sunny(),
            gold(),
            "release",
            MessageBody::ResourceRelease {
                connector_id: "slack".to_owned(),
                operation: "send".to_owned(),
                reservation_id: "r-1".to_owned(),
            },
        );
        assert!(filter.matches(&msg));
    }

    // ── Mailbox with filter ──────────────────────────────────────────

    #[test]
    fn mailbox_receive_filtered() {
        let mut mb = Mailbox::new(sunny());
        let msg1 = MailMessage::new(gold(), sunny(), "urgent task", text_body("body"))
            .with_priority(Priority::Urgent);
        let msg2 = MailMessage::new(gold(), sunny(), "normal task", text_body("body"))
            .with_priority(Priority::Normal);
        mb.deliver(msg1).unwrap();
        mb.deliver(msg2).unwrap();

        let filter = MailFilter::new().priority_min(Priority::High);
        let results = mb.receive_filtered(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].subject, "urgent task");
    }

    #[test]
    fn mailbox_receive_filtered_empty() {
        let mb = Mailbox::new(sunny());
        let filter = MailFilter::new().with_sender("GoldOx");
        let results = mb.receive_filtered(&filter);
        assert!(results.is_empty());
    }

    // ── Thread summaries ─────────────────────────────────────────────

    #[test]
    fn thread_summary_single_thread() {
        let mut mb = Mailbox::new(sunny());
        let msg1 = MailMessage::new(gold(), sunny(), "Project A", text_body("msg1"))
            .with_thread("thread-1");
        let msg2 = MailMessage::new(gold(), sunny(), "Project A", text_body("msg2"))
            .with_thread("thread-1");
        mb.deliver(msg1).unwrap();
        mb.deliver(msg2).unwrap();

        let threads = mb.list_threads();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].thread_id, "thread-1");
        assert_eq!(threads[0].message_count, 2);
        assert_eq!(threads[0].participant_count, 2); // gold + sunny
    }

    #[test]
    fn thread_summary_multiple_threads() {
        let mut mb = Mailbox::new(sunny());
        let msg1 = MailMessage::new(gold(), sunny(), "A", text_body("1")).with_thread("t-1");
        let msg2 = MailMessage::new(gold(), sunny(), "B", text_body("2")).with_thread("t-2");
        mb.deliver(msg1).unwrap();
        mb.deliver(msg2).unwrap();

        let threads = mb.list_threads();
        assert_eq!(threads.len(), 2);
    }

    #[test]
    fn thread_summary_no_thread_id_uses_message_id() {
        let mut mb = Mailbox::new(sunny());
        let msg = MailMessage::new(gold(), sunny(), "Solo", text_body("alone"));
        let msg_id = msg.id.clone();
        mb.deliver(msg).unwrap();

        let threads = mb.list_threads();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].thread_id, msg_id);
        assert_eq!(threads[0].message_count, 1);
    }

    #[test]
    fn thread_summary_includes_outbox() {
        let mut mb = Mailbox::new(sunny());
        let outgoing =
            MailMessage::new(sunny(), gold(), "Outbound", text_body("out")).with_thread("t-shared");
        mb.send(outgoing).unwrap();

        let incoming =
            MailMessage::new(gold(), sunny(), "Reply", text_body("in")).with_thread("t-shared");
        mb.deliver(incoming).unwrap();

        let threads = mb.list_threads();
        assert_eq!(threads.len(), 1);
        assert_eq!(threads[0].message_count, 2);
        assert_eq!(threads[0].participant_count, 2);
    }

    // ── Reservation store ────────────────────────────────────────────

    #[test]
    fn reservation_store_new_is_empty() {
        let store = ReservationStore::new();
        assert_eq!(store.total_count(), 0);
        assert!(store.active_reservations().is_empty());
    }

    #[test]
    fn reservation_grant_on_empty() {
        let mut store = ReservationStore::new();
        let result = store.request_reservation(ReservationRequest {
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            requester: sunny(),
            duration_secs: 300,
            reason: "creating issue".to_owned(),
        });
        if let ReservationResult::Granted { reservation } = result {
            assert_eq!(reservation.connector_id, "github");
            assert_eq!(reservation.holder, sunny());
        } else {
            panic!("expected Granted");
        }
    }

    #[test]
    fn reservation_denied_when_held() {
        let mut store = ReservationStore::new();
        // First reservation.
        store.request_reservation(ReservationRequest {
            connector_id: "slack".to_owned(),
            operation: "messages.send".to_owned(),
            requester: sunny(),
            duration_secs: 3600,
            reason: "batch send".to_owned(),
        });

        // Queue up 3 waiters to fill the queue.
        for _ in 0..3 {
            store.request_reservation(ReservationRequest {
                connector_id: "slack".to_owned(),
                operation: "messages.send".to_owned(),
                requester: gold(),
                duration_secs: 60,
                reason: "waiting".to_owned(),
            });
        }

        // 4th request should be denied (queue full).
        let result = store.request_reservation(ReservationRequest {
            connector_id: "slack".to_owned(),
            operation: "messages.send".to_owned(),
            requester: green(),
            duration_secs: 60,
            reason: "also waiting".to_owned(),
        });
        matches!(result, ReservationResult::Denied { .. });
    }

    #[test]
    fn reservation_queued_when_held() {
        let mut store = ReservationStore::new();
        store.request_reservation(ReservationRequest {
            connector_id: "slack".to_owned(),
            operation: "messages.send".to_owned(),
            requester: sunny(),
            duration_secs: 3600,
            reason: "batch send".to_owned(),
        });

        let result = store.request_reservation(ReservationRequest {
            connector_id: "slack".to_owned(),
            operation: "messages.send".to_owned(),
            requester: gold(),
            duration_secs: 60,
            reason: "waiting".to_owned(),
        });
        if let ReservationResult::Queued { position } = result {
            assert_eq!(position, 1);
        } else {
            panic!("expected Queued, got {result:?}");
        }
    }

    #[test]
    fn reservation_different_ops_both_granted() {
        let mut store = ReservationStore::new();
        let r1 = store.request_reservation(ReservationRequest {
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            requester: sunny(),
            duration_secs: 300,
            reason: "creating".to_owned(),
        });
        let r2 = store.request_reservation(ReservationRequest {
            connector_id: "github".to_owned(),
            operation: "issues.list".to_owned(),
            requester: gold(),
            duration_secs: 300,
            reason: "listing".to_owned(),
        });
        assert!(matches!(r1, ReservationResult::Granted { .. }));
        assert!(matches!(r2, ReservationResult::Granted { .. }));
    }

    #[test]
    fn reservation_different_connectors_both_granted() {
        let mut store = ReservationStore::new();
        let r1 = store.request_reservation(ReservationRequest {
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            requester: sunny(),
            duration_secs: 300,
            reason: "github work".to_owned(),
        });
        let r2 = store.request_reservation(ReservationRequest {
            connector_id: "slack".to_owned(),
            operation: "issues.create".to_owned(),
            requester: gold(),
            duration_secs: 300,
            reason: "slack work".to_owned(),
        });
        assert!(matches!(r1, ReservationResult::Granted { .. }));
        assert!(matches!(r2, ReservationResult::Granted { .. }));
    }

    #[test]
    fn reservation_release() {
        let mut store = ReservationStore::new();
        let result = store.request_reservation(ReservationRequest {
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            requester: sunny(),
            duration_secs: 300,
            reason: "work".to_owned(),
        });
        let id = if let ReservationResult::Granted { reservation } = result {
            reservation.id
        } else {
            panic!("expected Granted");
        };
        store.release_reservation(&id).unwrap();
        assert_eq!(store.total_count(), 0);
    }

    #[test]
    fn reservation_release_nonexistent() {
        let mut store = ReservationStore::new();
        assert!(store.release_reservation("nonexistent").is_err());
    }

    #[test]
    fn reservation_check_found() {
        let mut store = ReservationStore::new();
        store.request_reservation(ReservationRequest {
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            requester: sunny(),
            duration_secs: 300,
            reason: "work".to_owned(),
        });
        let check = store.check_reservation("github", "issues.create");
        assert!(check.is_some());
        assert_eq!(check.unwrap().holder, sunny());
    }

    #[test]
    fn reservation_check_not_found() {
        let store = ReservationStore::new();
        assert!(store.check_reservation("github", "issues.create").is_none());
    }

    #[test]
    fn reservation_active_count() {
        let mut store = ReservationStore::new();
        store.request_reservation(ReservationRequest {
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            requester: sunny(),
            duration_secs: 300,
            reason: "work".to_owned(),
        });
        store.request_reservation(ReservationRequest {
            connector_id: "slack".to_owned(),
            operation: "messages.send".to_owned(),
            requester: gold(),
            duration_secs: 300,
            reason: "work".to_owned(),
        });
        assert_eq!(store.active_reservations().len(), 2);
    }

    #[test]
    fn reservation_cleanup_expired_none() {
        let mut store = ReservationStore::new();
        store.request_reservation(ReservationRequest {
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            requester: sunny(),
            duration_secs: 3600,
            reason: "work".to_owned(),
        });
        let cleaned = store.cleanup_expired();
        assert_eq!(cleaned, 0);
        assert_eq!(store.total_count(), 1);
    }

    #[test]
    fn reservation_serde_roundtrip() {
        let res = Reservation {
            id: "res-001".to_owned(),
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            holder: sunny(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            reason: "testing".to_owned(),
        };
        let json = serde_json::to_value(&res).unwrap();
        let back: Reservation = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "res-001");
        assert_eq!(back.holder, sunny());
    }

    #[test]
    fn reservation_result_granted_serde() {
        let res = Reservation {
            id: "r-1".to_owned(),
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            holder: sunny(),
            acquired_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(60),
            reason: "test".to_owned(),
        };
        let result = ReservationResult::Granted { reservation: res };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "granted");
        let back: ReservationResult = serde_json::from_value(json).unwrap();
        assert!(matches!(back, ReservationResult::Granted { .. }));
    }

    #[test]
    fn reservation_result_denied_serde() {
        let result = ReservationResult::Denied {
            held_by: gold(),
            expires_at: Utc::now(),
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "denied");
    }

    #[test]
    fn reservation_result_queued_serde() {
        let result = ReservationResult::Queued { position: 2 };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["status"], "queued");
        assert_eq!(json["position"], 2);
    }

    // ── Workflow coordinator ─────────────────────────────────────────

    #[test]
    fn workflow_coordinator_new_is_empty() {
        let coord = WorkflowCoordinator::new();
        assert_eq!(coord.active_count(), 0);
        assert!(coord.workflow_ids().is_empty());
    }

    #[test]
    fn workflow_create() {
        let mut coord = WorkflowCoordinator::new();
        let id = coord.create_workflow(
            "test workflow",
            vec![
                NewWorkflowStep {
                    assigned_to: sunny(),
                    operation: "step-a".to_owned(),
                },
                NewWorkflowStep {
                    assigned_to: gold(),
                    operation: "step-b".to_owned(),
                },
            ],
        );
        let wf = coord.workflow_status(&id).unwrap();
        assert_eq!(wf.name, "test workflow");
        assert_eq!(wf.steps.len(), 2);
        assert_eq!(wf.status, WorkflowStatus::Pending);
        assert_eq!(wf.current_step, 0);
    }

    #[test]
    fn workflow_advance_first_step() {
        let mut coord = WorkflowCoordinator::new();
        let id = coord.create_workflow(
            "wf",
            vec![
                NewWorkflowStep {
                    assigned_to: sunny(),
                    operation: "a".to_owned(),
                },
                NewWorkflowStep {
                    assigned_to: gold(),
                    operation: "b".to_owned(),
                },
            ],
        );
        let next = coord.advance_workflow(&id, json!("done")).unwrap();
        assert!(next.is_some());
        let next_step = next.unwrap();
        assert_eq!(next_step.assigned_to, gold());
        assert_eq!(next_step.status, StepStatus::InProgress);

        let wf = coord.workflow_status(&id).unwrap();
        assert_eq!(wf.steps[0].status, StepStatus::Completed);
        assert_eq!(wf.status, WorkflowStatus::InProgress);
    }

    #[test]
    fn workflow_advance_to_completion() {
        let mut coord = WorkflowCoordinator::new();
        let id = coord.create_workflow(
            "wf",
            vec![
                NewWorkflowStep {
                    assigned_to: sunny(),
                    operation: "a".to_owned(),
                },
                NewWorkflowStep {
                    assigned_to: gold(),
                    operation: "b".to_owned(),
                },
            ],
        );
        coord.advance_workflow(&id, json!("step-a done")).unwrap();
        let result = coord.advance_workflow(&id, json!("step-b done")).unwrap();
        assert!(result.is_none()); // no more steps

        let wf = coord.workflow_status(&id).unwrap();
        assert_eq!(wf.status, WorkflowStatus::Completed);
        assert_eq!(wf.steps[0].status, StepStatus::Completed);
        assert_eq!(wf.steps[1].status, StepStatus::Completed);
    }

    #[test]
    fn workflow_advance_completed_fails() {
        let mut coord = WorkflowCoordinator::new();
        let id = coord.create_workflow(
            "wf",
            vec![NewWorkflowStep {
                assigned_to: sunny(),
                operation: "a".to_owned(),
            }],
        );
        coord.advance_workflow(&id, json!("done")).unwrap();
        let result = coord.advance_workflow(&id, json!("again"));
        assert!(result.is_err());
    }

    #[test]
    fn workflow_fail() {
        let mut coord = WorkflowCoordinator::new();
        let id = coord.create_workflow(
            "wf",
            vec![
                NewWorkflowStep {
                    assigned_to: sunny(),
                    operation: "a".to_owned(),
                },
                NewWorkflowStep {
                    assigned_to: gold(),
                    operation: "b".to_owned(),
                },
            ],
        );
        coord
            .fail_workflow(&id, json!({"error": "timeout"}))
            .unwrap();
        let wf = coord.workflow_status(&id).unwrap();
        assert_eq!(wf.status, WorkflowStatus::Failed);
        assert_eq!(wf.steps[0].status, StepStatus::Failed);
        assert_eq!(wf.steps[1].status, StepStatus::Skipped);
    }

    #[test]
    fn workflow_fail_already_terminal() {
        let mut coord = WorkflowCoordinator::new();
        let id = coord.create_workflow(
            "wf",
            vec![NewWorkflowStep {
                assigned_to: sunny(),
                operation: "a".to_owned(),
            }],
        );
        coord.advance_workflow(&id, json!("done")).unwrap();
        let result = coord.fail_workflow(&id, json!("too late"));
        assert!(result.is_err());
    }

    #[test]
    fn workflow_cancel() {
        let mut coord = WorkflowCoordinator::new();
        let id = coord.create_workflow(
            "wf",
            vec![
                NewWorkflowStep {
                    assigned_to: sunny(),
                    operation: "a".to_owned(),
                },
                NewWorkflowStep {
                    assigned_to: gold(),
                    operation: "b".to_owned(),
                },
            ],
        );
        coord.cancel_workflow(&id).unwrap();
        let wf = coord.workflow_status(&id).unwrap();
        assert_eq!(wf.status, WorkflowStatus::Cancelled);
        assert_eq!(wf.steps[0].status, StepStatus::Skipped);
        assert_eq!(wf.steps[1].status, StepStatus::Skipped);
    }

    #[test]
    fn workflow_cancel_already_terminal() {
        let mut coord = WorkflowCoordinator::new();
        let id = coord.create_workflow(
            "wf",
            vec![NewWorkflowStep {
                assigned_to: sunny(),
                operation: "a".to_owned(),
            }],
        );
        coord.cancel_workflow(&id).unwrap();
        let result = coord.cancel_workflow(&id);
        assert!(result.is_err());
    }

    #[test]
    fn workflow_status_nonexistent() {
        let coord = WorkflowCoordinator::new();
        assert!(coord.workflow_status("nonexistent").is_none());
    }

    #[test]
    fn workflow_multiple_simultaneous() {
        let mut coord = WorkflowCoordinator::new();
        let id1 = coord.create_workflow(
            "wf-1",
            vec![NewWorkflowStep {
                assigned_to: sunny(),
                operation: "a".to_owned(),
            }],
        );
        let id2 = coord.create_workflow(
            "wf-2",
            vec![NewWorkflowStep {
                assigned_to: gold(),
                operation: "b".to_owned(),
            }],
        );
        assert_eq!(coord.active_count(), 2);
        assert_eq!(coord.workflow_ids().len(), 2);

        coord.advance_workflow(&id1, json!("done")).unwrap();
        assert_eq!(coord.active_count(), 1);

        coord.advance_workflow(&id2, json!("done")).unwrap();
        assert_eq!(coord.active_count(), 0);
    }

    #[test]
    fn workflow_advance_not_found() {
        let mut coord = WorkflowCoordinator::new();
        let result = coord.advance_workflow("ghost", json!("nope"));
        assert!(result.is_err());
    }

    #[test]
    fn workflow_serde_roundtrip() {
        let wf = Workflow {
            id: "wf-001".to_owned(),
            name: "test".to_owned(),
            steps: vec![WorkflowStep {
                id: "step-0".to_owned(),
                assigned_to: sunny(),
                operation: "test-op".to_owned(),
                status: StepStatus::Pending,
                result: None,
            }],
            current_step: 0,
            status: WorkflowStatus::Pending,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_value(&wf).unwrap();
        let back: Workflow = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "wf-001");
        assert_eq!(back.steps.len(), 1);
    }

    #[test]
    fn workflow_step_serde_roundtrip() {
        let step = WorkflowStep {
            id: "step-0".to_owned(),
            assigned_to: gold(),
            operation: "issues.create".to_owned(),
            status: StepStatus::Completed,
            result: Some(json!({"issue_id": 42})),
        };
        let json = serde_json::to_value(&step).unwrap();
        let back: WorkflowStep = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "step-0");
        assert_eq!(back.status, StepStatus::Completed);
        assert_eq!(back.result.unwrap()["issue_id"], 42);
    }

    #[test]
    fn workflow_status_serde_all_variants() {
        let variants = [
            WorkflowStatus::Pending,
            WorkflowStatus::InProgress,
            WorkflowStatus::Completed,
            WorkflowStatus::Failed,
            WorkflowStatus::Cancelled,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: WorkflowStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn step_status_serde_all_variants() {
        let variants = [
            StepStatus::Pending,
            StepStatus::InProgress,
            StepStatus::Completed,
            StepStatus::Failed,
            StepStatus::Skipped,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: StepStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn workflow_status_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&WorkflowStatus::InProgress).unwrap(),
            "\"in_progress\""
        );
    }

    #[test]
    fn step_status_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&StepStatus::InProgress).unwrap(),
            "\"in_progress\""
        );
    }

    // ── BodyType discriminant ────────────────────────────────────────

    #[test]
    fn body_type_discriminant_text() {
        assert_eq!(message_body_type(&text_body("x")), BodyType::Text);
    }

    #[test]
    fn body_type_discriminant_announce() {
        assert_eq!(
            message_body_type(&MessageBody::ConnectorAnnounce {
                connector_id: "c".to_owned(),
                operations: Vec::new(),
                zone: "z".to_owned(),
            }),
            BodyType::ConnectorAnnounce
        );
    }

    #[test]
    fn body_type_discriminant_reserve() {
        assert_eq!(
            message_body_type(&MessageBody::ResourceReserve {
                connector_id: "c".to_owned(),
                operation: "o".to_owned(),
                duration_secs: 1,
                reason: "r".to_owned(),
            }),
            BodyType::ResourceReserve
        );
    }

    #[test]
    fn body_type_discriminant_release() {
        assert_eq!(
            message_body_type(&MessageBody::ResourceRelease {
                connector_id: "c".to_owned(),
                operation: "o".to_owned(),
                reservation_id: "r".to_owned(),
            }),
            BodyType::ResourceRelease
        );
    }

    #[test]
    fn body_type_discriminant_handoff() {
        assert_eq!(
            message_body_type(&MessageBody::WorkflowHandoff {
                workflow_id: "w".to_owned(),
                step_completed: "s".to_owned(),
                next_step: "n".to_owned(),
                context: json!(null),
            }),
            BodyType::WorkflowHandoff
        );
    }

    #[test]
    fn body_type_discriminant_status() {
        assert_eq!(
            message_body_type(&MessageBody::StatusUpdate {
                task_id: "t".to_owned(),
                status: "s".to_owned(),
                detail: "d".to_owned(),
            }),
            BodyType::StatusUpdate
        );
    }

    #[test]
    fn body_type_serde_roundtrip() {
        let variants = [
            BodyType::Text,
            BodyType::ConnectorAnnounce,
            BodyType::ResourceReserve,
            BodyType::ResourceRelease,
            BodyType::WorkflowHandoff,
            BodyType::StatusUpdate,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: BodyType = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    // ── Reservation key ──────────────────────────────────────────────

    #[test]
    fn reservation_key_format() {
        assert_eq!(
            reservation_key("github", "issues.create"),
            "github:issues.create"
        );
    }

    // ── split_pascal_words ───────────────────────────────────────────

    #[test]
    fn split_pascal_valid() {
        let words = split_pascal_words("SunnyMoose").unwrap();
        assert_eq!(words, vec!["Sunny", "Moose"]);
    }

    #[test]
    fn split_pascal_three_words() {
        let words = split_pascal_words("SunnyBigMoose").unwrap();
        assert_eq!(words, vec!["Sunny", "Big", "Moose"]);
    }

    #[test]
    fn split_pascal_empty() {
        assert!(split_pascal_words("").is_none());
    }

    #[test]
    fn split_pascal_lowercase_start() {
        assert!(split_pascal_words("sunnyMoose").is_none());
    }

    #[test]
    fn split_pascal_with_digits() {
        assert!(split_pascal_words("Sunny123").is_none());
    }

    #[test]
    fn split_pascal_single_letter_word() {
        // "AB" → words ["A", "B"] but each <2 chars, so None
        assert!(split_pascal_words("AB").is_none());
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn agent_id_unicode_rejected() {
        assert!(AgentId::parse("S\u{00fc}nnyMoose").is_none());
    }

    #[test]
    fn mail_message_subject_can_be_empty() {
        let msg = MailMessage::new(sunny(), gold(), "", text_body("body"));
        assert!(msg.subject.is_empty());
    }

    #[test]
    fn mail_filter_subject_contains_empty_matches_all() {
        let filter = MailFilter::new().subject_contains("");
        let msg = make_msg(sunny(), gold(), "anything", text_body("body"));
        assert!(filter.matches(&msg));
    }

    #[test]
    fn reservation_after_release_can_be_re_granted() {
        let mut store = ReservationStore::new();
        let r = store.request_reservation(ReservationRequest {
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            requester: sunny(),
            duration_secs: 300,
            reason: "first".to_owned(),
        });
        let id = if let ReservationResult::Granted { reservation } = r {
            reservation.id
        } else {
            panic!("expected Granted");
        };
        store.release_reservation(&id).unwrap();

        // Now a different agent can get the same resource.
        let r2 = store.request_reservation(ReservationRequest {
            connector_id: "github".to_owned(),
            operation: "issues.create".to_owned(),
            requester: gold(),
            duration_secs: 300,
            reason: "second".to_owned(),
        });
        assert!(matches!(r2, ReservationResult::Granted { .. }));
    }

    #[test]
    fn workflow_three_step_full_lifecycle() {
        let mut coord = WorkflowCoordinator::new();
        let id = coord.create_workflow(
            "pipeline",
            vec![
                NewWorkflowStep {
                    assigned_to: sunny(),
                    operation: "fetch".to_owned(),
                },
                NewWorkflowStep {
                    assigned_to: gold(),
                    operation: "transform".to_owned(),
                },
                NewWorkflowStep {
                    assigned_to: green(),
                    operation: "publish".to_owned(),
                },
            ],
        );

        // Step 0: fetch
        let next = coord.advance_workflow(&id, json!({"rows": 100})).unwrap();
        assert_eq!(next.unwrap().operation, "transform");

        // Step 1: transform
        let next = coord
            .advance_workflow(&id, json!({"transformed": true}))
            .unwrap();
        assert_eq!(next.unwrap().operation, "publish");

        // Step 2: publish (final)
        let next = coord
            .advance_workflow(&id, json!({"published": true}))
            .unwrap();
        assert!(next.is_none());

        let wf = coord.workflow_status(&id).unwrap();
        assert_eq!(wf.status, WorkflowStatus::Completed);
        for step in &wf.steps {
            assert_eq!(step.status, StepStatus::Completed);
            assert!(step.result.is_some());
        }
    }

    #[test]
    fn workflow_fail_mid_pipeline() {
        let mut coord = WorkflowCoordinator::new();
        let id = coord.create_workflow(
            "pipeline",
            vec![
                NewWorkflowStep {
                    assigned_to: sunny(),
                    operation: "a".to_owned(),
                },
                NewWorkflowStep {
                    assigned_to: gold(),
                    operation: "b".to_owned(),
                },
                NewWorkflowStep {
                    assigned_to: green(),
                    operation: "c".to_owned(),
                },
            ],
        );

        // Complete step 0.
        coord.advance_workflow(&id, json!("ok")).unwrap();

        // Fail at step 1.
        coord.fail_workflow(&id, json!({"error": "oops"})).unwrap();

        let wf = coord.workflow_status(&id).unwrap();
        assert_eq!(wf.status, WorkflowStatus::Failed);
        assert_eq!(wf.steps[0].status, StepStatus::Completed);
        assert_eq!(wf.steps[1].status, StepStatus::Failed);
        assert_eq!(wf.steps[2].status, StepStatus::Skipped);
    }
}
