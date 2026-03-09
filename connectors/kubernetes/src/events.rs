//! Kubernetes event watching and subscription system.
//!
//! Provides streaming access to Kubernetes watch APIs and events.
//! Supports monitoring resource changes, detecting failures and rollouts,
//! and building alerting pipelines with bounded, backpressured event buffers.
//!
//! Event payloads are treated as tainted external input and stored as
//! opaque `serde_json::Value` blobs.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Watch event types
// ---------------------------------------------------------------------------

/// The type of a Kubernetes watch event as returned by the Watch API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WatchEventType {
    /// A new resource was created.
    Added,
    /// An existing resource was modified.
    Modified,
    /// A resource was deleted.
    Deleted,
    /// A periodic bookmark for resource version tracking.
    Bookmark,
    /// An error event from the watch stream.
    Error,
}

impl std::fmt::Display for WatchEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Added => write!(f, "ADDED"),
            Self::Modified => write!(f, "MODIFIED"),
            Self::Deleted => write!(f, "DELETED"),
            Self::Bookmark => write!(f, "BOOKMARK"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

// ---------------------------------------------------------------------------
// WatchEvent
// ---------------------------------------------------------------------------

/// A single event received from a Kubernetes watch stream.
///
/// The `payload` field contains the raw JSON object from the API and should be
/// treated as tainted external input — never trust its structure or contents
/// without validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchEvent {
    /// The type of mutation observed.
    pub event_type: WatchEventType,
    /// The API resource kind (e.g. `"Pod"`, `"Deployment"`).
    pub resource_kind: String,
    /// The resource name from `metadata.name`.
    pub name: String,
    /// The namespace, if any.
    pub namespace: Option<String>,
    /// The `metadata.resourceVersion` at the time of the event.
    pub resource_version: Option<String>,
    /// ISO-8601 timestamp of when the event was recorded.
    pub timestamp: Option<String>,
    /// The raw JSON payload — tainted external input.
    pub payload: serde_json::Value,
    /// Labels attached to the resource.
    pub labels: HashMap<String, String>,
}

impl WatchEvent {
    /// Create a new `WatchEvent`.
    #[must_use]
    pub fn new(
        event_type: WatchEventType,
        resource_kind: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            event_type,
            resource_kind: resource_kind.into(),
            name: name.into(),
            namespace: None,
            resource_version: None,
            timestamp: None,
            payload: serde_json::Value::Null,
            labels: HashMap::new(),
        }
    }

    /// Set the namespace.
    #[must_use]
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Set the resource version.
    #[must_use]
    pub fn with_resource_version(mut self, rv: impl Into<String>) -> Self {
        self.resource_version = Some(rv.into());
        self
    }

    /// Set the timestamp.
    #[must_use]
    pub fn with_timestamp(mut self, ts: impl Into<String>) -> Self {
        self.timestamp = Some(ts.into());
        self
    }

    /// Set the payload.
    #[must_use]
    pub fn with_payload(mut self, payload: serde_json::Value) -> Self {
        self.payload = payload;
        self
    }

    /// Add a single label.
    #[must_use]
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// Set all labels at once.
    #[must_use]
    pub fn with_labels(mut self, labels: HashMap<String, String>) -> Self {
        self.labels = labels;
        self
    }

    /// Returns `true` when the event represents an error.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self.event_type, WatchEventType::Error)
    }

    /// Returns `true` when the event is a bookmark.
    #[must_use]
    pub const fn is_bookmark(&self) -> bool {
        matches!(self.event_type, WatchEventType::Bookmark)
    }

    /// Returns `true` for mutation events (Added, Modified, Deleted).
    #[must_use]
    pub const fn is_mutation(&self) -> bool {
        matches!(
            self.event_type,
            WatchEventType::Added | WatchEventType::Modified | WatchEventType::Deleted
        )
    }
}

// ---------------------------------------------------------------------------
// WatchFilter
// ---------------------------------------------------------------------------

/// Filters applied when subscribing to a watch stream.
///
/// Follows the builder pattern — start with `WatchFilter::new()` and chain
/// `.with_*()` calls.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchFilter {
    /// Restrict events to a single namespace.
    pub namespace: Option<String>,
    /// Kubernetes label selector expression (e.g. `"app=nginx"`).
    pub label_selector: Option<String>,
    /// Kubernetes field selector expression (e.g. `"status.phase=Running"`).
    pub field_selector: Option<String>,
    /// Only watch these resource kinds (empty = all).
    pub resource_kinds: Vec<String>,
    /// Resume from a specific resource version.
    pub resource_version_start: Option<String>,
}

impl WatchFilter {
    /// Create an empty filter (matches everything).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to a namespace.
    #[must_use]
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Set a label selector.
    #[must_use]
    pub fn with_label(mut self, selector: impl Into<String>) -> Self {
        self.label_selector = Some(selector.into());
        self
    }

    /// Set a field selector.
    #[must_use]
    pub fn with_field(mut self, selector: impl Into<String>) -> Self {
        self.field_selector = Some(selector.into());
        self
    }

    /// Add a resource kind to watch.
    #[must_use]
    pub fn with_kind(mut self, kind: impl Into<String>) -> Self {
        self.resource_kinds.push(kind.into());
        self
    }

    /// Set the starting resource version.
    #[must_use]
    pub fn with_resource_version(mut self, rv: impl Into<String>) -> Self {
        self.resource_version_start = Some(rv.into());
        self
    }

    /// Returns `true` when the filter has no constraints at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.namespace.is_none()
            && self.label_selector.is_none()
            && self.field_selector.is_none()
            && self.resource_kinds.is_empty()
            && self.resource_version_start.is_none()
    }

    /// Check whether a [`WatchEvent`] matches this filter.
    ///
    /// Label selector matching is simplified: we check whether *all*
    /// `key=value` pairs in the selector appear in the event labels.
    /// Field selectors are not evaluated client-side and always match.
    #[must_use]
    pub fn matches(&self, event: &WatchEvent) -> bool {
        // Namespace filter
        if let Some(ref ns) = self.namespace {
            match &event.namespace {
                Some(ens) if ens != ns => return false,
                None => return false,
                _ => {}
            }
        }

        // Resource kind filter
        if !self.resource_kinds.is_empty()
            && !self.resource_kinds.iter().any(|k| k == &event.resource_kind)
        {
            return false;
        }

        // Simplified label selector matching: "key=value,key2=value2"
        if let Some(ref selector) = self.label_selector {
            for part in selector.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some((key, value)) = part.split_once('=') {
                    match event.labels.get(key.trim()) {
                        Some(v) if v == value.trim() => {}
                        _ => return false,
                    }
                }
            }
        }

        true
    }
}

// ---------------------------------------------------------------------------
// OverflowPolicy + EventBuffer
// ---------------------------------------------------------------------------

/// Strategy for handling buffer overflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OverflowPolicy {
    /// Drop the oldest event when the buffer is full.
    DropOldest,
    /// Drop the newest (incoming) event when the buffer is full.
    DropNewest,
    /// Reject the new event and signal backpressure.
    RejectNew,
}

/// Current status snapshot of an [`EventBuffer`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BufferStatus {
    /// Number of events currently in the buffer.
    pub current_size: usize,
    /// Maximum capacity.
    pub capacity: usize,
    /// Total number of events dropped since creation.
    pub dropped_total: u64,
    /// Whether the buffer is at capacity.
    pub is_full: bool,
    /// Timestamp of the oldest buffered event, if any.
    pub oldest_timestamp: Option<String>,
    /// Timestamp of the newest buffered event, if any.
    pub newest_timestamp: Option<String>,
}

/// A bounded ring-buffer for watch events with configurable overflow policy.
#[derive(Debug, Clone)]
pub struct EventBuffer {
    events: VecDeque<WatchEvent>,
    capacity: usize,
    dropped_count: u64,
    overflow_policy: OverflowPolicy,
}

impl EventBuffer {
    /// Create a new buffer with the given capacity and overflow policy.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize, policy: OverflowPolicy) -> Self {
        assert!(capacity > 0, "EventBuffer capacity must be > 0");
        Self {
            events: VecDeque::with_capacity(capacity),
            capacity,
            dropped_count: 0,
            overflow_policy: policy,
        }
    }

    /// Try to push an event into the buffer.
    ///
    /// Returns `true` if the event was accepted, `false` if it was dropped
    /// (only possible with `RejectNew` when full).
    pub fn push(&mut self, event: WatchEvent) -> bool {
        if self.events.len() >= self.capacity {
            match self.overflow_policy {
                OverflowPolicy::DropOldest => {
                    self.events.pop_front();
                    self.dropped_count += 1;
                    self.events.push_back(event);
                    true
                }
                OverflowPolicy::DropNewest => {
                    self.dropped_count += 1;
                    false
                }
                OverflowPolicy::RejectNew => {
                    self.dropped_count += 1;
                    false
                }
            }
        } else {
            self.events.push_back(event);
            true
        }
    }

    /// Drain all events from the buffer, returning them in insertion order.
    pub fn drain(&mut self) -> Vec<WatchEvent> {
        self.events.drain(..).collect()
    }

    /// Peek at the front event without removing it.
    #[must_use]
    pub fn peek_front(&self) -> Option<&WatchEvent> {
        self.events.front()
    }

    /// Peek at the back event without removing it.
    #[must_use]
    pub fn peek_back(&self) -> Option<&WatchEvent> {
        self.events.back()
    }

    /// Current number of events in the buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Whether the buffer is at capacity.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.events.len() >= self.capacity
    }

    /// Total number of dropped events since creation.
    #[must_use]
    pub const fn dropped_count(&self) -> u64 {
        self.dropped_count
    }

    /// The configured capacity.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The overflow policy.
    #[must_use]
    pub const fn overflow_policy(&self) -> OverflowPolicy {
        self.overflow_policy
    }

    /// Produce a status snapshot.
    #[must_use]
    pub fn status(&self) -> BufferStatus {
        BufferStatus {
            current_size: self.events.len(),
            capacity: self.capacity,
            dropped_total: self.dropped_count,
            is_full: self.is_full(),
            oldest_timestamp: self
                .events
                .front()
                .and_then(|e| e.timestamp.clone()),
            newest_timestamp: self
                .events
                .back()
                .and_then(|e| e.timestamp.clone()),
        }
    }

    /// Clear all buffered events (does not reset dropped count).
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

// ---------------------------------------------------------------------------
// EventSubscription
// ---------------------------------------------------------------------------

/// An individual subscription to a filtered stream of watch events.
#[derive(Debug, Clone)]
pub struct EventSubscription {
    /// Unique subscription identifier.
    pub id: u64,
    /// Filter controlling which events this subscription receives.
    pub filter: WatchFilter,
    /// Bounded event buffer.
    buffer: EventBuffer,
    /// When the subscription was created (ISO-8601).
    pub created_at: String,
    /// Whether the subscription is still active.
    active: bool,
    /// The resource version of the last accepted event.
    last_event_version: Option<String>,
}

impl EventSubscription {
    /// Create a new active subscription.
    #[must_use]
    pub fn new(id: u64, filter: WatchFilter, buffer_capacity: usize, policy: OverflowPolicy) -> Self {
        Self {
            id,
            filter,
            buffer: EventBuffer::new(buffer_capacity, policy),
            created_at: String::from("2026-01-01T00:00:00Z"),
            active: true,
            last_event_version: None,
        }
    }

    /// Create a subscription with a specific timestamp.
    #[must_use]
    pub fn with_created_at(mut self, ts: impl Into<String>) -> Self {
        self.created_at = ts.into();
        self
    }

    /// Try to push an event. The event is only buffered if the subscription
    /// is active and the event matches the filter.
    ///
    /// Returns `true` if the event was accepted into the buffer.
    pub fn push_event(&mut self, event: &WatchEvent) -> bool {
        if !self.active {
            return false;
        }
        if !self.filter.matches(event) {
            return false;
        }
        let accepted = self.buffer.push(event.clone());
        if accepted {
            if let Some(ref rv) = event.resource_version {
                self.last_event_version = Some(rv.clone());
            }
        }
        accepted
    }

    /// Drain all buffered events.
    pub fn drain_events(&mut self) -> Vec<WatchEvent> {
        self.buffer.drain()
    }

    /// Get a status snapshot of the underlying buffer.
    #[must_use]
    pub fn status(&self) -> BufferStatus {
        self.buffer.status()
    }

    /// Deactivate the subscription. No further events will be accepted.
    pub const fn deactivate(&mut self) {
        self.active = false;
    }

    /// Whether the subscription is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Whether the buffer is full (backpressure signal).
    #[must_use]
    pub fn is_backpressured(&self) -> bool {
        self.buffer.is_full()
    }

    /// The resource version of the last successfully buffered event.
    #[must_use]
    pub fn last_event_version(&self) -> Option<&str> {
        self.last_event_version.as_deref()
    }

    /// Number of events currently buffered.
    #[must_use]
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    /// Total events dropped by this subscription.
    #[must_use]
    pub const fn dropped_count(&self) -> u64 {
        self.buffer.dropped_count()
    }
}

// ---------------------------------------------------------------------------
// SubscriptionManager
// ---------------------------------------------------------------------------

/// Error returned when creating a subscription fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionError {
    /// Maximum number of subscriptions reached.
    MaxSubscriptionsReached { limit: usize },
}

impl std::fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MaxSubscriptionsReached { limit } => {
                write!(f, "max subscriptions reached (limit: {limit})")
            }
        }
    }
}

impl std::error::Error for SubscriptionError {}

/// Manages a collection of event subscriptions, routing incoming watch events
/// to all matching subscribers.
#[derive(Debug)]
pub struct SubscriptionManager {
    subscriptions: HashMap<u64, EventSubscription>,
    max_subscriptions: usize,
    next_id: u64,
}

impl SubscriptionManager {
    /// Create a new manager with a maximum subscription count.
    #[must_use]
    pub fn new(max_subscriptions: usize) -> Self {
        Self {
            subscriptions: HashMap::new(),
            max_subscriptions,
            next_id: 1,
        }
    }

    /// Create a new subscription, returning its id.
    ///
    /// # Errors
    ///
    /// Returns [`SubscriptionError::MaxSubscriptionsReached`] if the limit is
    /// already reached.
    pub fn create_subscription(
        &mut self,
        filter: WatchFilter,
        buffer_capacity: usize,
        policy: OverflowPolicy,
    ) -> Result<u64, SubscriptionError> {
        if self.subscriptions.len() >= self.max_subscriptions {
            return Err(SubscriptionError::MaxSubscriptionsReached {
                limit: self.max_subscriptions,
            });
        }
        let id = self.next_id;
        self.next_id += 1;
        let sub = EventSubscription::new(id, filter, buffer_capacity, policy);
        self.subscriptions.insert(id, sub);
        Ok(id)
    }

    /// Remove a subscription by id. Returns the removed subscription if found.
    pub fn remove_subscription(&mut self, id: u64) -> Option<EventSubscription> {
        self.subscriptions.remove(&id)
    }

    /// Push an event to all active, matching subscriptions.
    ///
    /// Returns the number of subscriptions that accepted the event.
    pub fn push_to_matching(&mut self, event: &WatchEvent) -> usize {
        let mut count = 0;
        for sub in self.subscriptions.values_mut() {
            if sub.push_event(event) {
                count += 1;
            }
        }
        count
    }

    /// Number of active subscriptions.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.subscriptions.values().filter(|s| s.is_active()).count()
    }

    /// Total number of subscriptions (active and inactive).
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Get a status snapshot for a subscription.
    #[must_use]
    pub fn subscription_status(&self, id: u64) -> Option<BufferStatus> {
        self.subscriptions.get(&id).map(EventSubscription::status)
    }

    /// Get a reference to a subscription.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&EventSubscription> {
        self.subscriptions.get(&id)
    }

    /// Get a mutable reference to a subscription.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut EventSubscription> {
        self.subscriptions.get_mut(&id)
    }

    /// Drain events from a specific subscription.
    pub fn drain_events(&mut self, id: u64) -> Option<Vec<WatchEvent>> {
        self.subscriptions.get_mut(&id).map(EventSubscription::drain_events)
    }

    /// Deactivate a subscription (but don't remove it).
    pub fn deactivate(&mut self, id: u64) -> bool {
        if let Some(sub) = self.subscriptions.get_mut(&id) {
            sub.deactivate();
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Cluster events
// ---------------------------------------------------------------------------

/// The type / severity of a Kubernetes cluster event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClusterEventType {
    /// Informational event.
    Normal,
    /// Warning event.
    Warning,
}

impl std::fmt::Display for ClusterEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "Normal"),
            Self::Warning => write!(f, "Warning"),
        }
    }
}

/// A Kubernetes cluster event (from the Events API).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterEvent {
    /// Unique event identifier.
    pub uid: String,
    /// Short machine-readable reason (e.g. `"Pulled"`, `"FailedScheduling"`).
    pub reason: String,
    /// Human-readable message.
    pub message: String,
    /// Normal or Warning.
    pub event_type: ClusterEventType,
    /// The component that reported the event (e.g. `"kubelet"`).
    pub source_component: Option<String>,
    /// The kind of the object this event is about.
    pub regarding_kind: Option<String>,
    /// The name of the object this event is about.
    pub regarding_name: Option<String>,
    /// The namespace of the object this event is about.
    pub regarding_namespace: Option<String>,
    /// How many times this event has been seen.
    pub count: u32,
    /// ISO-8601 timestamp of the first occurrence.
    pub first_timestamp: Option<String>,
    /// ISO-8601 timestamp of the most recent occurrence.
    pub last_timestamp: Option<String>,
}

impl ClusterEvent {
    /// Create a new cluster event.
    #[must_use]
    pub fn new(
        uid: impl Into<String>,
        reason: impl Into<String>,
        message: impl Into<String>,
        event_type: ClusterEventType,
    ) -> Self {
        Self {
            uid: uid.into(),
            reason: reason.into(),
            message: message.into(),
            event_type,
            source_component: None,
            regarding_kind: None,
            regarding_name: None,
            regarding_namespace: None,
            count: 1,
            first_timestamp: None,
            last_timestamp: None,
        }
    }

    /// Set the source component.
    #[must_use]
    pub fn with_source(mut self, component: impl Into<String>) -> Self {
        self.source_component = Some(component.into());
        self
    }

    /// Set the regarding object.
    #[must_use]
    pub fn with_regarding(
        mut self,
        kind: impl Into<String>,
        name: impl Into<String>,
        namespace: Option<String>,
    ) -> Self {
        self.regarding_kind = Some(kind.into());
        self.regarding_name = Some(name.into());
        self.regarding_namespace = namespace;
        self
    }

    /// Set the occurrence count.
    #[must_use]
    pub const fn with_count(mut self, count: u32) -> Self {
        self.count = count;
        self
    }

    /// Set the first and last timestamps.
    #[must_use]
    pub fn with_timestamps(
        mut self,
        first: impl Into<String>,
        last: impl Into<String>,
    ) -> Self {
        self.first_timestamp = Some(first.into());
        self.last_timestamp = Some(last.into());
        self
    }

    /// Whether this is a warning event.
    #[must_use]
    pub const fn is_warning(&self) -> bool {
        matches!(self.event_type, ClusterEventType::Warning)
    }

    /// Whether this is a normal event.
    #[must_use]
    pub const fn is_normal(&self) -> bool {
        matches!(self.event_type, ClusterEventType::Normal)
    }

    /// Convert this cluster event into a [`WatchEvent`] for subscription routing.
    #[must_use]
    pub fn to_watch_event(&self) -> WatchEvent {
        let mut labels = HashMap::new();
        if let Some(ref src) = self.source_component {
            labels.insert("source".to_string(), src.clone());
        }
        labels.insert("reason".to_string(), self.reason.clone());

        let event_type_str = self.event_type.to_string();
        let payload = serde_json::json!({
            "uid": self.uid,
            "reason": self.reason,
            "message": self.message,
            "type": event_type_str,
            "count": self.count,
        });

        WatchEvent {
            event_type: WatchEventType::Added,
            resource_kind: String::from("Event"),
            name: self.uid.clone(),
            namespace: self.regarding_namespace.clone(),
            resource_version: None,
            timestamp: self.last_timestamp.clone(),
            payload,
            labels,
        }
    }
}

// ---------------------------------------------------------------------------
// Rollout status
// ---------------------------------------------------------------------------

/// A condition on a Kubernetes deployment rollout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutCondition {
    /// Condition type (e.g. `"Available"`, `"Progressing"`).
    pub condition_type: String,
    /// Status string (`"True"`, `"False"`, `"Unknown"`).
    pub status: String,
    /// Machine-readable reason.
    pub reason: Option<String>,
    /// Human-readable message.
    pub message: Option<String>,
}

impl RolloutCondition {
    /// Create a new rollout condition.
    #[must_use]
    pub fn new(
        condition_type: impl Into<String>,
        status: impl Into<String>,
    ) -> Self {
        Self {
            condition_type: condition_type.into(),
            status: status.into(),
            reason: None,
            message: None,
        }
    }

    /// Set the reason.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Set the message.
    #[must_use]
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Whether this condition is `True`.
    #[must_use]
    pub fn is_true(&self) -> bool {
        self.status == "True"
    }

    /// Whether this condition is `False`.
    #[must_use]
    pub fn is_false(&self) -> bool {
        self.status == "False"
    }
}

/// Status of a Kubernetes deployment rollout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutStatus {
    /// Name of the deployment.
    pub deployment_name: String,
    /// Namespace of the deployment.
    pub namespace: Option<String>,
    /// Desired number of replicas.
    pub desired_replicas: u32,
    /// Number of replicas that are ready.
    pub ready_replicas: u32,
    /// Number of replicas running the updated spec.
    pub updated_replicas: u32,
    /// Whether the deployment is fully available.
    pub available: bool,
    /// Deployment conditions.
    pub conditions: Vec<RolloutCondition>,
}

impl RolloutStatus {
    /// Create a new rollout status.
    #[must_use]
    pub fn new(
        deployment_name: impl Into<String>,
        desired_replicas: u32,
    ) -> Self {
        Self {
            deployment_name: deployment_name.into(),
            namespace: None,
            desired_replicas,
            ready_replicas: 0,
            updated_replicas: 0,
            available: false,
            conditions: Vec::new(),
        }
    }

    /// Set the namespace.
    #[must_use]
    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Set ready replicas.
    #[must_use]
    pub const fn with_ready_replicas(mut self, count: u32) -> Self {
        self.ready_replicas = count;
        self
    }

    /// Set updated replicas.
    #[must_use]
    pub const fn with_updated_replicas(mut self, count: u32) -> Self {
        self.updated_replicas = count;
        self
    }

    /// Set availability.
    #[must_use]
    pub const fn with_available(mut self, available: bool) -> Self {
        self.available = available;
        self
    }

    /// Add a condition.
    #[must_use]
    pub fn with_condition(mut self, condition: RolloutCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// Whether the rollout is complete (all replicas ready and updated).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.ready_replicas >= self.desired_replicas
            && self.updated_replicas >= self.desired_replicas
            && self.available
    }

    /// Percentage of replicas that are ready (0–100).
    #[must_use]
    pub const fn ready_percentage(&self) -> u32 {
        if self.desired_replicas == 0 {
            return 100;
        }
        (self.ready_replicas * 100) / self.desired_replicas
    }

    /// Whether any condition indicates a failure.
    #[must_use]
    pub fn has_failure_condition(&self) -> bool {
        self.conditions.iter().any(|c| {
            c.condition_type == "Available" && c.is_false()
                || c.reason.as_deref() == Some("ProgressDeadlineExceeded")
        })
    }

    /// Find a condition by type.
    #[must_use]
    pub fn find_condition(&self, condition_type: &str) -> Option<&RolloutCondition> {
        self.conditions
            .iter()
            .find(|c| c.condition_type == condition_type)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- WatchEventType ----

    #[test]
    fn watch_event_type_display() {
        assert_eq!(WatchEventType::Added.to_string(), "ADDED");
        assert_eq!(WatchEventType::Modified.to_string(), "MODIFIED");
        assert_eq!(WatchEventType::Deleted.to_string(), "DELETED");
        assert_eq!(WatchEventType::Bookmark.to_string(), "BOOKMARK");
        assert_eq!(WatchEventType::Error.to_string(), "ERROR");
    }

    #[test]
    fn watch_event_type_serde_roundtrip() {
        for ty in [
            WatchEventType::Added,
            WatchEventType::Modified,
            WatchEventType::Deleted,
            WatchEventType::Bookmark,
            WatchEventType::Error,
        ] {
            let json = serde_json::to_string(&ty).unwrap();
            let back: WatchEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(ty, back);
        }
    }

    #[test]
    fn watch_event_type_serde_screaming_snake() {
        let json = serde_json::to_string(&WatchEventType::Added).unwrap();
        assert_eq!(json, "\"ADDED\"");
        let json = serde_json::to_string(&WatchEventType::Bookmark).unwrap();
        assert_eq!(json, "\"BOOKMARK\"");
    }

    #[test]
    fn watch_event_type_equality_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(WatchEventType::Added);
        set.insert(WatchEventType::Added);
        assert_eq!(set.len(), 1);
        set.insert(WatchEventType::Deleted);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn watch_event_type_clone_and_copy() {
        let t = WatchEventType::Modified;
        let t2 = t;
        assert_eq!(t, t2);
    }

    // ---- WatchEvent ----

    #[test]
    fn watch_event_new_defaults() {
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "my-pod");
        assert_eq!(e.event_type, WatchEventType::Added);
        assert_eq!(e.resource_kind, "Pod");
        assert_eq!(e.name, "my-pod");
        assert!(e.namespace.is_none());
        assert!(e.resource_version.is_none());
        assert!(e.timestamp.is_none());
        assert_eq!(e.payload, serde_json::Value::Null);
        assert!(e.labels.is_empty());
    }

    #[test]
    fn watch_event_builder_chain() {
        let e = WatchEvent::new(WatchEventType::Modified, "Deployment", "web")
            .with_namespace("production")
            .with_resource_version("12345")
            .with_timestamp("2026-01-15T10:00:00Z")
            .with_payload(serde_json::json!({"replicas": 3}))
            .with_label("app", "web")
            .with_label("env", "prod");

        assert_eq!(e.namespace.as_deref(), Some("production"));
        assert_eq!(e.resource_version.as_deref(), Some("12345"));
        assert_eq!(e.timestamp.as_deref(), Some("2026-01-15T10:00:00Z"));
        assert_eq!(e.payload["replicas"], 3);
        assert_eq!(e.labels.get("app").unwrap(), "web");
        assert_eq!(e.labels.get("env").unwrap(), "prod");
    }

    #[test]
    fn watch_event_with_labels_map() {
        let mut labels = HashMap::new();
        labels.insert("tier".to_string(), "frontend".to_string());
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p1")
            .with_labels(labels);
        assert_eq!(e.labels.len(), 1);
        assert_eq!(e.labels.get("tier").unwrap(), "frontend");
    }

    #[test]
    fn watch_event_is_error() {
        let e = WatchEvent::new(WatchEventType::Error, "Pod", "bad");
        assert!(e.is_error());
        assert!(!e.is_bookmark());
        assert!(!e.is_mutation());
    }

    #[test]
    fn watch_event_is_bookmark() {
        let e = WatchEvent::new(WatchEventType::Bookmark, "Pod", "bm");
        assert!(e.is_bookmark());
        assert!(!e.is_error());
        assert!(!e.is_mutation());
    }

    #[test]
    fn watch_event_is_mutation() {
        assert!(WatchEvent::new(WatchEventType::Added, "Pod", "a").is_mutation());
        assert!(WatchEvent::new(WatchEventType::Modified, "Pod", "b").is_mutation());
        assert!(WatchEvent::new(WatchEventType::Deleted, "Pod", "c").is_mutation());
        assert!(!WatchEvent::new(WatchEventType::Bookmark, "Pod", "d").is_mutation());
        assert!(!WatchEvent::new(WatchEventType::Error, "Pod", "e").is_mutation());
    }

    #[test]
    fn watch_event_serde_roundtrip() {
        let e = WatchEvent::new(WatchEventType::Added, "Service", "svc")
            .with_namespace("default")
            .with_resource_version("999")
            .with_timestamp("2026-01-01T00:00:00Z")
            .with_payload(serde_json::json!({"port": 80}))
            .with_label("app", "nginx");

        let json = serde_json::to_string(&e).unwrap();
        let back: WatchEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(back.event_type, WatchEventType::Added);
        assert_eq!(back.resource_kind, "Service");
        assert_eq!(back.name, "svc");
        assert_eq!(back.namespace.as_deref(), Some("default"));
        assert_eq!(back.labels.get("app").unwrap(), "nginx");
    }

    #[test]
    fn watch_event_clone() {
        let original = WatchEvent::new(WatchEventType::Added, "Pod", "clone-me")
            .with_namespace("ns")
            .with_label("key", "val");
        let cloned = original.clone();
        // Use original after clone to prove clone is independent
        assert_eq!(original.name, "clone-me");
        assert_eq!(cloned.name, "clone-me");
        assert_eq!(cloned.namespace.as_deref(), Some("ns"));
        assert_eq!(cloned.labels.get("key").unwrap(), "val");
    }

    #[test]
    fn watch_event_empty_name() {
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "");
        assert!(e.name.is_empty());
    }

    #[test]
    fn watch_event_large_payload() {
        let big = serde_json::json!({
            "data": "x".repeat(10000),
            "nested": {"a": [1, 2, 3]}
        });
        let e = WatchEvent::new(WatchEventType::Modified, "ConfigMap", "big")
            .with_payload(big.clone());
        assert_eq!(e.payload, big);
    }

    // ---- WatchFilter ----

    #[test]
    fn watch_filter_new_is_empty() {
        let f = WatchFilter::new();
        assert!(f.is_empty());
        assert!(f.namespace.is_none());
        assert!(f.label_selector.is_none());
        assert!(f.field_selector.is_none());
        assert!(f.resource_kinds.is_empty());
        assert!(f.resource_version_start.is_none());
    }

    #[test]
    fn watch_filter_builder() {
        let f = WatchFilter::new()
            .with_namespace("kube-system")
            .with_label("app=dns")
            .with_field("status.phase=Running")
            .with_kind("Pod")
            .with_kind("Service")
            .with_resource_version("100");

        assert!(!f.is_empty());
        assert_eq!(f.namespace.as_deref(), Some("kube-system"));
        assert_eq!(f.label_selector.as_deref(), Some("app=dns"));
        assert_eq!(f.field_selector.as_deref(), Some("status.phase=Running"));
        assert_eq!(f.resource_kinds, vec!["Pod", "Service"]);
        assert_eq!(f.resource_version_start.as_deref(), Some("100"));
    }

    #[test]
    fn watch_filter_matches_no_constraints() {
        let f = WatchFilter::new();
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p1");
        assert!(f.matches(&e));
    }

    #[test]
    fn watch_filter_matches_namespace() {
        let f = WatchFilter::new().with_namespace("prod");
        let e1 = WatchEvent::new(WatchEventType::Added, "Pod", "p1")
            .with_namespace("prod");
        let e2 = WatchEvent::new(WatchEventType::Added, "Pod", "p2")
            .with_namespace("dev");
        let e3 = WatchEvent::new(WatchEventType::Added, "Pod", "p3");

        assert!(f.matches(&e1));
        assert!(!f.matches(&e2));
        assert!(!f.matches(&e3)); // no namespace doesn't match
    }

    #[test]
    fn watch_filter_matches_kind() {
        let f = WatchFilter::new().with_kind("Pod").with_kind("Service");
        let e1 = WatchEvent::new(WatchEventType::Added, "Pod", "p1");
        let e2 = WatchEvent::new(WatchEventType::Added, "Service", "s1");
        let e3 = WatchEvent::new(WatchEventType::Added, "Deployment", "d1");

        assert!(f.matches(&e1));
        assert!(f.matches(&e2));
        assert!(!f.matches(&e3));
    }

    #[test]
    fn watch_filter_matches_labels() {
        let f = WatchFilter::new().with_label("app=nginx,env=prod");
        let e1 = WatchEvent::new(WatchEventType::Added, "Pod", "p1")
            .with_label("app", "nginx")
            .with_label("env", "prod");
        let e2 = WatchEvent::new(WatchEventType::Added, "Pod", "p2")
            .with_label("app", "nginx");
        let e3 = WatchEvent::new(WatchEventType::Added, "Pod", "p3")
            .with_label("app", "redis")
            .with_label("env", "prod");

        assert!(f.matches(&e1));
        assert!(!f.matches(&e2)); // missing env
        assert!(!f.matches(&e3)); // wrong app
    }

    #[test]
    fn watch_filter_matches_combined() {
        let f = WatchFilter::new()
            .with_namespace("staging")
            .with_kind("Deployment")
            .with_label("app=api");

        let e = WatchEvent::new(WatchEventType::Modified, "Deployment", "api-v2")
            .with_namespace("staging")
            .with_label("app", "api");
        assert!(f.matches(&e));

        // wrong namespace
        let e2 = WatchEvent::new(WatchEventType::Modified, "Deployment", "api-v2")
            .with_namespace("prod")
            .with_label("app", "api");
        assert!(!f.matches(&e2));

        // wrong kind
        let e3 = WatchEvent::new(WatchEventType::Modified, "Service", "api-v2")
            .with_namespace("staging")
            .with_label("app", "api");
        assert!(!f.matches(&e3));
    }

    #[test]
    fn watch_filter_empty_label_selector_matches_all() {
        let f = WatchFilter::new().with_label("");
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p");
        assert!(f.matches(&e));
    }

    #[test]
    fn watch_filter_serde_roundtrip() {
        let f = WatchFilter::new()
            .with_namespace("ns")
            .with_kind("Pod")
            .with_label("app=web");
        let json = serde_json::to_string(&f).unwrap();
        let back: WatchFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(back.namespace.as_deref(), Some("ns"));
        assert_eq!(back.resource_kinds, vec!["Pod"]);
    }

    #[test]
    fn watch_filter_default() {
        let f = WatchFilter::default();
        assert!(f.is_empty());
    }

    #[test]
    fn watch_filter_label_with_spaces() {
        let f = WatchFilter::new().with_label(" app = nginx , env = prod ");
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p1")
            .with_label("app", "nginx")
            .with_label("env", "prod");
        assert!(f.matches(&e));
    }

    #[test]
    fn watch_filter_multiple_kinds() {
        let f = WatchFilter::new()
            .with_kind("Pod")
            .with_kind("Deployment")
            .with_kind("Service")
            .with_kind("ConfigMap");
        assert_eq!(f.resource_kinds.len(), 4);

        for kind in &["Pod", "Deployment", "Service", "ConfigMap"] {
            let e = WatchEvent::new(WatchEventType::Added, *kind, "test");
            assert!(f.matches(&e));
        }

        let e = WatchEvent::new(WatchEventType::Added, "Secret", "s");
        assert!(!f.matches(&e));
    }

    // ---- EventBuffer ----

    #[test]
    fn event_buffer_new() {
        let buf = EventBuffer::new(10, OverflowPolicy::DropOldest);
        assert_eq!(buf.capacity(), 10);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert!(!buf.is_full());
        assert_eq!(buf.dropped_count(), 0);
        assert_eq!(buf.overflow_policy(), OverflowPolicy::DropOldest);
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn event_buffer_zero_capacity_panics() {
        let _ = EventBuffer::new(0, OverflowPolicy::DropOldest);
    }

    #[test]
    fn event_buffer_push_and_drain() {
        let mut buf = EventBuffer::new(5, OverflowPolicy::DropOldest);
        for i in 0..3 {
            let e = WatchEvent::new(WatchEventType::Added, "Pod", format!("p{i}"));
            assert!(buf.push(e));
        }
        assert_eq!(buf.len(), 3);

        let events = buf.drain();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].name, "p0");
        assert_eq!(events[2].name, "p2");
        assert!(buf.is_empty());
    }

    #[test]
    fn event_buffer_drop_oldest() {
        let mut buf = EventBuffer::new(3, OverflowPolicy::DropOldest);
        for i in 0..5 {
            buf.push(WatchEvent::new(WatchEventType::Added, "Pod", format!("p{i}")));
        }
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.dropped_count(), 2);

        let events = buf.drain();
        assert_eq!(events[0].name, "p2");
        assert_eq!(events[1].name, "p3");
        assert_eq!(events[2].name, "p4");
    }

    #[test]
    fn event_buffer_drop_newest() {
        let mut buf = EventBuffer::new(3, OverflowPolicy::DropNewest);
        for i in 0..5 {
            buf.push(WatchEvent::new(WatchEventType::Added, "Pod", format!("p{i}")));
        }
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.dropped_count(), 2);

        let events = buf.drain();
        assert_eq!(events[0].name, "p0");
        assert_eq!(events[1].name, "p1");
        assert_eq!(events[2].name, "p2");
    }

    #[test]
    fn event_buffer_reject_new() {
        let mut buf = EventBuffer::new(2, OverflowPolicy::RejectNew);
        assert!(buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p0")));
        assert!(buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p1")));
        assert!(!buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p2")));
        assert_eq!(buf.len(), 2);
        assert_eq!(buf.dropped_count(), 1);

        let events = buf.drain();
        assert_eq!(events[0].name, "p0");
        assert_eq!(events[1].name, "p1");
    }

    #[test]
    fn event_buffer_is_full() {
        let mut buf = EventBuffer::new(2, OverflowPolicy::RejectNew);
        assert!(!buf.is_full());
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p0"));
        assert!(!buf.is_full());
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p1"));
        assert!(buf.is_full());
    }

    #[test]
    fn event_buffer_peek() {
        let mut buf = EventBuffer::new(5, OverflowPolicy::DropOldest);
        assert!(buf.peek_front().is_none());
        assert!(buf.peek_back().is_none());

        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "first"));
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "last"));

        assert_eq!(buf.peek_front().unwrap().name, "first");
        assert_eq!(buf.peek_back().unwrap().name, "last");
    }

    #[test]
    fn event_buffer_clear() {
        let mut buf = EventBuffer::new(5, OverflowPolicy::DropOldest);
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p1"));
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p2"));
        assert_eq!(buf.len(), 2);
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn event_buffer_status() {
        let mut buf = EventBuffer::new(5, OverflowPolicy::DropOldest);
        buf.push(
            WatchEvent::new(WatchEventType::Added, "Pod", "p1")
                .with_timestamp("2026-01-01T00:00:00Z"),
        );
        buf.push(
            WatchEvent::new(WatchEventType::Added, "Pod", "p2")
                .with_timestamp("2026-01-02T00:00:00Z"),
        );

        let s = buf.status();
        assert_eq!(s.current_size, 2);
        assert_eq!(s.capacity, 5);
        assert_eq!(s.dropped_total, 0);
        assert!(!s.is_full);
        assert_eq!(s.oldest_timestamp.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(s.newest_timestamp.as_deref(), Some("2026-01-02T00:00:00Z"));
    }

    #[test]
    fn event_buffer_status_empty() {
        let buf = EventBuffer::new(5, OverflowPolicy::DropOldest);
        let s = buf.status();
        assert_eq!(s.current_size, 0);
        assert!(s.oldest_timestamp.is_none());
        assert!(s.newest_timestamp.is_none());
    }

    #[test]
    fn event_buffer_capacity_one() {
        let mut buf = EventBuffer::new(1, OverflowPolicy::DropOldest);
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p0"));
        assert!(buf.is_full());
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p1"));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.dropped_count(), 1);
        let events = buf.drain();
        assert_eq!(events[0].name, "p1");
    }

    #[test]
    fn event_buffer_drop_oldest_returns_true() {
        let mut buf = EventBuffer::new(1, OverflowPolicy::DropOldest);
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p0"));
        let accepted = buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p1"));
        assert!(accepted); // DropOldest always accepts
    }

    #[test]
    fn event_buffer_drop_newest_returns_false() {
        let mut buf = EventBuffer::new(1, OverflowPolicy::DropNewest);
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p0"));
        let accepted = buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "p1"));
        assert!(!accepted);
    }

    #[test]
    fn event_buffer_multiple_drain_cycles() {
        let mut buf = EventBuffer::new(3, OverflowPolicy::DropOldest);
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "a"));
        let first = buf.drain();
        assert_eq!(first.len(), 1);
        assert!(buf.is_empty());

        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "b"));
        buf.push(WatchEvent::new(WatchEventType::Added, "Pod", "c"));
        let second = buf.drain();
        assert_eq!(second.len(), 2);
    }

    // ---- OverflowPolicy ----

    #[test]
    fn overflow_policy_serde_roundtrip() {
        for p in [
            OverflowPolicy::DropOldest,
            OverflowPolicy::DropNewest,
            OverflowPolicy::RejectNew,
        ] {
            let json = serde_json::to_string(&p).unwrap();
            let back: OverflowPolicy = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }

    #[test]
    fn overflow_policy_equality() {
        assert_eq!(OverflowPolicy::DropOldest, OverflowPolicy::DropOldest);
        assert_ne!(OverflowPolicy::DropOldest, OverflowPolicy::DropNewest);
        assert_ne!(OverflowPolicy::DropNewest, OverflowPolicy::RejectNew);
    }

    // ---- BufferStatus ----

    #[test]
    fn buffer_status_serde_roundtrip() {
        let s = BufferStatus {
            current_size: 5,
            capacity: 10,
            dropped_total: 2,
            is_full: false,
            oldest_timestamp: Some("2026-01-01T00:00:00Z".to_string()),
            newest_timestamp: Some("2026-01-02T00:00:00Z".to_string()),
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: BufferStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.current_size, 5);
        assert_eq!(back.capacity, 10);
        assert_eq!(back.dropped_total, 2);
    }

    // ---- EventSubscription ----

    #[test]
    fn subscription_new_defaults() {
        let sub = EventSubscription::new(1, WatchFilter::new(), 10, OverflowPolicy::DropOldest);
        assert_eq!(sub.id, 1);
        assert!(sub.is_active());
        assert!(!sub.is_backpressured());
        assert_eq!(sub.buffered_count(), 0);
        assert_eq!(sub.dropped_count(), 0);
        assert!(sub.last_event_version().is_none());
    }

    #[test]
    fn subscription_with_created_at() {
        let sub = EventSubscription::new(1, WatchFilter::new(), 10, OverflowPolicy::DropOldest)
            .with_created_at("2026-03-09T12:00:00Z");
        assert_eq!(sub.created_at, "2026-03-09T12:00:00Z");
    }

    #[test]
    fn subscription_push_and_drain() {
        let mut sub = EventSubscription::new(1, WatchFilter::new(), 10, OverflowPolicy::DropOldest);
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p1")
            .with_resource_version("100");
        assert!(sub.push_event(&e));
        assert_eq!(sub.buffered_count(), 1);
        assert_eq!(sub.last_event_version(), Some("100"));

        let events = sub.drain_events();
        assert_eq!(events.len(), 1);
        assert_eq!(sub.buffered_count(), 0);
    }

    #[test]
    fn subscription_respects_filter() {
        let filter = WatchFilter::new().with_namespace("prod");
        let mut sub = EventSubscription::new(1, filter, 10, OverflowPolicy::DropOldest);

        let e1 = WatchEvent::new(WatchEventType::Added, "Pod", "p1")
            .with_namespace("prod");
        let e2 = WatchEvent::new(WatchEventType::Added, "Pod", "p2")
            .with_namespace("dev");

        assert!(sub.push_event(&e1));
        assert!(!sub.push_event(&e2));
        assert_eq!(sub.buffered_count(), 1);
    }

    #[test]
    fn subscription_deactivate_rejects_events() {
        let mut sub = EventSubscription::new(1, WatchFilter::new(), 10, OverflowPolicy::DropOldest);
        sub.deactivate();
        assert!(!sub.is_active());

        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p1");
        assert!(!sub.push_event(&e));
        assert_eq!(sub.buffered_count(), 0);
    }

    #[test]
    fn subscription_backpressure() {
        let mut sub = EventSubscription::new(1, WatchFilter::new(), 2, OverflowPolicy::RejectNew);
        sub.push_event(&WatchEvent::new(WatchEventType::Added, "Pod", "p1"));
        assert!(!sub.is_backpressured());
        sub.push_event(&WatchEvent::new(WatchEventType::Added, "Pod", "p2"));
        assert!(sub.is_backpressured());

        // RejectNew should reject
        let rejected = sub.push_event(&WatchEvent::new(WatchEventType::Added, "Pod", "p3"));
        assert!(!rejected);
        assert_eq!(sub.dropped_count(), 1);
    }

    #[test]
    fn subscription_status() {
        let mut sub = EventSubscription::new(1, WatchFilter::new(), 5, OverflowPolicy::DropOldest);
        sub.push_event(
            &WatchEvent::new(WatchEventType::Added, "Pod", "p1")
                .with_timestamp("2026-01-01T00:00:00Z"),
        );
        let s = sub.status();
        assert_eq!(s.current_size, 1);
        assert_eq!(s.capacity, 5);
        assert!(!s.is_full);
    }

    #[test]
    fn subscription_last_event_version_tracks_accepted_only() {
        let filter = WatchFilter::new().with_namespace("ns");
        let mut sub = EventSubscription::new(1, filter, 10, OverflowPolicy::DropOldest);

        // Non-matching event should not update version
        let e1 = WatchEvent::new(WatchEventType::Added, "Pod", "p1")
            .with_namespace("other")
            .with_resource_version("1");
        sub.push_event(&e1);
        assert!(sub.last_event_version().is_none());

        // Matching event should update
        let e2 = WatchEvent::new(WatchEventType::Added, "Pod", "p2")
            .with_namespace("ns")
            .with_resource_version("2");
        sub.push_event(&e2);
        assert_eq!(sub.last_event_version(), Some("2"));
    }

    #[test]
    fn subscription_event_without_resource_version() {
        let mut sub = EventSubscription::new(1, WatchFilter::new(), 10, OverflowPolicy::DropOldest);
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p1");
        sub.push_event(&e);
        assert!(sub.last_event_version().is_none());
    }

    #[test]
    fn subscription_drain_preserves_order() {
        let mut sub = EventSubscription::new(1, WatchFilter::new(), 10, OverflowPolicy::DropOldest);
        for i in 0..5 {
            sub.push_event(&WatchEvent::new(
                WatchEventType::Added,
                "Pod",
                format!("p{i}"),
            ));
        }
        let events = sub.drain_events();
        for (i, e) in events.iter().enumerate() {
            assert_eq!(e.name, format!("p{i}"));
        }
    }

    // ---- SubscriptionManager ----

    #[test]
    fn manager_new() {
        let mgr = SubscriptionManager::new(10);
        assert_eq!(mgr.active_count(), 0);
        assert_eq!(mgr.total_count(), 0);
    }

    #[test]
    fn manager_create_subscription() {
        let mut mgr = SubscriptionManager::new(10);
        let id = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        assert_eq!(id, 1);
        assert_eq!(mgr.active_count(), 1);
        assert_eq!(mgr.total_count(), 1);
    }

    #[test]
    fn manager_create_multiple() {
        let mut mgr = SubscriptionManager::new(10);
        let id1 = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        let id2 = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        assert_ne!(id1, id2);
        assert_eq!(mgr.total_count(), 2);
    }

    #[test]
    fn manager_max_subscriptions() {
        let mut mgr = SubscriptionManager::new(2);
        mgr.create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        mgr.create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        let err = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap_err();
        assert_eq!(
            err,
            SubscriptionError::MaxSubscriptionsReached { limit: 2 }
        );
    }

    #[test]
    fn manager_remove_subscription() {
        let mut mgr = SubscriptionManager::new(10);
        let id = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        let removed = mgr.remove_subscription(id);
        assert!(removed.is_some());
        assert_eq!(mgr.total_count(), 0);
    }

    #[test]
    fn manager_remove_nonexistent() {
        let mut mgr = SubscriptionManager::new(10);
        assert!(mgr.remove_subscription(999).is_none());
    }

    #[test]
    fn manager_push_to_matching() {
        let mut mgr = SubscriptionManager::new(10);
        mgr.create_subscription(
            WatchFilter::new().with_namespace("prod"),
            5,
            OverflowPolicy::DropOldest,
        )
        .unwrap();
        mgr.create_subscription(
            WatchFilter::new().with_namespace("dev"),
            5,
            OverflowPolicy::DropOldest,
        )
        .unwrap();
        mgr.create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();

        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p1")
            .with_namespace("prod");
        let count = mgr.push_to_matching(&e);
        // Matches: "prod" filter and "no filter" (matches all)
        assert_eq!(count, 2);
    }

    #[test]
    fn manager_push_no_matching() {
        let mut mgr = SubscriptionManager::new(10);
        mgr.create_subscription(
            WatchFilter::new().with_namespace("prod"),
            5,
            OverflowPolicy::DropOldest,
        )
        .unwrap();

        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p1")
            .with_namespace("dev");
        let count = mgr.push_to_matching(&e);
        assert_eq!(count, 0);
    }

    #[test]
    fn manager_subscription_status() {
        let mut mgr = SubscriptionManager::new(10);
        let id = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        let s = mgr.subscription_status(id).unwrap();
        assert_eq!(s.current_size, 0);
        assert_eq!(s.capacity, 5);
    }

    #[test]
    fn manager_subscription_status_nonexistent() {
        let mgr = SubscriptionManager::new(10);
        assert!(mgr.subscription_status(42).is_none());
    }

    #[test]
    fn manager_get() {
        let mut mgr = SubscriptionManager::new(10);
        let id = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        assert!(mgr.get(id).is_some());
        assert!(mgr.get(999).is_none());
    }

    #[test]
    fn manager_get_mut() {
        let mut mgr = SubscriptionManager::new(10);
        let id = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        let sub = mgr.get_mut(id).unwrap();
        sub.deactivate();
        assert!(!mgr.get(id).unwrap().is_active());
    }

    #[test]
    fn manager_drain_events() {
        let mut mgr = SubscriptionManager::new(10);
        let id = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        mgr.push_to_matching(&WatchEvent::new(WatchEventType::Added, "Pod", "p1"));
        let events = mgr.drain_events(id).unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn manager_drain_nonexistent() {
        let mut mgr = SubscriptionManager::new(10);
        assert!(mgr.drain_events(42).is_none());
    }

    #[test]
    fn manager_deactivate() {
        let mut mgr = SubscriptionManager::new(10);
        let id = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        assert!(mgr.deactivate(id));
        assert_eq!(mgr.active_count(), 0);
        assert_eq!(mgr.total_count(), 1); // still present
    }

    #[test]
    fn manager_deactivate_nonexistent() {
        let mut mgr = SubscriptionManager::new(10);
        assert!(!mgr.deactivate(42));
    }

    #[test]
    fn manager_active_count_excludes_inactive() {
        let mut mgr = SubscriptionManager::new(10);
        let id1 = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        mgr.create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        assert_eq!(mgr.active_count(), 2);
        mgr.deactivate(id1);
        assert_eq!(mgr.active_count(), 1);
        assert_eq!(mgr.total_count(), 2);
    }

    #[test]
    fn manager_ids_are_monotonic() {
        let mut mgr = SubscriptionManager::new(10);
        let id1 = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        let id2 = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        let id3 = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        assert!(id1 < id2);
        assert!(id2 < id3);
    }

    #[test]
    fn manager_removed_id_not_reused() {
        let mut mgr = SubscriptionManager::new(10);
        let id1 = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        mgr.remove_subscription(id1);
        let id2 = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        assert!(id2 > id1);
    }

    #[test]
    fn manager_push_to_inactive_subscription() {
        let mut mgr = SubscriptionManager::new(10);
        let id = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        mgr.deactivate(id);
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p1");
        let count = mgr.push_to_matching(&e);
        assert_eq!(count, 0);
    }

    // ---- SubscriptionError ----

    #[test]
    fn subscription_error_display() {
        let err = SubscriptionError::MaxSubscriptionsReached { limit: 42 };
        assert_eq!(err.to_string(), "max subscriptions reached (limit: 42)");
    }

    #[test]
    fn subscription_error_is_std_error() {
        let err = SubscriptionError::MaxSubscriptionsReached { limit: 1 };
        let e: &dyn std::error::Error = &err;
        // Verify it implements Error trait properly
        assert!(!e.to_string().is_empty());
    }

    // ---- ClusterEvent ----

    #[test]
    fn cluster_event_new() {
        let ce = ClusterEvent::new("uid-1", "Pulled", "Image pulled", ClusterEventType::Normal);
        assert_eq!(ce.uid, "uid-1");
        assert_eq!(ce.reason, "Pulled");
        assert_eq!(ce.message, "Image pulled");
        assert_eq!(ce.event_type, ClusterEventType::Normal);
        assert_eq!(ce.count, 1);
        assert!(ce.source_component.is_none());
        assert!(ce.regarding_kind.is_none());
    }

    #[test]
    fn cluster_event_builder() {
        let ce = ClusterEvent::new("uid-2", "FailedScheduling", "no nodes", ClusterEventType::Warning)
            .with_source("scheduler")
            .with_regarding("Pod", "my-pod", Some("default".to_string()))
            .with_count(5)
            .with_timestamps("2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z");

        assert_eq!(ce.source_component.as_deref(), Some("scheduler"));
        assert_eq!(ce.regarding_kind.as_deref(), Some("Pod"));
        assert_eq!(ce.regarding_name.as_deref(), Some("my-pod"));
        assert_eq!(ce.regarding_namespace.as_deref(), Some("default"));
        assert_eq!(ce.count, 5);
        assert_eq!(ce.first_timestamp.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(ce.last_timestamp.as_deref(), Some("2026-01-01T01:00:00Z"));
    }

    #[test]
    fn cluster_event_is_warning() {
        let ce = ClusterEvent::new("u", "r", "m", ClusterEventType::Warning);
        assert!(ce.is_warning());
        assert!(!ce.is_normal());
    }

    #[test]
    fn cluster_event_is_normal() {
        let ce = ClusterEvent::new("u", "r", "m", ClusterEventType::Normal);
        assert!(ce.is_normal());
        assert!(!ce.is_warning());
    }

    #[test]
    fn cluster_event_serde_roundtrip() {
        let ce = ClusterEvent::new("uid-x", "Pulled", "ok", ClusterEventType::Normal)
            .with_source("kubelet")
            .with_regarding("Pod", "p1", None)
            .with_count(3)
            .with_timestamps("t1", "t2");

        let json = serde_json::to_string(&ce).unwrap();
        let back: ClusterEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uid, "uid-x");
        assert_eq!(back.count, 3);
        assert_eq!(back.source_component.as_deref(), Some("kubelet"));
    }

    #[test]
    fn cluster_event_to_watch_event() {
        let ce = ClusterEvent::new("uid-w", "Killed", "OOM", ClusterEventType::Warning)
            .with_source("kubelet")
            .with_regarding("Pod", "hungry", Some("prod".to_string()))
            .with_timestamps("t0", "t1");

        let we = ce.to_watch_event();
        assert_eq!(we.event_type, WatchEventType::Added);
        assert_eq!(we.resource_kind, "Event");
        assert_eq!(we.name, "uid-w");
        assert_eq!(we.namespace.as_deref(), Some("prod"));
        assert_eq!(we.timestamp.as_deref(), Some("t1"));
        assert_eq!(we.labels.get("source").unwrap(), "kubelet");
        assert_eq!(we.labels.get("reason").unwrap(), "Killed");
        assert_eq!(we.payload["message"], "OOM");
    }

    #[test]
    fn cluster_event_to_watch_event_no_source() {
        let ce = ClusterEvent::new("u", "r", "m", ClusterEventType::Normal);
        let we = ce.to_watch_event();
        assert!(!we.labels.contains_key("source"));
        assert_eq!(we.labels.get("reason").unwrap(), "r");
    }

    #[test]
    fn cluster_event_regarding_no_namespace() {
        let ce = ClusterEvent::new("u", "r", "m", ClusterEventType::Normal)
            .with_regarding("Node", "node-1", None);
        assert!(ce.regarding_namespace.is_none());
        assert_eq!(ce.regarding_kind.as_deref(), Some("Node"));
    }

    // ---- ClusterEventType ----

    #[test]
    fn cluster_event_type_display() {
        assert_eq!(ClusterEventType::Normal.to_string(), "Normal");
        assert_eq!(ClusterEventType::Warning.to_string(), "Warning");
    }

    #[test]
    fn cluster_event_type_serde_roundtrip() {
        for t in [ClusterEventType::Normal, ClusterEventType::Warning] {
            let json = serde_json::to_string(&t).unwrap();
            let back: ClusterEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn cluster_event_type_equality() {
        assert_eq!(ClusterEventType::Normal, ClusterEventType::Normal);
        assert_ne!(ClusterEventType::Normal, ClusterEventType::Warning);
    }

    // ---- RolloutCondition ----

    #[test]
    fn rollout_condition_new() {
        let c = RolloutCondition::new("Available", "True");
        assert_eq!(c.condition_type, "Available");
        assert_eq!(c.status, "True");
        assert!(c.reason.is_none());
        assert!(c.message.is_none());
    }

    #[test]
    fn rollout_condition_builder() {
        let c = RolloutCondition::new("Progressing", "False")
            .with_reason("ProgressDeadlineExceeded")
            .with_message("timed out");
        assert_eq!(c.reason.as_deref(), Some("ProgressDeadlineExceeded"));
        assert_eq!(c.message.as_deref(), Some("timed out"));
    }

    #[test]
    fn rollout_condition_is_true_false() {
        let t = RolloutCondition::new("Available", "True");
        assert!(t.is_true());
        assert!(!t.is_false());

        let f = RolloutCondition::new("Available", "False");
        assert!(f.is_false());
        assert!(!f.is_true());

        let u = RolloutCondition::new("Available", "Unknown");
        assert!(!u.is_true());
        assert!(!u.is_false());
    }

    #[test]
    fn rollout_condition_serde_roundtrip() {
        let c = RolloutCondition::new("Progressing", "True")
            .with_reason("NewReplicaSetAvailable")
            .with_message("has min availability");
        let json = serde_json::to_string(&c).unwrap();
        let back: RolloutCondition = serde_json::from_str(&json).unwrap();
        assert_eq!(back.condition_type, "Progressing");
        assert_eq!(back.reason.as_deref(), Some("NewReplicaSetAvailable"));
    }

    // ---- RolloutStatus ----

    #[test]
    fn rollout_status_new() {
        let r = RolloutStatus::new("web", 3);
        assert_eq!(r.deployment_name, "web");
        assert!(r.namespace.is_none());
        assert_eq!(r.desired_replicas, 3);
        assert_eq!(r.ready_replicas, 0);
        assert_eq!(r.updated_replicas, 0);
        assert!(!r.available);
        assert!(r.conditions.is_empty());
    }

    #[test]
    fn rollout_status_builder() {
        let r = RolloutStatus::new("api", 5)
            .with_namespace("prod")
            .with_ready_replicas(5)
            .with_updated_replicas(5)
            .with_available(true)
            .with_condition(RolloutCondition::new("Available", "True"));

        assert_eq!(r.namespace.as_deref(), Some("prod"));
        assert_eq!(r.ready_replicas, 5);
        assert_eq!(r.updated_replicas, 5);
        assert!(r.available);
        assert_eq!(r.conditions.len(), 1);
    }

    #[test]
    fn rollout_status_is_complete() {
        let r = RolloutStatus::new("web", 3)
            .with_ready_replicas(3)
            .with_updated_replicas(3)
            .with_available(true);
        assert!(r.is_complete());
    }

    #[test]
    fn rollout_status_not_complete_ready_short() {
        let r = RolloutStatus::new("web", 3)
            .with_ready_replicas(2)
            .with_updated_replicas(3)
            .with_available(true);
        assert!(!r.is_complete());
    }

    #[test]
    fn rollout_status_not_complete_updated_short() {
        let r = RolloutStatus::new("web", 3)
            .with_ready_replicas(3)
            .with_updated_replicas(2)
            .with_available(true);
        assert!(!r.is_complete());
    }

    #[test]
    fn rollout_status_not_complete_unavailable() {
        let r = RolloutStatus::new("web", 3)
            .with_ready_replicas(3)
            .with_updated_replicas(3)
            .with_available(false);
        assert!(!r.is_complete());
    }

    #[test]
    fn rollout_status_ready_percentage() {
        let r = RolloutStatus::new("web", 4).with_ready_replicas(2);
        assert_eq!(r.ready_percentage(), 50);
    }

    #[test]
    fn rollout_status_ready_percentage_zero_desired() {
        let r = RolloutStatus::new("web", 0);
        assert_eq!(r.ready_percentage(), 100);
    }

    #[test]
    fn rollout_status_ready_percentage_full() {
        let r = RolloutStatus::new("web", 3).with_ready_replicas(3);
        assert_eq!(r.ready_percentage(), 100);
    }

    #[test]
    fn rollout_status_ready_percentage_none() {
        let r = RolloutStatus::new("web", 5);
        assert_eq!(r.ready_percentage(), 0);
    }

    #[test]
    fn rollout_status_has_failure_condition_available_false() {
        let r = RolloutStatus::new("web", 3)
            .with_condition(RolloutCondition::new("Available", "False"));
        assert!(r.has_failure_condition());
    }

    #[test]
    fn rollout_status_has_failure_condition_deadline() {
        let r = RolloutStatus::new("web", 3).with_condition(
            RolloutCondition::new("Progressing", "False")
                .with_reason("ProgressDeadlineExceeded"),
        );
        assert!(r.has_failure_condition());
    }

    #[test]
    fn rollout_status_no_failure_condition() {
        let r = RolloutStatus::new("web", 3)
            .with_condition(RolloutCondition::new("Available", "True"))
            .with_condition(RolloutCondition::new("Progressing", "True"));
        assert!(!r.has_failure_condition());
    }

    #[test]
    fn rollout_status_find_condition() {
        let r = RolloutStatus::new("web", 3)
            .with_condition(RolloutCondition::new("Available", "True"))
            .with_condition(
                RolloutCondition::new("Progressing", "True")
                    .with_reason("NewReplicaSetAvailable"),
            );

        let c = r.find_condition("Progressing").unwrap();
        assert_eq!(c.reason.as_deref(), Some("NewReplicaSetAvailable"));
        assert!(r.find_condition("NonExistent").is_none());
    }

    #[test]
    fn rollout_status_serde_roundtrip() {
        let r = RolloutStatus::new("api", 3)
            .with_namespace("staging")
            .with_ready_replicas(2)
            .with_updated_replicas(3)
            .with_available(false)
            .with_condition(RolloutCondition::new("Progressing", "True"));

        let json = serde_json::to_string(&r).unwrap();
        let back: RolloutStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.deployment_name, "api");
        assert_eq!(back.namespace.as_deref(), Some("staging"));
        assert_eq!(back.ready_replicas, 2);
        assert_eq!(back.conditions.len(), 1);
    }

    #[test]
    fn rollout_status_multiple_conditions() {
        let r = RolloutStatus::new("web", 3)
            .with_condition(RolloutCondition::new("Available", "True"))
            .with_condition(RolloutCondition::new("Progressing", "True"))
            .with_condition(
                RolloutCondition::new("ReplicaFailure", "False")
                    .with_message("all good"),
            );
        assert_eq!(r.conditions.len(), 3);
    }

    // ---- Integration / edge cases ----

    #[test]
    fn full_pipeline_filter_to_subscription() {
        let filter = WatchFilter::new()
            .with_namespace("monitoring")
            .with_kind("Pod")
            .with_label("app=prometheus");

        let mut sub = EventSubscription::new(1, filter, 100, OverflowPolicy::DropOldest);

        let good = WatchEvent::new(WatchEventType::Added, "Pod", "prom-0")
            .with_namespace("monitoring")
            .with_label("app", "prometheus");
        let bad_ns = WatchEvent::new(WatchEventType::Added, "Pod", "prom-1")
            .with_namespace("default")
            .with_label("app", "prometheus");
        let bad_kind = WatchEvent::new(WatchEventType::Added, "Service", "prom-svc")
            .with_namespace("monitoring")
            .with_label("app", "prometheus");
        let bad_label = WatchEvent::new(WatchEventType::Added, "Pod", "grafana-0")
            .with_namespace("monitoring")
            .with_label("app", "grafana");

        assert!(sub.push_event(&good));
        assert!(!sub.push_event(&bad_ns));
        assert!(!sub.push_event(&bad_kind));
        assert!(!sub.push_event(&bad_label));

        assert_eq!(sub.buffered_count(), 1);
    }

    #[test]
    fn manager_multi_subscriber_routing() {
        let mut mgr = SubscriptionManager::new(10);

        // Sub 1: all pods
        mgr.create_subscription(
            WatchFilter::new().with_kind("Pod"),
            10,
            OverflowPolicy::DropOldest,
        )
        .unwrap();

        // Sub 2: only deployments in prod
        mgr.create_subscription(
            WatchFilter::new()
                .with_kind("Deployment")
                .with_namespace("prod"),
            10,
            OverflowPolicy::DropOldest,
        )
        .unwrap();

        // Sub 3: everything
        mgr.create_subscription(WatchFilter::new(), 10, OverflowPolicy::DropOldest)
            .unwrap();

        // Pod event -> matches sub 1 and sub 3
        let pod_event = WatchEvent::new(WatchEventType::Added, "Pod", "p1")
            .with_namespace("dev");
        assert_eq!(mgr.push_to_matching(&pod_event), 2);

        // Deployment in prod -> matches sub 2 and sub 3
        let deploy_event = WatchEvent::new(WatchEventType::Modified, "Deployment", "d1")
            .with_namespace("prod");
        assert_eq!(mgr.push_to_matching(&deploy_event), 2);

        // Deployment in dev -> matches sub 3 only
        let deploy_dev = WatchEvent::new(WatchEventType::Modified, "Deployment", "d2")
            .with_namespace("dev");
        assert_eq!(mgr.push_to_matching(&deploy_dev), 1);
    }

    #[test]
    fn cluster_event_routed_through_manager() {
        let mut mgr = SubscriptionManager::new(10);
        mgr.create_subscription(
            WatchFilter::new().with_kind("Event"),
            10,
            OverflowPolicy::DropOldest,
        )
        .unwrap();

        let ce = ClusterEvent::new("uid-1", "Pulled", "ok", ClusterEventType::Normal)
            .with_regarding("Pod", "p1", Some("default".to_string()));
        let we = ce.to_watch_event();
        let count = mgr.push_to_matching(&we);
        assert_eq!(count, 1);
    }

    #[test]
    fn backpressure_across_subscriptions() {
        let mut mgr = SubscriptionManager::new(10);
        let id = mgr
            .create_subscription(WatchFilter::new(), 2, OverflowPolicy::RejectNew)
            .unwrap();

        mgr.push_to_matching(&WatchEvent::new(WatchEventType::Added, "Pod", "p1"));
        mgr.push_to_matching(&WatchEvent::new(WatchEventType::Added, "Pod", "p2"));
        assert!(mgr.get(id).unwrap().is_backpressured());

        // Third push should be rejected
        let count = mgr.push_to_matching(&WatchEvent::new(WatchEventType::Added, "Pod", "p3"));
        assert_eq!(count, 0);

        // Drain and push again
        mgr.drain_events(id);
        assert!(!mgr.get(id).unwrap().is_backpressured());
        let count = mgr.push_to_matching(&WatchEvent::new(WatchEventType::Added, "Pod", "p4"));
        assert_eq!(count, 1);
    }

    #[test]
    fn event_buffer_stress_drop_oldest() {
        let mut buf = EventBuffer::new(10, OverflowPolicy::DropOldest);
        for i in 0..1000 {
            buf.push(WatchEvent::new(
                WatchEventType::Added,
                "Pod",
                format!("p{i}"),
            ));
        }
        assert_eq!(buf.len(), 10);
        assert_eq!(buf.dropped_count(), 990);
        let events = buf.drain();
        assert_eq!(events[0].name, "p990");
        assert_eq!(events[9].name, "p999");
    }

    #[test]
    fn watch_filter_single_label_match() {
        let f = WatchFilter::new().with_label("tier=backend");
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p")
            .with_label("tier", "backend")
            .with_label("extra", "ignored");
        assert!(f.matches(&e));
    }

    #[test]
    fn watch_filter_label_no_value() {
        // "key=" means empty value
        let f = WatchFilter::new().with_label("key=");
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p")
            .with_label("key", "");
        assert!(f.matches(&e));
    }

    #[test]
    fn watch_event_type_all_variants_covered() {
        let types = [
            WatchEventType::Added,
            WatchEventType::Modified,
            WatchEventType::Deleted,
            WatchEventType::Bookmark,
            WatchEventType::Error,
        ];
        assert_eq!(types.len(), 5);
        // Ensure display works for all
        for t in &types {
            assert!(!t.to_string().is_empty());
        }
    }

    #[test]
    fn rollout_status_is_complete_with_extra_replicas() {
        // More ready than desired (autoscaler)
        let r = RolloutStatus::new("web", 3)
            .with_ready_replicas(5)
            .with_updated_replicas(5)
            .with_available(true);
        assert!(r.is_complete());
    }

    #[test]
    fn rollout_status_ready_percentage_rounding() {
        let r = RolloutStatus::new("web", 3).with_ready_replicas(1);
        // 1/3 * 100 = 33 (integer division)
        assert_eq!(r.ready_percentage(), 33);
    }

    #[test]
    fn event_buffer_status_after_overflow() {
        let mut buf = EventBuffer::new(2, OverflowPolicy::DropOldest);
        buf.push(
            WatchEvent::new(WatchEventType::Added, "Pod", "p0")
                .with_timestamp("t0"),
        );
        buf.push(
            WatchEvent::new(WatchEventType::Added, "Pod", "p1")
                .with_timestamp("t1"),
        );
        buf.push(
            WatchEvent::new(WatchEventType::Added, "Pod", "p2")
                .with_timestamp("t2"),
        );

        let s = buf.status();
        assert_eq!(s.dropped_total, 1);
        assert!(s.is_full);
        assert_eq!(s.oldest_timestamp.as_deref(), Some("t1"));
        assert_eq!(s.newest_timestamp.as_deref(), Some("t2"));
    }

    #[test]
    fn watch_event_debug_format() {
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "debug-test");
        let debug = format!("{e:?}");
        assert!(debug.contains("debug-test"));
        assert!(debug.contains("Added"));
    }

    #[test]
    fn rollout_condition_clone() {
        let original = RolloutCondition::new("Available", "True")
            .with_reason("MinimumReplicasAvailable")
            .with_message("Deployment has min availability");
        let cloned = original.clone();
        assert_eq!(original.condition_type, "Available");
        assert_eq!(cloned.condition_type, "Available");
        assert_eq!(cloned.reason.as_deref(), Some("MinimumReplicasAvailable"));
    }

    #[test]
    fn cluster_event_clone() {
        let original = ClusterEvent::new("u1", "Pulled", "ok", ClusterEventType::Normal)
            .with_source("kubelet")
            .with_count(7);
        let cloned = original.clone();
        assert_eq!(original.uid, "u1");
        assert_eq!(cloned.uid, "u1");
        assert_eq!(cloned.count, 7);
        assert_eq!(cloned.source_component.as_deref(), Some("kubelet"));
    }

    #[test]
    fn manager_create_after_remove_frees_slot() {
        let mut mgr = SubscriptionManager::new(2);
        let id1 = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        mgr.create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();

        // At limit
        assert!(mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .is_err());

        // Remove one
        mgr.remove_subscription(id1);

        // Now can create
        let id3 = mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        assert!(id3 > id1);
    }

    #[test]
    fn subscription_overflow_drop_oldest_tracks_version() {
        let mut sub = EventSubscription::new(1, WatchFilter::new(), 2, OverflowPolicy::DropOldest);
        sub.push_event(
            &WatchEvent::new(WatchEventType::Added, "Pod", "p0")
                .with_resource_version("10"),
        );
        sub.push_event(
            &WatchEvent::new(WatchEventType::Added, "Pod", "p1")
                .with_resource_version("20"),
        );
        sub.push_event(
            &WatchEvent::new(WatchEventType::Added, "Pod", "p2")
                .with_resource_version("30"),
        );
        assert_eq!(sub.last_event_version(), Some("30"));
        assert_eq!(sub.dropped_count(), 1);
    }

    #[test]
    fn buffer_status_serde_with_none_timestamps() {
        let s = BufferStatus {
            current_size: 0,
            capacity: 10,
            dropped_total: 0,
            is_full: false,
            oldest_timestamp: None,
            newest_timestamp: None,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: BufferStatus = serde_json::from_str(&json).unwrap();
        assert!(back.oldest_timestamp.is_none());
        assert!(back.newest_timestamp.is_none());
    }

    #[test]
    fn watch_filter_field_selector_not_evaluated_client_side() {
        let f = WatchFilter::new().with_field("status.phase=Running");
        // Field selectors aren't evaluated locally, so everything matches
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p1");
        assert!(f.matches(&e));
    }

    #[test]
    fn watch_event_multiple_labels() {
        let e = WatchEvent::new(WatchEventType::Added, "Pod", "p")
            .with_label("a", "1")
            .with_label("b", "2")
            .with_label("c", "3")
            .with_label("d", "4");
        assert_eq!(e.labels.len(), 4);
    }

    #[test]
    fn overflow_policy_debug() {
        let p = OverflowPolicy::DropOldest;
        let debug = format!("{p:?}");
        assert!(debug.contains("DropOldest"));
    }

    #[test]
    fn subscription_manager_max_one() {
        let mut mgr = SubscriptionManager::new(1);
        mgr.create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .unwrap();
        assert!(mgr
            .create_subscription(WatchFilter::new(), 5, OverflowPolicy::DropOldest)
            .is_err());
    }

    #[test]
    fn cluster_event_default_count_is_one() {
        let ce = ClusterEvent::new("u", "r", "m", ClusterEventType::Normal);
        assert_eq!(ce.count, 1);
    }

    #[test]
    fn rollout_status_no_conditions_no_failure() {
        let r = RolloutStatus::new("web", 3);
        assert!(!r.has_failure_condition());
    }

    #[test]
    fn rollout_status_find_condition_none_when_empty() {
        let r = RolloutStatus::new("web", 3);
        assert!(r.find_condition("Available").is_none());
    }

    #[test]
    fn watch_event_null_payload_roundtrip() {
        let e = WatchEvent::new(WatchEventType::Deleted, "ConfigMap", "cm");
        assert_eq!(e.payload, serde_json::Value::Null);
        let json = serde_json::to_string(&e).unwrap();
        let back: WatchEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.payload, serde_json::Value::Null);
    }

    #[test]
    fn event_buffer_drain_empty() {
        let mut buf = EventBuffer::new(5, OverflowPolicy::DropOldest);
        let events = buf.drain();
        assert!(events.is_empty());
    }

    #[test]
    fn subscription_drain_empty() {
        let mut sub = EventSubscription::new(1, WatchFilter::new(), 5, OverflowPolicy::DropOldest);
        let events = sub.drain_events();
        assert!(events.is_empty());
    }
}
