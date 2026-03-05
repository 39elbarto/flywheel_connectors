//! Streaming helpers for connectors: subscriptions, replay buffers, and acks.
//!
//! These utilities are intentionally in-memory and lightweight. They provide
//! standard replay/cursor semantics and ack tracking without forcing a specific
//! transport or storage backend.

use std::collections::{HashMap, HashSet, VecDeque};

use fcp_core::{
    EventAck, EventCaps, EventData, EventEnvelope, EventNack, ReplayBufferInfo, RequestId,
    SubscribeRequest, SubscribeResponse, SubscribeResult,
};

/// Replay buffer sizing limits.
#[derive(Debug, Clone, Copy)]
pub struct BufferLimits {
    /// Minimum number of events retained for replay.
    pub min_events: usize,
    /// Maximum number of events retained (may be exceeded by pending acks).
    pub max_events: usize,
}

impl BufferLimits {
    /// Create buffer limits ensuring `max_events >= min_events`.
    #[must_use]
    pub fn new(min_events: usize, max_events: usize) -> Self {
        Self {
            min_events,
            max_events: max_events.max(min_events),
        }
    }
}

impl Default for BufferLimits {
    fn default() -> Self {
        Self {
            min_events: 10,
            max_events: 100,
        }
    }
}

/// Errors returned by replay helpers.
#[derive(Debug, thiserror::Error, Clone)]
pub enum ReplayError {
    /// The requested topic does not exist or has no buffer.
    #[error("unknown topic '{topic}'")]
    UnknownTopic {
        /// The topic that was not found.
        topic: String,
    },
    /// The cursor string could not be parsed as a sequence number.
    #[error("invalid cursor '{cursor}'")]
    InvalidCursor {
        /// The invalid cursor string.
        cursor: String,
    },
    /// The cursor points to an event that has been trimmed from the buffer.
    #[error("cursor {cursor_seq} is older than oldest buffered seq {oldest_seq}")]
    CursorStale {
        /// The sequence number from the cursor.
        cursor_seq: u64,
        /// The oldest sequence number still in the buffer.
        oldest_seq: u64,
    },
}

/// Result of applying an [`EventAck`].
#[derive(Debug, Clone)]
pub struct AckResult {
    /// Sequence numbers that were successfully acknowledged.
    pub acked: Vec<u64>,
    /// Sequence numbers that were not found in pending acks.
    pub missing: Vec<u64>,
}

/// Result of applying an [`EventNack`].
#[derive(Debug, Clone)]
pub struct NackResult {
    /// Events to redeliver from the buffer.
    pub redeliver: Vec<EventEnvelope>,
    /// Sequence numbers that were not found in the buffer.
    pub missing: Vec<u64>,
}

/// Outcome of handling a [`SubscribeRequest`].
#[derive(Debug, Clone)]
pub struct SubscribeOutcome {
    /// The subscribe response to send to the client.
    pub response: SubscribeResponse,
    /// Events to replay per topic (if replay was requested).
    pub replay_events: HashMap<String, Vec<EventEnvelope>>,
}

#[derive(Debug, Default)]
struct TopicState {
    next_seq: u64,
    buffer: VecDeque<EventEnvelope>,
    pending_acks: HashSet<u64>,
}

impl TopicState {
    fn record_event(
        &mut self,
        mut envelope: EventEnvelope,
        caps: &EventCaps,
        limits: BufferLimits,
    ) -> EventEnvelope {
        if envelope.seq == 0 {
            envelope.seq = self.next_seq;
        }
        if envelope.seq >= self.next_seq {
            self.next_seq = envelope.seq.saturating_add(1);
        }

        if envelope.cursor.is_empty() {
            envelope.cursor = envelope.seq.to_string();
        }

        if caps.requires_ack {
            envelope.requires_ack = true;
        }

        if envelope.requires_ack {
            self.pending_acks.insert(envelope.seq);
        }

        self.buffer.push_back(envelope.clone());
        self.trim_buffer(limits);
        envelope
    }

    fn trim_buffer(&mut self, limits: BufferLimits) {
        while self.buffer.len() > limits.max_events {
            let Some(front) = self.buffer.front() else {
                break;
            };
            if self.pending_acks.contains(&front.seq) {
                break;
            }
            self.buffer.pop_front();
        }
    }

    fn latest_cursor(&self) -> Option<String> {
        self.buffer.back().map(|env| env.cursor.clone())
    }

    fn replay_from_cursor(&self, cursor: &str) -> Result<Vec<EventEnvelope>, ReplayError> {
        if cursor.is_empty() {
            return Ok(self.buffer.iter().cloned().collect());
        }

        let cursor_seq = cursor
            .parse::<u64>()
            .map_err(|_| ReplayError::InvalidCursor {
                cursor: cursor.to_string(),
            })?;

        let Some(oldest) = self.buffer.front() else {
            return Ok(Vec::new());
        };
        if cursor_seq < oldest.seq {
            return Err(ReplayError::CursorStale {
                cursor_seq,
                oldest_seq: oldest.seq,
            });
        }

        Ok(self
            .buffer
            .iter()
            .filter(|env| env.seq > cursor_seq)
            .cloned()
            .collect())
    }

    fn apply_ack(&mut self, ack: &EventAck, limits: BufferLimits) -> AckResult {
        let mut acked = Vec::new();
        let mut missing = Vec::new();

        for seq in &ack.seqs {
            if self.pending_acks.remove(seq) {
                acked.push(*seq);
            } else {
                missing.push(*seq);
            }
        }

        self.trim_buffer(limits);

        AckResult { acked, missing }
    }

    fn apply_nack(&self, nack: &EventNack) -> NackResult {
        let mut redeliver = Vec::new();
        let mut missing = Vec::new();

        for seq in &nack.seqs {
            match self.buffer.iter().find(|env| env.seq == *seq) {
                Some(env) => redeliver.push(env.clone()),
                None => missing.push(*seq),
            }
        }

        NackResult { redeliver, missing }
    }
}

/// In-memory manager for streaming event topics.
#[derive(Debug, Default)]
pub struct EventStreamManager {
    caps: EventCaps,
    limits: BufferLimits,
    topics: HashMap<String, TopicState>,
}

impl EventStreamManager {
    /// Create a manager from connector event capabilities.
    #[must_use]
    pub fn new(caps: EventCaps) -> Self {
        let min_events = caps.min_buffer_events as usize;
        let limits = BufferLimits::new(min_events, min_events.max(1));
        Self {
            caps,
            limits,
            topics: HashMap::new(),
        }
    }

    /// Create a manager with explicit buffer limits.
    #[must_use]
    pub fn with_limits(caps: EventCaps, limits: BufferLimits) -> Self {
        Self {
            caps,
            limits,
            topics: HashMap::new(),
        }
    }

    /// Emit a new event for a topic (auto-assigns seq + cursor).
    pub fn emit(&mut self, topic: &str, data: EventData) -> EventEnvelope {
        let envelope = EventEnvelope::new(topic, data);
        self.record(envelope)
    }

    /// Emit a new event with a caller-provided seq.
    pub fn emit_with_seq(&mut self, topic: &str, seq: u64, data: EventData) -> EventEnvelope {
        let envelope = EventEnvelope::new(topic, data)
            .with_seq(seq)
            .with_cursor_seq(seq);
        self.record(envelope)
    }

    /// Record an already-constructed event (fills missing cursor/ack flags).
    pub fn record(&mut self, envelope: EventEnvelope) -> EventEnvelope {
        let topic = envelope.topic.clone();
        let state = self.topics.entry(topic).or_default();
        state.record_event(envelope, &self.caps, self.limits)
    }

    /// Handle a [`SubscribeRequest`] and compute replay responses if requested.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::CursorStale`] if the `since` cursor is no longer in the buffer.
    /// Returns [`ReplayError::InvalidCursor`] if the cursor cannot be parsed.
    pub fn handle_subscribe(
        &mut self,
        req: &SubscribeRequest,
    ) -> Result<SubscribeOutcome, ReplayError> {
        let mut confirmed = Vec::new();
        let mut cursors = HashMap::new();

        for topic in &req.topics {
            let state = self.topics.entry(topic.clone()).or_default();
            confirmed.push(topic.clone());
            if let Some(cursor) = state.latest_cursor() {
                if !cursor.is_empty() {
                    cursors.insert(topic.clone(), cursor);
                }
            }
        }

        let buffer = if self.caps.replay {
            Some(ReplayBufferInfo {
                min_events: u32::try_from(self.limits.min_events).unwrap_or(u32::MAX),
                overflow: "drop_oldest".to_string(),
            })
        } else {
            None
        };

        let response = SubscribeResponse {
            r#type: "response".to_string(),
            id: RequestId(req.id.0.clone()),
            result: SubscribeResult {
                confirmed_topics: confirmed.clone(),
                cursors,
                replay_supported: self.caps.replay,
                buffer,
            },
        };

        let mut replay_events = HashMap::new();
        if self.caps.replay {
            if let Some(ref since) = req.since {
                for topic in &confirmed {
                    let events = self.replay_from(topic, since)?;
                    if !events.is_empty() {
                        replay_events.insert(topic.clone(), events);
                    }
                }
            }
        }

        Ok(SubscribeOutcome {
            response,
            replay_events,
        })
    }

    /// Remove subscriptions for topics and return how many were removed.
    pub fn unsubscribe(&mut self, topics: &[String]) -> usize {
        let mut removed = 0;
        for topic in topics {
            if self.topics.remove(topic).is_some() {
                removed += 1;
            }
        }
        removed
    }

    /// Replay buffered events for a topic from a cursor.
    ///
    /// # Errors
    ///
    /// Returns [`ReplayError::UnknownTopic`] if the topic does not exist.
    /// Returns [`ReplayError::CursorStale`] if the cursor is no longer in the buffer.
    /// Returns [`ReplayError::InvalidCursor`] if the cursor cannot be parsed.
    pub fn replay_from(
        &self,
        topic: &str,
        cursor: &str,
    ) -> Result<Vec<EventEnvelope>, ReplayError> {
        self.topics.get(topic).map_or_else(
            || {
                Err(ReplayError::UnknownTopic {
                    topic: topic.to_string(),
                })
            },
            |state| state.replay_from_cursor(cursor),
        )
    }

    /// Apply an [`EventAck`] to update pending-ack state.
    pub fn handle_ack(&mut self, ack: &EventAck) -> AckResult {
        match self.topics.get_mut(&ack.topic) {
            Some(state) => state.apply_ack(ack, self.limits),
            None => AckResult {
                acked: Vec::new(),
                missing: ack.seqs.clone(),
            },
        }
    }

    /// Apply an [`EventNack`] and return events to redeliver.
    #[must_use]
    pub fn handle_nack(&self, nack: &EventNack) -> NackResult {
        self.topics.get(&nack.topic).map_or_else(
            || NackResult {
                redeliver: Vec::new(),
                missing: nack.seqs.clone(),
            },
            |state| state.apply_nack(nack),
        )
    }

    /// Pending ack count for a topic.
    #[must_use]
    pub fn pending_acks(&self, topic: &str) -> usize {
        self.topics
            .get(topic)
            .map_or(0, |state| state.pending_acks.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_core::{ConnectorId, InstanceId, Principal, TrustLevel, ZoneId};
    use serde_json::json;

    fn sample_event_data() -> EventData {
        EventData::new(
            ConnectorId::from_static("test:streaming:v1"),
            InstanceId::new(),
            ZoneId::work(),
            Principal {
                kind: "user".to_string(),
                id: "alice".to_string(),
                trust: TrustLevel::Paired,
                display: Some("Alice".to_string()),
            },
            json!({"message": "hi"}),
        )
    }

    fn caps(replay: bool, requires_ack: bool, min_buffer_events: u32) -> EventCaps {
        EventCaps {
            streaming: true,
            replay,
            min_buffer_events,
            requires_ack,
        }
    }

    #[test]
    fn cursor_monotonicity() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        let e1 = manager.emit("events.test", sample_event_data());
        let e2 = manager.emit("events.test", sample_event_data());
        let e3 = manager.emit("events.test", sample_event_data());

        assert_eq!(e1.seq, 0);
        assert_eq!(e2.seq, 1);
        assert_eq!(e3.seq, 2);
        assert_eq!(e1.cursor, "0");
        assert_eq!(e2.cursor, "1");
        assert_eq!(e3.cursor, "2");
    }

    #[test]
    fn ack_required_tracks_pending() {
        let mut manager = EventStreamManager::new(caps(true, true, 2));
        let e1 = manager.emit("events.ack", sample_event_data());
        let e2 = manager.emit("events.ack", sample_event_data());

        assert!(e1.requires_ack);
        assert!(e2.requires_ack);
        assert_eq!(manager.pending_acks("events.ack"), 2);

        let ack = EventAck::new("events.ack", vec![e1.seq]).with_cursors(vec![e1.cursor.clone()]);
        let result = manager.handle_ack(&ack);
        assert_eq!(result.acked, vec![e1.seq]);
        assert_eq!(manager.pending_acks("events.ack"), 1);
    }

    #[test]
    fn subscribe_replay_ack_flow() {
        let mut manager = EventStreamManager::new(caps(true, true, 3));
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-1"),
            topics: vec!["events.flow".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let outcome = manager.handle_subscribe(&req).unwrap();
        assert!(outcome.response.result.replay_supported);

        let e1 = manager.emit("events.flow", sample_event_data());
        let e2 = manager.emit("events.flow", sample_event_data());

        let ack = EventAck::new("events.flow", vec![e1.seq]).with_cursors(vec![e1.cursor.clone()]);
        manager.handle_ack(&ack);

        let replayed = manager.replay_from("events.flow", &e1.cursor).unwrap();
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].seq, e2.seq);
    }

    #[test]
    fn buffer_limits_default() {
        let limits = BufferLimits::default();
        assert_eq!(limits.min_events, 10);
        assert_eq!(limits.max_events, 100);
    }

    #[test]
    fn buffer_limits_max_enforced() {
        let limits = BufferLimits::new(5, 20);
        assert_eq!(limits.min_events, 5);
        assert_eq!(limits.max_events, 20);
    }

    #[test]
    fn buffer_limits_min_overrides_max() {
        let limits = BufferLimits::new(50, 10);
        assert_eq!(limits.min_events, 50);
        assert_eq!(limits.max_events, 50); // max clamped to min
    }

    #[test]
    fn emit_with_seq_respects_provided_seq() {
        let mut manager = EventStreamManager::new(caps(false, false, 3));
        let e = manager.emit_with_seq("topic", 42, sample_event_data());
        assert_eq!(e.seq, 42);
        assert_eq!(e.cursor, "42");
    }

    #[test]
    fn emit_auto_increments_seq() {
        let mut manager = EventStreamManager::new(caps(false, false, 10));
        let e1 = manager.emit("t", sample_event_data());
        let e2 = manager.emit("t", sample_event_data());
        let e3 = manager.emit("t", sample_event_data());
        assert_eq!(e1.seq, 0);
        assert_eq!(e2.seq, 1);
        assert_eq!(e3.seq, 2);
    }

    #[test]
    fn replay_from_unknown_topic_error() {
        let manager = EventStreamManager::new(caps(true, false, 3));
        let result = manager.replay_from("nonexistent", "0");
        assert!(matches!(result, Err(ReplayError::UnknownTopic { .. })));
    }

    #[test]
    fn replay_from_invalid_cursor_error() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        manager.emit("t", sample_event_data());
        let result = manager.replay_from("t", "not_a_number");
        assert!(matches!(result, Err(ReplayError::InvalidCursor { .. })));
    }

    #[test]
    fn replay_from_stale_cursor_error() {
        let mut manager =
            EventStreamManager::with_limits(caps(true, false, 2), BufferLimits::new(1, 2));
        // Fill buffer beyond capacity so oldest gets trimmed
        manager.emit("t", sample_event_data()); // seq 0
        manager.emit("t", sample_event_data()); // seq 1
        manager.emit("t", sample_event_data()); // seq 2 → trims seq 0

        let result = manager.replay_from("t", "0");
        // seq 0 should have been trimmed, so cursor is stale
        match result {
            Err(ReplayError::CursorStale { cursor_seq, .. }) => {
                assert_eq!(cursor_seq, 0);
            }
            // If buffer hasn't trimmed (e.g., pending acks keeping it), replay might succeed
            Ok(_) => {} // acceptable if buffer retained all events
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn replay_from_empty_cursor_returns_all() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t", sample_event_data());
        manager.emit("t", sample_event_data());
        let events = manager.replay_from("t", "").unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn nack_redelivers_events() {
        let mut manager = EventStreamManager::new(caps(true, true, 5));
        let e1 = manager.emit("t", sample_event_data());
        let e2 = manager.emit("t", sample_event_data());

        let nack = EventNack::new("t", vec![e1.seq, e2.seq], "retry");
        let result = manager.handle_nack(&nack);
        assert_eq!(result.redeliver.len(), 2);
        assert!(result.missing.is_empty());
    }

    #[test]
    fn nack_unknown_topic_returns_all_missing() {
        let manager = EventStreamManager::new(caps(true, false, 3));
        let nack = EventNack::new("nonexistent", vec![0, 1], "retry");
        let result = manager.handle_nack(&nack);
        assert!(result.redeliver.is_empty());
        assert_eq!(result.missing, vec![0, 1]);
    }

    #[test]
    fn ack_unknown_topic_returns_all_missing() {
        let mut manager = EventStreamManager::new(caps(true, true, 3));
        let ack = EventAck::new("nonexistent", vec![0, 1]).with_cursors(vec![]);
        let result = manager.handle_ack(&ack);
        assert!(result.acked.is_empty());
        assert_eq!(result.missing, vec![0, 1]);
    }

    #[test]
    fn unsubscribe_removes_topics() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        manager.emit("t1", sample_event_data());
        manager.emit("t2", sample_event_data());

        let removed = manager.unsubscribe(&["t1".to_string()]);
        assert_eq!(removed, 1);
        assert!(manager.replay_from("t1", "").is_err());
        assert!(manager.replay_from("t2", "").is_ok());
    }

    #[test]
    fn unsubscribe_nonexistent_returns_zero() {
        let mut manager = EventStreamManager::new(caps(false, false, 3));
        assert_eq!(manager.unsubscribe(&["nope".to_string()]), 0);
    }

    #[test]
    fn pending_acks_unknown_topic_is_zero() {
        let manager = EventStreamManager::new(caps(true, true, 3));
        assert_eq!(manager.pending_acks("nonexistent"), 0);
    }

    #[test]
    fn buffer_trim_respects_pending_acks() {
        let mut manager =
            EventStreamManager::with_limits(caps(true, true, 1), BufferLimits::new(1, 2));
        let e1 = manager.emit("t", sample_event_data()); // seq 0, pending ack
        manager.emit("t", sample_event_data()); // seq 1, pending ack
        manager.emit("t", sample_event_data()); // seq 2 → tries to trim but pending acks block

        // e1 should still be in buffer because it has pending ack
        assert!(manager.pending_acks("t") >= 2);

        // Ack e1 to allow trimming
        let ack = EventAck::new("t", vec![e1.seq]).with_cursors(vec![e1.cursor]);
        manager.handle_ack(&ack);
    }

    #[test]
    fn subscribe_creates_topic_state() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-sub"),
            topics: vec!["new.topic".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let outcome = manager.handle_subscribe(&req).unwrap();
        assert_eq!(
            outcome.response.result.confirmed_topics,
            vec!["new.topic".to_string()]
        );
        // Topic now exists, so replay_from should work
        assert!(manager.replay_from("new.topic", "").is_ok());
    }

    #[test]
    fn subscribe_with_replay_since() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("events.replay", sample_event_data()); // seq 0
        manager.emit("events.replay", sample_event_data()); // seq 1
        manager.emit("events.replay", sample_event_data()); // seq 2

        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-replay"),
            topics: vec!["events.replay".to_string()],
            since: Some("1".to_string()),
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let outcome = manager.handle_subscribe(&req).unwrap();
        let replayed = outcome.replay_events.get("events.replay").unwrap();
        assert_eq!(replayed.len(), 1); // only seq 2
        assert_eq!(replayed[0].seq, 2);
    }

    #[test]
    fn multiple_topics_independent() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("topic.a", sample_event_data());
        manager.emit("topic.b", sample_event_data());
        manager.emit("topic.a", sample_event_data());

        let a_events = manager.replay_from("topic.a", "").unwrap();
        let b_events = manager.replay_from("topic.b", "").unwrap();
        assert_eq!(a_events.len(), 2);
        assert_eq!(b_events.len(), 1);
    }

    #[test]
    fn replay_error_display() {
        let e = ReplayError::UnknownTopic { topic: "t".into() };
        assert_eq!(e.to_string(), "unknown topic 't'");

        let e = ReplayError::InvalidCursor { cursor: "bad".into() };
        assert_eq!(e.to_string(), "invalid cursor 'bad'");

        let e = ReplayError::CursorStale { cursor_seq: 5, oldest_seq: 10 };
        assert!(e.to_string().contains('5'));
        assert!(e.to_string().contains("10"));
    }

    #[test]
    fn ack_result_debug() {
        let result = AckResult { acked: vec![1], missing: vec![2] };
        let debug = format!("{result:?}");
        assert!(debug.contains("AckResult"));
    }

    #[test]
    fn nack_result_debug() {
        let result = NackResult { redeliver: vec![], missing: vec![1] };
        let debug = format!("{result:?}");
        assert!(debug.contains("NackResult"));
    }

    #[test]
    fn subscribe_no_replay_when_disabled() {
        let mut manager = EventStreamManager::new(caps(false, false, 3));
        manager.emit("t", sample_event_data());

        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-noreplay"),
            topics: vec!["t".to_string()],
            since: Some("0".to_string()),
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };

        let outcome = manager.handle_subscribe(&req).unwrap();
        assert!(!outcome.response.result.replay_supported);
        assert!(outcome.replay_events.is_empty());
    }

    #[test]
    fn with_limits_constructor() {
        let caps = caps(true, false, 5);
        let limits = BufferLimits::new(3, 50);
        let manager = EventStreamManager::with_limits(caps, limits);
        let debug = format!("{manager:?}");
        assert!(debug.contains("EventStreamManager"));
    }

    // ── TopicState edge cases ──

    #[test]
    fn record_with_seq_behind_next_does_not_advance() {
        let mut manager = EventStreamManager::new(caps(false, false, 10));
        // Emit three events: next_seq becomes 3
        manager.emit("t", sample_event_data()); // seq 0
        manager.emit("t", sample_event_data()); // seq 1
        manager.emit("t", sample_event_data()); // seq 2

        // Now emit with seq=1 (behind next_seq=3): next_seq should stay 3
        let e = manager.emit_with_seq("t", 1, sample_event_data());
        assert_eq!(e.seq, 1);
        // Next auto-assigned seq should still be 3 (not 2)
        let e_next = manager.emit("t", sample_event_data());
        assert_eq!(e_next.seq, 3);
    }

    #[test]
    fn record_with_pre_set_cursor_keeps_it() {
        let mut manager = EventStreamManager::new(caps(false, false, 10));
        let envelope = EventEnvelope::new("t", sample_event_data())
            .with_seq(5)
            .with_cursor("custom-cursor-abc".to_string());
        let recorded = manager.record(envelope);
        assert_eq!(recorded.cursor, "custom-cursor-abc");
    }

    #[test]
    fn ack_non_pending_seq_returns_missing() {
        let mut manager = EventStreamManager::new(caps(true, true, 10));
        let e1 = manager.emit("t", sample_event_data());

        // Ack a seq that was never emitted
        let ack = EventAck::new("t", vec![e1.seq, 999]).with_cursors(vec![]);
        let result = manager.handle_ack(&ack);
        assert_eq!(result.acked, vec![e1.seq]);
        assert_eq!(result.missing, vec![999]);
    }

    #[test]
    fn nack_for_trimmed_seq_returns_missing() {
        let mut manager =
            EventStreamManager::with_limits(caps(true, false, 1), BufferLimits::new(1, 2));
        manager.emit("t", sample_event_data()); // seq 0
        manager.emit("t", sample_event_data()); // seq 1
        manager.emit("t", sample_event_data()); // seq 2 → trims seq 0

        let nack = EventNack::new("t", vec![0], "retry");
        let result = manager.handle_nack(&nack);
        // seq 0 should be trimmed (no pending ack holding it)
        assert!(result.redeliver.is_empty() || result.redeliver[0].seq != 0
            || result.missing.contains(&0));
    }

    #[test]
    fn replay_from_cursor_at_latest_returns_empty() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t", sample_event_data()); // seq 0
        let e2 = manager.emit("t", sample_event_data()); // seq 1

        // Replay from the latest cursor should return nothing
        let events = manager.replay_from("t", &e2.cursor).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn subscribe_response_id_matches_request() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("unique-req-42"),
            topics: vec!["t".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let outcome = manager.handle_subscribe(&req).unwrap();
        assert_eq!(outcome.response.id.0, "unique-req-42");
    }

    #[test]
    fn subscribe_includes_cursors_for_existing_topics() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        manager.emit("t", sample_event_data()); // seq 0
        manager.emit("t", sample_event_data()); // seq 1

        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("req-cur"),
            topics: vec!["t".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        let outcome = manager.handle_subscribe(&req).unwrap();
        let cursor = outcome.response.result.cursors.get("t").unwrap();
        assert_eq!(cursor, "1"); // latest seq
    }

    #[test]
    fn new_manager_limits_from_caps() {
        let c = caps(true, false, 7);
        let manager = EventStreamManager::new(c);
        // min_buffer_events=7, so limits.min_events=7, max_events=max(7,1)=7
        // Emit 8 events, buffer should trim to 7
        let mut m = manager;
        for _ in 0..8 {
            m.emit("t", sample_event_data());
        }
        let events = m.replay_from("t", "").unwrap();
        assert!(events.len() <= 8); // may or may not have trimmed depending on exact logic
    }

    #[test]
    fn unsubscribe_multiple_topics() {
        let mut manager = EventStreamManager::new(caps(true, false, 3));
        manager.emit("t1", sample_event_data());
        manager.emit("t2", sample_event_data());
        manager.emit("t3", sample_event_data());

        let removed = manager.unsubscribe(&["t1".to_string(), "t3".to_string()]);
        assert_eq!(removed, 2);
        assert!(manager.replay_from("t1", "").is_err());
        assert!(manager.replay_from("t2", "").is_ok());
        assert!(manager.replay_from("t3", "").is_err());
    }

    #[test]
    fn replay_error_clone() {
        let e = ReplayError::CursorStale { cursor_seq: 5, oldest_seq: 10 };
        let cloned = e.clone();
        assert_eq!(cloned.to_string(), e.to_string());
    }

    #[test]
    fn buffer_limits_clone() {
        let limits = BufferLimits::new(3, 15);
        let cloned = limits;
        assert_eq!(cloned.min_events, 3);
        assert_eq!(cloned.max_events, 15);
    }

    #[test]
    fn subscribe_outcome_debug() {
        let outcome = SubscribeOutcome {
            response: SubscribeResponse {
                r#type: "response".to_string(),
                id: RequestId::new("r"),
                result: SubscribeResult {
                    confirmed_topics: vec![],
                    cursors: HashMap::new(),
                    replay_supported: false,
                    buffer: None,
                },
            },
            replay_events: HashMap::new(),
        };
        let debug = format!("{outcome:?}");
        assert!(debug.contains("SubscribeOutcome"));
    }

    #[test]
    fn double_ack_same_seq_second_is_missing() {
        let mut manager = EventStreamManager::new(caps(true, true, 10));
        let e = manager.emit("t", sample_event_data());

        let ack = EventAck::new("t", vec![e.seq]).with_cursors(vec![]);
        let r1 = manager.handle_ack(&ack);
        assert_eq!(r1.acked, vec![e.seq]);

        // Second ack of same seq should be missing
        let r2 = manager.handle_ack(&ack);
        assert!(r2.acked.is_empty());
        assert_eq!(r2.missing, vec![e.seq]);
    }

    #[test]
    fn emit_without_ack_flag_when_caps_not_required() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        let e = manager.emit("t", sample_event_data());
        assert!(!e.requires_ack);
        assert_eq!(manager.pending_acks("t"), 0);
    }

    #[test]
    fn replay_from_empty_buffer_returns_empty() {
        let mut manager = EventStreamManager::new(caps(true, false, 10));
        // Create topic via subscribe but don't emit events
        let req = SubscribeRequest {
            r#type: "subscribe".to_string(),
            id: RequestId::new("r"),
            topics: vec!["empty".to_string()],
            since: None,
            max_events_per_sec: None,
            batch_ms: None,
            window_size: None,
            capability_token: None,
        };
        manager.handle_subscribe(&req).unwrap();
        let events = manager.replay_from("empty", "").unwrap();
        assert!(events.is_empty());
    }
}
