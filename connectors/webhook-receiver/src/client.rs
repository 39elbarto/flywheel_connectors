//! In-memory webhook endpoint and event store.
//!
//! Unlike other connectors that wrap an HTTP client, the webhook receiver
//! stores all state locally. It manages webhook endpoint registrations and
//! buffers received events.

use std::cmp::Reverse;
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use tracing::debug;

use crate::{
    error::{WebhookReceiverError, WebhookReceiverResult},
    types::{EndpointSummary, WebhookEndpoint, WebhookEvent},
};

/// Maximum number of endpoints that can be registered.
pub const MAX_ENDPOINTS: usize = 100;

/// Maximum number of events stored per endpoint.
pub const MAX_EVENTS_PER_ENDPOINT: usize = 1000;

/// Default limit for recent events query.
pub const DEFAULT_EVENTS_LIMIT: usize = 50;

/// Maximum limit for recent events query.
pub const MAX_EVENTS_LIMIT: usize = 100;

/// In-memory store for webhook endpoints and received events.
#[derive(Debug)]
pub struct WebhookStore {
    /// Registered endpoints, keyed by `endpoint_id`.
    endpoints: HashMap<String, WebhookEndpoint>,
    /// Events per endpoint, keyed by `endpoint_id`.
    events: HashMap<String, Vec<WebhookEvent>>,
}

impl WebhookStore {
    /// Create a new empty webhook store.
    pub fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
            events: HashMap::new(),
        }
    }

    /// Register a new webhook endpoint.
    pub fn create_endpoint(
        &mut self,
        path: String,
        signing_secret: String,
        allowed_sources: Vec<String>,
    ) -> WebhookReceiverResult<WebhookEndpoint> {
        // Check for duplicate path
        if self.endpoints.values().any(|ep| ep.path == path) {
            return Err(WebhookReceiverError::DuplicatePath { path });
        }

        // Check capacity
        if self.endpoints.len() >= MAX_ENDPOINTS {
            return Err(WebhookReceiverError::CapacityExceeded {
                message: format!("Maximum of {MAX_ENDPOINTS} endpoints reached"),
            });
        }

        let endpoint = WebhookEndpoint::new(path, signing_secret, allowed_sources);
        debug!(endpoint_id = %endpoint.endpoint_id, path = %endpoint.path, "Created webhook endpoint");

        self.endpoints
            .insert(endpoint.endpoint_id.clone(), endpoint.clone());
        self.events.insert(endpoint.endpoint_id.clone(), Vec::new());

        Ok(endpoint)
    }

    /// Delete a webhook endpoint and its events.
    pub fn delete_endpoint(&mut self, endpoint_id: &str) -> WebhookReceiverResult<()> {
        if self.endpoints.remove(endpoint_id).is_none() {
            return Err(WebhookReceiverError::EndpointNotFound {
                endpoint_id: endpoint_id.into(),
            });
        }
        self.events.remove(endpoint_id);
        debug!(endpoint_id = %endpoint_id, "Deleted webhook endpoint");
        Ok(())
    }

    /// List all registered endpoints with event counts.
    pub fn list_endpoints(&self) -> Vec<EndpointSummary> {
        self.endpoints
            .values()
            .map(|ep| {
                let event_count = self.events.get(&ep.endpoint_id).map_or(0, Vec::len);
                EndpointSummary::from_endpoint(ep, event_count)
            })
            .collect()
    }

    /// Get a specific endpoint by ID.
    pub fn get_endpoint(&self, endpoint_id: &str) -> WebhookReceiverResult<&WebhookEndpoint> {
        self.endpoints
            .get(endpoint_id)
            .ok_or_else(|| WebhookReceiverError::EndpointNotFound {
                endpoint_id: endpoint_id.into(),
            })
    }

    /// Record a received webhook event.
    pub fn record_event(&mut self, event: WebhookEvent) -> WebhookReceiverResult<()> {
        let endpoint_id = event.endpoint_id.clone();
        if !self.endpoints.contains_key(&endpoint_id) {
            return Err(WebhookReceiverError::EndpointNotFound { endpoint_id });
        }

        let events = self.events.entry(endpoint_id).or_default();

        // Evict oldest events if at capacity
        if events.len() >= MAX_EVENTS_PER_ENDPOINT {
            events.remove(0);
        }

        events.push(event);
        Ok(())
    }

    /// Get recent events, optionally filtered by endpoint and time.
    pub fn get_recent_events(
        &self,
        endpoint_id: Option<&str>,
        limit: Option<usize>,
        since_ts: Option<DateTime<Utc>>,
    ) -> WebhookReceiverResult<Vec<WebhookEvent>> {
        let limit = limit.unwrap_or(DEFAULT_EVENTS_LIMIT).min(MAX_EVENTS_LIMIT);

        // If endpoint_id is specified, validate it exists
        if let Some(eid) = endpoint_id {
            if !self.endpoints.contains_key(eid) {
                return Err(WebhookReceiverError::EndpointNotFound {
                    endpoint_id: eid.into(),
                });
            }
        }

        let mut all_events: Vec<WebhookEvent> = if let Some(eid) = endpoint_id {
            self.events
                .get(eid)
                .map_or_else(Vec::new, |evts| evts.clone())
        } else {
            self.events.values().flat_map(|v| v.clone()).collect()
        };

        // Filter by since_ts if provided
        if let Some(since) = since_ts {
            all_events.retain(|e| e.received_at >= since);
        }

        // Sort by received_at descending (most recent first)
        all_events.sort_by_key(|e| Reverse(e.received_at));

        // Apply limit
        all_events.truncate(limit);

        Ok(all_events)
    }

    /// Get the number of registered endpoints.
    pub fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    /// Get the total number of stored events.
    pub fn total_event_count(&self) -> usize {
        self.events.values().map(Vec::len).sum()
    }

    /// Clear all endpoints and events.
    pub fn clear(&mut self) {
        self.endpoints.clear();
        self.events.clear();
    }
}

impl Default for WebhookStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn store_new_is_empty() {
        let store = WebhookStore::new();
        assert_eq!(store.endpoint_count(), 0);
        assert_eq!(store.total_event_count(), 0);
    }

    #[test]
    fn store_default_is_empty() {
        let store = WebhookStore::default();
        assert_eq!(store.endpoint_count(), 0);
        assert_eq!(store.total_event_count(), 0);
    }

    #[test]
    fn create_endpoint_basic() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/github".into(), "secret".into(), vec![])
            .unwrap();
        assert!(ep.endpoint_id.starts_with("ep_"));
        assert_eq!(ep.path, "/hooks/github");
        assert_eq!(store.endpoint_count(), 1);
    }

    #[test]
    fn create_endpoint_with_allowed_sources() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint(
                "/hooks/stripe".into(),
                "whsec_123".into(),
                vec!["10.0.0.0/8".into(), "172.16.0.0/12".into()],
            )
            .unwrap();
        assert_eq!(ep.allowed_sources.len(), 2);
    }

    #[test]
    fn create_endpoint_duplicate_path_rejected() {
        let mut store = WebhookStore::new();
        store
            .create_endpoint("/hooks/github".into(), "s1".into(), vec![])
            .unwrap();
        let result = store.create_endpoint("/hooks/github".into(), "s2".into(), vec![]);
        assert!(result.is_err());
        match result.unwrap_err() {
            WebhookReceiverError::DuplicatePath { path } => {
                assert_eq!(path, "/hooks/github");
            }
            other => panic!("expected DuplicatePath, got {other:?}"),
        }
    }

    #[test]
    fn create_endpoint_different_paths_allowed() {
        let mut store = WebhookStore::new();
        store
            .create_endpoint("/hooks/github".into(), "s1".into(), vec![])
            .unwrap();
        store
            .create_endpoint("/hooks/stripe".into(), "s2".into(), vec![])
            .unwrap();
        assert_eq!(store.endpoint_count(), 2);
    }

    #[test]
    fn delete_endpoint_success() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        store.delete_endpoint(&ep.endpoint_id).unwrap();
        assert_eq!(store.endpoint_count(), 0);
    }

    #[test]
    fn delete_endpoint_removes_events() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
        store.record_event(event).unwrap();
        assert_eq!(store.total_event_count(), 1);
        store.delete_endpoint(&ep.endpoint_id).unwrap();
        assert_eq!(store.total_event_count(), 0);
    }

    #[test]
    fn delete_endpoint_not_found() {
        let mut store = WebhookStore::new();
        let result = store.delete_endpoint("ep_nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn list_endpoints_empty() {
        let store = WebhookStore::new();
        assert!(store.list_endpoints().is_empty());
    }

    #[test]
    fn list_endpoints_returns_all() {
        let mut store = WebhookStore::new();
        store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();
        let list = store.list_endpoints();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn list_endpoints_includes_event_counts() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..3 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }
        let list = store.list_endpoints();
        let summary = list
            .iter()
            .find(|s| s.endpoint_id == ep.endpoint_id)
            .unwrap();
        assert_eq!(summary.event_count, 3);
    }

    #[test]
    fn get_endpoint_success() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let found = store.get_endpoint(&ep.endpoint_id).unwrap();
        assert_eq!(found.path, "/hooks/test");
    }

    #[test]
    fn get_endpoint_not_found() {
        let store = WebhookStore::new();
        let result = store.get_endpoint("ep_nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn record_event_success() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let event = WebhookEvent::new(
            ep.endpoint_id,
            json!({"type": "push"}),
            true,
            Some("1.2.3.4".into()),
        );
        store.record_event(event).unwrap();
        assert_eq!(store.total_event_count(), 1);
    }

    #[test]
    fn record_event_endpoint_not_found() {
        let mut store = WebhookStore::new();
        let event = WebhookEvent::new("ep_nonexistent".into(), json!({}), true, None);
        let result = store.record_event(event);
        assert!(result.is_err());
    }

    #[test]
    fn record_event_evicts_oldest_at_capacity() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();

        // Fill to capacity
        for i in 0..MAX_EVENTS_PER_ENDPOINT {
            let mut event =
                WebhookEvent::new(ep.endpoint_id.clone(), json!({"index": i}), true, None);
            event.event_id = format!("evt_{i}");
            store.record_event(event).unwrap();
        }
        assert_eq!(store.total_event_count(), MAX_EVENTS_PER_ENDPOINT);

        // Add one more; oldest should be evicted
        let mut new_event =
            WebhookEvent::new(ep.endpoint_id.clone(), json!({"index": "new"}), true, None);
        new_event.event_id = "evt_new".into();
        store.record_event(new_event).unwrap();
        assert_eq!(store.total_event_count(), MAX_EVENTS_PER_ENDPOINT);

        // Verify the oldest was evicted
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), Some(MAX_EVENTS_LIMIT), None)
            .unwrap();
        let ids: Vec<&str> = events.iter().map(|e| e.event_id.as_str()).collect();
        assert!(!ids.contains(&"evt_0"));
        assert!(ids.contains(&"evt_new"));
    }

    #[test]
    fn get_recent_events_all() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..5 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn get_recent_events_with_limit() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..10 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), Some(3), None)
            .unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn get_recent_events_limit_capped_at_max() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..150 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), Some(200), None)
            .unwrap();
        assert_eq!(events.len(), MAX_EVENTS_LIMIT);
    }

    #[test]
    fn get_recent_events_default_limit() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..100 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        assert_eq!(events.len(), DEFAULT_EVENTS_LIMIT);
    }

    #[test]
    fn get_recent_events_across_endpoints() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();
        store
            .record_event(WebhookEvent::new(ep1.endpoint_id, json!({}), true, None))
            .unwrap();
        store
            .record_event(WebhookEvent::new(ep2.endpoint_id, json!({}), true, None))
            .unwrap();

        // Without filter, gets events from all endpoints
        let events = store.get_recent_events(None, None, None).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn get_recent_events_filtered_by_endpoint() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..3 {
            store
                .record_event(WebhookEvent::new(
                    ep1.endpoint_id.clone(),
                    json!({}),
                    true,
                    None,
                ))
                .unwrap();
        }
        store
            .record_event(WebhookEvent::new(ep2.endpoint_id, json!({}), true, None))
            .unwrap();

        let events = store
            .get_recent_events(Some(&ep1.endpoint_id), None, None)
            .unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn get_recent_events_endpoint_not_found() {
        let store = WebhookStore::new();
        let result = store.get_recent_events(Some("ep_nope"), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn get_recent_events_sorted_most_recent_first() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();

        for _ in 0..5 {
            let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
            store.record_event(event).unwrap();
        }

        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        for i in 1..events.len() {
            assert!(events[i - 1].received_at >= events[i].received_at);
        }
    }

    #[test]
    fn get_recent_events_with_since_ts() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();

        // Record an event "in the past"
        let mut old_event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
        old_event.received_at = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        store.record_event(old_event).unwrap();

        // Record a recent event
        let recent_event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
        store.record_event(recent_event).unwrap();

        let since = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, Some(since))
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn clear_removes_everything() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        store
            .record_event(WebhookEvent::new(ep.endpoint_id, json!({}), true, None))
            .unwrap();
        store.clear();
        assert_eq!(store.endpoint_count(), 0);
        assert_eq!(store.total_event_count(), 0);
    }

    #[test]
    fn store_debug_format() {
        let store = WebhookStore::new();
        let dbg = format!("{store:?}");
        assert!(dbg.contains("WebhookStore"));
    }

    #[test]
    fn multiple_events_multiple_endpoints() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s1".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s2".into(), vec![])
            .unwrap();
        let ep3 = store
            .create_endpoint("/c".into(), "s3".into(), vec![])
            .unwrap();

        for ep_id in [&ep1.endpoint_id, &ep2.endpoint_id, &ep3.endpoint_id] {
            for _ in 0..5 {
                store
                    .record_event(WebhookEvent::new(ep_id.clone(), json!({}), true, None))
                    .unwrap();
            }
        }

        assert_eq!(store.endpoint_count(), 3);
        assert_eq!(store.total_event_count(), 15);
    }

    #[test]
    fn get_recent_events_empty_store() {
        let store = WebhookStore::new();
        let events = store.get_recent_events(None, None, None).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn get_recent_events_no_events_for_endpoint() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn delete_then_recreate_same_path() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/hooks/reuse".into(), "s".into(), vec![])
            .unwrap();
        store.delete_endpoint(&ep1.endpoint_id).unwrap();
        let ep2 = store
            .create_endpoint("/hooks/reuse".into(), "s".into(), vec![])
            .unwrap();
        assert_ne!(ep1.endpoint_id, ep2.endpoint_id);
    }

    #[test]
    fn constants_values() {
        assert_eq!(MAX_ENDPOINTS, 100);
        assert_eq!(MAX_EVENTS_PER_ENDPOINT, 1000);
        assert_eq!(DEFAULT_EVENTS_LIMIT, 50);
        assert_eq!(MAX_EVENTS_LIMIT, 100);
    }

    #[test]
    fn store_clear_then_create_again() {
        let mut store = WebhookStore::new();
        store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        store.clear();
        assert_eq!(store.endpoint_count(), 0);
        // Can create with same path after clear
        store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        assert_eq!(store.endpoint_count(), 1);
    }

    #[test]
    fn get_endpoint_returns_correct_data() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint(
                "/hooks/verify".into(),
                "secret123".into(),
                vec!["10.0.0.0/8".into()],
            )
            .unwrap();
        let found = store.get_endpoint(&ep.endpoint_id).unwrap();
        assert_eq!(found.signing_secret, "secret123");
        assert_eq!(found.allowed_sources.len(), 1);
        assert_eq!(found.allowed_sources[0], "10.0.0.0/8");
    }

    #[test]
    fn total_event_count_across_endpoints() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();

        for _ in 0..3 {
            store
                .record_event(WebhookEvent::new(
                    ep1.endpoint_id.clone(),
                    json!({}),
                    true,
                    None,
                ))
                .unwrap();
        }
        for _ in 0..7 {
            store
                .record_event(WebhookEvent::new(
                    ep2.endpoint_id.clone(),
                    json!({}),
                    true,
                    None,
                ))
                .unwrap();
        }

        assert_eq!(store.total_event_count(), 10);
    }

    #[test]
    fn delete_endpoint_only_removes_that_endpoint() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();

        store
            .record_event(WebhookEvent::new(
                ep1.endpoint_id.clone(),
                json!({}),
                true,
                None,
            ))
            .unwrap();
        let ep2_id = ep2.endpoint_id;
        store
            .record_event(WebhookEvent::new(ep2_id, json!({}), true, None))
            .unwrap();

        store.delete_endpoint(&ep1.endpoint_id).unwrap();
        assert_eq!(store.endpoint_count(), 1);
        assert_eq!(store.total_event_count(), 1);
    }

    #[test]
    fn list_endpoints_order_independent() {
        let mut store = WebhookStore::new();
        store
            .create_endpoint("/z".into(), "s".into(), vec![])
            .unwrap();
        store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        store
            .create_endpoint("/m".into(), "s".into(), vec![])
            .unwrap();
        let list = store.list_endpoints();
        assert_eq!(list.len(), 3);
        let paths: Vec<&str> = list.iter().map(|s| s.path.as_str()).collect();
        assert!(paths.contains(&"/z"));
        assert!(paths.contains(&"/a"));
        assert!(paths.contains(&"/m"));
    }

    #[test]
    fn get_recent_events_limit_of_zero() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        store
            .record_event(WebhookEvent::new(
                ep.endpoint_id.clone(),
                json!({}),
                true,
                None,
            ))
            .unwrap();
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), Some(0), None)
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn get_recent_events_limit_of_one() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        for _ in 0..5 {
            store
                .record_event(WebhookEvent::new(
                    ep.endpoint_id.clone(),
                    json!({}),
                    true,
                    None,
                ))
                .unwrap();
        }
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), Some(1), None)
            .unwrap();
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn record_event_with_source_ip() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let event = WebhookEvent::new(
            ep.endpoint_id.clone(),
            json!({}),
            true,
            Some("192.168.1.100".into()),
        );
        store.record_event(event).unwrap();
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        assert_eq!(events[0].source_ip, Some("192.168.1.100".into()));
    }

    #[test]
    fn record_event_with_invalid_signature() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        let event = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), false, None);
        store.record_event(event).unwrap();
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, None)
            .unwrap();
        assert!(!events[0].signature_valid);
    }

    #[test]
    fn endpoint_count_after_multiple_creates_and_deletes() {
        let mut store = WebhookStore::new();
        let ep1 = store
            .create_endpoint("/a".into(), "s".into(), vec![])
            .unwrap();
        let ep2 = store
            .create_endpoint("/b".into(), "s".into(), vec![])
            .unwrap();
        let _ep3 = store
            .create_endpoint("/c".into(), "s".into(), vec![])
            .unwrap();
        assert_eq!(store.endpoint_count(), 3);
        store.delete_endpoint(&ep1.endpoint_id).unwrap();
        assert_eq!(store.endpoint_count(), 2);
        store.delete_endpoint(&ep2.endpoint_id).unwrap();
        assert_eq!(store.endpoint_count(), 1);
    }

    #[test]
    fn get_recent_events_since_ts_filters_old() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();

        // Old event
        let mut old = WebhookEvent::new(ep.endpoint_id.clone(), json!({"old": true}), true, None);
        old.received_at = chrono::DateTime::parse_from_rfc3339("2020-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        store.record_event(old).unwrap();

        // Recent events
        for _ in 0..3 {
            store
                .record_event(WebhookEvent::new(
                    ep.endpoint_id.clone(),
                    json!({}),
                    true,
                    None,
                ))
                .unwrap();
        }

        let since = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, Some(since))
            .unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn get_recent_events_since_ts_all_old() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();

        let mut old = WebhookEvent::new(ep.endpoint_id.clone(), json!({}), true, None);
        old.received_at = chrono::DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        store.record_event(old).unwrap();

        let since = chrono::DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let events = store
            .get_recent_events(Some(&ep.endpoint_id), None, Some(since))
            .unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn double_delete_returns_error() {
        let mut store = WebhookStore::new();
        let ep = store
            .create_endpoint("/hooks/test".into(), "s".into(), vec![])
            .unwrap();
        store.delete_endpoint(&ep.endpoint_id).unwrap();
        let result = store.delete_endpoint(&ep.endpoint_id);
        assert!(result.is_err());
    }
}
