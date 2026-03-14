//! Google Workspace Events and Pub/Sub data types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Google Workspace Events notification endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct NotificationEndpoint {
    #[serde(default)]
    pub pubsub_topic: String,
}

/// Workspace Events payload options.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PayloadOptions {
    #[serde(default)]
    pub include_resource: bool,
    #[serde(default)]
    pub field_mask: String,
}

/// Subscription lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubscriptionState {
    #[default]
    StateUnspecified,
    Active,
    Suspended,
    Deleted,
}

/// Google Workspace Events subscription.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSubscription {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub uid: String,
    #[serde(default)]
    pub target_resource: String,
    #[serde(default)]
    pub event_types: Vec<String>,
    #[serde(default)]
    pub notification_endpoint: Option<NotificationEndpoint>,
    #[serde(default)]
    pub payload_options: Option<PayloadOptions>,
    #[serde(default)]
    pub state: SubscriptionState,
    #[serde(default)]
    pub suspension_reason: String,
    #[serde(default)]
    pub reconciling: bool,
    #[serde(default)]
    pub create_time: String,
    #[serde(default)]
    pub update_time: String,
    #[serde(default)]
    pub expire_time: String,
    #[serde(default)]
    pub etag: String,
}

/// Response from listing subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListSubscriptionsResponse {
    #[serde(default)]
    pub subscriptions: Vec<WorkspaceSubscription>,
    #[serde(default)]
    pub next_page_token: String,
}

/// Long-running operation response used by create/reactivate/delete flows.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LongRunningOperation {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub response: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

/// Pub/Sub message wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PubsubMessage {
    #[serde(default)]
    pub data: String,
    #[serde(default)]
    pub message_id: String,
    #[serde(default)]
    pub publish_time: String,
    #[serde(default)]
    pub ordering_key: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

/// A Pub/Sub received message.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ReceivedMessage {
    #[serde(default)]
    pub ack_id: String,
    #[serde(default)]
    pub message: Option<PubsubMessage>,
    #[serde(default)]
    pub delivery_attempt: u32,
}

/// Response from Pub/Sub pull.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PullResponse {
    #[serde(default)]
    pub received_messages: Vec<ReceivedMessage>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn subscription_serde_defaults() {
        let sub: WorkspaceSubscription = serde_json::from_value(json!({
            "name": "subscriptions/abc",
            "targetResource": "//chat.googleapis.com/spaces/AAAA",
            "eventTypes": ["google.workspace.chat.message.v1.created"]
        }))
        .unwrap();
        assert_eq!(sub.name, "subscriptions/abc");
        assert_eq!(sub.target_resource, "//chat.googleapis.com/spaces/AAAA");
        assert_eq!(sub.event_types.len(), 1);
        assert_eq!(sub.state, SubscriptionState::StateUnspecified);
    }

    #[test]
    fn pull_response_defaults() {
        let response: PullResponse = serde_json::from_value(json!({})).unwrap();
        assert!(response.received_messages.is_empty());
    }
}
