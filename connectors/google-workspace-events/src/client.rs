//! Google Workspace Events + Pub/Sub client.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fcp_google_discovery::auth::GoogleMaterializedAuth;
use reqwest::Client;
use serde::de::DeserializeOwned;
use tracing::{instrument, warn};

use crate::error::{WorkspaceEventsError, WorkspaceEventsResult};
use crate::types::{
    ListSubscriptionsResponse, LongRunningOperation, PullResponse, WorkspaceSubscription,
};

/// Default Google Workspace Events API base URL.
pub const DEFAULT_EVENTS_BASE_URL: &str = "https://workspaceevents.googleapis.com/v1";
/// Default Google Cloud Pub/Sub API base URL.
pub const DEFAULT_PUBSUB_BASE_URL: &str = "https://pubsub.googleapis.com/v1";

#[derive(Debug, Clone, Copy)]
enum MissingResourceKind {
    WorkspaceSubscription,
    PubsubSubscription,
    Unknown,
}

/// Google Workspace Events client.
pub struct WorkspaceEventsClient {
    client: Client,
    auth: GoogleMaterializedAuth,
    events_base_url: String,
    pubsub_base_url: String,
    total_requests: AtomicU64,
}

impl fmt::Debug for WorkspaceEventsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkspaceEventsClient")
            .field("auth", &self.auth_redacted_label())
            .field("events_base_url", &self.events_base_url)
            .field("pubsub_base_url", &self.pubsub_base_url)
            .finish_non_exhaustive()
    }
}

impl WorkspaceEventsClient {
    /// Create a new client with shared Google auth.
    pub fn new_with_auth(auth: GoogleMaterializedAuth) -> WorkspaceEventsResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-google-workspace-events/0.1.0")
            .build()
            .map_err(WorkspaceEventsError::Http)?;

        Ok(Self {
            client,
            auth,
            events_base_url: DEFAULT_EVENTS_BASE_URL.to_string(),
            pubsub_base_url: DEFAULT_PUBSUB_BASE_URL.to_string(),
            total_requests: AtomicU64::new(0),
        })
    }

    /// Override base URLs for tests.
    #[must_use]
    pub fn with_base_urls(
        mut self,
        events_base_url: impl Into<String>,
        pubsub_base_url: impl Into<String>,
    ) -> Self {
        self.events_base_url = events_base_url.into();
        self.pubsub_base_url = pubsub_base_url.into();
        self
    }

    /// Render a redacted auth label suitable for logs/diagnostics.
    #[must_use]
    pub fn auth_redacted_label(&self) -> String {
        match &self.auth {
            GoogleMaterializedAuth::BearerToken { source, .. } => source.to_string(),
            GoogleMaterializedAuth::CredentialReference { credential_id, .. } => {
                format!("credential_id:{credential_id}")
            }
        }
    }

    /// Total requests issued by the client.
    #[must_use]
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Basic connectivity probe.
    pub async fn health_check(&self) -> WorkspaceEventsResult<()> {
        let _ = self.list_subscriptions(Some(1), None).await?;
        Ok(())
    }

    /// List subscriptions.
    #[instrument(skip(self))]
    pub async fn list_subscriptions(
        &self,
        page_size: Option<u32>,
        page_token: Option<&str>,
    ) -> WorkspaceEventsResult<ListSubscriptionsResponse> {
        let mut url = format!("{}/subscriptions", self.events_base_url);
        let mut params = Vec::new();
        if let Some(page_size) = page_size {
            params.push(format!("pageSize={page_size}"));
        }
        if let Some(page_token) = page_token {
            params.push(format!(
                "pageToken={}",
                percent_encoding::utf8_percent_encode(
                    page_token,
                    percent_encoding::NON_ALPHANUMERIC,
                )
            ));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        self.get_json(&url, MissingResourceKind::Unknown).await
    }

    /// Get a subscription by resource name.
    #[instrument(skip(self), fields(subscription_name))]
    pub async fn get_subscription(
        &self,
        subscription_name: &str,
    ) -> WorkspaceEventsResult<WorkspaceSubscription> {
        let url = format!("{}/{}", self.events_base_url, subscription_name);
        self.get_json(&url, MissingResourceKind::WorkspaceSubscription)
            .await
    }

    /// Create a subscription.
    #[instrument(skip(self, event_types), fields(target_resource))]
    pub async fn create_subscription(
        &self,
        target_resource: &str,
        event_types: &[String],
        pubsub_topic: &str,
        ttl: Option<&str>,
        include_resource: bool,
        field_mask: Option<&str>,
    ) -> WorkspaceEventsResult<LongRunningOperation> {
        let url = format!("{}/subscriptions", self.events_base_url);
        let mut body = serde_json::json!({
            "targetResource": target_resource,
            "eventTypes": event_types,
            "notificationEndpoint": {
                "pubsubTopic": pubsub_topic
            },
            "payloadOptions": {
                "includeResource": include_resource
            }
        });
        if let Some(ttl) = ttl {
            body["ttl"] = serde_json::json!(ttl);
        }
        if let Some(field_mask) = field_mask.filter(|mask| !mask.is_empty()) {
            body["payloadOptions"]["fieldMask"] = serde_json::json!(field_mask);
        }
        self.post_json(&url, &body, MissingResourceKind::Unknown)
            .await
    }

    /// Reactivate a suspended subscription.
    #[instrument(skip(self), fields(subscription_name))]
    pub async fn reactivate_subscription(
        &self,
        subscription_name: &str,
        ttl: Option<&str>,
    ) -> WorkspaceEventsResult<LongRunningOperation> {
        let url = format!("{}/{subscription_name}:reactivate", self.events_base_url);
        let body = if let Some(ttl) = ttl {
            serde_json::json!({ "ttl": ttl })
        } else {
            serde_json::json!({})
        };
        self.post_json(&url, &body, MissingResourceKind::WorkspaceSubscription)
            .await
    }

    /// Delete a subscription.
    #[instrument(skip(self), fields(subscription_name))]
    pub async fn delete_subscription(
        &self,
        subscription_name: &str,
        validate_only: bool,
    ) -> WorkspaceEventsResult<LongRunningOperation> {
        let url = if validate_only {
            format!(
                "{}/{subscription_name}?validateOnly=true",
                self.events_base_url
            )
        } else {
            format!("{}/{}", self.events_base_url, subscription_name)
        };
        self.delete_json(&url, MissingResourceKind::WorkspaceSubscription)
            .await
    }

    /// Pull Pub/Sub messages for the configured delivery subscription.
    #[instrument(skip(self), fields(pubsub_subscription))]
    pub async fn pull_events(
        &self,
        pubsub_subscription: &str,
        max_messages: u32,
    ) -> WorkspaceEventsResult<PullResponse> {
        let url = format!("{}/{pubsub_subscription}:pull", self.pubsub_base_url);
        let body = serde_json::json!({
            "maxMessages": max_messages
        });
        self.post_json(&url, &body, MissingResourceKind::PubsubSubscription)
            .await
    }

    /// Acknowledge Pub/Sub messages after they are processed.
    #[instrument(skip(self, ack_ids), fields(pubsub_subscription))]
    pub async fn ack_events(
        &self,
        pubsub_subscription: &str,
        ack_ids: &[String],
    ) -> WorkspaceEventsResult<serde_json::Value> {
        let url = format!("{}/{pubsub_subscription}:acknowledge", self.pubsub_base_url);
        let body = serde_json::json!({
            "ackIds": ack_ids
        });
        self.post_json(&url, &body, MissingResourceKind::PubsubSubscription)
            .await
    }

    fn bearer_token(&self) -> Option<&str> {
        match &self.auth {
            GoogleMaterializedAuth::BearerToken { access_token, .. } => Some(access_token),
            GoogleMaterializedAuth::CredentialReference { .. } => None,
        }
    }

    async fn get_json<T: DeserializeOwned + Default>(
        &self,
        url: &str,
        missing_kind: MissingResourceKind,
    ) -> WorkspaceEventsResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let token = self
            .bearer_token()
            .ok_or(WorkspaceEventsError::Unauthorized)?;
        let resp = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(WorkspaceEventsError::Http)?;
        self.handle_response(resp, missing_kind).await
    }

    async fn post_json<T: DeserializeOwned + Default, B: serde::Serialize>(
        &self,
        url: &str,
        body: &B,
        missing_kind: MissingResourceKind,
    ) -> WorkspaceEventsResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let token = self
            .bearer_token()
            .ok_or(WorkspaceEventsError::Unauthorized)?;
        let resp = self
            .client
            .post(url)
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .map_err(WorkspaceEventsError::Http)?;
        self.handle_response(resp, missing_kind).await
    }

    async fn delete_json<T: DeserializeOwned + Default>(
        &self,
        url: &str,
        missing_kind: MissingResourceKind,
    ) -> WorkspaceEventsResult<T> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        let token = self
            .bearer_token()
            .ok_or(WorkspaceEventsError::Unauthorized)?;
        let resp = self
            .client
            .delete(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(WorkspaceEventsError::Http)?;
        self.handle_response(resp, missing_kind).await
    }

    async fn handle_response<T: DeserializeOwned + Default>(
        &self,
        resp: reqwest::Response,
        missing_kind: MissingResourceKind,
    ) -> WorkspaceEventsResult<T> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await.map_err(WorkspaceEventsError::Http)?;
            if body.trim().is_empty() {
                return Ok(T::default());
            }
            return serde_json::from_str(&body).map_err(WorkspaceEventsError::Json);
        }

        let code = status.as_u16();
        let body = resp.text().await.unwrap_or_default();
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&body) {
            let message = value
                .get("error")
                .and_then(|e| e.get("message"))
                .and_then(|v| v.as_str())
                .or_else(|| value.get("message").and_then(|v| v.as_str()))
                .unwrap_or(&body)
                .to_string();
            Err(map_api_error(code, message, missing_kind))
        } else {
            let preview: String = body.chars().take(200).collect();
            warn!(
                status = code,
                body_preview = %preview,
                "Workspace Events API error"
            );
            Err(map_api_error(code, body, missing_kind))
        }
    }
}

fn map_api_error(
    status_code: u16,
    message: String,
    missing_kind: MissingResourceKind,
) -> WorkspaceEventsError {
    match status_code {
        401 | 403 => WorkspaceEventsError::Unauthorized,
        404 => match missing_kind {
            MissingResourceKind::WorkspaceSubscription => {
                WorkspaceEventsError::SubscriptionNotFound {
                    subscription_name: message,
                }
            }
            MissingResourceKind::PubsubSubscription => {
                WorkspaceEventsError::PubsubSubscriptionNotFound {
                    subscription_name: message,
                }
            }
            MissingResourceKind::Unknown => WorkspaceEventsError::Api {
                status_code,
                message,
            },
        },
        429 => WorkspaceEventsError::RateLimited {
            retry_after_ms: 60_000,
        },
        _ => WorkspaceEventsError::Api {
            status_code,
            message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_redacted_label_credential_ref() {
        let credential_id = fcp_core::CredentialId::new();
        let client =
            WorkspaceEventsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
                credential_id,
                quota_project_id: None,
            })
            .unwrap();
        assert!(client.auth_redacted_label().starts_with("credential_id:"));
    }

    #[test]
    fn total_requests_starts_at_zero() {
        let credential_id = fcp_core::CredentialId::new();
        let client =
            WorkspaceEventsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
                credential_id,
                quota_project_id: None,
            })
            .unwrap();
        assert_eq!(client.total_requests(), 0);
    }
}
