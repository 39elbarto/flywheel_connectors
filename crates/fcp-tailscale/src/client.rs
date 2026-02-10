//! Tailscale ``LocalAPI`` client abstraction.
//!
//! This module provides a trait-based abstraction for the Tailscale `LocalAPI`,
//! allowing for easy testing with mock implementations.
//!
//! # `LocalAPI` Endpoints
//!
//! - `/localapi/v0/status` - Get current tailnet status
//! - `/localapi/v0/whois?addr=<ip>` - Look up peer by IP address

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{TailscaleError, TailscaleResult};
use crate::identity::NodeId;
use crate::tag::TailscaleTag;

/// Trait for Tailscale `LocalAPI` clients.
///
/// This abstraction allows for both real and mock implementations,
/// making testing possible without a real tailnet connection.
#[allow(async_fn_in_trait)]
pub trait TailscaleClient: Send + Sync {
    /// Get the current tailnet status.
    async fn status(&self) -> TailscaleResult<TailscaleStatus>;

    /// Look up a peer by IP address.
    async fn whois(&self, addr: IpAddr) -> TailscaleResult<PeerInfo>;

    /// Get all online peers.
    async fn online_peers(&self) -> TailscaleResult<Vec<PeerInfo>> {
        let status = self.status().await?;
        Ok(status.peer.into_values().filter(|p| p.online).collect())
    }

    /// Check if connected to the tailnet.
    async fn is_connected(&self) -> TailscaleResult<bool> {
        let status = self.status().await?;
        Ok(status.backend_state == "Running")
    }
}

/// Tailnet status from `LocalAPI`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TailscaleStatus {
    /// Backend state (e.g., "Running", "Stopped").
    pub backend_state: String,

    /// This node's information.
    #[serde(rename = "Self")]
    pub self_node: SelfNode,

    /// Map of peer node IDs to peer info.
    #[serde(default)]
    pub peer: HashMap<String, PeerInfo>,

    /// Current user (if logged in).
    pub user: Option<UserInfo>,

    /// Tailnet name.
    #[serde(rename = "CurrentTailnet")]
    pub tailnet: Option<TailnetInfo>,
}

impl TailscaleStatus {
    /// Get peers as a more convenient map.
    #[must_use]
    pub fn peers(&self) -> HashMap<NodeId, PeerInfo> {
        self.peer
            .iter()
            .map(|(k, v)| (NodeId::new(k.clone()), v.clone()))
            .collect()
    }
}

/// This node's information from status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SelfNode {
    /// Node ID.
    #[serde(rename = "ID")]
    pub id: String,

    /// Public key.
    pub public_key: String,

    /// Hostname.
    pub host_name: String,

    /// DNS name.
    #[serde(rename = "DNSName")]
    pub dns_name: String,

    /// IP addresses.
    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Vec<IpAddr>,

    /// Tags assigned to this node.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Whether this node is online.
    pub online: bool,
}

/// Information about a peer node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PeerInfo {
    /// Node ID.
    #[serde(rename = "ID")]
    pub id: String,

    /// Public key.
    pub public_key: String,

    /// Hostname.
    pub host_name: String,

    /// DNS name.
    #[serde(rename = "DNSName")]
    pub dns_name: String,

    /// IP addresses.
    #[serde(rename = "TailscaleIPs")]
    pub tailscale_ips: Vec<IpAddr>,

    /// Tags assigned to this peer.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Whether this peer is online.
    pub online: bool,

    /// Operating system.
    #[serde(rename = "OS")]
    pub os: Option<String>,

    /// Last seen timestamp.
    pub last_seen: Option<String>,
}

impl PeerInfo {
    /// Get this peer's node ID.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        NodeId::new(&self.id)
    }

    /// Get this peer's tags as `TailscaleTag` objects.
    #[must_use]
    pub fn tailscale_tags(&self) -> Vec<TailscaleTag> {
        self.tags
            .iter()
            .filter_map(|t| TailscaleTag::new(t).ok())
            .collect()
    }

    /// Get this peer's FCP tags (zone memberships).
    #[must_use]
    pub fn fcp_tags(&self) -> Vec<TailscaleTag> {
        self.tailscale_tags()
            .into_iter()
            .filter(TailscaleTag::is_fcp_tag)
            .collect()
    }
}

/// User information from status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct UserInfo {
    /// User ID.
    #[serde(rename = "ID")]
    pub id: i64,

    /// Login name.
    pub login_name: String,

    /// Display name.
    pub display_name: String,
}

/// Tailnet information from status.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct TailnetInfo {
    /// Tailnet name.
    pub name: String,

    /// Whether this is a personal tailnet.
    pub is_personal: Option<bool>,
}

/// Real `LocalAPI` client using Unix socket or HTTP.
pub struct LocalApiClient {
    /// HTTP client for making requests.
    client: reqwest::Client,

    /// Base URL for the `LocalAPI` (socket path or HTTP URL).
    base_url: String,
}

impl LocalApiClient {
    /// Create a new `LocalAPI` client using the default socket path.
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be created.
    pub fn new() -> TailscaleResult<Self> {
        Self::with_socket(crate::DEFAULT_LOCALAPI_SOCKET)
    }

    /// Create a new `LocalAPI` client using a custom socket path.
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be created.
    pub fn with_socket(_socket_path: &str) -> TailscaleResult<Self> {
        // Unix socket support requires additional dependencies not currently enabled.
        Err(TailscaleError::LocalApiRequest(
            "Unix socket support not enabled in this build".into(),
        ))
    }

    /// Create a new `LocalAPI` client using an HTTP URL.
    ///
    /// This is useful for testing or when the `LocalAPI` is exposed over HTTP.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn with_http(base_url: impl Into<String>) -> TailscaleResult<Self> {
        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| TailscaleError::LocalApiRequest(e.to_string()))?;

        Ok(Self {
            client,
            base_url: base_url.into(),
        })
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> TailscaleResult<T> {
        let url = format!("{}{path}", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| TailscaleError::LocalApiRequest(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            // Limit body size for error messages to prevent DoS
            let body_bytes = response.bytes().await.unwrap_or_default();
            let body =
                String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(4096)]).into_owned();
            return Err(TailscaleError::LocalApiError(format!("{status}: {body}")));
        }

        response
            .json()
            .await
            .map_err(|e| TailscaleError::ParseError(e.to_string()))
    }
}

impl TailscaleClient for LocalApiClient {
    async fn status(&self) -> TailscaleResult<TailscaleStatus> {
        self.get("/localapi/v0/status").await
    }

    async fn whois(&self, addr: IpAddr) -> TailscaleResult<PeerInfo> {
        self.get(&format!("/localapi/v0/whois?addr={addr}")).await
    }
}

/// Mock Tailscale client for testing.
///
/// This implementation stores peers in memory and allows tests to
/// configure the tailnet state without a real Tailscale connection.
#[derive(Debug, Clone, Default)]
pub struct MockTailscaleClient {
    inner: Arc<RwLock<MockState>>,
}

#[derive(Debug, Default)]
struct MockState {
    backend_state: String,
    self_node: Option<SelfNode>,
    peers: HashMap<String, PeerInfo>,
    connected: bool,
}

impl MockTailscaleClient {
    /// Create a new mock client.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(MockState {
                backend_state: "Running".to_string(),
                connected: true,
                ..Default::default()
            })),
        }
    }

    /// Create a disconnected mock client.
    #[must_use]
    pub fn disconnected() -> Self {
        Self {
            inner: Arc::new(RwLock::new(MockState {
                backend_state: "Stopped".to_string(),
                connected: false,
                ..Default::default()
            })),
        }
    }

    /// Set this node's information.
    pub async fn set_self_node(&self, node: SelfNode) {
        self.inner.write().await.self_node = Some(node);
    }

    /// Add a peer to the mock tailnet.
    pub async fn add_peer(&self, peer: PeerInfo) {
        self.inner.write().await.peers.insert(peer.id.clone(), peer);
    }

    /// Remove a peer from the mock tailnet.
    pub async fn remove_peer(&self, node_id: &str) {
        self.inner.write().await.peers.remove(node_id);
    }

    /// Set a peer's online status.
    pub async fn set_peer_online(&self, node_id: &str, online: bool) {
        if let Some(peer) = self.inner.write().await.peers.get_mut(node_id) {
            peer.online = online;
        }
    }

    /// Set the backend state.
    pub async fn set_backend_state(&self, state: impl Into<String>) {
        let state = state.into();
        let mut inner = self.inner.write().await;
        inner.connected = state == "Running";
        inner.backend_state = state;
    }

    /// Create a mock peer with common defaults.
    #[must_use]
    pub fn mock_peer(id: &str, hostname: &str, ip: IpAddr, tags: &[&str]) -> PeerInfo {
        PeerInfo {
            id: id.to_string(),
            public_key: format!("pubkey:{id}"),
            host_name: hostname.to_string(),
            dns_name: format!("{hostname}.tailnet.ts.net"),
            tailscale_ips: vec![ip],
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
            online: true,
            os: Some("linux".to_string()),
            last_seen: None,
        }
    }

    /// Create a mock self node.
    #[must_use]
    pub fn mock_self_node(id: &str, hostname: &str, ip: IpAddr, tags: &[&str]) -> SelfNode {
        SelfNode {
            id: id.to_string(),
            public_key: format!("pubkey:{id}"),
            host_name: hostname.to_string(),
            dns_name: format!("{hostname}.tailnet.ts.net"),
            tailscale_ips: vec![ip],
            tags: tags.iter().map(|s| (*s).to_string()).collect(),
            online: true,
        }
    }
}

impl TailscaleClient for MockTailscaleClient {
    async fn status(&self) -> TailscaleResult<TailscaleStatus> {
        let inner = self.inner.read().await;

        if !inner.connected {
            return Err(TailscaleError::NotConnected);
        }

        let self_node = inner.self_node.clone().unwrap_or_else(|| SelfNode {
            id: "mock-self".to_string(),
            public_key: "pubkey:mock-self".to_string(),
            host_name: "mock-host".to_string(),
            dns_name: "mock-host.tailnet.ts.net".to_string(),
            tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
            tags: vec![],
            online: true,
        });

        Ok(TailscaleStatus {
            backend_state: inner.backend_state.clone(),
            self_node,
            peer: inner.peers.clone(),
            user: None,
            tailnet: Some(TailnetInfo {
                name: "mock-tailnet".to_string(),
                is_personal: Some(false),
            }),
        })
    }

    async fn whois(&self, addr: IpAddr) -> TailscaleResult<PeerInfo> {
        let inner = self.inner.read().await;

        if !inner.connected {
            return Err(TailscaleError::NotConnected);
        }

        // Search for peer by IP
        let result = inner
            .peers
            .values()
            .find(|peer| peer.tailscale_ips.contains(&addr))
            .cloned();

        drop(inner);

        result.ok_or_else(|| TailscaleError::PeerNotFound(addr.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_client_status() {
        let client = MockTailscaleClient::new();

        let status = client.status().await.unwrap();
        assert_eq!(status.backend_state, "Running");
    }

    #[tokio::test]
    async fn test_mock_client_disconnected() {
        let client = MockTailscaleClient::disconnected();

        let result = client.status().await;
        assert!(matches!(result, Err(TailscaleError::NotConnected)));
    }

    #[tokio::test]
    async fn test_mock_client_add_peer() {
        let client = MockTailscaleClient::new();

        let peer = MockTailscaleClient::mock_peer(
            "node-123",
            "server1",
            "100.64.0.2".parse().unwrap(),
            &["tag:fcp-work", "tag:server"],
        );
        client.add_peer(peer).await;

        let status = client.status().await.unwrap();
        assert_eq!(status.peer.len(), 1);
        assert!(status.peer.contains_key("node-123"));
    }

    #[tokio::test]
    async fn test_mock_client_whois() {
        let client = MockTailscaleClient::new();

        let ip: IpAddr = "100.64.0.5".parse().unwrap();
        let peer = MockTailscaleClient::mock_peer("node-456", "worker1", ip, &["tag:fcp-private"]);
        client.add_peer(peer).await;

        let found = client.whois(ip).await.unwrap();
        assert_eq!(found.id, "node-456");
        assert_eq!(found.host_name, "worker1");
    }

    #[tokio::test]
    async fn test_mock_client_whois_not_found() {
        let client = MockTailscaleClient::new();

        let result = client.whois("100.64.0.99".parse().unwrap()).await;
        assert!(matches!(result, Err(TailscaleError::PeerNotFound(_))));
    }

    #[tokio::test]
    async fn test_mock_client_online_peers() {
        let client = MockTailscaleClient::new();

        // Add online and offline peers
        let online_peer = MockTailscaleClient::mock_peer(
            "node-1",
            "online-server",
            "100.64.0.2".parse().unwrap(),
            &[],
        );
        let mut offline_peer = MockTailscaleClient::mock_peer(
            "node-2",
            "offline-server",
            "100.64.0.3".parse().unwrap(),
            &[],
        );
        offline_peer.online = false;

        client.add_peer(online_peer).await;
        client.add_peer(offline_peer).await;

        let online = client.online_peers().await.unwrap();
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].host_name, "online-server");
    }

    #[tokio::test]
    async fn test_mock_client_set_peer_online() {
        let client = MockTailscaleClient::new();

        let peer =
            MockTailscaleClient::mock_peer("node-1", "server", "100.64.0.2".parse().unwrap(), &[]);
        client.add_peer(peer).await;

        // Initially online
        let online = client.online_peers().await.unwrap();
        assert_eq!(online.len(), 1);

        // Set offline
        client.set_peer_online("node-1", false).await;
        let online = client.online_peers().await.unwrap();
        assert_eq!(online.len(), 0);
    }

    #[tokio::test]
    async fn test_peer_info_fcp_tags() {
        let peer = MockTailscaleClient::mock_peer(
            "node-1",
            "server",
            "100.64.0.2".parse().unwrap(),
            &["tag:fcp-work", "tag:server", "tag:fcp-private"],
        );

        let fcp_tags = peer.fcp_tags();
        assert_eq!(fcp_tags.len(), 2);
        assert!(fcp_tags.iter().any(|t| t.as_str() == "tag:fcp-work"));
        assert!(fcp_tags.iter().any(|t| t.as_str() == "tag:fcp-private"));
    }

    #[tokio::test]
    async fn test_is_connected() {
        let connected = MockTailscaleClient::new();
        assert!(connected.is_connected().await.unwrap());

        let disconnected = MockTailscaleClient::disconnected();
        // Disconnected returns error, not false
        assert!(disconnected.is_connected().await.is_err());
    }
}
