//! Tailscale ``LocalAPI`` client abstraction.
//!
//! This module provides a trait-based abstraction for the Tailscale `LocalAPI`,
//! allowing for easy testing with mock implementations.
//!
//! # `LocalAPI` Endpoints
//!
//! - `/localapi/v0/status` - Get current tailnet status
//! - `/localapi/v0/whois?addr=<ip>` - Look up peer by IP address

use fcp_async_core::sync::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

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

        let mut base_url_str = base_url.into();
        if base_url_str.ends_with('/') {
            base_url_str.pop();
        }

        Ok(Self {
            client,
            base_url: base_url_str,
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

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_status() {
        let client = MockTailscaleClient::new();

        let status = client.status().await.unwrap();
        assert_eq!(status.backend_state, "Running");
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_disconnected() {
        let client = MockTailscaleClient::disconnected();

        let result = client.status().await;
        assert!(matches!(result, Err(TailscaleError::NotConnected)));
    }

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_whois() {
        let client = MockTailscaleClient::new();

        let ip: IpAddr = "100.64.0.5".parse().unwrap();
        let peer = MockTailscaleClient::mock_peer("node-456", "worker1", ip, &["tag:fcp-private"]);
        client.add_peer(peer).await;

        let found = client.whois(ip).await.unwrap();
        assert_eq!(found.id, "node-456");
        assert_eq!(found.host_name, "worker1");
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_whois_not_found() {
        let client = MockTailscaleClient::new();

        let result = client.whois("100.64.0.99".parse().unwrap()).await;
        assert!(matches!(result, Err(TailscaleError::PeerNotFound(_))));
    }

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
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

    #[fcp_async_core::runtime::test]
    async fn test_is_connected() {
        let connected = MockTailscaleClient::new();
        assert!(connected.is_connected().await.unwrap());

        let disconnected = MockTailscaleClient::disconnected();
        // Disconnected returns error, not false
        assert!(disconnected.is_connected().await.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_remove_peer() {
        let client = MockTailscaleClient::new();

        let peer =
            MockTailscaleClient::mock_peer("node-1", "server1", "100.64.0.2".parse().unwrap(), &[]);
        client.add_peer(peer).await;

        let status = client.status().await.unwrap();
        assert_eq!(status.peer.len(), 1);

        client.remove_peer("node-1").await;
        let status = client.status().await.unwrap();
        assert!(status.peer.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_remove_nonexistent_peer() {
        let client = MockTailscaleClient::new();
        // Removing a non-existent peer should not panic
        client.remove_peer("nonexistent").await;
        let status = client.status().await.unwrap();
        assert!(status.peer.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_whois_disconnected() {
        let client = MockTailscaleClient::disconnected();
        let result = client.whois("100.64.0.1".parse().unwrap()).await;
        assert!(matches!(result, Err(TailscaleError::NotConnected)));
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_online_peers_disconnected() {
        let client = MockTailscaleClient::disconnected();
        let result = client.online_peers().await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_set_backend_state() {
        let client = MockTailscaleClient::new();
        assert!(client.is_connected().await.unwrap());

        client.set_backend_state("Stopped").await;
        // After setting to Stopped, client becomes disconnected
        assert!(client.status().await.is_err());

        client.set_backend_state("Running").await;
        assert!(client.is_connected().await.unwrap());
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_set_self_node() {
        let client = MockTailscaleClient::new();
        let self_node = MockTailscaleClient::mock_self_node(
            "my-node",
            "my-host",
            "100.64.0.1".parse().unwrap(),
            &["tag:fcp-owner"],
        );
        client.set_self_node(self_node).await;

        let status = client.status().await.unwrap();
        assert_eq!(status.self_node.id, "my-node");
        assert_eq!(status.self_node.host_name, "my-host");
        assert_eq!(status.self_node.tags, vec!["tag:fcp-owner"]);
    }

    #[test]
    fn test_peer_info_node_id() {
        let peer =
            MockTailscaleClient::mock_peer("node-42", "host", "100.64.0.2".parse().unwrap(), &[]);
        assert_eq!(peer.node_id().as_str(), "node-42");
    }

    #[test]
    fn test_peer_info_tailscale_tags() {
        let peer = MockTailscaleClient::mock_peer(
            "node-1",
            "host",
            "100.64.0.2".parse().unwrap(),
            &["tag:fcp-work", "tag:server", "not-a-tag"],
        );

        let tags = peer.tailscale_tags();
        // "not-a-tag" should be filtered out (no "tag:" prefix)
        assert_eq!(tags.len(), 2);
    }

    #[test]
    fn test_peer_info_no_tags() {
        let peer =
            MockTailscaleClient::mock_peer("node-1", "host", "100.64.0.2".parse().unwrap(), &[]);
        assert!(peer.tailscale_tags().is_empty());
        assert!(peer.fcp_tags().is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_tailscale_status_peers_method() {
        let client = MockTailscaleClient::new();
        let peer =
            MockTailscaleClient::mock_peer("node-1", "host", "100.64.0.2".parse().unwrap(), &[]);
        client.add_peer(peer).await;

        let status = client.status().await.unwrap();
        let peers = status.peers();
        assert_eq!(peers.len(), 1);
        assert!(peers.contains_key(&NodeId::new("node-1")));
    }

    #[test]
    fn test_local_api_client_socket_returns_error() {
        let result = LocalApiClient::new();
        assert!(result.is_err());
    }

    #[test]
    fn test_local_api_client_with_http() {
        let result = LocalApiClient::with_http("http://127.0.0.1:8080");
        assert!(result.is_ok());
    }

    #[fcp_async_core::runtime::test]
    async fn test_mock_client_set_peer_online_nonexistent() {
        let client = MockTailscaleClient::new();
        // Setting online status for non-existent peer should not panic
        client.set_peer_online("nonexistent", true).await;
        let status = client.status().await.unwrap();
        assert!(status.peer.is_empty());
    }

    // ── Serde roundtrip tests ────────────────────────────────────────

    #[test]
    fn tailscale_status_serde_roundtrip() {
        let status = TailscaleStatus {
            backend_state: "Running".into(),
            self_node: SelfNode {
                id: "self-1".into(),
                public_key: "pubkey:self".into(),
                host_name: "myhost".into(),
                dns_name: "myhost.ts.net".into(),
                tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
                tags: vec!["tag:fcp-work".into()],
                online: true,
            },
            peer: HashMap::new(),
            user: Some(UserInfo {
                id: 42,
                login_name: "user@example.com".into(),
                display_name: "Test User".into(),
            }),
            tailnet: Some(TailnetInfo {
                name: "example.com".into(),
                is_personal: Some(false),
            }),
        };
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: TailscaleStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.backend_state, "Running");
        assert_eq!(deserialized.self_node.id, "self-1");
        assert!(deserialized.user.is_some());
        assert_eq!(deserialized.user.as_ref().unwrap().id, 42);
        assert!(deserialized.tailnet.is_some());
    }

    #[test]
    fn peer_info_serde_roundtrip() {
        let peer = PeerInfo {
            id: "node-42".into(),
            public_key: "pubkey:42".into(),
            host_name: "worker".into(),
            dns_name: "worker.ts.net".into(),
            tailscale_ips: vec![
                "100.64.0.2".parse().unwrap(),
                "fd7a:115c:a1e0::2".parse().unwrap(),
            ],
            tags: vec!["tag:fcp-work".into(), "tag:server".into()],
            online: true,
            os: Some("linux".into()),
            last_seen: Some("2026-03-05T12:00:00Z".into()),
        };
        let json = serde_json::to_string(&peer).unwrap();
        let deserialized: PeerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "node-42");
        assert_eq!(deserialized.tailscale_ips.len(), 2);
        assert_eq!(deserialized.tags.len(), 2);
        assert_eq!(deserialized.os.as_deref(), Some("linux"));
        assert!(deserialized.last_seen.is_some());
    }

    #[test]
    fn peer_info_serde_minimal() {
        // Test with optional fields absent
        let json = r#"{
            "ID": "n1",
            "PublicKey": "pk",
            "HostName": "h",
            "DNSName": "d.ts.net",
            "TailscaleIPs": ["100.64.0.1"],
            "Online": false
        }"#;
        let peer: PeerInfo = serde_json::from_str(json).unwrap();
        assert_eq!(peer.id, "n1");
        assert!(!peer.online);
        assert!(peer.os.is_none());
        assert!(peer.last_seen.is_none());
        assert!(peer.tags.is_empty()); // default
    }

    #[test]
    fn self_node_serde_roundtrip() {
        let node = SelfNode {
            id: "self-1".into(),
            public_key: "pk:self".into(),
            host_name: "myhost".into(),
            dns_name: "myhost.ts.net".into(),
            tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
            tags: vec![],
            online: true,
        };
        let json = serde_json::to_string(&node).unwrap();
        let deserialized: SelfNode = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, "self-1");
        assert!(deserialized.tags.is_empty());
    }

    #[test]
    fn user_info_serde_roundtrip() {
        let user = UserInfo {
            id: 100,
            login_name: "user@example.com".into(),
            display_name: "Test User".into(),
        };
        let json = serde_json::to_string(&user).unwrap();
        let deserialized: UserInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, 100);
        assert_eq!(deserialized.login_name, "user@example.com");
    }

    #[test]
    fn tailnet_info_serde_roundtrip() {
        let info = TailnetInfo {
            name: "example.com".into(),
            is_personal: Some(true),
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: TailnetInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.name, "example.com");
        assert_eq!(deserialized.is_personal, Some(true));
    }

    #[test]
    fn tailnet_info_serde_without_personal() {
        let info = TailnetInfo {
            name: "corp.com".into(),
            is_personal: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let deserialized: TailnetInfo = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_personal.is_none());
    }

    // ── PeerInfo method edge cases ───────────────────────────────────

    #[test]
    fn peer_info_fcp_tags_filters_non_fcp() {
        let peer = MockTailscaleClient::mock_peer(
            "n1",
            "h",
            "100.64.0.1".parse().unwrap(),
            &["tag:server", "tag:fcp-work", "tag:fcp-owner", "tag:infra"],
        );
        let fcp = peer.fcp_tags();
        assert_eq!(fcp.len(), 2);
        let names: Vec<_> = fcp.iter().map(|t| t.as_str().to_string()).collect();
        assert!(names.contains(&"tag:fcp-work".to_string()));
        assert!(names.contains(&"tag:fcp-owner".to_string()));
    }

    #[test]
    fn peer_info_tailscale_tags_invalid_filtered() {
        let peer = PeerInfo {
            id: "n1".into(),
            public_key: "pk".into(),
            host_name: "h".into(),
            dns_name: "d.ts.net".into(),
            tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
            tags: vec!["not-a-valid-tag".into(), "tag:valid".into()],
            online: true,
            os: None,
            last_seen: None,
        };
        let tags = peer.tailscale_tags();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].as_str(), "tag:valid");
    }

    // ── TailscaleStatus peers() ──────────────────────────────────────

    #[fcp_async_core::runtime::test]
    async fn status_peers_converts_keys_to_node_id() {
        let client = MockTailscaleClient::new();
        let p1 = MockTailscaleClient::mock_peer(
            "node-aaa",
            "h1",
            "100.64.0.2".parse().unwrap(),
            &[],
        );
        let p2 = MockTailscaleClient::mock_peer(
            "node-bbb",
            "h2",
            "100.64.0.3".parse().unwrap(),
            &[],
        );
        client.add_peer(p1).await;
        client.add_peer(p2).await;

        let status = client.status().await.unwrap();
        let peers = status.peers();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains_key(&NodeId::new("node-aaa")));
        assert!(peers.contains_key(&NodeId::new("node-bbb")));
    }

    #[fcp_async_core::runtime::test]
    async fn status_peers_empty_when_no_peers() {
        let client = MockTailscaleClient::new();
        let status = client.status().await.unwrap();
        let peers = status.peers();
        assert!(peers.is_empty());
    }

    // ── MockTailscaleClient state transitions ────────────────────────

    #[fcp_async_core::runtime::test]
    async fn mock_client_backend_state_cycle() {
        let client = MockTailscaleClient::new();

        // Running -> Stopped -> NeedsLogin -> Running
        assert!(client.is_connected().await.unwrap());

        client.set_backend_state("Stopped").await;
        assert!(client.status().await.is_err());

        client.set_backend_state("NeedsLogin").await;
        assert!(client.status().await.is_err());

        client.set_backend_state("Running").await;
        let status = client.status().await.unwrap();
        assert_eq!(status.backend_state, "Running");
    }

    #[fcp_async_core::runtime::test]
    async fn mock_client_default_self_node() {
        let client = MockTailscaleClient::new();
        let status = client.status().await.unwrap();
        // Default self_node has id "mock-self"
        assert_eq!(status.self_node.id, "mock-self");
        assert_eq!(status.self_node.host_name, "mock-host");
        assert!(status.self_node.online);
    }

    #[fcp_async_core::runtime::test]
    async fn mock_client_multiple_peers_same_operations() {
        let client = MockTailscaleClient::new();

        for i in 0..5 {
            let ip: IpAddr = format!("100.64.0.{}", 10 + i).parse().unwrap();
            let peer = MockTailscaleClient::mock_peer(
                &format!("node-{i}"),
                &format!("host-{i}"),
                ip,
                &[],
            );
            client.add_peer(peer).await;
        }

        let status = client.status().await.unwrap();
        assert_eq!(status.peer.len(), 5);

        // Remove two
        client.remove_peer("node-0").await;
        client.remove_peer("node-4").await;
        let status = client.status().await.unwrap();
        assert_eq!(status.peer.len(), 3);

        // Whois should find remaining
        let found = client.whois("100.64.0.12".parse().unwrap()).await;
        assert!(found.is_ok());
        assert_eq!(found.unwrap().id, "node-2");
    }

    // ── Debug/Clone traits ───────────────────────────────────────────

    #[test]
    fn mock_tailscale_client_debug() {
        let client = MockTailscaleClient::new();
        let debug = format!("{client:?}");
        assert!(debug.contains("MockTailscaleClient"));
    }

    #[test]
    fn mock_tailscale_client_clone() {
        let client = MockTailscaleClient::new();
        let cloned = client.clone();
        // Clone should produce equivalent instance
        assert_eq!(format!("{client:?}"), format!("{cloned:?}"));
    }

    #[test]
    fn mock_tailscale_client_default() {
        let client = MockTailscaleClient::default();
        // Default is disconnected (backend_state is empty)
        let debug = format!("{client:?}");
        assert!(debug.contains("MockTailscaleClient"));
    }

    // ── LocalApiClient URL normalization ─────────────────────────────

    #[test]
    fn local_api_client_strips_trailing_slash() {
        let client = LocalApiClient::with_http("http://127.0.0.1:8080/").unwrap();
        assert_eq!(client.base_url, "http://127.0.0.1:8080");
    }

    #[test]
    fn local_api_client_no_trailing_slash() {
        let client = LocalApiClient::with_http("http://127.0.0.1:8080").unwrap();
        assert_eq!(client.base_url, "http://127.0.0.1:8080");
    }

    #[test]
    fn local_api_client_custom_socket_returns_error() {
        let result = LocalApiClient::with_socket("/tmp/test.sock");
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("Unix socket")),
            Ok(_) => panic!("expected error"),
        }
    }

    // ── TailscaleStatus from JSON ────────────────────────────────────

    #[test]
    fn tailscale_status_from_realistic_json() {
        let json = r#"{
            "BackendState": "Running",
            "Self": {
                "ID": "n12345",
                "PublicKey": "nodekey:abc123",
                "HostName": "fcp-node",
                "DNSName": "fcp-node.tailnet.ts.net.",
                "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
                "Tags": ["tag:fcp-work", "tag:fcp-owner"],
                "Online": true
            },
            "Peer": {
                "node-peer1": {
                    "ID": "node-peer1",
                    "PublicKey": "nodekey:peer1",
                    "HostName": "peer1",
                    "DNSName": "peer1.tailnet.ts.net.",
                    "TailscaleIPs": ["100.64.0.2"],
                    "Tags": ["tag:fcp-work"],
                    "Online": true,
                    "OS": "linux",
                    "LastSeen": "2026-03-05T10:00:00Z"
                }
            },
            "CurrentTailnet": {
                "Name": "example.com",
                "IsPersonal": false
            }
        }"#;
        let status: TailscaleStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.backend_state, "Running");
        assert_eq!(status.self_node.tailscale_ips.len(), 2);
        assert_eq!(status.self_node.tags.len(), 2);
        assert_eq!(status.peer.len(), 1);
        let peer = &status.peer["node-peer1"];
        assert_eq!(peer.os.as_deref(), Some("linux"));
        assert!(status.tailnet.is_some());
    }

    #[test]
    fn tailscale_status_from_minimal_json() {
        let json = r#"{
            "BackendState": "Stopped",
            "Self": {
                "ID": "n1",
                "PublicKey": "pk",
                "HostName": "h",
                "DNSName": "h.ts.net",
                "TailscaleIPs": [],
                "Online": false
            }
        }"#;
        let status: TailscaleStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.backend_state, "Stopped");
        assert!(status.peer.is_empty());
        assert!(status.user.is_none());
        assert!(status.tailnet.is_none());
    }
}
