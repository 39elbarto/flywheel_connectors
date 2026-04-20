//! Integration tests for fcp-tailscale: mock client, identity, attestation, tags.
//!
//! These tests exercise the public API surface without real Tailscale connections,
//! using `MockTailscaleClient` for peer/status scenarios and real crypto for
//! attestation signing/verification.

use std::net::{IpAddr, Ipv4Addr};

use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_crypto::x25519::X25519SecretKey;
use fcp_tailscale::{
    FCP_TAG_PREFIX, MeshIdentity, MockTailscaleClient, NodeId, NodeKeyAttestation, NodeKeys,
    TailscaleClient, TailscaleError, TailscaleTag, ZoneAclGenerator, ZoneAclRule, ZoneTagMapping,
};

// ── helpers ──

const fn test_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(100, 64, 1, 1))
}

const fn test_ip2() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(100, 64, 1, 2))
}

fn test_node_keys() -> NodeKeys {
    let signing = Ed25519SigningKey::generate();
    let encryption = X25519SecretKey::generate();
    let issuance = Ed25519SigningKey::generate();
    NodeKeys::new(
        signing.verifying_key(),
        encryption.public_key(),
        issuance.verifying_key(),
    )
}

// ── TailscaleTag ──

#[test]
fn tag_valid_creation() {
    let tag = TailscaleTag::new("tag:fcp-work").expect("valid tag");
    assert_eq!(tag.as_str(), "tag:fcp-work");
    assert!(tag.is_fcp_tag());
    assert_eq!(tag.fcp_suffix(), Some("work"));
}

#[test]
fn tag_non_fcp_tag() {
    let tag = TailscaleTag::new("tag:server").expect("valid tag");
    assert!(!tag.is_fcp_tag());
    assert_eq!(tag.fcp_suffix(), None);
}

#[test]
fn tag_invalid_no_prefix() {
    let result = TailscaleTag::new("no-prefix");
    assert!(result.is_err());
}

#[test]
fn tag_fcp_tag_factory() {
    let tag = TailscaleTag::fcp_tag("community");
    assert_eq!(tag.as_str(), "tag:fcp-community");
    assert!(tag.is_fcp_tag());
    assert_eq!(tag.fcp_suffix(), Some("community"));
}

#[test]
fn tag_equality_and_clone() {
    let a = TailscaleTag::fcp_tag("work");
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn tag_display() {
    let tag = TailscaleTag::fcp_tag("private");
    assert_eq!(format!("{tag}"), "tag:fcp-private");
}

#[test]
fn tag_serde_roundtrip() {
    let tag = TailscaleTag::fcp_tag("owner");
    let json = serde_json::to_string(&tag).expect("serialize");
    let deserialized: TailscaleTag = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(tag, deserialized);
}

// ── ZoneTagMapping ──

#[test]
fn zone_to_tag_valid() {
    let tag = ZoneTagMapping::zone_to_tag("z:work").expect("valid zone");
    assert_eq!(tag.as_str(), "tag:fcp-work");
}

#[test]
fn zone_to_tag_all_standard_zones() {
    let zones = ZoneTagMapping::standard_zones();
    assert!(zones.len() >= 5);
    for zone in zones {
        let tag = ZoneTagMapping::zone_to_tag(zone).expect("should parse");
        assert!(tag.is_fcp_tag());
    }
}

#[test]
fn zone_to_tag_invalid_prefix() {
    let result = ZoneTagMapping::zone_to_tag("invalid:work");
    assert!(result.is_err());
}

#[test]
fn tag_to_zone_roundtrip() {
    let original = "z:work";
    let tag = ZoneTagMapping::zone_to_tag(original).expect("zone_to_tag");
    let zone = ZoneTagMapping::tag_to_zone(&tag).expect("tag_to_zone");
    assert_eq!(zone, original);
}

#[test]
fn tag_to_zone_non_fcp_returns_none() {
    let tag = TailscaleTag::new("tag:server").expect("valid tag");
    assert!(ZoneTagMapping::tag_to_zone(&tag).is_none());
}

#[test]
fn try_tag_to_zone_non_fcp_returns_error() {
    let tag = TailscaleTag::new("tag:server").expect("valid tag");
    let result = ZoneTagMapping::try_tag_to_zone(&tag);
    assert!(result.is_err());
}

#[test]
fn is_valid_zone_id_standard_zones() {
    assert!(ZoneTagMapping::is_valid_zone_id("z:work"));
    assert!(ZoneTagMapping::is_valid_zone_id("z:owner"));
    assert!(ZoneTagMapping::is_valid_zone_id("z:private"));
    assert!(ZoneTagMapping::is_valid_zone_id("z:community"));
    assert!(ZoneTagMapping::is_valid_zone_id("z:public"));
}

#[test]
fn is_valid_zone_id_rejects_bad_formats() {
    assert!(!ZoneTagMapping::is_valid_zone_id("work"));
    assert!(!ZoneTagMapping::is_valid_zone_id("z:"));
    assert!(!ZoneTagMapping::is_valid_zone_id("z:-leading"));
    assert!(!ZoneTagMapping::is_valid_zone_id("z:trailing-"));
    assert!(!ZoneTagMapping::is_valid_zone_id(""));
}

#[test]
fn validate_zone_id_returns_input_on_success() {
    let result = ZoneTagMapping::validate_zone_id("z:work").expect("valid");
    assert_eq!(result, "z:work");
}

#[test]
fn validate_zone_id_errors_on_invalid() {
    let result = ZoneTagMapping::validate_zone_id("bad");
    assert!(result.is_err());
}

// ── ZoneAclGenerator ──

#[test]
fn acl_generator_single_zone_rule() {
    let acl_gen = ZoneAclGenerator::default();
    let rule = acl_gen.zone_access_rule("z:work").expect("acl rule");
    assert_eq!(rule.action, "accept");
    assert!(!rule.src.is_empty());
    assert!(!rule.dst.is_empty());
}

#[test]
fn acl_generator_all_zone_rules() {
    let acl_gen = ZoneAclGenerator::default();
    let rules = acl_gen.all_zone_rules().expect("all rules");
    assert!(rules.len() >= 5, "should have rules for all standard zones");
}

#[test]
fn acl_mapping_and_rule_snapshot() {
    let acl_gen = ZoneAclGenerator::new(4200, 4201);
    let mappings = ZoneTagMapping::standard_zones()
        .iter()
        .map(|zone| {
            let tag = ZoneTagMapping::zone_to_tag(zone).expect("zone tag");
            serde_json::json!({
                "zone": zone,
                "tag": tag.as_str(),
                "roundtrip_zone": ZoneTagMapping::tag_to_zone(&tag).expect("roundtrip"),
            })
        })
        .collect::<Vec<_>>();
    let rules = acl_gen.all_zone_rules().expect("all rules");

    insta::assert_json_snapshot!(
        "acl_mapping_and_rule_snapshot",
        serde_json::json!({
            "mappings": mappings,
            "rules": rules,
        })
    );
}

#[test]
fn acl_generator_custom_ports() {
    let acl_gen = ZoneAclGenerator::new(5000, 5001);
    let rule = acl_gen.zone_access_rule("z:work").expect("acl rule");
    let dst_str = rule.dst.join(",");
    assert!(dst_str.contains("5000") || dst_str.contains("5001"));
}

#[test]
fn acl_rule_serde_roundtrip() {
    let acl_gen = ZoneAclGenerator::default();
    let rule = acl_gen.zone_access_rule("z:work").expect("acl rule");
    let json = serde_json::to_string(&rule).expect("serialize");
    let deserialized: ZoneAclRule = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.action, rule.action);
    assert_eq!(deserialized.src, rule.src);
    assert_eq!(deserialized.dst, rule.dst);
}

#[test]
fn acl_generator_invalid_zone_errors() {
    let acl_gen = ZoneAclGenerator::default();
    let result = acl_gen.zone_access_rule("invalid-zone");
    assert!(result.is_err());
}

// ── NodeId ──

#[test]
fn node_id_creation_and_display() {
    let id = NodeId::new("nodeA123");
    assert_eq!(id.as_str(), "nodeA123");
    assert_eq!(format!("{id}"), "nodeA123");
}

#[test]
fn node_id_equality_and_hash() {
    use std::collections::HashSet;
    let a = NodeId::new("node1");
    let b = NodeId::new("node1");
    let c = NodeId::new("node2");
    assert_eq!(a, b);
    assert_ne!(a, c);

    let mut set = HashSet::new();
    set.insert(a);
    assert!(set.contains(&b));
    assert!(!set.contains(&c));
}

#[test]
fn node_id_serde_roundtrip() {
    let id = NodeId::new("test-node-42");
    let json = serde_json::to_string(&id).expect("serialize");
    let deserialized: NodeId = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(id, deserialized);
}

// ── NodeKeys ──

#[test]
fn node_keys_kid_uniqueness() {
    let keys = test_node_keys();
    let signing_kid = keys.signing_kid();
    let encryption_kid = keys.encryption_kid();
    let issuance_kid = keys.issuance_kid();
    // All three key IDs should be distinct
    assert_ne!(signing_kid, encryption_kid);
    assert_ne!(signing_kid, issuance_kid);
    assert_ne!(encryption_kid, issuance_kid);
}

#[test]
fn node_keys_serde_roundtrip() {
    let keys = test_node_keys();
    let json = serde_json::to_string(&keys).expect("serialize");
    let deserialized: NodeKeys = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(keys.signing_kid(), deserialized.signing_kid());
}

// ── NodeKeyAttestation ──

#[test]
fn attestation_sign_and_verify() {
    let owner_key = Ed25519SigningKey::generate();
    let node_keys = test_node_keys();
    let node_id = NodeId::new("test-node");
    let tags = vec![TailscaleTag::fcp_tag("work")];

    let attestation =
        NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).expect("sign");

    assert!(!attestation.is_expired());
    assert!(attestation.remaining_validity().num_hours() > 0);

    attestation
        .verify(&owner_key.verifying_key(), &node_id, &node_keys, &tags)
        .expect("verify should pass");
}

#[test]
fn attestation_wrong_owner_key_fails() {
    let owner_key = Ed25519SigningKey::generate();
    let wrong_key = Ed25519SigningKey::generate();
    let node_keys = test_node_keys();
    let node_id = NodeId::new("test-node");
    let tags = vec![TailscaleTag::fcp_tag("work")];

    let attestation =
        NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).expect("sign");

    let result = attestation.verify(&wrong_key.verifying_key(), &node_id, &node_keys, &tags);
    assert!(result.is_err(), "wrong owner key should fail verification");
}

#[test]
fn attestation_wrong_node_id_fails() {
    let owner_key = Ed25519SigningKey::generate();
    let node_keys = test_node_keys();
    let node_id = NodeId::new("correct-node");
    let wrong_id = NodeId::new("wrong-node");
    let tags = vec![TailscaleTag::fcp_tag("work")];

    let attestation =
        NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).expect("sign");

    let result = attestation.verify(&owner_key.verifying_key(), &wrong_id, &node_keys, &tags);
    assert!(result.is_err(), "wrong node ID should fail verification");
}

#[test]
fn attestation_wrong_tags_fails() {
    let owner_key = Ed25519SigningKey::generate();
    let node_keys = test_node_keys();
    let node_id = NodeId::new("test-node");
    let tags = vec![TailscaleTag::fcp_tag("work")];
    let wrong_tags = vec![TailscaleTag::fcp_tag("private")];

    let attestation =
        NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).expect("sign");

    let result = attestation.verify(
        &owner_key.verifying_key(),
        &node_id,
        &node_keys,
        &wrong_tags,
    );
    assert!(result.is_err(), "wrong tags should fail verification");
}

#[test]
fn attestation_zero_validity_expired() {
    let owner_key = Ed25519SigningKey::generate();
    let node_keys = test_node_keys();
    let node_id = NodeId::new("test-node");
    let tags = vec![TailscaleTag::fcp_tag("work")];

    let attestation =
        NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 0).expect("sign");

    assert!(attestation.is_expired(), "zero hours should be expired");
}

// ── MeshIdentity ──

#[test]
fn mesh_identity_creation_and_fcp_tags() {
    let owner_key = Ed25519SigningKey::generate();
    let node_keys = test_node_keys();
    let tags = vec![
        TailscaleTag::fcp_tag("work"),
        TailscaleTag::new("tag:server").unwrap(),
        TailscaleTag::fcp_tag("community"),
    ];

    let identity = MeshIdentity::new(
        NodeId::new("node1"),
        "host1".to_string(),
        vec![test_ip()],
        tags,
        owner_key.verifying_key(),
        node_keys,
    );

    let fcp_tags = identity.fcp_tags();
    assert_eq!(fcp_tags.len(), 2, "should only include FCP tags");
    assert!(fcp_tags.iter().any(|t| t.as_str() == "tag:fcp-work"));
    assert!(fcp_tags.iter().any(|t| t.as_str() == "tag:fcp-community"));
}

#[test]
fn mesh_identity_with_attestation() {
    let owner_key = Ed25519SigningKey::generate();
    let node_keys = test_node_keys();
    let node_id = NodeId::new("node1");
    let tags = vec![TailscaleTag::fcp_tag("work")];

    let attestation =
        NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).expect("sign");

    let identity = MeshIdentity::new(
        node_id,
        "host1".to_string(),
        vec![test_ip()],
        tags,
        owner_key.verifying_key(),
        node_keys,
    )
    .with_attestation(attestation);

    identity
        .verify_attestation()
        .expect("attestation should verify");
    assert!(identity.is_attestation_valid());
}

#[test]
fn mesh_identity_without_attestation_verify_fails() {
    let owner_key = Ed25519SigningKey::generate();
    let node_keys = test_node_keys();

    let identity = MeshIdentity::new(
        NodeId::new("node1"),
        "host1".to_string(),
        vec![test_ip()],
        vec![TailscaleTag::fcp_tag("work")],
        owner_key.verifying_key(),
        node_keys,
    );

    let result = identity.verify_attestation();
    assert!(result.is_err(), "no attestation should fail verify");
}

#[test]
fn mesh_identity_serde_roundtrip() {
    let owner_key = Ed25519SigningKey::generate();
    let node_keys = test_node_keys();
    let identity = MeshIdentity::new(
        NodeId::new("node-serde"),
        "serde-host".to_string(),
        vec![test_ip()],
        vec![TailscaleTag::fcp_tag("work")],
        owner_key.verifying_key(),
        node_keys,
    );

    let json = serde_json::to_string(&identity).expect("serialize");
    let deserialized: MeshIdentity = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(identity.node_id, deserialized.node_id);
    assert_eq!(identity.hostname, deserialized.hostname);
}

// ── MockTailscaleClient ──

#[fcp_async_core::runtime::test]
async fn mock_client_status_returns_connected() {
    let client = MockTailscaleClient::new();
    let status = client.status().await.expect("status");
    assert_eq!(status.backend_state, "Running");
}

#[fcp_async_core::runtime::test]
async fn mock_client_disconnected_status() {
    let client = MockTailscaleClient::disconnected();
    let result = client.status().await;
    assert!(result.is_err(), "disconnected client should return error");
    assert!(matches!(result.unwrap_err(), TailscaleError::NotConnected));
}

#[fcp_async_core::runtime::test]
async fn mock_client_is_connected() {
    let client = MockTailscaleClient::new();
    assert!(client.is_connected().await.expect("connected"));

    let disconnected = MockTailscaleClient::disconnected();
    // Disconnected client returns NotConnected error from status()
    let result = disconnected.status().await;
    assert!(matches!(result, Err(TailscaleError::NotConnected)));
}

#[fcp_async_core::runtime::test]
async fn mock_client_add_and_query_peer() {
    let client = MockTailscaleClient::new();
    let peer = MockTailscaleClient::mock_peer("peer1", "peer-host", test_ip2(), &["tag:fcp-work"]);
    client.add_peer(peer).await;

    let status = client.status().await.expect("status");
    assert_eq!(status.peer.len(), 1);
    let peer_info = status.peer.values().next().expect("peer");
    assert_eq!(peer_info.host_name, "peer-host");
}

#[fcp_async_core::runtime::test]
async fn mock_client_whois_lookup() {
    let client = MockTailscaleClient::new();
    let peer_ip = test_ip2();
    let peer = MockTailscaleClient::mock_peer("peer1", "peer-host", peer_ip, &["tag:fcp-work"]);
    client.add_peer(peer).await;

    let info = client.whois(peer_ip).await.expect("whois");
    assert_eq!(info.host_name, "peer-host");
    assert!(info.online);
}

#[fcp_async_core::runtime::test]
async fn mock_client_whois_unknown_ip() {
    let client = MockTailscaleClient::new();
    let result = client.whois(test_ip2()).await;
    assert!(result.is_err(), "unknown IP should fail whois");
}

#[fcp_async_core::runtime::test]
async fn mock_client_online_peers() {
    let client = MockTailscaleClient::new();
    client
        .add_peer(MockTailscaleClient::mock_peer(
            "p1",
            "host1",
            test_ip(),
            &["tag:fcp-work"],
        ))
        .await;
    client
        .add_peer(MockTailscaleClient::mock_peer(
            "p2",
            "host2",
            test_ip2(),
            &["tag:fcp-community"],
        ))
        .await;

    let peers = client.online_peers().await.expect("online peers");
    assert_eq!(peers.len(), 2);
}

#[fcp_async_core::runtime::test]
async fn mock_client_remove_peer() {
    let client = MockTailscaleClient::new();
    client
        .add_peer(MockTailscaleClient::mock_peer(
            "p1",
            "host1",
            test_ip(),
            &[],
        ))
        .await;
    assert_eq!(client.online_peers().await.expect("peers").len(), 1);

    client.remove_peer("p1").await;
    assert_eq!(client.online_peers().await.expect("peers").len(), 0);
}

#[fcp_async_core::runtime::test]
async fn mock_client_set_peer_offline() {
    let client = MockTailscaleClient::new();
    client
        .add_peer(MockTailscaleClient::mock_peer(
            "p1",
            "host1",
            test_ip(),
            &[],
        ))
        .await;

    client.set_peer_online("p1", false).await;
    let peers = client.online_peers().await.expect("peers");
    assert!(peers.is_empty(), "offline peer should not appear");
}

#[fcp_async_core::runtime::test]
async fn mock_client_set_backend_state() {
    let client = MockTailscaleClient::new();
    // Verify starts as connected
    assert!(client.status().await.is_ok());

    // Set to non-Running state → disconnected
    client.set_backend_state("NeedsLogin").await;
    let result = client.status().await;
    assert!(
        matches!(result, Err(TailscaleError::NotConnected)),
        "NeedsLogin should make client disconnected"
    );

    // Set back to Running → connected again
    client.set_backend_state("Running").await;
    let status = client.status().await.expect("reconnected");
    assert_eq!(status.backend_state, "Running");
}

// ── PeerInfo methods ──

#[test]
fn peer_info_tailscale_tags() {
    let peer = MockTailscaleClient::mock_peer(
        "p1",
        "host",
        test_ip(),
        &["tag:fcp-work", "tag:server", "tag:fcp-community"],
    );
    let ts_tags = peer.tailscale_tags();
    assert_eq!(ts_tags.len(), 3, "all valid tags");

    let fcp_tags = peer.fcp_tags();
    assert_eq!(fcp_tags.len(), 2, "only fcp tags");
}

#[test]
fn peer_info_node_id_conversion() {
    let peer = MockTailscaleClient::mock_peer("nodeXYZ", "host", test_ip(), &[]);
    let node_id = peer.node_id();
    assert_eq!(node_id.as_str(), "nodeXYZ");
}

// ── TailscaleStatus::peers() ──

#[fcp_async_core::runtime::test]
async fn status_peers_keyed_by_node_id() {
    let client = MockTailscaleClient::new();
    client
        .add_peer(MockTailscaleClient::mock_peer(
            "node-abc",
            "host1",
            test_ip(),
            &[],
        ))
        .await;

    let status = client.status().await.expect("status");
    let peers = status.peers();
    assert!(peers.contains_key(&NodeId::new("node-abc")));
}

// ── TailscaleError display ──

#[test]
fn error_display_invalid_tag() {
    let err = TailscaleError::InvalidTag("bad".to_string());
    assert!(err.to_string().contains("bad"));
}

#[test]
fn error_display_not_connected() {
    let err = TailscaleError::NotConnected;
    let msg = err.to_string();
    assert!(!msg.is_empty());
}

#[test]
fn error_display_peer_not_found() {
    let err = TailscaleError::PeerNotFound("10.0.0.1".to_string());
    assert!(err.to_string().contains("10.0.0.1"));
}

#[test]
fn error_display_invalid_attestation() {
    let err = TailscaleError::InvalidAttestation;
    assert!(!err.to_string().is_empty());
}

#[test]
fn error_display_attestation_expired() {
    let err = TailscaleError::AttestationExpired;
    assert!(!err.to_string().is_empty());
}

// ── FCP_TAG_PREFIX constant ──

#[test]
fn fcp_tag_prefix_value() {
    assert_eq!(FCP_TAG_PREFIX, "tag:fcp-");
}

// ── full pipeline: mock client → identity → attestation ──

#[fcp_async_core::runtime::test]
async fn full_pipeline_client_to_identity_to_attestation() {
    let owner_key = Ed25519SigningKey::generate();
    let node_keys = test_node_keys();

    // Set up mock client with self node
    let client = MockTailscaleClient::new();
    let self_node = MockTailscaleClient::mock_self_node(
        "my-node",
        "my-host",
        test_ip(),
        &["tag:fcp-work", "tag:fcp-community"],
    );
    client.set_self_node(self_node).await;

    // Add a peer
    client
        .add_peer(MockTailscaleClient::mock_peer(
            "peer-node",
            "peer-host",
            test_ip2(),
            &["tag:fcp-work"],
        ))
        .await;

    // Get status
    let status = client.status().await.expect("status");
    assert!(client.is_connected().await.expect("connected"));
    assert_eq!(status.peer.len(), 1);

    // Build identity from self node
    let self_info = &status.self_node;
    let tags: Vec<TailscaleTag> = self_info
        .tags
        .iter()
        .filter_map(|t| TailscaleTag::new(t).ok())
        .collect();

    let node_id = NodeId::new(&self_info.id);
    let identity = MeshIdentity::new(
        node_id.clone(),
        self_info.host_name.clone(),
        self_info.tailscale_ips.clone(),
        tags.clone(),
        owner_key.verifying_key(),
        node_keys.clone(),
    );

    // FCP tags should be filtered
    assert_eq!(identity.fcp_tags().len(), 2);

    // Sign attestation
    let attestation =
        NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).expect("sign");

    let identity = identity.with_attestation(attestation);
    identity.verify_attestation().expect("attestation valid");
    assert!(identity.is_attestation_valid());

    // Peer lookup
    let peer = client.whois(test_ip2()).await.expect("whois");
    let peer_fcp_tags = peer.fcp_tags();
    assert_eq!(peer_fcp_tags.len(), 1);
    assert_eq!(peer_fcp_tags[0].as_str(), "tag:fcp-work");

    // Zone mapping from peer tags
    let zone = ZoneTagMapping::tag_to_zone(&peer_fcp_tags[0]).expect("zone from tag");
    assert_eq!(zone, "z:work");
}
