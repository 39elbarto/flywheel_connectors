use std::time::Duration;

use fcp_core::{
    DEFAULT_MESH_NODE_HEARTBEAT_INTERVAL, DEFAULT_MESH_NODE_LEASE_TTL, DEFAULT_MESH_NODE_MAX_PEERS,
    MeshNodeConfig,
};

#[test]
fn mesh_node_config_defaults_pin_documented_values() {
    let config = MeshNodeConfig::default();

    assert_eq!(config.heartbeat_interval, Duration::from_secs(30));
    assert_eq!(config.max_peers, 32);
    assert_eq!(config.lease_ttl, Duration::from_secs(300));
}

#[test]
fn mesh_node_config_new_matches_default_and_exported_constants() {
    let config = MeshNodeConfig::new();

    assert_eq!(config, MeshNodeConfig::default());
    assert_eq!(
        config.heartbeat_interval,
        DEFAULT_MESH_NODE_HEARTBEAT_INTERVAL
    );
    assert_eq!(config.max_peers, DEFAULT_MESH_NODE_MAX_PEERS);
    assert_eq!(config.lease_ttl, DEFAULT_MESH_NODE_LEASE_TTL);
}
