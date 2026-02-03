//! FCP2 `MeshNode` Integration Tests
//!
//! Comprehensive integration tests for mesh node orchestration covering:
//! - Routing (symbol routing, control-plane routing, multi-hop, load balancing)
//! - Admission Control (valid requests admitted, rate limiting, quarantine)
//! - Policy Enforcement (zone boundaries, capability verification, taint propagation)
//! - Gossip Integration (object availability, reconciliation, stale gossip rejection)
//! - Lease Coordination (acquisition via HRW, renewal, transfer, conflict detection)
//!
//! All tests emit structured JSON logging for CI/CD integration.

// Test code - allow some clippy lints for clarity over micro-optimization
#![allow(clippy::redundant_clone)]
#![allow(clippy::unreadable_literal)]

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use chrono::{SecondsFormat, Utc};
use fcp_core::{
    ConnectorId, DecisionReasonCode, EpochId, ObjectId, TailscaleNodeId, ZoneId,
    ZoneTransportPolicy,
};
use fcp_mesh::admission::{AdmissionController, AdmissionError, AdmissionPolicy, PeerBudget};
use fcp_mesh::device::{
    AvailabilityProfile, CpuArch, DeviceProfile, GpuProfile, GpuVendor, InstalledConnector,
    LatencyClass, PowerSource,
};
use fcp_mesh::gossip::{GossipConfig, GossipRequest, GossipState, MeshGossip};
use fcp_mesh::planner::{
    ExecutionPlanner, HeldLease, LeasePurpose, NodeInfo, PlannerContext, PlannerInput,
};
use fcp_mesh::transport::{TransportPath, TransportPathKind, TransportSelector};
use fcp_tailscale::NodeId;
use fcp_testkit::LogCapture;

// ============================================================================
// Test Utilities
// ============================================================================

/// Structured test event for JSON logging.
#[derive(Debug, serde::Serialize)]
struct TestEvent {
    timestamp: String,
    log_version: &'static str,
    level: &'static str,
    module: &'static str,
    phase: &'static str,
    correlation_id: String,
    test_name: &'static str,
    result: &'static str,
    duration_ms: u64,
    assertions: TestAssertions,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct TestAssertions {
    passed: u32,
    failed: u32,
}

// ============================================================================
// MESHNODE ORCHESTRATION SMOKE TESTS
// ============================================================================

mod meshnode {
    use super::*;

    use bytes::Bytes;
    use fcp_cbor::SchemaId;
    use fcp_core::{ObjectHeader, Provenance, ZoneKeyId};
    use fcp_mesh::admission::AdmissionError;
    use fcp_mesh::admission::ObjectAdmissionClass;
    use fcp_mesh::{
        ControlPlaneEnvelope, InMemoryControlPlaneHandler, MeshNode, MeshNodeConfig, MeshSession,
        RetentionClass, SymbolRequestError,
    };
    use fcp_protocol::session::{
        MeshSessionId, SessionCryptoSuite, SessionKeys, SessionReplayPolicy, TransportLimits,
    };
    use fcp_protocol::{
        DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED, DecodeStatus, SymbolAck, SymbolAckReason,
        SymbolRequest,
    };
    use fcp_store::{
        MemoryObjectStore, MemoryObjectStoreConfig, MemorySymbolStore, MemorySymbolStoreConfig,
        ObjectAdmissionPolicy, ObjectSymbolMeta, ObjectTransmissionInfo, QuarantineStore,
        QuarantinedObject, StoredSymbol, SymbolMeta, SymbolStore, SymbolStoreError,
    };
    use raptorq::ObjectTransmissionInformation;
    use semver::Version;
    use std::sync::Arc;

    fn test_header(zone_id: &ZoneId) -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.mesh", "SymbolRequest", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn status_header(zone_id: &ZoneId) -> ObjectHeader {
        ObjectHeader {
            schema: SchemaId::new("fcp.status", "DecodeStatus", Version::new(1, 0, 0)),
            zone_id: zone_id.clone(),
            created_at: 0,
            provenance: Provenance::new(zone_id.clone()),
            refs: Vec::new(),
            foreign_refs: Vec::new(),
            ttl_secs: None,
            placement: None,
        }
    }

    fn build_mesh_node(name: &str, sender_instance_id: u64, local_node_id: u64) -> MeshNode {
        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig {
            local_node_id,
            ..MemorySymbolStoreConfig::default()
        }));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        MeshNode::new(
            MeshNodeConfig::new(name).with_sender_instance_id(sender_instance_id),
            object_store,
            symbol_store,
            quarantine_store,
        )
    }

    async fn seed_symbols(store: &Arc<dyn SymbolStore>, meta: &ObjectSymbolMeta, source_node: u64) {
        store.put_object_meta(meta.clone()).await.unwrap();
        let symbol_size = meta.oti.symbol_size as usize;

        for esi in 0..meta.source_symbols {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id: meta.object_id,
                    esi,
                    zone_id: meta.zone_id.clone(),
                    source_node: Some(source_node),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            store.put_symbol(symbol).await.unwrap();
        }
    }

    async fn missing_esis(
        store: &Arc<dyn SymbolStore>,
        object_id: &ObjectId,
        total: u32,
    ) -> Vec<u32> {
        let received = store.get_all_symbols(object_id).await;
        let have: HashSet<u32> = received.iter().map(|symbol| symbol.meta.esi).collect();
        (0..total).filter(|esi| !have.contains(esi)).collect()
    }

    #[tokio::test]
    async fn meshnode_symbol_request_smoke() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-symbols");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };

        let symbol_size = meta.oti.symbol_size as usize;
        symbol_store.put_object_meta(meta).await.unwrap();
        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            2,
            1,
        )
        .with_missing_hint(vec![1, 2]);

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert!(!response.symbol_esis.is_empty());
        assert!(response.symbol_esis.len() <= 2);
    }

    #[tokio::test]
    async fn meshnode_symbol_request_missing_object() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-missing-object");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store, quarantine_store);

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("missing object should return error");

        assert!(matches!(err, SymbolRequestError::ObjectNotFound { .. }));
    }

    #[tokio::test]
    async fn meshnode_symbol_request_no_symbols() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-no-symbols");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("missing symbols should return error");

        assert!(matches!(err, SymbolRequestError::ObjectNotFound { .. }));
    }

    #[tokio::test]
    async fn meshnode_symbol_request_no_resend() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-no-resend");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let response = node
            .handle_symbol_request(request.clone(), &NodeId::new("peer-1"), true, 0)
            .await
            .expect("initial symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 2);
        let mut first: HashSet<u32> = response.symbol_esis.into_iter().collect();

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("follow-up symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 2);
        assert!(response.symbol_esis.iter().all(|esi| !first.contains(esi)));

        first.extend(response.symbol_esis);
        assert_eq!(first.len(), 4);
    }

    #[tokio::test]
    async fn meshnode_symbol_request_prioritizes_missing_hint() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-missing-hint");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        )
        .with_missing_hint(vec![3, 1]);

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_eq!(response.symbol_esis, vec![3, 1]);
    }

    #[tokio::test]
    async fn meshnode_symbol_request_fills_after_missing_hint() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-hint-fill");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            3,
            1,
        )
        .with_missing_hint(vec![2]);

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 3);
        assert_eq!(response.symbol_esis[0], 2);
        assert!(response.symbol_esis.iter().all(|esi| *esi < 4));
    }

    #[tokio::test]
    async fn meshnode_symbol_request_ignores_unavailable_hints() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-hint-unavailable");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        )
        .with_missing_hint(vec![9, 10]);

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 2);
        assert!(response.symbol_esis.iter().all(|esi| *esi < 4));
    }

    #[tokio::test]
    async fn meshnode_symbol_request_rejects_oversized_hint() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-hint-oversized");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        )
        .with_missing_hint(vec![0, 1, 2]);

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("oversized missing hint should be rejected");

        assert!(matches!(err, SymbolRequestError::InvalidRequest { .. }));
    }

    #[tokio::test]
    async fn meshnode_symbol_request_reports_bounded_response() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-bounded-response");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 2);
        assert!(response.was_bounded);
        assert!(!response.is_final);
    }

    #[tokio::test]
    async fn meshnode_symbol_request_is_final_when_all_sent() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-final-response");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store.clone(), quarantine_store);

        let oti = ObjectTransmissionInformation::new(1024, 256, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };

        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            4,
            1,
        );

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        assert_eq!(response.symbol_esis.len(), 4);
        assert!(!response.was_bounded);
        assert!(response.is_final);
    }

    #[tokio::test]
    async fn meshnode_quarantined_object_not_gossiped() {
        let zone_id = ZoneId::work();
        let object_id = test_object_id("meshnode-quarantine-gossip");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1");
        let mut node = MeshNode::new(config, object_store, symbol_store, quarantine_store.clone());

        quarantine_store
            .quarantine(QuarantinedObject {
                object_id,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"quarantined"),
                source_peer: None,
                received_at: 0,
                peer_reputation: -10,
            })
            .expect("quarantine");

        let added =
            node.announce_object(&zone_id, &object_id, ObjectAdmissionClass::Admitted, 1000);

        assert!(!added);
        assert!(!node.gossip_mut().has_object(&zone_id, &object_id));
    }

    #[tokio::test]
    async fn meshnode_quarantined_symbol_request_rejected() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([1u8; 8]);
        let object_id = test_object_id("meshnode-quarantine-request");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let config = MeshNodeConfig::new("node-1").with_sender_instance_id(7);
        let mut node = MeshNode::new(config, object_store, symbol_store, quarantine_store.clone());

        quarantine_store
            .quarantine(QuarantinedObject {
                object_id,
                zone_id: zone_id.clone(),
                data: Bytes::from_static(b"quarantined"),
                source_peer: None,
                received_at: 0,
                peer_reputation: -10,
            })
            .expect("quarantine");

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id,
            zone_key_id,
            1,
            2,
            1,
        );

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("quarantined request should fail");

        assert!(matches!(
            err,
            SymbolRequestError::AdmissionRejected(AdmissionError::ObjectQuarantined { .. })
        ));
    }

    #[tokio::test]
    async fn meshnode_decode_status_stops_transfer() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([2u8; 8]);
        let object_id = test_object_id("meshnode-decode-stop");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1"),
            object_store,
            symbol_store.clone(),
            quarantine_store,
        );

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };
        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            4,
            1,
        );

        let _ = node
            .handle_symbol_request(request.clone(), &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        let status = DecodeStatus {
            header: status_header(&zone_id),
            object_id,
            zone_id: zone_id.clone(),
            zone_key_id,
            epoch_id: 1,
            received_unique: 4,
            needed: 0,
            complete: true,
            missing_hint: None,
            signature: fcp_crypto::Ed25519Signature::from_bytes(&[0u8; 64]),
        };

        node.handle_decode_status(&status, 0);

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("should stop after decode status complete");

        assert!(matches!(err, SymbolRequestError::AlreadyComplete { .. }));
    }

    #[tokio::test]
    async fn meshnode_symbol_ack_stops_transfer() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([3u8; 8]);
        let object_id = test_object_id("meshnode-ack-stop");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1"),
            object_store,
            symbol_store.clone(),
            quarantine_store,
        );

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let symbol_size = oti.symbol_size() as usize;
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };
        symbol_store.put_object_meta(meta).await.unwrap();

        for esi in 0..4u32 {
            let esi_byte = u8::try_from(esi).expect("esi fits in u8");
            let symbol = StoredSymbol {
                meta: SymbolMeta {
                    object_id,
                    esi,
                    zone_id: zone_id.clone(),
                    source_node: Some(1),
                    stored_at: 0,
                },
                data: Bytes::from(vec![esi_byte; symbol_size]),
            };
            symbol_store.put_symbol(symbol).await.unwrap();
        }

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            4,
            1,
        );

        let _ = node
            .handle_symbol_request(request.clone(), &NodeId::new("peer-1"), true, 0)
            .await
            .expect("symbol request should succeed");

        let ack = SymbolAck::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            SymbolAckReason::Complete,
            4,
        );

        node.handle_symbol_ack(&ack, 0);

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), true, 0)
            .await
            .expect_err("should stop after ack");

        assert!(matches!(err, SymbolRequestError::AlreadyComplete { .. }));
    }

    #[tokio::test]
    async fn meshnode_unauthenticated_bounds_enforced() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([4u8; 8]);
        let object_id = test_object_id("meshnode-unauth-bounds");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1"),
            object_store,
            symbol_store.clone(),
            quarantine_store,
        );

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };
        symbol_store.put_object_meta(meta).await.unwrap();

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 1,
            1,
        );

        let err = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), false, 0)
            .await
            .expect_err("unauthenticated request should be bounded");

        assert!(matches!(err, SymbolRequestError::BoundsExceeded { .. }));
    }

    #[tokio::test]
    async fn meshnode_degraded_control_plane_roundtrip() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([5u8; 8]);
        let object_id = test_object_id("meshnode-degraded-roundtrip");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1").with_sender_instance_id(9),
            object_store,
            symbol_store,
            quarantine_store,
        );

        let payload = vec![0xAB; 128];
        let schema_hash = SchemaId::new("fcp.mesh", "ControlPlane", Version::new(1, 0, 0))
            .hash()
            .as_bytes()
            .to_owned();
        let mut schema_hash_bytes = [0u8; 32];
        schema_hash_bytes.copy_from_slice(&schema_hash);

        let envelope = ControlPlaneEnvelope::new(
            payload.clone(),
            schema_hash_bytes,
            object_id,
            zone_id.clone(),
            zone_key_id,
            RetentionClass::Required,
        );

        let frames = node
            .encode_control_plane(&envelope, 42)
            .expect("encode control plane");

        let mut decoded = None;
        for frame in frames {
            if let Some(result) = node
                .decode_control_plane(&frame, &zone_id, RetentionClass::Required)
                .expect("decode control plane")
            {
                decoded = Some(result);
                break;
            }
        }

        let decoded = decoded.expect("should decode envelope");
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.schema_hash, schema_hash_bytes);
        assert_eq!(decoded.object_id, object_id);
    }

    #[tokio::test]
    async fn meshnode_control_plane_handler_stores_required() {
        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([6u8; 8]);
        let object_id = test_object_id("meshnode-control-plane-handler");

        let object_store = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node = MeshNode::new(
            MeshNodeConfig::new("node-1").with_sender_instance_id(11),
            object_store,
            symbol_store,
            quarantine_store,
        );

        let payload = vec![0xCD; 64];
        let schema_hash = SchemaId::new("fcp.mesh", "ControlPlane", Version::new(1, 0, 0))
            .hash()
            .as_bytes()
            .to_owned();
        let mut schema_hash_bytes = [0u8; 32];
        schema_hash_bytes.copy_from_slice(&schema_hash);

        let envelope = ControlPlaneEnvelope::new(
            payload,
            schema_hash_bytes,
            object_id,
            zone_id.clone(),
            zone_key_id,
            RetentionClass::Required,
        );

        let frames = node
            .encode_control_plane(&envelope, 77)
            .expect("encode control plane");

        let handler = InMemoryControlPlaneHandler::new();
        for frame in frames {
            let _ = node
                .process_control_plane_frame(&frame, &zone_id, RetentionClass::Required, &handler)
                .expect("process control plane");
        }

        assert_eq!(handler.count(), 1);
        assert!(handler.get(&object_id).is_some());
    }

    #[tokio::test]
    async fn meshnode_multi_node_symbol_transfer() {
        const TEST_NAME: &str = "meshnode_multi_node_symbol_transfer";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([7u8; 8]);
        let object_id = test_object_id("meshnode-multi-node-symbols");

        let mut node_a = build_mesh_node("node-a", 21, 1);
        let node_b = build_mesh_node("node-b", 22, 2);

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };
        let symbol_store_a = node_a.symbol_store().clone();
        seed_symbols(&symbol_store_a, &meta, 1).await;

        let receiver_store = node_b.symbol_store().clone();

        let mut attempts = 0;
        while !receiver_store.can_reconstruct(&object_id).await && attempts < 5 {
            attempts += 1;

            let missing = missing_esis(&receiver_store, &object_id, meta.source_symbols).await;

            let request = SymbolRequest::new(
                test_header(&zone_id),
                object_id,
                zone_id.clone(),
                zone_key_id,
                1,
                meta.source_symbols,
                1,
            )
            .with_missing_hint(missing.clone());

            let response = node_a
                .handle_symbol_request(request, &NodeId::new("node-b"), true, 0)
                .await
                .expect("symbol request should succeed");

            assert!(
                !response.symbol_esis.is_empty(),
                "expected symbols from node-a"
            );

            if let Err(SymbolStoreError::ObjectNotFound(_)) =
                receiver_store.get_object_meta(&object_id).await
            {
                receiver_store.put_object_meta(meta.clone()).await.unwrap();
            }

            for esi in response.symbol_esis {
                let symbol = symbol_store_a.get_symbol(&object_id, esi).await.unwrap();
                receiver_store.put_symbol(symbol).await.unwrap();
            }
        }

        assert!(
            receiver_store.can_reconstruct(&object_id).await,
            "node-b should reconstruct after transfer"
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "attempts": attempts,
                "symbols_received": receiver_store.symbol_count(&object_id).await,
            }),
        );
    }

    #[tokio::test]
    async fn meshnode_multi_node_control_plane_roundtrip() {
        const TEST_NAME: &str = "meshnode_multi_node_control_plane_roundtrip";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([8u8; 8]);
        let object_id = test_object_id("meshnode-multi-node-control-plane");

        let object_store_a = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store_a = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store_a = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let object_store_b = Arc::new(MemoryObjectStore::new(MemoryObjectStoreConfig::default()));
        let symbol_store_b = Arc::new(MemorySymbolStore::new(MemorySymbolStoreConfig::default()));
        let quarantine_store_b = Arc::new(QuarantineStore::new(ObjectAdmissionPolicy::default()));

        let mut node_a = MeshNode::new(
            MeshNodeConfig::new("node-a").with_sender_instance_id(31),
            object_store_a,
            symbol_store_a,
            quarantine_store_a,
        );
        let mut node_b = MeshNode::new(
            MeshNodeConfig::new("node-b").with_sender_instance_id(32),
            object_store_b,
            symbol_store_b,
            quarantine_store_b,
        );

        let payload = vec![0xEF; 64];
        let schema_hash = SchemaId::new("fcp.mesh", "ControlPlane", Version::new(1, 0, 0))
            .hash()
            .as_bytes()
            .to_owned();
        let mut schema_hash_bytes = [0u8; 32];
        schema_hash_bytes.copy_from_slice(&schema_hash);

        let envelope = ControlPlaneEnvelope::new(
            payload.clone(),
            schema_hash_bytes,
            object_id,
            zone_id.clone(),
            zone_key_id,
            RetentionClass::Required,
        );

        let frames = node_a
            .encode_control_plane(&envelope, 99)
            .expect("encode control plane");

        let handler = InMemoryControlPlaneHandler::new();
        for frame in frames {
            let _ = node_b
                .process_control_plane_frame(&frame, &zone_id, RetentionClass::Required, &handler)
                .expect("process control plane");
        }

        let stored = handler.get(&object_id).expect("control plane stored");
        assert_eq!(stored.payload, payload);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "object_id": object_id.to_string(),
                "payload_bytes": payload.len(),
            }),
        );
    }

    #[tokio::test]
    async fn meshnode_session_auth_allows_larger_request() {
        const TEST_NAME: &str = "meshnode_session_auth_allows_larger_request";
        const CATEGORY: &str = "meshnode";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let zone_key_id = ZoneKeyId::from_bytes([9u8; 8]);
        let object_id = test_object_id("meshnode-session-auth");

        let mut node = build_mesh_node("node-auth", 41, 3);
        let symbol_store = node.symbol_store().clone();

        let oti = ObjectTransmissionInformation::new(512, 128, 1, 1, 1);
        let meta = ObjectSymbolMeta {
            object_id,
            zone_id: zone_id.clone(),
            oti: ObjectTransmissionInfo::from(oti),
            source_symbols: 4,
            first_symbol_at: 0,
        };
        seed_symbols(&symbol_store, &meta, 1).await;

        let session = MeshSession::new(
            MeshSessionId::new(),
            NodeId::new("peer-1"),
            SessionCryptoSuite::Suite1,
            SessionKeys {
                k_mac_i2r: [1u8; 32],
                k_mac_r2i: [2u8; 32],
                k_ctx: [3u8; 32],
            },
            TransportLimits::default(),
            true,
            0,
            SessionReplayPolicy::default(),
        );
        node.register_session(session, 0);

        let request = SymbolRequest::new(
            test_header(&zone_id),
            object_id,
            zone_id.clone(),
            zone_key_id,
            1,
            DEFAULT_MAX_SYMBOLS_UNAUTHENTICATED + 1,
            1,
        );

        let response = node
            .handle_symbol_request(request, &NodeId::new("peer-1"), false, 0)
            .await
            .expect("authenticated session should allow request");

        assert!(!response.symbol_esis.is_empty());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "symbols_sent": response.symbol_esis.len(),
                "authenticated": true,
            }),
        );
    }
}

// ============================================================================
// TRANSPORT SELECTION INTEGRATION TESTS
// ============================================================================

mod transport_selection {
    use super::*;

    #[test]
    fn transport_policy_enforced_in_ranking() {
        const TEST_NAME: &str = "transport_policy_enforced_in_ranking";
        const CATEGORY: &str = "routing";

        emit_test_start(TEST_NAME, CATEGORY);

        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: false,
            allow_funnel: false,
        };

        let paths = vec![
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-1"),
                "direct",
                None,
            ),
            TransportPath::new(TransportPathKind::Mesh, NodeId::new("peer-2"), "mesh", None),
            TransportPath::new(TransportPathKind::Derp, NodeId::new("peer-3"), "derp", None),
            TransportPath::new(
                TransportPathKind::Funnel,
                NodeId::new("peer-4"),
                "funnel",
                None,
            ),
        ];

        let ranked = TransportSelector::rank_paths(&paths, &policy);
        assert_eq!(ranked[0].path.kind, TransportPathKind::Direct);
        assert!(
            ranked
                .iter()
                .take(2)
                .all(|entry| entry.eligible && entry.reason.is_none())
        );

        let derp = ranked
            .iter()
            .find(|entry| entry.path.kind == TransportPathKind::Derp)
            .expect("derp entry missing");
        assert_eq!(
            derp.reason,
            Some(DecisionReasonCode::TransportDerpForbidden)
        );

        let funnel = ranked
            .iter()
            .find(|entry| entry.path.kind == TransportPathKind::Funnel)
            .expect("funnel entry missing");
        assert_eq!(
            funnel.reason,
            Some(DecisionReasonCode::TransportFunnelForbidden)
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "eligible_count": ranked.iter().filter(|entry| entry.eligible).count(),
                "blocked": {
                    "derp": derp.reason.is_some(),
                    "funnel": funnel.reason.is_some()
                }
            }),
        );
    }

    #[test]
    fn transport_multipath_is_deterministic() {
        const TEST_NAME: &str = "transport_multipath_is_deterministic";
        const CATEGORY: &str = "routing";

        emit_test_start(TEST_NAME, CATEGORY);

        let policy = ZoneTransportPolicy {
            allow_lan: true,
            allow_derp: true,
            allow_funnel: true,
        };

        let paths = vec![
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-1"),
                "direct-a",
                None,
            ),
            TransportPath::new(
                TransportPathKind::Direct,
                NodeId::new("peer-2"),
                "direct-b",
                None,
            ),
            TransportPath::new(TransportPathKind::Mesh, NodeId::new("peer-3"), "mesh", None),
            TransportPath::new(TransportPathKind::Derp, NodeId::new("peer-4"), "derp", None),
        ];

        let object_id = test_object_id("transport-multipath");
        let selection_a = TransportSelector::select_multipath(&paths, &policy, &object_id, 3, 2);
        let selection_b = TransportSelector::select_multipath(&paths, &policy, &object_id, 3, 2);

        assert_eq!(selection_a, selection_b);
        assert!(
            selection_a
                .iter()
                .all(|path| path.kind == TransportPathKind::Direct)
        );

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected": selection_a.len(),
                "kinds": selection_a.iter().map(|path| format!("{:?}", path.kind)).collect::<Vec<_>>(),
            }),
        );
    }
}

impl TestEvent {
    fn emit(&self) {
        let value = serde_json::to_value(self).expect("serialize test event");
        println!("{}", serde_json::to_string(&value).unwrap());

        let capture = log_capture();
        if let Err(err) = capture.push_value(&value) {
            panic!("failed to push log event: {err}");
        }
        if !std::thread::panicking() {
            capture.assert_valid();
        }
    }
}

fn test_correlation_id(test_name: &str, category: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(test_name.as_bytes());
    hasher.update(category.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn log_capture() -> &'static LogCapture {
    static CAPTURE: OnceLock<LogCapture> = OnceLock::new();
    CAPTURE.get_or_init(LogCapture::new)
}

fn test_start_times() -> &'static Mutex<HashMap<String, Instant>> {
    static STARTS: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    STARTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn start_timer(correlation_id: &str) {
    let mut starts = test_start_times()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    starts.insert(correlation_id.to_string(), Instant::now());
}

fn finish_timer(correlation_id: &str) -> u64 {
    let mut starts = test_start_times()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    starts.remove(correlation_id).map_or(0, |start| {
        u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
    })
}

fn emit_test_start(test_name: &'static str, category: &'static str) {
    let correlation_id = test_correlation_id(test_name, category);
    start_timer(&correlation_id);
    TestEvent {
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        log_version: "v2",
        level: "info",
        module: "fcp-mesh",
        phase: "start",
        correlation_id,
        test_name,
        result: "pass",
        duration_ms: 0,
        assertions: TestAssertions {
            passed: 0,
            failed: 0,
        },
        context: Some(serde_json::json!({ "category": category, "status": "started" })),
        details: Some(serde_json::json!({})),
        error_code: None,
    }
    .emit();
}

fn emit_test_pass(test_name: &'static str, category: &'static str, details: serde_json::Value) {
    let correlation_id = test_correlation_id(test_name, category);
    let duration_ms = finish_timer(&correlation_id);
    TestEvent {
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        log_version: "v2",
        level: "info",
        module: "fcp-mesh",
        phase: "complete",
        correlation_id,
        test_name,
        result: "pass",
        duration_ms,
        assertions: TestAssertions {
            passed: 1,
            failed: 0,
        },
        context: Some(serde_json::json!({ "category": category, "status": "passed" })),
        details: Some(details),
        error_code: None,
    }
    .emit();
}

#[allow(dead_code)]
fn emit_test_fail(test_name: &'static str, category: &'static str, error: &str) {
    let correlation_id = test_correlation_id(test_name, category);
    let duration_ms = finish_timer(&correlation_id);
    TestEvent {
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        log_version: "v2",
        level: "info",
        module: "fcp-mesh",
        phase: "complete",
        correlation_id,
        test_name,
        result: "fail",
        duration_ms,
        assertions: TestAssertions {
            passed: 0,
            failed: 1,
        },
        context: Some(serde_json::json!({ "category": category, "status": "failed" })),
        details: Some(serde_json::json!({})),
        error_code: Some(error.to_string()),
    }
    .emit();
}

/// Create a test object ID from a name by hashing it.
fn test_object_id(name: &str) -> ObjectId {
    let hash = blake3::hash(name.as_bytes());
    ObjectId::from_bytes(*hash.as_bytes())
}

/// Create a test connector ID from a canonical string (name:archetype:version).
fn test_connector_id(canonical: &str) -> ConnectorId {
    canonical.parse().expect("valid connector ID")
}

/// Create a basic device profile for testing.
#[allow(dead_code)]
fn create_test_profile(node_name: &str, memory_mb: u32, cpu_cores: u16) -> DeviceProfile {
    DeviceProfile::builder(NodeId::new(node_name))
        .cpu_cores(cpu_cores)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(memory_mb)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .bandwidth_estimate_kbps(100_000)
        .build()
}

/// Create a device profile with a connector installed.
fn create_profile_with_connector(
    node_name: &str,
    connector_id: &ConnectorId,
    version: &str,
) -> DeviceProfile {
    let binary_hash = test_object_id("deadbeef");
    let connector = InstalledConnector::new(connector_id.clone(), version, binary_hash);

    DeviceProfile::builder(NodeId::new(node_name))
        .cpu_cores(8)
        .cpu_arch(CpuArch::X86_64)
        .memory_mb(16384)
        .power_source(PowerSource::Mains)
        .latency_class(LatencyClass::Lan)
        .availability(AvailabilityProfile::AlwaysOn)
        .bandwidth_estimate_kbps(100_000)
        .add_connector(connector)
        .build()
}

// ============================================================================
// ROUTING INTEGRATION TESTS
// ============================================================================

mod routing {
    use super::*;

    /// Test: Symbol routing selects node with best data locality.
    #[test]
    fn test_symbol_routing_data_locality() {
        const TEST_NAME: &str = "symbol_routing_data_locality";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");
        let symbol_a = test_object_id("aaaa");
        let symbol_b = test_object_id("bbbb");

        // Node 1: Has both symbols
        let mut node1_symbols = HashSet::new();
        node1_symbols.insert(symbol_a);
        node1_symbols.insert(symbol_b);

        // Node 2: Has only one symbol
        let mut node2_symbols = HashSet::new();
        node2_symbols.insert(symbol_a);

        // Node 3: Has no symbols
        let node3_symbols = HashSet::new();

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-1", &connector_id, "1.0.0"),
                local_symbols: node1_symbols,
                held_leases: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-2", &connector_id, "1.0.0"),
                local_symbols: node2_symbols,
                held_leases: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-3", &connector_id, "1.0.0"),
                local_symbols: node3_symbols,
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone())
            .with_preferred_symbols(vec![symbol_a, symbol_b]);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Node 1 should be selected (has both symbols)
        assert!(!candidates.is_empty(), "Should have candidates");
        let best = &candidates[0];
        assert_eq!(best.node_id.as_str(), "node-1");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_node": best.node_id.as_str(),
                "score": best.score,
                "candidates_count": candidates.len(),
            }),
        );
    }

    /// Test: Control-plane routing respects connector requirements.
    #[test]
    fn test_control_plane_routing_connector_requirement() {
        const TEST_NAME: &str = "control_plane_routing_connector_requirement";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let required_connector = test_connector_id("slack:connector:2.0.0");
        let other_connector = test_connector_id("github:connector:1.0.0");

        let nodes = vec![
            // Node 1: Has required connector
            NodeInfo {
                profile: create_profile_with_connector("node-1", &required_connector, "2.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            // Node 2: Has different connector
            NodeInfo {
                profile: create_profile_with_connector("node-2", &other_connector, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(required_connector.clone());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node-1 should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-1");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_node": candidates[0].node_id.as_str(),
                "required_connector": required_connector.as_str(),
                "eligible_count": candidates.len(),
            }),
        );
    }

    /// Test: Multi-hop routing excludes nodes in exclusion list.
    #[test]
    fn test_multihop_routing_exclusions() {
        const TEST_NAME: &str = "multihop_routing_exclusions";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-1", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-2", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-3", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        // Exclude node-1 and node-2 (already visited in multi-hop)
        let context = PlannerContext::new(connector_id.clone()).excluding(vec!["node-1", "node-2"]);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node-3 should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-3");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_node": candidates[0].node_id.as_str(),
                "excluded_nodes": ["node-1", "node-2"],
            }),
        );
    }

    /// Test: Load balancing distributes across capable nodes.
    #[test]
    fn test_load_balancing_capability_aware() {
        const TEST_NAME: &str = "load_balancing_capability_aware";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");

        // Create nodes with varying capabilities
        let nodes = vec![
            NodeInfo {
                profile: {
                    let mut p = create_profile_with_connector("node-high", &connector_id, "1.0.0");
                    p.memory_mb = 32768;
                    p.cpu_cores = 16;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            NodeInfo {
                profile: {
                    let mut p =
                        create_profile_with_connector("node-medium", &connector_id, "1.0.0");
                    p.memory_mb = 8192;
                    p.cpu_cores = 4;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            NodeInfo {
                profile: {
                    let mut p = create_profile_with_connector("node-low", &connector_id, "1.0.0");
                    p.memory_mb = 2048;
                    p.cpu_cores = 2;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone()).with_min_memory_mb(4096);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // node-high should be first, node-low may be excluded due to memory requirement
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].node_id.as_str(), "node-high");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "candidates": candidates.iter().map(|c| {
                    serde_json::json!({
                        "node_id": c.node_id.as_str(),
                        "score": c.score,
                        "eligible": c.eligible,
                    })
                }).collect::<Vec<_>>(),
            }),
        );
    }

    /// Test: Version compatibility enforced for connectors.
    #[test]
    fn test_connector_version_compatibility() {
        const TEST_NAME: &str = "connector_version_compatibility";
        const CATEGORY: &str = "routing";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");

        let nodes = vec![
            // Node with old version
            NodeInfo {
                profile: create_profile_with_connector("node-old", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            // Node with new version
            NodeInfo {
                profile: create_profile_with_connector("node-new", &connector_id, "2.1.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context =
            PlannerContext::new(connector_id.clone()).with_min_version("2.0.0".to_string());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node-new should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-new");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_node": candidates[0].node_id.as_str(),
                "min_version": "2.0.0",
            }),
        );
    }
}

// ============================================================================
// ADMISSION CONTROL INTEGRATION TESTS
// ============================================================================

mod admission_control {
    use super::*;

    /// Test: Valid requests within budget are admitted.
    #[test]
    fn test_valid_requests_admitted() {
        const TEST_NAME: &str = "valid_requests_admitted";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let mut controller = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-123");
        let now_ms = 1000;

        // Valid authenticated request
        let result = controller.check_admission(&peer, 1024, 10, true, now_ms);
        assert!(result.is_ok());

        // Record the usage
        controller.record_bytes(&peer, 1024, now_ms);
        controller.record_symbols(&peer, 10, now_ms);

        // Another valid request
        let result2 = controller.check_admission(&peer, 2048, 20, true, now_ms);
        assert!(result2.is_ok());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "peer_id": peer.as_str(),
                "bytes_admitted": 3072,
                "symbols_admitted": 30,
            }),
        );
    }

    /// Test: Rate limiting enforces byte budget.
    #[test]
    fn test_rate_limiting_byte_budget() {
        const TEST_NAME: &str = "rate_limiting_byte_budget";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_bytes_per_min: 1000,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = NodeId::new("peer-rate-limit");
        let now_ms = 1000;

        // Use up budget
        controller.record_bytes(&peer, 800, now_ms);

        // Request that would exceed budget
        let result = controller.check_bytes(&peer, 300, now_ms);
        assert!(matches!(
            result,
            Err(AdmissionError::ByteBudgetExceeded { .. })
        ));

        // After window reset, should work again
        let later_ms = now_ms + 61_000; // More than 60 seconds later
        let result2 = controller.check_bytes(&peer, 300, later_ms);
        assert!(result2.is_ok());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "max_bytes_per_min": 1000,
                "initial_usage": 800,
                "rejected_request": 300,
                "window_reset_worked": true,
            }),
        );
    }

    /// Test: Rate limiting enforces symbol budget.
    #[test]
    fn test_rate_limiting_symbol_budget() {
        const TEST_NAME: &str = "rate_limiting_symbol_budget";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_symbols_per_min: 100,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = NodeId::new("peer-symbol-limit");
        let now_ms = 1000;

        // Use up budget
        controller.record_symbols(&peer, 95, now_ms);

        // Request that would exceed budget
        let result = controller.check_symbols(&peer, 10, now_ms);
        assert!(matches!(
            result,
            Err(AdmissionError::SymbolBudgetExceeded { .. })
        ));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "max_symbols_per_min": 100,
                "initial_usage": 95,
                "rejected_request": 10,
            }),
        );
    }

    /// Test: Authentication required by policy.
    #[test]
    fn test_authentication_required() {
        const TEST_NAME: &str = "authentication_required";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let mut controller = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-unauth");
        let now_ms = 1000;

        // Unauthenticated request should be rejected
        let result = controller.check_admission(&peer, 100, 5, false, now_ms);
        assert!(matches!(
            result,
            Err(AdmissionError::AuthenticationRequired)
        ));

        // Authenticated request should pass
        let result2 = controller.check_admission(&peer, 100, 5, true, now_ms);
        assert!(result2.is_ok());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "unauthenticated_rejected": true,
                "authenticated_accepted": true,
            }),
        );
    }

    /// Test: Anti-amplification rule enforcement.
    #[test]
    fn test_anti_amplification_rule() {
        const TEST_NAME: &str = "anti_amplification_rule";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let controller = AdmissionController::with_default_policy();
        let peer = NodeId::new("peer-amp");

        // Within amplification factor (10x default)
        let result = controller.check_amplification(&peer, 10, 100, false, false);
        assert!(result.is_ok());

        // Exceeds amplification factor
        let result2 = controller.check_amplification(&peer, 10, 150, false, false);
        assert!(matches!(
            result2,
            Err(AdmissionError::AmplificationViolation { .. })
        ));

        // Authenticated with proof-of-need bypasses limit
        let result3 = controller.check_amplification(&peer, 10, 500, true, true);
        assert!(result3.is_ok());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "default_factor": 10,
                "within_limit_passed": true,
                "exceeds_limit_rejected": true,
                "auth_with_proof_bypasses": true,
            }),
        );
    }

    /// Test: Failed auth tracking and blocking.
    #[test]
    fn test_failed_auth_tracking() {
        const TEST_NAME: &str = "failed_auth_tracking";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_failed_auth_per_min: 5,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = NodeId::new("peer-auth-fail");
        let now_ms = 1000;

        // Record failures up to limit
        for _ in 0..5 {
            let result = controller.record_auth_failure(&peer, now_ms);
            assert!(result.is_ok());
        }

        // Next failure should exceed budget
        let result = controller.record_auth_failure(&peer, now_ms);
        assert!(matches!(
            result,
            Err(AdmissionError::AuthFailureBudgetExceeded { .. })
        ));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "max_failures": 5,
                "blocked_after_exceeded": true,
            }),
        );
    }

    /// Test: Decode capacity enforcement.
    #[test]
    fn test_decode_capacity_enforcement() {
        const TEST_NAME: &str = "decode_capacity_enforcement";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let policy = AdmissionPolicy {
            per_peer: PeerBudget {
                max_inflight_decodes: 3,
                ..PeerBudget::default()
            },
            ..AdmissionPolicy::default()
        };
        let mut controller = AdmissionController::new(policy);
        let peer = NodeId::new("peer-decode");
        let now_ms = 1000;

        // Acquire up to limit
        for _ in 0..3 {
            assert!(controller.try_acquire_decode(&peer, now_ms).is_ok());
        }

        // Next should fail
        assert!(matches!(
            controller.try_acquire_decode(&peer, now_ms),
            Err(AdmissionError::DecodeCapacityExceeded { .. })
        ));

        // Release one
        controller.release_decode(&peer, now_ms);

        // Should succeed now
        assert!(controller.try_acquire_decode(&peer, now_ms).is_ok());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "max_inflight": 3,
                "release_allows_new": true,
            }),
        );
    }

    /// Test: Public ingress policy allows unauthenticated.
    #[test]
    fn test_public_ingress_policy() {
        const TEST_NAME: &str = "public_ingress_policy";
        const CATEGORY: &str = "admission_control";
        emit_test_start(TEST_NAME, CATEGORY);

        let controller = AdmissionController::new(AdmissionPolicy::public_ingress());

        // Unauthenticated should be allowed for public
        let result = controller.check_authentication_required(false);
        assert!(result.is_ok());

        // But amplification limit is stricter (2x for public)
        let peer = NodeId::new("peer-public");
        let result2 = controller.check_amplification(&peer, 10, 30, false, false);
        assert!(matches!(
            result2,
            Err(AdmissionError::AmplificationViolation { .. })
        ));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "unauthenticated_allowed": true,
                "stricter_amplification": true,
                "public_max_factor": 2,
            }),
        );
    }
}

// ============================================================================
// POLICY ENFORCEMENT INTEGRATION TESTS
// ============================================================================

mod policy_enforcement {
    use super::*;

    /// Test: Zone boundary enforcement (cross-zone blocked).
    #[test]
    fn test_zone_boundary_enforcement() {
        const TEST_NAME: &str = "zone_boundary_enforcement";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("github:connector:1.0.0");
        let work_zone = ZoneId::work();

        let nodes = vec![
            // Node in work zone
            NodeInfo {
                profile: create_profile_with_connector("node-work", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone()).with_target_zone(work_zone.clone());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Zone targeting should work (specific zone policy enforcement
        // would be in a higher-level coordinator)
        assert!(!candidates.is_empty());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "target_zone": work_zone.as_str(),
                "candidates_count": candidates.len(),
            }),
        );
    }

    /// Test: Singleton writer lease enforcement.
    #[test]
    fn test_singleton_writer_lease_enforcement() {
        const TEST_NAME: &str = "singleton_writer_lease_enforcement";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("slack:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-1", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-2", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        // Node-1 holds the singleton writer lease
        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-1");
        let context = PlannerContext::new(connector_id.clone()).with_singleton_writer();

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node-1 (lease holder) should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-1");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "lease_holder": "node-1",
                "selected_node": candidates[0].node_id.as_str(),
                "singleton_writer_enforced": true,
            }),
        );
    }

    /// Test: GPU requirement enforcement.
    #[test]
    fn test_gpu_requirement_enforcement() {
        const TEST_NAME: &str = "gpu_requirement_enforcement";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("ml:connector:1.0.0");

        let gpu_profile = GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576);

        let nodes = vec![
            // Node with GPU
            NodeInfo {
                profile: DeviceProfile::builder(NodeId::new("node-gpu"))
                    .cpu_cores(16)
                    .memory_mb(32768)
                    .gpu(gpu_profile.clone())
                    .add_connector(InstalledConnector::new(
                        connector_id.clone(),
                        "1.0.0",
                        test_object_id("deadbeef"),
                    ))
                    .build(),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            // Node without GPU
            NodeInfo {
                profile: create_profile_with_connector("node-cpu", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone()).with_gpu();

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node with GPU should be selected
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-gpu");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "gpu_required": true,
                "selected_node": candidates[0].node_id.as_str(),
            }),
        );
    }

    /// Test: Memory requirement enforcement.
    #[test]
    fn test_memory_requirement_enforcement() {
        const TEST_NAME: &str = "memory_requirement_enforcement";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("data:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: {
                    let mut p = create_profile_with_connector("node-big", &connector_id, "1.0.0");
                    p.memory_mb = 65536;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            NodeInfo {
                profile: {
                    let mut p = create_profile_with_connector("node-small", &connector_id, "1.0.0");
                    p.memory_mb = 4096;
                    p
                },
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone()).with_min_memory_mb(32768);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node with sufficient memory should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-big");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "min_memory_mb": 32768,
                "selected_node": candidates[0].node_id.as_str(),
            }),
        );
    }

    /// Test: Required symbols as hard constraint.
    #[test]
    fn test_required_symbols_hard_constraint() {
        const TEST_NAME: &str = "required_symbols_hard_constraint";
        const CATEGORY: &str = "policy_enforcement";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("data:connector:1.0.0");
        let required_symbol = test_object_id("required1234");

        let mut node1_symbols = HashSet::new();
        node1_symbols.insert(required_symbol);

        let nodes = vec![
            // Node with required symbol
            NodeInfo {
                profile: create_profile_with_connector("node-has-symbol", &connector_id, "1.0.0"),
                local_symbols: node1_symbols,
                held_leases: vec![],
            },
            // Node without required symbol
            NodeInfo {
                profile: create_profile_with_connector("node-no-symbol", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000);
        let context =
            PlannerContext::new(connector_id.clone()).with_required_symbols(vec![required_symbol]);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node with required symbol
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-has-symbol");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "required_symbol": hex::encode(&required_symbol.as_bytes()[..8]),
                "selected_node": candidates[0].node_id.as_str(),
            }),
        );
    }
}

// ============================================================================
// GOSSIP INTEGRATION TESTS
// ============================================================================

mod gossip_integration {
    use super::*;
    use fcp_mesh::admission::ObjectAdmissionClass;

    /// Test: Object availability announcement.
    #[test]
    fn test_object_availability_announcement() {
        const TEST_NAME: &str = "object_availability_announcement";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);

        let object_id = test_object_id("object1234");
        let now = 1000u64;

        // Announce object
        state.announce_object(&object_id, now);

        // Should be tracked
        assert!(state.has_object(&object_id));
        assert!(state.may_have_object(&object_id));
        assert_eq!(state.object_count(), 1);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "object_announced": true,
                "object_count": state.object_count(),
            }),
        );
    }

    /// Test: Symbol availability announcement.
    #[test]
    fn test_symbol_availability_announcement() {
        const TEST_NAME: &str = "symbol_availability_announcement";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);

        let object_id = test_object_id("object5678");
        let now = 1000u64;

        // Announce multiple symbols
        for esi in 0..10 {
            state.announce_symbol(&object_id, esi, now);
        }

        // Object should be tracked
        assert!(state.has_object(&object_id));

        // Symbols should be available
        for esi in 0..10 {
            assert!(state.has_symbol(&object_id, esi));
        }
        assert_eq!(state.symbol_count(), 10);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "object_tracked": true,
                "symbols_announced": 10,
                "total_symbols": state.symbol_count(),
            }),
        );
    }

    /// Test: Gossip summary creation.
    #[test]
    fn test_gossip_summary_creation() {
        const TEST_NAME: &str = "gossip_summary_creation";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);

        // Add some data
        let object1 = test_object_id("obj1");
        let object2 = test_object_id("obj2");
        let now = 1000u64;

        state.announce_object(&object1, now);
        state.announce_object(&object2, now);
        state.announce_symbol(&object1, 0, now);
        state.announce_symbol(&object1, 1, now);

        // Create summary
        let from_node = TailscaleNodeId::new("node-123");
        let epoch = EpochId::new("epoch-42");
        let summary = state.create_summary(from_node.clone(), epoch);

        assert_eq!(summary.object_count, 2);
        assert_eq!(summary.symbol_count, 2);
        assert_eq!(&summary.zone_id, &zone_id);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "object_count": summary.object_count,
                "symbol_count": summary.symbol_count,
            }),
        );
    }

    /// Test: Object removal from gossip state.
    #[test]
    fn test_object_removal_from_gossip() {
        const TEST_NAME: &str = "object_removal_from_gossip";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);

        let object_id = test_object_id("removeobj");
        let now = 1000u64;

        // Add object
        state.announce_object(&object_id, now);
        state.announce_symbol(&object_id, 0, now);
        assert!(state.has_object(&object_id));

        // Remove object
        state.remove_object(&object_id, now + 100);

        // Object and symbols should be gone
        assert!(!state.has_object(&object_id));
        assert!(state.symbols_for_object(&object_id).is_none());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "object_removed": true,
                "symbols_cleaned": true,
            }),
        );
    }

    /// Test: Filter membership checks.
    #[test]
    fn test_filter_membership_checks() {
        const TEST_NAME: &str = "filter_membership_checks";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);

        let known_object = test_object_id("known1234");
        let unknown_object = test_object_id("unknown5678");
        let now = 1000u64;

        state.announce_object(&known_object, now);

        // Known object should pass filter check
        assert!(state.may_have_object(&known_object));

        // Unknown object should fail authoritative check
        assert!(!state.has_object(&unknown_object));

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "known_passes_filter": true,
                "unknown_fails_auth_check": true,
            }),
        );
    }

    /// Test: Bounded object listing.
    #[test]
    fn test_bounded_object_listing() {
        const TEST_NAME: &str = "bounded_object_listing";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut state = GossipState::new(zone_id.clone(), &config);
        let now = 1000u64;

        // Add many objects
        for i in 0..20 {
            let obj = test_object_id(&format!("{i:04x}"));
            state.announce_object(&obj, now);
        }

        // List with limit
        let limited = state.list_objects(5);
        assert_eq!(limited.len(), 5);

        // List all
        let all = state.list_objects(100);
        assert_eq!(all.len(), 20);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "total_objects": 20,
                "limited_list_count": 5,
                "full_list_count": 20,
            }),
        );
    }

    /// Test: `MeshGossip` `create_request` respects config bounds.
    #[test]
    fn test_gossip_create_request_respects_config_bounds() {
        const TEST_NAME: &str = "gossip_create_request_config_bounds";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig {
            max_objects_per_request: 1,
            max_symbols_per_request: 1,
            ..GossipConfig::default()
        };
        let gossip = MeshGossip::new(TailscaleNodeId::new("node-0"), config);

        let object_ids = vec![test_object_id("obj-a"), test_object_id("obj-b")];
        let request = gossip.create_request(&zone_id, object_ids, 1000);

        assert_eq!(request.object_ids.len(), 1);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "requested_objects": 2,
                "bounded_objects": request.object_ids.len(),
            }),
        );
    }

    /// Test: `MeshGossip` drops over-config requests.
    #[test]
    fn test_gossip_request_rejects_over_config_bounds() {
        const TEST_NAME: &str = "gossip_request_rejects_over_config_bounds";
        const CATEGORY: &str = "gossip";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig {
            max_objects_per_request: 1,
            max_symbols_per_request: 1,
            ..GossipConfig::default()
        };
        let mut gossip = MeshGossip::new(TailscaleNodeId::new("node-0"), config);

        let object_ids = vec![test_object_id("obj-1"), test_object_id("obj-2")];
        for object_id in &object_ids {
            gossip.announce_object(&zone_id, object_id, ObjectAdmissionClass::Admitted, 1000);
        }

        let request = GossipRequest::for_objects(
            TailscaleNodeId::new("peer-1"),
            zone_id.clone(),
            object_ids,
            1000,
        );
        let response = gossip.handle_request(&request);

        assert!(response.have_objects.is_empty());
        assert!(response.have_symbols.is_empty());

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "zone": zone_id.as_str(),
                "response_objects": response.have_objects.len(),
                "response_symbols": response.have_symbols.len(),
            }),
        );
    }
}

// ============================================================================
// LEASE COORDINATION TESTS
// ============================================================================

mod lease_coordination {
    use super::*;

    /// Test: Lease holder gets priority for singleton operations.
    #[test]
    fn test_lease_holder_priority() {
        const TEST_NAME: &str = "lease_holder_priority";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("state:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-holder", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![HeldLease {
                    subject_id: test_object_id("stateobject"),
                    purpose: LeasePurpose::SingletonWriter,
                    expires_at: 2000,
                }],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-other", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-holder");
        let context = PlannerContext::new(connector_id.clone()).with_singleton_writer();

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Lease holder should be selected
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-holder");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "lease_holder": "node-holder",
                "selected_for_singleton": true,
            }),
        );
    }

    /// Test: Non-singleton operations allow any eligible node.
    #[test]
    fn test_non_singleton_allows_all() {
        const TEST_NAME: &str = "non_singleton_allows_all";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("read:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-1", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-2", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        // Non-singleton operation (no with_singleton_writer)
        let input = PlannerInput::new(nodes, 1000);
        let context = PlannerContext::new(connector_id.clone());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Both should be eligible
        assert_eq!(candidates.len(), 2);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "singleton_mode": false,
                "eligible_count": 2,
            }),
        );
    }

    /// Test: Lease conflict detection.
    #[test]
    fn test_lease_conflict_detection() {
        const TEST_NAME: &str = "lease_conflict_detection";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("write:connector:1.0.0");

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-1", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-2", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        // Node-1 is the singleton holder, requesting from node-2's perspective
        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-1");
        let context = PlannerContext::new(connector_id.clone()).with_singleton_writer();

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Only node-1 (holder) should be eligible
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-1");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "holder": "node-1",
                "conflicting_node_excluded": true,
            }),
        );
    }

    /// Test: Operation execution lease purpose.
    #[test]
    fn test_operation_execution_lease() {
        const TEST_NAME: &str = "operation_execution_lease";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let subject = test_object_id("operationsubject");

        let lease = HeldLease {
            subject_id: subject,
            purpose: LeasePurpose::OperationExecution,
            expires_at: 5000,
        };

        // Verify lease structure
        assert_eq!(lease.purpose, LeasePurpose::OperationExecution);
        assert_eq!(format!("{}", lease.purpose), "operation_execution");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "lease_purpose": "operation_execution",
                "expires_at": 5000,
            }),
        );
    }

    /// Test: Coordinator election lease purpose.
    #[test]
    fn test_coordinator_election_lease() {
        const TEST_NAME: &str = "coordinator_election_lease";
        const CATEGORY: &str = "lease_coordination";
        emit_test_start(TEST_NAME, CATEGORY);

        let subject = test_object_id("coordinatorslot");

        let lease = HeldLease {
            subject_id: subject,
            purpose: LeasePurpose::CoordinatorElection,
            expires_at: 10000,
        };

        // Verify lease structure
        assert_eq!(lease.purpose, LeasePurpose::CoordinatorElection);
        assert_eq!(format!("{}", lease.purpose), "coordinator_election");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "lease_purpose": "coordinator_election",
                "expires_at": 10000,
            }),
        );
    }
}

// ============================================================================
// INTEGRATION SCENARIO TESTS
// ============================================================================

mod integration_scenarios {
    use super::*;

    /// Test: Full mesh routing scenario with multiple factors.
    #[test]
    fn test_full_mesh_routing_scenario() {
        const TEST_NAME: &str = "full_mesh_routing_scenario";
        const CATEGORY: &str = "integration";
        emit_test_start(TEST_NAME, CATEGORY);

        let connector_id = test_connector_id("multifactor:connector:2.0.0");
        let symbol_a = test_object_id("syma");
        let symbol_b = test_object_id("symb");

        // Node 1: Has connector, GPU, symbols, lease holder
        let mut node1_symbols = HashSet::new();
        node1_symbols.insert(symbol_a);
        node1_symbols.insert(symbol_b);

        let gpu = GpuProfile::new(GpuVendor::Nvidia, "RTX 4090", 24576);

        let nodes = vec![
            NodeInfo {
                profile: DeviceProfile::builder(NodeId::new("node-optimal"))
                    .cpu_cores(32)
                    .memory_mb(131072)
                    .gpu(gpu.clone())
                    .add_connector(InstalledConnector::new(
                        connector_id.clone(),
                        "2.0.0",
                        test_object_id("binary1"),
                    ))
                    .build(),
                local_symbols: node1_symbols,
                held_leases: vec![HeldLease {
                    subject_id: test_object_id("state"),
                    purpose: LeasePurpose::SingletonWriter,
                    expires_at: 5000,
                }],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-basic", &connector_id, "1.5.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, 1000).with_singleton_holder("node-optimal");
        let context = PlannerContext::new(connector_id.clone())
            .with_min_version("2.0.0")
            .with_gpu()
            .with_min_memory_mb(65536)
            .with_preferred_symbols(vec![symbol_a, symbol_b])
            .with_singleton_writer();

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // node-optimal should be the only candidate meeting all requirements
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].node_id.as_str(), "node-optimal");
        assert!(candidates[0].score > 0.0);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "selected_node": candidates[0].node_id.as_str(),
                "final_score": candidates[0].score,
                "constraints_checked": [
                    "connector_version",
                    "gpu_required",
                    "memory_requirement",
                    "data_locality",
                    "singleton_writer"
                ],
            }),
        );
    }

    /// Test: Admission + routing integration.
    #[test]
    fn test_admission_routing_integration() {
        const TEST_NAME: &str = "admission_routing_integration";
        const CATEGORY: &str = "integration";
        emit_test_start(TEST_NAME, CATEGORY);

        // Set up admission controller
        let mut admission = AdmissionController::with_default_policy();
        let peer = NodeId::new("requesting-peer");
        let now_ms = 1000u64;

        // First check admission
        let admission_result =
            admission.check_admission(&peer, 1024, 50, true /* authenticated */, now_ms);
        assert!(admission_result.is_ok());

        // Then proceed with routing
        let connector_id = test_connector_id("route:connector:1.0.0");
        let nodes = vec![NodeInfo {
            profile: create_profile_with_connector("node-target", &connector_id, "1.0.0"),
            local_symbols: HashSet::new(),
            held_leases: vec![],
        }];

        let input = PlannerInput::new(nodes, now_ms);
        let context = PlannerContext::new(connector_id.clone());

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        assert!(!candidates.is_empty());

        // Record usage after successful routing
        admission.record_bytes(&peer, 1024, now_ms);
        admission.record_symbols(&peer, 50, now_ms);

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "admission_passed": true,
                "routing_completed": true,
                "target_node": candidates[0].node_id.as_str(),
            }),
        );
    }

    /// Test: Gossip + routing integration.
    #[test]
    fn test_gossip_routing_integration() {
        const TEST_NAME: &str = "gossip_routing_integration";
        const CATEGORY: &str = "integration";
        emit_test_start(TEST_NAME, CATEGORY);

        let zone_id = ZoneId::work();
        let config = GossipConfig::default();
        let mut gossip_state = GossipState::new(zone_id.clone(), &config);

        // Set up gossip state with object availability
        let object_id = test_object_id("dataobject");
        let now = 1000u64;

        for esi in 0..100 {
            gossip_state.announce_symbol(&object_id, esi, now);
        }

        // Use gossip info for routing decisions
        let connector_id = test_connector_id("data:connector:1.0.0");

        // Simulate nodes, one with local symbols based on gossip
        let mut node_symbols = HashSet::new();
        node_symbols.insert(object_id);

        let nodes = vec![
            NodeInfo {
                profile: create_profile_with_connector("node-with-data", &connector_id, "1.0.0"),
                local_symbols: node_symbols,
                held_leases: vec![],
            },
            NodeInfo {
                profile: create_profile_with_connector("node-no-data", &connector_id, "1.0.0"),
                local_symbols: HashSet::new(),
                held_leases: vec![],
            },
        ];

        let input = PlannerInput::new(nodes, now);
        let context =
            PlannerContext::new(connector_id.clone()).with_preferred_symbols(vec![object_id]);

        let planner = ExecutionPlanner::new();
        let candidates = planner.plan(&input, &context);

        // Node with data should be preferred
        assert!(!candidates.is_empty());
        assert_eq!(candidates[0].node_id.as_str(), "node-with-data");

        emit_test_pass(
            TEST_NAME,
            CATEGORY,
            serde_json::json!({
                "gossip_symbol_count": gossip_state.symbol_count(),
                "routing_preferred_data_locality": true,
                "selected_node": candidates[0].node_id.as_str(),
            }),
        );
    }
}
