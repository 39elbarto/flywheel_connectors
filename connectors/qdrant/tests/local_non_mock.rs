//! Local non-mock acceptance coverage for the Qdrant connector.

#![cfg(feature = "integration-testcontainer")]
#![allow(clippy::future_not_send, clippy::too_many_lines)]

use chrono::{Duration, Utc};
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::{
    CapabilityConstraints, CapabilityId, CapabilityToken, FcpError, HandshakeRequest, InstanceId,
    ZoneId,
};
use fcp_qdrant::connector::QdrantConnector;
use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Value, json};
use testcontainers::{
    GenericImage,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "qdrant";
const FIXTURE_ID: &str = "qdrant-testcontainer-local-acceptance";
const COLLECTION_NAME: &str = "fcp_qdrant_local_acceptance";
const QDRANT_HTTP_PORT: u16 = 6333;

fn capability_for_operation(operation: &str) -> &'static str {
    match operation {
        "qdrant.create_collection" | "qdrant.delete_collection" => "qdrant.collections.write",
        "qdrant.upsert_points" | "qdrant.delete_points" => "qdrant.points.write",
        "qdrant.search"
        | "qdrant.query_points"
        | "qdrant.batch_query_points"
        | "qdrant.get_points"
        | "qdrant.scroll"
        | "qdrant.count" => "qdrant.points.read",
        _ => "qdrant.collections.read",
    }
}

fn capability_token(
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &str,
) -> CapabilityToken {
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut constraints_cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut constraints_cbor)
        .expect("serialize capability constraints");

    let now = Utc::now();
    let raw = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id("z:work")
        .target_instance(instance_id.as_str())
        .principal("user:test")
        .operations(&[operation])
        .issuer("node:test")
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&constraints_cbor)
        .expect("constraints cbor should validate")
        .sign(signing_key)
        .expect("capability token should sign");
    CapabilityToken::from_raw(raw)
}

async fn bring_up_qdrant() -> (String, testcontainers::ContainerAsync<GenericImage>) {
    let container = GenericImage::new("qdrant/qdrant", "v1.11.5")
        .with_exposed_port(QDRANT_HTTP_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Actix runtime found"))
        .start()
        .await
        .expect("start qdrant testcontainer");

    let host_port = container
        .get_host_port_ipv4(QDRANT_HTTP_PORT.tcp())
        .await
        .expect("get mapped qdrant port");

    (format!("http://127.0.0.1:{host_port}"), container)
}

async fn configured_connector(
    base_url: &str,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
) -> QdrantConnector {
    let mut connector = QdrantConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "test-qdrant-key",
            "cluster_url": base_url,
        }))
        .await
        .expect("configure qdrant connector");

    connector
        .handle_handshake(
            serde_json::to_value(HandshakeRequest {
                protocol_version: "2.0.0".into(),
                zone: ZoneId::work(),
                zone_dir: None,
                host_public_key: signing_key.verifying_key().to_bytes(),
                nonce: [11u8; 32],
                capabilities_requested: vec![
                    CapabilityId::from_static("qdrant.collections.read"),
                    CapabilityId::from_static("qdrant.collections.write"),
                    CapabilityId::from_static("qdrant.points.read"),
                    CapabilityId::from_static("qdrant.points.write"),
                ],
                host: None,
                transport_caps: None,
                requested_instance_id: Some(instance_id.clone()),
            })
            .expect("serialize handshake"),
        )
        .await
        .expect("handshake qdrant connector");

    connector
}

async fn invoke(
    connector: &QdrantConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &str,
    input: Value,
) -> Value {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_token(signing_key, instance_id, operation),
        }))
        .await
        .expect("qdrant invocation should succeed")
}

async fn invoke_error(
    connector: &QdrantConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    operation: &str,
    input: Value,
) -> FcpError {
    connector
        .handle_invoke(json!({
            "operation": operation,
            "input": input,
            "capability_token": capability_token(signing_key, instance_id, operation),
        }))
        .await
        .expect_err("qdrant invocation should fail")
}

async fn wait_for_exact_count(
    connector: &QdrantConnector,
    signing_key: &Ed25519SigningKey,
    instance_id: &InstanceId,
    expected: u64,
) {
    let mut last_observed = None;

    for _ in 0..60 {
        let count = invoke(
            connector,
            signing_key,
            instance_id,
            "qdrant.count",
            json!({
                "collection_name": COLLECTION_NAME,
                "exact": true,
            }),
        )
        .await;
        let observed = count["count"].as_u64().expect("count is numeric");
        if observed == expected {
            return;
        }
        last_observed = Some(observed);
        fcp_async_core::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    panic!("timed out waiting for qdrant count {expected}; last observed {last_observed:?}");
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::KeyValue,
        "qdrant-testcontainer",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "qdrant-http-ready",
        FixtureStartupProbeKind::TcpConnect,
        "127.0.0.1:redacted-qdrant-port",
        10_000,
        "real Qdrant HTTP API accepts connector traffic before mutations",
    ))
    .with_seed(FixtureSeedRecord::new(
        COLLECTION_NAME,
        "point-1",
        json!({
            "id": 1,
            "vector": [1.0, 0.0, 0.0],
            "payload": {"kind": "axis-x"}
        }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "delete-point-2",
            COLLECTION_NAME,
            "point-2",
            "connector deletes one vector point from the real Qdrant collection",
        )
        .with_before(json!({"point_count": 3}))
        .with_after(json!({"point_count": 2})),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-collection",
        COLLECTION_NAME,
        "list_collections_absence",
        "acceptance collection is absent after teardown",
    ))
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn qdrant_connector_acceptance_exercises_real_testcontainer_boundary() {
    let (base_url, _container) = bring_up_qdrant().await;
    let signing_key = Ed25519SigningKey::generate();
    let instance_id = InstanceId::new();
    let connector = configured_connector(&base_url, &signing_key, &instance_id).await;
    let fixture = fixture_contract();
    assert_stateful_fixture_pack_complete(&fixture);

    let health = connector.handle_health().await.expect("health check");
    assert_eq!(health["status"], "healthy");
    let doctor = connector.handle_doctor().await.expect("doctor check");
    assert_eq!(doctor["status"], "healthy");

    let create = invoke(
        &connector,
        &signing_key,
        &instance_id,
        "qdrant.create_collection",
        json!({
            "collection_name": COLLECTION_NAME,
            "vectors": {"size": 3, "distance": "Cosine"},
        }),
    )
    .await;
    assert_eq!(create["receipt"]["operation"], "qdrant.create_collection");

    let listed = invoke(
        &connector,
        &signing_key,
        &instance_id,
        "qdrant.list_collections",
        json!({}),
    )
    .await;
    assert!(
        listed["collections"]
            .as_array()
            .expect("collections array")
            .iter()
            .any(|collection| collection["name"] == COLLECTION_NAME),
        "created collection must be visible in Qdrant list_collections"
    );

    invoke(
        &connector,
        &signing_key,
        &instance_id,
        "qdrant.upsert_points",
        json!({
            "collection_name": COLLECTION_NAME,
            "points": [
                {"id": 1, "vector": [1.0, 0.0, 0.0], "payload": {"kind": "axis-x"}},
                {"id": 2, "vector": [0.0, 1.0, 0.0], "payload": {"kind": "axis-y"}},
                {"id": 3, "vector": [0.0, 0.0, 1.0], "payload": {"kind": "axis-z"}}
            ],
        }),
    )
    .await;
    wait_for_exact_count(&connector, &signing_key, &instance_id, 3).await;

    let scroll = invoke(
        &connector,
        &signing_key,
        &instance_id,
        "qdrant.scroll",
        json!({
            "collection_name": COLLECTION_NAME,
            "limit": 10,
            "with_payload": true,
            "with_vectors": false,
        }),
    )
    .await;
    let kinds = scroll["result"]["points"]
        .as_array()
        .expect("scroll points array")
        .iter()
        .filter_map(|point| point["payload"]["kind"].as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(kinds, ["axis-x", "axis-y", "axis-z"].into_iter().collect());

    let search = invoke(
        &connector,
        &signing_key,
        &instance_id,
        "qdrant.search",
        json!({
            "collection_name": COLLECTION_NAME,
            "vector": [0.98, 0.02, 0.0],
            "limit": 2,
            "with_payload": true,
        }),
    )
    .await;
    assert_eq!(search["result"][0]["id"], 1);
    assert_eq!(search["result"][0]["payload"]["kind"], "axis-x");

    invoke(
        &connector,
        &signing_key,
        &instance_id,
        "qdrant.delete_points",
        json!({
            "collection_name": COLLECTION_NAME,
            "points": [2],
        }),
    )
    .await;
    wait_for_exact_count(&connector, &signing_key, &instance_id, 2).await;

    invoke(
        &connector,
        &signing_key,
        &instance_id,
        "qdrant.delete_collection",
        json!({ "collection_name": COLLECTION_NAME }),
    )
    .await;
    let after_cleanup = invoke(
        &connector,
        &signing_key,
        &instance_id,
        "qdrant.list_collections",
        json!({}),
    )
    .await;
    let collection_present = after_cleanup["collections"]
        .as_array()
        .expect("collections array")
        .iter()
        .any(|collection| collection["name"] == COLLECTION_NAME);
    assert!(!collection_present);

    let missing = invoke_error(
        &connector,
        &signing_key,
        &instance_id,
        "qdrant.collection_info",
        json!({ "collection_name": COLLECTION_NAME }),
    )
    .await;
    assert!(
        matches!(
            missing,
            FcpError::External {
                status_code: Some(404),
                ..
            }
        ),
        "deleted collection must surface terminal 404, got {missing:?}"
    );

    let cleanup = CleanupVerificationResult::new(
        "cleanup-collection",
        COLLECTION_NAME,
        "list_collections_absence",
        "acceptance collection is absent after teardown",
        json!({ "collection_present": collection_present }),
        !collection_present,
    );
    let evidence = json!({
        "schema_version": "fcp-qdrant-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "service": "qdrant/qdrant:v1.11.5",
        "base_url": "redacted-local-qdrant-testcontainer",
        "operations": [
            "qdrant.create_collection",
            "qdrant.list_collections",
            "qdrant.upsert_points",
            "qdrant.count",
            "qdrant.scroll",
            "qdrant.search",
            "qdrant.delete_points",
            "qdrant.delete_collection",
            "qdrant.collection_info:deleted_collection_404"
        ],
        "fixture_contract": fixture.to_json(),
        "cleanup": cleanup,
    });

    assert_eq!(evidence["suite_class"], ACCEPTANCE_SUITE_CLASS);
    assert_eq!(evidence["cleanup"]["passed"], true);
    assert!(
        !serde_json::to_string(&evidence)
            .expect("serialize evidence")
            .contains(&base_url),
        "acceptance evidence must not expose dynamic local endpoint"
    );
}
