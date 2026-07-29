//! Local non-mock acceptance coverage for the Elasticsearch connector.

#![cfg(feature = "integration-testcontainer")]
#![allow(clippy::future_not_send, clippy::too_many_lines)]

use fcp_elasticsearch::connector::ElasticsearchConnector;
use fcp_prelude::FcpError;
use fcp_testkit::database_helpers::{
    CleanupVerificationResult, FixtureCleanupCheck, FixtureMutationRecord, FixtureSeedRecord,
    FixtureStartupProbe, FixtureStartupProbeKind, SeededStatefulFixturePack, StatefulFixtureFamily,
    assert_stateful_fixture_pack_complete,
};
use serde_json::{Value, json};
use testcontainers::{
    GenericImage, ImageExt,
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
};

const ACCEPTANCE_SUITE_CLASS: &str = "local_non_mock";
const CONNECTOR_ID: &str = "elasticsearch";
const FIXTURE_ID: &str = "elasticsearch-testcontainer-local-acceptance";
const INDEX_NAME: &str = "fcp_es_local_acceptance";
const ELASTICSEARCH_HTTP_PORT: u16 = 9200;

async fn bring_up_elasticsearch() -> (String, testcontainers::ContainerAsync<GenericImage>) {
    let container = GenericImage::new("docker.elastic.co/elasticsearch/elasticsearch", "8.15.3")
        .with_exposed_port(ELASTICSEARCH_HTTP_PORT.tcp())
        .with_wait_for(WaitFor::message_on_stdout("started"))
        .with_env_var("discovery.type", "single-node")
        .with_env_var("xpack.security.enabled", "false")
        .with_env_var("xpack.security.http.ssl.enabled", "false")
        .with_env_var("ingest.geoip.downloader.enabled", "false")
        .with_env_var("ES_JAVA_OPTS", "-Xms512m -Xmx512m")
        .start()
        .await
        .expect("start elasticsearch testcontainer");

    let host_port = container
        .get_host_port_ipv4(ELASTICSEARCH_HTTP_PORT.tcp())
        .await
        .expect("get mapped elasticsearch port");

    (format!("http://127.0.0.1:{host_port}"), container)
}

async fn configured_connector(base_url: &str) -> ElasticsearchConnector {
    let mut connector = ElasticsearchConnector::new();
    connector
        .handle_configure(json!({
            "api_key": "test-elasticsearch-key",
            "base_url": base_url,
        }))
        .await
        .expect("configure elasticsearch connector");

    connector
        .handle_handshake(json!({ "session_id": "elasticsearch-local-acceptance" }))
        .await
        .expect("handshake elasticsearch connector");

    connector
}

async fn invoke(connector: &ElasticsearchConnector, operation_id: &str, input: Value) -> Value {
    connector
        .handle_invoke(json!({
            "operation_id": operation_id,
            "input": input,
        }))
        .await
        .expect("elasticsearch invocation should succeed")
}

async fn invoke_error(
    connector: &ElasticsearchConnector,
    operation_id: &str,
    input: Value,
) -> FcpError {
    connector
        .handle_invoke(json!({
            "operation_id": operation_id,
            "input": input,
        }))
        .await
        .expect_err("elasticsearch invocation should fail")
}

async fn refresh_index(base_url: &str) {
    let response = reqwest::Client::new()
        .post(format!("{base_url}/{INDEX_NAME}/_refresh"))
        .send()
        .await
        .expect("send refresh request to elasticsearch");
    assert!(
        response.status().is_success(),
        "refresh must succeed before search assertions: {}",
        response.status()
    );
}

async fn wait_for_search_hits(
    connector: &ElasticsearchConnector,
    base_url: &str,
    expected_hits: usize,
) {
    let mut last_observed = 0usize;

    for _ in 0..60 {
        refresh_index(base_url).await;
        let search = invoke(
            connector,
            "elasticsearch.search",
            json!({
                "index": INDEX_NAME,
                "query": {"match_all": {}},
                "size": 10,
            }),
        )
        .await;
        let observed = search["hits"]["hits"].as_array().expect("hits array").len();
        if observed == expected_hits {
            return;
        }
        last_observed = observed;
        fcp_async_core::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    panic!(
        "timed out waiting for elasticsearch search hits {expected_hits}; last observed {last_observed}"
    );
}

fn fixture_contract() -> SeededStatefulFixturePack {
    SeededStatefulFixturePack::new(
        FIXTURE_ID,
        StatefulFixtureFamily::KeyValue,
        "elasticsearch-testcontainer",
    )
    .with_startup_probe(FixtureStartupProbe::new(
        "elasticsearch-http-ready",
        FixtureStartupProbeKind::TcpConnect,
        "127.0.0.1:redacted-elasticsearch-port",
        30_000,
        "real Elasticsearch HTTP API accepts connector traffic before mutations",
    ))
    .with_seed(FixtureSeedRecord::new(
        INDEX_NAME,
        "doc-1",
        json!({
            "title": "vector search checklist",
            "tag": "alpha",
            "score": 1
        }),
    ))
    .with_mutation(
        FixtureMutationRecord::new(
            "bulk-index-doc-2",
            INDEX_NAME,
            "doc-2",
            "connector bulk operation writes a second document into the real Elasticsearch index",
        )
        .with_before(json!({"hit_count": 1}))
        .with_after(json!({"hit_count": 2})),
    )
    .with_cleanup_check(FixtureCleanupCheck::new(
        "cleanup-index",
        INDEX_NAME,
        "index_absence_after_delete",
        "acceptance index is absent after teardown",
    ))
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn elasticsearch_connector_acceptance_exercises_real_testcontainer_boundary() {
    let (base_url, _container) = bring_up_elasticsearch().await;
    let connector = configured_connector(&base_url).await;
    let fixture = fixture_contract();
    assert_stateful_fixture_pack_complete(&fixture);

    let health = connector.handle_health().await.expect("health check");
    assert_eq!(health["status"], "healthy");
    let doctor = connector.handle_doctor().await.expect("doctor check");
    assert_eq!(doctor["status"], "healthy");

    let cluster = invoke(&connector, "elasticsearch.cluster.health", json!({})).await;
    assert_eq!(cluster["number_of_nodes"], 1);

    let indexed = invoke(
        &connector,
        "elasticsearch.index_document",
        json!({
            "index": INDEX_NAME,
            "id": "doc-1",
            "document": {
                "title": "vector search checklist",
                "tag": "alpha",
                "score": 1
            },
        }),
    )
    .await;
    assert_eq!(indexed["_id"], "doc-1");
    assert!(matches!(
        indexed["result"].as_str(),
        Some("created" | "updated")
    ));

    let fetched = invoke(
        &connector,
        "elasticsearch.get_document",
        json!({
            "index": INDEX_NAME,
            "id": "doc-1",
        }),
    )
    .await;
    assert_eq!(fetched["_source"]["tag"], "alpha");

    let bulk = invoke(
        &connector,
        "elasticsearch.bulk",
        json!({
            "operations": [
                {"index": {"_index": INDEX_NAME, "_id": "doc-2"}},
                {"title": "cleanup evidence checklist", "tag": "beta", "score": 2}
            ],
        }),
    )
    .await;
    assert_eq!(bulk["errors"], false);
    wait_for_search_hits(&connector, &base_url, 2).await;

    let search = invoke(
        &connector,
        "elasticsearch.search",
        json!({
            "index": INDEX_NAME,
            "query": {"match": {"tag": "beta"}},
            "size": 10,
        }),
    )
    .await;
    let beta_hits = search["hits"]["hits"]
        .as_array()
        .expect("search hits array")
        .iter()
        .filter(|hit| hit["_source"]["tag"] == "beta")
        .count();
    assert_eq!(beta_hits, 1);

    let indices = invoke(
        &connector,
        "elasticsearch.indices.list",
        json!({ "pattern": INDEX_NAME }),
    )
    .await;
    assert!(
        indices["indices"]
            .as_array()
            .expect("indices array")
            .iter()
            .any(|index| index["index"] == INDEX_NAME),
        "created index must be visible in _cat indices output"
    );

    let deleted = invoke(
        &connector,
        "elasticsearch.indices.delete",
        json!({ "index": INDEX_NAME }),
    )
    .await;
    assert_eq!(deleted["acknowledged"], true);

    let missing = invoke_error(
        &connector,
        "elasticsearch.get_document",
        json!({
            "index": INDEX_NAME,
            "id": "doc-1",
        }),
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
        "deleted index must surface terminal 404, got {missing:?}"
    );

    let cleanup = CleanupVerificationResult::new(
        "cleanup-index",
        INDEX_NAME,
        "index_absence_after_delete",
        "acceptance index is absent after teardown",
        json!({ "deleted_index_get_document_status": 404 }),
        true,
    );
    let evidence = json!({
        "schema_version": "fcp-elasticsearch-local-acceptance/v1",
        "suite_class": ACCEPTANCE_SUITE_CLASS,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "connector": CONNECTOR_ID,
        "fixture_id": FIXTURE_ID,
        "service": "docker.elastic.co/elasticsearch/elasticsearch:8.15.3",
        "base_url": "redacted-local-elasticsearch-testcontainer",
        "operations": [
            "elasticsearch.cluster.health",
            "elasticsearch.index_document",
            "elasticsearch.get_document",
            "elasticsearch.bulk",
            "elasticsearch.search",
            "elasticsearch.indices.list",
            "elasticsearch.indices.delete",
            "elasticsearch.get_document:deleted_index_404"
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
