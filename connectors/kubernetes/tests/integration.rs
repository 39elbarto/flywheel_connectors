//! Integration tests for the FCP Kubernetes connector.

#![allow(
    clippy::cast_possible_truncation,
    clippy::future_not_send,
    clippy::missing_errors_doc,
    clippy::missing_fields_in_debug,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::unreadable_literal,
    clippy::unused_async
)]

use serde_json::json;
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use fcp_kubernetes::connector::KubernetesConnector;

async fn setup_connector(mock_url: &str) -> KubernetesConnector {
    let mut c = KubernetesConnector::new();
    c.handle_configure(json!({ "bearer_token": "test-k8s-token", "base_url": mock_url }))
        .await
        .unwrap();
    c.handle_handshake(json!({"session_id": "test"}))
        .await
        .unwrap();
    c
}

// -- Lifecycle --

#[fcp_async_core::runtime::test]
async fn lifecycle_health_unconfigured() {
    let c = KubernetesConnector::new();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_full() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_health().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_handshake_before_configure_fails() {
    let mut c = KubernetesConnector::new();
    assert!(c.handle_handshake(json!({})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_shutdown() {
    let server = MockServer::start().await;
    let mut c = setup_connector(&server.uri()).await;
    c.handle_shutdown(json!({})).await.unwrap();
    assert_eq!(c.handle_health().await.unwrap()["status"], "unconfigured");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_self_check() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_self_check().await.unwrap()["status"], "ok");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_doctor() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert_eq!(c.handle_doctor().await.unwrap()["status"], "healthy");
}

#[fcp_async_core::runtime::test]
async fn lifecycle_introspect() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    let intro = c.handle_introspect().await.unwrap();
    assert_eq!(intro["operations"].as_array().unwrap().len(), 18);
}

// -- list_pods --

#[fcp_async_core::runtime::test]
async fn list_pods() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .and(header("Authorization", "Bearer test-k8s-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "PodList",
            "items": [
                {"metadata": {"name": "nginx-abc123"}, "status": {"phase": "Running"}},
                {"metadata": {"name": "redis-xyz789"}, "status": {"phase": "Running"}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}}),
        )
        .await
        .unwrap();
    assert_eq!(result["pods"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn list_pods_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/production/pods"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"kind": "PodList", "items": []})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "production"}}),
        )
        .await
        .unwrap();
    assert!(result["pods"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn list_pods_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "kubernetes.list_pods", "input": {}}))
            .await
            .is_err()
    );
}

// -- get_pod --

#[fcp_async_core::runtime::test]
async fn get_pod() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods/nginx-abc123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Pod", "metadata": {"name": "nginx-abc123"}, "status": {"phase": "Running"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_pod", "input": {"namespace": "default", "name": "nginx-abc123"}})).await.unwrap();
    assert_eq!(result["pod"]["metadata"]["name"], "nginx-abc123");
}

#[fcp_async_core::runtime::test]
async fn get_pod_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "kubernetes.get_pod", "input": {"name": "nginx"}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn get_pod_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.get_pod", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

// -- delete_pod --

#[fcp_async_core::runtime::test]
async fn delete_pod() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/namespaces/default/pods/nginx-abc123"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kind": "Status", "status": "Success"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.delete_pod", "input": {"namespace": "default", "name": "nginx-abc123"}})).await.unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn delete_pod_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.delete_pod", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

// -- get_pod_logs --

#[fcp_async_core::runtime::test]
async fn get_pod_logs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"/api/v1/namespaces/default/pods/nginx-abc123/log.*",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("Starting nginx\nReady to accept connections"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_pod_logs", "input": {"namespace": "default", "name": "nginx-abc123", "tail_lines": 100}})).await.unwrap();
    assert!(result["logs"].as_str().unwrap().contains("Starting nginx"));
}

#[fcp_async_core::runtime::test]
async fn get_pod_logs_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.get_pod_logs", "input": {"name": "nginx"}})
        )
        .await
        .is_err()
    );
}

// -- stream_pod_logs --

#[fcp_async_core::runtime::test]
async fn stream_pod_logs() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(
            r"/api/v1/namespaces/default/pods/nginx-abc123/log.*",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("live log line 1\nlive log line 2"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.stream_pod_logs", "input": {"namespace": "default", "name": "nginx-abc123"}})).await.unwrap();
    assert!(
        result["log_line"]
            .as_str()
            .unwrap()
            .contains("live log line")
    );
}

// -- list_deployments --

#[fcp_async_core::runtime::test]
async fn list_deployments() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/apis/apps/v1/namespaces/default/deployments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "DeploymentList",
            "items": [{"metadata": {"name": "web-app"}, "spec": {"replicas": 3}}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.list_deployments", "input": {"namespace": "default"}})).await.unwrap();
    assert_eq!(result["deployments"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn list_deployments_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "kubernetes.list_deployments", "input": {}}))
            .await
            .is_err()
    );
}

// -- get_deployment --

#[fcp_async_core::runtime::test]
async fn get_deployment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/apis/apps/v1/namespaces/default/deployments/web-app"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"kind": "Deployment", "metadata": {"name": "web-app"}, "spec": {"replicas": 3}}),
        ))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_deployment", "input": {"namespace": "default", "name": "web-app"}})).await.unwrap();
    assert_eq!(result["deployment"]["metadata"]["name"], "web-app");
}

// -- scale_deployment --

#[fcp_async_core::runtime::test]
async fn scale_deployment() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path(
            "/apis/apps/v1/namespaces/default/deployments/web-app/scale",
        ))
        .and(header(
            "Content-Type",
            "application/strategic-merge-patch+json",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"kind": "Scale", "spec": {"replicas": 5}, "status": {"replicas": 5}}),
        ))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.scale_deployment", "input": {"namespace": "default", "name": "web-app", "replicas": 5}})).await.unwrap();
    assert_eq!(result["deployment"]["spec"]["replicas"], 5);
}

#[fcp_async_core::runtime::test]
async fn scale_deployment_missing_replicas() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "kubernetes.scale_deployment", "input": {"namespace": "default", "name": "web-app"}})).await.is_err());
}

// -- rollout_restart --

#[fcp_async_core::runtime::test]
async fn rollout_restart() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/apis/apps/v1/namespaces/default/deployments/web-app"))
        .and(header(
            "Content-Type",
            "application/strategic-merge-patch+json",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kind": "Deployment", "metadata": {"name": "web-app"}})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.rollout_restart", "input": {"namespace": "default", "name": "web-app"}})).await.unwrap();
    assert_eq!(result["deployment"]["metadata"]["name"], "web-app");
}

#[fcp_async_core::runtime::test]
async fn rollout_restart_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.rollout_restart", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

// -- get_service --

#[fcp_async_core::runtime::test]
async fn get_service() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/services/api-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"kind": "Service", "metadata": {"name": "api-server"}, "spec": {"type": "ClusterIP"}})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_service", "input": {"namespace": "default", "name": "api-server"}})).await.unwrap();
    assert_eq!(result["service"]["metadata"]["name"], "api-server");
}

// -- get_configmap --

#[fcp_async_core::runtime::test]
async fn get_configmap() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/configmaps/app-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"kind": "ConfigMap", "metadata": {"name": "app-config"}, "data": {"LOG_LEVEL": "info"}})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_configmap", "input": {"namespace": "default", "name": "app-config"}})).await.unwrap();
    assert_eq!(result["configmap"]["data"]["LOG_LEVEL"], "info");
}

// -- update_configmap --

#[fcp_async_core::runtime::test]
async fn update_configmap() {
    let server = MockServer::start().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/namespaces/default/configmaps/app-config"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"kind": "ConfigMap", "metadata": {"name": "app-config"}, "data": {"LOG_LEVEL": "debug"}})))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.update_configmap", "input": {"namespace": "default", "name": "app-config", "data": {"LOG_LEVEL": "debug"}}})).await.unwrap();
    assert_eq!(result["configmap"]["data"]["LOG_LEVEL"], "debug");
}

#[fcp_async_core::runtime::test]
async fn update_configmap_missing_data() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "kubernetes.update_configmap", "input": {"namespace": "default", "name": "app-config"}})).await.is_err());
}

// -- get_secret --

#[fcp_async_core::runtime::test]
async fn get_secret_redacted() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/secrets/db-credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Secret", "metadata": {"name": "db-credentials"}, "type": "Opaque",
            "data": {"username": "YWRtaW4=", "password": "c2VjcmV0"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_secret", "input": {"namespace": "default", "name": "db-credentials"}})).await.unwrap();
    assert!(result["secret"]["data"].is_null());
    assert_eq!(result["secret"]["data_keys"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn get_secret_unmasked() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/secrets/db-credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Secret", "metadata": {"name": "db-credentials"},
            "data": {"username": "YWRtaW4=", "password": "c2VjcmV0"}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({"operation_id": "kubernetes.get_secret", "input": {"namespace": "default", "name": "db-credentials", "unmask": true}})).await.unwrap();
    assert!(result["secret"]["data"].is_object());
}

// -- watch_events --

#[fcp_async_core::runtime::test]
async fn watch_events() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "EventList",
            "items": [{"reason": "Pulled", "message": "Successfully pulled image", "type": "Normal"}]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c
        .handle_invoke(
            json!({"operation_id": "kubernetes.watch_events", "input": {"namespace": "default"}}),
        )
        .await
        .unwrap();
    assert_eq!(result["events"].as_array().unwrap().len(), 1);
}

#[fcp_async_core::runtime::test]
async fn watch_events_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "kubernetes.watch_events", "input": {}}))
            .await
            .is_err()
    );
}

// -- create_pod --

#[fcp_async_core::runtime::test]
async fn create_pod() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/namespaces/default/pods"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "Pod",
            "metadata": {"name": "debug-pod", "namespace": "default"},
            "spec": {"containers": [{"name": "debug", "image": "busybox"}]}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({
        "operation_id": "kubernetes.create_pod",
        "input": {
            "namespace": "default",
            "name": "debug-pod",
            "spec": {"containers": [{"name": "debug", "image": "busybox"}]}
        }
    })).await.unwrap();
    assert_eq!(result["pod"]["metadata"]["name"], "debug-pod");
}

#[fcp_async_core::runtime::test]
async fn create_pod_with_labels() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "Pod",
            "metadata": {"name": "labeled-pod", "namespace": "default", "labels": {"app": "test"}},
            "spec": {"containers": [{"name": "app", "image": "nginx"}]}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({
        "operation_id": "kubernetes.create_pod",
        "input": {
            "namespace": "default",
            "name": "labeled-pod",
            "spec": {"containers": [{"name": "app", "image": "nginx"}]},
            "labels": {"app": "test"}
        }
    })).await.unwrap();
    assert_eq!(result["pod"]["metadata"]["name"], "labeled-pod");
}

#[fcp_async_core::runtime::test]
async fn create_pod_missing_spec() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({
        "operation_id": "kubernetes.create_pod",
        "input": {"namespace": "default", "name": "test-pod"}
    })).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn create_pod_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({
        "operation_id": "kubernetes.create_pod",
        "input": {"name": "test-pod", "spec": {"containers": []}}
    })).await.is_err());
}

// -- apply_deployment --

#[fcp_async_core::runtime::test]
async fn apply_deployment_create() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/apis/apps/v1/namespaces/default/deployments"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "kind": "Deployment",
            "metadata": {"name": "web-app", "namespace": "default"},
            "spec": {"replicas": 3}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({
        "operation_id": "kubernetes.apply_deployment",
        "input": {
            "namespace": "default",
            "name": "web-app",
            "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "web"}}, "template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "web", "image": "nginx"}]}}}
        }
    })).await.unwrap();
    assert_eq!(result["deployment"]["metadata"]["name"], "web-app");
}

#[fcp_async_core::runtime::test]
async fn apply_deployment_update() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path(
            "/apis/apps/v1/namespaces/default/deployments/web-app",
        ))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "Deployment",
            "metadata": {"name": "web-app", "namespace": "default"},
            "spec": {"replicas": 5}
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({
        "operation_id": "kubernetes.apply_deployment",
        "input": {
            "namespace": "default",
            "name": "web-app",
            "update": true,
            "spec": {"replicas": 5, "selector": {"matchLabels": {"app": "web"}}, "template": {"metadata": {"labels": {"app": "web"}}, "spec": {"containers": [{"name": "web", "image": "nginx:1.26"}]}}}
        }
    })).await.unwrap();
    assert_eq!(result["deployment"]["spec"]["replicas"], 5);
}

#[fcp_async_core::runtime::test]
async fn apply_deployment_missing_spec() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({
        "operation_id": "kubernetes.apply_deployment",
        "input": {"namespace": "default", "name": "web-app"}
    })).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn apply_deployment_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({
        "operation_id": "kubernetes.apply_deployment",
        "input": {"namespace": "default", "spec": {"replicas": 1}}
    })).await.is_err());
}

// -- delete_deployment --

#[fcp_async_core::runtime::test]
async fn delete_deployment() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path(
            "/apis/apps/v1/namespaces/default/deployments/old-app",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"kind": "Status", "status": "Success"})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({
        "operation_id": "kubernetes.delete_deployment",
        "input": {"namespace": "default", "name": "old-app"}
    })).await.unwrap();
    assert_eq!(result["deleted"], true);
}

#[fcp_async_core::runtime::test]
async fn delete_deployment_missing_name() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({
        "operation_id": "kubernetes.delete_deployment",
        "input": {"namespace": "default"}
    })).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn delete_deployment_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({
        "operation_id": "kubernetes.delete_deployment",
        "input": {"name": "old-app"}
    })).await.is_err());
}

// -- list_services --

#[fcp_async_core::runtime::test]
async fn list_services() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/services"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "ServiceList",
            "items": [
                {"metadata": {"name": "api-server"}, "spec": {"type": "ClusterIP"}},
                {"metadata": {"name": "frontend"}, "spec": {"type": "NodePort"}},
            ]
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({
        "operation_id": "kubernetes.list_services",
        "input": {"namespace": "default"}
    })).await.unwrap();
    assert_eq!(result["services"].as_array().unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn list_services_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/production/services"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kind": "ServiceList", "items": []
        })))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let result = c.handle_invoke(json!({
        "operation_id": "kubernetes.list_services",
        "input": {"namespace": "production"}
    })).await.unwrap();
    assert!(result["services"].as_array().unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn list_services_missing_namespace() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({
        "operation_id": "kubernetes.list_services",
        "input": {}
    })).await.is_err());
}

// -- simulate new ops --

#[fcp_async_core::runtime::test]
async fn simulate_create_pod() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.create_pod"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_apply_deployment() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.apply_deployment"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_delete_deployment() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.delete_deployment"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_list_services() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.list_services"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Error handling --

#[fcp_async_core::runtime::test]
async fn error_401() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(json!({"kind": "Status", "message": "Unauthorized", "code": 401})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_403() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/kube-system/pods"))
        .respond_with(
            ResponseTemplate::new(403).set_body_json(
                json!({"kind": "Status", "message": "pods is forbidden", "code": 403}),
            ),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "kube-system"}})
        )
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods/missing-pod"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"kind": "Status", "message": "pods not found", "code": 404})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(c.handle_invoke(json!({"operation_id": "kubernetes.get_pod", "input": {"namespace": "default", "name": "missing-pod"}})).await.is_err());
}

#[fcp_async_core::runtime::test]
async fn error_429() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(
                    json!({"kind": "Status", "message": "Too many requests", "code": 429}),
                )
                .insert_header("retry-after", "60"),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn error_500() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}})
        )
        .await
        .is_err()
    );
}

// -- Unknown op / Simulate --

#[fcp_async_core::runtime::test]
async fn unknown_operation() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_invoke(json!({"operation_id": "kubernetes.nope", "input": {}}))
            .await
            .is_err()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_known() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.list_pods"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_unknown() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        !c.handle_simulate(json!({"operation_id": "kubernetes.nope"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_delete_pod() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.delete_pod"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_get_secret() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.get_secret"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

#[fcp_async_core::runtime::test]
async fn simulate_watch_events() {
    let server = MockServer::start().await;
    let c = setup_connector(&server.uri()).await;
    assert!(
        c.handle_simulate(json!({"operation_id": "kubernetes.watch_events"}))
            .await
            .unwrap()["allowed"]
            .as_bool()
            .unwrap()
    );
}

// -- Counters --

#[fcp_async_core::runtime::test]
async fn counters_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"kind": "PodList", "items": []})),
        )
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    c.handle_invoke(
        json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}}),
    )
    .await
    .unwrap();
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 0);
}

#[fcp_async_core::runtime::test]
async fn counters_error_increment() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/namespaces/default/pods"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal error"))
        .mount(&server)
        .await;

    let c = setup_connector(&server.uri()).await;
    let _ = c
        .handle_invoke(
            json!({"operation_id": "kubernetes.list_pods", "input": {"namespace": "default"}}),
        )
        .await;
    let h = c.handle_health().await.unwrap();
    assert_eq!(h["requests"], 1);
    assert_eq!(h["errors"], 1);
}
