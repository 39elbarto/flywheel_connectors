//! Kubernetes API types.

use serde::{Deserialize, Serialize};

/// A Kubernetes namespace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    pub name: Option<String>,
    pub status: Option<String>,
    pub labels: Option<serde_json::Value>,
    pub creation_timestamp: Option<String>,
}

/// A Kubernetes pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pod {
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub status: Option<PodStatus>,
    pub labels: Option<serde_json::Value>,
    pub node_name: Option<String>,
    pub creation_timestamp: Option<String>,
}

/// Pod status information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodStatus {
    pub phase: Option<String>,
    pub conditions: Option<Vec<serde_json::Value>>,
    pub container_statuses: Option<Vec<ContainerStatus>>,
    pub host_ip: Option<String>,
    pub pod_ip: Option<String>,
}

/// Container status within a pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStatus {
    pub name: Option<String>,
    pub ready: Option<bool>,
    pub restart_count: Option<u32>,
    pub image: Option<String>,
    pub state: Option<serde_json::Value>,
}

/// A Kubernetes deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub spec: Option<DeploymentSpec>,
    pub labels: Option<serde_json::Value>,
    pub creation_timestamp: Option<String>,
}

/// Deployment spec subset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentSpec {
    pub replicas: Option<u32>,
    pub selector: Option<serde_json::Value>,
}

/// Kubernetes Scale sub-resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scale {
    pub kind: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub spec: Option<ScaleSpec>,
    pub status: Option<ScaleStatus>,
}

/// Scale spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaleSpec {
    pub replicas: Option<u32>,
}

/// Scale status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaleStatus {
    pub replicas: Option<u32>,
}

/// Rollout status for a deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutStatus {
    pub deployment_name: Option<String>,
    pub namespace: Option<String>,
    pub replicas: Option<u32>,
    pub updated_replicas: Option<u32>,
    pub ready_replicas: Option<u32>,
    pub available_replicas: Option<u32>,
    pub unavailable_replicas: Option<u32>,
    pub observed_generation: Option<u64>,
    pub conditions: Option<Vec<RolloutCondition>>,
    pub rollout_complete: bool,
}

/// A condition reported by the deployment controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutCondition {
    pub condition_type: Option<String>,
    pub status: Option<String>,
    pub reason: Option<String>,
    pub message: Option<String>,
    pub last_transition_time: Option<String>,
    pub last_update_time: Option<String>,
}

/// A single revision entry from rollout history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutRevision {
    pub revision: Option<u64>,
    pub name: Option<String>,
    pub creation_timestamp: Option<String>,
    pub replicas: Option<u32>,
    pub image: Option<String>,
    pub labels: Option<serde_json::Value>,
}

/// A Kubernetes service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub spec: Option<ServiceSpec>,
    pub labels: Option<serde_json::Value>,
    pub creation_timestamp: Option<String>,
}

/// Service spec subset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSpec {
    pub r#type: Option<String>,
    pub cluster_ip: Option<String>,
    pub ports: Option<Vec<serde_json::Value>>,
    pub selector: Option<serde_json::Value>,
}

/// A Kubernetes `ConfigMap`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigMap {
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub data: Option<serde_json::Value>,
    pub labels: Option<serde_json::Value>,
    pub creation_timestamp: Option<String>,
}

/// A Kubernetes `Secret` (metadata view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMeta {
    pub name: Option<String>,
    pub namespace: Option<String>,
    pub r#type: Option<String>,
    pub labels: Option<serde_json::Value>,
    pub creation_timestamp: Option<String>,
}

/// Result of an `exec` command in a pod container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Kubernetes API error response body (Status object).
///
/// Kubernetes returns `{"kind": "Status", "message": "...", "reason": "NotFound", "code": 404}` on errors.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorResponse {
    /// The error message from Kubernetes.
    pub message: Option<String>,
    /// The reason string (e.g., `"NotFound"`, `"Forbidden"`).
    pub reason: Option<String>,
    /// HTTP status code echoed in the body.
    pub code: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn namespace_roundtrip() {
        let ns: Namespace = serde_json::from_value(json!({
            "name": "default",
            "status": "Active",
            "labels": {"kubernetes.io/metadata.name": "default"},
            "creation_timestamp": "2024-01-01T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(ns.name, Some("default".into()));
        assert_eq!(ns.status, Some("Active".into()));
        assert!(ns.labels.is_some());
        let re = serde_json::to_value(&ns).unwrap();
        assert_eq!(re["name"], "default");
    }

    #[test]
    fn namespace_minimal() {
        let ns: Namespace = serde_json::from_value(json!({})).unwrap();
        assert!(ns.name.is_none());
        assert!(ns.status.is_none());
        assert!(ns.labels.is_none());
        assert!(ns.creation_timestamp.is_none());
    }

    #[test]
    fn pod_roundtrip() {
        let p: Pod = serde_json::from_value(json!({
            "name": "nginx-abc123",
            "namespace": "default",
            "status": {
                "phase": "Running",
                "host_ip": "10.0.0.1",
                "pod_ip": "172.16.0.5",
            },
            "labels": {"app": "nginx"},
            "node_name": "node-1",
            "creation_timestamp": "2024-01-15T12:00:00Z",
        }))
        .unwrap();
        assert_eq!(p.name, Some("nginx-abc123".into()));
        assert_eq!(p.namespace, Some("default".into()));
        assert!(p.status.is_some());
        let status = p.status.unwrap();
        assert_eq!(status.phase, Some("Running".into()));
        assert_eq!(status.pod_ip, Some("172.16.0.5".into()));
        assert_eq!(p.node_name, Some("node-1".into()));
    }

    #[test]
    fn pod_minimal() {
        let p: Pod = serde_json::from_value(json!({})).unwrap();
        assert!(p.name.is_none());
        assert!(p.namespace.is_none());
        assert!(p.status.is_none());
    }

    #[test]
    fn pod_status_with_containers() {
        let s: PodStatus = serde_json::from_value(json!({
            "phase": "Running",
            "container_statuses": [
                {
                    "name": "app",
                    "ready": true,
                    "restart_count": 0,
                    "image": "nginx:1.25",
                    "state": {"running": {"startedAt": "2024-01-15T12:00:00Z"}},
                }
            ],
        }))
        .unwrap();
        assert_eq!(s.phase, Some("Running".into()));
        assert_eq!(s.container_statuses.as_ref().unwrap().len(), 1);
        let c = &s.container_statuses.unwrap()[0];
        assert_eq!(c.name, Some("app".into()));
        assert_eq!(c.ready, Some(true));
        assert_eq!(c.restart_count, Some(0));
    }

    #[test]
    fn container_status_roundtrip() {
        let c: ContainerStatus = serde_json::from_value(json!({
            "name": "sidecar",
            "ready": false,
            "restart_count": 3,
            "image": "envoy:latest",
        }))
        .unwrap();
        assert_eq!(c.name, Some("sidecar".into()));
        assert_eq!(c.ready, Some(false));
        assert_eq!(c.restart_count, Some(3));
        assert_eq!(c.image, Some("envoy:latest".into()));
        let re = serde_json::to_value(&c).unwrap();
        assert_eq!(re["restart_count"], 3);
    }

    #[test]
    fn container_status_minimal() {
        let c: ContainerStatus = serde_json::from_value(json!({})).unwrap();
        assert!(c.name.is_none());
        assert!(c.ready.is_none());
    }

    #[test]
    fn deployment_roundtrip() {
        let d: Deployment = serde_json::from_value(json!({
            "name": "web-app",
            "namespace": "production",
            "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "web"}}},
            "labels": {"app": "web"},
            "creation_timestamp": "2024-02-01T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(d.name, Some("web-app".into()));
        assert_eq!(d.namespace, Some("production".into()));
        assert!(d.spec.is_some());
        let spec = d.spec.unwrap();
        assert_eq!(spec.replicas, Some(3));
        assert!(spec.selector.is_some());
    }

    #[test]
    fn deployment_minimal() {
        let d: Deployment = serde_json::from_value(json!({})).unwrap();
        assert!(d.name.is_none());
        assert!(d.namespace.is_none());
        assert!(d.spec.is_none());
    }

    #[test]
    fn deployment_spec_roundtrip() {
        let s: DeploymentSpec = serde_json::from_value(json!({
            "replicas": 5,
        }))
        .unwrap();
        assert_eq!(s.replicas, Some(5));
        assert!(s.selector.is_none());
    }

    #[test]
    fn scale_roundtrip() {
        let s: Scale = serde_json::from_value(json!({
            "kind": "Scale",
            "metadata": {"name": "web-app", "namespace": "default"},
            "spec": {"replicas": 3},
            "status": {"replicas": 3},
        }))
        .unwrap();
        assert_eq!(s.kind, Some("Scale".into()));
        assert_eq!(s.spec.as_ref().unwrap().replicas, Some(3));
        assert_eq!(s.status.as_ref().unwrap().replicas, Some(3));
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["spec"]["replicas"], 3);
    }

    #[test]
    fn scale_minimal() {
        let s: Scale = serde_json::from_value(json!({})).unwrap();
        assert!(s.kind.is_none());
        assert!(s.spec.is_none());
        assert!(s.status.is_none());
    }

    #[test]
    fn api_error_response_with_fields() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "kind": "Status",
            "message": "pods \"nginx\" not found",
            "reason": "NotFound",
            "code": 404,
        }))
        .unwrap();
        assert_eq!(e.message, Some("pods \"nginx\" not found".into()));
        assert_eq!(e.reason, Some("NotFound".into()));
        assert_eq!(e.code, Some(404));
    }

    #[test]
    fn api_error_response_empty() {
        let e: ApiErrorResponse = serde_json::from_value(json!({})).unwrap();
        assert!(e.message.is_none());
        assert!(e.reason.is_none());
        assert!(e.code.is_none());
    }

    #[test]
    fn api_error_response_message_only() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "Unauthorized",
        }))
        .unwrap();
        assert_eq!(e.message, Some("Unauthorized".into()));
        assert!(e.reason.is_none());
    }

    #[test]
    fn namespace_extra_fields_ignored() {
        let ns: Namespace = serde_json::from_value(json!({
            "name": "test",
            "unknown_field": "ignored",
        }))
        .unwrap();
        assert_eq!(ns.name, Some("test".into()));
    }

    #[test]
    fn pod_extra_fields_ignored() {
        let p: Pod = serde_json::from_value(json!({
            "name": "test",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(p.name, Some("test".into()));
    }

    #[test]
    fn deployment_extra_fields_ignored() {
        let d: Deployment = serde_json::from_value(json!({
            "name": "test",
            "unknown_field": true,
        }))
        .unwrap();
        assert_eq!(d.name, Some("test".into()));
    }

    #[test]
    fn pod_serialize_roundtrip() {
        let p = Pod {
            name: Some("nginx".into()),
            namespace: Some("default".into()),
            status: Some(PodStatus {
                phase: Some("Running".into()),
                conditions: None,
                container_statuses: None,
                host_ip: None,
                pod_ip: Some("10.0.0.1".into()),
            }),
            labels: None,
            node_name: None,
            creation_timestamp: None,
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["name"], "nginx");
        assert_eq!(v["status"]["phase"], "Running");
        assert_eq!(v["status"]["pod_ip"], "10.0.0.1");
    }

    #[test]
    fn namespace_clone() {
        let ns: Namespace = serde_json::from_value(json!({
            "name": "test",
            "status": "Active",
        }))
        .unwrap();
        let ns2 = ns.clone();
        assert_eq!(ns.name, ns2.name);
        assert_eq!(ns.status, ns2.status);
    }

    #[test]
    fn namespace_debug() {
        let ns: Namespace = serde_json::from_value(json!({"name": "test"})).unwrap();
        let dbg = format!("{ns:?}");
        assert!(dbg.contains("Namespace"));
    }

    #[test]
    fn pod_clone() {
        let p: Pod = serde_json::from_value(json!({"name": "nginx"})).unwrap();
        let p2 = p.clone();
        assert_eq!(p.name, p2.name);
    }

    #[test]
    fn pod_debug() {
        let p: Pod = serde_json::from_value(json!({"name": "nginx"})).unwrap();
        let dbg = format!("{p:?}");
        assert!(dbg.contains("Pod"));
    }

    #[test]
    fn pod_status_minimal() {
        let s: PodStatus = serde_json::from_value(json!({})).unwrap();
        assert!(s.phase.is_none());
        assert!(s.conditions.is_none());
        assert!(s.container_statuses.is_none());
        assert!(s.host_ip.is_none());
        assert!(s.pod_ip.is_none());
    }

    #[test]
    fn pod_status_clone() {
        let s: PodStatus = serde_json::from_value(json!({"phase": "Running"})).unwrap();
        let s2 = s.clone();
        assert_eq!(s.phase, s2.phase);
    }

    #[test]
    fn container_status_clone() {
        let c: ContainerStatus = serde_json::from_value(json!({"name": "app"})).unwrap();
        let c2 = c.clone();
        assert_eq!(c.name, c2.name);
    }

    #[test]
    fn deployment_clone() {
        let d: Deployment = serde_json::from_value(json!({"name": "web"})).unwrap();
        let d2 = d.clone();
        assert_eq!(d.name, d2.name);
    }

    #[test]
    fn deployment_debug() {
        let d: Deployment = serde_json::from_value(json!({"name": "web"})).unwrap();
        let dbg = format!("{d:?}");
        assert!(dbg.contains("Deployment"));
    }

    #[test]
    fn deployment_spec_minimal() {
        let s: DeploymentSpec = serde_json::from_value(json!({})).unwrap();
        assert!(s.replicas.is_none());
        assert!(s.selector.is_none());
    }

    #[test]
    fn scale_clone() {
        let s: Scale = serde_json::from_value(json!({"kind": "Scale"})).unwrap();
        let s2 = s.clone();
        assert_eq!(s.kind, s2.kind);
    }

    #[test]
    fn scale_spec_minimal() {
        let s: ScaleSpec = serde_json::from_value(json!({})).unwrap();
        assert!(s.replicas.is_none());
    }

    #[test]
    fn scale_status_minimal() {
        let s: ScaleStatus = serde_json::from_value(json!({})).unwrap();
        assert!(s.replicas.is_none());
    }

    #[test]
    fn api_error_response_clone() {
        let e: ApiErrorResponse = serde_json::from_value(json!({
            "message": "not found",
            "reason": "NotFound",
            "code": 404,
        }))
        .unwrap();
        let e2 = e.clone();
        assert_eq!(e.message, e2.message);
        assert_eq!(e.code, e2.code);
    }

    #[test]
    fn api_error_response_debug() {
        let e: ApiErrorResponse = serde_json::from_value(json!({"message": "err"})).unwrap();
        let dbg = format!("{e:?}");
        assert!(dbg.contains("ApiErrorResponse"));
    }

    // ── ConfigMap ──────────────────────────────────────────────────

    #[test]
    fn configmap_roundtrip() {
        let cm: ConfigMap = serde_json::from_value(json!({
            "name": "app-config",
            "namespace": "default",
            "data": {"LOG_LEVEL": "info", "DB_HOST": "postgres"},
            "labels": {"app": "web"},
            "creation_timestamp": "2024-06-01T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(cm.name, Some("app-config".into()));
        assert_eq!(cm.namespace, Some("default".into()));
        assert!(cm.data.is_some());
        let re = serde_json::to_value(&cm).unwrap();
        assert_eq!(re["name"], "app-config");
        assert_eq!(re["data"]["LOG_LEVEL"], "info");
    }

    #[test]
    fn configmap_minimal() {
        let cm: ConfigMap = serde_json::from_value(json!({})).unwrap();
        assert!(cm.name.is_none());
        assert!(cm.namespace.is_none());
        assert!(cm.data.is_none());
        assert!(cm.labels.is_none());
        assert!(cm.creation_timestamp.is_none());
    }

    #[test]
    fn configmap_clone() {
        let cm: ConfigMap = serde_json::from_value(json!({"name": "test"})).unwrap();
        let cm2 = cm.clone();
        assert_eq!(cm.name, cm2.name);
    }

    #[test]
    fn configmap_debug() {
        let cm: ConfigMap = serde_json::from_value(json!({"name": "test"})).unwrap();
        let dbg = format!("{cm:?}");
        assert!(dbg.contains("ConfigMap"));
    }

    #[test]
    fn configmap_extra_fields_ignored() {
        let cm: ConfigMap = serde_json::from_value(json!({
            "name": "test",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(cm.name, Some("test".into()));
    }

    // ── SecretMeta ───────────────────────────────────────────────

    #[test]
    fn secret_meta_roundtrip() {
        let s: SecretMeta = serde_json::from_value(json!({
            "name": "db-creds",
            "namespace": "production",
            "type": "Opaque",
            "labels": {"app": "db"},
            "creation_timestamp": "2024-06-01T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(s.name, Some("db-creds".into()));
        assert_eq!(s.namespace, Some("production".into()));
        assert_eq!(s.r#type, Some("Opaque".into()));
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["name"], "db-creds");
        assert_eq!(re["type"], "Opaque");
    }

    #[test]
    fn secret_meta_minimal() {
        let s: SecretMeta = serde_json::from_value(json!({})).unwrap();
        assert!(s.name.is_none());
        assert!(s.namespace.is_none());
        assert!(s.r#type.is_none());
    }

    #[test]
    fn secret_meta_clone() {
        let s: SecretMeta = serde_json::from_value(json!({"name": "test"})).unwrap();
        let s2 = s.clone();
        assert_eq!(s.name, s2.name);
    }

    #[test]
    fn secret_meta_debug() {
        let s: SecretMeta = serde_json::from_value(json!({"name": "test"})).unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SecretMeta"));
    }

    // ── ExecResult ───────────────────────────────────────────────

    #[test]
    fn exec_result_roundtrip() {
        let er: ExecResult = serde_json::from_value(json!({
            "stdout": "hello world\n",
            "stderr": "",
            "exit_code": 0,
        }))
        .unwrap();
        assert_eq!(er.stdout, "hello world\n");
        assert_eq!(er.stderr, "");
        assert_eq!(er.exit_code, 0);
        let re = serde_json::to_value(&er).unwrap();
        assert_eq!(re["exit_code"], 0);
    }

    #[test]
    fn exec_result_with_stderr() {
        let er: ExecResult = serde_json::from_value(json!({
            "stdout": "",
            "stderr": "command not found",
            "exit_code": 127,
        }))
        .unwrap();
        assert_eq!(er.stderr, "command not found");
        assert_eq!(er.exit_code, 127);
    }

    #[test]
    fn exec_result_clone() {
        let er: ExecResult = serde_json::from_value(json!({
            "stdout": "ok",
            "stderr": "",
            "exit_code": 0,
        }))
        .unwrap();
        let er2 = er.clone();
        assert_eq!(er.stdout, er2.stdout);
        assert_eq!(er.exit_code, er2.exit_code);
    }

    #[test]
    fn exec_result_debug() {
        let er: ExecResult = serde_json::from_value(json!({
            "stdout": "ok",
            "stderr": "",
            "exit_code": 0,
        }))
        .unwrap();
        let dbg = format!("{er:?}");
        assert!(dbg.contains("ExecResult"));
    }

    #[test]
    fn exec_result_negative_exit_code() {
        let er: ExecResult = serde_json::from_value(json!({
            "stdout": "",
            "stderr": "killed",
            "exit_code": -1,
        }))
        .unwrap();
        assert_eq!(er.exit_code, -1);
    }

    // ── Service ────────────────────────────────────────────────────

    #[test]
    fn service_roundtrip() {
        let s: Service = serde_json::from_value(json!({
            "name": "api-server",
            "namespace": "production",
            "spec": {
                "type": "ClusterIP",
                "cluster_ip": "10.96.0.1",
                "ports": [{"port": 80, "targetPort": 8080}],
                "selector": {"app": "api"}
            },
            "labels": {"app": "api"},
            "creation_timestamp": "2024-06-01T00:00:00Z",
        }))
        .unwrap();
        assert_eq!(s.name, Some("api-server".into()));
        assert_eq!(s.namespace, Some("production".into()));
        assert!(s.spec.is_some());
        let spec = s.spec.as_ref().unwrap();
        assert_eq!(spec.r#type, Some("ClusterIP".into()));
        assert_eq!(spec.cluster_ip, Some("10.96.0.1".into()));
        assert_eq!(spec.ports.as_ref().unwrap().len(), 1);
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["name"], "api-server");
    }

    #[test]
    fn service_minimal() {
        let s: Service = serde_json::from_value(json!({})).unwrap();
        assert!(s.name.is_none());
        assert!(s.namespace.is_none());
        assert!(s.spec.is_none());
        assert!(s.labels.is_none());
        assert!(s.creation_timestamp.is_none());
    }

    #[test]
    fn service_clone() {
        let s: Service = serde_json::from_value(json!({"name": "svc"})).unwrap();
        let s2 = s.clone();
        assert_eq!(s.name, s2.name);
    }

    #[test]
    fn service_debug() {
        let s: Service = serde_json::from_value(json!({"name": "svc"})).unwrap();
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Service"));
    }

    #[test]
    fn service_extra_fields_ignored() {
        let s: Service = serde_json::from_value(json!({
            "name": "test",
            "unknown_field": 42,
        }))
        .unwrap();
        assert_eq!(s.name, Some("test".into()));
    }

    #[test]
    fn service_spec_minimal() {
        let s: ServiceSpec = serde_json::from_value(json!({})).unwrap();
        assert!(s.r#type.is_none());
        assert!(s.cluster_ip.is_none());
        assert!(s.ports.is_none());
        assert!(s.selector.is_none());
    }

    #[test]
    fn service_spec_roundtrip() {
        let s: ServiceSpec = serde_json::from_value(json!({
            "type": "NodePort",
            "cluster_ip": "10.96.0.5",
            "ports": [{"port": 443}],
            "selector": {"app": "web"},
        }))
        .unwrap();
        assert_eq!(s.r#type, Some("NodePort".into()));
        assert_eq!(s.cluster_ip, Some("10.96.0.5".into()));
        assert_eq!(s.ports.as_ref().unwrap().len(), 1);
        let re = serde_json::to_value(&s).unwrap();
        assert_eq!(re["type"], "NodePort");
    }

    #[test]
    fn service_spec_clone() {
        let s: ServiceSpec = serde_json::from_value(json!({"type": "ClusterIP"})).unwrap();
        let s2 = s.clone();
        assert_eq!(s.r#type, s2.r#type);
    }

    #[test]
    fn service_serialize_roundtrip() {
        let s = Service {
            name: Some("my-svc".into()),
            namespace: Some("default".into()),
            spec: Some(ServiceSpec {
                r#type: Some("ClusterIP".into()),
                cluster_ip: Some("10.96.0.1".into()),
                ports: None,
                selector: None,
            }),
            labels: None,
            creation_timestamp: None,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["name"], "my-svc");
        assert_eq!(v["spec"]["type"], "ClusterIP");
    }

    #[test]
    fn pod_status_with_conditions() {
        let s: PodStatus = serde_json::from_value(json!({
            "phase": "Running",
            "conditions": [
                {"type": "Ready", "status": "True"},
                {"type": "ContainersReady", "status": "True"},
            ],
        }))
        .unwrap();
        assert_eq!(s.conditions.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn scale_serialize_roundtrip() {
        let s = Scale {
            kind: Some("Scale".into()),
            metadata: None,
            spec: Some(ScaleSpec { replicas: Some(5) }),
            status: Some(ScaleStatus { replicas: Some(5) }),
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["spec"]["replicas"], 5);
        assert_eq!(v["status"]["replicas"], 5);
    }
}
