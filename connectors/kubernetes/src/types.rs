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
}
