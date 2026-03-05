//! Kubernetes API client.

use std::fmt;
use std::time::Duration;

use fcp_core::CredentialId;
use reqwest::{Client, Response, StatusCode};
use std::fmt::Write as _;
use tracing::{debug, instrument};

use crate::{
    error::{KubernetesError, KubernetesResult},
    types::ApiErrorResponse,
};

/// Default Kubernetes API base URL (in-cluster).
pub const DEFAULT_BASE_URL: &str = "https://kubernetes.default.svc";

/// Authentication mode for the Kubernetes API.
#[derive(Clone)]
pub enum KubernetesAuth {
    /// Bearer token (passed as `Authorization: Bearer <token>`).
    BearerToken(String),
    /// Secretless credential reference (egress proxy injection).
    CredentialId(CredentialId),
}

impl KubernetesAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::BearerToken(_) => "bearer_token:redacted".to_string(),
            Self::CredentialId(id) => format!("credential_id:{id}"),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for KubernetesAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BearerToken(_) => f.debug_tuple("BearerToken").field(&"<redacted>").finish(),
            Self::CredentialId(id) => f.debug_tuple("CredentialId").field(id).finish(),
        }
    }
}

/// Kubernetes API client.
pub struct KubernetesClient {
    client: Client,
    auth: KubernetesAuth,
    base_url: String,
}

impl fmt::Debug for KubernetesClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KubernetesClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl KubernetesClient {
    /// Create a new Kubernetes client.
    pub fn new(auth: KubernetesAuth, base_url: Option<&str>) -> KubernetesResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("fcp-kubernetes/0.1.0 (FCP connector)")
            .build()?;

        Ok(Self {
            client,
            auth,
            base_url: base_url
                .unwrap_or(DEFAULT_BASE_URL)
                .trim_end_matches('/')
                .to_string(),
        })
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            KubernetesAuth::BearerToken(token) => {
                req.header("Authorization", format!("Bearer {token}"))
            }
            KubernetesAuth::CredentialId(id) => {
                req.header("X-FCP-Credential-Id", id.to_string())
            }
        }
    }

    async fn handle_response(&self, resp: Response) -> KubernetesResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.text().await?;
            if body.is_empty() {
                return Ok(serde_json::json!({}));
            }
            Ok(serde_json::from_str(&body)?)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_text_response(&self, resp: Response) -> KubernetesResult<String> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp.text().await?)
        } else {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            let body = resp.text().await.unwrap_or_default();
            let detail = serde_json::from_str::<ApiErrorResponse>(&body)
                .ok()
                .and_then(|e| e.message)
                .unwrap_or_else(|| {
                    if body.is_empty() {
                        format!("HTTP {}", status.as_u16())
                    } else {
                        body.clone()
                    }
                });
            match status.as_u16() {
                401 => Err(KubernetesError::Unauthorized),
                403 => Err(KubernetesError::Forbidden),
                404 => Err(KubernetesError::NotFound { resource: detail }),
                429 => Err(KubernetesError::RateLimited {
                    retry_after_ms: retry_after.unwrap_or(60) * 1000,
                }),
                code => Err(KubernetesError::Api { status_code: code, message: detail }),
            }
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> KubernetesResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let body = resp.text().await.unwrap_or_default();

        let detail = serde_json::from_str::<ApiErrorResponse>(&body)
            .ok()
            .and_then(|e| e.message)
            .unwrap_or_else(|| {
                if body.is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    body.clone()
                }
            });

        match status.as_u16() {
            401 => Err(KubernetesError::Unauthorized),
            403 => Err(KubernetesError::Forbidden),
            404 => Err(KubernetesError::NotFound { resource: detail }),
            429 => Err(KubernetesError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60) * 1000,
            }),
            code => Err(KubernetesError::Api { status_code: code, message: detail }),
        }
    }

    #[instrument(skip(self), fields(url))]
    async fn get(&self, path: &str) -> KubernetesResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET request");
        let req = self
            .add_auth(self.client.get(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn get_text(&self, path: &str) -> KubernetesResult<String> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "GET text request");
        let req = self.add_auth(self.client.get(&url));
        let resp = req.send().await?;
        self.handle_text_response(resp).await
    }

    #[instrument(skip(self, body), fields(url))]
    async fn patch(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> KubernetesResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "PATCH request");
        let req = self
            .add_auth(self.client.patch(&url))
            .header("Accept", "application/json")
            .header("Content-Type", "application/strategic-merge-patch+json")
            .json(body);
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    #[instrument(skip(self), fields(url))]
    async fn delete(&self, path: &str) -> KubernetesResult<serde_json::Value> {
        let url = format!("{}{path}", self.base_url);
        debug!(url = %url, "DELETE request");
        let req = self
            .add_auth(self.client.delete(&url))
            .header("Accept", "application/json");
        let resp = req.send().await?;
        self.handle_response(resp).await
    }

    /// List all namespaces.
    pub async fn list_namespaces(&self) -> KubernetesResult<serde_json::Value> {
        self.get("/api/v1/namespaces").await
    }

    /// List pods in a namespace.
    pub async fn list_pods(
        &self,
        namespace: &str,
        label_selector: Option<&str>,
        field_selector: Option<&str>,
    ) -> KubernetesResult<serde_json::Value> {
        let mut path = format!("/api/v1/namespaces/{namespace}/pods");
        let mut params = Vec::new();
        if let Some(ls) = label_selector {
            params.push(format!("labelSelector={ls}"));
        }
        if let Some(fs) = field_selector {
            params.push(format!("fieldSelector={fs}"));
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        self.get(&path).await
    }

    /// Get a specific pod.
    pub async fn get_pod(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        self.get(&format!("/api/v1/namespaces/{namespace}/pods/{name}"))
            .await
    }

    /// Delete a pod.
    pub async fn delete_pod(
        &self,
        namespace: &str,
        name: &str,
        grace_period_seconds: Option<u64>,
    ) -> KubernetesResult<serde_json::Value> {
        let mut path = format!("/api/v1/namespaces/{namespace}/pods/{name}");
        if let Some(gp) = grace_period_seconds {
            let _ = write!(path, "?gracePeriodSeconds={gp}");
        }
        self.delete(&path).await
    }

    /// Get pod logs.
    pub async fn get_pod_logs(
        &self,
        namespace: &str,
        name: &str,
        container: Option<&str>,
        tail_lines: Option<u64>,
        since_seconds: Option<u64>,
    ) -> KubernetesResult<String> {
        let mut path = format!("/api/v1/namespaces/{namespace}/pods/{name}/log");
        let mut params = Vec::new();
        if let Some(c) = container {
            params.push(format!("container={c}"));
        }
        if let Some(t) = tail_lines {
            params.push(format!("tailLines={t}"));
        }
        if let Some(s) = since_seconds {
            params.push(format!("sinceSeconds={s}"));
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        self.get_text(&path).await
    }

    /// Stream pod logs (follow mode).
    pub async fn stream_pod_logs(
        &self,
        namespace: &str,
        name: &str,
        container: Option<&str>,
        tail_lines: Option<u64>,
    ) -> KubernetesResult<String> {
        let mut path = format!("/api/v1/namespaces/{namespace}/pods/{name}/log");
        let mut params = vec!["follow=true".to_string()];
        if let Some(c) = container {
            params.push(format!("container={c}"));
        }
        if let Some(t) = tail_lines {
            params.push(format!("tailLines={t}"));
        }
        path.push('?');
        path.push_str(&params.join("&"));
        self.get_text(&path).await
    }

    /// List deployments in a namespace.
    pub async fn list_deployments(
        &self,
        namespace: &str,
        label_selector: Option<&str>,
    ) -> KubernetesResult<serde_json::Value> {
        let mut path = format!("/apis/apps/v1/namespaces/{namespace}/deployments");
        if let Some(ls) = label_selector {
            let _ = write!(path, "?labelSelector={ls}");
        }
        self.get(&path).await
    }

    /// Get a specific deployment.
    pub async fn get_deployment(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        self.get(&format!(
            "/apis/apps/v1/namespaces/{namespace}/deployments/{name}"
        ))
        .await
    }

    /// Scale a deployment.
    pub async fn scale_deployment(
        &self,
        namespace: &str,
        name: &str,
        replicas: u32,
    ) -> KubernetesResult<serde_json::Value> {
        let body = serde_json::json!({
            "spec": {
                "replicas": replicas
            }
        });
        self.patch(
            &format!("/apis/apps/v1/namespaces/{namespace}/deployments/{name}/scale"),
            &body,
        )
        .await
    }

    /// Rollout restart a deployment.
    pub async fn rollout_restart(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        let now = epoch_timestamp();
        let body = serde_json::json!({
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": now
                        }
                    }
                }
            }
        });
        self.patch(
            &format!("/apis/apps/v1/namespaces/{namespace}/deployments/{name}"),
            &body,
        )
        .await
    }

    /// Get a service by name.
    pub async fn get_service(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        self.get(&format!("/api/v1/namespaces/{namespace}/services/{name}"))
            .await
    }

    /// Get a `ConfigMap` by name.
    pub async fn get_configmap(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        self.get(&format!(
            "/api/v1/namespaces/{namespace}/configmaps/{name}"
        ))
        .await
    }

    /// Update a `ConfigMap`.
    pub async fn update_configmap(
        &self,
        namespace: &str,
        name: &str,
        data: &serde_json::Value,
    ) -> KubernetesResult<serde_json::Value> {
        let body = serde_json::json!({
            "data": data
        });
        self.patch(
            &format!("/api/v1/namespaces/{namespace}/configmaps/{name}"),
            &body,
        )
        .await
    }

    /// Get a secret by name.
    pub async fn get_secret(
        &self,
        namespace: &str,
        name: &str,
    ) -> KubernetesResult<serde_json::Value> {
        self.get(&format!("/api/v1/namespaces/{namespace}/secrets/{name}"))
            .await
    }

    /// List events in a namespace.
    pub async fn list_events(
        &self,
        namespace: &str,
        field_selector: Option<&str>,
        resource_version: Option<&str>,
    ) -> KubernetesResult<serde_json::Value> {
        let mut path = format!("/api/v1/namespaces/{namespace}/events");
        let mut params = Vec::new();
        if let Some(fs) = field_selector {
            params.push(format!("fieldSelector={fs}"));
        }
        if let Some(rv) = resource_version {
            params.push(format!("resourceVersion={rv}"));
        }
        if !params.is_empty() {
            path.push('?');
            path.push_str(&params.join("&"));
        }
        self.get(&path).await
    }
}

fn epoch_timestamp() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_token() {
        let auth = KubernetesAuth::BearerToken("super-secret-token".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("super-secret-token"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let token = KubernetesAuth::BearerToken("tok".into());
        assert!(!token.is_secretless());
        let cred = KubernetesAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label() {
        let token = KubernetesAuth::BearerToken("tok".into());
        assert_eq!(token.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_label() {
        let cred = KubernetesAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert!(label.starts_with("credential_id:"));
    }

    #[test]
    fn client_new_default_url() {
        let client =
            KubernetesClient::new(KubernetesAuth::BearerToken("tok".into()), None).unwrap();
        assert_eq!(client.base_url, DEFAULT_BASE_URL);
    }

    #[test]
    fn client_new_custom_url() {
        let client = KubernetesClient::new(
            KubernetesAuth::BearerToken("tok".into()),
            Some("https://k8s.example.com/"),
        )
        .unwrap();
        assert_eq!(client.base_url, "https://k8s.example.com");
    }

    #[test]
    fn client_debug_redacts() {
        let client =
            KubernetesClient::new(KubernetesAuth::BearerToken("secret".into()), None).unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_bearer_clone() {
        let auth = KubernetesAuth::BearerToken("tok".into());
        let cloned = auth.clone();
        assert_eq!(auth.redacted_label(), "bearer_token:redacted");
        assert_eq!(cloned.redacted_label(), "bearer_token:redacted");
    }

    #[test]
    fn auth_credential_clone() {
        let auth = KubernetesAuth::CredentialId(CredentialId::new());
        let cloned = auth.clone();
        assert!(auth.is_secretless());
        assert!(cloned.is_secretless());
    }

    #[test]
    fn client_strips_trailing_slash() {
        let client = KubernetesClient::new(
            KubernetesAuth::BearerToken("tok".into()),
            Some("https://k8s.example.com///"),
        )
        .unwrap();
        assert!(!client.base_url.ends_with('/'));
    }

    #[test]
    fn client_debug_shows_base_url() {
        let client = KubernetesClient::new(
            KubernetesAuth::BearerToken("tok".into()),
            Some("https://my-cluster.example.com"),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("my-cluster.example.com"));
    }

    #[test]
    fn auth_debug_credential_shows_id() {
        let cred = KubernetesAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn epoch_timestamp_is_numeric() {
        let ts = epoch_timestamp();
        assert!(ts.parse::<u64>().is_ok(), "timestamp should be numeric: {ts}");
    }
}
