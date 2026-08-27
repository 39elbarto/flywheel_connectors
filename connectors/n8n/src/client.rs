//! n8n API client.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use fcp_manifest::{
    Base64Bytes, HostEgressContext, HostEgressDecisionMetadata, HostEgressHttpHeader,
    HostEgressHttpRequest, HostEgressHttpResponse,
};
use fcp_prelude::CredentialId;
use fcp_sdk::migration::HostEgressProxyError;
#[cfg(test)]
use fcp_sdk::migration::InheritedChannelStage;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use reqwest::{Client, Method, Response, StatusCode, Url};
use serde::de::DeserializeOwned;
use tracing::{debug, instrument};

use crate::{
    error::{N8nError, N8nResult},
    types::{
        CredentialListResponse, Execution, ExecutionListResponse, Folder, FolderListResponse,
        ListResponse, ProjectListResponse, TagListResponse, WorkflowDetail, WorkflowListResponse,
    },
};

#[cfg(test)]
use crate::types::Workflow;

pub(crate) const DEFAULT_LIST_LIMIT: u64 = 50;
pub(crate) const MAX_LIST_LIMIT: u64 = 200;
pub(crate) const MAX_CURSOR_BYTES: usize = 4096;
const MAX_PROVIDER_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListQuery {
    pub(crate) limit: u64,
    pub(crate) cursor: Option<String>,
}

impl ListQuery {
    pub(crate) fn new(limit: u64, cursor: Option<String>) -> N8nResult<Self> {
        if !(1..=MAX_LIST_LIMIT).contains(&limit) {
            return Err(N8nError::InvalidInput(
                "list limit must be an integer from 1 through 200".into(),
            ));
        }
        if let Some(cursor) = cursor.as_deref() {
            validate_cursor(cursor)?;
        }
        Ok(Self { limit, cursor })
    }
}

pub(crate) fn validate_cursor(cursor: &str) -> N8nResult<()> {
    if !cursor_is_valid(cursor) {
        return Err(N8nError::InvalidInput(
            "list cursor must be a non-empty opaque string of at most 4096 UTF-8 bytes without control characters".into(),
        ));
    }
    Ok(())
}

fn validate_provider_cursor(cursor: &str) -> N8nResult<()> {
    if !cursor_is_valid(cursor) {
        return Err(N8nError::MalformedProviderResponse);
    }
    Ok(())
}

fn cursor_is_valid(cursor: &str) -> bool {
    !cursor.is_empty() && cursor.len() <= MAX_CURSOR_BYTES && !cursor.chars().any(char::is_control)
}

/// Authentication mode for the n8n API.
#[derive(Clone)]
pub enum N8nAuth {
    /// API key (passed as `X-N8N-API-KEY: <key>` header).
    ApiKey(String),
    /// Host-managed credential reference. The direct client never injects or
    /// transmits the referenced secret.
    CredentialId(CredentialId),
}

impl N8nAuth {
    #[must_use]
    pub fn redacted_label(&self) -> String {
        match self {
            Self::ApiKey(_) => "api_key:redacted".to_string(),
            Self::CredentialId(_) => "credential_id:redacted".to_string(),
        }
    }

    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

impl fmt::Debug for N8nAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiKey(_) => f.debug_tuple("ApiKey").field(&"<redacted>").finish(),
            Self::CredentialId(_) => f.debug_tuple("CredentialId").field(&"<redacted>").finish(),
        }
    }
}

/// n8n API client.
pub struct N8nClient {
    client: Client,
    auth: N8nAuth,
    base_url: Url,
    runtime: ConnectorRuntime,
}

impl fmt::Debug for N8nClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("N8nClient")
            .field("auth", &self.auth)
            .field("base_url", &self.base_url.as_str())
            .finish()
    }
}

impl N8nClient {
    /// Create a new n8n client.
    ///
    /// `base_url` is required for n8n (self-hosted).
    pub fn new(auth: N8nAuth, base_url: &str) -> N8nResult<Self> {
        let runtime_config = ConnectorRuntimeConfig::default()
            .with_request_timeout(Duration::from_secs(30))
            .with_host_egress_from_env()
            .map_err(|_| {
                N8nError::InvalidInput("invalid host egress launch configuration".into())
            })?;
        Self::new_with_runtime_config(auth, base_url, runtime_config)
    }

    /// Create a client with trusted host-supplied runtime configuration.
    pub(crate) fn new_with_runtime_config(
        auth: N8nAuth,
        base_url: &str,
        runtime_config: ConnectorRuntimeConfig,
    ) -> N8nResult<Self> {
        if runtime_config.request_timeout.is_zero() || runtime_config.connect_timeout.is_zero() {
            return Err(N8nError::InvalidInput(
                "runtime request and connect timeouts must be non-zero".into(),
            ));
        }
        let client = Client::builder()
            .connect_timeout(runtime_config.connect_timeout)
            .timeout(runtime_config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("fcp-n8n/0.1.0 (FCP connector)")
            .build()?;
        let base_url = Self::canonicalize_base_url(base_url)?;
        let base_url = Url::parse(&format!("{base_url}/")).map_err(|error| {
            N8nError::InvalidInput(format!("base_url could not be canonicalized: {error}"))
        })?;

        Ok(Self {
            client,
            auth,
            base_url,
            runtime: ConnectorRuntime::new(runtime_config),
        })
    }

    /// Canonicalize and validate the operator-approved n8n API root.
    pub fn canonicalize_base_url(base_url: &str) -> N8nResult<String> {
        let parsed = Url::parse(base_url.trim())
            .map_err(|_| N8nError::InvalidInput("base_url must be an absolute URL".into()))?;
        if parsed.username() != "" || parsed.password().is_some() {
            return Err(N8nError::InvalidInput(
                "base_url must not contain userinfo".into(),
            ));
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err(N8nError::InvalidInput(
                "base_url must not contain query or fragment".into(),
            ));
        }
        let Some(host) = parsed.host_str() else {
            return Err(N8nError::InvalidInput(
                "base_url must include a host".into(),
            ));
        };
        let local = is_loopback_host(host);
        let is_https = parsed.scheme() == "https";
        if !(is_https || (local && parsed.scheme() == "http")) {
            return Err(N8nError::InvalidInput(
                "base_url must use HTTPS; HTTP is allowed only for loopback tests".into(),
            ));
        }
        if !local && is_ip_literal(host) {
            return Err(N8nError::InvalidInput(
                "base_url must not use a non-loopback IP literal".into(),
            ));
        }
        let expected_port = if local { None } else { Some(443) };
        if let Some(port) = parsed.port()
            && Some(port) != expected_port
            && !local
        {
            return Err(N8nError::InvalidInput(
                "base_url must use port 443 for production HTTPS".into(),
            ));
        }
        let path = parsed.path().trim_end_matches('/');
        if path != "/api/v1" {
            return Err(N8nError::InvalidInput(
                "base_url path must be exactly /api/v1".into(),
            ));
        }
        if parsed.path().contains('%') {
            return Err(N8nError::InvalidInput(
                "base_url path must not contain percent-encoded ambiguity".into(),
            ));
        }

        let mut canonical = parsed;
        canonical.set_path("/api/v1");
        canonical.set_query(None);
        canonical.set_fragment(None);
        if canonical.port() == Some(443) {
            canonical.set_port(None).map_err(|()| {
                N8nError::InvalidInput("base_url port could not be canonicalized".into())
            })?;
        }
        Ok(canonical.to_string().trim_end_matches('/').to_string())
    }

    /// Trigger graceful shutdown.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
    }

    fn add_auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            N8nAuth::ApiKey(key) => req.header("X-N8N-API-KEY", key),
            // The host-mediated egress path owns credential resolution. This
            // direct client refuses CredentialId requests before this helper
            // is reached, and never forwards the reference to the provider.
            N8nAuth::CredentialId(_) => req,
        }
    }

    fn ensure_provider_egress_allowed(&self) -> N8nResult<()> {
        if matches!(self.auth, N8nAuth::CredentialId(_)) {
            return Err(N8nError::InvalidInput(
                "credential_id requires host-mediated secret injection; direct provider egress is unavailable".into(),
            ));
        }

        let is_loopback = self.base_url.host_str().is_some_and(is_loopback_host);
        if !is_loopback {
            return Err(N8nError::InvalidInput(
                "production n8n provider egress requires host-mediated network enforcement".into(),
            ));
        }
        Ok(())
    }

    async fn handle_response(&self, resp: Response) -> N8nResult<serde_json::Value> {
        let status = resp.status();
        if status.is_success() {
            let body = read_bounded_body(resp).await?;
            decode_success_body(status, &body)
        } else {
            self.handle_error(status, resp).await
        }
    }

    async fn handle_error(
        &self,
        status: StatusCode,
        resp: Response,
    ) -> N8nResult<serde_json::Value> {
        let retry_after = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        let _body = read_bounded_body(resp).await?;
        let detail = format!("n8n provider returned HTTP {}", status.as_u16());

        match status.as_u16() {
            401 => Err(N8nError::Unauthorized),
            403 => Err(N8nError::Forbidden),
            404 => Err(N8nError::NotFound {
                resource: "n8n resource".into(),
            }),
            429 => Err(N8nError::RateLimited {
                retry_after_ms: retry_after.unwrap_or(60).saturating_mul(1000),
            }),
            code => Err(N8nError::Api {
                status_code: code,
                message: detail,
            }),
        }
    }

    #[instrument(skip(self, path))]
    async fn get(&self, path: &str) -> N8nResult<serde_json::Value> {
        let url = self.resolve_path(path)?;
        self.get_url(url).await
    }

    #[instrument(skip(self, url))]
    async fn get_url(&self, url: Url) -> N8nResult<serde_json::Value> {
        self.ensure_provider_egress_allowed()?;
        debug!(has_query = url.query().is_some(), "GET request");
        let req = self
            .add_auth(self.client.get(url))
            .header("Accept", "application/json");
        let resp = req.send().await.map_err(|_| N8nError::Api {
            status_code: 502,
            message: "n8n provider transport failed".into(),
        })?;
        self.handle_response(resp).await
    }

    async fn get_url_with_context(
        &self,
        url: Url,
        context: Option<HostEgressContext>,
    ) -> N8nResult<serde_json::Value> {
        match (&self.auth, context) {
            (N8nAuth::ApiKey(_), _) => self.get_url(url).await,
            (N8nAuth::CredentialId(_), Some(context)) => self.get_url_mediated(url, context).await,
            (N8nAuth::CredentialId(_), None) => Err(N8nError::InvalidInput(
                "credential_id requires verified request attribution".into(),
            )),
        }
    }

    /// Perform the single provider mutation attempt used by the guarded draft
    /// state machine. Credential references route through the verified
    /// host-egress proxy; direct API-key requests remain loopback-test-only.
    async fn write_json(
        &self,
        method: Method,
        url: Url,
        body: &serde_json::Value,
        context: Option<HostEgressContext>,
        require_json_response: bool,
    ) -> N8nResult<serde_json::Value> {
        if matches!(self.auth, N8nAuth::CredentialId(_)) {
            let context = context.ok_or_else(|| {
                N8nError::InvalidInput("credential_id requires verified request attribution".into())
            })?;
            return self
                .write_json_mediated(method, url, body, context, require_json_response)
                .await;
        }
        self.ensure_provider_egress_allowed()?;
        let req = self
            .add_auth(self.client.request(method, url))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .json(body);
        let response = req.send().await.map_err(|_| N8nError::UnknownOutcome)?;
        let status = response.status();
        if !status.is_success() {
            if status.is_server_error() {
                let _ = read_bounded_body(response).await;
                return Err(N8nError::UnknownOutcome);
            }
            return self.handle_error(status, response).await;
        }
        let body = read_bounded_body(response)
            .await
            .map_err(|_| N8nError::UnknownOutcome)?;
        decode_write_success(status, &body, require_json_response)
    }

    /// Perform a single mutation request without a request body.  Lifecycle
    /// `unpublish` is intentionally sent this way; an empty JSON object would
    /// be a different provider contract and is therefore not substituted.
    async fn write_no_body(
        &self,
        method: Method,
        url: Url,
        context: Option<HostEgressContext>,
        require_json_response: bool,
    ) -> N8nResult<serde_json::Value> {
        if matches!(self.auth, N8nAuth::CredentialId(_)) {
            let context = context.ok_or_else(|| {
                N8nError::InvalidInput("credential_id requires verified request attribution".into())
            })?;
            let response = self
                .host_egress_http(
                    &url,
                    method,
                    vec![HostEgressHttpHeader {
                        name: "Accept".to_string(),
                        value: "application/json".to_string(),
                    }],
                    None,
                    context,
                    true,
                )
                .await?;
            let status =
                StatusCode::from_u16(response.status).map_err(|_| N8nError::UnknownOutcome)?;
            if status.is_server_error() {
                return Err(N8nError::UnknownOutcome);
            }
            if status.is_success() {
                return decode_write_success(
                    status,
                    response.body.as_bytes(),
                    require_json_response,
                );
            }
            return decode_mediated_response(&response);
        }

        self.ensure_provider_egress_allowed()?;
        let response = self
            .add_auth(self.client.request(method, url))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|_| N8nError::UnknownOutcome)?;
        let status = response.status();
        if !status.is_success() {
            if status.is_server_error() {
                let _ = read_bounded_body(response).await;
                return Err(N8nError::UnknownOutcome);
            }
            return self.handle_error(status, response).await;
        }
        let body = read_bounded_body(response)
            .await
            .map_err(|_| N8nError::UnknownOutcome)?;
        decode_write_success(status, &body, require_json_response)
    }

    async fn write_json_mediated(
        &self,
        method: Method,
        url: Url,
        body: &serde_json::Value,
        context: HostEgressContext,
        require_json_response: bool,
    ) -> N8nResult<serde_json::Value> {
        let body = serde_json::to_vec(body)?;
        let response = self
            .host_egress_http(
                &url,
                method,
                vec![
                    HostEgressHttpHeader {
                        name: "Accept".to_string(),
                        value: "application/json".to_string(),
                    },
                    HostEgressHttpHeader {
                        name: "Content-Type".to_string(),
                        value: "application/json".to_string(),
                    },
                ],
                Some(Base64Bytes::from_vec(body)),
                context,
                true,
            )
            .await?;
        let status = StatusCode::from_u16(response.status).map_err(|_| N8nError::UnknownOutcome)?;
        if status.is_server_error() {
            return Err(N8nError::UnknownOutcome);
        }
        if status.is_success() {
            return decode_write_success(status, response.body.as_bytes(), require_json_response);
        }
        decode_mediated_response(&response)
    }

    async fn host_egress_http(
        &self,
        url: &Url,
        method: Method,
        headers: Vec<HostEgressHttpHeader>,
        body: Option<Base64Bytes>,
        context: HostEgressContext,
        write: bool,
    ) -> N8nResult<HostEgressHttpResponse> {
        let credential_id = match &self.auth {
            N8nAuth::CredentialId(credential_id) => credential_id,
            N8nAuth::ApiKey(_) => {
                return Err(N8nError::InvalidInput(
                    "host-mediated egress requires credential_id auth".into(),
                ));
            }
        };
        let proxy = self
            .runtime
            .host_egress_proxy_client()
            .map_err(|_| {
                N8nError::InvalidInput("trusted host egress proxy configuration is invalid".into())
            })?
            .ok_or_else(|| {
                N8nError::InvalidInput(
                    "credential_id requires the trusted host egress proxy configuration".into(),
                )
            })?;
        let request = HostEgressHttpRequest {
            context: context.clone(),
            url: url.to_string(),
            method: method.as_str().to_string(),
            headers,
            body,
            credential_id: Some(credential_id.to_string()),
        };
        let response = proxy.http(&request).await.map_err(|error| {
            if write {
                N8nError::UnknownOutcome
            } else {
                map_host_egress_error(&error)
            }
        })?;
        validate_host_egress_decision(&response.egress, &context, url).map_err(|_| {
            if write {
                N8nError::UnknownOutcome
            } else {
                N8nError::MalformedProviderResponse
            }
        })?;
        Ok(response)
    }

    async fn get_url_mediated(
        &self,
        url: Url,
        context: HostEgressContext,
    ) -> N8nResult<serde_json::Value> {
        let response = self
            .host_egress_http(
                &url,
                Method::GET,
                vec![HostEgressHttpHeader {
                    name: "Accept".to_string(),
                    value: "application/json".to_string(),
                }],
                None,
                context,
                false,
            )
            .await?;
        decode_mediated_response(&response)
    }

    fn resolve_path(&self, path: &str) -> N8nResult<Url> {
        if !path.starts_with('/')
            || path.contains("..")
            || path.contains('\\')
            || path.contains('?')
            || path.contains('#')
        {
            return Err(N8nError::InvalidInput(
                "provider path is not a safe connector-owned path".into(),
            ));
        }
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|_| N8nError::InvalidInput("provider path could not be resolved".into()))
    }

    fn resolve_path_segments(&self, segments: &[(&str, &str)]) -> N8nResult<Url> {
        let mut url = self.base_url.clone();
        let mut path_segments = url
            .path_segments_mut()
            .map_err(|()| N8nError::InvalidInput("provider path could not be resolved".into()))?;
        path_segments.pop_if_empty();
        for (field, value) in segments {
            let value = sanitize_path_segment(value, field)?;
            path_segments.push(value);
        }
        drop(path_segments);
        Ok(url)
    }

    // -- Workflows --

    /// List all workflows.
    async fn list_workflows(
        &self,
        query: &ListQuery,
        context: Option<HostEgressContext>,
    ) -> N8nResult<serde_json::Value> {
        let mut url = self.resolve_path("/workflows")?;
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("limit", &query.limit.to_string());
            if let Some(cursor) = query.cursor.as_deref() {
                query_pairs.append_pair("cursor", cursor);
            }
            query_pairs.append_pair("excludePinnedData", "true");
        }
        self.get_url_with_context(url, context).await
    }

    /// Perform a bounded read-only readiness probe and discard provider data.
    pub async fn self_check(&self) -> N8nResult<()> {
        let mut url = self.resolve_path("/workflows")?;
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("limit", "1");
            query_pairs.append_pair("excludePinnedData", "true");
        }
        let response = self.get_url(url).await?;
        let _ = response;
        Ok(())
    }

    /// Get a specific workflow by ID.
    async fn get_workflow(
        &self,
        id: &str,
        context: Option<HostEgressContext>,
    ) -> N8nResult<serde_json::Value> {
        let url =
            self.resolve_path_segments(&[("path segment", "workflows"), ("workflow id", id)])?;
        self.get_url_with_context(url, context).await
    }

    // -- Executions --

    /// List recent executions.
    async fn list_executions(
        &self,
        query: &ListQuery,
        context: Option<HostEgressContext>,
    ) -> N8nResult<serde_json::Value> {
        let mut url = self.resolve_path("/executions")?;
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("limit", &query.limit.to_string());
            if let Some(cursor) = query.cursor.as_deref() {
                query_pairs.append_pair("cursor", cursor);
            }
            query_pairs.append_pair("includeData", "false");
            query_pairs.append_pair("ignoreDataSizeLimit", "false");
            query_pairs.append_pair("redactExecutionData", "true");
        }
        self.get_url_with_context(url, context).await
    }

    // -- Projects --

    /// List projects with the shared bounded pagination query.
    async fn list_projects(
        &self,
        query: &ListQuery,
        context: Option<HostEgressContext>,
    ) -> N8nResult<serde_json::Value> {
        let mut url = self.resolve_path("/projects")?;
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("limit", &query.limit.to_string());
            if let Some(cursor) = query.cursor.as_deref() {
                query_pairs.append_pair("cursor", cursor);
            }
        }
        self.get_url_with_context(url, context).await
    }

    // -- Credentials --

    /// List safe credential metadata without requesting credential values.
    async fn list_credentials(
        &self,
        query: &ListQuery,
        context: Option<HostEgressContext>,
    ) -> N8nResult<serde_json::Value> {
        let mut url = self.resolve_path("/credentials")?;
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("limit", &query.limit.to_string());
            if let Some(cursor) = query.cursor.as_deref() {
                query_pairs.append_pair("cursor", cursor);
            }
        }
        self.get_url_with_context(url, context).await
    }

    // -- Tags --

    /// List tags with the shared bounded pagination query.
    async fn list_tags(
        &self,
        query: &ListQuery,
        context: Option<HostEgressContext>,
    ) -> N8nResult<serde_json::Value> {
        let mut url = self.resolve_path("/tags")?;
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("limit", &query.limit.to_string());
            if let Some(cursor) = query.cursor.as_deref() {
                query_pairs.append_pair("cursor", cursor);
            }
        }
        self.get_url_with_context(url, context).await
    }

    // -- Folders --

    /// List folders within a project using n8n's folder-specific pagination.
    async fn list_folders(
        &self,
        project_id: &str,
        parent_folder_id: Option<&str>,
        skip: u64,
        take: u64,
        context: Option<HostEgressContext>,
    ) -> N8nResult<serde_json::Value> {
        if !(1..=200).contains(&take) {
            return Err(N8nError::InvalidInput(
                "folder take must be an integer from 1 through 200".into(),
            ));
        }
        let parent_folder_id = parent_folder_id
            .map(|id| sanitize_path_segment(id, "parent folder id"))
            .transpose()?;
        let mut url = self.resolve_path_segments(&[
            ("path segment", "projects"),
            ("project id", project_id),
            ("path segment", "folders"),
        ])?;
        {
            let mut query_pairs = url.query_pairs_mut();
            query_pairs.append_pair("select", r#"["id","name","parentFolder"]"#);
            if let Some(parent_folder_id) = parent_folder_id {
                let filter = serde_json::to_string(&serde_json::json!({
                    "parentFolderId": parent_folder_id,
                }))?;
                query_pairs.append_pair("filter", &filter);
            }
            query_pairs.append_pair("skip", &skip.to_string());
            query_pairs.append_pair("take", &take.to_string());
        }
        self.get_url_with_context(url, context).await
    }

    /// Get a specific folder within a project.
    async fn get_folder(
        &self,
        project_id: &str,
        folder_id: &str,
        context: Option<HostEgressContext>,
    ) -> N8nResult<serde_json::Value> {
        let url = self.resolve_path_segments(&[
            ("path segment", "projects"),
            ("project id", project_id),
            ("path segment", "folders"),
            ("folder id", folder_id),
        ])?;
        self.get_url_with_context(url, context).await
    }

    /// Get a specific execution by ID.
    async fn get_execution(
        &self,
        id: &str,
        context: Option<HostEgressContext>,
    ) -> N8nResult<serde_json::Value> {
        let url =
            self.resolve_path_segments(&[("path segment", "executions"), ("execution id", id)])?;
        self.get_url_with_context(url, context).await
    }

    /// List workflows using the typed provider DTO layer.
    ///
    /// This wrapper preserves [`Self::list_workflows`] and its exact provider
    /// route while making the response shape explicit for future normalization.
    pub(crate) async fn list_workflows_typed(
        &self,
        query: &ListQuery,
        context: Option<HostEgressContext>,
    ) -> N8nResult<WorkflowListResponse> {
        decode_list_typed(self.list_workflows(query, context).await?)
    }

    /// Get a workflow using the typed provider DTO layer.
    pub(crate) async fn get_workflow_typed(
        &self,
        id: &str,
        context: Option<HostEgressContext>,
    ) -> N8nResult<WorkflowDetail> {
        decode_typed(self.get_workflow(id, context).await?)
    }

    /// Publish one workflow through the proven official route.  The response
    /// is decoded before the caller performs its independent GET readback.
    pub(crate) async fn publish_workflow(
        &self,
        id: &str,
        version_id: Option<&str>,
        context: Option<HostEgressContext>,
    ) -> N8nResult<WorkflowDetail> {
        let url = self.resolve_path_segments(&[
            ("path segment", "workflows"),
            ("workflow id", id),
            ("path segment", "publish"),
        ])?;
        let response = match version_id {
            Some(version_id) => {
                self.write_json(
                    Method::POST,
                    url,
                    &serde_json::json!({"versionId": version_id}),
                    context,
                    true,
                )
                .await?
            }
            None => self.write_no_body(Method::POST, url, context, true).await?,
        };
        decode_typed(response)
    }

    /// Unpublish one workflow through the proven official route.  The request
    /// deliberately has no body and the typed response is required.
    pub(crate) async fn unpublish_workflow(
        &self,
        id: &str,
        context: Option<HostEgressContext>,
    ) -> N8nResult<WorkflowDetail> {
        let url = self.resolve_path_segments(&[
            ("path segment", "workflows"),
            ("workflow id", id),
            ("path segment", "unpublish"),
        ])?;
        let response = self.write_no_body(Method::POST, url, context, true).await?;
        decode_typed(response)
    }

    /// Delete one disposable workflow through the exact REST route.  The
    /// caller performs an independent GET afterwards; a transport error or
    /// malformed 2xx response is therefore an unknown outcome.
    pub(crate) async fn delete_workflow_disposable(
        &self,
        id: &str,
        context: Option<HostEgressContext>,
    ) -> N8nResult<WorkflowDetail> {
        let url =
            self.resolve_path_segments(&[("path segment", "workflows"), ("workflow id", id)])?;
        let response = self
            .write_no_body(Method::DELETE, url, context, true)
            .await?;
        decode_typed(response)
    }

    /// Attempt one draft create and return only the provider-assigned ID.
    pub(crate) async fn create_workflow_draft(
        &self,
        payload: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> N8nResult<String> {
        let url = self.resolve_path("/workflows")?;
        let response = self
            .write_json(Method::POST, url, payload, context, true)
            .await?;
        response
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .ok_or(N8nError::UnknownOutcome)
    }

    /// Attempt one draft update.  n8n's REST surface uses `PUT` for the
    /// workflow resource; the independent GET readback happens in the caller.
    pub(crate) async fn update_workflow_draft(
        &self,
        id: &str,
        payload: &serde_json::Value,
        context: Option<HostEgressContext>,
    ) -> N8nResult<()> {
        let url =
            self.resolve_path_segments(&[("path segment", "workflows"), ("workflow id", id)])?;
        let _ = self
            .write_json(Method::PUT, url, payload, context, false)
            .await?;
        Ok(())
    }

    /// Change only the allow-listed official MCP availability setting.
    ///
    /// n8n's public workflow PUT requires the workflow name, nodes,
    /// connections, and settings even for a settings-only change. Build the
    /// provider payload from the already verified detail read, preserving
    /// static/pinned data when present. Lifecycle and published-version fields
    /// are deliberately never sent; the caller performs independent detail
    /// reads before and after this single provider attempt.
    pub(crate) async fn update_workflow_mcp_access(
        &self,
        detail: &WorkflowDetail,
        desired: bool,
        context: Option<HostEgressContext>,
    ) -> N8nResult<()> {
        let url = self
            .resolve_path_segments(&[("path segment", "workflows"), ("workflow id", &detail.id)])?;
        let name = detail
            .name
            .clone()
            .ok_or(N8nError::MalformedProviderResponse)?;
        let mut settings = match detail.settings.clone() {
            None | Some(serde_json::Value::Null) => serde_json::Map::new(),
            Some(serde_json::Value::Object(settings)) => settings,
            Some(_) => return Err(N8nError::MalformedProviderResponse),
        };
        settings.insert("availableInMCP".into(), serde_json::Value::Bool(desired));
        let mut payload = serde_json::json!({
            "name": name,
            "nodes": detail.nodes,
            "connections": detail.connections,
            "settings": settings,
        });
        if let Some(static_data) = &detail.static_data {
            payload["staticData"] = static_data.clone();
        }
        if let Some(pin_data) = &detail.pin_data {
            payload["pinData"] = pin_data.clone();
        }
        let _ = self
            .write_json(Method::PUT, url, &payload, context, false)
            .await?;
        Ok(())
    }

    /// List executions using the typed provider DTO layer.
    pub(crate) async fn list_executions_typed(
        &self,
        query: &ListQuery,
        context: Option<HostEgressContext>,
    ) -> N8nResult<ExecutionListResponse> {
        decode_list_typed(self.list_executions(query, context).await?)
    }

    /// List projects using the typed provider DTO layer.
    pub(crate) async fn list_projects_typed(
        &self,
        query: &ListQuery,
        context: Option<HostEgressContext>,
    ) -> N8nResult<ProjectListResponse> {
        decode_list_typed(self.list_projects(query, context).await?)
    }

    /// List credential metadata using the typed provider DTO layer.
    pub(crate) async fn list_credentials_typed(
        &self,
        query: &ListQuery,
        context: Option<HostEgressContext>,
    ) -> N8nResult<CredentialListResponse> {
        decode_list_typed(self.list_credentials(query, context).await?)
    }

    /// List tags using the typed provider DTO layer.
    pub(crate) async fn list_tags_typed(
        &self,
        query: &ListQuery,
        context: Option<HostEgressContext>,
    ) -> N8nResult<TagListResponse> {
        decode_list_typed(self.list_tags(query, context).await?)
    }

    /// List folders using the typed provider DTO layer.
    pub(crate) async fn list_folders_typed(
        &self,
        project_id: &str,
        parent_folder_id: Option<&str>,
        skip: u64,
        take: u64,
        context: Option<HostEgressContext>,
    ) -> N8nResult<FolderListResponse> {
        decode_typed(
            self.list_folders(project_id, parent_folder_id, skip, take, context)
                .await?,
        )
    }

    /// Get a folder using the typed provider DTO layer.
    pub(crate) async fn get_folder_typed(
        &self,
        project_id: &str,
        folder_id: &str,
        context: Option<HostEgressContext>,
    ) -> N8nResult<Folder> {
        decode_typed(self.get_folder(project_id, folder_id, context).await?)
    }

    /// Get an execution using the typed provider DTO layer.
    pub(crate) async fn get_execution_typed(
        &self,
        id: &str,
        context: Option<HostEgressContext>,
    ) -> N8nResult<Execution> {
        decode_typed(self.get_execution(id, context).await?)
    }
}

async fn read_bounded_body(mut response: Response) -> N8nResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(N8nError::MalformedProviderResponse);
    }

    let mut body = Vec::with_capacity(
        response
            .content_length()
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or_default()
            .min(MAX_PROVIDER_RESPONSE_BYTES),
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| N8nError::MalformedProviderResponse)?
    {
        if chunk.len() > MAX_PROVIDER_RESPONSE_BYTES.saturating_sub(body.len()) {
            return Err(N8nError::MalformedProviderResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn map_host_egress_error(error: &HostEgressProxyError) -> N8nError {
    let message = match error {
        HostEgressProxyError::Transport(_) => "host egress proxy transport failed",
        HostEgressProxyError::InheritedChannel => "host egress proxy inherited channel failed",
        HostEgressProxyError::InheritedChannelStage(stage) => stage.fixed_message(),
        HostEgressProxyError::RequestEnvelopeTooLarge => {
            "host egress proxy request exceeded the configured limit"
        }
        HostEgressProxyError::MalformedRequestEnvelope => {
            "host egress proxy request envelope was malformed"
        }
        HostEgressProxyError::EnvelopeTooLarge => {
            "host egress proxy response exceeded the configured limit"
        }
        HostEgressProxyError::MalformedEnvelope => {
            "host egress proxy returned a malformed response envelope"
        }
        HostEgressProxyError::Rejected { .. } => "host egress proxy rejected mediated request",
    };
    N8nError::Api {
        status_code: 502,
        message: message.into(),
    }
}

fn validate_host_egress_decision(
    decision: &HostEgressDecisionMetadata,
    context: &HostEgressContext,
    target: &Url,
) -> N8nResult<()> {
    let expected_host = target
        .host_str()
        .ok_or(N8nError::MalformedProviderResponse)?;
    let expected_port = target
        .port_or_known_default()
        .ok_or(N8nError::MalformedProviderResponse)?;
    if decision.connector_id != context.connector_id
        || decision.operation_id != context.operation_id
        || decision.zone_id != context.zone_id
        || decision.request_id != context.request_id
        || decision.correlation_id != context.correlation_id
        || decision.execution_mode != "host_egress_proxy"
        || decision.constraint_source != "managed_connector_config.operation_network_constraints"
        || decision.decision != "allow"
        || decision.resolved_host != expected_host
        || decision.resolved_port != expected_port
        || !decision.credential_injected
    {
        return Err(N8nError::MalformedProviderResponse);
    }
    Ok(())
}

fn decode_mediated_response(response: &HostEgressHttpResponse) -> N8nResult<serde_json::Value> {
    if response.body.as_bytes().len() > MAX_PROVIDER_RESPONSE_BYTES {
        return Err(N8nError::MalformedProviderResponse);
    }
    let status =
        StatusCode::from_u16(response.status).map_err(|_| N8nError::MalformedProviderResponse)?;
    if status.is_success() {
        return decode_success_body(status, response.body.as_bytes());
    }

    let retry_after = response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("retry-after"))
        .and_then(|header| header.value.parse::<u64>().ok());
    map_provider_status(status.as_u16(), retry_after)
}

fn map_provider_status(
    status_code: u16,
    retry_after_seconds: Option<u64>,
) -> N8nResult<serde_json::Value> {
    match status_code {
        401 => Err(N8nError::Unauthorized),
        403 => Err(N8nError::Forbidden),
        404 => Err(N8nError::NotFound {
            resource: "n8n resource".into(),
        }),
        429 => Err(N8nError::RateLimited {
            retry_after_ms: retry_after_seconds.unwrap_or(60).saturating_mul(1000),
        }),
        code => Err(N8nError::Api {
            status_code: code,
            message: format!("n8n provider returned HTTP {code}"),
        }),
    }
}

fn decode_typed<T>(value: serde_json::Value) -> N8nResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value).map_err(|_| N8nError::MalformedProviderResponse)
}

fn decode_list_typed<T>(value: serde_json::Value) -> N8nResult<ListResponse<T>>
where
    T: DeserializeOwned,
{
    let page: ListResponse<T> = decode_typed(value)?;
    if let Some(cursor) = page.next_cursor.as_deref() {
        validate_provider_cursor(cursor)?;
    }
    Ok(page)
}

pub(crate) fn sanitize_path_segment<'a>(value: &'a str, field: &str) -> N8nResult<&'a str> {
    if value.trim().is_empty() || value != value.trim() {
        return Err(N8nError::InvalidInput(format!(
            "{field} must be a non-empty single path segment"
        )));
    }

    let lower = value.to_ascii_lowercase();
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.contains('?')
        || value.contains('#')
        || value.contains('&')
        || value.contains('=')
        || value.contains('%')
        || value.chars().any(char::is_control)
        || lower.contains("%2f")
        || lower.contains("%5c")
    {
        return Err(N8nError::InvalidInput(format!(
            "{field} contains path traversal characters"
        )));
    }

    Ok(value)
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
}

fn is_ip_literal(host: &str) -> bool {
    host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok()
}

fn decode_success_body(status: StatusCode, body: &[u8]) -> N8nResult<serde_json::Value> {
    if status == StatusCode::NO_CONTENT {
        return Ok(serde_json::json!({}));
    }
    if body.iter().all(u8::is_ascii_whitespace) {
        return Err(N8nError::Api {
            status_code: status.as_u16(),
            message: "empty response body".into(),
        });
    }
    serde_json::from_slice(body).map_err(|_| N8nError::MalformedProviderResponse)
}

fn decode_write_success(
    status: StatusCode,
    body: &[u8],
    require_json_response: bool,
) -> N8nResult<serde_json::Value> {
    if !require_json_response {
        return Ok(serde_json::json!({}));
    }
    decode_success_body(status, body).map_err(|_| N8nError::UnknownOutcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_key() {
        let auth = N8nAuth::ApiKey("secret-api-key-12345".into());
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret-api-key-12345"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_secretless_detection() {
        let key = N8nAuth::ApiKey("key".into());
        assert!(!key.is_secretless());
        let cred = N8nAuth::CredentialId(CredentialId::new());
        assert!(cred.is_secretless());
    }

    #[test]
    fn auth_redacted_label_api_key() {
        let key = N8nAuth::ApiKey("key".into());
        assert_eq!(key.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn auth_redacted_label_credential() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert_eq!(label, "credential_id:redacted");
    }

    #[test]
    fn credential_auth_debug_redacts_reference() {
        let id = CredentialId::new();
        let id_text = id.to_string();
        let debug = format!("{:?}", N8nAuth::CredentialId(id));
        assert!(!debug.contains(&id_text));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn decode_success_body_rejects_empty_ok() {
        let err = decode_success_body(StatusCode::OK, b"").unwrap_err();
        assert!(matches!(
            err,
            N8nError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_rejects_whitespace_ok() {
        let err = decode_success_body(StatusCode::OK, b"  \n\t").unwrap_err();
        assert!(matches!(
            err,
            N8nError::Api {
                status_code: 200,
                message
            } if message == "empty response body"
        ));
    }

    #[test]
    fn decode_success_body_allows_empty_no_content() {
        assert_eq!(
            decode_success_body(StatusCode::NO_CONTENT, b"").unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn update_acknowledgement_accepts_empty_success_before_independent_readback() {
        assert_eq!(
            decode_write_success(StatusCode::OK, b"", false).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn create_response_still_requires_provider_json() {
        assert!(matches!(
            decode_write_success(StatusCode::OK, b"", true),
            Err(N8nError::UnknownOutcome)
        ));
    }

    #[test]
    fn typed_decoder_uses_provider_dto_layer() {
        let page: WorkflowListResponse = decode_typed(serde_json::json!({
            "data": [{
                "id": "1001",
                "name": "Daily Report",
                "versionId": "version-1001",
            }],
            "nextCursor": "cursor-1",
        }))
        .unwrap();
        assert_eq!(page.data.len(), 1);
        assert_eq!(page.data[0].id, "1001");
        assert_eq!(page.data[0].version_id, Some("version-1001".into()));
        assert_eq!(page.next_cursor, Some("cursor-1".into()));
    }

    #[test]
    fn typed_project_decoder_preserves_only_project_contract_fields() {
        let page: ProjectListResponse = decode_typed(serde_json::json!({
            "data": [{
                "id": "project-1",
                "name": "Operations",
                "type": "team",
                "users": [{"id": "secret-user"}],
                "unknownField": "marker.unknown",
            }],
            "nextCursor": null,
        }))
        .unwrap();
        assert_eq!(page.data[0].id, "project-1");
        assert_eq!(page.data[0].name, "Operations");
        assert_eq!(page.data[0].project_type, Some("team".into()));
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn typed_tag_decoder_discards_provider_timestamps() {
        let page: TagListResponse = decode_typed(serde_json::json!({
            "data": [{
                "id": "tag-1",
                "name": "production",
                "createdAt": "ignored",
                "updatedAt": "ignored",
                "unknownField": "marker.tag.unknown",
            }],
            "nextCursor": null,
        }))
        .unwrap();
        let output = serde_json::to_value(page.data[0].clone().into_view()).unwrap();
        assert_eq!(
            output,
            serde_json::json!({"id": "tag-1", "name": "production"})
        );
    }

    #[test]
    fn list_query_enforces_bounds_without_normalizing_cursor() {
        let query = ListQuery::new(200, Some("cursor with spaces/%".into())).unwrap();
        assert_eq!(query.limit, 200);
        assert_eq!(query.cursor.as_deref(), Some("cursor with spaces/%"));
        assert!(ListQuery::new(0, None).is_err());
        assert!(ListQuery::new(201, None).is_err());
    }

    #[test]
    fn cursor_validation_rejects_empty_control_and_oversized_values() {
        assert!(validate_cursor("").is_err());
        assert!(validate_cursor("cursor\nvalue").is_err());
        assert!(validate_cursor(&"x".repeat(MAX_CURSOR_BYTES + 1)).is_err());
        assert!(validate_cursor("opaque-cursor").is_ok());
    }

    #[test]
    fn malformed_provider_cursors_are_not_user_input_errors() {
        for cursor in ["", "cursor\nvalue"] {
            let error = decode_list_typed::<Workflow>(serde_json::json!({
                "data": [],
                "nextCursor": cursor,
            }))
            .unwrap_err();
            assert!(matches!(error, N8nError::MalformedProviderResponse));
        }

        let error = decode_list_typed::<Workflow>(serde_json::json!({
            "data": [],
            "nextCursor": "x".repeat(MAX_CURSOR_BYTES + 1),
        }))
        .unwrap_err();
        assert!(matches!(error, N8nError::MalformedProviderResponse));
    }

    #[test]
    fn client_new_strips_trailing_slash() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1/",
        )
        .unwrap();
        assert_eq!(client.base_url.as_str(), "https://n8n.example.com/api/v1/");
    }

    #[test]
    fn host_egress_error_mapping_is_exhaustive_and_redacted() {
        let cases = [
            (
                HostEgressProxyError::InheritedChannel,
                "host egress proxy inherited channel failed",
            ),
            (
                HostEgressProxyError::InheritedChannelStage(InheritedChannelStage::Poisoned),
                "host egress proxy inherited channel was unavailable or poisoned",
            ),
            (
                HostEgressProxyError::InheritedChannelStage(InheritedChannelStage::ReadEof),
                "host egress proxy inherited channel reached EOF",
            ),
            (
                HostEgressProxyError::InheritedChannelStage(InheritedChannelStage::Validation),
                "host egress proxy inherited channel returned an invalid response",
            ),
            (
                HostEgressProxyError::InheritedChannelStage(InheritedChannelStage::Timeout),
                "host egress proxy inherited channel timed out",
            ),
            (
                HostEgressProxyError::RequestEnvelopeTooLarge,
                "host egress proxy request exceeded the configured limit",
            ),
            (
                HostEgressProxyError::MalformedRequestEnvelope,
                "host egress proxy request envelope was malformed",
            ),
        ];
        for (error, expected) in cases {
            let mapped = map_host_egress_error(&error);
            match mapped {
                N8nError::Api {
                    status_code: 502,
                    message,
                } => assert_eq!(message, expected),
                other => panic!("unexpected mapped host egress error: {other:?}"),
            }
            let rendered = error.to_string();
            assert!(!rendered.contains("secret"));
        }
    }

    #[test]
    fn client_new_no_trailing_slash() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        assert_eq!(client.base_url.as_str(), "https://n8n.example.com/api/v1/");
    }

    #[test]
    fn client_debug_redacts() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("super-secret".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("super-secret"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn auth_debug_credential_id() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert!(dbg.contains("CredentialId"));
    }

    #[test]
    fn auth_clone() {
        let auth = N8nAuth::ApiKey("key".into());
        #[allow(clippy::redundant_clone)]
        let cloned = auth.clone();
        assert_eq!(cloned.redacted_label(), "api_key:redacted");
    }

    #[test]
    fn client_base_url_preserved() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "http://localhost:5678/api/v1",
        )
        .unwrap();
        assert_eq!(client.base_url.as_str(), "http://localhost:5678/api/v1/");
    }

    #[test]
    fn client_new_multiple_trailing_slashes() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1///",
        )
        .unwrap();
        assert_eq!(client.base_url.as_str(), "https://n8n.example.com/api/v1/");
    }

    #[test]
    fn sanitize_path_segment_accepts_plain_ids() {
        assert_eq!(
            sanitize_path_segment("1001", "workflow id").unwrap(),
            "1001"
        );
        assert_eq!(
            sanitize_path_segment("exec_abc-123", "execution id").unwrap(),
            "exec_abc-123"
        );
    }

    #[test]
    fn sanitize_path_segment_rejects_traversal_markers() {
        let err = sanitize_path_segment("../admin", "workflow id")
            .expect_err("path traversal should be rejected");
        assert!(matches!(err, N8nError::InvalidInput(message) if message.contains("workflow id")));
        sanitize_path_segment("id/../admin", "workflow id").expect_err("slash rejected");
        sanitize_path_segment("id%2Fadmin", "workflow id").expect_err("encoded slash rejected");
        sanitize_path_segment(" id", "workflow id").expect_err("leading space rejected");
    }

    #[test]
    fn auth_api_key_is_not_secretless() {
        assert!(!N8nAuth::ApiKey("key".into()).is_secretless());
    }

    #[test]
    fn auth_credential_id_is_secretless() {
        assert!(N8nAuth::CredentialId(CredentialId::new()).is_secretless());
    }

    #[test]
    fn auth_debug_bearer_shows_redacted_tuple() {
        let auth = N8nAuth::ApiKey("my-secret-key".into());
        let dbg = format!("{auth:?}");
        assert!(dbg.starts_with("ApiKey("));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn client_debug_contains_struct_name() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("N8nClient"));
    }

    #[test]
    fn client_debug_contains_base_url() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "https://custom.n8n.io/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("custom.n8n.io"));
    }

    #[test]
    fn auth_clone_credential_id() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        #[allow(clippy::redundant_clone)]
        let cloned = cred.clone();
        assert!(cloned.is_secretless());
    }

    #[test]
    fn auth_redacted_label_does_not_contain_key() {
        let auth = N8nAuth::ApiKey("very-secret-key-value".into());
        let label = auth.redacted_label();
        assert!(!label.contains("very-secret-key-value"));
    }

    #[test]
    fn client_new_with_localhost() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "http://127.0.0.1:5678/api/v1",
        )
        .unwrap();
        assert_eq!(client.base_url.as_str(), "http://127.0.0.1:5678/api/v1/");
    }

    #[test]
    fn client_new_with_port() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("key".into()),
            "http://localhost:8443/api/v1",
        )
        .unwrap();
        assert!(client.base_url.as_str().contains("8443"));
    }

    #[test]
    fn auth_debug_credential_redacts_reference() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let dbg = format!("{cred:?}");
        assert_eq!(dbg, "CredentialId(\"<redacted>\")");
    }

    #[test]
    fn client_new_empty_url() {
        assert!(N8nClient::new(N8nAuth::ApiKey("key".into()), "").is_err());
    }

    #[test]
    fn auth_redacted_label_hides_credential_reference() {
        let cred = N8nAuth::CredentialId(CredentialId::new());
        let label = cred.redacted_label();
        assert_eq!(label, "credential_id:redacted");
    }

    #[test]
    fn client_debug_does_not_leak_api_key_value() {
        let client = N8nClient::new(
            N8nAuth::ApiKey("xyzzy-super-secret-key-99".into()),
            "https://n8n.example.com/api/v1",
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(!dbg.contains("xyzzy-super-secret-key-99"));
        assert!(dbg.contains("N8nClient"));
        assert!(dbg.contains("base_url"));
    }

    #[test]
    fn canonical_base_url_rejects_unsafe_components() {
        for value in [
            "https://user:pass@n8n.example.com/api/v1",
            "https://n8n.example.com/api/v1?token=secret",
            "https://n8n.example.com/api/v1#fragment",
            "https://n8n.example.com/admin",
            "https://192.0.2.1/api/v1",
            "http://n8n.example.com/api/v1",
        ] {
            assert!(
                N8nClient::canonicalize_base_url(value).is_err(),
                "unsafe base URL accepted: {value}"
            );
        }
    }

    #[test]
    fn canonical_base_url_allows_loopback_http_only_for_tests() {
        assert_eq!(
            N8nClient::canonicalize_base_url("http://127.0.0.1:5678/api/v1/").unwrap(),
            "http://127.0.0.1:5678/api/v1"
        );
        assert_eq!(
            N8nClient::canonicalize_base_url("https://n8n.example.com:443/api/v1").unwrap(),
            "https://n8n.example.com/api/v1"
        );
    }
}
